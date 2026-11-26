//! Vault's change events (ADR 0306). With `VAULT_EVENTS=1`, botd subscribes to Vault
//! Enterprise's event stream, `sys/events/subscribe/kv-v2/*` (a WebSocket of JSON events), in
//! the secrets' namespace with its own token, and reads a name in its folders again as soon
//! as Vault says it was written, patched, deleted, undeleted or destroyed. The read carries the
//! event's `vault_index`, so a standby that hasn't caught up with the change can't answer
//! from before it. The cache time still bounds an answer's age when events are lost, and
//! after a gap in the stream every cached answer is read again (`ExternalStore::refresh`).
//!
//! - The first subscription is made at startup, and botd doesn't start without it.
//! - Before the token it was made with is due, or when botd's token changes, and at least
//!   hourly, a new subscription is opened before the old one is closed and read to its end,
//!   so no event falls between them. When the old token may have stopped events early (botd
//!   has a new one, or the new subscription opened at or after the old token's lease ran
//!   out), everything is read again.
//! - Each change is read again where it is applied, one after another, after the store's
//!   epoch moves, so neither a read in flight nor the change's own can cache over a newer one.
//!   A name changed again before it is read waits once; too many waiting make way for one
//!   read of everything.
//! - botd pings every 30 s; a stream whose server answered a ping once and then stops
//!   answering is lost. A lost stream is subscribed to again, waiting 1 s, then twice as long
//!   each time up to a minute.
//! - Audited: `secret.vault_events` (`subscribed`, `lost`, `resumed`), and what each change
//!   or gap read again as `secret.cache_refreshed`, with `trigger` `vault-event` or
//!   `vault-events-resumed`, never a value.
//!
//! Only the client side of RFC 6455 that this needs is here: the handshake over reqwest's
//! upgraded connection, masked pings, pongs and a close out, and messages in.

use super::super::external::{self, ExternalStore, Refresh, RefreshError, Scope};
use super::super::{Error, SecretStore};
use super::{unavailable, Auth, Config, Inner, Vault};
use crate::audit::{Event, Outcome};
use crate::obs::log::{log_info, log_warn};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// The event types botd subscribes to: every KV v2 change. Only its own folders' are used,
/// and Vault sends only those its policy lets it subscribe to.
const EVENTS: &str = "sys/events/subscribe/kv-v2/*";
/// RFC 6455's key suffix for `Sec-WebSocket-Accept`.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The longest message botd takes; Vault's events are a few hundred bytes.
const MAX_MESSAGE: usize = 1 << 20;
/// Longest a subscription lasts before botd makes a new one (and the old one is closed).
const RESUBSCRIBE: Duration = Duration::from_secs(3600);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long the old stream is read for events after a new one is open.
const DRAIN: Duration = Duration::from_secs(2);

#[cfg(not(test))]
mod timing {
    use std::time::Duration;
    pub const PING: Duration = Duration::from_secs(30);
    pub const PONG_WAIT: Duration = Duration::from_secs(75);
    pub const BACKOFF_START: Duration = Duration::from_secs(1);
    pub const MIN_RESUBSCRIBE: Duration = Duration::from_secs(10);
    /// Longest a frame botd sends may take to go out before the stream counts as lost.
    pub const WRITE_WAIT: Duration = Duration::from_secs(10);
}
#[cfg(test)]
mod timing {
    use std::time::Duration;
    pub const PING: Duration = Duration::from_millis(100);
    pub const PONG_WAIT: Duration = Duration::from_millis(350);
    pub const BACKOFF_START: Duration = Duration::from_millis(50);
    pub const MIN_RESUBSCRIBE: Duration = Duration::from_millis(500);
    pub const WRITE_WAIT: Duration = Duration::from_millis(300);
}
use timing::*;

const TEXT: u8 = 0x1;
const CLOSE: u8 = 0x8;
const PING_OP: u8 = 0x9;
const PONG_OP: u8 = 0xA;

/// `Sec-WebSocket-Accept` for `key`.
pub(crate) fn accept_key(key: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}{GUID}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(d.as_ref())
}

/// One frame to send, masked with `mask` as a client must.
pub(crate) fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(m | n as u8),
        n if n <= 0xFFFF => {
            out.push(m | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(m | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A message, or a control frame, as read.
#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    Text(String),
    Binary,
    Ping(Vec<u8>),
    Pong,
    Close,
}

/// Reads messages off a WebSocket: control frames as they come, data frames joined across
/// continuations. A server's frames must be unmasked and a client's masked (`masked`).
pub(crate) struct Reader<R> {
    io: R,
    masked: bool,
    /// The message being continued: whether it is text, and what came so far.
    partial: Option<(bool, Vec<u8>)>,
}

fn bad(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string())
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub(crate) fn new(io: R, masked: bool) -> Reader<R> {
        Reader { io, masked, partial: None }
    }

    pub(crate) async fn next(&mut self) -> std::io::Result<Frame> {
        loop {
            let mut h = [0u8; 2];
            self.io.read_exact(&mut h).await?;
            let fin = h[0] & 0x80 != 0;
            if h[0] & 0x70 != 0 {
                return Err(bad("a frame with reserved bits set"));
            }
            let opcode = h[0] & 0x0F;
            if (h[1] & 0x80 != 0) != self.masked {
                return Err(bad(if self.masked { "an unmasked frame from a client" } else { "a masked frame from the server" }));
            }
            let len = match h[1] & 0x7F {
                126 => {
                    let mut b = [0u8; 2];
                    self.io.read_exact(&mut b).await?;
                    u64::from(u16::from_be_bytes(b))
                }
                127 => {
                    let mut b = [0u8; 8];
                    self.io.read_exact(&mut b).await?;
                    u64::from_be_bytes(b)
                }
                n => u64::from(n),
            };
            if opcode >= 0x8 && (len > 125 || !fin) {
                return Err(bad("a control frame too long or in pieces"));
            }
            let so_far = self.partial.as_ref().map_or(0, |(_, d)| d.len());
            if so_far as u64 + len > MAX_MESSAGE as u64 {
                return Err(bad("a message over 1 MiB"));
            }
            let mut key = [0u8; 4];
            if self.masked {
                self.io.read_exact(&mut key).await?;
            }
            let mut payload = vec![0u8; len as usize];
            self.io.read_exact(&mut payload).await?;
            if self.masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= key[i % 4];
                }
            }
            match (opcode, self.partial.as_mut()) {
                (CLOSE, _) => return Ok(Frame::Close),
                (PING_OP, _) => return Ok(Frame::Ping(payload)),
                (PONG_OP, _) => return Ok(Frame::Pong),
                (0x0, Some((_, data))) => data.extend(payload),
                (0x1 | 0x2, None) => self.partial = Some((opcode == TEXT, payload)),
                _ => return Err(bad("a frame out of order")),
            }
            if fin && let Some((text, data)) = self.partial.take() {
                return match text {
                    true => String::from_utf8(data).map(Frame::Text).map_err(|_| bad("text that isn't UTF-8")),
                    false => Ok(Frame::Binary),
                };
            }
        }
    }
}

/// A change Vault announced to one of botd's names.
#[derive(Debug, PartialEq)]
pub(crate) struct Seen {
    pub scope: Scope,
    pub name: String,
    /// The event's `vault_index`, for a read that can't be answered from before it.
    pub index: Option<String>,
    pub event: String,
}

/// The change `text` (one event, as Vault's JSON) announces to a name botd reads, if any:
/// in `cfg`'s mount, prefix and namespace, in a shared folder or, with `users`, a user's.
pub(crate) fn seen(text: &str, cfg: &Config, users: bool) -> Option<Seen> {
    let v: Value = serde_json::from_str(text).ok()?;
    let data = &v["data"];
    let event = data["event_type"].as_str().filter(|t| t.starts_with("kv-v2/"))?;
    if let Some(ns) = data["namespace"].as_str()
        && ns.trim_matches('/') != cfg.namespace.as_deref().unwrap_or_default()
    {
        return None;
    }
    let mount = format!("{}/", cfg.mount);
    let mount_path = data["plugin_info"]["mount_path"].as_str();
    if mount_path.is_some_and(|m| m.trim_start_matches('/') != mount) {
        return None;
    }
    let meta = &data["event"]["metadata"];
    let path = meta["path"].as_str().or_else(|| meta["data_path"].as_str())?.trim_start_matches('/');
    let rel = match path.strip_prefix(&mount) {
        Some(r) => r,
        // A path relative to the mount, which the event names as ours.
        None if mount_path.is_some() => path,
        None => return None,
    };
    let (kind, rest) = rel.split_once('/')?;
    if !matches!(kind, "data" | "metadata" | "delete" | "undelete" | "destroy") {
        return None;
    }
    let rest = rest.strip_prefix(&format!("{}/", cfg.prefix))?;
    let (scope, name) = match rest.split_once('/')? {
        ("bots", n) => (Scope::Bots, n),
        ("server", n) => (Scope::Server, n),
        ("users", r) if users => {
            let (id, n) = r.split_once('/')?;
            (Scope::user(id)?, n)
        }
        _ => return None,
    };
    if name.contains('/') || !scope.holds(name) {
        return None;
    }
    let index = meta["vault_index"].as_str().filter(|i| !i.is_empty() && i.len() <= 1024 && i.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))).map(String::from);
    Some(Seen { scope, name: name.to_string(), index, event: event.to_string() })
}

/// What the stream tells the thread that applies it to the store.
#[derive(Debug, PartialEq)]
enum Note {
    Changed { scope: Scope, name: String, event: String, index: Option<String> },
    /// Read everything cached again: subscribed again after a gap, or after a token that may
    /// have stopped events early, so events may have been missed; or too many changes waited.
    /// At the newest index of the changes it stands for, when it stands for some.
    Resumed(Option<String>),
}

/// Most names waiting to be read again; past it they make way for one read of everything.
const MAX_PENDING: usize = 1024;

/// Changes waiting for the thread that applies them. A name changed again before it is read
/// waits once, so a busy name can't hold up the rest or pile up reads; past `MAX_PENDING`
/// names, they are dropped for one read of everything cached. Each is read at the newest
/// index seen so far: Vault sends events in order, so it covers every change before it, and
/// no read or list asks for less than one already applied.
#[derive(Default)]
struct Pending {
    order: VecDeque<(Scope, String)>,
    /// The latest event type for each name waiting.
    latest: HashMap<(Scope, String), String>,
    all: bool,
    newest: Option<String>,
    /// The read of everything stands for dropped changes, so it asks for `newest` too.
    floor: bool,
    sender_gone: bool,
    receiver_gone: bool,
}

#[derive(Default)]
struct Queue {
    pending: Mutex<Pending>,
    ready: Condvar,
}

impl Queue {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The stream's end of the queue.
struct Tx(Arc<Queue>);
/// The applying thread's end.
struct Rx(Arc<Queue>);

fn queue() -> (Tx, Rx) {
    let q = Arc::new(Queue::default());
    (Tx(Arc::clone(&q)), Rx(q))
}

impl Tx {
    fn send(&self, note: Note) {
        let mut p = self.0.lock();
        match note {
            Note::Resumed(index) => {
                p.all = true;
                if index.is_some() {
                    p.newest = index;
                    p.floor = true;
                }
            }
            Note::Changed { scope, name, event, index } => {
                if index.is_some() {
                    p.newest = index;
                }
                let key = (scope, name);
                if let Some(waiting) = p.latest.get_mut(&key) {
                    *waiting = event;
                } else if p.order.len() >= MAX_PENDING {
                    p.order.clear();
                    p.latest.clear();
                    p.all = true;
                    p.floor = true;
                } else {
                    p.order.push_back(key.clone());
                    p.latest.insert(key, event);
                }
            }
        }
        drop(p);
        self.0.ready.notify_one();
    }

    /// Nothing applies changes any more: the store is gone.
    fn is_closed(&self) -> bool {
        self.0.lock().receiver_gone
    }
}

impl Drop for Tx {
    fn drop(&mut self) {
        self.0.lock().sender_gone = true;
        self.0.ready.notify_one();
    }
}

impl Rx {
    /// The next thing to apply, a read of everything first; None once the stream is gone.
    fn recv(&self) -> Option<Note> {
        let mut p = self.0.lock();
        loop {
            if std::mem::take(&mut p.all) {
                let index = if std::mem::take(&mut p.floor) { p.newest.clone() } else { None };
                return Some(Note::Resumed(index));
            }
            if let Some(key) = p.order.pop_front() {
                let event = p.latest.remove(&key).unwrap_or_default();
                return Some(Note::Changed { scope: key.0, name: key.1, event, index: p.newest.clone() });
            }
            if p.sender_gone {
                return None;
            }
            p = self.0.ready.wait(p).unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for Rx {
    fn drop(&mut self) {
        self.0.lock().receiver_gone = true;
    }
}

/// A subscription Vault accepted, and the token it was made with.
struct Subscribed {
    io: reqwest::Upgraded,
    token: Zeroizing<String>,
    /// When to subscribe again: before that token is due.
    due: Instant,
    /// The token may be past its time by `due` (a lease shorter than `MIN_RESUBSCRIBE`), so
    /// the next subscription reads everything again.
    late: bool,
    /// When that token's lease runs out, if known: a stream that outlives it may stop
    /// delivering events without a word.
    expires: Option<Instant>,
}

impl Inner {
    /// Subscribes to `EVENTS`; when Vault refuses the token, gets a new one and asks once more.
    /// A token file is read each time, as Vault Agent may have written a new token to it.
    async fn subscribe(&self) -> Result<Subscribed, Error> {
        let file = matches!(self.cfg.auth, Auth::Token { file: Some(_), .. });
        for fresh in [file, true] {
            let token = self.token(fresh).await?;
            if let Some(io) = self.subscribe_with(&token, fresh).await? {
                let (due, late, expires) = self.due_for(&token).await;
                return Ok(Subscribed { io, token, due, late, expires });
            }
        }
        unreachable!("the second pass returns")
    }

    async fn subscribe_with(&self, token: &str, last: bool) -> Result<Option<reqwest::Upgraded>, Error> {
        let key = base64::engine::general_purpose::STANDARD.encode(crate::random_bytes(16));
        let res = self
            .request(reqwest::Method::GET, &format!("{EVENTS}?json=true"))
            .header("X-Vault-Token", token)
            .header(reqwest::header::CONNECTION, "Upgrade")
            .header(reqwest::header::UPGRADE, "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", &key)
            .send()
            .await
            .map_err(|e| unavailable(EVENTS, e))?;
        let status = res.status();
        match status {
            reqwest::StatusCode::SWITCHING_PROTOCOLS => {}
            reqwest::StatusCode::FORBIDDEN if !last => return Ok(None),
            reqwest::StatusCode::FORBIDDEN => {
                return Err(Error::Unavailable(format!("Vault answered {status} for {EVENTS}; botd's policy needs read on {EVENTS}, and list and subscribe (with subscribe_event_types) on its folders")));
            }
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED | reqwest::StatusCode::NOT_IMPLEMENTED => {
                return Err(Error::Unavailable(format!(
                    "Vault answered {status} for {EVENTS}: change events need Vault Enterprise 1.16 or later, or HCP Vault Dedicated; leave VAULT_EVENTS out on Vault's community edition and OpenBao"
                )));
            }
            s if s.is_redirection() => {
                return Err(Error::Unavailable(format!("Vault answered {s} for {EVENTS}: point VAULT_ADDR at the active node or a performance standby, which take subscriptions")));
            }
            s => return Err(Error::Unavailable(format!("Vault answered {s} for {EVENTS}"))),
        }
        let header = |k: reqwest::header::HeaderName| res.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        if header(reqwest::header::SEC_WEBSOCKET_ACCEPT) != accept_key(&key) || !header(reqwest::header::UPGRADE).eq_ignore_ascii_case("websocket") {
            return Err(Error::Unavailable(format!("Vault: the answer to {EVENTS} isn't a WebSocket")));
        }
        res.upgrade().await.map(Some).map_err(|e| unavailable(EVENTS, e))
    }

    /// When to subscribe again with a new token: before `token` is due, as botd logs in
    /// again (two thirds of the way through its lease), or two thirds of the way through a
    /// given token's TTL; within `MIN_RESUBSCRIBE` and `RESUBSCRIBE` from now. True when
    /// that is later than the token allows. Then when the token runs out, if known.
    async fn due_for(&self, token: &str) -> (Instant, bool, Option<Instant>) {
        let now = Instant::now();
        let (due, expires) = match &self.cfg.auth {
            Auth::Token { .. } => match self.token_life(token, "auth/token/lookup-self", reqwest::Method::GET, None, true).await {
                Ok(Some((ttl, _))) if ttl > 0 => (Some(now + Duration::from_secs(ttl) * 2 / 3), Some(now + Duration::from_secs(ttl))),
                _ => (None, None),
            },
            _ => self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.value.as_str() == token).map_or((None, None), |t| (t.renew_at, t.expires)),
        };
        let due = due.unwrap_or(now + RESUBSCRIBE);
        (due.clamp(now + MIN_RESUBSCRIBE, now + RESUBSCRIBE), due < now + MIN_RESUBSCRIBE, expires)
    }

    /// Whether botd still uses `token`: when it has a new one (Vault refused the old, or Vault
    /// Agent wrote a new one to the file), a stream made with the old one may stop without a word.
    fn uses(&self, token: &str) -> bool {
        let cached = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_none_or(|t| t.value.as_str() == token);
        let file = match &self.cfg.auth {
            Auth::Token { file: Some(path), .. } => std::fs::read_to_string(path).ok().map(Zeroizing::new),
            _ => None,
        };
        cached && file.is_none_or(|f| f.trim().is_empty() || f.trim() == token)
    }

    /// Hands on what `text` announces a change to, if botd reads that name; it is read again
    /// where the changes are applied, one after another.
    fn announce(&self, text: &str, users: bool, tx: &Tx) {
        let Some(s) = seen(text, &self.cfg, users) else { return };
        tx.send(Note::Changed { scope: s.scope, name: s.name, event: s.event, index: s.index });
    }
}

/// Why a stream stopped being followed.
enum End {
    /// Time for a new subscription; the old one still works. `catch_up`: it may have
    /// stopped delivering events already, so read everything again once the new one is open.
    Due { catch_up: bool },
    Lost(String),
    /// Nothing applies changes any more: the store is gone.
    Stopped,
}

/// One subscription being read: messages come from a task of their own, so a ping never
/// interrupts a read halfway through a frame.
struct Stream {
    writer: tokio::io::WriteHalf<reqwest::Upgraded>,
    rx: mpsc::Receiver<std::io::Result<Frame>>,
    task: tokio::task::JoinHandle<()>,
    token: Zeroizing<String>,
    due: Instant,
    late: bool,
    expires: Option<Instant>,
    /// The reader met the stream's end (a close, an error, or none left), maybe while botd
    /// was still opening the next one.
    ended: Arc<AtomicBool>,
    /// Vault answered a ping on this stream, so from then on it must keep doing so.
    answers: bool,
    /// Since when a ping has waited for its answer.
    waiting: Option<Instant>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Stream {
    fn new(s: Subscribed) -> Stream {
        let (reader, writer) = tokio::io::split(s.io);
        let (tx, rx) = mpsc::channel(64);
        let ended = Arc::new(AtomicBool::new(false));
        let end = Arc::clone(&ended);
        let task = tokio::spawn(async move {
            let mut r = Reader::new(reader, false);
            loop {
                let f = r.next().await;
                let last = matches!(f, Err(_) | Ok(Frame::Close));
                if last {
                    end.store(true, Ordering::SeqCst);
                }
                if tx.send(f).await.is_err() || last {
                    break;
                }
            }
        });
        Stream { writer, rx, task, token: s.token, due: s.due, late: s.late, expires: s.expires, ended, answers: false, waiting: None }
    }

    /// Sends a frame, within `WRITE_WAIT`: a peer that stops reading can't hold botd here.
    async fn send(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mask: [u8; 4] = crate::random_bytes(4).try_into().unwrap_or_default();
        let bytes = frame(opcode, payload, Some(mask));
        let write = async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        };
        tokio::time::timeout(WRITE_WAIT, write).await.unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
    }

    /// Follows the stream until it is due, lost, or no longer needed.
    async fn follow(&mut self, inner: &Inner, users: bool, tx: &Tx) -> End {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + PING, PING);
        let due = tokio::time::sleep_until(self.due.into());
        tokio::pin!(due);
        loop {
            tokio::select! {
                () = &mut due => return End::Due { catch_up: self.late },
                m = self.rx.recv() => match m {
                    Some(Ok(Frame::Text(t))) => inner.announce(&t, users, tx),
                    Some(Ok(Frame::Binary)) => {}
                    Some(Ok(Frame::Ping(p))) => {
                        if self.send(PONG_OP, &p).await.is_err() {
                            return End::Lost("botd couldn't answer Vault's ping".into());
                        }
                    }
                    Some(Ok(Frame::Pong)) => {
                        self.answers = true;
                        self.waiting = None;
                    }
                    Some(Ok(Frame::Close)) => return End::Lost("Vault closed the stream".into()),
                    Some(Err(e)) => return End::Lost(format!("the stream broke: {e}")),
                    None => return End::Lost("the stream ended".into()),
                },
                _ = tick.tick() => {
                    if tx.is_closed() {
                        return End::Stopped;
                    }
                    if !inner.uses(&self.token) {
                        return End::Due { catch_up: true };
                    }
                    if self.answers && self.waiting.is_some_and(|at| at.elapsed() >= PONG_WAIT) {
                        return End::Lost("Vault stopped answering pings".into());
                    }
                    self.waiting.get_or_insert_with(Instant::now);
                    if self.send(PING_OP, b"").await.is_err() {
                        return End::Lost("botd couldn't ping Vault".into());
                    }
                }
            }
        }
    }

    /// Closes the stream once a new one is open, reading the events still on their way
    /// until Vault closes its side or `DRAIN` is up.
    async fn finish(mut self, inner: &Inner, users: bool, tx: &Tx) {
        let until = tokio::time::Instant::now() + DRAIN;
        let _ = tokio::time::timeout_at(until, self.send(CLOSE, &1000u16.to_be_bytes())).await;
        while let Ok(Some(Ok(f))) = tokio::time::timeout_at(until, self.rx.recv()).await {
            match f {
                Frame::Text(t) => inner.announce(&t, users, tx),
                Frame::Close => break,
                _ => {}
            }
        }
    }
}

/// `secret.vault_events`: the stream's `state`, against Vault's address.
fn audit_state(addr: &str, state: &str, error: Option<&str>) {
    let e = Event::new(external::actor(), "secret.vault_events").target("vault", addr);
    external::audit(match error {
        None => e.details(json!({ "store": "vault", "state": state })),
        Some(err) => e.outcome(Outcome::Failure).details(json!({ "store": "vault", "state": state, "error": err })),
    });
}

/// Follows the stream from the first subscription, for as long as the store is there.
async fn follow(inner: Arc<Inner>, first: Subscribed, users: bool, tx: Tx) {
    let addr = inner.cfg.addr.clone();
    let mut stream = Stream::new(first);
    loop {
        let why = loop {
            match stream.follow(&inner, users, &tx).await {
                End::Stopped => return,
                End::Lost(why) => break why,
                End::Due { catch_up } => match inner.subscribe().await {
                    Ok(new) => {
                        // Opened only after the old token ran out (a slow login or Vault), or
                        // after the old stream ended: changes in between had no event.
                        let catch_up = catch_up || stream.ended.load(Ordering::SeqCst) || stream.expires.is_some_and(|at| Instant::now() >= at);
                        std::mem::replace(&mut stream, Stream::new(new)).finish(&inner, users, &tx).await;
                        if catch_up {
                            log_info!("Vault: subscribed to change events with a new token; reading every cached secret again, as the old stream may have stopped early (ADR 0306).");
                            tx.send(Note::Resumed(None));
                        }
                    }
                    // The old stream may still work: keep it, and try again a little later. Its
                    // token may run out meanwhile, so the next one reads everything again.
                    Err(e) => {
                        log_warn!("Vault: couldn't renew the subscription to change events ({e}); keeping the current one (ADR 0306).");
                        stream.due = Instant::now() + MIN_RESUBSCRIBE;
                        stream.late = true;
                    }
                },
            }
        };
        drop(stream);
        log_warn!("Vault: change events stopped ({why}); subscribing again. Until then a change reaches botd within SECRETS_CACHE_SECONDS (ADR 0306).");
        audit_state(&addr, "lost", Some(&why));
        let mut wait = BACKOFF_START;
        stream = loop {
            tokio::time::sleep(wait).await;
            if tx.is_closed() {
                return;
            }
            match inner.subscribe().await {
                Ok(s) => break Stream::new(s),
                Err(e) => {
                    wait = (wait * 2).min(BACKOFF_MAX);
                    log_warn!("Vault: subscribing to change events again failed ({e}); trying again in {} s (ADR 0306).", wait.as_secs().max(1));
                }
            }
        };
        log_info!("Vault: change events resumed; reading every cached secret again for changes made meanwhile (ADR 0306).");
        audit_state(&addr, "resumed", None);
        tx.send(Note::Resumed(None));
    }
}

/// `secret.cache_refreshed` for what botd read again on its own, by `trigger`.
fn audit_refresh(report: &Refresh, target: (&str, &str), trigger: &str, event: Option<&str>) {
    let mut details = report.audit_details();
    details["trigger"] = json!(trigger);
    if let Some(e) = event {
        details["event"] = json!(e);
    }
    let outcome = if report.ok() { Outcome::Success } else { Outcome::Failure };
    external::audit(Event::new(external::actor(), "secret.cache_refreshed").target(target.0, target.1).outcome(outcome).details(details));
}

/// Applies what the stream announces to the store, on a thread of its own: reads and
/// refreshes block, and must not hold up the stream.
fn apply(store: Weak<ExternalStore>, rx: Rx) {
    while let Some(note) = rx.recv() {
        let Some(store) = store.upgrade() else { return };
        match note {
            Note::Changed { scope, name, event, index } => {
                let Some(entry) = store.changed(&scope, &name, index.as_deref()) else { continue };
                let folder = scope.folder('/');
                if entry.restart {
                    log_warn!("Vault: {name} in {folder} changed ({event}), but botd read it at startup and keeps the old value until it restarts (ADR 0291).");
                } else {
                    log_info!("Vault: {name} in {folder} changed ({event}); new runs get what Vault has now (VAULT_EVENTS, ADR 0306).");
                }
                let report = Refresh { store: store.kind(), names: Some(vec![name.clone()]), entries: vec![entry], folders: Vec::new() };
                audit_refresh(&report, ("secret", &name), "vault-event", Some(&event));
            }
            Note::Resumed(index) => {
                let mut tries = 0;
                let report = loop {
                    match store.refresh_at(None, index.as_deref()) {
                        Ok(r) => break Some(r),
                        // An admin's refresh began before the gap ended: wait for it, then read again.
                        Err(RefreshError::Busy) if tries < 60 => {
                            tries += 1;
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        Err(e) => {
                            log_warn!("Vault: couldn't read the cache again after change events resumed ({e}); answers cached before end within SECRETS_CACHE_SECONDS (ADR 0306).");
                            break None;
                        }
                    }
                };
                if let Some(r) = report {
                    if !r.restart().is_empty() {
                        log_warn!("Vault: {} changed while change events were down, but botd read them at startup and keeps the old values until it restarts (ADR 0291).", r.restart().join(", "));
                    }
                    audit_refresh(&r, ("secret_store", r.store), "vault-events-resumed", None);
                }
            }
        }
    }
}

/// Subscribes now, so botd doesn't start when Vault won't take it, then follows the stream
/// on Vault's runtime and applies it to `store` on a thread of its own.
pub(super) fn start(vault: &Vault, store: Weak<ExternalStore>) -> Result<(), Error> {
    let users = store.upgrade().is_some_and(|s| s.user_folders());
    let first = vault.run(|i| async move { i.subscribe().await })?;
    audit_state(&vault.inner.cfg.addr, "subscribed", None);
    let (tx, rx) = queue();
    std::thread::Builder::new().name("vault-events".into()).spawn(move || apply(store, rx)).map_err(|e| unavailable("change events", e))?;
    vault.worker.spawn(follow(Arc::clone(&vault.inner), first, users, tx))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::super::env::EnvStore;
    use super::super::super::external::tests::audited;
    use super::super::super::http::tests::settings;
    use super::super::super::leases::tests::wait_for;
    use super::super::super::redact;
    use super::super::tests::{check, put, stand_in, F};
    use super::*;
    use axum::extract::{Request, State};
    use axum::response::{IntoResponse, Response};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// What the stand-in sends down a subscription.
    pub(crate) enum Out {
        Text(String),
        Close,
    }

    /// The stand-in's event streams.
    #[derive(Default)]
    pub(crate) struct Hub {
        subs: Mutex<Vec<mpsc::UnboundedSender<Out>>>,
        pub subscriptions: AtomicUsize,
        /// Subscriptions asked for, counted before `delay_ms`.
        pub asked: AtomicUsize,
        /// The token of each subscription.
        pub tokens: Mutex<Vec<String>>,
        /// Answers subscriptions with this status instead.
        pub status: AtomicUsize,
        /// Stops answering pings.
        pub silent: AtomicBool,
        /// How long each subscription waits for its answer, in milliseconds.
        pub delay_ms: AtomicUsize,
        pub pongs: AtomicUsize,
        /// Close frames botd sent.
        pub closes: AtomicUsize,
        /// The `X-Vault-Index` of each KV read that had one.
        pub indexes: Mutex<Vec<String>>,
        /// The same, for each list.
        pub list_indexes: Mutex<Vec<String>>,
    }

    impl Hub {
        /// Sends `text` down every open stream.
        pub(crate) fn emit(&self, text: &str) {
            self.subs.lock().unwrap().retain(|s| s.send(Out::Text(text.to_string())).is_ok());
        }

        /// Closes every stream as Vault does, with a close frame.
        pub(crate) fn close_all(&self) {
            for s in self.subs.lock().unwrap().drain(..) {
                let _ = s.send(Out::Close);
            }
        }

        /// Drops every stream's connection without a word.
        pub(crate) fn cut(&self) {
            self.subs.lock().unwrap().clear();
        }

        pub(crate) fn open(&self) -> usize {
            self.subs.lock().unwrap().iter().filter(|s| !s.is_closed()).count()
        }

        pub(crate) fn saw(&self, h: &axum::http::HeaderMap) {
            if let Some(i) = h.get("x-vault-index").and_then(|v| v.to_str().ok()) {
                self.indexes.lock().unwrap().push(i.to_string());
            }
        }

        pub(crate) fn listed(&self, h: &axum::http::HeaderMap) {
            if let Some(i) = h.get("x-vault-index").and_then(|v| v.to_str().ok()) {
                self.list_indexes.lock().unwrap().push(i.to_string());
            }
        }
    }

    /// An event as Vault sends it, for `op` on `<mount>/<kind>/<path>`.
    pub(crate) fn event(op: &str, kind: &str, path: &str) -> String {
        let p = format!("secret/{kind}/{path}");
        json!({
            "id": crate::random_hex(8), "source": "vault://stand-in", "specversion": "1.0", "type": "*",
            "data": {
                "event": { "id": "e1", "metadata": { "current_version": "2", "data_path": p, "modified": "true", "operation": op, "path": p, "vault_index": "djE6c3RhbmQtaW4=" } },
                "event_type": format!("kv-v2/{op}"),
                "plugin_info": { "mount_class": "secret", "mount_accessor": "kv_1", "mount_path": "secret/", "plugin": "kv" }
            },
            "datacontentype": "application/cloudevents", "time": "2026-11-26T08:00:00Z"
        })
        .to_string()
    }

    /// `sys/events/subscribe/<types>`: the WebSocket handshake, then the hub's events down the
    /// stream, answering botd's pings and close.
    pub(crate) async fn subscribe(State(f): State<F>, mut req: Request) -> Response {
        let h = req.headers().clone();
        if let Err(e) = check(&f, &h) {
            return e.into_response();
        }
        f.events.asked.fetch_add(1, Ordering::SeqCst);
        if let ms @ 1.. = f.events.delay_ms.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(ms as u64)).await;
        }
        if let s @ 1.. = f.events.status.load(Ordering::SeqCst) {
            return axum::http::StatusCode::from_u16(s as u16).unwrap().into_response();
        }
        assert_eq!(req.uri().path(), "/v1/sys/events/subscribe/kv-v2/*");
        assert_eq!(req.uri().query(), Some("json=true"));
        let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        assert!(get("connection").eq_ignore_ascii_case("upgrade") && get("upgrade") == "websocket" && get("sec-websocket-version") == "13");
        let accept = accept_key(&get("sec-websocket-key"));
        f.events.subscriptions.fetch_add(1, Ordering::SeqCst);
        f.events.tokens.lock().unwrap().push(get("x-vault-token"));
        let (tx, mut out) = mpsc::unbounded_channel();
        f.events.subs.lock().unwrap().push(tx);
        let on = hyper::upgrade::on(&mut req);
        let hub = Arc::clone(&f);
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(on.await.unwrap());
            let (r, mut w) = tokio::io::split(io);
            let (ctx, mut client) = mpsc::channel(16);
            tokio::spawn(async move {
                let mut r = Reader::new(r, true);
                while let Ok(m) = r.next().await {
                    if ctx.send(m).await.is_err() {
                        break;
                    }
                }
            });
            loop {
                tokio::select! {
                    o = out.recv() => match o {
                        Some(Out::Text(t)) => { if w.write_all(&frame(TEXT, t.as_bytes(), None)).await.is_err() { break } }
                        Some(Out::Close) => { let _ = w.write_all(&frame(CLOSE, &1000u16.to_be_bytes(), None)).await; break }
                        None => break,
                    },
                    m = client.recv() => match m {
                        Some(Frame::Ping(p)) if !hub.events.silent.load(Ordering::SeqCst) => {
                            hub.events.pongs.fetch_add(1, Ordering::SeqCst);
                            if w.write_all(&frame(PONG_OP, &p, None)).await.is_err() { break }
                        }
                        Some(Frame::Close) => {
                            hub.events.closes.fetch_add(1, Ordering::SeqCst);
                            let _ = w.write_all(&frame(CLOSE, &1000u16.to_be_bytes(), None)).await;
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    },
                }
            }
        });
        Response::builder()
            .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn store(url: &str, extra: &[(&str, &str)], ttl: &str) -> Arc<ExternalStore> {
        let mut pairs = vec![("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url), ("VAULT_EVENTS", "1"), ("SECRETS_CACHE_SECONDS", ttl)];
        pairs.extend_from_slice(extra);
        external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap()
    }

    fn token_stand_in(token: &str) -> (String, F) {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push(token.into());
        (url, f)
    }

    fn get(x: &ExternalStore, name: &str) -> Option<String> {
        x.get(name).unwrap().map(|v| v.expose().to_string())
    }

    #[tokio::test]
    async fn frames_follow_rfc_6455() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455's own example");
        assert_eq!(frame(TEXT, b"Hello", None), [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        assert_eq!(frame(TEXT, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d])), [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
        let long = "x".repeat(300);
        assert_eq!(frame(TEXT, long.as_bytes(), None)[..4], [0x81, 126, 0x01, 0x2c]);
        assert_eq!(frame(TEXT, &vec![b'y'; 70_000], None)[..10], [0x81, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70]);

        // "Hel" then "lo" in a continuation, with a ping between them (RFC 6455 5.4), then the long one.
        let mut bytes = vec![0x01, 0x03, 0x48, 0x65, 0x6c];
        bytes.extend(frame(PING_OP, b"p", None));
        bytes.extend([0x80, 0x02, 0x6c, 0x6f]);
        bytes.extend(frame(TEXT, long.as_bytes(), None));
        bytes.extend(frame(CLOSE, &[], None));
        let mut r = Reader::new(&bytes[..], false);
        assert_eq!(r.next().await.unwrap(), Frame::Ping(b"p".to_vec()));
        assert_eq!(r.next().await.unwrap(), Frame::Text("Hello".into()));
        assert_eq!(r.next().await.unwrap(), Frame::Text(long.clone()));
        assert_eq!(r.next().await.unwrap(), Frame::Close);
        assert!(r.next().await.is_err(), "the end of the stream");

        let masked = frame(TEXT, b"Hello", Some([1, 2, 3, 4]));
        assert_eq!(Reader::new(&masked[..], true).next().await.unwrap(), Frame::Text("Hello".into()));
        for (bytes, why) in [
            (masked.clone(), "a masked frame from the server"),
            (frame(TEXT, b"Hello", None).iter().copied().map(|b| if b == 0x81 { 0xC1 } else { b }).collect(), "reserved bits"),
            ([vec![0x89, 126, 0, 200], vec![0; 200]].concat(), "control frame too long"),
            (vec![0x09, 0x00], "control frame too long or in pieces"),
            (vec![0x80, 0x01, 0x41], "out of order"),
            (vec![0x81, 127, 0, 0, 0, 0, 0, 0x10, 0, 1], "over 1 MiB"),
            (vec![0x81, 0x02, 0xc3, 0x28], "UTF-8"),
        ] {
            let e = Reader::new(&bytes[..], false).next().await.unwrap_err();
            assert!(e.to_string().contains(why), "{why}: {e}");
        }
        let e = Reader::new(&frame(TEXT, b"x", None)[..], true).next().await.unwrap_err();
        assert!(e.to_string().contains("unmasked frame from a client"), "{e}");
    }

    #[test]
    fn a_name_changed_again_waits_once_and_too_many_make_way_for_one_full_read() {
        let changed = |name: &str, index: &str| Note::Changed { scope: Scope::Bots, name: name.into(), event: "kv-v2/data-write".into(), index: Some(index.into()) };
        let (tx, rx) = queue();
        tx.send(changed("A_TOKEN", "1"));
        tx.send(changed("B_TOKEN", "2"));
        tx.send(changed("A_TOKEN", "3"));
        assert_eq!(rx.recv(), Some(changed("A_TOKEN", "3")), "once, in its first place, at the newest index");
        assert_eq!(rx.recv(), Some(changed("B_TOKEN", "3")), "never at less than one already applied");

        for i in 0..MAX_PENDING {
            tx.send(changed(&format!("N{i}_TOKEN"), "4"));
        }
        tx.send(changed("C_TOKEN", "5"));
        assert_eq!(rx.recv(), Some(Note::Resumed(Some("5".into()))), "everything read again instead, at the newest change's index");
        tx.send(changed("D_TOKEN", "6"));
        tx.send(Note::Resumed(None));
        assert_eq!(rx.recv(), Some(Note::Resumed(None)), "a full read first");
        assert_eq!(rx.recv(), Some(changed("D_TOKEN", "6")));
        assert!(!tx.is_closed());
        drop(tx);
        assert_eq!(rx.recv(), None, "the stream is gone");
        let (tx, rx) = queue();
        drop(rx);
        assert!(tx.is_closed(), "the store is gone");
    }

    #[test]
    fn only_changes_to_botds_own_names_are_taken() {
        let pairs = [("VAULT_ADDR", "http://127.0.0.1:8200"), ("VAULT_TOKEN", "t"), ("VAULT_NAMESPACE", "admin/team-a")];
        let cfg = Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap();
        let ours = |op: &str, kind: &str, path: &str| {
            let mut v: Value = serde_json::from_str(&event(op, kind, path)).unwrap();
            v["data"]["namespace"] = json!("admin/team-a/");
            v.to_string()
        };
        let s = seen(&ours("data-write", "data", "superbot/bots/OPENAI_API_KEY"), &cfg, false).unwrap();
        assert_eq!(s, Seen { scope: Scope::Bots, name: "OPENAI_API_KEY".into(), index: Some("djE6c3RhbmQtaW4=".into()), event: "kv-v2/data-write".into() });
        for (op, kind) in [("data-delete", "data"), ("delete", "delete"), ("undelete", "undelete"), ("destroy", "destroy"), ("metadata-delete", "metadata"), ("data-patch", "data")] {
            assert_eq!(seen(&ours(op, kind, "superbot/server/LINODE_TOKEN"), &cfg, false).unwrap().scope, Scope::Server, "{op}");
        }
        // A path relative to the mount, as the event's plugin_info names it.
        let mut rel: Value = serde_json::from_str(&ours("data-write", "data", "superbot/bots/OPENAI_API_KEY")).unwrap();
        rel["data"]["event"]["metadata"]["path"] = json!("data/superbot/bots/OPENAI_API_KEY");
        assert_eq!(seen(&rel.to_string(), &cfg, false).unwrap().name, "OPENAI_API_KEY");
        let user = ours("data-write", "data", "superbot/users/ua1/OPENAI_API_KEY");
        assert_eq!(seen(&user, &cfg, false), None, "user folders off");
        assert_eq!(seen(&user, &cfg, true).unwrap().scope, Scope::user("ua1").unwrap());

        let other_mount = ours("data-write", "data", "superbot/bots/OPENAI_API_KEY").replace("\"secret/\"", "\"kv/\"");
        let mut other_ns: Value = serde_json::from_str(&ours("data-write", "data", "superbot/bots/OPENAI_API_KEY")).unwrap();
        other_ns["data"]["namespace"] = json!("admin/team-b/");
        let mut bad_index: Value = serde_json::from_str(&ours("data-write", "data", "superbot/bots/OPENAI_API_KEY")).unwrap();
        bad_index["data"]["event"]["metadata"]["vault_index"] = json!("a b\r\nX-Other: 1");
        assert_eq!(seen(&bad_index.to_string(), &cfg, false).unwrap().index, None, "never a header value botd can't send as it is");
        for (text, why) in [
            (ours("data-write", "data", "other/bots/OPENAI_API_KEY"), "another prefix"),
            (ours("data-write", "data", "superbot/bots/LINODE_TOKEN"), "a name of another folder"),
            (ours("data-write", "data", "superbot/bots/nested/DEEPER"), "a nested path"),
            (ours("data-write", "data", "superbot/bots/AUTH_PASSWORD"), "a reserved name"),
            (ours("data-write", "config", "superbot/bots/OPENAI_API_KEY"), "not a secret's path"),
            (ours("config-write", "config", ""), "the mount's config"),
            (other_mount, "another mount"),
            (other_ns.to_string(), "another namespace"),
            (ours("data-write", "data", "superbot/bots/OPENAI_API_KEY").replace("kv-v2/data-write", "kv-v1/write"), "not KV v2"),
            ("not json".into(), "not JSON"),
        ] {
            assert_eq!(seen(&text, &cfg, true), None, "{why}");
        }
    }

    #[test]
    fn a_rotation_in_vault_reaches_new_runs_at_once() {
        let (url, f) = token_stand_in("hvs.events");
        put(&f, "bots/EVENTS_ROTATED_TOKEN", "events-rotated-1");
        put(&f, "bots/EVENTS_STARTUP_TOKEN", "events-startup-1");
        put(&f, "bots/EVENTS_DELETED_TOKEN", "events-deleted-1");
        let x = store(&url, &[("VAULT_TOKEN", "hvs.events")], "3600");
        assert!(x.describe().contains("following Vault's change events"), "{}", x.describe());
        x.check().unwrap();
        assert!(x.watch().unwrap());
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 1);
        assert_eq!(*f.events.tokens.lock().unwrap(), ["hvs.events"]);
        assert_eq!(audited(&url).iter().filter(|e| e.action == "secret.vault_events" && e.details["state"] == "subscribed").count(), 1);
        assert_eq!(get(&x, "EVENTS_ROTATED_TOKEN").as_deref(), Some("events-rotated-1"));
        assert_eq!(get(&x, "EVENTS_DELETED_TOKEN").as_deref(), Some("events-deleted-1"));
        let startup = external::Startup(Arc::clone(&x));
        assert_eq!(startup.get("EVENTS_STARTUP_TOKEN").unwrap().unwrap().expose(), "events-startup-1");

        // Rotated: the cache (an hour) holds the old value until Vault says it changed.
        put(&f, "bots/EVENTS_ROTATED_TOKEN", "events-rotated-2");
        assert_eq!(get(&x, "EVENTS_ROTATED_TOKEN").as_deref(), Some("events-rotated-1"));
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_ROTATED_TOKEN"));
        wait_for(|| get(&x, "EVENTS_ROTATED_TOKEN").as_deref() == Some("events-rotated-2"));
        // Audited once the folder is listed again too.
        wait_for(|| audited("EVENTS_ROTATED_TOKEN").iter().any(|e| e.action == "secret.cache_refreshed"));
        assert!(f.events.indexes.lock().unwrap().contains(&"djE6c3RhbmQtaW4=".to_string()), "read at the event's index");
        assert!(f.events.list_indexes.lock().unwrap().contains(&"djE6c3RhbmQtaW4=".to_string()), "and its folder listed at it");

        // A new name shows in the folder at once, though its list was cached for an hour.
        assert!(!x.names().unwrap().contains(&"EVENTS_ADDED_TOKEN".to_string()));
        put(&f, "bots/EVENTS_ADDED_TOKEN", "events-added-1");
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_ADDED_TOKEN"));
        wait_for(|| x.names().unwrap().contains(&"EVENTS_ADDED_TOKEN".to_string()));
        assert_eq!(redact::text("events-rotated-2"), redact::MARK);
        let refreshed = audited("EVENTS_ROTATED_TOKEN").into_iter().find(|e| e.action == "secret.cache_refreshed").expect("audited");
        assert_eq!((refreshed.details["trigger"].as_str(), refreshed.details["event"].as_str()), (Some("vault-event"), Some("kv-v2/data-write")));
        assert_eq!(refreshed.details["entries"][0]["result"], "changed");
        assert!(!refreshed.details.to_string().contains("events-rotated"), "never a value");

        // Deleted, and one botd's startup settings read, which needs a restart.
        f.kv.lock().unwrap().remove("superbot/bots/EVENTS_DELETED_TOKEN");
        f.events.emit(&event("metadata-delete", "metadata", "superbot/bots/EVENTS_DELETED_TOKEN"));
        put(&f, "bots/EVENTS_STARTUP_TOKEN", "events-startup-2");
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_STARTUP_TOKEN"));
        wait_for(|| get(&x, "EVENTS_DELETED_TOKEN").is_none());
        wait_for(|| audited("EVENTS_STARTUP_TOKEN").iter().any(|e| e.action == "secret.cache_refreshed"));
        let restart = audited("EVENTS_STARTUP_TOKEN").into_iter().find(|e| e.action == "secret.cache_refreshed").unwrap();
        assert_eq!(restart.details["restart"], json!(["EVENTS_STARTUP_TOKEN"]));
        let removed = audited("EVENTS_DELETED_TOKEN").into_iter().find(|e| e.action == "secret.cache_refreshed").unwrap();
        assert_eq!(removed.details["entries"][0]["result"], "removed");

        // Names botd doesn't read there aren't read at all.
        let reads = f.reads.load(Ordering::SeqCst);
        for path in ["other/bots/EVENTS_ROTATED_TOKEN", "superbot/users/ua1/EVENTS_ROTATED_TOKEN", "superbot/bots/LINODE_TOKEN"] {
            f.events.emit(&event("data-write", "data", path));
        }
        put(&f, "bots/EVENTS_ROTATED_TOKEN", "events-rotated-3");
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_ROTATED_TOKEN"));
        wait_for(|| get(&x, "EVENTS_ROTATED_TOKEN").as_deref() == Some("events-rotated-3"));
        assert_eq!(f.reads.load(Ordering::SeqCst), reads + 1, "only the last event is for a name botd reads");
        wait_for(|| f.events.pongs.load(Ordering::SeqCst) > 0);
        for v in ["events-rotated-1", "events-rotated-2", "events-rotated-3", "events-startup-1", "events-startup-2", "events-deleted-1", "events-added-1"] {
            redact::forget(v);
        }
    }

    #[test]
    fn after_a_gap_every_cached_answer_is_read_again() {
        let (url, f) = token_stand_in("hvs.gap");
        put(&f, "bots/EVENTS_GAP_TOKEN", "events-gap-1");
        let x = store(&url, &[("VAULT_TOKEN", "hvs.gap")], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        assert_eq!(get(&x, "EVENTS_GAP_TOKEN").as_deref(), Some("events-gap-1"));

        // Vault closes the stream; a change made meanwhile has no event, but is read again.
        f.events.status.store(503, Ordering::SeqCst);
        f.events.close_all();
        put(&f, "bots/EVENTS_GAP_TOKEN", "events-gap-2");
        wait_for(|| audited(&url).iter().any(|e| e.details["state"] == "lost"));
        std::thread::sleep(BACKOFF_START * 4);
        assert_eq!(get(&x, "EVENTS_GAP_TOKEN").as_deref(), Some("events-gap-1"), "not yet: botd couldn't subscribe again");
        f.events.status.store(0, Ordering::SeqCst);
        wait_for(|| get(&x, "EVENTS_GAP_TOKEN").as_deref() == Some("events-gap-2"));
        let lost = audited(&url).into_iter().find(|e| e.details["state"] == "lost").unwrap();
        assert_eq!((lost.outcome, lost.details["error"].as_str()), (Outcome::Failure, Some("Vault closed the stream")));
        assert!(audited(&url).iter().any(|e| e.details["state"] == "resumed"));
        wait_for(|| audited("vault").iter().any(|e| e.action == "secret.cache_refreshed" && e.details["trigger"] == "vault-events-resumed"));

        // A connection dropped without a word, then a server that stops answering pings.
        f.events.cut();
        wait_for(|| f.events.subscriptions.load(Ordering::SeqCst) >= 3);
        let pongs = f.events.pongs.load(Ordering::SeqCst);
        wait_for(|| f.events.pongs.load(Ordering::SeqCst) > pongs);
        f.events.silent.store(true, Ordering::SeqCst);
        wait_for(|| audited(&url).iter().any(|e| e.details["error"] == "Vault stopped answering pings"));
        f.events.silent.store(false, Ordering::SeqCst);
        wait_for(|| f.events.open() == 1 && f.events.subscriptions.load(Ordering::SeqCst) >= 4);
        put(&f, "bots/EVENTS_GAP_TOKEN", "events-gap-3");
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_GAP_TOKEN"));
        wait_for(|| get(&x, "EVENTS_GAP_TOKEN").as_deref() == Some("events-gap-3"));
        for v in ["events-gap-1", "events-gap-2", "events-gap-3"] {
            redact::forget(v);
        }
    }

    #[test]
    fn each_new_token_gets_a_new_subscription_before_the_old_one_closes() {
        let (url, f) = stand_in();
        // Each AppRole login lasts a second, so botd logs in again within one.
        f.lease.store(1, Ordering::SeqCst);
        put(&f, "bots/EVENTS_MOVED_TOKEN", "events-moved-1");
        let x = store(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1")], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        wait_for(|| f.events.subscriptions.load(Ordering::SeqCst) >= 3 && f.events.closes.load(Ordering::SeqCst) >= 2);
        let tokens = f.events.tokens.lock().unwrap().clone();
        assert!(tokens.windows(2).all(|w| w[0] != w[1]), "each with a new login: {tokens:?}");
        assert!(f.events.open() <= 2, "the old one closed once the new one was open");
        assert!(!audited(&url).iter().any(|e| e.details["state"] == "lost"), "no gap, so nothing to read again");
        assert_eq!(get(&x, "EVENTS_MOVED_TOKEN").as_deref(), Some("events-moved-1"));
        put(&f, "bots/EVENTS_MOVED_TOKEN", "events-moved-2");
        f.events.emit(&event("data-write", "data", "superbot/bots/EVENTS_MOVED_TOKEN"));
        wait_for(|| get(&x, "EVENTS_MOVED_TOKEN").as_deref() == Some("events-moved-2"));
        redact::forget("events-moved-1");
        redact::forget("events-moved-2");
    }

    /// botd read every cached answer again, `name` among them, as after a gap.
    fn caught_up(name: &str) -> bool {
        audited("vault").iter().any(|e| {
            e.action == "secret.cache_refreshed" && e.details["trigger"] == "vault-events-resumed" && e.details["entries"].as_array().is_some_and(|a| a.iter().any(|x| x["name"] == name))
        })
    }

    #[test]
    fn a_new_token_in_the_file_gets_a_new_subscription_and_a_catch_up() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().extend(["hvs.agent-1".to_string(), "hvs.agent-2".to_string()]);
        let file = super::super::tests::token_file("vault-events-agent", "hvs.agent-1\n");
        put(&f, "bots/EVENTS_AGENT_TOKEN", "events-agent-1");
        let x = store(&url, &[("VAULT_TOKEN_FILE", file.to_str().unwrap())], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        assert_eq!(get(&x, "EVENTS_AGENT_TOKEN").as_deref(), Some("events-agent-1"));

        // Vault Agent writes a new token; the old one may already be revoked, its stream quiet.
        put(&f, "bots/EVENTS_AGENT_TOKEN", "events-agent-2");
        std::fs::write(&file, "hvs.agent-2\n").unwrap();
        wait_for(|| f.events.subscriptions.load(Ordering::SeqCst) >= 2 && f.events.closes.load(Ordering::SeqCst) >= 1);
        assert_eq!(*f.events.tokens.lock().unwrap(), ["hvs.agent-1", "hvs.agent-2"]);
        wait_for(|| caught_up("EVENTS_AGENT_TOKEN"));
        assert_eq!(get(&x, "EVENTS_AGENT_TOKEN").as_deref(), Some("events-agent-2"), "a change with no event, read again");
        assert!(!audited(&url).iter().any(|e| e.details["state"] == "lost"));
        std::thread::sleep(PING * 3);
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 2, "once per new token");
        redact::forget("events-agent-1");
        redact::forget("events-agent-2");
    }

    #[test]
    fn a_renewal_that_comes_late_reads_everything_again() {
        let (url, f) = stand_in();
        f.lease.store(1, Ordering::SeqCst);
        put(&f, "bots/EVENTS_LATE_TOKEN", "events-late-1");
        let x = store(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1")], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        assert_eq!(get(&x, "EVENTS_LATE_TOKEN").as_deref(), Some("events-late-1"));

        // Vault won't take a new subscription when it is due: the old one is kept past its token.
        f.events.status.store(503, Ordering::SeqCst);
        put(&f, "bots/EVENTS_LATE_TOKEN", "events-late-2");
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 1);
        assert_eq!(get(&x, "EVENTS_LATE_TOKEN").as_deref(), Some("events-late-1"));
        f.events.status.store(0, Ordering::SeqCst);
        wait_for(|| caught_up("EVENTS_LATE_TOKEN"));
        assert_eq!(get(&x, "EVENTS_LATE_TOKEN").as_deref(), Some("events-late-2"));
        assert!(!audited(&url).iter().any(|e| e.details["state"] == "lost"), "the old stream never broke");
        redact::forget("events-late-1");
        redact::forget("events-late-2");
    }

    #[test]
    fn a_new_subscription_that_opens_after_the_old_token_ran_out_reads_everything_again() {
        let (url, f) = stand_in();
        // A 6 s login: botd subscribes again at 4 s, well past MIN_RESUBSCRIBE, so not late.
        f.lease.store(6, Ordering::SeqCst);
        put(&f, "bots/EVENTS_EXPIRED_TOKEN", "events-expired-1");
        let x = store(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1")], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        assert_eq!(get(&x, "EVENTS_EXPIRED_TOKEN").as_deref(), Some("events-expired-1"));

        // Vault is slow to take the new subscription: it opens at 6.5 s, after the old token
        // ran out, though the new token (renewed at 8 s) isn't late.
        f.events.delay_ms.store(2500, Ordering::SeqCst);
        put(&f, "bots/EVENTS_EXPIRED_TOKEN", "events-expired-2");
        let until = Instant::now() + Duration::from_secs(15);
        while f.events.subscriptions.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        f.events.delay_ms.store(0, Ordering::SeqCst);
        wait_for(|| caught_up("EVENTS_EXPIRED_TOKEN"));
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 2, "with the subscription that opened late, not a later one");
        assert_eq!(get(&x, "EVENTS_EXPIRED_TOKEN").as_deref(), Some("events-expired-2"), "a change with no event, read again");
        assert!(!audited(&url).iter().any(|e| e.details["state"] == "lost"), "the old stream never broke");
        redact::forget("events-expired-1");
        redact::forget("events-expired-2");
    }

    #[test]
    fn an_old_stream_that_ends_while_its_replacement_opens_reads_everything_again() {
        let (url, f) = stand_in();
        // A 6 s login: botd subscribes again at 4 s, and the new stream opens at 5 s, before
        // the old token runs out.
        f.lease.store(6, Ordering::SeqCst);
        put(&f, "bots/EVENTS_HANDOFF_TOKEN", "events-handoff-1");
        let x = store(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1")], "3600");
        x.check().unwrap();
        x.watch().unwrap();
        assert_eq!(get(&x, "EVENTS_HANDOFF_TOKEN").as_deref(), Some("events-handoff-1"));

        f.events.delay_ms.store(1000, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(15);
        while f.events.asked.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Vault closes the old stream while the new one is opening; the change between has
        // no event on either.
        f.events.close_all();
        put(&f, "bots/EVENTS_HANDOFF_TOKEN", "events-handoff-2");
        while f.events.subscriptions.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        f.events.delay_ms.store(0, Ordering::SeqCst);
        wait_for(|| caught_up("EVENTS_HANDOFF_TOKEN"));
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 2, "with the new subscription, not a later one");
        assert_eq!(get(&x, "EVENTS_HANDOFF_TOKEN").as_deref(), Some("events-handoff-2"), "a change with no event, read again");
        redact::forget("events-handoff-1");
        redact::forget("events-handoff-2");
    }

    #[test]
    fn botd_wont_start_without_the_events_it_was_asked_to_follow() {
        let (url, f) = token_stand_in("hvs.refused");
        let x = store(&url, &[("VAULT_TOKEN", "hvs.refused")], "60");
        for (status, want) in [(404, "change events need Vault Enterprise 1.16 or later"), (403, "botd's policy needs read on sys/events/subscribe/kv-v2/*"), (307, "point VAULT_ADDR at the active node"), (500, "Vault answered 500")] {
            f.events.status.store(status, Ordering::SeqCst);
            let e = x.watch().unwrap_err().to_string();
            assert!(e.contains(want), "{status}: {e}");
        }
        assert_eq!(f.events.subscriptions.load(Ordering::SeqCst), 0);

        // Vault refuses the token once: a new one (read again from its file) is used.
        let (url, f) = stand_in();
        let file = super::super::tests::token_file("vault-events-token", "hvs.old\n");
        f.tokens.lock().unwrap().push("hvs.new".into());
        let x = store(&url, &[("VAULT_TOKEN_FILE", file.to_str().unwrap())], "60");
        std::fs::write(&file, "hvs.new\n").unwrap();
        assert!(x.watch().unwrap());
        assert_eq!(*f.events.tokens.lock().unwrap(), ["hvs.new"]);

        // Off by default, and only for Vault.
        let (url, _f) = token_stand_in("hvs.off");
        let pairs = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_TOKEN", "hvs.off")];
        let off = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        assert!(!off.watch().unwrap());
        assert!(!off.describe().contains("change events"));
        let bad = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_TOKEN", "hvs.off"), ("VAULT_EVENTS", "yes")];
        let e = external::from_env(&settings(&bad), &EnvStore::fixed(&bad)).err().unwrap();
        assert!(e.contains("VAULT_EVENTS must be 1"));
        assert_eq!(external::unused_settings(&settings(&[("VAULT_EVENTS", "1")]), "aws"), ["VAULT_EVENTS"]);
    }
}
