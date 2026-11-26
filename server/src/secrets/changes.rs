//! What following a store's change events shares across backends: Vault's WebSocket stream
//! (ADR 0306) and GCP Secret Manager's Pub/Sub subscription (ADR 0325). A backend's stream
//! hands each change to a `Tx`; a thread of its own takes them from the `Rx` and reads each
//! name again (`apply`), one after another, since reads and refreshes block. `Status` keeps
//! what the stream is doing for `botctl secrets backend` and `/metrics` (ADR 0318).

use super::external::{self, ExternalStore, Refresh, RefreshError, Scope};
use super::SecretStore;
use crate::audit::{Event, Outcome};
use crate::obs::log::{log_info, log_warn};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

/// What a stream tells the thread that applies it to the store.
#[derive(Debug, PartialEq)]
pub(crate) enum Note {
    /// `index`: the position of the change, for a read that can't be answered from before
    /// it (Vault's `vault_index`); None for stores without one.
    Changed { scope: Scope, name: String, event: String, index: Option<String> },
    /// Read everything cached again: subscribed again after a gap, or after a token that may
    /// have stopped events early, so events may have been missed; or too many changes waited.
    /// At the newest index of the changes it stands for, when it stands for some.
    Resumed(Option<String>),
}

/// Most names waiting to be read again; past it they make way for one read of everything.
pub(crate) const MAX_PENDING: usize = 1024;

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
pub(crate) struct Tx(Arc<Queue>);
/// The applying thread's end.
pub(crate) struct Rx(Arc<Queue>);

pub(crate) fn queue() -> (Tx, Rx) {
    let q = Arc::new(Queue::default());
    (Tx(Arc::clone(&q)), Rx(q))
}

impl Tx {
    pub(crate) fn send(&self, note: Note) {
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
    pub(crate) fn is_closed(&self) -> bool {
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
    pub(crate) fn recv(&self) -> Option<Note> {
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

/// What the stream is doing, for `botctl secrets backend` and `/metrics` (ADR 0318): counts
/// and botd's own reasons, never a path, a value or the store's text.
#[derive(Default)]
pub(crate) struct Status {
    /// The first subscription was made: botd follows the store's events.
    on: AtomicBool,
    following: AtomicBool,
    /// When `following` last changed, in ms since the epoch.
    since: AtomicI64,
    changes: AtomicU64,
    last_change: AtomicI64,
    lost: AtomicU64,
    catch_ups: AtomicU64,
    last_loss: Mutex<Option<String>>,
}

impl Status {
    pub(crate) fn following(&self, on: bool) {
        self.since.store(crate::db::now(), Ordering::SeqCst);
        self.following.store(on, Ordering::SeqCst);
        self.on.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_following(&self) -> bool {
        self.following.load(Ordering::SeqCst)
    }

    pub(crate) fn lost(&self, why: &str) {
        *self.last_loss.lock().unwrap_or_else(|e| e.into_inner()) = Some(why.to_string());
        self.lost.fetch_add(1, Ordering::SeqCst);
        self.following(false);
    }

    /// The stream is still open but may deliver nothing: the token it was made with ran out
    /// and no new subscription could be made. Not a loss: nothing broke, and no catch-up yet.
    pub(crate) fn stalled(&self, why: &str) {
        if self.following.load(Ordering::SeqCst) {
            *self.last_loss.lock().unwrap_or_else(|e| e.into_inner()) = Some(why.to_string());
            self.following(false);
        }
    }

    /// A new subscription replaced the one kept past its token.
    pub(crate) fn renewed(&self) {
        if !self.following.load(Ordering::SeqCst) {
            self.following(true);
        }
    }

    fn changed(&self) {
        self.last_change.store(crate::db::now(), Ordering::SeqCst);
        self.changes.fetch_add(1, Ordering::SeqCst);
    }

    fn caught_up(&self) {
        self.catch_ups.fetch_add(1, Ordering::SeqCst);
    }

    /// None until botd follows the events.
    pub(crate) fn view(&self) -> Option<external::WatchStatus> {
        self.on.load(Ordering::SeqCst).then(|| external::WatchStatus {
            following: self.following.load(Ordering::SeqCst),
            since_ms: self.since.load(Ordering::SeqCst),
            changes: self.changes.load(Ordering::SeqCst),
            last_change_ms: Some(self.last_change.load(Ordering::SeqCst)).filter(|t| *t > 0),
            lost: self.lost.load(Ordering::SeqCst),
            catch_ups: self.catch_ups.load(Ordering::SeqCst),
            last_loss: self.last_loss.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        })
    }
}

/// Whose change events these are, for log lines and the audit log.
pub(crate) struct Source {
    /// "Vault", "GCP Secret Manager".
    pub label: &'static str,
    /// The setting that turned them on, and its ADR: "VAULT_EVENTS, ADR 0306".
    pub setting: &'static str,
    /// `trigger` of `secret.cache_refreshed` for one change, and for the read of everything
    /// after a gap.
    pub change: &'static str,
    pub resumed: &'static str,
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
pub(crate) fn apply(store: Weak<ExternalStore>, rx: Rx, status: Arc<Status>, from: &Source) {
    let label = from.label;
    while let Some(note) = rx.recv() {
        let Some(store) = store.upgrade() else { return };
        match note {
            Note::Changed { scope, name, event, index } => {
                let Some(entry) = store.changed(&scope, &name, index.as_deref()) else { continue };
                status.changed();
                let folder = scope.folder('/');
                if entry.restart {
                    log_warn!("{label}: {name} in {folder} changed ({event}), but botd read it at startup and keeps the old value until it restarts (ADR 0291).");
                } else {
                    log_info!("{label}: {name} in {folder} changed ({event}); new runs get what {label} has now ({}).", from.setting);
                }
                let report = Refresh { store: store.kind(), names: Some(vec![name.clone()]), entries: vec![entry], folders: Vec::new() };
                audit_refresh(&report, ("secret", &name), from.change, Some(&event));
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
                            log_warn!("{label}: couldn't read the cache again after change events resumed ({e}); answers cached before end within SECRETS_CACHE_SECONDS ({}).", from.setting);
                            break None;
                        }
                    }
                };
                if let Some(r) = report {
                    status.caught_up();
                    if !r.restart().is_empty() {
                        log_warn!("{label}: {} changed while change events were down, but botd read them at startup and keeps the old values until it restarts (ADR 0291).", r.restart().join(", "));
                    }
                    audit_refresh(&r, ("secret_store", r.store), from.resumed, None);
                }
            }
        }
    }
}

/// Starts the thread that applies changes from `rx` to `store`.
pub(crate) fn start_applying(thread: &str, store: Weak<ExternalStore>, rx: Rx, status: Arc<Status>, from: &'static Source) -> std::io::Result<()> {
    std::thread::Builder::new().name(thread.into()).spawn(move || apply(store, rx, status, from)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn changes_without_an_index_are_read_without_one() {
        let changed = |name: &str| Note::Changed { scope: Scope::Bots, name: name.into(), event: "SECRET_VERSION_ADD".into(), index: None };
        let (tx, rx) = queue();
        tx.send(changed("A_TOKEN"));
        tx.send(changed("A_TOKEN"));
        tx.send(Note::Resumed(None));
        assert_eq!(rx.recv(), Some(Note::Resumed(None)));
        assert_eq!(rx.recv(), Some(changed("A_TOKEN")), "once");
    }
}
