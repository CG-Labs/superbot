//! Push from Google Workspace (ADR 0216). The Directory API's watch channels tell botd
//! within seconds that a user was added, changed (suspended, archived, renamed), deleted
//! or undeleted, and a pass starts at once instead of at the next interval.
//!
//! A notification is a hint, never state: botd reads nothing from it but which channel
//! sent it, and starts the same full pass as the schedule, with its fail-closed reads and
//! removal guards. A forged or replayed one can do no more than start a pass early, and
//! the schedule goes on if push stops. Group membership has no watch in the Directory
//! API, so someone taken out of a group still waits for the schedule.
//!
//! Each channel's token is an HMAC of its id under a key derived from the master key, so
//! botd knows the channels it made before a restart without storing them, and stops each
//! one it no longer uses when that channel next delivers. Off by default
//! (GOOGLE_DIRECTORY_PUSH).

use super::*;
use std::collections::BTreeSet;

/// Where Google sends notifications, outside `/api`: Google has no session.
pub const PATH: &str = "/scim/google/push";
/// Notifications have a small JSON body, which botd doesn't read.
pub const MAX_BODY: usize = 16 * 1024;
/// One channel each. `makeAdmin` changes nothing SuperBot keeps.
pub const EVENTS: [&str; 4] = ["add", "update", "delete", "undelete"];
/// Asked of Google, which may give less (2 hours by default, 2 days at most).
const TTL: Duration = Duration::from_secs(6 * 3600);
/// New channels are made this long before the old ones end, or at three quarters of
/// their life if that's sooner.
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 60);
const MIN_RENEW: Duration = Duration::from_secs(60);
const WATCH_RETRY: Duration = Duration::from_secs(5 * 60);
/// Google sends a `sync` message as soon as a channel is made, so botd must be serving.
const FIRST_WATCH: Duration = Duration::from_secs(10);
/// A burst of changes, like a bulk suspension, becomes one pass.
const SETTLE: Duration = Duration::from_secs(5);
/// Pushed passes start at least this far apart, so a stream of changes can't make
/// botd read the whole directory without pause.
const MIN_GAP: Duration = Duration::from_secs(30);
/// Google's limit on a channel id.
const MAX_ID: usize = 64;
const PREFIX: &str = "superbot-";
const KEY_PURPOSE: &str = "scim/google-push-channel";
/// Leftover channels being stopped at once.
const MAX_STOPPING: usize = 64;

/// GOOGLE_DIRECTORY_PUSH: off, or the address on PUBLIC_URL Google sends changes to.
pub fn address(var: &dyn Fn(&str) -> String) -> Result<Option<String>, String> {
    if !on_off("GOOGLE_DIRECTORY_PUSH", &var("GOOGLE_DIRECTORY_PUSH"))? {
        return Ok(None);
    }
    let base = crate::billing::public_url(var).map_err(|_| "GOOGLE_DIRECTORY_PUSH=on needs the address Google sends changes to: set PUBLIC_URL (like https://superbot.example.com)".to_string())?;
    if !base.starts_with("https://") {
        return Err(format!("GOOGLE_DIRECTORY_PUSH=on needs an https PUBLIC_URL with a certificate Google trusts, not {base}"));
    }
    Ok(Some(format!("{base}{PATH}")))
}

pub(crate) fn channel_token(id: &str) -> String {
    let key = crate::secrets::sealed::cipher().derive(KEY_PURPOSE);
    let tag = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key[..]), id.as_bytes());
    crate::audit_line::hex(tag.as_ref())
}

/// Why a notification isn't from a channel botd made, if it isn't.
fn check(id: &str, token: &str) -> Result<(), &'static str> {
    if id.is_empty() || token.is_empty() {
        return Err("missing");
    }
    let shaped = id.len() <= MAX_ID && id.strip_prefix(PREFIX).is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_hexdigit()));
    if !shaped {
        return Err("unknown_channel");
    }
    aws_lc_rs::constant_time::verify_slices_are_equal(channel_token(id).as_bytes(), token.as_bytes()).map_err(|_| "bad_token")
}

#[derive(Clone, Debug)]
struct Channel {
    id: String,
    resource_id: String,
    event: &'static str,
    /// Unix ms, if Google gave one.
    expires_at: Option<i64>,
}

#[derive(Default)]
struct State {
    channels: Vec<Channel>,
    /// Ids of channels this process asked for and hasn't stopped, so a `sync` message
    /// that beats the watch answer isn't taken for a leftover.
    made: HashSet<String>,
    renewed_at: Option<i64>,
    failure: Option<Value>,
    notifications: u64,
    last_notification: Option<i64>,
    /// What Google said changed since the last pass started.
    pending: BTreeSet<&'static str>,
    last_started: Option<tokio::time::Instant>,
    refused: u64,
    stopping: HashSet<String>,
    stopped: u64,
}

impl State {
    /// Channels that haven't ended: a failed renewal keeps old ones past their end.
    fn live(&self, now: i64) -> usize {
        self.channels.iter().filter(|c| c.expires_at.is_none_or(|e| e > now)).count()
    }
}

/// Push's channels and what they've delivered.
pub struct Push {
    /// None: push is off, and channels left from when it was on are stopped.
    address: Option<String>,
    nudge: tokio::sync::Notify,
    state: std::sync::Mutex<State>,
}

impl Push {
    pub fn new(address: Option<String>) -> Push {
        Push { address, nudge: tokio::sync::Notify::new(), state: Default::default() }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sleeps for `wait`, or until Google pushes a change and the burst settles; then
    /// says which. A change pushed while a pass ran ends the wait at once.
    pub async fn wait(&self, wait: Duration) -> Trigger {
        let deadline = tokio::time::Instant::now() + wait;
        'nudged: loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return Trigger::Schedule,
                _ = self.nudge.notified() => {}
            }
            // A nudge whose change a pass has since read (one pushed while the last burst
            // settled, say) starts nothing.
            let Some(gap) = self.pass_due() else { continue };
            let mut sleep = SETTLE.max(gap);
            // An admin's pass may begin meanwhile, which restarts the gap.
            loop {
                tokio::time::sleep(sleep).await;
                match self.pass_due() {
                    None => continue 'nudged,
                    Some(gap) if gap.is_zero() => return Trigger::Push,
                    Some(gap) => sleep = gap,
                }
            }
        }
    }

    /// How long until a pushed pass may start, if one is owed.
    fn pass_due(&self) -> Option<Duration> {
        let s = self.state();
        (!s.pending.is_empty()).then(|| s.last_started.map(|t| MIN_GAP.saturating_sub(t.elapsed())).unwrap_or_default())
    }

    /// Called as a pass starts reading: returns what Google said changed since the last
    /// one did, for its audit event, and starts the gap before the next pushed pass.
    pub fn begin(&self) -> Vec<&'static str> {
        let mut s = self.state();
        s.last_started = Some(tokio::time::Instant::now());
        std::mem::take(&mut s.pending).into_iter().collect()
    }

    /// Changes a pass took but didn't apply, owed another pass.
    pub fn give_back(&self, changes: &[&'static str]) {
        if changes.is_empty() {
            return;
        }
        self.state().pending.extend(changes);
        self.nudge.notify_one();
    }

    /// Lets a test's next pushed pass start without the gap after the passes it set up with.
    #[cfg(test)]
    pub(crate) fn forget_last_pass(&self) {
        self.state().last_started = None;
    }

    fn note(&self, change: &str) {
        let mut s = self.state();
        s.notifications += 1;
        s.last_notification = Some(crate::db::now());
        s.pending.insert(EVENTS.into_iter().find(|e| *e == change).unwrap_or("other"));
        drop(s);
        self.nudge.notify_one();
    }

    pub fn status(&self) -> Value {
        let Some(address) = &self.address else { return json!({ "enabled": false }) };
        let s = self.state();
        json!({
            "enabled": true,
            "address": address,
            "watching": s.live(crate::db::now()) > 0,
            "channels": s.channels.iter().map(|c| json!({ "event": c.event, "expiresAt": c.expires_at })).collect::<Vec<_>>(),
            "renewedAt": s.renewed_at,
            "failure": s.failure,
            "notifications": s.notifications,
            "lastNotificationAt": s.last_notification,
            "refused": s.refused,
            "leftoversStopped": s.stopped,
        })
    }
}

// Google's side: watch and stop.

async fn post(d: &Directory, token: &str, url: url::Url, body: &Value, what: &str) -> Result<Vec<u8>, Failure> {
    let res = d.http.post(url).bearer_auth(token).json(body).send().await.map_err(|e| fail("unreachable", format!("Google's Directory API couldn't be reached for {what}: {}", e.without_url())))?;
    let status = res.status();
    let bytes = read(res, what).await?;
    if !status.is_success() {
        return Err(refused(status, &bytes, what));
    }
    Ok(bytes)
}

async fn watch(d: &Directory, token: &str, address: &str, event: &'static str) -> Result<Channel, Failure> {
    let id = format!("{PREFIX}{}", crate::random_hex(16));
    d.push.state().made.insert(id.clone());
    let what = format!("users' {event} events");
    let body = json!({ "id": id, "type": "web_hook", "address": address, "token": channel_token(&id), "params": { "ttl": TTL.as_secs().to_string() } });
    let url = d.url(&["users", "watch"], &[("customer", d.settings.customer.as_str()), ("event", event)])?;
    let answer = async {
        let v: Value = serde_json::from_slice(&post(d, token, url, &body, &what).await?).map_err(|_| odd(&what))?;
        if v["kind"] != "api#channel" || v["id"] != id.as_str() {
            return Err(odd(&what));
        }
        let resource_id = v["resourceId"].as_str().filter(|r| resource_shaped(r)).ok_or_else(|| odd(&what))?.to_string();
        // int64 fields come as strings in Google's JSON.
        let expires_at = match &v["expiration"] {
            Value::Null => None,
            Value::String(s) => Some(s.parse::<i64>().map_err(|_| odd(&what))?),
            Value::Number(n) => Some(n.as_i64().ok_or_else(|| odd(&what))?),
            _ => return Err(odd(&what)),
        };
        Ok(Channel { id: id.clone(), resource_id, event, expires_at })
    }
    .await;
    if answer.is_err() {
        // If Google made it anyway, it's a leftover: stopped when it first delivers.
        d.push.state().made.remove(&id);
    }
    answer
}

fn resource_shaped(r: &str) -> bool {
    !r.is_empty() && r.len() <= 256 && r.bytes().all(|b| b.is_ascii_graphic())
}

async fn stop(d: &Directory, token: &str, id: &str, resource_id: &str) -> Result<(), Failure> {
    let mut url = url::Url::parse(&d.settings.api).map_err(|e| fail("google_error", e.to_string()))?;
    // channels.stop is under directory_v1, not directory/v1 like the rest.
    url.path_segments_mut().map_err(|_| fail("google_error", "GOOGLE_DIRECTORY_API_URL can't have a path"))?.pop_if_empty().extend(["admin", "directory_v1", "channels", "stop"]);
    d.push.state().made.remove(id);
    match post(d, token, url, &json!({ "id": id, "resourceId": resource_id }), &format!("the channel {id}")).await {
        Err(f) if f.reason == "not_found" => Ok(()),
        r => r.map(|_| ()),
    }
}

async fn stop_all(d: &Directory, token: &str, channels: &[Channel]) {
    for c in channels {
        if let Err(f) = stop(d, token, &c.id, &c.resource_id).await {
            crate::obs::log::log_warn!("Google Workspace push: couldn't stop the channel {} ({}); it ends by itself.", c.id, f.detail);
        }
    }
}

/// When to make the next channels, from when the earliest one ends.
fn renew_wait(ends: Option<i64>, now: i64) -> Duration {
    let left = ends.map(|e| Duration::from_millis(e.saturating_sub(now).max(0) as u64)).unwrap_or(TTL);
    left.saturating_sub(RENEW_BEFORE).max(left * 3 / 4).max(MIN_RENEW)
}

/// Makes a channel for each event, then stops the ones they replace. A failure keeps
/// the old ones (they still work until they end) and is audited once until channels
/// are made again. Returns how long until the next renewal.
pub async fn renew(a: &Arc<Auth>, d: &Directory) -> Duration {
    let Some(address) = d.push.address.as_deref() else { return TTL };
    let Some(app) = a.app.clone() else { return WATCH_RETRY };
    let made = async {
        let token = d.token().await?;
        let mut made = Vec::new();
        for event in EVENTS {
            match watch(d, &token, address, event).await {
                Ok(c) => made.push(c),
                Err(f) => {
                    stop_all(d, &token, &made).await;
                    return Err(f);
                }
            }
        }
        Ok((token, made))
    }
    .await;
    let s = &d.settings;
    let who = caller(a, s).who;
    let now = crate::db::now();
    match made {
        Ok((token, made)) => {
            let ends = made.iter().filter_map(|c| c.expires_at).min();
            let (old, first, recovered) = {
                let mut st = d.push.state();
                let old = std::mem::replace(&mut st.channels, made);
                let first = st.renewed_at.is_none();
                st.renewed_at = Some(now);
                (old, first, st.failure.take().is_some())
            };
            stop_all(d, &token, &old).await;
            if first || recovered {
                let details = json!({ "tenant": s.tenant, "address": address, "events": EVENTS, "expiresAt": ends, "recovered": recovered });
                app.db.record(&who.event("scim.google_push_watching").target("scim_tenant", &s.tenant).details(details));
                crate::obs::log::log_info!("Google Workspace push: watching user changes, sent to {address}.");
            }
            renew_wait(ends, now)
        }
        Err(f) => {
            let (first, left, until) = {
                let mut st = d.push.state();
                let first = st.failure.is_none();
                st.failure = Some(json!({ "reason": f.reason, "detail": f.detail, "at": now }));
                (first, st.live(now), st.channels.iter().filter_map(|c| c.expires_at).filter(|e| *e > now).min())
            };
            if first {
                let details = json!({ "tenant": s.tenant, "address": address, "reason": f.reason, "detail": f.detail, "channelsLeft": left, "channelsEnd": until });
                app.db.record(&who.event("scim.google_push_failed").target("scim_tenant", &s.tenant).outcome(Outcome::Failure).details(details));
            }
            crate::obs::log::log_warn!("Google Workspace push: couldn't watch user changes ({}); the sync still runs every {} minutes.", f.detail, s.interval.as_secs() / 60);
            WATCH_RETRY
        }
    }
}

/// Makes channels once botd is serving, and new ones before they end.
pub fn start(a: Arc<Auth>, d: Arc<Directory>) {
    if d.push.address.is_none() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_WATCH).await;
        loop {
            let wait = renew(&a, &d).await;
            tokio::time::sleep(wait).await;
        }
    });
}

/// Stops a channel botd made before a restart, or before push was turned off, once.
fn stop_leftover(d: &Arc<Directory>, id: &str, resource_id: &str) {
    if !resource_shaped(resource_id) {
        return;
    }
    {
        let mut st = d.push.state();
        if st.stopping.len() >= MAX_STOPPING || !st.stopping.insert(id.to_string()) {
            return;
        }
    }
    let (d, id, resource_id) = (d.clone(), id.to_string(), resource_id.to_string());
    tokio::spawn(async move {
        let done = match d.token().await {
            Ok(token) => stop(&d, &token, &id, &resource_id).await,
            Err(f) => Err(f),
        };
        let mut st = d.push.state();
        st.stopping.remove(&id);
        match done {
            Ok(()) => {
                st.stopped += 1;
                crate::obs::log::log_info!("Google Workspace push: stopped the channel {id}, left from before.");
            }
            Err(f) => crate::obs::log::log_warn!("Google Workspace push: couldn't stop the channel {id}, left from before ({}).", f.detail),
        }
    });
}

/// `POST /scim/google/push`: Google's notification that a user changed. Answered at
/// once; the pass runs after. 404 while the sync is off, 401 for a channel botd didn't
/// make (audited as `scim.google_push_refused`, throttled per address).
pub async fn receive(Extension(a): Extension<Arc<Auth>>, req: Request) -> Response {
    let Some(d) = a.scim.google.clone() else {
        return (StatusCode::NOT_FOUND, "The Google Workspace sync is off on this server.").into_response();
    };
    let Some(app) = a.app.clone() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let h = req.headers();
    let header = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").trim();
    let (id, token, change, resource) = (header("x-goog-channel-id"), header("x-goog-channel-token"), header("x-goog-resource-state"), header("x-goog-resource-id"));
    if let Err(reason) = check(id, token) {
        d.push.state().refused += 1;
        let source = crate::request_source(&req, a.trust_forwarded);
        if let Some(missed) = a.logins.failure(&format!("{}|google_push", source.ip.as_deref().unwrap_or("")), crate::db::now()) {
            let actor = Actor { kind: ActorKind::System, id: Some("scim:google-push".into()), method: Some("google_push".into()), ..Default::default() };
            let details = json!({ "tenant": d.settings.tenant, "reason": reason, "unloggedSinceLast": missed });
            app.db.record(&Who { actor, source }.event("scim.google_push_refused").target("scim_tenant", &d.settings.tenant).outcome(Outcome::Failure).details(details));
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let current = d.push.address.is_some() && {
        let st = d.push.state();
        st.made.contains(id) || st.channels.iter().any(|c| c.id == id)
    };
    if !current {
        stop_leftover(&d, id, resource);
    }
    if d.push.address.is_some() && change != "sync" {
        d.push.note(change);
    }
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned().unwrap_or_default()
    }

    #[test]
    fn push_is_off_unless_turned_on_and_needs_an_https_address() {
        assert_eq!(address(&vars(&[("PUBLIC_URL", "https://superbot.example.com")])), Ok(None));
        assert_eq!(address(&vars(&[("GOOGLE_DIRECTORY_PUSH", "on"), ("PUBLIC_URL", "https://superbot.example.com/")])), Ok(Some("https://superbot.example.com/scim/google/push".into())));
        assert_eq!(address(&vars(&[("GOOGLE_DIRECTORY_PUSH", "on"), ("ALLOWED_HOSTS", "bots.example.com")])), Ok(Some("https://bots.example.com/scim/google/push".into())));
        assert!(address(&vars(&[("GOOGLE_DIRECTORY_PUSH", "on")])).unwrap_err().contains("PUBLIC_URL"));
        assert!(address(&vars(&[("GOOGLE_DIRECTORY_PUSH", "on"), ("PUBLIC_URL", "http://localhost:8080")])).unwrap_err().contains("https"));
        assert!(address(&vars(&[("GOOGLE_DIRECTORY_PUSH", "maybe"), ("PUBLIC_URL", "https://superbot.example.com")])).is_err());
    }

    #[test]
    fn only_channels_botd_made_are_taken() {
        let id = format!("{PREFIX}{}", "ab".repeat(16));
        let token = channel_token(&id);
        assert_eq!(check(&id, &token), Ok(()));
        assert_eq!(check(&id, &token[1..]), Err("bad_token"));
        assert_eq!(check(&format!("{PREFIX}{}", "cd".repeat(16)), &token), Err("bad_token"), "a token is for its own channel only");
        assert_eq!(check("someone-elses", &token), Err("unknown_channel"));
        assert_eq!(check(&format!("{PREFIX}{}", "a".repeat(64)), &token), Err("unknown_channel"));
        assert_eq!(check(&id, ""), Err("missing"));
        assert_eq!(check("", &token), Err("missing"));
    }

    #[test]
    fn channels_are_renewed_before_they_end() {
        let h = |n: u64| Duration::from_secs(n * 3600);
        assert_eq!(renew_wait(None, 0), h(6) - RENEW_BEFORE);
        assert_eq!(renew_wait(Some(6 * 3_600_000), 0), h(6) - RENEW_BEFORE);
        assert_eq!(renew_wait(Some(2 * 3_600_000), 0), h(2) * 3 / 4, "Google's default of 2 hours");
        assert_eq!(renew_wait(Some(48 * 3_600_000), 0), h(48) - RENEW_BEFORE);
        assert_eq!(renew_wait(Some(30_000), 0), MIN_RENEW);
        assert_eq!(renew_wait(Some(0), 1_000), MIN_RENEW, "already ended");
    }

    #[tokio::test(start_paused = true)]
    async fn a_push_ends_the_wait_after_the_burst_settles_and_not_sooner_than_the_gap() {
        use tokio::time::Instant;
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()));
        let hour = Duration::from_secs(3600);
        assert!(matches!(p.wait(Duration::from_secs(1)).await, Trigger::Schedule));
        p.note("update");
        p.note("delete");
        p.note("makeAdmin");
        let t = Instant::now();
        assert!(matches!(p.wait(hour).await, Trigger::Push), "a change pushed before the wait began still counts");
        assert!((SETTLE..SETTLE + Duration::from_secs(1)).contains(&t.elapsed()), "{:?}", t.elapsed());
        assert_eq!(p.begin(), vec!["delete", "other", "update"]);
        assert!(p.begin().is_empty());

        // The nudges left by the burst start no second pass: that one read their changes.
        let t = Instant::now();
        assert!(matches!(p.wait(Duration::from_secs(60)).await, Trigger::Schedule));
        assert_eq!(t.elapsed(), Duration::from_secs(60));

        // A pass that started long ago (waiting for the lock, say) doesn't count: the gap
        // runs from when the last one began reading.
        tokio::time::sleep(MIN_GAP).await;
        let started = Instant::now();
        p.begin();
        p.note("add");
        assert!(matches!(p.wait(hour).await, Trigger::Push));
        assert!((MIN_GAP..MIN_GAP + Duration::from_secs(1)).contains(&started.elapsed()), "{:?}", started.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_a_failed_pass_took_gets_another() {
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()));
        p.note("update");
        let taken = p.begin();
        p.give_back(&[]);
        assert!(matches!(p.wait(Duration::from_secs(60)).await, Trigger::Schedule), "the note's nudge was spent by that pass");
        p.give_back(&taken);
        let t = tokio::time::Instant::now();
        assert!(matches!(p.wait(Duration::from_secs(3600)).await, Trigger::Push));
        assert!(t.elapsed() < MIN_GAP + SETTLE, "{:?}", t.elapsed());
        assert_eq!(p.begin(), vec!["update"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_admin_pass_while_a_burst_settles_restarts_the_gap() {
        use tokio::time::{sleep, Instant};
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()));
        p.note("add");
        let admin = async {
            sleep(SETTLE / 2).await;
            let began = Instant::now();
            assert_eq!(p.begin(), vec!["add"]);
            p.note("update");
            began
        };
        let (trigger, began) = tokio::join!(p.wait(Duration::from_secs(3600)), admin);
        assert!(matches!(trigger, Trigger::Push));
        assert!((MIN_GAP..MIN_GAP + Duration::from_secs(1)).contains(&began.elapsed()), "{:?}", began.elapsed());
        assert_eq!(p.begin(), vec!["update"]);
    }

    #[test]
    fn channels_past_their_end_arent_watching() {
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()));
        let now = crate::db::now();
        let channel = |expires_at| Channel { id: format!("{PREFIX}00"), resource_id: "r".into(), event: "update", expires_at };
        p.state().channels = vec![channel(Some(now - 1_000)), channel(Some(now - 1))];
        assert_eq!(p.status()["watching"], false, "a failed renewal keeps ended channels");
        assert_eq!(p.state().live(now), 0);
        p.state().channels.push(channel(Some(now + 60_000)));
        assert_eq!(p.status()["watching"], true);
        p.state().channels = vec![channel(None)];
        assert_eq!(p.status()["watching"], true, "no end given");
    }
}
