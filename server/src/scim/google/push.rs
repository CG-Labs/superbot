//! Push from Google Workspace (ADR 0216). The Directory API's watch channels tell botd
//! within seconds that a user was added, changed (suspended, archived, renamed), deleted
//! or undeleted, and a pass starts at once instead of at the next interval.
//!
//! A notification is a hint, never state: botd reads nothing from it but which channel
//! sent it, and starts the same full pass as the schedule, with its fail-closed reads and
//! removal guards. A forged or replayed one can do no more than start a pass early, and
//! the schedule goes on if push stops.
//!
//! Group membership has no watch in the Directory API. With GOOGLE_DIRECTORY_PUSH_GROUPS
//! (ADR 0244), botd also watches the Reports API's admin activity for members added to
//! or removed from a group, and groups deleted, with a token of its own that carries only
//! the audit read-only scope. Those channels are made, renewed and fail apart from the
//! user ones, so a missing delegation of that scope never stops user push.
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
/// Admin activity that changes who is in a group, made in the Admin console or through
/// the Directory API (a directory sync tool, an HR system), one channel each. Google
/// logs these within a couple of minutes.
pub const GROUP_EVENTS: [&str; 3] = ["ADD_GROUP_MEMBER", "REMOVE_GROUP_MEMBER", "DELETE_GROUP"];
/// Asked for only by the group channels' own token, never by a pass.
pub const REPORTS_SCOPE: &str = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
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
const GROUPS_PREFIX: &str = "superbot-g-";
const KEY_PURPOSE: &str = "scim/google-push-channel";
/// Leftover channels being stopped at once.
const MAX_STOPPING: usize = 64;

/// What a set of channels watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    /// Users, through the Directory API (ADR 0216).
    Users,
    /// Group membership, through the Reports API's admin activity (ADR 0244).
    Groups,
}

impl Watch {
    const ALL: [Watch; 2] = [Watch::Users, Watch::Groups];

    fn events(self) -> &'static [&'static str] {
        match self {
            Watch::Users => &EVENTS,
            Watch::Groups => &GROUP_EVENTS,
        }
    }

    /// A channel's id says which API made it, so a leftover is stopped where it lives.
    fn prefix(self) -> &'static str {
        match self {
            Watch::Users => PREFIX,
            Watch::Groups => GROUPS_PREFIX,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Watch::Users => "users",
            Watch::Groups => "groups",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Watch::Users => "user changes",
            Watch::Groups => "group membership changes",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

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

/// GOOGLE_DIRECTORY_PUSH_GROUPS: whether group membership changes are watched too.
/// `names_groups`: the sync reads at least one group, so a change to one can matter.
pub fn groups(var: &dyn Fn(&str) -> String, address: Option<&str>, names_groups: bool) -> Result<bool, String> {
    if !on_off("GOOGLE_DIRECTORY_PUSH_GROUPS", &var("GOOGLE_DIRECTORY_PUSH_GROUPS"))? {
        return Ok(false);
    }
    if address.is_none() {
        return Err("GOOGLE_DIRECTORY_PUSH_GROUPS=on needs GOOGLE_DIRECTORY_PUSH=on: group changes come to the same address.".into());
    }
    if !names_groups {
        return Err("GOOGLE_DIRECTORY_PUSH_GROUPS=on needs a group in GOOGLE_DIRECTORY_GROUPS, GOOGLE_DIRECTORY_TEAM_GROUPS or GOOGLE_DIRECTORY_ROLE_GROUPS: the sync reads no group, and moves between organizational units are pushed as user changes already.".into());
    }
    Ok(true)
}

pub(crate) fn channel_token(id: &str) -> String {
    let key = crate::secrets::sealed::cipher().derive(KEY_PURPOSE);
    let tag = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key[..]), id.as_bytes());
    crate::audit_line::hex(tag.as_ref())
}

/// What a notification's channel watches, or why it isn't one botd made.
fn check(id: &str, token: &str) -> Result<Watch, &'static str> {
    if id.is_empty() || token.is_empty() {
        return Err("missing");
    }
    let shaped = |w: &Watch| id.strip_prefix(w.prefix()).is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_hexdigit()));
    let Some(watch) = Watch::ALL.into_iter().filter(|_| id.len() <= MAX_ID).find(shaped) else { return Err("unknown_channel") };
    aws_lc_rs::constant_time::verify_slices_are_equal(channel_token(id).as_bytes(), token.as_bytes()).map_err(|_| "bad_token")?;
    Ok(watch)
}

#[derive(Clone, Debug)]
struct Channel {
    id: String,
    resource_id: String,
    watch: Watch,
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
    /// By `Watch::index`: each set is renewed, and fails, on its own.
    renewed_at: [Option<i64>; 2],
    failure: [Option<Value>; 2],
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
    /// A set's channels that haven't ended: a failed renewal keeps old ones past their end.
    fn live(&self, watch: Watch, now: i64) -> usize {
        self.channels.iter().filter(|c| c.watch == watch && c.expires_at.is_none_or(|e| e > now)).count()
    }
}

/// Push's channels and what they've delivered.
pub struct Push {
    /// None: push is off, and channels left from when it was on are stopped.
    address: Option<String>,
    /// Group membership is watched too (GOOGLE_DIRECTORY_PUSH_GROUPS).
    groups: bool,
    nudge: tokio::sync::Notify,
    state: std::sync::Mutex<State>,
}

impl Push {
    pub fn new(address: Option<String>, groups: bool) -> Push {
        let groups = groups && address.is_some();
        Push { address, groups, nudge: tokio::sync::Notify::new(), state: Default::default() }
    }

    fn watches(&self, watch: Watch) -> bool {
        self.address.is_some() && (watch == Watch::Users || self.groups)
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
        s.pending.insert(EVENTS.into_iter().chain(GROUP_EVENTS).find(|e| *e == change).unwrap_or("other"));
        drop(s);
        self.nudge.notify_one();
    }

    /// The user channels' state at the top, as before group push; the group channels'
    /// under `groups`.
    pub fn status(&self) -> Value {
        let Some(address) = &self.address else { return json!({ "enabled": false }) };
        let s = self.state();
        let now = crate::db::now();
        let (users, groups) = (Watch::Users.index(), Watch::Groups.index());
        json!({
            "enabled": true,
            "address": address,
            "watching": s.live(Watch::Users, now) > 0,
            "channels": s.channels.iter().map(|c| json!({ "watch": c.watch.name(), "event": c.event, "expiresAt": c.expires_at })).collect::<Vec<_>>(),
            "renewedAt": s.renewed_at[users],
            "failure": s.failure[users],
            "groups": if self.groups {
                json!({ "enabled": true, "watching": s.live(Watch::Groups, now) > 0, "renewedAt": s.renewed_at[groups], "failure": s.failure[groups] })
            } else {
                json!({ "enabled": false })
            },
            "notifications": s.notifications,
            "lastNotificationAt": s.last_notification,
            "refused": s.refused,
            "leftoversStopped": s.stopped,
        })
    }
}

// Google's side: watch and stop.

async fn post(d: &Directory, token: &str, url: url::Url, body: &Value, what: &str) -> Result<Vec<u8>, Failure> {
    let res = d.http.post(url).bearer_auth(token).json(body).send().await.map_err(|e| fail("unreachable", format!("Google's Admin SDK API couldn't be reached for {what}: {}", e.without_url())))?;
    let status = res.status();
    let bytes = read(res, what).await?;
    if !status.is_success() {
        return Err(refused(status, &bytes, what));
    }
    Ok(bytes)
}

/// The Admin SDK path under GOOGLE_DIRECTORY_API_URL.
fn api_url(d: &Directory, segments: &[&str], query: &[(&str, &str)]) -> Result<url::Url, Failure> {
    let mut url = url::Url::parse(&d.settings.api).map_err(|e| fail("google_error", e.to_string()))?;
    url.path_segments_mut().map_err(|_| fail("google_error", "GOOGLE_DIRECTORY_API_URL can't have a path"))?.pop_if_empty().extend(segments);
    url.query_pairs_mut().extend_pairs(query);
    Ok(url)
}

/// Where a set's channels are made: users.watch, or activities.watch on everyone's
/// admin activity, one event name each.
fn watch_url(d: &Directory, watch: Watch, event: &str) -> Result<url::Url, Failure> {
    let customer = d.settings.customer.as_str();
    match watch {
        Watch::Users => d.url(&["users", "watch"], &[("customer", customer), ("event", event)]),
        Watch::Groups => {
            let mut query = vec![("eventName", event)];
            // The Reports API takes no `my_customer`: it is the admin's own customer.
            if customer != "my_customer" {
                query.push(("customerId", customer));
            }
            api_url(d, &["admin", "reports", "v1", "activity", "users", "all", "applications", "admin", "watch"], &query)
        }
    }
}

/// The token a set's calls use: a pass's for users, one with only the audit read-only
/// scope for groups, so a pass never holds audit access.
async fn token_for(d: &Directory, watch: Watch) -> Result<Zeroizing<String>, Failure> {
    match watch {
        Watch::Users => d.token().await,
        Watch::Groups => d.token_with(REPORTS_SCOPE).await,
    }
}

async fn watch(d: &Directory, token: &str, address: &str, watch: Watch, event: &'static str) -> Result<Channel, Failure> {
    let id = format!("{}{}", watch.prefix(), crate::random_hex(16));
    d.push.state().made.insert(id.clone());
    let what = match watch {
        Watch::Users => format!("users' {event} events"),
        Watch::Groups => format!("admin activity {event}"),
    };
    let body = json!({ "id": id, "type": "web_hook", "address": address, "token": channel_token(&id), "params": { "ttl": TTL.as_secs().to_string() } });
    let url = watch_url(d, watch, event)?;
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
        Ok(Channel { id: id.clone(), resource_id, watch, event, expires_at })
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

async fn stop(d: &Directory, token: &str, watch: Watch, id: &str, resource_id: &str) -> Result<(), Failure> {
    // channels.stop is under directory_v1 and reports_v1, not directory/v1 like the rest.
    let api = match watch {
        Watch::Users => "directory_v1",
        Watch::Groups => "reports_v1",
    };
    let url = api_url(d, &["admin", api, "channels", "stop"], &[])?;
    d.push.state().made.remove(id);
    match post(d, token, url, &json!({ "id": id, "resourceId": resource_id }), &format!("the channel {id}")).await {
        Err(f) if f.reason == "not_found" => Ok(()),
        r => r.map(|_| ()),
    }
}

async fn stop_all(d: &Directory, token: &str, channels: &[Channel]) {
    for c in channels {
        if let Err(f) = stop(d, token, c.watch, &c.id, &c.resource_id).await {
            crate::obs::log::log_warn!("Google Workspace push: couldn't stop the channel {} ({}); it ends by itself.", c.id, f.detail);
        }
    }
}

/// When to make the next channels, from when the earliest one ends.
fn renew_wait(ends: Option<i64>, now: i64) -> Duration {
    let left = ends.map(|e| Duration::from_millis(e.saturating_sub(now).max(0) as u64)).unwrap_or(TTL);
    left.saturating_sub(RENEW_BEFORE).max(left * 3 / 4).max(MIN_RENEW)
}

/// Makes a channel for each of a set's events, then stops the ones they replace. A
/// failure keeps the old ones (they still work until they end) and is audited once
/// until the set's channels are made again; the other set is untouched. Returns how
/// long until the set's next renewal.
pub async fn renew(a: &Arc<Auth>, d: &Directory, set: Watch) -> Duration {
    let Some(address) = d.push.address.as_deref().filter(|_| d.push.watches(set)) else { return TTL };
    let Some(app) = a.app.clone() else { return WATCH_RETRY };
    let i = set.index();
    let made = async {
        let token = token_for(d, set).await?;
        let mut made = Vec::new();
        for event in set.events() {
            match watch(d, &token, address, set, event).await {
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
                let (old, kept): (Vec<Channel>, Vec<Channel>) = std::mem::take(&mut st.channels).into_iter().partition(|c| c.watch == set);
                st.channels = kept;
                st.channels.extend(made);
                let first = st.renewed_at[i].is_none();
                st.renewed_at[i] = Some(now);
                (old, first, st.failure[i].take().is_some())
            };
            stop_all(d, &token, &old).await;
            if first || recovered {
                let details = json!({ "tenant": s.tenant, "address": address, "watch": set.name(), "events": set.events(), "expiresAt": ends, "recovered": recovered });
                app.db.record(&who.event("scim.google_push_watching").target("scim_tenant", &s.tenant).details(details));
                crate::obs::log::log_info!("Google Workspace push: watching {}, sent to {address}.", set.what());
            }
            renew_wait(ends, now)
        }
        Err(f) => {
            let (first, left, until) = {
                let mut st = d.push.state();
                let first = st.failure[i].is_none();
                st.failure[i] = Some(json!({ "reason": f.reason, "detail": f.detail, "at": now }));
                (first, st.live(set, now), st.channels.iter().filter(|c| c.watch == set).filter_map(|c| c.expires_at).filter(|e| *e > now).min())
            };
            if first {
                let details = json!({ "tenant": s.tenant, "address": address, "watch": set.name(), "reason": f.reason, "detail": f.detail, "channelsLeft": left, "channelsEnd": until });
                app.db.record(&who.event("scim.google_push_failed").target("scim_tenant", &s.tenant).outcome(Outcome::Failure).details(details));
            }
            crate::obs::log::log_warn!("Google Workspace push: couldn't watch {} ({}); the sync still runs every {} minutes.", set.what(), f.detail, s.interval.as_secs() / 60);
            WATCH_RETRY
        }
    }
}

/// Makes each set's channels once botd is serving, and new ones before they end.
pub fn start(a: Arc<Auth>, d: Arc<Directory>) {
    for set in Watch::ALL.into_iter().filter(|w| d.push.watches(*w)) {
        let (a, d) = (a.clone(), d.clone());
        tokio::spawn(async move {
            tokio::time::sleep(FIRST_WATCH).await;
            loop {
                let wait = renew(&a, &d, set).await;
                tokio::time::sleep(wait).await;
            }
        });
    }
}

/// Stops a channel botd made before a restart, or before push was turned off, once.
fn stop_leftover(d: &Arc<Directory>, watch: Watch, id: &str, resource_id: &str) {
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
        let done = match token_for(&d, watch).await {
            Ok(token) => stop(&d, &token, watch, &id, &resource_id).await,
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

/// `POST /scim/google/push`: Google's notification that a user, or a group's members,
/// changed. Answered at once; the pass runs after. 404 while the sync is off, 401 for a
/// channel botd didn't make (audited as `scim.google_push_refused`, throttled per
/// address).
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
    let watch = match check(id, token) {
        Ok(watch) => watch,
        Err(reason) => {
            d.push.state().refused += 1;
            let source = crate::request_source(&req, a.trust_forwarded);
            if let Some(missed) = a.logins.failure(&format!("{}|google_push", source.ip.as_deref().unwrap_or("")), crate::db::now()) {
                let actor = Actor { kind: ActorKind::System, id: Some("scim:google-push".into()), method: Some("google_push".into()), ..Default::default() };
                let details = json!({ "tenant": d.settings.tenant, "reason": reason, "unloggedSinceLast": missed });
                app.db.record(&Who { actor, source }.event("scim.google_push_refused").target("scim_tenant", &d.settings.tenant).outcome(Outcome::Failure).details(details));
            }
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let current = d.push.watches(watch) && {
        let st = d.push.state();
        st.made.contains(id) || st.channels.iter().any(|c| c.id == id)
    };
    if !current {
        stop_leftover(&d, watch, id, resource);
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
        assert_eq!(check(&id, &token), Ok(Watch::Users));
        assert_eq!(check(&id, &token[1..]), Err("bad_token"));
        assert_eq!(check(&format!("{PREFIX}{}", "cd".repeat(16)), &token), Err("bad_token"), "a token is for its own channel only");
        assert_eq!(check("someone-elses", &token), Err("unknown_channel"));
        assert_eq!(check(&format!("{PREFIX}{}", "a".repeat(64)), &token), Err("unknown_channel"));
        assert_eq!(check(&id, ""), Err("missing"));
        assert_eq!(check("", &token), Err("missing"));

        // A group channel's id says so, and its token is its own.
        let group = format!("{GROUPS_PREFIX}{}", "ab".repeat(16));
        assert_eq!(check(&group, &channel_token(&group)), Ok(Watch::Groups));
        assert_eq!(check(&group, &token), Err("bad_token"), "a user channel's token isn't a group channel's");
        assert_eq!(check(&format!("{GROUPS_PREFIX}{}", "a".repeat(64)), &channel_token(&group)), Err("unknown_channel"));
        assert_eq!(check("superbot-x-ab", &channel_token("superbot-x-ab")), Err("unknown_channel"));
        assert_eq!(check(GROUPS_PREFIX, &channel_token(GROUPS_PREFIX)), Err("unknown_channel"));
    }

    #[test]
    fn group_push_needs_user_push_and_a_group() {
        let push = Some("https://superbot.example.com/scim/google/push");
        assert_eq!(groups(&vars(&[]), push, true), Ok(false), "off by default");
        assert_eq!(groups(&vars(&[("GOOGLE_DIRECTORY_PUSH_GROUPS", "on")]), push, true), Ok(true));
        assert!(groups(&vars(&[("GOOGLE_DIRECTORY_PUSH_GROUPS", "on")]), None, true).unwrap_err().contains("GOOGLE_DIRECTORY_PUSH=on"));
        assert!(groups(&vars(&[("GOOGLE_DIRECTORY_PUSH_GROUPS", "on")]), push, false).unwrap_err().contains("GOOGLE_DIRECTORY_GROUPS"));
        assert!(groups(&vars(&[("GOOGLE_DIRECTORY_PUSH_GROUPS", "sometimes")]), push, true).is_err());
        assert_eq!(groups(&vars(&[("GOOGLE_DIRECTORY_PUSH_GROUPS", "off")]), None, false), Ok(false));
    }

    #[test]
    fn group_changes_are_named_in_the_pass_they_start() {
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()), true);
        p.note("REMOVE_GROUP_MEMBER");
        p.note("DELETE_GROUP");
        p.note("CHANGE_GROUP_NAME");
        p.note("update");
        assert_eq!(p.begin(), vec!["DELETE_GROUP", "REMOVE_GROUP_MEMBER", "other", "update"]);
        assert!(!Push::new(None, true).watches(Watch::Groups), "group push needs push");
        assert!(!Push::new(Some("https://superbot.example.com/scim/google/push".into()), false).watches(Watch::Groups));
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
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()), false);
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
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()), false);
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
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()), false);
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
        let p = Push::new(Some("https://superbot.example.com/scim/google/push".into()), true);
        let now = crate::db::now();
        let channel = |watch, expires_at| Channel { id: format!("{PREFIX}00"), resource_id: "r".into(), watch, event: "update", expires_at };
        p.state().channels = vec![channel(Watch::Users, Some(now - 1_000)), channel(Watch::Users, Some(now - 1))];
        assert_eq!(p.status()["watching"], false, "a failed renewal keeps ended channels");
        assert_eq!(p.state().live(Watch::Users, now), 0);
        p.state().channels.push(channel(Watch::Users, Some(now + 60_000)));
        assert_eq!(p.status()["watching"], true);
        p.state().channels = vec![channel(Watch::Users, None)];
        assert_eq!(p.status()["watching"], true, "no end given");

        // Each set is watching on its own.
        assert_eq!(p.status()["groups"], json!({ "enabled": true, "watching": false, "renewedAt": null, "failure": null }));
        p.state().channels = vec![channel(Watch::Groups, Some(now + 60_000))];
        assert_eq!((p.status()["watching"].as_bool(), p.status()["groups"]["watching"].as_bool()), (Some(false), Some(true)));
        let off = Push::new(Some("https://superbot.example.com/scim/google/push".into()), false);
        assert_eq!(off.status()["groups"], json!({ "enabled": false }));
    }
}
