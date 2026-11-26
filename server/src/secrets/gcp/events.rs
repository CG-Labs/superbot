//! GCP Secret Manager's change events (ADR 0325). Secret Manager publishes a Pub/Sub message to
//! the topics on a secret whenever the secret or one of its versions changes. With
//! `GCP_SECRET_MANAGER_EVENTS` naming a subscription to such a topic, botd pulls it with its
//! own token and reads a name in its folders again as soon as a message says it changed. The
//! cache time still bounds an answer's age when messages are late, and after pulls fail every
//! cached answer is read again (`ExternalStore::refresh`).
//!
//! - At startup botd checks that the subscription is there and that it may pull from it
//!   (`testIamPermissions`), and doesn't start otherwise.
//! - Pulls wait on Pub/Sub for messages; each one is acknowledged once its change is queued,
//!   whether or not it is for a name botd reads, so none comes back.
//! - Only `secretId` and `eventType` are used, never the message's data. A change to a name
//!   in botd's prefix and folders is read again where changes are applied
//!   (`changes::apply`); `SECRET_ROTATE` (a reminder, not a change) and `TOPIC_CONFIGURED`
//!   (a test message) are not.
//! - A pull or acknowledgement that fails is tried again, waiting 1 s and then twice as long
//!   each time up to a minute; once one works, everything cached is read again, as messages
//!   may have gone past the subscription's retention, or the subscription may be new.
//! - Audited: `secret.gcp_events` (`subscribed`, `lost`, `resumed`), and what each change or
//!   gap read again as `secret.cache_refreshed`, with `trigger` `gcp-event` or
//!   `gcp-events-resumed`, never a value. The state shows in `botctl secrets backend` and
//!   `/metrics` (`changes::Status`, ADR 0318).

use super::super::changes::{self, Note, Tx};
use super::super::external::{self, ExternalStore, Scope};
use super::super::{http, Error};
use super::{Config, Inner, SecretManager};
use crate::audit::{Event, Outcome};
use crate::obs::log::{log_info, log_warn};
use serde_json::{json, Value};
use std::sync::{Arc, Weak};
use std::time::Instant;
use zeroize::Zeroizing;

/// The permission a pull needs, which `roles/pubsub.subscriber` gives.
const CONSUME: &str = "pubsub.subscriptions.consume";
/// Most messages one pull takes.
const MAX_MESSAGES: usize = 100;
/// Longest `secretId` or ack id taken; Google's are well under it.
const MAX_ATTRIBUTE: usize = 1024;
/// Event types that announce no change to a value: a rotation reminder, and the test message
/// sent when a secret's topics are set.
const NOT_CHANGES: [&str; 2] = ["SECRET_ROTATE", "TOPIC_CONFIGURED"];

#[cfg(not(test))]
mod timing {
    use std::time::Duration;
    /// Longest botd waits on one pull. Pub/Sub holds a pull open for a while when it has no
    /// messages, so a pull that times out after connecting is an empty answer, not a failure.
    pub const PULL_WAIT: Duration = Duration::from_secs(60);
    /// Pulls that bring nothing are at least this far apart, should Pub/Sub answer them at once.
    pub const MIN_PULL: Duration = Duration::from_secs(1);
    pub const BACKOFF_START: Duration = Duration::from_secs(1);
    pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
}
#[cfg(test)]
mod timing {
    use std::time::Duration;
    pub const PULL_WAIT: Duration = Duration::from_millis(600);
    pub const MIN_PULL: Duration = Duration::from_millis(20);
    pub const BACKOFF_START: Duration = Duration::from_millis(50);
    pub const BACKOFF_MAX: Duration = Duration::from_millis(400);
}
use timing::*;

const SOURCE: changes::Source = changes::Source { label: "GCP Secret Manager", setting: "GCP_SECRET_MANAGER_EVENTS, ADR 0325", change: "gcp-event", resumed: "gcp-events-resumed" };

/// A change Secret Manager announced to one of botd's names.
#[derive(Debug, PartialEq)]
pub(crate) struct Seen {
    pub scope: Scope,
    pub name: String,
    pub event: String,
}

/// The change a message's `attributes` announce to a name botd reads, if any: a secret in
/// `cfg`'s prefix and location (or none), in a shared folder or, with `users`, a user's. The
/// project in `secretId` isn't checked, as Google may name it by number; the name is read from
/// botd's own project either way.
pub(crate) fn seen(attributes: &Value, cfg: &Config, users: bool) -> Option<Seen> {
    let event = attributes["eventType"].as_str().filter(|t| t.len() <= 64 && t.starts_with("SECRET_") && t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))?;
    if NOT_CHANGES.contains(&event) {
        return None;
    }
    let secret = attributes["secretId"].as_str().filter(|s| s.len() <= MAX_ATTRIBUTE)?;
    let (project, rest) = secret.strip_prefix("projects/")?.split_once('/')?;
    if project.is_empty() {
        return None;
    }
    let id = match (rest.strip_prefix("locations/"), cfg.location()) {
        (Some(r), Some(want)) => {
            let (location, r) = r.split_once('/')?;
            if location != want {
                return None;
            }
            r.strip_prefix("secrets/")?
        }
        (None, None) => rest.strip_prefix("secrets/")?,
        _ => return None,
    };
    let folders = id.strip_prefix(&format!("{}-", cfg.prefix))?;
    let (scope, name) = if let Some(n) = folders.strip_prefix("bots-") {
        (Scope::Bots, n)
    } else if let Some(n) = folders.strip_prefix("server-") {
        (Scope::Server, n)
    } else if let Some(r) = folders.strip_prefix("users-")
        && users
    {
        // User ids are only a-z and 0-9, so the first `-` ends one.
        let (user, n) = r.split_once('-')?;
        (Scope::user(user)?, n)
    } else {
        return None;
    };
    if !scope.holds(name) {
        return None;
    }
    Some(Seen { scope, name: name.to_string(), event: event.to_string() })
}

/// One pull's messages: each one's ack id, and its attributes.
struct Pulled {
    ack_ids: Vec<String>,
    attributes: Vec<Value>,
}

/// The messages in a pull's answer; an error, botd's own words, when it isn't one.
fn pulled(body: &[u8]) -> Result<Pulled, String> {
    let odd = || "Pub/Sub's answer to a pull isn't a list of messages".to_string();
    let v: Value = serde_json::from_slice(body).map_err(|_| odd())?;
    if !v.is_object() {
        return Err(odd());
    }
    let received = match &v["receivedMessages"] {
        Value::Null => return Ok(Pulled { ack_ids: Vec::new(), attributes: Vec::new() }),
        Value::Array(a) => a,
        _ => return Err(odd()),
    };
    let mut out = Pulled { ack_ids: Vec::new(), attributes: Vec::new() };
    for m in received {
        let ack = m["ackId"].as_str().filter(|a| !a.is_empty() && a.len() <= MAX_ATTRIBUTE && a.bytes().all(|b| b.is_ascii_graphic())).ok_or_else(odd)?;
        out.ack_ids.push(ack.to_string());
        out.attributes.push(m["message"]["attributes"].clone());
    }
    Ok(out)
}

/// What one call to Pub/Sub came to.
enum Call {
    Answered(reqwest::StatusCode, Zeroizing<Vec<u8>>),
    /// Connected, but no answer within the client's time: for a pull, no messages yet.
    TimedOut,
}

/// Why a call couldn't be made: botd's own words, safe for the stream's state and the audit
/// log, and the sign-in's own error, when that was it, for startup.
struct Failed {
    why: String,
    sign_in: Option<Error>,
}

impl Inner {
    fn subscription(&self) -> &str {
        self.cfg.events.as_deref().unwrap_or_default()
    }

    /// POSTs `body` to `<subscription>:<verb>` with botd's token; when Pub/Sub refuses the
    /// token, gets a new one and asks once more.
    async fn pubsub(&self, client: &reqwest::Client, verb: &str, body: &Value) -> Result<Call, Failed> {
        // `%` is allowed in a subscription id, and must reach Google as itself.
        let url = format!("{}/v1/{}:{verb}", self.cfg.pubsub_endpoint, self.subscription().replace('%', "%25"));
        for fresh in [false, true] {
            let token = self.token(fresh).await.map_err(|e| Failed { why: "botd couldn't sign in to Google".into(), sign_in: Some(e) })?;
            let res = match client.post(&url).bearer_auth(token.as_str()).json(body).send().await {
                Ok(r) => r,
                Err(e) if e.is_timeout() && !e.is_connect() => return Ok(Call::TimedOut),
                Err(_) => return Err(Failed { why: "botd couldn't reach Pub/Sub".into(), sign_in: None }),
            };
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                continue;
            }
            // Only a wait for the answer's start is an empty pull; one that starts and stalls is a failure.
            return match res.bytes().await {
                Ok(b) => Ok(Call::Answered(status, Zeroizing::new(b.to_vec()))),
                Err(e) if e.is_timeout() => Err(Failed { why: format!("Pub/Sub answered {status}, but the answer didn't finish in time"), sign_in: None }),
                Err(_) => Err(Failed { why: format!("Pub/Sub answered {status}, but the answer broke off"), sign_in: None }),
            };
        }
        unreachable!("the second pass returns")
    }

    /// Startup: the subscription is there and botd may pull from it.
    async fn check_subscription(&self) -> Result<(), Error> {
        let sub = self.subscription();
        let call = self.pubsub(&self.http, "testIamPermissions", &json!({ "permissions": [CONSUME] })).await.map_err(|f| f.sign_in.unwrap_or_else(|| Error::Unavailable(format!("GCP Pub/Sub: {} for {sub}", f.why))))?;
        let (status, body) = match call {
            Call::Answered(s, b) => (s, b),
            Call::TimedOut => return Err(Error::Unavailable(format!("GCP Pub/Sub: no answer in time for {sub}"))),
        };
        let hint = match status.as_u16() {
            200 => {
                let v: Value = serde_json::from_slice(&body).unwrap_or_default();
                let granted = v["permissions"].as_array().is_some_and(|p| p.iter().any(|p| p == CONSUME));
                if granted {
                    return Ok(());
                }
                return Err(Error::Unavailable(format!("GCP Pub/Sub: botd's service account can't pull from {sub}; grant it roles/pubsub.subscriber on the subscription")));
            }
            404 => "; is there a subscription by that name? Create one on the topic SuperBot's secrets publish to",
            403 => "; the Pub/Sub API must be on in botd's project, and botd's service account needs roles/pubsub.subscriber on the subscription",
            _ => "",
        };
        Err(Error::Unavailable(format!("GCP Pub/Sub answered {status}{} for {sub}{hint}", http::error_code(&body))))
    }

    /// Waits on Pub/Sub for messages; none when it had none in time.
    async fn pull(&self, client: &reqwest::Client) -> Result<Pulled, String> {
        match self.pubsub(client, "pull", &json!({ "maxMessages": MAX_MESSAGES })).await.map_err(|f| f.why)? {
            Call::TimedOut => Ok(Pulled { ack_ids: Vec::new(), attributes: Vec::new() }),
            Call::Answered(s, body) if s.is_success() => pulled(&body),
            Call::Answered(s, body) => Err(format!("Pub/Sub answered {s}{} to a pull", http::error_code(&body))),
        }
    }

    async fn acknowledge(&self, ack_ids: &[String]) -> Result<(), String> {
        match self.pubsub(&self.http, "acknowledge", &json!({ "ackIds": ack_ids })).await.map_err(|f| f.why)? {
            Call::Answered(s, _) if s.is_success() => Ok(()),
            Call::Answered(s, body) => Err(format!("Pub/Sub answered {s}{} to botd's acknowledgement", http::error_code(&body))),
            Call::TimedOut => Err("Pub/Sub didn't answer botd's acknowledgement in time".into()),
        }
    }
}

/// `secret.gcp_events`: the subscription's `state`, against its name.
fn audit_state(subscription: &str, state: &str, error: Option<&str>) {
    let e = Event::new(external::actor(), "secret.gcp_events").target("pubsub_subscription", subscription);
    external::audit(match error {
        None => e.details(json!({ "store": "gcp-secret-manager", "state": state })),
        Some(err) => e.outcome(Outcome::Failure).details(json!({ "store": "gcp-secret-manager", "state": state, "error": err })),
    });
}

/// Pulls the subscription for as long as the store is there, handing each change to `tx`.
async fn follow(inner: Arc<Inner>, pulls: reqwest::Client, store: Weak<ExternalStore>, users: bool, tx: Tx) {
    let sub = inner.subscription().to_string();
    let mut wait = BACKOFF_START;
    loop {
        if tx.is_closed() || store.strong_count() == 0 {
            return;
        }
        let started = Instant::now();
        let got = match inner.pull(&pulls).await {
            Ok(p) => {
                for a in &p.attributes {
                    if let Some(s) = seen(a, &inner.cfg, users) {
                        tx.send(Note::Changed { scope: s.scope, name: s.name, event: s.event, index: None });
                    }
                }
                match p.ack_ids.is_empty() {
                    true => Ok(false),
                    false => inner.acknowledge(&p.ack_ids).await.map(|()| true),
                }
            }
            Err(why) => Err(why),
        };
        match got {
            Ok(any) => {
                if !inner.events.is_following() {
                    inner.events.following(true);
                    log_info!("GCP Secret Manager: pulling change events from {sub} again; reading every cached secret again for changes made meanwhile (ADR 0325).");
                    audit_state(&sub, "resumed", None);
                    tx.send(Note::Resumed(None));
                }
                wait = BACKOFF_START;
                if !any {
                    tokio::time::sleep_until((started + MIN_PULL).into()).await;
                }
            }
            Err(why) => {
                if inner.events.is_following() {
                    inner.events.lost(&why);
                    log_warn!("GCP Secret Manager: change events stopped ({why}); pulling again. Until then a change reaches botd within SECRETS_CACHE_SECONDS (ADR 0325).");
                    audit_state(&sub, "lost", Some(&why));
                } else {
                    log_warn!("GCP Secret Manager: pulling change events failed again ({why}); trying again in {} s (ADR 0325).", wait.as_secs().max(1));
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Checks the subscription now, so botd doesn't start when it can't pull from it, then pulls
/// it on Secret Manager's runtime and applies the changes to `store` on a thread of its own.
pub(super) fn start(sm: &SecretManager, store: Weak<ExternalStore>) -> Result<(), Error> {
    let users = store.upgrade().is_some_and(|s| s.user_folders());
    let inner = Arc::clone(&sm.inner);
    sm.worker.run(async move { inner.check_subscription().await })?;
    let pulls = reqwest::Client::builder()
        .connect_timeout(http::CONNECT_TIMEOUT)
        .timeout(PULL_WAIT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Unavailable(format!("GCP Pub/Sub client: {e}")))?;
    audit_state(sm.inner.subscription(), "subscribed", None);
    sm.inner.events.following(true);
    let (tx, rx) = changes::queue();
    changes::start_applying("gcp-events", store.clone(), rx, Arc::clone(&sm.inner.events), &SOURCE).map_err(|e| Error::Unavailable(format!("GCP Secret Manager: change events: {e}")))?;
    sm.worker.spawn(follow(Arc::clone(&sm.inner), pulls, store, users, tx))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::super::env::EnvStore;
    use super::super::super::external::tests::audited;
    use super::super::super::http::tests::settings;
    use super::super::super::leases::tests::wait_for;
    use super::super::super::{redact, SecretStore};
    use super::super::tests::{authorized, put, stand_in, F};
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Json;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    const SUBSCRIPTION: &str = "projects/proj-1/subscriptions/superbot-secrets";
    /// Allowed, and reaches Google as written only if botd escapes the `%`.
    const ODD_SUBSCRIPTION: &str = "projects/proj-1/subscriptions/superbot%41";

    /// The stand-in's subscription: messages waiting, those delivered, and what botd did.
    #[derive(Default)]
    pub(crate) struct PubSub {
        waiting: Mutex<VecDeque<(String, Value)>>,
        pub acked: Mutex<Vec<String>>,
        pub pulls: AtomicUsize,
        /// Answers pulls with this status instead.
        pub status: AtomicUsize,
        /// Answers acknowledgements with this status instead.
        pub ack_status: AtomicUsize,
        /// `testIamPermissions`: the subscription isn't there (1), botd may not pull (2), or
        /// the API is off (3).
        pub check: AtomicUsize,
        /// How long a pull with nothing to deliver waits, in milliseconds.
        pub hold_ms: AtomicUsize,
        /// Pulls get a 503's headers, then a body that never ends.
        pub stall: std::sync::atomic::AtomicBool,
        delivered: AtomicUsize,
    }

    impl PubSub {
        /// Publishes a message with `attributes`, as Secret Manager does.
        pub(crate) fn publish(&self, attributes: Value) {
            let ack = format!("ack-{}-{}", self.delivered.fetch_add(1, Ordering::SeqCst), crate::random_hex(4));
            self.waiting.lock().unwrap().push_back((ack, attributes));
        }

        /// Secret Manager's message for `event` on `<project>/secrets/<id>`.
        pub(crate) fn changed(&self, event: &str, id: &str) {
            self.publish(json!({ "eventType": event, "dataFormat": "JSON_API_V1", "secretId": format!("projects/123456789/secrets/{id}"), "timestamp": "2026-11-26T08:00:00Z" }));
        }

        fn waiting(&self) -> usize {
            self.waiting.lock().unwrap().len()
        }
    }

    fn refuse(code: u16, status: &str) -> (StatusCode, Json<Value>) {
        let code = StatusCode::from_u16(code).unwrap();
        (code, Json(json!({ "error": { "code": code.as_u16(), "status": status, "message": "quoting-the-request" } })))
    }

    /// Pub/Sub's `<subscription>:pull`, `:acknowledge` and `:testIamPermissions`; None for any
    /// other path.
    pub(crate) async fn pubsub(f: &F, rest: &str, h: &HeaderMap, body: &Value) -> Option<Response> {
        let (sub, verb) = rest.rsplit_once(':')?;
        if !sub.contains("/subscriptions/") {
            return None;
        }
        if let Err(e) = authorized(f, h) {
            return Some(e.into_response());
        }
        if verb == "pull" && f.pubsub.stall.load(Ordering::SeqCst) {
            let never = tokio_stream::pending::<Result<Vec<u8>, std::io::Error>>();
            return Some((StatusCode::SERVICE_UNAVAILABLE, axum::body::Body::from_stream(never)).into_response());
        }
        Some(subscription(f, sub, verb, body).await.into_response())
    }

    async fn subscription(f: &F, sub: &str, verb: &str, body: &Value) -> (StatusCode, Json<Value>) {
        assert!([SUBSCRIPTION, ODD_SUBSCRIPTION].contains(&sub), "{sub}");
        let p = &f.pubsub;
        match verb {
            "testIamPermissions" => match p.check.load(Ordering::SeqCst) {
                1 => refuse(404, "NOT_FOUND"),
                2 => (StatusCode::OK, Json(json!({}))),
                3 => refuse(403, "PERMISSION_DENIED"),
                _ => {
                    assert_eq!(body["permissions"], json!([CONSUME]));
                    (StatusCode::OK, Json(json!({ "permissions": [CONSUME] })))
                }
            },
            "pull" => {
                p.pulls.fetch_add(1, Ordering::SeqCst);
                if let s @ 1.. = p.status.load(Ordering::SeqCst) {
                    return refuse(s as u16, "UNAVAILABLE");
                }
                let max = body["maxMessages"].as_u64().unwrap() as usize;
                let until = Instant::now() + Duration::from_millis(p.hold_ms.load(Ordering::SeqCst).max(1) as u64);
                loop {
                    let taken: Vec<(String, Value)> = {
                        let mut w = p.waiting.lock().unwrap();
                        let n = w.len().min(max);
                        w.drain(..n).collect()
                    };
                    if !taken.is_empty() {
                        let received: Vec<Value> = taken.into_iter().map(|(ack, a)| json!({ "ackId": ack, "message": { "data": "e30=", "attributes": a, "messageId": "1", "publishTime": "2026-11-26T08:00:00Z" } })).collect();
                        break (StatusCode::OK, Json(json!({ "receivedMessages": received })));
                    }
                    if Instant::now() >= until {
                        break (StatusCode::OK, Json(json!({})));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            "acknowledge" => {
                if let s @ 1.. = p.ack_status.load(Ordering::SeqCst) {
                    return refuse(s as u16, "INVALID_ARGUMENT");
                }
                let ids = body["ackIds"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string());
                p.acked.lock().unwrap().extend(ids);
                (StatusCode::OK, Json(json!({})))
            }
            other => panic!("Pub/Sub has no {other}"),
        }
    }

    fn pairs<'a>(url: &'a str, host: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("SECRETS_BACKEND", "gcp-secret-manager"),
            ("GCP_SECRET_MANAGER_PROJECT", "proj-1"),
            ("GCP_SECRET_MANAGER_ENDPOINT", url),
            ("GCP_PUBSUB_ENDPOINT", url),
            ("GCE_METADATA_HOST", host),
            ("GCP_SECRET_MANAGER_EVENTS", "superbot-secrets"),
        ]
    }

    fn on(pairs: &[(&str, &str)]) -> Arc<ExternalStore> {
        let cfg = Config::from_env(&settings(pairs), &EnvStore::fixed(&[])).unwrap();
        Arc::new(ExternalStore::new(Box::new(SecretManager::new(cfg).unwrap()), Duration::from_secs(3600)))
    }

    /// A store on the stand-in, set to follow its subscription, not following it yet.
    fn store_unwatched(url: &str) -> Arc<ExternalStore> {
        on(&pairs(url, url.trim_start_matches("http://")))
    }

    /// A store on the stand-in, following its subscription.
    fn store(url: &str) -> Arc<ExternalStore> {
        let x = store_unwatched(url);
        assert!(x.watch().unwrap(), "following");
        x
    }

    fn get(x: &ExternalStore, name: &str) -> Option<String> {
        x.get(name).unwrap().map(|v| v.expose().to_string())
    }

    fn refreshed(name: &str, trigger: &str) -> Vec<crate::audit::Event> {
        audited(name).into_iter().filter(|e| e.action == "secret.cache_refreshed" && e.details["trigger"] == trigger).collect()
    }

    fn cfg(extra: &[(&str, &str)]) -> Config {
        let mut pairs = vec![("GCP_SECRET_MANAGER_PROJECT", "proj-1")];
        pairs.extend_from_slice(extra);
        Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap()
    }

    #[test]
    fn only_changes_to_botds_own_names_are_taken() {
        let c = cfg(&[]);
        let at = |event: &str, secret: &str| json!({ "eventType": event, "dataFormat": "JSON_API_V1", "secretId": secret });
        let s = seen(&at("SECRET_VERSION_ADD", "projects/123456789/secrets/superbot-bots-OPENAI_API_KEY"), &c, false).unwrap();
        assert_eq!(s, Seen { scope: Scope::Bots, name: "OPENAI_API_KEY".into(), event: "SECRET_VERSION_ADD".into() });
        let s = seen(&at("SECRET_DELETE", "projects/proj-1/secrets/superbot-server-LINODE_TOKEN"), &c, false).unwrap();
        assert_eq!((s.scope, s.name.as_str()), (Scope::Server, "LINODE_TOKEN"), "by project id or number");
        for event in ["SECRET_CREATE", "SECRET_UPDATE", "SECRET_VERSION_ENABLE", "SECRET_VERSION_DISABLE", "SECRET_VERSION_DESTROY", "SECRET_VERSION_DESTROY_SCHEDULED", "SECRET_SOMETHING_NEW"] {
            assert!(seen(&at(event, "projects/p/secrets/superbot-bots-GH_TOKEN"), &c, false).is_some(), "{event}: every change, new kinds too");
        }
        let user = at("SECRET_VERSION_ADD", "projects/p/secrets/superbot-users-ua1-OPENAI_API_KEY");
        assert_eq!(seen(&user, &c, true).unwrap().scope, Scope::user("ua1").unwrap());
        assert!(seen(&user, &c, false).is_none(), "users' folders off");
        for (event, secret, why) in [
            ("SECRET_ROTATE", "projects/p/secrets/superbot-bots-GH_TOKEN", "a reminder, not a change"),
            ("TOPIC_CONFIGURED", "projects/p/secrets/superbot-bots-GH_TOKEN", "a test message"),
            ("secret_version_add", "projects/p/secrets/superbot-bots-GH_TOKEN", "not Secret Manager's"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/other-bots-GH_TOKEN", "another prefix"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-bots-LINODE_TOKEN", "botd's own, in the Bots' folder"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-server-OPENAI_API_KEY", "a Bots' name in botd's folder"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-bots-PATH", "a reserved name"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-other-GH_TOKEN", "another folder"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-users-ua1-LINODE_TOKEN", "a name no user may save"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-users-UA1-GH_TOKEN", "an id that can't name a folder"),
            ("SECRET_VERSION_ADD", "projects/p/locations/europe-west2/secrets/superbot-bots-GH_TOKEN", "a regional secret, botd's are global"),
            ("SECRET_VERSION_ADD", "projects//secrets/superbot-bots-GH_TOKEN", "no project"),
            ("SECRET_VERSION_ADD", "superbot-bots-GH_TOKEN", "not a resource name"),
            ("SECRET_VERSION_ADD", "projects/p/secrets/superbot-bots-GH_TOKEN/versions/3", "a version, not the secret"),
        ] {
            assert!(seen(&at(event, secret), &c, true).is_none(), "{why}");
        }
        assert!(seen(&json!({ "eventType": "SECRET_VERSION_ADD" }), &c, false).is_none(), "no secretId");
        assert!(seen(&Value::Null, &c, false).is_none(), "no attributes");

        let regional = cfg(&[("GCP_SECRET_MANAGER_LOCATION", "europe-west2"), ("GCP_SECRET_MANAGER_PREFIX", "acme-prod")]);
        assert!(seen(&at("SECRET_VERSION_ADD", "projects/p/locations/europe-west2/secrets/acme-prod-bots-GH_TOKEN"), &regional, false).is_some());
        for other in ["projects/p/locations/us-east1/secrets/acme-prod-bots-GH_TOKEN", "projects/p/secrets/acme-prod-bots-GH_TOKEN"] {
            assert!(seen(&at("SECRET_VERSION_ADD", other), &regional, false).is_none(), "{other}: another location");
        }
    }

    #[test]
    fn a_pulls_answer_is_checked() {
        let p = pulled(br#"{"receivedMessages":[{"ackId":"a1","message":{"attributes":{"eventType":"SECRET_CREATE"}}},{"ackId":"a2","message":{}}]}"#).unwrap();
        assert_eq!(p.ack_ids, ["a1", "a2"]);
        assert_eq!((p.attributes[0]["eventType"].as_str(), p.attributes[1].is_null()), (Some("SECRET_CREATE"), true), "a message with no attributes is still acknowledged");
        assert!(pulled(b"{}").unwrap().ack_ids.is_empty(), "nothing yet");
        for odd in [&b"[]"[..], b"<html>", br#"{"receivedMessages":{}}"#, br#"{"receivedMessages":[{"message":{}}]}"#, br#"{"receivedMessages":[{"ackId":"has space"}]}"#] {
            assert_eq!(pulled(odd).err().unwrap(), "Pub/Sub's answer to a pull isn't a list of messages");
        }
    }

    #[test]
    fn a_change_in_secret_manager_reaches_new_runs_at_once() {
        let (url, f) = stand_in();
        let old = format!("gcp-ev-old-{}", crate::random_hex(6));
        let new = format!("gcp-ev-new-{}", crate::random_hex(6));
        put(&f, "secrets/superbot-bots-GCP_EV_TOKEN", &old);
        put(&f, "secrets/superbot-server-SMTP_PASSWORD", "gcp-ev-smtp-1");
        put(&f, "secrets/superbot-users-uev1-OPENAI_API_KEY", "gcp-ev-user-1");
        let x = Arc::new(external::tests::users_on(store_unwatched(&url)));
        assert!(x.watch().unwrap());
        assert!(x.describe().contains("following change events from projects/proj-1/subscriptions/superbot-secrets"), "{}", x.describe());
        assert_eq!(get(&x, "GCP_EV_TOKEN").as_deref(), Some(old.as_str()));
        assert_eq!(x.user_get("uev1", "OPENAI_API_KEY").unwrap().unwrap().expose(), "gcp-ev-user-1");
        let w = x.watch_status().unwrap();
        assert_eq!((w.following, w.changes, w.lost), (true, 0, 0));

        let reads = f.reads.load(Ordering::SeqCst);
        put(&f, "secrets/superbot-bots-GCP_EV_TOKEN", &new);
        f.pubsub.changed("TOPIC_CONFIGURED", "superbot-bots-GCP_EV_TOKEN");
        f.pubsub.changed("SECRET_ROTATE", "superbot-bots-GCP_EV_TOKEN");
        f.pubsub.changed("SECRET_VERSION_ADD", "other-app-SECRET");
        f.pubsub.changed("SECRET_VERSION_ADD", "superbot-bots-GCP_EV_TOKEN");
        wait_for(|| get(&x, "GCP_EV_TOKEN").as_deref() == Some(new.as_str()));
        wait_for(|| f.pubsub.acked.lock().unwrap().len() == 4);
        assert_eq!(f.reads.load(Ordering::SeqCst) - reads, 1, "only the change is read, once; no request for the others");
        let ev = refreshed("GCP_EV_TOKEN", "gcp-event");
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!((ev[0].details["event"].as_str(), ev[0].details["entries"][0]["result"].as_str()), (Some("SECRET_VERSION_ADD"), Some("changed")));
        assert!(!format!("{ev:?}").contains(&new) && !format!("{ev:?}").contains(&old), "never a value");
        assert_eq!(redact::text(&new), redact::MARK, "the new value is redacted");

        // Deleted: gone at once. A user's own folder, and botd's own folder, the same way.
        f.secrets.lock().unwrap().remove("projects/proj-1/secrets/superbot-bots-GCP_EV_TOKEN");
        f.pubsub.changed("SECRET_DELETE", "superbot-bots-GCP_EV_TOKEN");
        put(&f, "secrets/superbot-users-uev1-OPENAI_API_KEY", "gcp-ev-user-2");
        f.pubsub.changed("SECRET_VERSION_ADD", "superbot-users-uev1-OPENAI_API_KEY");
        wait_for(|| get(&x, "GCP_EV_TOKEN").is_none());
        wait_for(|| x.user_get("uev1", "OPENAI_API_KEY").unwrap().unwrap().expose() == "gcp-ev-user-2");
        let w = x.watch_status().unwrap();
        assert_eq!((w.following, w.changes, w.catch_ups), (true, 3, 0));
        assert!(w.last_change_ms.is_some());

        // Google refuses botd's token: it signs in again and keeps pulling.
        let sign_ins = f.sign_ins.load(Ordering::SeqCst);
        f.tokens.lock().unwrap().clear();
        put(&f, "secrets/superbot-server-SMTP_PASSWORD", "gcp-ev-smtp-2");
        f.pubsub.changed("SECRET_VERSION_ADD", "superbot-server-SMTP_PASSWORD");
        wait_for(|| refreshed("SMTP_PASSWORD", "gcp-event").len() == 1);
        assert!(f.sign_ins.load(Ordering::SeqCst) > sign_ins);
        assert_eq!(get(&x, "SMTP_PASSWORD").as_deref(), Some("gcp-ev-smtp-2"));
        assert_eq!(x.watch_status().unwrap().lost, 0, "a refused token isn't a lost stream");
        assert!(audited(SUBSCRIPTION).iter().any(|e| e.action == "secret.gcp_events" && e.details["state"] == "subscribed"));
        for v in [old.as_str(), new.as_str(), "gcp-ev-smtp-1", "gcp-ev-smtp-2"] {
            redact::forget(v);
        }
        redact::forget_for("uev1", "gcp-ev-user-1");
        redact::forget_for("uev1", "gcp-ev-user-2");
    }

    #[test]
    fn after_pulls_fail_every_cached_answer_is_read_again() {
        let (url, f) = stand_in();
        put(&f, "secrets/superbot-bots-GCP_GAP_TOKEN", "gcp-gap-1");
        let x = store(&url);
        assert_eq!(get(&x, "GCP_GAP_TOKEN").as_deref(), Some("gcp-gap-1"));
        f.pubsub.status.store(503, Ordering::SeqCst);
        wait_for(|| !x.watch_status().unwrap().following);
        let w = x.watch_status().unwrap();
        assert_eq!((w.lost, w.last_loss.as_deref()), (1, Some("Pub/Sub answered 503 Service Unavailable (UNAVAILABLE) to a pull")));
        let lost: Vec<_> = audited(SUBSCRIPTION).into_iter().filter(|e| e.details["state"] == "lost").collect();
        assert!(lost.iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "Pub/Sub answered 503 Service Unavailable (UNAVAILABLE) to a pull"));
        assert!(!format!("{lost:?}").contains("quoting"), "never Google's text");

        // Changed while pulls failed, with its message lost: the read after the gap finds it.
        put(&f, "secrets/superbot-bots-GCP_GAP_TOKEN", "gcp-gap-2");
        let pulls = f.pubsub.pulls.load(Ordering::SeqCst);
        wait_for(|| f.pubsub.pulls.load(Ordering::SeqCst) >= pulls + 2);
        assert_eq!(x.watch_status().unwrap().lost, 1, "failing again isn't counted again");
        f.pubsub.status.store(0, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().catch_ups == 1);
        let w = x.watch_status().unwrap();
        assert_eq!((w.following, w.lost), (true, 1));
        assert_eq!(get(&x, "GCP_GAP_TOKEN").as_deref(), Some("gcp-gap-2"));
        assert!(audited(SUBSCRIPTION).iter().any(|e| e.details["state"] == "resumed"));
        assert!(audited("gcp-secret-manager").iter().any(|e| e.action == "secret.cache_refreshed" && e.details["trigger"] == "gcp-events-resumed"));

        // A message botd can't acknowledge comes back; that is a loss too, not a loop of reads.
        f.pubsub.ack_status.store(400, Ordering::SeqCst);
        f.pubsub.changed("SECRET_VERSION_ADD", "superbot-bots-GCP_GAP_TOKEN");
        wait_for(|| x.watch_status().unwrap().lost == 2);
        assert!(x.watch_status().unwrap().last_loss.unwrap().contains("400 Bad Request (INVALID_ARGUMENT) to botd's acknowledgement"));
        f.pubsub.ack_status.store(0, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().catch_ups == 2);

        // An answer that starts and stalls is a failure, not an empty pull.
        f.pubsub.stall.store(true, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().lost == 3);
        assert_eq!(x.watch_status().unwrap().last_loss.as_deref(), Some("Pub/Sub answered 503 Service Unavailable, but the answer didn't finish in time"));
        f.pubsub.stall.store(false, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().catch_ups == 3);

        // Pub/Sub out of reach: the same.
        f.down.store(true, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().lost == 4);
        f.down.store(false, Ordering::SeqCst);
        wait_for(|| x.watch_status().unwrap().following);
        redact::forget("gcp-gap-1");
        redact::forget("gcp-gap-2");
    }

    #[test]
    fn a_pull_that_waits_longer_than_botd_is_no_failure() {
        let (url, f) = stand_in();
        f.pubsub.hold_ms.store(PULL_WAIT.as_millis() as usize + 400, Ordering::SeqCst);
        put(&f, "secrets/superbot-bots-GCP_SLOW_TOKEN", "gcp-slow-1");
        let x = store(&url);
        assert_eq!(get(&x, "GCP_SLOW_TOKEN").as_deref(), Some("gcp-slow-1"));
        wait_for(|| f.pubsub.pulls.load(Ordering::SeqCst) >= 3);
        let w = x.watch_status().unwrap();
        assert_eq!((w.following, w.lost, w.catch_ups), (true, 0, 0), "timed out with nothing to say: still followed");
        put(&f, "secrets/superbot-bots-GCP_SLOW_TOKEN", "gcp-slow-2");
        f.pubsub.changed("SECRET_VERSION_ADD", "superbot-bots-GCP_SLOW_TOKEN");
        wait_for(|| get(&x, "GCP_SLOW_TOKEN").as_deref() == Some("gcp-slow-2"));
        assert_eq!(f.pubsub.waiting(), 0);
        redact::forget("gcp-slow-1");
        redact::forget("gcp-slow-2");
    }

    #[test]
    fn botd_wont_start_without_a_subscription_it_can_pull_from() {
        let (url, f) = stand_in();
        for (mode, err) in [
            (1, "GCP Pub/Sub answered 404 Not Found (NOT_FOUND) for projects/proj-1/subscriptions/superbot-secrets; is there a subscription by that name?"),
            (2, "botd's service account can't pull from projects/proj-1/subscriptions/superbot-secrets; grant it roles/pubsub.subscriber on the subscription"),
            (3, "GCP Pub/Sub answered 403 Forbidden (PERMISSION_DENIED) for projects/proj-1/subscriptions/superbot-secrets; the Pub/Sub API must be on"),
        ] {
            f.pubsub.check.store(mode, Ordering::SeqCst);
            let x = store_unwatched(&url);
            let e = x.watch().unwrap_err().to_string();
            assert!(e.contains(err) && !e.contains("quoting"), "{mode}: {e}");
            assert!(x.watch_status().is_none(), "not following");
        }
        assert_eq!(f.pubsub.pulls.load(Ordering::SeqCst), 0, "never pulled");
        f.pubsub.check.store(0, Ordering::SeqCst);
        f.down.store(true, Ordering::SeqCst);
        assert!(store_unwatched(&url).watch().unwrap_err().to_string().contains("503"), "Google down");
        f.down.store(false, Ordering::SeqCst);

        // Off: no subscription, nothing asked.
        let host = url.trim_start_matches("http://");
        let off: Vec<_> = pairs(&url, host).into_iter().filter(|(k, _)| *k != "GCP_SECRET_MANAGER_EVENTS").collect();
        let x = on(&off);
        assert!(!x.watch().unwrap() && x.watch_status().is_none());
        assert!(!x.describe().contains("change events"));

        // A `%` in the id names that subscription, not an escape.
        let odd: Vec<_> = off.into_iter().chain([("GCP_SECRET_MANAGER_EVENTS", "superbot%41")]).collect();
        let x = on(&odd);
        assert!(x.watch().unwrap(), "pulls {ODD_SUBSCRIPTION}");
        let pulls = f.pubsub.pulls.load(Ordering::SeqCst);
        wait_for(|| f.pubsub.pulls.load(Ordering::SeqCst) > pulls);
        assert_eq!(x.watch_status().unwrap().lost, 0);
    }

    #[test]
    fn the_setting_is_checked() {
        let with = |v: &str| Config::from_env(&settings(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1"), ("GCP_SECRET_MANAGER_EVENTS", v)]), &EnvStore::fixed(&[])).map(|c| c.events);
        assert_eq!(with("").unwrap(), None);
        assert_eq!(with(" superbot-secrets ").unwrap().as_deref(), Some(SUBSCRIPTION), "in GCP_SECRET_MANAGER_PROJECT");
        assert_eq!(with("projects/events-proj/subscriptions/sb.secrets~1").unwrap().as_deref(), Some("projects/events-proj/subscriptions/sb.secrets~1"), "or another project");
        for (bad, err) in [
            ("ab", "3 to 255"),
            ("1abc", "starting with a letter"),
            ("goog-secrets", "not with goog"),
            ("a/b/c", "isn't a Pub/Sub subscription id"),
            ("projects/proj-1", "must be a Pub/Sub subscription"),
            ("projects/Proj 1/subscriptions/abc", "GCP_SECRET_MANAGER_EVENTS's project"),
        ] {
            let e = with(bad).err().unwrap();
            assert!(e.contains(err), "{bad}: {e}");
        }
        let e = Config::from_env(&settings(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1"), ("GCP_PUBSUB_ENDPOINT", "http://pubsub.example.com")]), &EnvStore::fixed(&[])).err().unwrap();
        assert!(e.contains("GCP_PUBSUB_ENDPOINT") && e.contains("must use https"));
        let var = settings(&[("GCP_SECRET_MANAGER_EVENTS", "superbot-secrets")]);
        assert_eq!(external::unused_settings(&var, "vault"), ["GCP_SECRET_MANAGER_EVENTS"], "only SECRETS_BACKEND=gcp-secret-manager reads it");
        let var = settings(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1"), ("GCP_SECRET_MANAGER_EVENTS", "superbot-secrets")]);
        let reached = super::super::reaches(&var).unwrap();
        assert!(reached.iter().any(|(k, u, _)| *k == "GCP_PUBSUB_ENDPOINT" && u == "https://pubsub.googleapis.com"), "{reached:?}");
        let reached = super::super::reaches(&settings(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1")])).unwrap();
        assert!(!reached.iter().any(|(k, ..)| *k == "GCP_PUBSUB_ENDPOINT"), "only when on");
    }
}
