//! Outbound allow-lists for users' machines (ADR 0135), set by server admins: one for
//! the whole server and, for any user, one of their own. The server's is `open` (the
//! default: the internet stays open, the deny rules of ADR 0126 still hold) or
//! `allow_list`. A user's is `inherit` (the default), `open` or `allow_list`; with an
//! allow-list either way, their machine may reach the server's entries and their own.
//!
//! botd sends each machine's agent its effective policy when an admin changes it and
//! whenever a heartbeat shows the agent holds another, and won't start a run on a
//! machine whose allow-list isn't loaded. Every change is audited
//! (`server.egress_policy_changed`, `user.egress_policy_changed`), and so is what each
//! machine says of it (`machine.egress_policy_applied`, `machine.egress_policy_failed`).
//! A machine's run limits (ADR 0135) are reported beside it: botd audits
//! `machine.run_limits_unavailable` when an agent can't hold runs to them.

use super::egress_allow;
use super::enroll::{self, Enrollment};
use super::route::Refusal;
use super::wire::{self, EgressPolicy, EgressReport, Heartbeat};
use super::{State as MachineState, event};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res, bad};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State as AppS};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

const SERVER_KEY: &str = "machine_egress_policy";
const USER_KEY: &str = "machine_egress_policy:user:";
pub const INHERIT: &str = "inherit";
/// An agent that holds another policy, or failed to load it, is sent it again after this long.
const RESEND_MS: i64 = 10 * 60_000;

/// A saved policy: the server's (`open` or `allow_list`) or a user's (also `inherit`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Saved {
    pub mode: String,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Saved {
    fn open() -> Saved {
        Saved { mode: wire::EGRESS_OPEN.into(), allow: vec![] }
    }
}

fn load(app: &App, key: &str) -> Option<Saved> {
    app.db.setting(key).and_then(|v| serde_json::from_str(&v).ok())
}

pub fn server(app: &App) -> Saved {
    load(app, SERVER_KEY).unwrap_or_else(Saved::open)
}

pub fn own(app: &App, user_id: &str) -> Option<Saved> {
    load(app, &format!("{USER_KEY}{user_id}")).filter(|s| s.mode != INHERIT)
}

/// The policy `server` and `own` come to, with its id.
pub fn resolve(server: &Saved, own: Option<&Saved>) -> EgressPolicy {
    let mode = own.map_or(server.mode.as_str(), |o| o.mode.as_str()).to_string();
    let allow = if mode == wire::EGRESS_ALLOW_LIST {
        let mut all: Vec<String> = server.allow.iter().chain(own.map_or(&[][..], |o| &o.allow[..])).cloned().collect();
        all.sort();
        all.dedup();
        all
    } else {
        vec![]
    };
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{mode}\n{}", allow.join("\n")).as_bytes());
    let id = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    EgressPolicy { id, mode, allow }
}

/// `user_id`'s machine's policy now.
pub fn effective(app: &App, user_id: &str) -> EgressPolicy {
    resolve(&server(app), own(app, user_id).as_ref())
}

/// A policy from a request, checked: its mode, and its entries as the agent will read
/// them (`egress_allow::entries`), sorted, each once. `user`: `inherit` is allowed.
fn checked(body: Result<Json<Saved>, JsonRejection>, user: bool) -> Res<Saved> {
    let Ok(Json(s)) = body else {
        return Err(bad("Send {\"mode\": \"open\" | \"allow_list\", \"allow\": [\"api.example.com\", \"203.0.113.0/24\"]}."));
    };
    let mode = s.mode.trim().replace('-', "_");
    if !(egress_allow::mode_ok(&mode) || user && mode == INHERIT) {
        return Err(bad(if user { "mode must be inherit, open or allow_list" } else { "mode must be open or allow_list" }));
    }
    if mode != wire::EGRESS_ALLOW_LIST && !s.allow.is_empty() {
        return Err(bad("Only an allow_list lists hosts."));
    }
    let allow = egress_allow::entries(&s.allow).map_err(bad)?.iter().map(|e| e.as_str().to_string()).collect();
    Ok(Saved { mode, allow })
}

/// Refused when `server`'s and `own`'s entries together are more than an agent holds,
/// which would hold every run for that user back.
fn fits(server: &Saved, own: Option<&Saved>, whose: &str) -> Res<()> {
    let n = resolve(server, own).allow.len();
    if n > wire::EGRESS_MAX_ENTRIES {
        return Err(bad(format!(
            "{whose} would have {n} allow-list entries with the server's and their own together; a machine holds at most {}.",
            wire::EGRESS_MAX_ENTRIES
        )));
    }
    Ok(())
}

fn changes(from: &Saved, to: &Saved) -> Value {
    let added: Vec<&String> = to.allow.iter().filter(|a| !from.allow.contains(a)).collect();
    let removed: Vec<&String> = from.allow.iter().filter(|a| !to.allow.contains(a)).collect();
    json!({ "from": from, "to": to, "added": added, "removed": removed })
}

/// The control plane with enrollment, from botd's own state.
fn enrollment(app: &App) -> Res<&std::sync::Arc<Enrollment>> {
    let cp = app.control_plane.get().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))?;
    enroll::need(cp)
}

/// When each machine was last sent which policy, so a failing agent isn't sent it on
/// every heartbeat.
static SENT: Mutex<Option<HashMap<String, (String, i64)>>> = Mutex::new(None);

static PUSHING: Mutex<Option<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

fn mark_sent(machine_id: &str, id: &str) {
    SENT.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(machine_id.into(), (id.into(), now()));
}

fn sent_lately(machine_id: &str, id: &str, at: i64) -> bool {
    SENT.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(machine_id).cloned())
        .is_some_and(|(sent, when)| sent == id && at - when < RESEND_MS)
}

/// Whether `hb` says the agent holds `p`, loaded.
pub fn in_place(p: &EgressPolicy, hb: Option<&EgressReport>) -> bool {
    match hb {
        Some(r) if r.id == p.id => r.state == wire::EGRESS_STATE_ON || (p.mode == wire::EGRESS_OPEN && r.state == wire::EGRESS_STATE_OPEN),
        // An agent never sent a policy is open, which an open policy needs nothing more of.
        Some(r) => p.mode == wire::EGRESS_OPEN && r.id.is_empty(),
        None => p.mode == wire::EGRESS_OPEN,
    }
}

/// Sends `m`'s agent its policy now. Its answer: how the rules stand there.
pub async fn push(app: &App, e: &Enrollment, m: &Machine) -> Result<EgressReport, String> {
    // Read and sent under one lock per machine, so an older, wider list can't reach
    // the agent after a newer one.
    let lock = PUSHING.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).entry(m.id.clone()).or_default().clone();
    let _held = lock.lock().await;
    let p = effective(app, &m.user_id);
    mark_sent(&m.id, &p.id);
    match e.call_agent(app, m, reqwest::Method::PUT, "/v1/egress-policy", &p).await {
        Ok((200, body)) => serde_json::from_value(body).map_err(|_| "its agent's answer wasn't a report".to_string()),
        Ok((code, body)) => Err(body["error"].as_str().map_or(format!("it answered {code}"), String::from)),
        Err(e) => Err(e),
    }
}

/// After a heartbeat: sends the agent its policy if it holds another (or failed to
/// load it), at most every `RESEND_MS` for the same one.
pub async fn follow_up(app: &App, e: &Enrollment, m: &Machine, hb: &Heartbeat) {
    if !hb.can.iter().any(|c| c == wire::CAN_EGRESS_POLICY) {
        return;
    }
    let p = effective(app, &m.user_id);
    if in_place(&p, hb.egress_policy.as_ref()) || sent_lately(&m.id, &p.id, now()) {
        return;
    }
    let _ = push(app, e, m).await;
}

/// Why a run can't start on `m` now, if its user's allow-list isn't loaded there.
pub fn check_run(app: &App, m: &Machine, hb: &Heartbeat) -> Result<(), Refusal> {
    let p = effective(app, &m.user_id);
    if p.mode != wire::EGRESS_ALLOW_LIST || in_place(&p, hb.egress_policy.as_ref()) {
        return Ok(());
    }
    if !hb.can.iter().any(|c| c == wire::CAN_EGRESS_POLICY) {
        return Err(Refusal::EgressPolicy("its agent can't hold an allow-list: upgrade it".into()));
    }
    let r = hb.egress_policy.as_ref();
    Err(Refusal::EgressPolicy(match r {
        Some(r) if r.id == p.id => r.error.clone().unwrap_or_else(|| format!("its rules are {}", r.state)),
        _ => "it hasn't taken the current allow-list yet".into(),
    }))
}

/// What a heartbeat says of the allow-list and run limits, for `agentUpkeep`. Without
/// the time of the last refresh, so a refresh alone changes nothing.
pub fn upkeep_json(hb: &Heartbeat) -> (Value, Value) {
    let egress = hb.egress_policy.as_ref().map_or(Value::Null, |r| {
        json!({ "id": r.id, "mode": r.mode, "state": r.state, "addresses": r.addresses, "unresolved": r.unresolved, "error": r.error })
    });
    (egress, json!(hb.run_limits))
}

/// Audits a change in what a machine says: its allow-list loaded or failing, and run
/// limits that it can't hold runs to.
pub fn observed(app: &App, m: &Machine, by: &Who, old: Option<&Value>, new: &Value) {
    let (was_e, now_e) = (old.map(|o| &o["egressPolicy"]), &new["egressPolicy"]);
    if !now_e.is_null() && was_e.is_none_or(|w| w["id"] != now_e["id"] || w["state"] != now_e["state"] || w["error"] != now_e["error"]) {
        let d = json!({ "policyId": now_e["id"], "mode": now_e["mode"], "addresses": now_e["addresses"], "unresolved": now_e["unresolved"], "error": now_e["error"] });
        match now_e["state"].as_str() {
            Some(wire::EGRESS_STATE_FAILED) => app.db.record(&event(by, "machine.egress_policy_failed", m, d).outcome(Outcome::Failure)),
            Some(wire::EGRESS_STATE_ON | wire::EGRESS_STATE_OPEN) if !now_e["id"].as_str().unwrap_or("").is_empty() => {
                app.db.record(&event(by, "machine.egress_policy_applied", m, d))
            }
            _ => {}
        }
    }
    let (was_l, now_l) = (old.map(|o| &o["runLimits"]), &new["runLimits"]);
    if now_l["state"] == wire::RUN_LIMITS_UNAVAILABLE && was_l.is_none_or(|w| w["state"] != now_l["state"] || w["error"] != now_l["error"]) {
        let d = json!({ "error": now_l["error"] });
        app.db.record(&event(by, "machine.run_limits_unavailable", m, d).outcome(Outcome::Failure));
    }
}

/// Sends every enrolled, running machine whose policy may have changed its policy, a
/// few at a time, in the background. Those it misses get it after their next heartbeat.
fn push_all(app: AppState, only: Option<Vec<Machine>>) {
    let Ok(e) = enrollment(&app).cloned() else { return };
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let machines = only.unwrap_or_else(|| app.db.machines(Some(MachineState::Running)));
        futures_util::stream::iter(machines.into_iter().filter(|m| m.enrollment == "enrolled"))
            .for_each_concurrent(4, |m| {
                let (app, e) = (app.clone(), e.clone());
                async move {
                    let _ = push(&app, &e, &m).await;
                }
            })
            .await;
    });
}

// Admin API.

fn server_view(app: &App) -> Value {
    let s = server(app);
    let own = app.db.users().iter().filter(|u| own(app, &u.id).is_some()).count();
    json!({ "mode": s.mode, "allow": s.allow, "usersWithOwnPolicy": own })
}

/// `GET /api/machines/egress-policy`: the server's outbound allow-list.
pub async fn get_server(AppS(app): AppS<AppState>) -> Res {
    enrollment(&app)?;
    Ok(Json(server_view(&app)))
}

/// Held across a change's `fits` check and its write, so a server and a user change
/// can't each fit alone and save a combined list too long for an agent.
static SAVING: Mutex<()> = Mutex::new(());

/// `PUT /api/machines/egress-policy` `{mode, allow}`: sets the server's, and sends every
/// machine its policy.
pub async fn set_server(AppS(app): AppS<AppState>, Extension(by): Extension<Who>, body: Result<Json<Saved>, JsonRejection>) -> Res {
    enrollment(&app)?;
    let to = checked(body, false)?;
    let _saving = SAVING.lock().unwrap_or_else(|e| e.into_inner());
    for u in app.db.users() {
        if let Some(o) = own(&app, &u.id) {
            fits(&to, Some(&o), u.email.as_deref().unwrap_or(&u.id))?;
        }
    }
    let from = server(&app);
    if from != to {
        app.db.set_setting(SERVER_KEY, &serde_json::to_string(&to).unwrap_or_default());
        app.db.record(&by.event("server.egress_policy_changed").target("server", "egress_policy").details(changes(&from, &to)));
        push_all(app.clone(), None);
    }
    Ok(Json(server_view(&app)))
}

fn user_view(app: &App, user_id: &str) -> Value {
    let p = effective(app, user_id);
    let m = app.db.user_machine(user_id);
    let reported: Option<EgressReport> =
        m.as_ref().and_then(|m| m.agent_upkeep.as_ref()).and_then(|u| serde_json::from_value(u["egressPolicy"].clone()).ok());
    json!({
        "server": server(app),
        "own": load(app, &format!("{USER_KEY}{user_id}")).unwrap_or(Saved { mode: INHERIT.into(), allow: vec![] }),
        "effective": p,
        "machine": m.map(|m| json!({
            "id": m.id,
            "report": reported,
            "inPlace": in_place(&p, reported.as_ref()),
            "runLimits": m.agent_upkeep.as_ref().map(|u| u["runLimits"].clone()),
        })),
    })
}

/// `GET /api/users/{key}/machine/egress-policy`: theirs, the server's, what their
/// machine gets, and what it says it holds.
pub async fn get_user(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    enrollment(&app)?;
    let u = need_user_key(&app, &key)?;
    Ok(Json(user_view(&app, &u.id)))
}

/// `PUT /api/users/{key}/machine/egress-policy` `{mode, allow}`: sets a user's own
/// (`inherit` drops it), and sends their machine its policy.
pub async fn set_user(AppS(app): AppS<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>, body: Result<Json<Saved>, JsonRejection>) -> Res {
    enrollment(&app)?;
    let to = checked(body, true)?;
    let u = need_user_key(&app, &key)?;
    let _saving = SAVING.lock().unwrap_or_else(|e| e.into_inner());
    fits(&server(&app), Some(&to).filter(|t| t.mode != INHERIT), "Their machine")?;
    let k = format!("{USER_KEY}{}", u.id);
    let from = load(&app, &k).unwrap_or(Saved { mode: INHERIT.into(), allow: vec![] });
    if from != to {
        if to.mode == INHERIT {
            app.db.clear_setting(&k);
        } else {
            app.db.set_setting(&k, &serde_json::to_string(&to).unwrap_or_default());
        }
        let mut d = changes(&from, &to);
        d["userEmail"] = json!(u.email);
        d["effective"] = json!(effective(&app, &u.id));
        app.db.record(&by.event("user.egress_policy_changed").target("user", &u.id).details(d));
        if let Some(m) = app.db.user_machine(&u.id) {
            push_all(app.clone(), Some(vec![m]));
        }
    }
    Ok(Json(user_view(&app, &u.id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(mode: &str, allow: &[&str]) -> Saved {
        Saved { mode: mode.into(), allow: allow.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn a_users_list_adds_to_the_servers_and_their_mode_wins() {
        let open = Saved::open();
        let list = saved("allow_list", &["api.anthropic.com", "203.0.113.0/24"]);
        assert_eq!(resolve(&open, None).mode, "open");
        assert!(resolve(&open, None).allow.is_empty());
        let p = resolve(&list, None);
        assert_eq!((p.mode.as_str(), p.allow.len()), ("allow_list", 2));
        // Their own entries join the server's; an open server with a listed user lists only theirs.
        let mine = saved("allow_list", &["registry.npmjs.org", "api.anthropic.com"]);
        assert_eq!(resolve(&list, Some(&mine)).allow, ["203.0.113.0/24", "api.anthropic.com", "registry.npmjs.org"]);
        assert_eq!(resolve(&open, Some(&mine)).allow, ["api.anthropic.com", "registry.npmjs.org"]);
        // Open for them alone: nothing listed.
        let p = resolve(&list, Some(&Saved::open()));
        assert_eq!((p.mode.as_str(), p.allow.len()), ("open", 0));
        // The id follows what is sent, not how it was written.
        assert_eq!(resolve(&list, None).id, resolve(&saved("allow_list", &["203.0.113.0/24", "api.anthropic.com"]), None).id);
        assert_ne!(resolve(&list, None).id, resolve(&open, None).id);
    }

    #[test]
    fn policies_are_in_place_once_the_agent_holds_them_loaded() {
        let p = resolve(&saved("allow_list", &["api.example.com"]), None);
        let r = |id: &str, state: &str| EgressReport { id: id.into(), mode: "allow_list".into(), state: state.into(), ..Default::default() };
        assert!(in_place(&p, Some(&r(&p.id, "on"))));
        assert!(!in_place(&p, Some(&r(&p.id, "failed"))));
        assert!(!in_place(&p, Some(&r("other", "on"))));
        assert!(!in_place(&p, None), "an agent that can't take one");
        let open = resolve(&Saved::open(), None);
        assert!(in_place(&open, None) && in_place(&open, Some(&EgressReport::default())), "never sent one: open");
        assert!(!in_place(&open, Some(&r("old", "on"))), "still holds an old list");
    }

    #[test]
    fn the_server_and_a_user_together_fit_on_a_machine() {
        let many = |p: &str, n: usize| Saved { mode: "allow_list".into(), allow: (0..n).map(|i| format!("{p}{i}.example.com")).collect() };
        let full = many("s", wire::EGRESS_MAX_ENTRIES);
        assert!(fits(&full, None, "x").is_ok());
        assert!(fits(&full, Some(&many("s", 3)), "x").is_ok(), "the same entries count once");
        let e = fits(&full, Some(&many("u", 1)), "ada@example.com").unwrap_err();
        assert!(e.1.contains("ada@example.com") && e.1.contains("257"), "{}", e.1);
        assert!(fits(&full, Some(&Saved::open()), "x").is_ok(), "open for them alone lists nothing");
    }

    #[test]
    fn requests_are_checked() {
        let ok = |m: &str, a: &[&str], user: bool| checked(Ok(Json(saved(m, a))), user);
        assert_eq!(ok("allow-list", &["B.example.com", "b.example.com"], false).unwrap().allow, ["b.example.com"]);
        assert!(ok("inherit", &[], false).is_err() && ok("inherit", &[], true).is_ok());
        assert!(ok("open", &["a.example.com"], false).is_err(), "open lists nothing");
        assert!(ok("allow_list", &["*.example.com"], false).is_err());
        assert!(ok("closed", &[], true).is_err());
    }
}
