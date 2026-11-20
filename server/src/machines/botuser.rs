//! Bots' own OS user on users' machines (ADR 0042), botd's side. With
//! MACHINE_BOT_USER=on, after a heartbeat botd asks each idle agent that can to run its
//! Bots as their own unprivileged user (`superbot-bots`): the agent makes it if it must,
//! hands it the Bots' home (workspace, logins, the folder copy), and from then on runs
//! every harness, login and cleanup as it. Until the agent says it's ready, a routed run
//! is refused (`bot_user_pending`), never run as root or anywhere else; an agent too old
//! to do it is refused as outdated, so upgrading it (ADR 0039) is the way on. Every step
//! is audited. Off, nothing here does anything.

use super::enroll::{self, Enrollment};
use super::route::Refusal;
use super::wire::{self, BotUserRequest, Heartbeat};
use super::{ControlPlane, event, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::{Extension, Path, State as AppS};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

pub const OFF: &str = "Bots' own user on machines is off. Set MACHINE_BOT_USER=on to turn it on.";
/// An agent that hasn't taken the request is asked again after this long.
const RESEND_MS: i64 = 5 * 60_000;
/// One that failed to set it up is asked again after this long.
const RETRY_FAILED_MS: i64 = 30 * 60_000;

/// When botd last asked each machine, by id.
#[derive(Default)]
pub struct Asked(Mutex<HashMap<String, i64>>);

impl Asked {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// MACHINE_BOT_USER: on or off (the default).
pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<bool, String> {
    match var("MACHINE_BOT_USER").trim() {
        "" | "off" => Ok(false),
        "on" => Ok(true),
        v => Err(format!("MACHINE_BOT_USER must be on or off, not \"{v}\"")),
    }
}

fn can(hb: &Heartbeat) -> bool {
    hb.can.iter().any(|c| c == wire::CAN_BOT_USER)
}

/// Whether a run may start on the machine, as far as the Bots' user goes.
pub fn check_run(e: &Enrollment, hb: &Heartbeat) -> Result<(), Refusal> {
    if !e.bot_user {
        return Ok(());
    }
    if !can(hb) {
        return Err(Refusal::Outdated(hb.version.clone()));
    }
    match hb.bot_user.as_ref().map(|s| s.state.as_str()) {
        Some(wire::BOT_USER_READY) => Ok(()),
        Some(wire::BOT_USER_FAILED) => Err(Refusal::BotUserFailed),
        _ => Err(Refusal::BotUserPending),
    }
}

/// Whether to ask the agent now: it can, it's idle, it hasn't got the user, and it
/// wasn't asked lately (or, after a failure, for a while).
fn due(hb: &Heartbeat, asked: Option<i64>, at: i64) -> bool {
    if !can(hb) || hb.jobs > 0 {
        return false;
    }
    let since = |t: i64, ms: i64| at - t >= ms;
    match &hb.bot_user {
        None => asked.is_none_or(|t| since(t, RESEND_MS)),
        Some(s) if s.state == wire::BOT_USER_FAILED => {
            since(s.at, RETRY_FAILED_MS) && asked.is_none_or(|t| since(t, RETRY_FAILED_MS))
        }
        Some(_) => false,
    }
}

async fn ask(app: &App, e: &Enrollment, m: &Machine, by: &Who) -> Result<Value, ApiError> {
    e.asked.lock().insert(m.id.clone(), now());
    let details = json!({ "user": wire::BOT_USER });
    match e.call_agent(app, m, reqwest::Method::PUT, "/v1/bot-user", &BotUserRequest {}).await {
        Ok((code, reply)) if (200..300).contains(&code) => {
            app.db.record(&event(by, "machine.bot_user_requested", m, details));
            Ok(reply)
        }
        res => {
            let why = match res {
                Ok((code, body)) => body["error"].as_str().map_or(format!("it answered {code}"), String::from),
                Err(e) => e,
            };
            let mut d = details;
            d["error"] = json!(why);
            app.db.record(&event(by, "machine.bot_user_requested", m, d).outcome(Outcome::Failure));
            Err(ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't take the request: {why}")))
        }
    }
}

/// After a periodic heartbeat: asks for the Bots' user if it's due.
pub async fn follow_up(app: &App, e: &Enrollment, m: &Machine, hb: &Heartbeat) {
    if !e.bot_user {
        return;
    }
    let asked = e.asked.lock().get(&m.id).copied();
    if due(hb, asked, now()) {
        let _ = ask(app, e, m, &system(m)).await;
    }
}

/// What a heartbeat says of the Bots' user, as kept with the agent's upkeep.
pub fn upkeep_json(hb: &Heartbeat) -> Value {
    match &hb.bot_user {
        Some(s) => json!({ "state": s.state, "user": s.user, "uid": s.uid, "error": s.error, "at": s.at }),
        None => Value::Null,
    }
}

/// Records the Bots' user becoming ready, or failing, once per change.
pub fn observed(app: &App, m: &Machine, by: &Who, old: Option<&Value>, new: &Value) {
    let state = |v: Option<&Value>| v.and_then(|v| v["state"].as_str()).map(String::from);
    let (was, now) = (state(old), state(Some(new)));
    let d = || json!({ "user": new["user"], "uid": new["uid"] });
    match now.as_deref() {
        Some(wire::BOT_USER_READY) if was.as_deref() != Some(wire::BOT_USER_READY) => {
            app.db.record(&event(by, "machine.bot_user_ready", m, d()));
        }
        Some(wire::BOT_USER_FAILED) if was.as_deref() != Some(wire::BOT_USER_FAILED) || old.map(|o| &o["at"]) != Some(&new["at"]) => {
            let mut d = d();
            d["error"] = new["error"].clone();
            app.db.record(&event(by, "machine.bot_user_failed", m, d).outcome(Outcome::Failure));
        }
        _ => {}
    }
}

fn control_plane(app: &App) -> Res<&ControlPlane> {
    app.control_plane.get().map(|cp| &**cp).ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))
}

/// `POST /api/users/{key}/machine/bot-user`: asks its agent for the Bots' user now,
/// even after a failure. 202 with what the agent said; heartbeats and the audit log
/// say how it went.
pub async fn now_for(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<(StatusCode, Json<Value>)> {
    let e = enroll::need(control_plane(&app)?)?;
    if !e.bot_user {
        return Err(ApiError(StatusCode::CONFLICT, OFF.into()));
    }
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    if m.enrollment != "enrolled" {
        return Err(ApiError(StatusCode::CONFLICT, "Its agent isn't enrolled.".into()));
    }
    let hb = enroll::heartbeat(&app, e, &m)
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))?;
    if !can(&hb) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't run Bots as their own user: it is older than ADR 0042. Upgrade it.".into(),
        ));
    }
    let reply = ask(&app, e, &m, &by).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "machineId": m.id, "botUser": reply }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(can: bool, jobs: u32, state: Option<(&str, i64)>) -> Heartbeat {
        Heartbeat {
            can: if can { vec![wire::CAN_BOT_USER.into()] } else { vec![] },
            jobs,
            bot_user: state.map(|(s, at)| wire::BotUserStatus { state: s.into(), user: wire::BOT_USER.into(), at, ..Default::default() }),
            ..Default::default()
        }
    }

    #[test]
    fn off_by_default_and_only_on_or_off() {
        assert!(!from_env(&|_| String::new()).unwrap());
        assert!(from_env(&|_| "on".into()).unwrap());
        assert!(!from_env(&|_| "off".into()).unwrap());
        assert!(from_env(&|_| "yes".into()).is_err());
    }

    #[test]
    fn asked_once_when_idle_and_again_only_after_a_while() {
        let t = 100 * 60_000;
        assert!(due(&hb(true, 0, None), None, t));
        assert!(!due(&hb(false, 0, None), None, t), "an agent that can't");
        assert!(!due(&hb(true, 1, None), None, t), "busy");
        assert!(!due(&hb(true, 0, None), Some(t - 60_000), t), "asked a minute ago");
        assert!(due(&hb(true, 0, None), Some(t - RESEND_MS), t));
        assert!(!due(&hb(true, 0, Some((wire::BOT_USER_SETTING_UP, t))), None, t));
        assert!(!due(&hb(true, 0, Some((wire::BOT_USER_READY, t))), None, t));
        assert!(!due(&hb(true, 0, Some((wire::BOT_USER_FAILED, t - 60_000))), None, t), "failed just now");
        assert!(due(&hb(true, 0, Some((wire::BOT_USER_FAILED, t - RETRY_FAILED_MS))), None, t));
        assert!(!due(&hb(true, 0, Some((wire::BOT_USER_FAILED, t - RETRY_FAILED_MS))), Some(t - 60_000), t));
    }
}
