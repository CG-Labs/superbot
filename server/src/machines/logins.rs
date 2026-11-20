//! Harness logins on users' machines (ADR 0041), botd's side. With
//! MACHINE_HARNESS_LOGINS=on, a user (or an admin for them) runs a harness CLI's own
//! login on their machine: botd asks the agent over mutual TLS to run it in a terminal
//! there, relays what it shows and the lines typed back, and never stores either. The
//! credentials the login saves stay on the machine; heartbeats say only whether they
//! exist. A routed run of a harness that isn't logged in there, without a key for it in
//! the owner's secrets, is refused (`harness_not_logged_in`). Every step is audited.
//!
//! Only harnesses with a `machine_login` (Claude Code, Codex) have one. Pi and Hermes
//! keep using API keys from secrets, as on this server.

use super::enroll::{self, Enrollment, take_lines};
use super::route::{self, Refusal};
use super::wire::{self, Heartbeat, LoginEvent, LoginRequest};
use super::{ControlPlane, State, event};
use crate::adapters::MachineLogin;
use crate::audit::{Outcome, Who};
use crate::db::{Machine, User};
use crate::rbac::Principal;
use crate::runner::App;
use crate::users::{Caller, need_user_key};
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, State as AppS};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// How long a login may wait for its user.
const LOGIN_SECS: u64 = 900;
pub const OFF: &str = "Harness logins on machines are off. Set MACHINE_HARNESS_LOGINS=on to turn them on.";

/// A login running on a machine, by its id.
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub machine_id: String,
    pub harness: String,
}

#[derive(Default)]
pub struct Sessions(Mutex<HashMap<String, Session>>);

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, id: &str, user_id: &str) -> Option<Session> {
        self.lock().get(id).filter(|s| s.user_id == user_id).cloned()
    }
}

/// The harness's login on a machine, if it has one.
pub fn recipe(harness: &str) -> Option<MachineLogin> {
    crate::adapters::get(harness)?.machine_login()
}

fn escape(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `cred=<harness>:<file>` for every harness with a login: heartbeats ask the agent
/// whether each exists.
pub fn cred_query() -> Vec<String> {
    crate::adapters::NAMES
        .iter()
        .filter_map(|name| Some((name, recipe(name)?)))
        .flat_map(|(name, r)| r.files.iter().map(move |f| format!("cred={}", escape(&format!("{name}:{f}")))))
        .collect()
}

/// Whether runs get one of the login's keys, so they need no login: the server-wide
/// ones, and `owner`'s own if given (a run for someone else gets none, ADR 0046).
fn keyed(owner: Option<&str>, r: &MachineLogin) -> bool {
    let s = crate::secrets::global();
    owner
        .map_or_else(|| s.harness_env(), |o| s.harness_env_for(o))
        .into_iter()
        .chain(s.inherited_harness_env())
        .any(|(k, v)| r.keys.contains(&k.as_str()) && !v.expose().trim().is_empty())
}

/// Whether a run of `bin` may start on its owner's machine, as far as logins go.
/// `owner`: whose own keys the run gets, if anyone's.
pub fn check_run(e: &Enrollment, hb: &Heartbeat, owner: Option<&str>, bin: &str) -> Result<(), Refusal> {
    match recipe(bin) {
        Some(r) if e.logins => route::logged_in(hb, bin, keyed(owner, &r)),
        _ => Ok(()),
    }
}

/// The same, for a teammate's run as their own user (ADR 0048): the machine's logins
/// live in the Bots' home, which that user can't read, so only a server-wide key does.
pub fn check_teammate_run(bin: &str) -> Result<(), Refusal> {
    match recipe(bin) {
        Some(r) if !keyed(None, &r) => Err(Refusal::NoTeammateKey(bin.into())),
        _ => Ok(()),
    }
}

fn control_plane(app: &App) -> Res<&ControlPlane> {
    app.control_plane
        .get()
        .map(|cp| &**cp)
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))
}

fn need_on(app: &App) -> Res<Arc<Enrollment>> {
    let e = enroll::need(control_plane(app)?)?;
    if !e.logins {
        return Err(ApiError(StatusCode::CONFLICT, OFF.into()));
    }
    Ok(e.clone())
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn need_recipe(harness: &str) -> Res<MachineLogin> {
    recipe(harness).ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "Name claude or codex. Pi and Hermes have no login on a machine: they use API keys from secrets.".into(),
        )
    })
}

/// The user's machine, running with an enrolled agent.
fn ready_machine(app: &App, u: &User) -> Res<Machine> {
    if !u.active() {
        return Err(ApiError(StatusCode::FORBIDDEN, "That user is disabled.".into()));
    }
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    if m.state != State::Running || m.enrollment != "enrolled" {
        return Err(conflict(format!(
            "The machine is {} and its agent is {}; it must be running and enrolled.",
            m.state.as_str(),
            m.enrollment
        )));
    }
    Ok(m)
}

async fn heartbeat(app: &App, e: &Enrollment, m: &Machine) -> Res<Heartbeat> {
    let hb = enroll::heartbeat(app, e, m)
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))?;
    if !hb.can.iter().any(|c| c == wire::CAN_LOGINS) {
        return Err(conflict("Its agent can't run logins: it is older than ADR 0041. Upgrade it."));
    }
    Ok(hb)
}

fn view(e: &Enrollment, m: &Machine, hb: &Heartbeat) -> Value {
    let harnesses: serde_json::Map<String, Value> = crate::adapters::NAMES
        .iter()
        .filter(|n| recipe(n).is_some())
        .map(|n| {
            let st = hb.logins.get(*n).cloned().unwrap_or_default();
            let keyed = recipe(n).is_some_and(|r| keyed(Some(&m.user_id), &r));
            (
                n.to_string(),
                json!({ "state": if st.state.is_empty() { wire::LOGGED_OUT } else { st.state.as_str() }, "since": st.since, "keyInSecrets": keyed }),
            )
        })
        .collect();
    json!({ "machineId": m.id, "logins": if e.logins { "on" } else { "off" }, "harnesses": harnesses })
}

fn agent_error(code: u16, reply: &Value) -> ApiError {
    let why = reply["error"].as_str().unwrap_or("no reason given");
    ApiError(StatusCode::BAD_GATEWAY, format!("Its agent refused ({code}): {why}"))
}

/// The signed-in person, never a Bot.
fn me(c: &Caller) -> Res<User> {
    if c.principal == Principal::Bot {
        return Err(ApiError(StatusCode::FORBIDDEN, "A Bot can't log in harnesses on a machine.".into()));
    }
    c.user.clone().ok_or_else(|| crate::not_found("Machine"))
}

fn line(e: &LoginEvent) -> Bytes {
    let mut v = serde_json::to_vec(e).unwrap_or_default();
    v.push(b'\n');
    Bytes::from(v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    harness: String,
}

/// Starts the login on the user's machine and streams what it shows back as JSON
/// lines (`LoginEvent`s), the first naming the login for `input`. If the caller goes
/// away, the login there is stopped.
async fn start(app: AppState, by: Who, u: User, harness: String) -> Res<Response> {
    let e = need_on(&app)?;
    let r = need_recipe(&harness)?;
    let m = ready_machine(&app, &u)?;
    let hb = heartbeat(&app, &e, &m).await?;
    if hb.logins.get(&harness).is_some_and(|l| l.state == wire::LOGGING_IN) {
        return Err(conflict(format!("A {harness} login is already running there.")));
    }
    let address = m.ipv4.clone().ok_or_else(|| conflict("The machine has no address yet."))?;
    let id = format!("l{}", crate::random_hex(8));
    let req = LoginRequest {
        login_id: id.clone(),
        harness: harness.clone(),
        args: r.args.iter().map(|a| a.to_string()).collect(),
        files: r.files.iter().map(|f| f.to_string()).collect(),
        timeout_secs: LOGIN_SECS,
    };
    let details = {
        let (harness, id) = (harness.clone(), id.clone());
        move |extra: Value| {
            let mut d = json!({ "harness": harness, "loginId": id });
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
                d.extend(x);
            }
            d
        }
    };
    e.sessions.lock().insert(
        id.clone(),
        Session {
            user_id: u.id.clone(),
            machine_id: m.id.clone(),
            harness: harness.clone(),
        },
    );
    app.db.record(&event(&by, "machine.harness_login_started", &m, details(json!({}))));
    let failed = |why: String| {
        e.sessions.lock().remove(&id);
        app.db.record(
            &event(&by, "machine.harness_login_finished", &m, details(json!({ "loggedIn": false, "error": why })))
                .outcome(Outcome::Failure),
        );
    };
    let pins = app.db.machine_pins(&m.id);
    let sent = match e.job_client(pins.clone()) {
        Ok(c) => c.post(e.agent_url(&address, "/v1/logins")).json(&req).send().await.map_err(enroll::without_url),
        Err(why) => Err(why),
    };
    let mut res = match sent {
        Ok(res) => res,
        Err(why) => {
            failed(why.clone());
            return Err(ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")));
        }
    };
    if !res.status().is_success() {
        let code = res.status().as_u16();
        let reply = enroll::read_capped(&mut res, enroll::MAX_REPLY)
            .await
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let err = agent_error(code, &reply);
        failed(err.1.clone());
        return Err(err);
    }
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut end: Option<(bool, bool, String)> = None;
        let mut error: Option<String> = None;
        let mut gone = false;
        'read: loop {
            match res.chunk().await {
                Ok(Some(bytes)) => {
                    let Some(events) = take_lines::<LoginEvent>(&mut buf, &bytes) else {
                        error = Some("its agent sent too much at once".into());
                        break;
                    };
                    for ev in events {
                        match &ev {
                            LoginEvent::Exit { success, logged_in, status } => end = Some((*success, *logged_in, status.clone())),
                            LoginEvent::Error { message } => error = Some(message.clone()),
                            _ => {}
                        }
                        if tx.send(Ok(line(&ev))).await.is_err() {
                            gone = true;
                            break 'read;
                        }
                    }
                }
                Ok(None) => break,
                Err(why) => {
                    error = Some(format!("lost the machine: {}", enroll::without_url(why)));
                    break;
                }
            }
        }
        match end {
            Some((success, logged_in, status)) => {
                let ev = event(&by, "machine.harness_login_finished", &m, details(json!({ "loggedIn": logged_in, "success": success, "status": status })));
                app.db.record(&if logged_in { ev } else { ev.outcome(Outcome::Failure) });
            }
            None if gone => {
                if let Ok((c, _)) = e.pinned(pins) {
                    let _ = c.post(e.agent_url(&address, &format!("/v1/logins/{id}/abort"))).send().await;
                }
                app.db.record(&event(&by, "machine.harness_login_aborted", &m, details(json!({ "reason": "caller_left" }))));
            }
            None => {
                let message = error.unwrap_or_else(|| "its agent stopped answering".into());
                let _ = tx.send(Ok(line(&LoginEvent::Error { message: message.clone() }))).await;
                app.db.record(
                    &event(&by, "machine.harness_login_finished", &m, details(json!({ "loggedIn": false, "error": message })))
                        .outcome(Outcome::Failure),
                );
            }
        }
        e.sessions.lock().remove(&id);
    });
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputBody {
    text: String,
}

/// Types a line into a running login. What was typed is never kept or audited.
async fn input(app: AppState, by: Who, u: User, id: String, text: String) -> Res<StatusCode> {
    let e = need_on(&app)?;
    let s = e.sessions.get(&id, &u.id).ok_or_else(|| crate::not_found("Login"))?;
    let m = app.db.machine(&s.machine_id).ok_or_else(|| crate::not_found("Machine"))?;
    let path = format!("/v1/logins/{id}/input");
    let (code, reply) = e
        .call_agent(&app, &m, reqwest::Method::POST, &path, &wire::LoginInput { text: text.clone() })
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))?;
    if !(200..300).contains(&code) {
        return Err(agent_error(code, &reply));
    }
    app.db.record(&event(&by, "machine.harness_login_input", &m, json!({ "harness": s.harness, "loginId": id, "chars": text.chars().count() })));
    Ok(StatusCode::NO_CONTENT)
}

async fn abort(app: AppState, by: Who, u: User, id: String) -> Res<StatusCode> {
    let e = need_on(&app)?;
    let s = e.sessions.get(&id, &u.id).ok_or_else(|| crate::not_found("Login"))?;
    let m = app.db.machine(&s.machine_id).ok_or_else(|| crate::not_found("Machine"))?;
    let (code, reply) = e
        .call_agent(&app, &m, reqwest::Method::POST, &format!("/v1/logins/{id}/abort"), &json!({}))
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))?;
    if !(200..300).contains(&code) {
        return Err(agent_error(code, &reply));
    }
    app.db.record(&event(&by, "machine.harness_login_aborted", &m, json!({ "harness": s.harness, "loginId": id, "reason": "asked" })));
    Ok(StatusCode::NO_CONTENT)
}

async fn status(app: AppState, u: User) -> Res {
    let e = need_on(&app)?;
    let m = ready_machine(&app, &u)?;
    let hb = heartbeat(&app, &e, &m).await?;
    Ok(Json(view(&e, &m, &hb)))
}

/// Logs the harness out there: its credential files are removed.
async fn logout(app: AppState, by: Who, u: User, harness: String) -> Res {
    let e = need_on(&app)?;
    let r = need_recipe(&harness)?;
    let m = ready_machine(&app, &u)?;
    heartbeat(&app, &e, &m).await?;
    let body = wire::ForgetRequest {
        harness: harness.clone(),
        files: r.files.iter().map(|f| f.to_string()).collect(),
    };
    let (code, reply) = e
        .call_agent(&app, &m, reqwest::Method::POST, "/v1/logins/forget", &body)
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))?;
    if !(200..300).contains(&code) {
        return Err(agent_error(code, &reply));
    }
    app.db.record(&event(&by, "machine.harness_logged_out", &m, json!({ "harness": harness, "removed": reply["removed"] })));
    let hb = heartbeat(&app, &e, &m).await?;
    let mut v = view(&e, &m, &hb);
    v["removed"] = reply["removed"].clone();
    Ok(Json(v))
}

// Admin API, under `/api/users/{key}/machine` (admin only, rbac::classify).

/// `POST /api/users/{key}/machine/harness-login` `{harness}`: a stream of `LoginEvent`s.
pub async fn admin_start(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    Json(b): Json<StartBody>,
) -> Res<Response> {
    let u = need_user_key(&app, &key)?;
    start(app, by, u, b.harness).await
}

/// `POST /api/users/{key}/machine/harness-login/{id}/input` `{text}`.
pub async fn admin_input(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path((key, id)): Path<(String, String)>,
    Json(b): Json<InputBody>,
) -> Res<StatusCode> {
    let u = need_user_key(&app, &key)?;
    input(app, by, u, id, b.text).await
}

/// `DELETE /api/users/{key}/machine/harness-login/{id}`: stops it.
pub async fn admin_abort(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path((key, id)): Path<(String, String)>,
) -> Res<StatusCode> {
    let u = need_user_key(&app, &key)?;
    abort(app, by, u, id).await
}

/// `GET /api/users/{key}/machine/harness-logins`: whether each harness is logged in there.
pub async fn admin_status(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    status(app, u).await
}

/// `DELETE /api/users/{key}/machine/harness-logins/{harness}`: logs it out there.
pub async fn admin_logout(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path((key, harness)): Path<(String, String)>,
) -> Res {
    let u = need_user_key(&app, &key)?;
    logout(app, by, u, harness).await
}

// The same for the caller's own machine, under `/api/machine` (signed-in people).

pub async fn my_start(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Extension(c): Extension<Caller>,
    Json(b): Json<StartBody>,
) -> Res<Response> {
    let u = me(&c)?;
    start(app, by, u, b.harness).await
}

pub async fn my_input(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Extension(c): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<InputBody>,
) -> Res<StatusCode> {
    let u = me(&c)?;
    input(app, by, u, id, b.text).await
}

pub async fn my_abort(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Extension(c): Extension<Caller>,
    Path(id): Path<String>,
) -> Res<StatusCode> {
    let u = me(&c)?;
    abort(app, by, u, id).await
}

pub async fn my_status(AppS(app): AppS<AppState>, Extension(c): Extension<Caller>) -> Res {
    let u = me(&c)?;
    status(app, u).await
}

pub async fn my_logout(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Extension(c): Extension<Caller>,
    Path(harness): Path<String>,
) -> Res {
    let u = me(&c)?;
    logout(app, by, u, harness).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_claude_and_codex_log_in_on_a_machine_and_heartbeats_ask_for_their_files() {
        let with: Vec<&str> = crate::adapters::NAMES.iter().copied().filter(|n| recipe(n).is_some()).collect();
        assert_eq!(with, ["claude", "codex"]);
        assert_eq!(
            cred_query(),
            ["cred=claude%3A.claude%2F.credentials.json", "cred=codex%3A.codex%2Fauth.json"]
        );
        for n in with {
            let r = recipe(n).unwrap();
            assert!(r.files.iter().all(|f| wire::home_path(f)) && !r.keys.is_empty(), "{n}");
        }
    }
}
