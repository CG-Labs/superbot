//! A teammate's own harness logins for an owner's shared Bots on this server (ADR 0064).
//! With `ISOLATION_TEAMMATES` on, a teammate's runs of those Bots go as an account of
//! their own, `sb-t-<hash>`, and need their own login there (or a server-wide key). The
//! teammate logs in from the app, as on the owner's machine (ADR 0062): botd runs the
//! harness CLI's login in a terminal as that account, through `superbot-run`, relays
//! what it shows and the lines typed back, and keeps neither. What it saves stays in
//! that account's HOME, which botd checks and clears as the account, never by reading it.
//! The same API as machine logins (`/api/machine/teammate/{owner}/...`) lands here when
//! the owner's Bots run on this server.

use crate::accounts::Space;
use crate::audit::{Outcome, Who};
use crate::db::User;
use crate::machines::logins::recipe;
use crate::machines::terminal::{self, Logins};
use crate::machines::wire::{self, LoginEvent, LoginRequest};
use crate::runner::App;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// How long a login may wait for its user.
const LOGIN_SECS: u64 = 900;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Clone, Debug)]
struct Session {
    owner: String,
    teammate: String,
    harness: String,
}

/// The logins running on this server for teammates, by id.
#[derive(Default)]
pub struct Local {
    terminal: Arc<Logins>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Local {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The login `id`, only if it's `teammate`'s for `owner`'s Bots.
    fn get(&self, id: &str, owner: &str, teammate: &str) -> Option<Session> {
        self.lock().get(id).filter(|s| s.owner == owner && s.teammate == teammate).cloned()
    }

    fn running(&self, owner: &str, teammate: &str) -> Vec<String> {
        self.terminal.running_for(Space::Teammate { owner, teammate }.dir().as_deref())
    }

    /// Stops every login `teammate` has running for `owner`'s Bots (ADR 0066). How many.
    pub fn stop_for(&self, owner: &str, teammate: &str) -> u32 {
        Space::Teammate { owner, teammate }.dir().map_or(0, |d| self.terminal.abort_for(&d))
    }
}

/// Whether `owner`'s teammates log in on this server: teammate accounts are on, and the
/// owner's Bots run here, not on their machine.
pub fn on(app: &App, owner: &str) -> bool {
    app.teammate_accounts() && app.runs_here(owner)
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn gateway(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_GATEWAY, msg.into())
}

fn need_recipe(harness: &str) -> Res<crate::adapters::MachineLogin> {
    recipe(harness).ok_or_else(|| crate::bad("Only Claude Code and Codex log in. Pi and Hermes use API keys from secrets."))
}

fn need_isolation(app: &App) -> Res<Arc<crate::accounts::Isolation>> {
    app.isolation.get().cloned().ok_or_else(|| conflict("Per-user accounts are off."))
}

fn files(r: &crate::adapters::MachineLogin) -> Vec<String> {
    r.files.iter().map(|f| f.to_string()).collect()
}

/// Audit details for a teammate's login: whose, which account, and where.
fn details(space: Space, mut d: Value) -> Value {
    d["forUser"] = json!(space.teammate());
    d["account"] = json!(space.account());
    d["on"] = json!("server");
    d
}

fn line(e: &LoginEvent) -> Bytes {
    let mut v = serde_json::to_vec(e).unwrap_or_default();
    v.push(b'\n');
    Bytes::from(v)
}

/// Whether `harness` is logged in for `space`, checked as its account. None: it isn't,
/// or the account isn't there yet. Never makes the account.
async fn since(app: &App, space: Space<'_>, harness: &str) -> Result<Option<i64>, String> {
    let (Some(iso), Some(r)) = (app.isolation.get().cloned(), recipe(harness)) else { return Ok(None) };
    if !iso.ready_in(space) {
        return Ok(None);
    }
    let (Some(run_as), Some(home)) = (iso.run_as_in(space), iso.home_in(space)) else { return Ok(None) };
    let files = files(&r);
    tokio::task::spawn_blocking(move || run_as.login_since(&home, &files)).await.unwrap_or_else(|e| Err(e.to_string()))
}

/// A teammate's own logins for the owner's Bots here. Asking never makes their account.
/// `serverKey`: a server-wide key logs their runs in without one.
async fn view(app: &App, owner: &User, teammate: &str) -> Value {
    let space = Space::Teammate { owner: &owner.id, teammate };
    let ready = app.isolation().is_some_and(|i| i.ready_in(space));
    let running = app.teammate_logins.running(&owner.id, teammate);
    let mut harnesses = serde_json::Map::new();
    for n in crate::adapters::NAMES.iter().filter(|n| recipe(n).is_some()) {
        let at = match since(app, space, n).await {
            Ok(at) => at,
            Err(e) => {
                crate::obs::log::log_warn!("Teammate logins: couldn't check a {n} login as its account: {e}");
                None
            }
        };
        let state = match at {
            _ if running.iter().any(|h| h == n) => wire::LOGGING_IN,
            Some(_) => wire::LOGGED_IN,
            None => wire::LOGGED_OUT,
        };
        let keyed = crate::machines::logins::teammate_login_needed(n).is_none();
        harnesses.insert(n.to_string(), json!({ "state": state, "since": at, "serverKey": keyed }));
    }
    json!({
        "machineId": null, "on": "server", "owner": { "id": owner.id, "name": owner.name }, "forUser": teammate,
        "logins": "on", "hasUser": ready, "harnesses": harnesses,
    })
}

/// Starts the login as the teammate's account for the owner's Bots, making the account
/// if it's new, and streams what it shows back as JSON lines (`LoginEvent`s), the first
/// naming the login for `input`. If the caller goes away, the login is stopped.
pub async fn start(app: AppState, by: Who, owner: User, teammate: String, harness: String) -> Res<Response> {
    let r = need_recipe(&harness)?;
    let bin = crate::adapters::get(&harness).map(|a| a.bin()).ok_or_else(|| crate::bad("Unknown harness"))?;
    let iso = need_isolation(&app)?;
    let space = Space::Teammate { owner: &owner.id, teammate: &teammate };
    // Held until the login has started, so a removal (ADR 0066) stops it, never races it.
    let _in_use = crate::teammate_removals::enter(&app, &owner.id, &teammate).ok_or_else(|| conflict("Your account for these Bots on this server is being removed. Try again in a few minutes."))?;
    if !crate::teammate_removals::wanted(&app, &owner.id, &teammate) {
        return Err(crate::not_found("Machine"));
    }
    let run_as = app.ensure_space(space, &by).await.map_err(|e| gateway(format!("Couldn't set up your account on this server: {e}")))?;
    let (Some(home), Some(dir)) = (iso.home_in(space), space.dir()) else { return Err(crate::bad("Those ids can't name an account")) };
    let id = format!("l{}", crate::random_hex(8));
    let args: Vec<String> = r.args.iter().map(|a| a.to_string()).collect();
    let req = LoginRequest { login_id: id.clone(), harness: harness.clone(), args: args.clone(), files: files(&r), timeout_secs: LOGIN_SECS, for_user: Some(dir) };
    let (sudo, argv) = run_as.argv_strings(bin, args);
    let run = terminal::Command { bin: sudo, args: argv };
    // sudo resets PATH; superbot-run puts this one back, so the CLI is found as runs find it.
    let path = std::env::var("PATH").unwrap_or_else(|_| DEFAULT_PATH.into());
    let env = BTreeMap::from([("SUPERBOT_PATH".to_string(), path)]);
    let d = |extra: Value| {
        let mut d = details(space, json!({ "harness": harness, "loginId": id }));
        if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
            d.extend(x);
        }
        d
    };
    let event = |action: &str| by.event(action).target("user", &owner.id);
    let (mut rx, stop) = match app.teammate_logins.terminal.start(&req, &run, &home, &env, None) {
        Ok(started) => started,
        Err((code, why)) => {
            app.db.record(&event("harness.login_finished").outcome(Outcome::Failure).details(d(json!({ "loggedIn": false, "error": why }))));
            return Err(ApiError(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), why));
        }
    };
    app.teammate_logins.lock().insert(id.clone(), Session { owner: owner.id.clone(), teammate: teammate.clone(), harness: harness.clone() });
    app.db.record(&event("harness.login_started").details(d(json!({}))));
    let finished = d(json!({}));
    let (tx, out) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let (app2, by2, owner_id) = (app.clone(), by.clone(), owner.id.clone());
    tokio::spawn(async move {
        let app = app2;
        let mut gone = false;
        let mut end: Option<(bool, bool, String)> = None;
        while let Some(mut ev) = rx.recv().await {
            if let LoginEvent::Exit { success, logged_in, status } = &mut ev {
                // Checked as the account: botd may not see into its HOME.
                let space = Space::Teammate { owner: &owner_id, teammate: &teammate };
                *logged_in = matches!(since(&app, space, &harness).await, Ok(Some(_)));
                end = Some((*success, *logged_in, status.clone()));
            }
            if !gone && tx.send(Ok(line(&ev))).await.is_err() {
                gone = true;
                let _ = stop.send(true);
            }
        }
        let with = |mut d: Value, extra: Value| {
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
                d.extend(x);
            }
            d
        };
        let event = |action: &str| by2.event(action).target("user", &owner_id);
        match end {
            _ if gone => app.db.record(&event("harness.login_aborted").details(with(finished, json!({ "reason": "caller_left" })))),
            Some((success, logged_in, status)) => {
                let e = event("harness.login_finished").details(with(finished, json!({ "loggedIn": logged_in, "success": success, "status": status })));
                app.db.record(&if logged_in { e } else { e.outcome(Outcome::Failure) });
            }
            None => {
                let e = event("harness.login_finished").details(with(finished, json!({ "loggedIn": false, "error": "the login stopped without exiting" })));
                app.db.record(&e.outcome(Outcome::Failure));
            }
        }
        app.teammate_logins.lock().remove(&id);
    });
    Ok(([(header::CONTENT_TYPE, "application/x-ndjson")], Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(out))).into_response())
}

/// Types a line into a running login. What was typed is never kept or audited.
pub async fn input(app: AppState, by: Who, owner: User, teammate: String, id: String, text: String) -> Res<StatusCode> {
    let s = app.teammate_logins.get(&id, &owner.id, &teammate).ok_or_else(|| crate::not_found("Login"))?;
    app.teammate_logins
        .terminal
        .input(&id, &text)
        .map_err(|(code, why)| ApiError(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST), why))?;
    let space = Space::Teammate { owner: &owner.id, teammate: &teammate };
    let d = details(space, json!({ "harness": s.harness, "loginId": id, "chars": text.chars().count() }));
    app.db.record(&by.event("harness.login_input").target("user", &owner.id).details(d));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn abort(app: AppState, by: Who, owner: User, teammate: String, id: String) -> Res<StatusCode> {
    let s = app.teammate_logins.get(&id, &owner.id, &teammate).ok_or_else(|| crate::not_found("Login"))?;
    app.teammate_logins.terminal.abort(&id);
    let space = Space::Teammate { owner: &owner.id, teammate: &teammate };
    let d = details(space, json!({ "harness": s.harness, "loginId": id, "reason": "asked" }));
    app.db.record(&by.event("harness.login_aborted").target("user", &owner.id).details(d));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn status(app: AppState, owner: User, teammate: String) -> Res {
    need_isolation(&app)?;
    Ok(Json(view(&app, &owner, &teammate).await))
}

/// Logs the harness out for the teammate: its credential files are removed from their
/// account's HOME, as that account. Never while a login of it is running.
pub async fn logout(app: AppState, by: Who, owner: User, teammate: String, harness: String) -> Res {
    let r = need_recipe(&harness)?;
    let iso = need_isolation(&app)?;
    let space = Space::Teammate { owner: &owner.id, teammate: &teammate };
    if app.teammate_logins.running(&owner.id, &teammate).contains(&harness) {
        return Err(conflict(format!("A {harness} login is running. Stop it first.")));
    }
    let removed = match (iso.ready_in(space), iso.run_as_in(space), iso.home_in(space)) {
        (true, Some(run_as), Some(home)) => {
            let files = files(&r);
            tokio::task::spawn_blocking(move || run_as.forget(&home, &files))
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
                .map_err(|e| gateway(format!("Couldn't log {harness} out: {e}")))?
        }
        _ => 0,
    };
    let d = details(space, json!({ "harness": harness, "removed": removed }));
    app.db.record(&by.event("harness.logged_out").target("user", &owner.id).details(d));
    let mut v = view(&app, &owner, &teammate).await;
    v["removed"] = json!(removed);
    Ok(Json(v))
}
