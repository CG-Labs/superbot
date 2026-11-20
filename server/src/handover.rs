//! A disabled user's routines and Bots (SCIM-05). Disabling someone, by an admin,
//! `botctl`, or SCIM, pauses every routine that runs on their behalf: on their Bots, or
//! written by them. The scheduler and the runner refuse a routine whose owner or author
//! is disabled anyway. Paused routines come back only when an admin resumes them (or
//! with `ROUTINES_ON_ENABLE=resume`), and an admin can hand a disabled user's Bots and
//! routines to someone else. Design: docs/adr/0047-disabled-users-routines.md.

use crate::acl::{Access, Viewer};
use crate::audit::{Outcome, Who};
use crate::db::{self, Db, Routine, User};
use crate::rbac::Role;
use crate::runner::App;
use crate::users::need_user_key;
use crate::{bad, not_found, ApiError, AppState, Res};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const OWNER_DISABLED: &str = "owner_disabled";
pub const AUTHOR_DISABLED: &str = "author_disabled";

/// `ROUTINES_ON_ENABLE`: `paused` (default) keeps a re-enabled user's routines paused
/// until an admin resumes them; `resume` turns them back on with the user.
pub fn resume_on_enable(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "paused" => Ok(false),
        "resume" => Ok(true),
        _ => Err(format!("ROUTINES_ON_ENABLE must be paused or resume, not \"{raw}\"")),
    }
}

/// Whose disabled account stops a routine now: its Bot's owner first, then whoever
/// wrote its instruction (whom its runs are for, ADR 0046). A user who is gone counts
/// as disabled.
pub fn blocked(db: &Db, owner: &str, author: Option<&str>) -> Option<(&'static str, String)> {
    let off = |id: &str| !db.user(id).is_some_and(|u| u.active());
    if off(owner) {
        return Some((OWNER_DISABLED, owner.to_string()));
    }
    author.filter(|a| off(a)).map(|a| (AUTHOR_DISABLED, a.to_string()))
}

/// Pauses one routine for `user` and audits it. False when it was already off.
pub fn pause(app: &App, by: &Who, r: &Routine, reason: &str, user: &str) -> bool {
    if !app.db.pause_routine(&r.id, reason, user, db::now()) {
        return false;
    }
    let details = json!({ "name": r.name, "reason": reason, "forUser": user });
    app.db.record(&by.event("routine.paused").target("routine", &r.id).bot(&r.bot_id).details(details));
    true
}

/// Every routine that runs on `user`'s behalf, with why: on a Bot they own, or written
/// by them on someone else's.
fn on_behalf_of(app: &App, user: &str) -> Vec<(Routine, &'static str)> {
    let owners: HashMap<String, String> = app.db.bots().into_iter().map(|b| (b.id, b.owner_id)).collect();
    app.db
        .routines(None)
        .into_iter()
        .filter_map(|r| {
            let reason = if owners.get(&r.bot_id).map(String::as_str) == Some(user) {
                OWNER_DISABLED
            } else if r.author_id.as_deref() == Some(user) {
                AUTHOR_DISABLED
            } else {
                return None;
            };
            Some((r, reason))
        })
        .collect()
}

/// `user` was just disabled: pause each routine of theirs that is on. Returns how many.
pub fn user_disabled(app: &App, by: &Who, user: &str) -> usize {
    on_behalf_of(app, user).into_iter().filter(|(r, _)| r.enabled).filter(|(r, reason)| pause(app, by, r, reason, user)).count()
}

/// Pauses the routines of users who were disabled before botd paused routines on
/// disable (an upgrade), so re-enabling them later can't restart those unasked.
pub fn pause_already_disabled(app: &App, by: &Who) -> usize {
    app.db.users().into_iter().filter(|u| !u.active()).map(|u| user_disabled(app, by, &u.id)).sum()
}

/// `user` was just enabled: their paused routines stay paused unless the server says
/// otherwise. Returns how many were resumed.
pub fn user_enabled(app: &App, by: &Who, user: &str) -> usize {
    if app.resume_routines_on_enable.get() != Some(&true) {
        return 0;
    }
    resume(app, by, app.db.routines_paused_for(user), "user_enabled").len()
}

/// Turns paused routines back on, each only if no one it runs for is disabled now; one
/// that still is stays paused, now for that person. Returns those resumed.
fn resume(app: &App, by: &Who, routines: Vec<Routine>, why: &str) -> Vec<Routine> {
    let mut out = Vec::new();
    for r in routines {
        let Some(owner) = app.db.bot_owner(&r.bot_id) else { continue };
        if let Some((reason, user)) = blocked(&app.db, &owner, r.author_id.as_deref()) {
            app.db.repause_routine(&r.id, reason, &user);
            continue;
        }
        if app.db.resume_routine(&r.id) {
            let details = json!({ "name": r.name, "reason": why, "pausedFor": r.paused_for, "pausedReason": r.paused_reason });
            app.db.record(&by.event("routine.resumed").target("routine", &r.id).bot(&r.bot_id).details(details));
            out.extend(app.db.routine(&r.id));
        }
    }
    out
}

fn routine_view(app: &App, r: &Routine) -> Value {
    let bot = app.db.bot(&r.bot_id);
    json!({
        "id": r.id, "name": r.name, "cron": r.cron, "enabled": r.enabled,
        "bot": bot.map(|b| json!({ "id": b.id, "name": b.name, "ownerId": b.owner_id })),
        "authorId": r.author_id, "pausedReason": r.paused_reason, "pausedFor": r.paused_for, "pausedAt": r.paused_at,
    })
}

/// `GET /api/users/{key}/routines`: every routine that runs on this user's behalf, and
/// which are paused for them.
pub async fn list(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    let mut list: Vec<Routine> = on_behalf_of(&app, &u.id).into_iter().map(|(r, _)| r).collect();
    for r in app.db.routines_paused_for(&u.id) {
        if !list.iter().any(|x| x.id == r.id) {
            list.push(r);
        }
    }
    Ok(Json(json!({ "user": crate::users::user_view(&u), "routines": list.iter().map(|r| routine_view(&app, r)).collect::<Vec<_>>() })))
}

/// `POST /api/users/{key}/routines/resume`: turns back on the routines paused for this
/// user, now that they are enabled again.
pub async fn resume_for(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    if !u.active() {
        return Err(ApiError(StatusCode::CONFLICT, format!("{} is disabled. Enable them first, or hand their Bots over.", u.name)));
    }
    let paused = app.db.routines_paused_for(&u.id);
    let resumed = resume(&app, &by, paused.clone(), "admin");
    let kept: Vec<Value> = paused.iter().filter(|r| !resumed.iter().any(|x| x.id == r.id)).filter_map(|r| app.db.routine(&r.id)).map(|r| routine_view(&app, &r)).collect();
    Ok(Json(json!({ "resumed": resumed.iter().map(|r| routine_view(&app, r)).collect::<Vec<_>>(), "stillPaused": kept })))
}

/// `POST /api/users/{key}/handover {to, resumeRoutines?}`: gives a disabled user's Bots
/// to `to`, and moves the routines they wrote (and the pauses held for them) to `to`
/// where `to` can run that Bot. Routines stay paused unless `resumeRoutines` is true.
pub async fn handover(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
    let from = need_user_key(&app, &key)?;
    let to_key = v["to"].as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("to must be a user id or email"))?;
    let resume_now = match &v["resumeRoutines"] {
        Value::Null => false,
        Value::Bool(b) => *b,
        _ => return Err(bad("resumeRoutines must be true or false")),
    };
    let to = app.db.find_user(to_key).ok_or_else(|| not_found("User"))?;
    check(&from, &to)?;
    let bots: Vec<db::Bot> = app.db.bots().into_iter().filter(|b| b.owner_id == from.id).collect();
    let tier = app.tier_of(&to.id);
    if let Some(max) = tier.limits.max_bots {
        let have = app.db.bots().iter().filter(|b| b.owner_id == to.id).count();
        if have + bots.len() > max as usize {
            let details = json!({ "reason": "tier_bot_limit", "to": to.id, "bots": bots.len(), "has": have, "tier": tier.name, "limit": max });
            app.db.record(&by.event("user.handover_refused").target("user", &from.id).outcome(Outcome::Denied).details(details));
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                format!("{}'s plan ({}) allows {max} Bots; they have {have}, and {} has {}.", to.name, tier.label, from.name, bots.len()),
            ));
        }
    }
    // A refusal midway (someone took a slot meanwhile) still moves the routines of the
    // Bots already given, so none is left with the new owner but held for the old.
    let (mut moved, mut refused) = (Vec::new(), None);
    for b in &bots {
        if let Err(e) = crate::give_bot(&app, &by, b, &to).await {
            refused = Some(e);
            break;
        }
        moved.push(b.id.clone());
    }
    let viewer = Viewer::person(&app.db, &to.id);
    let (mut routines, mut skipped) = (Vec::new(), Vec::new());
    for r in app.db.routines(None).into_iter().filter(|r| r.author_id.as_deref() == Some(&from.id) || r.paused_for.as_deref() == Some(&from.id)) {
        let can = app.db.bot(&r.bot_id).is_some_and(|b| viewer.access(&app.db, &b) >= Access::Operate);
        if !can {
            skipped.push(r.id);
            continue;
        }
        app.db.hand_over_routine(&r.id, &from.id, &to.id);
        let details = json!({ "name": r.name, "from": from.id, "to": to.id, "paused": !r.enabled && r.paused_reason.is_some() });
        app.db.record(&by.event("routine.handed_over").target("routine", &r.id).bot(&r.bot_id).details(details));
        routines.push(r.id);
    }
    if let Some(e) = refused {
        record(&app, &by, &from, &to, &moved, &routines, &skipped, &[]);
        return Err(e);
    }
    let resumed: Vec<String> = if resume_now {
        let paused = routines.iter().filter_map(|id| app.db.routine(id)).filter(|r| r.paused_for.as_deref() == Some(&to.id)).collect();
        resume(&app, &by, paused, "handover").into_iter().map(|r| r.id).collect()
    } else {
        Vec::new()
    };
    record(&app, &by, &from, &to, &moved, &routines, &skipped, &resumed);
    Ok(Json(json!({ "from": from.id, "to": to.id, "bots": moved, "routines": routines, "skipped": skipped, "resumed": resumed })))
}

/// Who can hand over to whom: from a disabled user to an active one who can run Bots.
fn check(from: &User, to: &User) -> Res<()> {
    if from.active() {
        return Err(ApiError(StatusCode::CONFLICT, format!("{} is active. Hand over a disabled user's Bots; give one Bot away from its access settings.", from.name)));
    }
    if to.id == from.id {
        return Err(bad("Hand over to someone else"));
    }
    if !to.active() {
        return Err(bad("That user is disabled"));
    }
    if to.role == Role::Readonly {
        return Err(bad("That user is read-only, so they can't run Bots or routines"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record(app: &App, by: &Who, from: &User, to: &User, bots: &[String], routines: &[String], skipped: &[String], resumed: &[String]) {
    let details = json!({ "to": to.id, "bots": bots, "routines": routines, "skipped": skipped, "resumed": resumed });
    app.db.record(&by.event("user.handed_over").target("user", &from.id).details(details));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_enable_flag() {
        assert_eq!(resume_on_enable(""), Ok(false));
        assert_eq!(resume_on_enable("paused"), Ok(false));
        assert_eq!(resume_on_enable(" Resume "), Ok(true));
        assert!(resume_on_enable("yes").is_err());
    }
}
