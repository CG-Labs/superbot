//! Erasing a user's personal data on request (GDPR article 17; SOC 2 CC6.5-1). An admin
//! erases a user with `POST /api/users/{key}/erase` (`botctl user erase`): their Bots with
//! their chats, routines and approvals, their sign-ins, second factor, sealed secrets and
//! files in botd's folders go; what they wrote in others' chats is replaced; the user row
//! stays as a tombstone with no personal data; and every audit event about them names
//! them by a pseudonym instead. A legal hold on chat they're in, a team they're the
//! only owner of, a plan they pay for, or a machine not yet destroyed refuses it first.
//! Design: docs/adr/0100-erasing-a-users-data.md.

use crate::audit::{Outcome, Who};
use crate::db::{EraseError, UserPatch};
use crate::users::{self, OPERATOR};
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

/// Why an erasure was refused, in `user.erase_refused`.
const HELD: &str = "legal_hold";
const LAST_OWNER: &str = "last_team_owner";
const PAYING: &str = "paying";
const MACHINE: &str = "machine";
const PRIMARY: &str = "primary_bot";
/// The reason Bots, grants and offboarding record for an erasure.
const REASON: &str = "user_erased";

/// One erasure at a time, so two requests for one user can't both run its steps.
static ERASING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// A new pseudonym: `erased-` and 64 random bits as hex.
pub fn pseudonym() -> String {
    format!("erased-{}", crate::random_hex(8))
}

/// `POST /api/users/{key}/erase` `{destroyMachine?: bool}`. Admin-only (`rbac::classify`).
/// Erasing someone already erased answers as the first time did, and changes nothing.
pub async fn erase(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, body: Bytes) -> Res {
    let v: Value = if body.iter().all(u8::is_ascii_whitespace) { Value::Null } else { serde_json::from_slice(&body).map_err(|e| bad(format!("Invalid JSON: {e}")))? };
    let destroy_machine = match &v["destroyMachine"] {
        Value::Null => false,
        Value::Bool(b) => *b,
        _ => return Err(bad("destroyMachine must be true or false")),
    };
    let _one = ERASING.lock().await;
    let u = app.db.find_user_any(&key).ok_or_else(|| not_found("User"))?;
    if u.erased_at.is_some() {
        return Ok(Json(json!({ "erased": true, "already": true, "pseudonym": u.erased_as, "user": users::user_view(&u) })));
    }
    if u.id == OPERATOR {
        return Err(conflict("The owner (break-glass) account can't be erased: it is the way back in."));
    }
    if by.actor.id.as_deref() == Some(u.id.as_str()) {
        return Err(conflict("You can't erase yourself. Ask another admin."));
    }
    let refuse = |reason: &str, details: Value, msg: String| {
        let mut d = details;
        d["reason"] = json!(reason);
        app.db.record(&by.event("user.erase_refused").target("user", &u.id).details(d).outcome(Outcome::Denied));
        Err(conflict(msg))
    };
    let bots: Vec<crate::db::Bot> = app.db.bots().into_iter().filter(|b| b.owner_id == u.id).collect();
    let bot_ids: Vec<String> = bots.iter().map(|b| b.id.clone()).collect();
    let held = app.db.erasure_holds(&u.id, &bot_ids);
    if !held.is_empty() {
        let msg = format!("They're under a legal hold: the chat of {} is held, and they or their Bots are in it. Release the hold first (botctl retention release <bot>).", held.join(", "));
        return refuse(HELD, json!({ "bots": held }), msg);
    }
    if let Some(team) = crate::teams::last_owner_of(&app, &u.id) {
        return refuse(LAST_OWNER, json!({ "team": team }), "They're their team's only owner. Make someone else an owner first, or delete the team.".into());
    }
    if let Some(s) = app.db.user_paying(&u.id) {
        return refuse(PAYING, json!({ "subscription": s.subscription_id }), "They pay for a plan. Cancel it in the billing portal first; they can be erased once it has ended.".into());
    }
    if let Some(b) = bots.iter().find(|b| b.primary) {
        return refuse(PRIMARY, json!({ "bot": b.id }), "They own the primary Bot, which can't be deleted. Give it to someone else first.".into());
    }
    let mut machine = Value::Null;
    if let Some(m) = app.db.user_machine(&u.id) {
        if !destroy_machine {
            let msg = format!("They have a machine ({}). Destroy it first (botctl machine destroy {}), or erase with destroyMachine: true (botctl user erase {} --destroy-machine --yes).", m.state.as_str(), u.id, u.id);
            return refuse(MACHINE, json!({ "machine": m.id, "state": m.state.as_str() }), msg);
        }
        crate::machines::destroy_as(&app, &a.machines, &by, &u.id, &|_| true).await?;
        if let Some(m) = app.db.user_machine(&u.id) {
            return Err(conflict(format!("Their machine is {} now. Erase them again once it is destroyed.", m.state.as_str())));
        }
        machine = json!({ "id": m.id, "destroyed": true });
    }

    let team = crate::teams::erase_member(&app, &by, &u.id).await?;
    if u.active() {
        app.db.update_user(&u.id, UserPatch { status: Some("disabled"), ..Default::default() }).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        users::disabled(&app, &a, &by, &u.id);
        users::lost_access(&app, &by, &u.id, crate::machines::offboard::DELETED).await;
    } else {
        a.sso.forget_user(&u.id);
        a.mfa.forget_user(&u.id);
    }
    for bot in app.db.bots() {
        if bot.owner_id != u.id && app.live_run(&bot.id).is_some() && app.requested_by(&bot) == u.id {
            app.stop(&bot.id);
        }
    }
    let mut grants = 0;
    for (bot_id, level) in app.db.user_grants(&u.id) {
        if app.db.remove_grant(&bot_id, &u.id).is_some() {
            grants += 1;
            let d = json!({ "user": u.id, "level": level, "reason": REASON });
            app.db.record(&by.event("bot.access_revoked").target("bot", &bot_id).bot(&bot_id).details(d));
            crate::acl_changed(&app, &by, &bot_id, true).await;
        }
    }
    let mut files = 0;
    for b in &bots {
        app.stop(&b.id);
        if let Some(screens) = &app.screens {
            screens.remove(&b.id).await;
        }
        crate::machines::screens::close(&app, &by, &b.id, REASON).await;
        if !app.db.delete_bot_unless_held(&b.id) {
            if app.db.bot_chat_held(&b.id) {
                return Err(conflict(format!("The chat of {} was held meanwhile. Release the hold, then erase them again.", b.id)));
            }
            continue;
        }
        crate::notify::forget_bot(&app, &b.id);
        app.db.record(&by.event("bot.deleted").target("bot", &b.id).bot(&b.id).details(json!({ "name": b.name, "harness": b.harness, "reason": REASON })));
        app.send(json!({ "type": "botDeleted", "botId": b.id }));
        files += usize::from(remove(app.bot_dir(&b.id)));
    }
    crate::machines::offboard::check_owner(&app, &by, &u.id);
    let secrets = crate::secrets::global().user_forget(&u.id).map_err(crate::secret_error)?;
    let users_dir = |root: &std::path::Path| crate::paths::child(&crate::paths::child(&crate::paths::canonical(root)?, crate::isolation::USERS)?, &u.id);
    files += usize::from(remove(users_dir(&app.cfg.data_dir)));
    let isolation_left = match app.isolation() {
        None => {
            files += usize::from(remove(users_dir(&app.cfg.workspace)));
            false
        }
        Some(iso) => iso.user_root(&u.id).is_some_and(|d| d.exists()),
    };

    let p = pseudonym();
    let erased = match app.db.erase_user(&u.id, &p, by.actor.id.as_deref(), &bot_ids) {
        Ok(e) => e,
        Err(EraseError::Gone) => return Err(not_found("User")),
        Err(EraseError::Held(b)) => {
            return Err(conflict(format!("The chat of {} was held meanwhile. Release the hold, then erase them again.", b.join(", "))));
        }
        Err(EraseError::Db(e)) => return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)),
    };
    let mut details = serde_json::to_value(&erased).unwrap_or_default();
    details["pseudonym"] = json!(p);
    details["bots"] = json!(bot_ids.len());
    details["grants"] = json!(erased.grants + grants);
    details["secrets"] = json!(secrets);
    details["files"] = json!(files);
    details["isolationFolderLeft"] = json!(isolation_left);
    details["machine"] = machine;
    details["team"] = json!(team);
    app.db.record(&by.event("user.erased").target("user", &p).details(details.clone()));
    app.send(json!({ "type": "resync" }));
    let u = app.db.user(&u.id).ok_or_else(|| not_found("User"))?;
    Ok(Json(json!({ "erased": true, "already": false, "pseudonym": p, "user": users::user_view(&u), "removed": details })))
}

/// Deletes a folder of botd's own. Whether there was one.
fn remove(dir: Option<std::path::PathBuf>) -> bool {
    dir.filter(|d| d.is_dir()).is_some_and(|d| std::fs::remove_dir_all(d).is_ok())
}

#[cfg(test)]
mod tests {
    use crate::db::Scrub;
    use serde_json::json;

    #[test]
    fn scrub_replaces_ids_emails_and_exact_names() {
        let s = Scrub::new("u1a2b3c4d", "erased-00", vec!["Ada@Example.com".into()], vec!["Ada Lovelace".into(), "x".into()]);
        assert_eq!(s.text("u1a2b3c4d").as_deref(), Some("erased-00"));
        assert_eq!(s.text("users/u1a2b3c4d/machine").as_deref(), Some("users/erased-00/machine"));
        assert_eq!(s.text("invited ADA@example.COM to t1").as_deref(), Some("invited erased-00 to t1"));
        assert_eq!(s.text(" ada lovelace ").as_deref(), Some("erased-00"));
        assert_eq!(s.text("Ada Lovelace's Bot"), None, "names only whole");
        assert_eq!(s.text("x"), None, "one letter is no name");
        assert_eq!(s.text("member"), None);
        assert_eq!(s.text("ädä@example.com ada@example.com").as_deref(), Some("erased-00"), "outside ASCII, the whole string");
        let mut v = json!({ "user": "u1a2b3c4d", "email": "ada@example.com", "name": "Ada Lovelace", "role": "member", "n": 3, "list": ["Ada Lovelace", "b"] });
        assert!(s.value(&mut v));
        assert_eq!(v, json!({ "user": "erased-00", "email": "erased-00", "name": "erased-00", "role": "member", "n": 3, "list": ["erased-00", "b"] }));
        assert!(!s.value(&mut json!({ "role": "member" })));
    }

    #[test]
    fn pseudonyms_are_random_and_plain() {
        let (a, b) = (super::pseudonym(), super::pseudonym());
        assert_ne!(a, b);
        assert!(a.starts_with("erased-") && a.len() == 7 + 16 && a[7..].bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
    }
}
