//! Erasing a user's personal data on request (GDPR article 17; SOC 2 CC6.5-1). An admin
//! erases a user with `POST /api/users/{key}/erase` (`botctl user erase`): their Bots with
//! their chats, routines and approvals, their sign-ins, second factor, sealed secrets and
//! files in botd's folders go; what they wrote in others' chats is replaced; the user row
//! stays as a tombstone with no personal data; and every audit event about them names
//! them by a pseudonym instead. A legal hold on chat they're in, a team they're the
//! only owner of, a plan they pay for, or a machine not yet destroyed refuses it first.
//! Design: docs/adr/0102-erasing-a-users-data.md.

use crate::audit::{Outcome, Who};
use crate::db::{EraseError, UserPatch};
use crate::users::{self, OPERATOR};
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

/// Why an erasure was refused, in `user.erase_refused`.
const HELD: &str = "legal_hold";
const LAST_OWNER: &str = "last_team_owner";
const PAYING: &str = "paying";
const TEAM_PAYS: &str = "team_pays";
const CHECKOUT_PAID: &str = "checkout_paid";
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

/// `POST /api/users/{key}/erase` `{destroyMachine?: bool}` (send `{}` for none). Admin-only (`rbac::classify`).
/// Erasing someone already erased answers as the first time did, and changes nothing.
pub async fn erase(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
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
    // Bots deleted by an erasure that stopped part way still count, so what they wrote in
    // others' chats is erased when it is retried.
    let owned = |app: &AppState| -> Vec<crate::db::Bot> { app.db.bots().into_iter().filter(|b| b.owner_id == u.id).collect() };
    let mut bots = owned(&app);
    let mut bot_ids = app.db.erasing_bots(&u.id);
    add_new(&mut bot_ids, &bots);
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
    if let Some(m) = app.db.team_member(&u.id).filter(|m| app.db.team_members(&m.team_id).len() == 1)
        && let Some(s) = app.db.team_paying(&m.team_id)
    {
        let msg = "They're the last member of a team that pays for a plan, which would go with them. Cancel the team's plan first.".into();
        return refuse(TEAM_PAYS, json!({ "team": m.team_id, "subscription": s.subscription_id }), msg);
    }
    // A checkout page still open could be paid after they're gone. The lock is checkout's
    // own, held until the erasure ends; by then they can't sign in to open another.
    let _checkout = match a.payments.checkout() {
        Some(co) => {
            let guard = co.lock(&u.id).lock_owned().await;
            match crate::billing::close_last(&app, &co.stripe, crate::billing::Payer::User(&u.id)).await {
                crate::billing::Last::Closed => {}
                crate::billing::Last::Paid => {
                    return refuse(CHECKOUT_PAID, json!({}), "Their last checkout was paid; a plan is on the way. Cancel it once it starts, then erase them.".into());
                }
                crate::billing::Last::Unknown(e) => {
                    crate::obs::log::log_warn!("erasure: closing {}'s last Stripe checkout: {e}", u.id);
                    return Err(ApiError(StatusCode::BAD_GATEWAY, "Stripe couldn't say whether their open checkout was paid. Try again in a minute.".into()));
                }
            }
            Some(guard)
        }
        None => None,
    };
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
    // Disabled now, so they can't make more Bots; take any made while the machine went.
    bots = owned(&app);
    add_new(&mut bot_ids, &bots);
    let held = app.db.erasure_holds(&u.id, &bot_ids);
    if !held.is_empty() {
        return Err(conflict(format!("The chat of {} was held meanwhile. Release the hold, then erase them again.", held.join(", "))));
    }
    app.db.set_erasing_bots(&u.id, &bot_ids);
    // Runs record their end as whoever asked, so they must be over before the log is rewritten.
    let mut stopping: Vec<String> = bots.iter().map(|b| b.id.clone()).collect();
    for bot in app.db.bots() {
        if bot.owner_id != u.id && app.live_run(&bot.id).is_some() && app.requested_by(&bot) == u.id {
            stopping.push(bot.id.clone());
        }
    }
    for id in &stopping {
        app.stop(id);
    }
    if !settled(&app, &stopping).await {
        return Err(conflict("Runs they started are still stopping. Erase them again in a minute."));
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
        files += usize::from(remove(app.bot_dir(&b.id))?);
    }
    crate::machines::offboard::check_owner(&app, &by, &u.id);
    let secrets = crate::secrets::global().user_forget(&u.id).map_err(crate::secret_error)?;
    let users_dir = |root: &std::path::Path| crate::paths::child(&crate::paths::child(&crate::paths::canonical(root)?, crate::isolation::USERS)?, &u.id);
    files += usize::from(remove(users_dir(&app.cfg.data_dir))?);
    let isolation_left = match app.isolation() {
        None => {
            files += usize::from(remove(users_dir(&app.cfg.workspace))?);
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

/// Deletes a folder of botd's own. Whether there was one. A folder it can't delete stops
/// the erasure before anything is marked erased, so trying again tries it again.
fn remove(dir: Option<std::path::PathBuf>) -> Res<bool> {
    let Some(d) = dir.filter(|d| d.is_dir()) else {
        return Ok(false);
    };
    std::fs::remove_dir_all(&d).map(|_| true).map_err(|e| {
        crate::obs::log::log_warn!("erasure: deleting {}: {e}", d.display());
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "A folder of theirs couldn't be deleted; see the server log. Nothing is marked erased yet, so erase them again once it's fixed.".into())
    })
}

fn add_new(ids: &mut Vec<String>, bots: &[crate::db::Bot]) {
    for b in bots {
        if !ids.contains(&b.id) {
            ids.push(b.id.clone());
        }
    }
}

/// Whether every run on `bots` has ended, waiting up to 30 seconds.
async fn settled(app: &AppState, bots: &[String]) -> bool {
    for _ in 0..300 {
        if bots.iter().all(|b| app.live_run(b).is_none()) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
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
