//! Handing an existing Bot to one of its owner's service accounts to keep, and taking it
//! back (ADR 0229, on ADR 0222). The Bot stays its owner's (machine, plan, keys, memory);
//! the account manages it within its role, scopes and owner, as it does a Bot it made.
//! Only a person decides: the Bot's owner or an admin, never a service account or a Bot.

use crate::acl::Access;
use crate::audit::{Outcome, Who};
use crate::db::{self, KeepRefusal};
use crate::rbac::Principal;
use crate::service_accounts::{self, MAX_KEPT_BOTS};
use crate::users::Caller;
use crate::{bad, not_found, ApiError, AppState, Res};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

/// Whether `c` may choose which of `bot`'s owner's service accounts keeps it: a person
/// who is its owner or an admin. Teammates who can see or use the Bot can't: lending the
/// owner's keys and memory to automation is the owner's call.
fn may_decide(c: &Caller, bot: &db::Bot) -> bool {
    c.principal != Principal::Bot && c.service.is_none() && c.user.as_ref().is_none_or(|u| !u.service) && (c.admin() || c.user.as_ref().is_some_and(|u| u.id == bot.owner_id))
}

/// The owner's live service accounts that could keep `bot`, for those who may choose, so
/// the apps offer only those. `full`: it keeps as many Bots as one may already.
fn keepers(app: &AppState, bot: &db::Bot) -> Value {
    let list: Vec<Value> = app
        .db
        .service_accounts()
        .into_iter()
        .filter(|s| s.deleted_at.is_none() && s.owner_id == bot.owner_id)
        .map(|s| {
            let kept = app.db.kept_bots(&s.user.id).len();
            let keeps = bot.service_account_id.as_deref() == Some(s.user.id.as_str());
            json!({
                "id": s.user.id, "name": s.user.name, "role": s.user.role, "status": s.user.status,
                "keptBots": kept, "full": !keeps && kept >= MAX_KEPT_BOTS as usize,
            })
        })
        .collect();
    json!(list)
}

/// A Bot's access view (ADR 0017), with `keepers` and `maxKeptBots` for those who may
/// choose its keeper. A primary Bot has none: it stays its owner's own.
pub fn access_view(app: &AppState, c: &Caller, bot: &db::Bot, access: Access) -> Value {
    let mut v = crate::access_view(app, bot, access);
    if access == Access::Manage && may_decide(c, bot) && !bot.primary {
        v["keepers"] = keepers(app, bot);
        v["maxKeptBots"] = json!(MAX_KEPT_BOTS);
    }
    v
}

/// The owner's Bots `c` may hand to service account `sa` (ADR 0229), for its view: not
/// primary, not already its own, and ones `c` manages. `keptBy` names another account
/// that keeps one now; handing it over moves it.
pub fn keepable(app: &AppState, c: &Caller, by: &Who, sa: &db::ServiceAccount) -> Value {
    let viewer = crate::viewer(app, c, by);
    let list: Vec<Value> = app
        .db
        .bots()
        .into_iter()
        .filter(|b| b.owner_id == sa.owner_id && !b.primary && b.service_account_id.as_deref() != Some(sa.user.id.as_str()))
        .filter(|b| may_decide(c, b) && viewer.access(&app.db, b) == Access::Manage)
        .map(|b| {
            let kept_by = b.service_account_id.as_deref().and_then(|id| app.db.user(id)).map(|u| json!({ "id": u.id, "name": u.name }));
            json!({ "id": b.id, "name": b.name, "visibility": b.visibility, "keptBy": kept_by })
        })
        .collect();
    json!(list)
}

/// `PUT /api/bots/{id}/keeper` `{serviceAccount: <id>}`: one of the Bot owner's service
/// accounts keeps it from now on, taking over from any other, and its grant on the Bot
/// goes (keeping gives more). Owner or admin, with `manage` on the Bot.
pub async fn put(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    crate::need_user(c.principal)?;
    let (bot, _) = crate::need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let key = v["serviceAccount"].as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("serviceAccount must be a service account's id"))?;
    let refused = |reason: &str, extra: Value| {
        let mut d = json!({ "reason": reason, "serviceAccount": key, "owner": bot.owner_id });
        if let (Some(d), Value::Object(e)) = (d.as_object_mut(), extra) {
            d.extend(e);
        }
        app.db.record(&by.event("bot.keep_refused").target("bot", &id).bot(&id).outcome(Outcome::Denied).details(d));
    };
    if !may_decide(&c, &bot) {
        refused("not_owner", json!({}));
        return Err(ApiError(StatusCode::FORBIDDEN, "Only the Bot's owner or an admin can choose which service account keeps it.".into()));
    }
    if bot.primary {
        refused("primary_bot", json!({}));
        return Err(ApiError(StatusCode::CONFLICT, "A primary Bot stays its owner's own. Hand over another Bot, or let the service account make one.".into()));
    }
    let Some(sa) = app.db.service_account(key).filter(|s| s.deleted_at.is_none()) else {
        if app.db.find_user(key).is_some() {
            return Err(bad("That's a person. Only a service account keeps a Bot; give a person the Bot or a grant instead."));
        }
        return Err(not_found("Service account"));
    };
    if sa.owner_id != bot.owner_id {
        refused("service_account_owner", json!({ "accountOwner": sa.owner_id }));
        // Only admins learn that someone else's account exists.
        return Err(if c.admin() { ApiError(StatusCode::CONFLICT, "That service account isn't the Bot owner's. A service account keeps only its own owner's Bots.".into()) } else { not_found("Service account") });
    }
    let Some(handed) = crate::erasure::unless_erasing(&[&bot.owner_id], || app.db.keep_bot(&id, &bot.owner_id, &sa.user.id, MAX_KEPT_BOTS)) else {
        return Err(ApiError(StatusCode::CONFLICT, "Its owner is being erased. Try again once that's done.".into()));
    };
    let handed = handed.map_err(|why| match why {
        KeepRefusal::Limit => {
            refused("service_account_bot_limit", json!({ "limit": MAX_KEPT_BOTS }));
            ApiError(StatusCode::CONFLICT, format!("{} keeps {MAX_KEPT_BOTS} Bots already, as many as a service account may. Let one go first.", sa.user.name))
        }
        KeepRefusal::Account => {
            refused("service_account_changed", json!({}));
            ApiError(StatusCode::CONFLICT, "That service account was deleted or given another owner meanwhile.".into())
        }
        KeepRefusal::Bot => {
            refused("bot_changed", json!({}));
            ApiError(StatusCode::CONFLICT, "This Bot was deleted or given another owner meanwhile.".into())
        }
    })?;
    if handed.from.as_deref() != Some(sa.user.id.as_str()) {
        // The account it took over from stops keeping it, and the run it has going there
        // (with the owner's keys) stops.
        if let Some(from) = &handed.from {
            service_accounts::note_released(&app, &by, from, std::slice::from_ref(&id), "reassigned");
        }
        let details = json!({ "serviceAccount": sa.user.id, "name": sa.user.name, "owner": bot.owner_id, "from": handed.from, "grantRemoved": handed.grant });
        app.db.record(&by.event("bot.service_account_assigned").target("bot", &id).bot(&id).details(details));
        crate::acl_changed(&app, &by, &id, handed.from.is_some()).await;
    }
    let after = crate::need_bot(&app, &id)?;
    let access = crate::viewer(&app, &c, &by).access(&app.db, &after);
    Ok(Json(access_view(&app, &c, &after, access)))
}

/// `DELETE /api/bots/{id}/keeper`: the service account keeping it stops; the Bot stays its
/// owner's, and the run the account has going there stops. Owner or admin: letting go only
/// narrows, so it needs no more than seeing the Bot.
pub async fn delete(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    crate::need_user(c.principal)?;
    let (bot, _) = crate::need_bot_access(&app, &c, &by, &id, Access::View)?;
    if !may_decide(&c, &bot) {
        let d = json!({ "reason": "not_owner", "serviceAccount": bot.service_account_id, "owner": bot.owner_id });
        app.db.record(&by.event("bot.keep_refused").target("bot", &id).bot(&id).outcome(Outcome::Denied).details(d));
        return Err(ApiError(StatusCode::FORBIDDEN, "Only the Bot's owner or an admin can take it from a service account.".into()));
    }
    let sa = bot.service_account_id.clone().filter(|sa| app.db.release_kept_bot(&id, sa)).ok_or_else(|| not_found("Service account keeping this Bot"))?;
    service_accounts::note_released(&app, &by, &sa, std::slice::from_ref(&id), "released");
    crate::acl_changed(&app, &by, &id, true).await;
    let after = crate::need_bot(&app, &id)?;
    let access = crate::viewer(&app, &c, &by).access(&app.db, &after);
    Ok(Json(access_view(&app, &c, &after, access)))
}
