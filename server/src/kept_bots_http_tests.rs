//! Handing an existing Bot to one of its owner's service accounts, and taking it back
//! (ADR 0229), on the real router: only the Bot's owner or an admin decides, only for the
//! owner's own live accounts, within the per-account limit; the account then manages it as
//! one it made (ADR 0222), and loses it, with its run there, when it's taken back or moved.

use crate::acl::{Grant, Visibility};
use crate::service_accounts_http_tests::{account, role, token};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// A member service account owned by `owner_id`, and a token for it.
async fn owned(port: u16, admin: &str, owner_id: &str, name: &str) -> (String, String) {
    let sa = account(port, admin, json!({ "name": name, "role": "member" })).await;
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{sa}"), admin, &json!({ "owner": owner_id }).to_string()).await;
    assert_eq!(code, 200, "{v}");
    let (tok, _) = token(port, admin, &sa, json!({})).await;
    (sa, tok)
}

async fn bot(port: u16, who: &str, name: &str, visibility: &str) -> String {
    let (code, v) = json_call(port, "POST", "/api/bots", who, &json!({ "name": name, "visibility": visibility }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn keep(port: u16, who: &str, bot: &str, sa: &str) -> (u16, Value) {
    json_call(port, "PUT", &format!("/api/bots/{bot}/keeper"), who, &json!({ "serviceAccount": sa }).to_string()).await
}

fn access_of(list: &Value, bot: &str) -> Option<String> {
    list.as_array().unwrap().iter().find(|b| b["id"] == bot).and_then(|b| b["access"].as_str()).map(String::from)
}

fn ids(list: &Value) -> Vec<&str> {
    list.as_array().map(|a| a.iter().filter_map(|b| b["id"].as_str()).collect()).unwrap_or_default()
}

async fn digest(port: u16, admin: &str) -> String {
    let (code, v) = json_call(port, "GET", "/api/access-review", admin, "").await;
    assert_eq!(code, 200, "{v}");
    v["digest"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn an_owner_hands_an_existing_bot_to_their_service_account_and_takes_it_back() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (sa, tok) = owned(port, &admin, &ana, "Ana's CI").await;
    let ledger = bot(port, &ana_auth, "Ledger", "private").await;
    let notes = bot(port, &ana_auth, "Notes", "private").await;
    let main = app.db.create_bot_owned("Ana's own", "#fff", "waddle", "claude", None, true, &ana, Visibility::Private).id;

    // Ana sees which of her accounts could keep it; her primary Bot offers none.
    let (_, v) = json_call(port, "GET", &format!("/api/bots/{ledger}/access"), &ana_auth, "").await;
    assert_eq!(v["keepers"], json!([{ "id": sa, "name": "Ana's CI", "role": "member", "status": "active", "keptBots": 0, "full": false }]), "{v}");
    assert_eq!(v["maxKeptBots"], json!(service_accounts::MAX_KEPT_BOTS));
    let (_, v) = json_call(port, "GET", &format!("/api/bots/{main}/access"), &ana_auth, "").await;
    assert!(v.get("keepers").is_none(), "{v}");

    // Granted operator, it runs Ledger but can't change it.
    assert_eq!(call(port, "PUT", &format!("/api/bots/{ledger}/grants/{sa}"), &ana_auth, r#"{"level":"operator"}"#).await.0, 200);
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    assert_eq!(access_of(&list, &ledger).as_deref(), Some("operate"), "{list}");
    let before = digest(port, &admin).await;

    // Handed to it, it keeps and manages Ledger; its grant goes; it stays Ana's and private.
    let (code, v) = keep(port, &ana_auth, &ledger, &sa).await;
    assert_eq!((code, v["serviceAccount"]["id"].as_str()), (200, Some(sa.as_str())), "{v}");
    assert_eq!(v["keepers"][0]["keptBots"], json!(1), "{v}");
    let b = app.db.bot(&ledger).unwrap();
    assert_eq!((b.owner_id.as_str(), b.service_account_id.as_deref(), b.visibility), (ana.as_str(), Some(sa.as_str()), Visibility::Private));
    assert_eq!(app.db.grant(&ledger, &sa), None::<Grant>);
    let made = events(port, &admin, "bot.service_account_assigned").await;
    assert_eq!(made.len(), 1, "{made:?}");
    assert_eq!(
        (made[0]["actorId"].as_str(), made[0]["targetId"].as_str(), made[0]["details"]["serviceAccount"].as_str(), made[0]["details"]["grantRemoved"].as_str(), made[0]["details"]["from"].clone()),
        (Some(ana.as_str()), Some(ledger.as_str()), Some(sa.as_str()), Some("operator"), Value::Null),
        "{made:?}"
    );
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    assert_eq!(access_of(&list, &ledger).as_deref(), Some("manage"), "{list}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/bots/{ledger}"), &tok, r#"{"name":"Ledger v2"}"#).await;
    assert_eq!((code, v["name"].as_str()), (200, Some("Ledger v2")), "{v}");
    assert_ne!(digest(port, &admin).await, before, "what it can do with the Bot changed, so an earlier sign-off is stale");
    // Again: nothing changes, nothing is audited.
    assert_eq!(keep(port, &ana_auth, &ledger, &sa).await.0, 200);
    assert_eq!(events(port, &admin, "bot.service_account_assigned").await.len(), 1);

    // It can't choose for itself, either way.
    assert_eq!(keep(port, &tok, &notes, &sa).await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{ledger}/keeper"), &tok, "").await.0, 403);

    // Its admin view lists what it keeps and what may be handed to it: not Ledger again, nor Ana's primary Bot.
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert_eq!(v["keptBotList"], json!([{ "id": ledger, "name": "Ledger v2", "visibility": "private" }]), "{v}");
    assert_eq!(ids(&v["keepable"]), [notes.as_str()], "{v}");

    // Taken back, it stays Ana's, and the account reaches it no more.
    let (code, v) = json_call(port, "DELETE", &format!("/api/bots/{ledger}/keeper"), &ana_auth, "").await;
    assert_eq!((code, v.get("serviceAccount")), (200, None), "{v}");
    assert_eq!(app.db.bot(&ledger).unwrap().owner_id, ana);
    assert_eq!(call(port, "GET", &format!("/api/bots/{ledger}/messages"), &tok, "").await.0, 404);
    let released = events(port, &admin, "bot.service_account_released").await;
    assert_eq!((released[0]["targetId"].as_str(), released[0]["details"]["reason"].as_str(), released[0]["details"]["serviceAccount"].as_str()), (Some(ledger.as_str()), Some("released"), Some(sa.as_str())), "{released:?}");
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{ledger}/keeper"), &ana_auth, "").await.0, 404, "once");
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert_eq!((v["keptBotList"].clone(), v["keptBots"].clone()), (json!([]), json!(0)), "{v}");
}

#[tokio::test]
async fn only_the_owner_or_an_admin_hands_a_bot_and_only_to_the_owners_own_accounts() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (bea, bea_auth) = user_with(port, &admin, "bea@example.com", "member").await;
    let (sa, _) = owned(port, &admin, &ana, "Ana's CI").await;
    let (beas, _) = owned(port, &admin, &bea, "Bea's CI").await;
    let shared = bot(port, &ana_auth, "Shared", "shared").await;
    let private = bot(port, &ana_auth, "Private", "private").await;

    // Bea uses Ana's shared Bot, but she doesn't decide who keeps it, nor learn Ana's accounts.
    let (_, v) = json_call(port, "GET", &format!("/api/bots/{shared}/access"), &bea_auth, "").await;
    assert_eq!((v["access"].as_str(), v.get("keepers")), (Some("operate"), None), "{v}");
    assert_eq!(keep(port, &bea_auth, &shared, &sa).await.0, 403);
    assert_eq!(keep(port, &bea_auth, &private, &sa).await.0, 404, "she can't see it");
    assert_eq!(keep(port, &admin, &shared, &sa).await.0, 200);
    let (code, v) = json_call(port, "DELETE", &format!("/api/bots/{shared}/keeper"), &bea_auth, "").await;
    assert_eq!(code, 403, "{v}");
    let refused = events(port, &admin, "bot.keep_refused").await;
    assert!(refused.iter().any(|e| e["actorId"] == json!(bea) && e["details"]["reason"] == "not_owner"), "{refused:?}");
    assert_eq!(app.db.bot(&shared).unwrap().service_account_id.as_deref(), Some(sa.as_str()));

    // Only Ana's own live accounts: someone else's is unknown to her and refused for an admin.
    let (code, v) = keep(port, &ana_auth, &private, &beas).await;
    assert_eq!(code, 404, "{v}");
    let (code, v) = keep(port, &admin, &private, &beas).await;
    assert_eq!(code, 409, "{v}");
    let refused = events(port, &admin, "bot.keep_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["accountOwner"].as_str()), (Some("service_account_owner"), Some(bea.as_str())), "{refused:?}");
    assert_eq!(keep(port, &ana_auth, &private, &bea).await.0, 400, "a person keeps no Bot");
    assert_eq!(keep(port, &ana_auth, &private, "nope").await.0, 404);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{private}/keeper"), &ana_auth, "{}").await.0, 400);

    // Her primary Bot stays her own.
    let main = app.db.create_bot_owned("Ana's own", "#fff", "waddle", "claude", None, true, &ana, Visibility::Private).id;
    assert_eq!(keep(port, &ana_auth, &main, &sa).await.0, 409);
    assert_eq!(events(port, &admin, "bot.keep_refused").await[0]["details"]["reason"], "primary_bot");

    // Read-only, Ana manages none of her Bots, so she hands none over.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    assert_eq!(keep(port, &ana_auth, &private, &sa).await.0, 403);
    assert_eq!(app.db.bot(&private).unwrap().service_account_id, None);

    // A deleted account keeps nothing and is offered nowhere.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{sa}"), &admin, "").await.0, 200);
    assert_eq!(keep(port, &ana_auth, &private, &sa).await.0, 404);
    let (_, v) = json_call(port, "GET", &format!("/api/bots/{private}/access"), &ana_auth, "").await;
    assert_eq!(v["keepers"], json!([]), "{v}");
}

#[tokio::test]
async fn handing_it_to_another_account_moves_it_within_the_limit() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (ci, ci_tok) = owned(port, &admin, &ana, "Ana's CI").await;
    let (nightly, nightly_tok) = owned(port, &admin, &ana, "Nightly").await;
    let ledger = bot(port, &ana_auth, "Ledger", "private").await;
    assert_eq!(keep(port, &ana_auth, &ledger, &ci).await.0, 200);

    // Handed to Nightly, it moves: CI lets it go, audited as reassigned.
    let (code, v) = keep(port, &ana_auth, &ledger, &nightly).await;
    assert_eq!((code, v["serviceAccount"]["id"].as_str()), (200, Some(nightly.as_str())), "{v}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{ledger}/messages"), &ci_tok, "").await.0, 404);
    assert_eq!(call(port, "GET", &format!("/api/bots/{ledger}/messages"), &nightly_tok, "").await.0, 200);
    let released = events(port, &admin, "bot.service_account_released").await;
    assert_eq!((released[0]["details"]["reason"].as_str(), released[0]["details"]["serviceAccount"].as_str()), (Some("reassigned"), Some(ci.as_str())), "{released:?}");
    let assigned = events(port, &admin, "bot.service_account_assigned").await;
    assert_eq!(assigned[0]["details"]["from"].as_str(), Some(ci.as_str()), "{assigned:?}");

    // CI keeps as many as one may: it is offered as full, and refused.
    for i in 0..service_accounts::MAX_KEPT_BOTS {
        let (code, v) = json_call(port, "POST", "/api/bots", &ci_tok, &json!({ "name": format!("PR {i}") }).to_string()).await;
        assert_eq!(code, 201, "{v}");
    }
    let (_, v) = json_call(port, "GET", &format!("/api/bots/{ledger}/access"), &ana_auth, "").await;
    let full: Vec<(&str, bool)> = v["keepers"].as_array().unwrap().iter().map(|k| (k["name"].as_str().unwrap(), k["full"] == true)).collect();
    assert_eq!(full, [("Ana's CI", true), ("Nightly", false)], "{v}");
    let (code, v) = keep(port, &ana_auth, &ledger, &ci).await;
    assert_eq!(code, 409, "{v}");
    let refused = events(port, &admin, "bot.keep_refused").await;
    assert_eq!(refused[0]["details"]["reason"], "service_account_bot_limit", "{refused:?}");
    assert_eq!(app.db.bot(&ledger).unwrap().service_account_id.as_deref(), Some(nightly.as_str()), "it stays with Nightly");
}

#[tokio::test]
async fn the_access_review_sees_a_handed_bot_as_kept_and_delegates_dont_choose() {
    let (port, _, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (sa, _) = owned(port, &admin, &ana, "Ana's CI").await;
    let ledger = bot(port, &ana_auth, "Ledger", "private").await;
    assert_eq!(keep(port, &admin, &ledger, &sa).await.0, 200);
    let (_, review) = json_call(port, "GET", "/api/access-review", &admin, "").await;
    let row = review["serviceAccounts"].as_array().unwrap().iter().find(|s| s["id"] == json!(sa)).cloned().unwrap();
    let kept = row["botAccess"]["bots"].as_array().unwrap().iter().find(|b| b["id"] == json!(ledger)).cloned().unwrap();
    assert_eq!((kept["access"].as_str(), kept["kept"].clone()), (Some("manage"), json!(true)), "{row}");
    // A role whose holders manage users doesn't let them choose another owner's keeper.
    let helpdesk = role(port, &admin, "Help desk", "member", &["users.manage", "bots.manage"]).await;
    let (cam, cam_auth) = user_with(port, &admin, "cam@example.com", "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helpdesk}/users/{cam}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{ledger}/keeper"), &cam_auth, "").await.0, 404, "Ledger is private to Ana");
}

#[tokio::test]
async fn keeping_a_bot_its_access_already_covers_still_makes_an_earlier_sign_off_stale() {
    let (port, _, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let sa = account(port, &admin, json!({ "name": "Ana's reader", "role": "readonly" })).await;
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, &json!({ "owner": ana }).to_string()).await;
    assert_eq!(code, 200, "{v}");
    let (tok, _) = token(port, &admin, &sa, json!({})).await;
    let shared = bot(port, &ana_auth, "Shared", "shared").await;
    let access = |list: Value| access_of(&list, &shared);
    assert_eq!(access(json_call(port, "GET", "/api/bots", &tok, "").await.1).as_deref(), Some("view"));
    let before = digest(port, &admin).await;

    // Read-only, it only views the Bot it keeps: the same access, but the report says "kept".
    assert_eq!(keep(port, &ana_auth, &shared, &sa).await.0, 200);
    assert_eq!(access(json_call(port, "GET", "/api/bots", &tok, "").await.1).as_deref(), Some("view"));
    let kept = digest(port, &admin).await;
    assert_ne!(kept, before, "the report changed, so an earlier sign-off is stale");

    // Taken back, the report is as it was, and so is its digest.
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{shared}/keeper"), &ana_auth, "").await.0, 200);
    assert_eq!(digest(port, &admin).await, before);
}
