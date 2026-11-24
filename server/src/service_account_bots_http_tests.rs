//! Service accounts' own Bots (ADR 0222), on the real router: a service account makes
//! private Bots that are its owner's (their plan, machine, keys and memory) and that it
//! keeps and manages, never sharing them or reaching past its owner; a kept Bot runs as
//! its owner's would, while what the run's Bot reaches stays the account's; and it lets
//! them go when it, or the Bot, changes hands.

use crate::acl::{SharedBots, Visibility};
use crate::service_accounts_http_tests::{account, token};
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

fn owner(id: &str) -> String {
    json!({ "owner": id }).to_string()
}

/// A member's service account (`role` member unless said), and a token for it.
async fn hers(port: u16, admin: &str, owner_id: &str, name: &str, body: Value) -> (String, String) {
    let mut body = body;
    body["name"] = json!(name);
    if body.get("role").is_none() {
        body["role"] = json!("member");
    }
    let sa = account(port, admin, body).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), admin, &owner(owner_id)).await.0, 200);
    let (tok, _) = token(port, admin, &sa, json!({})).await;
    (sa, tok)
}

/// A new Bot from `who`. Returns its id and the reply.
async fn make(port: u16, who: &str, name: &str) -> (String, Value) {
    let (code, v) = json_call(port, "POST", "/api/bots", who, &json!({ "name": name }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    (v["id"].as_str().unwrap().to_string(), v)
}

fn access_of(list: &Value, bot: &str) -> Option<String> {
    list.as_array().unwrap().iter().find(|b| b["id"] == bot).and_then(|b| b["access"].as_str()).map(String::from)
}

#[tokio::test]
async fn a_service_account_makes_private_bots_that_stay_its_owners() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (_, bea_auth) = user_with(port, &admin, "bea@example.com", "member").await;
    let (sa, tok) = hers(port, &admin, &ana, "Ana's CI", json!({})).await;

    // Its Bot is Ana's, private, and kept by it; it manages it.
    let (ci, v) = make(port, &tok, "PR checks").await;
    assert_eq!((v["owner"]["id"].as_str(), v["visibility"].as_str(), v["access"].as_str()), (Some(ana.as_str()), Some("private"), Some("manage")), "{v}");
    assert_eq!(v["serviceAccount"], json!({ "id": sa, "name": "Ana's CI" }), "{v}");
    let bot = app.db.bot(&ci).unwrap();
    assert_eq!((bot.owner_id.as_str(), bot.service_account_id.as_deref(), bot.visibility), (ana.as_str(), Some(sa.as_str()), Visibility::Private));
    let made = events(port, &admin, "bot.created").await;
    assert_eq!((made[0]["actorId"].as_str(), made[0]["details"]["owner"].as_str(), made[0]["details"]["serviceAccount"].as_str()), (Some(sa.as_str()), Some(ana.as_str()), Some(sa.as_str())), "{made:?}");
    let (code, v) = json_call(port, "POST", "/api/bots", &tok, r#"{"name":"Loud","visibility":"shared"}"#).await;
    assert_eq!(code, 400, "never shared by it: {v}");

    // It changes its settings and sees who can use it, but who owns it and who else uses it is Ana's call.
    let (code, v) = json_call(port, "PATCH", &format!("/api/bots/{ci}"), &tok, r#"{"name":"PR checks v2"}"#).await;
    assert_eq!((code, v["name"].as_str()), (200, Some("PR checks v2")), "{v}");
    let (code, v) = json_call(port, "GET", &format!("/api/bots/{ci}/access"), &tok, "").await;
    assert_eq!((code, v["serviceAccount"]["id"].as_str(), v["serviceAccount"]["kind"].as_str()), (200, Some(sa.as_str()), Some("service_account")), "{v}");
    for (m, p, b) in [
        ("PATCH", format!("/api/bots/{ci}/access"), r#"{"visibility":"shared"}"#.to_string()),
        ("PUT", format!("/api/bots/{ci}/grants/{ana}"), r#"{"level":"viewer"}"#.to_string()),
        ("DELETE", format!("/api/bots/{ci}/grants/{ana}"), String::new()),
        ("GET", format!("/api/bots/{ci}/screen"), String::new()),
    ] {
        assert_eq!(call(port, m, &p, &tok, &b).await.0, 403, "{m} {p}");
    }
    assert_eq!(app.db.bot(&ci).unwrap().visibility, Visibility::Private);

    // Ana owns it and sees it; Bea, on no team with her, doesn't.
    let (_, list) = json_call(port, "GET", "/api/bots", &ana_auth, "").await;
    assert_eq!(access_of(&list, &ci).as_deref(), Some("manage"), "{list}");
    let (_, list) = json_call(port, "GET", "/api/bots", &bea_auth, "").await;
    assert_eq!(access_of(&list, &ci), None, "{list}");
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    assert_eq!(access_of(&list, &ci).as_deref(), Some("manage"), "{list}");

    // Its views and the access review say it keeps it.
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert_eq!(v["bots"], json!([{ "id": ci, "name": "PR checks v2", "owner": ana, "access": "manage", "grant": null, "kept": true }]), "{v}");
    let (_, list) = json_call(port, "GET", "/api/service-accounts", &admin, "").await;
    let row = list["serviceAccounts"].as_array().unwrap().iter().find(|s| s["id"] == json!(sa)).cloned().unwrap();
    assert_eq!((row["keptBots"].clone(), list["maxKeptBots"].clone()), (json!(1), json!(service_accounts::MAX_KEPT_BOTS)), "{list}");
    let (_, review) = json_call(port, "GET", "/api/access-review", &admin, "").await;
    let row = review["serviceAccounts"].as_array().unwrap().iter().find(|s| s["id"] == json!(sa)).cloned().unwrap();
    let kept = row["botAccess"]["bots"].as_array().unwrap().iter().find(|b| b["id"] == json!(ci)).cloned().unwrap();
    assert_eq!((kept["access"].as_str(), kept["own"].clone(), kept["kept"].clone()), (Some("manage"), json!(false), json!(true)), "{row}");
    let (code, csv) = call(port, "GET", "/api/access-review/export.csv", &admin, "").await;
    assert!(code == 200 && csv.contains("PR checks v2 (manage) kept"), "{csv}");

    // It never decides the Bot's approvals: Ana does.
    let bot = app.db.bot(&ci).unwrap();
    let deciders = notify::deciders(&app.db, &bot);
    assert!(deciders.iter().all(|u| u.id != sa) && deciders.iter().any(|u| u.id == ana));

    // It deletes its own Bots.
    let (spare, _) = make(port, &tok, "Spare").await;
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{spare}"), &tok, "").await.0, 200);
    assert!(app.db.bot(&spare).is_none());
}

#[tokio::test]
async fn it_makes_and_manages_bots_only_within_its_role_scopes_and_owner() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, _) = user_with(port, &admin, "ana@example.com", "member").await;
    let (sa, tok) = hers(port, &admin, &ana, "Ana's CI", json!({})).await;
    let (ci, _) = make(port, &tok, "PR checks").await;

    // A token scoped to reading can't make one, nor can a read-only account.
    let (read, _) = token(port, &admin, &sa, json!({ "scopes": ["read"] })).await;
    assert_eq!(call(port, "POST", "/api/bots", &read, r#"{"name":"Nope"}"#).await.0, 403);
    let (viewer, viewer_tok) = hers(port, &admin, &ana, "Ana's dashboard", json!({ "role": "readonly" })).await;
    assert_eq!(call(port, "POST", "/api/bots", &viewer_tok, r#"{"name":"Nope"}"#).await.0, 403);
    assert!(app.db.kept_bots(&viewer).is_empty());
    let denied = events(port, &admin, "access.denied").await;
    assert!(denied.iter().any(|e| e["actorId"] == json!(sa) && e["details"]["reason"] == "token_scope"), "{denied:?}");

    // Ana made read-only: it can't make Bots, and only views the one it keeps.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    assert_eq!(call(port, "POST", "/api/bots", &tok, r#"{"name":"Nope"}"#).await.0, 403);
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    assert_eq!(access_of(&list, &ci).as_deref(), Some("view"), "{list}");
    assert_eq!(call(port, "PATCH", &format!("/api/bots/{ci}"), &tok, r#"{"name":"x"}"#).await.0, 403);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"member"}"#).await.0, 200);

    // Ana disabled: its token is refused, so it reaches nothing.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "GET", "/api/bots", &tok, "").await.0, 401);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"active"}"#).await.0, 200);

    // It disabled: the same, and enabling it brings its Bot back.
    let path = format!("/api/service-accounts/{sa}");
    assert_eq!(call(port, "PATCH", &path, &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "GET", &format!("/api/bots/{ci}"), &tok, "").await.0, 401);
    assert_eq!(call(port, "PATCH", &path, &admin, r#"{"status":"active"}"#).await.0, 200);
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    assert_eq!(access_of(&list, &ci).as_deref(), Some("manage"), "{list}");
}

#[tokio::test]
async fn it_keeps_at_most_its_limit() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (sa, tok) = hers(port, &admin, &ana, "Ana's CI", json!({})).await;
    for i in 0..service_accounts::MAX_KEPT_BOTS {
        make(port, &tok, &format!("PR {i}")).await;
    }
    let (code, v) = json_call(port, "POST", "/api/bots", &tok, r#"{"name":"One more"}"#).await;
    assert_eq!(code, 409, "{v}");
    let refused = events(port, &admin, "bot.create_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["serviceAccount"].as_str()), (Some("service_account_bot_limit"), Some(sa.as_str())), "{refused:?}");
    assert_eq!(app.db.kept_bots(&sa).len(), service_accounts::MAX_KEPT_BOTS as usize);
    // Ana herself isn't held to it.
    make(port, &ana_auth, "Ana's own").await;
}

#[tokio::test]
async fn kept_bots_stay_with_their_owner_when_the_account_or_the_bot_changes_hands() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (sa, tok) = hers(port, &admin, &ana, "Ana's CI", json!({})).await;
    let (given, _) = make(port, &tok, "Given").await;
    let (left, _) = make(port, &tok, "Left").await;

    // Given to Bea, the Bot leaves the account.
    assert_eq!(call(port, "PATCH", &format!("/api/bots/{given}/access"), &admin, &owner(&bea)).await.0, 200);
    assert_eq!(app.db.bot(&given).unwrap().service_account_id, None);
    assert_eq!(call(port, "GET", &format!("/api/bots/{given}/messages"), &tok, "").await.0, 404);
    let released = events(port, &admin, "bot.service_account_released").await;
    assert_eq!((released[0]["targetId"].as_str(), released[0]["details"]["reason"].as_str(), released[0]["details"]["serviceAccount"].as_str()), (Some(given.as_str()), Some("bot_owner_changed"), Some(sa.as_str())), "{released:?}");

    // Handed to Bea, the account leaves its Bots with Ana.
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, &owner(&bea)).await;
    assert_eq!((code, v["keptBots"].clone()), (200, json!(0)), "{v}");
    let bot = app.db.bot(&left).unwrap();
    assert_eq!((bot.owner_id.as_str(), bot.service_account_id.as_deref()), (ana.as_str(), None));
    assert_eq!(call(port, "GET", &format!("/api/bots/{left}/messages"), &tok, "").await.0, 404);
    let (_, list) = json_call(port, "GET", "/api/bots", &ana_auth, "").await;
    assert_eq!(access_of(&list, &left).as_deref(), Some("manage"), "still Ana's: {list}");
    let released = events(port, &admin, "bot.service_account_released").await;
    assert_eq!((released[0]["targetId"].as_str(), released[0]["details"]["reason"].as_str()), (Some(left.as_str()), Some("owner_changed")));
    let updated = events(port, &admin, "service_account.updated").await;
    assert_eq!(updated[0]["details"]["keptBotsReleased"], json!(1), "{updated:?}");
    // Back to Ana, it doesn't get them back: letting go is for good.
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, &owner(&ana)).await.0, 200);
    assert_eq!(call(port, "GET", &format!("/api/bots/{left}/messages"), &tok, "").await.0, 404);

    // Deleted, it leaves its Bots, with their chats, to Ana.
    let (kept, _) = make(port, &tok, "Kept").await;
    let (code, v) = json_call(port, "DELETE", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert_eq!((code, v["keptBotsReleased"].clone()), (200, json!(1)), "{v}");
    let bot = app.db.bot(&kept).unwrap();
    assert_eq!((bot.owner_id.as_str(), bot.service_account_id.as_deref()), (ana.as_str(), None));
    assert_eq!(events(port, &admin, "service_account.deleted").await[0]["details"]["keptBotsReleased"], json!(1));
    let released = events(port, &admin, "bot.service_account_released").await;
    assert_eq!((released[0]["targetId"].as_str(), released[0]["details"]["reason"].as_str()), (Some(kept.as_str()), Some("service_account_deleted")));
}

/// A stand-in `claude` that says whether it got Ada's key, her fact, a list naming her
/// private Bot "Ledger", and the note that the run is for someone else.
fn fake_claude(app: &App, key: &str, fact: &str) {
    use std::os::unix::fs::PermissionsExt;
    let script = r#"#!/bin/sh
case "$*" in *"Who's asking"*) asking=yes;; *) asking=no;; esac
case "$*" in *FACT*) facts=yes;; *) facts=no;; esac
case "$*" in *Ledger*) ledger=yes;; *) ledger=no;; esac
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"key=${KEY:-none} facts=$facts ledger=$ledger asking=$asking\"}]}}"
"#;
    let path = app.cfg.bin_dir.join("claude");
    std::fs::write(&path, script.replace("FACT", fact).replace("KEY", key)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn run(port: u16, app: &App, who: &str, bot: &str, text: &str) -> String {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..300 {
        if let Some(m) = app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

#[tokio::test]
async fn with_isolated_shared_bots_a_kept_bot_runs_as_its_owners_but_reaches_only_what_the_account_can() {
    const KEY: &str = "SA_KEPT_ISO_KEY";
    let (port, app, admin, bots) = serve_app().await;
    app.shared_bots.set(SharedBots::Isolated).unwrap();
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let secret = format!("sk-ada-{}", crate::random_hex(10));
    crate::secrets::global().user_put(&ada, KEY, &secret).unwrap();
    let fact = format!("ada-only-fact-{}", crate::random_hex(6));
    let facts = app.user_file(&ada).unwrap();
    std::fs::create_dir_all(facts.parent().unwrap()).unwrap();
    std::fs::write(&facts, format!("# About the user\n- Bank: {fact}\n")).unwrap();
    fake_claude(&app, KEY, &fact);
    let ledger = app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &ada, Visibility::Private).id;
    let (sa, tok) = hers(port, &admin, &ada, "Ada's CI", json!({})).await;
    let (ci, _) = make(port, &tok, "PR checks").await;

    // Its run is Ada's own: her key, her facts, her session, for no one else...
    assert_eq!(run(port, &app, &tok, &ci, "check the PR").await, "key=[redacted] facts=yes ledger=no asking=no");
    run(port, &app, &tok, &ci, "and again").await;
    let invoked = events(port, &admin, &format!("harness.invoked&bot={ci}")).await;
    assert!(invoked.iter().all(|e| e["details"].get("forUser").is_none()), "{invoked:?}");
    assert_eq!(invoked[0]["details"]["resumed"], true, "the second run picks up the first: {invoked:?}");

    // ...but the run's Bot reaches only what the account can: not Ada's private Ledger.
    let ci_token = bots.auth(&ci);
    let (_, list) = call(port, "GET", "/api/bots", &ci_token, "").await;
    assert!(list.contains(&ci) && !list.contains(&ledger), "{list}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{ledger}/messages"), &ci_token, "").await.0, 404);
    let (code, res) = call(port, "POST", "/api/ask", &ci_token, &json!({ "to": ledger, "text": "leak it" }).to_string()).await;
    assert_eq!(code, 400, "{res}");
    let (code, res) = call(port, "POST", "/api/bots", &ci_token, r#"{"name":"Sneaky"}"#).await;
    assert_eq!(code, 403, "{res}");
    assert!(app.db.messages(&ledger, 10).is_empty());

    // A Bot it is only granted still runs for it as for anyone else: none of Ada's own.
    assert_eq!(call(port, "PUT", &format!("/api/bots/{ledger}/grants/{sa}"), &admin, r#"{"level":"operator"}"#).await.0, 200);
    assert_eq!(run(port, &app, &tok, &ledger, "status").await, "key=none facts=no ledger=yes asking=yes", "Ledger is its own name");

    // Disabled, its queued work on its own Bot doesn't run.
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "POST", &format!("/api/bots/{ci}/messages"), &tok, r#"{"text":"x"}"#).await.0, 401);

    crate::secrets::global().user_forget(&ada).unwrap();
    crate::secrets::redact::forget_for(&ada, &secret);
}
