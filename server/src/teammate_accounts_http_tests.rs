//! Teammate accounts on one server (ADR 0064), on the real router: with per-user accounts
//! and isolated shared Bots, a teammate's runs of an owner's Bot and their own harness
//! logins for it go to an account of their own, never the owner's. Without root no
//! account can be made here, so these check what botd decides and audits; the OS test
//! (accounts_os_tests, deploy/test-isolation.sh) checks what the accounts can reach.

use crate::acl::{SharedBots, Visibility};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
    c_id: String,
    c: String,
    team: crate::db::Bot,
}

/// Ada shares a Bot with Bea, not Cy, who has a private Bot of his own. The account helper
/// always fails (`/bin/false` as sudo).
async fn world(teammates: bool, shared: SharedBots) -> World {
    let (port, app, admin, _) = serve_app().await;
    let root = app.cfg.data_dir.parent().unwrap().join(format!("iso-{}", short_id()));
    std::fs::create_dir_all(&root).unwrap();
    let mut iso = accounts::for_tests(&root, "/bin/false");
    iso.teammates = teammates;
    let _ = app.isolation.set(Arc::new(iso));
    app.shared_bots.set(shared).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let (c_id, c) = user_with(port, &admin, "cy@example.com", "member").await;
    let team = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Private);
    app.db.set_grant(&team.id, &b_id, crate::acl::Grant::Operator, &a_id);
    app.db.create_bot_owned("Cy's", "#fff", "waddle", "claude", None, false, &c_id, Visibility::Private);
    World { port, app, admin, a_id, a, b_id, b, c_id, c, team }
}

async fn events(w: &World, action: &str) -> Vec<Value> {
    let (code, body) = call(w.port, "GET", &format!("/api/audit?action={action}&limit=200"), &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

#[tokio::test]
async fn admins_log_a_teammate_in_for_an_owners_bots_only_when_teammates_have_accounts() {
    let off = world(false, SharedBots::Isolated).await;
    let body = json!({ "harness": "claude", "owner": off.a_id }).to_string();
    let (code, res) = call(off.port, "POST", &format!("/api/users/{}/harness-login", off.b_id), &off.admin, &body).await;
    assert_eq!(code, 409, "{res}");
    assert!(res.contains("ISOLATION_TEAMMATES"), "{res}");

    let w = world(true, SharedBots::Isolated).await;
    let login = |who: &str, owner: Value| json!({ "harness": "claude", "owner": owner }).to_string().replace("WHO", who);
    for (who, owner, want) in [
        (&w.b_id, json!(w.b_id), 400),
        (&w.b_id, json!("nobody"), 404),
        (&w.b_id, json!(7), 400),
        (&w.b_id, json!(w.c_id), 400),
        (&w.c_id, json!(w.b_id), 400),
    ] {
        let (code, res) = call(w.port, "POST", &format!("/api/users/{who}/harness-login"), &w.admin, &login(who, owner.clone())).await;
        assert_eq!(code, want, "{who} for {owner}: {res}");
    }
    // A member can't, not even for their own login.
    let (code, _) = call(w.port, "POST", &format!("/api/users/{}/harness-login", w.b_id), &w.b, &login(&w.b_id, json!(w.a_id))).await;
    assert_eq!(code, 403);

    // The helper fails: 502, audited against the owner with the teammate and their account.
    let (code, res) = call(w.port, "POST", &format!("/api/users/{}/harness-login", w.b_id), &w.admin, &login(&w.b_id, json!(w.a_id))).await;
    assert_eq!(code, 502, "{res}");
    let failed = events(&w, "isolation.account_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["targetId"], w.a_id.as_str());
    assert_eq!(failed[0]["details"]["forUser"], w.b_id.as_str());
    let account = accounts::teammate_account(&w.a_id, &w.b_id).unwrap();
    assert_eq!(failed[0]["details"]["account"], account.as_str());
    assert_ne!(account, accounts::account(&w.a_id).unwrap());
    assert!(events(&w, "harness.login_started").await.is_empty());
}

#[tokio::test]
async fn a_teammates_logins_land_on_this_server_when_the_owners_bots_run_here() {
    let w = world(true, SharedBots::Isolated).await;
    let base = format!("/api/machine/teammate/{}", w.a_id);

    let (code, res) = call(w.port, "GET", &format!("{base}/harness-logins"), &w.b, "").await;
    assert_eq!(code, 200, "{res}");
    let v = parse(&res);
    assert_eq!((v["on"].as_str(), v["machineId"].is_null(), v["forUser"].as_str()), (Some("server"), true, Some(w.b_id.as_str())), "{v}");
    assert_eq!(v["owner"]["id"], w.a_id.as_str());
    assert_eq!(v["hasUser"], false, "asking never makes the account");
    assert_eq!(v["harnesses"]["claude"]["state"], "logged_out", "{v}");
    assert_eq!(v["harnesses"]["claude"]["serverKey"], false);
    assert!(v["harnesses"].get("pi").is_none(), "Pi takes keys");

    // Nobody else learns anything: not the owner, not someone who can't run her Bots.
    for who in [&w.a, &w.c] {
        let (code, _) = call(w.port, "GET", &format!("{base}/harness-logins"), who, "").await;
        assert_eq!(code, 404);
    }

    // The account can't be made: 502, audited, no login started.
    let (code, res) = call(w.port, "POST", &format!("{base}/harness-login"), &w.b, r#"{"harness":"claude"}"#).await;
    assert_eq!(code, 502, "{res}");
    let failed = events(&w, "isolation.account_failed").await;
    assert!(failed.iter().any(|e| e["details"]["forUser"] == w.b_id.as_str()), "{failed:?}");
    let (code, _) = call(w.port, "POST", &format!("{base}/harness-login"), &w.b, r#"{"harness":"pi"}"#).await;
    assert_eq!(code, 400);
    let (code, _) = call(w.port, "POST", &format!("{base}/harness-login/l123/input"), &w.b, r#"{"text":"x"}"#).await;
    assert_eq!(code, 404, "no such login of hers");

    // Logging out with no account removes nothing, and says so in the audit log.
    let (code, res) = call(w.port, "DELETE", &format!("{base}/harness-logins/claude"), &w.b, "").await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(parse(&res)["removed"], 0);
    let out = events(&w, "harness.logged_out").await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!((out[0]["targetId"].as_str(), out[0]["details"]["forUser"].as_str(), out[0]["details"]["on"].as_str()), (Some(w.a_id.as_str()), Some(w.b_id.as_str()), Some("server")));

    // Admins see it too.
    let (code, res) = call(w.port, "GET", &format!("/api/users/{}/machine/teammates/{}/harness-logins", w.a_id, w.b_id), &w.admin, "").await;
    assert_eq!((code, parse(&res)["on"].as_str()), (200, Some("server")), "{res}");

    // The app offers Bea her own login on Ada's shared Bot.
    let (_, list) = call(w.port, "GET", "/api/bots", &w.b, "").await;
    let team = parse(&list).as_array().unwrap().iter().find(|b| b["id"] == w.team.id.as_str()).cloned().unwrap();
    assert_eq!(team["teammateLogins"], true, "{team}");
}

#[tokio::test]
async fn without_teammate_accounts_nothing_lands_here() {
    for (teammates, shared) in [(false, SharedBots::Isolated), (true, SharedBots::Open)] {
        let w = world(teammates, shared).await;
        let (code, _) = call(w.port, "GET", &format!("/api/machine/teammate/{}/harness-logins", w.a_id), &w.b, "").await;
        assert_eq!(code, 404, "{teammates} {shared:?}");
        let (_, list) = call(w.port, "GET", "/api/bots", &w.b, "").await;
        assert!(!list.contains("teammateLogins"), "{list}");
    }
}

/// Sends `text` as `who` and waits for the Bot's reply.
async fn run(w: &World, who: &str, text: &str) -> String {
    let before = w.app.db.last_id();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", w.team.id), who, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..300 {
        if let Some(m) = w.app.db.replies_after(&w.team.id, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply");
}

#[tokio::test]
async fn a_teammates_run_never_falls_back_to_the_owners_account() {
    let w = world(true, SharedBots::Isolated).await;
    let reply = run(&w, &w.b, "hi").await;
    assert!(reply.contains("couldn't set up an account for you"), "{reply}");
    let refused = events(&w, "bot.run_refused").await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["forUser"].as_str()), (Some("no_account"), Some(w.b_id.as_str())), "{d}");
    assert_eq!(d["account"], accounts::teammate_account(&w.a_id, &w.b_id).unwrap().as_str());
    assert!(events(&w, "harness.invoked").await.is_empty(), "nothing ran");

    // Ada's own run still wants her own account.
    let reply = run(&w, &w.a, "hi").await;
    assert!(reply.contains("my owner's account"), "{reply}");
    let refused = events(&w, "bot.run_refused").await;
    let own = refused.iter().find(|e| e["details"].get("forUser").is_none()).unwrap();
    assert_eq!(own["details"]["account"], accounts::account(&w.a_id).unwrap().as_str());

    // With teammate accounts off, Bea's run goes as Ada's account (ADR 0046), as before.
    let off = world(false, SharedBots::Isolated).await;
    run(&off, &off.b, "hi").await;
    let refused = events(&off, "bot.run_refused").await;
    assert_eq!(refused[0]["details"]["account"], accounts::account(&off.a_id).unwrap().as_str(), "{refused:?}");
}
