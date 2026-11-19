//! Per-user isolation (ADR 0028), on the real router: user B can't reach user A's Bots,
//! folders, secrets, screens, or sessions through any route, as a person or through a
//! Bot of theirs; a Bot can only act as itself; shared Bots still work for others and
//! still run in their owner's space; and with routing on, a Bot runs only on its
//! owner's machine. Nothing here talks to Linode.

use crate::acl::Visibility;
use crate::auth_review_http_tests::routes;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::recording::Recording;
use crate::machines::ControlPlane;
use crate::rbac::{self, Principal, Role};
use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with, BotKey};
use crate::users_http_tests::{parse, user_with};
use crate::*;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    key: BotKey,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
}

async fn world() -> World {
    let (port, app, admin, key) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    World { port, app, admin, key, a_id, a, b_id, b }
}

async fn events(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// A stand-in `claude` that reports where it ran and whether it got `var`.
fn fake_claude(app: &App, var: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let script = r#"#!/bin/sh
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"cwd=$(pwd) key=${VAR:-none} bot=$BOT_ID\"}]}}"
"#;
    std::fs::write(&path, script.replace("VAR", var)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Sends `text` and waits for the Bot's reply.
async fn run(w: &World, who: &str, bot: &str, text: &str) -> String {
    let before = w.app.db.last_id();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{bot}/messages"), who, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..300 {
        if let Some(m) = w.app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

#[tokio::test]
async fn another_user_reaches_none_of_a_private_bot_through_any_route() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    let (_, viewer) = user_with(port, &w.admin, "vic@example.com", "readonly").await;
    let pa = app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let pb = app.db.create_bot_owned("Scout", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let b_bot = w.key.auth(&pb.id);
    let a_bot = w.key.auth(&pa.id);

    // Things of A's for B to go after: a routine, a pending approval, and chat.
    let (code, r) = call(port, "POST", &format!("/api/bots/{}/routines", pa.id), &w.a, r#"{"name":"Close","cron":"0 9 * * *","instruction":"close the books"}"#).await;
    assert_eq!(code, 201, "{r}");
    let routine = parse(&r)["id"].as_str().unwrap().to_string();
    let check = json!({ "from": pa.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push origin main" }, "cwd": "/tmp" } }).to_string();
    let hook = tokio::spawn({
        let a_bot = a_bot.clone();
        async move { call(port, "POST", "/api/approvals/check", &a_bot, &check).await }
    });
    let approval = loop {
        if let Some(a) = app.db.approvals(Some("pending"), None, 1).pop() {
            break a.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    app.db.add_message(&pa.id, "user", "the payroll numbers", None, false, None);
    let messages = app.db.messages(&pa.id, 100).len();

    let body_for = |m: &str, p: &str| -> String {
        match (m, p.rsplit('/').next().unwrap_or("")) {
            ("POST", "messages") => r#"{"text":"what are the payroll numbers?"}"#.into(),
            ("POST", "routines") => r#"{"name":"Mine","cron":"0 9 * * *","instruction":"x"}"#.into(),
            ("PATCH", "access") => r#"{"visibility":"shared"}"#.into(),
            ("PUT", "policy") => r#"{"mode":"bypass"}"#.into(),
            ("PUT", _) if p.contains("/grants/") => r#"{"level":"operator"}"#.into(),
            ("PATCH", _) if p.starts_with("/api/routines/") => r#"{"enabled":false}"#.into(),
            ("PATCH", _) => r#"{"name":"Pwned","visibility":"shared"}"#.into(),
            _ => "{}".into(),
        }
    };
    let mut walked = 0;
    for (m, p) in routes() {
        let path = if p.starts_with("/api/bots/{id}") {
            p.replace("{id}", &pa.id).replace("{user}", &w.b_id)
        } else if p == "/api/routines/{id}" {
            p.replace("{id}", &routine)
        } else if p.starts_with("/api/approvals/{id}/") {
            p.replace("{id}", &approval)
        } else {
            continue;
        };
        let need = rbac::classify(&axum::http::Method::from_bytes(m.as_bytes()).unwrap(), &path);
        let body = body_for(&m, &path);
        for (who, auth, role) in [("Bea", &w.b, Role::Member), ("a read-only user", &viewer, Role::Readonly)] {
            let (code, res) = call(port, &m, &path, auth, &body).await;
            let want = if rbac::allows(Principal::User(role), need) { 404 } else { 403 };
            assert_eq!(code, want, "{who}: {m} {path}: {res}");
            assert!(!res.contains("payroll") && !res.contains("Ledger"), "{who}: {m} {path}: {res}");
        }
        let (code, res) = call(port, &m, &path, &b_bot, &body).await;
        assert!([403, 404].contains(&code), "Bea's Bot: {m} {path}: {code} {res}");
        walked += 1;
    }
    assert!(walked >= 15, "{walked} routes");

    // Routes that name the Bot in the body or query.
    let named = [
        ("POST", "/api/ask".to_string(), json!({ "from": pb.id, "to": pa.id, "text": "the payroll?" })),
        ("POST", "/api/handoff".to_string(), json!({ "from": pa.id, "text": "log in" })),
        ("POST", "/api/approvals/check".to_string(), json!({ "from": pa.id, "event": { "tool_name": "Bash", "tool_input": { "command": "ls" } } })),
        ("GET", format!("/api/policy/rules?bot={}", pa.id), json!({})),
        ("GET", format!("/api/approvals?bot={}", pa.id), json!({})),
    ];
    for (m, p, body) in &named {
        let (code, res) = call(port, m, p, &w.b, &body.to_string()).await;
        assert!([400, 403, 404].contains(&code), "Bea: {m} {p}: {code} {res}");
        assert!(!res.contains("payroll") && !res.contains("Ledger"), "{res}");
    }
    let (code, res) = call(port, "POST", "/api/ask", &b_bot, &named[0].2.to_string()).await;
    assert_eq!(code, 400, "Bea's Bot can't find it to ask: {res}");

    // Lists and the stream of state leave it out.
    for (who, auth) in [("Bea", &w.b), ("Bea's Bot", &b_bot)] {
        for p in ["/api/bots", "/api/state", "/api/approvals"] {
            let (_, res) = call(port, "GET", p, auth, "").await;
            assert!(!res.contains(&pa.id) && !res.contains("payroll"), "{who} {p}: {res}");
        }
    }

    // Nothing changed.
    let after = app.db.bot(&pa.id).unwrap();
    assert_eq!((after.name.as_str(), after.visibility, after.owner_id.as_str()), ("Ledger", Visibility::Private, w.a_id.as_str()));
    assert!(app.db.grant(&pa.id, &w.b_id).is_none());
    assert_eq!(app.db.messages(&pa.id, 100).len(), messages);
    assert!(app.db.routines(Some(&pa.id)).iter().any(|r| r.id == routine && r.enabled));
    assert_eq!(app.db.approvals(Some("pending"), None, 10).len(), 1, "still waiting on Ada");
    assert_eq!(call(port, "POST", &format!("/api/approvals/{approval}/deny"), &w.a, "{}").await.0, 200);
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("deny"));
    let hidden = events(port, &w.admin, "action=access.denied").await;
    assert!(hidden.iter().any(|e| e["details"]["reason"] == "bot_acl" && e["targetId"] == pa.id.as_str() && e["actorId"] == w.b_id.as_str()));
}

#[tokio::test]
async fn a_bot_can_only_act_as_itself() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    let a1 = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let b1 = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let b2 = app.db.create_bot_owned("Bea's other", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    app.db.add_message(&a1.id, "user", "ada-private-note", None, false, None);
    let a_bot = w.key.auth(&a1.id);
    let b_bot = w.key.auth(&b1.id);

    // B's Bot claiming to be A's, every way botctl could say it.
    let claim = format!("X-SuperBot-Bot: {}\r\n", a1.id);
    let (code, _, res) = call_with(port, "GET", &format!("/api/bots/{}/messages", a1.id), &b_bot, &claim, "").await;
    assert_eq!(code, 403, "{res}");
    let (code, _, _) = call_with(port, "GET", "/api/bots", &b_bot, &claim, "").await;
    assert_eq!(code, 403);
    let mismatch = events(port, &w.admin, "action=access.denied&actor=bot").await;
    assert!(mismatch.iter().any(|e| e["details"]["reason"] == "bot_mismatch" && e["actorId"] == b1.id.as_str()), "{mismatch:?}");
    for (p, body) in [
        ("/api/ask", json!({ "from": a1.id, "to": b2.id, "text": "hi" })),
        ("/api/handoff", json!({ "from": a1.id, "text": "log in" })),
    ] {
        let (code, res) = call(port, "POST", p, &b_bot, &body.to_string()).await;
        assert_eq!(code, 403, "{p}: {res}");
    }
    let check = json!({ "from": a1.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "ls" } } }).to_string();
    let (code, res) = call(port, "POST", "/api/approvals/check", &b_bot, &check).await;
    assert_eq!((code, res.lines().next()), (200, Some("deny")), "the hook can't borrow A's Bot's rules");
    assert!(app.db.approvals(None, None, 10).is_empty());

    // And it can't reach A's Bot as itself either.
    assert_eq!(call(port, "GET", &format!("/api/bots/{}/messages", a1.id), &b_bot, "").await.0, 404);
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", a1.id), &b_bot, r#"{"text":"hi"}"#).await.0, 404);
    assert_eq!(call(port, "GET", &format!("/api/bots/{}/screen", a1.id), &b_bot, "").await.0, 404);
    let (_, list) = call(port, "GET", "/api/bots", &b_bot, "").await;
    assert!(list.contains(&b2.id) && !list.contains(&a1.id), "{list}");
    let (_, res) = call(port, "GET", &format!("/api/bots/{}/messages", a1.id), &a_bot, "").await;
    assert!(res.contains("ada-private-note"), "A's own Bot still reads its chat");

    // Leaving `from` out means itself; a new Bot it makes is its owner's.
    let (code, made) = call(port, "POST", "/api/bots", &b_bot, r#"{"name":"Child"}"#).await;
    assert_eq!(code, 201, "{made}");
    assert_eq!(parse(&made)["owner"]["id"], w.b_id.as_str());

    // Tokens that aren't this start's, are made up, or belong to a Bot that's gone.
    let mac = b_bot.rsplit_once('.').unwrap().1;
    let shared_style = format!("Bearer {}", crate::random_hex(24));
    let forged = format!("Bearer sbb_{}.{mac}", a1.id);
    let other_start = BotKey(crate::random_hex(32)).auth(&b1.id);
    app.db.delete_bot(&b2.id);
    let gone = w.key.auth(&b2.id);
    for (who, auth) in [("a deleted Bot", &gone), ("one shared token", &shared_style), ("B's MAC on A's id", &forged), ("another start's key", &other_start)] {
        assert_eq!(call(port, "GET", "/api/bots", auth, "").await.0, 401, "{who}");
    }
    // Failures are logged once per client per window; the first was the deleted Bot's.
    let failed = events(port, &w.admin, "action=auth.login_failed").await;
    assert!(failed.iter().any(|e| e["details"]["reason"] == "bot_gone" && e["authMethod"] == "bot_token"), "{failed:?}");
}

#[tokio::test]
async fn a_bot_can_do_no_more_than_its_owner() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    let (r_id, _) = user_with(port, &w.admin, "rae@example.com", "readonly").await;
    let rb = app.db.create_bot_owned("Rae's", "#fff", "waddle", "claude", None, false, &r_id, Visibility::Private);
    let r_bot = w.key.auth(&rb.id);
    assert_eq!(call(port, "GET", "/api/bots", &r_bot, "").await.0, 200);
    let (code, res) = call(port, "POST", "/api/bots", &r_bot, r#"{"name":"More"}"#).await;
    assert_eq!(code, 403, "a read-only user's Bot can't make Bots: {res}");
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/routines", rb.id), &r_bot, r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#).await.0, 403);
    let denied = events(port, &w.admin, "action=access.denied").await;
    assert!(denied.iter().any(|e| e["details"]["reason"] == "owner_role" && e["actorId"] == rb.id.as_str()));

    // A disabled owner's Bot keeps nothing.
    let ab = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let a_bot = w.key.auth(&ab.id);
    assert!(call(port, "GET", "/api/bots", &a_bot, "").await.1.contains(&ab.id));
    assert_eq!(call(port, "PATCH", &format!("/api/users/{}", w.a_id), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);
    let (code, list) = call(port, "GET", "/api/bots", &a_bot, "").await;
    assert_eq!(code, 403, "{list}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{}/messages", ab.id), &a_bot, "").await.0, 403);
}

#[tokio::test]
async fn each_users_secrets_reach_only_their_bots() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    fake_claude(app, "ISO_TEST_API_KEY");
    let ab = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let bb = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let value = format!("sk-ant-ada-{}", crate::random_hex(12));
    let put = json!({ "value": value }).to_string();
    let path = "/api/me/secrets/ISO_TEST_API_KEY";

    // Only people keep secrets, and only their own.
    assert_eq!(call(port, "PUT", path, "", &put).await.0, 401);
    for bot in [&ab, &bb] {
        let auth = w.key.auth(&bot.id);
        assert_eq!(call(port, "PUT", path, &auth, &put).await.0, 403);
        assert_eq!(call(port, "GET", "/api/me/secrets", &auth, "").await.0, 403);
        assert_eq!(call(port, "DELETE", path, &auth, "").await.0, 403);
    }
    for bad in ["PATH", "BOT_TOKEN", "LINODE_TOKEN", "TURNSTILE_SECRET", "SSO_X_CLIENT_SECRET", "lower"] {
        assert_eq!(call(port, "PUT", &format!("/api/me/secrets/{bad}"), &w.a, &put).await.0, 400, "{bad}");
    }
    let (code, res) = call(port, "PUT", path, &w.a, &put).await;
    assert_eq!(code, 200, "{res}");
    assert!(!res.contains(&value));
    let (_, mine) = call(port, "GET", "/api/me/secrets", &w.a, "").await;
    assert!(mine.contains("ISO_TEST_API_KEY") && !mine.contains(&value), "{mine}");
    let (_, theirs) = call(port, "GET", "/api/me/secrets", &w.b, "").await;
    assert_eq!(parse(&theirs)["secrets"], json!([]), "Bea sees none of Ada's");
    assert_eq!(call(port, "DELETE", path, &w.b, "").await.0, 404, "Bea can't delete Ada's");
    assert!(crate::secrets::global().user_list(&w.a_id).unwrap().iter().any(|l| l.name == "ISO_TEST_API_KEY"));
    let (_, server_wide) = call(port, "GET", "/api/secrets", &w.admin, "").await;
    assert!(!server_wide.contains("ISO_TEST_API_KEY"), "not a server-wide secret");

    // Admins see the names, not the values; nobody else sees them at all.
    let admin_path = format!("/api/users/{}/secrets", w.a_id);
    let (code, listed) = call(port, "GET", &admin_path, &w.admin, "").await;
    assert!(code == 200 && listed.contains("ISO_TEST_API_KEY") && !listed.contains(&value), "{code} {listed}");
    for auth in [&w.b, &w.a, &w.key.auth(&ab.id)] {
        assert_eq!(call(port, "GET", &admin_path, auth, "").await.0, 403);
        assert_eq!(call(port, "DELETE", &admin_path, auth, "").await.0, 403);
    }

    // Ada's Bot gets it; Bea's doesn't. The reply that echoes it is redacted.
    let ada = run(&w, &w.a, &ab.id, "go").await;
    assert!(ada.contains("key=[redacted]") && !ada.contains(&value), "{ada}");
    let bea = run(&w, &w.b, &bb.id, "go").await;
    assert!(bea.contains("key=none"), "{bea}");

    let audit = events(port, &w.admin, "action=secret.*").await;
    assert!(audit.iter().any(|e| e["action"] == "secret.set" && e["details"]["scope"] == "user" && e["details"]["userId"] == w.a_id.as_str()));
    assert!(!serde_json::to_string(&audit).unwrap().contains(&value));
    let (code, gone) = call(port, "DELETE", &admin_path, &w.admin, "").await;
    assert_eq!((code, parse(&gone)["deleted"].as_u64()), (200, Some(1)));
    assert!(crate::secrets::global().user_list(&w.a_id).unwrap().is_empty());
    crate::secrets::redact::forget(&value);
}

#[tokio::test]
async fn each_users_bots_work_in_their_own_folder() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    fake_claude(app, "UNSET_VAR");
    let ab = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let bb = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let ws = crate::paths::canonical(&app.cfg.workspace).unwrap();
    let ada = run(&w, &w.a, &ab.id, "where are you?").await;
    let bea = run(&w, &w.b, &bb.id, "where are you?").await;
    let a_dir = ws.join("users").join(&w.a_id);
    let b_dir = ws.join("users").join(&w.b_id);
    assert!(ada.contains(&format!("cwd={}", a_dir.display())), "{ada}");
    assert!(bea.contains(&format!("cwd={}", b_dir.display())), "{bea}");
    assert_ne!(app.user_file(&w.a_id), app.user_file(&w.b_id));
    let facts = |u: &str| std::fs::read_to_string(app.user_file(u).unwrap()).unwrap();
    assert!(facts(&w.a_id).contains("- Name: ada") && facts(&w.b_id).contains("- Name: bea"), "{} {}", facts(&w.a_id), facts(&w.b_id));
    assert!(!app.cfg.data_dir.join("USER.md").exists(), "no facts file shared by every user");
    // No route serves files, so B has no way to A's folder through the API, and the
    // approval policy counts A's folder as outside B's Bot's workspace.
    assert_eq!(app.policy_ctx(&bb).workspace, b_dir);
    assert_eq!(call(port, "GET", &format!("/api/users/{}/bots", w.a_id), &w.b, "").await.0, 403);
}

#[tokio::test]
async fn shared_bots_work_for_others_but_stay_their_owners() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    fake_claude(app, "ISO_SHARED_KEY");
    let value = format!("sk-shared-ada-{}", crate::random_hex(10));
    crate::secrets::global().user_put(&w.a_id, "ISO_SHARED_KEY", &value).unwrap();
    let shared = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Shared);
    let granted = app.db.create_bot_owned("Granted", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{}/grants/{}", granted.id, w.b_id), &w.a, r#"{"level":"operator"}"#).await.0, 200);
    let a_dir = crate::paths::canonical(&app.cfg.workspace).unwrap().join("users").join(&w.a_id);

    for bot in [&shared, &granted] {
        // Bea can use it: chat, its screen, its routines.
        let (_, list) = call(port, "GET", "/api/bots", &w.b, "").await;
        assert!(list.contains(&bot.id), "{list}");
        let (code, res) = call(port, "GET", &format!("/api/bots/{}/screen", bot.id), &w.b, "").await;
        assert!(code == 404 && res.contains("Screens are off"), "past the ACL: {res}");
        assert_eq!(call(port, "POST", &format!("/api/bots/{}/routines", bot.id), &w.b, r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#).await.0, 201);
        // It still runs as Ada's: in her folder, with her keys.
        let reply = run(&w, &w.b, &bot.id, "status").await;
        assert!(reply.contains(&format!("cwd={}", a_dir.display())) && reply.contains("key=[redacted]"), "{reply}");
        // Bea can't make it hers or change who sees it.
        for (m, p, b) in [
            ("PATCH", format!("/api/bots/{}", bot.id), r#"{"name":"Bea's now"}"#.to_string()),
            ("DELETE", format!("/api/bots/{}", bot.id), String::new()),
            ("PATCH", format!("/api/bots/{}/access", bot.id), r#"{"visibility":"private"}"#.to_string()),
            ("PATCH", format!("/api/bots/{}/access", bot.id), json!({ "owner": w.b_id }).to_string()),
            ("PUT", format!("/api/bots/{}/grants/{}", bot.id, w.b_id), r#"{"level":"operator"}"#.to_string()),
        ] {
            let (code, res) = call(port, m, &p, &w.b, &b).await;
            assert_eq!(code, 403, "{m} {p}: {res}");
        }
        assert_eq!(app.db.bot(&bot.id).unwrap().owner_id, w.a_id);
    }
    // Bea's own Bot can ask the shared one, which still answers from Ada's space.
    let bb = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let ask = json!({ "to": shared.id, "text": "status?" }).to_string();
    let (code, reply) = call(port, "POST", "/api/ask", &w.key.auth(&bb.id), &ask).await;
    assert_eq!(code, 200, "{reply}");
    assert!(reply.contains(&format!("cwd={}", a_dir.display())), "{reply}");
    // Revoking the grant ends it.
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{}/grants/{}", granted.id, w.b_id), &w.a, "").await.0, 200);
    assert_eq!(call(port, "GET", &format!("/api/bots/{}/messages", granted.id), &w.b, "").await.0, 404);
    crate::secrets::global().user_forget(&w.a_id).unwrap();
    crate::secrets::redact::forget(&value);
}

#[tokio::test]
async fn people_reach_only_their_own_sessions() {
    let w = world().await;
    let port = w.port;
    let a_session = {
        let (_, me) = call(port, "GET", "/api/auth/me", &w.a, "").await;
        parse(&me)["session"]["id"].as_str().map(String::from)
    };
    for (m, p) in [
        ("GET", "/api/sessions".to_string()),
        ("DELETE", format!("/api/sessions/{}", a_session.clone().unwrap_or_else(|| "s1".into()))),
        ("DELETE", format!("/api/users/{}/sessions", w.a_id)),
        ("GET", format!("/api/users/{}", w.a_id)),
        ("GET", format!("/api/users/{}/bots", w.a_id)),
        ("POST", format!("/api/users/{}/login-codes", w.a_id)),
        ("GET", format!("/api/users/{}/machine", w.a_id)),
    ] {
        assert_eq!(call(port, m, &p, &w.b, "").await.0, 403, "{m} {p}");
    }
    assert_eq!(call(port, "GET", "/api/auth/me", &w.a, "").await.0, 200, "Ada's session lives");
    // Bea's sign-out ends her session only.
    assert_eq!(call(port, "POST", "/api/auth/logout", &w.b, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/auth/me", &w.b, "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/auth/me", &w.a, "").await.0, 200);
}

#[tokio::test]
async fn with_routing_on_a_bot_runs_only_on_its_owners_machine() {
    let fake = Arc::new(Fake::default());
    let link = Arc::new(Recording::default());
    let (p, l): (Arc<dyn MachineProvider>, Arc<dyn crate::machines::route::MachineLink>) = (fake.clone(), link.clone());
    let (port, app, owner, key) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(p);
        (cp.routing, cp.link) = (true, l);
        a.machines = Arc::new(cp);
    })
    .await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let w = World { port, app: app.clone(), admin: admin.clone(), key, a_id: a_id.clone(), a: a.clone(), b_id: b_id.clone(), b: b.clone() };
    fake_claude(&app, "UNSET_VAR");
    let ab = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Private);
    let team = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Shared);
    let bb = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &b_id, Visibility::Private);

    // Ada's machine isn't up yet: her Bots don't run, here or anywhere.
    assert_eq!(call(port, "POST", &format!("/api/users/{a_id}/machine"), &admin, "{}").await.0, 202);
    let said = run(&w, &a, &ab.id, "hi").await;
    assert!(said.contains("your computer is provisioning"), "{said}");
    let (code, v) = call(port, "POST", "/api/machines/reconcile", &admin, "").await;
    assert_eq!(code, 200, "{v}");
    let machine = app.db.user_machine(&a_id).unwrap();
    assert_eq!(machine.state, crate::machines::State::Running);

    // Running: Ada's work goes to her machine, and nothing runs here.
    for (who, bot) in [(&a, &ab), (&b, &team)] {
        let before = link.sent.lock().unwrap().len();
        let (code, m) = call(port, "POST", &format!("/api/bots/{}/messages", bot.id), who, r#"{"text":"go"}"#).await;
        assert_eq!(code, 202, "{m}");
        let id = parse(&m)["id"].as_i64().unwrap();
        for _ in 0..200 {
            if link.sent.lock().unwrap().len() > before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let sent = link.sent.lock().unwrap().last().cloned().unwrap();
        assert_eq!((sent.0.machine_id.as_str(), sent.0.user_id.as_str()), (machine.id.as_str(), a_id.as_str()), "the owner's machine, whoever asked");
        assert_eq!((sent.1.bot_id.as_str(), sent.1.owner_id.as_str(), sent.1.message_id), (bot.id.as_str(), a_id.as_str(), id));
    }
    let routed = events(port, &admin, "action=bot.run_routed").await;
    assert_eq!(routed.len(), 2);
    assert!(routed.iter().all(|e| e["details"]["machine"] == machine.id.as_str() && e["details"]["link"] == "recording"));
    assert!(events(port, &admin, &format!("action=harness.invoked&bot={}", ab.id)).await.is_empty(), "nothing ran on this server");

    // Bea has no machine: her Bot is refused, not run on Ada's or here.
    let said = run(&w, &b, &bb.id, "hi").await;
    assert!(said.contains("you don't have a computer"), "{said}");
    assert!(link.sent.lock().unwrap().iter().all(|(to, job)| to.user_id == a_id && job.owner_id == a_id));
    let refused = events(port, &admin, "action=bot.run_refused").await;
    assert!(refused.iter().any(|e| e["botId"] == bb.id.as_str() && e["details"]["reason"] == "no_machine" && e["outcome"] == "denied"), "{refused:?}");

    // Suspended: refused again.
    assert_eq!(call(port, "POST", &format!("/api/users/{a_id}/machine/suspend"), &admin, "").await.0, 200);
    let said = run(&w, &a, &ab.id, "hi").await;
    assert!(said.contains("suspended"), "{said}");
    assert_eq!(fake.calls("create"), 1);
}

#[test]
fn the_unenrolled_link_refuses_every_job() {
    use crate::machines::route::{Assigned, Job, MachineLink, Unenrolled};
    let to = Assigned { machine_id: "m1".into(), user_id: "u1".into(), address: Some("192.0.2.1".into()) };
    let job = Job { bot_id: "b1".into(), owner_id: "u1".into(), message_id: 1 };
    let r = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(Unenrolled.dispatch(&to, job));
    assert!(r.unwrap_err().contains("can't send work"));
}
