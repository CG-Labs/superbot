//! Tiers and hidden model routing (ADR 0033), on the real router: without a tiers file
//! nothing changes; on a managed tier nobody can set a Bot to a model outside it, only
//! admins see models, every run takes the route the Bot owner's tier picks, and the
//! tier's limits hold, counted per user. Only admins assign tiers, and it's audited.

use crate::acl::Visibility;
use crate::acl_http_tests::read_until;
use crate::tests::{audit_list, call, serve_app, BotKey};
use crate::tiers::{Tiers, EXAMPLE};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::io::AsyncWriteExt;

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

/// A server on the example tiers (starter is the default), with Ada and Bea, members.
async fn world() -> World {
    let (port, app, admin, key) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(EXAMPLE, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    fake_claude(&app);
    World { port, app, admin, key, a_id, a, b_id, b }
}

/// A stand-in `claude` that replies with the model and effort it was started with.
pub(crate) fn fake_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let script = r#"#!/bin/sh
model=default effort=default
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model=$2; shift ;;
    --effort) effort=$2; shift ;;
    --) break ;;
  esac
  shift
done
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"model=$model effort=$effort\"}]}}"
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Sends `text` and waits for the Bot's reply.
pub(crate) async fn run(port: u16, app: &App, who: &str, bot: &str) -> String {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..300 {
        if let Some(m) = app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

async fn audit(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn set_tier(w: &World, user: &str, tier: Value) -> (u16, Value) {
    let (code, body) = call(w.port, "PATCH", &format!("/api/users/{user}"), &w.admin, &json!({ "tier": tier }).to_string()).await;
    (code, parse(&body))
}

#[tokio::test]
async fn without_tiers_nothing_changes() {
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let (_, a) = user_with(port, &admin, "ada@example.com", "member").await;
    // Any harness, model, and effort, as before tiers.
    let (code, made) = call(port, "POST", "/api/bots", &a, r#"{"name":"Free","harness":"claude","model":"claude-anything-9"}"#).await;
    assert_eq!(code, 201, "{made}");
    let id = parse(&made)["id"].as_str().unwrap().to_string();
    let (code, made) = call(port, "PATCH", &format!("/api/bots/{id}"), &a, r#"{"effort":"max"}"#).await;
    assert_eq!(code, 200, "{made}");
    let made = parse(&made);
    assert_eq!((made["model"].as_str(), made["effort"].as_str()), (Some("claude-anything-9"), Some("max")));
    assert_eq!(made["tier"], json!({ "name": "self-host", "label": "Self-host", "managed": false }));
    let id = id.as_str();
    assert_eq!(run(port, &app, &a, id).await, "model=claude-anything-9 effort=max");
    let (code, _) = call(port, "GET", "/api/harnesses/claude/models", &a, "").await;
    assert_eq!(code, 200);
    let (_, me) = call(port, "GET", "/api/me/tier", &a, "").await;
    let me = parse(&me);
    assert_eq!((me["name"].as_str(), me["managed"].as_bool(), me["usage"]["runs"].as_u64()), (Some("self-host"), Some(false), Some(1)));
    let (_, state) = call(port, "GET", "/api/state", &a, "").await;
    assert_eq!(parse(&state)["me"]["tier"]["name"], "self-host");
}

#[tokio::test]
async fn nobody_sets_a_model_outside_their_tier() {
    let w = world().await;
    let (port, a) = (w.port, &w.a);
    // Ada is on the default tier, starter: one Claude model at low effort.
    let refused = [
        r#"{"name":"X","harness":"claude","model":"claude-opus-4-1"}"#,
        r#"{"name":"X","harness":"codex"}"#,
        r#"{"name":"X","harness":"claude","effort":"max"}"#,
    ];
    for body in refused {
        let (code, res) = call(port, "POST", "/api/bots", a, body).await;
        assert_eq!(code, 403, "{body}: {res}");
    }
    let (code, made) = call(port, "POST", "/api/bots", a, r#"{"name":"Mine"}"#).await;
    assert_eq!(code, 201, "{made}");
    let made = parse(&made);
    let id = made["id"].as_str().unwrap().to_string();
    assert_eq!(made["harness"], "claude");
    // The model is the plan's, and not Ada's to see.
    assert!(made.get("model").is_none() && made.get("effort").is_none() && made.get("route").is_none(), "{made}");
    assert_eq!(made["tier"], json!({ "name": "starter", "label": "Starter", "managed": true }));

    let path = format!("/api/bots/{id}");
    for body in [r#"{"model":"claude-opus-4-1"}"#, r#"{"effort":"high"}"#, r#"{"harness":"pi"}"#] {
        let (code, res) = call(port, "PATCH", &path, a, body).await;
        assert_eq!(code, 403, "{body}: {res}");
    }
    // The plan's own model, or none, is fine; so is everything that isn't routing.
    assert_eq!(call(port, "PATCH", &path, a, r#"{"model":"claude-haiku-4-5"}"#).await.0, 200);
    assert_eq!(call(port, "PATCH", &path, a, r#"{"model":null,"name":"Renamed"}"#).await.0, 200);
    // Admins are held to the tier too: it is the routing table.
    let (code, res) = call(port, "PATCH", &path, &w.admin, r#"{"model":"claude-opus-4-1"}"#).await;
    assert_eq!(code, 403, "{res}");

    // No model names anywhere Ada looks.
    for p in ["/api/bots", "/api/state", "/api/me/tier", "/api/auth/me"] {
        let (code, body) = call(port, "GET", p, a, "").await;
        assert_eq!(code, 200, "{p}");
        assert!(!body.contains("haiku") && !body.contains("\"model\""), "{p}: {body}");
    }
    let (code, res) = call(port, "GET", "/api/harnesses/claude/models", a, "").await;
    assert_eq!(code, 403, "{res}");
    assert_eq!(call(port, "GET", "/api/harnesses/claude/models?tier=pro", a, "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/tiers", a, "").await.0, 403);

    // Admins see the model, the route it runs on, and every tier's routes.
    let (_, list) = call(port, "GET", "/api/bots", &w.admin, "").await;
    let mine = parse(&list).as_array().unwrap().iter().find(|b| b["id"] == id.as_str()).cloned().unwrap();
    assert_eq!(mine["route"], json!({ "harness": "claude", "model": "claude-haiku-4-5", "effort": "low" }));
    assert!(mine.get("model").is_some(), "{mine}");
    // An admin editing Ada's Bot is offered her tier's installed harnesses, not their own.
    let installed = |of: &[&str]| json!(adapters::installed().into_iter().filter(|h| of.contains(h)).collect::<Vec<_>>());
    assert_eq!(set_tier(&w, &w.a_id, json!("pro")).await.0, 200);
    let (_, list) = call(port, "GET", "/api/bots", &w.admin, "").await;
    let mine = parse(&list).as_array().unwrap().iter().find(|b| b["id"] == id.as_str()).cloned().unwrap();
    assert_eq!(mine["harnesses"], installed(&["claude", "hermes"]));
    let (_, state) = call(port, "GET", "/api/state", &w.admin, "").await;
    assert_eq!(parse(&state)["harnesses"], installed(&["claude"]), "the admin's own tier, starter");
    assert_eq!(set_tier(&w, &w.a_id, Value::Null).await.0, 200);
    let (_, models) = call(port, "GET", "/api/harnesses/claude/models?tier=pro", &w.admin, "").await;
    let ids: Vec<String> = parse(&models).as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids, ["claude-sonnet-4-5", "claude-opus-4-1"]);
    assert_eq!(call(port, "GET", "/api/harnesses/claude/models?tier=gold", &w.admin, "").await.0, 404);
    let (code, tiers) = call(port, "GET", "/api/tiers", &w.admin, "").await;
    assert_eq!(code, 200);
    let tiers = parse(&tiers);
    assert_eq!(tiers["default"], "starter");
    assert_eq!(tiers["tiers"][1]["routes"][2]["provider"], "openrouter");

    // Bea, a member Ada shares with, sees no model either.
    let (code, _) = call(port, "PATCH", &format!("/api/bots/{id}/access"), a, r#"{"visibility":"shared"}"#).await;
    assert_eq!(code, 200);
    let (_, theirs) = call(port, "GET", "/api/bots", &w.b, "").await;
    assert!(theirs.contains(&id) && !theirs.contains("haiku"), "{theirs}");
}

#[tokio::test]
async fn every_run_takes_the_owners_tier_route() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    // Set straight in the store, as a Bot from before tiers would be.
    let bot = app.db.create_bot_owned("Legacy", "#fff", "waddle", "claude", Some("claude-opus-4-1"), false, &w.a_id, Visibility::Shared);
    app.db.update_bot(&bot.id, db::BotPatch { effort: Some(Some("max".into())), ..Default::default() });

    // Starter: its one model, at its effort, whatever the Bot says.
    assert_eq!(run(port, app, &w.a, &bot.id).await, "model=claude-haiku-4-5 effort=low");
    // The owner's tier, not the asker's: Bea (pro) asking Ada's Bot.
    assert_eq!(set_tier(&w, &w.b_id, json!("pro")).await.0, 200);
    assert_eq!(run(port, app, &w.b, &bot.id).await, "model=claude-haiku-4-5 effort=low");
    // Pro has that model: now it runs on it, at the route's effort.
    assert_eq!(set_tier(&w, &w.a_id, json!("pro")).await.0, 200);
    assert_eq!(run(port, app, &w.a, &bot.id).await, "model=claude-opus-4-1 effort=high");
    // An effort alone is checked against the route of the model the Bot keeps.
    let path = format!("/api/bots/{}", bot.id);
    assert_eq!(call(port, "PATCH", &path, &w.a, r#"{"effort":"high"}"#).await.0, 200);
    assert_eq!(call(port, "PATCH", &path, &w.a, r#"{"effort":"low"}"#).await.0, 403);
    // Self-host: exactly the Bot's settings.
    assert_eq!(set_tier(&w, &w.a_id, json!("self-host")).await.0, 200);
    assert_eq!(call(port, "PATCH", &path, &w.a, r#"{"effort":"max"}"#).await.0, 200);
    assert_eq!(run(port, app, &w.a, &bot.id).await, "model=claude-opus-4-1 effort=max");
    assert_eq!(set_tier(&w, &w.a_id, Value::Null).await.0, 200);

    let invoked = audit(port, &w.admin, &format!("action=harness.invoked&bot={}", bot.id)).await;
    let routes: Vec<(String, String)> =
        invoked.iter().map(|e| (e["details"]["tier"].as_str().unwrap().into(), e["details"]["model"].as_str().unwrap().into())).collect();
    for want in [("starter", "claude-haiku-4-5"), ("pro", "claude-opus-4-1"), ("self-host", "claude-opus-4-1")] {
        assert!(routes.contains(&(want.0.into(), want.1.into())), "{want:?} in {routes:?}");
    }

    // A harness the tier doesn't have doesn't run on something else: it's refused.
    let codex = app.db.create_bot_owned("Codex", "#fff", "waddle", "codex", None, false, &w.a_id, Visibility::Private);
    let said = run(port, app, &w.a, &codex.id).await;
    assert!(said.contains("doesn't include the codex harness"), "{said}");
    let refused = audit(port, &w.admin, &format!("action=bot.run_refused&bot={}", codex.id)).await;
    assert_eq!(refused[0]["details"]["reason"], "tier_harness");
    assert_eq!(refused[0]["outcome"], "denied");
}

#[tokio::test]
async fn only_admins_assign_tiers_and_it_is_audited() {
    let w = world().await;
    let path = format!("/api/users/{}", w.b_id);
    assert_eq!(call(w.port, "PATCH", &path, &w.a, r#"{"tier":"pro"}"#).await.0, 403);
    let (code, res) = set_tier(&w, &w.b_id, json!("gold")).await;
    assert_eq!(code, 400);
    assert!(res["error"].as_str().unwrap().contains("starter, pro, self-host"), "{res}");
    let (code, u) = set_tier(&w, &w.b_id, json!("pro")).await;
    assert_eq!((code, u["tier"].as_str()), (200, Some("pro")));
    // Patching something else leaves it; null puts them back on the default.
    assert_eq!(call(w.port, "PATCH", &path, &w.admin, r#"{"name":"Bea"}"#).await.0, 200);
    assert_eq!(w.app.db.user(&w.b_id).unwrap().tier.as_deref(), Some("pro"));
    let (code, u) = set_tier(&w, &w.b_id, Value::Null).await;
    assert_eq!((code, u["tier"].clone()), (200, Value::Null));

    let ev: Vec<Value> = audit(w.port, &w.admin, "action=user.tier_changed").await.into_iter().filter(|e| e["targetId"] == w.b_id.as_str()).collect();
    assert_eq!(ev.len(), 2, "{ev:?}");
    let up = ev.iter().find(|e| e["details"]["to"] == "pro").unwrap();
    assert_eq!(up["details"], json!({ "from": null, "to": "pro", "effectiveFrom": "starter", "effectiveTo": "pro" }));
    assert_eq!(up["actorId"], users::OPERATOR);
    let down = ev.iter().find(|e| e["details"]["from"] == "pro").unwrap();
    assert_eq!(down["details"]["effectiveTo"], "starter");

    // The admin portal shows each person's plan and use, with no models.
    let (_, user) = call(w.port, "GET", &path, &w.admin, "").await;
    let user = parse(&user);
    assert_eq!((user["tier"].clone(), user["plan"]["name"].as_str()), (Value::Null, Some("starter")));
    assert_eq!(user["plan"]["limits"]["maxBots"], 2);
}

#[tokio::test]
async fn tier_limits_hold_per_user() {
    let w = world().await;
    let (port, app) = (w.port, &w.app);
    // Starter: 2 Bots each.
    let mut mine = Vec::new();
    for n in ["One", "Two"] {
        let (code, b) = call(port, "POST", "/api/bots", &w.a, &json!({ "name": n }).to_string()).await;
        assert_eq!(code, 201, "{b}");
        mine.push(parse(&b)["id"].as_str().unwrap().to_string());
    }
    let (code, res) = call(port, "POST", "/api/bots", &w.a, r#"{"name":"Three"}"#).await;
    assert_eq!(code, 403);
    assert!(res.contains("allows 2 Bots"), "{res}");
    // Ada's Bots aren't Bea's: she still has both of hers, and a Bot can't make a third for Ada.
    assert_eq!(call(port, "POST", "/api/bots", &w.b, r#"{"name":"Hers"}"#).await.0, 201);
    assert_eq!(call(port, "POST", "/api/bots", &w.key.auth(&mine[0]), r#"{"name":"Child"}"#).await.0, 403);
    // Nor can an admin hand Ada another.
    let theirs = app.db.create_bot_owned("Spare", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let (code, res) = call(port, "PATCH", &format!("/api/bots/{}/access", theirs.id), &w.admin, &json!({ "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 403, "{res}");
    assert_eq!(app.db.bot(&theirs.id).unwrap().owner_id, w.b_id, "a refused transfer changes nothing");

    // Starter: 3 runs a month, counted for the Bot's owner whoever asks.
    let shared = &mine[0];
    assert_eq!(call(port, "PATCH", &format!("/api/bots/{shared}/access"), &w.a, r#"{"visibility":"shared"}"#).await.0, 200);
    for who in [&w.a, &w.b, &w.a] {
        assert!(run(port, app, who, shared).await.starts_with("model="));
    }
    let said = run(port, app, &w.a, shared).await;
    assert!(said.contains("allows 3 runs a month"), "{said}");
    let refused = audit(port, &w.admin, &format!("action=bot.run_refused&bot={shared}")).await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["limit"].as_u64()), (Some("tier_limit"), Some(3)));

    let usage = |who: &str| {
        let who = who.to_string();
        async move { parse(&call(port, "GET", "/api/me/tier", &who, "").await.1)["usage"].clone() }
    };
    let a = usage(&w.a).await;
    assert_eq!((a["runs"].as_u64(), a["bots"].as_u64()), (Some(3), Some(2)));
    let b = usage(&w.b).await;
    assert_eq!((b["runs"].as_u64(), b["bots"].as_u64()), (Some(0), Some(2)));
    // Bea's runs are hers: her own Bot still runs.
    let hers = app.db.create_bot_owned("Hers2", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    assert!(run(port, app, &w.b, &hers.id).await.starts_with("model="));
    // A Bot's plan is its owner's; it has none of its own to ask for.
    assert_eq!(call(port, "GET", "/api/me/tier", &w.key.auth(shared), "").await.0, 403);
    // Its owner's plan, not the operator's, decides what it may list.
    assert_eq!(set_tier(&w, users::OPERATOR, json!("self-host")).await.0, 200);
    assert_eq!(call(port, "GET", "/api/harnesses/claude/models", &w.admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/harnesses/claude/models", &w.key.auth(shared), "").await.0, 403);
    let (_, state) = call(port, "GET", "/api/state", &w.key.auth(shared), "").await;
    assert_eq!(parse(&state)["me"]["tier"]["name"], "starter");
    assert_eq!(set_tier(&w, users::OPERATOR, Value::Null).await.0, 200);
    assert_eq!(set_tier(&w, &w.a_id, json!("self-host")).await.0, 200);
    assert_eq!(call(port, "GET", "/api/harnesses/claude/models", &w.key.auth(shared), "").await.0, 200, "the operator is on starter");
    // Moving Ada up lifts the limit at once.
    assert_eq!(set_tier(&w, &w.a_id, json!("pro")).await.0, 200);
    assert!(run(port, app, &w.a, shared).await.starts_with("model=claude-sonnet-4-5"));
}

#[tokio::test]
async fn the_live_stream_shows_models_only_to_admins() {
    let w = world().await;
    let bot = w.app.db.create_bot_owned("Live", "#fff", "waddle", "claude", Some("claude-haiku-4-5"), false, &w.a_id, Visibility::Shared);
    let mut streams = Vec::new();
    for who in [&w.a, &w.admin] {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", w.port)).await.unwrap();
        let req = format!("GET /api/events HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nAuthorization: {who}\r\n\r\n", w.port);
        s.write_all(req.as_bytes()).await.unwrap();
        read_until(&mut s, "\r\n\r\n").await;
        streams.push(s);
    }
    w.app.push_bot(&bot.id);
    // One event each, whole: SSE ends an event with a blank line.
    let member = read_until(&mut streams[0], "\n\n").await;
    assert!(member.contains(&bot.id) && member.contains(r#""managed":true"#), "{member}");
    assert!(!member.contains("haiku") && !member.contains(r#""model""#), "{member}");
    let admin = read_until(&mut streams[1], "\n\n").await;
    assert!(admin.contains(r#""model":"claude-haiku-4-5""#) && admin.contains(r#""route""#), "{admin}");
}

/// A managed tier whose first route is Hermes, and an open one (ADR 0079).
const HERMES_FIRST: &str = r#"{
  "default": "team",
  "tiers": [
    { "name": "team", "label": "Team",
      "routes": [{ "harness": "hermes", "model": "anthropic/claude-sonnet-4.5" }, { "harness": "claude", "model": "claude-sonnet-4-5" }] },
    { "name": "self-host", "routes": "any" }
  ]
}"#;

/// A stand-in `hermes` that answers every run.
fn fake_hermes(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("hermes");
    let script = r#"#!/bin/sh
[ "$1" = gateway ] && exit 0
cat >/dev/null
printf '%s\n' '{"type":"result","session_id":"s1","exit_code":0,"text":"Hermes ran."}'
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn new_bots_get_their_plans_harness_and_open_tiers_the_servers() {
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(HERMES_FIRST, None).unwrap())).unwrap();
    assert_eq!(app.cfg.default_harness, "claude");
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    fake_claude(&app);
    fake_hermes(&app);
    let made = |body: &'static str| {
        let a = a.clone();
        async move {
            let (code, made) = call(port, "POST", "/api/bots", &a, body).await;
            assert_eq!(code, 201, "{made}");
            parse(&made)
        }
    };
    let created = |id: String| {
        let admin = admin.clone();
        async move { audit(port, &admin, &format!("action=bot.created&bot={id}")).await[0]["details"].clone() }
    };

    // On a managed plan, the plan's harness, though the server's is claude.
    let (_, state) = call(port, "GET", "/api/state", &a, "").await;
    assert_eq!(parse(&state)["defaultHarness"], "hermes");
    let new = made(r#"{"name":"New"}"#).await;
    assert_eq!(new["harness"], "hermes");
    let new_id = new["id"].as_str().unwrap().to_string();
    let d = created(new_id.clone()).await;
    assert_eq!((d["harnessFrom"].as_str(), d["tier"].as_str(), d["harness"].as_str()), (Some("plan"), Some("team"), Some("hermes")));
    assert_eq!(run(port, &app, &a, &new_id).await, "Hermes ran.");
    // Another of the plan's harnesses, when asked for.
    let chosen = made(r#"{"name":"Picked","harness":"claude"}"#).await;
    assert_eq!(chosen["harness"], "claude");
    assert_eq!(created(chosen["id"].as_str().unwrap().into()).await["harnessFrom"], "chosen");

    // Self-host: DEFAULT_HARNESS, as before.
    let (code, _) = call(port, "PATCH", &format!("/api/users/{a_id}"), &admin, r#"{"tier":"self-host"}"#).await;
    assert_eq!(code, 200);
    let (_, state) = call(port, "GET", "/api/state", &a, "").await;
    assert_eq!(parse(&state)["defaultHarness"], "claude");
    let open = made(r#"{"name":"Open"}"#).await;
    assert_eq!(open["harness"], "claude");
    let d = created(open["id"].as_str().unwrap().into()).await;
    assert_eq!((d["harnessFrom"].as_str(), d["tier"].as_str()), (Some("server"), Some("self-host")));

    // Hermes not installed here: refused up front and why, and not counted as a run.
    let (code, _) = call(port, "PATCH", &format!("/api/users/{a_id}"), &admin, r#"{"tier":null}"#).await;
    assert_eq!(code, 200);
    std::fs::remove_file(app.cfg.bin_dir.join("hermes")).unwrap();
    if adapters::version::resolve("hermes", &std::env::var("PATH").unwrap_or_default(), &app.cfg.workspace).is_none() {
        let runs = || async { parse(&call(port, "GET", "/api/me/tier", &a, "").await.1)["usage"]["runs"].as_u64() };
        let before = runs().await;
        let said = run(port, &app, &a, &new_id).await;
        assert!(said.contains("hermes isn't installed on this server") && said.contains("--with-hermes"), "{said}");
        assert!(said.contains("or switch me to another harness"), "the plan has another: {said}");
        let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={new_id}")).await;
        let d = &refused[0]["details"];
        assert_eq!((d["reason"].as_str(), d["harness"].as_str(), d["host"].as_str(), d["tier"].as_str()), (Some("harness_missing"), Some("hermes"), Some("server"), Some("team")));
        assert_eq!(refused[0]["outcome"], "denied");
        assert_eq!(runs().await, before, "a refused run isn't counted");
    }
}

#[tokio::test]
async fn admins_move_a_plans_bots_onto_its_default_only_when_asked() {
    use std::os::unix::fs::PermissionsExt;
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(HERMES_FIRST, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, _) = user_with(port, &admin, "bea@example.com", "member").await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{b_id}"), &admin, r#"{"tier":"self-host"}"#).await.0, 200);
    // Bots from before the default, on Claude: the default alone doesn't move them.
    let one = app.db.create_bot_owned("One", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Private);
    let two = app.db.create_bot_owned("Two", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Private);
    app.db.update_bot(&two.id, db::BotPatch { session_id: Some(Some("old-session".into())), ..Default::default() });
    let hers = app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &b_id, Visibility::Private);
    let harness = |id: &str| app.db.bot(id).unwrap().harness;
    let ids = |v: &Value, k: &str| v[k].as_array().unwrap().iter().map(|b| b["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    let mv = |tier: &str, body: Value| {
        let (admin, path) = (admin.clone(), format!("/api/tiers/{tier}/move-bots"));
        async move {
            let (code, res) = call(port, "POST", &path, &admin, &body.to_string()).await;
            (code, parse(&res))
        }
    };

    assert_eq!(call(port, "POST", "/api/tiers/team/move-bots", &a, "{}").await.0, 403, "admins only");
    assert_eq!(mv("gold", json!({})).await.0, 404);
    let (code, res) = mv("self-host", json!({})).await;
    assert_eq!(code, 400, "an open tier has no default to move to: {res}");
    let (code, res) = mv("team", json!({ "user": "bea@example.com" })).await;
    assert_eq!(code, 409, "{res}");

    // A dry run lists them and changes nothing.
    let (code, res) = mv("team", json!({ "user": "ada@example.com", "dryRun": true })).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!((res["to"].as_str(), res["dryRun"].as_bool()), (Some("hermes"), Some(true)));
    let mut listed = ids(&res, "moved");
    listed.sort();
    let mut want = vec![one.id.clone(), two.id.clone()];
    want.sort();
    assert_eq!(listed, want);
    assert_eq!((harness(&one.id), harness(&two.id)), ("claude".into(), "claude".into()));
    assert!(audit(port, &admin, "action=tier.bots_moved").await.is_empty());

    // A Bot mid-run keeps its harness until it's done: skipped, and moved on a later call.
    let slow = app.cfg.bin_dir.join("claude");
    std::fs::write(&slow, "#!/bin/sh\nsleep 2\nprintf '%s\\n' '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"done\"}]}}'\n").unwrap();
    std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = app.db.last_id();
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", one.id), &a, r#"{"text":"go"}"#).await.0, 202);
    for _ in 0..100 {
        if app.is_busy(&one.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.is_busy(&one.id));
    let (code, res) = mv("team", json!({ "user": "ada@example.com" })).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!((ids(&res, "moved"), ids(&res, "skipped")), (vec![two.id.clone()], vec![one.id.clone()]));
    assert_eq!(res["skipped"][0]["reason"], "busy");
    let moved = app.db.bot(&two.id).unwrap();
    assert_eq!((moved.harness.as_str(), moved.session_id.as_deref()), ("hermes", None), "a new harness starts a new session");
    assert_eq!(harness(&one.id), "claude");
    let updated = audit(port, &admin, &format!("action=bot.updated&bot={}", two.id)).await;
    assert_eq!((updated[0]["details"]["via"].as_str(), updated[0]["details"]["tier"].as_str()), (Some("tier_default"), Some("team")));
    assert_eq!(updated[0]["actorId"], users::OPERATOR);
    let summary = audit(port, &admin, "action=tier.bots_moved").await;
    assert_eq!(summary[0]["details"], json!({ "to": "hermes", "moved": 1, "skipped": 1, "user": a_id }));
    assert_eq!(summary[0]["targetId"], "team");

    for _ in 0..300 {
        if !app.db.replies_after(&one.id, before).is_empty() && !app.is_busy(&one.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The whole plan, this time: Ada's last one and the operator's, never Bea's on self-host.
    let (_, res) = mv("team", json!({})).await;
    assert!(ids(&res, "moved").contains(&one.id) && ids(&res, "skipped").is_empty(), "{res}");
    assert_eq!(harness(&one.id), "hermes");
    assert_eq!(harness(&hers.id), "claude", "self-host Bots are left alone");
    let (_, res) = mv("team", json!({})).await;
    assert!(ids(&res, "moved").is_empty(), "nothing left to move: {res}");
}
