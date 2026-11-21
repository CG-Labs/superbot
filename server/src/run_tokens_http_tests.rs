//! HTTP tests for per-run tokens (ADR 0083), on the real router with real runs: every
//! run of a Bot, its owner's own included, gets a `BOT_TOKEN` of its own that acts only
//! as that Bot, never past its owner, and only while that run is live.

use crate::shared_bots_http_tests::{closes, open_stream};
use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

/// Installs a fake `bin` that writes its environment to `env` and, if `wait`, waits for
/// `go` before replying in `reply`'s format. Each run finds neither file left over.
fn fake(app: &App, bin: &str, wait: bool, reply: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = &app.cfg.bin_dir;
    let (env, go) = (dir.join(format!("{bin}.env")), dir.join(format!("{bin}.go")));
    let hold = if wait { format!("while [ ! -f '{go}' ]; do sleep 0.05; done\nrm -f '{go}'\n", go = go.display()) } else { String::new() };
    let script = format!("#!/bin/sh\n[ \"$1\" = --version ] && {{ echo '{bin} 99.0.0'; exit 0; }}\nenv > '{e}.tmp' && mv '{e}.tmp' '{e}'\n{hold}printf '%s\\n' '{reply}'\n", e = env.display());
    let path = dir.join(bin);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (env, go)
}

const CLAUDE_REPLY: &str = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Done here."}]}}"#;

/// The run's environment, once the fake harness has written it; the file is then removed.
async fn run_env(path: &std::path::Path) -> HashMap<String, String> {
    for _ in 0..500 {
        if let Ok(s) = std::fs::read_to_string(path) {
            let _ = std::fs::remove_file(path);
            return s.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the harness never started");
}

async fn audit(port: u16, admin: &str, query: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", &format!("/api/audit?{query}"), admin, "").await.1)
}

/// Waits until the Bot has finished `n` runs.
async fn finished(port: u16, admin: &str, bot: &str, n: usize) {
    for _ in 0..500 {
        if audit(port, admin, &format!("action=bot.run_finished&bot={bot}")).await.len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("run {n} of {bot} never finished");
}

fn bearer(env: &HashMap<String, String>) -> String {
    format!("Bearer {}", env["BOT_TOKEN"])
}

#[tokio::test]
async fn an_owners_run_gets_its_own_token_and_it_ends_with_the_run() {
    let (port, app, admin, _) = serve_app().await;
    let (go_env, go) = fake(&app, "claude", true, CLAUDE_REPLY);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, b) = call(port, "POST", "/api/bots", &ada, r#"{"name":"Mine","harness":"claude"}"#).await;
    assert_eq!(code, 201, "{b}");
    let bot = parse(&b)["id"].as_str().unwrap().to_string();

    // Ada asks her own Bot, signed in with her session.
    assert_eq!(call(port, "POST", &format!("/api/bots/{bot}/messages"), &ada, r#"{"text":"one"}"#).await.0, 202);
    let first = run_env(&go_env).await;
    let token = first["BOT_TOKEN"].clone();
    let run = first["SUPERBOT_RUN_ID"].clone();
    let (named, rest) = token.strip_prefix("sbb_").unwrap().split_once('.').unwrap();
    let token_id = rest.split_once('.').unwrap().0.to_string();
    assert_eq!(named, bot, "it names its Bot");

    // Nothing owner-level reaches the run: not Ada's session, not botd's key or password,
    // no operator token, only the run's own.
    let session = ada.strip_prefix("Bearer ").unwrap();
    for (k, v) in &first {
        assert!(!v.contains(session) && !v.contains(&app.cfg.bot_key), "{k} carries an owner-level credential");
        assert!(!v.starts_with(users::SESSION_PREFIX), "{k} is a session token");
    }
    for k in adapters::SECRET_ENV {
        assert!(!first.contains_key(k), "{k} reached the run");
    }

    // While the run is live, the token works as its Bot, for its owner.
    let (code, list) = call(port, "GET", "/api/bots", &bearer(&first), "").await;
    assert_eq!(code, 200, "{list}");
    assert!(list.contains(&bot));
    assert!(crate::secrets::redact::known().contains(&token), "chats redact the live token");
    let stream = open_stream(port, &bearer(&first)).await;
    let issued = audit(port, &admin, &format!("action=bot.token_issued&bot={bot}")).await;
    assert_eq!(issued.len(), 1, "{issued:?}");
    let d = &issued[0]["details"];
    assert_eq!((d["jti"].as_str(), d["runId"].as_str(), d["owner"].as_str()), (Some(token_id.as_str()), Some(run.as_str()), Some(ada_id.as_str())));
    assert!(d["forUser"].is_null() && d["expiresAt"].as_i64().unwrap() > db::now(), "{d}");
    assert_eq!(issued[0]["actorId"], ada_id.as_str(), "issued for whoever started the run");

    // The run ends: its token, and anything still holding it, is done.
    std::fs::write(&go, "").unwrap();
    finished(port, &admin, &bot, 1).await;
    assert!(closes(stream).await, "its open event stream closes with it");
    let (code, _) = call(port, "GET", "/api/bots", &bearer(&first), "").await;
    assert_eq!(code, 401, "a token outlives no run");
    let failed = audit(port, &admin, "action=auth.login_failed").await;
    assert!(failed.iter().any(|e| e["details"]["reason"] == "run_over" && e["authMethod"] == "bot_token"), "{failed:?}");
    let revoked = audit(port, &admin, &format!("action=bot.token_revoked&bot={bot}")).await;
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    let d = &revoked[0]["details"];
    assert_eq!((d["jti"].as_str(), d["runId"].as_str(), d["reason"].as_str()), (Some(token_id.as_str()), Some(run.as_str()), Some("run_ended")));
    assert!(!crate::secrets::redact::known().contains(&token), "the redactor doesn't keep every finished run's token");

    // The next run gets a new token; the old one stays dead while it's live.
    assert_eq!(call(port, "POST", &format!("/api/bots/{bot}/messages"), &ada, r#"{"text":"two"}"#).await.0, 202);
    let second = run_env(&go_env).await;
    assert_ne!(second["BOT_TOKEN"], token);
    assert_ne!(second["SUPERBOT_RUN_ID"], run);
    assert_eq!(call(port, "GET", "/api/bots", &bearer(&first), "").await.0, 401, "an earlier run's token stays dead");
    assert_eq!(call(port, "GET", "/api/bots", &bearer(&second), "").await.0, 200);
    std::fs::write(&go, "").unwrap();
    finished(port, &admin, &bot, 2).await;
    assert_eq!(call(port, "GET", "/api/bots", &bearer(&second), "").await.0, 401);
}

#[tokio::test]
async fn a_run_token_acts_only_as_its_bot_and_never_past_its_owner() {
    let (port, app, admin, _) = serve_app().await;
    let (go_env, go) = fake(&app, "claude", true, CLAUDE_REPLY);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea_id, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let mine = app.db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, &ada_id, acl::Visibility::Private);
    let twin = app.db.create_bot_owned("Twin", "#fff", "waddle", "claude", None, false, &ada_id, acl::Visibility::Private);
    let beas = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &bea_id, acl::Visibility::Private);
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", mine.id), &ada, r#"{"text":"go"}"#).await.0, 202);
    let env = run_env(&go_env).await;
    let auth = bearer(&env);

    // A token past its expiry is refused even if botd never heard its run end.
    let (stale, _) = app.run_tokens.issue(&mine.id, &ada_id, "r-stale", None, db::now() - 10_000, 5_000);
    assert_eq!(call(port, "GET", "/api/bots", &format!("Bearer {stale}"), "").await.0, 401);
    let failed = audit(port, &admin, "action=auth.login_failed").await;
    assert_eq!(failed[0]["details"]["reason"], "token_expired", "{failed:?}");

    // Not another Bot, its owner's or anyone else's.
    for other in [&twin.id, &beas.id] {
        let header = format!("X-SuperBot-Bot: {other}\r\n");
        assert_eq!(call_with(port, "GET", "/api/bots", &auth, &header, "").await.0, 403, "naming {other}");
        let ask = json!({ "from": other, "to": mine.id, "text": "hi" }).to_string();
        assert_eq!(call(port, "POST", "/api/ask", &auth, &ask).await.0, 403, "asking as {other}");
        let swapped = env["BOT_TOKEN"].replacen(&format!("sbb_{}.", mine.id), &format!("sbb_{other}."), 1);
        assert_eq!(call(port, "GET", "/api/bots", &format!("Bearer {swapped}"), "").await.0, 401, "its token under {other}'s id");
    }
    let check = json!({ "from": twin.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "ls" }, "cwd": "/tmp" } }).to_string();
    let (_, verdict) = call(port, "POST", "/api/approvals/check", &auth, &check).await;
    assert_eq!(verdict.lines().next(), Some("deny"), "no approval check for another Bot");
    let (code, list) = call(port, "GET", "/api/bots", &auth, "").await;
    assert!(code == 200 && !list.contains(&beas.id), "{list}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{}/messages", beas.id), &auth, "").await.0, 404, "another user's Bot");

    // Never past its owner: nothing only admins or people may do, and once Ada is
    // read-only, no writes, though the run goes on.
    assert_eq!(call(port, "GET", "/api/users", &auth, "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/me/secrets", &auth, "").await.0, 403);
    let (code, made) = call(port, "POST", "/api/bots", &auth, r#"{"name":"Child"}"#).await;
    assert_eq!(code, 201, "{made}");
    assert_eq!(parse(&made)["owner"]["id"], ada_id.as_str(), "what it makes is its owner's");
    let (code, r) = call(port, "PATCH", &format!("/api/users/{ada_id}"), &admin, r#"{"role":"readonly"}"#).await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(call(port, "POST", "/api/bots", &auth, r#"{"name":"Child2"}"#).await.0, 403);
    let denied = audit(port, &admin, "action=access.denied").await;
    assert!(denied.iter().any(|e| e["details"]["reason"] == "owner_role"), "{denied:?}");

    std::fs::write(&go, "").unwrap();
    finished(port, &admin, &mine.id, 1).await;
    assert_eq!(call(port, "GET", "/api/bots", &auth, "").await.0, 401);
}

#[tokio::test]
async fn every_harness_gets_a_token_that_ends_with_its_run() {
    let (port, app, admin, _) = serve_app().await;
    let replies = [
        ("claude", CLAUDE_REPLY),
        ("codex", r#"{"type":"item.completed","item":{"type":"agent_message","text":"Done here."}}"#),
        ("pi", r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"Done here."}]}}"#),
        ("hermes", r#"{"type": "text", "text": "Done here."}"#),
    ];
    for (harness, reply) in replies {
        let bin = adapters::get(harness).unwrap().bin();
        let (env_file, _) = fake(&app, bin, false, reply);
        let bot = app.db.create_bot(harness, "#fff", "waddle", harness, None, false);
        assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", bot.id), &admin, r#"{"text":"go"}"#).await.0, 202);
        let env = run_env(&env_file).await;
        finished(port, &admin, &bot.id, 1).await;
        let (_, said) = call(port, "GET", &format!("/api/bots/{}/messages", bot.id), &admin, "").await;
        assert!(said.contains("Done here."), "{harness} ran: {said}");
        assert!(env["BOT_TOKEN"].starts_with(&format!("sbb_{}.", bot.id)), "{harness}");
        assert_eq!(call(port, "GET", "/api/bots", &bearer(&env), "").await.0, 401, "{harness}: dead once its run ended");
        let issued = audit(port, &admin, &format!("action=bot.token_issued&bot={}", bot.id)).await;
        let revoked = audit(port, &admin, &format!("action=bot.token_revoked&bot={}", bot.id)).await;
        assert!(!issued.is_empty() && issued.len() == revoked.len(), "{harness}: {issued:?} {revoked:?}");
    }
}
