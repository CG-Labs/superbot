//! HTTP tests for "Approve for this run" (ADR 0051), on the real router: a real run
//! hands its id to the harness, a run approval covers that run's later calls of the
//! same kind, and nothing outlives the run.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn check(bot: &str, run: Option<&str>, cmd: &str) -> String {
    json!({ "from": bot, "harness": "claude", "run": run, "event": { "tool_name": "Bash", "tool_input": { "command": cmd }, "cwd": "/tmp" } }).to_string()
}

async fn pending(port: u16, auth: &str) -> Value {
    for _ in 0..300 {
        let (_, list) = call(port, "GET", "/api/approvals?status=pending", auth, "").await;
        if let Some(a) = parse(&list).as_array().and_then(|l| l.first().cloned()) {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no pending approval");
}

/// A fake harness that writes down its run id, then waits for `go` before replying.
fn fake_claude(app: &App) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = &app.cfg.bin_dir;
    let (seen, go) = (dir.join("run-id"), dir.join("go"));
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Pushed."}]}}"#;
    let script = format!("#!/bin/sh\necho \"$SUPERBOT_RUN_ID\" > '{}'\nwhile [ ! -f '{}' ]; do sleep 0.05; done\necho '{reply}'\n", seen.display(), go.display());
    let path = dir.join("claude");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (seen, go)
}

#[tokio::test]
async fn a_run_approval_covers_the_rest_of_a_real_run_and_ends_with_it() {
    let (port, app, admin, key) = serve_app().await;
    let (seen, go) = fake_claude(&app);
    let (_, b) = call(port, "POST", "/api/bots", &admin, &json!({ "name": "Pusher", "harness": "claude" }).to_string()).await;
    let bot = parse(&b)["id"].as_str().unwrap().to_string();
    let bot_auth = key.auth(&bot);
    let (code, m) = call(port, "POST", &format!("/api/bots/{bot}/messages"), &admin, r#"{"text":"push it"}"#).await;
    assert_eq!(code, 202, "{m}");
    let run = loop {
        match std::fs::read_to_string(&seen) {
            Ok(s) if !s.trim().is_empty() => break s.trim().to_string(),
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    assert_eq!(app.live_run(&bot).as_deref(), Some(run.as_str()));

    let hook = tokio::spawn({
        let (body, auth) = (check(&bot, Some(&run), "git push origin main"), bot_auth.clone());
        async move { call(port, "POST", "/api/approvals/check", &auth, &body).await }
    });
    let a = pending(port, &admin).await;
    assert_eq!((a["runId"].as_str(), a["runScope"]["covers"].clone(), a["scope"].clone()), (Some(run.as_str()), json!(["Pushes to a git remote"]), Value::Null));
    let id = a["id"].as_str().unwrap();
    let (code, done) = call(port, "POST", &format!("/api/approvals/{id}/approve"), &admin, r#"{"scope":"run"}"#).await;
    assert_eq!((code, parse(&done)["scope"].as_str()), (200, Some("run")), "{done}");
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("allow"));

    let (_, again) = call(port, "POST", "/api/approvals/check", &bot_auth, &check(&bot, Some(&run), "git push origin feature")).await;
    assert_eq!(again.lines().collect::<Vec<_>>(), ["allow", "Approved for the rest of this task"]);
    let (_, list) = call(port, "GET", "/api/approvals", &admin, "").await;
    assert_eq!(parse(&list).as_array().unwrap().len(), 1);
    let (_, log) = call(port, "GET", "/api/audit?action=policy.allowed", &admin, "").await;
    let auto = &audit_list(&log)[0];
    assert_eq!((auto["targetType"].as_str(), auto["targetId"].as_str(), auto["details"]["scope"].as_str()), (Some("approval"), Some(id), Some("run")));
    let (_, rules) = call(port, "GET", "/api/policy/rules", &admin, "").await;
    assert_eq!(parse(&rules), json!([]), "a run approval saves no rule");

    // The run ends: the grant is listed on it, and the same call asks again.
    std::fs::write(&go, "").unwrap();
    let finished = loop {
        let (_, log) = call(port, "GET", &format!("/api/audit?action=bot.run_finished&bot={bot}"), &admin, "").await;
        if let Some(e) = audit_list(&log).into_iter().next() {
            break e;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(finished["details"]["runGrants"], json!([id]));
    assert!(app.live_run(&bot).is_none());
    let hook = tokio::spawn({
        let (body, auth) = (check(&bot, Some(&run), "git push origin feature"), bot_auth.clone());
        async move { call(port, "POST", "/api/approvals/check", &auth, &body).await }
    });
    let b = pending(port, &admin).await;
    assert!(b["runId"].is_null() && b["runScope"].is_null(), "{b}");
    let bid = b["id"].as_str().unwrap();
    assert_eq!(call(port, "POST", &format!("/api/approvals/{bid}/approve"), &admin, r#"{"scope":"run"}"#).await.0, 400);
    assert_eq!(call(port, "POST", &format!("/api/approvals/{bid}/deny"), &admin, "").await.0, 200);
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("deny"));
}

#[tokio::test]
async fn run_scope_takes_the_rights_of_approving_and_nothing_else() {
    let (port, app, admin, key) = serve_app().await;
    let (member_id, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, other) = user_with(port, &admin, "o@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let bot = app.db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, &member_id, Visibility::Private);
    let run = app.start_test_run(&bot.id);
    let bot_auth = key.auth(&bot.id);
    let hook = tokio::spawn({
        let (body, auth) = (check(&bot.id, Some(&run), "git push"), bot_auth.clone());
        async move { call(port, "POST", "/api/approvals/check", &auth, &body).await }
    });
    let a = pending(port, &admin).await;
    let path = format!("/api/approvals/{}/approve", a["id"].as_str().unwrap());
    let deny = path.replace("/approve", "/deny");

    assert_eq!(call(port, "POST", &path, &bot_auth, r#"{"scope":"run"}"#).await.0, 403);
    assert_eq!(call(port, "POST", &path, &readonly, r#"{"scope":"run"}"#).await.0, 403);
    assert_eq!(call(port, "POST", &path, &other, r#"{"scope":"run"}"#).await.0, 404);
    for (url, body) in [(&path, r#"{"scope":"forever"}"#), (&deny, r#"{"scope":"run"}"#), (&path, r#"{"scope":"run","remember":"bot"}"#)] {
        let (code, res) = call(port, "POST", url, &admin, body).await;
        assert_eq!(code, 400, "{body}: {res}");
    }
    assert_eq!(pending(port, &admin).await["status"], "pending");

    // The Bot's owner, a member, can approve it for the run, as she can approve it once.
    let (code, res) = call(port, "POST", &path, &member, r#"{"scope":"run","note":"today only"}"#).await;
    assert_eq!((code, parse(&res)["scope"].as_str()), (200, Some("run")), "{res}");
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("allow"));
    assert_eq!(call(port, "POST", &path, &member, r#"{"scope":"run"}"#).await.0, 409);
    let (_, log) = call(port, "GET", "/api/audit?action=approval.approved", &admin, "").await;
    let e = &audit_list(&log)[0];
    assert_eq!((e["actorId"].as_str(), e["details"]["scope"].as_str(), e["details"]["runId"].as_str()), (Some(member_id.as_str()), Some("run"), Some(run.as_str())));
    assert_eq!((e["details"]["covers"].clone(), e["details"]["note"].as_str()), (json!(["Pushes to a git remote"]), Some("today only")));

    // Another Bot's run id never unlocks this Bot's calls, nor this run's id another Bot's.
    let (_, again) = call(port, "POST", "/api/approvals/check", &bot_auth, &check(&bot.id, Some(&run), "git push")).await;
    assert_eq!(again.lines().next(), Some("allow"));
    let twin = app.db.create_bot_owned("Twin", "#fff", "waddle", "claude", None, false, &member_id, Visibility::Private);
    app.start_test_run(&twin.id);
    let hook = tokio::spawn({
        let (body, auth) = (check(&twin.id, Some(&run), "git push"), key.auth(&twin.id));
        async move { call(port, "POST", "/api/approvals/check", &auth, &body).await }
    });
    let t = pending(port, &admin).await;
    assert_eq!((t["botId"].as_str(), t["runId"].clone()), (Some(twin.id.as_str()), Value::Null));
    call(port, "POST", &format!("/api/approvals/{}/deny", t["id"].as_str().unwrap()), &admin, "").await;
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("deny"));
}
