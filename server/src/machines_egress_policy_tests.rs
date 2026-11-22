//! Outbound allow-lists and run limits (ADR 0135), end to end on loopback: botd, its
//! machine port and the real agent over mutual TLS, as in `machines_mtls_tests`. The
//! agent's nft is a stand-in that keeps the rules it is given;
//! `machines_hardening_tests` loads them into a real kernel as root.

use crate::machines::heartbeats;
use crate::machines_mtls_tests::{Env, agent_with_config, events, json_call, machine_for, reply_after, send, serve_with};
use crate::users_http_tests::user_with;
use crate::*;
use std::os::unix::fs::PermissionsExt;

/// A stand-in Claude that answers at once.
const QUICK: &str = r#"#!/bin/sh
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ran"}]}}'
"#;

/// An nft that keeps what it is fed in `rules`, and refuses while `fail` exists.
fn stand_in_nft(dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let nft = dir.join("nft");
    let d = dir.display();
    std::fs::write(&nft, format!("#!/bin/sh\n[ \"$1\" = list ] && exit 1\n[ -e {d}/fail ] && {{ echo 'Error: Operation not permitted' >&2; exit 1; }}\ncat > {d}/rules\n")).unwrap();
    std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755)).unwrap();
    nft
}

/// Heartbeats until `done` holds for what botd says of `uid`'s allow-list.
async fn beat_until(env: &Env, uid: &str, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..400 {
        heartbeats(&env.app, &env.cp).await;
        let (code, v) = json_call(env, "GET", &format!("/api/users/{uid}/machine/egress-policy"), "").await;
        assert_eq!(code, 200, "{v}");
        if done(&v) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never {what}");
}

#[tokio::test]
async fn an_allow_list_reaches_the_machine_and_runs_wait_until_it_is_loaded() {
    let mut env = serve_with(|e| e.with_run_limits()).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let dir = crate::db::temp_path("nft");
    let nft = stand_in_nft(&dir);
    let _m = agent_with_config(&mut env, &mid, &token, QUICK, |mut c| {
        c.nft = nft;
        c
    })
    .await;
    let bot = env.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &uid, crate::acl::Visibility::Shared);

    // Open by default: runs go, with the default limits, which this agent can't hold.
    let v = beat_until(&env, &uid, "reported", |v| !v["machine"]["report"].is_null()).await;
    assert_eq!((v["effective"]["mode"].as_str(), v["machine"]["inPlace"].as_bool()), (Some("open"), Some(true)), "{v}");
    assert_eq!(v["machine"]["runLimits"]["state"], "unavailable", "{v}");
    let un = events(&env, "machine.run_limits_unavailable").await;
    assert_eq!(un.len(), 1, "{un:?}");
    assert!(un[0]["details"]["error"].as_str().unwrap().contains("delegated"), "{un:?}");
    let before = send(&env, &bot.id, "hello").await;
    assert!(reply_after(&env, &bot.id, before).await == "ran");
    let routed = events(&env, "bot.run_routed").await;
    assert_eq!(routed[0]["details"]["runLimits"], json!({ "cpuPercent": 80, "memoryPercent": 75, "pids": 1024, "ioWeight": 100 }));

    // Only admins set it, and only entries the agent can hold.
    let (_, member) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let body = r#"{"mode":"allow_list","allow":["203.0.113.0/24"]}"#;
    assert_eq!(crate::tests::call(env.port, "PUT", "/api/machines/egress-policy", &member, body).await.0, 403);
    for bad in [r#"{"mode":"allow_list","allow":["*.example.com"]}"#, r#"{"mode":"open","allow":["a.example.com"]}"#, r#"{"mode":"inherit"}"#, "{}"] {
        let (code, v) = json_call(&env, "PUT", "/api/machines/egress-policy", bad).await;
        assert_eq!(code, 400, "{bad}: {v}");
    }
    assert!(events(&env, "server.egress_policy_changed").await.is_empty());

    // A list the machine fails to load: audited, and runs wait, saying why.
    std::fs::write(dir.join("fail"), "").unwrap();
    let (code, v) = json_call(&env, "PUT", "/api/machines/egress-policy", body).await;
    assert_eq!((code, v["mode"].as_str()), (200, Some("allow_list")), "{v}");
    let changed = events(&env, "server.egress_policy_changed").await;
    assert_eq!((changed.len(), &changed[0]["details"]["added"]), (1, &json!(["203.0.113.0/24"])), "{changed:?}");
    let v = beat_until(&env, &uid, "failed", |v| v["machine"]["report"]["state"] == "failed").await;
    assert_eq!(v["machine"]["inPlace"], false, "{v}");
    assert!(v["machine"]["report"]["error"].as_str().unwrap().contains("not permitted"), "{v}");
    let failed = events(&env, "machine.egress_policy_failed").await;
    assert_eq!((failed.len(), failed[0]["outcome"].as_str()), (1, Some("failure")), "{failed:?}");
    let before = send(&env, &bot.id, "blocked").await;
    assert!(reply_after(&env, &bot.id, before).await.contains("outbound allow-list isn't in place"));
    let refused = events(&env, "bot.run_refused").await;
    assert_eq!(refused[0]["details"]["reason"], "egress_policy_pending", "{refused:?}");

    // Ada's own entries join the server's; loaded, runs go again.
    std::fs::remove_file(dir.join("fail")).unwrap();
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{uid}/machine/egress-policy"), r#"{"mode":"allow_list","allow":["198.51.100.7"]}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["effective"]["allow"], json!(["198.51.100.7/32", "203.0.113.0/24"]), "{v}");
    let mine = events(&env, "user.egress_policy_changed").await;
    assert_eq!((mine.len(), mine[0]["targetId"].as_str()), (1, Some(uid.as_str())), "{mine:?}");
    beat_until(&env, &uid, "loaded", |v| v["machine"]["inPlace"] == true).await;
    let rules = std::fs::read_to_string(dir.join("rules")).unwrap();
    assert!(rules.contains("203.0.113.0/24") && rules.contains("198.51.100.7/32") && rules.contains("counter reject"), "{rules}");
    assert_eq!(events(&env, "machine.egress_policy_applied").await.len(), 1);
    let before = send(&env, &bot.id, "allowed").await;
    assert!(reply_after(&env, &bot.id, before).await == "ran");

    // Open for Ada alone: the table goes, and the change is audited.
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{uid}/machine/egress-policy"), r#"{"mode":"open"}"#).await;
    assert_eq!((code, v["effective"]["mode"].as_str()), (200, Some("open")), "{v}");
    beat_until(&env, &uid, "open", |v| v["machine"]["report"]["state"] == "open").await;
    assert!(std::fs::read_to_string(dir.join("rules")).unwrap().contains("delete table inet superbot_allow"));
    assert_eq!(events(&env, "user.egress_policy_changed").await.len(), 2);
    // Setting the same again changes nothing.
    json_call(&env, "PUT", &format!("/api/users/{uid}/machine/egress-policy"), r#"{"mode":"open"}"#).await;
    assert_eq!(events(&env, "user.egress_policy_changed").await.len(), 2);
}
