//! Short-lived credentials for each run (ADR 0185), on the real router: a Bot's run gets
//! a new lease's values in its environment, redacted from its reply, and the lease is
//! revoked once the run ends; a name whose field is empty is taken out of the run, over
//! a saved secret of that name; a lease that can't be made refuses the run, audited as
//! `secrets_unavailable`, and the Bot says so.

use crate::acl::Visibility;
use crate::secrets::leases::tests::{fake, set_for_owner, wait_for};
use crate::secrets::leases::{parse, RunCredentials};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::user_with;
use crate::*;
use std::sync::atomic::Ordering;

/// A stand-in `claude` that says whether it got `LEASE_TOKEN` and `LEASE_SESSION_TOKEN`.
fn fake_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let script = r#"#!/bin/sh
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"lease=${LEASE_TOKEN:-none} session=${LEASE_SESSION_TOKEN:-none}\"}]}}"
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn run(port: u16, app: &AppState, who: &str, bot: &str) -> String {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"deploy"}"#).await;
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
async fn a_run_gets_a_new_lease_revoked_when_it_ends_and_none_refuses_it() {
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Deployer", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    let path = format!("runtest/creds/{ada_id}");
    let f = fake(&[(path.as_str(), &[("token", Some("lease-http-token-5e6f")), ("session", None)])]);
    set_for_owner(&ada_id, RunCredentials::new(f.clone(), parse("runtest/creds/{owner} LEASE_TOKEN=token LEASE_SESSION_TOKEN=session").unwrap()));
    crate::secrets::global().user_put(&ada_id, "LEASE_SESSION_TOKEN", "stale-saved-session-5e6f").unwrap();

    let reply = run(port, &app, &ada, &bot.id).await;
    assert_eq!(reply, "lease=[redacted] session=none", "the run got the lease's value, its reply doesn't show it, and the empty field took the saved one out");
    wait_for(|| f.revoked.lock().unwrap().len() == 1);
    assert_eq!(*f.revoked.lock().unwrap(), [format!("{path}/lease0")], "revoked once the run ended");
    assert_eq!(run(port, &app, &ada, &bot.id).await, "lease=[redacted] session=none");
    wait_for(|| f.revoked.lock().unwrap().len() == 2);
    assert_eq!(f.issued.load(Ordering::SeqCst), 2, "a new lease for each run");

    f.down.store(true, Ordering::SeqCst);
    let reply = run(port, &app, &ada, &bot.id).await;
    assert!(reply.contains("the secret store can't be read"), "{reply}");
    let (code, body) = call(port, "GET", &format!("/api/audit?action=bot.run_refused&bot={}&limit=50", bot.id), &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let refused = audit_list(&body);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["details"]["reason"], "secrets_unavailable");
    assert_eq!(f.issued.load(Ordering::SeqCst), 2);
    crate::secrets::redact::forget_for(&ada_id, "stale-saved-session-5e6f");
}
