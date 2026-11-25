//! Short-lived credentials for each run (ADR 0185), on the real router: a Bot's run gets
//! a new lease's values in its environment, redacted from its reply, and the lease is
//! revoked once the run ends; a name whose field is empty is taken out of the run, over
//! a saved secret of that name; a lease that can't be made refuses the run, audited as
//! `secrets_unavailable`, and the Bot says so. A plan's model provider key may come only
//! from a lease; if that lease gives it empty, the run is refused. A run whose lease
//! can't be revoked (an STS session, ADR 0194) stops when it expires. A run that outlasts
//! its lease's TTL keeps it by renewing it, until the backend won't renew it further
//! (ADR 0221); then the run stops when the lease ends.

use crate::acl::Visibility;
use crate::secrets::leases::tests::{fake, set_for_owner, wait_for, Fake};
use crate::secrets::leases::{parse, RunCredentials};
use crate::tests::{audit_list, call, serve_app};
use crate::tiers::Tiers;
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

/// A stand-in `hermes` that says the provider it was given and whether its key came.
fn fake_hermes(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("hermes");
    let script = r#"#!/bin/sh
[ "$1" = gateway ] && exit 0
cat >/dev/null
provider=none
while [ $# -gt 0 ]; do
  case "$1" in
    --provider) provider=$2; shift ;;
  esac
  shift
done
printf '{"type":"result","exit_code":0,"text":"provider=%s key=%s"}\n' "$provider" "${HERMES_PROVIDER_SUPERBOT_LEASED_API_KEY:-none}"
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

const TIERS: &str = r#"{
  "providers": {
    "leased": { "protocol": "openai-chat", "baseUrl": "https://leased.example/v1", "keySecret": "LEASE_E2E_PROVIDER_KEY" }
  },
  "tiers": [
    { "name": "pro", "label": "Pro", "routes": [
        { "harness": "hermes", "provider": "leased", "model": "gpt-5" },
        { "harness": "claude", "model": "claude-sonnet-4-5" }
    ] }
  ]
}"#;

async fn run(port: u16, app: &AppState, who: &str, bot: &str) -> String {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"deploy"}"#).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..600 {
        if let Some(m) = app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

/// `wait_for` off the test's one runtime thread: the run that revokes its leases as it
/// ends shares that thread, and may still be finishing after its reply is saved.
async fn revoked(f: &Arc<Fake>, n: usize) {
    let f = f.clone();
    tokio::task::spawn_blocking(move || wait_for(|| f.revoked.lock().unwrap().len() == n)).await.unwrap();
}

async fn refusals(port: u16, admin: &str, bot: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action=bot.run_refused&bot={bot}&limit=50"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
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
    revoked(&f, 1).await;
    assert_eq!(*f.revoked.lock().unwrap(), [format!("{path}/lease0")], "revoked once the run ended");
    assert_eq!(run(port, &app, &ada, &bot.id).await, "lease=[redacted] session=none");
    revoked(&f, 2).await;
    assert_eq!(f.issued.load(Ordering::SeqCst), 2, "a new lease for each run");
    assert_eq!(*f.run_for.lock().unwrap(), [app.cfg.run_timeout; 2], "asked to outlast the longest run");

    f.down.store(true, Ordering::SeqCst);
    let reply = run(port, &app, &ada, &bot.id).await;
    assert!(reply.contains("the secret store can't be read"), "{reply}");
    let refused = refusals(port, &admin, &bot.id).await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["details"]["reason"], "secrets_unavailable");
    assert_eq!(f.issued.load(Ordering::SeqCst), 2);
    crate::secrets::redact::forget_for(&ada_id, "stale-saved-session-5e6f");
}

#[tokio::test]
async fn a_plans_provider_key_may_come_only_from_a_lease() {
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    fake_hermes(&app);
    let wanted = "runtest/model/{owner} LEASE_E2E_PROVIDER_KEY=key";

    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "hermes", None, false, &ada_id, Visibility::Private);
    let path = format!("runtest/model/{ada_id}");
    let f = fake(&[(path.as_str(), &[("key", Some("sk-leased-e2e-7a8b"))])]);
    set_for_owner(&ada_id, RunCredentials::new(f.clone(), parse(wanted).unwrap()));
    assert_eq!(run(port, &app, &ada, &bot.id).await, "provider=superbot-leased key=[redacted]", "no saved key, so only the lease gave it");
    revoked(&f, 1).await;
    assert!(refusals(port, &admin, &bot.id).await.is_empty());

    // The lease gives the key empty: refused before the harness starts, and revoked.
    let (bea_id, bea) = user_with(port, &admin, "bea@example.com", "member").await;
    let bot = app.db.create_bot_owned("Bea's", "#fff", "waddle", "hermes", None, false, &bea_id, Visibility::Private);
    let path = format!("runtest/model/{bea_id}");
    let f = fake(&[(path.as_str(), &[("key", None)])]);
    set_for_owner(&bea_id, RunCredentials::new(f.clone(), parse(wanted).unwrap()));
    let reply = run(port, &app, &bea, &bot.id).await;
    assert!(reply.contains("the secret store can't be read"), "{reply}");
    let refused = refusals(port, &admin, &bot.id).await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["details"]["reason"], "secrets_unavailable");
    revoked(&f, 1).await;
}

/// A stand-in `claude` that takes longer than its STS session lasts.
fn slow_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    std::fs::write(&path, "#!/bin/sh\nsleep 20\necho '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"finished\"}]}}'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn a_run_stops_when_its_sts_session_expires() {
    let (port, app, admin, _) = serve_app().await;
    slow_claude(&app);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Deployer", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    let f = fake(&[("sts/role/short", &[("SessionToken", Some("sts-http-session-4d3c"))])]);
    f.unrevocable.store(true, Ordering::SeqCst);
    f.ttl.store(1, Ordering::SeqCst);
    set_for_owner(&ada_id, RunCredentials::new(f.clone(), parse("sts/role/short STS_HTTP_TOKEN=SessionToken").unwrap()));

    let started = std::time::Instant::now();
    let reply = run(port, &app, &ada, &bot.id).await;
    assert!(reply.contains("short-lived credentials for this task expired"), "{reply}");
    assert!(started.elapsed() < Duration::from_secs(10), "stopped with its session, not at the run timeout");
    assert!(f.revoked.lock().unwrap().is_empty(), "an STS session is never revoked");
}

#[tokio::test]
async fn a_run_outlives_its_leases_ttl_by_renewing_them_until_the_max_ttl_stops_it() {
    let (port, app, admin, _) = serve_app().await;
    slow_claude(&app);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Deployer", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    let path = format!("renewtest/creds/{ada_id}");
    let f = fake(&[(path.as_str(), &[("password", Some("renew-http-pass-2f3a"))])]);
    f.ttl.store(2, Ordering::SeqCst);
    set_for_owner(&ada_id, RunCredentials::new(f.clone(), parse("renewtest/creds/{owner} RENEW_HTTP_PASSWORD=password").unwrap()));

    // Renewed by its 2 s TTL twice, then the role's max TTL gives 1 s: the run stops then.
    let started = std::time::Instant::now();
    let msg = tokio::spawn({
        let ada = ada.clone();
        let bot = bot.id.clone();
        let app = app.clone();
        async move { run(port, &app, &ada, &bot).await }
    });
    {
        let f = f.clone();
        tokio::task::spawn_blocking(move || wait_for(|| f.renewals.lock().unwrap().len() >= 2)).await.unwrap();
    }
    f.renew_cap.store(1, Ordering::SeqCst);
    let reply = msg.await.unwrap();
    assert!(reply.contains("short-lived credentials for this task expired"), "{reply}");
    let took = started.elapsed();
    assert!(took > Duration::from_secs(3) && took < Duration::from_secs(12), "past its first TTL, stopped with its last renewal: {took:?}");
    revoked(&f, 1).await;
    assert_eq!(*f.revoked.lock().unwrap(), [format!("{path}/lease0")], "revoked as the run ended");
    let renewals = f.renewals.lock().unwrap().clone();
    assert!(renewals.len() >= 3 && renewals.iter().all(|(id, n)| *id == format!("{path}/lease0") && *n == 2), "{renewals:?}");
}
