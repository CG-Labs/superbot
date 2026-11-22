//! Recovery objectives for machines backed up by their provider (Linode Backups, ADR
//! 0110), on the real router with the in-memory provider standing in for Linode:
//! when the last backup succeeded is read with the machine, a machine past its RPO is
//! audited and alerted once and cleared by a newer backup, backups found off are
//! turned on or reported, and `/metrics` shows it all by tier. Nothing here talks to
//! Linode.

use crate::machines::fake::Fake;
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::{ControlPlane, recovery};
use crate::obs_http_tests::total;
use crate::tests::{audit_list, call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const HOUR: i64 = 3_600_000;

async fn serve() -> (u16, AppState, String, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, owner, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin, fake)
}

fn watch(app: &AppState) -> usize {
    recovery::watch(app, app.control_plane.get().unwrap())
}

async fn json_call(port: u16, method: &str, path: &str, who: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, "").await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(port: u16, admin: &str) {
    let (code, v) = json_call(port, "POST", "/api/machines/reconcile", admin).await;
    assert_eq!(code, 200, "{v}");
}

fn alerts_to(app: &AppState, mail: &crate::notify::smtp::fake::Server) {
    let smtp = crate::notify::smtp::Smtp::for_test("127.0.0.1", mail.port, crate::notify::smtp::Tls::None, None, None);
    let _ = app.notifier.set(Arc::new(crate::notify::Notifier::new(Some(smtp), Some("https://bots.example.com".into()))));
    let s = crate::notify::Settings {
        email: crate::notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: true },
        ..Default::default()
    };
    crate::notify::save(&app.db, &s);
}

async fn mail_with(mail: &crate::notify::smtp::fake::Server, subject: &str) -> crate::notify::smtp::fake::Received {
    for _ in 0..200 {
        if let Some(m) = mail.got.lock().unwrap().iter().find(|m| m.headers.contains(subject)).cloned() {
            return m;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("no mail \"{subject}\"");
}

#[tokio::test]
async fn machines_are_held_to_an_rpo_by_their_providers_backups() {
    let (port, app, admin, fake) = serve().await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&app, &mail);
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let path = format!("/api/users/{uid}/machine");
    let (code, m) = json_call(port, "POST", &path, &admin).await;
    assert_eq!(code, 202, "{m}");
    reconcile(port, &admin).await;
    reconcile(port, &admin).await;
    let m = app.db.user_machine(&uid).unwrap();
    let pid = m.provider_id.clone().unwrap();
    assert!(m.backups && fake.calls("enable_backups") == 1, "botd turns them on");

    // New, with no backup yet: within its RPO (26 hours by default), and admins see it.
    assert_eq!(watch(&app), 0);
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    let r = &view["recovery"];
    assert_eq!((r["backups"].as_str(), r["tracked"].as_bool(), r["rpoHours"].as_i64(), r["breach"].as_bool()), (Some("provider"), Some(true), Some(26), Some(false)), "{view}");
    assert!(r["lastBackupAt"].is_null(), "{view}");

    // The provider's last successful backup is read with the machine and kept.
    let at = db::now() - HOUR;
    fake.set(&pid, |pm| pm.last_backup_at = Some(at));
    reconcile(port, &admin).await;
    assert_eq!(app.db.machine(&m.id).unwrap().provider_backup_at, Some(at));
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert_eq!((view["recovery"]["lastBackupAt"].as_i64(), view["providerBackupAt"].as_i64()), (Some(at), Some(at)), "{view}");
    assert_eq!(watch(&app), 0);

    // Its newest backup 27 hours old: a breach, audited once and alerted.
    app.db.machine_backdate(&m.id, 30 * HOUR);
    let stale = db::now() - 27 * HOUR;
    fake.set(&pid, |pm| pm.last_backup_at = Some(stale));
    reconcile(port, &admin).await;
    assert_eq!(watch(&app), 1);
    assert_eq!(watch(&app), 1, "still open");
    let breached = events(port, &admin, "machine.rpo_breached").await;
    assert_eq!(breached.len(), 1, "once, not every check: {breached:?}");
    let d = &breached[0]["details"];
    assert_eq!((breached[0]["targetId"].as_str(), breached[0]["outcome"].as_str()), (Some(m.id.as_str()), Some("failure")));
    assert_eq!((d["backups"].as_str(), d["rpoHours"].as_i64(), d["lastBackupAt"].as_i64(), d["backupsOn"].as_bool()), (Some("provider"), Some(26), Some(stale), Some(true)), "{d}");
    let got = mail_with(&mail, "ada@example.com's machine has no Fake backup within its RPO").await;
    assert_eq!(got.to, ["ops@example.com"]);
    assert!(got.body.contains("Newest Fake backup:") && got.body.contains("27.0 hours ago"), "{}", got.body);
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert!(view["recovery"]["breach"] == true && view["recovery"]["breachedAt"].is_i64(), "{view}");

    // /metrics shows it by tier, with no machine, user or email.
    let metrics = crate::obs::render(&app);
    assert_eq!(total(&metrics, "superbot_machine_rpo_breaches_open"), 1.0, "{metrics}");
    assert_eq!(total(&metrics, r#"superbot_machines_past_provider_backup_rpo{provider="fake",tier="starter"}"#), 1.0, "{metrics}");
    assert_eq!(total(&metrics, r#"superbot_machines_provider_backups{provider="fake",tier="starter",backups="on"}"#), 1.0, "{metrics}");
    assert_eq!(total(&metrics, r#"superbot_machines_provider_backups{provider="fake",tier="starter",backups="off"}"#), 0.0, "{metrics}");
    assert!(total(&metrics, "superbot_machine_provider_backup_age_max_seconds{") >= 27.0 * 3600.0, "{metrics}");
    assert_eq!(total(&metrics, "superbot_machine_provider_backup_rpo_seconds{"), 26.0 * 3600.0, "{metrics}");
    assert!(!metrics.contains("superbot_machines_rpo_tracked"), "off-host backups' gauges stay off: {metrics}");
    assert!(!metrics.contains(&m.id) && !metrics.contains(&uid) && !metrics.contains(&pid) && !metrics.contains("ada@"), "{metrics}");
    // The alert rules use only metrics botd writes.
    let types: std::collections::BTreeSet<String> = metrics.lines().filter_map(|l| Some(l.strip_prefix("# TYPE ")?.split(' ').next()?.to_string())).collect();
    let used = crate::machines_placement_tests::metric_names(include_str!("../../deploy/prometheus/superbot-backups.rules.yml"));
    assert!(!used.is_empty() && used.is_subset(&types), "the rules use metrics botd doesn't write: {:?}", used.difference(&types).collect::<Vec<_>>());

    // A newer backup ends it.
    fake.set(&pid, |pm| pm.last_backup_at = Some(db::now() - HOUR));
    reconcile(port, &admin).await;
    assert_eq!(watch(&app), 0);
    let recovered = events(port, &admin, "machine.rpo_recovered").await;
    assert_eq!((recovered.len(), recovered[0]["details"]["reason"].as_str()), (1, Some("backed_up")), "{recovered:?}");
    mail_with(&mail, "ada@example.com's machine is back within its RPO").await;
    let metrics = crate::obs::render(&app);
    assert_eq!(total(&metrics, "superbot_machines_past_provider_backup_rpo{"), 0.0, "{metrics}");
    assert_eq!(total(&metrics, "superbot_machine_rpo_breaches_open"), 0.0, "{metrics}");

    // Backups turned off at the provider (deleting them too) are turned on again; when
    // that fails it's recorded, counted as off, and the machine falls past its RPO.
    fake.set(&pid, |pm| (pm.backups, pm.last_backup_at) = (false, None));
    fake.fail_next("enable_backups", ProviderError::Api { status: 400, message: "Backups are not available".into() });
    reconcile(port, &admin).await;
    let failed = events(port, &admin, "machine.backups_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    let metrics = crate::obs::render(&app);
    assert_eq!(total(&metrics, r#"superbot_machines_provider_backups{provider="fake",tier="starter",backups="off"}"#), 1.0, "{metrics}");
    assert_eq!(watch(&app), 1, "no backup since it was made, 30 hours ago");
    let mut breaches = Vec::new();
    for _ in 0..200 {
        breaches = mail.got.lock().unwrap().iter().filter(|x| x.headers.contains("no Fake backup")).cloned().collect();
        if breaches.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(breaches.len(), 2, "a second breach, a second alert");
    let body = &breaches[1].body;
    assert!(body.contains("No Fake backup of it yet.") && body.contains("backups are off"), "{body}");
    reconcile(port, &admin).await;
    assert!(app.db.machine(&m.id).unwrap().backups, "on again at the next pass");
    assert_eq!(fake.calls("enable_backups"), 3);

    // A suspended machine's disk doesn't change: not held to it, and the breach ends.
    let (code, v) = json_call(port, "POST", &format!("{path}/suspend"), &admin).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(watch(&app), 0);
    let recovered = events(port, &admin, "machine.rpo_recovered").await;
    assert_eq!(recovered[0]["details"]["reason"].as_str(), Some("suspended"), "{recovered:?}");
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert_eq!((view["recovery"]["tracked"].as_bool(), view["recovery"]["untrackedReason"].as_str()), (Some(false), Some("suspended")), "{view}");
    let metrics = crate::obs::render(&app);
    assert_eq!(total(&metrics, "superbot_machines_provider_backups{"), 0.0, "only running machines count: {metrics}");
}

#[tokio::test]
async fn a_machine_isnt_held_to_it_before_the_provider_says_after_an_upgrade() {
    let (port, app, admin, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let path = format!("/api/users/{uid}/machine");
    assert_eq!(json_call(port, "POST", &path, &admin).await.0, 202);
    reconcile(port, &admin).await;
    reconcile(port, &admin).await;
    let m = app.db.user_machine(&uid).unwrap();
    let pid = m.provider_id.clone().unwrap();
    app.db.machine_backdate(&m.id, 30 * HOUR);

    // An old machine with no backup time saved, as on the first start after upgrading:
    // nothing until reconciling has asked the provider, however old it is.
    app.control_plane.get().unwrap().forget_provider_seen();
    assert_eq!(watch(&app), 0);
    assert!(events(port, &admin, "machine.rpo_breached").await.is_empty());
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert_eq!((view["recovery"]["tracked"].as_bool(), view["recovery"]["untrackedReason"].as_str()), (Some(false), Some("not_checked_yet")), "{view}");

    // Its backup is current: held to it, within it.
    fake.set(&pid, |pm| pm.last_backup_at = Some(db::now() - HOUR));
    reconcile(port, &admin).await;
    assert_eq!(watch(&app), 0);
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert_eq!(view["recovery"]["tracked"].as_bool(), Some(true), "{view}");

    // A saved time counts at once after a restart, and the provider saying there's none
    // is a breach.
    app.control_plane.get().unwrap().forget_provider_seen();
    assert_eq!(watch(&app), 0);
    fake.set(&pid, |pm| pm.last_backup_at = None);
    reconcile(port, &admin).await;
    assert_eq!(watch(&app), 1);
}

#[tokio::test]
async fn nothing_is_held_to_an_rpo_with_backups_off() {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, owner, _) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(p);
        cp.backups = false;
        cp.provider_backups = None;
        a.machines = Arc::new(cp);
    })
    .await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let path = format!("/api/users/{uid}/machine");
    assert_eq!(json_call(port, "POST", &path, &admin).await.0, 202);
    reconcile(port, &admin).await;
    let m = app.db.user_machine(&uid).unwrap();
    app.db.machine_backdate(&m.id, 30 * HOUR);
    assert_eq!((fake.calls("enable_backups"), watch(&app)), (0, 0));
    let (_, view) = json_call(port, "GET", &path, &admin).await;
    assert!(view["recovery"].is_null() && view["backups"] == false, "{view}");
    // Still counted as off, for the operator who didn't mean it.
    let metrics = crate::obs::render(&app);
    assert_eq!(total(&metrics, r#"superbot_machines_provider_backups{provider="fake",tier="starter",backups="off"}"#), 1.0, "{metrics}");
    assert!(!metrics.contains("superbot_machine_provider_backup_rpo_seconds") && !metrics.contains("superbot_machine_rpo_breaches_open"), "{metrics}");
}
