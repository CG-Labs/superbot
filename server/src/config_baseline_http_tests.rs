//! The configuration baseline check (ADR 0193) on the real router, at startup and in the
//! evidence bundle: admins only, audited with its digest, refusing to start under
//! `required` while a setting fails, and kept in `baseline.json` without an observed value.

use crate::audit::{Actor, Event};
use crate::config_baseline::{self as baseline, Mode, RULES, Settings, Startup};
use crate::evidence::{self, Inputs, Period};
use crate::support::tests::untar;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn today() -> chrono::NaiveDate {
    chrono::Utc::now().date_naive()
}

/// The audited baseline checks, oldest first.
fn checks(app: &runner::App) -> Vec<db::AuditEvent> {
    app.db.audit_events(&audit::Filter { actions: vec![baseline::CHECKED.into()], ..Default::default() }, 100, true)
}

/// A server that meets every rule botd can judge on a test app (no machines, Bots here).
fn passing(mode: Mode, exceptions: Vec<&'static str>) -> Startup {
    Startup { settings: Settings { mode, exceptions }, mfa_pinned: Some(mfa::Policy::Admins), signin_alerts: true, chromium_sandbox: true, evidence_monthly: true, ..Startup::default() }
}

#[tokio::test]
async fn only_admins_check_it_and_each_check_is_audited_with_its_digest() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let (delegate_id, delegate) = user_with(port, &admin, "d@example.com", "member").await;
    let every = ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"];
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Everything delegable", "permissions": every }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    let path = format!("/api/roles/{}/users/{delegate_id}", parse(&role)["id"].as_str().unwrap());
    assert_eq!(call(port, "PUT", &path, &admin, "").await.0, 200);
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for (who, auth) in [("member", member.as_str()), ("readonly", readonly.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", "/api/baseline", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/baseline", "", "").await.0, 401);
    assert!(checks(&app).is_empty(), "a refused request checks nothing");

    let (code, body) = call(port, "GET", "/api/baseline", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["format"].as_u64(), v["mode"].as_str(), v["botd"].as_str()), (Some(1), Some("off"), Some(env!("CARGO_PKG_VERSION"))));
    assert_eq!(v["baseline"], "docs/security/configuration-baseline.md");
    let rows = v["checks"].as_array().unwrap();
    assert_eq!(rows.iter().map(|c| c["setting"].as_str().unwrap()).collect::<Vec<_>>(), RULES.iter().map(|r| r.setting).collect::<Vec<_>>(), "every rule, in the table's order");
    assert!(rows.iter().all(|c| ["pass", "fail", "exception", "manual", "not_applicable"].contains(&c["status"].as_str().unwrap())), "{v}");
    assert_eq!(v["ok"], false, "a test server isn't set up as the baseline says: {v}");
    assert!(v["failing"].as_array().unwrap().contains(&json!("CONFIG_BASELINE")), "{v}");
    let total: u64 = v["counts"].as_object().unwrap().values().map(|n| n.as_u64().unwrap()).sum();
    assert_eq!(total as usize, RULES.len());

    let (_, audit) = call(port, "GET", "/api/audit?action=server.baseline_checked", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 1, "{events:?}");
    let (e, d) = (&events[0], &events[0]["details"]);
    assert_eq!((e["outcome"].as_str(), e["actorKind"].as_str()), (Some("failure"), Some("user")), "{e}");
    assert_eq!((d["source"].as_str(), d["digest"].as_str(), d["failed"].clone()), (Some("request"), v["digest"].as_str(), v["failing"].clone()), "{e}");
    assert!(d.get("checks").is_none(), "the audit event has names and counts, not observed values: {d}");
}

#[test]
fn on_checks_at_start_and_audits_it() {
    let app = runner::test_app();
    assert_eq!(baseline::at_startup(&app, passing(Mode::On, vec![])), Ok(()));
    let events = checks(&app);
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!((e.actor_kind.as_str(), e.outcome.as_str()), ("system", "failure"), "a test app has no database or backup encryption policy");
    assert_eq!((e.details["source"].as_str(), e.details["mode"].as_str(), e.details["refused"].as_bool()), (Some("start"), Some("on"), Some(false)));
    let failed: Vec<&str> = e.details["failed"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
    assert_eq!(failed, ["SUPERBOT_DATABASE_ENCRYPTION", "SUPERBOT_BACKUP_ENCRYPTION", "SERVER_BACKUP_OFF_HOST", "ISOLATION"]);

    let later = baseline::check(&app, db::now());
    assert_eq!(later.mode, Mode::On, "later checks judge what botd parsed at start");
    assert_eq!(later.digest, e.details["digest"].as_str().unwrap(), "the same settings, the same digest");
}

#[test]
fn off_checks_nothing_at_start() {
    let app = runner::test_app();
    assert_eq!(baseline::at_startup(&app, passing(Mode::Off, vec![])), Ok(()));
    assert!(checks(&app).is_empty());
    assert_eq!(baseline::check(&app, db::now()).with(baseline::Status::Fail).last(), Some(&"CONFIG_BASELINE"));
}

#[test]
fn required_refuses_to_start_while_a_setting_fails_unless_an_exception_waives_it() {
    let app = runner::test_app();
    let err = baseline::at_startup(&app, passing(Mode::Required, vec!["ISOLATION"])).unwrap_err();
    assert!(err.contains("CONFIG_BASELINE=required") && err.contains("SUPERBOT_DATABASE_ENCRYPTION, SUPERBOT_BACKUP_ENCRYPTION, SERVER_BACKUP_OFF_HOST isn't"), "{err}");
    assert!(!err.contains("ISOLATION"), "waived: {err}");
    let e = checks(&app).pop().unwrap();
    assert_eq!((e.details["refused"].as_bool(), e.details["excepted"].clone()), (Some(true), json!(["ISOLATION"])), "the refusal is audited");

    let waived = runner::test_app();
    let all = vec!["SUPERBOT_DATABASE_ENCRYPTION", "SUPERBOT_BACKUP_ENCRYPTION", "SERVER_BACKUP_OFF_HOST", "ISOLATION", "TEAMS"];
    assert_eq!(baseline::at_startup(&waived, passing(Mode::Required, all)), Ok(()));
    let e = checks(&waived).pop().unwrap();
    assert_eq!((e.outcome.as_str(), e.details["refused"].as_bool(), e.details["unusedExceptions"].clone()), ("success", Some(false), json!(["TEAMS"])));
}

#[test]
fn the_evidence_bundle_keeps_the_check_now_and_each_check_in_its_period() {
    let app = runner::test_app();
    baseline::at_startup(&app, passing(Mode::On, vec!["ISOLATION"])).unwrap();
    let mut forged = baseline::evaluate(&baseline::Facts::default(), &[], 0).view();
    forged["failed"] = json!(["AUTH_MFA", "jane@example.com"]);
    forged["source"] = json!("203.0.113.9");
    app.db.record(&Event::new(Actor::system("baseline"), baseline::CHECKED).details(forged));

    let p = Period { from: today(), to: today().succ_opt().unwrap() };
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Off };
    let tar = evidence::build(&app, &inputs, &p, db::now(), false).tar;
    let entries = untar(&tar);
    let text = |name: &str| String::from_utf8(entries.iter().find(|(n, _)| n.ends_with(&format!("/{name}"))).unwrap_or_else(|| panic!("{name}")).1.clone()).unwrap();
    let raw = text("baseline.json");
    let b = parse(&raw);
    assert_eq!(b["now"]["mode"], "on", "{b}");
    assert_eq!(b["now"]["excepted"], json!(["ISOLATION"]));
    assert_eq!(b["now"]["checks"].as_array().unwrap().len(), RULES.len());
    assert_eq!((b["checksInPeriod"].as_u64(), b["checksListed"].as_u64()), (Some(2), Some(2)), "{b}");
    assert_eq!(b["periodCovered"]["days"], 1);
    let first = &b["checks"][0];
    assert_eq!((first["source"].as_str(), first["mode"].as_str(), first["excepted"].clone()), (Some("start"), Some("on"), json!(["ISOLATION"])), "{first}");
    assert_eq!(first["digest"], b["now"]["digest"], "nothing changed since start");
    assert_eq!((b["checks"][1]["failed"].clone(), b["checks"][1]["source"].clone()), (json!(["AUTH_MFA"]), Value::Null), "only known names and codes");
    assert!(!raw.contains("jane@example.com") && !raw.contains("203.0.113.9"), "{raw}");
    assert_eq!(baseline::check(&app, db::now()).mode, Mode::On);
    assert_eq!(checks(&app).len(), 2, "making the bundle doesn't audit a check");

    let manifest = parse(&text("manifest.json"));
    assert_eq!(manifest["format"].as_u64(), Some(u64::from(evidence::FORMAT)));
    let file = manifest["files"].as_array().unwrap().iter().find(|f| f["name"] == "baseline.json").cloned().expect("listed");
    assert_eq!((file["criteria"].clone(), file["checklist"].clone()), (json!(["CC5.1", "CC7.1"]), json!(["CC5.1-1"])), "{file}");
}
