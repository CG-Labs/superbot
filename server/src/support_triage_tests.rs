//! Support triage (ADR 0220) against the bundles botd really makes, online and offline,
//! so a change to either bundle that the triage can't read fails here rather than on a
//! customer's ticket.

use crate::audit::{Actor, Event, Outcome};
use crate::db::{self, NewStatusIncident};
use crate::support_check::{self, Logs, Settings};
use crate::support_triage::{self, Finding, Kind, Level, Options, Triage};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn ids(t: &Triage) -> Vec<&str> {
    t.findings.iter().map(|f| f.id.as_str()).collect()
}

fn find<'a>(t: &'a Triage, id: &str) -> &'a Finding {
    t.findings.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("no {id} in {:?}", ids(t)))
}

/// Each file of a ustar bundle, by its name inside the bundle's folder.
fn names(tar: &[u8]) -> Vec<String> {
    crate::support::tests::untar(tar).into_iter().map(|(n, _)| n.rsplit('/').next().unwrap().to_string()).collect()
}

#[test]
fn it_knows_both_bundles_formats_and_files() {
    assert_eq!(support_triage::ONLINE_FORMAT, u64::from(crate::support::FORMAT), "the online bundle changed: teach support_triage the new format");
    assert_eq!(support_triage::OFFLINE_FORMAT, u64::from(support_check::FORMAT), "the offline bundle changed: teach support_triage the new format");
}

/// botctl builds support_triage without botd's health check, so it keeps its own table of
/// the items' guides; this holds the two together.
#[test]
fn it_knows_each_health_check_items_guide() {
    let ids: Vec<&str> = crate::health_check::ITEMS.iter().map(|i| i.id).collect();
    for id in support_triage::HEALTH_CHECK_SHOWN_ELSEWHERE {
        assert!(ids.contains(&id), "{id} isn't a health check item");
    }
    for it in crate::health_check::ITEMS.iter().filter(|i| !support_triage::HEALTH_CHECK_SHOWN_ELSEWHERE.contains(&i.id)) {
        let ours = support_triage::HEALTH_CHECK_GUIDES.iter().find(|(id, _)| *id == it.id).map(|(_, g)| format!("docs/{g}"));
        let playbook = ["docs/support/", "docs/sso/", "docs/ops/"].iter().any(|p| it.guide.starts_with(p));
        assert_eq!(ours.as_deref(), playbook.then_some(it.guide), "{}'s guide", it.id);
    }
    assert!(support_triage::HEALTH_CHECK_GUIDES.iter().all(|(id, _)| ids.contains(id)), "every guide is an item's");
}

#[test]
fn it_reads_the_online_bundle_botd_makes() {
    let app = crate::runner::test_app();
    let api = vec!["api".to_string()];
    let incident = NewStatusIncident { id: "inc_triage", title: "API errors", impact: "critical", components: &api, state: "investigating", body: "Looking into it.", by: None };
    app.db.status_incident_create(&incident).unwrap();
    for _ in 0..12 {
        app.db.record(&Event::new(Actor::system("sso"), "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "bad_signature" })));
    }
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    app.db.add_approval(&bot.id, "claude", "Bash", "shell", "rm -rf build", &json!({}), "shell_destructive", "asks", db::now() + 600_000);
    let setup = json!({ "checklist": [{ "id": "backups", "label": "Server backups copied off this host", "done": false }], "done": 0, "total": 1 });
    let auth = crate::Auth::new(Some(app.clone()));
    let checks = crate::support::Checks::judge(&app, &auth, &setup, db::now());
    let built = crate::support::build(&app, &[], setup, checks, db::now());
    for n in names(&built.tar) {
        assert!(support_triage::FILES.contains(&n.as_str()), "support_triage doesn't read {n}");
    }

    let bundle = support_triage::read_tar(&built.tar).unwrap();
    assert_eq!(bundle.name, built.name);
    let t = support_triage::triage(&bundle, &Options::new(chrono::Utc::now())).unwrap();
    assert_eq!((t.kind, t.botd.as_deref(), t.missing.len()), (Kind::Online, Some(env!("CARGO_PKG_VERSION")), 0), "{:?}", t.missing);
    assert!(!ids(&t).contains(&"bundle.unreadable") && !ids(&t).contains(&"bundle.format") && !ids(&t).contains(&"bundle.stale"), "{:?}", ids(&t));

    let api = find(&t, "status.api");
    assert_eq!((api.level, api.severity), (Level::Fail, Some(1)), "a critical incident on the API");
    assert!(find(&t, "status.incident").summary.starts_with("Open status page incident \"API errors\" (critical, investigating, since "));
    let sign_in = find(&t, "audit.sign_in");
    assert_eq!(sign_in.level, Level::Warn);
    assert!(sign_in.summary.starts_with("12 sign-in failures in the 7 days to ") && sign_in.summary.contains("bad_signature ×12"), "{}", sign_in.summary);
    assert_eq!(sign_in.runbooks, ["support/runbook-saml.md#reasons-and-fixes"]);
    assert_eq!(find(&t, "setup.open").summary, "Setup checklist 0 of 1 done; open: Server backups copied off this host");
    assert_eq!(find(&t, "signal.backups").level, Level::Warn, "server backups aren't set up");
    let onboarding = find(&t, "onboarding.open");
    assert_eq!((onboarding.level, onboarding.severity), (Level::Info, None), "onboarding sets no severity");
    assert!(onboarding.summary.starts_with("Onboarding check ") && onboarding.summary.contains(&format!(" of {} items open: ", crate::onboarding::ITEMS.len())), "{}", onboarding.summary);
    for open in ["Identity provider set up (idp)", "Server backups off the host, encrypted (server_backups)"] {
        assert!(onboarding.summary.contains(open), "{open}: {}", onboarding.summary);
    }
    assert!(!onboarding.summary.contains("first_bundle"), "the bundle is one");
    let check = find(&t, "health_check.open");
    assert_eq!((check.level, check.severity), (Level::Info, None), "the health check sets no severity");
    for open in ["Incidents closed and reviewed (incidents)", "Server backups within their RPO (backups)"] {
        assert!(check.summary.contains(open), "{open}: {}", check.summary);
    }
    assert!(!check.summary.contains("(setup)") && !check.summary.contains("(score)"), "shown above: {}", check.summary);
    assert!(check.runbooks.contains(&"support/incident-review.md#the-review-draft") && check.runbooks.contains(&"support/runbook-backups.md"), "{:?}", check.runbooks);
    assert!(!ids(&t).contains(&"health_check.saml"), "no native SAML provider");

    assert!(t.testing, "tests run in testing mode");
    let v: Value = t.json();
    assert_eq!((v["suggestedSeverity"].clone(), v["cappedForTesting"].clone(), v["failed"].clone()), (json!(3), json!(true), json!(false)), "{v:#}");
    let mut production = Options::new(chrono::Utc::now());
    production.production = true;
    assert_eq!(support_triage::triage(&bundle, &production).unwrap().severity().unwrap().0, 1);
}

#[test]
fn it_reads_the_offline_bundle_botd_makes() {
    let root = db::temp_path("triage-offline");
    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    drop(db::Db::open(&data.join("app.sqlite")).unwrap());
    let file: BTreeMap<String, String> = [("DATA_DIR", data.display().to_string()), ("BACKUP_DIR", root.join("backups").display().to_string()), ("TESTING_MODE", "on".into()), ("PORT", "1".into())]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let settings = Settings::new(Some((root.join(".env"), file)), None, BTreeMap::new());
    let built = support_check::bundle(&settings, &Logs::None, db::now());
    for n in names(&built.tar) {
        assert!(support_triage::FILES.contains(&n.as_str()), "support_triage doesn't read {n}");
    }

    let bundle = support_triage::read_tar(&built.tar).unwrap();
    let t = support_triage::triage(&bundle, &Options::new(chrono::Utc::now())).unwrap();
    assert_eq!((t.kind, t.missing.len()), (Kind::Offline, 0), "{:?}", t.missing);
    let check: Value = serde_json::from_slice(&crate::support::tests::untar(&built.tar).into_iter().find(|(n, _)| n.ends_with("/check.json")).unwrap().1).unwrap();
    for f in check["findings"].as_array().unwrap() {
        let id = format!("check.{}", f["id"].as_str().unwrap());
        let flagged = matches!(f["status"].as_str(), Some("warn" | "fail"));
        assert_eq!(ids(&t).contains(&id.as_str()), flagged, "{id} is {}: {:?}", f["status"], ids(&t));
    }
    let botd = find(&t, "check.botd");
    assert_eq!((botd.level, botd.severity), (Level::Fail, Some(1)), "nothing runs on this DATA_DIR");
    assert!(ids(&t).contains(&"logs.none"));
    assert!(t.testing && t.severity().unwrap().0 == 3, "testing mode caps it");
    assert!(t.text().contains("Testing mode: not production"));
}
