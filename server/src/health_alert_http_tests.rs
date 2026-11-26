//! Health score alerts (ADR 0307) on a real server: today's score, recorded after a healthy
//! day, is audited and sent to the alert list once, naming nobody; `/metrics` shows the
//! newest day, and the shipped rules use only metrics botd writes.

use crate::machines_hosts_tests::until;
use crate::db::HealthScoreDay;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const DAY_MS: i64 = 86_400_000;

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

#[tokio::test]
async fn a_fall_is_audited_and_sent_once_and_metrics_show_the_newest_day() {
    let (port, app, admin, _) = serve_app().await;
    user_with(port, &admin, "ada@customer.example.com", "member").await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    let smtp = crate::notify::smtp::Smtp::for_test("127.0.0.1", mail.port, crate::notify::smtp::Tls::None, None, None);
    let _ = app.notifier.set(Arc::new(crate::notify::Notifier::new(Some(smtp), Some("https://bots.example.com".into()))));
    let s = crate::notify::Settings { email: crate::notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: true }, ..Default::default() };
    crate::notify::save(&app.db, &s);

    let yesterday = db::now() - DAY_MS;
    let all_ok = json!({ "adoption": "ok", "runs": "ok", "identity": "ok", "backups": "ok", "approvals": "ok", "license": "ok" });
    let day = HealthScoreDay { day: health_history::date_of(yesterday), at: yesterday, window_days: 30, score: Some(100), band: "healthy".into(), signals: all_ok.to_string() };
    assert!(app.db.health_score_record(&day).unwrap());
    assert!(health_history::record(&app, db::now()).unwrap());
    let (code, live) = call(port, "GET", "/api/support/health-score", &admin, "").await;
    assert_eq!(code, 200, "{live}");
    let live = parse(&live);
    let band = live["band"].as_str().unwrap().to_string();
    assert!(band == "watch" || band == "at_risk", "a new server isn't healthy: backups aren't set up: {live:#}");

    let fell = events(port, &admin, health_alert::FELL).await;
    assert_eq!(fell.len(), 1, "{fell:?}");
    let d = &fell[0]["details"];
    assert_eq!((d["fromScore"].as_u64(), d["score"].clone(), d["band"].as_str(), d["bandFell"].as_bool()), (Some(100), live["score"].clone(), Some(band.as_str()), Some(true)), "{d}");
    assert_eq!((fell[0]["actorKind"].as_str(), fell[0]["targetType"].as_str(), fell[0]["targetId"].as_str()), (Some("system"), Some("support"), Some("health_score")), "{:?}", fell[0]);

    let mut got = None;
    until("the notice", || {
        got = mail.got.lock().unwrap().iter().find(|m| m.headers.contains("The customer health score fell")).cloned();
        got.is_some()
    })
    .await;
    let got = got.unwrap();
    assert_eq!(got.to, ["ops@example.com"]);
    for want in [format!("The band fell from healthy to {}.", band.replace('_', " ")), "https://bots.example.com/console/#support".into(), "botctl health-score".into()] {
        assert!(got.body.contains(&want), "{want}: {}", got.body);
    }
    assert!(!got.body.contains("ada@") && !d.to_string().contains("ada@"), "{}", got.body);
    let mut sent = Vec::new();
    until("the notice audited", || {
        sent = app.db.audit_events(&audit::Filter { actions: vec!["notification.sent".into()], ..Default::default() }, 10, false);
        !sent.is_empty()
    })
    .await;
    assert_eq!(sent[0].details["event"], health_alert::FELL);

    assert!(!health_history::record(&app, db::now()).unwrap(), "once a day");
    assert_eq!(events(port, &admin, health_alert::FELL).await.len(), 1, "told once");

    let m = obs::render(&app);
    assert!(m.contains(&format!("superbot_health_score {}\n", live["score"])), "{m}");
    assert!(m.contains(&format!("superbot_health_score_band{{band=\"{band}\"}} 1\n")), "{m}");
    assert!(m.contains("superbot_health_score_band{band=\"healthy\"} 0\n"), "{m}");
    let types: std::collections::BTreeSet<String> = m.lines().filter_map(|l| Some(l.strip_prefix("# TYPE ")?.split(' ').next()?.to_string())).collect();
    let used = crate::machines_placement_tests::metric_names(include_str!("../../deploy/prometheus/superbot-health-score.rules.yml"));
    assert!(!used.is_empty() && used.is_subset(&types), "the rules use metrics botd doesn't write: {:?}", used.difference(&types).collect::<Vec<_>>());
}
