//! Health score history (ADR 0157) on the real router: admins only, oldest day first, with
//! the trend, and no names, emails or reason codes in what's kept.

use crate::db::HealthScoreDay;
use crate::tests::{call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const DAY_MS: i64 = 86_400_000;

fn past(days_ago: i64, score: u32, band: &str, signals: Value) -> HealthScoreDay {
    let at = db::now() - days_ago * DAY_MS;
    HealthScoreDay { day: health_history::date_of(at), at, window_days: 30, score: Some(score), band: band.into(), signals: signals.to_string() }
}

#[tokio::test]
async fn only_admins_get_it() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (delegate_id, delegate) = user_with(port, &admin, "d@example.com", "member").await;
    let every = ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"];
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Everything delegable", "permissions": every }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    let path = format!("/api/roles/{}/users/{delegate_id}", parse(&role)["id"].as_str().unwrap());
    assert_eq!(call(port, "PUT", &path, &admin, "").await.0, 200);
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for (who, auth) in [("member", member.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", "/api/support/health-score/history", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/health-score/history", "", "").await.0, 401);
    for bad in ["0", "3651", "ninety"] {
        let (code, body) = call(port, "GET", &format!("/api/support/health-score/history?days={bad}"), &admin, "").await;
        assert_eq!(code, 400, "{bad}: {body}");
        assert!(body.contains("days must be"), "{body}");
    }
}

#[tokio::test]
async fn it_shows_the_days_recorded_and_the_trend() {
    let (port, app, admin, _) = serve_app().await;
    user_with(port, &admin, "a@customer.example.com", "member").await;
    let (code, body) = call(port, "GET", "/api/support/health-score/history", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!((r["days"].as_i64(), r["points"].as_array().map(Vec::len), r["trend"].clone()), (Some(90), Some(0), Value::Null), "{r:#}");
    assert_eq!((r["recording"].as_bool(), r["keepDays"].as_u64()), (Some(true), Some(400)));

    assert!(app.db.health_score_record(&past(120, 95, "healthy", json!({ "runs": "ok" }))), "older than the window");
    assert!(app.db.health_score_record(&past(40, 92, "healthy", json!({ "adoption": "ok", "runs": "ok", "backups": "ok" }))));
    assert!(app.db.health_score_record(&past(10, 71, "watch", json!({ "adoption": "watch", "runs": "ok", "backups": "ok" }))));
    assert!(health_history::record(&app, db::now()), "today's, from the live score");
    assert!(!health_history::record(&app, db::now()), "once a day");

    let (code, body) = call(port, "GET", "/api/support/health-score/history", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    let points = r["points"].as_array().unwrap();
    assert_eq!(points.len(), 3, "{r:#}");
    assert_eq!((points[0]["score"].as_u64(), points[1]["score"].as_u64()), (Some(92), Some(71)));
    let today = &points[2];
    assert_eq!(today["date"], health_history::date_of(db::now()));
    assert_eq!(today["signals"].as_object().map(|s| s.len()), Some(health_score::SIGNALS.len()), "{today:#}");
    assert_eq!(today["signals"]["backups"], "watch", "no server backups in tests");
    let t = &r["trend"];
    assert_eq!((t["fromScore"].as_u64(), t["toScore"].clone(), t["fromBand"].as_str()), (Some(92), today["score"].clone(), Some("healthy")), "{t:#}");
    assert!(t["worse"].as_array().unwrap().contains(&json!("backups")), "ok 40 days ago, watch today: {t:#}");

    let (_, body) = call(port, "GET", "/api/support/health-score/history?days=15", &admin, "").await;
    let r = parse(&body);
    assert_eq!(r["points"].as_array().map(Vec::len), Some(2), "{r:#}");
    assert_eq!(r["trend"]["fromScore"], 71);
    let (_, body) = call(port, "GET", "/api/support/health-score/history?days=365", &admin, "").await;
    assert_eq!(parse(&body)["points"].as_array().map(Vec::len), Some(4));

    for (table, row) in app.db.all_rows() {
        if table == "health_scores" {
            assert!(!row.contains("customer.example.com") && !row.contains("summary") && !row.contains("facts"), "{row}");
        }
    }
}
