//! Incident review drafts (ADR 0201) on the real router: admins only, like every
//! `/api/status` route; built from the incident's timeline and botd's audit log; as JSON
//! or a Markdown download; audited; and never a name, email or address.

use crate::audit::{Actor, ActorKind, Event, Outcome};
use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const MIN: i64 = 60_000;

/// Posts an incident and its updates, then moves them to `t0` plus each one's minutes.
async fn incident(port: u16, app: &AppState, admin: &str, t0: i64, posts: &[(i64, &str, &str)]) -> String {
    let (code, body) = call(port, "POST", "/api/status/incidents", admin, &json!({ "title": "Bot runs fail", "body": posts[0].2, "impact": "critical", "components": ["runners"] }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let id = parse(&body)["id"].as_str().unwrap().to_string();
    for (_, state, text) in &posts[1..] {
        let (code, body) = call(port, "POST", &format!("/api/status/incidents/{id}/updates"), admin, &json!({ "state": state, "body": text }).to_string()).await;
        assert_eq!(code, 201, "{body}");
    }
    app.db.execute_raw(&format!("UPDATE status_incidents SET created_at = {t0} WHERE id = '{id}'")).unwrap();
    for (n, (min, state, _)) in posts.iter().enumerate() {
        let at = t0 + min * MIN;
        app.db.execute_raw(&format!("UPDATE status_incident_updates SET created_at = {at} WHERE incident_id = '{id}' AND id = (SELECT id FROM status_incident_updates WHERE incident_id = '{id}' ORDER BY id LIMIT 1 OFFSET {n})")).unwrap();
        if *state == "resolved" {
            app.db.execute_raw(&format!("UPDATE status_incidents SET resolved_at = {at} WHERE id = '{id}'")).unwrap();
        }
    }
    id
}

#[tokio::test]
async fn only_admins_draft_a_review() {
    let (port, app, admin, key) = serve_app().await;
    let id = incident(port, &app, &admin, db::now() - 60 * MIN, &[(0, "investigating", "Looking.")]).await;
    let path = format!("/api/status/incidents/{id}/review");
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for (who, auth) in [("member", member.as_str()), ("readonly", readonly.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", &path, auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", &path, "", "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/status/incidents/inc_nope/review", &admin, "").await.0, 404);
    let (code, body) = call(port, "GET", &path, &admin, "").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(parse(&body)["open"], true);
}

#[tokio::test]
async fn a_review_sets_botds_records_beside_the_timeline() {
    let (port, app, admin, _) = serve_app().await;
    let t0 = db::now() - 6 * 60 * MIN;
    let id = incident(port, &app, &admin, t0, &[(0, "investigating", "Runs are failing."), (30, "identified", "A bad policy."), (130, "monitoring", "Rolled back."), (150, "resolved", "Fixed.")]).await;
    let person = Actor { kind: ActorKind::User, id: Some("usr_ada".into()), name: Some("Ada Lovelace".into()), email: Some("ada@customer.example.com".into()), ..Default::default() };
    app.db.record_at(&Event::new(person.clone(), "policy.updated").target("policy", "default"), t0 - 40 * MIN).unwrap();
    app.db.record_at(&Event::new(Actor::system("server"), "server.started").details(json!({ "version": "0.9.1" })), t0 - 30 * MIN).unwrap();
    app.db.record_at(&Event::new(Actor::system("x"), "bot.run_finished").details(json!({ "result": "done" })), t0 - 100 * MIN).unwrap();
    for n in 0..3 {
        app.db.record_at(&Event::new(Actor::system("x"), "bot.run_finished").outcome(Outcome::Failure).details(json!({ "result": "error" })), t0 + (5 + n) * MIN).unwrap();
    }
    app.db.record_at(&Event::new(Actor::system("x"), "bot.run_finished").details(json!({ "result": "done" })), t0 + 140 * MIN).unwrap();
    app.db.record_at(&Event::new(person, "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "not_linked", "email": "ada@customer.example.com" })), t0 + 9 * MIN).unwrap();
    app.db.record_at(&Event::new(Actor::system("x"), "bot.run_finished").outcome(Outcome::Failure), t0 + 200 * MIN).unwrap();

    let detected = chrono::DateTime::from_timestamp_millis(t0 - 25 * MIN).unwrap().to_rfc3339();
    let (code, body) = call(port, "GET", &format!("/api/status/incidents/{id}/review?detected={}&lead=6", detected.replace('+', "%2B")), &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!((r["open"].clone(), r["durationMinutes"].clone(), r["leadHours"].clone()), (json!(false), json!(175), json!(6)), "{r:#}");
    assert_eq!(r["incident"]["components"], json!(["Harness runners"]));
    let t = &r["targets"];
    assert_eq!((t["postedAfterMinutes"].clone(), t["postedLate"].clone()), (json!(25), json!(true)), "{t:#}");
    assert_eq!((t["longestGapMinutes"].clone(), t["lateUpdates"].as_array().unwrap().len()), (json!(100), 1), "{t:#}");
    assert_eq!((t["toIdentifiedMinutes"].clone(), t["toResolvedMinutes"].clone()), (json!(55), json!(175)));
    let sources: Vec<&str> = r["timeline"].as_array().unwrap().iter().map(|e| e["source"].as_str().unwrap()).collect();
    assert_eq!(sources, ["change", "botd", "status_page", "status_page", "status_page", "status_page"], "{r:#}");
    assert_eq!(r["timeline"][1]["version"], "0.9.1");
    assert_eq!(r["timeline"][0]["actorKind"], "user");
    let d = &r["during"];
    assert_eq!((d["runsFinished"].clone(), d["runsFailed"].clone(), d["signInFailures"].clone()), (json!(4), json!(3), json!(1)), "the run after it ended isn't counted: {d:#}");
    assert_eq!((r["before"]["runsFinished"].clone(), r["before"]["minutes"].clone()), (json!(1), json!(175)));
    for never in ["usr_ada", "Ada", "ada@", "default\""] {
        assert!(!body.contains(never), "names nobody: {never} in {body}");
    }

    let (code, head, md) = call_with(port, "GET", &format!("/api/status/incidents/{id}/review?format=markdown"), &admin, "", "").await;
    assert_eq!(code, 200, "{md}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: text/markdown"), "{head}");
    assert!(lower.contains(&format!("content-disposition: attachment; filename=\"incident-review-{id}.md\"")), "{head}");
    assert!(lower.contains("cache-control: no-store"), "{head}");
    assert!(md.starts_with("# Incident review: Bot runs fail") && md.contains("## Actions") && md.contains("**missed 1 time**"), "{md}");
    assert!(md.contains("| Detected | _To fill in._"), "no detection time this time: {md}");
    assert!(md.contains("| Identified | 30 min after the first post |") && md.contains("| Duration | 2 h 30 min, from the first post |"), "{md}");

    let (_, audit) = call(port, "GET", "/api/audit?action=status.incident_reviewed", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["targetId"], id.as_str());
    assert_eq!((events[0]["details"]["format"].clone(), events[1]["details"]["detected"].clone()), (json!("markdown"), json!(true)));
}

#[tokio::test]
async fn bad_options_are_refused() {
    let (port, app, admin, _) = serve_app().await;
    let t0 = db::now() - 60 * MIN;
    let id = incident(port, &app, &admin, t0, &[(0, "investigating", "Looking.")]).await;
    for q in ["lead=0", "lead=200", "format=pdf", "detected=soon"] {
        let (code, body) = call(port, "GET", &format!("/api/status/incidents/{id}/review?{q}"), &admin, "").await;
        assert_eq!(code, 400, "{q}: {body}");
    }
    let late = t0 + 5 * MIN;
    let (code, body) = call(port, "GET", &format!("/api/status/incidents/{id}/review?detected={late}"), &admin, "").await;
    assert_eq!(code, 400, "{body}");
    assert!(body.contains("detected must be at or before"), "{body}");
}
