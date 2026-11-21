//! The status page (ADR 0090) on the real router: open to anyone and safe to be,
//! derived from live checks and recent counters, raised by admins' incident notes, and
//! off with STATUS_PAGE=off. Only admins manage incidents.

use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

/// `/status.json`, checking it answers 503 exactly when it reports a major outage.
async fn public(port: u16) -> Value {
    let (code, body) = call(port, "GET", "/status.json", "", "").await;
    let s = parse(&body);
    assert_eq!(code, if s["status"] == "major_outage" { 503 } else { 200 }, "{body}");
    s
}

fn component<'a>(s: &'a Value, id: &str) -> Option<&'a Value> {
    s["components"].as_array().unwrap().iter().find(|c| c["id"] == id)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

#[tokio::test]
async fn the_pages_are_open_and_show_core_components() {
    let (port, _, _, _) = serve_app().await;
    let s = public(port).await;
    assert_eq!((s["status"].as_str(), s["description"].as_str()), (Some("operational"), Some("All systems operational")), "{s}");
    let ids: Vec<&str> = s["components"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["api", "database", "runners"], "no control plane or notifications here: {s}");
    assert!(component(&s, "database").is_some_and(|c| c["status"] == "operational" && c["name"] == "Database"), "{s}");
    assert_eq!(s["incidents"], json!([]));

    let (code, head, body) = call_with(port, "GET", "/status", "", "", "").await;
    assert_eq!(code, 200);
    assert!(header(&head, "content-type").is_some_and(|v| v.starts_with("text/html")), "{head}");
    assert!(header(&head, "content-security-policy").is_some_and(|v| v.contains("default-src 'none'") && !v.contains("script")), "{head}");
    assert_eq!(header(&head, "x-content-type-options"), Some("nosniff"));
    assert!(body.contains("All systems operational") && body.contains("Harness runners") && !body.contains("<script"), "{body}");
}

#[tokio::test]
async fn recent_errors_and_failed_runs_show() {
    let (port, app, _, _) = serve_app().await;
    let now = db::now();
    app.db.metrics().bump_recent(now, |r| (r.requests, r.errors) = (100, 30));
    app.db.metrics().bump_recent(now, |r| (r.runs_done, r.runs_failed) = (3, 1));
    app.status.invalidate();
    let s = public(port).await;
    assert_eq!(component(&s, "api").unwrap()["status"], "partial_outage", "{s}");
    assert_eq!(component(&s, "api").unwrap()["note"], "Many requests are failing.", "{s}");
    assert_eq!(component(&s, "runners").unwrap()["status"], "degraded_performance", "{s}");
    assert_eq!(s["status"], "partial_outage", "the worst component: {s}");
}

#[tokio::test]
async fn the_snapshot_is_shared_for_a_few_seconds() {
    let (port, app, _, _) = serve_app().await;
    assert_eq!(public(port).await["status"], "operational");
    app.db.metrics().bump_recent(db::now(), |r| (r.requests, r.errors) = (100, 100));
    assert_eq!(public(port).await["status"], "operational", "still the cached snapshot");
    app.status.invalidate();
    assert_eq!(public(port).await["status"], "major_outage");
    assert_eq!(call(port, "GET", "/status.json", "", "").await.0, 503, "an uptime probe sees a major outage as down");
    assert_eq!(call(port, "GET", "/status", "", "").await.0, 200, "people still get the page");
}

#[tokio::test]
async fn probes_dont_dilute_the_api_error_share() {
    let (port, app, _, _) = serve_app().await;
    app.db.metrics().bump_recent(db::now(), |r| (r.requests, r.errors) = (20, 20));
    for _ in 0..30 {
        call(port, "GET", "/healthz", "", "").await;
        app.status.invalidate();
        call(port, "GET", "/status.json", "", "").await;
    }
    app.status.invalidate();
    assert_eq!(component(&public(port).await, "api").unwrap()["status"], "major_outage");
}

#[tokio::test]
async fn every_open_incident_counts_not_just_those_listed() {
    let (port, _, owner, _) = serve_app().await;
    let (code, _) = call(port, "POST", "/api/status/incidents", &owner, r#"{"title":"Down","body":"Everything.","impact":"critical","components":["api"]}"#).await;
    assert_eq!(code, 201);
    for n in 0..25 {
        let body = json!({ "title": format!("Note {n}"), "body": "FYI.", "impact": "none" }).to_string();
        assert_eq!(call(port, "POST", "/api/status/incidents", &owner, &body).await.0, 201);
    }
    let s = public(port).await;
    assert_eq!(s["incidents"].as_array().unwrap().len(), 20, "the list is capped");
    assert!(!s.to_string().contains("\"Down\""), "the critical one is off the list: {s}");
    assert_eq!((s["status"].as_str(), component(&s, "api").unwrap()["status"].as_str()), (Some("major_outage"), Some("major_outage")), "{s}");
}

#[tokio::test]
async fn machines_and_notifications_show_when_this_server_uses_them() {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, _, _) = serve_app_with(move |a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let _ = app.notifier.set(Arc::new(notify::Notifier::new(None, None)));
    let s = public(port).await;
    assert!(component(&s, "machines").is_some_and(|c| c["status"] == "operational" && c["name"] == "Machines and control plane"), "{s}");
    assert!(component(&s, "notifications").is_none(), "a notifier with no channel on isn't shown: {s}");

    let mut on = notify::load(&app.db);
    on.webhook.enabled = true;
    notify::save(&app.db, &on);
    app.status.invalidate();
    let s = public(port).await;
    assert!(component(&s, "notifications").is_some_and(|c| c["status"] == "operational"), "{s}");

    for _ in 0..5 {
        app.db.metrics().audited("notification.failed", "failure", None);
    }
    app.status.invalidate();
    assert_eq!(component(&public(port).await, "notifications").unwrap()["status"], "partial_outage");
}

#[tokio::test]
async fn admins_post_incidents_that_raise_components_until_resolved() {
    let (port, app, owner, _) = serve_app().await;
    let (admin_id, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (code, body) = call(
        port,
        "POST",
        "/api/status/incidents",
        &admin,
        &json!({ "title": "Slow Bot runs", "body": "Runs are slow to start.\nWe're looking.", "impact": "major", "components": ["runners", "runners"] }).to_string(),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let i = parse(&body);
    let id = i["id"].as_str().unwrap().to_string();
    assert_eq!((i["state"].as_str(), i["impact"].as_str(), i["createdBy"].as_str()), (Some("investigating"), Some("major"), Some(admin_id.as_str())), "{i}");
    assert_eq!(i["components"], json!(["runners"]), "duplicates dropped");

    let s = public(port).await;
    assert_eq!(component(&s, "runners").unwrap()["status"], "partial_outage", "{s}");
    assert_eq!(component(&s, "api").unwrap()["status"], "operational", "{s}");
    assert_eq!(s["status"], "partial_outage");
    let shown = &s["incidents"][0];
    assert_eq!((shown["title"].as_str(), shown["updates"][0]["body"].as_str()), (Some("Slow Bot runs"), Some("Runs are slow to start.\nWe're looking.")), "{s}");
    let text = s.to_string();
    assert!(!text.contains(&admin_id) && !text.contains("example.com") && !text.contains("createdBy"), "no author on the public page: {text}");
    let (_, html) = call(port, "GET", "/status", "", "").await;
    assert!(html.contains("Slow Bot runs") && html.contains("Partial outage"), "{html}");

    let (code, body) = call(port, "PATCH", &format!("/api/status/incidents/{id}"), &admin, r#"{"impact":"minor","components":["runners","api"]}"#).await;
    assert_eq!(code, 200, "{body}");
    let s = public(port).await;
    assert_eq!((component(&s, "runners").unwrap()["status"].as_str(), component(&s, "api").unwrap()["status"].as_str()), (Some("degraded_performance"), Some("degraded_performance")), "{s}");

    let (code, body) = call(port, "POST", &format!("/api/status/incidents/{id}/updates"), &admin, r#"{"state":"resolved","body":"Fixed."}"#).await;
    assert_eq!(code, 201, "{body}");
    let i = parse(&body);
    assert!(i["resolvedAt"].is_i64() && i["state"] == "resolved" && i["updates"].as_array().unwrap().len() == 2, "{i}");
    assert_eq!(i["updates"][0]["body"], "Fixed.", "newest first");
    let s = public(port).await;
    assert_eq!(s["status"], "operational", "resolved incidents raise nothing: {s}");
    assert_eq!(s["incidents"][0]["state"], "resolved", "still in the history: {s}");

    // Reopening clears the resolved time.
    let (_, body) = call(port, "POST", &format!("/api/status/incidents/{id}/updates"), &admin, r#"{"state":"monitoring","body":"Back again."}"#).await;
    assert!(parse(&body)["resolvedAt"].is_null(), "{body}");

    let (code, body) = call(port, "GET", "/api/status/incidents", &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(parse(&body)["incidents"].as_array().unwrap().len(), 1);

    let (code, _) = call(port, "DELETE", &format!("/api/status/incidents/{id}"), &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(public(port).await["incidents"], json!([]));
    assert_eq!(call(port, "DELETE", &format!("/api/status/incidents/{id}"), &admin, "").await.0, 404);

    let (_, body) = call(port, "GET", "/api/audit?action=status.*&limit=50", &admin, "").await;
    let actions: Vec<String> = audit_list(&body).iter().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    for a in ["status.incident_created", "status.incident_updated", "status.incident_deleted"] {
        assert!(actions.iter().any(|x| x == a), "{a} in {actions:?}");
    }
    assert!(app.db.status_incident(&id).unwrap().is_none());
    assert_eq!(call(port, "PATCH", &format!("/api/status/incidents/{id}"), &admin, r#"{"title":"x"}"#).await.0, 404);
}

#[tokio::test]
async fn an_open_incident_on_no_component_still_sets_the_overall_status() {
    let (port, _, owner, _) = serve_app().await;
    let (code, body) = call(port, "POST", "/api/status/incidents", &owner, r#"{"title":"Planned upgrade","body":"Back in 10 minutes.","impact":"maintenance"}"#).await;
    assert_eq!(code, 201, "{body}");
    let s = public(port).await;
    assert_eq!((s["status"].as_str(), s["description"].as_str()), (Some("under_maintenance"), Some("Maintenance underway")), "{s}");
    assert!(s["components"].as_array().unwrap().iter().all(|c| c["status"] == "operational"), "{s}");
}

#[tokio::test]
async fn only_admins_manage_incidents_and_input_is_checked() {
    let (port, app, owner, key) = serve_app().await;
    let (_, member) = user_with(port, &owner, "al@example.com", "member").await;
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
    let ok = r#"{"title":"t","body":"b"}"#;
    for who in [member.as_str(), key.auth(&bot.id).as_str()] {
        assert_eq!(call(port, "POST", "/api/status/incidents", who, ok).await.0, 403);
        assert_eq!(call(port, "GET", "/api/status/incidents", who, "").await.0, 403);
    }
    assert_eq!(call(port, "POST", "/api/status/incidents", "", ok).await.0, 401);
    assert_eq!(call(port, "GET", "/api/status/incidents", "", "").await.0, 401);

    let long = "x".repeat(status::MAX_TITLE + 1);
    for bad in [
        json!({ "body": "b" }),
        json!({ "title": "t" }),
        json!({ "title": "   ", "body": "b" }),
        json!({ "title": long, "body": "b" }),
        json!({ "title": "t", "body": "b", "impact": "apocalyptic" }),
        json!({ "title": "t", "body": "b", "state": "done" }),
        json!({ "title": "t", "body": "b", "components": ["db.internal.example"] }),
        json!({ "title": "t", "body": "b", "components": "api" }),
    ] {
        assert_eq!(call(port, "POST", "/api/status/incidents", &owner, &bad.to_string()).await.0, 400, "{bad}");
    }
    assert_eq!(call(port, "POST", "/api/status/incidents/inc_nope/updates", &owner, r#"{"state":"resolved","body":"x"}"#).await.0, 404);
    assert_eq!(public(port).await["incidents"], json!([]));
}

#[tokio::test]
async fn secrets_and_control_characters_never_reach_the_page() {
    let (port, _, owner, _) = serve_app().await;
    let secret = format!("sk-live-{}", random_hex(16));
    secrets::redact::register(&secret);
    let body = json!({ "title": "Oops\u{7}\ttitle", "body": format!("Rotated {secret} today\u{1b}[31m") }).to_string();
    let (code, res) = call(port, "POST", "/api/status/incidents", &owner, &body).await;
    assert_eq!(code, 201, "{res}");
    let s = public(port).await.to_string();
    assert!(!s.contains(&secret) && !s.contains("\\u0007") && !s.contains("\\u001b"), "{s}");
    assert!(s.contains("Oopstitle"), "{s}");
}

/// The burn-rate rules in deploy/ name only metrics botd exports, so a renamed metric
/// can't silently leave an alert that never fires.
#[tokio::test]
async fn the_slo_rules_use_only_metrics_botd_exports() {
    let (_, app, _, _) = serve_app().await;
    let rendered = obs::render(&app);
    let rules = include_str!("../../deploy/prometheus/superbot-slo.rules.yml");
    let mut names: Vec<&str> = Vec::new();
    for (i, _) in rules.match_indices("superbot_") {
        let rest = &rules[i..];
        let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
        let name = &rest[..end];
        let before = rules[..i].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '/') {
            continue;
        }
        names.push(name);
    }
    assert!(names.contains(&"superbot_http_requests_total") && names.contains(&"superbot_runs_total"), "{names:?}");
    for n in names {
        let family = n.trim_end_matches("_bucket").trim_end_matches("_sum").trim_end_matches("_count");
        assert!(rendered.contains(&format!("# TYPE {family} ")), "{n} isn't a metric botd exports");
    }
    for label in ["status_class=\"5xx\"", "route_class!~\"healthz|status\"", "result=~\"error|timeout\""] {
        assert!(rules.contains(label), "{label}");
    }
    for class in ["healthz", "status"] {
        assert_eq!(obs::route_class(if class == "status" { "/status.json" } else { "/healthz" }), class);
    }
}

#[tokio::test]
async fn status_page_off_answers_404() {
    let (port, app, owner, _) = serve_app().await;
    app.status.set_enabled(false);
    assert_eq!(call(port, "GET", "/status.json", "", "").await.0, 404);
    assert_eq!(call(port, "GET", "/status", "", "").await.0, 404);
    // Admins can still prepare notes.
    let (code, body) = call(port, "GET", "/api/status/incidents", &owner, "").await;
    assert_eq!((code, parse(&body)["enabled"].as_bool()), (200, Some(false)), "{body}");
}
