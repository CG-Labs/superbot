//! Residency in the app (ADR 0168): the people a pin holds see it, and fetch the
//! residency report (ADR 0155) on their own pin, or on their team's as its owner or an
//! admin. On the real router, with the in-memory provider for Linode.

use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::{ControlPlane, residency_me, residency_report};
use crate::tests::{audit_list, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn pin(region: &str, reference: &str) -> String {
    json!({ "region": region, "reference": reference }).to_string()
}

async fn get(port: u16, path: &str, who: &str) -> (u16, Value) {
    let (code, body) = call(port, "GET", path, who, "").await;
    (code, serde_json::from_str(&body).unwrap_or(Value::Null))
}

async fn generated(port: u16, admin: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={}&limit=200", residency_report::GENERATED), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn serve() -> (u16, AppState, String, crate::tests::BotKey) {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, owner, bots) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin, bots)
}

#[tokio::test]
async fn a_pinned_person_sees_their_pin_and_gets_its_report() {
    let (port, _, admin, bots) = serve().await;
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let (_, bea_s) = user_with(port, &admin, "bea@example.com", "readonly").await;

    let (code, v) = get(port, "/api/me/residency", &ada_s).await;
    assert_eq!((code, v["pin"].clone(), v["reports"].clone()), (200, Value::Null, json!([])), "{v}");
    assert_eq!(get(port, "/api/me/residency/report", &ada_s).await.0, 404);

    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("de-fra-2", "DPA-2026-014")).await.0, 200);
    let (code, v) = get(port, "/api/me/residency", &ada_s).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        (v["pin"]["on"].as_str(), v["pin"]["region"].as_str(), v["pin"]["reference"].as_str(), v["status"].as_str(), v["reports"].clone()),
        (Some("user"), Some("de-fra-2"), Some("DPA-2026-014"), Some("kept"), json!(["user"])),
        "{v}"
    );
    assert_eq!((v["machine"].clone(), v["backups"]["outside"].as_u64(), v["modelRoutes"]["inRegion"].as_bool()), (Value::Null, Some(0), Some(false)), "{v}");
    assert!(v["modelRoutes"]["gap"].as_str().unwrap().contains("open routing"), "{v}");

    // Her report is the admins' report on her pin, audited as hers and self-service.
    let (code, r) = get(port, "/api/me/residency/report", &ada_s).await;
    assert_eq!(code, 200, "{r}");
    assert_eq!((r["subject"]["type"].as_str(), r["subject"]["id"].as_str(), r["pin"]["reference"].as_str()), (Some("user"), Some(ada.as_str()), Some("DPA-2026-014")), "{r}");
    assert_eq!(r["digest"].as_str().unwrap(), residency_report::digest(&r));
    let audited = generated(port, &admin).await;
    assert_eq!(
        (audited[0]["actorId"].as_str(), audited[0]["targetId"].as_str(), audited[0]["details"]["selfService"].as_bool(), audited[0]["details"]["digest"].as_str()),
        (Some(ada.as_str()), Some(ada.as_str()), Some(true), r["digest"].as_str()),
        "{audited:?}"
    );
    let (code, head, md) = call_with(port, "GET", "/api/me/residency/report?format=markdown&on=user", &ada_s, "", "").await;
    assert!(code == 200 && md.starts_with("# Data residency report") && md.contains("under DPA-2026-014"), "{md}");
    assert!(head.to_ascii_lowercase().contains("content-disposition: attachment; filename=\"superbot-residency-user-"), "{head}");
    let (_, admins) = get(port, &format!("/api/users/{ada}/residency/report"), &admin).await;
    assert_eq!(generated(port, &admin).await[0]["details"]["selfService"].as_bool(), Some(false), "{admins}");

    // Bad queries are refused before they count; a team she isn't on has no report.
    for (q, want) in [("on=team", 404), ("on=everyone", 400), ("format=pdf", 400), ("from=soon", 400)] {
        assert_eq!(get(port, &format!("/api/me/residency/report?{q}"), &ada_s).await.0, want, "{q}");
    }

    // Each report reads the audit log for its period, so they are limited per person.
    for _ in 2..residency_me::MAX_REPORTS {
        assert_eq!(get(port, "/api/me/residency/report", &ada_s).await.0, 200);
    }
    let (code, v) = get(port, "/api/me/residency/report", &ada_s).await;
    assert!(code == 429 && v["error"].as_str().unwrap().contains("every 10 minutes"), "{code} {v}");
    assert_eq!(get(port, &format!("/api/users/{ada}/residency/report"), &admin).await.0, 200, "admins aren't limited");

    // Someone unpinned sees nothing, read-only included; a Bot's token isn't a person.
    let (code, v) = get(port, "/api/me/residency", &bea_s).await;
    assert_eq!((code, v["pin"].clone()), (200, Value::Null), "{v}");
    assert_eq!(get(port, "/api/me/residency/report", &bea_s).await.0, 404);
    let bot = bots.auth_as("b-none", &ada);
    for path in ["/api/me/residency", "/api/me/residency/report"] {
        let (code, body) = call(port, "GET", path, &bot, "").await;
        assert!(code == 401 || code == 403, "{path}: {code} {body}");
        assert!(!body.contains("DPA-2026-014"), "{body}");
    }
}

#[tokio::test]
async fn a_teams_pin_shows_to_its_members_and_its_report_only_to_owners_and_admins() {
    let (port, app, admin, _) = serve().await;
    app.teams.set(Default::default()).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, bea_s) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, body) = call(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let team = parse(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/machine"), &admin, "").await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), &admin, &pin("de-fra-2", "MSA-7")).await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), &admin, "{}").await.0, 200);

    // A member sees the team's pin, but not its reference, and gets no report of it.
    let (code, v) = get(port, "/api/me/residency", &bea_s).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["pin"]["on"].as_str(), v["pin"]["team"]["name"].as_str(), v["pin"]["region"].as_str()), (Some("team"), Some("Acme"), Some("de-fra-2")), "{v}");
    assert!(v["pin"].get("reference").is_none() && v["ownPin"].is_null() && v["reports"] == json!([]), "{v}");
    for q in ["", "?on=team"] {
        let (code, v) = get(port, &format!("/api/me/residency/report{q}"), &bea_s).await;
        assert!(code == 403 && v["error"].as_str().unwrap().contains("owners and admins"), "{q}: {v}");
    }

    // Its owner sees the reference and gets the team's report, covering both of them.
    let (_, v) = get(port, "/api/me/residency", &ada_s).await;
    assert_eq!((v["pin"]["reference"].as_str(), v["reports"].clone()), (Some("MSA-7"), json!(["team"])), "{v}");
    let (code, r) = get(port, "/api/me/residency/report", &ada_s).await;
    assert_eq!((code, r["subject"]["type"].as_str(), r["subject"]["name"].as_str()), (200, Some("team"), Some("Team Acme")), "{r}");
    let mut people: Vec<&str> = r["people"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
    people.sort();
    let mut want = [ada.as_str(), bea.as_str()];
    want.sort();
    assert_eq!(people, want, "{r}");
    assert_eq!(get(port, "/api/me/residency/report?on=user", &ada_s).await.0, 404, "no pin of her own");

    // A member's own pin, agreeing with the team's, is hers to get a report on.
    assert_eq!(call(port, "PUT", &format!("/api/users/{bea}/residency"), &admin, &pin("de-fra-2", "DPA-bea")).await.0, 200);
    let (_, v) = get(port, "/api/me/residency", &bea_s).await;
    assert_eq!((v["pin"]["on"].as_str(), v["ownPin"]["reference"].as_str(), v["reports"].clone()), (Some("team"), Some("DPA-bea"), json!(["user"])), "{v}");
    let (code, r) = get(port, "/api/me/residency/report", &bea_s).await;
    assert_eq!((code, r["subject"]["type"].as_str(), r["subject"]["id"].as_str()), (200, Some("user"), Some(bea.as_str())), "{r}");
    assert_eq!(get(port, "/api/me/residency/report?on=team", &bea_s).await.0, 403);
}
