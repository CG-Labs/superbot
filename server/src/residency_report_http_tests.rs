//! The residency report (ADR 0155): for one pin, where its data is, what the pin refused
//! or held to its region in the period, and a digest over it. On the real router, with
//! stand-ins for Incus hosts and S3, and the in-memory provider for Linode.

use crate::audit::{Outcome, Who};
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::incus::fleet::{Fleet, Member};
use crate::machines::provider::{MachineProvider, Policy};
use crate::machines::residency_report;
use crate::machines_hosts_tests::{DOWN_MS, back_up, events, json_call, machine_for, serve_with};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn pin(region: &str, reference: &str) -> String {
    json!({ "region": region, "reference": reference }).to_string()
}

fn tagged(m: Member, region: &str) -> Member {
    Member { region: Some(region.into()), ..m }
}

fn refusals(r: &Value) -> Vec<(String, Option<String>, u64)> {
    r["activity"]["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["action"].as_str().unwrap().to_string(), e["kind"].as_str().map(String::from), e["count"].as_u64().unwrap()))
        .collect()
}

#[tokio::test]
async fn a_users_report_shows_where_their_data_is_what_was_refused_and_held_and_is_sealed() {
    let env = serve_with(|a, b, c| Fleet::new(vec![tagged(a, "gb-lon"), tagged(b, "de-fra-2"), tagged(c, "gb-lon")], DOWN_MS).with_policy(Policy::Fill)).await;
    let (fra, fra_s) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    let m = machine_for(&env, &env.b, "b", &fra, true).await;
    back_up(&env, &fra).await;
    let report = format!("/api/users/{fra}/residency/report");

    // Only a pinned user has a report, and only admins see it.
    let (code, v) = json_call(&env, "GET", &report, "").await;
    assert!(code == 404 && v["error"].as_str().unwrap().contains("Residency pin on this user"), "{v}");
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/residency"), &pin("de-fra-2", "DPA-2026-014")).await.0, 200);
    assert_eq!(call(env.port, "GET", &report, &fra_s, "").await.0, 403);

    // The pin refuses a region change and a restore onto a London host.
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"gb-lon"}"#).await.0, 409);
    let b = env.app.db.machine_backups(&m.id).remove(0);
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{fra}/machine/restore"), &json!({ "backupId": b.id, "host": "a" }).to_string()).await.0, 409);
    // Runs: one held to Frankfurt for her, one held elsewhere, and refusals for her pin and another.
    let by = Who::system("test");
    let invoked = |regions: Value| by.event("harness.invoked").bot("b-none").details(json!({ "forUser": fra, "residency": { "regions": regions } }));
    env.app.db.record(&invoked(json!(["de-fra-2"])));
    env.app.db.record(&invoked(json!(["gb-lon"])));
    env.app.db.record(&by.event("harness.invoked").bot("b-none").details(json!({ "forUser": fra })));
    let run_refused = |subject: &str| {
        let pins = json!([{ "region": "de-fra-2", "pinnedOn": "user", "subjectId": subject, "reference": "x" }]);
        by.event("bot.run_refused").outcome(Outcome::Denied).details(json!({ "reason": "residency_pinned", "pins": pins }))
    };
    env.app.db.record(&run_refused(&fra));
    env.app.db.record(&run_refused("someone-else"));
    // A run that carried her, refused over her region under another pin (a team's that
    // agrees with hers), and a held run of a Bot since deleted: both by the people recorded.
    let team_pin = json!([{ "region": "de-fra-2", "pinnedOn": "team", "subjectId": "t-other", "reference": "y" }]);
    let d = json!({ "reason": "residency_pinned", "pins": team_pin, "pinnedRegions": ["de-fra-2"], "people": ["someone-else", fra] });
    env.app.db.record(&by.event("bot.run_refused").outcome(Outcome::Denied).details(d));
    env.app.db.record(&by.event("harness.invoked").bot("b-gone").details(json!({ "residency": { "regions": ["de-fra-2"], "people": [fra] } })));
    env.app.db.record(&by.event("harness.invoked").bot("b-gone").details(json!({ "forUser": fra, "residency": { "regions": ["de-fra-2"], "people": ["someone-else"] } })));

    let (code, r) = json_call(&env, "GET", &report, "").await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(
        (r["format"].as_str(), r["subject"]["type"].as_str(), r["subject"]["id"].as_str(), r["subject"]["name"].as_str(), r["pin"]["region"].as_str(), r["pin"]["reference"].as_str()),
        (Some(residency_report::FORMAT), Some("user"), Some(fra.as_str()), Some("User fra"), Some("de-fra-2"), Some("DPA-2026-014")),
        "{r}"
    );
    assert_eq!((r["status"].as_str(), r["outside"].as_array().map(Vec::len)), (Some("kept"), Some(0)), "{r}");
    let p = &r["people"][0];
    assert_eq!(
        (p["machine"]["id"].as_str(), p["machine"]["host"].as_str(), p["machine"]["hostRegion"].as_str(), p["machine"]["inRegion"].as_bool()),
        (Some(m.id.as_str()), Some("b"), Some("de-fra-2"), Some(true)),
        "{r}"
    );
    assert_eq!((p["backups"]["kept"].as_u64(), p["backups"]["inRegion"].as_u64(), p["backups"]["outside"].as_u64()), (Some(1), Some(1), Some(0)), "{r}");
    assert_eq!(p["modelRoutes"]["inRegion"].as_bool(), Some(false), "an open plan has no route held there");
    assert!(r["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("open routing")), "{r}");
    assert_eq!((r["region"]["hosts"].clone(), r["region"]["backupStore"].as_bool()), (json!(["b"]), Some(true)), "{r}");
    let changes = r["activity"]["pinChanges"].as_array().unwrap();
    assert_eq!((changes.len(), changes[0]["action"].as_str(), changes[0]["reference"].as_str()), (1, Some("user.residency_pinned"), Some("DPA-2026-014")), "{r}");
    assert_eq!(
        refusals(&r),
        [
            ("bot.run_refused".to_string(), Some("run".to_string()), 2),
            ("machine.residency_refused".to_string(), Some("move".to_string()), 1),
            ("user.region_change_refused".to_string(), None, 1),
        ],
        "{r}"
    );
    assert_eq!((r["activity"]["heldRuns"].as_u64(), r["activity"]["truncated"].as_bool()), (Some(2), Some(false)), "{r}");
    assert!(r["notCovered"][0].as_str().unwrap().contains("botd's own database"), "{r}");

    // The digest is over the report without it, and the report is audited with it.
    let digest = r["digest"].as_str().unwrap();
    assert_eq!(digest, residency_report::digest(&r));
    let generated = events(&env, residency_report::GENERATED).await;
    assert_eq!(
        (generated[0]["targetType"].as_str(), generated[0]["targetId"].as_str(), generated[0]["details"]["digest"].as_str(), generated[0]["details"]["status"].as_str()),
        (Some("user"), Some(fra.as_str()), Some(digest), Some("kept")),
        "{generated:?}"
    );

    // As Markdown, for the customer.
    let (code, md) = call(env.port, "GET", &format!("{report}?format=markdown"), &env.admin, "").await;
    assert_eq!(code, 200, "{md}");
    assert!(md.starts_with("# Data residency report") && md.contains("under DPA-2026-014") && md.contains("| `machine.residency_refused` | move | 1 |"), "{md}");
    let md_digest = &events(&env, residency_report::GENERATED).await[0]["details"]["digest"];
    assert!(md.contains(&format!("Digest: `{}`", md_digest.as_str().unwrap())), "{md}");
    // It carries the JSON it seals, so the customer can check the digest.
    let start = md.find("```json\n").unwrap() + "```json\n".len();
    let sealed: Value = serde_json::from_str(&md[start..start + md[start..].find("\n```\n").unwrap()]).unwrap();
    assert_eq!((sealed["digest"].clone(), residency_report::digest(&sealed)), (md_digest.clone(), md_digest.as_str().unwrap().to_string()));

    // A period before the pin has none of it; bad queries are refused.
    let (code, old) = json_call(&env, "GET", &format!("{report}?from=2020-01-01&to=2020-06-01"), "").await;
    assert_eq!(code, 200, "{old}");
    assert_eq!((old["activity"]["pinChanges"].as_array().map(Vec::len), old["activity"]["refusals"].as_array().map(Vec::len), old["activity"]["heldRuns"].as_u64()), (Some(0), Some(0), Some(0)));
    for q in ["format=pdf", "from=2026-11-02&to=2026-11-01", "from=2020-01-01", "from=soon"] {
        assert_eq!(json_call(&env, "GET", &format!("{report}?{q}"), "").await.0, 400, "{q}");
    }

    // A backup in London's store (here, one that failed) is data outside the region.
    let n = crate::db::NewMachineBackup { id: "blon", machine: &m, object_key: "t/lon.incus", store_region: Some("gb-lon"), encrypted: false, created_by: Some("schedule") };
    env.app.db.machine_backup_start(&n).unwrap();
    assert!(env.app.db.machine_backup_end("blon", None, Some("botd stopped")));
    let (_, r) = json_call(&env, "GET", &report, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"][0].as_str().unwrap().contains("fra: 1 of their machine backups are in a store outside de-fra-2"), "{r}");
    assert_eq!(r["people"][0]["backups"]["outside"].as_u64(), Some(1), "{r}");
}

#[tokio::test]
async fn a_teams_report_covers_its_members_and_refusals_on_the_team() {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake;
    let (port, app, owner, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    app.teams.set(Default::default()).unwrap();
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, body) = call(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let team = parse(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/machine"), &admin, "").await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), &admin, &pin("de-fra-2", "MSA-7")).await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), &admin, "{}").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{team}"), &admin, "").await.0, 409);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/region"), &admin, r#"{"region":"gb-lon"}"#).await.0, 409);

    let (code, body) = call(port, "GET", &format!("/api/teams/{team}/residency/report"), &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!((r["subject"]["type"].as_str(), r["subject"]["name"].as_str(), r["status"].as_str()), (Some("team"), Some("Team Acme"), Some("kept")), "{r}");
    let mut people: Vec<&str> = r["people"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
    people.sort();
    let mut want = [ada.as_str(), bea.as_str()];
    want.sort();
    assert_eq!(people, want, "{r}");
    let bea_row = r["people"].as_array().unwrap().iter().find(|p| p["id"] == bea.as_str()).unwrap();
    assert_eq!((bea_row["machine"]["region"].as_str(), bea_row["machine"]["inRegion"].as_bool(), bea_row["machine"]["host"].clone()), (Some("de-fra-2"), Some(true), Value::Null), "{r}");
    assert_eq!(r["region"]["hosts"], Value::Null, "Linode has no hosts of botd's");
    assert_eq!(refusals(&r), [("team.delete_refused".to_string(), None, 1), ("team.region_change_refused".to_string(), None, 1)], "{r}");
    assert_eq!(r["activity"]["pinChanges"][0]["action"].as_str(), Some("team.residency_pinned"), "{r}");
    assert_eq!(r["digest"].as_str().unwrap(), residency_report::digest(&r));

    // A member's own report points at the team's.
    let (code, body) = call(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert!(code == 404 && body.contains(&format!("botctl team residency {team} report")), "{body}");
    assert_eq!(call(port, "GET", "/api/teams/nope/residency/report", &admin, "").await.0, 404);
}
