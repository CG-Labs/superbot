//! Data regions (ADR 0117): admins set where a user's or a team's machines and backups
//! live, and nothing is made, placed, restored or backed up anywhere else. On the real
//! router, with the in-memory provider for Linode and stand-ins for Incus hosts and S3.

use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::incus::fleet::{Fleet, Member};
use crate::machines::provider::{MachineProvider, Policy};
use crate::machines_hosts_tests::{DOWN_MS, Env, back_up, json_call, machine_for, serve_with};
use crate::tests::{audit_list, call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn call_json(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// Linode, with MACHINE_REGIONS=gb-lon,de-fra-2.
async fn linode() -> (u16, AppState, String, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, owner, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    app.teams.set(Default::default()).unwrap();
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin, fake)
}

#[tokio::test]
async fn a_users_region_is_where_their_linode_is_made_and_a_request_elsewhere_is_refused() {
    let (port, app, admin, fake) = linode().await;
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;

    let (code, v) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["default"].as_str(), v["regions"][1]["id"].as_str(), v["regions"][0]["default"].as_bool()), (Some("gb-lon"), Some("de-fra-2"), Some(true)), "{v}");

    // Only admins see or set regions; only offered ones, or null for the default.
    for (m, p, b) in [("GET", "/api/regions".to_string(), ""), ("GET", format!("/api/users/{ada}/region"), ""), ("PUT", format!("/api/users/{ada}/region"), r#"{"region":"de-fra-2"}"#)] {
        assert_eq!(call(port, m, &p, &ada_s, b).await.0, 403, "{m} {p}");
    }
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"us-east"}"#).await;
    assert_eq!(code, 400, "{v}");
    assert!(v["error"].as_str().unwrap().contains("gb-lon, de-fra-2"), "{v}");

    let (code, v) = call_json(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!((code, v["own"].as_str(), v["effective"]["region"].as_str(), v["effective"]["source"].as_str()), (200, Some("de-fra-2"), Some("de-fra-2"), Some("user")), "{v}");
    let changed = events(port, &admin, "user.region_changed").await;
    assert_eq!(changed.len(), 1);
    assert_eq!((changed[0]["details"]["from"].clone(), changed[0]["details"]["to"].as_str(), changed[0]["details"]["effectiveFrom"].as_str()), (Value::Null, Some("de-fra-2"), Some("gb-lon")));
    let (_, u) = call_json(port, "GET", &format!("/api/users/{ada}"), &admin, "").await;
    assert_eq!((u["region"].as_str(), u["dataRegion"]["region"].as_str()), (Some("de-fra-2"), Some("de-fra-2")), "{u}");

    // Asking for another region is refused and audited; leaving it out puts it there.
    let (code, v) = call_json(port, "POST", &format!("/api/users/{ada}/machine"), &admin, r#"{"region":"gb-lon"}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("belongs in de-fra-2"), "{v}");
    let refused = events(port, &admin, "machine.refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["askedRegion"].as_str(), refused[0]["outcome"].as_str()), (Some("data_region"), Some("gb-lon"), Some("denied")));
    assert_eq!(fake.calls("create"), 0, "nothing was made anywhere");
    let (code, m) = call_json(port, "POST", &format!("/api/users/{ada}/machine"), &admin, "").await;
    assert_eq!((code, m["region"].as_str(), m["dataRegion"]["region"].as_str()), (202, Some("de-fra-2"), Some("de-fra-2")), "{m}");
    let pm = fake.get(m["providerId"].as_str().unwrap()).await.unwrap();
    assert_eq!(pm.region, "de-fra-2", "the Linode is made in that region");

    // Someone with no region set may still ask for any offered one, as before.
    let (code, m) = call_json(port, "POST", &format!("/api/users/{bea}/machine"), &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!((code, m["region"].as_str()), (202, Some("de-fra-2")), "{m}");

    // Moving someone's data while their machine is elsewhere is refused, and audited.
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":null}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("machine is in de-fra-2"), "{v}");
    let refused = events(port, &admin, "user.region_change_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["effectiveTo"].as_str()), (Some("machine_elsewhere"), Some("gb-lon")));
    assert_eq!(app.db.user(&ada).unwrap().region.as_deref(), Some("de-fra-2"));
    // Setting what's set already changes nothing and isn't audited again.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"de-fra-2"}"#).await.0, 200);
    assert_eq!(events(port, &admin, "user.region_changed").await.len(), 1);
}

#[tokio::test]
async fn a_teams_region_applies_to_members_without_their_own_and_changes_only_when_nothing_is_left_behind() {
    let (port, app, admin, fake) = linode().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (al, _) = user_with(port, &admin, "al@example.com", "member").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    let (code, t) = call_json(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    assert_eq!(app.db.user_machine(&ada).unwrap().region, "gb-lon", "the server's default before the team has one");

    // Ada's team machine is in London, so the team can't move to Frankfurt yet.
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/region"), &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("ada@example.com (gb-lon)") || v["error"].as_str().unwrap().contains("(gb-lon)"), "{v}");
    let refused = events(port, &admin, "team.region_change_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["blocked"][0]["userId"].as_str()), (1, Some(ada.as_str())));

    // Once she keeps London as her own, the team's region is for everyone else.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"gb-lon"}"#).await.0, 200);
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/region"), &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!((code, v["region"].as_str(), v["membersWithOwnRegion"].as_u64()), (200, Some("de-fra-2"), Some(1)), "{v}");
    let changed = events(port, &admin, "team.region_changed").await;
    assert_eq!((changed[0]["details"]["to"].as_str(), changed[0]["details"]["members"].as_u64()), (Some("de-fra-2"), Some(0)));
    let (_, t) = call_json(port, "GET", &format!("/api/teams/{team}"), &admin, "").await;
    assert_eq!(t["region"].as_str(), Some("de-fra-2"), "{t}");

    // A new member's team machine is made in Frankfurt.
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/members/{al}"), &admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str(), v["machine"]["region"].as_str()), (200, Some("requested"), Some("de-fra-2")), "{v}");
    let m = app.db.user_machine(&al).unwrap();
    assert_eq!(fake.get(m.provider_id.as_deref().unwrap()).await.unwrap().region, "de-fra-2");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{al}/region"), &admin, "").await;
    assert_eq!((r["effective"]["source"].as_str(), r["team"]["region"].as_str(), r["machine"]["inRegion"].as_bool()), (Some("team"), Some("de-fra-2"), Some(true)), "{r}");

    // Someone whose machine is in London can't join: their data would belong in Frankfurt.
    assert_eq!(call(port, "POST", &format!("/api/users/{cy}/machine"), &admin, "").await.0, 202);
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/members/{cy}"), &admin, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("keeps its data in de-fra-2"), "{v}");
    assert_eq!(app.db.team_id_of(&cy), None);
    let refused = events(port, &admin, "team.join_refused").await;
    assert_eq!((refused[0]["details"]["user"].as_str(), refused[0]["details"]["reason"].as_str()), (Some(cy.as_str()), Some("data_region")));
}

fn tagged(m: Member, region: &str) -> Member {
    Member { region: Some(region.into()), ..m }
}

/// Incus hosts `a` (London), `b` (Frankfurt) and `c` (London), filled in that order.
async fn incus() -> Env {
    serve_with(|a, b, c| Fleet::new(vec![tagged(a, "gb-lon"), tagged(b, "de-fra-2"), tagged(c, "gb-lon")], DOWN_MS).with_policy(Policy::Fill)).await
}

#[tokio::test]
async fn incus_machines_go_only_on_hosts_in_their_region_and_back_up_to_its_store() {
    let env = incus().await;
    let (code, v) = json_call(&env, "GET", "/api/regions", "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["hostRegions"].as_bool(), v["regions"][0]["hosts"].clone(), v["regions"][1]["hosts"].clone()), (Some(true), json!(["a", "c"]), json!(["b"])), "{v}");
    assert_eq!((v["regions"][0]["backups"]["store"].as_str(), v["regions"][1]["backups"]["store"].as_str()), (Some("default"), Some("de-fra-2")), "{v}");
    assert_eq!(v["backups"]["warnings"], json!([]), "{v}");

    // Frankfurt's machine goes on b, though filling would pick a.
    let (fra, _) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    let m = machine_for(&env, &env.b, "b", &fra, true).await;
    assert_eq!(m.region, "de-fra-2");
    let (lon, _) = user_with(env.port, &env.admin, "lon@example.com", "member").await;
    let n = machine_for(&env, &env.a, "a", &lon, true).await;
    assert_eq!(n.region, "gb-lon");

    // Each backup goes to its region's store, and says so.
    let b = back_up(&env, &fra).await;
    assert_eq!(b.store_region.as_deref(), Some("de-fra-2"));
    let fra_store = &env.stores[0].1;
    assert!(fra_store.keys().iter().any(|k| k == &b.object_key), "{:?}", fra_store.keys());
    assert!(!env.s3.keys().iter().any(|k| k.contains(&m.id)), "nothing of Frankfurt's in the default store");
    let made = crate::machines_hosts_tests::events(&env, "machine.backup_created").await;
    assert_eq!((made[0]["details"]["store"].as_str(), made[0]["details"]["inRegion"].as_bool()), (Some("de-fra-2"), Some(true)));
    let c = back_up(&env, &lon).await;
    assert_eq!(c.store_region, None);
    assert!(env.s3.keys().iter().any(|k| k == &c.object_key));

    // A restore stays in its region: onto a London host is refused.
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra}/machine/restore"), &json!({ "backupId": b.id, "host": "a" }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Host a is in gb-lon, and this machine's data stays in de-fra-2"), "{v}");

    // With b drained there's no room in Frankfurt: refused, never put in London.
    assert_eq!(json_call(&env, "PUT", "/api/machines/hosts/b/drain", r#"{"reason":"maintenance"}"#).await.0, 200);
    let (fra2, _) = user_with(env.port, &env.admin, "fra2@example.com", "member").await;
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra2}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra2}/machine"), "").await;
    assert_eq!(code, 409, "{v}");
    let why = v["error"].as_str().unwrap();
    assert!(why.contains("machine in de-fra-2") && why.contains("a is in gb-lon") && why.contains("b is drained"), "{why}");
    assert!(env.app.db.user_machine(&fra2).is_none());
    assert_eq!(env.a.w().instances.len() + env.c.w().instances.len(), 1, "only London's own machine is in London");

    // Once destroyed and its backups deleted, Frankfurt's user can move to London.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/users/{fra}/machine"), "").await;
    assert_eq!((code, v["state"].as_str()), (200, Some("destroyed")), "{v}");
    let (code, v) = json_call(&env, "DELETE", &format!("/api/machines/{}/backups", m.id), "").await;
    assert_eq!((code, v["backups"].as_array().map(Vec::len)), (200, Some(1)), "{v}");
    assert!(!fra_store.keys().iter().any(|k| k.contains(&m.id)), "deleted from Frankfurt's store: {:?}", fra_store.keys());
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"gb-lon"}"#).await;
    assert_eq!((code, v["effective"]["region"].as_str()), (200, Some("gb-lon")), "{v}");
}
