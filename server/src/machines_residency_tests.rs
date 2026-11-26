//! Contractual data residency (ADR 0129): an admin pins a user or a team to a data
//! region, and their machines, backups and restores stay there or are refused and
//! audited. On the real router, with the in-memory provider for Linode and stand-ins for
//! Incus hosts and S3.

use crate::db::PinOn;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::incus::fleet::{Fleet, Member};
use crate::machines::provider::{MachineProvider, Policy};
use crate::machines::server_data::{Copies, Policy as ServerDataPolicy, ServerData};
use crate::machines_hosts_tests::{DOWN_MS, Env, back_up, events, json_call, machine_for, reconcile, serve_with, serve_with_offsite};
use crate::tests::{audit_list, call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn call_json(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn audit(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

fn pin(region: &str, reference: &str) -> String {
    json!({ "region": region, "reference": reference }).to_string()
}

fn tagged(m: Member, region: &str) -> Member {
    Member { region: Some(region.into()), ..m }
}

/// Incus hosts `a` (London), `b` (Frankfurt) and `c` (London); `stores` says which
/// regions other than London keep a backup store of their own.
async fn incus(frankfurt_store: bool) -> Env {
    let build = |a, b, c| Fleet::new(vec![tagged(a, "gb-lon"), tagged(b, "de-fra-2"), tagged(c, "gb-lon")], DOWN_MS).with_policy(Policy::Fill);
    match frankfurt_store {
        true => serve_with(build).await,
        false => serve_with_offsite(build, |s| s.stores.retain(|(r, _)| r != "de-fra-2")).await,
    }
}

#[tokio::test]
async fn a_pinned_users_region_and_restores_stay_in_it_and_a_pin_needs_all_their_data_there() {
    let env = incus(true).await;
    let (fra, fra_s) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    let m = machine_for(&env, &env.b, "b", &fra, true).await;
    let b = back_up(&env, &fra).await;
    assert_eq!(b.store_region.as_deref(), Some("de-fra-2"));

    // Only admins pin, only to an offered region, and only under a reference.
    let path = format!("/api/users/{fra}/residency");
    assert_eq!(call(env.port, "PUT", &path, &fra_s, &pin("de-fra-2", "DPA-1")).await.0, 403);
    assert_eq!(json_call(&env, "PUT", &path, &pin("us-east", "DPA-1")).await.0, 400);
    assert_eq!(json_call(&env, "PUT", &path, r#"{"region":"de-fra-2"}"#).await.0, 400);

    let (code, v) = json_call(&env, "PUT", &path, &pin("de-fra-2", "DPA-2026-014")).await;
    assert_eq!((code, v["residency"]["region"].as_str(), v["residency"]["reference"].as_str(), v["residency"]["subjectType"].as_str()), (200, Some("de-fra-2"), Some("DPA-2026-014"), Some("user")), "{v}");
    let pinned = events(&env, "user.residency_pinned").await;
    assert_eq!((pinned.len(), pinned[0]["details"]["region"].as_str(), pinned[0]["details"]["renewed"].as_bool()), (1, Some("de-fra-2"), Some(false)), "{pinned:?}");
    let (_, u) = json_call(&env, "GET", &format!("/api/users/{fra}"), "").await;
    assert_eq!(u["residency"]["region"].as_str(), Some("de-fra-2"), "{u}");

    // Their region can't be moved or cleared while pinned: refused and audited.
    for to in [r#"{"region":"gb-lon"}"#, r#"{"region":null}"#] {
        let (code, v) = json_call(&env, "PUT", &format!("/api/users/{fra}/region"), to).await;
        assert_eq!(code, 409, "{v}");
        assert!(v["error"].as_str().unwrap().contains("pinned to de-fra-2 (DPA-2026-014)"), "{v}");
    }
    let refused = events(&env, "user.region_change_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["reason"].as_str(), refused[0]["details"]["pinnedRegion"].as_str()), (2, Some("residency_pinned"), Some("de-fra-2")));
    assert_eq!(env.app.db.user(&fra).unwrap().region.as_deref(), Some("de-fra-2"));

    // A restore onto a London host is refused before anything is made, as a move.
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra}/machine/restore"), &json!({ "backupId": b.id, "host": "a" }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Host a is in gb-lon"), "{v}");
    let refused = events(&env, "machine.residency_refused").await;
    assert_eq!(
        (refused[0]["details"]["action"].as_str(), refused[0]["details"]["pinnedOn"].as_str(), refused[0]["targetId"].as_str(), refused[0]["outcome"].as_str()),
        (Some("move"), Some("user"), Some(m.id.as_str()), Some("denied"))
    );
    assert!(env.a.instance(&format!("{}-restore", m.label)).is_none() && env.a.instance(&m.label).is_none());
    // Backups still go to Frankfurt's store.
    assert_eq!(back_up(&env, &fra).await.store_region.as_deref(), Some("de-fra-2"));

    // Someone whose machine is in London can't be pinned to Frankfurt.
    let (lon, _) = user_with(env.port, &env.admin, "lon@example.com", "member").await;
    let lm = machine_for(&env, &env.a, "a", &lon, false).await;
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{lon}/residency"), &pin("de-fra-2", "DPA-2")).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("their machine is in gb-lon"), "{v}");
    let refused = events(&env, "user.residency_pin_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["targetId"].as_str()), (Some("data_outside"), Some(lon.as_str())));
    assert!(env.app.db.residency_pin(PinOn::User, &lon).is_none());
    // Once the machine is gone, a backup that failed (perhaps after its upload) still counts.
    let n = crate::db::NewMachineBackup { id: "bfailed", machine: &lm, object_key: "t/failed.incus", store_region: None, encrypted: false, created_by: Some("schedule") };
    env.app.db.machine_backup_start(&n).unwrap();
    assert!(env.app.db.machine_backup_end("bfailed", None, Some("botd stopped")));
    assert_eq!(json_call(&env, "DELETE", &format!("/api/users/{lon}/machine"), "").await.0, 200);
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{lon}/residency"), &pin("de-fra-2", "DPA-2")).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("1 of their machine backups are in a store outside de-fra-2"), "{v}");

    // Pinned elsewhere needs an unpin first; the same region again renews the reference.
    let (code, v) = json_call(&env, "PUT", &path, &pin("gb-lon", "DPA-3")).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Unpin first"), "{v}");
    let (code, v) = json_call(&env, "PUT", &path, &pin("de-fra-2", "DPA-2027-001")).await;
    assert_eq!((code, v["residency"]["reference"].as_str()), (200, Some("DPA-2027-001")), "{v}");
    assert_eq!(events(&env, "user.residency_pinned").await[0]["details"]["renewed"].as_bool(), Some(true));

    // The regions page shows the pin.
    let (_, r) = json_call(&env, "GET", "/api/regions", "").await;
    assert_eq!((r["regions"][1]["pinned"]["users"].as_u64(), r["residency"]["pins"][0]["name"].as_str()), (Some(1), Some("fra")), "{r}");
    // Its data is all in de-fra-2; only its open plan's model routes aren't (ADR 0139).
    let w = r["residency"]["warnings"].as_array().unwrap();
    assert!(w.len() == 1 && w[0].as_str().unwrap().contains("the Self-host plan has open routing, so no model route is held to de-fra-2"), "{r}");

    // Unpinning needs a reason, is audited, and leaves the region as it was.
    assert_eq!(json_call(&env, "DELETE", &path, r#"{"reason":" "}"#).await.0, 400);
    let (code, v) = json_call(&env, "DELETE", &path, r#"{"reason":"agreement ended"}"#).await;
    assert_eq!((code, v["residency"].clone(), v["own"].as_str()), (200, Value::Null, Some("de-fra-2")), "{v}");
    let unpinned = events(&env, "user.residency_unpinned").await;
    assert_eq!((unpinned[0]["details"]["reason"].as_str(), unpinned[0]["details"]["reference"].as_str()), (Some("agreement ended"), Some("DPA-2027-001")));
    assert_eq!(json_call(&env, "DELETE", &path, r#"{"reason":"again"}"#).await.0, 404);
}

#[tokio::test]
async fn without_a_store_in_the_region_a_pin_is_refused_and_pinned_backups_restores_and_recovery_stop() {
    let env = incus(false).await;
    let (fra, _) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    let m = machine_for(&env, &env.b, "b", &fra, true).await;
    // Unpinned, with MACHINE_BACKUP_RESIDENCY=warn, it goes to the default store in London.
    let b = back_up(&env, &fra).await;
    assert_eq!(b.store_region, None);

    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{fra}/residency"), &pin("de-fra-2", "DPA-1")).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("machine backups have no store in de-fra-2"), "{v}");
    assert_eq!(events(&env, "user.residency_pin_refused").await[0]["details"]["reason"].as_str(), Some("region_not_ready"));

    // A pin made before the store went away: nothing goes to, or comes from, London's store.
    env.app.db.pin_residency(PinOn::User, &fra, "de-fra-2", "DPA-1", None).unwrap();
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra}/machine/backups"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("no backup store is set there"), "{v}");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra}/machine/restore"), &json!({ "backupId": b.id }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("isn't said to be in de-fra-2"), "{v}");
    let refused = events(&env, "machine.residency_refused").await;
    let actions: Vec<&str> = refused.iter().filter_map(|e| e["details"]["action"].as_str()).collect();
    assert_eq!(actions, ["restore", "backup"], "{refused:?}");
    assert_eq!(env.app.db.machine_backups(&m.id).len(), 1, "no new backup");
    let (_, r) = json_call(&env, "GET", "/api/regions", "").await;
    let w = r["residency"]["warnings"][0].as_str().unwrap_or_default();
    assert!(w.contains("User fra is pinned to de-fra-2") && w.contains("no store in de-fra-2") && w.contains("1 of their machine backups"), "{r}");

    // Host b is lost: its pinned machine isn't restored from London's store, and that's audited.
    env.b.w().down = true;
    reconcile(&env).await;
    env.app.db.machine_host_failing_backdate("b", DOWN_MS);
    reconcile(&env).await;
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/b/recover", "{}").await;
    assert_eq!(code, 202, "{out}");
    assert_eq!(out["restoring"].as_array().map(Vec::len), Some(0), "{out}");
    let skipped = out["skipped"].as_array().unwrap().iter().find(|s| s["machineId"] == m.id.as_str()).unwrap_or_else(|| panic!("{out}"));
    assert!(skipped["reason"].as_str().unwrap().contains("isn't said to be in de-fra-2"), "{out}");
    let refused = events(&env, "machine.residency_refused").await;
    assert_eq!(refused[0]["details"]["action"].as_str(), Some("recover"), "{refused:?}");
    assert!(env.a.instance(&m.label).is_none() && env.c.instance(&m.label).is_none(), "never made in London");
}

#[tokio::test]
async fn with_hosts_untagged_after_a_pin_no_new_machine_is_made_asked_for_or_retried() {
    let env = serve_with(|a, b, c| Fleet::new(vec![a, b, c], DOWN_MS).with_policy(Policy::Fill)).await;
    let (fra, _) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    let (lon, _) = user_with(env.port, &env.admin, "lon@example.com", "member").await;
    let made = |label: &str| [&env.a, &env.b, &env.c].iter().any(|s| s.instance(label).is_some());

    // Pinned while hosts were tagged; the tags have since gone.
    env.app.db.pin_residency(PinOn::User, &fra, "local", "DPA-1", None).unwrap();
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{fra}/machine"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Incus hosts aren't tagged with data regions"), "{v}");
    let refused = events(&env, "machine.residency_refused").await;
    assert_eq!(
        (refused[0]["details"]["action"].as_str(), refused[0]["targetType"].as_str(), refused[0]["targetId"].as_str()),
        (Some("create"), Some("user"), Some(fra.as_str())),
        "{refused:?}"
    );
    assert!(env.app.db.user_machine(&fra).is_none());

    // A machine already pending when the pin landed waits, audited once, until tagged.
    let new = crate::db::NewMachine { user_id: &lon, provider: "incus", label_prefix: &env.cp.label_prefix, tier: "starter", plan: &env.cp.tiers[0].1, region: "local", created_by: None };
    let m = env.app.db.add_machine(&new).unwrap_or_else(|_| panic!("added"));
    env.app.db.pin_residency(PinOn::User, &lon, "local", "DPA-2", None).unwrap();
    reconcile(&env).await;
    reconcile(&env).await;
    let m = env.app.db.machine(&m.id).unwrap();
    assert_eq!((m.state, m.provider_id.as_deref(), m.placed_on.as_deref()), (crate::machines::State::Pending, None, None), "{m:?}");
    assert!(m.last_error.as_deref().unwrap_or_default().contains("aren't tagged"), "{m:?}");
    assert!(!made(&m.label));
    let refused = events(&env, "machine.residency_refused").await;
    assert_eq!(refused.iter().filter(|e| e["targetId"] == m.id.as_str()).count(), 1, "{refused:?}");
    assert_eq!(refused[0]["details"]["action"].as_str(), Some("create"));

    // Unpinned, it is made.
    assert!(env.app.db.unpin_residency(PinOn::User, &lon).unwrap());
    reconcile(&env).await;
    assert!(env.app.db.machine(&m.id).unwrap().provider_id.is_some() && made(&m.label));
}

#[tokio::test]
async fn a_pin_checks_the_host_a_machine_is_on_not_only_its_record() {
    let env = incus(true).await;
    let (fra, _) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    // Made before hosts were tagged: recorded as Frankfurt, but on host a, in London.
    let mut m = machine_for(&env, &env.a, "a", &fra, false).await;
    m.region = "de-fra-2".into();
    assert!(env.app.db.save_machine(&m, m.state));
    env.app.db.set_user_region(&fra, Some("de-fra-2"));

    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{fra}/residency"), &pin("de-fra-2", "DPA-1")).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("their machine is on host a, in gb-lon"), "{v}");
    assert_eq!(events(&env, "user.residency_pin_refused").await[0]["details"]["reason"].as_str(), Some("data_outside"));
    assert!(env.app.db.residency_pin(PinOn::User, &fra).is_none());
}

/// Linode, with MACHINE_REGIONS=gb-lon,de-fra-2.
async fn linode() -> (u16, AppState, String) {
    let (port, app, admin, _) = linode_with(ServerData::default()).await;
    (port, app, admin)
}

/// As `linode`, with botd's own data where `server_data` says (ADR 0184).
async fn linode_with(server_data: ServerData) -> (u16, AppState, String, Arc<ControlPlane>) {
    linode_set(|cp| cp.server_data = server_data).await
}

/// As `linode`, with the control plane as `set` leaves it.
async fn linode_set(set: impl FnOnce(&mut ControlPlane)) -> (u16, AppState, String, Arc<ControlPlane>) {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake;
    let mut cp = ControlPlane::for_tests(p);
    set(&mut cp);
    let cp = Arc::new(cp);
    let shared = cp.clone();
    let (port, app, owner, _) = serve_app_with(move |a| a.machines = shared).await;
    app.teams.set(Default::default()).unwrap();
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin, cp)
}

fn in_london(policy: ServerDataPolicy) -> ServerData {
    ServerData { region: Some("gb-lon".into()), copies: Copies::OnHost, destination: None, policy }
}

#[tokio::test]
async fn a_pinned_team_keeps_members_and_its_region_in_it_and_cant_be_deleted_until_unpinned() {
    let (port, app, admin) = linode().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    let (code, t) = call_json(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    let path = format!("/api/teams/{team}/residency");
    assert_eq!(app.db.user_machine(&ada).unwrap().region, "gb-lon");

    // Ada's machine is in London: the team can't be pinned to Frankfurt yet.
    let (code, v) = call_json(port, "PUT", &path, &admin, &pin("de-fra-2", "MSA-7")).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("ada (their machine is in gb-lon)"), "{v}");
    let refused = audit(port, &admin, "team.residency_pin_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["blocked"][0]["userId"].as_str()), (Some("data_outside"), Some(ada.as_str())));

    // Once it's gone, the pin sets the team's region and shows on the team.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/machine"), &admin, "").await.0, 200);
    let (code, v) = call_json(port, "PUT", &path, &admin, &pin("de-fra-2", "MSA-7")).await;
    assert_eq!((code, v["region"].as_str(), v["residency"]["region"].as_str(), v["residency"]["subjectType"].as_str()), (200, Some("de-fra-2"), Some("de-fra-2"), Some("team")), "{v}");
    assert_eq!(audit(port, &admin, "team.residency_pinned").await[0]["details"]["reference"].as_str(), Some("MSA-7"));
    let (_, t) = call_json(port, "GET", &format!("/api/teams/{team}"), &admin, "").await;
    assert_eq!((t["region"].as_str(), t["residency"]["region"].as_str(), t["residency"]["reference"].as_str()), (Some("de-fra-2"), Some("de-fra-2"), Some("MSA-7")), "{t}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/region"), &admin, "").await;
    assert_eq!((r["effective"]["region"].as_str(), r["residency"]["subjectType"].as_str()), (Some("de-fra-2"), Some("team")), "{r}");

    // The team's region, and a member's own, can't move away from it.
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/region"), &admin, r#"{"region":"gb-lon"}"#).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Team Acme's data is pinned to de-fra-2"), "{v}");
    assert_eq!(audit(port, &admin, "team.region_change_refused").await[0]["details"]["reason"].as_str(), Some("residency_pinned"));
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"gb-lon"}"#).await.0, 409);
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":"de-fra-2"}"#).await.0, 200, "the same region is fine");
    // Her own pin, agreeing with the team's, holds her own region even though the team's would allow clearing it.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("de-fra-2", "DPA-ada")).await.0, 200);
    // Her own pin shows apart from the team's, so it can be unpinned on its own.
    let (_, u) = call_json(port, "GET", &format!("/api/users/{ada}"), &admin, "").await;
    assert_eq!((u["residency"]["subjectType"].as_str(), u["ownResidency"]["reference"].as_str()), (Some("team"), Some("DPA-ada")), "{u}");
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{ada}/region"), &admin, r#"{"region":null}"#).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Their data is pinned to de-fra-2 (DPA-ada)"), "{v}");
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"covered by the team"}"#).await.0, 200);
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-9")).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(audit(port, &admin, "user.residency_pin_refused").await[0]["details"]["reason"].as_str(), Some("team_pinned"));

    // Nobody joins with data elsewhere; someone with none joins, and theirs is made in Frankfurt.
    assert_eq!(call(port, "POST", &format!("/api/users/{cy}/machine"), &admin, r#"{"region":"gb-lon"}"#).await.0, 202);
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/members/{cy}"), &admin, "{}").await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("their machine is in gb-lon"), "{v}");
    assert_eq!(audit(port, &admin, "team.join_refused").await[0]["details"]["reason"].as_str(), Some("residency_pinned"));
    assert_eq!(app.db.team_id_of(&cy), None);
    let (code, v) = call_json(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), &admin, "{}").await;
    assert_eq!((code, v["machine"]["region"].as_str()), (200, Some("de-fra-2")), "{v}");

    // Pinned teams aren't deleted; unpinning needs a reason, then both work.
    let (code, v) = call_json(port, "DELETE", &format!("/api/teams/{team}"), &admin, "").await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Unpin it first"), "{v}");
    assert_eq!(audit(port, &admin, "team.delete_refused").await[0]["details"]["reason"].as_str(), Some("residency_pinned"));
    assert_eq!(call(port, "DELETE", &path, &admin, "{}").await.0, 400);
    let (code, v) = call_json(port, "DELETE", &path, &admin, r#"{"reason":"moved to the EU contract"}"#).await;
    assert_eq!((code, v["residency"].clone(), v["region"].as_str()), (200, Value::Null, Some("de-fra-2")), "{v}");
    assert_eq!(audit(port, &admin, "team.residency_unpinned").await[0]["details"]["reason"].as_str(), Some("moved to the EU contract"));
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{team}"), &admin, "").await.0, 200);
    assert!(app.db.residency_pins().is_empty());

    // Erasing someone takes their own pin, and their email out of any other pin's reference.
    let (dan, _) = user_with(port, &admin, "dan@example.com", "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/users/{dan}/residency"), &admin, &pin("gb-lon", "DPA-dan")).await.0, 200);
    let (code, t) = call_json(port, "POST", "/api/teams", &admin, &json!({ "name": "Beta", "owner": "cy@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let beta = t["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "PUT", &format!("/api/teams/{beta}/residency"), &admin, &pin("gb-lon", "MSA-8, signed by dan@example.com")).await.0, 200);
    let egress = format!("{}{dan}", crate::machines::egress_policy::USER_KEY);
    app.db.set_setting(&egress, r#"{"mode":"allow_list","allow":["api.example.com"]}"#);
    let (code, v) = call_json(port, "POST", &format!("/api/users/{dan}/erase"), &admin, "{}").await;
    assert_eq!(code, 200, "{v}");
    assert!(app.db.residency_pin(PinOn::User, &dan).is_none());
    assert_eq!(app.db.setting(&egress), None);
    let reference = app.db.residency_pin(PinOn::Team, &beta).unwrap().reference;
    assert!(reference.starts_with("MSA-8, signed by ") && !reference.contains("dan@example.com"), "{reference}");
}

#[tokio::test]
async fn someone_leaving_a_pinned_team_keeps_its_pin_unless_they_are_erased() {
    let (port, app, admin) = linode().await;
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, bea_s) = user_with(port, &admin, "bea@example.com", "member").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    let (code, t) = call_json(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    for u in [&bea, &cy] {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{u}"), &admin, "{}").await.0, 200);
    }
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), &admin, &pin("gb-lon", "MSA-7")).await.0, 200);
    assert_eq!(app.db.user(&bea).unwrap().region, None, "held by the team's region while on it");

    // Taken off the team: its pin stays on her data as her own, audited.
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{team}/members/{bea}"), &admin, "").await.0, 200);
    let kept = audit(port, &admin, "user.residency_pin_kept").await;
    let d = &kept[0]["details"];
    assert_eq!((kept.len(), kept[0]["targetId"].as_str(), d["region"].as_str(), d["reference"].as_str()), (1, Some(bea.as_str()), Some("gb-lon"), Some("MSA-7")), "{kept:?}");
    assert_eq!((d["team"].as_str(), d["teamName"].as_str(), d["reason"].as_str()), (Some(team.as_str()), Some("Acme"), Some("removed")), "{d}");
    let (_, u) = call_json(port, "GET", &format!("/api/users/{bea}"), &admin, "").await;
    assert_eq!((u["residency"]["subjectType"].as_str(), u["residency"]["region"].as_str(), u["residency"]["keptFrom"].as_str()), (Some("user"), Some("gb-lon"), Some(team.as_str())), "{u}");
    assert_eq!(app.db.user(&bea).unwrap().region.as_deref(), Some("gb-lon"));
    assert_eq!(app.db.user_machine(&bea).unwrap().region, "gb-lon", "her suspended machine is still held");
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{bea}/region"), &admin, r#"{"region":"de-fra-2"}"#).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Their data is pinned to gb-lon (MSA-7)"), "{v}");
    let (_, r) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert_eq!(r["residency"]["startup"].as_str(), Some("warn"), "{r}");
    assert!(r["residency"]["pins"].as_array().unwrap().iter().any(|p| p["name"] == "bea" && p["keptFrom"] == team.as_str()), "{r}");

    // She sees her pin and where it came from, but not the team's agreement, which she
    // never managed; her report leaves it out too. An admin's has it.
    let (code, me) = call_json(port, "GET", "/api/me/residency", &bea_s, "").await;
    assert_eq!(code, 200, "{me}");
    assert_eq!((me["pin"]["on"].as_str(), me["pin"]["keptFrom"]["team"]["name"].as_str(), me["reports"].clone()), (Some("user"), Some("Acme"), json!(["user"])), "{me}");
    assert!(me["pin"].get("reference").is_none(), "{me}");
    let (code, r) = call_json(port, "GET", "/api/me/residency/report?on=user", &bea_s, "").await;
    assert_eq!(code, 200, "{r}");
    assert_eq!((r["pin"]["reference"].clone(), r["pin"]["keptFrom"]["name"].as_str()), (Value::Null, Some("Acme")), "{r}");
    let changes = r["activity"]["pinChanges"].as_array().unwrap();
    assert!(changes.iter().any(|c| c["action"] == "user.residency_pin_kept" && c["reference"].is_null()), "{r}");
    assert!(!r.to_string().contains("MSA-7"), "{r}");
    let (code, md) = call(port, "GET", "/api/me/residency/report?on=user&format=markdown", &bea_s, "").await;
    assert!(code == 200 && md.contains("kept from team Acme's pin when they left it") && !md.contains("MSA-7"), "{md}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{bea}/residency/report"), &admin, "").await;
    assert_eq!(r["pin"]["reference"].as_str(), Some("MSA-7"), "{r}");
    assert!(r["activity"]["pinChanges"].as_array().unwrap().iter().any(|c| c["action"] == "user.residency_pin_kept" && c["reference"] == "MSA-7"), "{r}");
    assert!(r["notCovered"][3].as_str().unwrap().contains("a pin of their own, kept from the team's"), "{r}");

    // An admin renewing it makes it hers, with its own agreement she sees.
    assert_eq!(call(port, "PUT", &format!("/api/users/{bea}/residency"), &admin, &pin("gb-lon", "DPA-bea")).await.0, 200);
    let (_, me) = call_json(port, "GET", "/api/me/residency", &bea_s, "").await;
    assert_eq!((me["pin"]["reference"].as_str(), me["pin"].get("keptFrom")), (Some("DPA-bea"), None), "{me}");
    // Her report's history still never shows the team's agreement; an admin's does.
    for format in ["json", "markdown"] {
        let (code, r) = call(port, "GET", &format!("/api/me/residency/report?on=user&format={format}"), &bea_s, "").await;
        assert!(code == 200 && r.contains("DPA-bea") && r.contains("user.residency_pin_kept") && !r.contains("MSA-7"), "{format}: {r}");
    }
    let (_, r) = call_json(port, "GET", &format!("/api/users/{bea}/residency/report"), &admin, "").await;
    assert!(r["activity"]["pinChanges"].as_array().unwrap().iter().any(|c| c["action"] == "user.residency_pin_kept" && c["reference"] == "MSA-7"), "{r}");

    // Someone being erased keeps nothing: their pin would go with them.
    let (code, v) = call_json(port, "POST", &format!("/api/users/{cy}/erase"), &admin, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 200, "{v}");
    assert!(app.db.residency_pin(PinOn::User, &cy).is_none());
    assert_eq!(audit(port, &admin, "user.residency_pin_kept").await.len(), 1);

    // The last member leaving deletes the team and its pin, and keeps it on her data.
    let (code, v) = call_json(port, "POST", "/api/team/leave", &ada_s, "").await;
    assert_eq!(code, 200, "{v}");
    assert!(app.db.team(&team).is_none() && app.db.residency_pin(PinOn::Team, &team).is_none());
    let p = app.db.residency_pin(PinOn::User, &ada).unwrap();
    assert_eq!((p.region.as_str(), p.reference.as_str(), p.kept_from.as_deref()), ("gb-lon", "MSA-7", Some(team.as_str())));
    let kept = audit(port, &admin, "user.residency_pin_kept").await;
    assert_eq!((kept.len(), kept[0]["targetId"].as_str(), kept[0]["details"]["reason"].as_str()), (2, Some(ada.as_str()), Some("left")), "{kept:?}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!((me["pin"]["keptFrom"]["team"]["id"].as_str(), me["pin"]["keptFrom"]["team"]["name"].clone()), (Some(team.as_str()), Value::Null), "the team is gone: {me}");
}

async fn reconcile_as(port: u16, admin: &str) -> Value {
    let (code, r) = call_json(port, "POST", "/api/machines/reconcile", admin, "").await;
    assert_eq!(code, 200, "{r}");
    r
}

/// Bea, taken off team Acme after it was pinned to London (MSA-7), keeping its pin, with
/// her machine still there. Her id, session and the team's id.
async fn bea_kept_acmes_pin(port: u16, admin: &str) -> (String, String, String) {
    user_with(port, admin, "ada@example.com", "member").await;
    let (bea, bea_s) = user_with(port, admin, "bea@example.com", "member").await;
    let (code, t) = call_json(port, "POST", "/api/teams", admin, &json!({ "name": "Acme", "owner": "ada@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), admin, "{}").await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), admin, &pin("gb-lon", "MSA-7")).await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{team}/members/{bea}"), admin, "").await.0, 200);
    (bea, bea_s, team)
}

#[tokio::test]
async fn a_kept_pin_ends_by_itself_once_the_leavers_machine_is_gone() {
    use crate::machines::residency::KEPT_PIN_ENDED;
    let (port, app, admin) = linode().await;
    let (bea, bea_s, team) = bea_kept_acmes_pin(port, &admin).await;

    // Her machine is still there: the pin holds it, and she's told it ends once it's gone.
    let r = reconcile_as(port, &admin).await;
    assert!(r.get("keptPinsEnded").is_none(), "{r}");
    assert!(app.db.user_machine(&bea).is_some() && app.db.residency_pin(PinOn::User, &bea).is_some());
    let (_, me) = call_json(port, "GET", "/api/me/residency", &bea_s, "").await;
    assert_eq!(me["pin"]["keptFrom"]["endsWhenDataGone"].as_bool(), Some(true), "{me}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert_eq!(regions["residency"]["keptPins"].as_str(), Some("end"), "{regions}");

    // Destroyed: the next pass ends it, audited by botd itself, and her region stays.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{bea}/machine"), &admin, "").await.0, 200);
    let r = reconcile_as(port, &admin).await;
    assert_eq!(r["keptPinsEnded"].as_u64(), Some(1), "{r}");
    let ended = audit(port, &admin, KEPT_PIN_ENDED).await;
    let d = &ended[0]["details"];
    assert_eq!((ended.len(), ended[0]["targetId"].as_str(), ended[0]["actorKind"].as_str(), ended[0]["actorId"].as_str()), (1, Some(bea.as_str()), Some("system"), Some("residency")), "{ended:?}");
    assert_eq!((d["reason"].as_str(), d["region"].as_str(), d["reference"].as_str(), d["keptFrom"].as_str(), d["teamName"].as_str()), (Some("data_gone"), Some("gb-lon"), Some("MSA-7"), Some(team.as_str()), Some("Acme")), "{d}");
    assert!(app.db.residency_pin(PinOn::User, &bea).is_none());
    assert_eq!(app.db.user(&bea).unwrap().region.as_deref(), Some("gb-lon"));
    let (_, me) = call_json(port, "GET", "/api/me/residency", &bea_s, "").await;
    assert_eq!(me["pin"], Value::Null, "{me}");
    reconcile_as(port, &admin).await;
    assert_eq!(audit(port, &admin, KEPT_PIN_ENDED).await.len(), 1, "once");
    // Nothing holds her region now.
    assert_eq!(call(port, "PUT", &format!("/api/users/{bea}/region"), &admin, r#"{"region":"de-fra-2"}"#).await.0, 200);

    // A later pin of her own: her report lists the end without the team's agreement; an admin's has it.
    assert_eq!(call(port, "PUT", &format!("/api/users/{bea}/residency"), &admin, &pin("de-fra-2", "DPA-bea")).await.0, 200);
    for format in ["json", "markdown"] {
        let (code, r) = call(port, "GET", &format!("/api/me/residency/report?on=user&format={format}"), &bea_s, "").await;
        assert!(code == 200 && r.contains(KEPT_PIN_ENDED) && r.contains("DPA-bea") && !r.contains("MSA-7"), "{format}: {r}");
    }
    let (_, r) = call_json(port, "GET", &format!("/api/users/{bea}/residency/report"), &admin, "").await;
    assert!(r["activity"]["pinChanges"].as_array().unwrap().iter().any(|c| c["action"] == KEPT_PIN_ENDED && c["reference"] == "MSA-7" && c["reason"] == "data_gone"), "{r}");
    // An ordinary pin never ends by itself, with no machine data either.
    reconcile_as(port, &admin).await;
    assert_eq!(app.db.residency_pin(PinOn::User, &bea).unwrap().reference, "DPA-bea");
}

#[tokio::test]
async fn with_residency_kept_pins_keep_a_leavers_pin_stays_until_unpinned() {
    use crate::machines::residency::{KEPT_PIN_ENDED, KeptPins};
    let (port, app, admin, _) = linode_set(|cp| cp.kept_pins = KeptPins::Keep).await;
    let (bea, bea_s, _) = bea_kept_acmes_pin(port, &admin).await;
    let (_, me) = call_json(port, "GET", "/api/me/residency", &bea_s, "").await;
    assert_eq!(me["pin"]["keptFrom"]["endsWhenDataGone"].as_bool(), Some(false), "{me}");

    assert_eq!(call(port, "DELETE", &format!("/api/users/{bea}/machine"), &admin, "").await.0, 200);
    let r = reconcile_as(port, &admin).await;
    assert!(r.get("keptPinsEnded").is_none(), "{r}");
    assert!(app.db.residency_pin(PinOn::User, &bea).is_some() && audit(port, &admin, KEPT_PIN_ENDED).await.is_empty());
    // Admins are told it holds nothing now.
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert_eq!(regions["residency"]["keptPins"].as_str(), Some("keep"), "{regions}");
    let w = regions["residency"]["warnings"].to_string();
    assert!(w.contains("User bea is pinned to gb-lon (MSA-7), kept from their former team's pin, and botd holds none of their machine data") && w.contains("RESIDENCY_KEPT_PINS=keep"), "{regions}");
    assert_eq!(call(port, "DELETE", &format!("/api/users/{bea}/residency"), &admin, r#"{"reason":"left Acme; nothing left"}"#).await.0, 200);
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(!regions["residency"]["warnings"].to_string().contains("RESIDENCY_KEPT_PINS"), "{regions}");
}

#[tokio::test]
async fn a_kept_pin_waits_for_the_leavers_backups_to_be_deleted() {
    use crate::machines::residency::KEPT_PIN_ENDED;
    let env = incus(true).await;
    let (bea, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let m = machine_for(&env, &env.a, "a", &bea, true).await;
    back_up(&env, &bea).await;
    let t = env.app.db.create_team("Acme", None);
    assert!(env.app.db.add_team_member(&t.id, &bea, "member", None));
    env.app.db.pin_residency(PinOn::Team, &t.id, "gb-lon", "MSA-7", None).unwrap();
    assert!(env.app.db.remove_team_member_keeping_pin(&t.id, &bea, false, true).unwrap().1.is_some());

    // Her machine is destroyed, but its backup is still in London's store: still held.
    assert_eq!(json_call(&env, "DELETE", &format!("/api/users/{bea}/machine"), "").await.0, 200);
    reconcile(&env).await;
    assert!(env.app.db.user_machine(&bea).is_none());
    assert!(env.app.db.residency_pin(PinOn::User, &bea).is_some() && events(&env, KEPT_PIN_ENDED).await.is_empty());

    // Once its backups are deleted, it ends.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/machines/{}/backups", m.id), "").await;
    assert_eq!(code, 200, "{v}");
    let r = reconcile(&env).await;
    assert_eq!(r["keptPinsEnded"].as_u64(), Some(1), "{r}");
    assert!(env.app.db.residency_pin(PinOn::User, &bea).is_none());
    assert_eq!(events(&env, KEPT_PIN_ENDED).await[0]["details"]["keptFrom"].as_str(), Some(t.id.as_str()));
}

#[tokio::test]
async fn with_residency_startup_refuse_botd_wont_start_while_a_pin_cant_be_kept() {
    use crate::machines::residency::{Startup, at_startup};
    let env = incus(false).await;
    let (fra, _) = user_with(env.port, &env.admin, "fra@example.com", "member").await;
    let (lon, _) = user_with(env.port, &env.admin, "lon@example.com", "member").await;
    machine_for(&env, &env.a, "a", &lon, false).await;
    // London has a store and her machine is there: a pin it keeps. Her open plan has no
    // model route held there, but runs are refused one by one, so that doesn't stop botd.
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{lon}/residency"), &pin("gb-lon", "DPA-lon")).await.0, 200);
    let w = at_startup(&env.app, &env.cp, Startup::Refuse).unwrap();
    assert!(w.len() == 1 && w[0].contains("User lon") && w[0].contains("ADR 0139"), "{w:?}");

    // Frankfurt has no backup store, and fra was pinned there before it went.
    assert_eq!(json_call(&env, "PUT", &format!("/api/users/{fra}/region"), r#"{"region":"de-fra-2"}"#).await.0, 200);
    machine_for(&env, &env.b, "b", &fra, true).await;
    env.app.db.pin_residency(PinOn::User, &fra, "de-fra-2", "DPA-fra", None).unwrap();
    let w = at_startup(&env.app, &env.cp, Startup::Warn).unwrap();
    assert!(w.iter().any(|w| w.contains("User fra is pinned to de-fra-2 (DPA-fra), but machine backups have no store in de-fra-2")), "{w:?}");
    assert!(events(&env, "residency.startup_refused").await.is_empty(), "warn only warns");

    let e = at_startup(&env.app, &env.cp, Startup::Refuse).unwrap_err();
    assert!(e.starts_with("RESIDENCY_STARTUP=refuse, and this server can't keep 1 residency pin: User fra is pinned to de-fra-2"), "{e}");
    assert!(e.contains("RESIDENCY_STARTUP=warn to unpin with a reason") && !e.contains("User lon"), "{e}");
    let refused = events(&env, "residency.startup_refused").await;
    assert_eq!((refused.len(), refused[0]["outcome"].as_str(), refused[0]["actorKind"].as_str()), (1, Some("denied"), Some("system")), "{refused:?}");
    let d = &refused[0]["details"];
    assert_eq!((d["policy"].as_str(), d["pins"].as_array().map(Vec::len), d["pins"][0]["subjectId"].as_str(), d["pins"][0]["reference"].as_str()), (Some("refuse"), Some(1), Some(fra.as_str()), Some("DPA-fra")), "{d}");
    assert!(d["pins"][0]["error"].as_str().unwrap().contains("no store in de-fra-2"), "{d}");

    // Unpinned with a reason (started with warn to do it), it starts again.
    assert_eq!(json_call(&env, "DELETE", &format!("/api/users/{fra}/residency"), r#"{"reason":"store retired; customer told"}"#).await.0, 200);
    assert!(at_startup(&env.app, &env.cp, Startup::Refuse).is_ok());
}

#[tokio::test]
async fn reports_and_the_app_say_whether_botds_own_data_is_in_a_pins_region() {
    let (port, app, admin, _) = linode_with(in_london(ServerDataPolicy::Report)).await;
    let (lon, lon_s) = user_with(port, &admin, "lon@example.com", "member").await;
    let (fra, fra_s) = user_with(port, &admin, "fra@example.com", "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/users/{lon}/residency"), &admin, &pin("gb-lon", "DPA-lon")).await.0, 200);
    // `report` only shows where botd's own data is: a pin elsewhere is still made.
    assert_eq!(call(port, "PUT", &format!("/api/users/{fra}/residency"), &admin, &pin("de-fra-2", "DPA-fra")).await.0, 200);

    let (code, r) = call_json(port, "GET", &format!("/api/users/{lon}/residency/report"), &admin, "").await;
    assert_eq!(code, 200, "{r}");
    let s = &r["serverData"];
    assert_eq!((s["region"].as_str(), s["inRegion"].as_bool(), s["backups"]["offHost"].as_bool(), s["policy"].as_str()), (Some("gb-lon"), Some(true), Some(false), Some("report")), "{r}");
    assert!(!r["notCovered"].to_string().contains("botd's own database"), "covered once botd's data is stated to be in the region: {r}");
    assert_eq!(r["digest"].as_str(), Some(crate::machines::residency_report::digest(&r).as_str()), "the digest covers it");
    let (_, md) = call(port, "GET", &format!("/api/users/{lon}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("## botd's own data") && md.contains("- **Region:** gb-lon (as the operator states it)") && md.contains("- **In the pinned region:** yes"), "{md}");
    assert!(md.contains("shown, not enforced (RESIDENCY_SERVER_DATA=report)"), "{md}");

    let (_, r) = call_json(port, "GET", &format!("/api/users/{fra}/residency/report"), &admin, "").await;
    assert_eq!((r["serverData"]["inRegion"].as_bool(), r["status"].as_str()), (Some(false), Some("kept")), "report mode never makes a pin unkept: {r}");
    assert_eq!(r["serverData"]["outside"], json!(["botd's own database and files are in gb-lon"]), "{r}");
    assert!(r["notCovered"][0].as_str().unwrap().contains("which are where the operator runs botd: botd's own database and files are in gb-lon (ADR 0129, ADR 0184)"), "{r}");

    // People see it in the app.
    let (_, me) = call_json(port, "GET", "/api/me/residency", &lon_s, "").await;
    assert_eq!(me["serverData"], json!({ "region": "gb-lon", "inRegion": true, "backupsInRegion": true, "required": false }), "{me}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &fra_s, "").await;
    assert_eq!(me["serverData"], json!({ "region": "gb-lon", "inRegion": false, "backupsInRegion": true, "required": false }), "{me}");
    assert_eq!(me["status"].as_str(), Some("kept"), "report mode: {me}");

    // A copy made to a store botd no longer copies to is a warning: botd can't say where it is.
    let n = crate::db::NewServerBackup { id: "sb-old", archive: "superbot-20261101-031500.tar.gz.age", destination: "https://old-s3/b/server/", object_key: "server/a", created_at: 1, encrypted_by: Some("archive") };
    app.db.server_backup_start(&n).unwrap();
    assert!(app.db.server_backup_end("sb-old", Some((10, "abc", None)), None));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{lon}/residency/report"), &admin, "").await;
    assert_eq!((r["serverData"]["earlierCopies"].as_i64(), r["serverData"]["inRegion"].as_bool()), (Some(1), Some(true)), "{r}");
    assert!(r["warnings"].to_string().contains("1 server backup copies were made to a store botd no longer copies to"), "{r}");
    assert!(!r["warnings"].to_string().contains("old-s3"), "the store's address isn't shown: {r}");

    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let s = &regions["residency"]["serverData"];
    assert_eq!((s["region"].as_str(), s["policy"].as_str(), s["earlierCopies"].as_i64()), (Some("gb-lon"), Some("report"), Some(1)), "{regions}");
    let w = regions["residency"]["warnings"].to_string();
    assert!(!w.contains("botd's own database"), "report mode adds no warnings about botd's data region: {regions}");
    assert!(w.contains("fra's Bots run on botd's own server, and botd's own server is in gb-lon"), "runs are still held to the pin's region (ADR 0267): {regions}");
    assert!(w.contains("1 server backup copies were made to a store botd no longer copies to") && !w.contains("old-s3"), "{regions}");
}

#[tokio::test]
async fn with_residency_server_data_require_every_pin_is_held_to_botds_own_region() {
    use crate::machines::residency::{Startup, at_startup};
    let (port, app, admin, cp) = linode_with(in_london(ServerDataPolicy::Require)).await;
    let (fra, fra_s) = user_with(port, &admin, "fra@example.com", "member").await;
    user_with(port, &admin, "lon@example.com", "member").await;

    // A user or team pinned elsewhere is refused and audited.
    let (code, v) = call_json(port, "PUT", &format!("/api/users/{fra}/residency"), &admin, &pin("de-fra-2", "DPA-fra")).await;
    assert_eq!(code, 409, "{v}");
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("de-fra-2 can't hold pinned data on this server: botd's own database and files are in gb-lon") && e.contains("RESIDENCY_SERVER_DATA=require"), "{e}");
    let refused = audit(port, &admin, "user.residency_pin_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["targetId"].as_str()), (Some("server_data_outside"), Some(fra.as_str())), "{refused:?}");
    assert!(app.db.residency_pin(PinOn::User, &fra).is_none());
    let (code, t) = call_json(port, "POST", "/api/teams", &admin, &json!({ "name": "Acme", "owner": "lon@example.com" }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), &admin, &pin("de-fra-2", "MSA-7")).await.0, 409);
    assert_eq!(audit(port, &admin, "team.residency_pin_refused").await[0]["details"]["reason"].as_str(), Some("server_data_outside"));

    // In botd's own region, pins are made, and botd starts.
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/residency"), &admin, &pin("gb-lon", "MSA-7")).await.0, 200);
    let (_, r) = call_json(port, "GET", &format!("/api/teams/{team}/residency/report"), &admin, "").await;
    assert_eq!((r["status"].as_str(), r["serverData"]["inRegion"].as_bool(), r["serverData"]["policy"].as_str()), (Some("kept"), Some(true), Some("require")), "{r}");
    assert!(at_startup(&app, &cp, Startup::Refuse).is_ok());

    // A pin made elsewhere before `require` (or before botd's region changed) can't be kept.
    app.db.pin_residency(PinOn::User, &fra, "de-fra-2", "DPA-fra", None).unwrap();
    let w = at_startup(&app, &cp, Startup::Warn).unwrap();
    assert!(w.iter().any(|w| w.contains("User fra is pinned to de-fra-2 (DPA-fra), but botd's own database and files are in gb-lon")), "{w:?}");
    let e = at_startup(&app, &cp, Startup::Refuse).unwrap_err();
    assert!(e.contains("can't keep 1 residency pin: User fra") && e.contains("server data region"), "{e}");
    let refused = audit(port, &admin, "residency.startup_refused").await;
    assert!(refused[0]["details"]["pins"][0]["error"].as_str().unwrap().contains("botd's own database and files are in gb-lon"), "{refused:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{fra}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("botd: botd's own database and files are in gb-lon (RESIDENCY_SERVER_DATA=require, ADR 0184)"), "{r}");
    let (_, md) = call(port, "GET", &format!("/api/users/{fra}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **In the pinned region:** no") && md.contains("- Outside: botd's own database and files are in gb-lon"), "{md}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &fra_s, "").await;
    assert_eq!((me["status"].as_str(), me["serverData"]["required"].as_bool(), me["serverData"]["inRegion"].as_bool()), (Some("data_outside"), Some(true), Some(false)), "the app sees what the report does: {me}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(regions["residency"]["warnings"].to_string().contains("botd's own database and files are in gb-lon"), "{regions}");
}

#[tokio::test]
async fn a_pinned_persons_chats_are_kept_in_their_regions_chat_store_and_come_back_when_unpinned() {
    use crate::machines::chat_stores::{self, MOVED, Settings};
    let scratch = crate::db::Scratch::new();
    let (lon, fra) = (scratch.path().join("lon"), scratch.path().join("fra"));
    std::fs::create_dir_all(&lon).unwrap();
    std::fs::create_dir_all(&fra).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone()), ("de-fra-2".into(), fra.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    let opened =
        chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (lines, rekeyed) = (opened.lines, opened.rekeyed);
    assert_eq!(rekeyed, 0);
    assert!(lines.iter().any(|l| l.contains("made gb-lon's store")) && lines.iter().any(|l| l.contains("made de-fra-2's store")), "{lines:?}");
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private).id;
    for text in ["hello", "a contract draft"] {
        app.db.add_message(&bot, "user", text, None, false, None);
    }
    let count = |dir: &std::path::Path| rusqlite::Connection::open(dir.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap();
    let in_store = || count(&lon);
    assert_eq!(in_store(), 0, "unpinned: chats stay in botd's own database");

    // A pin moves her chats into London's store, audited; reads see them as before.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!(in_store(), 2);
    assert_eq!(app.db.messages(&bot, 10).len(), 2);
    let moved = audit(port, &admin, MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["messages"].as_i64(), moved[0]["actorId"].as_str()), (Some("gb-lon"), Some(2), Some("residency")), "{moved:?}");
    // New messages go straight there.
    app.db.add_message(&bot, "assistant", "noted", None, false, None);
    assert_eq!(in_store(), 3);

    // The report, the app and the regions page say so.
    let (code, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(code, 200, "{r}");
    let c = &r["chats"];
    assert_eq!((c["store"].as_bool(), c["inRegion"].as_bool(), c["messages"]["inStore"].as_i64(), c["messages"]["inServerDatabase"].as_i64()), (Some(true), Some(true), Some(3), Some(0)), "{r}");
    assert!(r["notCovered"][0].as_str().unwrap().starts_with("botd's own database apart from chats"), "{r}");
    assert!(r["warnings"].to_string().contains("gb-lon's chat store has no backup from the last day"), "{r}");
    assert_eq!(r["digest"].as_str(), Some(crate::machines::residency_report::digest(&r).as_str()), "the digest covers it");
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("## Chats") && md.contains("- **Messages in it:** 3"), "{md}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"], json!({ "store": true, "inRegion": true, "moving": false, "earlierBackups": 0, "signIns": true, "secrets": true, "secondFactors": true, "usageRecords": true }), "{me}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let lon_row = regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == "gb-lon").unwrap();
    assert_eq!(lon_row["chatStore"]["messages"].as_i64(), Some(3), "{regions}");
    assert_eq!(regions["residency"]["chatStores"]["stores"][0]["region"].as_str(), Some("gb-lon"), "{regions}");

    // A backup is made in the region's folder, not with server backups.
    let at = crate::db::now();
    let done = chat_stores::backup_pass(&app.db, 7, at);
    let path = done[0].1.as_ref().unwrap();
    assert!(path.starts_with(lon.join("backups")), "{path:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["chats"]["lastBackupAt"].as_i64().map(|t| t / 1000), Some(at / 1000), "{r}");
    assert!(!r["warnings"].to_string().contains("chat store"), "{r}");

    // A message left out of the store (a move that failed) makes the pin unkept until the
    // next pass moves it.
    let stray = app.db.messages(&bot, 1)[0].id;
    app.db
        .conn_for_tests()
        .execute_batch(&format!("INSERT INTO main.messages SELECT * FROM chats_0.messages WHERE id = {stray}; DELETE FROM chats_0.messages WHERE id = {stray};"))
        .unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their Bots have 1 chat message in botd's own database, not gb-lon's chat store"), "{r}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!((me["status"].as_str(), me["chats"]["inRegion"].as_bool(), me["chats"]["moving"].as_bool()), (Some("data_outside"), Some(false), Some(true)), "{me}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(regions["residency"]["warnings"].to_string().contains("not gb-lon's chat store"), "{regions}");
    assert_eq!(reconcile_as(port, &admin).await["chatsMoved"].as_i64(), Some(1));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("kept"), "{r}");

    // Unpinned, they come back.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!(in_store(), 0);
    assert_eq!(app.db.messages(&bot, 10).len(), 3);

    // Pinned to Frankfurt, they go to its store, but London's backup from before still
    // holds them: the report says so and doesn't claim them all in the region.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("de-fra-2", "DPA-2")).await.0, 200);
    assert_eq!((in_store(), count(&fra)), (0, 3));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    let c = &r["chats"];
    assert_eq!((c["inRegion"].as_bool(), c["earlierCopies"][0]["region"].as_str(), c["earlierCopies"][0]["backups"].as_i64()), (Some(false), Some("gb-lon"), Some(1)), "{r}");
    assert!(r["warnings"].to_string().contains("1 backups of gb-lon's chat store were made before their chats, routines or approvals moved out of it"), "{r}");
    assert!(r["notCovered"][0].as_str().unwrap().starts_with("botd's own database (accounts, chats,"), "{r}");
    assert_eq!(r["status"].as_str(), Some("kept"), "old backups are disclosed, not unkept: {r}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(
        me["chats"],
        json!({ "store": true, "inRegion": false, "moving": false, "earlierBackups": 1, "signIns": true, "secrets": true, "secondFactors": true, "usageRecords": true }),
        "the move is done; only old backups are left: {me}"
    );

    // Left there for hours (a check that keeps failing), admins are warned.
    app.db.conn_for_tests().execute("UPDATE main.chat_moves_out SET moved_at = moved_at - 4 * 3600000 WHERE region = 'gb-lon'", []).unwrap();
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(regions["residency"]["warnings"].to_string().contains("gb-lon's chat store's backups may still hold the rows of 1 Bot that left it"), "{regions}");

    // The next check takes them out of London's backup, which stays a restore point; the
    // report, the app and the audit log say so (ADR 0238).
    let cleared = chat_stores::clear_pass(&app.db, crate::db::now());
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    let done = cleared[0].1.as_ref().unwrap();
    assert_eq!((cleared[0].0.as_str(), done.backups, done.held.messages), ("gb-lon", 1, 3), "{cleared:?}");
    let old = rusqlite::Connection::open(path).unwrap();
    assert_eq!(old.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    assert_eq!(old.query_row("SELECT region FROM chat_store", [], |r| r.get::<_, String>(0)).unwrap(), "gb-lon");
    let entry = audit(port, &admin, chat_stores::CLEARED).await;
    assert_eq!((entry[0]["details"]["region"].as_str(), entry[0]["details"]["backups"].as_i64(), entry[0]["details"]["messages"].as_i64(), entry[0]["actorId"].as_str()), (Some("gb-lon"), Some(1), Some(3), Some("residency")), "{entry:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["chats"]["inRegion"].as_bool(), r["chats"]["earlierCopies"].as_array().map(Vec::len)), (Some(true), Some(0)), "{r}");
    assert!(!r["warnings"].to_string().contains("backups of gb-lon's chat store"), "{r}");
    assert_eq!(r["digest"].as_str(), Some(crate::machines::residency_report::digest(&r).as_str()));
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"], json!({ "store": true, "inRegion": true, "moving": false, "earlierBackups": 0, "signIns": true, "secrets": true, "secondFactors": true, "usageRecords": true }), "{me}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(!regions["residency"]["warnings"].to_string().contains("may still hold the rows"), "{regions}");
}

#[tokio::test]
async fn a_pinned_persons_routines_and_approvals_are_kept_with_their_chats() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private).id;
    let body = r#"{"name":"Standup","cron":"0 9 * * 1-5","instruction":"summarise the contract"}"#;
    let (code, r) = call_json(port, "POST", &format!("/api/bots/{bot}/routines"), &ada_s, body).await;
    assert_eq!(code, 201, "{r}");
    let asked = |subject: &str| app.db.add_approval(&bot, "claude", "Bash", "command", subject, &json!({ "command": subject }), "risky", "asks", crate::db::now() + 3_600_000).id;
    let first = asked("git push origin main");
    let count = |table: &str| rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!((count("routines"), count("approvals")), (0, 0), "unpinned: they stay in botd's own database");

    // A pin moves them with her chats, audited; new ones go straight there.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!((count("routines"), count("approvals")), (1, 1));
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["routines"].as_i64(), moved[0]["details"]["approvals"].as_i64()), (Some(1), Some(1)), "{moved:?}");
    let second = asked("rm -rf build");
    assert_eq!(count("approvals"), 2);

    // Everything that reads or changes them works as before.
    let (code, routines) = call_json(port, "GET", &format!("/api/bots/{bot}/routines"), &ada_s, "").await;
    assert_eq!((code, routines.as_array().map(Vec::len)), (200, Some(1)), "{routines}");
    let rid = routines[0]["id"].as_str().unwrap();
    assert_eq!(call(port, "PATCH", &format!("/api/routines/{rid}"), &ada_s, r#"{"enabled":false}"#).await.0, 200);
    let (_, routines) = call_json(port, "GET", &format!("/api/bots/{bot}/routines"), &ada_s, "").await;
    assert_eq!(routines[0]["enabled"].as_bool(), Some(false), "{routines}");
    let (_, list) = call_json(port, "GET", "/api/approvals", &admin, "").await;
    let ids: Vec<&str> = list.as_array().unwrap().iter().filter_map(|a| a["id"].as_str()).collect();
    assert_eq!(ids, [second.as_str(), first.as_str()], "newest first: {list}");
    let (code, done) = call_json(port, "POST", &format!("/api/approvals/{first}/approve"), &admin, r#"{"remember":"bot"}"#).await;
    assert_eq!(code, 200, "{done}");
    assert_eq!(app.db.approval(&first).unwrap().status, "approved");
    assert_eq!(app.db.approval(&second).unwrap().input, json!({ "command": "rm -rf build" }), "its sealed input opens where it is kept");

    // The report, the app and the regions page count them.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    let c = &r["chats"];
    assert_eq!((c["inRegion"].as_bool(), c["routines"]["inStore"].as_i64(), c["approvals"]["inStore"].as_i64(), c["approvals"]["inServerDatabase"].as_i64()), (Some(true), Some(1), Some(2), Some(0)), "{r}");
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("## Chats, routines, approvals and memory") && md.contains("- **Routines in it:** 1") && md.contains("- **Approvals in it:** 2"), "{md}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let lon_row = regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == "gb-lon").unwrap();
    assert_eq!((lon_row["chatStore"]["routines"].as_i64(), lon_row["chatStore"]["approvals"].as_i64()), (Some(1), Some(2)), "{regions}");

    // A routine and an approval left out of the store make the pin unkept until reconcile moves them.
    app.db
        .conn_for_tests()
        .execute_batch(&format!(
            "INSERT INTO main.routines SELECT * FROM chats_0.routines; DELETE FROM chats_0.routines; \
             INSERT INTO main.approvals SELECT * FROM chats_0.approvals WHERE id = '{second}'; DELETE FROM chats_0.approvals WHERE id = '{second}';"
        ))
        .unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their Bots have 1 routine and 1 approval in botd's own database, not gb-lon's chat store"), "{r}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"]["moving"].as_bool(), Some(true), "{me}");
    let done = reconcile_as(port, &admin).await;
    assert_eq!((done["routinesMoved"].as_i64(), done["approvalsMoved"].as_i64()), (Some(1), Some(1)), "{done}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("kept"), "{r}");

    // Unpinned, they come back.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!((count("routines"), count("approvals")), (0, 0));
    assert_eq!(app.db.routines(Some(&bot)).len(), 1);
    assert_eq!(app.db.approval(&second).unwrap().input, json!({ "command": "rm -rf build" }));
}

#[tokio::test]
async fn a_pinned_persons_bots_memory_is_kept_in_their_regions_chat_store_not_in_data_dir() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private).id;
    let file = app.data_memory_file(&bot).unwrap();
    let word = "memory-1f9a3c-the-client-plan";
    app.keep_memory_text(&bot, word).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), word, "unpinned: kept in its file in DATA_DIR");
    let count = || rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM memories", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(count(), 0);

    // A pin moves it into London's store and deletes its file, audited.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!((count(), file.exists()), (1, false));
    assert_eq!(app.kept_memory(&bot).as_deref(), Some(word));
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["memories"].as_i64()), (Some("gb-lon"), Some(1)), "{moved:?}");
    // Saved there from now on: what a run sends back never lands in DATA_DIR.
    app.keep_memory_text(&bot, "learned on the machine").unwrap();
    assert_eq!((count(), file.exists(), app.kept_memory(&bot).as_deref()), (1, false, Some("learned on the machine")));

    // The report, the app and the regions page count it.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    let c = &r["chats"];
    assert_eq!((c["inRegion"].as_bool(), c["memories"]["inStore"].as_i64(), c["memories"]["inServerDatabase"].as_i64()), (Some(true), Some(1), Some(0)), "{r}");
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Bots' memory in it:** 1"), "{md}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let lon_row = regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == "gb-lon").unwrap();
    assert_eq!(lon_row["chatStore"]["memories"].as_i64(), Some(1), "{regions}");

    // A memory file left in DATA_DIR makes the pin unkept until reconcile deletes it; the
    // store's copy is the newer one.
    std::fs::write(&file, "stale").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their Bots have 1 Bot memory in botd's own database or its files, not gb-lon's chat store"), "{r}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"]["moving"].as_bool(), Some(true), "{me}");
    reconcile_as(port, &admin).await;
    assert_eq!((file.exists(), app.kept_memory(&bot).as_deref()), (false, Some("learned on the machine")));
    // A row left in botd's own table is moved by reconcile.
    app.db.conn_for_tests().execute_batch("INSERT INTO main.memories SELECT * FROM chats_0.memories; DELETE FROM chats_0.memories;").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert_eq!(reconcile_as(port, &admin).await["memoriesMoved"].as_i64(), Some(1));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("kept"), "{r}");

    // Unpinned, it is written back to its file.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!((count(), std::fs::read_to_string(&file).unwrap().as_str()), (0, "learned on the machine"));
    assert!(app.db.memory(&bot).is_none());

    // A run that saves after an unpin, before any pass moves the memory back, isn't
    // overwritten by the older copy in the store.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-2")).await.0, 200);
    assert_eq!((count(), file.exists()), (1, false));
    app.db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
    app.keep_memory_text(&bot, "saved after the unpin").unwrap();
    chat_stores::place(&app.db, &app.cfg.data_dir);
    assert_eq!((count(), std::fs::read_to_string(&file).unwrap().as_str()), (0, "saved after the unpin"));
    assert!(app.db.memory(&bot).is_none());

    // When that pass can't take it back to its file, the save goes to its row, never past it,
    // and a later pass writes it.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-3")).await.0, 200);
    app.db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
    std::fs::create_dir(&file).unwrap();
    app.keep_memory_text(&bot, "saved while the file was blocked").unwrap();
    assert_eq!(app.kept_memory(&bot).as_deref(), Some("saved while the file was blocked"));
    std::fs::remove_dir(&file).unwrap();
    chat_stores::place(&app.db, &app.cfg.data_dir);
    assert_eq!((app.db.memory(&bot), std::fs::read_to_string(&file).unwrap().as_str()), (None, "saved while the file was blocked"));
}

#[tokio::test]
async fn a_pinned_persons_facts_are_kept_in_their_regions_chat_store_not_in_data_dir() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private);
    let file = app.data_user_file(&ada).unwrap();
    let word = "facts-4b8e20-ada-works-from-leeds";
    app.keep_facts_text(&ada, word).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), word, "unpinned: kept in the file in DATA_DIR");
    let count = || rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM facts", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(count(), 0);

    // A pin moves them into London's store and deletes the file, audited.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!((count(), file.exists()), (1, false));
    assert_eq!(app.kept_facts(&ada).as_deref(), Some(word));
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["facts"].as_i64()), (Some("gb-lon"), Some(1)), "{moved:?}");
    // Saved there from now on, and a new Bot's first facts never land in DATA_DIR.
    app.keep_facts_text(&ada, "learned on the machine").unwrap();
    app.init_bot_files(&bot);
    assert_eq!((count(), file.exists(), app.kept_facts(&ada).as_deref()), (1, false, Some("learned on the machine")));

    // The report, the app and the regions page count them.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    let c = &r["chats"];
    assert_eq!((c["inRegion"].as_bool(), c["facts"]["inStore"].as_i64(), c["facts"]["inServerDatabase"].as_i64()), (Some(true), Some(1), Some(0)), "{r}");
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Owners' facts in it:** 1"), "{md}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let lon_row = regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == "gb-lon").unwrap();
    assert_eq!(lon_row["chatStore"]["facts"].as_i64(), Some(1), "{regions}");

    // A file left in DATA_DIR makes the pin unkept until reconcile deletes it; the store's
    // copy is the newer one.
    std::fs::write(&file, "stale").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their facts are in botd's own database or its files, not gb-lon's chat store"), "{r}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"]["moving"].as_bool(), Some(true), "{me}");
    reconcile_as(port, &admin).await;
    assert_eq!((file.exists(), app.kept_facts(&ada).as_deref()), (false, Some("learned on the machine")));
    // A row left in botd's own table is moved by reconcile.
    app.db.conn_for_tests().execute_batch("INSERT INTO main.facts SELECT * FROM chats_0.facts; DELETE FROM chats_0.facts;").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert_eq!(reconcile_as(port, &admin).await["factsMoved"].as_i64(), Some(1));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("kept"), "{r}");

    // Unpinned, they are written back to the file.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!((count(), std::fs::read_to_string(&file).unwrap().as_str()), (0, "learned on the machine"));
    assert!(app.db.facts(&ada).is_none());

    // When a pass can't take them back to the file, a save goes to the row, never past it,
    // and a later pass writes it.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-2")).await.0, 200);
    app.db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
    std::fs::create_dir(&file).unwrap();
    app.keep_facts_text(&ada, "saved while the file was blocked").unwrap();
    assert_eq!(app.kept_facts(&ada).as_deref(), Some("saved while the file was blocked"));
    std::fs::remove_dir(&file).unwrap();
    chat_stores::place(&app.db, &app.cfg.data_dir);
    assert_eq!((app.db.facts(&ada), std::fs::read_to_string(&file).unwrap().as_str()), (None, "saved while the file was blocked"));

    // Erased while pinned, their facts leave the store and aren't written back.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-3")).await.0, 200);
    assert_eq!((count(), file.exists()), (1, false));
    let (status, erased) = call_json(port, "POST", &format!("/api/users/{ada}/erase"), &admin, "{}").await;
    assert_eq!(status, 200, "{erased}");
    reconcile_as(port, &admin).await;
    assert_eq!((count(), file.exists(), app.db.facts(&ada)), (0, false, None));
}

#[tokio::test]
async fn a_pinned_persons_sign_ins_are_kept_in_their_regions_chat_store() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let count = || rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(count(), 0, "unpinned: in botd's own database");

    // A pin moves her session into London's store, audited, and it still signs her in.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!(count(), 1);
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["sessions"].as_i64()), (Some("gb-lon"), Some(1)), "{moved:?}");
    let (_, hers) = call_json(port, "GET", &format!("/api/sessions?user={ada}"), &admin, "").await;
    assert_eq!(hers.as_array().map(Vec::len), Some(1), "{hers}");
    assert_eq!(call(port, "GET", "/api/me/residency", &ada_s, "").await.0, 200);
    // Signing in again lands there too.
    let again = crate::users_http_tests::signed_in(port, &admin, &ada).await.unwrap();
    assert_eq!(count(), 2);

    // The report counts them.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["status"].as_str(), r["chats"]["sessions"]["inStore"].as_i64(), r["chats"]["sessions"]["inServerDatabase"].as_i64()), (Some("kept"), Some(2), Some(0)), "{r}");
    assert!(
        r["notCovered"][0].as_str().unwrap().contains("owners' facts, sign-ins, own secrets, second factors and model usage records, which are in the region's chat store (accounts, the audit log"),
        "{r}"
    );
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Sign-in sessions in it:** 2"), "{md}");

    // One left in botd's own database makes the pin unkept until reconcile moves it.
    app.db.conn_for_tests().execute_batch("INSERT INTO main.sessions SELECT * FROM chats_0.sessions LIMIT 1; DELETE FROM chats_0.sessions WHERE id IN (SELECT id FROM main.sessions);").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("they have 1 sign-in session in botd's own database, not gb-lon's chat store (ADR 0283)"), "{r}");
    assert_eq!(reconcile_as(port, &admin).await["sessionsMoved"].as_i64(), Some(1));
    assert_eq!(count(), 2);

    // Revoked where it is kept: signing out ends it.
    assert_eq!(call(port, "POST", "/api/auth/logout", &again, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/me/residency", &again, "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/me/residency", &ada_s, "").await.0, 200, "her other session still works");
    let (_, hers) = call_json(port, "GET", &format!("/api/sessions?user={ada}"), &admin, "").await;
    assert_eq!(hers.as_array().map(Vec::len), Some(1), "{hers}");

    // Unpinned, they come back to botd's own database.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!(count(), 0);
    assert_eq!(call(port, "GET", "/api/me/residency", &ada_s, "").await.0, 200);
}

#[tokio::test]
async fn a_pinned_persons_own_secrets_are_kept_in_their_regions_chat_store() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let value = cipher.seal(&crate::secrets::sealed::user_context(&ada, "OPENAI_API_KEY"), b"sk-0293");
    app.db.conn_for_tests().execute("INSERT INTO main.user_secrets VALUES (?1, 'OPENAI_API_KEY', ?2, 1, 1)", [&ada, &value]).unwrap();
    let count = || rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM user_secrets", [], |r| r.get::<_, i64>(0)).unwrap();

    // A pin moves it into London's store, audited, and the report counts it there.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!(count(), 1);
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["personalKeys"].as_i64()), (Some("gb-lon"), Some(1)), "{moved:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["status"].as_str(), r["chats"]["personalKeys"]["inStore"].as_i64(), r["chats"]["personalKeys"]["inServerDatabase"].as_i64()), (Some("kept"), Some(1), Some(0)), "{r}");
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Personal secrets in it:** 1"), "{md}");

    // One left in botd's own database makes the pin unkept until reconcile moves it.
    app.db.conn_for_tests().execute_batch("INSERT INTO main.user_secrets SELECT * FROM chats_0.user_secrets; DELETE FROM chats_0.user_secrets;").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their own secrets are in botd's own database, not gb-lon's chat store (ADR 0293)"), "{r}");
    assert_eq!(reconcile_as(port, &admin).await["personalKeysMoved"].as_i64(), Some(1));
    assert_eq!(count(), 1);

    // Unpinned, it comes back to botd's own database.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!(count(), 0);
}

#[tokio::test]
async fn a_pinned_persons_second_factor_is_kept_in_their_regions_chat_store_and_still_signs_them_in() {
    use crate::machines::chat_stores::{self, Settings};
    use crate::mfa_http_tests::{code, enrol};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let (key, recovery) = enrol(port, &ada_s).await;
    let count =
        |table: &str| rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap();
    let in_main = |table: &str| app.db.conn_for_tests().query_row(&format!("SELECT COUNT(*) FROM main.{table}"), [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!((count("user_mfa"), in_main("user_mfa")), (0, 1), "unpinned: in botd's own database");

    // A pin moves it and its recovery codes into London's store, audited.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!((count("user_mfa"), count("mfa_recovery_codes"), in_main("user_mfa"), in_main("mfa_recovery_codes")), (1, 10, 0, 0));
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["secondFactors"].as_i64(), moved[0]["details"]["recoveryCodes"].as_i64()), (Some(1), Some(10)), "{moved:?}");
    let (_, view) = call_json(port, "GET", "/api/auth/mfa", &ada_s, "").await;
    assert_eq!((view["enabled"].as_bool(), view["recoveryCodesLeft"].as_i64()), (Some(true), Some(10)), "{view}");

    // Sign-in still asks for it and takes a code from it, and new recovery codes are written there.
    let (_, c) = call(port, "POST", &format!("/api/users/{ada}/login-codes"), &admin, "").await;
    let (_, res) = call_json(port, "POST", "/api/auth/login", "", &json!({ "code": parse(&c)["code"] }).to_string()).await;
    assert_eq!(res["mfa"].as_str(), Some("totp"), "{res}");
    let (status, res) = call_json(port, "POST", "/api/auth/login", "", &json!({ "challenge": res["challenge"], "totp": code(&key, 1) }).to_string()).await;
    assert_eq!((status, res["session"]["mfa"].as_str()), (200, Some("totp")), "{res}");
    let (status, res) = call_json(port, "POST", "/api/auth/mfa/recovery-codes", &ada_s, &json!({ "recoveryCode": recovery[0] }).to_string()).await;
    assert_eq!(status, 200, "{res}");
    assert_eq!((count("mfa_recovery_codes"), in_main("mfa_recovery_codes")), (10, 0));

    // The report counts them.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(
        (r["status"].as_str(), r["chats"]["secondFactors"]["inStore"].as_i64(), r["chats"]["secondFactors"]["inServerDatabase"].as_i64()),
        (Some("kept"), Some(1), Some(0)),
        "{r}"
    );
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Second factors in it:** 1") && md.contains("- **Recovery codes in it:** 10"), "{md}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"]["secondFactors"].as_bool(), Some(true), "{me}");

    // One left in botd's own database makes the pin unkept until reconcile moves it.
    app.db
        .conn_for_tests()
        .execute_batch(
            "INSERT INTO main.user_mfa SELECT * FROM chats_0.user_mfa; INSERT INTO main.mfa_recovery_codes SELECT * FROM chats_0.mfa_recovery_codes; \
             DELETE FROM chats_0.mfa_recovery_codes; DELETE FROM chats_0.user_mfa;",
        )
        .unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("their second factor is in botd's own database, not gb-lon's chat store (ADR 0299)"), "{r}");
    let done = reconcile_as(port, &admin).await;
    assert_eq!((done["secondFactorsMoved"].as_i64(), done["recoveryCodesMoved"].as_i64()), (Some(1), Some(10)), "{done}");
    assert_eq!((count("user_mfa"), in_main("user_mfa")), (1, 0));

    // Unpinned, it comes back to botd's own database.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!((count("user_mfa"), count("mfa_recovery_codes"), in_main("user_mfa"), in_main("mfa_recovery_codes")), (0, 0, 1, 10));
    let (_, view) = call_json(port, "GET", "/api/auth/mfa", &ada_s, "").await;
    assert_eq!(view["enabled"].as_bool(), Some(true), "{view}");
}

#[tokio::test]
async fn a_pinned_persons_usage_records_are_kept_in_their_regions_chat_store_and_still_count() {
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let lon = scratch.path().join("lon");
    std::fs::create_dir_all(&lon).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, _) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let used = |run: &str, tokens: u64| {
        let row = crate::db::TokenRow {
            user_id: ada.clone(),
            bot_id: "bot-0304".into(),
            run_id: run.into(),
            message_id: None,
            harness: "claude".into(),
            model: Some("m".into()),
            reported: true,
            input: tokens,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            at: crate::db::now(),
            meter: None,
        };
        app.db.record_tokens(&[row]).unwrap();
    };
    used("r1", 100);
    let count = || rusqlite::Connection::open(lon.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM token_usage", [], |r| r.get::<_, i64>(0)).unwrap();
    let tokens = || async { call_json(port, "GET", "/api/me/usage", &ada_s, "").await.1["tokens"]["total"].as_u64() };

    // A pin moves them into London's store, audited, and her usage still counts them.
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    assert_eq!(count(), 1);
    let moved = audit(port, &admin, chat_stores::MOVED).await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["usageRecords"].as_i64()), (Some("gb-lon"), Some(1)), "{moved:?}");
    assert_eq!(tokens().await, Some(100));
    // New ones are written there.
    used("r2", 20);
    assert_eq!(count(), 2);
    assert_eq!(tokens().await, Some(120));

    // The report counts them.
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(
        (r["status"].as_str(), r["chats"]["usageRecords"]["inStore"].as_i64(), r["chats"]["usageRecords"]["inServerDatabase"].as_i64()),
        (Some("kept"), Some(2), Some(0)),
        "{r}"
    );
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Model usage records in it:** 2"), "{md}");
    let (_, me) = call_json(port, "GET", "/api/me/residency", &ada_s, "").await;
    assert_eq!(me["chats"]["usageRecords"].as_bool(), Some(true), "{me}");

    // One left in botd's own database makes the pin unkept until reconcile moves it.
    app.db.conn_for_tests().execute_batch("INSERT INTO main.token_usage SELECT * FROM chats_0.token_usage LIMIT 1; DELETE FROM chats_0.token_usage WHERE id IN (SELECT id FROM main.token_usage);").unwrap();
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!(r["status"].as_str(), Some("data_outside"), "{r}");
    assert!(r["outside"].to_string().contains("they have 1 model usage record in botd's own database, not gb-lon's chat store (ADR 0304)"), "{r}");
    assert_eq!(reconcile_as(port, &admin).await["usageRecordsMoved"].as_i64(), Some(1));
    assert_eq!(count(), 2);

    // Unpinned, they come back to botd's own database.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"contract ended"}"#).await.0, 200);
    assert_eq!(count(), 0);
    assert_eq!(tokens().await, Some(120));
}

#[tokio::test]
async fn a_pinned_persons_store_backups_are_copied_off_the_host_into_a_bucket_in_their_region() {
    use crate::machines::chat_store_copies::{self, COPIED, Copies};
    use crate::machines::chat_stores::{self, CLEARED, Settings};
    use crate::machines::s3_standin::{self, StandIn};
    let scratch = crate::db::Scratch::new();
    let (lon, fra) = (scratch.path().join("lon"), scratch.path().join("fra"));
    std::fs::create_dir_all(&lon).unwrap();
    std::fs::create_dir_all(&fra).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone()), ("de-fra-2".into(), fra.clone())], keep: 7, forget: Vec::new() };
    let bucket = StandIn::start().await;
    let copies = Copies::new(chat_store_copies::Settings { stores: vec![("gb-lon".into(), bucket.settings())], prefix: "acme/".into(), recipients: Vec::new() }).unwrap();
    let set = settings.clone();
    let (port, app, admin, cp) = linode_set(move |cp| {
        cp.chat_stores = set;
        cp.chat_copies = Some(Arc::new(copies));
    })
    .await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private).id;
    let word = "chat-5d70-contract-terms";
    app.db.add_message(&bot, "user", word, None, false, None);
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);

    // The hourly check backs London's store up in its folder and copies it to London's bucket.
    chat_stores::hourly(&app, &cp).await;
    let keys = bucket.keys();
    let store = app.db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
    assert!(keys.len() == 1 && keys[0].starts_with(&format!("acme/region-data/gb-lon/{}/chats-", store.id)), "{keys:?}");
    let has = |k: &str| bucket.w().objects[k].windows(word.len()).any(|x| x == word.as_bytes());
    assert!(has(&keys[0]));
    let copied = audit(port, &admin, COPIED).await;
    assert_eq!((copied[0]["details"]["region"].as_str(), copied[0]["details"]["uploaded"].as_i64(), copied[0]["actorId"].as_str()), (Some("gb-lon"), Some(1), Some("residency")), "{copied:?}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let row = |regions: &Value, r: &str| regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == r).unwrap()["chatStore"].clone();
    let off = row(&regions, "gb-lon")["offHost"].clone();
    assert_eq!((off["copies"].as_i64(), off["bucket"].as_str(), off["error"].is_null()), (Some(1), Some(s3_standin::BUCKET), true), "{regions}");
    assert!(row(&regions, "de-fra-2")["offHost"].is_null(), "Frankfurt has no bucket: {regions}");
    assert!(!regions.to_string().contains(s3_standin::SECRET));
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["chats"]["offHost"]["copies"].as_i64(), r["chats"]["offHost"]["failing"].as_bool()), (Some(1), Some(false)), "{r}");
    assert!(r["chats"]["offHost"]["bucket"].is_null(), "no bucket names for customers: {r}");
    assert_eq!(r["digest"].as_str(), Some(crate::machines::residency_report::digest(&r).as_str()));
    let (_, md) = call(port, "GET", &format!("/api/users/{ada}/residency/report?format=markdown"), &admin, "").await;
    assert!(md.contains("- **Store's backups copied off the host:** 1 to a bucket in gb-lon, newest "), "{md}");

    // Pinned to Frankfurt, her chat leaves London. The bucket refuses on the next check:
    // London's backup is rewritten, but its copy still holds her chat, so the move stays
    // an earlier copy, and admins and the report are told.
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/residency"), &admin, r#"{"reason":"moving to Frankfurt"}"#).await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("de-fra-2", "DPA-2")).await.0, 200);
    bucket.w().fail = Some(("POST".into(), 503));
    chat_stores::hourly(&app, &cp).await;
    assert!(has(&keys[0]), "the old copy is still there");
    let cleared = audit(port, &admin, CLEARED).await;
    assert_eq!(cleared[0]["outcome"].as_str(), Some("failure"), "{cleared:?}");
    assert!(cleared[0]["details"]["error"].as_str().unwrap().contains("the backups' copies off the host"), "{cleared:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["chats"]["inRegion"].as_bool(), r["chats"]["earlierCopies"][0]["region"].as_str()), (Some(false), Some("gb-lon")), "{r}");
    assert!(r["chats"]["offHost"].is_null(), "Frankfurt's store isn't copied: {r}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(regions["residency"]["warnings"].to_string().contains("gb-lon's chat store's backups couldn't all be copied off the host"), "{regions}");
    assert!(row(&regions, "gb-lon")["offHost"]["error"].as_str().unwrap().contains("503"), "{regions}");

    // The next check replaces the copy and only then records the move as cleared.
    chat_stores::hourly(&app, &cp).await;
    let now_keys = bucket.keys();
    assert!(now_keys.len() == 1 && now_keys != keys && !has(&now_keys[0]), "{now_keys:?}");
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["chats"]["inRegion"].as_bool(), r["chats"]["earlierCopies"].as_array().map(Vec::len)), (Some(true), Some(0)), "{r}");
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(!regions["residency"]["warnings"].to_string().contains("copied off the host"), "{regions}");
    let copied = audit(port, &admin, COPIED).await;
    assert_eq!((copied[0]["details"]["uploaded"].as_i64(), copied[0]["details"]["deleted"].as_i64()), (Some(1), Some(1)), "{copied:?}");
}

#[tokio::test]
async fn an_admin_moves_a_regions_chat_store_to_another_folder_while_botd_runs() {
    use crate::machines::chat_store_move::{NOTE, STORE_MOVED};
    use crate::machines::chat_stores::{self, Settings};
    let scratch = crate::db::Scratch::new();
    let (lon, fra, lon2) = (scratch.path().join("lon"), scratch.path().join("fra"), scratch.path().join("lon-2"));
    std::fs::create_dir_all(&lon).unwrap();
    std::fs::create_dir_all(&fra).unwrap();
    let settings = Settings { dirs: vec![("gb-lon".into(), lon.clone()), ("de-fra-2".into(), fra.clone())], keep: 7, forget: Vec::new() };
    let set = settings.clone();
    let (port, app, admin, cp) = linode_set(move |cp| cp.chat_stores = set).await;
    let cipher = crate::secrets::sealed::cipher();
    chat_stores::open(&app.db, &settings, &app.cfg.data_dir, None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false }).unwrap();
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &ada, crate::acl::Visibility::Private).id;
    app.db.add_message(&bot, "user", "chat-0309-before", None, false, None);
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada}/residency"), &admin, &pin("gb-lon", "DPA-1")).await.0, 200);
    chat_stores::hourly(&app, &cp).await;
    let rows = |p: &std::path::Path| rusqlite::Connection::open(p.join("chats.sqlite")).unwrap().query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(rows(&lon), 1);

    // Only admins move a store, to an empty folder outside DATA_DIR and every store's own.
    let path = "/api/regions/gb-lon/chat-store/move";
    let to = |f: &std::path::Path| json!({ "folder": f }).to_string();
    assert_eq!(call(port, "POST", path, &ada_s, &to(&lon2)).await.0, 403);
    assert_eq!(call(port, "POST", path, &admin, r#"{"dir":"/x"}"#).await.0, 400);
    assert_eq!(call(port, "POST", "/api/regions/us-east/chat-store/move", &admin, &to(&lon2)).await.0, 404);
    let refused = |folder: String| {
        let admin = admin.clone();
        async move { call_json(port, "POST", path, &admin, &json!({ "folder": folder }).to_string()).await }
    };
    for (folder, why) in [
        ("lon-2".to_string(), "absolute path"),
        (app.cfg.data_dir.join("lon").display().to_string(), "outside DATA_DIR"),
        (lon.join("inner").display().to_string(), "gb-lon's store's own folder"),
        (fra.display().to_string(), "de-fra-2's chat store's folder"),
    ] {
        let (code, body) = refused(folder.clone()).await;
        assert!(code == 409 && body["error"].as_str().unwrap().contains(why), "{folder}: {code} {body}");
    }
    assert!(!lon.join("inner").exists() && !app.cfg.data_dir.join("lon").exists(), "folders made for a refused move are removed");
    std::fs::create_dir_all(&lon2).unwrap();
    std::fs::write(lon2.join("other.txt"), "x").unwrap();
    let (code, body) = refused(lon2.display().to_string()).await;
    assert!(code == 409 && body["error"].as_str().unwrap().contains("isn't empty"), "{body}");
    std::fs::remove_file(lon2.join("other.txt")).unwrap();
    let failed = audit(port, &admin, STORE_MOVED).await;
    assert!(failed.iter().all(|e| e["outcome"] == "failure") && failed.len() == 5, "{failed:?}");

    // Moved: the store and its backup are in the new folder, the old one keeps only a note,
    // and the move is audited with what REGION_DATA_DIRS must say now.
    let (code, m) = call_json(port, "POST", path, &admin, &to(&lon2)).await;
    assert_eq!(code, 200, "{m}");
    let want = format!("gb-lon={},de-fra-2={}", lon2.display(), fra.display());
    assert_eq!((m["to"].as_str(), m["backups"].as_i64(), m["regionDataDirs"].as_str()), (Some(lon2.to_str().unwrap()), Some(1), Some(want.as_str())), "{m}");
    assert!(m["next"].as_str().unwrap().contains(&format!("Set REGION_DATA_DIRS={want}")), "{m}");
    assert_eq!(rows(&lon2), 1);
    assert_eq!(std::fs::read_dir(lon2.join("backups")).unwrap().count(), 1);
    let left: Vec<String> = std::fs::read_dir(&lon).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left, vec![NOTE.to_string()]);
    assert!(std::fs::read_to_string(lon.join(NOTE)).unwrap().contains(&format!("Set REGION_DATA_DIRS to gb-lon={}", lon2.display())));
    let moved = audit(port, &admin, STORE_MOVED).await;
    assert_eq!((moved[0]["outcome"].as_str(), moved[0]["details"]["to"].as_str(), moved[0]["targetId"].as_str()), (Some("success"), Some(lon2.to_str().unwrap()), Some("gb-lon")), "{moved:?}");

    // botd keeps going there: new messages, the report and the hourly check.
    app.db.add_message(&bot, "user", "chat-0309-after", None, false, None);
    assert_eq!(rows(&lon2), 2);
    let (_, r) = call_json(port, "GET", &format!("/api/users/{ada}/residency/report"), &admin, "").await;
    assert_eq!((r["status"].as_str(), r["chats"]["messages"]["inStore"].as_i64()), (Some("kept"), Some(2)), "{r}");
    chat_stores::hourly(&app, &cp).await;
    assert!(audit(port, &admin, chat_stores::BACKUP_FAILED).await.is_empty());

    // Admins are told REGION_DATA_DIRS still names the old folder.
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    let w = regions["residency"]["warnings"].to_string();
    assert!(w.contains(&format!("gb-lon's chat store was moved to {} while botd ran, but REGION_DATA_DIRS still names {}", lon2.display(), lon.display())), "{regions}");
    let row = regions["regions"].as_array().unwrap().iter().find(|x| x["id"] == "gb-lon").unwrap()["chatStore"].clone();
    assert_eq!((row["messages"].as_i64(), row["backups"].as_i64()), (Some(2), Some(1)), "{regions}");

    // Moved back, the old folder's note is no obstacle and the warning goes.
    let (code, m) = call_json(port, "POST", path, &admin, &to(&lon)).await;
    assert_eq!((code, m["backups"].as_i64()), (200, Some(1)), "{m}");
    assert_eq!(rows(&lon), 2);
    assert!(!lon.join(NOTE).exists() && lon2.join(NOTE).exists() && !lon2.join("chats.sqlite").exists());
    let (_, regions) = call_json(port, "GET", "/api/regions", &admin, "").await;
    assert!(!regions["residency"]["warnings"].to_string().contains("was moved to"), "{regions}");
}
