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
    assert!(!w.contains("botd's own"), "report mode adds no warnings about botd's region: {regions}");
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
