//! Contractual data residency (ADR 0129): an admin pins a user or a team to a data
//! region, and their machines, backups and restores stay there or are refused and
//! audited. On the real router, with the in-memory provider for Linode and stand-ins for
//! Incus hosts and S3.

use crate::db::PinOn;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::incus::fleet::{Fleet, Member};
use crate::machines::provider::{MachineProvider, Policy};
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
    machine_for(&env, &env.a, "a", &lon, false).await;
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{lon}/residency"), &pin("de-fra-2", "DPA-2")).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("their machine is in gb-lon"), "{v}");
    let refused = events(&env, "user.residency_pin_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["targetId"].as_str()), (Some("data_outside"), Some(lon.as_str())));
    assert!(env.app.db.residency_pin(PinOn::User, &lon).is_none());

    // Pinned elsewhere needs an unpin first; the same region again renews the reference.
    let (code, v) = json_call(&env, "PUT", &path, &pin("gb-lon", "DPA-3")).await;
    assert!(code == 409 && v["error"].as_str().unwrap().contains("Unpin first"), "{v}");
    let (code, v) = json_call(&env, "PUT", &path, &pin("de-fra-2", "DPA-2027-001")).await;
    assert_eq!((code, v["residency"]["reference"].as_str()), (200, Some("DPA-2027-001")), "{v}");
    assert_eq!(events(&env, "user.residency_pinned").await[0]["details"]["renewed"].as_bool(), Some(true));

    // The regions page shows the pin.
    let (_, r) = json_call(&env, "GET", "/api/regions", "").await;
    assert_eq!((r["regions"][1]["pinned"]["users"].as_u64(), r["residency"]["pins"][0]["name"].as_str()), (Some(1), Some("fra")), "{r}");
    assert_eq!(r["residency"]["warnings"], json!([]), "{r}");

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
    env.app.db.set_residency_pin(PinOn::User, &fra, "de-fra-2", "DPA-1", None);
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

/// Linode, with MACHINE_REGIONS=gb-lon,de-fra-2.
async fn linode() -> (u16, AppState, String) {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake;
    let (port, app, owner, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    app.teams.set(Default::default()).unwrap();
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin)
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
}
