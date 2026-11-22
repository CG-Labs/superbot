//! Deleting a destroyed machine's backups on request (ADR 0108) on the real router, with a
//! stand-in object store: only once the machine is destroyed, admins only, every object
//! under the machine's prefix and no other machine's, audited, and safe to ask again.
//! Erasing a user (ADR 0102) deletes their machines' backups only when asked.

use crate::db::{Machine, MachineBackup, NewMachineBackup, NewMachineRestore, now};
use crate::machines::backup::{self, Offsite, Settings};
use crate::machines::fake::Fake;
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::s3_standin::StandIn;
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const DAY_MS: i64 = 86_400_000;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
    cp: Arc<ControlPlane>,
    s3: Option<StandIn>,
}

/// botd on the fake provider, with off-host backups to a stand-in store when `store`.
async fn serve(store: bool) -> Env {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    let s3 = if store { Some(StandIn::start().await) } else { None };
    if let Some(s) = &s3 {
        cp.offsite = Some(Arc::new(Offsite::new(Settings::with(s.settings(), "t/", Vec::new())).unwrap()));
    }
    let cp = Arc::new(cp);
    let c = cp.clone();
    let (port, app, admin, _) = serve_app_with(move |a| a.machines = c).await;
    Env { port, app, admin, fake, cp, s3 }
}

async fn json_call(env: &Env, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(env.port, "GET", &format!("/api/audit?action={action}&limit=200"), &env.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn erase(env: &Env, user: &str, body: &str) -> (u16, Value) {
    json_call(env, "POST", &format!("/api/users/{user}/erase"), &env.admin, body).await
}

/// A new machine for `user`.
async fn machine_of(env: &Env, user: &str) -> Machine {
    let (code, m) = json_call(env, "POST", &format!("/api/users/{user}/machine"), &env.admin, "{}").await;
    assert_eq!(code, 202, "{m}");
    env.app.db.machine(m["id"].as_str().unwrap()).unwrap()
}

/// A member with a machine: their id and the machine.
async fn member_with_machine(env: &Env, email: &str) -> (String, Machine) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    let m = machine_of(env, &uid).await;
    (uid, m)
}

async fn destroy(env: &Env, user: &str) {
    let (code, v) = json_call(env, "DELETE", &format!("/api/users/{user}/machine"), &env.admin, "").await;
    assert_eq!(code, 200, "{v}");
}

/// A backup of `m` that is `done` (with its data and manifest in the store, if there is
/// one), `failed`, or still `running`.
fn backup_of(env: &Env, m: &Machine, state: &str) -> MachineBackup {
    let id = format!("b{}", random_hex(8));
    let key = format!("t/machines/{}/{id}.incus", m.id);
    let n = NewMachineBackup { id: &id, machine: m, object_key: &key, encrypted: false, created_by: Some("schedule") };
    env.app.db.machine_backup_start(&n).unwrap();
    match state {
        "done" => {
            assert!(env.app.db.machine_backup_end(&id, Some((4, "sha", now() + 7 * DAY_MS)), None));
            if let Some(s) = &env.s3 {
                let mut w = s.w();
                w.objects.insert(key.clone(), b"disk".to_vec());
                w.objects.insert(format!("t/machines/{}/{id}.json", m.id), b"{}".to_vec());
            }
        }
        "failed" => assert!(env.app.db.machine_backup_end(&id, None, Some("export failed"))),
        _ => {}
    }
    env.app.db.machine_backup(&id).unwrap()
}

fn ids(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    out.sort();
    out
}

#[tokio::test]
async fn a_destroyed_machines_backups_go_on_request_and_nothing_else_does() {
    let env = serve(true).await;
    let s3 = env.s3.as_ref().unwrap();
    let (uid, m) = member_with_machine(&env, "ada@example.com").await;
    let (done, failed) = (backup_of(&env, &m, "done"), backup_of(&env, &m, "failed"));
    s3.w().objects.insert(format!("t/machines/{}/left-by-an-old-botd.incus", m.id), b"disk".to_vec());
    let (_, other) = member_with_machine(&env, "bea@example.com").await;
    let theirs = backup_of(&env, &other, "done");
    let n = NewMachineRestore { id: "rleft", machine: &m, backup_id: &done.id, by: None, rto_ms: None, from_host: None, to_host: None, reason: None };
    env.app.db.machine_restore_start(&n).unwrap();
    assert!(env.app.db.machine_restore_move("rleft", &["importing"], "failed", Some("botd stopped mid-restore")));
    let path = format!("/api/machines/{}/backups", m.id);

    // Admins only.
    let (_, member) = user_with(env.port, &env.admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(env.port, &env.admin, "r@example.com", "readonly").await;
    for who in [&member, &readonly] {
        assert_eq!(call(env.port, "DELETE", &path, who, "").await.0, 403);
    }
    assert_eq!(json_call(&env, "DELETE", "/api/machines/mnope/backups", &env.admin, "").await.0, 404);

    // A machine that still exists keeps them: refused, audited, nothing touched.
    let (code, e) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert_eq!(code, 409, "{e}");
    assert!(e["error"].as_str().unwrap().contains("only a destroyed machine's backups"), "{e}");
    let refused = events(&env, "machine.backups_delete_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["reason"].as_str(), refused[0]["outcome"].as_str()), (1, Some("not_destroyed"), Some("denied")), "{refused:?}");
    assert_eq!(s3.keys().len(), 5);
    assert_eq!(env.app.db.machine_backup(&done.id).unwrap().state, "done");

    destroy(&env, &uid).await;
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Destroyed);

    // A backup still running when it was destroyed is waited for.
    let running = backup_of(&env, &m, "running");
    let (code, e) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert_eq!(code, 409, "{e}");
    assert_eq!(events(&env, "machine.backups_delete_refused").await[0]["details"]["reason"].as_str(), Some("backup_running"));
    assert!(env.app.db.machine_backup_end(&running.id, None, Some("the machine went")));

    // The store failing part way: 502, audited, and nothing marked deleted that isn't.
    s3.w().fail = Some(("DELETE".into(), 503));
    let (code, e) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert_eq!(code, 502, "{e}");
    let failures = events(&env, "machine.backups_delete_failed").await;
    assert_eq!((failures.len(), failures[0]["outcome"].as_str(), failures[0]["details"]["left"].as_u64()), (1, Some("failure"), Some(3)), "{failures:?}");
    assert_eq!(env.app.db.machine_backup(&done.id).unwrap().state, "done");

    // Asked again: every backup of it, whatever else was under its prefix, and the copy a
    // restore left at the provider all go; another machine's backup stays.
    let deletes = env.fake.calls("delete");
    let (code, v) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert_eq!(code, 200, "{v}");
    let mut want = vec![done.id.clone(), failed.id.clone(), running.id.clone()];
    want.sort();
    assert_eq!(ids(&v["backups"]), want, "{v}");
    assert_eq!((v["strays"].as_u64(), v["restoreCopies"].as_u64(), v["machineId"].as_str(), v["userId"].as_str()), (Some(1), Some(1), Some(m.id.as_str()), Some(uid.as_str())), "{v}");
    assert_eq!(env.fake.calls("delete"), deletes + 1, "the restore copy");
    assert_eq!(s3.keys(), [theirs.object_key.clone(), format!("t/machines/{}/{}.json", other.id, theirs.id)]);
    for b in [&done, &failed, &running] {
        let b = env.app.db.machine_backup(&b.id).unwrap();
        assert!(b.state == "deleted" && b.deleted_at.is_some(), "{b:?}");
    }
    assert_eq!(env.app.db.machine_backup(&theirs.id).unwrap().state, "done");
    let deleted = events(&env, "machine.backup_deleted").await;
    assert_eq!(deleted.len(), 3, "{deleted:?}");
    assert!(deleted.iter().all(|e| e["details"]["reason"] == "requested" && e["targetId"] == m.id.as_str() && e["actorKind"] == "user"), "{deleted:?}");
    let summary = events(&env, "machine.backups_deleted").await;
    assert_eq!((summary.len(), summary[0]["details"]["strays"].as_u64(), summary[0]["details"]["restoreCopies"].as_u64()), (1, Some(1), Some(1)), "{summary:?}");
    let (_, all) = json_call(&env, "GET", "/api/machines/backups", &env.admin, "").await;
    assert_eq!(all["backups"].as_array().map(Vec::len), Some(1), "only the other machine's: {all}");

    // The provider failing on a later ask: 502, and nothing is left to report.
    env.fake.fail_next("delete", ProviderError::Transport("down".into()));
    let (code, e) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert!(code == 502 && e["error"].as_str().unwrap().contains("restore copy"), "{code} {e}");
    assert_eq!(events(&env, "machine.backups_delete_failed").await[0]["details"]["left"].as_u64(), Some(0));

    // Twice is once: nothing more goes, and retention has nothing left to do.
    let (code, v) = json_call(&env, "DELETE", &path, &env.admin, "").await;
    assert_eq!((code, v["backups"].as_array().map(Vec::len), v["strays"].as_u64()), (200, Some(0), Some(0)), "{v}");
    assert_eq!(events(&env, "machine.backup_deleted").await.len(), 3);
    assert_eq!(backup::prune(&env.app, env.cp.offsite.as_deref().unwrap()).await, 0);
}

#[tokio::test]
async fn erasing_a_user_deletes_their_machines_backups_only_when_asked() {
    let env = serve(true).await;
    let s3 = env.s3.as_ref().unwrap();
    let (ada, old) = member_with_machine(&env, "ada@example.com").await;
    let old_backup = backup_of(&env, &old, "done");
    destroy(&env, &ada).await;
    let live = machine_of(&env, &ada).await;
    let live_backup = backup_of(&env, &live, "done");
    let (_, other) = member_with_machine(&env, "bea@example.com").await;
    let hers = backup_of(&env, &other, "done");

    // Kept unless asked: refused before the machine goes.
    assert_eq!(erase(&env, &ada, r#"{"deleteBackups":"yes"}"#).await.0, 400);
    let (code, e) = erase(&env, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 409, "{e}");
    assert!(e["error"].as_str().unwrap().contains("--delete-backups"), "{e}");
    let refused = events(&env, "user.erase_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["backups"].as_u64()), (Some("machine_backups"), Some(2)), "{refused:?}");
    assert!(env.app.db.user_machine(&ada).is_some(), "not destroyed for an erasure that was refused");
    assert_eq!(s3.keys().len(), 6);

    // Asked: the machine is destroyed, then every backup of both of hers goes.
    let (code, v) = erase(&env, &ada, r#"{"destroyMachine":true,"deleteBackups":true}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["removed"]["machineBackups"].as_u64(), Some(2), "{v}");
    let p = v["pseudonym"].as_str().unwrap().to_string();
    assert_eq!(s3.keys(), [hers.object_key.clone(), format!("t/machines/{}/{}.json", other.id, hers.id)]);
    for b in [&old_backup, &live_backup] {
        assert_eq!(env.app.db.machine_backup(&b.id).unwrap().state, "deleted");
    }
    assert_eq!(env.app.db.machine(&live.id).unwrap().state, State::Destroyed);
    let deleted = events(&env, "machine.backup_deleted").await;
    assert_eq!(deleted.len(), 2, "{deleted:?}");
    assert!(deleted.iter().all(|e| e["details"]["reason"] == "user_erased" && e["details"]["userId"] == p.as_str()), "named by the pseudonym: {deleted:?}");
    assert!(!json!(deleted).to_string().contains(&ada), "{deleted:?}");
    assert_eq!(events(&env, "machine.backups_deleted").await.len(), 2, "one per machine");
    assert_eq!(events(&env, "user.erased").await[0]["details"]["machineBackups"].as_u64(), Some(2));
}

#[tokio::test]
async fn in_a_versioned_bucket_old_versions_and_markers_go_too() {
    let env = serve(true).await;
    let s3 = env.s3.as_ref().unwrap();
    let (uid, m) = member_with_machine(&env, "ada@example.com").await;
    let b = backup_of(&env, &m, "done");
    let (_, other) = member_with_machine(&env, "bea@example.com").await;
    let theirs = backup_of(&env, &other, "done");
    {
        let mut w = s3.w();
        w.versioning = Some("Enabled");
        let stray = format!("t/machines/{}/left.incus", m.id);
        w.old = vec![
            (b.object_key.clone(), "v-older".into(), false),
            (stray.clone(), "v-stray".into(), false),
            (stray, "v-marker".into(), true),
            (theirs.object_key.clone(), "v-theirs".into(), false),
        ];
    }
    destroy(&env, &uid).await;
    let (code, v) = json_call(&env, "DELETE", &format!("/api/machines/{}/backups", m.id), &env.admin, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["backups"].as_array().map(Vec::len), v["versions"].as_u64(), v["strays"].as_u64()), (Some(1), Some(5), Some(0)), "data, manifest, an older version, a stray's version and its marker: {v}");
    assert_eq!(s3.keys(), [theirs.object_key.clone(), format!("t/machines/{}/{}.json", other.id, theirs.id)]);
    assert_eq!(s3.w().old, [(theirs.object_key.clone(), "v-theirs".to_string(), false)], "another machine's versions stay");
    assert!(!s3.w().calls.iter().any(|c| c.starts_with("DELETE") && !c.contains("versionId=")), "no plain delete to leave a marker: {:?}", s3.w().calls);
    assert_eq!(events(&env, "machine.backups_deleted").await[0]["details"]["versions"].as_u64(), Some(5));
}

#[tokio::test]
async fn an_erasure_asked_again_finishes_what_it_left_and_counts_a_backup_begun_meanwhile() {
    let env = serve(true).await;
    let (ada, m) = member_with_machine(&env, "ada@example.com").await;
    let b = backup_of(&env, &m, "done");
    let n = NewMachineRestore { id: "rleft", machine: &m, backup_id: &b.id, by: None, rto_ms: None, from_host: None, to_host: None, reason: None };
    env.app.db.machine_restore_start(&n).unwrap();
    assert!(env.app.db.machine_restore_move("rleft", &["importing"], "failed", Some("botd stopped mid-restore")));
    destroy(&env, &ada).await;

    // The restore copy can't go yet: the backups did, so none is recorded as kept.
    let deletes = env.fake.calls("delete");
    env.fake.fail_next("delete", ProviderError::Transport("down".into()));
    let (code, e) = erase(&env, &ada, r#"{"deleteBackups":true}"#).await;
    assert!(code == 502 && e["error"].as_str().unwrap().contains("restore copy"), "{code} {e}");
    assert!(env.app.db.user_machine_backups_kept(&ada).is_empty());
    assert!(env.app.db.user(&ada).unwrap().erased_at.is_none());

    // Asked again, the copy is deleted before they're erased.
    let (code, v) = erase(&env, &ada, r#"{"deleteBackups":true}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(env.fake.calls("delete"), deletes + 2, "the copy, failing then going");
    assert_eq!(v["removed"]["machineBackups"].as_u64(), Some(0), "{v}");

    // A backup that ends while the machine is being destroyed is still counted.
    let (bea, hers) = member_with_machine(&env, "bea@example.com").await;
    env.fake.during_next("delete", {
        let (app, hers) = (env.app.clone(), hers.clone());
        move || {
            let n = NewMachineBackup { id: "blate", machine: &hers, object_key: "t/late.incus", encrypted: false, created_by: Some("schedule") };
            app.db.machine_backup_start(&n).unwrap();
        }
    });
    let (code, e) = erase(&env, &bea, r#"{"destroyMachine":true}"#).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("--delete-backups"), "{code} {e}");
    assert_eq!(env.app.db.machine(&hers.id).unwrap().state, State::Destroyed);
    assert!(env.app.db.user(&bea).unwrap().erased_at.is_none());
    assert_eq!(events(&env, "user.erase_refused").await[0]["details"]["reason"].as_str(), Some("machine_backups"));
}

#[tokio::test]
async fn with_backups_off_botd_refuses_rather_than_leave_them() {
    let env = serve(false).await;
    let (ada, m) = member_with_machine(&env, "ada@example.com").await;
    // Recorded while backups were on; the store's settings are gone since.
    backup_of(&env, &m, "done");
    destroy(&env, &ada).await;
    let (code, e) = json_call(&env, "DELETE", &format!("/api/machines/{}/backups", m.id), &env.admin, "").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("MACHINE_BACKUP_S3_BUCKET"), "{code} {e}");
    let refused = events(&env, "machine.backups_delete_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["reason"].as_str(), refused[0]["targetId"].as_str()), (1, Some("store_off"), Some(m.id.as_str())), "{refused:?}");

    let (code, e) = erase(&env, &ada, r#"{"deleteBackups":true}"#).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("off-host machine backups are off"), "{code} {e}");
    let refused = events(&env, "user.erase_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["store"].as_str()), (Some("machine_backups"), Some("off")), "{refused:?}");
    assert!(env.app.db.user(&ada).unwrap().erased_at.is_none());
}
