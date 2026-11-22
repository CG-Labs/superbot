//! Off-host copies of the server's backups (ADR 0109): settings default to on-host and
//! say so, the newest finished archive is copied to the S3 stand-in with a manifest,
//! encrypted on the way or as superbot-backup encrypted it, failures are audited and
//! retried, old copies go but never the newest, and the RPO is watched, alerted and
//! shown to admins and in `/metrics`.

use crate::machines::s3_standin::{self, StandIn};
use crate::server_backups::{self, Mode, ServerBackups, Source, Target};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400_000;

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
    let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    move |k: &str| m.get(k).cloned().unwrap_or_default()
}

fn settings(pairs: &[(&str, &str)]) -> Result<ServerBackups, String> {
    let store = secrets::env::EnvStore::fixed(pairs);
    ServerBackups::from_env(&store, &env_of(pairs), Path::new("/srv/superbot/data"))
}

const STORE: [(&str, &str); 3] =
    [("SERVER_BACKUP_S3_ENDPOINT", "https://s3.example.com"), ("SERVER_BACKUP_S3_ACCESS_KEY_ID", "AKIDEXAMPLE"), ("SERVER_BACKUP_S3_SECRET_ACCESS_KEY", "example-secret-0123456789")];

fn with_store(more: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut v = STORE.to_vec();
    v.push(("SERVER_BACKUP_S3_BUCKET", "server-backups"));
    v.extend_from_slice(more);
    v
}

fn machine_store(more: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![
        ("MACHINE_BACKUP_S3_ENDPOINT", "https://s3.example.com"),
        ("MACHINE_BACKUP_S3_BUCKET", "machine-backups"),
        ("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "example-secret-0123456789"),
    ];
    v.extend_from_slice(more);
    v
}

fn err(pairs: &[(&str, &str)]) -> String {
    settings(pairs).err().unwrap_or_else(|| panic!("{pairs:?} should be refused"))
}

#[test]
fn with_nothing_set_backups_stay_on_the_host_and_say_so() {
    let sb = settings(&[]).unwrap();
    assert_eq!((sb.mode, sb.target.is_none()), (Mode::Auto, true));
    assert_eq!(sb.dir, PathBuf::from("/srv/superbot/backups"), "beside DATA_DIR, as superbot-backup writes them");
    assert_eq!((sb.rpo_ms, sb.retention_days), (26 * HOUR, Some(30)));
    let w = sb.warning().unwrap();
    assert!(w.contains("stay on this host") && w.contains("SERVER_BACKUP_S3_BUCKET"), "{w}");
    assert!(sb.describe().starts_with("off ("), "{}", sb.describe());
    // Compose's BACKUP_DIR, and the sidecar's interval as the RPO's hint.
    let sb = settings(&[("BACKUP_DIR", "/backups"), ("SUPERBOT_BACKUP_INTERVAL", "3600")]).unwrap();
    assert_eq!((sb.dir, sb.rpo_ms), (PathBuf::from("/backups"), 3 * HOUR));
    assert_eq!(settings(&[("SUPERBOT_BACKUP_INTERVAL", "86400")]).unwrap().rpo_ms, 26 * HOUR);
    assert_eq!(settings(&[("SUPERBOT_BACKUP_INTERVAL", "soon")]).unwrap().rpo_ms, 26 * HOUR, "a hint botd can't read changes nothing");
}

#[test]
fn a_store_of_its_own_or_the_machine_backups_store() {
    let id = age::x25519::Identity::generate();
    let r = id.to_public().to_string();
    let r: &'static str = Box::leak(r.into_boxed_str());
    let sb = settings(&with_store(&[("SERVER_BACKUP_AGE_RECIPIENTS", r), ("SERVER_BACKUP_RPO_HOURS", "8"), ("SERVER_BACKUP_RETENTION_DAYS", "off")])).unwrap();
    let t = sb.target.as_ref().unwrap();
    assert_eq!((t.source, t.store.bucket.as_str(), t.prefix.as_str(), t.recipients.len()), (Source::Own, "server-backups", "superbot/", 1));
    assert_eq!((sb.rpo_ms, sb.retention_days, sb.warning()), (8 * HOUR, None, None));
    assert!(sb.describe().contains("s3.example.com/server-backups/superbot/server/"), "{}", sb.describe());
    assert!(!sb.describe().contains("example-secret"), "{}", sb.describe());
    let sb = settings(&with_store(&[("SERVER_BACKUP_S3_PREFIX", "/prod")])).unwrap();
    assert_eq!(sb.target.unwrap().prefix, "prod/");

    // Machine backups' store: their prefix and recipients, unless the server has its own.
    let sb = settings(&machine_store(&[("MACHINE_BACKUP_S3_PREFIX", "fleet"), ("MACHINE_BACKUP_AGE_RECIPIENTS", r)])).unwrap();
    let t = sb.target.unwrap();
    assert_eq!((t.source, t.store.bucket.as_str(), t.prefix.as_str(), t.recipients.len()), (Source::Machines, "machine-backups", "fleet/", 1));
    let other = age::x25519::Identity::generate().to_public().to_string();
    let other: &'static str = Box::leak(other.into_boxed_str());
    let both = machine_store(&[("MACHINE_BACKUP_AGE_RECIPIENTS", r), ("SERVER_BACKUP_AGE_RECIPIENTS", other)]);
    assert_eq!(settings(&both).unwrap().target.unwrap().recipients[0].to_string(), other);
    // Its own store wins over the machines'.
    let mut both = machine_store(&[]);
    both.extend(with_store(&[]));
    assert_eq!(settings(&both).unwrap().target.unwrap().source, Source::Own);
    // Off means off, store or not.
    let sb = settings(&with_store(&[("SERVER_BACKUP_OFF_HOST", "off")])).unwrap();
    assert!(sb.target.is_none() && sb.warning().unwrap().contains("SERVER_BACKUP_OFF_HOST=off"));
    assert!(settings(&with_store(&[("SERVER_BACKUP_OFF_HOST", "on")])).unwrap().target.is_some());
}

#[test]
fn settings_that_cant_work_stop_botd() {
    assert!(err(&[("SERVER_BACKUP_OFF_HOST", "on")]).contains("no store is set"));
    assert!(err(&[("SERVER_BACKUP_OFF_HOST", "maybe")]).contains("auto, on or off"));
    assert!(err(&[("SERVER_BACKUP_S3_ENDPOINT", "https://s3.example.com")]).contains("SERVER_BACKUP_S3_BUCKET isn't"));
    assert!(err(&[("SERVER_BACKUP_RPO_HOURS", "8")]).contains("nowhere to copy"));
    assert!(err(&[("SERVER_BACKUP_RETENTION_DAYS", "7")]).contains("nowhere to copy"));
    assert!(err(&with_store(&[("SERVER_BACKUP_RPO_HOURS", "1")])).contains("2 to 744"));
    assert!(err(&with_store(&[("SERVER_BACKUP_RETENTION_DAYS", "0")])).contains("1 to 3650"));
    assert!(err(&with_store(&[("SERVER_BACKUP_AGE_RECIPIENTS", "age1nope")])).contains("SERVER_BACKUP_AGE_RECIPIENTS"));
    assert!(err(&with_store(&[("SERVER_BACKUP_S3_ENDPOINT", "http://s3.example.com")])).contains("SERVER_BACKUP_S3_ENDPOINT must be https"));
    let mut no_key = with_store(&[]);
    no_key.retain(|(k, _)| *k != "SERVER_BACKUP_S3_SECRET_ACCESS_KEY");
    assert!(err(&no_key).contains("SERVER_BACKUP_S3_SECRET_ACCESS_KEY"));
    // superbot-backup's own recipients are its business: botd never reads them.
    assert!(settings(&[("SUPERBOT_BACKUP_AGE_RECIPIENTS", "ssh-ed25519 AAAA... ops")]).is_ok());
}

fn stamp(at: i64) -> String {
    chrono::DateTime::from_timestamp_millis(at).unwrap().format("%Y%m%d-%H%M%S").to_string()
}

/// Writes an archive made `ago` ms back, as superbot-backup names it.
fn archive(dir: &Path, ago: i64, encrypted: bool, body: &[u8]) -> String {
    let name = format!("superbot-{}.tar.gz{}", stamp(db::now() - ago), if encrypted { ".age" } else { "" });
    std::fs::write(dir.join(&name), body).unwrap();
    name
}

#[test]
fn only_finished_archives_count() {
    let dir = db::temp_path("sb-archives");
    std::fs::create_dir_all(&dir).unwrap();
    let old = archive(&dir, 2 * DAY, false, b"old");
    let new = archive(&dir, HOUR, true, b"new");
    std::fs::write(dir.join("superbot-20260101-000000.tar.gz.partial-x1Yz"), b"half").unwrap();
    std::fs::write(dir.join("notes.txt"), b"x").unwrap();
    std::fs::write(dir.join("superbot-bad name.tar.gz"), b"x").unwrap();
    std::fs::create_dir(dir.join("superbot-20991231-000000.tar.gz")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join(&old), dir.join("superbot-20991230-000000.tar.gz")).unwrap();
    let found = server_backups::archives(&dir);
    assert_eq!(found.iter().map(|a| (a.name.as_str(), a.encrypted)).collect::<Vec<_>>(), [(old.as_str(), false), (new.as_str(), true)]);
    assert_eq!(server_backups::named_time("superbot-20260102-031500.tar.gz"), Some(1_767_323_700_000));
    assert!(server_backups::archives(&dir.join("missing")).is_empty());
}

struct Setup {
    port: u16,
    app: AppState,
    admin: String,
    s3: StandIn,
    dir: PathBuf,
}

async fn setup(recipients: Vec<age::x25519::Recipient>, retention_days: Option<i64>) -> Setup {
    let (port, app, admin, _) = serve_app().await;
    let s3 = StandIn::start().await;
    let dir = db::temp_path("sb-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let mut sb = ServerBackups::with(&dir, Some(Target::new(s3.settings(), "superbot/", Source::Own, recipients).unwrap()));
    sb.retention_days = retention_days;
    app.server_backups.set(Arc::new(sb)).ok().unwrap();
    Setup { port, app, admin, s3, dir }
}

async fn audit(s: &Setup, action: &str) -> Vec<Value> {
    audit_list(&call(s.port, "GET", &format!("/api/audit?action={action}"), &s.admin, "").await.1)
}

fn decrypt(data: &[u8], id: &age::x25519::Identity) -> Vec<u8> {
    let d = age::Decryptor::new(data).unwrap();
    let mut r = d.decrypt(std::iter::once(id as &dyn age::Identity)).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    out
}

#[tokio::test]
async fn the_newest_archive_is_encrypted_and_copied_with_a_manifest() {
    let id = age::x25519::Identity::generate();
    let s = setup(vec![id.to_public()], Some(30)).await;
    archive(&s.dir, 2 * DAY, false, b"older archive");
    let name = archive(&s.dir, HOUR, false, b"the newest archive");
    let made = server_backups::pass(&s.app).await.expect("a copy");
    assert_eq!((made.state.as_str(), made.archive.as_str(), made.encrypted, made.encrypted_by.as_deref()), ("done", name.as_str(), true, Some("botd")));
    let stem = name.strip_suffix(".tar.gz").unwrap();
    let object = format!("superbot/server/{name}.age");
    assert_eq!(s.s3.keys(), [format!("superbot/server/{stem}.json"), object.clone()], "only the newest, and its manifest");
    let stored = s.s3.w().objects[&object].clone();
    assert_eq!(decrypt(&stored, &id), b"the newest archive");
    assert_eq!(made.size, Some(stored.len() as i64));
    let manifest: Value = serde_json::from_slice(&s.s3.w().objects[&format!("superbot/server/{stem}.json")]).unwrap();
    assert_eq!((manifest["format"].as_str(), manifest["archive"].as_str(), manifest["object"].as_str()), (Some(server_backups::FORMAT), Some(name.as_str()), Some(object.as_str())));
    assert_eq!((manifest["encryptedBy"].as_str(), manifest["sha256"].as_str(), manifest["recipients"][0].as_str()), (Some("botd"), made.sha256.as_deref(), Some(id.to_public().to_string().as_str())));
    assert_eq!(made.expires_at, Some(made.created_at + 30 * DAY));
    let ev = audit(&s, "server.backup_copied").await;
    assert_eq!(ev.len(), 1);
    assert_eq!((ev[0]["actorId"].as_str(), ev[0]["targetType"].as_str(), ev[0]["details"]["object"].as_str()), (Some("server-backups"), Some("server_backup"), Some(object.as_str())), "{}", ev[0]);

    // Nothing new: nothing copied.
    assert!(server_backups::pass(&s.app).await.is_none());
    assert_eq!(s.s3.keys().len(), 2);

    // Admins see where copies go, without credentials; others don't see it at all.
    let (code, body) = call(s.port, "GET", "/api/backups", &s.admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["offHost"].as_bool(), v["target"]["bucket"].as_str(), v["target"]["prefix"].as_str(), v["breach"].as_bool()), (Some(true), Some(s3_standin::BUCKET), Some("superbot/server/"), Some(false)));
    assert_eq!((v["backups"][0]["id"].as_str(), v["warning"].clone(), v["rpoHours"].as_i64()), (Some(made.id.as_str()), Value::Null, Some(26)));
    assert!(!body.contains(s3_standin::SECRET) && !body.contains(s3_standin::ACCESS_KEY), "{body}");
    let (_, member) = user_with(s.port, &s.admin, "mia@example.com", "member").await;
    assert_eq!(call(s.port, "GET", "/api/backups", &member, "").await.0, 403);
    assert_eq!(call(s.port, "POST", "/api/backups", &member, "").await.0, 403);

    // The checklist and the gauges.
    let (_, body) = call(s.port, "GET", "/api/setup", &s.admin, "").await;
    let item = parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "backups").unwrap().clone();
    assert_eq!(item["done"], true, "{item}");
    let m = obs::render(&s.app);
    assert!(m.contains("superbot_server_backup_off_host 1"), "{m}");
    assert!(m.contains("superbot_server_backup_past_rpo 0"), "{m}");
    assert!(m.contains("superbot_server_backup_rpo_seconds 93600"), "{m}");
    assert!(m.contains("superbot_server_backup_last_copy_timestamp_seconds"), "{m}");
    assert!(m.contains("event=\"server.backup_copied\",outcome=\"success\"} 1"), "{m}");
}

#[tokio::test]
async fn an_archive_superbot_backup_encrypted_is_copied_as_it_is() {
    let s = setup(Vec::new(), Some(30)).await;
    let name = archive(&s.dir, HOUR, true, b"age-encryption.org/v1 already");
    let made = server_backups::pass(&s.app).await.unwrap();
    assert_eq!((made.encrypted, made.encrypted_by.as_deref(), made.object_key.clone()), (true, Some("archive"), format!("superbot/server/{name}")));
    assert_eq!(s.s3.w().objects[&made.object_key], b"age-encryption.org/v1 already");
    let stem = name.strip_suffix(".tar.gz.age").unwrap();
    assert!(s.s3.keys().contains(&format!("superbot/server/{stem}.json")));

    // A plain one with no recipients goes as it is too, and says so.
    let plain = archive(&s.dir, 0, false, b"plain");
    let made = server_backups::pass(&s.app).await.unwrap();
    assert_eq!((made.archive, made.encrypted, made.encrypted_by), (plain, false, None));
    assert_eq!(s.s3.w().objects[&made.object_key], b"plain");
}

#[tokio::test]
async fn a_failed_copy_is_audited_and_tried_again_later() {
    let s = setup(Vec::new(), Some(30)).await;
    let name = archive(&s.dir, HOUR, false, b"archive");
    s.s3.w().fail = Some(("PUT".into(), 500));
    let made = server_backups::pass(&s.app).await.unwrap();
    assert_eq!(made.state, "failed");
    assert!(made.error.as_deref().is_some_and(|e| !e.is_empty()));
    let ev = audit(&s, "server.backup_copy_failed").await;
    assert_eq!((ev.len(), ev[0]["outcome"].as_str(), ev[0]["details"]["archive"].as_str()), (1, Some("failure"), Some(name.as_str())), "{ev:?}");
    assert!(s.s3.keys().is_empty(), "no half copy, no manifest");
    // Not again right away, nor from the console.
    assert!(server_backups::pass(&s.app).await.is_none());
    let (code, body) = call(s.port, "POST", "/api/backups", &s.admin, "").await;
    assert_eq!((code, parse(&body)["copied"].clone()), (200, Value::Null), "{body}");
    // After the retry delay, it goes.
    s.app.db.server_backup_backdate(&made.id, server_backups::RETRY_MS);
    let again = server_backups::pass(&s.app).await.unwrap();
    assert_eq!((again.state.as_str(), again.archive.as_str()), ("done", name.as_str()));
    assert_eq!(s.app.db.server_backups_of(&again.destination, &name).len(), 2, "both attempts are kept");
    let m = obs::render(&s.app);
    assert!(m.contains("event=\"server.backup_copy_failed\",outcome=\"failure\"} 1"), "{m}");
}

#[tokio::test]
async fn an_admin_can_copy_now() {
    let s = setup(Vec::new(), Some(30)).await;
    let name = archive(&s.dir, HOUR, false, b"archive");
    let (code, body) = call(s.port, "POST", "/api/backups", &s.admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["copied"]["archive"].as_str(), v["copied"]["state"].as_str()), (Some(name.as_str()), Some("done")), "{v}");
    let ev = audit(&s, "server.backup_copied").await;
    assert!(ev[0]["details"]["requestedBy"].is_string(), "{}", ev[0]);
}

#[tokio::test]
async fn copies_past_retention_go_but_never_the_newest() {
    let s = setup(Vec::new(), Some(7)).await;
    let sb = s.app.server_backups.get().unwrap().clone();
    let t = sb.target.as_ref().unwrap();
    archive(&s.dir, 3 * DAY, false, b"first");
    let first = server_backups::pass(&s.app).await.unwrap();
    // Only copy, past retention: kept, as it's the newest.
    s.app.db.server_backup_backdate(&first.id, 10 * DAY);
    assert_eq!(server_backups::prune(&s.app, &sb, t).await, 0);
    assert_eq!(s.s3.keys().len(), 2);
    archive(&s.dir, HOUR, false, b"second");
    let second = server_backups::pass(&s.app).await.unwrap();
    assert_eq!(second.state, "done");
    assert_eq!(server_backups::prune(&s.app, &sb, t).await, 1);
    assert_eq!(s.app.db.server_backup(&first.id).unwrap().state, "deleted");
    assert!(s.s3.keys().iter().all(|k| !k.contains(first.archive.strip_suffix(".tar.gz").unwrap())), "{:?}", s.s3.keys());
    let ev = audit(&s, "server.backup_deleted").await;
    assert_eq!((ev.len(), ev[0]["details"]["reason"].as_str()), (1, Some("retention")));

    // Retention counts as it is set now, not as it was when a copy was made.
    s.app.db.server_backup_backdate(&second.id, 5 * DAY);
    archive(&s.dir, 0, false, b"third");
    server_backups::pass(&s.app).await.unwrap();
    let mut shorter = ServerBackups::with(&s.dir, Some(Target::new(s.s3.settings(), "superbot/", Source::Own, Vec::new()).unwrap()));
    shorter.retention_days = Some(3);
    assert_eq!(server_backups::prune(&s.app, &shorter, shorter.target.as_ref().unwrap()).await, 1);
    assert_eq!(s.app.db.server_backup(&second.id).unwrap().state, "deleted");

    // Retention off: botd deletes nothing, even copies made while it was on.
    let s = setup(Vec::new(), None).await;
    let sb = s.app.server_backups.get().unwrap().clone();
    archive(&s.dir, 2 * DAY, false, b"kept");
    let old = server_backups::pass(&s.app).await.unwrap();
    assert_eq!(old.expires_at, None);
    s.app.db.server_backup_backdate(&old.id, 400 * DAY);
    archive(&s.dir, HOUR, false, b"newer");
    server_backups::pass(&s.app).await.unwrap();
    assert_eq!(server_backups::prune(&s.app, &sb, sb.target.as_ref().unwrap()).await, 0);
    assert_eq!((s.app.db.server_backup(&old.id).unwrap().state.as_str(), s.s3.keys().len()), ("done", 4));
}

#[tokio::test]
async fn a_new_store_starts_empty_and_the_old_one_is_left_alone() {
    let s = setup(Vec::new(), Some(7)).await;
    let name = archive(&s.dir, HOUR, false, b"archive");
    let made = server_backups::pass(&s.app).await.unwrap();
    assert!(server_backups::due(&s.app, s.app.server_backups.get().unwrap()).is_none());
    s.app.db.server_backup_backdate(&made.id, 30 * DAY);
    // The admin points copies somewhere else: the newest archive is due there, nothing
    // counts as copied yet, and the old store's copies aren't botd's to delete now.
    let moved = ServerBackups::with(&s.dir, Some(Target::new(s.s3.settings(), "moved/", Source::Own, Vec::new()).unwrap()));
    assert_eq!(server_backups::due(&s.app, &moved).map(|a| a.name), Some(name));
    let st = server_backups::status(&s.app, &moved);
    assert!(st.last.is_none() && st.covered_since.is_none(), "nothing in the new store");
    assert_eq!(server_backups::prune(&s.app, &moved, moved.target.as_ref().unwrap()).await, 0);
    assert_eq!(s.app.db.server_backup(&made.id).unwrap().state, "done");
    assert_ne!(made.destination, moved.target.as_ref().unwrap().destination());
}

#[tokio::test]
async fn the_checklist_waits_for_the_first_copy() {
    let s = setup(Vec::new(), Some(30)).await;
    let (_, body) = call(s.port, "GET", "/api/setup", &s.admin, "").await;
    let item = parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "backups").unwrap().clone();
    assert_eq!(item["done"], false, "nothing has reached the store yet: {item}");
    archive(&s.dir, HOUR, false, b"archive");
    server_backups::pass(&s.app).await.unwrap();
    let (_, body) = call(s.port, "GET", "/api/setup", &s.admin, "").await;
    let item = parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "backups").unwrap().clone();
    assert_eq!(item["done"], true, "{item}");
}

#[tokio::test]
async fn past_the_rpo_is_alerted_and_so_is_the_recovery() {
    let s = setup(Vec::new(), Some(30)).await;
    archive(&s.dir, 30 * HOUR, false, b"old");
    let old = server_backups::pass(&s.app).await.unwrap();
    assert_eq!(old.state, "done");
    let sb = s.app.server_backups.get().unwrap().clone();
    assert!(server_backups::watch(&s.app, &sb), "30 hours > 26");
    let ev = audit(&s, "server.backup_rpo_breached").await;
    assert_eq!((ev.len(), ev[0]["outcome"].as_str(), ev[0]["details"]["rpoHours"].as_i64()), (1, Some("failure"), Some(26)));
    assert!(server_backups::watch(&s.app, &sb), "still open, not alerted twice");
    assert_eq!(audit(&s, "server.backup_rpo_breached").await.len(), 1);
    let m = obs::render(&s.app);
    assert!(m.contains("superbot_server_backup_past_rpo 1"), "{m}");
    let (_, body) = call(s.port, "GET", "/api/setup", &s.admin, "").await;
    let item = parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "backups").unwrap().clone();
    assert_eq!(item["done"], false, "{item}");
    assert!(item["detail"].as_str().unwrap().contains("past the RPO"), "{item}");

    archive(&s.dir, 0, false, b"new");
    server_backups::pass(&s.app).await.unwrap();
    let ev = audit(&s, "server.backup_rpo_recovered").await;
    assert_eq!((ev.len(), ev[0]["details"]["reason"].as_str()), (1, Some("backed_up")), "{ev:?}");
    assert!(obs::render(&s.app).contains("superbot_server_backup_past_rpo 0"));
}

#[tokio::test]
async fn without_a_store_nothing_is_copied_and_admins_are_told() {
    let (port, app, admin, _) = serve_app().await;
    let dir = db::temp_path("sb-none");
    std::fs::create_dir_all(&dir).unwrap();
    archive(&dir, HOUR, false, b"stays");
    app.server_backups.set(Arc::new(ServerBackups::with(&dir, None))).ok().unwrap();
    server_backups::start(app.clone());
    assert!(server_backups::pass(&app).await.is_none());
    let (code, body) = call(port, "GET", "/api/backups", &admin, "").await;
    let v = parse(&body);
    assert_eq!((code, v["offHost"].as_bool(), v["target"].clone()), (200, Some(false), Value::Null), "{body}");
    assert!(v["warning"].as_str().unwrap().contains("stay on this host"), "{v}");
    assert!(v["newestArchive"]["name"].is_string(), "{v}");
    let (code, body) = call(port, "POST", "/api/backups", &admin, "").await;
    assert_eq!(code, 409, "{body}");
    let m = obs::render(&app);
    assert!(m.contains("superbot_server_backup_off_host 0"), "{m}");
    assert!(!m.contains("superbot_server_backup_past_rpo"), "no RPO to be past: {m}");
    assert!(app.db.server_backups(10).is_empty());
}

#[tokio::test]
async fn a_copy_cut_off_by_a_restart_ends_as_failed() {
    let s = setup(Vec::new(), Some(30)).await;
    let name = archive(&s.dir, HOUR, false, b"archive");
    let dest = s.app.server_backups.get().unwrap().target.as_ref().unwrap().destination();
    let n = db::NewServerBackup { id: "sbcut", archive: &name, destination: &dest, object_key: "superbot/server/x", created_at: db::now() - HOUR, encrypted_by: None };
    s.app.db.server_backup_start(&n).unwrap();
    assert!(server_backups::pass(&s.app).await.is_none(), "one copy at a time");
    server_backups::start(s.app.clone());
    let b = s.app.db.server_backup("sbcut").unwrap();
    assert_eq!((b.state.as_str(), b.error.as_deref()), ("failed", Some("botd stopped while it was running")));
    assert_eq!(audit(&s, "server.backup_copy_failed").await.len(), 1);
}
