//! Backups encrypted by default (ADR 0114): SUPERBOT_BACKUP_ENCRYPTION's settings, which
//! targets are plain and why, `required` refusing to start and to copy plain archives,
//! `off` keeping them plain by choice, and every change audited once and shown in the
//! startup log, the setup checklist, `GET /api/backups` and `/metrics`.

use crate::backup_encryption::{self, Policy};
use crate::machines::backup;
use crate::machines::s3_standin::StandIn;
use crate::server_backups::{self, ServerBackups, Source, Target};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::parse;
use crate::*;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

const HOUR: i64 = 3_600_000;

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
    let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    move |k: &str| m.get(k).cloned().unwrap_or_default()
}

fn settings(pairs: &[(&str, &str)]) -> Result<ServerBackups, String> {
    let store = secrets::env::EnvStore::fixed(pairs);
    ServerBackups::from_env(&store, &env_of(pairs), Path::new("/srv/superbot/data"))
}

fn machines(recipients: &str) -> backup::Settings {
    let pairs = [
        ("MACHINE_BACKUP_S3_ENDPOINT", "https://s3.example.com"),
        ("MACHINE_BACKUP_S3_BUCKET", "machine-backups"),
        ("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "example-secret-0123456789"),
        ("MACHINE_BACKUP_AGE_RECIPIENTS", recipients),
    ];
    backup::Settings::from_env(&secrets::env::EnvStore::fixed(&pairs), &env_of(&pairs), &[]).unwrap().unwrap()
}

/// A store of the server's own, encrypting plain archives to `recipients` (may be empty).
fn store(recipients: &str) -> Target {
    let pairs = [
        ("SERVER_BACKUP_S3_ENDPOINT", "https://s3.example.com"),
        ("SERVER_BACKUP_S3_BUCKET", "server-backups"),
        ("SERVER_BACKUP_S3_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("SERVER_BACKUP_S3_SECRET_ACCESS_KEY", "example-secret-0123456789"),
        ("SERVER_BACKUP_AGE_RECIPIENTS", recipients),
    ];
    settings(&pairs).unwrap().target.unwrap()
}

fn public() -> (age::x25519::Identity, String) {
    let id = age::x25519::Identity::generate();
    let r = id.to_public().to_string();
    (id, r)
}

fn archive(dir: &Path, ago: i64, encrypted: bool, body: &[u8]) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(db::now() - ago).unwrap().format("%Y%m%d-%H%M%S");
    let name = format!("superbot-{stamp}.tar.gz{}", if encrypted { ".age" } else { "" });
    std::fs::write(dir.join(&name), body).unwrap();
    name
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = db::temp_path(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn plain(ts: &[backup_encryption::Target]) -> Vec<&'static str> {
    ts.iter().filter(|t| !t.encrypted).map(|t| t.id).collect()
}

#[test]
fn the_policy_defaults_to_auto_and_odd_values_stop_botd() {
    assert_eq!(settings(&[]).unwrap().encryption, Policy::Auto);
    assert_eq!(settings(&[("SUPERBOT_BACKUP_ENCRYPTION", "Required")]).unwrap().encryption, Policy::Required);
    assert_eq!(settings(&[("SUPERBOT_BACKUP_ENCRYPTION", "off")]).unwrap().encryption, Policy::Off);
    let e = settings(&[("SUPERBOT_BACKUP_ENCRYPTION", "maybe")]).err().unwrap();
    assert!(e.contains("auto, required or off"), "{e}");
    // botd only asks whether superbot-backup has recipients, never parses them.
    assert!(!settings(&[]).unwrap().archive_recipients);
    assert!(settings(&[("SUPERBOT_BACKUP_AGE_RECIPIENTS", "ssh-ed25519 AAAA... ops")]).unwrap().archive_recipients);
    assert!(settings(&[("SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE", "/etc/superbot/recipients.txt")]).unwrap().archive_recipients);
}

#[test]
fn each_target_says_whether_it_is_encrypted_and_how_to_fix_it() {
    let dir = temp_dir("be-targets");
    let mut sb = ServerBackups::with(&dir, None);
    // Nothing set, no archives yet: the one target is plain.
    let ts = backup_encryption::targets(&sb, None);
    assert_eq!(plain(&ts), ["server_archives"]);
    assert!(ts[0].detail.contains("SUPERBOT_BACKUP_AGE_RECIPIENTS"), "{ts:?}");
    // Recipients set before the first archive: encrypted.
    sb.archive_recipients = true;
    assert!(plain(&backup_encryption::targets(&sb, None)).is_empty());
    // An archive written plain before the upgrade is plain until the next one.
    let old = archive(&dir, 2 * HOUR, false, b"old");
    let ts = backup_encryption::targets(&sb, None);
    assert_eq!(plain(&ts), ["server_archives"]);
    assert!(ts[0].detail.contains(&old) && ts[0].detail.contains("encrypts the next one"), "{ts:?}");
    archive(&dir, HOUR, true, b"new");
    assert!(plain(&backup_encryption::targets(&sb, None)).is_empty(), "the newest archive is what counts");

    // Off-host copies: encrypted when the archives are, or botd encrypts them on the way.
    sb.target = Some(store(""));
    assert!(plain(&backup_encryption::targets(&sb, None)).is_empty());
    let dir2 = temp_dir("be-targets-plain");
    let mut sb2 = ServerBackups::with(&dir2, Some(store("")));
    archive(&dir2, HOUR, false, b"plain");
    assert_eq!(plain(&backup_encryption::targets(&sb2, None)), ["server_archives", "server_copies"]);
    sb2.target = Some(store(&public().1));
    assert_eq!(plain(&backup_encryption::targets(&sb2, None)), ["server_archives"], "botd encrypts plain archives on the way");

    // Machines' backups: by their own recipients.
    let (_, r) = public();
    assert!(plain(&backup_encryption::targets(&sb, Some(&machines(&r)))).is_empty());
    let ts = backup_encryption::targets(&sb, Some(&machines("")));
    assert_eq!(plain(&ts), ["machines"]);
    assert!(ts.last().unwrap().detail.contains("MACHINE_BACKUP_AGE_RECIPIENTS"), "{ts:?}");
}

#[test]
fn required_refuses_to_start_with_any_target_set_to_be_plain() {
    let dir = temp_dir("be-required");
    let mut sb = ServerBackups::with(&dir, None);
    assert!(backup_encryption::check(&sb, None).is_ok(), "auto never refuses");
    sb.encryption = Policy::Required;
    let e = backup_encryption::check(&sb, None).err().unwrap();
    assert!(e.contains("server archives (set SUPERBOT_BACKUP_AGE_RECIPIENTS)"), "{e}");
    sb.archive_recipients = true;
    assert!(backup_encryption::check(&sb, None).is_ok());
    // A plain archive from before the recipients were set doesn't stop botd.
    archive(&dir, HOUR, false, b"old");
    assert!(backup_encryption::check(&sb, None).is_ok());
    let e = backup_encryption::check(&sb, Some(&machines(""))).err().unwrap();
    assert!(e.contains("MACHINE_BACKUP_AGE_RECIPIENTS") && !e.contains("server archives"), "{e}");
    assert!(backup_encryption::check(&sb, Some(&machines(&public().1))).is_ok());
    // Copies without archive recipients need botd's own.
    sb.archive_recipients = false;
    sb.target = Some(store(""));
    let e = backup_encryption::check(&sb, None).err().unwrap();
    assert!(e.contains("server archives") && e.contains("off this host"), "{e}");
    sb.target = Some(store(&public().1));
    let e = backup_encryption::check(&sb, None).err().unwrap();
    assert!(e.contains("server archives") && !e.contains("off this host"), "{e}");
}

#[test]
fn startup_warns_per_plain_target_unless_plaintext_was_chosen() {
    let dir = temp_dir("be-lines");
    let sb = ServerBackups::with(&dir, None);
    let ts = backup_encryption::targets(&sb, Some(&machines("")));
    let (line, warnings) = backup_encryption::startup_lines(Policy::Auto, &ts);
    assert!(line.contains("2 of 2 targets are plain"), "{line}");
    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].starts_with("Server archives on this host aren't encrypted") && warnings[1].contains("MACHINE_BACKUP_AGE_RECIPIENTS"), "{warnings:?}");
    let (line, warnings) = backup_encryption::startup_lines(Policy::Off, &ts);
    assert!(line.contains("plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off): server_archives, machines"), "{line}");
    assert!(warnings.is_empty());
    let ts = backup_encryption::targets(&sb, Some(&machines(&public().1))).into_iter().filter(|t| t.encrypted).collect::<Vec<_>>();
    let (line, warnings) = backup_encryption::startup_lines(Policy::Auto, &ts);
    assert!(line.starts_with("every target is encrypted (machines)") && warnings.is_empty(), "{line}");
}

async fn audit(port: u16, admin: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", "/api/audit?action=server.backup_encryption_changed", admin, "").await.1)
}

async fn checklist(port: u16, admin: &str) -> Value {
    let (_, body) = call(port, "GET", "/api/setup", admin, "").await;
    parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "backup_encryption").unwrap().clone()
}

#[tokio::test]
async fn plain_backups_are_shown_and_audited_until_they_are_encrypted() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("be-http");
    archive(&dir, HOUR, false, b"plain");
    app.server_backups.set(Arc::new(ServerBackups::with(&dir, None))).ok().unwrap();

    assert!(backup_encryption::watch(&app));
    assert!(!backup_encryption::watch(&app), "the same state is audited once");
    let ev = audit(port, &admin).await;
    assert_eq!(ev.len(), 1);
    let d = &ev[0]["details"];
    assert_eq!((d["policy"].as_str(), d["unencrypted"].clone(), d["plaintextAllowed"].as_bool(), d["previous"].clone()), (Some("auto"), json!(["server_archives"]), Some(false), Value::Null), "{d}");
    assert_eq!(ev[0]["actorId"].as_str(), Some("backup-encryption"));
    let m = obs::render(&app);
    assert!(m.contains("superbot_backup_encrypted{target=\"server_archives\"} 0") && m.contains("superbot_backup_plaintext_allowed 0"), "{m}");
    assert!(m.contains("event=\"server.backup_encryption_changed\""), "counted in superbot_events_total: {m}");
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], false, "{item}");
    assert!(item["detail"].as_str().unwrap().contains("SUPERBOT_BACKUP_AGE_RECIPIENTS"), "{item}");
    let (_, body) = call(port, "GET", "/api/backups", &admin, "").await;
    let v = parse(&body);
    assert_eq!((v["encryption"]["policy"].as_str(), v["encryption"]["allEncrypted"].as_bool()), (Some("auto"), Some(false)), "{v}");
    assert_eq!(v["encryption"]["targets"][0]["id"].as_str(), Some("server_archives"));

    // superbot-backup writes an encrypted archive: the next look audits the change.
    archive(&dir, 0, true, b"encrypted");
    assert!(backup_encryption::watch(&app));
    let ev = audit(port, &admin).await;
    assert_eq!((ev.len(), ev[0]["details"]["unencrypted"].clone(), ev[0]["details"]["previous"].as_str()), (2, json!([]), Some("auto plain=server_archives")), "{ev:?}");
    assert!(obs::render(&app).contains("superbot_backup_encrypted{target=\"server_archives\"} 1"));
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], true, "{item}");
    assert!(item["detail"].as_str().unwrap().contains("Keep the age identity off this host"), "{item}");
}

#[tokio::test]
async fn a_change_whose_event_wasnt_saved_is_audited_on_the_next_look() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("be-retry");
    app.server_backups.set(Arc::new(ServerBackups::with(&dir, None))).ok().unwrap();
    app.db
        .execute_raw("CREATE TEMP TRIGGER no_be BEFORE INSERT ON audit_events WHEN NEW.action = 'server.backup_encryption_changed' BEGIN SELECT RAISE(ABORT, 'disk full'); END")
        .unwrap();
    assert!(!backup_encryption::watch(&app));
    assert!(app.db.setting("backup_encryption_state").is_none(), "the state waits for its event");
    app.db.execute_raw("DROP TRIGGER no_be").unwrap();
    assert!(backup_encryption::watch(&app));
    assert!(!backup_encryption::watch(&app));
    assert_eq!(audit(port, &admin).await.len(), 1);
}

#[tokio::test]
async fn plaintext_by_choice_is_audited_and_still_shown() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("be-off");
    let mut sb = ServerBackups::with(&dir, None);
    sb.encryption = Policy::Off;
    app.server_backups.set(Arc::new(sb)).ok().unwrap();
    backup_encryption::start(app.clone());
    let ev = audit(port, &admin).await;
    assert_eq!(ev.len(), 1, "audited at start");
    assert_eq!((ev[0]["details"]["policy"].as_str(), ev[0]["details"]["plaintextAllowed"].as_bool()), (Some("off"), Some(true)), "{}", ev[0]);
    let m = obs::render(&app);
    assert!(m.contains("superbot_backup_encrypted{target=\"server_archives\"} 0") && m.contains("superbot_backup_plaintext_allowed 1"), "{m}");
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], false);
    assert!(item["detail"].as_str().unwrap().starts_with("Plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off)"), "{item}");
}

fn decrypt(data: &[u8], id: &age::x25519::Identity) -> Vec<u8> {
    let d = age::Decryptor::new(data).unwrap();
    let mut r = d.decrypt(std::iter::once(id as &dyn age::Identity)).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    out
}

#[tokio::test]
async fn required_never_copies_a_plain_archive_off_the_host() {
    let (port, app, admin, _) = serve_app().await;
    let s3 = StandIn::start().await;
    let dir = temp_dir("be-copy");
    let mut sb = ServerBackups::with(&dir, Some(Target::new(s3.settings(), "superbot/", Source::Own, Vec::new()).unwrap()));
    sb.encryption = Policy::Required;
    sb.archive_recipients = true;
    app.server_backups.set(Arc::new(sb)).ok().unwrap();
    let name = archive(&dir, HOUR, false, b"written before the recipients were set");
    let b = server_backups::pass(&app).await.expect("a copy attempt");
    assert_eq!(b.state, "failed");
    assert!(b.error.as_deref().unwrap().contains("SUPERBOT_BACKUP_ENCRYPTION=required") && b.error.as_deref().unwrap().contains(&name), "{b:?}");
    assert!(s3.keys().is_empty(), "nothing plain reached the store");
    let (_, body) = call(port, "GET", "/api/audit?action=server.backup_copy_failed", &admin, "").await;
    assert_eq!(audit_list(&body).len(), 1);

    // The next archive superbot-backup writes is encrypted, and is copied as it is.
    let (id, r) = public();
    let to: age::x25519::Recipient = r.parse().unwrap();
    let mut enc = age::Encryptor::with_recipients(std::iter::once(&to as &dyn age::Recipient)).unwrap().wrap_output(Vec::new()).unwrap();
    std::io::Write::write_all(&mut enc, b"the database").unwrap();
    let sealed = enc.finish().unwrap();
    let name = archive(&dir, 0, true, &sealed);
    let b = server_backups::pass(&app).await.expect("a copy");
    assert_eq!((b.state.as_str(), b.encrypted_by.as_deref()), ("done", Some("archive")), "{b:?}");
    let stored = s3.w().objects[&format!("superbot/server/{name}")].clone();
    assert_eq!(decrypt(&stored, &id), b"the database", "restored with the identity");
}
