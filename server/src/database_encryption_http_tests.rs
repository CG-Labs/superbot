//! The database encrypted at rest (ADR 0116): what botd shows and audits about it. A
//! plain database is shown in `/metrics`, the setup checklist and `GET /api/database`, and
//! audited once; encrypting it, its plain copy, deleting the copy, and plain by choice are
//! each audited once more. The file work itself is tested in `database_encryption`.

use crate::database_encryption::{self, Policy, Start, State, PLAIN_COPY_PREFIX};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn temp_dir(name: &str) -> PathBuf {
    let dir = db::temp_path(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn audit(port: u16, admin: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", "/api/audit?action=server.database_encryption_changed", admin, "").await.1)
}

async fn checklist(port: u16, admin: &str) -> Value {
    let (_, body) = call(port, "GET", "/api/setup", admin, "").await;
    parse(&body)["checklist"].as_array().unwrap().iter().find(|i| i["id"] == "database_encryption").unwrap().clone()
}

#[tokio::test]
async fn a_plain_database_is_shown_and_audited_until_it_is_encrypted_and_its_copy_deleted() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("dbe-http");
    app.database.set(State::new(Policy::Auto, Start::default(), &dir)).ok().unwrap();

    assert!(database_encryption::watch(&app));
    assert!(!database_encryption::watch(&app), "the same state is audited once");
    let ev = audit(port, &admin).await;
    assert_eq!(ev.len(), 1);
    let d = &ev[0]["details"];
    assert_eq!(
        (d["policy"].as_str(), d["encrypted"].as_bool(), d["plaintextAllowed"].as_bool(), d["previous"].clone()),
        (Some("auto"), Some(false), Some(false), Value::Null),
        "{d}"
    );
    assert_eq!(
        (ev[0]["actorId"].as_str(), ev[0]["targetType"].as_str(), ev[0]["targetId"].as_str()),
        (Some("database-encryption"), Some("server"), Some("database"))
    );
    let m = obs::render(&app);
    assert!(
        m.contains("superbot_database_encrypted 0") && m.contains("superbot_database_plaintext_allowed 0") && m.contains("superbot_database_plain_copies 0"),
        "{m}"
    );
    assert!(m.contains("event=\"server.database_encryption_changed\""), "counted in superbot_events_total: {m}");
    let types: std::collections::BTreeSet<String> = m.lines().filter_map(|l| Some(l.strip_prefix("# TYPE ")?.split(' ').next()?.to_string())).collect();
    let used = crate::machines_placement_tests::metric_names(include_str!("../../deploy/prometheus/superbot-database-encryption.rules.yml"));
    assert!(!used.is_empty() && used.is_subset(&types), "the rules use metrics botd doesn't write: {:?}", used.difference(&types).collect::<Vec<_>>());
    let item = checklist(port, &admin).await;
    assert_eq!((item["label"].as_str(), item["done"].as_bool()), (Some("Database encrypted"), Some(false)), "{item}");
    assert!(item["detail"].as_str().unwrap().contains("SUPERBOT_DATABASE_ENCRYPTION=required"), "{item}");
    let (code, body) = call(port, "GET", "/api/database", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!(
        (v["policy"].as_str(), v["encrypted"].as_bool(), v["cipher"].clone(), v["ok"].as_bool()),
        (Some("auto"), Some(false), Value::Null, Some(false)),
        "{v}"
    );
    let (_, member) = user_with(port, &admin, "mia@example.com", "member").await;
    assert_eq!(call(port, "GET", "/api/database", &member, "").await.0, 403, "admins only");
}

#[tokio::test]
async fn encrypting_with_a_plain_copy_kept_is_audited_then_deleting_the_copy_closes_the_item() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("dbe-http-migrated");
    app.db.set_setting("database_encryption_state", "auto encrypted=false plain_copies=");
    let copy = format!("{PLAIN_COPY_PREFIX}20261122-120000");
    std::fs::write(dir.join(&copy), b"SQLite format 3\0").unwrap();
    let start = Start { encrypted: true, migrated: Some(copy.clone()), ..Start::default() };
    app.database.set(State::new(Policy::Required, start, &dir)).ok().unwrap();

    database_encryption::start(app.clone());
    let ev = audit(port, &admin).await;
    assert_eq!(ev.len(), 1, "audited at start");
    let d = &ev[0]["details"];
    assert_eq!((d["encrypted"].as_bool(), d["cipher"].as_str(), d["migrated"].as_str()), (Some(true), Some("sqlcipher"), Some(copy.as_str())), "{d}");
    assert_eq!((d["plainCopies"].clone(), d["previous"].as_str()), (json!([copy]), Some("auto encrypted=false plain_copies=")), "{d}");
    let m = obs::render(&app);
    assert!(m.contains("superbot_database_encrypted 1") && m.contains("superbot_database_plain_copies 1"), "{m}");
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], false, "a plain copy is still on disk: {item}");
    assert!(item["detail"].as_str().unwrap().contains(&copy), "{item}");
    let v = parse(&call(port, "GET", "/api/database", &admin, "").await.1);
    assert_eq!((v["key"].as_str(), v["plainCopies"][0]["name"].as_str()), (Some("derived from the master key"), Some(copy.as_str())), "{v}");

    // The operator deletes the copy: the next look audits it and the item is done.
    std::fs::remove_file(dir.join(&copy)).unwrap();
    assert!(database_encryption::watch(&app));
    let ev = audit(port, &admin).await;
    assert_eq!((ev.len(), ev[0]["details"]["plainCopies"].clone(), ev[0]["details"]["migrated"].clone()), (2, json!([]), Value::Null), "{ev:?}");
    assert!(obs::render(&app).contains("superbot_database_plain_copies 0"));
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], true, "{item}");
    assert!(item["detail"].as_str().unwrap().contains("Keep the master key off this host"), "{item}");
}

#[tokio::test]
async fn a_rekey_is_audited_even_when_the_state_is_the_same() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("dbe-http-rekey");
    app.db.set_setting("database_encryption_state", "auto encrypted=true plain_copies=");
    app.database.set(State::new(Policy::Auto, Start { encrypted: true, rekeyed: true, ..Start::default() }, &dir)).ok().unwrap();
    assert!(database_encryption::watch(&app));
    assert!(!database_encryption::watch(&app));
    let ev = audit(port, &admin).await;
    assert_eq!((ev.len(), ev[0]["details"]["rekeyed"].as_bool()), (1, Some(true)), "{ev:?}");
}

#[tokio::test]
async fn plaintext_by_choice_is_audited_and_still_shown() {
    let (port, app, admin, _) = serve_app().await;
    let dir = temp_dir("dbe-http-off");
    app.database.set(State::new(Policy::Off, Start::default(), &dir)).ok().unwrap();
    app.db
        .execute_raw("CREATE TEMP TRIGGER no_dbe BEFORE INSERT ON audit_events WHEN NEW.action = 'server.database_encryption_changed' BEGIN SELECT RAISE(ABORT, 'disk full'); END")
        .unwrap();
    assert!(!database_encryption::watch(&app));
    assert!(app.db.setting("database_encryption_state").is_none(), "the state waits for its event");
    app.db.execute_raw("DROP TRIGGER no_dbe").unwrap();
    assert!(database_encryption::watch(&app));
    let ev = audit(port, &admin).await;
    assert_eq!((ev.len(), ev[0]["details"]["policy"].as_str(), ev[0]["details"]["plaintextAllowed"].as_bool()), (1, Some("off"), Some(true)), "{ev:?}");
    let m = obs::render(&app);
    assert!(m.contains("superbot_database_encrypted 0") && m.contains("superbot_database_plaintext_allowed 1"), "{m}");
    let item = checklist(port, &admin).await;
    assert_eq!(item["done"], false);
    assert!(item["detail"].as_str().unwrap().starts_with("Plain by choice (SUPERBOT_DATABASE_ENCRYPTION=off)"), "{item}");
}
