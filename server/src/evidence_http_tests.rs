//! Evidence bundles (ADR 0142) on the real router and on the schedule: admins only,
//! audited with digests that match, a tarball any `tar` reads whose `SHA256SUMS` checks,
//! each file holding its controls' evidence, and never a secret, a name, an email, a chat,
//! an IP address or a free-text note.

use crate::audit::{Actor, Event, Outcome};
use crate::evidence::{self, Inputs, Period, Settings};
use crate::secrets::redact;
use crate::support::tests::untar;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FILES: [&str; 11] = ["README.txt", "access-review.json", "changes.json", "backups.json", "retention.json", "sign-ins-and-alerts.json", "audit-summary.json", "baseline.json", "audit-integrity.json", "manifest.json", "SHA256SUMS"];

/// A `GET`'s status, response head and body bytes.
async fn fetch(port: u16, path: &str, auth: &str) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {auth}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut res = Vec::new();
    s.read_to_end(&mut res).await.unwrap();
    let split = res.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&res[..split]).to_string();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head, res[split + 4..].to_vec())
}

fn hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
}

/// The files by name inside the bundle's one folder, and the folder.
fn files(tar: &[u8]) -> (String, Vec<(String, String)>) {
    let entries = untar(tar);
    let folder = entries[0].0.split('/').next().unwrap().to_string();
    let f = entries.into_iter().map(|(n, b)| (n.strip_prefix(&format!("{folder}/")).expect("one folder").to_string(), String::from_utf8(b).expect("plain text"))).collect();
    (folder, f)
}

fn file<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
    &files.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name} missing")).1
}

fn today() -> chrono::NaiveDate {
    chrono::Utc::now().date_naive()
}

/// Today and tomorrow, so events recorded now are in the period.
fn now_period() -> String {
    format!("from={}&to={}", today(), today().succ_opt().unwrap())
}

#[tokio::test]
async fn only_admins_get_it_and_its_digests_are_audited() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let (delegate_id, delegate) = user_with(port, &admin, "d@example.com", "member").await;
    let every = ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"];
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Everything delegable", "permissions": every }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    let path = format!("/api/roles/{}/users/{delegate_id}", parse(&role)["id"].as_str().unwrap());
    assert_eq!(call(port, "PUT", &path, &admin, "").await.0, 200);
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for route in ["/api/evidence", "/api/evidence/bundle", "/api/evidence/baseline"] {
        for (who, auth) in [("member", member.as_str()), ("readonly", readonly.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
            assert_eq!(call(port, "GET", route, auth, "").await.0, 403, "{who} {route}");
        }
        assert_eq!(call(port, "GET", route, "", "").await.0, 401, "{route}");
    }

    let (code, head, body) = fetch(port, "/api/evidence/bundle", &admin).await;
    assert_eq!(code, 200, "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: application/x-tar") && lower.contains("cache-control: no-store"), "{head}");
    let last = Period::month_before(today());
    assert!(lower.contains(&format!("filename=\"superbot-evidence-{}-", last.label())), "last month by default: {head}");
    let (folder, f) = files(&body);
    assert_eq!(f.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), FILES);

    // SHA256SUMS checks every other file, and the manifest lists each file's digest.
    let sums = file(&f, "SHA256SUMS");
    assert_eq!(sums.lines().count(), FILES.len() - 1);
    for line in sums.lines() {
        let (digest, name) = line.split_once("  ").unwrap();
        assert_eq!(digest, hex(file(&f, name).as_bytes()), "{name}");
    }
    let manifest = parse(file(&f, "manifest.json"));
    assert_eq!((manifest["format"].as_u64(), manifest["period"]["from"].as_str()), (Some(u64::from(evidence::FORMAT)), Some(last.from.to_string().as_str())));
    for x in manifest["files"].as_array().unwrap() {
        assert_eq!(x["sha256"].as_str().unwrap(), hex(file(&f, x["name"].as_str().unwrap()).as_bytes()), "{x}");
    }
    let access = manifest["files"].as_array().unwrap().iter().find(|x| x["name"] == "access-review.json").unwrap();
    assert_eq!(access["checklist"], json!(["CC6.1-1", "CC6.2-1", "CC6.3-1", "CC6.3-2"]));

    let manifest_digest = hex(file(&f, "manifest.json").as_bytes());
    assert!(lower.contains(&format!("x-evidence-manifest-sha256: {manifest_digest}")), "{head}");
    let (_, audit) = call(port, "GET", "/api/audit?action=evidence.*", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 1, "{events:?}");
    let d = &events[0]["details"];
    assert_eq!(events[0]["action"], evidence::CREATED);
    assert_eq!((d["name"].as_str(), d["manifestSha256"].as_str(), d["sha256"].as_str()), (Some(folder.as_str()), Some(manifest_digest.as_str()), Some(hex(&body).as_str())));
    assert_eq!((d["bytes"].as_u64(), d["scheduled"].as_bool()), (Some(body.len() as u64), Some(false)));

    let dir = crate::db::temp_path("evidence-tar");
    std::fs::write(dir.join("b.tar"), &body).unwrap();
    if let Ok(o) = std::process::Command::new("tar").arg("-tf").arg(dir.join("b.tar")).output() {
        assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains(&format!("{folder}/SHA256SUMS")), "tar reads it");
    }
}

#[tokio::test]
async fn a_period_must_be_whole_days_in_the_past() {
    let (port, _, admin, _) = serve_app().await;
    for q in ["from=2026-01-01", "from=2026-02-01&to=2026-01-01", "from=2020-01-01&to=2026-01-01", "from=yesterday&to=today", "from=2999-01-01&to=2999-02-01"] {
        let (code, body) = call(port, "GET", &format!("/api/evidence/bundle?{q}"), &admin, "").await;
        assert_eq!(code, 400, "{q}: {body}");
    }
    let (_, audit) = call(port, "GET", "/api/audit?action=evidence.*", &admin, "").await;
    assert!(audit_list(&audit).is_empty(), "nothing made");
}

#[tokio::test]
async fn each_file_carries_its_controls_evidence() {
    let (port, app, admin, _) = serve_app().await;
    let (enrolled, _) = user_with(port, &admin, "with-mfa@example.com", "member").await;
    assert!(app.db.mfa_enable(&enrolled, "sealed", 1, &[]));
    let (plain_id, _) = user_with(port, &admin, "plain@example.com", "readonly").await;
    let sys = |a: &str| Event::new(Actor::system("server"), a);
    app.db.record(&sys("server.started").details(json!({ "version": "0.0.9" })));
    app.db.record(&sys("server.started").details(json!({ "version": "0.1.0", "mfaPolicy": "admins" })));
    app.db.record(&sys("server.backup_copied").target("server_backup", "superbot-20261122T031500Z.tar.gz.age").details(json!({ "bytes": 1234, "encrypted": true })));
    app.db.record(&sys("machine.restored").target("machine", "m1a2b3c4").details(json!({ "durationMs": 61_000, "rtoMinutes": 60 })));
    app.db.record(&sys("chat.pruned").details(json!({ "deleted": 7 })));
    app.db.record(&Event::new(Actor::system("sso"), "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "not_linked" })));
    app.db.record(&Event::new(Actor::system("signin-watch"), "auth.suspicious_sign_in").outcome(Outcome::Denied).details(json!({ "pattern": "burst_ip", "failures": 12 })));
    let sa = crate::service_accounts_http_tests::account(port, &admin, json!({ "name": "Nightly export", "description": "Free text" })).await;
    let _ = crate::service_accounts_http_tests::token(port, &admin, &sa, json!({ "name": "Cron job", "scopes": ["read"] })).await;
    let auditor = crate::service_accounts_http_tests::role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    let ends = crate::db::now() + crate::roles::DAY;
    let (code, body) = call(port, "PUT", &format!("/api/roles/{auditor}/users/{plain_id}"), &admin, &json!({ "expiresAt": ends }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    let (code, body) = call(port, "GET", "/api/access-review", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let digest = parse(&body)["digest"].as_str().unwrap().to_string();
    let (code, body) = call(port, "POST", "/api/access-review/complete", &admin, &json!({ "digest": digest, "notes": "All good" }).to_string()).await;
    assert_eq!(code, 201, "{body}");

    let (code, _, body) = fetch(port, &format!("/api/evidence/bundle?{}", now_period()), &admin).await;
    assert_eq!(code, 200);
    let (_, f) = files(&body);

    let access = parse(file(&f, "access-review.json"));
    let people = access["people"].as_array().unwrap();
    let person = |id: &str| people.iter().find(|p| p["id"] == id).cloned().expect("everyone who can sign in is listed");
    assert_eq!((person(&enrolled)["role"].as_str(), person(&enrolled)["mfa"]["enabled"].as_bool()), (Some("member"), Some(true)));
    assert_eq!((person(&plain_id)["role"].as_str(), person(&plain_id)["mfa"]["enabled"].as_bool()), (Some("readonly"), Some(false)));
    assert_eq!(person(&plain_id)["customRole"], json!({ "id": auditor, "permissions": ["audit.view"], "expiresAt": ends }), "when a role ends (ADR 0197)");
    assert!(person(&enrolled)["customRole"].is_null());
    assert_eq!((person(users::OPERATOR)["admin"].as_bool(), person(users::OPERATOR)["breakGlass"].as_bool()), (Some(true), Some(true)));
    assert_eq!(access["summary"]["people"].as_u64(), Some(people.len() as u64));
    assert_eq!(access["reviewsSignedOffInPeriod"], 1);
    assert_eq!(access["mfaPolicy"], "off");
    let signoff = access["period"]["events"].as_array().unwrap().iter().find(|e| e["action"] == "access_review.completed").cloned().unwrap();
    assert_eq!(signoff["details"]["digest"].as_str(), Some(digest.as_str()), "{signoff}");
    assert!(signoff["details"].get("notes").is_none(), "notes are free text: {signoff}");
    assert!(access["period"]["counts"]["user.created"]["success"].as_u64() >= Some(2), "{access}");
    // Service accounts (ADR 0165): ids, roles and token scopes, never their names or a token's.
    let s = &access["serviceAccounts"][0];
    assert_eq!((s["id"].as_str(), s["owner"].as_str(), s["role"].as_str(), s["tokens"][0]["scopes"].clone()), (Some(sa.as_str()), Some(users::OPERATOR), Some("readonly"), json!(["read"])), "{access}");
    assert_eq!(s["ownerOnTeam"], Value::Null, "in no team: {access}");
    let text = access["serviceAccounts"].to_string();
    assert!(!text.contains("Nightly export") && !text.contains("Free text") && !text.contains("Cron job") && !text.contains("sbsa_"), "{text}");
    assert_eq!(access["period"]["counts"]["service_token.created"]["success"], 1, "{access}");
    assert_eq!(access["periodCovered"]["days"], 1);

    let changes = parse(file(&f, "changes.json"));
    assert_eq!(changes["botdNow"], env!("CARGO_PKG_VERSION"));
    let versions: Vec<&str> = changes["starts"].as_array().unwrap().iter().filter_map(|s| s["version"].as_str()).collect();
    assert!(versions.ends_with(&["0.0.9", "0.1.0"]), "{changes}");
    let last = changes["versionChanges"].as_array().unwrap().last().cloned().unwrap();
    assert_eq!((last["from"].as_str(), last["to"].as_str()), (Some("0.0.9"), Some("0.1.0")), "{changes}");

    let backups = parse(file(&f, "backups.json"));
    let copied = &backups["period"]["counts"]["server.backup_copied"]["success"];
    assert_eq!(copied, 1, "{backups}");
    let day = today().to_string();
    assert_eq!(backups["period"]["daily"][&day]["machine.restored success"], 1, "{backups}");
    let restored = backups["period"]["events"].as_array().unwrap().iter().find(|e| e["action"] == "machine.restored").cloned().unwrap();
    assert_eq!((restored["target"]["id"].as_str(), restored["details"]["durationMs"].as_u64()), (Some("m1a2b3c4"), Some(61_000)));

    let retention = parse(file(&f, "retention.json"));
    assert_eq!(retention["auditKeepsPeriodPlusYear"], true, "no audit retention keeps everything");
    assert_eq!(retention["period"]["counts"]["chat.pruned"]["success"], 1);

    let signins = parse(file(&f, "sign-ins-and-alerts.json"));
    assert_eq!(signins["counts"]["auth.login_failed"]["failure"], 1, "{signins}");
    let watch = signins["events"].as_array().unwrap().iter().find(|e| e["action"] == "auth.suspicious_sign_in").cloned().unwrap();
    assert_eq!((watch["details"]["pattern"].as_str(), watch["details"]["failures"].as_u64()), (Some("burst_ip"), Some(12)));

    let summary = parse(file(&f, "audit-summary.json"));
    let all = app.db.audit_events(&audit::Filter { from: Some(Period::parse(Some(&day), Some(&today().succ_opt().unwrap().to_string()), today()).unwrap().start_ms()), ..Default::default() }, 100_000, true);
    let before: Vec<_> = all.iter().filter(|e| e.action != evidence::CREATED).collect();
    assert_eq!(summary["events"].as_u64(), Some(before.len() as u64), "{summary}");
    let mut h = Sha256::new();
    for e in &before {
        h.update(format!("{}\t{}\t{}\t{}\n", e.id, e.at, e.action, e.outcome).as_bytes());
    }
    let want: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(summary["digest"].as_str(), Some(want.as_str()), "the digest is reproducible from the audit log");

    // The configuration baseline as botd ran (ADR 0195): every setting, and the MFA policy
    // in force, here off, as a deviation.
    let baseline = parse(file(&f, "baseline.json"));
    assert_eq!(baseline["settings"].as_array().unwrap().len(), crate::baseline::SETTINGS.len());
    let row = baseline["settings"].as_array().unwrap().iter().find(|s| s["setting"] == "AUTH_MFA").cloned().unwrap();
    assert_eq!((row["status"].as_str(), row["value"].as_str()), (Some("fail"), Some("off")), "{row}");
    assert!(baseline["exceptions"]["deviations"].as_array().unwrap().contains(&json!("AUTH_MFA")), "{baseline}");
    assert_eq!(baseline["ok"], false);
    let manifest = parse(file(&f, "manifest.json"));
    let listed = manifest["files"].as_array().unwrap().iter().find(|x| x["name"] == "baseline.json").cloned().unwrap();
    assert_eq!((listed["criteria"].clone(), listed["checklist"].clone()), (json!(["CC5.1"]), json!(["CC5.1-1"])));
}

#[tokio::test]
async fn the_baseline_check_is_audited_with_its_digest_and_follows_the_mfa_policy() {
    let (port, app, admin, _) = serve_app().await;
    let (code, body) = call(port, "GET", "/api/evidence/baseline", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["format"], crate::baseline::FORMAT);
    assert_eq!(r["settings"].as_array().unwrap().len(), crate::baseline::SETTINGS.len());
    assert_eq!(r["counts"].as_object().unwrap().values().filter_map(Value::as_u64).sum::<u64>(), crate::baseline::SETTINGS.len() as u64);
    let (_, audit) = call(port, "GET", &format!("/api/audit?action={}", crate::baseline::CHECKED), &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 1, "{events:?}");
    let d = &events[0]["details"];
    assert_eq!((d["digest"].clone(), d["ok"].clone(), d["counts"].clone()), (r["digest"].clone(), r["ok"].clone(), r["counts"].clone()));
    assert!(d["deviations"].as_array().unwrap().contains(&json!("AUTH_MFA")), "{d}");
    assert!(d.get("settings").is_none(), "counts and names only: {d}");

    // An admin's policy, as the route reads it; over HTTP this admin would now need a second factor.
    let r2 = crate::baseline::run(&app, crate::mfa::Policy::Admins).view("now");
    let row = r2["settings"].as_array().unwrap().iter().find(|s| s["setting"] == "AUTH_MFA").cloned().unwrap();
    assert_eq!((row["status"].as_str(), row["value"].as_str()), (Some("pass"), Some("admins")), "{row}");
    assert_ne!(r2["digest"], r["digest"], "a different setting, a different digest");
}

#[tokio::test]
async fn no_secret_name_email_chat_ip_or_note_reaches_the_bundle() {
    let (port, app, admin, _) = serve_app().await;
    let secret = format!("plainly-secret-{}", random_hex(8));
    redact::register(&secret);
    let name = format!("Jane Q Customer {}", random_hex(3));
    let email = format!("jane-{}@customer.example.com", random_hex(4));
    let (code, body) = call(port, "POST", "/api/users", &admin, &json!({ "email": email, "name": name, "role": "member" }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let chat = format!("chat-words-{}", random_hex(6));
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    app.db.add_message(&bot.id, "user", &chat, None, false, None);
    let hold = format!("Litigation with Acme {}", random_hex(3));
    app.db.put_retention_hold(&bot.id, &hold, Some(users::OPERATOR));
    let mut actor = Actor::operator();
    actor.email = Some(email.clone());
    actor.name = Some(name.clone());
    app.db.record(&Event::new(actor, "auth.login_failed").outcome(Outcome::Failure).target("user", &email).details(json!({ "reason": format!("bad code for {email} from 203.0.113.9"), "email": email, "ip": "203.0.113.9", "token": secret })));
    app.db.record(&Event::new(Actor::system("server"), "user.updated").details(json!({ "changes": { "name": { "from": "ada", "to": name } }, "from": email })));
    let (code, body) = call(port, "GET", "/api/access-review", &admin, "").await;
    assert_eq!(code, 200);
    let digest = parse(&body)["digest"].as_str().unwrap().to_string();
    let note = format!("Checked with {name}");
    assert_eq!(call(port, "POST", "/api/access-review/complete", &admin, &json!({ "digest": digest, "notes": note }).to_string()).await.0, 201);

    let (code, _, body) = fetch(port, &format!("/api/evidence/bundle?{}", now_period()), &admin).await;
    assert_eq!(code, 200);
    let text = String::from_utf8_lossy(&body);
    for (what, v) in [("secret", secret.as_str()), ("name", name.as_str()), ("email", email.as_str()), ("email domain", "customer.example.com"), ("chat", chat.as_str()), ("hold reason", hold.as_str()), ("IP address", "203.0.113.9"), ("note", note.as_str()), ("bot name", "Walker")] {
        assert!(!text.contains(v), "the {what} is in the bundle");
    }
    let (_, f) = files(&body);
    let signins = parse(file(&f, "sign-ins-and-alerts.json"));
    let failed = signins["events"].as_array().unwrap().iter().find(|e| e["action"] == "auth.login_failed").cloned().unwrap();
    assert_eq!(failed["details"], json!({ "reason": "[text]" }), "{failed}");
    assert_eq!(failed["target"]["id"], "[email]", "{failed}");
    let retention = parse(file(&f, "retention.json"));
    assert_eq!(retention["holds"][0]["botId"].as_str(), Some(bot.id.as_str()), "{retention}");
    redact::forget(&secret);
}

#[tokio::test]
async fn the_schedule_writes_last_month_once_and_prunes_past_retention() {
    let (port, app, admin, _) = serve_app().await;
    let dir = crate::db::temp_path("evidence-schedule").join("evidence");
    let s = Settings { monthly: true, dir: dir.clone(), keep_days: Some(30) };
    let _ = app.evidence.set(Arc::new(s.clone()));
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Admins };
    std::fs::create_dir_all(&dir).unwrap();
    let old = "superbot-evidence-2020-01-01_2020-02-01-20200201T010000Z.tar";
    std::fs::write(dir.join(old), b"old").unwrap();
    std::fs::write(dir.join("notes.txt"), b"not a bundle").unwrap();

    let mut failed = None;
    evidence::tick(&app, &s, &inputs, db::now(), &mut failed);
    evidence::tick(&app, &s, &inputs, db::now(), &mut failed);
    let have = evidence::bundles(&dir);
    assert_eq!(have.len(), 1, "one bundle for last month, written once, the old one pruned: {have:?}");
    assert_eq!(have[0].2, Period::month_before(today()));
    assert!(dir.join("notes.txt").exists(), "only bundles are pruned");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(&have[0].0)).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let tar = std::fs::read(dir.join(&have[0].0)).unwrap();
    let (_, f) = files(&tar);
    assert_eq!(parse(file(&f, "manifest.json"))["scheduled"], true);
    assert_eq!(parse(file(&f, "access-review.json"))["mfaPolicy"], "admins");

    let (_, audit) = call(port, "GET", "/api/audit?action=evidence.*", &admin, "").await;
    let events = audit_list(&audit);
    let actions: Vec<&str> = events.iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, [evidence::PRUNED, evidence::CREATED], "{events:?}");
    assert_eq!(events[0]["details"]["names"], json!([old]));
    assert_eq!((events[1]["actorKind"].as_str(), events[1]["details"]["manifestSha256"].as_str()), (Some("system"), Some(hex(file(&f, "manifest.json").as_bytes()).as_str())));

    let (code, body) = call(port, "GET", "/api/evidence", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["schedule"].as_str(), v["keepDays"].as_u64()), (Some("monthly"), Some(30)));
    assert_eq!(v["bundles"][0]["name"].as_str(), Some(have[0].0.as_str()), "{v}");
    assert_eq!(v["newest"]["scheduled"], true, "{v}");
}

#[tokio::test]
async fn a_bundle_that_cant_be_written_is_audited_once() {
    let app = runner::test_app();
    let file = crate::db::temp_path("evidence-blocked").join("in-the-way");
    std::fs::write(&file, b"a file where the folder should be").unwrap();
    let s = Settings { monthly: true, dir: file.clone(), keep_days: None };
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Off };
    let mut failed = None;
    for _ in 0..3 {
        evidence::tick(&app, &s, &inputs, db::now(), &mut failed);
    }
    let f = audit::Filter { actions: vec!["evidence.*".into()], ..Default::default() };
    let events = app.db.audit_events(&f, 10, true);
    assert_eq!(events.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), [evidence::FAILED], "once, not every hour");
    assert_eq!(events[0].outcome, "failure");
    assert_eq!(failed, Some(Period::month_before(today())));
}

#[test]
fn every_deployment_is_listed_however_many_other_changes_there_are() {
    let app = runner::test_app();
    let actor = || Actor::system("test");
    app.db.record(&Event::new(actor(), "server.started").details(json!({ "version": "0.1.0" })));
    for _ in 0..5_001 {
        app.db.record(&Event::new(actor(), "policy.updated").details(json!({ "after": { "mode": "ask" } })));
    }
    app.db.record(&Event::new(actor(), "server.started").details(json!({ "version": "0.2.0" })));
    let p = Period { from: today(), to: today().succ_opt().unwrap() };
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Off };
    let (_, f) = files(&evidence::build(&app, &inputs, &p, db::now(), false).tar);
    let c = parse(file(&f, "changes.json"));
    assert!(c["period"]["eventsTotal"].as_u64() > c["period"]["eventsListed"].as_u64(), "past the listing cap: {}", c["period"]["eventsTotal"]);
    let versions: Vec<&str> = c["starts"].as_array().unwrap().iter().map(|s| s["version"].as_str().unwrap()).collect();
    assert_eq!(versions, ["0.1.0", "0.2.0"], "a start past the listing cap is still a deployment");
    assert_eq!(c["versionChanges"].as_array().unwrap().last().unwrap()["to"], "0.2.0");
}

#[tokio::test]
async fn a_month_already_past_retention_is_never_written() {
    let app = runner::test_app();
    let dir = crate::db::temp_path("evidence-short").join("evidence");
    let s = Settings { monthly: true, dir: dir.clone(), keep_days: Some(1) };
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Off };
    let at = |d: &str| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap().and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp_millis();
    let mut failed = None;
    evidence::tick(&app, &s, &inputs, at("2026-11-01"), &mut failed);
    assert_eq!(evidence::bundles(&dir).len(), 1, "written on the 1st");
    for day in ["2026-11-03", "2026-11-04", "2026-11-05"] {
        evidence::tick(&app, &s, &inputs, at(day), &mut failed);
        assert!(evidence::bundles(&dir).is_empty(), "pruned and not written again on {day}");
    }
    let f = audit::Filter { actions: vec!["evidence.*".into()], ..Default::default() };
    let actions: Vec<String> = app.db.audit_events(&f, 10, true).into_iter().map(|e| e.action).collect();
    assert_eq!(actions, [evidence::CREATED, evidence::PRUNED], "once each, not every hour");
}

fn listed(manifest: &Value, name: &str) -> (Value, Value) {
    let x = manifest["files"].as_array().unwrap().iter().find(|x| x["name"] == name).cloned().unwrap();
    (x["criteria"].clone(), x["checklist"].clone())
}

/// `audit-integrity.json` (ADR 0261): the chain's checks, checkpoints and export over the
/// period, naming CC2.1-2 and CC7.2-2 only while the period shows them holding, and the
/// period's last checkpoint, which a later check holds the log to.
#[tokio::test]
async fn the_audit_logs_guarding_is_evidence_only_while_it_held() {
    let (port, app, admin, _) = serve_app().await;
    let p = Period { from: today(), to: today().succ_opt().unwrap() };
    let inputs = Inputs { sessions: users::SessionConfig::default(), mfa: mfa::Policy::Off };
    let integrity = |app: &AppState| {
        let (_, f) = files(&evidence::build(app, &inputs, &p, db::now(), false).tar);
        (parse(file(&f, "audit-integrity.json")), parse(file(&f, "manifest.json")))
    };
    let by = audit::Who::system("audit_checkpoint");
    app.db.record(&Event::new(Actor::system("test"), "user.created"));
    crate::audit_chain::daily(&app).await;
    crate::audit_checkpoint::create(&app, &by, crate::audit_checkpoint::Trigger::Schedule).unwrap();

    // Checked and signed, but nothing ships it off the server: neither row.
    let (v, m) = integrity(&app);
    assert_eq!((v["summary"]["exportedEveryEvent"].clone(), v["summary"]["guardedThroughout"].clone()), (json!(false), json!(false)), "{v}");
    assert_eq!(v["exceptions"]["off"], json!(["export"]));
    assert_eq!(listed(&m, "audit-integrity.json"), (json!([]), json!([])));
    assert_eq!((v["checks"][0]["ok"].clone(), v["checks"][0]["whole"].clone(), v["daily"][today().to_string()]["checkpoints"].clone()), (json!(true), json!(true), json!(1)), "{v}");

    // A webhook that fails three times, then takes everything.
    let token = "siem-token-for-evidence-7c6b5a49";
    let (url, _) = crate::audit_chain_http_tests::collector(3).await;
    crate::audit_chain_http_tests::export_to(&app, &[("AUDIT_EXPORT", &url), ("AUDIT_EXPORT_HEADERS", &format!("Authorization=Bearer {token}"))]);
    let delivered = || app.audit_export.get().is_some_and(|x| x.delivered() >= app.db.audit_head());
    crate::audit_chain_http_tests::until("recovery", || app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_recovered")).await;
    crate::audit_chain::daily(&app).await;
    let cp = crate::audit_checkpoint::create(&app, &by, crate::audit_checkpoint::Trigger::Schedule).unwrap();
    crate::audit_chain_http_tests::until("delivery", delivered).await;
    let (v, m) = integrity(&app);
    assert_eq!((v["summary"]["exportedEveryEvent"].clone(), v["summary"]["guardedThroughout"].clone()), (json!(true), json!(true)), "{v}");
    assert_eq!(listed(&m, "audit-integrity.json"), (json!(["CC2.1", "CC7.2"]), json!(["CC2.1-2", "CC7.2-2"])));
    let sink = &v["export"]["sinks"][0];
    assert_eq!((sink["kind"].as_str(), sink["deliveredThroughPeriod"].as_bool()), (Some("webhook"), Some(true)), "{v}");
    let failure = &v["exceptions"]["exportFailures"][0];
    assert_eq!((failure["kind"].as_str(), failure["reason"].as_str()), (Some("webhook"), Some("delivery_failed")), "{v}");
    let text = v.to_string();
    assert!(!text.contains("127.0.0.1") && !text.contains(token) && !text.contains("ingest"), "no sink address or header: {text}");
    let pin = &v["periodEndCheckpoint"];
    assert_eq!((pin["event"].as_i64(), pin["seq"].as_i64(), pin["hash"].as_str()), (Some(cp.id), Some(cp.seq), Some(cp.hash.as_str())), "{v}");
    assert_eq!(pin["signature"].as_str(), Some(cp.signature.as_str()), "the signature survives the bundle's scrubbing");
    assert_eq!((v["chain"]["head"]["hash"].as_str().map(str::len), v["chain"]["lastCheck"]["ok"].as_bool()), (Some(64), Some(true)), "{v}");
    let (cut, criteria, rows) = crate::evidence_integrity::begin(&app, &p).finish(&app, Some(app.db.audit_head()), false, db::now());
    assert_eq!((criteria.len(), rows.len(), cut["summary"]["exportedEveryEvent"].as_bool()), (0, 0, Some(false)), "a scan cut short proves neither: {cut}");
    assert_eq!(cut["exceptions"]["periodNotFullyRead"].as_array().map(Vec::len), Some(1), "{cut}");
    let (code, body) = call(port, "GET", &format!("/api/audit/verify?pin={}:{}", cp.seq, cp.hash), &admin, "").await;
    assert_eq!((code, parse(&body)["pins"][0]["result"].as_str().map(String::from)), (200, Some("match".into())), "the month's pin holds the log: {body}");

    // An earlier period, checked within it and shipped.
    let earlier = Period { from: today().pred_opt().unwrap(), to: today() };
    let check = Event::new(Actor::system("audit_chain"), "audit.verified").details(json!({ "ok": true, "checked": 1 }));
    app.db.record_at(&check, earlier.start_ms() + 12 * 3_600_000).unwrap();
    crate::audit_chain_http_tests::until("delivery", delivered).await;
    let before = |app: &AppState| {
        let (_, f) = files(&evidence::build(app, &inputs, &earlier, db::now(), false).tar);
        (parse(file(&f, "audit-integrity.json")), parse(file(&f, "manifest.json")))
    };
    let (v, m) = before(&app);
    assert_eq!(listed(&m, "audit-integrity.json"), (json!(["CC2.1", "CC7.2"]), json!(["CC2.1-2", "CC7.2-2"])), "{v}");

    // A row changed: the next check fails, so the log wasn't guarded, though it was shipped.
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    app.db.execute_raw("UPDATE audit_events SET action = 'user.updated' WHERE action = 'user.created'").unwrap();
    crate::audit_chain::daily(&app).await;
    crate::audit_chain_http_tests::until("delivery", delivered).await;
    let (v, m) = integrity(&app);
    assert_eq!(v["summary"]["guardedThroughout"], false, "{v}");
    assert_eq!(listed(&m, "audit-integrity.json"), (json!(["CC2.1"]), json!(["CC2.1-2"])));
    assert_eq!(v["exceptions"]["lastCheckFailed"][0]["reason"], "contents", "{v}");
    assert_eq!(v["exceptions"]["failedChecks"].as_array().unwrap().len(), 1, "{v}");

    // That later failure takes CC7.2-2 back from the earlier period too.
    let (v, m) = before(&app);
    assert_eq!(listed(&m, "audit-integrity.json"), (json!(["CC2.1"]), json!(["CC2.1-2"])), "{v}");
    assert_eq!((v["chain"]["lastCheck"]["reason"].as_str(), v["chain"]["periodLastCheck"]["ok"].as_bool()), (Some("contents"), Some(true)), "{v}");
    assert_eq!(v["exceptions"]["lastCheckFailed"][0]["reason"], "contents", "{v}");
}
