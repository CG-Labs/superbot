//! The support bundle (ADR 0131) on the real router: admins only (no custom role reaches
//! it, ADR 0123), audited, a tarball any `tar` reads, with the files support needs, and
//! never a secret, an email or a chat.

use crate::audit::{Actor, Event, Outcome};
use crate::obs::log::{Level, log_warn, recent, render};
use crate::secrets::redact;
use crate::support::tests::untar;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FILES: [&str; 9] = ["README.txt", "version.json", "config.json", "health.json", "health-score.json", "health-score-history.json", "logs.jsonl", "audit-summary.json", "manifest.json"];

/// `GET /api/support/bundle`: the status, the response head, and the body's bytes.
async fn fetch(port: u16, auth: &str) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET /api/support/bundle HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {auth}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut res = Vec::new();
    s.read_to_end(&mut res).await.unwrap();
    let split = res.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&res[..split]).to_string();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head, res[split + 4..].to_vec())
}

/// The bundle's files by their name inside its folder, as text.
fn files(tar: &[u8]) -> Vec<(String, String)> {
    let entries = untar(tar);
    let folder = entries[0].0.split('/').next().unwrap().to_string();
    assert!(folder.starts_with("superbot-support-") && folder.ends_with('Z'), "{folder}");
    entries
        .into_iter()
        .map(|(n, b)| (n.strip_prefix(&format!("{folder}/")).expect("one folder").to_string(), String::from_utf8(b).expect("plain text")))
        .collect()
}

fn file<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
    &files.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name} missing")).1
}

#[tokio::test]
async fn only_admins_get_it_and_it_is_audited() {
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
    for (who, auth) in [("member", member.as_str()), ("readonly", readonly.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", "/api/support/bundle", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/bundle", "", "").await.0, 401);
    let (_, audit) = call(port, "GET", "/api/audit?action=support.*", &admin, "").await;
    assert!(audit_list(&audit).is_empty(), "nothing made yet");

    let (code, head, body) = fetch(port, &admin).await;
    assert_eq!(code, 200, "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: application/x-tar"), "{head}");
    assert!(lower.contains("content-disposition: attachment; filename=\"superbot-support-"), "{head}");
    assert!(lower.contains("cache-control: no-store"), "{head}");
    let f = files(&body);
    assert_eq!(f.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), FILES);

    let (_, audit) = call(port, "GET", "/api/audit?action=support.*", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["action"], "support.bundle_created");
    assert_eq!(events[0]["details"]["bytes"], body.len());
    assert_eq!(events[0]["details"]["files"], json!(FILES));
}

#[tokio::test]
async fn it_carries_what_support_asks_for_first() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    app.db.add_approval(&bot.id, "claude", "Bash", "shell", "rm -rf build", &json!({}), "shell_destructive", "asks", db::now() + 600_000);
    app.db.record(&Event::new(Actor::system("sso"), "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "not_linked" })));
    let f = files(&fetch(port, &admin).await.2);

    let version = parse(file(&f, "version.json"));
    assert_eq!(version["botd"], env!("CARGO_PKG_VERSION"));
    assert_eq!(version["product"], "SuperBot");

    let health = parse(file(&f, "health.json"));
    assert_eq!(health["approvals"]["pending"], 1, "{health}");
    assert!(health["approvals"]["oldestPendingSeconds"].is_u64(), "{health}");
    assert_eq!(health["status"]["components"][0]["id"], "api", "{health}");
    let score = parse(file(&f, "health-score.json"));
    assert_eq!(score["windowDays"], 30, "{score}");
    let ids: Vec<_> = score["signals"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, crate::health_score::SIGNALS.iter().map(|s| s.id).collect::<Vec<_>>(), "{score}");
    assert_eq!(score["signals"][4]["facts"]["pendingNow"], 1, "the approval waiting: {score}");
    let history = parse(file(&f, "health-score-history.json"));
    assert_eq!((history["days"].as_i64(), history["points"].as_array().map(Vec::len)), (Some(90), Some(0)), "nothing recorded yet: {history}");
    assert!(health["setup"]["checklist"].as_array().is_some_and(|c| c.iter().any(|i| i["id"] == "backups")), "{health}");
    assert!(health["license"]["summary"].is_object(), "{health}");

    let config = parse(file(&f, "config.json"));
    assert!(config["environment"].is_object() && config["redacted"].is_array(), "{config}");
    assert_eq!(config["policy"]["mode"], "ask", "{config}");
    assert_eq!(config["tiers"]["default"], "self-host", "{config}");

    let audit = parse(file(&f, "audit-summary.json"));
    let failed = audit["byAction"].as_array().unwrap().iter().find(|a| a["action"] == "auth.login_failed").cloned().unwrap_or_default();
    assert_eq!(failed["outcomes"]["failure"], 1, "{audit}");
    let problem = audit["recentProblems"].as_array().unwrap().iter().find(|p| p["action"] == "auth.login_failed").cloned().unwrap_or_default();
    assert_eq!((problem["reason"].as_str(), problem["outcome"].as_str()), (Some("not_linked"), Some("failure")), "{audit}");

    let manifest = parse(file(&f, "manifest.json"));
    assert_eq!(manifest["format"], support::FORMAT);
    let listed: Vec<&str> = manifest["files"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(listed, FILES[..FILES.len() - 1], "the manifest lists the files before it");
    for (name, body) in &f[..FILES.len() - 1] {
        let bytes = manifest["files"].as_array().unwrap().iter().find(|x| x["name"] == name.as_str()).unwrap()["bytes"].as_u64().unwrap();
        assert_eq!(bytes as usize, body.len(), "{name}");
    }
    assert!(file(&f, "logs.jsonl").lines().all(|l| l.starts_with('{')), "one JSON line each");
}

#[tokio::test]
async fn no_secret_email_or_chat_reaches_the_bundle() {
    let (port, app, admin, _) = serve_app().await;
    let secret = format!("plainly-secret-{}", random_hex(8));
    redact::register(&secret);
    let session = users::new_secret(users::SESSION_PREFIX);
    let chat = format!("chat-words-{}", random_hex(6));
    let email = format!("person-{}@customer.example.com", random_hex(4));
    let hook = format!("https://hooks.slack.com/services/T0/B0/{}", random_hex(12));
    // Straight into the kept lines: the test's secrets never go to stdout.
    recent::push(render(Level::Warn, &format!("provider said {secret} for {email} with {session} posting to {hook}"), json!({})));
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    app.db.add_message(&bot.id, "user", &chat, None, false, None);
    let mut actor = Actor::operator();
    actor.email = Some(email.clone());
    app.db.record(&Event::new(actor, "auth.login_failed").outcome(Outcome::Denied).details(json!({ "reason": "wrong_tenant", "email": email })));
    let path = format!("/clients/Jane Smith {}/notes.txt", random_hex(4));
    app.db.record(&Event::new(Actor::system("policy"), "policy.denied").outcome(Outcome::Denied).details(json!({ "reason": format!("Deletes {path} outside the workspace") })));

    let (code, _, body) = fetch(port, &admin).await;
    assert_eq!(code, 200);
    let text = String::from_utf8_lossy(&body);
    for (what, v) in [("registered secret", secret.as_str()), ("session token", session.as_str()), ("email", email.as_str()), ("chat", chat.as_str()), ("webhook path", "/services/T0/B0/"), ("tool input", "Jane Smith")] {
        assert!(!text.contains(v), "the {what} is in the bundle");
    }
    let f = files(&body);
    let audit = parse(file(&f, "audit-summary.json"));
    let reasons: Vec<(&str, &str)> = audit["recentProblems"].as_array().unwrap().iter().map(|p| (p["action"].as_str().unwrap(), p["reason"].as_str().unwrap_or_default())).collect();
    assert!(reasons.contains(&("policy.denied", "[text]")) && reasons.contains(&("auth.login_failed", "wrong_tenant")), "{reasons:?}");
    let logs = file(&f, "logs.jsonl");
    let line = logs.lines().find(|l| l.contains("provider said")).expect("the warning is logged");
    assert!(line.contains("provider said [redacted] for [email] with [redacted] posting to https://hooks.slack.com/[redacted]"), "{line}");
    redact::forget(&secret);
}

/// The licensee is named by the license, the setup checklist and the start event; none of
/// them, nor an IP address anywhere, reaches the bundle.
#[tokio::test]
async fn the_licensee_and_ip_addresses_stay_out() {
    let (port, app, admin, _) = serve_app().await;
    let mut c = crate::license::test_keys::claims(Some(25), 200);
    c.sub = format!("Northwind Traders {}", random_hex(4));
    let (code, body) = call(port, "PUT", "/api/license", &admin, &json!({ "key": crate::license::test_keys::mint(&c) }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    log_warn!("WARNING: {} reached 203.0.113.9:443 and 2001:db8::7 from 127.0.0.1", c.sub.to_uppercase());

    let (code, _, body) = fetch(port, &admin).await;
    assert_eq!(code, 200);
    let text = String::from_utf8_lossy(&body);
    for v in [c.sub.as_str(), &c.sub.to_uppercase(), "Northwind", "203.0.113.9", "2001:db8::7"] {
        assert!(!text.contains(v), "{v} is in the bundle");
    }
    let f = files(&body);
    let license = &parse(file(&f, "health.json"))["license"];
    assert_eq!(license["summary"]["licensee"], "[name]", "{license}");
    assert!(license["detail"].as_str().unwrap().starts_with("Licensed to [name] (business"), "{license}");
    let line = file(&f, "logs.jsonl").lines().find(|l| l.contains("reached [ip]")).expect("the warning is logged");
    assert!(line.contains("[name] reached [ip]:443 and [ip] from 127.0.0.1"), "{line}");
    assert_eq!(app.license.status().claims.map(|c| c.sub), Some(c.sub.clone()), "only the bundle hides it");
}

/// The environment, as `build` gets it: secrets by name and by shape, and secrets botd
/// knows, wherever they are, never reach any file.
#[tokio::test]
async fn settings_are_redacted_by_name_shape_and_known_value() {
    let (_, app, _, _) = serve_app().await;
    let known = format!("known-{}", random_hex(10));
    redact::register(&known);
    let api_key = format!("sk-ant-api03-{}", random_hex(20));
    let generated = format!("Q{}z", random_hex(16));
    let s3 = format!("wJalrXUtnFEMI/{}", random_hex(8));
    let vars: Vec<(String, String)> = [
        ("ANTHROPIC_API_KEY", api_key.clone()),
        ("SERVER_BACKUP_S3_SECRET_ACCESS_KEY", s3.clone()),
        ("SMTP_URL", format!("smtp://mailer:{known}@smtp.example.com:587")),
        ("MACHINE_LABEL_PREFIX", generated.clone()),
        ("ERROR_REPORT_DSN", format!("https://{}@o1.ingest.example.com/2", random_hex(16))),
        ("PRIMARY_BOT_NAME", format!("prefix {known} suffix")),
        ("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock".into()),
        ("OWNER_EMAIL", "owner@customer.example.com".into()),
        ("SUPERBOT_MASTER_KEY_FILE", "/etc/superbot/master.key".into()),
        ("PORT", "3000".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let b = support::build(&app, &vars, json!({}), db::now());
    let text = String::from_utf8_lossy(&b.tar);
    for v in [known.as_str(), api_key.as_str(), s3.as_str(), generated.as_str(), "owner@customer.example.com", "mailer:"] {
        assert!(!text.contains(v), "{v} is in the bundle");
    }
    let f = files(&b.tar);
    let env = &parse(file(&f, "config.json"))["environment"];
    assert_eq!(env["SMTP_URL"], "smtp://[redacted]@smtp.example.com:587");
    assert_eq!(env["PRIMARY_BOT_NAME"], "prefix [redacted] suffix");
    assert!(env.get("SSH_AUTH_SOCK").is_none(), "the host's own variables stay out");
    assert_eq!(parse(file(&f, "config.json"))["otherVariables"], 1);
    assert!(!text.contains("ssh-agent.sock"));
    assert_eq!(env["SUPERBOT_MASTER_KEY_FILE"], "/etc/superbot/master.key", "where the key is, not the key");
    assert_eq!(env["PORT"], "3000");
    for k in ["ANTHROPIC_API_KEY", "SERVER_BACKUP_S3_SECRET_ACCESS_KEY", "MACHINE_LABEL_PREFIX", "ERROR_REPORT_DSN", "OWNER_EMAIL"] {
        assert_eq!(env[k], "[redacted]", "{k}");
    }
    assert_eq!(b.redacted_settings, 7, "{env}");
    redact::forget(&known);
}
