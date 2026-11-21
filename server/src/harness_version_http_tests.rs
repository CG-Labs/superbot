//! HTTP tests for refusing guarded runs on a harness too old to run SuperBot's hook
//! (ADR 0059), on this server and on the owner's machine. Unguarded runs go on.

use crate::acl::Visibility;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::recording::Recording;
use crate::machines::wire::JobEvent;
use crate::machines::ControlPlane;
use crate::tests::{audit_list, call, serve_app, serve_app_with};
use crate::users_http_tests::user_with;
use crate::*;

const REPLY: &str = r#"{"type":"item.completed","item":{"type":"agent_message","text":"On it."}}"#;

/// A stand-in `codex` that says it is `version`, and otherwise keeps its arguments and
/// replies. Written as a new file each time, as an update would. Returns where it keeps
/// the arguments.
fn fake_codex(app: &App, version: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("codex");
    let tmp = app.cfg.bin_dir.join("codex.new");
    let script = format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$0.args\"\necho '{REPLY}'\n");
    std::fs::write(&tmp, script).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    app.cfg.bin_dir.join("codex.args")
}

async fn run(port: u16, app: &App, who: &str, bot: &str) -> String {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"tidy the repo"}"#).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..500 {
        if let Some(m) = app.db.replies_after(bot, before).into_iter().next() {
            for _ in 0..500 {
                if !app.is_running(bot) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

async fn events(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn set_mode(port: u16, admin: &str, bot: &str, mode: Value) {
    let (code, body) = call(port, "PUT", &format!("/api/bots/{bot}/policy"), admin, &json!({ "mode": mode }).to_string()).await;
    assert_eq!(code, 200, "{body}");
}

#[tokio::test]
async fn guarded_codex_runs_on_this_server_need_a_codex_that_runs_the_hook() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Cody", "#fff", "waddle", "codex", None, true);
    let args = fake_codex(&app, "codex-cli 0.140.0");

    // Guarded (fresh installs ask): refused before Codex runs, saying how to fix it.
    let said = run(port, &app, &admin, &bot.id).await;
    for want in ["approvals need the codex CLI 0.141.0 or newer", "this server has 0.140.0", "`npm install -g @openai/codex@0.171.0`", "bypass"] {
        assert!(said.contains(want), "{want:?} in {said}");
    }
    assert!(app.db.last_message(&bot.id).unwrap().error);
    assert!(!args.exists(), "Codex never got the task");
    assert!(events(port, &admin, &format!("action=harness.invoked&bot={}", bot.id)).await.is_empty());
    let refused = events(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["outcome"], "denied");
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["harness"].as_str(), d["version"].as_str(), d["minimum"].as_str()), (Some("harness_outdated"), Some("codex"), Some("0.140.0"), Some("0.141.0")));
    assert_eq!((d["host"].as_str(), d["machine"].clone(), d["detail"].clone()), (Some("server"), Value::Null, Value::Null));

    // Unguarded: runs as before, without asking Codex its version.
    set_mode(port, &admin, &bot.id, json!("bypass")).await;
    assert_eq!(run(port, &app, &admin, &bot.id).await, "On it.");
    assert!(std::fs::read_to_string(&args).unwrap().contains("exec"));
    let invoked = events(port, &admin, &format!("action=harness.invoked&bot={}", bot.id)).await;
    assert_eq!((invoked.len(), invoked[0]["details"]["guarded"].as_bool()), (1, Some(false)));

    // Guarded again, on a Codex whose version can't be read: refused too, and why.
    set_mode(port, &admin, &bot.id, Value::Null).await;
    std::fs::remove_file(&args).unwrap();
    fake_codex(&app, "codex-cli dev");
    let said = run(port, &app, &admin, &bot.id).await;
    assert!(said.contains("I couldn't tell which version this server has (--version printed \"codex-cli dev\")"), "{said}");
    assert!(!args.exists());
    let refused = events(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["version"].clone()), (Some("harness_version_unknown"), Value::Null));
    assert_eq!(refused[0]["details"]["detail"], "--version printed \"codex-cli dev\"");

    // Updated: the next guarded run goes through, with the hook.
    fake_codex(&app, "codex-cli 0.141.0");
    assert_eq!(run(port, &app, &admin, &bot.id).await, "On it.");
    assert!(std::fs::read_to_string(&args).unwrap().contains("--dangerously-bypass-hook-trust"));
    let invoked = events(port, &admin, &format!("action=harness.invoked&bot={}", bot.id)).await;
    assert_eq!((invoked.len(), invoked[0]["details"]["guarded"].as_bool()), (2, Some(true)));

    // No Codex at all: refused, not run.
    std::fs::remove_file(app.cfg.bin_dir.join("codex")).unwrap();
    if adapters::version::resolve("codex", &std::env::var("PATH").unwrap_or_default(), &app.cfg.workspace).is_none() {
        let said = run(port, &app, &admin, &bot.id).await;
        assert!(said.contains("codex isn't on this server's PATH"), "{said}");
    }
}

#[tokio::test]
async fn a_task_stopped_while_its_harness_is_checked_never_starts() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Cody", "#fff", "waddle", "codex", None, true);
    let args = fake_codex(&app, "codex-cli 0.171.0");
    let asked = app.cfg.bin_dir.join("asked");
    let script = std::fs::read_to_string(app.cfg.bin_dir.join("codex")).unwrap();
    let slow = script.replacen("then echo", &format!("then touch '{}'; sleep 1; echo", asked.display()), 1);
    std::fs::write(app.cfg.bin_dir.join("codex"), slow).unwrap();

    let before = app.db.last_id();
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", bot.id), &admin, r#"{"text":"tidy"}"#).await.0, 202);
    for _ in 0..250 {
        if asked.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(asked.exists(), "the check started");
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/stop", bot.id), &admin, "").await.0, 200);
    let mut said = None;
    for _ in 0..250 {
        said = app.db.replies_after(&bot.id, before).into_iter().next().map(|m| m.text);
        if said.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(said.as_deref(), Some("Stopped."));
    assert!(!args.exists(), "Codex never got the task");
    assert!(events(port, &admin, &format!("action=harness.invoked&bot={}", bot.id)).await.is_empty());

    // The stop was for that task only: the next one runs.
    assert_eq!(run(port, &app, &admin, &bot.id).await, "On it.");
}

#[tokio::test]
async fn harnesses_without_a_minimum_are_not_asked() {
    use std::os::unix::fs::PermissionsExt;
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Ada", "#fff", "waddle", "claude", None, true);
    let path = app.cfg.bin_dir.join("claude");
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"On it."}]}}"#;
    std::fs::write(&path, format!("#!/bin/sh\n[ \"$1\" = --version ] && echo asked >> \"$0.asked\"\necho '{reply}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run(port, &app, &admin, &bot.id).await, "On it.");
    assert!(!app.cfg.bin_dir.join("claude.asked").exists());
}

#[tokio::test]
async fn on_a_machine_the_codex_there_is_checked() {
    use crate::machines::route::Routing;
    let fake = Arc::new(Fake::default());
    let link = Arc::new(Recording::default());
    let (p, l): (Arc<dyn MachineProvider>, Arc<dyn crate::machines::route::MachineLink>) = (fake.clone(), link.clone());
    let (port, app, owner, _) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(p);
        (cp.routing, cp.link) = (Routing::On, l);
        a.machines = Arc::new(cp);
    })
    .await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    assert_eq!(call(port, "POST", &format!("/api/users/{a_id}/machine"), &admin, "{}").await.0, 202);
    assert_eq!(call(port, "POST", "/api/machines/reconcile", &admin, "").await.0, 200);
    let machine = app.db.user_machine(&a_id).unwrap();
    crate::machines::route::recording::enroll(&app.db, &machine);
    assert_eq!(call(port, "PUT", &format!("/api/users/{a_id}/placement"), &admin, "").await.0, 200);
    let bot = app.db.create_bot_owned("Cody", "#fff", "waddle", "codex", None, false, &a_id, Visibility::Private);
    let script = |version: &str| {
        let exit = JobEvent::Exit { success: true, status: "exit status: 0".into(), stderr: String::new(), files: Default::default(), too_big: vec![] };
        *link.script.lock().unwrap() = vec![JobEvent::Started, JobEvent::Line { line: version.into() }, JobEvent::Line { line: REPLY.into() }, exit];
    };
    let jobs = |from: usize| link.sent.lock().unwrap()[from..].iter().map(|(_, j)| (j.bin.clone(), j.args.clone(), j.cwd.clone())).collect::<Vec<_>>();

    // Too old there: asked as a job where the run would go, then refused.
    script("codex-cli 0.139.0");
    let said = run(port, &app, &a, &bot.id).await;
    for want in ["your computer has 0.139.0", "MACHINE_HARNESSES", "`botctl machine harnesses <user>`"] {
        assert!(said.contains(want), "{want:?} in {said}");
    }
    assert_eq!(jobs(0), [("codex".to_string(), vec!["--version".to_string()], "/home/bots/work".to_string())], "only the version check");
    let refused = events(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["version"].as_str(), d["host"].as_str(), d["machine"].as_str()), (Some("harness_outdated"), Some("0.139.0"), Some("machine"), Some(machine.id.as_str())));

    // It can't say: refused too. Others read a shared Bot's chat, so the machine's own
    // words go only to the audit log.
    let shared = app.db.create_bot_owned("Team", "#fff", "waddle", "codex", None, false, &a_id, Visibility::Shared);
    *link.script.lock().unwrap() = vec![JobEvent::Error { message: "codex isn't installed on this machine.".into() }];
    let said = run(port, &app, &a, &shared.id).await;
    assert!(said.contains("I couldn't tell which version your computer has.") && !said.contains("installed on this machine"), "{said}");
    let refused = events(port, &admin, &format!("action=bot.run_refused&bot={}", shared.id)).await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["detail"].as_str()), (Some("harness_version_unknown"), Some("codex isn't installed on this machine.")));
    let said = run(port, &app, &a, &bot.id).await;
    assert!(said.contains("(codex isn't installed on this machine.)"), "the owner's private Bot says why: {said}");

    // Unguarded: the run goes, unasked.
    script("codex-cli 0.139.0");
    set_mode(port, &admin, &bot.id, json!("bypass")).await;
    let n = link.sent.lock().unwrap().len();
    assert_eq!(run(port, &app, &a, &bot.id).await, "On it.");
    assert_eq!(jobs(n).len(), 1);
    assert_ne!(jobs(n)[0].1, ["--version"]);

    // Updated there: checked once, then the guarded runs go; the pass is remembered.
    set_mode(port, &admin, &bot.id, Value::Null).await;
    script("codex-cli 0.171.0");
    let n = link.sent.lock().unwrap().len();
    assert_eq!(run(port, &app, &a, &bot.id).await, "On it.");
    let sent = jobs(n);
    assert_eq!((sent.len(), sent[0].1.clone()), (2, vec!["--version".to_string()]), "{sent:?}");
    assert!(sent[1].1.iter().any(|x| x == "--dangerously-bypass-hook-trust"), "{sent:?}");
    let n = link.sent.lock().unwrap().len();
    assert_eq!(run(port, &app, &a, &bot.id).await, "On it.");
    assert_eq!(jobs(n).len(), 1, "not asked again");
}
