//! Per-user accounts on a real host (ADR 0037): user B's Bot runs through botd's real run
//! path, as B's account, and tries everything against user A's folder and logins.
//! Needs root's setup first, so it's ignored unless deploy/test-isolation.sh runs it (as
//! botd's service account, under the unit's sandboxing) with SUPERBOT_ISOLATION_OS_TEST=1.

use crate::accounts::{self, Isolation};
use crate::acl::Visibility;
use crate::db::Bot;
use crate::rbac::Role;
use crate::runner::{App, test_app};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn setup() -> Option<(Arc<App>, Arc<Isolation>)> {
    if std::env::var("SUPERBOT_ISOLATION_OS_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: run deploy/test-isolation.sh");
        return None;
    }
    let app = test_app();
    // As DATA_DIR is in production: in botd's home, which only botd's account can open.
    std::fs::set_permissions(&app.cfg.data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let run_dir = PathBuf::from(std::env::var("SUPERBOT_RUN_DIR").expect("SUPERBOT_RUN_DIR"));
    let get = |k: &str| match k {
        "ISOLATION" => "users".into(),
        _ => std::env::var(k).unwrap_or_default(),
    };
    let iso = Arc::new(Isolation::from_env(get, &run_dir, &app.cfg.data_dir).unwrap().unwrap());
    let _ = app.isolation.set(iso.clone());
    Some((app, iso))
}

fn user_and_bot(app: &App, email: &str) -> Bot {
    let u = app.db.create_user(None, Some(email), email, Role::Member).unwrap();
    app.db.create_bot_owned(email, "#fff", "waddle", "claude", None, false, &u.id, Visibility::Private)
}

/// Sends `text` to the Bot and waits for its run to finish; the fake harness's reply.
async fn run(app: &Arc<App>, bot: &Bot, text: &str) -> String {
    let msg = app.db.add_message(&bot.id, "user", text, None, false, Some("queued"));
    app.enqueue(msg.clone());
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(start.elapsed() < Duration::from_secs(60), "run didn't finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let replies: Vec<String> = app.db.messages(&bot.id, 20).into_iter().filter(|m| m.id > msg.id && m.role == "bot").map(|m| m.text).collect();
    replies.join("\n")
}

fn probes(reply: &str) -> HashMap<String, String> {
    reply.split(';').filter_map(|kv| kv.trim().split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn user_bs_run_cannot_reach_user_as_folder_or_logins() {
    let Some((app, iso)) = setup() else { return };
    let a = user_and_bot(&app, "a@example.com");
    let b = user_and_bot(&app, "b@example.com");
    let (a_acct, b_acct) = (accounts::account(&a.owner_id).unwrap(), accounts::account(&b.owner_id).unwrap());

    // A logs in (the fake harness writes a credential into A's HOME) and leaves memory.
    let wrote = run(&app, &a, "WRITE-CREDS").await;
    assert_eq!(wrote, "wrote", "{wrote}");
    let a_creds = iso.home(&a.owner_id).unwrap().join(".claude/.credentials.json");
    assert!(std::fs::read_to_string(&a_creds).unwrap().contains("A-SECRET"));
    let a_mem = app.memory_file(&a).unwrap();
    assert!(a_mem.is_file(), "A's memory copy is made at its first run");

    let targets = [
        ("creds", a_creds.clone()),
        ("a_root", iso.user_root(&a.owner_id).unwrap()),
        ("a_home", iso.home(&a.owner_id).unwrap()),
        ("a_workspace", iso.workspace(&a.owner_id).unwrap()),
        ("a_memory", a_mem.clone()),
        ("a_user", iso.user_file(&a.owner_id).unwrap()),
        ("all_users", iso.root.clone()),
        ("db", app.cfg.data_dir.join("app.sqlite")),
        ("data", app.cfg.data_dir.clone()),
    ];
    let probe = |who: &str| {
        let list: Vec<String> = targets.iter().map(|(k, p)| format!("{k}:{}", p.display())).collect();
        format!("PROBE {who} {}", list.join(" "))
    };

    // A reaches its own folder, so the probe can tell a read from a refusal.
    let own = probes(&run(&app, &a, &probe(&b_acct)).await);
    assert_eq!(own["creds"], "read", "{own:?}");
    assert_eq!(own["a_workspace"], "read", "{own:?}");
    assert_eq!(own["a_memory"], "read", "{own:?}");

    // B gets none of it.
    let got = probes(&run(&app, &b, &probe(&a_acct)).await);
    eprintln!("A's run saw: {own:?}\nB's run saw: {got:?}");
    assert_eq!(got["user"], b_acct, "{got:?}");
    assert_eq!(got["home"], iso.home(&b.owner_id).unwrap().display().to_string(), "{got:?}");
    assert_eq!(got["pwd"], iso.workspace(&b.owner_id).unwrap().display().to_string(), "{got:?}");
    assert!(got["tmpdir"].starts_with(&iso.home(&b.owner_id).unwrap().display().to_string()), "{got:?}");
    for (k, _) in &targets {
        assert_eq!(got[*k], "denied", "{k}: {got:?}");
    }
    for k in ["write_a_workspace", "write_a_memory", "write_all_users"] {
        assert_eq!(got[k], "denied", "{k}: {got:?}");
    }
    // No way up or sideways: not root, not A, not the account helper.
    for k in ["sudo_root", "sudo_other", "sudo_userctl"] {
        assert_eq!(got[k], "denied", "{k}: {got:?}");
    }
    // ProtectProc=invisible, from the unit's drop-in (not there without systemd).
    if std::env::var("SUPERBOT_PROCS_VISIBLE").as_deref() != Ok("1") {
        assert_eq!(got["other_procs"], "0", "other accounts' processes are hidden: {got:?}");
    }
    assert_eq!(got["server_secrets"], "absent", "{got:?}");
    assert_eq!(got["bot_token"], "present", "{got:?}");

    // B's writes left nothing behind; A's own did.
    let left = |dir: PathBuf, who: &str| dir.join(format!("probe-{who}")).exists();
    for dir in [a_mem.parent().unwrap().to_path_buf(), iso.workspace(&a.owner_id).unwrap()] {
        assert!(left(dir.clone(), &a_acct), "{}", dir.display());
        assert!(!left(dir.clone(), &b_acct), "{}", dir.display());
    }
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn stopping_a_run_stops_the_accounts_processes_too() {
    let Some((app, iso)) = setup() else { return };
    let c = user_and_bot(&app, "c@example.com");
    let msg = app.db.add_message(&c.id, "user", "SLEEP", None, false, Some("queued"));
    app.enqueue(msg.clone());
    let beat = iso.workspace(&c.owner_id).unwrap().join("heartbeat");
    let start = Instant::now();
    while !beat.exists() {
        assert!(start.elapsed() < Duration::from_secs(30), "the run never started");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    app.stop(&c.id);
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(start.elapsed() < Duration::from_secs(30), "the stop didn't end the run");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let then = std::fs::read_to_string(&beat).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(std::fs::read_to_string(&beat).unwrap(), then, "a process of the run is still going");
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn a_finished_run_leaves_no_processes_behind() {
    let Some((app, iso)) = setup() else { return };
    let d = user_and_bot(&app, "d@example.com");
    let msg = app.db.add_message(&d.id, "user", "LEAVE", None, false, Some("queued"));
    app.enqueue(msg.clone());
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(start.elapsed() < Duration::from_secs(30), "a tool the run left behind kept it going");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let beat = iso.workspace(&d.owner_id).unwrap().join("heartbeat");
    assert!(beat.exists(), "the tool never started");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let then = std::fs::read_to_string(&beat).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(std::fs::read_to_string(&beat).unwrap(), then, "a process of the run is still going");
}
