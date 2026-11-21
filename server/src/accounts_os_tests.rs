//! Per-user accounts on a real host (ADR 0037): user B's Bot runs through botd's real run
//! path, as B's account, and tries everything against user A's folder and logins.
//! Needs root's setup first, so it's ignored unless deploy/test-isolation.sh runs it (as
//! botd's service account, under the unit's sandboxing) with SUPERBOT_ISOLATION_OS_TEST=1.

use crate::accounts::{self, Isolation, Space};
use crate::acl::Visibility;
use crate::audit::{Actor, ActorKind, Who};
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
    let mut iso = Isolation::from_env(get, &run_dir, &app.cfg.data_dir)
        .unwrap()
        .unwrap();
    // Only isolated shared Bots use it, and only a test of those turns them on.
    iso.teammates = true;
    let iso = Arc::new(iso);
    let _ = app.isolation.set(iso.clone());
    Some((app, iso))
}

fn user_and_bot(app: &App, email: &str) -> Bot {
    let u = app
        .db
        .create_user(None, Some(email), email, Role::Member)
        .unwrap();
    app.db.create_bot_owned(
        email,
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &u.id,
        Visibility::Private,
    )
}

/// Sends `text` to the Bot and waits for its run to finish; the fake harness's reply.
async fn run(app: &Arc<App>, bot: &Bot, text: &str) -> String {
    run_for(app, bot, None, text).await
}

/// `run`, asked by `who` (None: the Bot's owner, as the runner).
async fn run_for(app: &Arc<App>, bot: &Bot, who: Option<&str>, text: &str) -> String {
    let mut msg = app
        .db
        .add_message(&bot.id, "user", text, None, false, Some("queued"));
    if let Some(u) = who {
        let by = person(u);
        app.db.set_requested_by(msg.id, &by);
        msg.requested_by = Some(by);
    }
    app.enqueue(msg.clone());
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "run didn't finish"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let replies: Vec<String> = app
        .db
        .messages(&bot.id, 20)
        .into_iter()
        .filter(|m| m.id > msg.id && m.role == "bot")
        .map(|m| m.text)
        .collect();
    replies.join("\n")
}

fn person(id: &str) -> Who {
    Who {
        actor: Actor {
            kind: ActorKind::User,
            id: Some(id.into()),
            ..Default::default()
        },
        source: Default::default(),
    }
}

fn probes(reply: &str) -> HashMap<String, String> {
    reply
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn user_bs_run_cannot_reach_user_as_folder_or_logins() {
    let Some((app, iso)) = setup() else { return };
    let a = user_and_bot(&app, "a@example.com");
    let b = user_and_bot(&app, "b@example.com");
    let (a_acct, b_acct) = (
        accounts::account(&a.owner_id).unwrap(),
        accounts::account(&b.owner_id).unwrap(),
    );

    // A logs in (the fake harness writes a credential into A's HOME) and leaves memory.
    let wrote = run(&app, &a, "WRITE-CREDS").await;
    assert_eq!(wrote, "wrote", "{wrote}");
    let a_creds = iso
        .home(&a.owner_id)
        .unwrap()
        .join(".claude/.credentials.json");
    assert!(
        std::fs::read_to_string(&a_creds)
            .unwrap()
            .contains("A-SECRET")
    );
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
        let list: Vec<String> = targets
            .iter()
            .map(|(k, p)| format!("{k}:{}", p.display()))
            .collect();
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
    assert_eq!(
        got["home"],
        iso.home(&b.owner_id).unwrap().display().to_string(),
        "{got:?}"
    );
    assert_eq!(
        got["pwd"],
        iso.workspace(&b.owner_id).unwrap().display().to_string(),
        "{got:?}"
    );
    assert!(
        got["tmpdir"].starts_with(&iso.home(&b.owner_id).unwrap().display().to_string()),
        "{got:?}"
    );
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
        assert_eq!(
            got["other_procs"], "0",
            "other accounts' processes are hidden: {got:?}"
        );
    }
    assert_eq!(got["server_secrets"], "absent", "{got:?}");
    assert_eq!(got["bot_token"], "present", "{got:?}");

    // B's writes left nothing behind; A's own did.
    let left = |dir: PathBuf, who: &str| dir.join(format!("probe-{who}")).exists();
    for dir in [
        a_mem.parent().unwrap().to_path_buf(),
        iso.workspace(&a.owner_id).unwrap(),
    ] {
        assert!(left(dir.clone(), &a_acct), "{}", dir.display());
        assert!(!left(dir.clone(), &b_acct), "{}", dir.display());
    }
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn stopping_a_run_stops_the_accounts_processes_too() {
    let Some((app, iso)) = setup() else { return };
    let c = user_and_bot(&app, "c@example.com");
    let msg = app
        .db
        .add_message(&c.id, "user", "SLEEP", None, false, Some("queued"));
    app.enqueue(msg.clone());
    let beat = iso.workspace(&c.owner_id).unwrap().join("heartbeat");
    let start = Instant::now();
    while !beat.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the run never started"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    app.stop(&c.id);
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the stop didn't end the run"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let then = std::fs::read_to_string(&beat).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        std::fs::read_to_string(&beat).unwrap(),
        then,
        "a process of the run is still going"
    );
}

#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn a_finished_run_leaves_no_processes_behind() {
    let Some((app, iso)) = setup() else { return };
    let d = user_and_bot(&app, "d@example.com");
    let msg = app
        .db
        .add_message(&d.id, "user", "LEAVE", None, false, Some("queued"));
    app.enqueue(msg.clone());
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "a tool the run left behind kept it going"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let beat = iso.workspace(&d.owner_id).unwrap().join("heartbeat");
    assert!(beat.exists(), "the tool never started");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let then = std::fs::read_to_string(&beat).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        std::fs::read_to_string(&beat).unwrap(),
        then,
        "a process of the run is still going"
    );
}

/// Pi and Hermes Agent (ADR 0058): botd's files for the run (Pi's guard, Hermes's managed
/// config) are the account's to read, not to change; botd's own files aren't its to read.
#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn pi_and_hermes_runs_cannot_read_botds_files_or_change_their_settings() {
    use std::os::unix::fs::MetadataExt;
    let Some((app, iso)) = setup() else { return };
    app.db
        .set_global_policy(&crate::policy::Policy::new(crate::policy::Mode::Ask));
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let key = PathBuf::from(
        std::env::var("SUPERBOT_OS_TEST_KEY_FILE").expect("SUPERBOT_OS_TEST_KEY_FILE"),
    );
    for harness in ["pi", "hermes"] {
        let email = format!("{harness}@example.com");
        let u = app
            .db
            .create_user(None, Some(&email), &email, Role::Member)
            .unwrap();
        let bot = app.db.create_bot_owned(
            &email,
            "#fff",
            "waddle",
            harness,
            None,
            false,
            &u.id,
            Visibility::Private,
        );
        let (settings, state) = (
            iso.bot_settings(&u.id, &bot.id).unwrap(),
            iso.bot_state(&u.id, &bot.id).unwrap(),
        );
        let (k, botds) = match harness {
            "pi" => ("guard", settings.join("superbot-guard.ts")),
            _ => ("managed", settings.join("hermes-managed/config.yaml")),
        };
        let targets = [
            ("db", app.cfg.data_dir.join("app.sqlite")),
            ("data", app.cfg.data_dir.clone()),
            ("env", home.join("superbot/.env")),
            ("key", key.clone()),
            ("botd_home", home.clone()),
            (k, botds.clone()),
            ("state", state.clone()),
        ];
        let list: Vec<String> = targets
            .iter()
            .map(|(k, p)| format!("{k}:{}", p.display()))
            .collect();
        let got = probes(&run(&app, &bot, &format!("PROBE nobody {}", list.join(" "))).await);
        eprintln!("{harness}'s run saw: {got:?}");
        assert!(
            !got.is_empty(),
            "{harness}: {:?}",
            app.db
                .messages(&bot.id, 20)
                .into_iter()
                .map(|m| (m.role, m.text))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            (got["harness"].as_str(), got["user"].as_str()),
            (harness, accounts::account(&u.id).unwrap().as_str()),
            "{got:?}"
        );
        for t in ["db", "data", "env", "key", "botd_home"] {
            assert_eq!(got[t], "denied", "{harness} {t}: {got:?}");
        }
        assert_eq!(got[k], "read", "{got:?}");
        assert_eq!(
            (
                got[&format!("write_{k}")].as_str(),
                got[&format!("replace_{k}")].as_str()
            ),
            ("denied", "denied"),
            "{got:?}"
        );
        assert_eq!(
            got["write_state"], "wrote",
            "the Bot's own state is the account's: {got:?}"
        );
        assert_eq!(
            (got["server_secrets"].as_str(), got["bot_token"].as_str()),
            ("absent", "present"),
            "{got:?}"
        );
        let m = std::fs::metadata(&botds).unwrap();
        // SAFETY: geteuid can't fail.
        assert_eq!(
            (m.uid(), m.mode() & 0o777),
            (unsafe { libc::geteuid() }, 0o640),
            "{}",
            botds.display()
        );

        if harness == "hermes" {
            // The probe left a gateway.pid: botd stops the daemon as the account, not as itself.
            let by = state.join("hermes/stopped-by");
            let start = Instant::now();
            while !by.exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "botd never ran hermes gateway stop"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(
                std::fs::read_to_string(&by).unwrap().trim(),
                accounts::account(&u.id).unwrap()
            );
        }
    }
}

fn audited(app: &App, action: &str) -> Vec<serde_json::Value> {
    let f = crate::audit::Filter {
        actions: vec![action.into()],
        ..Default::default()
    };
    app.db
        .audit_events(&f, 200, true)
        .into_iter()
        .map(|e| e.details)
        .collect()
}

/// A teammate's login for an owner's Bots, run from the app as their account there; what
/// it showed, and whether it ended logged in.
async fn log_in(app: &Arc<App>, owner: &str, teammate: &str) -> (String, bool) {
    use crate::machines::wire::LoginEvent;
    let owner = app.db.user(owner).unwrap();
    let res = crate::teammate_logins::start(
        app.clone(),
        person(teammate),
        owner,
        teammate.into(),
        "claude".into(),
    )
    .await
    .unwrap_or_else(|e| panic!("{}", e.1));
    let body = tokio::time::timeout(
        Duration::from_secs(60),
        axum::body::to_bytes(res.into_body(), 1 << 20),
    )
    .await
    .expect("the login never ended")
    .unwrap();
    let mut shown = String::new();
    let mut logged_in = false;
    for line in String::from_utf8_lossy(&body).lines() {
        match serde_json::from_str::<LoginEvent>(line).unwrap() {
            LoginEvent::Output { text } => shown.push_str(&text),
            LoginEvent::Exit { logged_in: l, .. } => logged_in = l,
            _ => {}
        }
    }
    (shown, logged_in)
}

/// ADR 0064: a teammate's run of a shared Bot on one server is an account of its own,
/// with their own harness login, and reaches neither the owner's logins and folders nor
/// another teammate's. Without a login of their own it's refused, never the owner's.
#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn a_teammates_run_of_a_shared_bot_is_their_own_account_and_login() {
    let Some((app, iso)) = setup() else { return };
    app.shared_bots
        .set(crate::acl::SharedBots::Isolated)
        .unwrap();
    assert!(app.teammate_accounts());
    let mk = |email: &str| {
        app.db
            .create_user(None, Some(email), email, Role::Member)
            .unwrap()
            .id
    };
    let (ada, bea, cy) = (
        mk("ada@example.com"),
        mk("bea@example.com"),
        mk("cy@example.com"),
    );
    let team = app.db.create_bot_owned(
        "Team",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &ada,
        Visibility::Shared,
    );
    let (bea_space, cy_space) = (Space::of(&ada, Some(&bea)), Space::of(&ada, Some(&cy)));
    let (ada_acct, bea_acct) = (
        accounts::account(&ada).unwrap(),
        bea_space.account().unwrap(),
    );

    // Ada logs in for her own Bots (the fake harness writes a credential into her HOME).
    assert_eq!(run(&app, &team, "WRITE-CREDS").await, "wrote");
    let ada_creds = iso.home(&ada).unwrap().join(".claude/.credentials.json");
    assert!(
        std::fs::read_to_string(&ada_creds)
            .unwrap()
            .contains("A-SECRET")
    );

    // Bea logs in for her own Bots too: that login is hers, not one for Ada's.
    let bea_bot = app.db.create_bot_owned(
        "Bea's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &bea,
        Visibility::Private,
    );
    assert_eq!(run(&app, &bea_bot, "WRITE-CREDS").await, "wrote");
    let bea_own_creds = iso.home(&bea).unwrap().join(".claude/.credentials.json");

    // Bea has no login for Ada's Bots: refused, never Ada's. Her account is made anyway.
    let refused = run_for(&app, &team, Some(&bea), "WRITE-CREDS").await;
    assert!(
        refused.contains("isn't logged in for you on this server"),
        "{refused}"
    );
    let why = audited(&app, "bot.run_refused");
    assert!(
        why.iter().any(|d| d["reason"] == "teammate_not_logged_in"
            && d["forUser"] == bea.as_str()
            && d["account"] == bea_acct.as_str()),
        "{why:?}"
    );
    assert!(iso.ready_in(bea_space));
    assert!(
        !audited(&app, "harness.invoked")
            .iter()
            .any(|d| d["forUser"] == bea.as_str()),
        "nothing ran for Bea"
    );

    // Bea logs in from the app: the login runs as her account for Ada's Bots, and lands there.
    let (shown, logged_in) = log_in(&app, &ada, &bea).await;
    assert!(logged_in, "{shown}");
    assert!(
        shown.contains(&format!("logged in as {bea_acct}")),
        "{shown}"
    );
    let bea_creds = iso
        .home_in(bea_space)
        .unwrap()
        .join(".claude/.credentials.json");
    let status =
        crate::teammate_logins::status(app.clone(), app.db.user(&ada).unwrap(), bea.clone())
            .await
            .unwrap()
            .0;
    assert_eq!(
        (
            status["hasUser"].as_bool(),
            status["harnesses"]["claude"]["state"].as_str()
        ),
        (Some(true), Some("logged_in")),
        "{status}"
    );
    // Cy, another teammate, logs in for Ada's Bots too: his own account, apart from Bea's.
    assert!(log_in(&app, &ada, &cy).await.1);
    let cy_creds = iso
        .home_in(cy_space)
        .unwrap()
        .join(".claude/.credentials.json");
    let started = audited(&app, "harness.login_started");
    assert!(
        started.iter().any(|d| d["forUser"] == bea.as_str()
            && d["account"] == bea_acct.as_str()
            && d["on"] == "server"),
        "{started:?}"
    );

    let targets = [
        ("own_creds", bea_creds.clone()),
        ("creds", ada_creds.clone()),
        ("a_root", iso.user_root(&ada).unwrap()),
        ("a_home", iso.home(&ada).unwrap()),
        ("a_workspace", iso.workspace(&ada).unwrap()),
        ("a_memory", app.memory_file(&team).unwrap()),
        ("a_user", iso.user_file(&ada).unwrap()),
        ("cy_creds", cy_creds.clone()),
        ("cy_root", iso.space_root(cy_space).unwrap()),
        ("bea_own_creds", bea_own_creds),
        ("bea_own_root", iso.user_root(&bea).unwrap()),
        ("db", app.cfg.data_dir.join("app.sqlite")),
        ("data", app.cfg.data_dir.clone()),
    ];
    let list: Vec<String> = targets
        .iter()
        .map(|(k, p)| format!("{k}:{}", p.display()))
        .collect();
    let probe = format!("PROBE {ada_acct} {}", list.join(" "));

    // Bea's run: her account, her folders, her login; nothing of Ada's or Cy's.
    let got = probes(&run_for(&app, &team, Some(&bea), &probe).await);
    eprintln!("Bea's run of Ada's Bot saw: {got:?}");
    assert_eq!(got["user"], bea_acct, "{got:?}");
    assert_eq!(
        got["home"],
        iso.home_in(bea_space).unwrap().display().to_string(),
        "{got:?}"
    );
    assert_eq!(
        got["pwd"],
        iso.workspace_in(bea_space).unwrap().display().to_string(),
        "{got:?}"
    );
    assert_eq!(got["own_creds"], "read", "her own login is hers: {got:?}");
    for k in [
        "creds",
        "a_root",
        "a_home",
        "a_workspace",
        "a_memory",
        "a_user",
        "cy_creds",
        "cy_root",
        "bea_own_creds",
        "bea_own_root",
        "db",
        "data",
    ] {
        assert_eq!(got[k], "denied", "{k}: {got:?}");
    }
    for k in ["write_a_workspace", "write_a_memory"] {
        assert_eq!(got[k], "denied", "{k}: {got:?}");
    }
    for k in ["sudo_root", "sudo_other", "sudo_userctl"] {
        assert_eq!(got[k], "denied", "{k}: {got:?}");
    }
    assert_eq!(
        (got["server_secrets"].as_str(), got["bot_token"].as_str()),
        ("absent", "present"),
        "{got:?}"
    );
    let invoked = audited(&app, "harness.invoked");
    assert!(
        invoked
            .iter()
            .any(|d| d["forUser"] == bea.as_str() && d["runAs"] == bea_acct.as_str()),
        "{invoked:?}"
    );

    // Ada's own run can't read Bea's login or folder either.
    let list = [
        format!("b_creds:{}", bea_creds.display()),
        format!("b_root:{}", iso.space_root(bea_space).unwrap().display()),
    ];
    let got = probes(&run(&app, &team, &format!("PROBE {bea_acct} {}", list.join(" "))).await);
    assert_eq!(got["user"], ada_acct, "{got:?}");
    assert_eq!(
        (got["b_creds"].as_str(), got["b_root"].as_str()),
        ("denied", "denied"),
        "{got:?}"
    );

    // Bea logs out: her login goes, as her account; her next run is refused again.
    let out = crate::teammate_logins::logout(
        app.clone(),
        person(&bea),
        app.db.user(&ada).unwrap(),
        bea.clone(),
        "claude".into(),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(out["removed"], 1, "{out}");
    let again = run_for(&app, &team, Some(&bea), "WRITE-CREDS").await;
    assert!(again.contains("isn't logged in for you"), "{again}");
    assert!(
        std::fs::read_to_string(&ada_creds)
            .unwrap()
            .contains("A-SECRET"),
        "Ada's login is untouched"
    );
}

/// ADR 0066: a leaving teammate's account goes: their running tool stopped, their work
/// handed to the owner's account, their login and folder deleted. The owner's account,
/// another teammate's, and the shared Bot keep working, and asking again changes nothing.
#[tokio::test]
#[ignore = "needs root's setup: deploy/test-isolation.sh"]
async fn a_leaving_teammates_account_goes_and_the_shared_bot_keeps_working() {
    let Some((app, iso)) = setup() else { return };
    app.shared_bots
        .set(crate::acl::SharedBots::Isolated)
        .unwrap();
    let mk = |email: &str| {
        app.db
            .create_user(None, Some(email), email, Role::Member)
            .unwrap()
            .id
    };
    let (ada, bea, cy) = (
        mk("ada@example.com"),
        mk("bea@example.com"),
        mk("cy@example.com"),
    );
    let team = app.db.create_bot_owned(
        "Team",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &ada,
        Visibility::Shared,
    );
    let (bea_space, cy_space) = (Space::of(&ada, Some(&bea)), Space::of(&ada, Some(&cy)));
    let (bea_acct, cy_acct) = (bea_space.account().unwrap(), cy_space.account().unwrap());
    assert_eq!(run(&app, &team, "WRITE-CREDS").await, "wrote");
    let ada_creds = iso.home(&ada).unwrap().join(".claude/.credentials.json");
    for t in [&bea, &cy] {
        assert!(log_in(&app, &ada, t).await.1);
    }
    let cy_creds = iso
        .home_in(cy_space)
        .unwrap()
        .join(".claude/.credentials.json");
    assert!(
        iso.teammate_pairs().contains(&(ada.clone(), bea.clone())),
        "{:?}",
        iso.teammate_pairs()
    );
    // As in a recreated container: deploy/test-isolation.sh left t1-t3's folder, not its
    // account. botd made it, so its data says so.
    let lost = iso.space_root(Space::of("t1", Some("t3"))).unwrap();
    assert!(crate::passwd::by_name(&Space::of("t1", Some("t3")).account().unwrap()).is_none());
    app.db.teammate_space_made("t1", "t3");

    // Bea's run is going, with a tool that ignores TERM, when she leaves.
    let mut msg = app
        .db
        .add_message(&team.id, "user", "SLEEP", None, false, Some("queued"));
    app.db.set_requested_by(msg.id, &person(&bea));
    msg.requested_by = Some(person(&bea));
    app.enqueue(msg.clone());
    let beat = iso.workspace_in(bea_space).unwrap().join("heartbeat");
    let start = Instant::now();
    while !beat.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "Bea's run never started"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    std::fs::write(
        iso.workspace_in(bea_space).unwrap().join("notes.txt"),
        "bea's notes",
    )
    .unwrap();

    app.db
        .update_user(
            &bea,
            crate::db::UserPatch {
                status: Some("disabled"),
                ..Default::default()
            },
        )
        .unwrap();
    crate::teammate_removals::left(&app, &Who::system("test"), &bea, "disabled");
    crate::teammate_removals::settled(&app).await;
    let removed = audited(&app, "isolation.teammate_removed");
    let d = removed
        .iter()
        .find(|d| d["forUser"] == bea.as_str())
        .unwrap_or_else(|| {
            panic!(
                "{removed:?} {:?}",
                audited(&app, "isolation.teammate_removal_failed")
            )
        });
    eprintln!("Removed: {d}");
    assert_eq!(
        (
            d["account"].as_str(),
            d["work"].as_str(),
            d["accountRemoved"].as_bool()
        ),
        (Some(bea_acct.as_str()), Some("archived"), Some(true)),
        "{d}"
    );
    // botd stops her run first, and waits for it to save its memory; the helper kills
    // whatever is left.
    assert_eq!(d["runsStopped"].as_i64(), Some(1), "{d}");
    assert!(
        crate::passwd::by_name(&bea_acct).is_none(),
        "the account is gone"
    );
    assert!(
        std::fs::symlink_metadata(iso.space_root(bea_space).unwrap()).is_err(),
        "the folder and login are gone"
    );
    let to = PathBuf::from(d["archivedTo"].as_str().unwrap());
    assert!(
        to.starts_with(iso.workspace(&ada).unwrap().join("from-teammates")),
        "{}",
        to.display()
    );
    assert_eq!(
        std::fs::read_to_string(to.join("notes.txt")).unwrap(),
        "bea's notes"
    );
    assert!(
        !to.join(".claude").exists() && !to.join("home").exists(),
        "the login isn't handed over"
    );

    // The tool is dead, and the run is over.
    let start = Instant::now();
    while app.db.message(msg.id).unwrap().status.as_deref() != Some("done") {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "Bea's run never ended"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let then = std::fs::read_to_string(to.join("heartbeat")).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        std::fs::read_to_string(to.join("heartbeat")).unwrap(),
        then,
        "a process of Bea's is still going"
    );

    // Ada's login, Cy's account and login are untouched, and the Bot works for both.
    assert!(
        std::fs::read_to_string(&ada_creds)
            .unwrap()
            .contains("A-SECRET")
    );
    assert!(iso.ready_in(cy_space) && cy_creds.is_file());
    assert_eq!(
        probes(&run(&app, &team, "PROBE nobody").await)["user"],
        accounts::account(&ada).unwrap()
    );
    assert_eq!(
        probes(&run_for(&app, &team, Some(&cy), "PROBE nobody").await)["user"],
        cy_acct
    );

    // Again changes nothing.
    crate::teammate_removals::left(&app, &Who::system("test"), &bea, "disabled");
    crate::teammate_removals::follow_up(&app);
    crate::teammate_removals::settled(&app).await;
    assert_eq!(
        audited(&app, "isolation.teammate_removed")
            .iter()
            .filter(|d| d["forUser"] == bea.as_str())
            .count(),
        1
    );
    assert!(
        std::fs::symlink_metadata(&lost).is_err(),
        "the folder of an account the container lost is cleaned up too"
    );
    let again = iso
        .remove_teammate(&ada, &bea, "0123456789abcdef", &accounts::Work::Delete)
        .unwrap();
    assert_eq!(
        (again.account_removed, again.work.as_str()),
        (false, "none")
    );
    assert_eq!(
        std::fs::read_to_string(to.join("notes.txt")).unwrap(),
        "bea's notes"
    );
    assert!(
        iso.ready_in(cy_space)
            && crate::passwd::by_name(&accounts::account(&ada).unwrap()).is_some()
    );

    // Back again, Bea gets a new account; her old work stays Ada's.
    app.db
        .update_user(
            &bea,
            crate::db::UserPatch {
                status: Some("active"),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(log_in(&app, &ada, &bea).await.1);
    assert!(iso.ready_in(bea_space));
    assert!(
        !iso.workspace_in(bea_space)
            .unwrap()
            .join("notes.txt")
            .exists()
    );
}
