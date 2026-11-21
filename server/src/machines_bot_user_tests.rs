//! Bots' own OS user on a user's machine (ADR 0043), end to end on loopback: the real
//! router, botd's machine port, and the real agent over mutual TLS. Tests can't make
//! users, so here the Bots' user is whoever runs them; the same code paths run. The
//! last test makes a real user and needs root: CI's isolation job runs it.

use crate::machines::agent::{self, Agent};
use crate::machines::{heartbeats, runas, terminal, wire};
use crate::machines_mtls_tests::{
    Env, agent_with, agent_with_config, events, json_call, machine_for, reply_after, send,
    serve_with, wait_for_event,
};
use crate::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// A stand-in Claude that says who it ran as, and whether it could read the agent's key
/// in `state`.
fn whoami(state: &std::path::Path) -> String {
    format!(
        r#"#!/bin/sh
me="$(id -u) $USER"
if head -c 1 "{key}" >/dev/null 2>&1; then key=read; else key=denied; fi
echo "$me" > "$HOME/whoami"
if [ -t 0 ]; then stat -c %u "$(tty)" > "$HOME/tty-owner"; fi
printf '{{"type":"assistant","message":{{"content":[{{"type":"text","text":"ran as %s key=%s"}}]}}}}\n' "$me" "$key"
"#,
        key = state.join("identity.pem").display()
    )
}

pub(crate) fn owned_bot(env: &Env, uid: &str) -> String {
    env.app
        .db
        .create_bot_owned(
            "Ada's",
            "#fff",
            "waddle",
            "claude",
            None,
            false,
            uid,
            crate::acl::Visibility::Shared,
        )
        .id
}

fn refusals(evs: &[Value], reason: &str) -> usize {
    evs.iter()
        .filter(|e| e["details"]["reason"] == reason)
        .count()
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

fn owner(p: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().uid()
}

/// Heartbeats until the agent says its Bots' user is ready, and botd has heard.
pub(crate) async fn until_ready(env: &Env, a: &Agent) -> Vec<Value> {
    for _ in 0..400 {
        if a.bot_user()
            .is_some_and(|s| s.state == wire::BOT_USER_READY)
        {
            heartbeats(&env.app, &env.cp).await;
            return wait_for_event(env, "machine.bot_user_ready").await;
        }
        heartbeats(&env.app, &env.cp).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the Bots' user never got ready: {:?}", a.bot_user());
}

fn euid() -> u32 {
    // SAFETY: no arguments.
    unsafe { libc::geteuid() }
}

#[tokio::test]
async fn bots_run_as_their_own_user_once_their_machine_has_set_it_up() {
    let mut env = serve_with(|e| e.with_bot_user()).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(
        &mut env,
        &mid,
        &token,
        &whoami(std::path::Path::new("/nonexistent")),
    )
    .await;
    let bot = owned_bot(&env, &uid);
    let me = runas::current_user().unwrap();

    // Not set up yet: refused, never run another way.
    let before = send(&env, &bot, "hello").await;
    let said = reply_after(&env, &bot, before).await;
    assert!(
        said.contains("setting up a separate account for your Bots"),
        "{said}"
    );
    assert_eq!(
        refusals(&events(&env, "bot.run_refused").await, "bot_user_pending"),
        1
    );
    assert!(events(&env, "harness.invoked").await.is_empty());
    assert!(m.agent.bot_user().is_none());

    // The next heartbeat asks for it; the agent hands it the home.
    let ready = until_ready(&env, &m.agent).await;
    let asked = events(&env, "machine.bot_user_requested").await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(
        (
            asked[0]["outcome"].as_str(),
            asked[0]["details"]["user"].as_str()
        ),
        (Some("success"), Some(wire::BOT_USER))
    );
    assert_eq!(
        (
            ready[0]["details"]["user"].as_str(),
            ready[0]["details"]["uid"].as_u64()
        ),
        (Some(me.as_str()), Some(euid() as u64)),
        "{ready:?}"
    );
    let cfg = &m.agent.cfg;
    assert_eq!(
        mode(&cfg.state_dir),
        0o711,
        "the Bots' user can get through to its home"
    );
    assert_eq!(mode(&cfg.home), 0o700);
    assert_eq!(mode(&cfg.state_dir.join("bot-user.json")), 0o600);

    // Runs now, as that user.
    let before = send(&env, &bot, "again").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        format!("ran as {} {me} key=denied", euid())
    );

    // Nothing more is asked; asking by hand says it's ready, as does the agent's view.
    heartbeats(&env.app, &env.cp).await;
    assert_eq!(events(&env, "machine.bot_user_requested").await.len(), 1);
    let (code, v) = json_call(
        &env,
        "POST",
        &format!("/api/users/{uid}/machine/bot-user"),
        "",
    )
    .await;
    assert_eq!(
        (code, v["botUser"]["state"].as_str()),
        (202, Some("ready")),
        "{v}"
    );
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/agent"), "").await;
    assert_eq!(v["agent"]["botUser"]["state"], "ready", "{v}");
    assert_eq!(
        events(&env, "machine.bot_user_ready").await.len(),
        1,
        "recorded once"
    );

    // A restarted agent keeps it. One set to another user than the one saved runs nothing.
    let id = || agent::load(cfg).unwrap();
    let again = Agent::new(cfg.clone(), id()).unwrap();
    assert_eq!(again.bot_user().unwrap().state, wire::BOT_USER_READY);
    let mut other = cfg.clone();
    other.bot_user = "superbot-no-such-user".into();
    let broken = Agent::new(other, id()).unwrap();
    let st = broken.bot_user().unwrap();
    assert_eq!(st.state, wire::BOT_USER_FAILED);
    assert!(st.error.unwrap().contains("superbot-no-such-user"));

    // A set-up cut short after saving picks up where it stopped; an unreadable record
    // runs nothing rather than running as root.
    let saved = cfg.state_dir.join("bot-user.json");
    let whole = std::fs::read_to_string(&saved).unwrap();
    assert!(whole.contains(r#""handed":true"#), "{whole}");
    write(
        &saved,
        &whole.replace(r#""handed":true"#, r#""handed":false"#),
    );
    let resumed = Agent::new(cfg.clone(), id()).unwrap();
    assert_eq!(resumed.bot_user().unwrap().state, wire::BOT_USER_READY);
    assert!(
        std::fs::read_to_string(&saved)
            .unwrap()
            .contains(r#""handed":true"#)
    );
    write(&saved, "{not json");
    let unreadable = Agent::new(cfg.clone(), id()).unwrap();
    assert_eq!(unreadable.bot_user().unwrap().state, wire::BOT_USER_FAILED);
    write(&saved, &whole);
}

#[tokio::test]
async fn off_by_default_nothing_is_asked_and_bots_run_as_before() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(
        &mut env,
        &mid,
        &token,
        &whoami(std::path::Path::new("/nonexistent")),
    )
    .await;
    let bot = owned_bot(&env, &uid);
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.bot_user_requested").await.is_empty());
    assert!(m.agent.bot_user().is_none());
    let before = send(&env, &bot, "hello").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        format!("ran as {}  key=denied", euid()),
        "no USER, as before"
    );
    let (code, v) = json_call(
        &env,
        "POST",
        &format!("/api/users/{uid}/machine/bot-user"),
        "",
    )
    .await;
    assert_eq!(code, 409, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("MACHINE_BOT_USER"),
        "{v}"
    );
    assert!(!m.agent.cfg.state_dir.join("bot-user.json").exists());
}

/// As root, on a host CI throws away: a real user is made, and every Bot path runs as it.
#[tokio::test]
#[ignore = "needs root: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_bots_get_their_own_os_user_and_cant_reach_the_agents_files() {
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") || !runas::is_root() {
        eprintln!("skipped: needs root and SUPERBOT_MACHINE_BOT_USER_TEST=1");
        return;
    }
    const USER: &str = "superbot-bots-test";
    let _ = std::process::Command::new("userdel").arg(USER).status();
    let mut env = serve_with(|e| e.with_bot_user().with_folder_sync(1 << 20)).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let state = crate::db::temp_path("agent-root");
    let m = agent_with_config(&mut env, &mid, &token, &whoami(&state), |mut c| {
        c.state_dir = state.clone();
        c.bot_user = USER.into();
        c.allow_own_user = false;
        c
    })
    .await;
    let (cfg, home) = (&m.agent.cfg, m.home.clone());
    let bot = owned_bot(&env, &uid);
    write(&env.app.data_memory_file(&bot).unwrap(), "- remembers");

    // Something left in the home while Bots ran as root: a link where the agent will
    // write the Bot's memory, to a file only root may write.
    let planted = state.join("planted");
    std::fs::write(&planted, "root's").unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o600)).unwrap();
    let memdir = home.join(format!("bots/{bot}"));
    std::fs::create_dir_all(&memdir).unwrap();
    std::os::unix::fs::symlink(&planted, memdir.join(".MEMORY.md.tmp")).unwrap();

    until_ready(&env, &m.agent).await;
    let (ids, _) = runas::lookup(USER).expect("the agent made the user");
    assert!(ids.uid != 0 && ids.gid != 0);
    assert_eq!((owner(&home), mode(&home)), (ids.uid, 0o700));
    assert_eq!(owner(&home.join(".local/bin/claude")), ids.uid);
    assert_eq!(
        owner(&memdir.join(".MEMORY.md.tmp")),
        ids.uid,
        "the link itself, not what it points to"
    );
    assert_eq!((owner(&planted), mode(&planted)), (0, 0o600));
    assert_eq!(
        (
            owner(&state.join("identity.pem")),
            mode(&state.join("identity.pem"))
        ),
        (0, 0o600)
    );
    assert_eq!(mode(&state), 0o711);

    // The link is followed as the Bots' user, who can't write there: root's file is safe.
    let before = send(&env, &bot, "hello").await;
    let _ = reply_after(&env, &bot, before).await;
    assert_eq!(std::fs::read_to_string(&planted).unwrap(), "root's");
    std::fs::remove_file(memdir.join(".MEMORY.md.tmp")).unwrap();

    // Runs as the Bots' user, which can't read the agent's key; what it and the agent
    // write in the home is that user's.
    let before = send(&env, &bot, "again").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        format!("ran as {} {USER} key=denied", ids.uid)
    );
    assert_eq!(owner(&home.join("whoami")), ids.uid);
    assert_eq!(owner(&memdir.join("MEMORY.md")), ids.uid);

    // The folder copy lands as that user.
    let ws = env.app.workspace_for(&uid).unwrap();
    write(&ws.join("notes/a.txt"), "alpha");
    let (code, v) = json_call(
        &env,
        "POST",
        &format!("/api/users/{uid}/machine/folder-sync"),
        "",
    )
    .await;
    assert_eq!(code, 202, "{v}");
    wait_for_event(&env, "machine.folder_sync_finished").await;
    assert_eq!(
        std::fs::read_to_string(home.join("work/notes/a.txt")).unwrap(),
        "alpha"
    );
    assert_eq!(owner(&home.join("work/notes/a.txt")), ids.uid);
    assert_eq!(owner(&home.join("work/notes")), ids.uid);

    // A login runs as that user too, in a terminal it owns.
    let r = wire::LoginRequest {
        login_id: "l1".into(),
        harness: "claude".into(),
        args: vec![],
        files: vec![".claude/.credentials.json".into()],
        timeout_secs: 60,
        for_user: None,
    };
    let env_vars = std::collections::BTreeMap::from([
        ("HOME".to_string(), home.display().to_string()),
        ("PATH".to_string(), cfg.harness_path.clone()),
        ("USER".to_string(), USER.to_string()),
    ]);
    let run = terminal::Command {
        bin: "claude",
        args: vec![],
    };
    let (mut rx, _stop) = m
        .agent
        .logins
        .start(&r, &run, &home, &env_vars, Some(ids))
        .unwrap();
    while let Some(ev) = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .unwrap()
    {
        if matches!(ev, wire::LoginEvent::Exit { .. }) {
            break;
        }
    }
    assert_eq!(
        std::fs::read_to_string(home.join("whoami")).unwrap().trim(),
        format!("{} {USER}", ids.uid)
    );
    assert_eq!(
        std::fs::read_to_string(home.join("tty-owner"))
            .unwrap()
            .trim(),
        ids.uid.to_string()
    );

    // A home that is the Bots' with no record of it (lost, or never saved) runs nothing.
    let cfg = &m.agent.cfg;
    std::fs::remove_file(cfg.state_dir.join("bot-user.json")).unwrap();
    let lost = Agent::new(cfg.clone(), agent::load(cfg).unwrap()).unwrap();
    let st = lost.bot_user().unwrap();
    assert_eq!(st.state, wire::BOT_USER_FAILED, "{st:?}");
    assert!(st.error.unwrap().contains("belongs to another user"));

    let _ = std::process::Command::new("userdel").arg(USER).status();
}

fn write(path: &std::path::Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}
