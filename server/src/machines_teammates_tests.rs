//! Teammates' own OS users on the owner's machine (ADR 0048), end to end on loopback:
//! the real router, botd's machine port and the real agent over mutual TLS. Tests can't
//! make users, so here a teammate's user is whoever runs them (`teammate_stand_in`) and
//! only the homes are apart; the same code paths run. The last test makes real users
//! and needs root: CI's isolation job runs it.

use crate::acl::Visibility;
use crate::machines::agent::{self, Agent};
use crate::machines::{heartbeats, runas, wire};
use crate::machines_bot_user_tests::until_ready;
use crate::machines_mtls_tests::{
    Env, OnMachine, agent_with_config, events, machine_for, reply_after, serve_with,
};
use crate::tests::call;
use crate::users_http_tests::user_with;
use crate::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// A stand-in Pi (it has no machine login, so a teammate's run needs no key) that says
/// who it ran as, where, and whether it could read `secret` in the owner's home.
fn whoami(secret: &Path) -> String {
    format!(
        r#"#!/bin/sh
if head -c 1 "{secret}" >/dev/null 2>&1; then o=read; else o=denied; fi
echo "$(id -u)" > "$HOME/whoami"
printf '{{"type":"message_end","message":{{"role":"assistant","content":[{{"type":"text","text":"uid=%s user=%s home=%s pwd=%s owner=%s"}}]}}}}\n' "$(id -u)" "$USER" "$HOME" "$(pwd)" "$o"
"#,
        secret = secret.display()
    )
}

fn install(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), body).unwrap();
    std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Pi among the agent's tools, which every user there may run, as harnesses it
/// installs are.
fn with_pi(c: agent::Config) -> agent::Config {
    let bin = c.tools.join("bin");
    install(
        &bin,
        "pi",
        &whoami(&c.home.join(".claude/.credentials.json")),
    );
    agent::Config {
        harness_path: format!("{}:{}", bin.display(), c.harness_path),
        ..c
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

/// What a line of the stand-in's reply says of `key`.
pub(crate) fn said<'a>(reply: &'a str, key: &str) -> &'a str {
    reply
        .split(' ')
        .find_map(|w| w.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in {reply}"))
}

/// Ada's machine, its Bots' user ready, with teammates' users on; Bea is a member.
pub(crate) struct World {
    pub env: Env,
    pub m: OnMachine,
    pub ada: String,
    pub bea_id: String,
    pub bea: String,
    pub secret: std::path::PathBuf,
}

async fn world(f: impl FnOnce(agent::Config) -> agent::Config) -> World {
    world_with(|e| e, |_| {}, f).await
}

/// `world`, with enrollment changed by `ef` as well.
pub(crate) async fn world_with(
    ef: impl FnOnce(crate::machines::enroll::Enrollment) -> crate::machines::enroll::Enrollment,
    auth: impl FnOnce(&mut crate::Auth) + Send + 'static,
    f: impl FnOnce(agent::Config) -> agent::Config,
) -> World {
    let mut env = crate::machines_mtls_tests::serve_with_auth(|e| ef(e.with_teammate_users()), auth).await;
    let (ada, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with_config(&mut env, &mid, &token, "#!/bin/sh\nexit 3\n", |c| {
        with_pi(f(c))
    })
    .await;
    let secret = m.agent.cfg.home.join(".claude/.credentials.json");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "ada's login").unwrap();
    until_ready(&env, &m.agent).await;
    let (bea_id, bea) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    World {
        env,
        m,
        ada,
        bea_id,
        bea,
        secret,
    }
}

pub(crate) fn shared_pi(w: &World) -> String {
    w.env
        .app
        .db
        .create_bot_owned(
            "Team",
            "#fff",
            "waddle",
            "pi",
            None,
            false,
            &w.ada,
            Visibility::Shared,
        )
        .id
}

/// Sends as `auth` and waits for the reply.
pub(crate) async fn run(w: &World, auth: &str, bot: &str, text: &str) -> String {
    let before = w.env.app.db.last_id();
    let (code, m) = call(
        w.env.port,
        "POST",
        &format!("/api/bots/{bot}/messages"),
        auth,
        &json!({ "text": text }).to_string(),
    )
    .await;
    assert_eq!(code, 202, "{m}");
    reply_after(&w.env, bot, before).await
}

pub(crate) async fn ada_auth(w: &World) -> String {
    crate::users_http_tests::signed_in(w.env.port, &w.env.admin, &w.ada)
        .await
        .unwrap()
}

/// `POST /v1/jobs` on the agent's router, as botd's certificate would.
async fn job(a: &std::sync::Arc<Agent>, j: &wire::JobRequest) -> (u16, String) {
    use tower::ServiceExt;
    let req = axum::http::Request::post("/v1/jobs")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(j).unwrap()))
        .unwrap();
    let res = agent::router(a.clone()).oneshot(req).await.unwrap();
    let code = res.status().as_u16();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (code, String::from_utf8_lossy(&body).into_owned())
}

fn job_for(w: &World, cwd: &Path, for_user: Option<&str>) -> wire::JobRequest {
    wire::JobRequest {
        protocol: wire::PROTOCOL,
        job_id: format!("j{}", crate::random_hex(4)),
        bot_id: "b1".into(),
        owner_id: w.ada.clone(),
        for_user: for_user.map(str::to_string),
        message_id: 1,
        bin: "pi".into(),
        args: vec![],
        env: Default::default(),
        cwd: cwd.display().to_string(),
        stdin: None,
        files: vec![],
        cleanup: None,
        collect: vec![],
    }
}

#[tokio::test]
async fn a_teammates_run_goes_to_their_own_home_on_the_owners_machine() {
    let me = runas::current_user().unwrap();
    let w = world(|c| agent::Config {
        teammate_stand_in: Some(me.clone()),
        ..c
    })
    .await;
    let team = shared_pi(&w);
    let home = w.m.agent.cfg.home.clone();
    let ada = ada_auth(&w).await;

    // Ada's own run: the Bots' home, as before.
    let mine = run(&w, &ada, &team, "go").await;
    assert_eq!(
        (said(&mine, "home"), said(&mine, "pwd")),
        (
            home.display().to_string().as_str(),
            home.join("work").display().to_string().as_str()
        ),
        "{mine}"
    );
    assert!(
        events(&w.env, "machine.teammate_user_created")
            .await
            .is_empty()
    );

    // Bea's: her own home under the teammates' folder, made for her now.
    let theirs = run(&w, &w.bea, &team, "go").await;
    let bea_home = w.m.agent.teammates.home_of(&w.bea_id);
    assert_eq!(
        said(&theirs, "home"),
        bea_home.display().to_string(),
        "{theirs}"
    );
    assert_eq!(
        said(&theirs, "pwd"),
        bea_home.join("work").display().to_string(),
        "{theirs}"
    );
    assert!(!bea_home.starts_with(&home));
    assert_eq!(mode(&bea_home), 0o700);
    assert_eq!(mode(&w.m.agent.cfg.teammates), 0o711);
    assert!(bea_home.join("whoami").is_file() && bea_home.join(format!("bots/{team}")).is_dir());
    assert_eq!(mode(&w.m.agent.cfg.state_dir.join("teammates.json")), 0o600);
    let created = events(&w.env, "machine.teammate_user_created").await;
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(
        (
            created[0]["details"]["forUser"].as_str(),
            created[0]["details"]["user"].as_str()
        ),
        (Some(w.bea_id.as_str()), Some(me.as_str()))
    );
    let invoked = events(&w.env, "harness.invoked").await;
    assert!(
        invoked
            .iter()
            .any(|e| e["details"]["forUser"] == w.bea_id.as_str()
                && e["details"]["teammateUser"] == me.as_str()),
        "{invoked:?}"
    );

    // Again: the same home, not made twice.
    let again = run(&w, &w.bea, &team, "again").await;
    assert_eq!(said(&again, "home"), bea_home.display().to_string());
    assert_eq!(
        events(&w.env, "machine.teammate_user_created").await.len(),
        1
    );

    // The agent itself refuses a teammate's job that reaches into the Bots' home, one
    // for another owner, and one naming no plain teammate.
    let (code, body) = job(
        &w.m.agent,
        &job_for(&w, &home.join("work"), Some(&w.bea_id)),
    )
    .await;
    assert_eq!(code, 400, "{body}");
    let mut other = job_for(&w, &bea_home.join("work"), Some(&w.bea_id));
    other.owner_id = w.bea_id.clone();
    assert_eq!(job(&w.m.agent, &other).await.0, 403);
    assert_eq!(
        job(
            &w.m.agent,
            &job_for(&w, &bea_home.join("work"), Some("../x"))
        )
        .await
        .0,
        400
    );
    // ... and an owner's job can't reach into a teammate's home.
    assert_eq!(
        job(&w.m.agent, &job_for(&w, &bea_home.join("work"), None))
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn an_agent_refuses_to_make_a_teammate_its_own_or_the_bots_user() {
    // No stand-in: a teammate's user that turns out to be the agent's own user (as the
    // Bots' user is, here) is refused, and so is Bea's run; nothing runs as the Bots'.
    let w = world(|c| c).await;
    let team = shared_pi(&w);
    let name = wire::teammate_user(&w.bea_id);
    if runas::lookup(&name).is_some() {
        eprintln!("skipped: {name} exists on this host");
        return;
    }
    let said = run(&w, &w.bea, &team, "go").await;
    assert!(
        said.contains("couldn't set up an account for you"),
        "{said}"
    );
    let refused = events(&w.env, "bot.run_refused").await;
    assert!(
        refused
            .iter()
            .any(|e| e["details"]["reason"] == "teammate_user_failed"
                && e["details"]["forUser"] == w.bea_id.as_str()),
        "{refused:?}"
    );
    assert!(
        events(&w.env, "harness.invoked").await.is_empty(),
        "nothing ran"
    );
}

#[tokio::test]
async fn teammates_runs_stay_as_before_unless_asked() {
    let mut env = serve_with(|e| e.with_bot_user()).await;
    let (ada, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with_config(&mut env, &mid, &token, "#!/bin/sh\nexit 3\n", with_pi).await;
    until_ready(&env, &m.agent).await;
    heartbeats(&env.app, &env.cp).await;
    let (_, bea) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let team = env
        .app
        .db
        .create_bot_owned(
            "Team",
            "#fff",
            "waddle",
            "pi",
            None,
            false,
            &ada,
            Visibility::Shared,
        )
        .id;
    let before = env.app.db.last_id();
    let (code, _) = call(
        env.port,
        "POST",
        &format!("/api/bots/{team}/messages"),
        &bea,
        r#"{"text":"go"}"#,
    )
    .await;
    assert_eq!(code, 202);
    let reply = reply_after(&env, &team, before).await;
    assert_eq!(
        said(&reply, "home"),
        m.agent.cfg.home.display().to_string(),
        "the Bots' home, as ADR 0046 has it"
    );
    assert!(
        events(&env, "machine.teammate_user_created")
            .await
            .is_empty()
    );
    assert!(!m.agent.cfg.state_dir.join("teammates.json").exists());
    assert!(
        std::fs::read_dir(&m.agent.cfg.teammates).map_or(true, |mut d| d.next().is_none()),
        "no teammate's home"
    );
}

/// As root, on a host CI throws away: real users are made, and a teammate's run can't
/// read the owner's home, logins or the agent's files.
#[tokio::test]
#[ignore = "needs root: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_a_teammates_run_gets_their_own_os_user_and_cant_read_the_owners_home() {
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") || !runas::is_root() {
        eprintln!("skipped: needs root and SUPERBOT_MACHINE_BOT_USER_TEST=1");
        return;
    }
    const USER: &str = "superbot-bots-tt";
    let _ = std::process::Command::new("userdel").arg(USER).status();
    let state = crate::db::temp_path("agent-root-tm");
    let w = world(|c| agent::Config {
        state_dir: state.clone(),
        bot_user: USER.into(),
        allow_own_user: false,
        teammates: state.join("teammates"),
        ..c
    })
    .await;
    let teammate = wire::teammate_user(&w.bea_id);
    let _ = std::process::Command::new("userdel")
        .arg(&teammate)
        .status();
    let team = shared_pi(&w);
    let (bots, _) = runas::lookup(USER).expect("the agent made the Bots' user");
    std::fs::set_permissions(&w.secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::chown(&w.secret, Some(bots.uid), Some(bots.gid)).unwrap();
    let ada = ada_auth(&w).await;

    // Ada's run, as the Bots' user, reads her own login.
    let mine = run(&w, &ada, &team, "go").await;
    assert_eq!(
        (said(&mine, "uid"), said(&mine, "owner")),
        (bots.uid.to_string().as_str(), "read"),
        "{mine}"
    );

    // Bea's, as her own user, can't.
    let theirs = run(&w, &w.bea, &team, "go").await;
    let (ids, _) = runas::lookup(&teammate).expect("the agent made Bea's user");
    assert!(
        ids.uid != 0 && ids.uid != bots.uid && ids.gid != bots.gid,
        "{ids:?}"
    );
    assert_eq!(
        (
            said(&theirs, "uid"),
            said(&theirs, "user"),
            said(&theirs, "owner")
        ),
        (ids.uid.to_string().as_str(), teammate.as_str(), "denied"),
        "{theirs}"
    );
    let bea_home = w.m.agent.teammates.home_of(&w.bea_id);
    assert_eq!(
        (std::fs::metadata(&bea_home).unwrap().uid(), mode(&bea_home)),
        (ids.uid, 0o700)
    );
    assert_eq!(
        std::fs::metadata(bea_home.join("whoami")).unwrap().uid(),
        ids.uid
    );
    // The Bots' user can't read Bea's home either.
    let peek = std::process::Command::new("runuser")
        .args(["-u", USER, "--", "ls", &bea_home.display().to_string()])
        .output()
        .unwrap();
    assert!(!peek.status.success(), "the Bots' user listed Bea's home");

    // A home taken over by a link is refused, never followed.
    std::fs::remove_dir_all(&bea_home).unwrap();
    std::os::unix::fs::symlink(&w.m.agent.cfg.home, &bea_home).unwrap();
    let said_now = run(&w, &w.bea, &team, "again").await;
    assert!(
        said_now.contains("couldn't set up an account for you"),
        "{said_now}"
    );
    assert_eq!(
        std::fs::symlink_metadata(&w.m.agent.cfg.home)
            .unwrap()
            .uid(),
        bots.uid,
        "the Bots' home stays theirs"
    );

    let _ = std::process::Command::new("userdel")
        .arg(&teammate)
        .status();
    let _ = std::process::Command::new("userdel").arg(USER).status();
}
