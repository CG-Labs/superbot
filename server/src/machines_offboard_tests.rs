//! Teammates leaving (ADR 0052), end to end on loopback: the real router, botd's
//! machine port and the real agent over mutual TLS. As in machines_teammates_tests, a
//! teammate's user is whoever runs the tests, so only homes and work are apart; the
//! agent's own removal of users and processes is tested with fake accounts in
//! machines::teammates.

use crate::acl::Visibility;
use crate::machines::agent;
use crate::machines::{heartbeats, runas};
use crate::machines_mtls_tests::{events, json_call, wait_for_event};
use crate::machines_teammates_tests::{World, ada_auth, run, shared_pi, world_with};
use crate::tests::call;
use crate::users_http_tests::user_with;
use serde_json::json;
use std::path::Path;

fn stand_in(c: agent::Config) -> agent::Config {
    agent::Config {
        teammate_stand_in: Some(runas::current_user().unwrap()),
        ..c
    }
}

/// Leaves a file in `home`'s work folder, as a teammate's run would.
fn work_in(home: &Path, name: &str, text: &str) {
    std::fs::create_dir_all(home.join("work")).unwrap();
    std::fs::write(home.join("work").join(name), text).unwrap();
}

fn removals(w: &World, state: &str) -> Vec<crate::db::TeammateCleanup> {
    w.env.app.db.teammate_cleanups(Some(state), None)
}

/// A round of heartbeats, and the removals it started.
async fn pass(w: &World) {
    heartbeats(&w.env.app, &w.env.cp).await;
    crate::machines::offboard::settled(&w.env.app).await;
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("never: {what}");
}

#[tokio::test]
async fn a_disabled_teammate_loses_their_user_and_their_work_goes_to_the_owner() {
    let w = world_with(|e| e, |_| {}, stand_in).await;
    let team = shared_pi(&w);
    let ada = ada_auth(&w).await;
    let (cy_id, cy) = user_with(w.env.port, &w.env.admin, "cy@example.com", "member").await;
    run(&w, &ada, &team, "go").await;
    run(&w, &w.bea, &team, "go").await;
    run(&w, &cy, &team, "go").await;
    let t = &w.m.agent.teammates;
    let (bea_home, cy_home) = (t.home_of(&w.bea_id), t.home_of(&cy_id));
    work_in(&bea_home, "notes.txt", "bea's notes");
    work_in(&cy_home, "plan.txt", "cy's plan");
    let owner_home = w.m.agent.cfg.home.clone();

    let (code, _) = json_call(&w.env, "PATCH", &format!("/api/users/{}", w.bea_id), r#"{"status":"disabled"}"#).await;
    assert_eq!(code, 200);
    let removed = wait_for_event(&w.env, "machine.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    let d = &removed[0]["details"];
    assert_eq!((d["forUser"].as_str(), d["reason"].as_str(), d["work"].as_str()), (Some(w.bea_id.as_str()), Some("disabled"), Some("archived")), "{d}");
    let queued = events(&w.env, "machine.teammate_removal_queued").await;
    assert_eq!(queued.len(), 1, "{queued:?}");

    // Bea's home is gone, and her work is in the owner's workspace, the Bots' to read.
    assert!(std::fs::symlink_metadata(&bea_home).is_err(), "Bea's home is still there");
    let to = Path::new(d["archivedTo"].as_str().unwrap()).to_path_buf();
    assert!(to.starts_with(owner_home.join("work/from-teammates")), "{}", to.display());
    assert!(to.file_name().unwrap().to_str().unwrap().starts_with("bea-"), "{}", to.display());
    assert_eq!(std::fs::read_to_string(to.join("notes.txt")).unwrap(), "bea's notes");
    assert!(!std::fs::read_to_string(w.m.agent.cfg.state_dir.join("teammates.json")).unwrap().contains(&w.bea_id));

    // Ada's home and login, and Cy's home and work, are untouched.
    assert_eq!(std::fs::read_to_string(&w.secret).unwrap(), "ada's login");
    assert_eq!(std::fs::read_to_string(cy_home.join("work/plan.txt")).unwrap(), "cy's plan");
    assert!(t.known().contains(&cy_id));
    assert!(events(&w.env, "machine.teammate_removal_failed").await.is_empty());

    // Asking again changes nothing: no second removal, however many passes.
    for _ in 0..2 {
        pass(&w).await;
        json_call(&w.env, "POST", "/api/machines/reconcile", "").await;
    }
    crate::machines::offboard::left(&w.env.app, &crate::audit::Who::system("test"), &w.bea_id, "disabled");
    pass(&w).await;
    assert_eq!(events(&w.env, "machine.teammate_removed").await.len(), 1);
    assert_eq!(events(&w.env, "machine.teammate_removal_queued").await.len(), 1);
    assert_eq!(removals(&w, "done").len(), 1);
    assert!(removals(&w, "pending").is_empty());
    assert_eq!(std::fs::read_to_string(cy_home.join("work/plan.txt")).unwrap(), "cy's plan");

    // The admin API shows who's left on the machine, and what was removed.
    let (code, v) = json_call(&w.env, "GET", &format!("/api/users/{}/machine/teammates", w.ada), "").await;
    assert_eq!(code, 200, "{v}");
    let there: Vec<&str> = v["teammates"].as_array().unwrap().iter().filter_map(|t| t["id"].as_str()).collect();
    assert_eq!(there, [cy_id.as_str()], "{v}");
    assert_eq!(v["teammates"][0]["wanted"], true);
    assert_eq!(v["canRemove"], true);
    assert_eq!(v["removals"][0]["state"], "done", "{v}");
    let (code, v) = json_call(&w.env, "GET", "/api/machines/teammate-removals?state=done", "").await;
    assert_eq!((code, v["files"].as_str(), v["removals"].as_array().map(Vec::len)), (200, Some("archive"), Some(1)), "{v}");
    assert_eq!(v["removals"][0]["teammate"]["email"], "bea@example.com");
    assert_eq!(json_call(&w.env, "GET", "/api/machines/teammate-removals?state=soon", "").await.0, 400);

    // Back again, Bea gets a new home; the owner's Bots never lost access to her work.
    json_call(&w.env, "PATCH", &format!("/api/users/{}", w.bea_id), r#"{"status":"active"}"#).await;
    let bea = crate::users_http_tests::signed_in(w.env.port, &w.env.admin, &w.bea_id).await.unwrap();
    run(&w, &bea, &team, "back").await;
    assert!(bea_home.join("whoami").is_file());
    assert!(to.join("notes.txt").is_file());
}

#[tokio::test]
async fn a_revoked_grant_is_retried_while_the_machine_is_offline_and_cancelled_only_if_never_asked() {
    let mut w = world_with(|e| e, |_| {}, stand_in).await;
    let private = w
        .env
        .app
        .db
        .create_bot_owned("Mine", "#fff", "waddle", "pi", None, false, &w.ada, Visibility::Private)
        .id;
    let ada = ada_auth(&w).await;
    let (cy_id, cy) = user_with(w.env.port, &w.env.admin, "cy@example.com", "member").await;
    for id in [&w.bea_id, &cy_id] {
        let (code, _) = call(w.env.port, "PUT", &format!("/api/bots/{private}/grants/{id}"), &ada, r#"{"level":"operator"}"#).await;
        assert_eq!(code, 200);
    }
    run(&w, &w.bea, &private, "go").await;
    run(&w, &cy, &private, "go").await;
    let t = w.m.agent.teammates.clone();
    let (bea_home, cy_home) = (t.home_of(&w.bea_id), t.home_of(&cy_id));
    pass(&w).await;

    // The machine goes away; both lose the Bot.
    w.m.server.abort();
    let _ = (&mut w.m.server).await;
    for id in [&w.bea_id, &cy_id] {
        let (code, _) = call(w.env.port, "DELETE", &format!("/api/bots/{private}/grants/{id}"), &ada, "").await;
        assert_eq!(code, 200);
    }
    wait_until("both failed once", || removals(&w, "pending").iter().all(|r| r.attempts >= 1) && removals(&w, "pending").len() == 2).await;
    let (_, v) = json_call(&w.env, "GET", "/api/machines/teammate-removals", "").await;
    assert_eq!(v["openByMachine"][0]["pending"], 2, "{v}");
    for _ in 0..3 {
        pass(&w).await;
    }
    let failed = events(&w.env, "machine.teammate_removal_failed").await;
    assert_eq!(failed.len(), 2, "one failure each in the log, not one a pass: {failed:?}");
    assert!(removals(&w, "pending").iter().all(|r| r.attempts >= 2 && r.last_error.is_some()));
    assert!(bea_home.is_dir() && cy_home.is_dir());

    // Cy gets it back before the machine does. The agent may have done part of hers
    // already, so it's finished rather than left half done; then it's back.
    let (code, _) = call(w.env.port, "PUT", &format!("/api/bots/{private}/grants/{cy_id}"), &ada, r#"{"level":"operator"}"#).await;
    assert_eq!(code, 200);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", w.env.e.agent_port)).await.unwrap();
    tokio::spawn(agent::serve(listener, w.m.agent.clone()));
    pass(&w).await;

    let removed = events(&w.env, "machine.teammate_removed").await;
    let mut who: Vec<&str> = removed.iter().filter_map(|e| e["details"]["forUser"].as_str()).collect();
    who.sort();
    let mut both = [w.bea_id.as_str(), cy_id.as_str()];
    both.sort();
    assert_eq!(who, both, "{removed:?}");
    assert!(removed.iter().all(|e| e["details"]["reason"] == "access_lost"));
    assert!(events(&w.env, "machine.teammate_removal_cancelled").await.is_empty());
    assert!(std::fs::symlink_metadata(&bea_home).is_err() && std::fs::symlink_metadata(&cy_home).is_err());
    assert_eq!(std::fs::read_to_string(&w.secret).unwrap(), "ada's login");
    assert!(removals(&w, "pending").is_empty());
    run(&w, &cy, &private, "back").await;
    assert!(cy_home.join("whoami").is_file(), "Cy gets a new home on her next run");

    // An agent too old to remove anyone isn't asked: Dee's removal waits, and is
    // cancelled when she gets the Bot back before the agent is upgraded.
    let (dee_id, dee) = user_with(w.env.port, &w.env.admin, "dee@example.com", "member").await;
    let (code, _) = call(w.env.port, "PUT", &format!("/api/bots/{private}/grants/{dee_id}"), &ada, r#"{"level":"operator"}"#).await;
    assert_eq!(code, 200);
    run(&w, &dee, &private, "go").await;
    pass(&w).await;
    let m = w.env.app.db.user_machine(&w.ada).unwrap();
    let mut old = m.agent_upkeep.clone().unwrap();
    old["can"] = json!(old["can"].as_array().unwrap().iter().filter(|c| *c != "teammate_removal").cloned().collect::<Vec<_>>());
    assert!(w.env.app.db.machine_upkeep_swap(&m.id, m.agent_upkeep.as_ref(), &old));
    assert_eq!(call(w.env.port, "DELETE", &format!("/api/bots/{private}/grants/{dee_id}"), &ada, "").await.0, 200);
    crate::machines::offboard::settled(&w.env.app).await;
    let waiting = removals(&w, "pending");
    assert_eq!((waiting.len(), waiting[0].attempts), (1, 0), "not asked");
    assert!(waiting[0].last_error.as_deref().unwrap().contains("upgrade"), "{:?}", waiting[0].last_error);
    assert_eq!(call(w.env.port, "PUT", &format!("/api/bots/{private}/grants/{dee_id}"), &ada, r#"{"level":"operator"}"#).await.0, 200);
    pass(&w).await;
    let cancelled = events(&w.env, "machine.teammate_removal_cancelled").await;
    assert_eq!((cancelled.len(), cancelled[0]["details"]["forUser"].as_str(), cancelled[0]["details"]["why"].as_str()), (1, Some(dee_id.as_str()), Some("access_back")));
    assert!(t.home_of(&dee_id).join("whoami").is_file(), "Dee keeps her home");
    assert!(removals(&w, "pending").is_empty());

    // Dee loses it again, and an admin asks for her removal while it waits: it's the
    // admin's now, so getting the Bot back before the agent is upgraded doesn't cancel it.
    let m = w.env.app.db.user_machine(&w.ada).unwrap();
    assert!(w.env.app.db.machine_upkeep_swap(&m.id, m.agent_upkeep.as_ref(), &old));
    assert_eq!(call(w.env.port, "DELETE", &format!("/api/bots/{private}/grants/{dee_id}"), &ada, "").await.0, 200);
    crate::machines::offboard::settled(&w.env.app).await;
    assert_eq!(removals(&w, "pending")[0].reason, "access_lost");
    let (code, v) = json_call(&w.env, "POST", &format!("/api/users/{}/machine/teammates/{dee_id}/remove", w.ada), "").await;
    assert_eq!(code, 202, "the agent is still too old: {v}");
    assert_eq!(removals(&w, "pending")[0].reason, "admin");
    let forced = events(&w.env, "machine.teammate_removal_forced").await;
    assert_eq!((forced.len(), forced[0]["details"]["was"].as_str()), (1, Some("access_lost")), "{forced:?}");
    assert_eq!(call(w.env.port, "PUT", &format!("/api/bots/{private}/grants/{dee_id}"), &ada, r#"{"level":"operator"}"#).await.0, 200);
    pass(&w).await;
    assert_eq!(events(&w.env, "machine.teammate_removal_cancelled").await.len(), 1, "only the earlier one");
    assert!(removals(&w, "pending").is_empty());
    let done = events(&w.env, "machine.teammate_removed").await;
    let dees: Vec<_> = done.iter().filter(|e| e["details"]["forUser"] == dee_id.as_str()).collect();
    assert_eq!((dees.len(), &dees[0]["details"]["reason"]), (1, &json!("admin")), "{done:?}");
    assert!(std::fs::symlink_metadata(t.home_of(&dee_id)).is_err(), "the admin's removal went through");
}

#[tokio::test]
async fn scim_deprovisioning_and_a_deleted_bot_remove_teammates_too() {
    let w = world_with(|e| e, |a| a.scim.enabled = true, stand_in).await;
    let (port, admin) = (w.env.port, w.env.admin.clone());
    let team = shared_pi(&w);
    let (code, t) = call(port, "POST", "/api/scim/tokens", &admin, r#"{"tenant":"okta"}"#).await;
    assert_eq!(code, 201, "{t}");
    let scim = format!("Bearer {}", crate::users_http_tests::parse(&t)["token"].as_str().unwrap());
    let mut ids = Vec::new();
    for (name, ext) in [("dee@example.com", "00u1"), ("eve@example.com", "00u2")] {
        let body = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": name, "externalId": ext, "active": true });
        let (code, u) = call(port, "POST", "/scim/v2/Users", &scim, &body.to_string()).await;
        assert_eq!(code, 201, "{u}");
        let id = crate::users_http_tests::parse(&u)["id"].as_str().unwrap().to_string();
        let auth = crate::users_http_tests::signed_in(port, &admin, &id).await.unwrap();
        run(&w, &auth, &team, "go").await;
        ids.push(id);
    }
    run(&w, &w.bea, &team, "go").await;
    let home = |id: &str| w.m.agent.teammates.home_of(id);

    let off = json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] });
    assert_eq!(call(port, "PATCH", &format!("/scim/v2/Users/{}", ids[0]), &scim, &off.to_string()).await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/scim/v2/Users/{}", ids[1]), &scim, "").await.0, 204);
    wait_until("both removed", || removals(&w, "done").len() == 2).await;
    let removed = events(&w.env, "machine.teammate_removed").await;
    assert!(removed.iter().all(|e| e["details"]["reason"] == "deprovisioned"), "{removed:?}");
    assert!(std::fs::symlink_metadata(home(&ids[0])).is_err() && std::fs::symlink_metadata(home(&ids[1])).is_err());
    assert!(home(&w.bea_id).is_dir(), "Bea still has the Bot");

    // The only Bot Bea shared with Ada is deleted: she has no use for a user there.
    let ada = ada_auth(&w).await;
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{team}"), &ada, "").await.0, 200);
    wait_until("Bea removed", || removals(&w, "done").len() == 3).await;
    assert!(std::fs::symlink_metadata(home(&w.bea_id)).is_err());
    assert_eq!(std::fs::read_to_string(&w.secret).unwrap(), "ada's login");
    let reasons: Vec<String> = removals(&w, "done").iter().map(|r| r.reason.clone()).collect();
    assert!(reasons.contains(&"access_lost".to_string()), "{reasons:?}");
}

/// As root, on a host CI throws away: Bea's real user, processes and temp files go;
/// her work goes to the Bots' user; Cy's user and the Bots' are untouched.
#[tokio::test]
#[ignore = "needs root: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_a_leaving_teammates_user_processes_and_files_go_and_no_one_elses() {
    use std::os::unix::fs::MetadataExt;
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") || !runas::is_root() {
        eprintln!("skipped: needs root and SUPERBOT_MACHINE_BOT_USER_TEST=1");
        return;
    }
    const USER: &str = "superbot-bots-to";
    let userdel = |u: &str| {
        let _ = std::process::Command::new("userdel").arg(u).status();
    };
    userdel(USER);
    let state = crate::db::temp_path("agent-root-off");
    let w = world_with(
        |e| e,
        |_| {},
        |c| agent::Config {
            state_dir: state.clone(),
            bot_user: USER.into(),
            allow_own_user: false,
            teammates: state.join("teammates"),
            ..c
        },
    )
    .await;
    let (cy_id, cy) = user_with(w.env.port, &w.env.admin, "cy@example.com", "member").await;
    let (bea_user, cy_user) = (crate::machines::wire::teammate_user(&w.bea_id), crate::machines::wire::teammate_user(&cy_id));
    userdel(&bea_user);
    userdel(&cy_user);
    let team = shared_pi(&w);
    run(&w, &w.bea, &team, "go").await;
    run(&w, &cy, &team, "go").await;
    let (bots, _) = runas::lookup(USER).expect("the Bots' user");
    let (bea_ids, _) = runas::lookup(&bea_user).expect("Bea's user");
    let (cy_ids, _) = runas::lookup(&cy_user).expect("Cy's user");
    let t = &w.m.agent.teammates;
    let (bea_home, cy_home) = (t.home_of(&w.bea_id), t.home_of(&cy_id));
    work_in(&bea_home, "notes.txt", "bea's notes");
    std::os::unix::fs::chown(bea_home.join("work/notes.txt"), Some(bea_ids.uid), Some(bea_ids.gid)).unwrap();
    // A second link to her own file is copied; one to root's secret is never read.
    std::fs::hard_link(bea_home.join("work/notes.txt"), bea_home.join("work/again.txt")).unwrap();
    let secret = state.join("root-only");
    std::fs::write(&secret, "root's").unwrap();
    std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    std::fs::hard_link(&secret, bea_home.join("work/secret")).unwrap();
    let as_user = |u: &str, cmd: &str| std::process::Command::new("runuser").args(["-u", u, "--", "sh", "-c", cmd]).spawn().unwrap();
    let mut bea_sleep = as_user(&bea_user, "exec sleep 300");
    let mut cy_sleep = as_user(&cy_user, "exec sleep 300");
    let bea_tmp = std::env::temp_dir().join(format!("bea-{}", crate::random_hex(4)));
    let made = std::process::Command::new("runuser").args(["-u", &bea_user, "--", "touch", &bea_tmp.display().to_string()]).status().unwrap();
    assert!(made.success());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let (code, _) = json_call(&w.env, "PATCH", &format!("/api/users/{}", w.bea_id), r#"{"status":"disabled"}"#).await;
    assert_eq!(code, 200);
    let removed = wait_for_event(&w.env, "machine.teammate_removed").await;
    let d = &removed[0]["details"];
    assert_eq!((d["userRemoved"].as_bool(), d["alreadyGone"].as_bool()), (Some(true), Some(false)), "{d}");
    assert!(d["processesStopped"].as_u64().unwrap() >= 1, "{d}");
    assert!(runas::lookup(&bea_user).is_none(), "Bea's user is gone");
    assert!(std::fs::symlink_metadata(&bea_home).is_err());
    assert!(!bea_tmp.exists(), "her temp files are gone");
    let _ = bea_sleep.wait();
    assert!(std::fs::read_dir("/proc").unwrap().flatten().all(|p| p.metadata().map_or(true, |m| m.uid() != bea_ids.uid)), "her processes were stopped");
    let to = Path::new(d["archivedTo"].as_str().unwrap()).to_path_buf();
    assert_eq!(std::fs::read_to_string(to.join("notes.txt")).unwrap(), "bea's notes");
    assert_eq!(std::fs::metadata(to.join("notes.txt")).unwrap().uid(), bots.uid, "the Bots' user has her work");
    let again = std::fs::metadata(to.join("again.txt")).unwrap();
    assert_eq!((again.uid(), again.nlink()), (bots.uid, 1), "a hard link of hers is a copy of its own");
    let s = std::fs::metadata(to.join("secret")).unwrap();
    assert_eq!((s.uid(), s.mode() & 0o777), (0, 0o600), "root's file isn't given away");
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "root's");

    // Cy and the Bots' user are untouched.
    assert_eq!(runas::lookup(&cy_user).map(|(i, _)| i), Some(cy_ids));
    assert_eq!(runas::lookup(USER).map(|(i, _)| i), Some(bots));
    assert_eq!(std::fs::metadata(&cy_home).unwrap().uid(), cy_ids.uid);
    let runs = |u: &str| std::process::Command::new("pgrep").args(["-u", u, "sleep"]).status().is_ok_and(|s| s.success());
    assert!(runs(&cy_user), "Cy's process still runs");
    let _ = std::process::Command::new("pkill").args(["-KILL", "-u", &cy_user]).status();
    let _ = cy_sleep.wait();
    userdel(&cy_user);
    userdel(USER);
}

#[tokio::test]
async fn deleted_work_is_held_then_purged_and_an_admin_can_remove_a_teammate_now() {
    let w = world_with(|e| e.with_teammate_files_deleted(3), |_| {}, stand_in).await;
    let team = shared_pi(&w);
    run(&w, &w.bea, &team, "go").await;
    let bea_home = w.m.agent.teammates.home_of(&w.bea_id);
    work_in(&bea_home, "notes.txt", "bea's notes");
    let owner_home = w.m.agent.cfg.home.clone();

    // Not the machine's own user, and not by a made-up name.
    let path = |t: &str| format!("/api/users/{}/machine/teammates/{t}/remove", w.ada);
    assert_eq!(json_call(&w.env, "POST", &path(&w.ada), "").await.0, 400);
    assert_eq!(json_call(&w.env, "POST", &path("..%2Fx"), "").await.0, 400);

    // Bea still has access; an admin removes her user anyway.
    let (code, v) = json_call(&w.env, "POST", &path("bea@example.com"), "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["removal"]["state"].as_str(), v["removal"]["reason"].as_str(), v["agent"]["files"].as_str()), (Some("held"), Some("admin"), Some("held")), "{v}");
    assert!(v["removal"]["purgeAt"].as_i64().unwrap() > crate::db::now() + 2 * 86_400_000);
    assert!(std::fs::symlink_metadata(&bea_home).is_err());
    assert!(!owner_home.join("work/from-teammates").exists(), "nothing archived");
    let id = v["removal"]["id"].as_str().unwrap().to_string();
    let held = w.m.agent.cfg.teammates.join(".left").join(&id);
    assert_eq!(std::fs::read_to_string(held.join("notes.txt")).unwrap(), "bea's notes");

    // Its days aren't up: kept. Then they are: deleted, once.
    pass(&w).await;
    assert!(held.is_dir());
    w.env.app.db.teammate_cleanup_due_now(&id);
    pass(&w).await;
    assert!(!held.exists());
    pass(&w).await;
    let purged = events(&w.env, "machine.teammate_files_purged").await;
    assert_eq!((purged.len(), purged[0]["details"]["purged"].as_bool()), (1, Some(true)), "{purged:?}");
    assert_eq!(w.env.app.db.teammate_cleanup(&id).unwrap().state, "done");

    // She still has access, so a later run makes her a new home.
    run(&w, &w.bea, &team, "again").await;
    assert!(bea_home.join("whoami").is_file());
    assert!(removals(&w, "pending").is_empty(), "an admin's removal isn't redone");
}

/// Old harness sessions on the machine go, in the owner's and teammates' homes and the
/// Bots' folders, and so does archived work once old, by the agent (ADR 0112).
#[tokio::test]
async fn retention_reaches_the_machine_for_sessions_and_archived_work() {
    const A: &str = "0b9d2f6e-3c1a-4e8b-9f00-1a2b3c4d5e6f";
    const B: &str = "1c8e3a7f-4d2b-4f9c-8e11-2b3c4d5e6f70";
    let w = world_with(|e| e, |_| {}, stand_in).await;
    let team = shared_pi(&w);
    let ada = ada_auth(&w).await;
    run(&w, &ada, &team, "go").await;
    run(&w, &w.bea, &team, "go").await;
    let t = &w.m.agent.teammates;
    let (owner_home, bea_home) = (w.m.agent.cfg.home.clone(), t.home_of(&w.bea_id));
    // Bea's own session, in her home there.
    let bea_session = bea_home.join(format!(
        ".codex/sessions/2026/01/02/rollout-2026-01-02T03-04-05-{A}.jsonl"
    ));
    std::fs::create_dir_all(bea_session.parent().unwrap()).unwrap();
    std::fs::write(&bea_session, "{}").unwrap();
    work_in(&bea_home, "notes.txt", "bea's notes");
    let claude = |home: &Path, id: &str| home.join(format!(".claude/projects/-work/{id}.jsonl"));
    let pi = owner_home.join(format!(
        "bots/{team}/pi-sessions/2026-01-02T03-04-05_s-{B}.jsonl"
    ));
    for f in [claude(&owner_home, A), pi.clone()] {
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "{}").unwrap();
    }
    std::fs::write(
        owner_home.join(".claude/projects/-work/notes.md"),
        "no session id",
    )
    .unwrap();

    // A reply lands before its run lets go of the Bot's session files; the pass skips a
    // Bot whose run still holds them.
    wait_until("the last run lets go of the Bot's session files", || {
        w.env.app.sweeping_session_files(&team).is_some()
    })
    .await;
    // Everything here is from today: a pass 100 days on finds it old.
    let later = crate::db::now() + 100 * 86_400_000;
    let p = crate::file_retention::prune_sessions(&w.env.app, 30, later).await;
    assert!(p["errors"].as_array().unwrap().is_empty(), "{p}");
    assert_eq!(
        p["places"].as_u64(),
        Some(2),
        "this server and the machine: {p}"
    );
    for gone in [claude(&owner_home, A), pi.clone(), bea_session.clone()] {
        assert!(!gone.exists(), "{}", gone.display());
    }
    assert!(
        owner_home.join(".claude/projects/-work/notes.md").is_file(),
        "no session id, never touched"
    );
    assert!(bea_home.join("work/notes.txt").is_file(), "only sessions");

    let (code, _) = json_call(
        &w.env,
        "PATCH",
        &format!("/api/users/{}", w.bea_id),
        r#"{"status":"disabled"}"#,
    )
    .await;
    assert_eq!(code, 200);
    let removed = wait_for_event(&w.env, "machine.teammate_removed").await;
    let to = Path::new(removed[0]["details"]["archivedTo"].as_str().unwrap()).to_path_buf();
    assert!(to.join("notes.txt").is_file());
    pass(&w).await;
    let f = crate::file_retention::prune_teammate_files(&w.env.app, 30, later).await;
    assert_eq!(
        (f["deleted"].as_u64(), f["errors"].as_array().map(Vec::len)),
        (Some(1), Some(0)),
        "{f}"
    );
    assert!(!to.exists() && owner_home.join("work/from-teammates").is_dir());
    assert_eq!(events(&w.env, "teammate_files.pruned").await.len(), 1);
}

/// The agent sweeps only for its own user, and only plain paths inside the homes there.
#[tokio::test]
async fn the_agent_refuses_a_sweep_outside_its_homes() {
    use tower::ServiceExt;
    let w = world_with(|e| e, |_| {}, stand_in).await;
    let ask = |body: serde_json::Value| {
        let req = axum::http::Request::post("/v1/retention")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let router = agent::router(w.m.agent.clone());
        async move { router.oneshot(req).await.unwrap().status().as_u16() }
    };
    let dir = |p: &str, depth: u32| json!([{ "path": p, "depth": depth }]);
    assert_eq!(
        ask(json!({ "ownerId": "someone-else", "before": 0 })).await,
        403
    );
    for bad in [
        json!({ "ownerId": w.ada, "before": 0, "home": dir("../etc", 1) }),
        json!({ "ownerId": w.ada, "before": 0, "home": dir("/etc", 1) }),
        json!({ "ownerId": w.ada, "before": 0, "state": dir("pi-sessions", 0) }),
        json!({ "ownerId": w.ada, "before": 0, "bots": ["../b"] }),
        json!({ "ownerId": w.ada, "before": 0, "archives": ["a/b"] }),
        json!({ "ownerId": w.ada, "before": 0, "probe": ["../hermes/state.db"] }),
        json!({ "ownerId": w.ada, "before": 0, "probe": ["b".repeat(161)] }),
        json!({ "ownerId": w.ada, "before": 0, "surprise": 1 }),
    ] {
        assert!(matches!(ask(bad.clone()).await, 400 | 422), "{bad}");
    }
    assert_eq!(
        ask(json!({ "ownerId": w.ada, "before": 0, "archives": ["nothing-here"] })).await,
        200
    );
    // It says which session databases are there, so a Bot's harness prunes only those.
    let db = w.m.agent.cfg.home.join("bots/b1/hermes/state.db");
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    std::fs::write(&db, "").unwrap();
    let body = json!({ "ownerId": w.ada, "before": 0, "probe": ["b1/hermes/state.db", "b2/hermes/state.db"] });
    let req = axum::http::Request::post("/v1/retention")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = agent::router(w.m.agent.clone()).oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(out["found"], json!([[null, "b1/hermes/state.db"]]), "{out}");
}
