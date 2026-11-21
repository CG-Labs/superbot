//! Harness logins and folder copies on a user's machine (ADR 0041), end to end on
//! loopback: the real router, botd's machine port, and the real agent over mutual TLS,
//! with a stand-in harness on its PATH.

use crate::machines_mtls_tests::{Env, agent_with, events, json_call, machine_for, reply_after, send, serve_with, wait_for_event};
use crate::*;

/// A stand-in Claude. `claude auth login` asks for a code in its terminal and saves a
/// login made from it; anything else is a run that says it ran.
const CLAUDE: &str = r#"#!/bin/sh
if [ "$1 $2" = "auth login" ]; then
  printf 'Open the link, then paste the code here: '
  read code
  mkdir -p "$HOME/.claude"
  printf '{"token":"%s-saved"}' "$code" > "$HOME/.claude/.credentials.json"
  echo "Logged in."
  exit 0
fi
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ran on the machine"}]}}'
"#;

/// A stand-in Claude whose login waits until it's stopped.
const SLOW_LOGIN: &str = "#!/bin/sh\necho 'Waiting for the browser...'\nsleep 60\n";

fn owned_bot(env: &Env, uid: &str) -> String {
    env.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, uid, crate::acl::Visibility::Shared).id
}

fn refusals(evs: &[Value], reason: &str) -> usize {
    evs.iter().filter(|e| e["details"]["reason"] == reason).count()
}

/// Waits for at least `n` `action` events, newest first.
async fn wait_for_events(env: &Env, action: &str, n: usize) -> Vec<Value> {
    for _ in 0..800 {
        let evs = events(env, action).await;
        if evs.len() >= n {
            return evs;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("fewer than {n} {action} events");
}

/// A login started through botd's API, read line by line.
pub(crate) struct Login {
    res: reqwest::Response,
    buf: Vec<u8>,
}

impl Login {
    async fn start(env: &Env, user: &str, harness: &str) -> Login {
        Login::open(env, &format!("/api/users/{user}/machine/harness-login"), &env.admin, harness).await
    }

    /// Starts one at `path`, as `auth`.
    pub(crate) async fn open(env: &Env, path: &str, auth: &str, harness: &str) -> Login {
        let res = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}{path}", env.port))
            .header("Authorization", auth)
            .json(&json!({ "harness": harness }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(res.headers()["content-type"], "application/x-ndjson");
        Login { res, buf: Vec::new() }
    }

    async fn next(&mut self) -> Value {
        loop {
            if let Some(at) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=at).collect();
                return serde_json::from_slice(&line).unwrap();
            }
            let chunk = tokio::time::timeout(Duration::from_secs(20), self.res.chunk()).await.unwrap().unwrap();
            self.buf.extend_from_slice(&chunk.expect("the login stream ended early"));
        }
    }

    /// Reads up to the first event of `kind`, gathering the output on the way.
    pub(crate) async fn until(&mut self, kind: &str) -> (Value, String) {
        self.reading(|ev, _| ev["type"] == kind).await
    }

    /// Reads until the output so far holds `text`.
    pub(crate) async fn until_shown(&mut self, text: &str) -> String {
        self.reading(|_, out| out.contains(text)).await.1
    }

    async fn reading(&mut self, done: impl Fn(&Value, &str) -> bool) -> (Value, String) {
        let mut out = String::new();
        let read = async {
            loop {
                let ev = self.next().await;
                if ev["type"] == "output" {
                    out.push_str(ev["text"].as_str().unwrap());
                }
                if done(&ev, &out) {
                    return ev;
                }
                assert_ne!(ev["type"], "exit", "ended early: {ev} after {out:?}");
            }
        };
        let ev = tokio::time::timeout(Duration::from_secs(30), read).await.expect("the login stalled");
        (ev, out)
    }
}

#[tokio::test]
async fn a_harness_logs_in_on_the_users_machine_and_only_then_runs_there() {
    let mut env = serve_with(|e| e.with_logins()).await;
    let (user, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, CLAUDE).await;
    let bot = owned_bot(&env, &user);

    // Not logged in there, and no key: refused, never run here instead.
    let before = send(&env, &bot, "hello").await;
    let said = reply_after(&env, &bot, before).await;
    assert!(said.contains("claude isn't logged in on your computer"), "{said}");
    assert_eq!(refusals(&events(&env, "bot.run_refused").await, "harness_not_logged_in"), 1);
    assert!(events(&env, "harness.invoked").await.is_empty());
    let (code, v) = json_call(&env, "GET", &format!("/api/users/{user}/machine/harness-logins"), "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["logins"].as_str(), v["harnesses"]["claude"]["state"].as_str()), (Some("on"), Some("logged_out")), "{v}");
    assert_eq!(v["harnesses"]["codex"]["state"], "logged_out");
    assert!(v["harnesses"]["pi"].is_null(), "Pi keeps using API keys: {v}");

    // The login runs in a terminal there; what it shows comes back, what's typed goes in.
    let mut login = Login::start(&env, &user, "claude").await;
    let (started, _) = login.until("started").await;
    let id = started["loginId"].as_str().unwrap().to_string();
    login.until_shown("paste the code here").await;
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{user}/machine/harness-login/{id}/input"), r#"{"text":"code-7a1f"}"#).await;
    assert_eq!(code, 204, "{v}");
    let (exit, out) = login.until("exit").await;
    assert_eq!((exit["loggedIn"].as_bool(), exit["success"].as_bool()), (Some(true), Some(true)), "{exit}");
    assert!(out.contains("Logged in."), "{out}");
    assert!(!out.contains("code-7a1f"), "the terminal doesn't echo what's typed: {out}");
    let saved = std::fs::read_to_string(m.home.join(".claude/.credentials.json")).unwrap();
    assert_eq!(saved, r#"{"token":"code-7a1f-saved"}"#, "the login is saved on the machine");

    let finished = wait_for_event(&env, "machine.harness_login_finished").await;
    assert_eq!((finished[0]["outcome"].as_str(), finished[0]["details"]["loggedIn"].as_bool()), (Some("success"), Some(true)), "{finished:?}");
    let typed = events(&env, "machine.harness_login_input").await;
    assert_eq!(typed[0]["details"]["chars"], 9, "{typed:?}");
    assert_eq!(events(&env, "machine.harness_login_started").await.len(), 1);

    // Logged in there now: the run goes ahead.
    let before = send(&env, &bot, "again").await;
    assert_eq!(reply_after(&env, &bot, before).await, "ran on the machine");
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{user}/machine/harness-logins"), "").await;
    assert_eq!(v["harnesses"]["claude"]["state"], "logged_in", "{v}");
    assert!(v["harnesses"]["claude"]["since"].is_i64(), "{v}");
    let changed = wait_for_event(&env, "machine.harness_login_changed").await;
    assert_eq!((changed[0]["details"]["harness"].as_str(), changed[0]["details"]["to"].as_str()), (Some("claude"), Some("logged_in")), "{changed:?}");

    // Neither the login nor what was typed ever reaches botd.
    let (_, all) = crate::tests::call(env.port, "GET", "/api/audit?limit=500", &env.admin, "").await;
    assert!(!all.contains("code-7a1f"), "{all}");
    let upkeep = env.app.db.machine(&mid).unwrap().agent_upkeep.unwrap().to_string();
    assert!(!upkeep.contains("code-7a1f") && upkeep.contains("logged_in"), "{upkeep}");

    // Logged out: the file is gone there, and runs are refused again.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/users/{user}/machine/harness-logins/claude"), "").await;
    assert_eq!((code, v["removed"].as_u64()), (200, Some(1)), "{v}");
    assert!(!m.home.join(".claude/.credentials.json").exists());
    assert_eq!(events(&env, "machine.harness_logged_out").await.len(), 1);
    let before = send(&env, &bot, "once more").await;
    assert!(reply_after(&env, &bot, before).await.contains("isn't logged in"));
    assert_eq!(refusals(&events(&env, "bot.run_refused").await, "harness_not_logged_in"), 2);

    // A key of their own is enough instead.
    crate::secrets::global().user_put(&user, "ANTHROPIC_API_KEY", "sk-ant-test-7f3e9c2b").unwrap();
    let before = send(&env, &bot, "with a key").await;
    assert_eq!(reply_after(&env, &bot, before).await, "ran on the machine");
    crate::secrets::global().user_delete(&user, "ANTHROPIC_API_KEY").unwrap();
}

#[tokio::test]
async fn a_login_can_be_stopped_and_only_known_harnesses_log_in() {
    let mut env = serve_with(|e| e.with_logins()).await;
    let (user, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, SLOW_LOGIN).await;
    for (harness, code) in [("pi", 400), ("hermes", 400), ("nope", 400)] {
        let (got, v) = json_call(&env, "POST", &format!("/api/users/{user}/machine/harness-login"), &json!({ "harness": harness }).to_string()).await;
        assert_eq!(got, code, "{harness}: {v}");
    }
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{user}/machine/harness-login"), r#"{"harness":"codex"}"#).await;
    assert_eq!(code, 502, "codex isn't installed there: {v}");

    let mut login = Login::start(&env, &user, "claude").await;
    let (started, _) = login.until("started").await;
    let id = started["loginId"].as_str().unwrap().to_string();
    assert_eq!(m.agent.running(), 1, "a login counts as busy, so upgrades wait for it");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{user}/machine/harness-login"), r#"{"harness":"claude"}"#).await;
    assert_eq!(code, 409, "one at a time: {v}");
    let (code, v) = json_call(&env, "DELETE", &format!("/api/users/{user}/machine/harness-logins/claude"), "").await;
    assert_eq!(code, 502, "can't log out mid-login: {v}");
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{user}/machine/harness-login/{id}"), "").await;
    assert_eq!(code, 204);
    let (exit, _) = login.until("exit").await;
    assert_eq!(exit["loggedIn"], false, "{exit}");
    assert_eq!(events(&env, "machine.harness_login_aborted").await[0]["details"]["reason"], "asked");
    let finished = wait_for_event(&env, "machine.harness_login_finished").await;
    assert_eq!(finished[0]["outcome"], "failure", "{finished:?}");
    assert!(m.agent.logins.running().is_empty());
    assert_eq!(m.agent.running(), 0);
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{user}/machine/harness-login/{id}/input"), r#"{"text":"late"}"#).await;
    assert_eq!(code, 404, "an ended login takes no input");
}

#[tokio::test]
async fn logins_and_folder_copies_are_off_by_default() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let _m = agent_with(&mut env, &mid, &token, CLAUDE).await;
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/harness-login"), r#"{"harness":"claude"}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("MACHINE_HARNESS_LOGINS"), "{v}");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 409, "{v}");
    let (code, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!((code, v["folderSync"].as_str()), (200, Some("off")), "{v}");
    // Runs need no login there, as before.
    let bot = owned_bot(&env, &uid);
    let before = send(&env, &bot, "hello").await;
    assert_eq!(reply_after(&env, &bot, before).await, "ran on the machine");
    assert!(events(&env, "machine.folder_sync_started").await.is_empty());
}

fn write(path: &std::path::Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

#[tokio::test]
async fn the_users_folder_is_copied_checked_once_and_never_over_their_changes() {
    use std::os::unix::fs::PermissionsExt;
    let mut env = serve_with(|e| e.with_folder_sync(1 << 20)).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, CLAUDE).await;
    let bot = owned_bot(&env, &uid);
    let ws = env.app.workspace_for(&uid).unwrap();
    write(&ws.join("notes/a.txt"), "alpha");
    write(&ws.join("empty.txt"), "");
    write(&ws.join("run.sh"), "#!/bin/sh\n");
    std::fs::set_permissions(ws.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", ws.join("link")).unwrap();
    write(&env.app.data_user_file(&uid).unwrap(), "Ada likes tea.");
    write(&env.app.data_memory_file(&bot).unwrap(), "- remembers the plan");

    // Assigning the user copies their folder.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/users/{uid}/placement"), "").await;
    assert_eq!(code, 200, "{v}");
    let (code, v) = json_call(&env, "PUT", &format!("/api/users/{uid}/placement"), "").await;
    assert_eq!(code, 200, "{v}");
    let done = wait_for_events(&env, "machine.folder_sync_finished", 1).await;
    assert_eq!(events(&env, "machine.folder_sync_started").await[0]["details"]["trigger"], "assigned");
    let d = &done[0]["details"];
    assert_eq!((d["files"].as_u64(), d["skipped"].as_u64(), d["copied"].as_u64(), d["seeded"].as_u64()), (Some(5), Some(1), Some(3), Some(2)), "{d}");
    let home = &m.home;
    assert_eq!(std::fs::read_to_string(home.join("work/notes/a.txt")).unwrap(), "alpha");
    assert_eq!(std::fs::read_to_string(home.join("work/empty.txt")).unwrap(), "");
    assert_ne!(std::fs::metadata(home.join("work/run.sh")).unwrap().permissions().mode() & 0o100, 0);
    assert!(std::fs::symlink_metadata(home.join("work/link")).is_err(), "links aren't copied");
    assert_eq!(std::fs::read_to_string(home.join("USER.md")).unwrap(), "Ada likes tea.");
    assert_eq!(std::fs::read_to_string(home.join(format!("bots/{bot}/MEMORY.md"))).unwrap(), "- remembers the plan");
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!((v["folderSync"].as_str(), v["status"]["state"].as_str(), v["copying"].as_bool()), (Some("on"), Some("done"), Some(false)), "{v}");

    // Again: nothing changed, so nothing is sent.
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 202, "{v}");
    let done = wait_for_events(&env, "machine.folder_sync_finished", 2).await;
    let d = &done[0]["details"];
    assert_eq!((d["sent"].as_u64(), d["copied"].as_u64(), d["unchanged"].as_u64()), (Some(0), Some(0), Some(5)), "{d}");

    // Changed both here and there: theirs is kept. New and untouched files come over;
    // facts and memory on the machine are never replaced.
    std::fs::write(home.join("work/notes/a.txt"), "edited there").unwrap();
    write(&ws.join("notes/a.txt"), "alpha 2");
    write(&ws.join("notes/b.txt"), "bravo");
    write(&ws.join("run.sh"), "#!/bin/sh\necho 2\n");
    write(&env.app.data_user_file(&uid).unwrap(), "Ada likes coffee now.");
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 202);
    let done = wait_for_events(&env, "machine.folder_sync_finished", 3).await;
    let d = &done[0]["details"];
    assert_eq!((d["copied"].as_u64(), d["conflicts"].as_u64(), d["kept"].as_u64()), (Some(2), Some(1), Some(1)), "{d}");
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(v["status"]["report"]["conflicts"], json!(["work/notes/a.txt"]), "{v}");
    assert_eq!(std::fs::read_to_string(home.join("work/notes/a.txt")).unwrap(), "edited there");
    assert_eq!(std::fs::read_to_string(home.join("work/notes/b.txt")).unwrap(), "bravo");
    assert_eq!(std::fs::read_to_string(home.join("work/run.sh")).unwrap(), "#!/bin/sh\necho 2\n");
    assert_eq!(std::fs::read_to_string(home.join("USER.md")).unwrap(), "Ada likes tea.");

    // Too big: nothing is sent, and it's said why.
    write(&ws.join("big.bin"), &"x".repeat(1 << 20));
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 202);
    let failed = wait_for_events(&env, "machine.folder_sync_failed", 1).await;
    assert_eq!((failed[0]["details"]["reason"].as_str(), failed[0]["outcome"].as_str()), (Some("too_big"), Some("failure")), "{failed:?}");
    assert!(!home.join("work/big.bin").exists());
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!((v["status"]["state"].as_str(), v["status"]["reason"].as_str()), (Some("failed"), Some("too_big")), "{v}");
    assert!(v["status"]["doneAt"].is_i64(), "the last copy that finished is kept: {v}");

    // The Bot still runs (its first copy is done), with the folder in place there.
    let before = send(&env, &bot, "hello").await;
    assert_eq!(reply_after(&env, &bot, before).await, "ran on the machine");
}

#[tokio::test]
async fn a_copy_to_a_machine_that_is_away_fails_audited_and_is_tried_again() {
    let mut env = serve_with(|e| e.with_folder_sync(1 << 20)).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let ws = env.app.workspace_for(&uid).unwrap();
    write(&ws.join("a.txt"), "alpha");
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 409, "not enrolled yet");
    let m = agent_with(&mut env, &mid, &token, CLAUDE).await;
    m.server.abort();
    let _ = m.server.await;
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!(code, 202);
    let failed = wait_for_events(&env, "machine.folder_sync_failed", 1).await;
    assert_eq!(failed[0]["details"]["reason"], "offline", "{failed:?}");
    let (_, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/folder-sync"), "").await;
    assert_eq!((v["status"]["attempts"].as_u64(), v["status"]["doneAt"].as_i64()), (Some(1), None), "{v}");
}
