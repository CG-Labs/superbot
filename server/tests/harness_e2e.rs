//! Approvals end to end through each real harness CLI (approvals follow-up 1, ADR 0057):
//! the real `botd` and `botctl` run Claude Code, Codex, Pi, and Hermes Agent with the hook
//! each adapter installs, and four calls go through it: an allowed one runs, one a deny
//! rule blocks never runs, and two `git push`es wait for a person, then run once approved
//! or fail once denied. Then each tool other than the shell that the canary counts for
//! that harness (ADR 0063) runs once allowed and is blocked once denied. Last, with a
//! `botctl hook` that allows everything without asking botd, each of those calls must
//! end its run as unguarded.
//!
//! By default the model is a fake (`FakeModel`) that each CLI reaches through its own
//! custom-endpoint setting, so everything but the model is real and no login is needed.
//! `SUPERBOT_E2E_MODEL=real` uses the harnesses' own logins and models instead
//! (`deploy/harness-e2e.sh` on a server). Ignored by `cargo test`; the `harness-e2e`
//! workflow installs the pinned CLIs (`deploy/install-harness-clis.sh`) and runs them
//! with `--ignored`.
//!
//! - `SUPERBOT_E2E_HARNESSES`: which to run (default: all).
//! - `SUPERBOT_E2E_REQUIRE=1`: a missing CLI fails instead of being skipped.
//! - `SUPERBOT_E2E_PASS_ENV`: in real mode, extra variables to hand to botd by name.
//! - `SUPERBOT_E2E_BOT_MODEL`: in real mode, the Bot's model (else the harness's default).

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git").current_dir(dir).args(["-c", "user.name=e2e", "-c", "user.email=e2e@example.invalid", "-c", "init.defaultBranch=main"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn has_ref(remote: &Path, name: &str) -> bool {
    Command::new("git").arg("-C").arg(remote).args(["rev-parse", "--verify", "--quiet", &format!("refs/heads/{name}")]).stdout(std::process::Stdio::null()).status().unwrap().success()
}

/// The four calls, in one Bot's session (each prompt resumes it).
fn approvals_hold(harness: &str, bin: &str) {
    if !wanted(harness, bin) {
        return;
    }
    let b = start(harness, false);
    let bot = call(&b, "GET", "/api/bots", Value::Null)[0].clone();
    assert_eq!(bot["harness"], harness);
    let id = bot["id"].as_str().unwrap().to_string();
    assert_eq!(call(&b, "GET", "/api/policy", Value::Null)["policy"]["mode"], "ask", "a fresh install asks");
    // The sandbox (ADR 0055) is another layer and depends on the host; keep it out of
    // the way of the pushes to a folder outside the workspace.
    call(&b, "PUT", "/api/policy", json!({ "sandbox": false }));
    call(&b, "POST", "/api/policy/rules", json!({ "action": "deny", "tool": "*", "pattern": "*e2e-forbidden*" }));
    // Hermes refuses a session without a model, and the fake endpoint has no default.
    let model = if real() { std::env::var("SUPERBOT_E2E_BOT_MODEL").ok().filter(|m| !m.is_empty()) } else { (harness == "hermes").then(|| MODEL.to_string()) };
    if let Some(m) = model {
        call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
    }
    let proof = std::fs::canonicalize(b.dir.join("proof")).unwrap();
    git(&proof, &["init", "-q", "--bare", "remote.git"]);
    git(&proof, &["init", "-q", "repo"]);
    let repo = proof.join("repo");
    std::fs::write(repo.join("README"), "e2e\n").unwrap();
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-q", "-m", "e2e"]);
    git(&repo, &["remote", "add", "origin", "../remote.git"]);
    let remote = proof.join("remote.git");
    let pass = |what: &str| println!("PASS {harness}: {what}");

    // Allowed: no class, no rule. It runs, through the hook (the canary would stop a
    // shell call that skipped it).
    let marker = proof.join("allowed.marker");
    let r = run(&b, &id, &prompt(&format!("touch {}", marker.display())), None, &|| {});
    assert!(r.approvals.is_empty(), "{harness}: an allowed call asked: {:?}", r.approvals);
    assert_ne!(r.result, "unguarded", "{harness} ran a shell command without the hook: {}", r.text);
    assert!(marker.exists(), "{harness}: the allowed command didn't run (result {}): {}", r.result, r.text);
    if !real() {
        assert!(r.text.contains(DONE), "{harness}: no reply after the command: {}", r.text);
    }
    pass("an allowed call runs without asking");

    // Blocked by policy: a deny rule, decided at once. The command never runs and the
    // agent is told why.
    let forbidden = proof.join("e2e-forbidden.marker");
    let r = run(&b, &id, &prompt(&format!("touch {}", forbidden.display())), None, &|| {});
    assert!(r.approvals.is_empty(), "{harness}: a denied call asked: {:?}", r.approvals);
    assert!(!forbidden.exists(), "{harness}: a call the policy denies ran: {}", r.text);
    let denied = audit(&b, "policy.denied").into_iter().map(|e| details(&e)).find(|d| d["subject"].as_str().unwrap_or_default().contains("e2e-forbidden"));
    let denied = denied.unwrap_or_else(|| panic!("{harness}: the hook never sent the denied call (result {}): {}", r.result, r.text));
    assert_eq!(denied["harness"], harness);
    if !real() {
        assert!(r.text.contains(DONE) && r.text.contains("deny rule"), "{harness}: the agent wasn't told why: {}", r.text);
    }
    pass("a call the policy denies is blocked at once");

    // Needs approval: waits, then runs once approved.
    let push = |branch: &str| format!("git -C {} push origin HEAD:refs/heads/{branch}", repo.display());
    let not_pushed = |branch: &'static str| {
        let remote = remote.clone();
        move || assert!(!has_ref(&remote, branch), "{harness}: {branch} was pushed before anyone decided")
    };
    let r = run(&b, &id, &prompt(&push("e2e-approved")), Some("approve"), &not_pushed("e2e-approved"));
    let [a] = r.approvals.as_slice() else { panic!("{harness}: wanted one approval, got {:?} (result {}): {}", r.approvals, r.result, r.text) };
    assert_eq!((a["harness"].as_str(), a["class"].as_str()), (Some(harness), Some("git_push")), "{a}");
    assert!(has_ref(&remote, "e2e-approved"), "{harness}: approved, but the push didn't happen (result {}): {}", r.result, r.text);
    if !real() {
        assert!(r.text.contains(DONE), "{harness}: no reply after the push: {}", r.text);
    }
    pass("a call that needs approval waits, and runs once approved");

    // Needs approval: waits, then fails once denied.
    let r = run(&b, &id, &prompt(&push("e2e-denied")), Some("deny"), &not_pushed("e2e-denied"));
    let [a] = r.approvals.as_slice() else { panic!("{harness}: wanted one approval, got {:?} (result {}): {}", r.approvals, r.result, r.text) };
    assert_eq!(a["class"], "git_push", "{a}");
    assert!(!has_ref(&remote, "e2e-denied"), "{harness}: denied, but the push happened: {}", r.text);
    if !real() {
        assert!(r.text.contains(DONE) && r.text.to_lowercase().contains("denied"), "{harness}: the agent wasn't told: {}", r.text);
    }
    pass("a call that needs approval waits, and fails once denied");

    // Calls other than shell commands (ADR 0063). Only the fake model calls an exact tool.
    if real() {
        println!("SKIP {harness}: other tools need the fake model");
        return;
    }
    for (tool, model) in other_tools(harness) {
        if let Some(m) = model {
            call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
        }
        let file = |name: &str| proof.join(format!("{name}-{}.txt", tool.replace('/', "-")));
        let ask = |path: &Path| format!("{}{tool}{}<<{}>>", TOOL.0, TOOL.1, other_tool_args(tool, path));

        // Allowed: it runs, through the hook (the canary would stop one that skipped it).
        let made = file("allowed");
        let r = run(&b, &id, &ask(&made), None, &|| {});
        assert!(r.approvals.is_empty(), "{harness}: an allowed {tool} call asked: {:?}", r.approvals);
        assert_ne!(r.result, "unguarded", "{harness} ran {tool} without the hook: {}", r.text);
        assert!(made.exists() && r.text.contains(DONE), "{harness}: the allowed {tool} call didn't run (result {}): {}", r.result, r.text);
        pass(&format!("{tool}: an allowed call runs through the hook"));

        // Blocked by policy: the hook sends it, and it never runs.
        let forbidden = file("e2e-forbidden");
        let r = run(&b, &id, &ask(&forbidden), None, &|| {});
        assert!(!forbidden.exists(), "{harness}: a {tool} call the policy denies ran: {}", r.text);
        let hooked = tool.replace('/', "__");
        let denied = audit(&b, "policy.denied").into_iter().map(|e| details(&e)).any(|d| d["tool"].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&hooked)));
        assert!(denied, "{harness}: the hook never sent the {tool} call (result {}): {}", r.result, r.text);
        assert!(r.text.contains(DONE) && r.text.contains("deny rule"), "{harness}: the agent wasn't told why: {}", r.text);
        pass(&format!("{tool}: a call the policy denies is blocked"));
    }
}

/// The canary, end to end: with a hook that never reaches botd, each call the canary
/// counts (a shell command, and in fake mode each of `other_tools`) still runs, and the
/// run must end `unguarded`. This proves each CLI's real output reaches the canary.
fn unhooked_runs_stop(harness: &str, bin: &str) {
    if !wanted(harness, bin) {
        return;
    }
    let b = start(harness, true);
    let id = call(&b, "GET", "/api/bots", Value::Null)[0]["id"].as_str().unwrap().to_string();
    call(&b, "PUT", "/api/policy", json!({ "sandbox": false }));
    let model = if real() { std::env::var("SUPERBOT_E2E_BOT_MODEL").ok().filter(|m| !m.is_empty()) } else { (harness == "hermes").then(|| MODEL.to_string()) };
    if let Some(m) = model {
        call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
    }
    let proof = std::fs::canonicalize(b.dir.join("proof")).unwrap();
    let r = run(&b, &id, &prompt(&format!("touch {}", proof.join("unhooked.marker").display())), None, &|| {});
    assert_eq!(r.result, "unguarded", "{harness}: a shell command ran without the hook and the canary missed it: {}", r.text);
    println!("PASS {harness}: a shell command that skips the hook stops the run");
    if real() {
        return;
    }
    for (tool, model) in other_tools(harness) {
        if let Some(m) = model {
            call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
        }
        let made = proof.join(format!("unhooked-{}.txt", tool.replace('/', "-")));
        let r = run(&b, &id, &format!("{}{tool}{}<<{}>>", TOOL.0, TOOL.1, other_tool_args(tool, &made)), None, &|| {});
        assert!(made.exists(), "{harness}: the unhooked {tool} call didn't run (result {}): {}", r.result, r.text);
        assert_eq!(r.result, "unguarded", "{harness}: {tool} ran without the hook and the canary missed it: {}", r.text);
        println!("PASS {harness}: {tool} that skips the hook stops the run");
    }
}

/// Fail-closed on a hook timeout, through the real Hermes (ADR 0011's gate, ADR 0075).
/// `botctl hook` hangs far past its timeout and would then allow the call, so only
/// Hermes killing it and failing closed (`fail_closed: true` in the managed config)
/// keeps the call from running. botd shortens every hook timeout to `HOOK_SECS` with
/// `SUPERBOT_TEST_HOOK_TIMEOUT_SECS` (testing mode only), so this takes seconds.
fn hermes_hook_timeout_blocks() {
    const HOOK_SECS: u64 = 3;
    const HANG_SECS: u64 = 90;
    if !wanted("hermes", "hermes") {
        return;
    }
    if real() {
        println!("SKIP hermes: the hook timeout test needs the fake model");
        return;
    }
    let hang = format!("cat >/dev/null; echo $$ >>\"$(dirname \"$0\")/../proof/hook-pids\"; sleep {HANG_SECS}; exit 0");
    let b = start_with("hermes", Some(&hang), &[("SUPERBOT_TEST_HOOK_TIMEOUT_SECS", &HOOK_SECS.to_string())]);
    let id = call(&b, "GET", "/api/bots", Value::Null)[0]["id"].as_str().unwrap().to_string();
    call(&b, "PUT", "/api/policy", json!({ "sandbox": false }));
    call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": MODEL }));
    let proof = std::fs::canonicalize(b.dir.join("proof")).unwrap();
    let pids = proof.join("hook-pids");
    let pass = |what: &str| println!("PASS hermes: {what}");

    let asks = [("terminal".to_string(), prompt(&format!("touch {}", proof.join("timeout-terminal.txt").display())))]
        .into_iter()
        .chain(other_tools("hermes").into_iter().map(|(tool, _)| {
            let made = proof.join(format!("timeout-{tool}.txt"));
            (tool.to_string(), format!("{}{tool}{}<<{}>>", TOOL.0, TOOL.1, other_tool_args(tool, &made)))
        }));
    for (n, (tool, ask)) in asks.enumerate() {
        let started = std::time::Instant::now();
        let r = run(&b, &id, &ask, None, &|| {});
        let took = started.elapsed();
        let made = proof.join(format!("timeout-{tool}.txt"));
        assert!(!made.exists(), "hermes: a {tool} call whose hook timed out ran (result {}): {}", r.result, r.text);
        let hooked = read(&pids);
        let pid = hooked.lines().nth(n).unwrap_or_else(|| panic!("hermes never ran the hook for {tool} (result {}): {}", r.result, r.text));
        assert!(took < std::time::Duration::from_secs(HANG_SECS), "hermes: {tool} waited {took:?}, so the hook wasn't timed out");
        assert_ne!(r.result, "unguarded", "hermes: {tool} looked unhooked: {}", r.text);
        let told = r.text.contains(DONE) && r.text.contains("failed closed") && r.text.contains(&format!("timed out after {HOOK_SECS}s"));
        assert!(told, "hermes: the agent wasn't told the hook timed out: {}", r.text);
        // Hermes kills the hung hook rather than leaving it behind.
        wait_for("the timed-out hook to be killed", std::time::Duration::from_secs(10), || {
            let stat = read(Path::new(&format!("/proc/{pid}/stat")));
            (stat.is_empty() || stat.rsplit_once(')').is_some_and(|(_, s)| s.trim_start().starts_with('Z'))).then_some(())
        });
        pass(&format!("{tool}: a hook that times out blocks the call ({took:.1?})"));
    }

    // The managed config botd wrote: the short timeout, failing closed as always.
    let config = find(&b.dir, "config.yaml", 10).into_iter().find(|p| p.parent().is_some_and(|d| d.ends_with("hermes-managed")));
    let config: Value = serde_json::from_str(&read(&config.expect("botd wrote no Hermes managed config"))).unwrap();
    let hook = &config["hooks"]["pre_tool_call"][0];
    assert_eq!((hook["timeout"].as_u64(), hook["fail_closed"].as_bool()), (Some(HOOK_SECS), Some(true)), "{config}");
    assert_eq!(config["hooks_auto_accept"], true);
    pass("the managed config fails closed with the short timeout");
}

/// Tools other than the shell that each harness reports through its hook and that the
/// canary counts, with the Bot model that makes the CLI offer it (ADR 0063).
fn other_tools(harness: &str) -> Vec<(&'static str, Option<&'static str>)> {
    match harness {
        "claude" => vec![("Write", None)],
        // Codex offers MCP tools as they are only to models it doesn't know, and
        // `apply_patch` only to ones it does.
        "codex" => vec![("mcp__e2e/touch", None), ("apply_patch", Some("gpt-5.5"))],
        "pi" => vec![("write", None)],
        "hermes" => vec![("write_file", None)],
        h => panic!("no other tools for {h}"),
    }
}

/// Arguments for a call of `tool` that creates `path`.
fn other_tool_args(tool: &str, path: &Path) -> Value {
    let p = path.display().to_string();
    match tool {
        "Write" => json!({ "file_path": p, "content": "e2e\n" }),
        "apply_patch" => json!(format!("*** Begin Patch\n*** Add File: {p}\n+e2e\n*** End Patch\n")),
        "mcp__e2e/touch" => json!({ "path": p }),
        _ => json!({ "path": p, "content": "e2e\n" }),
    }
}

#[test]
#[ignore = "needs the Claude Code CLI; see the harness-e2e workflow"]
fn claude_code_hooks_hold() {
    approvals_hold("claude", "claude");
    unhooked_runs_stop("claude", "claude");
}

#[test]
#[ignore = "needs the Codex CLI; see the harness-e2e workflow"]
fn codex_hooks_hold() {
    approvals_hold("codex", "codex");
    unhooked_runs_stop("codex", "codex");
}

#[test]
#[ignore = "needs the Pi CLI; see the harness-e2e workflow"]
fn pi_hooks_hold() {
    approvals_hold("pi", "pi");
    unhooked_runs_stop("pi", "pi");
}

#[test]
#[ignore = "needs the Hermes Agent CLI; see the harness-e2e workflow"]
fn hermes_hooks_hold() {
    approvals_hold("hermes", "hermes");
    unhooked_runs_stop("hermes", "hermes");
}

#[test]
#[ignore = "needs the Hermes Agent CLI; see the harness-e2e workflow"]
fn hermes_hook_timeout_fails_closed() {
    hermes_hook_timeout_blocks();
}

#[test]
fn the_fake_model_reads_each_format() {
    let tools = || vec![("Read".to_string(), json!({})), ("Bash".to_string(), json!({ "properties": { "command": {} } }))];
    let call_of = |r: Reply| match r {
        Reply::Call { name, args } => (name, args),
        Reply::Text(t) => panic!("{t}"),
    };
    // Newest prompt wins; a result after it ends the turn; an older result doesn't.
    let turns = vec![Turn::User("E2E-RUN<<ls>>".into()), Turn::Result("x".into()), Turn::User("then E2E-RUN<<git push>> please".into())];
    assert_eq!(call_of(decide(turns, tools())), ("Bash".into(), json!({ "command": "git push" })));
    let Reply::Text(t) = decide(vec![Turn::User("E2E-RUN<<ls>>".into()), Turn::Result("blocked: denied".into())], tools()) else { panic!() };
    assert_eq!(t, "E2E-DONE blocked: denied");
    let Reply::Text(t) = decide(vec![Turn::User("E2E-RUN<<ls>>".into())], vec![]) else { panic!() };
    assert_eq!(t, "ok", "side requests without tools get plain text");
    // Codex's exec_command takes `cmd`.
    let codex = vec![("exec_command".to_string(), json!({ "properties": { "cmd": {} } }))];
    assert_eq!(call_of(decide(vec![Turn::User("E2E-RUN<<ls>>".into())], codex)).1, json!({ "cmd": "ls" }));
    // Each format's conversation.
    let a = json!({ "messages": [{ "role": "user", "content": "E2E-RUN<<ls>>" }, { "role": "assistant", "content": [] },
        { "role": "user", "content": [{ "type": "tool_result", "content": [{ "type": "text", "text": "out" }] }] }] });
    assert!(matches!(anthropic_turns(&a).as_slice(), [Turn::User(_), Turn::Result(r)] if r == "out"));
    let r = json!({ "input": [{ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": "E2E-RUN<<ls>>" }] },
        { "type": "function_call", "name": "exec_command" }, { "type": "function_call_output", "output": "out" }] });
    assert!(matches!(responses_turns(&r).as_slice(), [Turn::User(u), Turn::Result(o)] if u.contains("E2E-RUN") && o == "out"));
    let c = json!({ "messages": [{ "role": "system", "content": "E2E-RUN<<no>>" }, { "role": "user", "content": "E2E-RUN<<ls>>" }, { "role": "tool", "content": "out" }] });
    assert!(matches!(chat_turns(&c).as_slice(), [Turn::User(_), Turn::Result(o)] if o == "out"));
    // One named tool: offered, or not; a freeform one; one in a namespace.
    let read = decide(vec![Turn::User(r#"E2E-RUN<<ls>> then E2E-TOOL<<Read>><<{"file_path":"/x"}>>"#.into())], tools());
    assert_eq!(call_of(read), ("Read".into(), json!({ "file_path": "/x" })));
    let Reply::Text(t) = decide(vec![Turn::User("E2E-TOOL<<Write>><<{}>>".into())], tools()) else { panic!() };
    assert!(t.starts_with("E2E-NO-TOOL Write"), "{t}");
    let freeform = match decide(vec![Turn::User(r#"E2E-TOOL<<apply_patch>><<"p">>"#.into())], vec![("apply_patch".into(), json!(null))]) {
        Reply::Call { args, .. } => args,
        Reply::Text(t) => panic!("{t}"),
    };
    assert_eq!(freeform, json!("p"));
    let mcp = decide(vec![Turn::User(r#"E2E-TOOL<<mcp__e2e/touch>><<{"path":"/x"}>>"#.into())], vec![("mcp__e2e".into(), json!(null))]);
    assert_eq!(call_of(mcp).0, "mcp__e2e/touch");
}
