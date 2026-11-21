//! Hermes Agent CLI (Nous Research): `hermes chat --oneshot --format stream-json`.
//!
//! Each Bot has its own Hermes data root (`HERMES_HOME`) in its state dir. `hermes chat`
//! is a client: the turn runs in a gateway daemon that Hermes starts per data root and
//! that outlives the CLI, so the adapter stops that daemon around every run. SuperBot's
//! settings go in a Hermes managed-scope dir, which Hermes merges over the Bot's own
//! `config.yaml` and the agent can't change with `hermes config set`.

use super::{Adapter, AgentEvent, ModelOption, RunInput, describe, str_of};
use crate::machines::wire::JobCleanup;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Default)]
pub struct Hermes {
    /// Text streamed since the last tool call: one chat bubble.
    block: String,
    /// The model `system/init` named, for the tokens `result` reports.
    model: Option<String>,
}

/// Hermes caps shell hook timeouts at 300 seconds.
const HOOK_TIMEOUT_SECS: u64 = 300;

/// `gateway stop` drains for at most 30 seconds, then kills.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn home(input: &RunInput) -> PathBuf {
    input.state_dir.join("hermes")
}

fn managed_dir(input: &RunInput) -> PathBuf {
    input.config_dir.join("hermes-managed")
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The managed `config.yaml` (JSON is YAML). Hermes runs `hooks.pre_tool_call` before
/// every tool call; `fail_closed` turns a crash, timeout, or bad output into a block.
/// Tools only see secret-looking variables listed in `env_passthrough`, so every
/// variable SuperBot sets for the run (BOT_TOKEN, saved secrets) is listed, plus
/// `secret_names`: secrets Bots get by inheriting botd's env, which aren't in
/// `input.env`. Hermes itself refuses its provider keys there. botd owns memory and routines.
fn managed_config(input: &RunInput, secret_names: &[String]) -> Value {
    let inherited = secret_names
        .iter()
        .filter(|n| crate::secrets::check_name(n).is_ok());
    let mut passthrough: Vec<&String> = input.env.keys().chain(inherited).collect();
    passthrough.sort();
    passthrough.dedup();
    let mut c = json!({
        "terminal": { "env_passthrough": passthrough },
        "memory": { "memory_enabled": false, "user_profile_enabled": false },
        "agent": { "disabled_toolsets": ["cronjob"] },
    });
    if let Some(g) = &input.guard {
        // The hook runs in the daemon's folder, not the Bot's, so name the real one.
        let command = format!(
            "{} --cwd {}",
            g.command,
            quote(&input.cwd.display().to_string())
        );
        c["hooks"] = json!({ "pre_tool_call": [{ "command": command, "timeout": g.timeout_secs.min(HOOK_TIMEOUT_SECS), "fail_closed": true }] });
        c["hooks_auto_accept"] = json!(true);
    }
    c
}

impl Adapter for Hermes {
    fn bin(&self) -> &'static str {
        "hermes"
    }

    fn files(&self, input: &RunInput) -> Vec<(PathBuf, String)> {
        let secret_names: Vec<String> = match crate::secrets::global().list() {
            Ok(list) => list.into_iter().map(|l| l.name).collect(),
            Err(e) => {
                eprintln!("hermes: listing secret names: {e}");
                Vec::new()
            }
        };
        vec![(
            managed_dir(input).join("config.yaml"),
            managed_config(input, &secret_names).to_string(),
        )]
    }

    fn args(&mut self, input: &RunInput, _out: &mut Vec<AgentEvent>) -> Vec<String> {
        // SuperBot's approval hook is the gate, so Hermes's own prompts are off (--yolo),
        // like --dangerously-skip-permissions for Claude Code.
        let mut a: Vec<String> = [
            "chat",
            "--oneshot",
            "--query-file",
            "-",
            "--format",
            "stream-json",
            "--source",
            "tool",
            "--yolo",
        ]
        .map(String::from)
        .into();
        if let Some(id) = &input.session_id {
            a.extend(["--resume".into(), id.clone()]);
        }
        if let Some(m) = &input.model {
            a.extend(["--model".into(), m.clone()]);
        }
        if let Some(e) = &input.effort {
            a.extend(["--reasoning".into(), e.clone()]);
        }
        // A tier's route names the provider (ADR 0033); else the server's setting.
        let env = |var: &str| {
            std::env::var(var)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        for (value, flag) in [
            (
                input
                    .provider
                    .clone()
                    .or_else(|| env("SUPERBOT_HERMES_PROVIDER")),
                "--provider",
            ),
            (env("SUPERBOT_HERMES_BASE_URL"), "--base-url"),
        ] {
            if let Some(v) = value {
                a.extend([flag.into(), v]);
            }
        }
        a
    }

    fn supports_provider(&self) -> bool {
        true
    }

    fn env(&self, input: &RunInput) -> Vec<(String, String)> {
        vec![
            ("HERMES_HOME".into(), home(input).display().to_string()),
            (
                "HERMES_MANAGED_DIR".into(),
                managed_dir(input).display().to_string(),
            ),
            ("HERMES_ACCEPT_HOOKS".into(), "1".into()),
            (
                "HERMES_EPHEMERAL_SYSTEM_PROMPT".into(),
                input.system.clone(),
            ),
        ]
    }

    fn stdin(&self, input: &RunInput) -> Option<String> {
        Some(input.prompt.clone())
    }

    /// A stopped or finished `hermes chat` only detaches: the turn keeps running in the
    /// daemon. Stopping the daemon ends it, and the next run starts one with fresh env.
    fn cleanup(&self, input: &RunInput) -> Option<JobCleanup> {
        let home = home(input).display().to_string();
        let mut env = BTreeMap::from([("HERMES_HOME".to_string(), home.clone())]);
        if let Some(path) = input.env.get("PATH") {
            env.insert("PATH".into(), path.clone());
        }
        Some(JobCleanup {
            when_exists: format!("{home}/gateway.pid"),
            bin: self.bin().into(),
            args: ["gateway", "stop", "--yes"].map(String::from).into(),
            env,
            cwd: input.state_dir.display().to_string(),
            timeout_secs: STOP_TIMEOUT.as_secs(),
        })
    }

    fn cleanup_failed(&self, input: &RunInput, why: &str) -> String {
        format!(
            "Couldn't stop this Bot's Hermes daemon ({why}), so its last turn may still be running. Try again; if this keeps happening, run `hermes gateway stop --yes` with HERMES_HOME={}.",
            home(input).display()
        )
    }

    fn max_hook_secs(&self) -> Option<u64> {
        Some(HOOK_TIMEOUT_SECS)
    }

    fn on_event(&mut self, e: &Value, out: &mut Vec<AgentEvent>) {
        let session = |out: &mut Vec<AgentEvent>| {
            if let Some(id) = e["session_id"].as_str().filter(|s| !s.is_empty()) {
                out.push(AgentEvent::Session(id.into()));
            }
        };
        match str_of(e, "type") {
            "system" => {
                self.model = e["model"]
                    .as_str()
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(String::from);
                session(out);
            }
            "text" => {
                let t = str_of(e, "text");
                // A new block after a tool call starts with blank lines.
                let t = if self.block.is_empty() {
                    t.trim_start()
                } else {
                    t
                };
                if !t.is_empty() {
                    self.block.push_str(t);
                    out.push(AgentEvent::TextDelta(t.into()));
                }
            }
            "tool_use" => {
                self.flush(out);
                out.push(AgentEvent::Tool {
                    name: str_of(e, "name").into(),
                    detail: describe(&e["input"]),
                });
            }
            "tool_result" if e["is_error"].as_bool() == Some(false) => {
                out.push(AgentEvent::ToolRan {
                    name: str_of(e, "name").into(),
                })
            }
            "result" => {
                session(out);
                self.usage(&e["tokens"], out);
                let code = e["exit_code"].as_i64().unwrap_or(0);
                let error = e["error"].as_str().filter(|s| !s.trim().is_empty());
                if code != 0 || error.is_some() {
                    self.block.clear();
                    let text = str_of(e, "text").trim();
                    let msg = error
                        .or((!text.is_empty()).then_some(text))
                        .map(String::from)
                        .unwrap_or_else(|| format!("Hermes failed (exit code {code})."));
                    out.push(AgentEvent::Error(msg));
                } else {
                    // `text` is the final reply, usually streamed already.
                    let streamed = self.block.trim_end().to_string();
                    self.flush(out);
                    let text = str_of(e, "text").trim();
                    if !text.is_empty() && !streamed.ends_with(text) {
                        out.push(AgentEvent::Text(text.into()));
                    }
                }
            }
            _ => {}
        }
    }

    /// Hermes has no command that lists models without a prompt, so the model is free text.
    fn shell_tool(&self) -> &'static str {
        "terminal"
    }

    /// `pre_tool_call` runs before every tool Hermes offers: files, search, code,
    /// clarify, delegation, skills, web and browser alike.
    fn hooks_tool(&self, _tool: &str) -> bool {
        true
    }

    fn models(&self) -> Vec<ModelOption> {
        let efforts = [
            "none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra",
        ];
        vec![ModelOption {
            id: String::new(),
            label: "Default model".into(),
            efforts: efforts.map(String::from).into(),
            aliases: Vec::new(),
        }]
    }
}

impl Hermes {
    /// `result.tokens`: `{input, output, total, cache_read, cache_write}`, Hermes's
    /// canonical counts (input excludes the cache). Hermes writes 0 for counts the
    /// provider didn't give, so all zeros is unknown, not free.
    fn usage(&self, t: &Value, out: &mut Vec<AgentEvent>) {
        let n = |k: &str| super::Usage::count(&t[k]);
        let u = super::Usage {
            model: self.model.clone(),
            input: n("input"),
            output: n("output"),
            cache_read: n("cache_read"),
            cache_write: n("cache_write"),
        };
        if u.total() > 0 {
            out.push(AgentEvent::Usage(u));
        }
    }

    fn flush(&mut self, out: &mut Vec<AgentEvent>) {
        let text = std::mem::take(&mut self.block);
        if !text.trim().is_empty() {
            out.push(AgentEvent::Text(text.trim_end().into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Guard;
    use super::*;
    use std::collections::HashMap;

    fn input(guard: bool) -> RunInput {
        let dir = std::env::temp_dir().join(format!("hermes-adapter-{}", crate::short_id()));
        RunInput {
            prompt: "-rf is a flag, not a file".into(),
            system: "You are Ada.".into(),
            session_id: None,
            cwd: "/srv/it's here".into(),
            provider: None,
            model: None,
            effort: None,
            env: HashMap::from([
                ("BOT_TOKEN".into(), "t0k3n".into()),
                ("GITHUB_TOKEN".into(), "ghp_x".into()),
            ]),
            config_dir: dir.clone(),
            state_dir: dir,
            guard: guard.then(|| Guard {
                command: "'/opt/bin/botctl' hook hermes".into(),
                timeout_secs: 300,
                wait: Duration::from_secs(240),
            }),
            run_as: None,
            sandbox: None,
        }
    }

    fn events(lines: &[&str]) -> Vec<String> {
        let mut h = Hermes::default();
        let mut out = Vec::new();
        for l in lines {
            h.on_event(&serde_json::from_str(l).unwrap(), &mut out);
        }
        out.into_iter()
            .map(|e| match e {
                AgentEvent::Session(s) => format!("session {s}"),
                AgentEvent::TextDelta(t) => format!("delta {t}"),
                AgentEvent::Text(t) => format!("text {t}"),
                AgentEvent::Tool { name, detail } => format!("tool {name}: {detail}"),
                AgentEvent::ToolRan { name } => format!("ran {name}"),
                AgentEvent::Error(m) => format!("error {m}"),
                AgentEvent::Usage(u) => format!(
                    "usage {} in={} out={} read={} write={}",
                    u.model.unwrap_or_default(),
                    u.input,
                    u.output,
                    u.cache_read,
                    u.cache_write
                ),
            })
            .collect()
    }

    #[test]
    fn tokens_come_from_the_result() {
        let ran = events(&[
            r#"{"type": "system", "subtype": "init", "model": "anthropic/claude-sonnet-4.5", "session_id": "", "timestamp": 1}"#,
            r#"{"type": "result", "session_id": "local-1", "exit_code": 0, "text": "Done.", "tokens": {"input": 1200, "output": 340, "total": 1940, "cache_read": 400, "cache_write": 0}}"#,
        ]);
        assert_eq!(
            ran[1],
            "usage anthropic/claude-sonnet-4.5 in=1200 out=340 read=400 write=0"
        );
        // A failed turn still spent what it spent.
        let failed = events(&[
            r#"{"type": "result", "exit_code": 1, "text": "", "error": "rate limited", "tokens": {"input": 10, "output": 0, "total": 10, "cache_read": 0, "cache_write": 0}}"#,
        ]);
        assert_eq!(
            failed,
            ["usage  in=10 out=0 read=0 write=0", "error rate limited"]
        );
        // All zeros (the provider gave no counts) or no tokens at all: unknown, so nothing.
        let zeros = events(&[
            r#"{"type": "result", "session_id": "s", "exit_code": 0, "text": "Hi", "tokens": {"input": 0, "output": 0, "total": 0, "cache_read": 0, "cache_write": 0}}"#,
        ]);
        assert!(!zeros.iter().any(|e| e.starts_with("usage")), "{zeros:?}");
        assert!(
            !events(&[r#"{"type": "result", "session_id": "s", "exit_code": 0, "text": "Hi"}"#])
                .iter()
                .any(|e| e.starts_with("usage"))
        );
    }

    #[test]
    fn command_line_and_env() {
        let mut i = input(true);
        let mut out = Vec::new();
        let a = Hermes::default().args(&i, &mut out);
        assert!(out.is_empty());
        assert_eq!(
            a,
            [
                "chat",
                "--oneshot",
                "--query-file",
                "-",
                "--format",
                "stream-json",
                "--source",
                "tool",
                "--yolo"
            ]
        );
        // The prompt goes on stdin, so a leading "-" can't become a flag.
        assert_eq!(
            Hermes::default().stdin(&i).as_deref(),
            Some("-rf is a flag, not a file")
        );
        let env: HashMap<String, String> = Hermes::default().env(&i).into_iter().collect();
        assert_eq!(
            env["HERMES_HOME"],
            i.state_dir.join("hermes").display().to_string()
        );
        assert_eq!(
            env["HERMES_MANAGED_DIR"],
            i.state_dir.join("hermes-managed").display().to_string()
        );
        assert_eq!(
            (
                env["HERMES_ACCEPT_HOOKS"].as_str(),
                env["HERMES_EPHEMERAL_SYSTEM_PROMPT"].as_str()
            ),
            ("1", "You are Ada.")
        );

        (i.session_id, i.model, i.effort) = (
            Some("local-abc".into()),
            Some("anthropic/claude-sonnet-4".into()),
            Some("high".into()),
        );
        let a = Hermes::default().args(&i, &mut out);
        assert!(a.windows(2).any(|w| w == ["--resume", "local-abc"]));
        assert!(
            a.windows(2)
                .any(|w| w == ["--model", "anthropic/claude-sonnet-4"])
        );
        assert!(a.windows(2).any(|w| w == ["--reasoning", "high"]));
        // A tier route's provider (ADR 0033).
        i.provider = Some("openrouter".into());
        let a = Hermes::default().args(&i, &mut out);
        assert!(a.windows(2).any(|w| w == ["--provider", "openrouter"]));
        assert_eq!(a.iter().filter(|x| *x == "--provider").count(), 1);
        let _ = std::fs::remove_dir_all(&i.state_dir);
    }

    fn write_files(i: &RunInput) {
        for (path, body) in Hermes::default().files(i) {
            crate::machines::job::write_private(&path, &body).unwrap();
        }
    }

    #[test]
    fn managed_config_installs_the_gate() {
        use std::os::unix::fs::PermissionsExt;
        let i = input(true);
        write_files(&i);
        let path = i.config_dir.join("hermes-managed/config.yaml");
        let c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            c["hooks"]["pre_tool_call"],
            json!([{ "command": r"'/opt/bin/botctl' hook hermes --cwd '/srv/it'\''s here'", "timeout": 300, "fail_closed": true }])
        );
        assert_eq!(c["hooks_auto_accept"], true);
        assert_eq!(
            c["terminal"]["env_passthrough"],
            json!(["BOT_TOKEN", "GITHUB_TOKEN"])
        );
        assert_eq!(
            c["memory"],
            json!({ "memory_enabled": false, "user_profile_enabled": false })
        );
        assert_eq!(c["agent"]["disabled_toolsets"], json!(["cronjob"]));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("t0k3n") && !text.contains("ghp_x"),
            "names only, never values"
        );

        // Secrets inherited from botd's env are listed too; botd's own never are.
        let names = [
            "NPM_TOKEN",
            "GITHUB_TOKEN",
            "SUPERBOT_MASTER_KEY",
            "AUTH_PASSWORD",
            "SSO_ENTRA_CLIENT_SECRET",
        ]
        .map(String::from);
        let c = managed_config(&i, &names);
        assert_eq!(
            c["terminal"]["env_passthrough"],
            json!(["BOT_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN"])
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Bypass: no hook, and a later run drops the old one.
        let mut bypass = input(false);
        (bypass.state_dir, bypass.config_dir) = (i.state_dir.clone(), i.config_dir.clone());
        write_files(&bypass);
        let c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(c.get("hooks").is_none(), "{c}");
        let _ = std::fs::remove_dir_all(&i.state_dir);
    }

    #[tokio::test]
    async fn a_gate_that_cant_be_written_is_an_error() {
        let mut i = input(true);
        i.config_dir = "/proc/superbot-no-such-dir".into();
        i.cwd = std::env::temp_dir();
        let mut out = Vec::new();
        let (_abort, rx) = tokio::sync::watch::channel(None);
        super::super::run(Box::new(Hermes::default()), i, rx, |e| out.push(e)).await;
        assert!(
            matches!(out.as_slice(), [AgentEvent::Error(m)] if m.contains("Couldn't write")),
            "never started"
        );
    }

    /// Lines as Hermes v0.23.2 writes them (`timestamp` and `tokens` trimmed).
    #[test]
    fn stream_json_maps_to_events() {
        let ran = events(&[
            r#"{"type": "system", "subtype": "init", "model": "m", "session_id": ""}"#,
            r#"{"type": "text", "text": "Pushing now."}"#,
            r#"{"type": "tool_use", "name": "terminal", "tool_call_id": "call_1", "input": {"command": "git push origin main"}}"#,
            r#"{"type": "tool_result", "name": "terminal", "tool_call_id": "call_1", "output": "{}", "duration_ms": 964, "is_error": true}"#,
            r#"{"type": "text", "text": "\n\nIt failed: not a git repository."}"#,
            r#"{"type": "result", "session_id": "local-5ca4", "exit_code": 0, "text": "It failed: not a git repository.", "duration_ms": 4467}"#,
        ]);
        assert_eq!(
            ran,
            [
                "delta Pushing now.",
                "text Pushing now.",
                "tool terminal: git push origin main",
                "delta It failed: not a git repository.",
                "session local-5ca4",
                "text It failed: not a git repository.",
            ]
        );
        // A call that ran ends without an error (as the pinned Hermes writes it).
        let read = events(&[
            r#"{"type": "tool_use", "name": "read_file", "tool_call_id": "call_2", "input": {"path": "/etc/hostname"}}"#,
            r#"{"type": "tool_result", "name": "read_file", "tool_call_id": "call_2", "output": "{\"content\": \"1|host\"}", "duration_ms": 205, "is_error": false}"#,
        ]);
        assert_eq!(read, ["tool read_file: /etc/hostname", "ran read_file"]);
        // A hook block emits no tool_use; the reply still arrives once.
        let blocked = events(&[
            r#"{"type": "text", "text": "Pushing now."}"#,
            r#"{"type": "text", "text": "\n\nTool said: blocked"}"#,
            r#"{"type": "result", "session_id": "local-1", "exit_code": 0, "text": "Tool said: blocked"}"#,
        ]);
        assert_eq!(
            blocked
                .iter()
                .filter(|e| e.starts_with("text "))
                .collect::<Vec<_>>(),
            ["text Pushing now.\n\nTool said: blocked"]
        );
        // Nothing streamed: the final text is the reply.
        assert_eq!(
            events(&[r#"{"type": "result", "session_id": "s", "exit_code": 0, "text": "Done."}"#]),
            ["session s", "text Done."]
        );
    }

    #[test]
    fn failures_are_errors() {
        let lost = events(&[
            r#"{"type": "result", "session_id": "", "exit_code": 1, "text": "", "error": "No session found matching 'local-x'."}"#,
        ]);
        assert_eq!(lost, ["error No session found matching 'local-x'."]);
        let init = events(&[
            r#"{"type": "result", "session_id": "", "exit_code": 1, "text": "", "error": "credentials or agent init failed"}"#,
        ]);
        assert_eq!(init, ["error credentials or agent init failed"]);
        assert_eq!(
            events(&[r#"{"type": "result", "exit_code": 2, "text": ""}"#]),
            ["error Hermes failed (exit code 2)."]
        );
        let partial = events(&[
            r#"{"type": "text", "text": "Half"}"#,
            r#"{"type": "result", "session_id": "s", "exit_code": 3, "text": "Turn lost"}"#,
        ]);
        assert_eq!(partial, ["delta Half", "session s", "error Turn lost"]);
    }

    #[tokio::test]
    async fn leftovers_are_stopped_only_when_a_daemon_ran() {
        use std::os::unix::fs::PermissionsExt;
        async fn stop(i: &RunInput) -> Result<(), String> {
            super::super::stop_leftovers(&Hermes::default(), i).await
        }
        let mut i = input(false);
        assert_eq!(
            stop(&i).await,
            Ok(()),
            "no gateway.pid, no `hermes gateway stop`"
        );
        assert_eq!(Hermes::default().max_hook_secs(), Some(300));

        // A stop that fails is reported, so the runner won't start a turn beside the old one.
        let bin = i.state_dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(home(&i)).unwrap();
        std::fs::write(home(&i).join("gateway.pid"), "{}").unwrap();
        i.env.insert("PATH".into(), bin.display().to_string());
        let stub = |body: &str| {
            std::fs::write(bin.join("hermes"), format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(bin.join("hermes"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        };
        stub("exit 0");
        assert_eq!(stop(&i).await, Ok(()));
        stub("exit 1");
        let err = stop(&i).await.unwrap_err();
        assert!(
            err.contains("Couldn't stop this Bot's Hermes daemon") && err.contains("failed"),
            "{err}"
        );
        std::fs::remove_file(bin.join("hermes")).unwrap();
        assert!(stop(&i).await.unwrap_err().contains("didn't start"));
        let _ = std::fs::remove_dir_all(&i.state_dir);
    }
}
