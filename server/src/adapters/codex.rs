//! Codex CLI: `codex exec --json`. Resumes with `codex exec resume <thread id>`.
//! Limitation: Codex fixes its instructions when a session starts, so later memory
//! changes reach it only through its memory file, not the system prompt.
//! Approvals: an inline PreToolUse hook. Hosted tools such as web search skip hooks.
//! Sandbox (ADR 0055): `workspace-write` with the network on, else none at all.

use super::{output, short, str_of, Adapter, AgentEvent, ModelOption, RunInput, Usage};
use serde_json::Value;

#[derive(Default)]
pub struct Codex {
    /// Said once per run that the sandbox can't start.
    sandbox_failed: bool,
}

/// `-c` overrides for the `workspace-write` sandbox. `codex exec resume` has no
/// `--sandbox`, so both take it as config. Never asking (`approval_policy`): what the
/// sandbox blocks fails, and SuperBot's hook is the approval gate.
fn sandbox_config(s: &super::Sandbox) -> Vec<String> {
    let roots: Vec<Value> = s.writable.iter().map(|p| Value::String(p.display().to_string())).collect();
    let mut c = vec![
        "sandbox_mode=\"workspace-write\"".to_string(),
        "approval_policy=\"never\"".into(),
        "sandbox_workspace_write.network_access=true".into(),
    ];
    if !roots.is_empty() {
        c.push(format!("sandbox_workspace_write.writable_roots={}", Value::Array(roots)));
    }
    c.into_iter().flat_map(|v| ["-c".to_string(), v]).collect()
}

impl Adapter for Codex {
    fn bin(&self) -> &'static str {
        "codex"
    }

    fn args(&mut self, input: &RunInput, _out: &mut Vec<AgentEvent>) -> Vec<String> {
        let mut a: Vec<String> = vec!["exec".into()];
        if input.session_id.is_some() {
            a.push("resume".into());
        }
        a.extend(["--json", "--skip-git-repo-check"].map(String::from));
        match &input.sandbox {
            Some(s) => a.extend(sandbox_config(s)),
            None => a.push("--dangerously-bypass-approvals-and-sandbox".into()),
        }
        a.extend(["-c".into(), format!("developer_instructions={}", Value::String(input.system.clone()))]);
        if let Some(m) = &input.model {
            a.extend(["-m".into(), m.clone()]);
        }
        if let Some(e) = &input.effort {
            a.extend(["-c".into(), format!("model_reasoning_effort={}", Value::String(e.clone()))]);
        }
        // Codex reads Claude-style PreToolUse hooks. Inline hooks need trust, which
        // `exec` can't prompt for; we generate this one, so we vouch for it.
        if let Some(g) = &input.guard {
            let hooks = format!(
                "hooks.PreToolUse=[{{matcher=\"*\",hooks=[{{type=\"command\",command={},timeout={}}}]}}]",
                Value::String(g.command.clone()),
                g.timeout_secs
            );
            a.extend(["-c".into(), "features.hooks=true".into(), "-c".into(), hooks, "--dangerously-bypass-hook-trust".into()]);
        }
        a.push("--".into());
        if let Some(id) = &input.session_id {
            a.push(id.clone());
        }
        a.push(input.prompt.clone());
        a
    }

    fn on_event(&mut self, e: &Value, out: &mut Vec<AgentEvent>) {
        let item = &e["item"];
        let kind = str_of(item, "type");
        match str_of(e, "type") {
            "thread.started" => out.push(AgentEvent::Session(str_of(e, "thread_id").into())),
            "item.completed" if kind == "agent_message" && !str_of(item, "text").trim().is_empty() => {
                out.push(AgentEvent::Text(str_of(item, "text").into()))
            }
            "item.completed" if kind == "command_execution" && !self.sandbox_failed => {
                if let Some(why) = sandbox_failure(str_of(item, "aggregated_output")) {
                    self.sandbox_failed = true;
                    out.push(AgentEvent::Error(format!(
                        "Codex's sandbox can't start on this computer ({why}), so my commands fail. Install bubblewrap (on Ubuntu 24.04, also its AppArmor profile), \
                         or turn the sandbox off for me in my approval settings."
                    )));
                }
            }
            "item.started" if kind == "command_execution" => {
                out.push(AgentEvent::Tool { name: "shell".into(), detail: unwrap(str_of(item, "command")) })
            }
            "item.started" if !kind.is_empty() && kind != "reasoning" => {
                let detail = match (item["server"].as_str(), item["tool"].as_str()) {
                    (Some(s), Some(t)) => format!("{s}.{t}"),
                    _ => str_of(item, "query").into(),
                };
                out.push(AgentEvent::Tool { name: kind.into(), detail })
            }
            // OpenAI counts cached prompt tokens inside `input_tokens`, and reasoning inside
            // `output_tokens`; `codex exec` doesn't name the model.
            "turn.completed" => {
                let u = &e["usage"];
                let (input, read, write) = (Usage::count(&u["input_tokens"]), Usage::count(&u["cached_input_tokens"]), Usage::count(&u["cache_write_input_tokens"]));
                let usage = Usage { model: None, input: input.saturating_sub(read).saturating_sub(write), output: Usage::count(&u["output_tokens"]), cache_read: read, cache_write: write };
                if usage.total() > 0 {
                    out.push(AgentEvent::Usage(usage));
                }
            }
            "turn.failed" | "error" => {
                let msg = e["error"]["message"].as_str().or(e["message"].as_str()).unwrap_or("Codex failed");
                out.push(AgentEvent::Error(msg.into()))
            }
            _ => {}
        }
    }

    /// From `codex debug models`: the models this login can use, and their efforts.
    fn shell_tool(&self) -> &'static str {
        "shell"
    }

    fn has_sandbox(&self) -> bool {
        true
    }

    fn login_args(&self) -> Option<&'static [&'static str]> {
        Some(&["login"])
    }

    /// The device code: nothing on a remote machine can take the browser's callback.
    fn machine_login(&self) -> Option<super::MachineLogin> {
        Some(super::MachineLogin {
            args: &["login", "--device-auth"],
            files: &[".codex/auth.json"],
            keys: &["OPENAI_API_KEY", "CODEX_API_KEY"],
        })
    }

    fn models(&self) -> Vec<ModelOption> {
        let v: Value = serde_json::from_str(&output("codex", &["debug", "models"])).unwrap_or_default();
        v["models"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|m| str_of(m, "visibility") == "list")
            .map(|m| ModelOption {
                id: str_of(m, "slug").into(),
                label: m["display_name"].as_str().unwrap_or(str_of(m, "slug")).into(),
                efforts: m["supported_reasoning_levels"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|l| l["effort"].as_str().map(String::from))
                    .collect(),
                aliases: vec![],
            })
            .collect()
    }
}

/// bubblewrap's own error when it can't make the sandbox: no user namespaces (a
/// container, Ubuntu's AppArmor restriction), or no network namespace.
fn sandbox_failure(output: &str) -> Option<&str> {
    const SIGNS: [&str; 5] = ["namespace", "uid map", "setting up uid", "loopback", "No permissions to create"];
    output.lines().map(str::trim).find(|l| l.starts_with("bwrap:") && SIGNS.iter().any(|s| l.contains(s)))
}

/// "/bin/bash -lc 'echo hi'" -> "echo hi"
fn unwrap(cmd: &str) -> String {
    let inner = cmd
        .split_once(" -lc '")
        .or_else(|| cmd.split_once(" -c '"))
        .and_then(|(_, rest)| rest.strip_suffix('\''))
        .unwrap_or(cmd);
    short(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokens_come_from_the_finished_turn() {
        let mut out = Vec::new();
        let line = r#"{"type":"turn.completed","usage":{"input_tokens":24763,"cached_input_tokens":24448,"cache_write_input_tokens":0,"output_tokens":122,"reasoning_output_tokens":64}}"#;
        Codex::default().on_event(&serde_json::from_str(line).unwrap(), &mut out);
        let [AgentEvent::Usage(u)] = out.as_slice() else { panic!("one usage event") };
        assert_eq!((u.model.as_deref(), u.input, u.cache_read, u.output, u.total()), (None, 315, 24448, 122, 24885));
        out.clear();
        Codex::default().on_event(&serde_json::from_str(r#"{"type":"turn.completed","usage":{}}"#).unwrap(), &mut out);
        Codex::default().on_event(&serde_json::from_str(r#"{"type":"turn.completed"}"#).unwrap(), &mut out);
        assert!(out.is_empty(), "no counts: unknown");
    }

    #[test]
    fn a_sandbox_that_cant_start_is_said_once() {
        let mut c = Codex::default();
        let mut out = Vec::new();
        let done = |o: &str| json!({ "type": "item.completed", "item": { "type": "command_execution", "aggregated_output": o } });
        c.on_event(&done("total 0\nbwrap is a fine word\n"), &mut out);
        assert!(out.is_empty());
        c.on_event(&done("bwrap: No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces.\n"), &mut out);
        c.on_event(&done("bwrap: setting up uid map: Permission denied\n"), &mut out);
        let [AgentEvent::Error(e)] = out.as_slice() else { panic!("one error, got {}", out.len()) };
        assert!(e.contains("bubblewrap") && e.contains("No permissions to create new namespace"), "{e}");
    }
}
