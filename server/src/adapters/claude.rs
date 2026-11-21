//! Claude Code CLI: `claude -p --output-format stream-json`.
//! Resumes with `--resume <session id>`. The system prompt is applied fresh every run.

use super::{describe, new_uuid, str_of, Adapter, AgentEvent, ModelOption, RunInput, Usage};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Default)]
pub struct Claude {
    id: String,
    saw_turn: bool,
    /// The model `system/init` named.
    model: Option<String>,
    /// Tool calls not finished yet: id to tool name, as results name only the id.
    calls: HashMap<String, String>,
}

/// Claude Code's sandbox for Bash (ADR 0055): writes to the working folder, the temp
/// folders, and `writable`. Its proxy refuses local addresses it isn't told about, so
/// botd's API is listed for `botctl`; other hosts stay open, as permissions are skipped.
/// No command may leave the sandbox. File tools and hooks run outside it, as in
/// Claude Code itself.
fn sandbox_settings(s: &super::Sandbox, api: Option<String>) -> Value {
    let writable: Vec<String> = s.writable.iter().map(|p| p.display().to_string()).collect();
    json!({
        "enabled": true,
        "allowUnsandboxedCommands": false,
        "filesystem": { "allowWrite": writable },
        "network": { "allowedDomains": api.into_iter().collect::<Vec<_>>() },
    })
}

impl Adapter for Claude {
    fn bin(&self) -> &'static str {
        "claude"
    }

    fn args(&mut self, input: &RunInput, _out: &mut Vec<AgentEvent>) -> Vec<String> {
        self.id = input.session_id.clone().unwrap_or_else(new_uuid);
        let mut a: Vec<String> = [
            "-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
            "--dangerously-skip-permissions", "--append-system-prompt", &input.system,
        ]
        .map(String::from)
        .into();
        a.extend([if input.session_id.is_some() { "--resume" } else { "--session-id" }.into(), self.id.clone()]);
        // A PreToolUse deny holds even with --dangerously-skip-permissions. Flag settings
        // outrank project files, so a workspace `disableAllHooks` can't switch it off.
        let mut settings = serde_json::Map::new();
        if let Some(g) = &input.guard {
            let hook = json!({ "type": "command", "command": g.command, "timeout": g.timeout_secs });
            settings.insert("disableAllHooks".into(), json!(false));
            settings.insert("hooks".into(), json!({ "PreToolUse": [{ "matcher": "*", "hooks": [hook] }] }));
        }
        if let Some(s) = &input.sandbox {
            settings.insert("sandbox".into(), sandbox_settings(s, super::api_host(input)));
        }
        if !settings.is_empty() {
            a.extend(["--settings".into(), Value::Object(settings).to_string()]);
        }
        if let Some(m) = &input.model {
            a.extend(["--model".into(), m.clone()]);
        }
        if let Some(e) = &input.effort {
            a.extend(["--effort".into(), e.clone()]);
        }
        a.extend(["--".into(), input.prompt.clone()]);
        a
    }

    fn on_event(&mut self, e: &Value, out: &mut Vec<AgentEvent>) {
        match str_of(e, "type") {
            "stream_event" => {
                let ev = &e["event"];
                if str_of(ev, "type") == "content_block_delta" && str_of(&ev["delta"], "type") == "text_delta" {
                    out.push(AgentEvent::TextDelta(str_of(&ev["delta"], "text").into()));
                }
            }
            "assistant" => {
                // Save the session only once it really exists.
                if !self.saw_turn {
                    self.saw_turn = true;
                    out.push(AgentEvent::Session(self.id.clone()));
                }
                for c in e["message"]["content"].as_array().into_iter().flatten() {
                    match str_of(c, "type") {
                        "text" if !str_of(c, "text").trim().is_empty() => out.push(AgentEvent::Text(str_of(c, "text").into())),
                        "tool_use" => {
                            self.calls.insert(str_of(c, "id").into(), str_of(c, "name").into());
                            out.push(AgentEvent::Tool { name: str_of(c, "name").into(), detail: describe(&c["input"]) })
                        }
                        _ => {}
                    }
                }
            }
            // Results come back as the user's turn; a call refused before the hook, by
            // the hook, or failing has `is_error`.
            "user" => {
                for c in e["message"]["content"].as_array().into_iter().flatten().filter(|c| str_of(c, "type") == "tool_result") {
                    if let Some(name) = self.calls.remove(str_of(c, "tool_use_id"))
                        && c["is_error"].as_bool() != Some(true)
                    {
                        out.push(AgentEvent::ToolRan { name });
                    }
                }
            }
            "system" if str_of(e, "subtype") == "init" => {
                self.model = e["model"].as_str().filter(|m| !m.is_empty()).map(String::from);
            }
            "result" => {
                usage(e, self.model.as_deref(), out);
                if e["is_error"].as_bool() == Some(true) {
                    let msg = e["result"].as_str().unwrap_or("Claude Code failed");
                    out.push(AgentEvent::Error(msg.into()));
                }
            }
            _ => {}
        }
    }

    /// Claude Code has no command to list models, so this is the current lineup.
    /// Update it when Anthropic ships new models.
    fn shell_tool(&self) -> &'static str {
        "Bash"
    }

    /// The `*` matcher runs the hook for every tool once Claude Code has checked the
    /// call's arguments.
    fn hooks_tool(&self, _tool: &str) -> bool {
        true
    }

    fn has_sandbox(&self) -> bool {
        true
    }

    /// The system's bubblewrap, and socat for its network proxy. Without them it runs
    /// commands unsandboxed.
    fn sandbox_needs(&self) -> &'static [&'static str] {
        &["bwrap", "socat"]
    }

    fn login_args(&self) -> Option<&'static [&'static str]> {
        Some(&["auth", "login"])
    }

    fn machine_login(&self) -> Option<super::MachineLogin> {
        Some(super::MachineLogin {
            args: &["auth", "login"],
            files: &[".claude/.credentials.json"],
            keys: &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"],
        })
    }

    fn models(&self) -> Vec<ModelOption> {
        let efforts: Vec<String> = ["low", "medium", "high", "xhigh", "max"].map(String::from).into();
        [
            ("claude-fable-5-2", "Fable 5.2", "fable"),
            ("claude-opus-5-5", "Opus 5.5", "opus"),
            ("claude-sonnet-5-5", "Sonnet 5.5", "sonnet"),
            ("claude-haiku-5-5", "Haiku 5.5", "haiku"),
        ]
        .map(|(id, label, alias)| ModelOption { id: id.into(), label: label.into(), efforts: efforts.clone(), aliases: vec![alias.into()] })
        .into()
    }
}

/// The tokens a `result` reports: `modelUsage`, one entry per model the run used (a
/// main model and a small one for background work), else the run's `usage` for the
/// model `system/init` named. Anthropic's `input_tokens` already leaves out the cache.
fn usage(e: &Value, model: Option<&str>, out: &mut Vec<AgentEvent>) {
    let n = Usage::count;
    let mut found = Vec::new();
    for (name, m) in e["modelUsage"].as_object().into_iter().flatten() {
        found.push(Usage {
            model: Some(name.clone()).filter(|n| !n.is_empty()),
            input: n(&m["inputTokens"]),
            output: n(&m["outputTokens"]),
            cache_read: n(&m["cacheReadInputTokens"]),
            cache_write: n(&m["cacheCreationInputTokens"]),
        });
    }
    if found.is_empty() {
        let u = &e["usage"];
        found.push(Usage {
            model: model.map(String::from),
            input: n(&u["input_tokens"]),
            output: n(&u["output_tokens"]),
            cache_read: n(&u["cache_read_input_tokens"]),
            cache_write: n(&u["cache_creation_input_tokens"]),
        });
    }
    out.extend(found.into_iter().filter(|u| u.total() > 0).map(AgentEvent::Usage));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage_of(lines: &[&str]) -> Vec<Usage> {
        let mut c = Claude::default();
        let mut out = Vec::new();
        for l in lines {
            c.on_event(&serde_json::from_str(l).unwrap(), &mut out);
        }
        out.into_iter().filter_map(|e| if let AgentEvent::Usage(u) = e { Some(u) } else { None }).collect()
    }

    #[test]
    fn tokens_come_from_the_result() {
        let init = r#"{"type":"system","subtype":"init","model":"claude-sonnet-5-5","session_id":"s"}"#;
        // Per model when Claude Code breaks it down.
        let both = usage_of(&[
            init,
            r#"{"type":"result","subtype":"success","is_error":false,"result":"ok","usage":{"input_tokens":9,"output_tokens":9},
               "modelUsage":{"claude-sonnet-5-5":{"inputTokens":120,"outputTokens":45,"cacheReadInputTokens":3000,"cacheCreationInputTokens":200},
                             "claude-haiku-5-5":{"inputTokens":30,"outputTokens":5,"cacheReadInputTokens":0,"cacheCreationInputTokens":0}}}"#,
        ]);
        let sonnet = both.iter().find(|u| u.model.as_deref() == Some("claude-sonnet-5-5")).unwrap();
        assert_eq!((sonnet.input, sonnet.output, sonnet.cache_read, sonnet.cache_write, sonnet.total()), (120, 45, 3000, 200, 3365));
        assert_eq!(both.len(), 2);
        // Else the run's usage, for the model init named; an error result still counts.
        let one = usage_of(&[
            init,
            r#"{"type":"result","is_error":true,"result":"overloaded","usage":{"input_tokens":7,"output_tokens":2,"cache_read_input_tokens":1,"cache_creation_input_tokens":0}}"#,
        ]);
        assert_eq!(one, [Usage { model: Some("claude-sonnet-5-5".into()), input: 7, output: 2, cache_read: 1, cache_write: 0 }]);
        // Nothing reported: no usage, so the run is unknown.
        assert!(usage_of(&[r#"{"type":"result","is_error":false,"result":"ok"}"#]).is_empty());
    }

    #[test]
    fn finished_calls_are_reported_by_name() {
        // As Claude Code 2.1 streams them: a read that ran, an edit refused before the hook.
        let lines = [
            r#"{"type":"assistant","message":{"content":[{"id":"toolu_1","input":{"file_path":"/w/x.txt"},"name":"Read","type":"tool_use"}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_1","type":"tool_result","content":[{"type":"text","text":"hi"}]}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"id":"toolu_2","input":{"file_path":"/w/y.txt"},"name":"Edit","type":"tool_use"}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"<tool_use_error>File does not exist.</tool_use_error>","is_error":true,"tool_use_id":"toolu_2"}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"again","tool_use_id":"toolu_1"}]}}"#,
        ];
        let mut c = Claude::default();
        let mut out = Vec::new();
        for l in lines {
            c.on_event(&serde_json::from_str(l).unwrap(), &mut out);
        }
        let ran: Vec<&str> = out.iter().filter_map(|e| if let AgentEvent::ToolRan { name } = e { Some(name.as_str()) } else { None }).collect();
        assert_eq!(ran, ["Read"], "once per call, never for an error");
        assert!(c.calls.is_empty());
    }
}
