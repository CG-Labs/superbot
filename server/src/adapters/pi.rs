//! Pi coding agent CLI: `pi --mode json`. Sessions are files in the Bot's own
//! session dir, addressed by a fixed --session-id, so resuming is the same call.

use super::{describe, new_uuid, output, str_of, Adapter, AgentEvent, ModelOption, RunInput, Usage};
use serde_json::Value;
use std::path::PathBuf;

pub struct Pi;

const GUARD_EXTENSION: &str = include_str!("pi_guard.ts");

fn guard_file(input: &RunInput) -> PathBuf {
    input.config_dir.join("superbot-guard.ts")
}

impl Adapter for Pi {
    /// `--session-dir` puts each Bot's sessions, `<time>_<session>.jsonl`, in its own folder.
    fn sessions(&self) -> super::Sessions {
        super::Sessions { home: &[], state: &[("pi-sessions", 1, true)] }
    }

    fn bin(&self) -> &'static str {
        "pi"
    }

    fn files(&self, input: &RunInput) -> Vec<(PathBuf, String)> {
        input.guard.iter().map(|_| (guard_file(input), GUARD_EXTENSION.to_string())).collect()
    }

    fn args(&mut self, input: &RunInput, out: &mut Vec<AgentEvent>) -> Vec<String> {
        let id = input.session_id.clone().unwrap_or_else(|| format!("s-{}", new_uuid()));
        out.push(AgentEvent::Session(id.clone()));
        let mut a: Vec<String> = vec![
            "--mode".into(), "json".into(),
            "--session-dir".into(), input.state_dir.join("pi-sessions").display().to_string(),
            "--session-id".into(), id,
            "--append-system-prompt".into(), input.system.clone(),
        ];
        if let Some(m) = &input.model {
            a.extend(["--model".into(), m.clone()]);
        }
        if let Some(e) = &input.effort {
            a.extend(["--thinking".into(), e.clone()]);
        }
        // Pi has no hook config, only TypeScript extensions: load a thin one that runs the gate.
        if input.guard.is_some() {
            a.extend(["--extension".into(), guard_file(input).display().to_string()]);
        }
        // A leading "@" would make pi read a file, so pad it.
        let p = &input.prompt;
        a.extend(["--".into(), if p.starts_with('@') { format!(" {p}") } else { p.clone() }]);
        a
    }

    fn on_event(&mut self, e: &Value, out: &mut Vec<AgentEvent>) {
        match str_of(e, "type") {
            "message_update" => {
                let m = &e["assistantMessageEvent"];
                if str_of(m, "type") == "text_delta" {
                    out.push(AgentEvent::TextDelta(str_of(m, "delta").into()));
                }
            }
            "message_end" if str_of(&e["message"], "role") == "assistant" => {
                let msg = &e["message"];
                for c in msg["content"].as_array().into_iter().flatten() {
                    if str_of(c, "type") == "text" && !str_of(c, "text").trim().is_empty() {
                        out.push(AgentEvent::Text(str_of(c, "text").into()));
                    }
                }
                // Each assistant message carries its own turn's counts, cache apart from input.
                let u = &msg["usage"];
                let usage = Usage {
                    model: msg["model"].as_str().filter(|m| !m.is_empty()).map(String::from),
                    input: Usage::count(&u["input"]),
                    output: Usage::count(&u["output"]),
                    cache_read: Usage::count(&u["cacheRead"]),
                    cache_write: Usage::count(&u["cacheWrite"]),
                };
                if usage.total() > 0 {
                    out.push(AgentEvent::Usage(usage));
                }
                if str_of(msg, "stopReason") == "error" {
                    out.push(AgentEvent::Error(msg["errorMessage"].as_str().unwrap_or("Pi failed").into()));
                }
            }
            "tool_execution_start" => {
                out.push(AgentEvent::Tool { name: str_of(e, "toolName").into(), detail: describe(&e["args"]) })
            }
            // Bad arguments and blocked calls end with `isError` too.
            "tool_execution_end" if e["isError"].as_bool() == Some(false) => out.push(AgentEvent::ToolRan { name: str_of(e, "toolName").into() }),
            "tool_execution_end" => out.push(AgentEvent::ToolFailed { name: str_of(e, "toolName").into() }),
            _ => {}
        }
    }

    /// From `pi --list-models`: models with credentials set up. Columns:
    /// provider, model, context, max-out, thinking (yes/no), images.
    fn shell_tool(&self) -> &'static str {
        "bash"
    }

    /// The extension's `tool_call` handler runs before every tool.
    fn hooks_tool(&self, _tool: &str) -> bool {
        true
    }

    fn models(&self) -> Vec<ModelOption> {
        let efforts: Vec<String> = ["off", "minimal", "low", "medium", "high", "xhigh", "max"].map(String::from).into();
        output("pi", &["--list-models"])
            .lines()
            .skip(1)
            .filter_map(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                let id = format!("{}/{}", c.first()?, c.get(1)?);
                let thinks = c.get(4) == Some(&"yes");
                Some(ModelOption { label: id.clone(), id, efforts: if thinks { efforts.clone() } else { vec![] }, aliases: vec![] })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_come_from_each_assistant_message() {
        let mut out = Vec::new();
        let line = r#"{"type":"message_end","message":{"role":"assistant","model":"gpt-5","content":[{"type":"text","text":"Hi"}],
            "usage":{"input":50,"output":12,"cacheRead":800,"cacheWrite":0,"totalTokens":862},"stopReason":"stop"}}"#;
        Pi.on_event(&serde_json::from_str(line).unwrap(), &mut out);
        let usage: Vec<&Usage> = out.iter().filter_map(|e| if let AgentEvent::Usage(u) = e { Some(u) } else { None }).collect();
        assert_eq!(usage, [&Usage { model: Some("gpt-5".into()), input: 50, output: 12, cache_read: 800, cache_write: 0 }]);
        out.clear();
        Pi.on_event(&serde_json::from_str(r#"{"type":"message_end","message":{"role":"user","usage":{"input":5}}}"#).unwrap(), &mut out);
        assert!(out.is_empty(), "only the model's own messages");
    }

    #[test]
    fn finished_calls_are_reported_by_name() {
        // As pi 1.5 prints them: a read that ran, one that failed, one with bad arguments.
        let lines = [
            r#"{"type":"tool_execution_start","toolCallId":"c1","toolName":"read","args":{"path":"/w/x.txt"}}"#,
            r#"{"type":"tool_execution_end","toolCallId":"c1","toolName":"read","result":{"content":[{"type":"text","text":"yo"}]},"isError":false,"durationMs":3}"#,
            r#"{"type":"tool_execution_end","toolCallId":"c2","toolName":"read","result":{"content":[{"type":"text","text":"ENOENT"}]},"isError":true,"durationMs":1}"#,
            r#"{"type":"tool_execution_end","toolCallId":"c3","toolName":"write","result":{"content":[{"type":"text","text":"Validation failed"}]},"isError":true}"#,
        ];
        let mut out = Vec::new();
        for l in lines {
            Pi.on_event(&serde_json::from_str(l).unwrap(), &mut out);
        }
        let ran: Vec<&str> = out.iter().filter_map(|e| if let AgentEvent::ToolRan { name } = e { Some(name.as_str()) } else { None }).collect();
        assert_eq!(ran, ["read"]);
        let failed: Vec<&str> = out.iter().filter_map(|e| if let AgentEvent::ToolFailed { name } = e { Some(name.as_str()) } else { None }).collect();
        assert_eq!(failed, ["read", "write"]);
    }
}
