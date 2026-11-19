//! `botctl`: the CLI Bots use for routines, other Bots, and handing their screen to the user. Works with any harness,
//! because every harness can run a shell command. Talks to botd over local HTTP.
//! A tiny HTTP/1.0 client over a TCP socket; no HTTP library.
//!
//! It is also the approval gate (`botctl hook <harness>`), and lets the operator manage
//! approvals and policy from a shell on the server (`SUPERBOT_PASSWORD`).

use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::net::TcpStream;

const HELP: &str = r#"botctl: manage your routines (scheduled tasks).

  botctl routines                                  List your routines
  botctl routine add "<name>" "<cron>" "<what to do>"
  botctl routine rm <id>                           Delete a routine
  botctl routine pause <id> | resume <id>
  botctl bots                                      List all Bots
  botctl ask "<Bot name or id>" "<message>"        Ask another Bot; prints its reply
  botctl handoff "<what you need>"                 Ask the user to take over your screen; waits for "Done"

Cron has 5 fields in the server's local time: minute hour day month weekday.
  "30 7 * * *"    every day at 07:30
  "0 9 * * 1-5"   weekdays at 09:00
  "*/15 * * * *"  every 15 minutes
When a routine fires, you get "<what to do>" as a message and your reply goes to the user's chat.
Confirm the schedule with the user in plain words.

`ask` and `handoff` can take minutes: run them with a long command timeout (10 minutes).
If the other Bot takes longer, its reply arrives later as a new message."#;

const ADMIN_HELP: &str = r#"Operator commands (run on the server; need SUPERBOT_PASSWORD set to AUTH_PASSWORD,
and BOT_API if botd isn't on http://127.0.0.1:3000):

  botctl policy [<bot>]                            Show the global or a Bot's policy
  botctl policy set <global|bot> [mode=ask|bypass] [timeout=<minutes>] [<class>=allow|ask|deny]...
  botctl policy reset <bot>                        Drop a Bot's override; it follows global again
  botctl rules [<bot>]                             List allow/deny rules
  botctl rule add <allow|deny> "<pattern>" [--tool <tool>] [--bot <bot>]
  botctl rule rm <id>
  botctl approvals [pending|all]                   List approvals
  botctl approve <id> [--remember | --remember-global]
  botctl deny <id> [--remember | --remember-global]
  botctl audit [<limit>]                           Recent audit events

Classes: shell_destructive, file_delete, outbound_message, network_install, git_push.
Patterns are globs (* and ?) over the command, path, URL, or tool arguments."#;

enum Cred {
    Bot,
    Operator,
}

fn base() -> String {
    std::env::var("BOT_API").unwrap_or_else(|_| "http://127.0.0.1:3000".into())
}

fn api(cred: Cred, method: &str, path: &str, body: Option<String>) -> Result<String, String> {
    let auth = match cred {
        Cred::Bot => match (std::env::var("BOT_API"), std::env::var("BOT_TOKEN")) {
            (Ok(_), Ok(token)) => format!("Bearer {token}"),
            _ => return Err("botctl only works inside a Bot run (BOT_API and BOT_TOKEN are missing).".into()),
        },
        Cred::Operator => match std::env::var("SUPERBOT_PASSWORD") {
            Ok(p) if !p.is_empty() => format!("Basic {}", base64(format!("superbot:{p}").as_bytes())),
            _ => return Err("Set SUPERBOT_PASSWORD to the server's AUTH_PASSWORD to manage approvals and policy.".into()),
        },
    };
    let base = base();
    let addr = base.trim_start_matches("http://").trim_end_matches('/');
    let mut s = TcpStream::connect(addr).map_err(|e| format!("Can't reach the server: {e}"))?;
    let body = body.unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nAuthorization: {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut res = String::new();
    s.read_to_string(&mut res).map_err(|e| e.to_string())?;
    let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if (200..300).contains(&code) {
        Ok(body.to_string())
    } else {
        let msg = serde_json::from_str::<Value>(body).ok().and_then(|v| v["error"].as_str().map(String::from)).unwrap_or(body.into());
        Err(format!("{msg} (HTTP {code})"))
    }
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn pretty(body: String) -> String {
    serde_json::from_str::<Value>(&body).ok().and_then(|v| serde_json::to_string_pretty(&v).ok()).unwrap_or(body)
}

/// The approval gate. The harness pipes its PreToolUse event on stdin; botd decides,
/// waiting for the user if needed. Exit 0 allows. Anything else must block, so every
/// failure (no server, bad reply) exits 2 with the reason on stderr.
fn hook(harness: &str) -> ! {
    let mut event = String::new();
    let verdict = std::io::stdin()
        .read_to_string(&mut event)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str::<Value>(&event).map_err(|e| format!("bad hook input: {e}")))
        .and_then(|event| {
            let body = json!({ "from": std::env::var("BOT_ID").unwrap_or_default(), "harness": harness, "event": event });
            api(Cred::Bot, "POST", "/api/approvals/check", Some(body.to_string()))
        });
    match verdict {
        Ok(r) if r.lines().next() == Some("allow") => std::process::exit(0),
        Ok(r) => {
            let reason = r.split_once('\n').map(|(_, r)| r.trim()).filter(|r| !r.is_empty()).unwrap_or("Blocked by SuperBot policy.");
            eprintln!("{reason}");
        }
        Err(e) => eprintln!("SuperBot's approval gate failed, so this action was blocked: {e}"),
    }
    std::process::exit(2)
}

fn policy_patch(args: &[&str]) -> Result<Value, String> {
    let mut patch = Map::new();
    let mut classes = Map::new();
    for a in args {
        let (k, v) = a.split_once('=').ok_or(format!("Expected key=value, got \"{a}\""))?;
        match k {
            "mode" => _ = patch.insert("mode".into(), json!(v)),
            "timeout" => _ = patch.insert("timeoutMinutes".into(), json!(v.parse::<u64>().map_err(|_| "timeout must be minutes")?)),
            class => _ = classes.insert(class.into(), json!(v)),
        }
    }
    if !classes.is_empty() {
        patch.insert("classes".into(), Value::Object(classes));
    }
    if patch.is_empty() {
        return Err("Nothing to set. Example: botctl policy set global mode=ask timeout=15 git_push=deny".into());
    }
    Ok(Value::Object(patch))
}

fn flag<'a>(rest: &[&'a str], name: &str) -> Option<&'a str> {
    rest.windows(2).find(|w| w[0] == name).map(|w| w[1])
}

fn decide(verb: &str, id: &str, rest: &[&str]) -> Result<String, String> {
    let remember = if rest.contains(&"--remember-global") {
        json!("global")
    } else if rest.contains(&"--remember") {
        json!("bot")
    } else {
        Value::Null
    };
    let body = json!({ "remember": remember }).to_string();
    api(Cred::Operator, "POST", &format!("/api/approvals/{id}/{verb}"), Some(body)).map(|_| if verb == "approve" { "Approved." } else { "Denied." }.into())
}

fn run(args: &[String]) -> Result<String, String> {
    let bot = std::env::var("BOT_ID").unwrap_or_default();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let op = |m: &str, p: &str, b: Option<String>| api(Cred::Operator, m, p, b).map(pretty);
    match a.as_slice() {
        ["routines"] | ["routine", "list"] => api(Cred::Bot, "GET", &format!("/api/bots/{bot}/routines"), None),
        ["routine", "add", name, cron, what] => {
            let body = json!({ "name": name, "cron": cron, "instruction": what }).to_string();
            api(Cred::Bot, "POST", &format!("/api/bots/{bot}/routines"), Some(body)).map(|_| format!("Added routine \"{name}\" ({cron})."))
        }
        ["routine", "rm" | "delete", id] => api(Cred::Bot, "DELETE", &format!("/api/routines/{id}"), None).map(|_| "Deleted.".into()),
        ["routine", cmd @ ("pause" | "resume"), id] => {
            let body = json!({ "enabled": *cmd == "resume" }).to_string();
            api(Cred::Bot, "PATCH", &format!("/api/routines/{id}"), Some(body)).map(|_| if *cmd == "pause" { "Paused." } else { "Resumed." }.into())
        }
        ["bots"] => api(Cred::Bot, "GET", "/api/bots", None),
        ["ask", to, message] => {
            let body = json!({ "from": bot, "to": to, "text": message }).to_string();
            api(Cred::Bot, "POST", "/api/ask", Some(body))
        }
        ["handoff", text] => {
            let body = json!({ "from": bot, "text": text }).to_string();
            api(Cred::Bot, "POST", "/api/handoff", Some(body))
        }
        ["hook", harness] => hook(harness),

        ["policy"] | ["policy", "global"] => op("GET", "/api/policy", None),
        ["policy", "set", "global", rest @ ..] => op("PUT", "/api/policy", Some(policy_patch(rest)?.to_string())),
        ["policy", "set", id, rest @ ..] => op("PUT", &format!("/api/bots/{id}/policy"), Some(policy_patch(rest)?.to_string())),
        ["policy", "reset", id] => op("DELETE", &format!("/api/bots/{id}/policy"), None).map(|_| "Reset. This Bot follows the global policy.".into()),
        ["policy", id] => op("GET", &format!("/api/bots/{id}/policy"), None),
        ["rules"] => op("GET", "/api/policy/rules", None),
        ["rules", id] => op("GET", &format!("/api/policy/rules?bot={id}"), None),
        ["rule", "add", action @ ("allow" | "deny"), pattern, rest @ ..] => {
            let body = json!({ "action": action, "pattern": pattern, "tool": flag(rest, "--tool"), "botId": flag(rest, "--bot") });
            op("POST", "/api/policy/rules", Some(body.to_string()))
        }
        ["rule", "rm" | "delete", id] => op("DELETE", &format!("/api/policy/rules/{id}"), None).map(|_| "Deleted.".into()),
        ["approvals"] => op("GET", "/api/approvals?status=pending", None),
        ["approvals", status] => op("GET", &format!("/api/approvals?status={status}"), None),
        [verb @ ("approve" | "deny"), id, rest @ ..] => decide(verb, id, rest),
        ["audit"] => op("GET", "/api/audit", None),
        ["audit", n] => op("GET", &format!("/api/audit?limit={n}"), None),
        ["help", "admin"] | ["admin"] => Ok(ADMIN_HELP.into()),
        _ => Ok(HELP.into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"superbot:pw"), "c3VwZXJib3Q6cHc=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }

    #[test]
    fn policy_set_builds_a_patch() {
        let p = policy_patch(&["mode=ask", "timeout=15", "git_push=deny"]).unwrap();
        assert_eq!(p, json!({ "mode": "ask", "timeoutMinutes": 15, "classes": { "git_push": "deny" } }));
        assert!(policy_patch(&[]).is_err());
        assert!(policy_patch(&["timeout=soon"]).is_err());
    }
}
