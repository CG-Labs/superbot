//! `botctl`: the CLI Bots use for routines, other Bots, and handing their screen to the user. Works with any harness,
//! because every harness can run a shell command. Talks to botd over local HTTP.
//! A tiny HTTP/1.0 client over a TCP socket; no HTTP library.
//!
//! It is also the approval gate (`botctl hook <harness>`), and lets an admin manage
//! approvals, policy, users, and sessions from a shell on the server (`SUPERBOT_TOKEN`
//! from `botctl login`, or the break-glass `SUPERBOT_PASSWORD`).

use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::net::TcpStream;

const HELP: &str = r#"botctl: manage your routines (scheduled tasks).

  botctl routines                                  List your routines
  botctl routine add "<name>" "<cron>" "<what to do>"
  botctl routine rm <id>                           Delete a routine
  botctl routine pause <id> | resume <id>
  botctl bots                                      List the Bots you can see (your owner's)
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

const ADMIN_HELP: &str = r#"Operator commands (run on the server; need SUPERBOT_TOKEN, or SUPERBOT_PASSWORD set to
AUTH_PASSWORD, and BOT_API if botd isn't on http://127.0.0.1:3000; both are only sent to this machine):

  botctl login [<code> | -]                        Sign in with a sign-in code (- reads it from stdin), or
                                                   with SUPERBOT_PASSWORD; prints a SUPERBOT_TOKEN
  botctl logout                                    End the SUPERBOT_TOKEN session
  botctl whoami                                    Who the token or password signs in as, and its role
  botctl users                                     List users
  botctl user add <email> ["<name>"] [--role admin|member|readonly]
  botctl user role <user> <admin|member|readonly>  <user> is an id or email
  botctl user disable <user> | enable <user>       Disabling ends the user's sessions
  botctl user tier <user> <tier|default>           Their plan: the models and limits they get
  botctl tiers                                     Every tier, its routes and limits, and the default
  botctl user isolation <user>                     With ISOLATION=users: the user's own account and folders
  botctl user isolate <user>                       Make that account and its folders now
  botctl user harness-login <user> <claude|codex> [-- <args>...]
                                                   Log a harness in as that user's account, for their
                                                   Bots only (as botd's service account, at a terminal)
  botctl setup [status | json]                     What the server still needs: the onboarding checklist
  botctl setup done | reopen | hide | show         Finish the setup wizard, reopen it, or hide it from admins
  botctl license [json]                            The self-host license, its seats, and when it ends
  botctl license install [<file> | -] < key        Install the license key CG-Labs sent (stdin by default)
  botctl license remove                            Back to the community edition (10 active people)
  botctl user code <user> [--ttl <minutes>]        A one-time sign-in code (default 60 minutes)
  botctl user identities <user>                    The user's SSO identities
  botctl user link <user> <provider> <subject> [--tenant <tenant-id>]
                                                   Let an SSO identity sign in as the user. Entra:
                                                   <subject> is the user's object id; Google,
                                                   Apple, and OIDC: the sub claim (or the mapped
                                                   subject); GitHub: the numeric user id
                                                   (gh api users/<login> --jq .id)
  botctl user unlink <user> <identity-id>
  botctl signup list [pending|approved|rejected|all]  Access requests from the get-started page
  botctl signup approve <id> [--role admin|member|readonly] [--ttl <minutes>]
                                                   Make the user (member by default) and print a
                                                   one-time sign-in code, once (default 3 days)
  botctl signup reject <id> [--reason "<text>"]    No email is sent either way
  botctl scim tokens                               SCIM tokens (never their values), and whether SCIM is on
  botctl scim token create <tenant> [--sso <provider>] [--label "<text>"]
                                                   A bearer token for an IdP's SCIM app, shown once.
                                                   <tenant> names the IdP connection (e.g. entra);
                                                   --sso: externalId is the person's subject there
  botctl scim token revoke <id>                    The IdP's users stay as they are
  botctl sessions [<user>]                         Live sessions
  botctl session revoke <id>
  botctl session revoke-all <user>

  botctl bot access <bot>                          Who owns a Bot, who can see it, and their grants
  botctl bot share <bot> | private <bot>           Shared with everyone, or only its owner and grants
  botctl bot owner <bot> <user>                    Give a Bot to another user (admins only)
  botctl bot grant <bot> <user> <viewer|operator>  viewer: read its chat; operator: also run it
  botctl bot revoke <bot> <user>

  botctl policy [<bot>]                            Show the global or a Bot's policy
  botctl policy set <global|bot> [mode=ask|bypass] [timeout=<minutes>] [<class>=allow|ask|deny]...
  botctl policy reset <bot>                        Drop a Bot's override; it follows global again
  botctl rules [<bot>]                             List allow/deny rules
  botctl rule add <allow|deny> "<pattern>" [--tool <tool>] [--bot <bot>]
  botctl rule rm <id>
  botctl approvals [pending|all]                   List approvals
  botctl approve <id> [--remember | --remember-global]
  botctl deny <id> [--remember | --remember-global]
  botctl audit [<limit>] [filters]                 Recent audit events, newest first
  botctl audit export [filters] > audit.csv        All matching events as CSV, oldest first
    filters: --from <time> --to <time> --action <a,b.*> --actor <user|bot|system[:id]>
             --actor user:<email> --method <password,code,sso,none,bot_token,scim_token>
             --idp <entra|google|oidc|github|apple|saml> --idp-provider <id> --subject <issuer|sub>
             --session <id> --on-behalf-of <user id|email> --outcome <success|failure|denied> --bot <id>
    times: YYYY-MM-DD (UTC), RFC 3339, or unix milliseconds
  botctl machine placement [<user>]                Where each user's Bots run: this server or their machine
  botctl machine assign <user>                     Run the user's Bots on their enrolled machine
  botctl machine unassign <user>                   Stop using it; with MACHINE_ROUTING=assigned they run here again
  botctl machine agent <user>                      Its agent's build, harness CLIs and upgrades, against botd's
  botctl machine upgrade <user>                    Upgrade its agent to botd's build now
  botctl machine upgrade <user> hold|release       Keep its agent at its build, or let it be upgraded again
  botctl machine harnesses <user>                  Install MACHINE_HARNESSES on it now, retrying failures
  botctl secrets                                   List secret names (never values)
  botctl secret set <NAME> < value-file            Save a secret, encrypted; Bots get it as $NAME
  botctl secret rm <NAME>                          Delete a saved secret

Classes: shell_destructive, file_delete, outbound_message, network_install, git_push.
Patterns are globs (* and ?) over the command, path, URL, or tool arguments."#;

enum Cred {
    Bot,
    Operator,
    /// Signing in: sends no Authorization, but the body holds a secret, so loopback only.
    Anonymous,
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
        Cred::Operator => operator_auth()?,
        Cred::Anonymous => String::new(),
    };
    let base = base();
    let addr = addr(&base)?;
    let operator = !matches!(cred, Cred::Bot);
    if operator && !loopback(addr) {
        return Err(format!("botctl sends SUPERBOT_TOKEN, SUPERBOT_PASSWORD, and sign-in codes only to a server on this machine, not {addr}. Run it on the server, or set BOT_API to an SSH tunnel on 127.0.0.1."));
    }
    let mut s = TcpStream::connect(addr).map_err(|e| format!("Can't reach the server: {e}"))?;
    if operator && !s.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
        return Err(format!("{addr} isn't on this machine, so botctl won't send credentials there."));
    }
    let auth = if auth.is_empty() { String::new() } else { format!("Authorization: {auth}\r\n") };
    let body = body.unwrap_or_default();
    // BOT_TOKEN is this Bot's own, so it says which Bot is calling (ADR 0029).
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\n{auth}User-Agent: botctl/{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        env!("CARGO_PKG_VERSION"),
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

/// The extra arguments of `botctl user harness-login`: none, or everything after `--`.
fn login_extra<'a>(rest: &'a [&'a str]) -> Result<Option<&'a [&'a str]>, String> {
    match rest {
        [] => Ok(None),
        ["--", args @ ..] => Ok(Some(args)),
        _ => Err("Usage: botctl user harness-login <user> <claude|codex> [-- <login arguments>...]".into()),
    }
}

/// `botctl user harness-login`: botd makes the user's account if needed and says how to
/// start the harness's login as it; this runs that here, at the admin's terminal. Only
/// botd's service account may switch to per-user accounts, so run it as that account.
fn harness_login(key: &str, harness: &str, rest: &[&str]) -> Result<String, String> {
    let body = json!({ "harness": harness, "args": login_extra(rest)? });
    let res = api(Cred::Operator, "POST", &format!("/api/users/{}/harness-login", encode(key)), Some(body.to_string()))?;
    let v: Value = serde_json::from_str(&res).map_err(|e| e.to_string())?;
    let argv: Vec<&str> = v["command"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let (Some((bin, args)), Some(home)) = (argv.split_first(), v["home"].as_str()) else {
        return Err(format!("Unexpected reply from the server: {res}"));
    };
    eprintln!("Starting the {harness} login as the user's own account (HOME {home}). Only their Bots will use it.");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(home).env_clear();
    for (k, val) in std::env::vars_os() {
        let k_str = k.to_string_lossy();
        if k_str == "TERM" || k_str == "LANG" || k_str.starts_with("LC_") {
            cmd.env(&k, val);
        }
    }
    // sudo resets PATH; superbot-run puts this one back, so the harness is found as botd finds it.
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("SUPERBOT_PATH", path);
    }
    let status = cmd.status().map_err(|e| format!("Couldn't start {bin}: {e}"))?;
    if status.success() {
        Ok(format!("Done. The user's Bots now use this {harness} login."))
    } else {
        Err(format!("The login exited with {status}. If sudo asked for a password, run botctl as botd's service account (sudo -iu <service user>)."))
    }
}

/// A session token from `botctl login` wins over the break-glass password.
fn operator_auth() -> Result<String, String> {
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    match (var("SUPERBOT_TOKEN"), var("SUPERBOT_PASSWORD")) {
        (Some(t), _) => Ok(format!("Bearer {t}")),
        (None, Some(p)) => Ok(format!("Basic {}", base64(format!("superbot:{p}").as_bytes()))),
        _ => Err("Set SUPERBOT_TOKEN (from botctl login <code>), or SUPERBOT_PASSWORD to the server's AUTH_PASSWORD.".into()),
    }
}

/// `botctl login`: the body for POST /api/auth/login.
fn login_body(arg: Option<&str>) -> Result<Value, String> {
    let code = match arg {
        Some("-") => {
            let mut c = String::new();
            std::io::stdin().read_to_string(&mut c).map_err(|e| e.to_string())?;
            Some(c.trim().to_string())
        }
        Some(c) => Some(c.trim().to_string()),
        None => None,
    };
    let body = match code {
        Some(c) if c.is_empty() => return Err("The sign-in code is empty.".into()),
        Some(c) => json!({ "code": c }),
        None => match std::env::var("SUPERBOT_PASSWORD") {
            Ok(p) if !p.is_empty() => json!({ "password": p }),
            _ => return Err("Give a sign-in code (botctl login <code>), or set SUPERBOT_PASSWORD.".into()),
        },
    };
    let mut body = body;
    body["session"] = json!("token");
    body["label"] = json!("botctl");
    Ok(body)
}

fn role(r: &str) -> Result<&str, String> {
    match r {
        "admin" | "member" | "readonly" | "read-only" => Ok(r),
        _ => Err(format!("Role must be admin, member, or readonly, not \"{r}\".")),
    }
}

/// The `host:port` in BOT_API. botctl speaks plain http only.
fn addr(base: &str) -> Result<&str, String> {
    let a = base.strip_prefix("http://").unwrap_or("").trim_end_matches('/');
    if a.is_empty() || a.contains(['/', '@', '?', '#']) {
        return Err(format!("BOT_API should look like http://127.0.0.1:3000, not {base}"));
    }
    Ok(a)
}

/// Whether `addr` names this machine. Plain http crosses any network in the clear,
/// so the operator password only goes to loopback.
fn loopback(addr: &str) -> bool {
    let host = match addr.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => addr.rsplit_once(':').map_or(addr, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
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
/// `--cwd` names the folder the tool runs in, for harnesses whose hook runs elsewhere.
fn hook(harness: &str, cwd: Option<&str>) -> ! {
    let mut event = String::new();
    let verdict = std::io::stdin()
        .read_to_string(&mut event)
        .map_err(|e| e.to_string())
        .and_then(|_| hook_body(harness, &std::env::var("BOT_ID").unwrap_or_default(), &event, cwd))
        .and_then(|body| api(Cred::Bot, "POST", "/api/approvals/check", Some(body)));
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

fn hook_body(harness: &str, bot: &str, event: &str, cwd: Option<&str>) -> Result<String, String> {
    let mut event = serde_json::from_str::<Value>(event).map_err(|e| format!("bad hook input: {e}"))?;
    if let Some(cwd) = cwd {
        if !cwd.starts_with('/') {
            return Err(format!("--cwd must be an absolute path, not {cwd}"));
        }
        let obj = event.as_object_mut().ok_or("bad hook input: not a JSON object")?;
        obj.insert("cwd".into(), json!(cwd));
    }
    Ok(json!({ "from": bot, "harness": harness, "event": event }).to_string())
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

/// Percent-encodes a query string value.
fn encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'*' | b',' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `botctl audit` options as a query string: `[<limit>] [--from <t>] [--action <a>] ...`.
fn audit_query(rest: &[&str]) -> Result<String, String> {
    let mut pairs = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--from" | "--to" | "--action" | "--actor" | "--method" | "--idp" | "--idp-provider" | "--subject" | "--session" | "--on-behalf-of" | "--outcome"
            | "--bot" | "--limit" => {
                let v = it.next().ok_or(format!("{a} needs a value"))?;
                let key = match *a {
                    "--idp-provider" => "idpProvider",
                    "--on-behalf-of" => "onBehalfOf",
                    k => &k[2..],
                };
                pairs.push(format!("{key}={}", encode(v)));
            }
            n if n.parse::<u32>().is_ok() => pairs.push(format!("limit={n}")),
            other => return Err(format!("Unknown audit option \"{other}\". See botctl admin.")),
        }
    }
    Ok(if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) })
}

fn flag<'a>(rest: &[&'a str], name: &str) -> Option<&'a str> {
    rest.windows(2).find(|w| w[0] == name).map(|w| w[1])
}

/// `botctl bot ...`: who owns and can see a Bot (ADR 0017). The request to send.
fn bot_access(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    let access = |bot: &str| format!("/api/bots/{}/access", encode(bot));
    let grant = |bot: &str, user: &str| format!("/api/bots/{}/grants/{}", encode(bot), encode(user));
    Ok(match args {
        ["access", bot] => ("GET", access(bot), None),
        [v @ ("share" | "private"), bot] => {
            let visibility = if *v == "share" { "shared" } else { "private" };
            ("PATCH", access(bot), Some(json!({ "visibility": visibility }).to_string()))
        }
        ["owner", bot, user] => ("PATCH", access(bot), Some(json!({ "owner": user }).to_string())),
        ["grant", bot, user, level @ ("viewer" | "operator")] => ("PUT", grant(bot, user), Some(json!({ "level": level }).to_string())),
        ["grant", ..] => return Err("Usage: botctl bot grant <bot> <user> <viewer|operator>".into()),
        ["revoke", bot, user] => ("DELETE", grant(bot, user), None),
        _ => return Err("Unknown bot command. See botctl admin.".into()),
    })
}

/// `botctl machine ...`: which computer each user's Bots run on (ADR 0036), and its
/// agent's harnesses and upgrades (ADR 0039).
fn machine_request(args: &[&str]) -> Result<(&'static str, String), String> {
    let at = |user: &str| format!("/api/users/{}/placement", encode(user));
    let machine = |user: &str, rest: &str| format!("/api/users/{}/machine/{rest}", encode(user));
    Ok(match args {
        ["placement"] | ["placements"] => ("GET", "/api/machines/placements".into()),
        ["placement", user] => ("GET", at(user)),
        ["assign", user] => ("PUT", at(user)),
        ["unassign", user] => ("DELETE", at(user)),
        ["agent", user] => ("GET", machine(user, "agent")),
        ["upgrade", user] => ("POST", machine(user, "agent/upgrade")),
        ["upgrade", user, "hold"] => ("PUT", machine(user, "agent/hold")),
        ["upgrade", user, "release"] => ("DELETE", machine(user, "agent/hold")),
        ["harnesses", user] => ("POST", machine(user, "harnesses")),
        _ => {
            return Err("Usage: botctl machine placement [<user>] | assign <user> | unassign <user> | agent <user> | upgrade <user> [hold|release] | harnesses <user>".into());
        }
    })
}

/// `botctl signup ...`: people who asked for access on the get-started page (ADR 0022).
fn signup_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    let at = |id: &str, verb: &str| format!("/api/signups/{}/{verb}", encode(id));
    Ok(match args {
        [] | ["list"] => ("GET", "/api/signups?status=pending".into(), None),
        ["list", "all"] => ("GET", "/api/signups".into(), None),
        ["list", s @ ("pending" | "approved" | "rejected")] => ("GET", format!("/api/signups?status={s}"), None),
        ["approve", id, rest @ ..] => {
            let ttl = flag(rest, "--ttl").map(|t| t.parse::<u32>().map_err(|_| "--ttl must be minutes")).transpose()?;
            let body = json!({ "role": flag(rest, "--role").map(role).transpose()?, "ttlMinutes": ttl });
            ("POST", at(id, "approve"), Some(body.to_string()))
        }
        ["reject", id, rest @ ..] => ("POST", at(id, "reject"), Some(json!({ "reason": flag(rest, "--reason") }).to_string())),
        _ => return Err("Usage: botctl signup list [pending|approved|rejected|all] | approve <id> [--role R] [--ttl M] | reject <id> [--reason TEXT]".into()),
    })
}

/// `botctl scim ...`: SCIM provisioning tokens (ADR 0023).
fn scim_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    Ok(match args {
        [] | ["tokens"] | ["token", "list"] => ("GET", "/api/scim/tokens".into(), None),
        ["token", "create", tenant, rest @ ..] if !tenant.starts_with("--") => {
            let body = json!({ "tenant": tenant, "sso": flag(rest, "--sso"), "label": flag(rest, "--label") });
            ("POST", "/api/scim/tokens".into(), Some(body.to_string()))
        }
        ["token", "revoke", id] => ("DELETE", format!("/api/scim/tokens/{}", encode(id)), None),
        _ => return Err("Usage: botctl scim tokens | token create <tenant> [--sso <provider>] [--label TEXT] | token revoke <id>".into()),
    })
}

/// What `botctl scim token create` prints: the token once, and where the IdP sends it.
fn scim_created(res: &Value) -> String {
    let t = &res["scimToken"];
    let mut out = format!(
        "Created SCIM token {} for tenant {}.\n\n{}\n\nIt is shown only once; paste it into the IdP's provisioning settings as the secret (bearer) token.\nTenant URL: https://<your-host>/scim/v2",
        t["id"].as_str().unwrap_or_default(),
        t["tenant"].as_str().unwrap_or_default(),
        res["token"].as_str().unwrap_or_default(),
    );
    if let Some(p) = t["ssoProvider"].as_str() {
        out.push_str(&format!("\nexternalId must be each person's subject in the SSO provider {p} (Entra: map objectId to externalId)."));
    }
    if res["enabled"] == false {
        out.push_str("\n\nSCIM is off on this server: set SCIM=on and restart botd before the IdP connects.");
    }
    out
}

/// What `botctl signup approve` prints: the code once, and how to let SSO sign them in.
fn approved(res: &Value) -> String {
    let mins = (res["expiresAt"].as_i64().unwrap_or_default() - now_ms()) / 60_000;
    let (email, user) = (res["user"]["email"].as_str().unwrap_or_default(), res["user"]["id"].as_str().unwrap_or_default());
    let mut out = format!(
        "Approved. {email} is now a {} user ({user}).\n\n{}\n\nA one-time sign-in code, good for about {} hours. It is shown only once; share it privately.",
        res["user"]["role"].as_str().unwrap_or_default(),
        res["code"].as_str().unwrap_or_default(),
        ((mins + 30) / 60).max(1),
    );
    let sso: Vec<String> = res["sso"].as_array().into_iter().flatten().filter_map(|p| p["id"].as_str()).map(|id| format!("  botctl user link {email} {id} <subject>")).collect();
    if !sso.is_empty() {
        out.push_str(&format!("\n\nTo let them sign in with single sign-on instead, link their identity:\n{}", sso.join("\n")));
    }
    out
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

fn env_name(name: &str) -> Result<&str, String> {
    if name.is_empty() || !name.bytes().all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit()) {
        return Err(format!("\"{name}\" isn't a valid name. Use an environment variable name like OPENAI_API_KEY."));
    }
    Ok(name)
}

/// The value comes on stdin, so it stays out of shell history and the process list.
fn stdin_value(mut input: impl Read) -> Result<String, String> {
    let mut v = String::new();
    input.read_to_string(&mut v).map_err(|e| format!("Couldn't read the value from stdin: {e}"))?;
    let v = v.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&v).to_string();
    if v.is_empty() {
        return Err("No value on stdin. Example: botctl secret set OPENAI_API_KEY < key.txt".into());
    }
    Ok(v)
}

/// `botctl setup ...`: the method and body for `/api/setup` (ADR 0034).
fn setup_request(a: &[&str]) -> Result<(&'static str, Option<String>), String> {
    let patch = |v: Value| Ok(("PATCH", Some(v.to_string())));
    match a {
        [] | ["status"] => Ok(("GET", None)),
        ["done"] => patch(json!({ "completed": true })),
        ["reopen"] => patch(json!({ "completed": false })),
        ["hide"] => patch(json!({ "dismissed": true })),
        ["show"] => patch(json!({ "dismissed": false })),
        _ => Err("Usage: botctl setup [status | json | done | reopen | hide | show]".into()),
    }
}

/// The setup checklist, for a terminal.
fn setup_summary(s: &Value) -> String {
    let p = &s["progress"];
    let state = if p["completedAt"].is_i64() {
        "finished"
    } else if p["dismissed"] == true {
        "hidden from admins"
    } else {
        "admins see the wizard in the console's Setup tab"
    };
    let mut out = format!("Setup: {} of {} done ({state}).\n", s["done"], s["total"]);
    for c in s["checklist"].as_array().into_iter().flatten() {
        let mark = if c["done"] == true { "x" } else { " " };
        out += &format!("  [{mark}] {}\n      {}\n", c["label"].as_str().unwrap_or_default(), c["detail"].as_str().unwrap_or_default());
    }
    for p in s["signIn"]["providers"].as_array().into_iter().flatten().filter(|p| p["ready"] != true) {
        out += &format!("\n{} needs its secret: botctl secret set {} < file\n", p["label"].as_str().unwrap_or_default(), p["secret"].as_str().unwrap_or_default());
    }
    if !p["completedAt"].is_i64() {
        out += "\nThe console's Setup tab has the commands for each step. When you're done: botctl setup done\n";
    }
    out
}

/// `GET /api/license`, for a terminal (ADR 0038).
fn license_summary(l: &Value) -> String {
    let s = &l["seats"];
    let seats = match s["limit"].as_u64() {
        Some(n) => format!("{} of {n} seats in use", s["used"]),
        None => format!("{} active, no seat limit", s["used"]),
    };
    let mut out = format!("License: {} ({seats}).\n  {}\n", l["mode"].as_str().unwrap_or_default(), l["detail"].as_str().unwrap_or_default());
    if let Some(id) = l["license"]["id"].as_str() {
        out += &format!("  Id {id}, source {}.\n", l["source"].as_str().unwrap_or_default());
    }
    for w in l["warnings"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|w| Some(*w) != l["detail"].as_str()) {
        out += &format!("  Warning: {w}\n");
    }
    out
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
        ["hook", harness] => hook(harness, None),
        ["hook", harness, "--cwd", cwd] => hook(harness, Some(cwd)),
        ["hook", ..] => {
            // Exit 0 would allow the tool call, so a malformed gate blocks.
            eprintln!("SuperBot's approval gate is misconfigured, so this action was blocked. Usage: botctl hook <harness> [--cwd <dir>]");
            std::process::exit(2)
        }

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
        ["bot", rest @ ..] => {
            let (method, path, body) = bot_access(rest)?;
            op(method, &path, body)
        }
        ["machine", rest @ ..] => {
            let (method, path) = machine_request(rest)?;
            op(method, &path, None)
        }
        ["signups"] | ["signup", ..] => {
            let (method, path, body) = signup_request(a.get(1..).unwrap_or_default())?;
            let res = api(Cred::Operator, method, &path, body)?;
            match a.get(1) {
                Some(&"approve") => Ok(approved(&serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                Some(&"reject") => Ok("Rejected. No email was sent.".into()),
                _ => Ok(pretty(res)),
            }
        }
        ["scim", rest @ ..] => {
            let (method, path, body) = scim_request(rest)?;
            let res = api(Cred::Operator, method, &path, body)?;
            match rest {
                ["token", "create", ..] => Ok(scim_created(&serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                ["token", "revoke", ..] => Ok("Revoked. The IdP can't provision with it any more; its users stay as they are.".into()),
                _ => Ok(pretty(res)),
            }
        }
        ["approvals"] => op("GET", "/api/approvals?status=pending", None),
        ["approvals", status] => op("GET", &format!("/api/approvals?status={status}"), None),
        [verb @ ("approve" | "deny"), id, rest @ ..] => decide(verb, id, rest),
        ["audit", "export", rest @ ..] => api(Cred::Operator, "GET", &format!("/api/audit/export.csv{}", audit_query(rest)?), None),
        ["audit", rest @ ..] => op("GET", &format!("/api/audit{}", audit_query(rest)?), None),

        ["login", rest @ ..] if rest.len() <= 1 => {
            let res: Value = serde_json::from_str(&api(Cred::Anonymous, "POST", "/api/auth/login", Some(login_body(rest.first().copied())?.to_string()))?).map_err(|e| e.to_string())?;
            let (token, who) = (res["token"].as_str().unwrap_or_default(), res["user"]["name"].as_str().unwrap_or_default());
            Ok(format!("Signed in as {who} ({}). Run:\n\n  export SUPERBOT_TOKEN={token}", res["user"]["role"].as_str().unwrap_or_default()))
        }
        ["logout"] => op("POST", "/api/auth/logout", None).map(|_| "Signed out. Unset SUPERBOT_TOKEN.".into()),
        ["whoami"] => op("GET", "/api/auth/me", None),
        ["users"] | ["user", "list"] => op("GET", "/api/users", None),
        ["user", "add", email, rest @ ..] => {
            let name = rest.first().filter(|n| !n.starts_with("--"));
            let body = json!({ "email": email, "name": name, "role": flag(rest, "--role").map(role).transpose()? });
            op("POST", "/api/users", Some(body.to_string()))
        }
        ["user", "role", key, r] => op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "role": role(r)? }).to_string())),
        ["user", "tier", key, t] => {
            let tier = if *t == "default" { Value::Null } else { json!(t) };
            op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "tier": tier }).to_string()))
        }
        ["user", "isolation", key] => op("GET", &format!("/api/users/{}/isolation", encode(key)), None),
        ["user", "isolate", key] => op("POST", &format!("/api/users/{}/isolation", encode(key)), None),
        ["user", "harness-login", key, harness, rest @ ..] => harness_login(key, harness, rest),
        ["tiers"] => op("GET", "/api/tiers", None),
        ["license"] | ["license", "status"] => Ok(license_summary(&serde_json::from_str(&api(Cred::Operator, "GET", "/api/license", None)?).map_err(|e| e.to_string())?)),
        ["license", "json"] => op("GET", "/api/license", None),
        ["license", "install", rest @ ..] if rest.len() <= 1 => {
            let key = match rest.first() {
                None | Some(&"-") => stdin_value(std::io::stdin())?,
                Some(path) => std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
            };
            let res = api(Cred::Operator, "PUT", "/api/license", Some(json!({ "key": key.trim() }).to_string()))?;
            Ok(format!("Installed.\n{}", license_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["license", "remove"] => {
            let res = api(Cred::Operator, "DELETE", "/api/license", None)?;
            Ok(format!("Removed.\n{}", license_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["setup", "json"] => op("GET", "/api/setup", None),
        ["setup", rest @ ..] => {
            let (method, body) = setup_request(rest)?;
            let res = api(Cred::Operator, method, "/api/setup", body)?;
            Ok(setup_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?))
        }
        ["user", cmd @ ("disable" | "enable"), key] => {
            let status = if *cmd == "disable" { "disabled" } else { "active" };
            op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "status": status }).to_string()))
        }
        ["user", "code", key, rest @ ..] => {
            let ttl = flag(rest, "--ttl").map(|t| t.parse::<u32>().map_err(|_| "--ttl must be minutes")).transpose()?;
            let body = json!({ "ttlMinutes": ttl }).to_string();
            let res: Value = serde_json::from_str(&api(Cred::Operator, "POST", &format!("/api/users/{}/login-codes", encode(key)), Some(body))?).map_err(|e| e.to_string())?;
            let mins = (res["expiresAt"].as_i64().unwrap_or_default() - now_ms()) / 60_000;
            Ok(format!("{}\n\nA one-time sign-in code for {}, good for about {} minutes. Share it privately.", res["code"].as_str().unwrap_or_default(), res["user"]["email"].as_str().unwrap_or(key), mins.max(1)))
        }
        ["user", "identities", key] => op("GET", &format!("/api/users/{}/identities", encode(key)), None),
        ["user", "link", key, provider, subject, rest @ ..] => {
            let body = json!({ "provider": provider, "subject": subject, "tenant": flag(rest, "--tenant") });
            op("POST", &format!("/api/users/{}/identities", encode(key)), Some(body.to_string()))
        }
        ["user", "unlink", key, id] => op("DELETE", &format!("/api/users/{}/identities/{}", encode(key), encode(id)), None),
        ["sessions"] => op("GET", "/api/sessions", None),
        ["sessions", key] => op("GET", &format!("/api/sessions?user={}", encode(key)), None),
        ["session", "revoke", id] => op("DELETE", &format!("/api/sessions/{}", encode(id)), None).map(|_| "Revoked.".into()),
        ["session", "revoke-all", key] => op("DELETE", &format!("/api/users/{}/sessions", encode(key)), None),
        ["secrets"] => op("GET", "/api/secrets", None),
        ["secret", "set", name] => {
            let name = env_name(name)?;
            let body = json!({ "value": stdin_value(std::io::stdin())? }).to_string();
            let res: Value = serde_json::from_str(&op("PUT", &format!("/api/secrets/{name}"), Some(body))?).unwrap_or_default();
            Ok(if res["secret"]["forBots"] == false {
                format!("Saved {name}. It is botd's own (single sign-on); Bots never get it.")
            } else {
                format!("Saved {name}. Bots get it as ${name} from their next run.")
            })
        }
        ["secret", "rm" | "delete", name] => op("DELETE", &format!("/api/secrets/{}", env_name(name)?), None).map(|_| "Deleted.".into()),
        ["help", "admin"] | ["admin"] => Ok(ADMIN_HELP.into()),
        _ => Ok(HELP.into()),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) if out.ends_with('\n') => print!("{out}"),
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
    fn harness_login_takes_extra_arguments_only_after_a_double_dash() {
        assert_eq!(login_extra(&[]), Ok(None));
        assert_eq!(login_extra(&["--"]), Ok(Some(&[][..])));
        assert_eq!(login_extra(&["--", "setup-token"]), Ok(Some(&["setup-token"][..])));
        assert!(login_extra(&["setup-token"]).is_err());
    }

    #[test]
    fn machine_commands_name_the_users_placement() {
        assert_eq!(machine_request(&["placement"]).unwrap(), ("GET", "/api/machines/placements".into()));
        assert_eq!(machine_request(&["placement", "a@example.com"]).unwrap(), ("GET", "/api/users/a%40example.com/placement".into()));
        assert_eq!(machine_request(&["assign", "u1"]).unwrap(), ("PUT", "/api/users/u1/placement".into()));
        assert_eq!(machine_request(&["unassign", "u1"]).unwrap(), ("DELETE", "/api/users/u1/placement".into()));
        assert!(machine_request(&["assign"]).is_err());
        assert_eq!(machine_request(&["agent", "a@example.com"]).unwrap(), ("GET", "/api/users/a%40example.com/machine/agent".into()));
        assert_eq!(machine_request(&["upgrade", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/agent/upgrade".into()));
        assert_eq!(machine_request(&["upgrade", "u1", "hold"]).unwrap(), ("PUT", "/api/users/u1/machine/agent/hold".into()));
        assert_eq!(machine_request(&["upgrade", "u1", "release"]).unwrap(), ("DELETE", "/api/users/u1/machine/agent/hold".into()));
        assert_eq!(machine_request(&["harnesses", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/harnesses".into()));
        assert!(machine_request(&["upgrade", "u1", "now"]).is_err());
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"superbot:pw"), "c3VwZXJib3Q6cHc=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }

    #[test]
    fn the_operator_password_only_goes_to_this_machine() {
        for a in ["127.0.0.1:3000", "127.1.2.3:80", "localhost:3000", "LOCALHOST:3000", "[::1]:3000"] {
            assert!(loopback(a), "{a}");
        }
        for a in ["192.0.2.7:3000", "example.com:3000", "localhost.example.com:3000", "[2001:db8::1]:3000", "0.0.0.0:3000", "127.0.0.1.example.com:3000"] {
            assert!(!loopback(a), "{a}");
        }
        assert_eq!(addr("http://127.0.0.1:3000/"), Ok("127.0.0.1:3000"));
        for b in ["https://127.0.0.1:3000", "127.0.0.1:3000", "http://user@192.0.2.7:3000", "http://192.0.2.7:3000/x", "http://"] {
            assert!(addr(b).is_err(), "{b}");
        }
        // SAFETY: tests in this binary don't read these variables concurrently.
        unsafe {
            std::env::set_var("BOT_API", "http://192.0.2.7:3000");
            std::env::set_var("SUPERBOT_PASSWORD", std::process::id().to_string());
        }
        let err = api(Cred::Operator, "GET", "/api/approvals", None).unwrap_err();
        assert!(err.contains("only to a server on this machine"), "{err}");
    }

    #[test]
    fn audit_options_become_a_query() {
        assert_eq!(audit_query(&[]).unwrap(), "");
        assert_eq!(audit_query(&["50"]).unwrap(), "?limit=50");
        assert_eq!(
            audit_query(&["--from", "2026-11-19T13:00:00+01:00", "--action", "bot.*,auth.login", "--actor", "bot:ab12"]).unwrap(),
            "?from=2026-11-19T13:00:00%2B01:00&action=bot.*,auth.login&actor=bot:ab12"
        );
        assert_eq!(audit_query(&["--to", "a b&c"]).unwrap(), "?to=a%20b%26c");
        assert_eq!(
            audit_query(&["--actor", "user:ada@example.com", "--method", "sso,password", "--idp", "entra", "--idp-provider", "work"]).unwrap(),
            "?actor=user:ada%40example.com&method=sso,password&idp=entra&idpProvider=work"
        );
        assert_eq!(
            audit_query(&["--subject", "https://idp.example/t1|oid-1", "--session", "s0a1b", "--on-behalf-of", "u42"]).unwrap(),
            "?subject=https:%2F%2Fidp.example%2Ft1%7Coid-1&session=s0a1b&onBehalfOf=u42"
        );
        assert!(audit_query(&["--from"]).is_err());
        assert!(audit_query(&["--nope", "x"]).is_err());
    }

    #[test]
    fn login_and_user_commands() {
        assert_eq!(login_body(Some(" sbc_abc ")).unwrap(), json!({ "code": "sbc_abc", "session": "token", "label": "botctl" }));
        assert!(login_body(Some("  ")).is_err());
        assert_eq!(role("read-only"), Ok("read-only"));
        assert!(role("root").is_err());
        assert_eq!(encode("a.b+c@example.com"), "a.b%2Bc%40example.com");
    }

    #[test]
    fn bot_access_commands() {
        let req = |a: &[&str]| bot_access(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["access", "b1"]), Ok(("GET", "/api/bots/b1/access".into(), None)));
        assert_eq!(req(&["share", "b1"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "visibility": "shared" })))));
        assert_eq!(req(&["private", "b1"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "visibility": "private" })))));
        assert_eq!(req(&["owner", "b1", "a@example.com"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "owner": "a@example.com" })))));
        assert_eq!(req(&["grant", "b1", "a+b@example.com", "operator"]), Ok(("PUT", "/api/bots/b1/grants/a%2Bb%40example.com".into(), Some(json!({ "level": "operator" })))));
        assert_eq!(req(&["revoke", "b1", "u1"]), Ok(("DELETE", "/api/bots/b1/grants/u1".into(), None)));
        assert!(req(&["grant", "b1", "u1", "owner"]).is_err());
        assert!(req(&["share"]).is_err());
        assert!(req(&[]).is_err());
    }

    #[test]
    fn setup_commands() {
        let req = |a: &[&str]| setup_request(a).map(|(m, b)| (m, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&[]), Ok(("GET", None)));
        assert_eq!(req(&["status"]), Ok(("GET", None)));
        assert_eq!(req(&["done"]), Ok(("PATCH", Some(json!({ "completed": true })))));
        assert_eq!(req(&["reopen"]), Ok(("PATCH", Some(json!({ "completed": false })))));
        assert_eq!(req(&["hide"]), Ok(("PATCH", Some(json!({ "dismissed": true })))));
        assert_eq!(req(&["show"]), Ok(("PATCH", Some(json!({ "dismissed": false })))));
        assert!(req(&["finish", "now"]).is_err());

        let s = json!({
            "progress": { "step": "signin", "dismissed": false, "completedAt": null },
            "done": 1, "total": 2,
            "checklist": [
                { "id": "domain", "label": "A public address with HTTPS", "done": true, "detail": "People reach SuperBot at https://bots.example.com." },
                { "id": "signin", "label": "Sign-in providers ready", "done": false, "detail": "Waiting for a secret: Okta." },
            ],
            "signIn": { "providers": [{ "label": "Okta", "ready": false, "secret": "SSO_OKTA_CLIENT_SECRET" }] },
        });
        let out = setup_summary(&s);
        assert!(out.starts_with("Setup: 1 of 2 done (admins see the wizard"), "{out}");
        assert!(out.contains("[x] A public address with HTTPS") && out.contains("[ ] Sign-in providers ready"), "{out}");
        assert!(out.contains("botctl secret set SSO_OKTA_CLIENT_SECRET < file") && out.contains("botctl setup done"), "{out}");
        let done = setup_summary(&json!({ "progress": { "completedAt": 1 }, "done": 2, "total": 2, "checklist": [] }));
        assert!(done.starts_with("Setup: 2 of 2 done (finished).") && !done.contains("botctl setup done"), "{done}");
    }

    #[test]
    fn license_summary_reads_like_a_status_line() {
        let grace = json!({
            "mode": "grace", "source": "file", "detail": "The license for Acme Ltd ended on 2027-01-01.",
            "license": { "id": "lic-7" }, "seats": { "limit": 30, "used": 31 },
            "warnings": ["The license for Acme Ltd ended on 2027-01-01.", "31 people are active, over the 30 seats allowed."],
        });
        let out = license_summary(&grace);
        assert!(out.starts_with("License: grace (31 of 30 seats in use).\n  The license for Acme Ltd ended"), "{out}");
        assert!(out.contains("Id lic-7, source file.") && out.contains("Warning: 31 people") && out.matches("ended on").count() == 1, "{out}");
        let open = license_summary(&json!({ "mode": "active", "detail": "Licensed.", "seats": { "limit": null, "used": 4 }, "warnings": [] }));
        assert!(open.starts_with("License: active (4 active, no seat limit)."), "{open}");
    }

    #[test]
    fn signup_commands() {
        let req = |a: &[&str]| signup_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&[]), Ok(("GET", "/api/signups?status=pending".into(), None)));
        assert_eq!(req(&["list", "all"]), Ok(("GET", "/api/signups".into(), None)));
        assert_eq!(req(&["list", "rejected"]), Ok(("GET", "/api/signups?status=rejected".into(), None)));
        assert_eq!(req(&["approve", "su1"]), Ok(("POST", "/api/signups/su1/approve".into(), Some(json!({ "role": null, "ttlMinutes": null })))));
        assert_eq!(
            req(&["approve", "su1", "--role", "readonly", "--ttl", "90"]),
            Ok(("POST", "/api/signups/su1/approve".into(), Some(json!({ "role": "readonly", "ttlMinutes": 90 }))))
        );
        assert_eq!(req(&["reject", "su1", "--reason", "spam"]), Ok(("POST", "/api/signups/su1/reject".into(), Some(json!({ "reason": "spam" })))));
        assert!(req(&["approve", "su1", "--role", "root"]).is_err());
        assert!(req(&["approve", "su1", "--ttl", "soon"]).is_err());
        assert!(req(&["list", "maybe"]).is_err());

        let res = json!({
            "user": { "id": "u1", "email": "ada@example.com", "role": "member" },
            "code": "sbc_x", "expiresAt": now_ms() + 3 * 24 * 3_600_000,
            "sso": [{ "id": "work", "label": "Work", "type": "entra" }],
        });
        let out = approved(&res);
        assert!(out.contains("sbc_x") && out.contains("about 72 hours") && out.contains("botctl user link ada@example.com work <subject>"), "{out}");
        assert!(!approved(&json!({ "sso": [] })).contains("user link"));
    }

    #[test]
    fn scim_commands() {
        let req = |a: &[&str]| scim_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["tokens"]), Ok(("GET", "/api/scim/tokens".into(), None)));
        assert_eq!(req(&["token", "create", "okta"]), Ok(("POST", "/api/scim/tokens".into(), Some(json!({ "tenant": "okta", "sso": null, "label": null })))));
        assert_eq!(
            req(&["token", "create", "entra", "--sso", "work", "--label", "Entra prod"]),
            Ok(("POST", "/api/scim/tokens".into(), Some(json!({ "tenant": "entra", "sso": "work", "label": "Entra prod" }))))
        );
        assert_eq!(req(&["token", "revoke", "st1"]), Ok(("DELETE", "/api/scim/tokens/st1".into(), None)));
        assert!(req(&["token", "create"]).is_err());
        assert!(req(&["token", "create", "--sso", "work"]).is_err());
        assert!(req(&["token", "revoke"]).is_err());

        let res = json!({ "token": "sbp_x", "enabled": false, "scimToken": { "id": "st1", "tenant": "entra", "ssoProvider": "work" } });
        let out = scim_created(&res);
        assert!(out.contains("sbp_x") && out.contains("shown only once") && out.contains("/scim/v2") && out.contains("objectId") && out.contains("SCIM=on"), "{out}");
        let on = scim_created(&json!({ "token": "sbp_y", "enabled": true, "scimToken": { "id": "st2", "tenant": "okta" } }));
        assert!(!on.contains("SCIM=on") && !on.contains("objectId"), "{on}");
    }

    #[test]
    fn hook_cwd_overrides_where_the_harness_says_it_runs() {
        let event = r#"{"tool_name":"terminal","tool_input":{"command":"ls"},"cwd":"/opt/hermes"}"#;
        let body: Value = serde_json::from_str(&hook_body("hermes", "b1", event, Some("/workspace")).unwrap()).unwrap();
        assert_eq!(body["event"]["cwd"], "/workspace");
        assert_eq!(body["event"]["tool_name"], "terminal");
        assert_eq!(body["from"], "b1");
        let body: Value = serde_json::from_str(&hook_body("claude", "b1", event, None).unwrap()).unwrap();
        assert_eq!(body["event"]["cwd"], "/opt/hermes");
        assert!(hook_body("hermes", "b1", event, Some("workspace")).is_err());
        assert!(hook_body("hermes", "b1", "[1]", Some("/workspace")).is_err());
        assert!(hook_body("hermes", "b1", "not json", None).is_err());
    }

    #[test]
    fn policy_set_builds_a_patch() {
        let p = policy_patch(&["mode=ask", "timeout=15", "git_push=deny"]).unwrap();
        assert_eq!(p, json!({ "mode": "ask", "timeoutMinutes": 15, "classes": { "git_push": "deny" } }));
        assert!(policy_patch(&[]).is_err());
        assert!(policy_patch(&["timeout=soon"]).is_err());
    }

    #[test]
    fn values_come_from_stdin_without_the_newline() {
        assert_eq!(stdin_value("sk-1\n".as_bytes()).unwrap(), "sk-1");
        assert_eq!(stdin_value("sk-1\r\n".as_bytes()).unwrap(), "sk-1");
        assert_eq!(stdin_value("a b\n\n".as_bytes()).unwrap(), "a b\n");
        assert!(stdin_value("\n".as_bytes()).is_err());
        assert!(env_name("OPENAI_API_KEY").is_ok());
        for bad in ["", "lower", "A/B", "../X", "A B"] {
            assert!(env_name(bad).is_err(), "{bad}");
        }
    }
}
