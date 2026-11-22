//! The onboarding wizard (ADR 0034): what a fresh install still needs, for its admins.
//! It reports the public address and HTTPS, the sign-in providers and whether each is
//! complete, the tiers, the license (ADR 0038), the admins besides the break-glass owner, and the approval mode,
//! and keeps the wizard's progress. botd writes only what it can change while running:
//! the progress here, and SSO secrets and the approval mode through their own audited
//! routes. Settings read at startup come back as copy-ready `.env` lines and commands.

use crate::audit::Who;
use crate::rbac::Role;
use crate::sso::Provider;
use crate::tiers::Tier;
use crate::users::{self, Caller};
use crate::{bad, need_user, ApiError, AppState, Auth, Res};
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub const STEPS: [&str; 4] = ["domain", "signin", "tiers", "finish"];

/// Where the wizard is. Kept in `settings` under `setup`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Progress {
    pub step: String,
    pub dismissed: bool,
    pub completed_at: Option<i64>,
    pub completed_by: Option<String>,
}

impl Default for Progress {
    fn default() -> Self {
        Progress { step: STEPS[0].into(), dismissed: false, completed_at: None, completed_by: None }
    }
}

impl Progress {
    /// Admins see the wizard until someone finishes or hides it.
    pub fn show(&self) -> bool {
        self.completed_at.is_none() && !self.dismissed
    }
}

/// The host part of a Host header or ALLOWED_HOSTS entry, without its port or brackets.
fn host_name(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    match h.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => h,
    }
}

fn local(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost") || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

/// The ALLOWED_HOSTS names people reach botd at from elsewhere: not loopback, not a bind-all address.
pub fn public_hosts(hosts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        let name = host_name(h);
        if !name.is_empty() && !local(name) && !out.contains(h) {
            out.push(h.clone());
        }
    }
    out
}

/// How this request reached botd: "https" or "http" through a proxy botd trusts (Caddy sets
/// X-Forwarded-Proto), or "direct" with no proxy in front. Trusted as `request_source` trusts
/// X-Forwarded-For: from a proxy on loopback, or from anyone with TRUST_FORWARDED_FOR=1.
pub fn scheme(headers: &HeaderMap, peer: Option<IpAddr>, trust_forwarded: bool) -> &'static str {
    let trusted = trust_forwarded || peer.is_some_and(|p| p.to_canonical().is_loopback());
    let proto = headers
        .get_all("x-forwarded-proto")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|v| !v.is_empty());
    match proto {
        Some(p) if trusted && p.eq_ignore_ascii_case("https") => "https",
        Some(_) if trusted => "http",
        _ => "direct",
    }
}

fn step(title: &str, text: impl Into<String>, commands: &[String]) -> Value {
    json!({ "title": title, "text": text.into(), "commands": commands })
}

/// The one-command installer, which needs no checkout. Re-running it resets TZ and
/// USER_NAME to the flags given (else UTC and Owner), so it passes botd's own.
fn installer_command(domain: &str) -> String {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let tz = env("TZ").unwrap_or_else(|| "UTC".into());
    let name = env("USER_NAME").unwrap_or_else(|| "Owner".into());
    format!(
        "curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh | sudo bash -s -- --upgrade --domain {} --tz {} --user-name {}",
        sh_quote(domain),
        sh_quote(&tz),
        sh_quote(&name)
    )
}

fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-/:+@".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Restarting botd, for settings it reads only at startup.
fn restart() -> Vec<Value> {
    vec![
        step("Bash installer", "Edit ~superbot/superbot/.env, then restart botd.", &["sudo systemctl restart superbot".into()]),
        step("Docker Compose", "Edit .env next to docker-compose.yml, then recreate botd.", &["docker compose up -d".into()]),
    ]
}

/// `scheme` is how this request came (see [`scheme`]); `on_this_machine`, whether it came
/// from loopback, where botctl and SSH tunnels reach botd without the proxy.
fn domain_view(a: &Auth, host: &str, scheme: &str, on_this_machine: bool) -> Value {
    let hosts = public_hosts(&a.hosts);
    let public_url = a.sso.public_url().map(String::from).or_else(|| hosts.first().map(|h| format!("https://{}", h.to_ascii_lowercase())));
    let here = Some(host.to_ascii_lowercase()).filter(|h| !local(host_name(h)) && hosts.contains(h));
    let name = here.or_else(|| hosts.first().cloned()).or_else(|| public_url.as_deref().and_then(|u| u.strip_prefix("https://")).map(String::from));
    let shown = name.clone().unwrap_or_else(|| "<your-domain>".into());
    let unchecked = scheme == "direct" && on_this_machine;
    let ok = public_url.is_some() && (scheme == "https" || unchecked);
    let detail = match (&public_url, scheme) {
        (None, _) => "No public address yet: botd answers only on this machine, and nobody else can sign in.".to_string(),
        (Some(u), "https") => format!("People reach SuperBot at {u}, over HTTPS."),
        (Some(u), "http") => format!("This request came over plain HTTP. Open {u}/console/ over HTTPS, and check that Caddy has its certificate."),
        (Some(u), _) if unchecked => format!("Set up for {u}. HTTPS can't be checked from this machine: open {u}/console/ in a browser to see."),
        (Some(u), _) => format!("Set up for {u}, but this request reached botd over plain HTTP, not through the HTTPS proxy. Open {u}/console/."),
    };
    let instructions = vec![
        step("DNS", format!("Point an A (and AAAA) record for {shown} at this server, and open ports 80 and 443."), &[]),
        step(
            "Bash installer",
            "Re-run the installer with the domain. It pulls the latest main and rebuilds, sets ALLOWED_HOSTS and CORS_ORIGINS in .env, writes Caddy's config, and restarts botd. Caddy gets the certificate. It also resets TZ and USER_NAME, so this passes botd's current ones.",
            &[installer_command(&shown)],
        ),
        step(
            "Docker Compose",
            "Set the domain, then recreate the stack. Caddy gets the certificate.",
            &[format!("./init.sh --domain {shown}"), "docker compose up -d".into()],
        ),
    ];
    json!({
        "publicUrl": public_url,
        "hosts": hosts,
        "domain": name,
        "requestHost": host,
        "scheme": scheme,
        "httpsChecked": scheme != "direct" || !on_this_machine,
        "ok": ok,
        "detail": detail,
        "instructions": instructions,
    })
}

/// Settings each provider type needs, after `SSO_<ID>_`. `<...>` are placeholders.
const TEMPLATES: [(&str, &str, &str, &[&str]); 6] = [
    ("entra", "Microsoft Entra ID", "docs/sso/entra.md", &["CLIENT_ID=<application-client-id>", "TENANT=<directory-tenant-id>", "# JIT_ROLE=off"]),
    ("google", "Google", "docs/sso/google.md", &["CLIENT_ID=<client-id>.apps.googleusercontent.com", "# HOSTED_DOMAINS=example.com", "# JIT_ROLE=off"]),
    ("github", "GitHub", "docs/sso/github.md", &["CLIENT_ID=<client-id>", "# ALLOWED_ORGS=<org>", "# JIT_ROLE=off"]),
    ("apple", "Apple", "docs/sso/apple.md", &["CLIENT_ID=<services-id>", "TEAM_ID=<team-id>", "KEY_ID=<key-id>", "# ALLOWED_DOMAINS=example.com"]),
    (
        "oidc",
        "Any OpenID Connect IdP (Okta, Keycloak, Auth0)",
        "docs/sso/oidc.md",
        &["TYPE=oidc", "ISSUER=https://<idp-host>/<issuer-path>", "CLIENT_ID=<client-id>", "LABEL=Company SSO", "# ALLOWED_DOMAINS=example.com"],
    ),
    (
        "saml",
        "A SAML IdP (Okta, Entra ID, ADFS, OneLogin)",
        "docs/sso/saml-native.md",
        &["TYPE=saml", "IDP_ENTITY_ID=<idp-entity-id>", "IDP_METADATA_URL=https://<idp-host>/<metadata-path>", "LABEL=Company SSO", "# ALLOWED_DOMAINS=example.com"],
    ),
];

/// Copy-ready `.env` lines that add each kind of provider next to the ones already set.
fn templates(providers: &[Arc<Provider>], public_url: Option<&str>, sso_public_url: Option<&str>) -> Vec<Value> {
    let ids: Vec<&str> = providers.iter().map(|p| p.id.as_str()).collect();
    TEMPLATES
        .iter()
        .map(|(id, label, docs, settings)| {
            let mut list = ids.clone();
            if !list.contains(id) {
                list.push(id);
            }
            let up = id.to_ascii_uppercase();
            let mut env = vec![format!("SSO_PROVIDERS={}", list.join(","))];
            if sso_public_url.is_none() {
                env.push(format!("SSO_PUBLIC_URL={}", public_url.unwrap_or("https://<your-domain>")));
            }
            for s in *settings {
                env.push(match s.strip_prefix("# ") {
                    Some(rest) => format!("# SSO_{up}_{rest}"),
                    None => format!("SSO_{up}_{s}"),
                });
            }
            // Native SAML has no secret; the IdP posts to its ACS rather than redirecting to a callback.
            let secret = match *id {
                "apple" => Some(format!("SSO_{up}_PRIVATE_KEY")),
                "saml" => None,
                _ => Some(format!("SSO_{up}_CLIENT_SECRET")),
            };
            let base = sso_public_url.or(public_url).unwrap_or("https://<your-domain>");
            let step = if *id == "saml" { "acs" } else { "callback" };
            json!({
                "id": id,
                "label": label,
                "docs": docs,
                "configured": ids.contains(id),
                "env": env.join("\n"),
                "secret": secret,
                "callbackUrl": format!("{base}/api/auth/sso/{id}/{step}"),
            })
        })
        .collect()
}

fn sign_in_view(app: &AppState, a: &Auth, public_url: Option<&str>) -> Value {
    let providers: Vec<Value> = a
        .sso
        .providers
        .iter()
        .map(|p| {
            // A value from the environment (or _FILE) wins over a saved one, so the wizard can't replace it.
            let source = crate::secrets::global().source(&p.env_var()).ok().flatten();
            json!({
                "id": p.id,
                "label": p.label,
                "type": p.type_name(),
                "ready": p.ready(),
                "problem": p.not_ready(),
                "secret": p.needs_secret().then(|| p.env_var()),
                "secretStore": source.map(|(store, _)| store),
                "secretSavable": source.is_none_or(|(_, writable)| writable),
                "callbackUrl": a.sso.callback_url(&p.id),
                "audience": p.audience(),
                "jitRole": p.jit_role.map(Role::as_str),
            })
        })
        .collect();
    let waiting = |secret: bool| a.sso.providers.iter().filter(|p| !p.ready() && p.needs_secret() == secret).map(|p| p.label.clone()).collect::<Vec<_>>().join(", ");
    let (for_secret, for_metadata) = (waiting(true), waiting(false));
    let admins: Vec<Value> = app
        .db
        .users()
        .into_iter()
        .filter(|u| u.role == Role::Admin && u.active() && u.id != users::OPERATOR)
        .map(|u| json!({ "id": u.id, "name": u.name, "email": u.email, "lastLoginAt": u.last_login_at }))
        .collect();
    let detail = match (a.sso.providers.len(), for_secret.is_empty(), for_metadata.is_empty()) {
        (0, ..) => "No SSO providers: people sign in with one-time codes from Users. Add a provider any time.".to_string(),
        (n, true, true) => format!("{n} SSO provider{} ready.", if n == 1 { "" } else { "s" }),
        (_, false, true) => format!("Waiting for a secret: {for_secret}. Saving it takes effect at once, no restart."),
        (_, true, false) => format!("Waiting for IdP metadata: {for_metadata}. Importing it takes effect at once, no restart."),
        (_, false, false) => format!("Waiting for a secret: {for_secret}; and for IdP metadata: {for_metadata}. Either takes effect at once, no restart."),
    };
    json!({
        "breakGlass": a.break_glass,
        "publicUrl": a.sso.public_url(),
        "providers": providers,
        "admins": admins,
        "scim": a.scim.enabled,
        "signups": a.signups.enabled,
        "ok": for_secret.is_empty() && for_metadata.is_empty(),
        "detail": detail,
        "templates": templates(&a.sso.providers, public_url, a.sso.public_url()),
        "restart": restart(),
    })
}

fn tiers_view(app: &AppState) -> Value {
    let t = app.tiers();
    let file = t.source != "built-in";
    let detail = if file {
        format!("{} tiers from {}; people without one get {}.", t.all().len(), t.source, t.default_tier().label)
    } else {
        "One built-in tier, self-host: any harness and model, no limits. Right for running SuperBot for yourself or your team.".to_string()
    };
    let instructions = vec![
        step("Write the file", "Copy deploy/tiers.example.json next to .env and edit its routes and limits. botd refuses to start on a mistake.", &[]),
        step("Bash installer", "Point botd at it in .env, then restart.", &["TIERS_FILE=<path-to>/tiers.json".into(), "DEFAULT_TIER=starter".into(), "sudo systemctl restart superbot".into()]),
        step(
            "Docker Compose",
            "Copy it into the data volume, point botd at it in .env, then recreate botd.",
            &["docker compose cp tiers.json botd:/data/tiers.json".into(), "TIERS_FILE=/data/tiers.json".into(), "docker compose up -d".into()],
        ),
        step("Give people a tier", "Anyone without one gets the default.", &["botctl user tier <email> <tier>".into()]),
    ];
    json!({
        "source": t.source,
        "fileLoaded": file,
        "default": t.default_tier().name,
        "tiers": t.all().iter().map(|x| {
            let mut v = x.view();
            v["newBots"] = json!(x.new_bot_harness(&app.cfg.default_harness));
            v
        }).collect::<Vec<_>>(),
        "managed": t.all().iter().any(Tier::managed),
        "ok": true,
        "detail": detail,
        "instructions": instructions,
    })
}

/// The license (ADR 0038), and how to install one. On the wizard's Plans step.
fn license_view(app: &AppState, a: &Auth) -> Value {
    let mut v = crate::license::view(app, a);
    v["instructions"] = json!([
        step("Console", "Paste the key CG-Labs sent you below, or in Settings. It takes effect at once, no restart.", &[]),
        step("botctl", "On the server, as the superbot user.", &["botctl license install < license.key".into(), "botctl license".into()]),
        step("Bash installer", "Or install it with the installer, which saves it in DATA_DIR.", &["sudo deploy/install.sh --upgrade --license-file <path-to>/license.key".into()]),
        step("Docker Compose", "Or set it in .env (it then wins over the console), and recreate botd.", &["LICENSE_KEY=<license-key>".into(), "docker compose up -d".into()]),
    ]);
    v
}

fn item(id: &str, label: &str, done: bool, detail: impl Into<String>) -> Value {
    json!({ "id": id, "label": label, "done": done, "detail": detail.into() })
}

/// Everything the wizard shows, for the request it answers. The support bundle
/// (ADR 0131) carries its checklist.
pub(crate) fn report(app: &AppState, a: &Auth, headers: &HeaderMap, peer: Option<IpAddr>) -> Value {
    let progress = app.db.setup_progress();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let on_this_machine = peer.is_some_and(|p| p.to_canonical().is_loopback());
    let domain = domain_view(a, host, scheme(headers, peer, a.trust_forwarded), on_this_machine);
    let sign_in = sign_in_view(app, a, domain["publicUrl"].as_str());
    let tiers = tiers_view(app);
    let license = license_view(app, a);
    let mode = app.db.global_policy().mode;
    let ask = mode == crate::policy::Mode::Ask;
    let others = sign_in["admins"].as_array().map_or(0, Vec::len);
    let admin_detail = match (others, a.break_glass) {
        (0, _) => "Only the owner account, which signs in with the break-glass password, is an admin. Add a second admin in Users and sign in as them.".to_string(),
        (n, true) => format!("{n} other admin{}. Once admins sign in with SSO or codes, you can set AUTH_BREAK_GLASS=0 and restart.", if n == 1 { "" } else { "s" }),
        (n, false) => format!("{n} other admin{}; break-glass sign-in is off.", if n == 1 { "" } else { "s" }),
    };
    let (backed_up, backups_detail) = crate::server_backups::checklist(app);
    let (encrypted, encryption_detail) = crate::backup_encryption::checklist(app);
    let (db_encrypted, db_detail) = crate::database_encryption::checklist(app);
    let checklist = vec![
        item("domain", "A public address with HTTPS", domain["ok"] == true, domain["detail"].as_str().unwrap_or_default()),
        item("signin", "Sign-in providers ready", sign_in["ok"] == true, sign_in["detail"].as_str().unwrap_or_default()),
        item("admin", "An admin besides the break-glass owner", others > 0, admin_detail),
        item("tiers", "Plans chosen", true, tiers["detail"].as_str().unwrap_or_default()),
        // A license, or testing mode the operator turned on; never no license at all (ADR 0068).
        item("license", "License in order", license["ok"] == true && license["warnings"].as_array().is_none_or(Vec::is_empty), license["detail"].as_str().unwrap_or_default()),
        item(
            "approvals",
            "Bots ask before risky actions",
            ask,
            if ask { "On: Bots ask a person before risky actions." } else { "Off (bypass): Bots run risky actions without asking. Turn approvals on unless this is a dev machine." },
        ),
        item("backups", "Server backups copied off this host", backed_up, backups_detail),
        item("backup_encryption", "Backups encrypted", encrypted, encryption_detail),
        item("database_encryption", "Database encrypted", db_encrypted, db_detail),
    ];
    let done = checklist.iter().filter(|c| c["done"] == true).count();
    let mut p = json!(progress);
    p["show"] = json!(progress.show());
    json!({
        "progress": p,
        "steps": STEPS,
        "domain": domain,
        "signIn": sign_in,
        "tiers": tiers,
        "license": license,
        "approvals": { "mode": mode, "ok": ask },
        "secretsBackend": crate::secrets::external::diagnostics(),
        "checklist": checklist,
        "done": done,
        "total": checklist.len(),
    })
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn peer_ip(peer: Peer) -> Option<IpAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr.ip())
}

/// `GET /api/setup` (admins): what's set up, what isn't, and how to finish.
pub async fn status(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, headers: HeaderMap, peer: Peer) -> Json<Value> {
    Json(report(&app, &a, &headers, peer_ip(peer)))
}

/// `PATCH /api/setup` (admins): `{step?, dismissed?, completed?}`. Moving between steps
/// isn't audited; finishing, reopening, hiding, and showing the wizard again are.
pub async fn update(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(c): Extension<Caller>,
    Extension(by): Extension<Who>,
    headers: HeaderMap,
    peer: Peer,
    Json(v): Json<Value>,
) -> Res {
    need_user(c.principal)?;
    let obj = v.as_object().ok_or_else(|| bad("Send a JSON object: {step?, dismissed?, completed?}."))?;
    if let Some(k) = obj.keys().find(|k| !["step", "dismissed", "completed"].contains(&k.as_str())) {
        return Err(bad(format!("Unknown field \"{k}\". Send step, dismissed, or completed.")));
    }
    let step = match obj.get("step") {
        None => None,
        Some(s) => Some(s.as_str().filter(|s| STEPS.contains(s)).ok_or_else(|| bad(format!("step must be one of {}.", STEPS.join(", "))))?),
    };
    let dismissed = obj.get("dismissed").map(|d| d.as_bool().ok_or_else(|| bad("dismissed must be true or false."))).transpose()?;
    let completed = obj.get("completed").map(|d| d.as_bool().ok_or_else(|| bad("completed must be true or false."))).transpose()?;
    let (before, p) = app.db.update_setup_progress(|p| {
        if let Some(s) = step {
            p.step = s.into();
        }
        if let Some(d) = dismissed {
            p.dismissed = d;
        }
        match completed {
            Some(true) if p.completed_at.is_none() => {
                p.completed_at = Some(crate::db::now());
                p.completed_by = c.user.as_ref().map(|u| u.id.clone());
                p.step = "finish".into();
            }
            Some(false) => {
                p.completed_at = None;
                p.completed_by = None;
                p.dismissed = false;
            }
            _ => {}
        }
        Ok::<_, ApiError>(())
    })?;
    let out = report(&app, &a, &headers, peer_ip(peer));
    let event = |action: &str| by.event(action).target("setup", "server");
    if before.completed_at.is_none() && p.completed_at.is_some() {
        let open: Vec<&Value> = out["checklist"].as_array().into_iter().flatten().filter(|i| i["done"] != true).map(|i| &i["id"]).collect();
        app.db.record(&event("setup.completed").details(json!({ "done": out["done"], "total": out["total"], "open": open })));
    }
    if before.completed_at.is_some() && p.completed_at.is_none() {
        app.db.record(&event("setup.reopened"));
    }
    if !before.dismissed && p.dismissed {
        app.db.record(&event("setup.dismissed").details(json!({ "step": p.step })));
    }
    if before.dismissed && !p.dismissed && p.completed_at.is_none() && before.completed_at.is_none() {
        app.db.record(&event("setup.resumed").details(json!({ "step": p.step })));
    }
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn public_hosts_leave_out_this_machine() {
        let hosts = crate::allowed_hosts("0.0.0.0", 3000, "Bots.Example.com, localhost:8080,10.0.0.5:3000,[::1]:8443,app.localhost");
        assert_eq!(public_hosts(&hosts), ["bots.example.com", "10.0.0.5:3000"]);
        assert!(public_hosts(&crate::allowed_hosts("127.0.0.1", 80, "")).is_empty());
        assert_eq!(host_name("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_name("bots.example.com:8443"), "bots.example.com");
    }

    #[test]
    fn the_scheme_comes_only_from_a_trusted_proxy() {
        let mut h = HeaderMap::new();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let far: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(scheme(&h, Some(lo), false), "direct");
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(scheme(&h, Some(lo), false), "https");
        assert_eq!(scheme(&h, Some(far), false), "direct", "anyone can send the header straight to botd");
        assert_eq!(scheme(&h, Some(far), true), "https");
        h.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert_eq!(scheme(&h, Some(lo), false), "http");
        assert_eq!(scheme(&h, Some("::ffff:127.0.0.1".parse().unwrap()), false), "http");
    }

    #[test]
    fn progress_defaults_and_shows_until_done_or_hidden() {
        let p = Progress::default();
        assert_eq!((p.step.as_str(), p.show()), ("domain", true));
        assert!(!Progress { dismissed: true, ..p.clone() }.show());
        assert!(!Progress { completed_at: Some(1), ..p.clone() }.show());
        let old: Progress = serde_json::from_str(r#"{"step":"tiers"}"#).unwrap();
        assert_eq!((old.step.as_str(), old.dismissed), ("tiers", false));
    }

    #[test]
    fn installer_flags_are_shell_quoted() {
        assert_eq!(sh_quote("bots.example.com"), "bots.example.com");
        assert_eq!(sh_quote("Europe/Jersey"), "Europe/Jersey");
        assert_eq!(sh_quote("<your-domain>"), "'<your-domain>'");
        assert_eq!(sh_quote("Alex O'Neil"), r"'Alex O'\''Neil'");
        assert_eq!(sh_quote("$(id)"), "'$(id)'");
        assert_eq!(sh_quote(""), "''");
    }

    /// The `.env` lines the wizard hands out start botd once the placeholders are filled in.
    #[test]
    fn provider_templates_are_valid_settings() {
        let fill = [
            ("<application-client-id>", "11111111-2222-3333-4444-555555555555"),
            ("<directory-tenant-id>", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            ("<client-id>", "abc123"),
            ("<org>", "acme"),
            ("<services-id>", "com.example.superbot"),
            ("<team-id>", "ABCDE12345"),
            ("<key-id>", "KEY1234567"),
            ("<idp-host>", "idp.example.com"),
            ("<issuer-path>", "oauth2/default"),
            ("<broker-host>", "sso.example.com"),
            ("<realm>", "superbot"),
            ("<broker-client-id>", "superbot"),
            ("<idp-alias>", "adfs"),
            ("<idp-entity-id>", "http://adfs.example.com/adfs/services/trust"),
            ("<metadata-path>", "app/exk1abc/sso/saml/metadata"),
            ("<your-domain>", "bots.example.com"),
        ];
        let all = templates(&[], None, None);
        assert_eq!(all.len(), 6);
        for t in &all {
            let mut env = t["env"].as_str().unwrap().to_string();
            for (k, v) in fill {
                env = env.replace(k, v);
            }
            assert!(!env.contains('<'), "unfilled placeholder: {env}");
            let vars: std::collections::HashMap<String, String> =
                env.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let sso = crate::sso::Sso::from_vars(&|k| vars.get(k).cloned()).unwrap_or_else(|e| panic!("{}: {e}\n{env}", t["id"]));
            let p = &sso.providers[0];
            assert_eq!((p.id.as_str(), p.needs_secret().then(|| p.env_var())), (t["id"].as_str().unwrap(), t["secret"].as_str().map(String::from)));
            assert_eq!(sso.callback_url(&p.id), t["callbackUrl"].as_str().unwrap().replace("<your-domain>", "bots.example.com"));
        }
    }

    #[test]
    fn templates_add_to_the_providers_already_set() {
        let vars = |k: &str| match k {
            "SSO_PROVIDERS" => Some("google".to_string()),
            "SSO_PUBLIC_URL" => Some("https://bots.example.com".to_string()),
            "SSO_GOOGLE_CLIENT_ID" => Some("x.apps.googleusercontent.com".to_string()),
            _ => None,
        };
        let sso = crate::sso::Sso::from_vars(&vars).unwrap();
        let t = templates(&sso.providers, Some("https://bots.example.com"), sso.public_url());
        let entra = t.iter().find(|t| t["id"] == "entra").unwrap();
        assert!(entra["env"].as_str().unwrap().starts_with("SSO_PROVIDERS=google,entra\nSSO_ENTRA_CLIENT_ID="), "{entra}");
        assert_eq!(entra["callbackUrl"], "https://bots.example.com/api/auth/sso/entra/callback");
        let google = t.iter().find(|t| t["id"] == "google").unwrap();
        assert_eq!(google["configured"], true);
        assert!(google["env"].as_str().unwrap().starts_with("SSO_PROVIDERS=google\n"));
    }
}
