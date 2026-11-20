//! Enrollment and mutual TLS between the control plane and each user's machine
//! (ADR 0031). Off unless MACHINE_CONTROL_URL is set, and that needs the control
//! plane (LINODE_TOKEN).
//!
//! A machine boots with a one-time token in its cloud-init user data. Its agent
//! (`superbot-machine`) makes a key, sends the token and a signing request to botd's
//! machine port, and gets a certificate from the control-plane CA naming its user and
//! machine. From then on every call is mutual TLS: the machine trusts only the CA and
//! checks it is talking to the control plane; botd accepts only certificates it issued
//! and recorded, and when it calls a machine, only that machine's own.

use super::pki::{self, Ca, Issued, Peer};
use super::route::{Assigned, Dispatched, Job, MachineLink};
use super::wire;
use super::{ControlPlane, State};
use crate::audit::{Actor, Outcome, Source, Who};
use crate::db::{Machine, MachineCert, now};
use crate::runner::App;
use crate::secrets::sealed::Cipher;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, Res};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State as AxState};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// How long an enrollment token lasts. Building and booting a Linode takes minutes.
pub const TOKEN_MINUTES: i64 = 60;
/// A machine's certificate lifetime. Its agent asks for a new one with a third left.
pub const CERT_DAYS: i64 = 30;
/// botd's own certificate, renewed by itself with a third left.
const CONTROL_CERT_DAYS: i64 = 30;
pub const DEFAULT_AGENT_PORT: u16 = 7443;
/// The agent's binary, next to botd's, served to machines at `/v1/agent`.
pub const AGENT_BIN: &str = "superbot-machine";
const TOKEN_PREFIX: &str = "sbe_";
/// The derived-key purpose of the CA's key. Changing it makes a new CA.
const CA_PURPOSE: &str = "machine-ca/v1";
pub const OFF: &str =
    "Machine enrollment is off on this server. Set MACHINE_CONTROL_URL to turn it on.";

/// botd's current certificate, its key, and the TLS settings made from them.
struct ControlCert {
    issued: Issued,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    server: Arc<ServerConfig>,
}

pub struct Enrollment {
    /// What machines call: `https://<host>:<port>`, no trailing slash.
    pub url: String,
    host: String,
    /// Where botd listens for them.
    pub listen: SocketAddr,
    /// Where each machine's agent answers.
    pub agent_port: u16,
    ca: Ca,
    current: RwLock<Arc<ControlCert>>,
    /// The agent binary and its SHA-256, when it ships next to botd.
    agent: Option<(PathBuf, String)>,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("url", &self.url)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

impl Enrollment {
    /// MACHINE_CONTROL_URL turns it on: `https://<host>:<port>`, as machines will reach
    /// this server. MACHINE_LISTEN (default `0.0.0.0:<port>`) and MACHINE_AGENT_PORT
    /// (default 7443) are optional.
    pub fn from_env(
        var: &dyn Fn(&str) -> String,
        cipher: &Cipher,
        bin_dir: &FsPath,
    ) -> Result<Option<Enrollment>, String> {
        let raw = var("MACHINE_CONTROL_URL").trim().to_string();
        if raw.is_empty() {
            for k in ["MACHINE_LISTEN", "MACHINE_AGENT_PORT"] {
                if !var(k).trim().is_empty() {
                    return Err(format!("{k} needs MACHINE_CONTROL_URL"));
                }
            }
            return Ok(None);
        }
        let need = "MACHINE_CONTROL_URL must be https://<host>:<port>, as machines reach this server, e.g. https://<server-ip>:8443";
        let u = url::Url::parse(&raw).map_err(|_| need.to_string())?;
        let port = u.port().ok_or(need)?;
        if u.scheme() != "https"
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/"
        {
            return Err(need.into());
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return Err(need.into()),
        };
        let listen = match var("MACHINE_LISTEN").trim() {
            "" => SocketAddr::from(([0, 0, 0, 0], port)),
            l => l
                .parse()
                .map_err(|_| format!("MACHINE_LISTEN must be <ip>:<port>, not \"{l}\""))?,
        };
        let agent_port = match var("MACHINE_AGENT_PORT").trim() {
            "" => DEFAULT_AGENT_PORT,
            p => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("MACHINE_AGENT_PORT must be 1 to 65535")?,
        };
        let agent = std::fs::read(bin_dir.join(AGENT_BIN))
            .ok()
            .map(|b| (bin_dir.join(AGENT_BIN), sha256_hex(&b)));
        let ca = Ca::from_seed(&cipher.derive(CA_PURPOSE))?;
        Enrollment::new(
            u.as_str().trim_end_matches('/').to_string(),
            host,
            listen,
            agent_port,
            ca,
            agent,
        )
        .map(Some)
    }

    fn new(
        url: String,
        host: String,
        listen: SocketAddr,
        agent_port: u16,
        ca: Ca,
        agent: Option<(PathBuf, String)>,
    ) -> Result<Enrollment, String> {
        let current = RwLock::new(Arc::new(control_cert(&ca, &host)?));
        Ok(Enrollment {
            url,
            host,
            listen,
            agent_port,
            ca,
            current,
            agent,
        })
    }

    /// botd's machine port on 127.0.0.1:`port`, agents on `agent_port`, a CA from `seed`.
    #[cfg(test)]
    pub fn for_tests(seed: u8, port: u16, agent_port: u16) -> Enrollment {
        let ca = Ca::from_seed(&[seed; 32]).unwrap();
        Enrollment::new(
            format!("https://127.0.0.1:{port}"),
            "127.0.0.1".into(),
            SocketAddr::from(([127, 0, 0, 1], port)),
            agent_port,
            ca,
            None,
        )
        .unwrap()
    }

    /// A certificate from this CA that botd never recorded.
    #[cfg(test)]
    pub fn issue_unrecorded(&self, csr: &str, user_id: &str, machine_id: &str) -> Issued {
        self.ca
            .issue_machine(csr, user_id, machine_id, CERT_DAYS)
            .unwrap()
    }

    pub fn ca_pem(&self) -> &str {
        self.ca.pem()
    }

    pub fn describe(&self) -> String {
        format!(
            "on at {} (listening on {}, agents on port {}){}",
            self.url,
            self.listen,
            self.agent_port,
            if self.agent.is_some() {
                ""
            } else {
                "; superbot-machine isn't next to botd, so machines must be given it another way"
            }
        )
    }

    /// botd's certificate, renewed first when a third of its life is left.
    fn control(&self) -> Arc<ControlCert> {
        let cur = self.current.read().unwrap().clone();
        let left = cur.issued.not_after - now();
        if left > (cur.issued.not_after - cur.issued.not_before) / 3 {
            return cur;
        }
        let mut w = self.current.write().unwrap();
        if w.issued.fingerprint == cur.issued.fingerprint
            && let Ok(fresh) = control_cert(&self.ca, &self.host)
        {
            *w = Arc::new(fresh);
        }
        w.clone()
    }

    pub fn tls(self: &Arc<Self>) -> pki::Tls {
        let e = self.clone();
        Arc::new(move || e.control().server.clone())
    }

    /// A one-time token for `machine_id`: only its hash is kept.
    pub fn mint_token(
        &self,
        app: &App,
        machine_id: &str,
        created_by: Option<&str>,
    ) -> Result<(String, i64), String> {
        let token = format!(
            "{TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::random_bytes(32))
        );
        let expires = now() + TOKEN_MINUTES * 60_000;
        app.db
            .add_machine_token(
                machine_id,
                &sha256_hex(token.as_bytes()),
                expires,
                created_by,
            )
            .map_err(|e| e.to_string())?;
        Ok((token, expires))
    }

    /// cloud-init user data that installs the agent and enrolls the machine on first boot.
    pub fn user_data(&self, m: &Machine, token: &str) -> String {
        let indent = |s: &str| {
            s.lines()
                .map(|l| format!("      {l}\n"))
                .collect::<String>()
        };
        let mut out = format!(
            "#cloud-config\n\
             write_files:\n\
             \x20 - path: /etc/superbot/ca.pem\n\
             \x20   permissions: \"0644\"\n\
             \x20   content: |\n{ca}\
             \x20 - path: /etc/superbot/enroll-token\n\
             \x20   permissions: \"0600\"\n\
             \x20   content: \"{token}\"\n\
             \x20 - path: /etc/superbot/machine.env\n\
             \x20   permissions: \"0644\"\n\
             \x20   content: |\n\
             \x20     SUPERBOT_CONTROL_URL={url}\n\
             \x20     SUPERBOT_MACHINE_ID={id}\n\
             \x20     SUPERBOT_AGENT_LISTEN=0.0.0.0:{port}\n\
             \x20 - path: /etc/systemd/system/superbot-machine.service\n\
             \x20   permissions: \"0644\"\n\
             \x20   content: |\n{unit}",
            ca = indent(self.ca.pem()),
            url = self.url,
            id = m.id,
            port = self.agent_port,
            unit = indent(UNIT),
        );
        if let Some((_, sha)) = &self.agent {
            out.push_str(&format!(
                "runcmd:\n\
                 \x20 - [sh, -c, \"curl -fsS --retry 5 --cacert /etc/superbot/ca.pem -o /usr/local/bin/superbot-machine.new {url}/v1/agent && echo '{sha}  /usr/local/bin/superbot-machine.new' | sha256sum -c - && chmod 755 /usr/local/bin/superbot-machine.new && mv /usr/local/bin/superbot-machine.new /usr/local/bin/superbot-machine && systemctl daemon-reload && systemctl enable --now superbot-machine\"]\n",
                url = self.url,
            ));
        }
        out
    }

    /// An HTTPS client that accepts only `pins` and shows botd's certificate.
    fn pinned(&self, pins: Vec<String>) -> Result<(reqwest::Client, Arc<pki::Pinned>), String> {
        let c = self.control();
        let (config, verifier) =
            pki::pinned_client_config(pins, c.chain.clone(), c.key.clone_key())?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok((client, verifier))
    }

    fn agent_url(&self, address: &str, path: &str) -> String {
        format!("https://{address}:{}{path}", self.agent_port)
    }
}

fn control_cert(ca: &Ca, host: &str) -> Result<ControlCert, String> {
    let (issued, key) = ca.issue_control_plane(host, CONTROL_CERT_DAYS)?;
    let chain = vec![pki::cert_der(&issued.pem)?];
    let key = pki::key_der(&key.serialize_pem())?;
    let server = Arc::new(pki::server_config(
        ca.der(),
        chain.clone(),
        key.clone_key(),
        false,
    )?);
    Ok(ControlCert {
        issued,
        chain,
        key,
        server,
    })
}

const UNIT: &str = "[Unit]
Description=SuperBot machine agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/superbot/machine.env
Environment=SUPERBOT_ENROLL_TOKEN_FILE=/etc/superbot/enroll-token
ExecStart=/usr/local/bin/superbot-machine run
Restart=always
RestartSec=5
StateDirectory=superbot-machine
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/superbot

[Install]
WantedBy=multi-user.target
";

// Audit

/// A machine's agent, acting for the machine's user.
fn agent_who(user_id: &str, peer: &Peer) -> Who {
    Who {
        actor: Actor::system("machine_agent").on_behalf_of(user_id),
        source: Source {
            ip: Some(peer.addr.ip().to_string()),
            user_agent: None,
        },
    }
}

fn record(app: &App, by: &Who, action: &str, machine_id: &str, outcome: Outcome, details: Value) {
    app.db.record(
        &by.event(action)
            .target("machine", machine_id)
            .outcome(outcome)
            .details(details),
    );
}

/// Records certificates that were revoked as a side effect, if any.
fn record_revoked(app: &App, by: &Who, m: &Machine, reason: &str, fingerprints: &[String]) {
    if !fingerprints.is_empty() {
        record(
            app,
            by,
            "machine.cert_revoked",
            &m.id,
            Outcome::Success,
            json!({ "userId": m.user_id, "reason": reason, "certificates": fingerprints }),
        );
    }
}

// Lifecycle (called by the control plane with its lock held). They work on what is
// stored, so they apply whether or not enrollment is on now.

/// Suspended: the machine's certificates are held, so neither side accepts them.
pub fn hold(app: &App, by: &Who, m: &Machine) {
    let fps = app.db.set_machine_certs(&m.id, &["active"], "held", None);
    if !fps.is_empty() {
        record(
            app,
            by,
            "machine.cert_held",
            &m.id,
            Outcome::Success,
            json!({ "userId": m.user_id, "certificates": fps }),
        );
    }
}

/// Resumed: held certificates are active again. The machine can't get a new token
/// while it was off, so it keeps the certificate it had.
pub fn release(app: &App, by: &Who, m: &Machine) {
    let fps = app.db.set_machine_certs(&m.id, &["held"], "active", None);
    if !fps.is_empty() {
        record(
            app,
            by,
            "machine.cert_released",
            &m.id,
            Outcome::Success,
            json!({ "userId": m.user_id, "certificates": fps }),
        );
    }
}

/// Destroyed, lost, or an admin's call: every certificate and unused token is revoked
/// for good. The machine would have to enroll again with a new token.
pub fn revoke_all(app: &App, by: &Who, m: &Machine, reason: &str) -> usize {
    let tokens = app.db.revoke_machine_tokens(&m.id);
    let fps = app
        .db
        .set_machine_certs(&m.id, &["active", "held"], "revoked", Some(reason));
    if !fps.is_empty() || tokens > 0 {
        record(
            app,
            by,
            "machine.cert_revoked",
            &m.id,
            Outcome::Success,
            json!({ "userId": m.user_id, "reason": reason, "certificates": fps, "pendingEnrollments": tokens }),
        );
    }
    fps.len()
}

// botd's machine port

struct Port {
    app: AppState,
    e: Arc<Enrollment>,
}

fn reply(code: StatusCode, msg: &str) -> Response {
    (code, Json(wire::ErrorReply { error: msg.into() })).into_response()
}

const BAD_TOKEN: &str = "This enrollment token isn't valid. Ask an admin for a new one.";

fn accepting(s: State) -> bool {
    matches!(s, State::Provisioning | State::Running)
}

/// `POST /v1/enroll`: a token and a signing request for a certificate. The token must
/// be this machine's, unused, and unexpired, and the machine must be one being built
/// or running for an active user.
async fn enroll(
    AxState(p): AxState<Arc<Port>>,
    Extension(peer): Extension<Peer>,
    body: Bytes,
) -> Response {
    let Ok(req) = serde_json::from_slice::<wire::EnrollRequest>(&body) else {
        return reply(StatusCode::BAD_REQUEST, "Send {machineId, token, csr}.");
    };
    if !req.token.starts_with(TOKEN_PREFIX) || req.token.len() > 100 {
        return reply(StatusCode::UNAUTHORIZED, BAD_TOKEN);
    }
    // Unknown tokens aren't audited: anyone can reach this port, and a guess can't land.
    let Some(t) = p.app.db.machine_token(&sha256_hex(req.token.as_bytes())) else {
        return reply(StatusCode::UNAUTHORIZED, BAD_TOKEN);
    };
    let Some(m) = p.app.db.machine(&t.machine_id) else {
        return reply(StatusCode::UNAUTHORIZED, BAD_TOKEN);
    };
    let by = agent_who(&m.user_id, &peer);
    let refuse = |code: StatusCode, reason: &str, msg: &str| {
        record(
            &p.app,
            &by,
            "machine.enroll_failed",
            &m.id,
            Outcome::Denied,
            json!({ "userId": m.user_id, "reason": reason, "askedMachine": crate::audit::clip(&req.machine_id, 40) }),
        );
        reply(code, msg)
    };
    let at = now();
    let why = if req.machine_id != t.machine_id {
        Some("wrong_machine")
    } else if t.used_at.is_some() {
        Some("token_used")
    } else if t.revoked_at.is_some() {
        Some("token_revoked")
    } else if t.expires_at <= at {
        Some("token_expired")
    } else {
        None
    };
    if let Some(why) = why {
        return refuse(StatusCode::UNAUTHORIZED, why, BAD_TOKEN);
    }
    if !accepting(m.state) {
        return refuse(
            StatusCode::CONFLICT,
            "machine_not_ready",
            &format!("This machine is {} and can't enroll.", m.state.as_str()),
        );
    }
    if !p.app.db.user(&m.user_id).is_some_and(|u| u.active()) {
        return refuse(
            StatusCode::FORBIDDEN,
            "user_disabled",
            "This machine's user is disabled.",
        );
    }
    let issued = match p.e.ca.issue_machine(&req.csr, &m.user_id, &m.id, CERT_DAYS) {
        Ok(i) => i,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "bad_csr", &e),
    };
    let Some(replaced) = p.app.db.enroll_machine(t.id, &m.id, &m.user_id, &issued) else {
        return refuse(StatusCode::UNAUTHORIZED, "token_used", BAD_TOKEN);
    };
    record(
        &p.app,
        &by,
        "machine.enrolled",
        &m.id,
        Outcome::Success,
        json!({ "userId": m.user_id, "fingerprint": issued.fingerprint, "serial": issued.serial, "notAfter": issued.not_after }),
    );
    record_revoked(&p.app, &by, &m, "replaced", &replaced);
    Json(wire::CertificateReply {
        machine_id: m.id.clone(),
        user_id: m.user_id.clone(),
        certificate: issued.pem,
        ca: p.e.ca_pem().into(),
        not_after: issued.not_after,
    })
    .into_response()
}

/// The machine whose certificate the caller showed, if botd issued it, it is usable,
/// and it is for `machine_id`. A certificate acts only for its own machine and user,
/// whatever the request names.
#[allow(clippy::result_large_err)]
fn authenticate(
    p: &Port,
    peer: &Peer,
    machine_id: &str,
) -> Result<(MachineCert, Machine), Response> {
    let Some(der) = &peer.cert else {
        return Err(reply(
            StatusCode::UNAUTHORIZED,
            "Show this machine's certificate. Enroll first if it has none.",
        ));
    };
    let fp = pki::fingerprint(der);
    let Some(c) = p.app.db.machine_cert(&fp) else {
        return Err(reply(
            StatusCode::UNAUTHORIZED,
            "This server didn't issue that certificate to a machine.",
        ));
    };
    let by = agent_who(&c.user_id, peer);
    let deny = |code: StatusCode, reason: &str, msg: &str, extra: Value| {
        let mut d = json!({ "userId": c.user_id, "reason": reason, "fingerprint": c.fingerprint });
        if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
            d.extend(x);
        }
        record(
            &p.app,
            &by,
            "access.denied",
            &c.machine_id,
            Outcome::Denied,
            d,
        );
        Err(reply(code, msg))
    };
    let named = pki::facts(der)
        .map(|f| {
            f.uris
                .iter()
                .filter_map(|u| pki::parse_machine_uri(u))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if named != [(c.user_id.clone(), c.machine_id.clone())] {
        return deny(
            StatusCode::UNAUTHORIZED,
            "identity_mismatch",
            "That certificate doesn't name the machine it was issued to.",
            json!({}),
        );
    }
    match c.status.as_str() {
        "revoked" => {
            return deny(
                StatusCode::UNAUTHORIZED,
                "revoked",
                "That certificate was revoked.",
                json!({}),
            );
        }
        "held" => {
            return deny(
                StatusCode::FORBIDDEN,
                "held",
                "This machine is suspended.",
                json!({}),
            );
        }
        _ if !c.usable(now()) => {
            return deny(
                StatusCode::UNAUTHORIZED,
                "expired",
                "That certificate has expired.",
                json!({}),
            );
        }
        _ => {}
    }
    let m = match p.app.db.machine(&c.machine_id) {
        Some(m) if m.user_id == c.user_id && accepting(m.state) => m,
        _ => {
            return deny(
                StatusCode::UNAUTHORIZED,
                "machine_gone",
                "That machine isn't running.",
                json!({}),
            );
        }
    };
    if !p.app.db.user(&m.user_id).is_some_and(|u| u.active()) {
        return deny(
            StatusCode::FORBIDDEN,
            "user_disabled",
            "This machine's user is disabled.",
            json!({}),
        );
    }
    if machine_id != c.machine_id {
        let asked_user = p.app.db.machine(machine_id).map(|o| o.user_id);
        return deny(
            StatusCode::FORBIDDEN,
            "machine_mismatch",
            "A machine can act only for itself.",
            json!({ "askedMachine": crate::audit::clip(machine_id, 40), "askedUser": asked_user }),
        );
    }
    let revoked = p.app.db.machine_cert_seen(&fp);
    record_revoked(&p.app, &by, &m, "rotated", &revoked);
    Ok((c, m))
}

/// `GET /v1/machines/{id}`: the machine's own record, as botd sees it.
async fn status(
    AxState(p): AxState<Arc<Port>>,
    Extension(peer): Extension<Peer>,
    Path(id): Path<String>,
) -> Response {
    match authenticate(&p, &peer, &id) {
        Err(r) => r,
        Ok((c, m)) => Json(wire::MachineStatus {
            machine_id: m.id,
            user_id: m.user_id,
            state: m.state.as_str().into(),
            enrollment: m.enrollment,
            not_after: c.not_after,
        })
        .into_response(),
    }
}

/// `POST /v1/machines/{id}/certificate`: a new certificate for a new key, before the
/// current one runs out. The current one works until the new one is first used.
async fn rotate(
    AxState(p): AxState<Arc<Port>>,
    Extension(peer): Extension<Peer>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (c, m) = match authenticate(&p, &peer, &id) {
        Err(r) => return r,
        Ok(x) => x,
    };
    let Ok(req) = serde_json::from_slice::<wire::RotateRequest>(&body) else {
        return reply(StatusCode::BAD_REQUEST, "Send {csr}.");
    };
    let by = agent_who(&m.user_id, &peer);
    let issued = match p.e.ca.issue_machine(&req.csr, &m.user_id, &m.id, CERT_DAYS) {
        Ok(i) => i,
        Err(e) => return reply(StatusCode::BAD_REQUEST, &e),
    };
    let Some(superseded) = p.app.db.add_rotated_cert(&c, &issued) else {
        let cert_gone = p
            .app
            .db
            .machine_cert(&c.fingerprint)
            .is_none_or(|now| now.status != "active");
        let machine_gone = !p.app.db.machine(&m.id).is_some_and(|now| accepting(now.state));
        if cert_gone || machine_gone {
            return reply(
                StatusCode::UNAUTHORIZED,
                "This certificate was held or revoked, or the machine stopped, meanwhile.",
            );
        }
        return reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The new certificate wasn't saved.",
        );
    };
    record(
        &p.app,
        &by,
        "machine.cert_rotated",
        &m.id,
        Outcome::Success,
        json!({ "userId": m.user_id, "from": c.fingerprint, "fingerprint": issued.fingerprint, "serial": issued.serial, "notAfter": issued.not_after }),
    );
    record_revoked(&p.app, &by, &m, "superseded", &superseded);
    Json(wire::CertificateReply {
        machine_id: m.id,
        user_id: m.user_id,
        certificate: issued.pem,
        ca: p.e.ca_pem().into(),
        not_after: issued.not_after,
    })
    .into_response()
}

/// `GET /v1/agent`: the agent binary. Public code; cloud-init checks its SHA-256.
async fn agent_binary(AxState(p): AxState<Arc<Port>>) -> Response {
    let Some((path, _)) = p.e.agent.clone() else {
        return reply(
            StatusCode::NOT_FOUND,
            "superbot-machine isn't installed next to botd.",
        );
    };
    match tokio::task::spawn_blocking(move || std::fs::read(path)).await {
        Ok(Ok(b)) => ([(header::CONTENT_TYPE, "application/octet-stream")], b).into_response(),
        _ => reply(StatusCode::NOT_FOUND, "superbot-machine couldn't be read."),
    }
}

pub fn router(app: AppState, e: Arc<Enrollment>) -> axum::Router {
    axum::Router::new()
        .route("/v1/enroll", post(enroll))
        .route("/v1/machines/{id}", get(status))
        .route("/v1/machines/{id}/certificate", post(rotate))
        .route("/v1/agent", get(agent_binary))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(Port { app, e }))
}

/// Serves the machine port on `listener`.
pub async fn serve(listener: tokio::net::TcpListener, app: AppState, e: Arc<Enrollment>) {
    pki::serve(listener, e.tls(), router(app, e), |_| true).await
}

// Calling machines

/// Asks the machine's agent for a heartbeat over mutual TLS, pinned to the machine's
/// own certificates, and records the answer. A rotated certificate seen here for the
/// first time retires the ones before it.
pub async fn heartbeat(app: &App, e: &Enrollment, m: &Machine) -> Result<wire::Heartbeat, String> {
    let res = async {
        let pins = app.db.machine_pins(&m.id);
        if pins.is_empty() {
            return Err("it has no usable certificate".to_string());
        }
        let address = m.ipv4.as_deref().ok_or("it has no address yet")?;
        let (client, seen) = e.pinned(pins)?;
        let r = client
            .get(e.agent_url(address, "/v1/heartbeat"))
            .send()
            .await
            .map_err(|e| format!("its agent didn't answer: {}", without_url(e)))?;
        if !r.status().is_success() {
            return Err(format!("its agent answered {}", r.status().as_u16()));
        }
        let hb: wire::Heartbeat = r
            .json()
            .await
            .map_err(|_| "its agent's answer wasn't a heartbeat".to_string())?;
        let fp = seen.seen.lock().unwrap().clone().unwrap_or_default();
        if hb.machine_id != m.id || hb.user_id != m.user_id {
            return Err("its agent answered for another machine".into());
        }
        let revoked = app.db.machine_cert_seen(&fp);
        record_revoked(app, &Who::system("control_plane"), m, "rotated", &revoked);
        Ok(hb)
    }
    .await;
    app.db.machine_agent_seen(
        &m.id,
        res.as_ref()
            .map(|h| h.version.as_str())
            .map_err(String::as_str),
    );
    res
}

/// The error and its causes (TLS refusals are in there), without the URL.
fn without_url(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut s = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(inner) = src {
        s = format!("{s}: {inner}");
        src = inner.source();
    }
    s
}

/// Hands jobs to a user's machine over mutual TLS, to that machine's own pinned
/// certificate only. The agent doesn't run Bots yet, so it turns every job down and the
/// run is refused with that reason; the connection and both certificates are real.
pub struct Mtls(pub Arc<Enrollment>);

impl MachineLink for Mtls {
    fn name(&self) -> &'static str {
        "mtls"
    }

    fn dispatch<'a>(&'a self, to: &'a Assigned, job: Job) -> Dispatched<'a> {
        Box::pin(async move {
            let address = to
                .address
                .as_deref()
                .ok_or("your computer has no address yet")?;
            let (client, _) = self.0.pinned(to.pins.clone())?;
            let body = wire::JobRequest {
                bot_id: job.bot_id,
                owner_id: job.owner_id,
                message_id: job.message_id,
            };
            let r = client
                .post(self.0.agent_url(address, "/v1/jobs"))
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("it didn't answer ({})", without_url(e)))?;
            match r.status() {
                s if s.is_success() => Ok(()),
                StatusCode::NOT_IMPLEMENTED => {
                    Err("it's connected, but it can't run Bots yet.".into())
                }
                s => Err(format!("it answered {}.", s.as_u16())),
            }
        })
    }
}

// Admin API, under `/api/users/{key}/machine` (admin only, rbac::classify).

fn need(cp: &ControlPlane) -> Res<&Arc<Enrollment>> {
    cp.need()?;
    cp.enrollment
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, OFF.into()))
}

/// `POST /api/users/{key}/machine/enrollment`: a new one-time token, shown once, for
/// enrolling a machine by hand (or again, after its certificates were revoked).
pub async fn issue_token(
    AxState(app): AxState<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let e = need(&a.machines)?;
    let u = need_user_key(&app, &key)?;
    let m = app
        .db
        .user_machine(&u.id)
        .ok_or_else(|| crate::not_found("Machine"))?;
    if !accepting(m.state) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!(
                "The machine is {}; it can enroll once it's running.",
                m.state.as_str()
            ),
        ));
    }
    let (token, expires_at) = e
        .mint_token(&app, &m.id, by.actor.id.as_deref())
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    record(
        &app,
        &by,
        "machine.enroll_token_issued",
        &m.id,
        Outcome::Success,
        json!({ "userId": m.user_id, "expiresAt": expires_at }),
    );
    Ok(Json(json!({
        "machineId": m.id,
        "token": token,
        "expiresAt": expires_at,
        "controlUrl": e.url,
        "ca": e.ca_pem(),
        "howTo": "On the machine: save the CA to /etc/superbot/ca.pem and the token to /etc/superbot/enroll-token (chmod 600), then run SUPERBOT_CONTROL_URL=<controlUrl> SUPERBOT_MACHINE_ID=<machineId> SUPERBOT_ENROLL_TOKEN_FILE=/etc/superbot/enroll-token superbot-machine enroll. The token works once, for this machine, within the hour.",
    })))
}

/// `DELETE /api/users/{key}/machine/certificates`: revokes the machine's certificates
/// and unused tokens now. It must enroll again with a new token.
pub async fn revoke(
    AxState(app): AxState<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    a.machines.need()?;
    let u = need_user_key(&app, &key)?;
    let _g = a.machines.ops.lock().await;
    let m = app
        .db
        .user_machine(&u.id)
        .ok_or_else(|| crate::not_found("Machine"))?;
    let n = revoke_all(&app, &by, &m, "admin");
    Ok(Json(
        json!({ "revoked": n, "machine": app.db.machine(&m.id).map(|m| super::admin_view(&app, &m)) }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::key::MasterKey;

    #[test]
    fn settings() {
        let cipher = Cipher::new(&MasterKey::generate());
        let bin = crate::db::temp_path("enroll-bin");
        let with = |vars: &'static [(&'static str, &'static str)]| {
            Enrollment::from_env(
                &|k| {
                    vars.iter()
                        .find(|(n, _)| *n == k)
                        .map(|(_, v)| v.to_string())
                        .unwrap_or_default()
                },
                &cipher,
                &bin,
            )
        };
        assert!(with(&[]).unwrap().is_none(), "off unless asked");
        assert!(
            with(&[("MACHINE_AGENT_PORT", "7000")]).is_err(),
            "agent settings alone are a mistake"
        );
        let e = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443/")])
            .unwrap()
            .unwrap();
        assert_eq!(
            (e.url.as_str(), e.listen.to_string().as_str(), e.agent_port),
            (
                "https://cp.example:8443",
                "0.0.0.0:8443",
                DEFAULT_AGENT_PORT
            )
        );
        assert!(e.describe().contains("isn't next to botd"));
        let e = with(&[
            ("MACHINE_CONTROL_URL", "https://[2001:db8::1]:9443"),
            ("MACHINE_LISTEN", "127.0.0.1:9443"),
            ("MACHINE_AGENT_PORT", "7000"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            (e.host.as_str(), e.listen.port(), e.agent_port),
            ("2001:db8::1", 9443, 7000)
        );
        for bad in [
            "http://cp.example:8443",
            "https://cp.example",
            "https://cp.example:8443/api",
            "https://u:p@cp.example:8443",
            "https://cp.example:8443?x=1",
            "cp.example:8443",
        ] {
            let vars: &'static [(&'static str, &'static str)] =
                Box::leak(Box::new([("MACHINE_CONTROL_URL", bad)]));
            assert!(with(vars).is_err(), "{bad}");
        }
        assert!(
            with(&[
                ("MACHINE_CONTROL_URL", "https://cp.example:8443"),
                ("MACHINE_AGENT_PORT", "0")
            ])
            .is_err()
        );
        assert!(
            with(&[
                ("MACHINE_CONTROL_URL", "https://cp.example:8443"),
                ("MACHINE_LISTEN", "everywhere")
            ])
            .is_err()
        );

        let a = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443")])
            .unwrap()
            .unwrap();
        assert_eq!(
            a.ca_pem(),
            e.ca_pem(),
            "the CA follows the master key, not the settings"
        );
        let other = Cipher::new(&MasterKey::generate());
        let b = Enrollment::from_env(
            &|k| {
                if k == "MACHINE_CONTROL_URL" {
                    "https://cp.example:8443".into()
                } else {
                    String::new()
                }
            },
            &other,
            &bin,
        )
        .unwrap()
        .unwrap();
        assert_ne!(a.ca_pem(), b.ca_pem(), "another master key, another CA");
    }

    #[test]
    fn user_data_carries_the_token_ca_and_agent() {
        let mut e = Enrollment::for_tests(3, 1, DEFAULT_AGENT_PORT);
        let app = crate::runner::test_app();
        let u = app
            .db
            .create_user(None, Some("ud@example.com"), "U", crate::rbac::Role::Member)
            .unwrap();
        let m = app
            .db
            .add_machine(&crate::db::NewMachine {
                user_id: &u.id,
                provider: "fake",
                label_prefix: "superbot",
                tier: "starter",
                plan: "g6-standard-1",
                region: "gb-lon",
                created_by: None,
            })
            .unwrap();
        let ud = e.user_data(&m, "sbe_tok");
        assert!(ud.starts_with("#cloud-config\n"));
        for want in [
            "content: \"sbe_tok\"",
            &format!("SUPERBOT_MACHINE_ID={}", m.id),
            "SUPERBOT_CONTROL_URL=https://127.0.0.1:1",
            "      -----BEGIN CERTIFICATE-----",
            "ExecStart=/usr/local/bin/superbot-machine run",
        ] {
            assert!(ud.contains(want), "{want}\n{ud}");
        }
        assert!(
            !ud.contains("runcmd"),
            "no download when botd has no agent to serve"
        );
        e.agent = Some((PathBuf::from("/nowhere"), "ab".repeat(32)));
        let ud = e.user_data(&m, "sbe_tok");
        assert!(
            ud.contains(&format!(
                "echo '{}  /usr/local/bin/superbot-machine.new' | sha256sum -c -",
                "ab".repeat(32)
            )),
            "{ud}"
        );
        assert!(
            ud.contains("--cacert /etc/superbot/ca.pem"),
            "the download trusts only our CA"
        );
    }
}
