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
use super::route::{Assigned, Checked, MachineLink, Ran};
use super::upkeep::Upkeep;
use super::wire::{self, JobEvent, JobRequest};
use super::{ControlPlane, State};
use crate::adapters::AbortReason;
use crate::audit::{Actor, Outcome, Source, Who};
use crate::db::{Machine, MachineCert, now};
use crate::runner::App;
use crate::secrets::sealed::Cipher;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, Res};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Request, State as AxState};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use base64::Engine;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// How long an enrollment token lasts. Building and booting a Linode takes minutes.
pub const TOKEN_MINUTES: i64 = 60;
/// How long a machine has to enroll before the reconciler reports it (ADR 0035).
pub const DEFAULT_ENROLL_TIMEOUT_MINUTES: i64 = 15;
/// A machine's certificate lifetime. Its agent asks for a new one with a third left.
pub const CERT_DAYS: i64 = 30;
/// botd's own certificate, renewed by itself with a third left.
const CONTROL_CERT_DAYS: i64 = 30;
pub const DEFAULT_AGENT_PORT: u16 = 7443;
/// The agent's binary, next to botd's, served to machines at `/v1/agent`.
pub const AGENT_BIN: &str = "superbot-machine";
/// Bots on a machine run `botctl` there too, served at `/v1/botctl`.
pub const BOTCTL_BIN: &str = "botctl";
/// A job stream with nothing on it this long (the agent pings every 15 seconds)
/// means the machine is gone.
const JOB_SILENCE: Duration = Duration::from_secs(60);
/// After a stop, how long the agent has to end the job before botd lets go of it.
const ABORT_GRACE: Duration = Duration::from_secs(30);
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
    /// A machine not enrolled this long after its token was issued is reported
    /// (MACHINE_ENROLL_TIMEOUT_MINUTES).
    pub enroll_timeout_ms: i64,
    ca: Ca,
    current: RwLock<Arc<ControlCert>>,
    /// The agent binary and its SHA-256, when it ships next to botd. Read once at
    /// start and shared by every download, so a download costs no new memory.
    agent: Option<(Bytes, String)>,
    /// botctl, the same way.
    botctl: Option<(Bytes, String)>,
    /// Harness CLIs and agent upgrades on machines (ADR 0039).
    pub upkeep: Upkeep,
    /// Harness logins on machines (MACHINE_HARNESS_LOGINS, ADR 0041), and those running.
    pub logins: bool,
    pub(super) sessions: super::logins::Sessions,
    /// Copying users' folders to their machines (MACHINE_FOLDER_SYNC, ADR 0041).
    pub folder: Option<super::folder::Settings>,
    pub(super) copying: super::folder::Copying,
    /// Bots run as their own OS user on machines (MACHINE_BOT_USER, ADR 0043), and
    /// when each agent was last asked to.
    pub bot_user: bool,
    pub(super) asked: super::botuser::Asked,
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
            for k in [
                "MACHINE_LISTEN",
                "MACHINE_AGENT_PORT",
                "MACHINE_ENROLL_TIMEOUT_MINUTES",
                "MACHINE_HARNESSES",
                "MACHINE_AGENT_UPGRADES",
                "MACHINE_HARNESS_LOGINS",
                "MACHINE_FOLDER_SYNC",
                "MACHINE_FOLDER_SYNC_MAX_MB",
                "MACHINE_BOT_USER",
            ] {
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
        let timeout = match var("MACHINE_ENROLL_TIMEOUT_MINUTES").trim() {
            "" => DEFAULT_ENROLL_TIMEOUT_MINUTES,
            m => m
                .parse::<i64>()
                .ok()
                .filter(|m| (5..=TOKEN_MINUTES).contains(m))
                .ok_or(format!(
                    "MACHINE_ENROLL_TIMEOUT_MINUTES must be 5 to {TOKEN_MINUTES} (a token lasts {TOKEN_MINUTES} minutes)"
                ))?,
        };
        let read = |name: &str| {
            std::fs::read(bin_dir.join(name)).ok().map(|b| {
                let sha = sha256_hex(&b);
                (Bytes::from(b), sha)
            })
        };
        let ca = Ca::from_seed(&cipher.derive(CA_PURPOSE))?;
        let mut e = Enrollment::new(
            u.as_str().trim_end_matches('/').to_string(),
            host,
            listen,
            agent_port,
            ca,
            read(AGENT_BIN),
        )?;
        e.botctl = read(BOTCTL_BIN);
        e.enroll_timeout_ms = timeout * 60_000;
        e.upkeep = Upkeep::from_env(var)?;
        e.logins = match var("MACHINE_HARNESS_LOGINS").trim() {
            "" | "off" => false,
            "on" => true,
            v => return Err(format!("MACHINE_HARNESS_LOGINS must be on or off, not \"{v}\"")),
        };
        e.folder = super::folder::Settings::from_env(var)?;
        e.bot_user = super::botuser::from_env(var)?;
        Ok(Some(e))
    }

    fn new(
        url: String,
        host: String,
        listen: SocketAddr,
        agent_port: u16,
        ca: Ca,
        agent: Option<(Bytes, String)>,
    ) -> Result<Enrollment, String> {
        let current = RwLock::new(Arc::new(control_cert(&ca, &host)?));
        Ok(Enrollment {
            url,
            host,
            listen,
            agent_port,
            enroll_timeout_ms: DEFAULT_ENROLL_TIMEOUT_MINUTES * 60_000,
            ca,
            current,
            agent,
            botctl: None,
            upkeep: Upkeep::default(),
            logins: false,
            sessions: Default::default(),
            folder: None,
            copying: Default::default(),
            bot_user: false,
            asked: Default::default(),
        })
    }

    /// The host in MACHINE_CONTROL_URL: a name, or an address without brackets.
    pub fn host(&self) -> &str {
        &self.host
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

    /// Serves `binary` as the agent download, as if it shipped next to botd.
    #[cfg(test)]
    pub fn with_agent(mut self, binary: &'static [u8]) -> Enrollment {
        self.agent = Some((Bytes::from_static(binary), sha256_hex(binary)));
        self
    }

    /// With MACHINE_HARNESS_LOGINS=on.
    #[cfg(test)]
    pub fn with_logins(mut self) -> Enrollment {
        self.logins = true;
        self
    }

    /// With MACHINE_FOLDER_SYNC=on, up to `max_bytes`.
    #[cfg(test)]
    pub fn with_folder_sync(mut self, max_bytes: u64) -> Enrollment {
        self.folder = Some(super::folder::Settings { max_bytes });
        self
    }

    /// With MACHINE_BOT_USER=on.
    #[cfg(test)]
    pub fn with_bot_user(mut self) -> Enrollment {
        self.bot_user = true;
        self
    }

    /// Serves `binary` as botctl, as if it shipped next to botd.
    #[cfg(test)]
    pub fn with_botctl(mut self, binary: &'static [u8]) -> Enrollment {
        self.botctl = Some((Bytes::from_static(binary), sha256_hex(binary)));
        self
    }

    /// SHA-256 of the agent botd ships, the build machines upgrade to.
    pub fn agent_sha256(&self) -> Option<&str> {
        self.agent.as_ref().map(|(_, sha)| sha.as_str())
    }

    pub fn botctl_sha256(&self) -> Option<&str> {
        self.botctl.as_ref().map(|(_, sha)| sha.as_str())
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
            "on at {} (listening on {}, agents on port {}, {} minutes to enroll; {}; harness logins {}; folder copies {}; Bots' own user {}){}",
            self.url,
            self.listen,
            self.agent_port,
            self.enroll_timeout_ms / 60_000,
            self.upkeep.describe(),
            if self.logins { "on" } else { "off" },
            self.folder.as_ref().map_or("off".to_string(), |f| format!("on, up to {} MiB", f.max_bytes >> 20)),
            if self.bot_user { "on" } else { "off" },
            match (&self.agent, &self.botctl) {
                (Some(_), Some(_)) => "",
                (None, _) =>
                    "; superbot-machine isn't next to botd, so machines must be given it another way",
                (_, None) =>
                    "; botctl isn't next to botd, so machines can't run Bots until they're given it",
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

    /// A one-time token for `machine_id`: only its hash is kept. The machine must
    /// enroll within the timeout from now.
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
        let at = now();
        let expires = at + TOKEN_MINUTES * 60_000;
        app.db
            .add_machine_token(
                machine_id,
                &sha256_hex(token.as_bytes()),
                expires,
                created_by,
                at + self.enroll_timeout_ms,
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
             \x20   content: |\n{unit}\
             \x20 - path: {GUARD_PATH}\n\
             \x20   permissions: \"0755\"\n\
             \x20   content: |\n{guard}",
            ca = indent(self.ca.pem()),
            url = self.url,
            id = m.id,
            port = self.agent_port,
            unit = indent(&self.unit()),
            guard = indent(GUARD),
        );
        if let Some((_, sha)) = &self.agent {
            // botctl first: the agent reports whether it's there when botd checks.
            let botctl = self.botctl.as_ref().map_or(String::new(), |(_, b)| {
                FIRSTBOOT_BOTCTL.replace("{url}", &self.url).replace("{sha}", b)
            });
            let bots = if self.bot_user { FIRSTBOOT_BOT_USER.replace("{user}", wire::BOT_USER) } else { String::new() };
            let script = FIRSTBOOT
                .replace("{botctl}\n", &botctl)
                .replace("{bot_user}\n", &bots)
                .replace("{url}", &self.url)
                .replace("{sha}", sha);
            out.push_str(&format!(
                "\x20 - path: {FIRSTBOOT_PATH}\n\
                 \x20   permissions: \"0700\"\n\
                 \x20   content: |\n{}\
                 runcmd:\n\
                 \x20 - [{FIRSTBOOT_PATH}]\n",
                indent(&script),
            ));
        }
        out
    }

    /// The agent's unit. With MACHINE_BOT_USER, its state folder lets the Bots' user
    /// through to its home (ADR 0043).
    pub fn unit(&self) -> String {
        if self.bot_user {
            UNIT.replace("StateDirectoryMode=0700", "StateDirectoryMode=0711")
        } else {
            UNIT.to_string()
        }
    }

    /// An HTTPS client that accepts only `pins` and shows botd's certificate.
    pub(super) fn pinned(&self, pins: Vec<String>) -> Result<(reqwest::Client, Arc<pki::Pinned>), String> {
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

    /// Like `pinned`, for a job's stream: no overall timeout, since a run can take
    /// hours, but a stream silent for `JOB_SILENCE` is a lost machine.
    pub(super) fn job_client(&self, pins: Vec<String>) -> Result<reqwest::Client, String> {
        let c = self.control();
        let (config, _) = pki::pinned_client_config(pins, c.chain.clone(), c.key.clone_key())?;
        reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(JOB_SILENCE)
            .build()
            .map_err(|e| e.to_string())
    }

    /// Like `pinned`, for copying a folder: each request gets up to `secs`.
    pub(super) fn upload_client(&self, pins: Vec<String>, secs: u64) -> Result<reqwest::Client, String> {
        let c = self.control();
        let (config, _) = pki::pinned_client_config(pins, c.chain.clone(), c.key.clone_key())?;
        reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(secs))
            .build()
            .map_err(|e| e.to_string())
    }

    pub(super) fn agent_url(&self, address: &str, path: &str) -> String {
        format!("https://{address}:{}{path}", self.agent_port)
    }

    /// Sends `body` to `m`'s agent at `path`, pinned to its certificates. Its status
    /// and JSON answer (`null` if none).
    pub(super) async fn call_agent<T: serde::Serialize + ?Sized>(
        &self,
        app: &App,
        m: &Machine,
        method: reqwest::Method,
        path: &str,
        body: &T,
    ) -> Result<(u16, Value), String> {
        let pins = app.db.machine_pins(&m.id);
        if pins.is_empty() {
            return Err("it has no usable certificate".into());
        }
        let address = m.ipv4.as_deref().ok_or("it has no address yet")?;
        let (client, _) = self.pinned(pins)?;
        let mut r = client
            .request(method, self.agent_url(address, path))
            .json(body)
            .send()
            .await
            .map_err(|e| format!("its agent didn't answer: {}", without_url(e)))?;
        let code = r.status().as_u16();
        let reply = read_capped(&mut r, MAX_REPLY)
            .await
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        Ok((code, reply))
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

const FIRSTBOOT_PATH: &str = "/usr/local/lib/superbot/firstboot";
const GUARD_PATH: &str = "/usr/local/lib/superbot/agent-guard";

/// Run once by cloud-init (ADR 0035): installs the agent botd ships (and botctl, when
/// botd ships it), each checked against the SHA-256 botd pinned, enrolls, and starts
/// the agent. Its output goes to the cloud-init log, so nothing in it may print the
/// token. Both live in /usr/local/lib/superbot, which the unit lets the agent write,
/// so it can upgrade them (ADR 0039); /usr/local/bin links to them.
const FIRSTBOOT: &str = r#"#!/bin/sh
set -eu
dir=/usr/local/lib/superbot
{botctl}
{bot_user}
bin=$dir/superbot-machine
curl -fsS --retry 10 --retry-delay 5 --retry-all-errors --cacert /etc/superbot/ca.pem -o "$bin.new" "{url}/v1/agent"
echo "{sha}  $bin.new" | sha256sum -c -
chmod 755 "$bin.new"
mv "$bin.new" "$bin"
ln -sfn "$bin" /usr/local/bin/superbot-machine
systemctl daemon-reload
systemctl enable superbot-machine
set -a
. /etc/superbot/machine.env
set +a
if SUPERBOT_ENROLL_TOKEN_FILE=/etc/superbot/enroll-token SUPERBOT_STATE_DIR=/var/lib/superbot-machine "$bin" enroll; then
  echo "superbot: enrolled"
else
  echo "superbot: enrolling failed; the agent will keep trying" >&2
fi
# cloud-init's copies of the user data hold the token; only the agent's file is needed.
rm -f /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i
systemctl start superbot-machine
"#;

/// FIRSTBOOT's step making the Bots' own user (ADR 0043), so the agent needn't. It
/// still hands the user its home when botd asks.
const FIRSTBOOT_BOT_USER: &str = r#"mkdir -p -m 0711 /var/lib/superbot-machine
mkdir -p -m 0700 /var/lib/superbot-machine/home
id -u {user} >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin --comment "SuperBot Bots" --home-dir /var/lib/superbot-machine/home {user}
"#;

/// FIRSTBOOT's botctl step (ADR 0036).
const FIRSTBOOT_BOTCTL: &str = r#"ctl=$dir/botctl
curl -fsS --retry 10 --retry-delay 5 --retry-all-errors --cacert /etc/superbot/ca.pem -o "$ctl.new" "{url}/v1/botctl"
echo "{sha}  $ctl.new" | sha256sum -c -
chmod 755 "$ctl.new"
mv "$ctl.new" "$ctl"
ln -sfn "$ctl" /usr/local/bin/botctl
"#;

/// Run before every start of the agent (ADR 0039). While an upgraded agent is on
/// trial it counts the starts; past three, the new agent can't be working, so the
/// files before it go back. The old agent then reports the upgrade rolled back. It
/// never stops the agent from starting.
pub const GUARD: &str = r#"#!/bin/sh
state=${STATE_DIRECTORY:-/var/lib/superbot-machine}
dir=${SUPERBOT_AGENT_DIR:-/usr/local/lib/superbot}
[ -f "$state/upgrade-trial.json" ] || exit 0
n=$(cat "$state/upgrade-trial.starts" 2>/dev/null || true)
case $n in ''|*[!0-9]*) n=0 ;; esac
n=$((n + 1))
echo "$n" > "$state/upgrade-trial.starts"
[ "$n" -gt 3 ] || exit 0
for f in botctl superbot-machine; do
  if [ -f "$dir/$f.prev" ]; then mv -f "$dir/$f.prev" "$dir/$f"; fi
done
echo "superbot: the upgraded agent didn't start; put the one before it back" >&2
exit 0
"#;

const UNIT: &str = "[Unit]
Description=SuperBot machine agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/superbot/machine.env
Environment=SUPERBOT_ENROLL_TOKEN_FILE=/etc/superbot/enroll-token
ExecStartPre=-/usr/local/lib/superbot/agent-guard
ExecStart=/usr/local/lib/superbot/superbot-machine run
Restart=always
RestartSec=5
StateDirectory=superbot-machine
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/superbot /usr/local/lib/superbot

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
    api: Option<Api>,
}

/// botd's own API, for the relay (`/v1/machines/{id}/api/...`): the router, and a
/// Host it accepts.
#[derive(Clone)]
pub struct Api {
    pub router: axum::Router,
    pub host: String,
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
        let machine_gone = !p
            .app
            .db
            .machine(&m.id)
            .is_some_and(|now| accepting(now.state));
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

fn binary(b: &Option<(Bytes, String)>, name: &str) -> Response {
    let Some((bytes, _)) = b.clone() else {
        return reply(
            StatusCode::NOT_FOUND,
            &format!("{name} isn't installed next to botd."),
        );
    };
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

/// `GET /v1/agent`: the agent binary. Public code; cloud-init checks its SHA-256.
async fn agent_binary(AxState(p): AxState<Arc<Port>>) -> Response {
    binary(&p.e.agent, AGENT_BIN)
}

/// `GET /v1/botctl`: botctl, for Bots on the machine. Public code, checked the same way.
async fn botctl_binary(AxState(p): AxState<Arc<Port>>) -> Response {
    binary(&p.e.botctl, BOTCTL_BIN)
}

/// Headers a Bot's call carries through the relay; nothing else crosses.
const RELAYED: [header::HeaderName; 4] = [
    header::AUTHORIZATION,
    header::CONTENT_TYPE,
    header::ACCEPT,
    header::USER_AGENT,
];

/// `ANY /v1/machines/{id}/api/{path}`: a call from a Bot on the machine (`botctl`, the
/// approval hook) to botd's `/api/{path}`, relayed by its agent. The machine shows its
/// certificate, and the call carries the Bot's own token, which must be for one of
/// that machine's user's Bots: a machine speaks for its own user only. From there the
/// API checks the token and the Bot's rights as for any Bot.
async fn relay(
    AxState(p): AxState<Arc<Port>>,
    Extension(peer): Extension<Peer>,
    Path((id, rest)): Path<(String, String)>,
    req: Request,
) -> Response {
    let (_, m) = match authenticate(&p, &peer, &id) {
        Err(r) => return r,
        Ok(x) => x,
    };
    let Some(api) = &p.api else {
        return reply(StatusCode::NOT_FOUND, "This server doesn't relay calls.");
    };
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with(crate::isolation::BOT_TOKEN_PREFIX));
    let bot = token.and_then(|t| crate::isolation::token_bot(&p.app.cfg.bot_key, t));
    if !bot.is_some_and(|(_, owner)| owner == m.user_id) {
        record(
            &p.app,
            &agent_who(&m.user_id, &peer),
            "access.denied",
            &m.id,
            Outcome::Denied,
            json!({ "userId": m.user_id, "reason": if bot.is_some() { "another_users_bot" } else { "no_bot_token" }, "path": crate::audit::clip(&rest, 80), "bot": bot.map(|(b, _)| b) }),
        );
        return reply(
            StatusCode::FORBIDDEN,
            "Only this machine's user's Bots can call botd through it, each with its own token.",
        );
    }
    if rest
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return reply(StatusCode::NOT_FOUND, "No such API path.");
    }
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let mut b = axum::http::Request::builder()
        .method(req.method().clone())
        .uri(format!("/api/{rest}{query}"))
        .header(header::HOST, &api.host);
    for h in RELAYED {
        if let Some(v) = req.headers().get(&h) {
            b = b.header(h, v.clone());
        }
    }
    let Ok(mut inner) = b.body(req.into_body()) else {
        return reply(StatusCode::BAD_REQUEST, "That request can't be relayed.");
    };
    // The machine's own address, so the audit log says where the call came from.
    inner.extensions_mut().insert(ConnectInfo(peer.addr));
    match tower::ServiceExt::oneshot(api.router.clone(), inner).await {
        Ok(r) => r.into_response(),
        Err(e) => match e {},
    }
}

pub fn router(app: AppState, e: Arc<Enrollment>, api: Option<Api>) -> axum::Router {
    axum::Router::new()
        .route("/v1/enroll", post(enroll))
        .route("/v1/machines/{id}", get(status))
        .route("/v1/machines/{id}/certificate", post(rotate))
        .route("/v1/machines/{id}/api/{*rest}", any(relay))
        .route("/v1/agent", get(agent_binary))
        .route("/v1/botctl", get(botctl_binary))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(Port { app, e, api }))
}

/// Serves the machine port on `listener`. `api`: botd's API, relayed for Bots on
/// machines.
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: AppState,
    e: Arc<Enrollment>,
    api: Option<Api>,
) {
    pki::serve(listener, e.tls(), router(app, e, api), pki::lifetime).await
}

// Calling machines

/// Asks the machine's agent for a heartbeat over mutual TLS, pinned to the machine's
/// own certificates, and records the answer. A rotated certificate seen here for the
/// first time retires the ones before it.
pub async fn heartbeat(app: &App, e: &Enrollment, m: &Machine) -> Result<wire::Heartbeat, String> {
    let to = Assigned {
        machine_id: m.id.clone(),
        user_id: m.user_id.clone(),
        address: m.ipv4.clone(),
        pins: app.db.machine_pins(&m.id),
    };
    probe(app, e, &to, &[]).await
}

/// `heartbeat`, also asking whether `bins` are installed there.
async fn probe(
    app: &App,
    e: &Enrollment,
    to: &Assigned,
    bins: &[&str],
) -> Result<wire::Heartbeat, String> {
    let res = async {
        if to.pins.is_empty() {
            return Err("it has no usable certificate".to_string());
        }
        let address = to.address.as_deref().ok_or("it has no address yet")?;
        let (client, seen) = e.pinned(to.pins.clone())?;
        let mut query: Vec<String> = bins.iter().map(|b| format!("bin={b}")).collect();
        if e.logins {
            query.extend(super::logins::cred_query());
        }
        let mut r = client
            .get(e.agent_url(address, &format!("/v1/heartbeat?{}", query.join("&"))))
            .send()
            .await
            .map_err(|e| format!("its agent didn't answer: {}", without_url(e)))?;
        if !r.status().is_success() {
            return Err(format!("its agent answered {}", r.status().as_u16()));
        }
        let hb: wire::Heartbeat = read_capped(&mut r, MAX_REPLY)
            .await
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or("its agent's answer wasn't a heartbeat")?;
        let fp = seen.seen.lock().unwrap().clone().unwrap_or_default();
        if hb.machine_id != to.machine_id || hb.user_id != to.user_id {
            return Err("its agent answered for another machine".into());
        }
        let revoked = app.db.machine_cert_seen(&fp);
        if let Some(m) = app.db.machine(&to.machine_id) {
            record_revoked(app, &Who::system("control_plane"), &m, "rotated", &revoked);
        }
        Ok(hb)
    }
    .await;
    app.db.machine_agent_seen(
        &to.machine_id,
        res.as_ref()
            .map(|h| h.version.as_str())
            .map_err(String::as_str),
    );
    if let Ok(hb) = &res {
        super::upkeep::observe(app, &to.machine_id, hb);
    }
    res
}

/// The error and its causes (TLS refusals are in there), without the URL.
pub(super) fn without_url(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut s = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(inner) = src {
        s = format!("{s}: {inner}");
        src = inner.source();
    }
    s
}

/// The most botd keeps of an agent's heartbeat or refusal.
pub(super) const MAX_REPLY: usize = 1 << 20;
/// The largest event a machine may send: one line of harness output, or the end of a
/// run with the files it sends back.
pub const MAX_EVENT: usize = 16 << 20;

/// The body, unless it is longer than `max` or breaks off. A machine's certificate
/// says who answered, not that the answer is sane.
pub(super) async fn read_capped(r: &mut reqwest::Response, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match r.chunk().await {
            Ok(Some(c)) if out.len() + c.len() <= max => out.extend_from_slice(&c),
            Ok(None) => return Some(out),
            _ => return None,
        }
    }
}

fn take_events(buf: &mut Vec<u8>, chunk: &[u8]) -> Option<Vec<JobEvent>> {
    take_lines(buf, chunk)
}

/// The whole events in `buf` once `chunk` is added; `buf` keeps the unfinished line.
/// Lines that aren't events are skipped. None: a line, finished or not, is over
/// `MAX_EVENT`.
pub(super) fn take_lines<T: serde::de::DeserializeOwned>(buf: &mut Vec<u8>, chunk: &[u8]) -> Option<Vec<T>> {
    // What was already in `buf` has no newline: search only what's new.
    let mut from = buf.len();
    buf.extend_from_slice(chunk);
    let mut events = Vec::new();
    while let Some(i) = buf[from..].iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = buf.drain(..=from + i).collect();
        from = 0;
        if line.len() > MAX_EVENT + 1 {
            return None;
        }
        if let Ok(ev) = serde_json::from_slice::<T>(&line) {
            events.push(ev);
        }
    }
    (buf.len() <= MAX_EVENT).then_some(events)
}

/// Hands jobs to a user's machine over mutual TLS, to that machine's own pinned
/// certificate only, and streams back what happens (ADR 0036).
pub struct Mtls(pub Arc<Enrollment>);

impl Mtls {
    async fn stream(
        &self,
        to: &Assigned,
        job: JobRequest,
        mut abort: watch::Receiver<AbortReason>,
        tx: &mpsc::Sender<JobEvent>,
    ) -> Result<(), String> {
        let address = to
            .address
            .as_deref()
            .ok_or("your computer has no address yet")?;
        let client = self.0.job_client(to.pins.clone())?;
        let job_id = job.job_id.clone();
        let mut r = client
            .post(self.0.agent_url(address, "/v1/jobs"))
            .json(&job)
            .send()
            .await
            .map_err(|e| format!("Your computer didn't take the job: {}.", without_url(e)))?;
        if !r.status().is_success() {
            let code = r.status().as_u16();
            let why = read_capped(&mut r, MAX_REPLY)
                .await
                .and_then(|b| serde_json::from_slice::<wire::ErrorReply>(&b).ok())
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(format!("Your computer turned the job down ({code}): {why}"));
        }
        // Whenever botd stops listening early, the machine is told to stop too.
        let stop_there = |reason: String| {
            let (e, pins, address, id) = (
                self.0.clone(),
                to.pins.clone(),
                address.to_string(),
                job_id.clone(),
            );
            tokio::spawn(async move {
                if let Ok((c, _)) = e.pinned(pins) {
                    let url = e.agent_url(&address, &format!("/v1/jobs/{id}/abort"));
                    let _ = c
                        .post(url)
                        .json(&wire::AbortRequest { reason })
                        .send()
                        .await;
                }
            });
        };
        let too_much = || {
            stop_there("too much output".into());
            Err(format!(
                "Your computer sent more than {} MiB in one go, so I stopped listening.",
                MAX_EVENT >> 20
            ))
        };
        let mut buf: Vec<u8> = Vec::new();
        let mut deadline: Option<tokio::time::Instant> = None;
        loop {
            let give_up = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                chunk = r.chunk() => match chunk {
                    Ok(Some(bytes)) => {
                        let Some(events) = take_events(&mut buf, &bytes) else {
                            return too_much();
                        };
                        for ev in events {
                            if !matches!(ev, JobEvent::Ping) && tx.send(ev).await.is_err() {
                                stop_there("botd stopped listening".into());
                                return Ok(());
                            }
                        }
                    }
                    Ok(None) => return Ok(()),
                    Err(e) => {
                        stop_there("lost the stream".into());
                        return Err(format!("Lost your computer during the run: {}.", without_url(e)));
                    }
                },
                reason = async { abort.wait_for(|r| r.is_some()).await.ok().and_then(|r| *r) }, if deadline.is_none() => {
                    deadline = Some(tokio::time::Instant::now() + ABORT_GRACE);
                    stop_there(reason.unwrap_or("stopped").to_string());
                }
                _ = give_up => return Err("Your computer didn't end the run when asked; I let go of it.".into()),
            }
        }
    }
}

impl MachineLink for Mtls {
    fn name(&self) -> &'static str {
        "mtls"
    }

    fn check<'a>(&'a self, app: &'a App, to: &'a Assigned, bins: &'a [&'a str]) -> Checked<'a> {
        Box::pin(probe(app, &self.0, to, bins))
    }

    fn run<'a>(
        &'a self,
        to: &'a Assigned,
        job: JobRequest,
        abort: watch::Receiver<AbortReason>,
        tx: mpsc::Sender<JobEvent>,
    ) -> Ran<'a> {
        Box::pin(async move {
            let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (fwd_tx, mut fwd_rx) = mpsc::channel::<JobEvent>(64);
            let watch_end = {
                let (ended, tx) = (ended.clone(), tx.clone());
                async move {
                    while let Some(ev) = fwd_rx.recv().await {
                        if matches!(
                            ev,
                            JobEvent::Exit { .. }
                                | JobEvent::Cleanup { .. }
                                | JobEvent::Error { .. }
                        ) {
                            ended.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            };
            let run = async move {
                let res = self.stream(to, job, abort, &fwd_tx).await;
                drop(fwd_tx);
                res
            };
            let (res, ()) = tokio::join!(run, watch_end);
            let message = match res {
                Err(m) => Some(m),
                Ok(()) if !ended.load(std::sync::atomic::Ordering::SeqCst) => {
                    Some("Your computer stopped answering before the run finished.".into())
                }
                Ok(()) => None,
            };
            if let Some(message) = message {
                let _ = tx.send(JobEvent::Error { message }).await;
            }
        })
    }
}

// Admin API, under `/api/users/{key}/machine` (admin only, rbac::classify).

pub(super) fn need(cp: &ControlPlane) -> Res<&Arc<Enrollment>> {
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
        assert!(with(&[("MACHINE_ENROLL_TIMEOUT_MINUTES", "20")]).is_err());
        assert!(with(&[("MACHINE_HARNESSES", "claude")]).is_err(), "harnesses need enrollment");
        assert!(with(&[("MACHINE_AGENT_UPGRADES", "auto")]).is_err());
        let e = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_HARNESSES", "pi")]).unwrap().unwrap();
        assert!(e.upkeep.plan.is_some() && e.describe().contains("harnesses on machines: pi@1.5.2; agent upgrades: manual"), "{}", e.describe());
        assert!(with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_HARNESSES", "nope")]).is_err());
        let e = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443")]).unwrap().unwrap();
        assert!(!e.logins && e.folder.is_none() && !e.bot_user, "logins, folder copies and the Bots' user are off unless asked");
        assert!(e.describe().contains("Bots' own user off"), "{}", e.describe());
        for v in ["MACHINE_HARNESS_LOGINS", "MACHINE_FOLDER_SYNC", "MACHINE_FOLDER_SYNC_MAX_MB", "MACHINE_BOT_USER"] {
            let vars: &'static [(&'static str, &'static str)] = Box::leak(Box::new([(v, "on")]));
            assert!(with(vars).is_err(), "{v} needs enrollment");
        }
        let e = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_HARNESS_LOGINS", "on"), ("MACHINE_FOLDER_SYNC", "on")]).unwrap().unwrap();
        assert!(e.logins && e.folder.as_ref().is_some_and(|f| f.max_bytes == 2048 << 20), "{}", e.describe());
        assert!(with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_HARNESS_LOGINS", "yes")]).is_err());
        let e = with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_BOT_USER", "on")]).unwrap().unwrap();
        assert!(e.bot_user && e.describe().contains("Bots' own user on"), "{}", e.describe());
        assert!(with(&[("MACHINE_CONTROL_URL", "https://cp.example:8443"), ("MACHINE_BOT_USER", "yes")]).is_err());
        for (raw, ok) in [("", Some(15)), ("5", Some(5)), ("60", Some(60)), ("4", None), ("61", None), ("soon", None)] {
            let vars: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
                ("MACHINE_CONTROL_URL", "https://cp.example:8443"),
                ("MACHINE_ENROLL_TIMEOUT_MINUTES", raw),
            ]));
            assert_eq!(
                with(vars).ok().flatten().map(|e| e.enroll_timeout_ms / 60_000),
                ok,
                "{raw}"
            );
        }
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
            "ExecStart=/usr/local/lib/superbot/superbot-machine run",
            "ExecStartPre=-/usr/local/lib/superbot/agent-guard",
            "ReadWritePaths=/etc/superbot /usr/local/lib/superbot",
            &format!("path: {GUARD_PATH}"),
        ] {
            assert!(ud.contains(want), "{want}\n{ud}");
        }
        assert!(ud.contains(&indent_lines(GUARD)), "the guard, as written");
        assert!(
            !ud.contains("runcmd"),
            "no download when botd has no agent to serve"
        );
        e.agent = Some((Bytes::from_static(b"agent"), "ab".repeat(32)));
        let ud = e.user_data(&m, "sbe_tok");
        let script = firstboot_in(&ud);
        for want in [
            format!("echo \"{}  $bin.new\" | sha256sum -c -", "ab".repeat(32)),
            "--cacert /etc/superbot/ca.pem -o \"$bin.new\" \"https://127.0.0.1:1/v1/agent\"".into(),
            "SUPERBOT_ENROLL_TOKEN_FILE=/etc/superbot/enroll-token SUPERBOT_STATE_DIR=/var/lib/superbot-machine \"$bin\" enroll".into(),
            "systemctl enable superbot-machine".into(),
            "rm -f /var/lib/cloud/instance/user-data.txt".into(),
            "bin=$dir/superbot-machine".into(),
            "ln -sfn \"$bin\" /usr/local/bin/superbot-machine".into(),
        ] {
            assert!(script.contains(&want), "{want}\n{script}");
        }
        let order = ["sha256sum -c", "systemctl enable", "\" enroll;", "rm -f /var/lib/cloud", "systemctl start"]
            .map(|s| script.find(s).unwrap_or_else(|| panic!("{s}")));
        assert!(order.windows(2).all(|w| w[0] < w[1]), "verify, install, enroll, scrub, start: {order:?}");
        assert!(
            ud.ends_with(&format!("runcmd:\n  - [{FIRSTBOOT_PATH}]\n")),
            "{ud}"
        );
        assert_eq!(
            ud.matches("sbe_tok").count(),
            1,
            "the token is written to its file only, never into a command"
        );
        assert!(!script.contains("set -x"), "the script's output is logged");
        assert!(!script.contains("botctl"), "no botctl to install");
        assert!(!script.contains("{botctl}"), "{script}");
        let check = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));

        e.botctl = Some((Bytes::from_static(b"botctl"), "cd".repeat(32)));
        let script = firstboot_in(&e.user_data(&m, "sbe_tok"));
        for want in [
            format!("echo \"{}  $ctl.new\" | sha256sum -c -", "cd".repeat(32)),
            "--cacert /etc/superbot/ca.pem -o \"$ctl.new\" \"https://127.0.0.1:1/v1/botctl\"".into(),
            format!("echo \"{}  $bin.new\" | sha256sum -c -", "ab".repeat(32)),
            "ctl=$dir/botctl".into(),
            "ln -sfn \"$ctl\" /usr/local/bin/botctl".into(),
        ] {
            assert!(script.contains(&want), "{want}\n{script}");
        }
        let order = ["/v1/botctl", "/v1/agent", "systemctl start"]
            .map(|s| script.find(s).unwrap_or_else(|| panic!("{s}")));
        assert!(order.windows(2).all(|w| w[0] < w[1]), "botctl before the agent starts: {order:?}");
        let check = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
        let ud = e.user_data(&m, "sbe_tok");
        assert!(ud.contains("StateDirectoryMode=0700") && !ud.contains("useradd"), "no Bots' user unless asked");

        // MACHINE_BOT_USER (ADR 0043): the user is made at first boot, and the state
        // folder lets it through to its home.
        e.bot_user = true;
        let ud = e.user_data(&m, "sbe_tok");
        assert!(ud.contains("StateDirectoryMode=0711") && !ud.contains("StateDirectoryMode=0700"), "{ud}");
        let script = firstboot_in(&ud);
        assert!(
            script.contains("id -u superbot-bots >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin --comment \"SuperBot Bots\" --home-dir /var/lib/superbot-machine/home superbot-bots"),
            "{script}"
        );
        let order = ["useradd", "/v1/agent", "systemctl start"].map(|s| script.find(s).unwrap_or_else(|| panic!("{s}")));
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
        let check = std::process::Command::new("sh").args(["-n", "-c", &script]).output().unwrap();
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    }

    #[test]
    fn job_events_are_split_by_line_and_capped() {
        let line = |ev: &JobEvent| format!("{}\n", serde_json::to_string(ev).unwrap());
        let mut buf = Vec::new();
        let started = line(&JobEvent::Started);
        let (a, b) = started.split_at(4);
        assert_eq!(take_events(&mut buf, a.as_bytes()), Some(vec![]));
        let ping = line(&JobEvent::Ping);
        assert_eq!(
            take_events(&mut buf, format!("{b}not json\n{ping}").as_bytes()),
            Some(vec![JobEvent::Started, JobEvent::Ping])
        );
        assert!(buf.is_empty());

        let huge = line(&JobEvent::Line { line: "a".repeat(MAX_EVENT) });
        assert_eq!(
            take_events(&mut Vec::new(), huge.as_bytes()),
            None,
            "a whole line over the cap, in one chunk"
        );
        assert_eq!(
            take_events(&mut Vec::new(), &huge.as_bytes()[..MAX_EVENT + 1]),
            None,
            "the start of one"
        );
        let most = "a".repeat(MAX_EVENT - 64);
        assert_eq!(
            take_events(&mut Vec::new(), line(&JobEvent::Line { line: most.clone() }).as_bytes()),
            Some(vec![JobEvent::Line { line: most }])
        );
    }

    fn indent_lines(s: &str) -> String {
        s.lines().map(|l| format!("      {l}\n")).collect()
    }

    /// The unit's guard, run as systemd would before each start, after an upgrade.
    #[test]
    fn the_guard_puts_the_old_agent_back_after_three_failed_starts() {
        let (state, dir) = (crate::db::temp_path("guard-state"), crate::db::temp_path("guard-bin"));
        let start = || {
            let out = std::process::Command::new("sh")
                .args(["-c", GUARD])
                .env("STATE_DIRECTORY", &state)
                .env("SUPERBOT_AGENT_DIR", &dir)
                .output()
                .unwrap();
            assert!(out.status.success(), "the guard never stops a start");
        };
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
        for (f, body) in [("superbot-machine", "new"), ("superbot-machine.prev", "old"), ("botctl", "new ctl"), ("botctl.prev", "old ctl")] {
            std::fs::write(dir.join(f), body).unwrap();
        }
        start();
        assert_eq!(read("superbot-machine"), "new", "no trial, nothing to do");
        std::fs::write(state.join("upgrade-trial.json"), "{}").unwrap();
        for n in 1..=3 {
            start();
            assert_eq!(read("superbot-machine"), "new", "start {n} of the new agent");
        }
        start();
        assert_eq!((read("superbot-machine"), read("botctl")), ("old".into(), "old ctl".into()), "the fourth start runs the old one");
        assert!(!dir.join("superbot-machine.prev").exists());
        start();
        assert_eq!(read("superbot-machine"), "old", "nothing left to put back");
    }

    /// The first-boot script as cloud-init will write it.
    fn firstboot_in(ud: &str) -> String {
        let at = ud.find(&format!("path: {FIRSTBOOT_PATH}")).unwrap();
        ud[at..]
            .lines()
            .skip(3)
            .take_while(|l| l.starts_with("      "))
            .map(|l| format!("{}\n", &l[6..]))
            .collect()
    }
}
