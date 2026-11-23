//! The machine agent (`superbot-machine`, ADR 0031, ADR 0036): it enrolls with the
//! control plane, keeps its certificate fresh, and answers botd over mutual TLS: a
//! heartbeat, and jobs, each one harness run for one of its user's Bots, streamed
//! back as it happens. It knows nothing of harnesses: botd builds each command. Bots
//! on the machine reach botd's API (approvals, `botctl`) through the agent's relay
//! on loopback, which forwards over mutual TLS. It also runs harness logins and takes
//! copies of the user's folder (ADR 0041), and says what the homes on it hold, for
//! the owner's storage limit (ADR 0105). Shared by the binary and botd's tests, so it
//! uses nothing of botd's but its sibling modules, `sandbox` and `walk`.
//!
//! Settings (cloud-init writes them to /etc/superbot/machine.env):
//! - `SUPERBOT_CONTROL_URL`: botd's machine port, `https://<host>:<port>`.
//! - `SUPERBOT_MACHINE_ID`: this machine's id at the control plane.
//! - `SUPERBOT_CA_FILE`: the control-plane CA (default /etc/superbot/ca.pem).
//! - `SUPERBOT_ENROLL_TOKEN`, or `SUPERBOT_ENROLL_TOKEN_FILE` (deleted once used).
//! - `SUPERBOT_AGENT_LISTEN`: default 0.0.0.0:7443.
//! - `STATE_DIRECTORY` (systemd) or `SUPERBOT_STATE_DIR`: where the key and
//!   certificate live (default /var/lib/superbot-machine).
//! - `SUPERBOT_HOME`: where Bots work (default `<state dir>/home`).
//! - `SUPERBOT_AGENT_API`: the relay to botd's API, loopback (default 127.0.0.1:7444).
//! - `SUPERBOT_TOOLS`: where harness CLIs are installed (ADR 0039; default
//!   `<state dir>/tools`).
//! - `SUPERBOT_HARNESS_PATH`: PATH for harnesses (default `<tools>/bin`, then
//!   `<home>/.local/bin`, then the system's). A harness counts as installed only if it
//!   resolves to a file under the tools, the home or `PROGRAM_ROOTS`.
//! - `SUPERBOT_MAX_JOBS`: jobs at once (default 32), a backstop: botd keeps the cap by
//!   the owner's tier and queues the rest (ADR 0073).
//! - `SUPERBOT_AGENT_BIN`: this binary, replaced by upgrades (ADR 0039; default
//!   `/usr/local/lib/superbot/superbot-machine`).
//! - `SUPERBOT_BOT_USER`: the OS user Bots run as once botd asks (ADR 0043; default
//!   `superbot-bots`). Never root, nor the agent's own user.
//! - `SUPERBOT_MAX_SCREENS`: Bots' screens shown at once (ADR 0045; default 4).
//! - `SUPERBOT_TEAMMATES`: where teammates' own homes are, for their runs of the
//!   user's shared Bots (ADR 0048; default `<state dir>/teammates`).
//! - `SUPERBOT_RUN_CGROUPS`: `delegated` when systemd delegates the unit its cgroup,
//!   so each run can be held to its limits in a cgroup of its own (ADR 0135).

use super::cgroup::{self, Cgroups};
use super::display::{self, Screens};
use super::egress_allow;
use super::job;
use super::landing::Landing;
use super::pki::{self, Peer};
use super::runas::{self, Ids};
use super::seccomp;
use super::team_rules;
use super::teammates::{Files, Teammate, Teammates};
use super::terminal::Logins;
use super::tools::Tools;
use super::upgrade::{self, Upgrader};
use super::wire;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Query, RawQuery, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How often a job stream says it's alive while the harness is quiet.
pub const PING_EVERY: Duration = Duration::from_secs(15);
/// The largest request a Bot may send botd through the relay.
pub const MAX_RELAY_BODY: usize = 32 << 20;
/// Where the machine image installs botctl.
pub const BOTCTL: &str = "/usr/local/bin/botctl";
/// Where cloud-init installs the agent (ADR 0039): a folder the unit lets it write,
/// so it can replace itself. `/usr/local/bin/superbot-machine` links here.
pub const AGENT_BIN: &str = "/usr/local/lib/superbot/superbot-machine";

#[derive(Clone)]
pub struct Config {
    pub control_url: String,
    pub machine_id: String,
    pub ca_pem: String,
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub token: Option<Zeroizing<String>>,
    pub token_file: Option<PathBuf>,
    /// HOME for harnesses, holding everything Bots keep here.
    pub home: PathBuf,
    /// The relay to botd's API. Loopback: it's for Bots on this machine.
    pub api_listen: SocketAddr,
    pub botctl: PathBuf,
    /// PATH for harnesses and what they run.
    pub harness_path: String,
    pub max_jobs: usize,
    /// Where harness CLIs are installed (ADR 0039).
    pub tools: PathBuf,
    /// This agent's own binary, which an upgrade replaces.
    pub exe: PathBuf,
    /// The OS user Bots run as once botd asks (ADR 0043).
    pub bot_user: String,
    /// Lets that be this agent's own user: only for tests, which can't make users.
    pub allow_own_user: bool,
    /// Bots' screens (ADR 0045).
    pub screens: display::Settings,
    /// Holds each teammate's own home (ADR 0048).
    pub teammates: PathBuf,
    /// Tests can't make users: every teammate runs as this existing one instead.
    pub teammate_stand_in: Option<String>,
    /// systemd delegates this unit its cgroup (ADR 0135).
    pub run_cgroups: bool,
    /// The nft that loads the outbound allow-list (ADR 0135).
    pub nft: PathBuf,
    /// The first boot's harness egress script (ADR 0126), which a team network's subnet
    /// is let through in (ADR 0202).
    pub egress_script: PathBuf,
}

/// Where harnesses and botctl may live, besides the Bots' home: the system's program
/// directories. A PATH entry elsewhere (say `/tmp`) isn't looked in.
const PROGRAM_ROOTS: [&str; 6] = ["/usr", "/opt", "/bin", "/sbin", "/snap", "/nix"];

/// Whether `p`, with symlinks resolved, is an executable file under one of `roots`.
fn runnable(p: &Path, roots: &[PathBuf]) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(p) = p.canonicalize() else {
        return false;
    };
    for root in roots {
        if p.starts_with(root) {
            return std::fs::metadata(&p)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
        }
    }
    false
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let var = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let control_url = var("SUPERBOT_CONTROL_URL")
            .ok_or("set SUPERBOT_CONTROL_URL (botd's machine port, https://<host>:<port>)")?
            .trim_end_matches('/')
            .to_string();
        if !control_url.starts_with("https://") {
            return Err("SUPERBOT_CONTROL_URL must be https://".into());
        }
        let machine_id = var("SUPERBOT_MACHINE_ID").ok_or("set SUPERBOT_MACHINE_ID")?;
        if machine_id.len() > 64
            || !machine_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("SUPERBOT_MACHINE_ID isn't a machine id".into());
        }
        let ca_file = var("SUPERBOT_CA_FILE").unwrap_or_else(|| "/etc/superbot/ca.pem".into());
        let ca_pem = std::fs::read_to_string(&ca_file).map_err(|e| format!("{ca_file}: {e}"))?;
        pki::cert_der(&ca_pem).map_err(|e| format!("{ca_file}: {e}"))?;
        let state_dir = PathBuf::from(
            var("STATE_DIRECTORY")
                .and_then(|d| d.split(':').next().map(String::from))
                .or_else(|| var("SUPERBOT_STATE_DIR"))
                .unwrap_or_else(|| "/var/lib/superbot-machine".into()),
        );
        let listen = var("SUPERBOT_AGENT_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:7443".into())
            .parse()
            .map_err(|_| "SUPERBOT_AGENT_LISTEN must be <ip>:<port>")?;
        let api_listen: SocketAddr = var("SUPERBOT_AGENT_API")
            .unwrap_or_else(|| "127.0.0.1:7444".into())
            .parse()
            .map_err(|_| "SUPERBOT_AGENT_API must be <ip>:<port>")?;
        if !api_listen.ip().is_loopback() {
            return Err("SUPERBOT_AGENT_API must be a loopback address".into());
        }
        let home = var("SUPERBOT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("home"));
        if !home.is_absolute() {
            return Err("SUPERBOT_HOME must be an absolute path".into());
        }
        let tools = var("SUPERBOT_TOOLS")
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("tools"));
        if !tools.is_absolute() {
            return Err("SUPERBOT_TOOLS must be an absolute path".into());
        }
        let harness_path = var("SUPERBOT_HARNESS_PATH").unwrap_or_else(|| {
            format!(
                "{}/bin:{}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                tools.display(),
                home.display()
            )
        });
        let max_jobs = var("SUPERBOT_MAX_JOBS")
            .map(|v| v.parse().map_err(|_| "SUPERBOT_MAX_JOBS must be a number"))
            .transpose()?
            .unwrap_or(32)
            .max(1);
        let bot_user = var("SUPERBOT_BOT_USER").unwrap_or_else(|| wire::BOT_USER.into());
        if !runas::plain_user(&bot_user) || bot_user == "root" {
            return Err("SUPERBOT_BOT_USER must be a plain user name, not root".into());
        }
        let max_screens = var("SUPERBOT_MAX_SCREENS")
            .map(|v| v.parse::<u32>().map_err(|_| "SUPERBOT_MAX_SCREENS must be a number"))
            .transpose()?
            .unwrap_or(4)
            .clamp(1, 50);
        let teammates = var("SUPERBOT_TEAMMATES")
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("teammates"));
        if !teammates.is_absolute() || teammates.starts_with(&home) || home.starts_with(&teammates) {
            return Err("SUPERBOT_TEAMMATES must be an absolute path apart from SUPERBOT_HOME".into());
        }
        Ok(Config {
            control_url,
            machine_id,
            ca_pem,
            state_dir,
            listen,
            token: var("SUPERBOT_ENROLL_TOKEN").map(Zeroizing::new),
            token_file: var("SUPERBOT_ENROLL_TOKEN_FILE").map(PathBuf::from),
            home,
            api_listen,
            botctl: BOTCTL.into(),
            harness_path,
            max_jobs,
            tools,
            exe: var("SUPERBOT_AGENT_BIN").unwrap_or_else(|| AGENT_BIN.into()).into(),
            bot_user,
            allow_own_user: false,
            screens: display::Settings {
                max: max_screens,
                ..display::Settings::default()
            },
            teammates,
            teammate_stand_in: None,
            run_cgroups: match var("SUPERBOT_RUN_CGROUPS").as_deref() {
                None | Some("off") => false,
                Some("delegated") => true,
                Some(_) => return Err("SUPERBOT_RUN_CGROUPS must be delegated or off".into()),
            },
            nft: "nft".into(),
            egress_script: team_rules::EGRESS_SCRIPT.into(),
        })
    }

    /// Where Bots work here, as botd is told.
    pub fn layout(&self) -> wire::Layout {
        let p = |p: PathBuf| p.display().to_string();
        wire::Layout {
            home: p(self.home.clone()),
            workspace: p(self.home.join("work")),
            bots: p(self.home.join("bots")),
            user_file: p(self.home.join("USER.md")),
            api: format!("http://{}", self.api_listen),
            botctl: runnable(&self.botctl, &self.roots()).then(|| p(self.botctl.clone())),
            // Checked as the Bots' user in the heartbeat's `layout`.
            sandbox: None,
            caches: crate::sandbox::caches(&self.home).into_iter().map(p).collect(),
        }
    }

    /// `PROGRAM_ROOTS`, the tools and the home, canonicalized; those that don't exist
    /// are left out.
    fn roots(&self) -> Vec<PathBuf> {
        PROGRAM_ROOTS
            .iter()
            .map(Path::new)
            .chain([self.tools.as_path(), self.home.as_path()])
            .filter_map(|r| r.canonicalize().ok())
            .collect()
    }

    /// The environment every job starts from; nothing of the agent's own. With
    /// `user`, jobs run as the Bots' user.
    fn host(&self, user: Option<Ids>) -> job::Host {
        let mut env = BTreeMap::from([
            ("HOME".to_string(), self.home.display().to_string()),
            ("PATH".to_string(), self.harness_path.clone()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]);
        if user.is_some() {
            env.insert("USER".into(), self.bot_user.clone());
            env.insert("LOGNAME".into(), self.bot_user.clone());
            env.insert("TMPDIR".into(), self.home.join(TMP).display().to_string());
        }
        job::Host {
            clear_env: true,
            remove: Vec::new(),
            env,
            user,
            limits: None,
        }
    }

    /// The environment a teammate's jobs and logins start from: their own home and user
    /// (ADR 0048), with their temporary folder made first, as them (ADR 0145).
    fn teammate_host(&self, t: &Teammate) -> Result<job::Host, String> {
        own_tmp(&t.home, t.ids)?;
        let env = BTreeMap::from([
            ("HOME".to_string(), t.home.display().to_string()),
            ("PATH".to_string(), self.harness_path.clone()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
            ("USER".to_string(), t.user.clone()),
            ("LOGNAME".to_string(), t.user.clone()),
            ("TMPDIR".to_string(), t.home.join(TMP).display().to_string()),
        ]);
        Ok(job::Host { clear_env: true, remove: Vec::new(), env, user: Some(t.ids), limits: None })
    }

    /// Why `ids` can't be the Bots' user, if it can't.
    fn check_bot_ids(&self, ids: Ids) -> Result<(), String> {
        if ids.uid == 0 || ids.gid == 0 {
            return Err(format!("{} is root or in root's group; Bots can't run as it.", self.bot_user));
        }
        // SAFETY: no arguments.
        let own = ids.uid == unsafe { libc::geteuid() };
        if own && !self.allow_own_user {
            return Err(format!("{} is the agent's own user; Bots need their own.", self.bot_user));
        }
        // Tests stand their own user in, whatever its groups.
        if !own && let Some(why) = runas::privileged(&self.bot_user, ids) {
            return Err(format!("{} {why}; Bots run only as an unprivileged user.", self.bot_user));
        }
        Ok(())
    }

    /// The state folder lets the Bots' user through to its home and the tools; the
    /// tools are readable by it. systemd makes the folder 0700 at every start.
    fn open_paths(&self, tools: &Tools) -> Result<(), String> {
        runas::chmod_dir(&self.state_dir, 0o711).map_err(|e| format!("{}: {e}", self.state_dir.display()))?;
        tools.open_up()
    }

    /// Whether `bin` is an executable on the harness PATH, under `roots`.
    fn has(&self, bin: &str) -> bool {
        let roots = self.roots();
        self.harness_path
            .split(':')
            .any(|dir| runnable(&Path::new(dir).join(bin), &roots))
    }

    fn ca(&self) -> CertificateDer<'static> {
        pki::cert_der(&self.ca_pem).expect("checked when loaded")
    }

    fn token(&self) -> Result<Zeroizing<String>, String> {
        if let Some(t) = &self.token {
            return Ok(t.clone());
        }
        let f = self.token_file.as_ref().ok_or(
            "not enrolled, and there's no enrollment token (SUPERBOT_ENROLL_TOKEN or _FILE)",
        )?;
        let t = Zeroizing::new(
            std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?,
        );
        Ok(Zeroizing::new(t.trim().to_string()))
    }
}

/// This machine's key and the certificate botd issued for it.
pub struct Identity {
    pub cert_pem: String,
    key_pem: Zeroizing<String>,
    pub user_id: String,
    pub machine_id: String,
    pub fingerprint: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl Identity {
    pub fn new(
        cert_pem: String,
        key_pem: Zeroizing<String>,
        machine_id: &str,
    ) -> Result<Identity, String> {
        let der = pki::cert_der(&cert_pem)?;
        let f = pki::facts(&der).ok_or("the certificate doesn't parse")?;
        let ids: Vec<_> = f
            .uris
            .iter()
            .filter_map(|u| pki::parse_machine_uri(u))
            .collect();
        let [(user_id, m)] = ids.as_slice() else {
            return Err("the certificate doesn't name one machine".into());
        };
        if m != machine_id {
            return Err(format!(
                "the certificate is for machine {m}, not {machine_id}"
            ));
        }
        pki::key_der(&key_pem)?;
        let key = rcgen::KeyPair::from_pem(&key_pem).map_err(|_| "the key doesn't parse")?;
        if rcgen::PublicKeyData::subject_public_key_info(&key) != f.spki {
            return Err("the key isn't the certificate's".into());
        }
        Ok(Identity {
            user_id: user_id.clone(),
            machine_id: m.clone(),
            fingerprint: pki::fingerprint(&der),
            not_before: f.not_before,
            not_after: f.not_after,
            cert_pem,
            key_pem,
        })
    }

    pub fn chain(
        &self,
    ) -> (
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        (
            vec![pki::cert_der(&self.cert_pem).expect("checked")],
            pki::key_der(&self.key_pem).expect("checked"),
        )
    }

    /// A third of its life left: time for a new one.
    pub fn due(&self, at: i64) -> bool {
        at >= self.not_after - (self.not_after - self.not_before) / 3
    }
}

fn write_private(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

const IDENTITY_FILE: &str = "identity.pem";
const END_CERT: &str = "-----END CERTIFICATE-----";

/// The certificate and its key in one file, replaced in one rename, so a crash leaves
/// either the old pair or the new one, never a key beside another key's certificate.
fn save(dir: &Path, id: &Identity) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let both = Zeroizing::new(format!(
        "{}\n{}",
        id.cert_pem.trim_end(),
        id.key_pem.as_str()
    ));
    write_private(&dir.join(IDENTITY_FILE), &both, 0o600)
}

/// The saved identity, if there is one, its key is its certificate's, and it is for
/// this machine.
pub fn load(cfg: &Config) -> Option<Identity> {
    let both = Zeroizing::new(std::fs::read_to_string(cfg.state_dir.join(IDENTITY_FILE)).ok()?);
    let at = both.find(END_CERT)? + END_CERT.len();
    let (cert, key) = both.split_at(at);
    Identity::new(
        format!("{cert}\n"),
        Zeroizing::new(key.trim_start().to_string()),
        &cfg.machine_id,
    )
    .ok()
}

fn client(cfg: &Config, id: Option<&Identity>) -> Result<reqwest::Client, String> {
    let config = pki::client_config(&cfg.ca(), id.map(Identity::chain))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())
}

/// Why a call to botd failed, and whether trying again soon could help.
#[derive(Debug)]
pub struct Failed {
    pub message: String,
    pub permanent: bool,
}

async fn certificate(
    cfg: &Config,
    req: reqwest::RequestBuilder,
    key: Zeroizing<String>,
) -> Result<Identity, Failed> {
    let transient = |message: String| Failed {
        message,
        permanent: false,
    };
    let r = req.send().await.map_err(|e| {
        transient(format!(
            "couldn't reach the control plane: {}",
            e.without_url()
        ))
    })?;
    let code = r.status();
    if !code.is_success() {
        let msg = r
            .json::<wire::ErrorReply>()
            .await
            .map(|e| e.error)
            .unwrap_or_default();
        return Err(Failed {
            message: format!("the control plane answered {}: {msg}", code.as_u16()),
            permanent: code.is_client_error(),
        });
    }
    let reply: wire::CertificateReply = r
        .json()
        .await
        .map_err(|_| transient("the control plane's answer wasn't a certificate".into()))?;
    let id = Identity::new(reply.certificate, key, &cfg.machine_id).map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    if id.user_id != reply.user_id {
        return Err(Failed {
            message: "the certificate names another user".into(),
            permanent: true,
        });
    }
    save(&cfg.state_dir, &id).map_err(transient)?;
    Ok(id)
}

/// Swaps the one-time token for a certificate. The key is made here and never leaves.
pub async fn enroll(cfg: &Config) -> Result<Identity, Failed> {
    let token = cfg.token().map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    let (key, csr) = pki::new_request(&cfg.machine_id).map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    let http = client(cfg, None).map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    let body = wire::EnrollRequest {
        machine_id: cfg.machine_id.clone(),
        token: token.to_string(),
        csr,
    };
    let id = certificate(
        cfg,
        http.post(format!("{}/v1/enroll", cfg.control_url))
            .json(&body),
        Zeroizing::new(key.serialize_pem()),
    )
    .await?;
    if let Some(f) = &cfg.token_file {
        let _ = std::fs::remove_file(f);
    }
    Ok(id)
}

/// A new certificate for a new key, asked for with the current one.
pub async fn rotate(cfg: &Config, current: &Identity) -> Result<Identity, Failed> {
    let (key, csr) = pki::new_request(&cfg.machine_id).map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    let http = client(cfg, Some(current)).map_err(|message| Failed {
        message,
        permanent: true,
    })?;
    let url = format!(
        "{}/v1/machines/{}/certificate",
        cfg.control_url, cfg.machine_id
    );
    certificate(
        cfg,
        http.post(url).json(&wire::RotateRequest { csr }),
        Zeroizing::new(key.serialize_pem()),
    )
    .await
}

/// How the control plane sees this machine, asked with its certificate.
pub async fn status(cfg: &Config, id: &Identity) -> Result<wire::MachineStatus, Failed> {
    let transient = |message: String| Failed {
        message,
        permanent: false,
    };
    let http = client(cfg, Some(id)).map_err(transient)?;
    let r = http
        .get(format!(
            "{}/v1/machines/{}",
            cfg.control_url, cfg.machine_id
        ))
        .send()
        .await
        .map_err(|e| {
            transient(format!(
                "couldn't reach the control plane: {}",
                e.without_url()
            ))
        })?;
    let code = r.status();
    if !code.is_success() {
        let msg = r
            .json::<wire::ErrorReply>()
            .await
            .map(|e| e.error)
            .unwrap_or_default();
        return Err(Failed {
            message: format!("the control plane answered {}: {msg}", code.as_u16()),
            permanent: code.is_client_error(),
        });
    }
    r.json()
        .await
        .map_err(|_| transient("the control plane's answer wasn't a status".into()))
}

/// The running agent: its identity, the TLS settings made from it, and its jobs.
pub struct Agent {
    pub cfg: Config,
    current: RwLock<(Arc<Identity>, Arc<ServerConfig>)>,
    /// Running jobs by id.
    jobs: Mutex<HashMap<String, RunningJob>>,
    /// Harness CLIs botd asked for (ADR 0039).
    pub tools: Arc<Tools>,
    /// Replacing this agent with botd's build (ADR 0039).
    pub upgrader: Upgrader,
    /// Harness logins running now, and copies of the user's folder (ADR 0041).
    pub logins: Arc<Logins>,
    pub landing: Arc<Landing>,
    /// True once the agent should exit, for systemd to start it again.
    restart: watch::Sender<bool>,
    /// The Bots' own user, once botd asked for one (ADR 0043).
    bot: RwLock<Bot>,
    /// Bots' screens (ADR 0045).
    pub screens: Arc<Screens>,
    /// Teammates' own users and homes (ADR 0048).
    pub teammates: Arc<Teammates>,
    /// What the Bots' and teammates' homes hold (ADR 0105).
    home_use: Arc<HomeUse>,
    /// Runs' cgroups, or why runs can't be held to limits here (ADR 0135).
    cgroups: Result<Cgroups, String>,
    /// The outbound allow-list botd sent, and how its rules stand (ADR 0135).
    egress: Mutex<Egress>,
    /// One load of the allow-list's rules at a time.
    egress_loading: tokio::sync::Mutex<()>,
    /// How the last change to the team network's subnet in the egress rules went
    /// (ADR 0202).
    team_rules: Mutex<Option<wire::TeamNetworkReport>>,
    /// One such change at a time.
    team_loading: tokio::sync::Mutex<()>,
}

#[derive(Clone, Debug, Default)]
struct Egress {
    policy: wire::EgressPolicy,
    report: wire::EgressReport,
}

const EGRESS_FILE: &str = "egress-policy.json";
/// How often an allow-list's hosts are resolved again.
pub const EGRESS_REFRESH: Duration = Duration::from_secs(300);

/// This process's cgroup, split for runs (ADR 0135), when the unit is delegated it.
fn run_cgroups(cfg: &Config) -> Result<Cgroups, String> {
    if !cfg.run_cgroups {
        return Err("the agent's unit isn't delegated its cgroup: rebuild the machine to hold runs to limits".into());
    }
    let root = Path::new("/sys/fs/cgroup");
    let own = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| format!("/proc/self/cgroup: {e}"))?;
    let base = cgroup::own_base(&own, root).ok_or("this machine has no cgroup v2")?;
    let (cpus, memory) = machine_size(&base);
    Cgroups::setup(&base, cpus, memory)
}

/// The machine's CPUs and memory now, as its runs may use them: an Incus resize
/// changes them under a running agent.
fn machine_size(base: &Path) -> (u32, u64) {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let memory = cgroup::machine_memory(base, Path::new("/sys/fs/cgroup"), &meminfo);
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    (cpus, memory)
}

/// How old the homes' measurement may get before a heartbeat starts another.
pub const HOME_USE_EVERY: Duration = Duration::from_secs(60);

/// What the Bots' and teammates' homes hold, for the owner's storage limit (ADR 0105).
/// Walking them can take a while, so it never happens on a request: a heartbeat says the
/// last measurement and starts another once it's `HOME_USE_EVERY` old, and a job's end
/// starts one at once, so the check before the next run sees what that job wrote. One
/// walk at a time, on its own thread.
#[derive(Default)]
pub struct HomeUse {
    last: Mutex<Option<(std::time::Instant, u64, bool)>>,
    walking: std::sync::atomic::AtomicBool,
    /// Asked for again while a walk ran: that walk may have missed what changed.
    again: std::sync::atomic::AtomicBool,
}

impl HomeUse {
    /// The last measurement: bytes, and whether that's a lower bound.
    pub fn latest(&self) -> Option<(u64, bool)> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).map(|(_, n, partial)| (n, partial))
    }

    /// Walks `roots` unless a walk is running (which then walks again if `now`), or,
    /// unless `now`, the last one is recent.
    pub fn refresh(self: &Arc<Self>, roots: &[PathBuf], now: bool) {
        use std::sync::atomic::Ordering::SeqCst;
        if now {
            self.again.store(true, SeqCst);
        } else if self.last.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|(at, _, _)| at.elapsed() < HOME_USE_EVERY) {
            return;
        }
        if self.walking.swap(true, SeqCst) {
            return;
        }
        let (me, roots) = (self.clone(), roots.to_vec());
        std::thread::spawn(move || {
            loop {
                me.again.store(false, SeqCst);
                let (n, partial) = crate::walk::walk(&roots, crate::walk::MAX_ENTRIES);
                *me.last.lock().unwrap_or_else(|e| e.into_inner()) = Some((std::time::Instant::now(), n, partial));
                me.walking.store(false, SeqCst);
                if !me.again.load(SeqCst) || me.walking.swap(true, SeqCst) {
                    break;
                }
            }
        });
    }
}

struct RunningJob {
    /// Sending true stops it.
    stop: watch::Sender<bool>,
    /// The teammate it runs for (ADR 0048); None: the owner.
    for_user: Option<String>,
}

/// Why `ids` can't be a teammate's user: root, the agent's own, or the Bots' (`bots`).
/// With a stand-in (tests) every teammate is the agent's user, so only root is refused.
fn not_teammates(stand_in: bool, bots: Option<Ids>) -> impl Fn(Ids) -> Result<(), String> {
    move |ids: Ids| {
        if ids.uid == 0 || ids.gid == 0 {
            return Err("a teammate's user can't be root or in root's group".into());
        }
        // SAFETY: no arguments.
        let own = ids.uid == unsafe { libc::geteuid() };
        let bots = bots.is_some_and(|b| ids.uid == b.uid || ids.gid == b.gid);
        if !stand_in && (own || bots) {
            return Err("a teammate's user can't be the agent's or the Bots' user".into());
        }
        if !stand_in {
            let name = runas::name_of(ids.uid).ok_or("a teammate's user has no name")?;
            if let Some(why) = runas::privileged(&name, ids) {
                return Err(format!("{name} {why}; teammates' runs go only to unprivileged users"));
            }
        }
        Ok(())
    }
}

/// Where the Bots' user stands. Once botd has asked, no job runs as root again.
#[derive(Clone, Default)]
struct Bot {
    status: Option<wire::BotUserStatus>,
    /// Set only when ready.
    ids: Option<Ids>,
}

const BOT_USER_FILE: &str = "bot-user.json";

/// The Bots' user, saved before it's handed the home, so a restart part-way picks up
/// where it stopped rather than running as root in a home that may already be its.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedBotUser {
    user: String,
    uid: u32,
    gid: u32,
    /// The whole home is its.
    #[serde(default)]
    handed: bool,
}

fn save_bot_user(cfg: &Config, ids: Ids, handed: bool) -> Result<(), String> {
    let saved = SavedBotUser { user: cfg.bot_user.clone(), uid: ids.uid, gid: ids.gid, handed };
    write_private(&cfg.state_dir.join(BOT_USER_FILE), &serde_json::to_string(&saved).unwrap_or_default(), 0o600)
}

fn bot_failed(user: &str, e: String) -> Bot {
    eprintln!("Bots' user: {e}");
    Bot { status: Some(bot_status(wire::BOT_USER_FAILED, user, None, Some(e))), ids: None }
}

fn bot_status(state: &str, user: &str, uid: Option<u32>, error: Option<String>) -> wire::BotUserStatus {
    wire::BotUserStatus {
        state: state.into(),
        user: user.into(),
        uid,
        error,
        at: now_ms(),
    }
}

/// The saved Bots' user, checked: still there, with the same ids, owning the home.
fn load_bot_user(cfg: &Config, tools: &Tools) -> Bot {
    let path = cfg.state_dir.join(BOT_USER_FILE);
    let saved = match std::fs::read(&path) {
        Ok(b) => match serde_json::from_slice::<SavedBotUser>(&b) {
            Ok(s) => s,
            Err(e) => return bot_failed(&cfg.bot_user, format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // SAFETY: no arguments.
            let me = unsafe { libc::geteuid() };
            return match std::fs::symlink_metadata(&cfg.home) {
                Ok(m) if m.uid() != me => bot_failed(
                    &cfg.bot_user,
                    format!("{} belongs to another user, but no Bots' user is saved.", cfg.home.display()),
                ),
                _ => Bot::default(),
            };
        }
        Err(e) => return bot_failed(&cfg.bot_user, format!("{}: {e}", path.display())),
    };
    let want = Ids { uid: saved.uid, gid: saved.gid };
    let checked = (|| {
        if saved.user != cfg.bot_user {
            return Err(format!("Bots ran as {}, but the agent is set to {}.", saved.user, cfg.bot_user));
        }
        match runas::lookup(&saved.user) {
            Some((ids, _)) if ids == want => {}
            Some(_) => return Err(format!("{} isn't the user it was.", saved.user)),
            None => return Err(format!("{} is gone.", saved.user)),
        }
        cfg.check_bot_ids(want)?;
        let owned = std::fs::symlink_metadata(&cfg.home).is_ok_and(|m| m.is_dir() && m.uid() == want.uid);
        if !saved.handed || !owned {
            runas::hand_over(&cfg.home, want).map_err(|e| format!("{}: {e}", cfg.home.display()))?;
        }
        cfg.open_paths(tools)?;
        if !saved.handed {
            save_bot_user(cfg, want, true)?;
        }
        Ok(())
    })();
    match checked {
        Ok(()) => Bot {
            status: Some(bot_status(wire::BOT_USER_READY, &saved.user, Some(want.uid), None)),
            ids: Some(want),
        },
        Err(e) => bot_failed(&saved.user, e),
    }
}

impl Agent {
    /// Also starts installing any harness CLIs a restart interrupted, and, after an
    /// upgrade, the clock on the new agent's trial.
    pub fn new(cfg: Config, id: Identity) -> Result<Arc<Agent>, String> {
        let server = Arc::new(server_config(&cfg, &id)?);
        let tools = Tools::new(cfg.tools.clone(), Some(cfg.ca_pem.as_str()).filter(|p| !p.is_empty()))?;
        let bot = load_bot_user(&cfg, &tools);
        if bot.status.is_none() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&cfg.home)
                .map_err(|e| format!("{}: {e}", cfg.home.display()))?;
        }
        if bot.status.is_none() || bot.ids.is_some() {
            work_dirs(&cfg, bot.ids)?;
        }
        let upgrader = Upgrader::new(cfg.exe.clone(), cfg.state_dir.clone(), VERSION);
        let landing = Arc::new(Landing::new(cfg.home.clone(), &cfg.state_dir)?);
        if let Some(ids) = bot.ids {
            landing.set_user(ids);
        }
        let screens = Arc::new(Screens::new(cfg.screens.clone(), cfg.home.clone(), cfg.bot_user.clone()));
        let teammates = Arc::new(Teammates::new(cfg.teammates.clone(), cfg.state_dir.clone(), cfg.teammate_stand_in.clone()));
        let cgroups = run_cgroups(&cfg);
        match &cgroups {
            Ok(cg) => println!("Runs are held to their limits in {}.", cg.runs().display()),
            Err(e) => eprintln!("Run limits: {e}"),
        }
        // A saved allow-list holds from the start: no job runs until its rules load.
        let saved: Option<wire::EgressPolicy> = std::fs::read(cfg.state_dir.join(EGRESS_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let egress = match saved {
            Some(policy) => {
                let report = wire::EgressReport {
                    id: policy.id.clone(),
                    mode: policy.mode.clone(),
                    state: wire::EGRESS_STATE_FAILED.into(),
                    error: Some("not loaded yet".into()),
                    ..Default::default()
                };
                Egress { policy, report }
            }
            None => Egress::default(),
        };
        let cfg_state_dir = cfg.state_dir.clone();
        let a = Arc::new(Agent {
            cfg,
            current: RwLock::new((Arc::new(id), server)),
            jobs: Mutex::default(),
            tools,
            upgrader,
            logins: Arc::default(),
            landing,
            restart: watch::channel(false).0,
            bot: RwLock::new(bot),
            screens,
            teammates,
            home_use: Arc::default(),
            cgroups,
            egress: Mutex::new(egress),
            egress_loading: tokio::sync::Mutex::new(()),
            team_rules: Mutex::new(last_team_rules(&cfg_state_dir)),
            team_loading: tokio::sync::Mutex::new(()),
        });
        let me = Arc::downgrade(&a);
        a.tools.set_control(
            &a.cfg.control_url,
            Box::new(move || me.upgrade().ok_or_else(|| "the agent is stopping".to_string()).and_then(|a| control_client(&a, None))),
        );
        a.home_use.refresh(&a.home_roots(), false);
        let mut tmps = vec![a.cfg.home.join(TMP)];
        if let Ok(homes) = std::fs::read_dir(a.teammates.root()) {
            tmps.extend(homes.flatten().map(|h| h.path().join(TMP)));
        }
        std::thread::spawn(move || sweep_tmps(&tmps, SystemTime::now()));
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(a.clone().keep_egress());
            tokio::spawn(a.tools.clone().work());
            a.screens.reap_in_background();
            if let Some(deadline) = a.upgrader.trial_deadline() {
                let trial = a.clone();
                tokio::spawn(async move {
                    tokio::time::sleep_until(deadline).await;
                    if trial.upgrader.trial_deadline().is_some() {
                        let why = "the control plane didn't reach the new agent in time";
                        eprintln!("Upgrade: {why}; putting the old agent back.");
                        if let Err(e) = trial.upgrader.roll_back(why) {
                            eprintln!("Upgrade: {e}");
                        }
                        trial.request_restart();
                    }
                });
            }
        }
        Ok(a)
    }

    /// Asks `run` to return, so systemd starts the agent again (its new binary).
    pub fn request_restart(&self) {
        self.restart.send_replace(true);
    }

    /// Becomes true when the agent should exit and be started again.
    pub fn restarting(&self) -> watch::Receiver<bool> {
        self.restart.subscribe()
    }

    /// Where the Bots and teammates keep files: what the owner's storage counts here.
    fn home_roots(&self) -> Vec<PathBuf> {
        vec![self.cfg.home.clone(), self.cfg.teammates.clone()]
    }

    fn jobs(&self) -> std::sync::MutexGuard<'_, HashMap<String, RunningJob>> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stops `user_id`'s jobs and waits a while for them to end. How many there were.
    async fn stop_jobs_for(&self, user_id: &str) -> u32 {
        let theirs: Vec<String> = self
            .jobs()
            .iter()
            .filter(|(_, j)| j.for_user.as_deref() == Some(user_id))
            .map(|(id, j)| {
                let _ = j.stop.send(true);
                id.clone()
            })
            .collect();
        for _ in 0..150 {
            if !theirs.iter().any(|id| self.jobs().contains_key(id)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        theirs.len() as u32
    }

    /// Jobs and logins running now: either holds off an upgrade.
    pub fn running(&self) -> usize {
        self.jobs().len() + self.logins.running().len()
    }

    /// Where the Bots' own user stands, as heartbeats say.
    #[allow(dead_code)]
    pub fn bot_user(&self) -> Option<wire::BotUserStatus> {
        self.bot().status
    }

    fn bot(&self) -> Bot {
        self.bot.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_bot(&self, b: Bot) {
        *self.bot.write().unwrap_or_else(|e| e.into_inner()) = b;
    }

    /// Whether the agent is handing the home to the Bots' user now.
    fn setting_up(&self) -> bool {
        self.bot().status.is_some_and(|s| s.state == wire::BOT_USER_SETTING_UP)
    }

    /// Who jobs and logins run as: the agent's user until botd asks for the Bots' own
    /// (ADR 0043), then only that one. Refused while it's set up, or if it can't be.
    #[allow(clippy::result_large_err)]
    fn job_user(&self) -> Result<Option<Ids>, Response> {
        let b = self.bot();
        match &b.status {
            None => Ok(None),
            Some(s) if s.state == wire::BOT_USER_READY => Ok(b.ids),
            Some(s) if s.state == wire::BOT_USER_SETTING_UP => Err(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "This machine is setting up its Bots' user. Try again in a few minutes.",
            )),
            Some(s) => Err(refuse(
                StatusCode::CONFLICT,
                format!(
                    "This machine couldn't set up its Bots' user: {}",
                    s.error.as_deref().unwrap_or("no reason given")
                ),
            )),
        }
    }

    /// `user_id`'s own user and home here, made on their first run (ADR 0048). Only
    /// once the Bots' user is ready: the owner's home must be that user's alone. Never
    /// the machine's own user, root, the agent's user or the Bots' user.
    #[allow(clippy::result_large_err)]
    async fn teammate(self: &Arc<Self>, user_id: &str) -> Result<Teammate, Response> {
        if !plain_name(user_id) {
            return Err(refuse(StatusCode::BAD_REQUEST, "The teammate's id isn't a plain name."));
        }
        if user_id == self.identity().user_id {
            return Err(refuse(StatusCode::BAD_REQUEST, "That is this machine's own user, not a teammate."));
        }
        let bots = match self.job_user()? {
            Some(ids) => ids,
            None => {
                return Err(refuse(
                    StatusCode::CONFLICT,
                    "Teammates get their own users only once Bots run as their own user here, and this machine hasn't been asked to set one up.",
                ));
            }
        };
        let (a, id) = (self.clone(), user_id.to_string());
        let made = tokio::task::spawn_blocking(move || {
            let stand_in = a.cfg.teammate_stand_in.is_some();
            a.teammates.ensure(&id, not_teammates(stand_in, Some(bots)))
        })
        .await;
        match made {
            Ok(Ok(t)) => Ok(t),
            Ok(Err(e)) => Err(refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't set up the teammate's user: {e}"))),
            Err(e) => Err(refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// Makes the Bots' user if it must, hands it the home, and saves it, so from now on
    /// everything a Bot touches runs as it. Copies of the folder wait meanwhile.
    fn set_up_bot_user(&self) -> Result<Ids, String> {
        let cfg = &self.cfg;
        let ids = runas::ensure_user(&cfg.bot_user, &cfg.home)?;
        cfg.check_bot_ids(ids)?;
        let _copies = self.landing.hold();
        // Saved, and copies switched, before anything is the Bots' user's: whatever fails
        // after this, or a restart, never has root writing in its home.
        save_bot_user(cfg, ids, false)?;
        self.landing.set_user(ids);
        let handed = runas::hand_over(&cfg.home, ids).map_err(|e| format!("{}: {e}", cfg.home.display()))?;
        cfg.open_paths(&self.tools)?;
        work_dirs(cfg, Some(ids))?;
        save_bot_user(cfg, ids, true)?;
        println!(
            "Bots now run as {}: handed it {} files, left {} as they were.",
            cfg.bot_user, handed.changed, handed.skipped
        );
        Ok(ids)
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.current.read().unwrap().0.clone()
    }

    pub fn replace(&self, id: Identity) -> Result<(), String> {
        let server = Arc::new(server_config(&self.cfg, &id)?);
        *self.current.write().unwrap() = (Arc::new(id), server);
        Ok(())
    }

    /// Takes up the saved identity if it isn't the one in use, as after
    /// `superbot-machine enroll` by hand, which revokes the old certificate. Returns
    /// whether it did.
    pub fn reload_if_changed(&self) -> bool {
        match load(&self.cfg) {
            Some(saved) if saved.fingerprint != self.identity().fingerprint => {
                self.replace(saved).is_ok()
            }
            _ => false,
        }
    }

    fn egress(&self) -> Egress {
        self.egress.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Loads the saved allow-list's rules, then resolves its hosts again every
    /// `EGRESS_REFRESH`, so the rules follow their addresses.
    async fn keep_egress(self: Arc<Self>) {
        let mut first = true;
        loop {
            // The policy is read under the lock, so a refresh never puts back one that a
            // newer request replaced while this waited.
            let one = self.egress_loading.lock().await;
            let p = self.egress().policy;
            // At start a saved `open` loads too: it clears a table left by a restart
            // mid-change, and reports open rather than not loaded.
            let hosts = p.mode == wire::EGRESS_ALLOW_LIST
                && egress_allow::entries(&p.allow).is_ok_and(|e| e.iter().any(|e| matches!(e, egress_allow::Entry::Host(_))));
            if hosts || (first && (p.mode == wire::EGRESS_ALLOW_LIST || !p.id.is_empty())) {
                self.load_egress(p).await;
            }
            drop(one);
            first = false;
            tokio::time::sleep(EGRESS_REFRESH).await;
        }
    }

    /// Takes `p` and loads its rules: the table goes for `open`, or is replaced whole
    /// with the list's addresses. Saved first, so a restart holds to it.
    async fn apply_egress(&self, p: wire::EgressPolicy) -> wire::EgressReport {
        let _one = self.egress_loading.lock().await;
        self.load_egress(p).await
    }

    /// `apply_egress`, for a caller holding `egress_loading`.
    async fn load_egress(&self, p: wire::EgressPolicy) -> wire::EgressReport {
        let mut report = wire::EgressReport { id: p.id.clone(), mode: p.mode.clone(), at: now_ms(), ..Default::default() };
        let had_list = self.egress().report.mode == wire::EGRESS_ALLOW_LIST;
        let saved = write_private(&self.cfg.state_dir.join(EGRESS_FILE), &serde_json::to_string(&p).unwrap_or_default(), 0o600);
        let loaded = match (&saved, p.mode.as_str()) {
            (Err(e), _) => Err(format!("couldn't save the policy: {e}")),
            (Ok(()), wire::EGRESS_OPEN) => {
                report.state = wire::EGRESS_STATE_OPEN.into();
                if had_list || egress_table_loaded(&self.cfg.nft) {
                    egress_allow::load(&self.cfg.nft, &egress_allow::removal())
                } else {
                    Ok(())
                }
            }
            (Ok(()), _) => {
                let list = egress_allow::entries(&p.allow).unwrap_or_default();
                let (addrs, unresolved) = egress_allow::addresses(&list, egress_allow::system_resolve).await;
                report.addresses = addrs.len() as u32;
                report.unresolved = unresolved;
                let ex = egress_exempt();
                let script = egress_allow::rules(&ex, &addrs);
                report.state = wire::EGRESS_STATE_ON.into();
                let nft = self.cfg.nft.clone();
                tokio::task::spawn_blocking(move || egress_allow::load(&nft, &script)).await.unwrap_or_else(|e| Err(e.to_string()))
            }
        };
        if let Err(e) = loaded {
            eprintln!("Outbound allow-list: {e}");
            report.state = wire::EGRESS_STATE_FAILED.into();
            report.error = Some(e);
        }
        *self.egress.lock().unwrap_or_else(|e| e.into_inner()) = Egress { policy: p, report: report.clone() };
        report
    }

    /// The team network subnet the egress script lets through now (ADR 0202).
    fn team_report(&self) -> wire::TeamNetworkReport {
        let last = self.team_rules.lock().unwrap_or_else(|e| e.into_inner()).clone();
        team_report(read_script(&self.cfg.egress_script), last.as_ref())
    }

    /// Lets `subnet` through in the egress script, and no other team subnet, then loads
    /// it again.
    async fn apply_team_rules(&self, subnet: Option<String>) -> wire::TeamNetworkReport {
        let _one = self.team_loading.lock().await;
        let (script, state) = (self.cfg.egress_script.clone(), self.cfg.state_dir.join(TEAM_RULES_STATE));
        let report = tokio::task::spawn_blocking(move || load_team_rules(&script, &state, subnet.as_deref()))
            .await
            .unwrap_or_else(|e| team_failed(None, e.to_string()));
        if let Some(e) = &report.error {
            eprintln!("Team network: {e}");
        }
        save_team_rules(&self.cfg.state_dir, &report);
        *self.team_rules.lock().unwrap_or_else(|e| e.into_inner()) = Some(report.clone());
        report
    }

    /// Rotates when due. Returns whether it did.
    pub async fn rotate_if_due(&self) -> Result<bool, Failed> {
        let id = self.identity();
        if !id.due(now_ms()) {
            return Ok(false);
        }
        let fresh = rotate(&self.cfg, &id).await?;
        self.replace(fresh).map_err(|message| Failed {
            message,
            permanent: false,
        })?;
        Ok(true)
    }
}

/// Where the egress script, run by the agent, says how it went: the unit's own place,
/// under /run, is read-only to the agent.
const TEAM_RULES_STATE: &str = "egress-reload";
/// How the agent's last change to the team subnet in the egress rules went.
const TEAM_RULES_LAST: &str = "team-network.json";

/// Kept across restarts of the agent: the script says what it lets through, not
/// whether it loaded.
fn save_team_rules(state_dir: &Path, r: &wire::TeamNetworkReport) {
    if let Ok(b) = serde_json::to_vec(r) {
        let _ = std::fs::write(state_dir.join(TEAM_RULES_LAST), b);
    }
}

fn last_team_rules(state_dir: &Path) -> Option<wire::TeamNetworkReport> {
    serde_json::from_slice(&std::fs::read(state_dir.join(TEAM_RULES_LAST)).ok()?).ok()
}

/// The most of an egress script read: the first boot's is a few kilobytes.
const SCRIPT_MAX: u64 = 256 * 1024;

/// The egress script, None if there is none: the machine wasn't hardened.
fn read_script(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("couldn't read the egress script: {e}")),
    };
    let mut s = String::new();
    f.take(SCRIPT_MAX).read_to_string(&mut s).map_err(|e| format!("couldn't read the egress script: {e}"))?;
    Ok(Some(s))
}

fn team_failed(subnet: Option<String>, error: String) -> wire::TeamNetworkReport {
    wire::TeamNetworkReport { subnet, state: wire::TEAM_RULES_FAILED.into(), error: Some(error) }
}

const NOT_OURS: &str = "the egress script isn't the one the first boot wrote";

/// What `script` lets through, and `last`'s state if it was the change that left it so.
fn team_report(script: Result<Option<String>, String>, last: Option<&wire::TeamNetworkReport>) -> wire::TeamNetworkReport {
    let s = match script {
        Ok(None) => return wire::TeamNetworkReport { subnet: None, state: wire::TEAM_RULES_NONE.into(), error: None },
        Ok(Some(s)) => s,
        Err(e) => return team_failed(None, e),
    };
    if !team_rules::editable(&s) {
        return team_failed(None, NOT_OURS.into());
    }
    let subnet = team_rules::subnet_in(&s);
    match last {
        Some(l) if l.subnet == subnet => l.clone(),
        _ => wire::TeamNetworkReport { subnet, state: wire::TEAM_RULES_ON.into(), error: None },
    }
}

/// Writes `subnet` into the egress script at `path` in place of any other, then runs
/// it, as the unit does at boot: it replaces the rules' table whole, in one transaction.
fn load_team_rules(path: &Path, state: &Path, subnet: Option<&str>) -> wire::TeamNetworkReport {
    let old = match read_script(path) {
        Ok(None) => return wire::TeamNetworkReport { subnet: None, state: wire::TEAM_RULES_NONE.into(), error: None },
        Ok(Some(s)) => s,
        Err(e) => return team_failed(None, e),
    };
    let Some(new) = team_rules::with_subnet(&old, subnet) else {
        return team_failed(None, NOT_OURS.into());
    };
    let now = team_rules::subnet_in(&new);
    if new != old {
        use std::os::unix::fs::PermissionsExt;
        let tmp = path.with_extension("new");
        let wrote = std::fs::write(&tmp, &new)
            .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)))
            .and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = wrote {
            let _ = std::fs::remove_file(&tmp);
            return team_failed(team_rules::subnet_in(&old), format!("couldn't write the egress script: {e}"));
        }
    }
    let _ = std::fs::create_dir_all(state);
    match std::process::Command::new(path).env("SUPERBOT_HARDENING_STATE", state).stdin(std::process::Stdio::null()).output() {
        Ok(o) if o.status.success() => wire::TeamNetworkReport { subnet: now, state: wire::TEAM_RULES_ON.into(), error: None },
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let why = err.trim().lines().last().map_or(format!("it exited with {}", o.status), String::from);
            team_failed(now, format!("the egress rules didn't load: {}", why.chars().take(200).collect::<String>()))
        }
        Err(e) => team_failed(now, format!("the egress script didn't start: {e}")),
    }
}

/// Whether this machine has an allow-list table loaded now.
fn egress_table_loaded(nft: &Path) -> bool {
    std::process::Command::new(nft)
        .args(["list", "table", "inet", egress_allow::TABLE])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Root, the OS's network daemons that exist here, and the resolvers, as the deny
/// rules of ADR 0126 let through.
fn egress_exempt() -> egress_allow::Exempt {
    let uids = egress_allow::DAEMONS.iter().filter_map(|n| runas::lookup(n).map(|(ids, _)| ids.uid)).collect();
    let (dns4, dns6) = egress_allow::resolvers(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
    egress_allow::Exempt { uids, dns4, dns6 }
}

/// Clients must show a certificate from the CA naming the control plane, so another
/// machine's certificate (from the same CA) can't call this one.
fn server_config(cfg: &Config, id: &Identity) -> Result<ServerConfig, String> {
    let (chain, key) = id.chain();
    pki::server_config(&cfg.ca(), chain, key, true)
}

pub fn admit(peer: &Peer) -> Option<Duration> {
    let control_plane = peer
        .cert
        .as_ref()
        .and_then(|c| pki::facts(c))
        .is_some_and(|f| f.uris.iter().any(|u| u == pki::CONTROL_PLANE_URI));
    control_plane.then_some(pki::AUTHENTICATED_LIFETIME)
}

fn refuse(code: StatusCode, error: impl Into<String>) -> Response {
    (
        code,
        Json(wire::ErrorReply {
            error: error.into(),
        }),
    )
        .into_response()
}

/// A program name for PATH to find, never a path.
fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && s != "."
        && s != ".."
}

/// `?bin=claude&bin=hermes`: the harnesses botd is about to run. Names this build
/// doesn't know are missing without a look, so the query never makes a path.
fn bins(query: Option<&str>) -> Vec<(String, Option<&'static str>)> {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.strip_prefix("bin="))
        .filter(|b| plain_name(b))
        .take(8)
        .map(|b| (b.to_string(), wire::harness_bin(b)))
        .collect()
}

fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `?cred=claude:.claude/.credentials.json`: where each harness keeps its login,
/// relative to HOME (ADR 0041). Grouped by harness; anything else is ignored.
fn creds(query: Option<&str>) -> BTreeMap<&'static str, Vec<String>> {
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for kv in query.unwrap_or("").split('&').filter_map(|kv| kv.strip_prefix("cred=")).take(16) {
        let Some((h, p)) = unescape(kv).and_then(|v| v.split_once(':').map(|(h, p)| (h.to_string(), p.to_string()))) else {
            continue;
        };
        if let Some(h) = wire::harness_bin(&h)
            && wire::home_path(&p)
        {
            out.entry(h).or_default().push(p);
        }
    }
    out
}

/// Whether each harness asked about is logged in for the owner, in the Bots' home, and
/// those logging in now. Teammates' own logins never count here (ADR 0062).
fn logins(a: &Agent, query: Option<&str>) -> BTreeMap<String, wire::LoginStatus> {
    login_states(&a.cfg.home, a.bot().ids, a.logins.running_for(None), query)
}

/// The same, for a teammate's own logins in their home (ADR 0062), looked at as their
/// user, so a link they put there reaches nothing they couldn't read themselves.
fn teammate_logins(a: &Agent, user_id: &str, t: Option<&Teammate>, query: Option<&str>) -> BTreeMap<String, wire::LoginStatus> {
    let running = a.logins.running_for(Some(user_id));
    match t {
        Some(t) => login_states(&t.home, Some(t.ids), running, query),
        None => {
            let mut out: BTreeMap<String, wire::LoginStatus> = creds(query)
                .into_keys()
                .map(|h| (h.to_string(), wire::LoginStatus { state: wire::LOGGED_OUT.into(), since: None }))
                .collect();
            for h in running {
                out.insert(h, wire::LoginStatus { state: wire::LOGGING_IN.into(), since: None });
            }
            out
        }
    }
}

fn login_states(home: &Path, user: Option<Ids>, running: Vec<String>, query: Option<&str>) -> BTreeMap<String, wire::LoginStatus> {
    let mut out: BTreeMap<String, wire::LoginStatus> = creds(query)
        .into_iter()
        .map(|(h, files)| {
            let since = runas::as_user(user, || super::terminal::logged_in(home, &files))
                .ok()
                .flatten();
            let state = match since {
                Some(_) => wire::LOGGED_IN,
                None if running.iter().any(|r| r == h) => wire::LOGGING_IN,
                None => wire::LOGGED_OUT,
            };
            (h.to_string(), wire::LoginStatus { state: state.into(), since })
        })
        .collect();
    for h in running {
        out.entry(h).or_insert_with(|| wire::LoginStatus {
            state: wire::LOGGING_IN.into(),
            since: None,
        });
    }
    out
}

/// The Bots' working folders, made as `user` (or the agent) if they aren't there.
fn work_dirs(cfg: &Config, user: Option<Ids>) -> Result<(), String> {
    runas::as_user(user, || {
        for dir in [cfg.home.join("work"), cfg.home.join("bots"), cfg.home.join(TMP)] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(())
    })
    .map_err(|e| e.to_string())?
}

/// The layout, with the Bots' package caches made first, as their user, so a sandboxed
/// run's first build has somewhere to download to (ADR 0055). The sandbox check runs
/// as that user too: root may make namespaces it can't.
fn layout(a: &Agent) -> wire::Layout {
    let mut l = a.cfg.layout();
    let ids = a.bot().ids;
    l.sandbox = Some(crate::sandbox::host_as(ids.map(|i| (i.uid, i.gid))));
    if let Ok(made) = runas::as_user(ids, || crate::sandbox::ensure_caches(&a.cfg.home)) {
        l.caches = made.into_iter().map(|p| p.display().to_string()).collect();
    }
    l
}

/// Only the control plane's certificate gets here (`admit`), so answering one is the
/// proof an upgraded agent works: its trial ends.
async fn heartbeat(State(a): State<Arc<Agent>>, RawQuery(q): RawQuery) -> Json<wire::Heartbeat> {
    if a.upgrader.commit() {
        println!("Upgrade: the control plane reached the new agent; keeping it.");
    }
    let id = a.identity();
    let (plan, harnesses) = a.tools.report();
    let disk = disk(&a.cfg.home).map(|d| {
        let (files, partial) = a.home_use.latest().map_or((None, false), |(n, p)| (Some(n), p));
        wire::Disk { files, partial, ..d }
    });
    a.home_use.refresh(&a.home_roots(), false);
    Json(wire::Heartbeat {
        machine_id: id.machine_id.clone(),
        user_id: id.user_id.clone(),
        version: VERSION.into(),
        certificate: id.fingerprint.clone(),
        time: now_ms(),
        protocol: wire::PROTOCOL,
        layout: Some(layout(&a)),
        missing: bins(q.as_deref())
            .into_iter()
            .filter(|(_, known)| !known.is_some_and(|k| a.cfg.has(k)))
            .map(|(b, _)| b)
            .collect(),
        jobs: a.running() as u32,
        can: [
            wire::CAN_HARNESSES,
            wire::CAN_LOGINS,
            wire::CAN_SYNC,
            wire::CAN_BOT_USER,
            wire::CAN_SCREENS,
            wire::CAN_TEAMMATES,
            wire::CAN_TEAMMATE_REMOVAL,
            wire::CAN_TEAMMATE_LOGINS,
            wire::CAN_INSTALL_AFTER,
            wire::CAN_RETENTION,
            wire::CAN_RUN_LIMITS,
            wire::CAN_EGRESS_POLICY,
            wire::CAN_LOCKED_DOWN,
            wire::CAN_HARNESS_MIRRORS,
            wire::CAN_HARNESS_BUNDLES,
            wire::CAN_TEAM_NETWORK,
        ]
            .into_iter()
            .chain(a.upgrader.build.is_some().then_some(wire::CAN_UPGRADE))
            .chain(seccomp::SUPPORTED.then_some(wire::CAN_SECCOMP))
            .map(String::from)
            .collect(),
        build: a.upgrader.build.clone(),
        plan,
        harnesses,
        upgrade: a.upgrader.report(),
        logins: logins(&a, q.as_deref()),
        bot_user: a.bot().status,
        screens: Some(a.screens.report()),
        teammates: Some(a.teammates.known()),
        disk,
        hardening: hardening(
            Path::new(HARDENING_STATUS),
            Path::new(HARDENING_EGRESS),
            Path::new(HARDENING_REBOOT),
        ),
        run_limits: Some(match &a.cgroups {
            Ok(cg) => cg.report(),
            Err(e) => Cgroups::unavailable(e.clone()),
        }),
        egress_policy: Some(a.egress().report),
        team_network: Some(a.team_report()),
    })
}

/// Where the first boot writes each hardening step's state as `step=state` lines
/// (ADR 0126), where the egress script says this boot's rules are loaded, and the
/// OS's flag for updates waiting on a reboot.
const HARDENING_STATUS: &str = "/etc/superbot/hardening";
const HARDENING_EGRESS: &str = "/run/superbot-hardening/egress";
const HARDENING_REBOOT: &str = "/run/reboot-required";

/// What those files say. None when the first boot didn't harden the machine. Only
/// root writes them, but they are read with care all the same: a little of each, and
/// a few short lower-case `step=state` lines.
fn hardening(status: &Path, egress: &Path, reboot: &Path) -> Option<wire::Hardening> {
    fn small(p: &Path) -> Option<String> {
        use std::io::Read;
        let mut s = String::new();
        std::fs::File::open(p).ok()?.take(1024).read_to_string(&mut s).ok()?;
        Some(s)
    }
    let word = |w: &str| !w.is_empty() && w.len() <= 16 && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    let steps = small(status)?
        .lines()
        .filter_map(|l| l.trim().split_once('='))
        .filter(|(k, v)| word(k) && word(v))
        .take(8)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Some(wire::Hardening {
        steps,
        egress: small(egress).is_some_and(|s| s.trim() == wire::HARDENING_ON),
        reboot_required: reboot.exists(),
    })
}

/// How full the disk holding `path` is.
fn disk(path: &Path) -> Option<wire::Disk> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `s` a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    let block = (s.f_frsize as u64).max(1);
    let total = (s.f_blocks as u64).saturating_mul(block);
    let free = (s.f_bfree as u64).saturating_mul(block);
    Some(wire::Disk { used: total.saturating_sub(free), total, ..Default::default() })
}

/// Whether `p` is an absolute path inside `home`, with no `..` to climb out.
fn inside(home: &Path, p: &str) -> bool {
    let p = Path::new(p);
    p.is_absolute()
        && p.starts_with(home)
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Why this machine won't run the job, if it won't.
fn check(cfg: &Config, user_id: &str, j: &wire::JobRequest, home: &Path) -> Result<(), (StatusCode, String)> {
    let bad = |m: String| Err((StatusCode::BAD_REQUEST, m));
    if j.protocol != wire::PROTOCOL {
        return bad(format!(
            "This agent speaks job protocol {}, not {}. Update it.",
            wire::PROTOCOL,
            j.protocol
        ));
    }
    // Its certificate names one user; it runs no one else's Bots, whatever botd says.
    if j.owner_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "This machine runs only its own user's Bots.".into(),
        ));
    }
    if !plain_name(&j.job_id) || !plain_name(&j.bot_id) {
        return bad("The job or Bot id isn't a plain name.".into());
    }
    if !plain_name(&j.bin) || j.cleanup.as_ref().is_some_and(|c| !plain_name(&c.bin)) {
        return bad("Harnesses are named, not paths: this machine's PATH finds them.".into());
    }
    let mut paths: Vec<&str> = vec![&j.cwd];
    paths.extend(j.files.iter().map(|f| f.path.as_str()));
    paths.extend(j.collect.iter().map(String::as_str));
    if let Some(c) = &j.cleanup {
        paths.extend([c.when_exists.as_str(), c.cwd.as_str()]);
    }
    if let Some(p) = paths.into_iter().find(|p| !inside(home, p)) {
        return bad(format!("{p} isn't inside {}.", home.display()));
    }
    let Some(bin) = wire::harness_bin(&j.bin) else {
        return bad(format!("{} isn't a harness this machine runs.", j.bin));
    };
    if let Some(c) = &j.cleanup
        && wire::harness_bin(&c.bin).is_none()
    {
        return bad(format!("{} isn't a harness this machine runs.", c.bin));
    }
    if !cfg.has(bin) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{} isn't installed on this machine.", j.bin),
        ));
    }
    Ok(())
}

/// The agent sets HOME, PATH and TMPDIR; a job can't move them.
fn scrub(env: &mut BTreeMap<String, String>) {
    env.retain(|k, _| k != "HOME" && k != "PATH" && k != "TMPDIR");
}

/// Each run user's own temporary folder, in its home (ADR 0145): /tmp is shared by
/// every user on the machine.
const TMP: &str = ".tmp";

/// How long what's left in a temporary folder is kept untouched before the agent's
/// start removes it.
const TMP_KEEP: Duration = Duration::from_secs(24 * 3600);
/// How many entries one leftover may hold for the sweep to look through it; a bigger one
/// is kept, and counts against the owner's storage.
const TMP_SWEEP_MAX: usize = 50_000;

/// `home`'s temporary folder, made as `ids` if it isn't there.
fn own_tmp(home: &Path, ids: Ids) -> Result<(), String> {
    let tmp = home.join(TMP);
    let made = runas::as_user(Some(ids), || match std::fs::DirBuilder::new().mode(0o700).create(&tmp) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tmp.is_dir() => Ok(()),
        r => r,
    });
    made.and_then(|r| r).map_err(|e| format!("Couldn't make {}: {e}", tmp.display()))
}

/// A job's own temporary folder in `home`'s, made as `user`; removed when the job ends.
fn job_tmp(home: &Path, job: &str, user: Option<Ids>) -> Option<PathBuf> {
    let dir = home.join(TMP).join(job);
    let made = runas::as_user(user, || std::fs::DirBuilder::new().mode(0o700).create(&dir));
    matches!(made, Ok(Ok(()))).then_some(dir)
}

/// Removes, from each temporary folder in `tmps` and as its owner, what neither it nor
/// anything in it has changed for `TMP_KEEP`, without following links. For the agent's
/// start, off its requests: nothing runs yet, so only what crashed runs and logins left.
fn sweep_tmps(tmps: &[PathBuf], now: SystemTime) {
    for tmp in tmps {
        let Ok(m) = tmp.symlink_metadata() else { continue };
        if !m.is_dir() {
            continue;
        }
        let owner = Ids { uid: m.uid(), gid: m.gid() };
        let _ = runas::as_user(Some(owner).filter(|o| o.uid != 0), || {
            let Ok(entries) = std::fs::read_dir(tmp) else { return };
            for e in entries.flatten() {
                let mut seen = 0;
                if newest(&e.path(), &mut seen).is_some_and(|t| now.duration_since(t).is_ok_and(|age| age > TMP_KEEP)) {
                    let p = e.path();
                    let _ = if p.symlink_metadata().is_ok_and(|m| m.is_dir()) { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
                }
            }
        });
    }
}

/// When `p`, or anything under it, last changed, not following links; None past
/// `TMP_SWEEP_MAX` entries or if any can't be read.
fn newest(p: &Path, seen: &mut usize) -> Option<SystemTime> {
    *seen += 1;
    if *seen > TMP_SWEEP_MAX {
        return None;
    }
    let m = p.symlink_metadata().ok()?;
    let mut t = m.modified().ok()?;
    if m.is_dir() {
        for e in std::fs::read_dir(p).ok()? {
            t = t.max(newest(&e.ok()?.path(), seen)?);
        }
    }
    Some(t)
}

fn ndjson(e: &impl serde::Serialize) -> Bytes {
    let mut line = serde_json::to_vec(e).unwrap_or_default();
    line.push(b'\n');
    Bytes::from(line)
}

/// Streams `rx` as JSON lines, with `ping` while it's quiet. `guard` is dropped when the
/// stream ends, however it ends.
fn stream<T: serde::Serialize + Send + 'static>(
    mut rx: mpsc::Receiver<T>,
    ping: T,
    guard: impl Send + 'static,
) -> Response {
    let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let _guard = guard;
        loop {
            let next = tokio::time::timeout(PING_EVERY, rx.recv()).await;
            let line = match next {
                Ok(Some(e)) => ndjson(&e),
                Ok(None) => break,
                Err(_) => ndjson(&ping),
            };
            if body_tx.send(Ok(line)).await.is_err() {
                break;
            }
        }
    });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx)),
    )
        .into_response()
}

/// A job's registration and its hold on the tools, kept until the harness has exited
/// and its cleanup has run, however the job ends.
struct Running(Arc<Agent>, String, #[allow(dead_code)] super::tools::JobPermit);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.jobs().remove(&self.1);
        // What the job wrote counts against the owner's storage before their next run.
        self.0.home_use.refresh(&self.0.home_roots(), true);
    }
}

/// Stops the job when its stream ends.
struct StopOnDrop(watch::Sender<bool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

/// `POST /v1/jobs`: runs the job and streams its events, one JSON object per line.
/// A request it refuses gets an error status before anything runs.
async fn start_job(State(a): State<Arc<Agent>>, Json(mut j): Json<wire::JobRequest>) -> Response {
    // A teammate's run (ADR 0048): their own user, and nothing outside their home.
    let home = j.for_user.as_deref().map_or(a.cfg.home.clone(), |u| a.teammates.home_of(u));
    if let Err((code, msg)) = check(&a.cfg, &a.identity().user_id, &j, &home) {
        return refuse(code, msg);
    }
    let teammate = match j.for_user.clone() {
        Some(u) => match a.teammate(&u).await {
            Ok(t) => Some(t),
            Err(r) => return r,
        },
        None => None,
    };
    scrub(&mut j.env);
    if let Some(c) = j.cleanup.as_mut() {
        scrub(&mut c.env);
    }
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let (permit, user) = {
        let mut jobs = a.jobs();
        let user = match a.job_user() {
            Ok(u) => u,
            Err(r) => return r,
        };
        if a.upgrader.staging() {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "This machine is updating its agent. Try again in a minute.",
            );
        }
        if jobs.contains_key(&j.job_id) {
            return refuse(StatusCode::CONFLICT, "That job is already running.");
        }
        // Checked with the jobs held: a removal marks the teammate, then stops what's here.
        if j.for_user.as_deref().is_some_and(|u| a.teammates.is_leaving(u)) {
            return refuse(StatusCode::CONFLICT, "That teammate's user is being removed.");
        }
        // An allow-list botd set holds every run: none starts while its rules aren't loaded.
        let egress = a.egress();
        if egress.policy.mode == wire::EGRESS_ALLOW_LIST && egress.report.state != wire::EGRESS_STATE_ON {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "This machine's outbound allow-list isn't loaded: {}",
                    egress.report.error.as_deref().unwrap_or("no reason given")
                ),
            );
        }
        if jobs.len() >= a.cfg.max_jobs {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("This machine is already running {} jobs.", jobs.len()),
            );
        }
        let Some(permit) = a.tools.job_permit() else {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "This machine is updating its harnesses. Try again in a minute.",
            );
        };
        jobs.insert(j.job_id.clone(), RunningJob { stop: stop_tx.clone(), for_user: j.for_user.clone() });
        (permit, user)
    };
    let running = Running(a.clone(), j.job_id.clone(), permit);
    let stop = StopOnDrop(stop_tx);
    let mut host = match &teammate {
        Some(t) => match a.cfg.teammate_host(t) {
            Ok(h) => h,
            Err(e) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        },
        None => {
            let _ = work_dirs(&a.cfg, user);
            a.cfg.host(user)
        }
    };
    let home = teammate.as_ref().map_or(&a.cfg.home, |t| &t.home);
    let tmp = job_tmp(home, &j.job_id, host.user);
    if let Some(t) = &tmp {
        host.env.insert("TMPDIR".into(), t.display().to_string());
    }
    // A run the agent can't hold to its limits still runs, and its exit says why.
    host.limits = j.limits.map(|l| match &a.cgroups {
        Ok(cg) => {
            let (cpus, memory) = machine_size(cg.base());
            match cg.resize(cpus, memory).and_then(|()| cg.start(&j.job_id, &l)) {
                Ok(rc) => job::Limiting::Cgroup(Arc::new(rc)),
                Err(e) => job::Limiting::Unavailable(e),
            }
        }
        Err(e) => job::Limiting::Unavailable(e.clone()),
    });
    let (ev_tx, ev_rx) = mpsc::channel::<wire::JobEvent>(256);
    let screen = a.screens.hold(&wire::screen_key(&j.bot_id, j.for_user.as_deref()));
    tokio::spawn(async move {
        let _running = running;
        let _screen = screen;
        let abort = async move {
            let _ = stop_rx.wait_for(|s| *s).await;
        };
        job::run(&host, &j, abort, &ev_tx).await;
        if let Some(t) = tmp {
            let user = host.user;
            let _ = tokio::task::spawn_blocking(move || runas::as_user(user, || std::fs::remove_dir_all(t))).await;
        }
    });
    // Held until the stream ends: dropping it stops the job.
    stream(ev_rx, wire::JobEvent::Ping, stop)
}

fn code_or(code: u16, fallback: StatusCode) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(fallback)
}

/// `POST /v1/logins`: runs a harness's login in a terminal here and streams what it
/// shows (ADR 0041). Its credentials stay in this machine's HOME: the Bots' for the
/// owner, or a teammate's own (`for_user`, ADR 0062), as their user, made if need be.
/// A dropped stream stops it. Like a job, it holds off agent upgrades and harness updates.
async fn start_login(State(a): State<Arc<Agent>>, Json(r): Json<wire::LoginRequest>) -> Response {
    let run = match super::terminal::check(&r, |b| a.cfg.has(b)) {
        Ok(run) => run,
        Err((code, msg)) => return refuse(code_or(code, StatusCode::BAD_REQUEST), msg),
    };
    let teammate = match r.for_user.as_deref() {
        Some(u) => match a.teammate(u).await {
            Ok(t) => Some(t),
            Err(r) => return r,
        },
        None => None,
    };
    let _jobs = a.jobs();
    let user = match a.job_user() {
        Ok(u) => u,
        Err(r) => return r,
    };
    // Checked with the jobs held, as for jobs: a removal marks the teammate first.
    if r.for_user.as_deref().is_some_and(|u| a.teammates.is_leaving(u)) {
        return refuse(StatusCode::CONFLICT, "That teammate's user is being removed.");
    }
    let (home, host) = match &teammate {
        Some(t) => match a.cfg.teammate_host(t) {
            Ok(h) => (t.home.clone(), h),
            Err(e) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        },
        None => (a.cfg.home.clone(), a.cfg.host(user)),
    };
    if a.upgrader.staging() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
    }
    let Some(permit) = a.tools.job_permit() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its harnesses. Try again in a minute.");
    };
    match a.logins.start(&r, &run, &home, &host.env, host.user) {
        Ok((rx, stop)) => stream(rx, wire::LoginEvent::Ping, (StopOnDrop(stop), permit)),
        Err((code, msg)) => refuse(code_or(code, StatusCode::CONFLICT), msg),
    }
}

async fn login_input(
    State(a): State<Arc<Agent>>,
    UrlPath(id): UrlPath<String>,
    Json(i): Json<wire::LoginInput>,
) -> Response {
    let logins = a.logins.clone();
    match tokio::task::spawn_blocking(move || logins.input(&id, &i.text)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err((code, msg))) => refuse(code_or(code, StatusCode::BAD_REQUEST), msg),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn login_abort(State(a): State<Arc<Agent>>, UrlPath(id): UrlPath<String>) -> Response {
    if a.logins.abort(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        refuse(StatusCode::NOT_FOUND, "No such login is running.")
    }
}

/// `POST /v1/logins/forget`: logs a harness out by removing its credential files.
async fn login_forget(State(a): State<Arc<Agent>>, Json(f): Json<wire::ForgetRequest>) -> Response {
    if wire::harness_bin(&f.harness).is_none() || f.files.len() > 4 || !f.files.iter().all(|p| wire::home_path(p)) {
        return refuse(StatusCode::BAD_REQUEST, "Name a harness and its credential files inside HOME.");
    }
    if let Some(u) = &f.for_user
        && (!plain_name(u) || *u == a.identity().user_id)
    {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's id isn't a plain name, or is this machine's own user.");
    }
    if a.logins.running_for(f.for_user.as_deref()).contains(&f.harness) {
        return refuse(StatusCode::CONFLICT, format!("A {} login is running here.", f.harness));
    }
    let user = match a.job_user() {
        Ok(u) => u,
        Err(r) => return r,
    };
    // A teammate's own login is removed as their user, from their home. One who has no
    // user here has nothing to remove.
    let (home, user) = match &f.for_user {
        None => (a.cfg.home.clone(), user),
        Some(u) => {
            let stand_in = a.cfg.teammate_stand_in.is_some();
            match a.teammates.existing(u, not_teammates(stand_in, user)) {
                Some(t) => (t.home, Some(t.ids)),
                None => return Json(wire::ForgetReply { removed: 0 }).into_response(),
            }
        }
    };
    let whose = if f.for_user.is_some() { "the teammate's" } else { "the Bots'" };
    match runas::as_user(user, || super::terminal::forget(&home, &f.files)) {
        Ok(removed) => Json(wire::ForgetReply { removed }).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't act as {whose} user: {e}")),
    }
}

fn landed<T: serde::Serialize>(r: Result<Result<T, (u16, String)>, tokio::task::JoinError>) -> Response {
    match r {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err((code, msg))) => refuse(code_or(code, StatusCode::BAD_REQUEST), msg),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `POST /v1/sync`: a copy of the user's folder begins (ADR 0041).
async fn sync_plan(State(a): State<Arc<Agent>>, Json(m): Json<wire::SyncManifest>) -> Response {
    if let Err(r) = a.job_user() {
        return r;
    }
    let landing = a.landing.clone();
    landed(tokio::task::spawn_blocking(move || landing.plan(m)).await)
}

#[derive(serde::Deserialize)]
struct Offset {
    offset: u64,
}

async fn sync_blob(
    State(a): State<Arc<Agent>>,
    UrlPath((id, sha)): UrlPath<(String, String)>,
    Query(o): Query<Offset>,
    body: Bytes,
) -> Response {
    let landing = a.landing.clone();
    match tokio::task::spawn_blocking(move || landing.put(&id, &sha, o.offset, &body)).await {
        Ok(Ok(r)) => Json(r).into_response(),
        Ok(Err((_, Some(held)))) => (StatusCode::CONFLICT, Json(held)).into_response(),
        Ok(Err(((code, msg), None))) => refuse(code_or(code, StatusCode::BAD_REQUEST), msg),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn sync_finish(State(a): State<Arc<Agent>>, UrlPath(id): UrlPath<String>) -> Response {
    if let Err(r) = a.job_user() {
        return r;
    }
    let landing = a.landing.clone();
    landed(tokio::task::spawn_blocking(move || landing.finish(&id)).await)
}

/// `POST /v1/jobs/{id}/abort`: stops a job; its stream ends with its exit.
async fn abort_job(
    State(a): State<Arc<Agent>>,
    UrlPath(id): UrlPath<String>,
    Json(_why): Json<wire::AbortRequest>,
) -> Response {
    match a.jobs().get(&id) {
        Some(j) => {
            let _ = j.stop.send(true);
            StatusCode::NO_CONTENT.into_response()
        }
        None => refuse(StatusCode::NOT_FOUND, "No such job is running."),
    }
}

/// `PUT /v1/harnesses`: the harness CLIs botd wants here (ADR 0039). They install in
/// the background; heartbeats say how it goes.
async fn set_harnesses(State(a): State<Arc<Agent>>, Json(plan): Json<wire::HarnessPlan>) -> Response {
    match a.tools.set_plan(plan) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(e) => refuse(StatusCode::BAD_REQUEST, e),
    }
}

/// A client for botd's machine port over the CA-pinned channel, with this machine's
/// certificate. `timeout`: for the whole request; without one, a download as large as
/// a bundle (ADR 0210) may take as long as it keeps moving.
fn control_client(a: &Agent, timeout: Option<Duration>) -> Result<reqwest::Client, String> {
    let config = pki::client_config(&a.cfg.ca(), Some(a.identity().chain()))?;
    let b = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .connect_timeout(Duration::from_secs(10));
    match timeout {
        Some(t) => b.timeout(t),
        None => b.read_timeout(Duration::from_secs(60)),
    }
    .build()
    .map_err(|e| e.to_string())
}

/// botd's `/v1/agent` or `/v1/botctl`, over the CA-pinned channel, with this machine's
/// certificate.
async fn fetch(a: &Agent, path: &str) -> Result<Vec<u8>, String> {
    let http = control_client(a, Some(Duration::from_secs(600)))?;
    let mut r = http
        .get(format!("{}{path}", a.cfg.control_url))
        .send()
        .await
        .map_err(|e| format!("couldn't reach the control plane: {}", e.without_url()))?;
    if !r.status().is_success() {
        return Err(format!("the control plane answered {} for {path}", r.status().as_u16()));
    }
    let mut out = Vec::new();
    while let Some(c) = r.chunk().await.map_err(|e| format!("{path}: {}", e.without_url()))? {
        if out.len() + c.len() > upgrade::MAX_BINARY {
            return Err(format!("{path} is over {} MiB", upgrade::MAX_BINARY >> 20));
        }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// `POST /v1/upgrade`: replaces this agent with botd's build, then restarts (ADR
/// 0039). Refused while jobs or logins run; neither starts until it's done.
async fn start_upgrade(State(a): State<Arc<Agent>>, Json(req): Json<wire::UpgradeRequest>) -> Response {
    {
        let jobs = a.jobs();
        if a.setting_up() {
            return refuse(StatusCode::CONFLICT, "This machine is setting up its Bots' user. Try again in a few minutes.");
        }
        if let Some((code, msg)) = a.upgrader.refuse(&req, jobs.len() + a.logins.running().len()) {
            return refuse(StatusCode::from_u16(code).unwrap_or(StatusCode::CONFLICT), msg);
        }
        if !a.upgrader.begin(&req) {
            return refuse(StatusCode::CONFLICT, "This agent is upgrading already.");
        }
    }
    let up = a.clone();
    tokio::spawn(async move {
        match up.upgrader.stage(&req, |path| fetch(&up, path)).await {
            Ok(()) => {
                println!("Upgrade: installed superbot-machine {} ({}); restarting.", req.version, &req.sha256[..16]);
                up.request_restart();
            }
            Err(e) => eprintln!("Upgrade: {e}"),
        }
    });
    (StatusCode::ACCEPTED, Json(a.upgrader.report())).into_response()
}

/// `PUT /v1/bot-user`: from now on, run Bots as their own user (ADR 0043). Refused
/// while jobs or logins run; none start until it's done. Heartbeats say how it went.
async fn set_bot_user(State(a): State<Arc<Agent>>, Json(_r): Json<wire::BotUserRequest>) -> Response {
    {
        let jobs = a.jobs();
        let b = a.bot();
        if let Some(s) = b.status.as_ref().filter(|s| s.state != wire::BOT_USER_FAILED) {
            let code = if s.state == wire::BOT_USER_READY { StatusCode::OK } else { StatusCode::ACCEPTED };
            return (code, Json(s.clone())).into_response();
        }
        if a.upgrader.staging() {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
        }
        let running = jobs.len() + a.logins.running().len();
        if running > 0 {
            return refuse(StatusCode::CONFLICT, format!("{running} jobs or logins are running here. Try again when they're done."));
        }
        a.set_bot(Bot {
            status: Some(bot_status(wire::BOT_USER_SETTING_UP, &a.cfg.bot_user, None, None)),
            ids: None,
        });
    }
    let up = a.clone();
    tokio::task::spawn_blocking(move || {
        let user = up.cfg.bot_user.clone();
        let b = match up.set_up_bot_user() {
            Ok(ids) => Bot {
                status: Some(bot_status(wire::BOT_USER_READY, &user, Some(ids.uid), None)),
                ids: Some(ids),
            },
            Err(e) => bot_failed(&user, e),
        };
        up.set_bot(b);
    });
    (StatusCode::ACCEPTED, Json(a.bot().status)).into_response()
}

/// `PUT /v1/screens/{bot}`: starts the Bot's screen, or gives it a new viewer token
/// (ADR 0045). Only ever as the Bots' own user: before botd has asked for one, or
/// while it can't be used, no screen starts.
async fn put_screen(State(a): State<Arc<Agent>>, UrlPath(bot): UrlPath<String>, Json(r): Json<wire::ScreenRequest>) -> Response {
    if r.protocol != wire::SCREEN_PROTOCOL {
        return refuse(
            StatusCode::BAD_REQUEST,
            format!("This agent speaks screen protocol {}, not {}. Update it.", wire::SCREEN_PROTOCOL, r.protocol),
        );
    }
    if r.owner_id != a.identity().user_id {
        return refuse(StatusCode::FORBIDDEN, "This machine shows only its own user's Bots.");
    }
    if !plain_name(&bot) || !wire::screen_token(&r.token) {
        return refuse(StatusCode::BAD_REQUEST, "Name a Bot and give a long hex token.");
    }
    if !(320..=7680).contains(&r.width) || !(240..=4320).contains(&r.height) {
        return refuse(StatusCode::BAD_REQUEST, "That screen size is out of range.");
    }
    let ids = match a.job_user() {
        Ok(Some(ids)) => ids,
        Ok(None) => {
            return refuse(
                StatusCode::CONFLICT,
                "Screens run only as the Bots' own user, and this machine hasn't been asked to set one up.",
            );
        }
        Err(r) => return r,
    };
    // A teammate's own screen of the Bot runs as their user, in their home (ADR 0048).
    let who = match &r.for_user {
        Some(u) => match a.teammate(u).await {
            Ok(t) => display::As { ids: t.ids, home: t.home, user: t.user },
            Err(r) => return r,
        },
        None => display::As { ids, home: a.cfg.home.clone(), user: a.cfg.bot_user.clone() },
    };
    let key = wire::screen_key(&bot, r.for_user.as_deref());
    if r.for_user.as_deref().is_some_and(|u| a.teammates.is_leaving(u)) {
        return refuse(StatusCode::CONFLICT, "That teammate's user is being removed.");
    }
    if a.upgrader.staging() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
    }
    let missing = a.screens.missing();
    if !missing.is_empty() {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, format!("This machine is missing {}.", missing.join(", ")));
    }
    match a.screens.ensure_as(&key, &r, &who).await {
        Ok(reply) => {
            if reply.started {
                println!("Screen {} of {key} started.", reply.display);
            }
            Json(reply).into_response()
        }
        Err((code, msg)) => refuse(code_or(code, StatusCode::SERVICE_UNAVAILABLE), msg),
    }
}

/// `?for=<user>`: a teammate's own screen of the Bot (ADR 0048).
#[derive(serde::Deserialize)]
struct ScreenFor {
    #[serde(rename = "for")]
    for_user: Option<String>,
}

impl ScreenFor {
    fn key(&self, bot: &str) -> Option<String> {
        match &self.for_user {
            Some(u) if !plain_name(u) => None,
            u => Some(wire::screen_key(bot, u.as_deref())),
        }
    }
}

async fn delete_screen(State(a): State<Arc<Agent>>, UrlPath(bot): UrlPath<String>, Query(f): Query<ScreenFor>) -> Response {
    let Some(key) = f.key(&bot) else {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's id isn't a plain name.");
    };
    if a.screens.stop(&key).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        refuse(StatusCode::NOT_FOUND, "No screen is up for that Bot here.")
    }
}

/// How long one viewer connection may stay open.
const TUNNEL_LIFETIME: Duration = Duration::from_secs(12 * 3600);

/// `GET /v1/screens/{bot}/tunnel`: one viewer connection, piped as raw bytes to the
/// Bot's voxl on loopback. The viewer port itself is never reachable from outside.
async fn screen_tunnel(State(a): State<Arc<Agent>>, UrlPath(bot): UrlPath<String>, Query(f): Query<ScreenFor>, mut req: Request) -> Response {
    let wants = req.headers().get(header::UPGRADE).and_then(|v| v.to_str().ok());
    if wants != Some(wire::SCREEN_UPGRADE) {
        return refuse(StatusCode::BAD_REQUEST, format!("Ask with Upgrade: {}.", wire::SCREEN_UPGRADE));
    }
    let Some(key) = f.key(&bot) else {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's id isn't a plain name.");
    };
    let (port, hold, permit) = match a.screens.tunnel(&key) {
        Ok(t) => t,
        Err((code, msg)) => return refuse(code_or(code, StatusCode::NOT_FOUND), msg),
    };
    let viewer = match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(e) => return refuse(StatusCode::BAD_GATEWAY, format!("The screen's viewer didn't answer: {e}")),
    };
    let Some(on) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "This connection can't be upgraded.");
    };
    tokio::spawn(async move {
        let _hold = (hold, permit);
        let Ok(up) = on.await else { return };
        let mut up = hyper_util::rt::TokioIo::new(up);
        let mut viewer = viewer;
        let _ = tokio::time::timeout(TUNNEL_LIFETIME, tokio::io::copy_bidirectional(&mut up, &mut viewer)).await;
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, wire::SCREEN_UPGRADE)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `PUT /v1/teammates/{user}`: the OS user and home a teammate's runs of this machine's
/// user's shared Bots get here, made on first use (ADR 0048). With `?cred=` (as for
/// heartbeats), it also says which of their own harness logins exist (ADR 0062).
async fn put_teammate(State(a): State<Arc<Agent>>, UrlPath(user): UrlPath<String>, RawQuery(q): RawQuery, Json(r): Json<wire::TeammateRequest>) -> Response {
    if r.owner_id != a.identity().user_id {
        return refuse(StatusCode::FORBIDDEN, "This machine runs only its own user's Bots.");
    }
    if a.upgrader.staging() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
    }
    match a.teammate(&user).await {
        Ok(t) => {
            if t.created {
                println!("Teammate user {} made for runs of shared Bots.", t.user);
            }
            let mut reply = t.reply();
            reply.logins = teammate_logins(&a, &user, Some(&t), q.as_deref());
            Json(reply).into_response()
        }
        Err(r) => r,
    }
}

/// `GET /v1/teammates/{user}/logins?cred=...`: which of a teammate's own harness logins
/// exist here (ADR 0062). Never makes their user: one who has none is logged out.
async fn get_teammate_logins(State(a): State<Arc<Agent>>, UrlPath(user): UrlPath<String>, RawQuery(q): RawQuery) -> Response {
    if !plain_name(&user) || user == a.identity().user_id {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's id isn't a plain name, or is this machine's own user.");
    }
    let bots = match a.job_user() {
        Ok(ids) => ids,
        Err(r) => return r,
    };
    let (b, id) = (a.clone(), user.clone());
    let found = tokio::task::spawn_blocking(move || {
        let stand_in = b.cfg.teammate_stand_in.is_some();
        b.teammates.existing(&id, not_teammates(stand_in, bots))
    })
    .await
    .ok()
    .flatten();
    let logins = teammate_logins(&a, &user, found.as_ref(), q.as_deref());
    Json(wire::TeammateLogins { known: found.is_some(), logins }).into_response()
}

/// `POST /v1/teammates/{user}/remove`: the teammate left (ADR 0052). Their jobs and
/// screens stop, then `Teammates::remove` does the rest. Never the machine's own user.
async fn remove_teammate(State(a): State<Arc<Agent>>, UrlPath(user): UrlPath<String>, Json(r): Json<wire::TeammateRemoval>) -> Response {
    if r.owner_id != a.identity().user_id {
        return refuse(StatusCode::FORBIDDEN, "This machine runs only its own user's Bots.");
    }
    if !plain_name(&user) || !plain_name(&r.cleanup_id) {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's and the removal's ids must be plain names.");
    }
    if user == r.owner_id {
        return refuse(StatusCode::BAD_REQUEST, "That is this machine's own user, not a teammate.");
    }
    let files = match (r.files.as_str(), r.archive_name.as_deref()) {
        (wire::TEAMMATE_FILES_ARCHIVE, Some(name)) if plain_name(name) => match a.job_user() {
            Ok(Some(ids)) => Files::Archive { home: a.cfg.home.clone(), ids, name: name.to_string() },
            Ok(None) => return refuse(StatusCode::CONFLICT, "Work is archived only to the Bots' own user, and this machine has none."),
            Err(r) => return r,
        },
        (wire::TEAMMATE_FILES_DELETE, None) if r.hold => Files::Hold,
        (wire::TEAMMATE_FILES_DELETE, None) => Files::Delete,
        _ => return refuse(StatusCode::BAD_REQUEST, "Say archive with a plain archive name, or delete."),
    };
    if a.upgrader.staging() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
    }
    let Some(leaving) = a.teammates.start_leaving(&user) else {
        return refuse(StatusCode::CONFLICT, "That teammate's user is being removed already.");
    };
    let jobs = a.stop_jobs_for(&user).await;
    // Their logins run as their user, so stopping its processes below ends them anyway.
    a.logins.abort_for(&user);
    let mut screens = 0;
    let suffix = format!("@{user}");
    for key in a.screens.report().running.into_iter().filter(|k| k.ends_with(&suffix)) {
        screens += a.screens.stop(&key).await as u32;
    }
    let (b, id) = (a.clone(), user.clone());
    let done = tokio::task::spawn_blocking(move || {
        let stand_in = b.cfg.teammate_stand_in.is_some();
        b.teammates.remove(&id, &r.cleanup_id, &files, not_teammates(stand_in, b.bot().ids))
    })
    .await;
    drop(leaving);
    match done {
        Ok(Ok(done)) => {
            if !done.already_gone {
                println!(
                    "Teammate user {} removed: {} jobs, {} screens and {} processes stopped; work {}.",
                    done.user, jobs, screens, done.processes_stopped, done.files
                );
            }
            Json(done.reply(jobs, screens)).into_response()
        }
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't remove the teammate's user: {e}")),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `POST /v1/teammates/{user}/purge`: deletes the work a removal held aside.
async fn purge_teammate(State(a): State<Arc<Agent>>, UrlPath(user): UrlPath<String>, Json(r): Json<wire::TeammatePurge>) -> Response {
    if r.owner_id != a.identity().user_id {
        return refuse(StatusCode::FORBIDDEN, "This machine runs only its own user's Bots.");
    }
    if !plain_name(&user) || !plain_name(&r.cleanup_id) {
        return refuse(StatusCode::BAD_REQUEST, "The teammate's and the removal's ids must be plain names.");
    }
    let t = a.teammates.clone();
    match tokio::task::spawn_blocking(move || t.purge(&r.cleanup_id)).await {
        Ok(Ok(purged)) => Json(wire::TeammatePurged { purged }).into_response(),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't delete the held work: {e}")),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// The sweep a `/v1/retention` request asks for, over the HOMEs Bots use here: the
/// user's, then each teammate's (ADR 0112). Err: a path or name that isn't plain.
fn retention_sweep(r: &wire::RetentionRequest, home: &Path, teammates: &[PathBuf]) -> Result<crate::sweep::Sweep, &'static str> {
    use crate::sweep::{Folder, Root, Sweep};
    let dirs_ok = r.home.iter().chain(&r.state).all(|d| wire::home_path(&d.path) && (1..=8).contains(&d.depth));
    if !dirs_ok || r.home.len() + r.state.len() > 32 {
        return Err("Session folders must be up to 32 plain paths inside HOME, each 1 to 8 folders deep.");
    }
    if !r.bots.iter().chain(&r.archives).all(|n| plain_name(n)) || r.bots.len() > 10_000 || r.archives.len() > 1_000 {
        return Err("Bot ids and archive names must be plain names.");
    }
    if !r.probe.iter().all(|p| p.len() <= 160 && crate::sweep::plain_path(p)) || r.probe.len() > 10_000 {
        return Err("Files to look for must be plain paths under a Bots folder.");
    }
    let base = |p: &Path| p.display().to_string();
    let mut s = Sweep { before: r.before, keep: r.keep.clone(), report: r.report.clone(), ..Default::default() };
    for h in std::iter::once(home).chain(teammates.iter().map(PathBuf::as_path)) {
        s.roots.extend(r.home.iter().map(|d| Root { base: base(h), path: d.path.clone(), depth: d.depth, transcript: d.transcript }));
        for bot in &r.bots {
            s.roots.extend(r.state.iter().map(|d| Root { base: base(h), path: format!("bots/{bot}/{}", d.path), depth: d.depth, transcript: d.transcript }));
        }
    }
    s.folders = r.archives.iter().map(|n| Folder { base: base(home), path: format!("work/{}/{n}", wire::TEAMMATE_ARCHIVE_DIR) }).collect();
    Ok(s)
}

/// `PUT /v1/egress-policy`: the outbound allow-list for every uid but root and the OS's
/// network daemons (ADR 0135). Answers how its rules stand once they are loaded.
async fn put_egress_policy(State(a): State<Arc<Agent>>, Json(p): Json<wire::EgressPolicy>) -> Response {
    if !egress_allow::mode_ok(&p.mode) {
        return refuse(StatusCode::BAD_REQUEST, "mode must be open or allow_list");
    }
    if let Err(e) = egress_allow::entries(&p.allow) {
        return refuse(StatusCode::BAD_REQUEST, e);
    }
    if p.mode == wire::EGRESS_OPEN && !p.allow.is_empty() {
        return refuse(StatusCode::BAD_REQUEST, "an open policy lists nothing");
    }
    Json(a.apply_egress(p).await).into_response()
}

/// `PUT /v1/team-network`: lets the harness egress rules through to the team network's
/// subnet, or to none (ADR 0202). Only a private IPv4 network is taken. Answers how the
/// rules stand once they are loaded.
async fn put_team_network(State(a): State<Arc<Agent>>, Json(r): Json<wire::TeamNetworkRules>) -> Response {
    let subnet = match r.subnet.as_deref().map(team_rules::subnet).transpose() {
        Ok(s) => s,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, e),
    };
    Json(a.apply_team_rules(subnet).await).into_response()
}

/// `POST /v1/retention`: deletes old harness session files and archived teammates' work
/// (ADR 0112). botd sends it only while none of the Bots it sweeps for is running.
async fn retention(State(a): State<Arc<Agent>>, Json(r): Json<wire::RetentionRequest>) -> Response {
    if r.owner_id != a.identity().user_id {
        return refuse(StatusCode::FORBIDDEN, "This machine runs only its own user's Bots.");
    }
    let teammates: Vec<(String, PathBuf)> = a.teammates.known().into_iter().filter(|t| plain_name(t)).map(|t| (t.clone(), a.teammates.home_of(&t))).collect();
    let homes: Vec<PathBuf> = teammates.iter().map(|(_, h)| h.clone()).collect();
    let s = match retention_sweep(&r, &a.cfg.home, &homes) {
        Ok(s) => s,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, e),
    };
    let home = a.cfg.home.clone();
    let swept = move || {
        let mut out = crate::sweep::run(&s);
        // Each probe in every HOME before the next, in botd's order, which it turns each
        // pass, so past the cap every database still gets its turn.
        let homes: Vec<(Option<String>, PathBuf)> = std::iter::once((None, home)).chain(teammates.into_iter().map(|(t, h)| (Some(t), h))).collect();
        'probes: for p in &r.probe {
            for (user, h) in &homes {
                if out.found.len() >= wire::RETENTION_FOUND_MAX {
                    break 'probes;
                }
                if std::fs::symlink_metadata(h.join("bots").join(p)).is_ok_and(|m| m.is_file()) {
                    out.found.push((user.clone(), p.clone()));
                }
            }
        }
        out
    };
    match tokio::task::spawn_blocking(swept).await {
        Ok(out) => Json(out).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router(a: Arc<Agent>) -> Router {
    Router::new()
        .route("/v1/heartbeat", get(heartbeat))
        .route("/v1/jobs", post(start_job))
        .route("/v1/jobs/{id}/abort", post(abort_job))
        .route("/v1/harnesses", axum::routing::put(set_harnesses))
        .route("/v1/upgrade", post(start_upgrade))
        .route("/v1/logins", post(start_login))
        .route("/v1/logins/forget", post(login_forget))
        .route("/v1/logins/{id}/input", post(login_input))
        .route("/v1/logins/{id}/abort", post(login_abort))
        .route("/v1/sync", post(sync_plan))
        .route("/v1/sync/{id}/blobs/{sha}", axum::routing::put(sync_blob))
        .route("/v1/sync/{id}/finish", post(sync_finish))
        .route("/v1/bot-user", axum::routing::put(set_bot_user))
        .route("/v1/screens/{bot}", axum::routing::put(put_screen).delete(delete_screen))
        .route("/v1/screens/{bot}/tunnel", get(screen_tunnel))
        .route("/v1/teammates/{user}", axum::routing::put(put_teammate))
        .route("/v1/teammates/{user}/logins", get(get_teammate_logins))
        .route("/v1/teammates/{user}/remove", post(remove_teammate))
        .route("/v1/teammates/{user}/purge", post(purge_teammate))
        .route("/v1/retention", post(retention))
        .route("/v1/egress-policy", axum::routing::put(put_egress_policy))
        .route("/v1/team-network", axum::routing::put(put_team_network))
        .layer(DefaultBodyLimit::max(MAX_RELAY_BODY))
        .with_state(a)
}

pub async fn serve(listener: tokio::net::TcpListener, a: Arc<Agent>) {
    let tls_agent = a.clone();
    let tls: pki::Tls = Arc::new(move || tls_agent.current.read().unwrap().1.clone());
    pki::serve_with(listener, tls, router(a), admit, true).await
}

/// For the relay: no overall timeout, since an approval can wait a day.
fn relay_client(cfg: &Config, id: &Identity) -> Result<reqwest::Client, String> {
    let config = pki::client_config(&cfg.ca(), Some(id.chain()))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())
}

/// Headers a Bot's call carries to botd; nothing else crosses.
const RELAYED: [header::HeaderName; 4] = [
    header::AUTHORIZATION,
    header::CONTENT_TYPE,
    header::ACCEPT,
    header::USER_AGENT,
];

/// `/api/...` on loopback: sends a Bot's call to botd over mutual TLS, as
/// `/v1/machines/<id>/api/...`, and its answer back. botd checks the Bot's token.
async fn relay(State(a): State<Arc<Agent>>, req: Request) -> Response {
    let Some(rest) = req.uri().path().strip_prefix("/api/") else {
        return refuse(StatusCode::NOT_FOUND, "Only /api/ is relayed.");
    };
    let mut url = format!(
        "{}/v1/machines/{}/api/{rest}",
        a.cfg.control_url, a.cfg.machine_id
    );
    if let Some(q) = req.uri().query() {
        url = format!("{url}?{q}");
    }
    let method = req.method().clone();
    let mut headers = HeaderMap::new();
    for h in RELAYED {
        if let Some(v) = req.headers().get(&h) {
            headers.insert(h, v.clone());
        }
    }
    let body = match axum::body::to_bytes(req.into_body(), MAX_RELAY_BODY).await {
        Ok(b) => b,
        Err(_) => return refuse(StatusCode::PAYLOAD_TOO_LARGE, "That request is too big."),
    };
    let client = match relay_client(&a.cfg, &a.identity()) {
        Ok(c) => c,
        Err(e) => return refuse(StatusCode::BAD_GATEWAY, e),
    };
    let r = client
        .request(method, url)
        .headers(headers)
        .body(body)
        .send()
        .await;
    match r {
        Ok(r) => {
            let mut res = Response::builder().status(r.status());
            if let Some(t) = r.headers().get(header::CONTENT_TYPE) {
                res = res.header(header::CONTENT_TYPE, t.clone());
            }
            let body = match r.bytes().await {
                Ok(b) => b,
                Err(e) => return refuse(StatusCode::BAD_GATEWAY, e.without_url().to_string()),
            };
            res.body(Body::from(body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => refuse(
            StatusCode::BAD_GATEWAY,
            format!("Couldn't reach botd: {}", e.without_url()),
        ),
    }
}

pub fn relay_router(a: Arc<Agent>) -> Router {
    Router::new()
        .route("/api/{*rest}", any(relay))
        .layer(DefaultBodyLimit::max(MAX_RELAY_BODY))
        .with_state(a)
}

/// Serves the relay on loopback, for Bots on this machine.
pub async fn serve_relay(listener: tokio::net::TcpListener, a: Arc<Agent>) {
    let _ = axum::serve(listener, relay_router(a)).await;
}

/// Enrolls if it must (retrying), then serves and rotates until stopped.
pub async fn run(cfg: Config) -> Result<(), String> {
    let id = match load(&cfg) {
        Some(id) => id,
        None => loop {
            match enroll(&cfg).await {
                Ok(id) => break id,
                Err(f) => {
                    eprintln!("Enrolling: {}", f.message);
                    // A refused token won't start working; don't hammer the control plane.
                    tokio::time::sleep(Duration::from_secs(if f.permanent { 600 } else { 15 }))
                        .await;
                }
            }
        },
    };
    println!(
        "Machine {}, certificate {} until {}.",
        id.machine_id,
        &id.fingerprint[..16],
        id.not_after
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.listen))?;
    println!("Answering the control plane on {}.", cfg.listen);
    let relay = tokio::net::TcpListener::bind(cfg.api_listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.api_listen))?;
    println!("Relaying Bots' calls to botd from {}.", cfg.api_listen);
    let agent = Agent::new(cfg, id)?;
    tokio::spawn(serve_relay(relay, agent.clone()));
    let rotating = agent.clone();
    tokio::spawn(async move {
        // Checks at once, so a machine restarted near its certificate's end renews it
        // while it still can.
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if rotating.reload_if_changed() {
                println!(
                    "Using the certificate {} saved by enroll.",
                    &rotating.identity().fingerprint[..16]
                );
            }
            match rotating.rotate_if_due().await {
                Ok(true) => println!(
                    "New certificate {}.",
                    &rotating.identity().fingerprint[..16]
                ),
                Ok(false) => {}
                Err(f) => {
                    eprintln!("Rotating: {}", f.message);
                    if f.permanent {
                        tokio::time::sleep(Duration::from_secs(600)).await;
                    }
                }
            }
        }
    });
    let mut restarting = agent.restarting();
    tokio::select! {
        () = serve(listener, agent) => {}
        _ = restarting.wait_for(|r| *r) => println!("Restarting."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An egress script shaped as the first boot's: it writes its heredoc where the rules
    /// go, and fails when told to.
    fn stand_in_egress(dir: &Path, fail: bool) -> PathBuf {
        let path = dir.join("egress");
        let tail = if fail { "echo 'nft: syntax error' >&2\nexit 1\n" } else { "" };
        let s = format!("#!/bin/sh\nset -e\n{{\n  cat <<'DENY'\n    ip daddr {{ 10.0.0.0/8 }} counter reject\nDENY\n}} > \"$SUPERBOT_HARDENING_STATE/rules\"\n{tail}");
        std::fs::write(&path, s).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn the_team_subnet_is_written_into_the_egress_script_and_loaded() {
        let dir = std::env::temp_dir().join(format!("sb-agent-team-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state");
        let script = stand_in_egress(&dir, false);
        let none = || team_report(read_script(&script), None);
        assert_eq!((none().state.as_str(), none().subnet), (wire::TEAM_RULES_ON, None));

        let r = load_team_rules(&script, &state, Some("10.248.0.0/22"));
        assert_eq!((r.state.as_str(), r.subnet.as_deref(), r.error), (wire::TEAM_RULES_ON, Some("10.248.0.0/22"), None));
        let rules = std::fs::read_to_string(state.join("rules")).unwrap();
        assert!(rules.starts_with("    ip daddr 10.248.0.0/22 accept\n    ip daddr { 10.0.0.0/8 }"), "before the denies: {rules}");
        assert_eq!(none().subnet.as_deref(), Some("10.248.0.0/22"), "read back from the script");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&script).unwrap().permissions().mode() & 0o777, 0o755);
        assert!(!script.with_extension("new").exists());

        let r = load_team_rules(&script, &state, None);
        assert_eq!((r.state.as_str(), r.subnet), (wire::TEAM_RULES_ON, None));
        assert!(!std::fs::read_to_string(state.join("rules")).unwrap().contains("accept"), "withdrawn");

        // A script that fails to load says so, and goes on saying so until a change.
        let script = stand_in_egress(&dir, true);
        let r = load_team_rules(&script, &state, Some("10.248.0.0/22"));
        assert_eq!((r.state.as_str(), r.subnet.as_deref()), (wire::TEAM_RULES_FAILED, Some("10.248.0.0/22")));
        assert!(r.error.as_deref().unwrap().ends_with("nft: syntax error"), "{:?}", r.error);
        assert_eq!(team_report(read_script(&script), Some(&r)), r);
        // And after the agent restarts: what the script says isn't taken for loaded.
        assert_eq!(last_team_rules(&state), None);
        save_team_rules(&state, &r);
        assert_eq!(team_report(read_script(&script), last_team_rules(&state).as_ref()), r);
        assert_eq!(team_report(read_script(&script), Some(&team_failed(None, "old".into()))).state, wire::TEAM_RULES_ON);

        // No script: nothing to let through. Someone else's script: left alone.
        let gone = dir.join("missing");
        assert_eq!(load_team_rules(&gone, &state, Some("10.248.0.0/22")).state, wire::TEAM_RULES_NONE);
        assert!(!gone.exists());
        let theirs = dir.join("theirs");
        std::fs::write(&theirs, "#!/bin/sh\nexit 0\n").unwrap();
        let r = load_team_rules(&theirs, &state, Some("10.248.0.0/22"));
        assert_eq!((r.state.as_str(), r.error.as_deref()), (wire::TEAM_RULES_FAILED, Some(NOT_OURS)));
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "#!/bin/sh\nexit 0\n");
        assert_eq!(team_report(read_script(&theirs), None).state, wire::TEAM_RULES_FAILED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_job_cant_move_its_home_path_or_temporary_folder() {
        let mut env: BTreeMap<String, String> =
            [("HOME", "/root"), ("PATH", "/tmp"), ("TMPDIR", "/tmp"), ("BOT_TOKEN", "t")].map(|(k, v)| (k.into(), v.into())).into();
        scrub(&mut env);
        assert_eq!(env.keys().collect::<Vec<_>>(), ["BOT_TOKEN"]);
    }

    #[test]
    fn only_what_nothing_in_has_changed_for_a_day_is_swept() {
        let root = std::env::temp_dir().join(format!("sb-agent-sweep-{}", std::process::id()));
        let tmp = root.join(TMP);
        let outside = root.join("outside");
        std::fs::create_dir_all(tmp.join("job-a/inner")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), "x").unwrap();
        std::fs::write(tmp.join("loose"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tmp.join("link")).unwrap();
        let day = TMP_KEEP + Duration::from_secs(60);
        sweep_tmps(std::slice::from_ref(&tmp), SystemTime::now());
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 3, "nothing a day old yet");
        // A file changed inside an old folder keeps the whole folder.
        let old = SystemTime::now() - day;
        for p in [tmp.join("job-a"), tmp.join("job-a/inner")] {
            std::fs::File::open(&p).unwrap().set_modified(old).unwrap();
        }
        std::fs::write(tmp.join("job-a/inner/fresh"), "x").unwrap();
        sweep_tmps(std::slice::from_ref(&tmp), SystemTime::now());
        assert!(tmp.join("job-a/inner/fresh").exists(), "a fresh file inside keeps its folder");
        sweep_tmps(std::slice::from_ref(&tmp), SystemTime::now() + day);
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0, "everything older went");
        assert!(outside.join("keep").exists(), "a link's target stays");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_job_gets_its_own_temporary_folder() {
        let home = std::env::temp_dir().join(format!("sb-agent-jobtmp-{}", std::process::id()));
        std::fs::create_dir_all(home.join(TMP)).unwrap();
        let dir = job_tmp(&home, "job-1", None).unwrap();
        assert_eq!(dir, home.join(TMP).join("job-1"));
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&dir).unwrap().permissions()) & 0o777, 0o700);
        assert_eq!(job_tmp(&home, "job-1", None), None, "never one another job has");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_teammates_temporary_folder_is_made_before_a_job_or_login() {
        let home = std::env::temp_dir().join(format!("sb-agent-tmp-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        // SAFETY: no arguments.
        let me = unsafe { Ids { uid: libc::geteuid(), gid: libc::getegid() } };
        own_tmp(&home, me).unwrap();
        let m = std::fs::metadata(home.join(TMP)).unwrap();
        assert!(m.is_dir() && std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777 == 0o700);
        own_tmp(&home, me).unwrap();
        std::fs::remove_dir(home.join(TMP)).unwrap();
        std::fs::write(home.join(TMP), "").unwrap();
        assert!(own_tmp(&home, me).unwrap_err().contains("Couldn't make"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn teammates_users_are_never_root_the_agents_the_bots_or_privileged() {
        let bots = Ids { uid: 990, gid: 990 };
        let check = not_teammates(false, Some(bots));
        assert!(check(Ids { uid: 0, gid: 5 }).is_err());
        assert!(check(Ids { uid: 5, gid: 0 }).is_err());
        assert!(check(bots).is_err());
        assert!(check(Ids { uid: 991, gid: 990 }).is_err(), "the Bots' group");
        // SAFETY: no arguments.
        let me = unsafe { Ids { uid: libc::geteuid(), gid: libc::getegid() } };
        assert!(check(me).is_err(), "the agent's own");
        assert!(check(Ids { uid: 4_000_000_001, gid: 4_000_000_001 }).unwrap_err().contains("no name"));
        // `nobody` is in no privileged group on any distribution we run on.
        if let Some((nobody, _)) = runas::lookup("nobody") {
            assert_eq!(check(nobody), Ok(()));
        }
        assert_eq!(not_teammates(true, Some(bots))(me), Ok(()), "a stand-in is the agent's own user");
    }

    #[test]
    fn hardening_is_read_with_care() {
        let dir = std::env::temp_dir().join(format!("sb-agent-hardening-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (status, egress, reboot) = (dir.join("hardening"), dir.join("egress"), dir.join("reboot-required"));
        assert_eq!(hardening(&status, &egress, &reboot), None, "not hardened");

        std::fs::write(&status, "ssh=on\nkernel=partial\nupdates=failed\nBAD=x\nlong=aaaaaaaaaaaaaaaaaaaaaaaa\nnoequals\n").unwrap();
        let h = hardening(&status, &egress, &reboot).unwrap();
        let steps: Vec<_> = h.steps.iter().map(|(k, v)| format!("{k}={v}")).collect();
        assert_eq!(steps, ["kernel=partial", "ssh=on", "updates=failed"]);
        assert!(!h.egress && !h.reboot_required);

        std::fs::write(&egress, "failed\n").unwrap();
        assert!(!hardening(&status, &egress, &reboot).unwrap().egress);
        std::fs::write(&egress, "on\n").unwrap();
        std::fs::write(&reboot, "").unwrap();
        let h = hardening(&status, &egress, &reboot).unwrap();
        assert!(h.egress && h.reboot_required);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
