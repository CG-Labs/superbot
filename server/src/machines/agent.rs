//! The machine agent (`superbot-machine`, ADR 0031, ADR 0036): it enrolls with the
//! control plane, keeps its certificate fresh, and answers botd over mutual TLS: a
//! heartbeat, and jobs, each one harness run for one of its user's Bots, streamed
//! back as it happens. It knows nothing of harnesses: botd builds each command. Bots
//! on the machine reach botd's API (approvals, `botctl`) through the agent's relay
//! on loopback, which forwards over mutual TLS. It also runs harness logins and takes
//! copies of the user's folder (ADR 0041). Shared by the binary and botd's tests, so
//! it uses nothing of botd's but its sibling modules.
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
//! - `SUPERBOT_MAX_JOBS`: jobs at once (default 8).
//! - `SUPERBOT_AGENT_BIN`: this binary, replaced by upgrades (ADR 0039; default
//!   `/usr/local/lib/superbot/superbot-machine`).
//! - `SUPERBOT_BOT_USER`: the OS user Bots run as once botd asks (ADR 0043; default
//!   `superbot-bots`). Never root, nor the agent's own user.

use super::job;
use super::landing::Landing;
use super::pki::{self, Peer};
use super::runas::{self, Ids};
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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
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
            .unwrap_or(8)
            .max(1);
        let bot_user = var("SUPERBOT_BOT_USER").unwrap_or_else(|| wire::BOT_USER.into());
        if !runas::plain_user(&bot_user) || bot_user == "root" {
            return Err("SUPERBOT_BOT_USER must be a plain user name, not root".into());
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
        }
        job::Host {
            clear_env: true,
            remove: Vec::new(),
            env,
            user,
        }
    }

    /// Why `ids` can't be the Bots' user, if it can't.
    fn check_bot_ids(&self, ids: Ids) -> Result<(), String> {
        if ids.uid == 0 || ids.gid == 0 {
            return Err(format!("{} is root or in root's group; Bots can't run as it.", self.bot_user));
        }
        // SAFETY: no arguments.
        if ids.uid == unsafe { libc::geteuid() } && !self.allow_own_user {
            return Err(format!("{} is the agent's own user; Bots need their own.", self.bot_user));
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
    /// Running jobs by id; sending true stops one.
    jobs: Mutex<HashMap<String, watch::Sender<bool>>>,
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
}

/// Where the Bots' user stands. Once botd has asked, no job runs as root again.
#[derive(Clone, Default)]
struct Bot {
    status: Option<wire::BotUserStatus>,
    /// Set only when ready.
    ids: Option<Ids>,
}

const BOT_USER_FILE: &str = "bot-user.json";

/// The Bots' user, saved once it owns the home.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedBotUser {
    user: String,
    uid: u32,
    gid: u32,
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
    let Some(saved) = std::fs::read(cfg.state_dir.join(BOT_USER_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<SavedBotUser>(&b).ok())
    else {
        return Bot::default();
    };
    let want = Ids { uid: saved.uid, gid: saved.gid };
    let checked = (|| {
        if saved.user != cfg.bot_user {
            return Err(format!("Bots ran as {}, but the agent is set to {}.", saved.user, cfg.bot_user));
        }
        match runas::lookup(&saved.user) {
            Some((ids, _)) if ids == want => {}
            Some(_) => return Err(format!("{} isn't the user it was (uid {}).", saved.user, saved.uid)),
            None => return Err(format!("{} is gone.", saved.user)),
        }
        cfg.check_bot_ids(want)?;
        use std::os::unix::fs::MetadataExt;
        let owned = std::fs::symlink_metadata(&cfg.home).is_ok_and(|m| m.is_dir() && m.uid() == want.uid);
        if !owned {
            runas::hand_over(&cfg.home, want).map_err(|e| format!("{}: {e}", cfg.home.display()))?;
        }
        cfg.open_paths(tools)
    })();
    match checked {
        Ok(()) => Bot {
            status: Some(bot_status(wire::BOT_USER_READY, &saved.user, Some(want.uid), None)),
            ids: Some(want),
        },
        Err(e) => {
            eprintln!("Bots' user: {e}");
            Bot {
                status: Some(bot_status(wire::BOT_USER_FAILED, &saved.user, Some(want.uid), Some(e))),
                ids: None,
            }
        }
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
        });
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(a.tools.clone().work());
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

    fn jobs(&self) -> std::sync::MutexGuard<'_, HashMap<String, watch::Sender<bool>>> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
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

    /// Makes the Bots' user if it must, hands it the home, and saves it, so from now on
    /// everything a Bot touches runs as it. Copies of the folder wait meanwhile.
    fn set_up_bot_user(&self) -> Result<Ids, String> {
        let cfg = &self.cfg;
        let ids = runas::ensure_user(&cfg.bot_user, &cfg.home)?;
        cfg.check_bot_ids(ids)?;
        let _copies = self.landing.hold();
        let handed = runas::hand_over(&cfg.home, ids).map_err(|e| format!("{}: {e}", cfg.home.display()))?;
        cfg.open_paths(&self.tools)?;
        work_dirs(cfg, Some(ids))?;
        let saved = SavedBotUser { user: cfg.bot_user.clone(), uid: ids.uid, gid: ids.gid };
        write_private(
            &cfg.state_dir.join(BOT_USER_FILE),
            &serde_json::to_string(&saved).unwrap_or_default(),
            0o600,
        )?;
        self.landing.set_user(ids);
        println!(
            "Bots now run as {} (uid {}): handed it {} files, left {} as they were.",
            cfg.bot_user, ids.uid, handed.changed, handed.skipped
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

/// Whether each harness asked about is logged in, and those logging in now.
fn logins(a: &Agent, query: Option<&str>) -> BTreeMap<String, wire::LoginStatus> {
    let running = a.logins.running();
    let mut out: BTreeMap<String, wire::LoginStatus> = creds(query)
        .into_iter()
        .map(|(h, files)| {
            let since = runas::as_user(a.bot().ids, || super::terminal::logged_in(&a.cfg.home, &files))
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
        for dir in [cfg.home.join("work"), cfg.home.join("bots")] {
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

/// Only the control plane's certificate gets here (`admit`), so answering one is the
/// proof an upgraded agent works: its trial ends.
async fn heartbeat(State(a): State<Arc<Agent>>, RawQuery(q): RawQuery) -> Json<wire::Heartbeat> {
    if a.upgrader.commit() {
        println!("Upgrade: the control plane reached the new agent; keeping it.");
    }
    let id = a.identity();
    let (plan, harnesses) = a.tools.report();
    Json(wire::Heartbeat {
        machine_id: id.machine_id.clone(),
        user_id: id.user_id.clone(),
        version: VERSION.into(),
        certificate: id.fingerprint.clone(),
        time: now_ms(),
        protocol: wire::PROTOCOL,
        layout: Some(a.cfg.layout()),
        missing: bins(q.as_deref())
            .into_iter()
            .filter(|(_, known)| !known.is_some_and(|k| a.cfg.has(k)))
            .map(|(b, _)| b)
            .collect(),
        jobs: a.running() as u32,
        can: [wire::CAN_HARNESSES, wire::CAN_LOGINS, wire::CAN_SYNC, wire::CAN_BOT_USER]
            .into_iter()
            .chain(a.upgrader.build.is_some().then_some(wire::CAN_UPGRADE))
            .map(String::from)
            .collect(),
        build: a.upgrader.build.clone(),
        plan,
        harnesses,
        upgrade: a.upgrader.report(),
        logins: logins(&a, q.as_deref()),
        bot_user: a.bot().status,
    })
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
fn check(cfg: &Config, user_id: &str, j: &wire::JobRequest) -> Result<(), (StatusCode, String)> {
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
    if let Some(p) = paths.into_iter().find(|p| !inside(&cfg.home, p)) {
        return bad(format!("{p} isn't inside {}.", cfg.home.display()));
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

/// The agent sets HOME and PATH; a job can't move them.
fn scrub(env: &mut BTreeMap<String, String>) {
    env.retain(|k, _| k != "HOME" && k != "PATH");
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
    if let Err((code, msg)) = check(&a.cfg, &a.identity().user_id, &j) {
        return refuse(code, msg);
    }
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
        jobs.insert(j.job_id.clone(), stop_tx.clone());
        (permit, user)
    };
    let running = Running(a.clone(), j.job_id.clone(), permit);
    let stop = StopOnDrop(stop_tx);
    let _ = work_dirs(&a.cfg, user);
    let (ev_tx, ev_rx) = mpsc::channel::<wire::JobEvent>(256);
    let host = a.cfg.host(user);
    tokio::spawn(async move {
        let _running = running;
        let abort = async move {
            let _ = stop_rx.wait_for(|s| *s).await;
        };
        job::run(&host, &j, abort, &ev_tx).await;
    });
    // Held until the stream ends: dropping it stops the job.
    stream(ev_rx, wire::JobEvent::Ping, stop)
}

fn code_or(code: u16, fallback: StatusCode) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(fallback)
}

/// `POST /v1/logins`: runs a harness's login in a terminal here and streams what it
/// shows (ADR 0041). Its credentials stay in this machine's HOME. A dropped stream
/// stops it. Like a job, it holds off agent upgrades and harness updates.
async fn start_login(State(a): State<Arc<Agent>>, Json(r): Json<wire::LoginRequest>) -> Response {
    let run = match super::terminal::check(&r, |b| a.cfg.has(b)) {
        Ok(run) => run,
        Err((code, msg)) => return refuse(code_or(code, StatusCode::BAD_REQUEST), msg),
    };
    let _jobs = a.jobs();
    let user = match a.job_user() {
        Ok(u) => u,
        Err(r) => return r,
    };
    let env = a.cfg.host(user).env;
    if a.upgrader.staging() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its agent. Try again in a minute.");
    }
    let Some(permit) = a.tools.job_permit() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "This machine is updating its harnesses. Try again in a minute.");
    };
    match a.logins.start(&r, &run, &a.cfg.home, &env, user) {
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
    if a.logins.running().contains(&f.harness) {
        return refuse(StatusCode::CONFLICT, format!("A {} login is running here.", f.harness));
    }
    let user = match a.job_user() {
        Ok(u) => u,
        Err(r) => return r,
    };
    match runas::as_user(user, || super::terminal::forget(&a.cfg.home, &f.files)) {
        Ok(removed) => Json(wire::ForgetReply { removed }).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't act as the Bots' user: {e}")),
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
        Some(stop) => {
            let _ = stop.send(true);
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

/// botd's `/v1/agent` or `/v1/botctl`, over the CA-pinned channel, with this machine's
/// certificate.
async fn fetch(a: &Agent, path: &str) -> Result<Vec<u8>, String> {
    let config = pki::client_config(&a.cfg.ca(), Some(a.identity().chain()))?;
    let http = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| e.to_string())?;
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
            Err(e) => {
                eprintln!("Bots' user: {e}");
                Bot {
                    status: Some(bot_status(wire::BOT_USER_FAILED, &user, None, Some(e))),
                    ids: None,
                }
            }
        };
        up.set_bot(b);
    });
    (StatusCode::ACCEPTED, Json(a.bot().status)).into_response()
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
        .layer(DefaultBodyLimit::max(MAX_RELAY_BODY))
        .with_state(a)
}

pub async fn serve(listener: tokio::net::TcpListener, a: Arc<Agent>) {
    let tls_agent = a.clone();
    let tls: pki::Tls = Arc::new(move || tls_agent.current.read().unwrap().1.clone());
    pki::serve(listener, tls, router(a), admit).await
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
