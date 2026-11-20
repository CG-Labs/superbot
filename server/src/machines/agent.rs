//! The machine agent (`superbot-machine`, ADR 0031), a stub for now: it enrolls with
//! the control plane, keeps its certificate fresh, and answers botd's heartbeat over
//! mutual TLS. It turns jobs down (501) until machines run Bots. Shared by the binary
//! and botd's tests, so it uses nothing of botd's but `pki` and `wire`.
//!
//! Settings (cloud-init writes them to /etc/superbot/machine.env):
//! - `SUPERBOT_CONTROL_URL`: botd's machine port, `https://<host>:<port>`.
//! - `SUPERBOT_MACHINE_ID`: this machine's id at the control plane.
//! - `SUPERBOT_CA_FILE`: the control-plane CA (default /etc/superbot/ca.pem).
//! - `SUPERBOT_ENROLL_TOKEN`, or `SUPERBOT_ENROLL_TOKEN_FILE` (deleted once used).
//! - `SUPERBOT_AGENT_LISTEN`: default 0.0.0.0:7443.
//! - `STATE_DIRECTORY` (systemd) or `SUPERBOT_STATE_DIR`: where the key and
//!   certificate live (default /var/lib/superbot-machine).

use super::pki::{self, Peer};
use super::wire;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use zeroize::Zeroizing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct Config {
    pub control_url: String,
    pub machine_id: String,
    pub ca_pem: String,
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub token: Option<Zeroizing<String>>,
    pub token_file: Option<PathBuf>,
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
        Ok(Config {
            control_url,
            machine_id,
            ca_pem,
            state_dir,
            listen,
            token: var("SUPERBOT_ENROLL_TOKEN").map(Zeroizing::new),
            token_file: var("SUPERBOT_ENROLL_TOKEN_FILE").map(PathBuf::from),
        })
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

/// The running agent: its identity and the TLS settings made from it.
pub struct Agent {
    pub cfg: Config,
    current: RwLock<(Arc<Identity>, Arc<ServerConfig>)>,
}

impl Agent {
    pub fn new(cfg: Config, id: Identity) -> Result<Arc<Agent>, String> {
        let server = Arc::new(server_config(&cfg, &id)?);
        Ok(Arc::new(Agent {
            cfg,
            current: RwLock::new((Arc::new(id), server)),
        }))
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.current.read().unwrap().0.clone()
    }

    pub fn replace(&self, id: Identity) -> Result<(), String> {
        let server = Arc::new(server_config(&self.cfg, &id)?);
        *self.current.write().unwrap() = (Arc::new(id), server);
        Ok(())
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

pub fn admit(peer: &Peer) -> bool {
    peer.cert
        .as_ref()
        .and_then(|c| pki::facts(c))
        .is_some_and(|f| f.uris.iter().any(|u| u == pki::CONTROL_PLANE_URI))
}

async fn heartbeat(State(a): State<Arc<Agent>>) -> Json<wire::Heartbeat> {
    let id = a.identity();
    Json(wire::Heartbeat {
        machine_id: id.machine_id.clone(),
        user_id: id.user_id.clone(),
        version: VERSION.into(),
        certificate: id.fingerprint.clone(),
        time: now_ms(),
    })
}

async fn job(Json(_job): Json<wire::JobRequest>) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(wire::ErrorReply {
            error: "This machine's agent can't run Bots yet.".into(),
        }),
    )
        .into_response()
}

pub fn router(a: Arc<Agent>) -> Router {
    Router::new()
        .route("/v1/heartbeat", get(heartbeat))
        .route("/v1/jobs", post(job))
        .with_state(a)
}

pub async fn serve(listener: tokio::net::TcpListener, a: Arc<Agent>) {
    let tls_agent = a.clone();
    let tls: pki::Tls = Arc::new(move || tls_agent.current.read().unwrap().1.clone());
    pki::serve(listener, tls, router(a), admit).await
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
    let agent = Agent::new(cfg, id)?;
    let rotating = agent.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            match rotating.rotate_if_due().await {
                Ok(true) => println!(
                    "New certificate {}.",
                    &rotating.identity().fingerprint[..16]
                ),
                Ok(false) => {}
                Err(f) => eprintln!("Rotating: {}", f.message),
            }
        }
    });
    serve(listener, agent).await;
    Ok(())
}
