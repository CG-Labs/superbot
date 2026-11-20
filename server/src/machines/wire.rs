//! What the control plane and a machine agent send each other (ADR 0031, ADR 0036).
//! Shared by botd and `superbot-machine`.
//!
//! botd's machine port (MACHINE_CONTROL_URL):
//! - `POST /v1/enroll` `EnrollRequest` -> `CertificateReply`. No client certificate.
//! - `GET /v1/machines/{id}` -> `MachineStatus`. The machine's own certificate.
//! - `POST /v1/machines/{id}/certificate` `RotateRequest` -> `CertificateReply`.
//! - `ANY /v1/machines/{id}/api/{path}`: botd's `/api/{path}`, for a Bot running on that
//!   machine (its own `BOT_TOKEN`, for one of the machine's user's Bots).
//! - `GET /v1/agent`, `GET /v1/botctl`: binaries, for cloud-init to install.
//!
//! The agent (MACHINE_AGENT_PORT), for botd's certificate only:
//! - `GET /v1/heartbeat[?bin=<name>...]` -> `Heartbeat`.
//! - `POST /v1/jobs` `JobRequest` -> a stream of `JobEvent`s, one JSON object per line.
//! - `POST /v1/jobs/{id}/abort` `AbortRequest`.
//! - `PUT /v1/harnesses` `HarnessPlan` (202): the harness CLIs to install (ADR 0038).
//! - `POST /v1/upgrade` `UpgradeRequest` (202): replace the agent with botd's build.
//!
//! Protocol 1 (`PROTOCOL`) is the first that runs Bots. A heartbeat without `protocol`
//! is from an agent before it, which can't. Installs and upgrades are additions to it:
//! an agent lists them in `can`.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The job protocol this build speaks. A job names it, and an agent refuses any other.
pub const PROTOCOL: u32 = 1;

/// The harness CLIs a heartbeat can ask about: every adapter's `bin()`.
pub const HARNESS_BINS: [&str; 4] = ["claude", "codex", "pi", "hermes"];

/// `name` as one of `HARNESS_BINS`, so what an agent looks up on disk is never the
/// request's own text.
pub fn harness_bin(name: &str) -> Option<&'static str> {
    HARNESS_BINS.into_iter().find(|k| *k == name)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollRequest {
    pub machine_id: String,
    pub token: String,
    /// A PEM certificate signing request for the machine's new key.
    pub csr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateRequest {
    pub csr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateReply {
    pub machine_id: String,
    pub user_id: String,
    pub certificate: String,
    pub ca: String,
    pub not_after: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineStatus {
    pub machine_id: String,
    pub user_id: String,
    pub state: String,
    pub enrollment: String,
    pub not_after: i64,
}

/// What an agent can do besides running jobs (`Heartbeat::can`).
pub const CAN_HARNESSES: &str = "harnesses";
pub const CAN_UPGRADE: &str = "upgrade";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Heartbeat {
    pub machine_id: String,
    pub user_id: String,
    pub version: String,
    /// Fingerprint of the certificate the agent serves with.
    pub certificate: String,
    pub time: i64,
    /// The job protocol it speaks; 0 (absent) before agents ran Bots.
    #[serde(default)]
    pub protocol: u32,
    /// Where Bots work on it. None before protocol 1.
    #[serde(default)]
    pub layout: Option<Layout>,
    /// Of the `bin`s the heartbeat asked about, those not on the harness PATH.
    #[serde(default)]
    pub missing: Vec<String>,
    /// Jobs running now.
    #[serde(default)]
    pub jobs: u32,
    /// `CAN_HARNESSES`, `CAN_UPGRADE`: empty before ADR 0038.
    #[serde(default)]
    pub can: Vec<String>,
    /// SHA-256 of the agent's own binary, when it knows it.
    #[serde(default)]
    pub build: Option<String>,
    /// `HarnessPlan::id` of the plan it holds, if any.
    #[serde(default)]
    pub plan: Option<String>,
    /// Each harness CLI it was asked for or has installed, by name.
    #[serde(default)]
    pub harnesses: BTreeMap<String, HarnessStatus>,
    /// Its current or last self-upgrade.
    #[serde(default)]
    pub upgrade: Option<UpgradeReport>,
}

/// The harness CLIs a machine should have (ADR 0038): pinned versions, each checked
/// against a checksum where its source has one. botd builds it from its adapters'
/// pins; the agent installs it without knowing what a harness is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessPlan {
    /// Node.js, for `Npm` sources. None when none is planned.
    pub node: Option<NodeRuntime>,
    pub harnesses: Vec<HarnessInstall>,
}

impl HarnessPlan {
    /// Names the plan: the start of the SHA-256 of its JSON.
    pub fn id(&self) -> String {
        use sha2::Digest;
        let d = sha2::Sha256::digest(serde_json::to_vec(self).unwrap_or_default());
        d.iter().take(8).map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeRuntime {
    pub version: String,
    /// By `std::env::consts::ARCH` (`x86_64`, `aarch64`).
    pub downloads: BTreeMap<String, Download>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Download {
    pub url: String,
    pub sha256: String,
}

/// One harness CLI: its program name (one of `HARNESS_BINS`), the exact version, and
/// where it comes from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessInstall {
    pub name: String,
    pub version: String,
    pub source: InstallSource,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum InstallSource {
    /// An npm package at `version`. `integrity` is the registry's SRI hash of its
    /// tarball (`sha512-...`), checked before it is installed; npm checks its
    /// dependencies against the registry's own hashes.
    Npm {
        package: String,
        integrity: Option<String>,
    },
    /// An installer script, checked against `sha256`, run with `args` and HOME set to
    /// a folder of its own. `bin` is where it leaves the program, under that folder.
    Script {
        url: String,
        sha256: String,
        args: Vec<String>,
        bin: String,
    },
}

/// A harness CLI on a machine.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessStatus {
    /// What is installed, if anything.
    pub version: Option<String>,
    /// What the plan asks for. None: installed, but no longer planned.
    pub wanted: Option<String>,
    /// `HARNESS_INSTALLED`, `HARNESS_QUEUED`, `HARNESS_INSTALLING` or `HARNESS_FAILED`.
    pub state: String,
    pub error: Option<String>,
    /// When `state` last changed.
    pub at: i64,
}

pub const HARNESS_INSTALLED: &str = "installed";
pub const HARNESS_QUEUED: &str = "queued";
pub const HARNESS_INSTALLING: &str = "installing";
pub const HARNESS_FAILED: &str = "failed";

/// Replace the agent with botd's build, served at `/v1/agent` (ADR 0038).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpgradeRequest {
    /// Chosen by botd; the agent's reports carry it back.
    pub id: String,
    pub version: String,
    /// SHA-256 of the new agent binary.
    pub sha256: String,
    /// SHA-256 of the botctl botd serves at `/v1/botctl`, replaced along with it.
    pub botctl_sha256: Option<String>,
    /// How long the new agent has to answer a heartbeat before it rolls back.
    pub trial_secs: u64,
}

/// How an upgrade went, as the agent saw it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeReport {
    pub id: String,
    /// `UPGRADE_STAGING`, `UPGRADE_TRIAL`, `UPGRADE_DONE`, `UPGRADE_ROLLED_BACK` or
    /// `UPGRADE_FAILED` (before the swap; nothing changed).
    pub state: String,
    pub from_version: String,
    pub from_build: String,
    pub to_version: String,
    pub to_build: String,
    pub reason: Option<String>,
    pub at: i64,
}

pub const UPGRADE_STAGING: &str = "staging";
pub const UPGRADE_TRIAL: &str = "trial";
pub const UPGRADE_DONE: &str = "done";
pub const UPGRADE_ROLLED_BACK: &str = "rolled_back";
pub const UPGRADE_FAILED: &str = "failed";

/// The machine's folders, as absolute paths on it. Every path in a job must be inside
/// `home`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layout {
    /// HOME for harnesses: their logins and sessions live here.
    pub home: String,
    /// The user's working folder, shared by all of their Bots.
    pub workspace: String,
    /// Holds one folder per Bot (`<bots>/<bot id>`): its memory and harness files.
    pub bots: String,
    /// Facts about the user, shared by their Bots.
    pub user_file: String,
    /// botd's API as Bots on the machine reach it (`BOT_API`): the agent relays it.
    pub api: String,
    /// `botctl` on the machine, if it is installed.
    pub botctl: Option<String>,
}

/// A file to write before the job starts: mode 0600, in folders made 0700.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobFile {
    pub path: String,
    pub body: String,
}

/// A command that stops what a harness leaves running, run before and after the job
/// when `whenExists` exists.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobCleanup {
    pub when_exists: String,
    pub bin: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub timeout_secs: u64,
}

/// One harness run for one Bot message. botd builds the command; the agent runs it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRequest {
    pub protocol: u32,
    /// Chosen by botd; names the job for `abort`.
    pub job_id: String,
    pub bot_id: String,
    /// Must be the machine's own user: an agent runs no one else's Bots.
    pub owner_id: String,
    pub message_id: i64,
    pub bin: String,
    pub args: Vec<String>,
    /// On top of the agent's own environment, which sets HOME and PATH.
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub stdin: Option<String>,
    pub files: Vec<JobFile>,
    pub cleanup: Option<JobCleanup>,
    /// Files to send back when the job ends (as they are then), e.g. the Bot's memory.
    pub collect: Vec<String>,
}

/// What a job stream carries, one per line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum JobEvent {
    /// The harness started.
    Started,
    /// One line of the harness's stdout, as it wrote it.
    Line { line: String },
    /// Sent while nothing else is, so botd can tell a quiet harness from a lost machine.
    Ping,
    /// A cleanup command failed. Before the run, nothing else follows.
    Cleanup { why: String },
    /// The job couldn't run: a file couldn't be written, or the harness didn't start.
    Error { message: String },
    /// The harness exited. `stderr` is the end of what it wrote there.
    #[serde(rename_all = "camelCase")]
    Exit {
        success: bool,
        status: String,
        stderr: String,
        /// The `collect` files that exist, by path.
        files: BTreeMap<String, String>,
        /// `collect` files too big to send. The agent keeps them: later jobs don't
        /// overwrite them until they're small enough to come back.
        #[serde(default)]
        too_big: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbortRequest {
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_tagged_lines_and_old_heartbeats_still_parse() {
        let e = JobEvent::Line {
            line: "{\"type\":\"text\"}".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"type":"line","line":"{\"type\":\"text\"}"}"#);
        assert_eq!(serde_json::from_str::<JobEvent>(&s).unwrap(), e);
        let exit: JobEvent = serde_json::from_str(
            r#"{"type":"exit","success":false,"status":"exit status: 1","stderr":"x","files":{}}"#,
        )
        .unwrap();
        assert!(matches!(exit, JobEvent::Exit { success: false, .. }));

        let old: Heartbeat = serde_json::from_str(
            r#"{"machineId":"m1","userId":"u1","version":"0.1.0","certificate":"ab","time":1}"#,
        )
        .unwrap();
        assert_eq!((old.protocol, old.layout, old.jobs), (0, None, 0));
    }
}
