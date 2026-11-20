//! What the control plane and a machine agent send each other (ADR 0031, ADR 0034).
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
//!
//! Protocol 1 (`PROTOCOL`) is the first that runs Bots. A heartbeat without `protocol`
//! is from an agent before it, which can't.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The job protocol this build speaks. A job names it, and an agent refuses any other.
pub const PROTOCOL: u32 = 1;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

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
