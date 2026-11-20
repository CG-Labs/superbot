//! What the control plane and a machine agent send each other (ADR 0031). Shared by
//! botd and `superbot-machine`.
//!
//! botd's machine port (MACHINE_CONTROL_URL):
//! - `POST /v1/enroll` `EnrollRequest` -> `CertificateReply`. No client certificate.
//! - `GET /v1/machines/{id}` -> `MachineStatus`. The machine's own certificate.
//! - `POST /v1/machines/{id}/certificate` `RotateRequest` -> `CertificateReply`.
//! - `GET /v1/agent`: this agent's binary, for cloud-init to install.
//!
//! The agent (MACHINE_AGENT_PORT), for botd's certificate only:
//! - `GET /v1/heartbeat` -> `Heartbeat`.
//! - `POST /v1/jobs` `JobRequest`: 501 until machines run Bots.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRequest {
    pub bot_id: String,
    pub owner_id: String,
    pub message_id: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: String,
}
