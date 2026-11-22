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
//! - `PUT /v1/harnesses` `HarnessPlan` (202): the harness CLIs to install (ADR 0039).
//! - `POST /v1/upgrade` `UpgradeRequest` (202): replace the agent with botd's build.
//! - `POST /v1/logins` `LoginRequest` -> a stream of `LoginEvent`s: a harness CLI's
//!   login, run in a terminal on the machine (ADR 0041).
//! - `POST /v1/logins/{id}/input` `LoginInput`, `POST /v1/logins/{id}/abort`.
//! - `POST /v1/logins/forget` `ForgetRequest` -> `ForgetReply`: log a harness out.
//! - `POST /v1/sync` `SyncManifest` -> `SyncPlan`: copy the user's folder (ADR 0041).
//! - `PUT /v1/sync/{id}/blobs/{sha256}?offset=<n>` (bytes) -> `BlobReply`.
//! - `POST /v1/sync/{id}/finish` -> `SyncReport`.
//! - `PUT /v1/bot-user` `BotUserRequest` (202): run Bots as their own OS user (ADR 0043).
//! - `PUT /v1/screens/{bot}` `ScreenRequest` -> `ScreenReply`: start the Bot's screen,
//!   or give a running one a new viewer token (ADR 0045).
//! - `DELETE /v1/screens/{bot}`: stop it.
//! - `GET /v1/screens/{bot}/tunnel` with `Upgrade: SCREEN_UPGRADE` (101): a raw byte
//!   pipe to the screen's viewer on the machine's loopback, one per viewer connection.
//! - `PUT /v1/teammates/{user}` `TeammateRequest` -> `TeammateReply`: the OS user and
//!   home a teammate's runs of the owner's shared Bots get on this machine (ADR 0048).
//!   Screen routes take `?for=<user>` for that teammate's own screen of the Bot.
//! - `POST /v1/teammates/{user}/remove` `TeammateRemoval` -> `TeammateRemoved`: the
//!   teammate left; stop their jobs, screens and processes, take their work aside,
//!   and remove their user and home (ADR 0052).
//! - `POST /v1/teammates/{user}/purge` `TeammatePurge` -> `TeammatePurged`: delete
//!   work a removal held aside.
//!
//! Protocol 1 (`PROTOCOL`) is the first that runs Bots. A heartbeat without `protocol`
//! is from an agent before it, which can't. Installs, upgrades, logins and folder
//! copies are additions to it: an agent lists them in `can`.

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

/// The words a machine login may pass its harness: every adapter's `machine_login().args`.
pub const LOGIN_WORDS: [&str; 3] = ["auth", "login", "--device-auth"];

/// `word` as one of `LOGIN_WORDS`, so what an agent runs is never the request's own text.
pub fn login_word(word: &str) -> Option<&'static str> {
    LOGIN_WORDS.into_iter().find(|k| *k == word)
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
pub const CAN_LOGINS: &str = "logins";
pub const CAN_SYNC: &str = "sync";
pub const CAN_BOT_USER: &str = "bot_user";
pub const CAN_SCREENS: &str = "screens";
pub const CAN_TEAMMATES: &str = "teammates";
pub const CAN_TEAMMATE_REMOVAL: &str = "teammate_removal";
pub const CAN_TEAMMATE_LOGINS: &str = "teammate_logins";
/// Runs an install's `after` script (`InstallSource::Script`, ADR 0072).
pub const CAN_INSTALL_AFTER: &str = "install_after";
/// Deletes old harness session files and archived teammates' work (`/v1/retention`, ADR 0112).
pub const CAN_RETENTION: &str = "retention";

/// The screen protocol this build speaks (ADR 0045). A request names it, an agent
/// refuses any other, and botd treats an agent that reports another as outdated.
pub const SCREEN_PROTOCOL: u32 = 1;

/// The `Upgrade` header of a screen tunnel.
pub const SCREEN_UPGRADE: &str = "superbot-screen/1";

/// What a screen runs, as found on the machine's system PATH: a virtual display, a
/// window manager, a session bus and the viewer.
pub const SCREEN_PROGRAMS: [&str; 4] = ["Xvfb", "openbox", "dbus-daemon", "voxl"];

/// Screens on a machine (ADR 0045).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenReport {
    pub protocol: u32,
    /// Of `SCREEN_PROGRAMS`, those it can't find.
    pub missing: Vec<String>,
    /// The Bots whose screen is up.
    pub running: Vec<String>,
    /// How many it shows at once.
    pub max: u32,
}

/// `PUT /v1/screens/{bot}`: start the Bot's screen as the Bots' user, or, if it is up,
/// keep it and let only `token` view it from now on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenRequest {
    pub protocol: u32,
    /// Must be the machine's own user, as for jobs.
    pub owner_id: String,
    /// The viewer's password: 32 to 128 lowercase hex characters, chosen by botd.
    pub token: String,
    pub width: u32,
    pub height: u32,
    /// Stop it after this long with no viewer, request or job of the Bot.
    pub idle_secs: u64,
    /// The teammate whose own screen of the Bot this is, run as their OS user on the
    /// machine (ADR 0048). None: the owner's, as the Bots' user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_user: Option<String>,
    /// Only X clients with the screen's cookie may connect to its display. Always so for
    /// a teammate's screen; botd asks for it on the owner's too once teammates have
    /// their own users, so neither can reach the other's display.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub xauth: bool,
}

/// Where a Bot's programs find its screen on the machine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenReply {
    /// `DISPLAY`, e.g. `:101`.
    pub display: String,
    /// `DBUS_SESSION_BUS_ADDRESS`.
    pub bus: String,
    /// It was started (not just kept) by this request.
    pub started: bool,
    /// `XAUTHORITY`, when the display takes only clients with its cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xauthority: Option<String>,
}

/// A screen's name on the agent: the Bot, or the Bot and the teammate it's for.
pub fn screen_key(bot: &str, for_user: Option<&str>) -> String {
    match for_user {
        Some(u) => format!("{bot}@{u}"),
        None => bot.to_string(),
    }
}

/// The OS user a teammate's runs get on a machine (ADR 0048): from their user id, so
/// it never holds the request's own text and fits useradd's 32 bytes.
pub fn teammate_user(user_id: &str) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(user_id.as_bytes());
    let hex: String = d.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{TEAMMATE_USER_PREFIX}{hex}")
}

pub const TEAMMATE_USER_PREFIX: &str = "superbot-t-";

/// `PUT /v1/teammates/{user}`: make or check the OS user and home of a teammate who
/// runs the machine's user's shared Bots (ADR 0048). Never the machine's own user.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeammateRequest {
    /// Must be the machine's own user, as for jobs.
    pub owner_id: String,
}

/// Where a teammate's runs happen on the machine. Every path in their jobs must be
/// inside `home`, which only their OS user can open.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammateReply {
    pub user: String,
    pub uid: u32,
    pub home: String,
    pub workspace: String,
    pub bots: String,
    /// The user was made by this request.
    pub created: bool,
    /// Each harness the request asked about with `cred=`, logged in or not in this
    /// teammate's own home (`CAN_TEAMMATE_LOGINS`, ADR 0062).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logins: BTreeMap<String, LoginStatus>,
}

/// `GET /v1/teammates/{user}/logins`: a teammate's own harness logins on the machine
/// (ADR 0062). Asking never makes their user.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammateLogins {
    /// They have a user here.
    pub known: bool,
    pub logins: BTreeMap<String, LoginStatus>,
}

/// What becomes of a leaving teammate's `work` folder (ADR 0052).
pub const TEAMMATE_FILES_ARCHIVE: &str = "archive";
pub const TEAMMATE_FILES_DELETE: &str = "delete";
/// Where archived work lands, in the owner's workspace.
pub const TEAMMATE_ARCHIVE_DIR: &str = "from-teammates";

/// `POST /v1/teammates/{user}/remove`: the teammate left (ADR 0052). Their jobs,
/// screens and processes stop; their `work` folder is archived to the owner's
/// workspace, held aside, or deleted; the rest of their home and their OS user go.
/// Asking again after it's done changes nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeammateRemoval {
    /// Must be the machine's own user, as for jobs.
    pub owner_id: String,
    /// botd's id for this removal: names held work, so a retry finds it.
    pub cleanup_id: String,
    /// `TEAMMATE_FILES_ARCHIVE` or `TEAMMATE_FILES_DELETE`.
    pub files: String,
    /// Archive: the folder's name in the owner's `work/from-teammates`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_name: Option<String>,
    /// Delete: keep the work aside, root's alone, until botd purges it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hold: bool,
}

/// What a removal did.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammateRemoved {
    /// Their OS user's name.
    pub user: String,
    /// Nothing of theirs was left: done before.
    pub already_gone: bool,
    /// Their OS user was deleted by this request.
    pub user_removed: bool,
    pub jobs_stopped: u32,
    pub screens_stopped: u32,
    pub processes_stopped: u32,
    /// Their files in shared temporary folders.
    pub temp_removed: u32,
    /// `archived`, `held`, `deleted` or `none` (no work folder).
    pub files: String,
    /// Where archived work is, in the owner's workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_to: Option<String>,
}

/// `POST /v1/teammates/{user}/purge`: delete work a removal held aside.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeammatePurge {
    pub owner_id: String,
    pub cleanup_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammatePurged {
    /// There was held work, and it's gone now.
    pub purged: bool,
}

/// `POST /v1/retention`: delete old harness session files in the HOMEs Bots use here (the
/// user's and each teammate's) and in the named Bots' own folders, and archived teammates'
/// work in the user's `work/from-teammates/` (ADR 0112). Paths are relative and plain.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionRequest {
    pub owner_id: String,
    /// Unix ms: sessions whose files all last changed before this go.
    pub before: i64,
    /// Session folders under each HOME, with how many folders down a session sits.
    #[serde(default)]
    pub home: Vec<SessionDir>,
    /// Bots whose own folders (`bots/<id>` in each HOME) are swept.
    #[serde(default)]
    pub bots: Vec<String>,
    /// Session folders under each of those Bots' folders.
    #[serde(default)]
    pub state: Vec<SessionDir>,
    /// Session ids that stay whatever their age: running Bots'.
    #[serde(default)]
    pub keep: Vec<String>,
    /// Session ids to say whether they went.
    #[serde(default)]
    pub report: Vec<String>,
    /// Archive names in `work/from-teammates/` to delete.
    #[serde(default)]
    pub archives: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionDir {
    pub path: String,
    pub depth: u32,
    /// It holds transcripts (`sweep::Root::transcript`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transcript: bool,
}

/// `token` as a viewer password: plain lowercase hex, long enough to guess at no rate.
pub fn screen_token(token: &str) -> bool {
    (32..=128).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The OS user Bots run as on a machine (ADR 0043). An agent may be set to another,
/// as tests are; botd never names one.
pub const BOT_USER: &str = "superbot-bots";
pub const BOT_USER_READY: &str = "ready";
pub const BOT_USER_SETTING_UP: &str = "setting_up";
pub const BOT_USER_FAILED: &str = "failed";

/// Whether Bots run as their own user on the machine (ADR 0043).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotUserStatus {
    /// `BOT_USER_READY`, `BOT_USER_SETTING_UP` or `BOT_USER_FAILED`.
    pub state: String,
    pub user: String,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub error: Option<String>,
    /// When it got to this state.
    pub at: i64,
}

/// `PUT /v1/bot-user`: from now on, run Bots as their own user. The agent makes the
/// user if it must and hands it the Bots' home; it can't be undone.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BotUserRequest {}

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
    /// Jobs and harness logins running now.
    #[serde(default)]
    pub jobs: u32,
    /// `CAN_HARNESSES`, `CAN_UPGRADE`: empty before ADR 0039.
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
    /// Each harness the heartbeat asked about with `cred=`, plus any logging in now.
    #[serde(default)]
    pub logins: BTreeMap<String, LoginStatus>,
    /// The Bots' own user, once botd has asked for one (ADR 0043).
    #[serde(default)]
    pub bot_user: Option<BotUserStatus>,
    /// Its screens, if it can show them (`CAN_SCREENS`).
    #[serde(default)]
    pub screens: Option<ScreenReport>,
    /// The ids of teammates who have their own user on it (ADR 0048), when it can
    /// remove them (`CAN_TEAMMATE_REMOVAL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teammates: Option<Vec<String>>,
    /// How full the disk holding the Bots' home is (ADR 0085). None before it said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<Disk>,
}

/// A disk's use, in bytes, as `statvfs` reports it: `used` is what is taken, root's
/// reserve included, so it is what a smaller disk would have to hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub used: u64,
    pub total: u64,
    /// What the Bots' home and teammates' homes hold, in bytes (ADR 0105): what the
    /// owner's plan's storage counts, not the system, harnesses or tools. None until the
    /// agent has measured them, and from agents before this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    /// `files` is a lower bound: some of it couldn't be read, or there was too much.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

/// Whether a harness is logged in on the machine: whether one of the credential files
/// botd named exists. The agent never reads them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    /// `LOGGED_IN`, `LOGGED_OUT` or `LOGGING_IN` (a login is running, none saved yet).
    pub state: String,
    /// When the credential file last changed, if there is one.
    pub since: Option<i64>,
}

pub const LOGGED_IN: &str = "logged_in";
pub const LOGGED_OUT: &str = "logged_out";
pub const LOGGING_IN: &str = "logging_in";

/// Whether `p` can name a file in the agent's HOME: relative, plain parts only.
pub fn home_path(p: &str) -> bool {
    p.len() <= 1024
        && !p.starts_with('/')
        && p.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.len() <= 255
                && s.chars().all(|c| !c.is_control() && c != '\\')
        })
}

/// A harness CLI's own login, run by the agent in a terminal on the machine (ADR 0041).
/// botd takes the command from the harness's adapter; the agent knows no harness.
/// What the login saves stays on the machine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    /// Chosen by botd; names the login for `input` and `abort`.
    pub login_id: String,
    /// One of `HARNESS_BINS`.
    pub harness: String,
    pub args: Vec<String>,
    /// Where the login saves its credentials, relative to HOME (`home_path`).
    pub files: Vec<String>,
    pub timeout_secs: u64,
    /// The teammate whose own login this is, run as their OS user in their home on the
    /// machine (ADR 0062). None: the owner's, in the Bots' home. Sent only to an agent
    /// that says `CAN_TEAMMATE_LOGINS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_user: Option<String>,
}

/// What a login stream carries, one per line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum LoginEvent {
    #[serde(rename_all = "camelCase")]
    Started { login_id: String },
    /// What the login wrote to its terminal, as it wrote it.
    Output { text: String },
    Ping,
    Error { message: String },
    /// It exited. `logged_in`: one of its credential files exists now.
    #[serde(rename_all = "camelCase")]
    Exit {
        success: bool,
        status: String,
        logged_in: bool,
    },
}

/// A line typed into a login: sent with Enter.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginInput {
    pub text: String,
}

/// Log a harness out: remove its credential files.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForgetRequest {
    pub harness: String,
    pub files: Vec<String>,
    /// The teammate whose own login to remove (ADR 0062). None: the owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_user: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgetReply {
    pub removed: u32,
}

/// One file of the user's folder (ADR 0041). `path` is relative to the agent's HOME:
/// `work/...` (their working folder), `USER.md`, or `bots/<id>/MEMORY.md`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncFile {
    pub path: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of its bytes.
    pub sha256: String,
    #[serde(default)]
    pub exec: bool,
    /// Written only if the machine has no file there: the user's facts and Bots'
    /// memory, which jobs keep up to date (ADR 0036).
    #[serde(default)]
    pub seed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncManifest {
    /// Chosen by botd; names this copy in later calls.
    pub sync_id: String,
    pub files: Vec<SyncFile>,
}

/// The file contents the agent still needs, by SHA-256, and how many bytes of each it
/// already holds from an earlier, interrupted copy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncNeed {
    pub sha256: String,
    pub size: u64,
    pub have: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPlan {
    pub sync_id: String,
    pub need: Vec<SyncNeed>,
}

/// The largest manifest botd sends, and plan or report it reads back. The agent takes
/// request bodies up to 32 MiB.
pub const MAX_MANIFEST: usize = 24 << 20;

/// A chunk was taken (or, on 409, refused): the bytes of that blob the agent holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobReply {
    pub have: u64,
    /// It is whole and its SHA-256 matched.
    pub done: bool,
}

/// What a folder copy did. Nothing on the machine is ever deleted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub sync_id: String,
    /// Written, each checked against its SHA-256 before it was put in place.
    pub copied: u64,
    /// Already the same on the machine.
    pub unchanged: u64,
    /// Seeds written, and seeds left alone because the machine has its own.
    pub seeded: u64,
    pub kept: u64,
    /// Changed on the machine since the last copy, so left as they are. Up to 50.
    pub conflicts: Vec<String>,
    pub conflict_count: u64,
    pub bytes: u64,
}

/// The harness CLIs a machine should have (ADR 0039): pinned versions, each checked
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
    /// `after`: a script botd sends with it, run the same way once it succeeds; only an
    /// agent that says `CAN_INSTALL_AFTER` is sent one.
    Script {
        url: String,
        sha256: String,
        args: Vec<String>,
        bin: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<String>,
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

/// Replace the agent with botd's build, served at `/v1/agent` (ADR 0039).
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
    /// What it has for harness sandboxes (ADR 0055). None: an older agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<crate::sandbox::Host>,
    /// Package caches under `home` that exist there, which a sandboxed Bot may write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caches: Vec<String>,
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
    /// A teammate's run of the owner's shared Bot (ADR 0048): it runs as that teammate's
    /// own OS user, in their home there, and every path must be inside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_user: Option<String>,
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
        assert!(old.logins.is_empty(), "an agent from before logins says nothing of them");
        assert!(old.screens.is_none(), "an agent from before screens says nothing of them");
    }

    #[test]
    fn screen_tokens_are_long_lowercase_hex() {
        assert!(screen_token(&"a1".repeat(16)));
        assert!(screen_token(&"f".repeat(128)));
        for bad in ["", "abc", &"A1".repeat(16), &"g".repeat(32), &"a".repeat(129), &format!("{} ", "a".repeat(32))] {
            assert!(!screen_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn home_paths_are_plain_and_relative() {
        for ok in ["USER.md", ".claude/.credentials.json", "work/a b/c.txt", "bots/b1/MEMORY.md"] {
            assert!(home_path(ok), "{ok}");
        }
        let long = "a".repeat(256);
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a/./b", "a//b", "a/", "a\\b", "a\nb", long.as_str()] {
            assert!(!home_path(bad), "{bad:?}");
        }
        let e = LoginEvent::Exit { success: true, status: "exit status: 0".into(), logged_in: true };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"type":"exit","success":true,"status":"exit status: 0","loggedIn":true}"#);
    }
}
