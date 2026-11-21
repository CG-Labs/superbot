//! SQLite storage: Bots, messages, routines, harness policy, approvals, and the
//! append-only audit log. One connection behind a mutex; every call is short.

use crate::acl::{Grant, Visibility};
use crate::audit;
use crate::machines::State as MachineState;
use crate::policy::{Action, Mode, Override, Policy, Rule};
use crate::rbac::Role;
use crate::secrets::{redact, sealed};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Serialize)]
pub struct Bot {
    pub id: String,
    pub name: String,
    pub color: String,
    pub shape: String,
    pub harness: String,
    pub model: Option<String>,
    pub effort: Option<String>,
    #[serde(skip)]
    pub session_id: Option<String>,
    pub primary: bool,
    pub hidden: bool,
    pub unread: bool,
    pub created_at: i64,
    /// The user who owns it (ADR 0017). Bots from before ACLs belong to `operator`.
    pub owner_id: String,
    pub visibility: Visibility,
    /// Suggested prompts in its details. None: the client's defaults; empty: none.
    pub prompts: Option<Vec<String>>,
}

/// One user's grant on one Bot (ADR 0017).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotGrant {
    pub bot_id: String,
    pub user_id: String,
    pub level: Grant,
    pub created_at: i64,
    pub created_by: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Message {
    pub id: i64,
    #[serde(rename = "botId")]
    pub bot_id: String,
    /// "user", "bot", or "routine"
    pub role: String,
    pub text: String,
    /// { title, options, picked? }
    pub question: Option<Value>,
    pub error: bool,
    /// "queued" | "running" | "done" for user and routine messages
    #[serde(skip)]
    pub status: Option<String>,
    /// For "peer" and "reply" messages: the other Bot's id.
    #[serde(rename = "fromBot")]
    pub from_bot: Option<String>,
    #[serde(rename = "at")]
    pub created_at: i64,
    /// Who asked for the run this message starts, for the audit log (ADR 0019).
    #[serde(skip)]
    pub requested_by: Option<audit::Who>,
}

#[derive(Clone, Serialize)]
pub struct Routine {
    pub id: String,
    pub bot_id: String,
    pub name: String,
    pub cron: String,
    pub instruction: String,
    pub enabled: bool,
    pub last_run_at: Option<i64>,
    pub created_at: i64,
    /// Who last wrote its instruction (ADR 0046); its runs are for them. None: from
    /// before, so its Bot's owner.
    pub author_id: Option<String>,
    /// Set when botd turned it off because someone it runs for was disabled (ADR 0047):
    /// `owner_disabled` or `author_disabled`. Cleared when it's resumed or turned on by hand.
    pub paused_reason: Option<String>,
    /// The disabled user it was paused for; resuming for them turns it back on.
    pub paused_for: Option<String>,
    pub paused_at: Option<i64>,
}

#[derive(Default)]
pub struct BotPatch {
    pub name: Option<String>,
    pub color: Option<String>,
    pub shape: Option<String>,
    pub harness: Option<String>,
    pub model: Option<Option<String>>,
    pub effort: Option<Option<String>>,
    pub session_id: Option<Option<String>>,
    pub hidden: Option<bool>,
    pub unread: Option<bool>,
    pub prompts: Option<Option<Vec<String>>>,
}

/// How many active users may hold a seat now (ADR 0038). None: no limit.
pub type SeatCap = Box<dyn Fn() -> Option<u32> + Send + Sync>;

/// The connection, and the seat limit every way of adding or re-enabling a user checks
/// under the same lock. Unset (as in most tests): no limit.
pub struct Db(Mutex<Connection>, std::sync::OnceLock<SeatCap>);

pub fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn bot_row(r: &Row) -> rusqlite::Result<Bot> {
    Ok(Bot {
        id: r.get("id")?,
        name: r.get("name")?,
        color: r.get("color")?,
        shape: r.get("shape")?,
        harness: r.get("harness")?,
        model: r.get("model")?,
        effort: r.get("effort")?,
        session_id: r.get("session_id")?,
        primary: r.get("primary_bot")?,
        hidden: r.get("hidden")?,
        unread: r.get("unread")?,
        created_at: r.get("created_at")?,
        owner_id: r.get("owner_id")?,
        // The column's CHECK allows only the two; anything else would fail closed.
        visibility: Visibility::parse(&r.get::<_, String>("visibility")?).unwrap_or(Visibility::Private),
        prompts: r.get::<_, Option<String>>("prompts")?.and_then(|j| serde_json::from_str(&j).ok()),
    })
}

fn grant_row(r: &Row) -> rusqlite::Result<BotGrant> {
    Ok(BotGrant {
        bot_id: r.get("bot_id")?,
        user_id: r.get("user_id")?,
        level: Grant::parse(&r.get::<_, String>("level")?).unwrap_or(Grant::Viewer),
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
    })
}

fn message_row(r: &Row) -> rusqlite::Result<Message> {
    let q: Option<String> = r.get("question")?;
    Ok(Message {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        role: r.get("role")?,
        text: r.get("text")?,
        question: q.and_then(|s| serde_json::from_str(&s).ok()),
        error: r.get("error")?,
        status: r.get("status")?,
        from_bot: r.get("from_bot")?,
        created_at: r.get("created_at")?,
        requested_by: r.get::<_, Option<String>>("requested_by")?.and_then(|s| serde_json::from_str(&s).ok()),
    })
}

/// One model's tokens for one run, to record (ADR 0050). `reported` false: the harness
/// didn't say, so the counts are 0 and unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenRow {
    pub user_id: String,
    pub bot_id: String,
    pub run_id: String,
    pub message_id: Option<i64>,
    pub harness: String,
    pub model: Option<String>,
    pub reported: bool,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub at: i64,
    /// Queue it for Stripe's meter.
    pub meter: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenTotals {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub runs: u64,
    /// Runs whose harness didn't report tokens.
    pub unreported_runs: u64,
}

impl TokenTotals {
    pub fn total(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenSummary {
    pub all: TokenTotals,
    pub by_model: Vec<(Option<String>, TokenTotals)>,
    pub by_bot: Vec<(String, TokenTotals)>,
}

/// A token row waiting for Stripe's meter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeterRow {
    pub id: i64,
    pub user_id: String,
    pub run_id: String,
    pub tokens: u64,
    pub at: i64,
    pub attempts: i64,
}

/// A subscription at a payment provider (ADR 0040). Every one a user has had is kept,
/// ended ones too, so a late event for one is judged against its own history.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub user_id: String,
    pub provider: String,
    pub customer_id: Option<String>,
    pub subscription_id: String,
    pub status: String,
    pub price_id: Option<String>,
    /// The tier it pays for; None when it pays for none (ended, or an unknown price).
    pub tier: Option<String>,
    /// Start of the paid period, Unix seconds (ADR 0050). None: from before it was kept.
    pub period_start: Option<i64>,
    /// End of the paid period, Unix seconds.
    pub period_end: Option<i64>,
    /// When the provider created the subscription, Unix seconds. Of a user's paying
    /// subscriptions, the one started last sets their tier.
    pub started: i64,
    /// When the provider made the last event applied, Unix seconds.
    pub event_created: i64,
    #[serde(skip)]
    pub updated_at: i64,
}

fn subscription_row(r: &Row) -> rusqlite::Result<Subscription> {
    Ok(Subscription {
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        customer_id: r.get("customer_id")?,
        subscription_id: r.get("subscription_id")?,
        status: r.get("status")?,
        price_id: r.get("price_id")?,
        tier: r.get("tier")?,
        period_start: r.get("period_start")?,
        period_end: r.get("period_end")?,
        started: r.get("started")?,
        event_created: r.get("event_created")?,
        updated_at: r.get("updated_at")?,
    })
}

/// The user's paying subscription started last: the one that sets their tier.
fn paying_subscription(c: &Connection, user_id: &str) -> rusqlite::Result<Option<Subscription>> {
    c.query_row(
        "SELECT * FROM subscriptions WHERE user_id = ? AND tier IS NOT NULL ORDER BY started DESC, subscription_id DESC LIMIT 1",
        [user_id],
        subscription_row,
    )
    .optional()
}

/// What a payment-provider event did (`Db::apply_subscription`).
#[derive(Debug, PartialEq)]
pub enum Applied {
    Duplicate,
    Stale,
    /// Recorded, but another subscription of the user's sets their tier.
    Superseded,
    /// The subscription belongs to another user.
    OtherUser,
    /// Its customer is linked to another user (ADR 0042).
    CustomerOfAnotherUser,
    Unchanged,
    Changed { from: Option<String>, to: Option<String> },
}

/// What linking a payment-provider customer to a user did (ADR 0042). A user has at most
/// one customer and a customer pays for one user; the first link stands.
#[derive(Debug, PartialEq)]
pub enum Linked {
    New,
    Already,
    /// The user is linked to this other customer already.
    UserHasAnother(String),
    /// The customer is linked to this other user already.
    OfAnotherUser(String),
    /// The provider deleted this customer: a late event can't bring it back.
    Deleted,
}

fn link_in(c: &Connection, user_id: &str, provider: &str, customer_id: &str, via: &str) -> rusqlite::Result<Linked> {
    let deleted: bool = c.query_row("SELECT COUNT(*) FROM billing_deleted_customers WHERE customer_id = ?", [customer_id], |r| r.get(0))?;
    if deleted {
        return Ok(Linked::Deleted);
    }
    let by_customer: Option<String> = c.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional()?;
    if let Some(u) = by_customer {
        return Ok(if u == user_id { Linked::Already } else { Linked::OfAnotherUser(u) });
    }
    let by_user: Option<String> = c.query_row("SELECT customer_id FROM billing_customers WHERE user_id = ?", [user_id], |r| r.get(0)).optional()?;
    if let Some(other) = by_user {
        return Ok(Linked::UserHasAnother(other));
    }
    c.execute(
        "INSERT INTO billing_customers (user_id, provider, customer_id, linked_at, linked_via) VALUES (?, ?, ?, ?, ?)",
        params![user_id, provider, customer_id, now(), via],
    )?;
    Ok(Linked::New)
}

/// Records a payment-provider event id. False when it was already applied.
fn first_delivery(c: &Connection, event_id: &str, event_type: &str) -> rusqlite::Result<bool> {
    Ok(c.execute("INSERT OR IGNORE INTO billing_events (event_id, type, received_at) VALUES (?, ?, ?)", params![event_id, event_type, now()])? == 1)
}

fn routine_row(r: &Row) -> rusqlite::Result<Routine> {
    Ok(Routine {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        name: r.get("name")?,
        cron: r.get("cron")?,
        instruction: r.get("instruction")?,
        enabled: r.get("enabled")?,
        last_run_at: r.get("last_run_at")?,
        created_at: r.get("created_at")?,
        author_id: r.get("author_id")?,
        paused_reason: r.get("paused_reason")?,
        paused_for: r.get("paused_for")?,
        paused_at: r.get("paused_at")?,
    })
}

/// A rule to save together with a decision.
pub struct NewRule<'a> {
    pub bot_id: Option<&'a str>,
    pub action: Action,
    pub tool: &'a str,
    pub pattern: &'a str,
    pub note: &'a str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub bot_id: String,
    pub harness: String,
    pub tool: String,
    /// "shell", "file", "web", "mcp", or "other"
    pub kind: String,
    /// The command, path, or arguments the user approves.
    pub subject: String,
    pub input: Value,
    pub class: String,
    pub reason: String,
    /// "pending" | "approved" | "denied" | "expired" | "cancelled"
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    /// "user" or "system"
    pub decided_by: Option<String>,
    pub note: Option<String>,
    /// The rule a "remember" decision created.
    pub rule_id: Option<String>,
    /// The run the call came from (`runId` in the audit log), when the hook named the
    /// Bot's live run (ADR 0051).
    pub run_id: Option<String>,
    /// What approving it for the rest of that run would cover: `{covers: [what], exact}`.
    /// None when it can only be approved once.
    pub run_scope: Option<Value>,
    /// How it was approved: "once" or "run". None until approved.
    pub scope: Option<String>,
}

/// One row of the audit log. See `audit.rs` and ADR 0009.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    /// Unix ms, UTC.
    pub at: i64,
    /// `at` as RFC 3339 UTC, e.g. `2026-11-19T13:46:00.123Z`.
    pub time: String,
    /// "user", "bot", or "system"
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    /// The IdP subject (`issuer|subject`) when the person signed in with SSO.
    pub actor_subject: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub bot_id: Option<String>,
    /// "success", "failure", or "denied"
    pub outcome: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: Value,
    // Per-user actors (ADR 0019). Null on rows written before it.
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    /// "password" (break-glass), "code", "sso", "none" (ALLOW_NO_AUTH), or "bot_token".
    pub auth_method: Option<String>,
    /// The SSO provider's type ("entra", "google", "oidc", "github", "apple", "saml"), and its configured id.
    pub idp: Option<String>,
    pub idp_provider: Option<String>,
    pub session_id: Option<String>,
    /// The user a Bot or the scheduler acted for.
    pub on_behalf_of: Option<String>,
}

/// A person who can sign in. `operator` is the owner and break-glass account.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub email: Option<String>,
    pub name: String,
    pub role: Role,
    /// "active" or "disabled"
    pub status: String,
    /// The IdP that vouches for this user, once OIDC lands (ADR 0012).
    pub idp_issuer: Option<String>,
    pub idp_subject: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// When a session last started for this user, how ("password", "code", "sso"),
    /// and through which SSO provider id (ADR 0021).
    pub last_login_at: Option<i64>,
    pub last_login_method: Option<String>,
    pub last_login_idp_provider: Option<String>,
    /// The tier an admin (later, billing) gave them. None: the default tier (ADR 0033).
    pub tier: Option<String>,
}

impl User {
    pub fn active(&self) -> bool {
        self.status == "active"
    }
}

/// A request for access from the public sign-up form (ADR 0022).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signup {
    pub id: String,
    pub name: String,
    pub email: String,
    pub company: String,
    pub team_size: String,
    pub use_case: String,
    /// `microsoft`, `google`, `github`, `apple`, or `other`.
    pub sign_in: String,
    /// "pending", "approved", or "rejected"
    pub status: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
    /// The user an approval made, and their role.
    pub user_id: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum AddSignup {
    /// This email has a pending request already.
    Duplicate,
    /// The pending cap is reached.
    Full,
}

#[derive(Debug, PartialEq)]
pub enum SignupError {
    NotFound,
    /// Approved or rejected already: the status it has.
    Closed(String),
    EmailTaken,
    /// Every seat is taken (ADR 0038); the request stays pending.
    NoSeat,
    Db(String),
}

pub struct NewSignup<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub company: &'a str,
    pub team_size: &'a str,
    pub use_case: &'a str,
    pub sign_in: &'a str,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

fn signup_row(r: &Row) -> rusqlite::Result<Signup> {
    Ok(Signup {
        id: r.get("id")?,
        name: r.get("name")?,
        email: r.get("email")?,
        company: r.get("company")?,
        team_size: r.get("team_size")?,
        use_case: r.get("use_case")?,
        sign_in: r.get("sign_in")?,
        status: r.get("status")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        created_at: r.get("created_at")?,
        decided_at: r.get("decided_at")?,
        decided_by: r.get("decided_by")?,
        reason: r.get("reason")?,
        user_id: r.get("user_id")?,
        role: r.get("role")?,
    })
}

/// One user's machine (ADR 0025). Destroyed rows stay, as history; a user has at
/// most one that isn't.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    /// The provider's id for it, once created.
    pub provider_id: Option<String>,
    /// Unique at the provider: `<prefix>-<id>`. Creating twice can't make two.
    pub label: String,
    /// The provider tag it is created with and found by: the label prefix when it was
    /// saved, so changing MACHINE_LABEL_PREFIX later can't lose it.
    pub tag: String,
    pub tier: String,
    pub plan: String,
    pub region: String,
    pub state: MachineState,
    /// The provider's last word on it (`running`, `offline`, ...), from reconciliation.
    pub provider_status: Option<String>,
    pub ipv4: Option<String>,
    pub backups: bool,
    pub last_error: Option<String>,
    /// When a create was last sent. One that went unanswered may still make a machine.
    pub create_sent_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
    pub destroyed_at: Option<i64>,
    /// Its agent's certificates (ADR 0031): `none` yet, `enrolled` (one is active),
    /// `held` (while suspended), or `revoked`.
    pub enrollment: String,
    pub enrolled_at: Option<i64>,
    /// The last heartbeat its agent answered, and what it said or why it didn't.
    pub agent_seen_at: Option<i64>,
    pub agent_version: Option<String>,
    pub agent_error: Option<String>,
    /// The provider firewall it was created behind or put behind (ADR 0035).
    pub firewall_id: Option<String>,
    /// When its current enrollment token was issued, plus the enrollment timeout.
    pub enroll_by: Option<i64>,
    /// When the reconciler found it hadn't enrolled by then. Cleared when it enrolls
    /// or gets a new token.
    pub enroll_overdue_at: Option<i64>,
    /// When an admin assigned it to its user, so their Bots run on it (ADR 0036).
    pub assigned_at: Option<i64>,
    pub assigned_by: Option<String>,
    /// What its agent last said of its build, harness CLIs and upgrades (ADR 0039).
    pub agent_upkeep: Option<Value>,
    /// When botd last sent it the harness plan, and the plan's id.
    pub harnesses_sent_at: Option<i64>,
    pub harnesses_sent_plan: Option<String>,
    /// An admin holding its agent at its build: nothing upgrades it.
    pub upgrade_hold_at: Option<i64>,
    pub upgrade_hold_by: Option<String>,
    /// The upgrade on its way: its id, the build, when it was sent, and `auto` or the
    /// admin who asked.
    pub upgrade_id: Option<String>,
    pub upgrade_build: Option<String>,
    pub upgrade_sent_at: Option<i64>,
    pub upgrade_by: Option<String>,
    /// A build that failed to upgrade it, so it isn't tried again by itself.
    pub upgrade_failed_build: Option<String>,
    /// Its latest rebuild with today's agent (ADR 0056): `queued`, `retrying`,
    /// `rebuilding`, `done`, `failed` or `cancelled`. None: never asked.
    pub rebuild_state: Option<String>,
    pub rebuild_id: Option<String>,
    /// `auto` or the admin who asked.
    pub rebuild_by: Option<String>,
    /// The admin accepted that files only on the machine are lost.
    pub rebuild_discard: bool,
    /// Rebuilds sent and checks that failed, for the backoff and the limit.
    pub rebuild_attempts: i64,
    /// Not tried again before this.
    pub rebuild_next_at: Option<i64>,
    pub rebuild_requested_at: Option<i64>,
    /// When it entered its state, and when the last rebuild was sent.
    pub rebuild_at: Option<i64>,
    pub rebuild_sent_at: Option<i64>,
    pub rebuild_error: Option<String>,
    /// Its agent's version when the rebuild was asked for.
    pub rebuild_from: Option<String>,
}

/// A certificate the control plane issued a machine (ADR 0031). Looked up by
/// fingerprint; the machine and user are botd's record, whatever the certificate says.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineCert {
    pub fingerprint: String,
    pub serial: String,
    pub machine_id: String,
    pub user_id: String,
    /// `active`, `held` (the machine is suspended), or `revoked`.
    pub status: String,
    /// `enrolled` or `rotated`.
    pub issued_for: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub not_after: i64,
    /// First used: after a rotation, the certificates before it are revoked then.
    pub first_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
}

impl MachineCert {
    pub fn usable(&self, at: i64) -> bool {
        self.status == "active" && self.not_before <= at && at < self.not_after
    }
}

/// A one-time enrollment token, by its hash.
#[derive(Clone, Debug)]
pub struct MachineToken {
    pub id: i64,
    pub machine_id: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

fn machine_cert_row(r: &Row) -> rusqlite::Result<MachineCert> {
    Ok(MachineCert {
        fingerprint: r.get("fingerprint")?,
        serial: r.get("serial")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        status: r.get("status")?,
        issued_for: r.get("issued_for")?,
        issued_at: r.get("issued_at")?,
        not_before: r.get("not_before")?,
        not_after: r.get("not_after")?,
        first_seen_at: r.get("first_seen_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_reason: r.get("revoked_reason")?,
    })
}

/// Sets a machine's `enrollment` from its certificates.
fn refresh_enrollment(c: &Connection, machine_id: &str) -> rusqlite::Result<usize> {
    c.execute(
        "UPDATE machines SET enrollment = COALESCE((
           SELECT CASE WHEN SUM(status = 'active') > 0 THEN 'enrolled' WHEN SUM(status = 'held') > 0 THEN 'held' ELSE 'revoked' END
           FROM machine_certs WHERE machine_id = ?1 HAVING COUNT(*) > 0), 'none')
         WHERE id = ?1",
        [machine_id],
    )
}

/// Revokes `machine_id`'s certificates that aren't yet and match `filter` (SQL over
/// `machine_certs`, never user input), and returns their fingerprints.
fn revoke_where(
    c: &Connection,
    machine_id: &str,
    filter: &str,
    reason: &str,
) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare(&format!(
        "UPDATE machine_certs SET status = 'revoked', revoked_at = ?2, revoked_reason = ?3
         WHERE machine_id = ?1 AND status <> 'revoked' AND ({filter}) RETURNING fingerprint"
    ))?;
    let out = s
        .query_map(params![machine_id, now(), reason], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(out)
}

pub struct NewMachine<'a> {
    pub user_id: &'a str,
    pub provider: &'a str,
    pub label_prefix: &'a str,
    pub tier: &'a str,
    pub plan: &'a str,
    pub region: &'a str,
    pub created_by: Option<&'a str>,
}

#[derive(Debug)]
pub enum AddMachine {
    /// The user's live machine.
    Exists(Box<Machine>),
    Db(String),
}

fn machine_row(r: &Row) -> rusqlite::Result<Machine> {
    Ok(Machine {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        provider_id: r.get("provider_id")?,
        label: r.get("label")?,
        tag: r.get("tag")?,
        tier: r.get("tier")?,
        plan: r.get("plan")?,
        region: r.get("region")?,
        // The column's CHECK allows only known states.
        state: MachineState::parse(&r.get::<_, String>("state")?).unwrap_or(MachineState::Error),
        provider_status: r.get("provider_status")?,
        ipv4: r.get("ipv4")?,
        backups: r.get("backups")?,
        last_error: r.get("last_error")?,
        create_sent_at: r.get("create_sent_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
        destroyed_at: r.get("destroyed_at")?,
        enrollment: r.get("enrollment")?,
        enrolled_at: r.get("enrolled_at")?,
        agent_seen_at: r.get("agent_seen_at")?,
        agent_version: r.get("agent_version")?,
        agent_error: r.get("agent_error")?,
        firewall_id: r.get("firewall_id")?,
        enroll_by: r.get("enroll_by")?,
        enroll_overdue_at: r.get("enroll_overdue_at")?,
        assigned_at: r.get("assigned_at")?,
        assigned_by: r.get("assigned_by")?,
        agent_upkeep: r.get::<_, Option<String>>("agent_upkeep")?.and_then(|j| serde_json::from_str(&j).ok()),
        harnesses_sent_at: r.get("harnesses_sent_at")?,
        harnesses_sent_plan: r.get("harnesses_sent_plan")?,
        upgrade_hold_at: r.get("upgrade_hold_at")?,
        upgrade_hold_by: r.get("upgrade_hold_by")?,
        upgrade_id: r.get("upgrade_id")?,
        upgrade_build: r.get("upgrade_build")?,
        upgrade_sent_at: r.get("upgrade_sent_at")?,
        upgrade_by: r.get("upgrade_by")?,
        upgrade_failed_build: r.get("upgrade_failed_build")?,
        rebuild_state: r.get("rebuild_state")?,
        rebuild_id: r.get("rebuild_id")?,
        rebuild_by: r.get("rebuild_by")?,
        rebuild_discard: r.get("rebuild_discard")?,
        rebuild_attempts: r.get("rebuild_attempts")?,
        rebuild_next_at: r.get("rebuild_next_at")?,
        rebuild_requested_at: r.get("rebuild_requested_at")?,
        rebuild_at: r.get("rebuild_at")?,
        rebuild_sent_at: r.get("rebuild_sent_at")?,
        rebuild_error: r.get("rebuild_error")?,
        rebuild_from: r.get("rebuild_from")?,
    })
}

#[derive(Default)]
pub struct UserPatch {
    pub email: Option<Option<String>>,
    pub name: Option<String>,
    pub role: Option<Role>,
    pub status: Option<&'static str>,
    /// Some(None): back to the default tier.
    pub tier: Option<Option<String>>,
}

/// A sign-in. The token itself is never stored, only its SHA-256.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub user_id: String,
    /// "cookie" (web app) or "token" (bearer: the client, botctl)
    pub kind: String,
    /// How the person proved who they are: "password" (break-glass), "code", or "sso".
    pub method: String,
    /// `issuer|subject` of the SSO identity that signed in, for the audit log.
    pub idp_subject: Option<String>,
    /// The SSO provider id it signed in with (from SSO_PROVIDERS).
    pub idp_provider: Option<String>,
    pub label: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
}

/// A phone that gets push notifications (ADR 0080), registered by one session and
/// removed with it. `token` is the provider's address for the device, sealed at rest
/// and never shown: anyone holding it can send to the phone.
#[derive(Clone)]
pub struct PushDevice {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub token: String,
    pub platform: String,
    pub approvals: bool,
    pub routines: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl std::fmt::Debug for PushDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushDevice").field("id", &self.id).field("user_id", &self.user_id).field("platform", &self.platform).finish_non_exhaustive()
    }
}

/// What a push is about, and so which of a device's switches it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushKind {
    Approvals,
    Routines,
}

/// How `put_push_device` changed things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushPut {
    /// A new device for this session (or a new token for it).
    Added,
    /// The token was another session's: it moved here, and that session lost it.
    Moved,
    /// Same token, switches changed.
    Updated,
    Unchanged,
}

/// Each person keeps at most this many devices; registering more drops the oldest.
pub const MAX_PUSH_DEVICES: usize = 20;
const PUSH_TOKEN_CONTEXT: &str = "push_devices.token";

pub struct NewSession<'a> {
    pub user_id: &'a str,
    pub token_hash: &'a str,
    pub kind: &'a str,
    pub method: &'a str,
    pub idp_subject: Option<&'a str>,
    pub idp_provider: Option<&'a str>,
    pub label: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub expires_at: i64,
}

/// An SSO identity linked to a user (ADR 0014). `(issuer, subject)` is the key; the
/// email is only what the IdP last said, never used to find anyone.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    /// The provider id from SSO_PROVIDERS, e.g. "entra".
    pub provider: String,
    pub issuer: String,
    /// Entra: the object id (`oid`); others: `sub`.
    pub subject: String,
    /// Entra: the tenant id (`tid`), which `issuer` also names.
    pub tenant: Option<String>,
    pub email: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub last_login_at: Option<i64>,
}

pub struct NewIdentity<'a> {
    pub provider: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub tenant: Option<&'a str>,
    pub email: Option<&'a str>,
    pub created_by: Option<&'a str>,
}

fn identity_row(r: &Row) -> rusqlite::Result<Identity> {
    Ok(Identity {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        issuer: r.get("issuer")?,
        subject: r.get("subject")?,
        tenant: r.get("tenant")?,
        email: r.get("email")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        last_login_at: r.get("last_login_at")?,
    })
}

/// A SCIM bearer token (ADR 0023). Only its SHA-256 is stored. Every token belongs to
/// a tenant: one IdP connection, whose users only its tokens can see.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimToken {
    pub id: String,
    pub tenant: String,
    pub label: Option<String>,
    /// The SSO provider whose subjects this tenant's `externalId`s are (from SSO_PROVIDERS).
    pub sso_provider: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
}

fn scim_token_row(r: &Row) -> rusqlite::Result<ScimToken> {
    Ok(ScimToken {
        id: r.get("id")?,
        tenant: r.get("tenant")?,
        label: r.get("label")?,
        sso_provider: r.get("sso_provider")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        last_used_at: r.get("last_used_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
    })
}

/// A user as a SCIM tenant provisioned it: the SCIM attributes botd has no column for
/// on `users`, and whether the IdP deleted it (users themselves are never deleted).
#[derive(Clone, Debug)]
pub struct ScimUser {
    pub user: User,
    pub tenant: String,
    pub external_id: Option<String>,
    pub user_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    /// `displayName` and `name.formatted` as the IdP sent them; `users.display_name` is
    /// what SuperBot shows, built from these.
    pub display_name: Option<String>,
    pub formatted: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// The columns of a `users` row joined with its `scim_users` row, the SCIM ones prefixed.
const SCIM_USER_SELECT: &str = "SELECT u.*, l.tenant AS scim_tenant, l.external_id AS scim_external_id, l.user_name AS scim_user_name,
  l.given_name AS scim_given_name, l.family_name AS scim_family_name, l.display_name AS scim_display_name,
  l.formatted AS scim_formatted, l.created_at AS scim_created_at,
  l.updated_at AS scim_updated_at, l.deleted_at AS scim_deleted_at
  FROM scim_users l JOIN users u ON u.id = l.user_id";

fn scim_user_row(r: &Row) -> rusqlite::Result<ScimUser> {
    Ok(ScimUser {
        user: user_row(r)?,
        tenant: r.get("scim_tenant")?,
        external_id: r.get("scim_external_id")?,
        user_name: r.get("scim_user_name")?,
        given_name: r.get("scim_given_name")?,
        family_name: r.get("scim_family_name")?,
        display_name: r.get("scim_display_name")?,
        formatted: r.get("scim_formatted")?,
        created_at: r.get("scim_created_at")?,
        updated_at: r.get("scim_updated_at")?,
        deleted_at: r.get("scim_deleted_at")?,
    })
}

/// How a SCIM tenant looks users up: `userName` (any case) or `externalId` (exactly).
#[derive(Clone, Debug, PartialEq)]
pub enum ScimKey {
    UserName(String),
    ExternalId(String),
}

/// What SCIM sets on a user. Never the role.
pub struct ScimFields<'a> {
    pub user_name: &'a str,
    pub external_id: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    /// What the IdP sent, if anything.
    pub scim_display_name: Option<&'a str>,
    pub formatted: Option<&'a str>,
    /// The name SuperBot shows.
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    /// None leaves the status as it is now, so an update that doesn't change `active`
    /// can't undo an admin's disable that landed after it read the user.
    pub active: Option<bool>,
}

/// Why a SCIM write was refused: something unique is someone else's already.
#[derive(Debug, PartialEq)]
pub enum ScimConflict {
    Email,
    UserName,
    ExternalId,
    Identity,
    /// The user belongs to another SCIM tenant, deleted there or not.
    OtherTenant,
    /// Deleted (or never this tenant's) by the time the write ran.
    Gone,
    /// Making the user active needs a seat, and none is free (ADR 0038).
    NoSeat,
    Db(String),
}

fn scim_conflict(e: rusqlite::Error) -> ScimConflict {
    let msg = e.to_string();
    match () {
        _ if !constraint(&e) => ScimConflict::Db(msg),
        _ if msg.contains("users.email") => ScimConflict::Email,
        _ if msg.contains("external_id") => ScimConflict::ExternalId,
        _ if msg.contains("user_name") => ScimConflict::UserName,
        _ if msg.contains("user_identities") => ScimConflict::Identity,
        _ => ScimConflict::Db(msg),
    }
}

#[derive(Debug, PartialEq)]
pub enum JitError {
    /// Another user has this email. Never merged by email: ask an admin to link instead.
    EmailTaken,
    /// Another sign-in linked this identity first.
    IdentityTaken,
    /// Every seat is taken (ADR 0038).
    NoSeat,
    Database,
}

/// Why a user wasn't added or changed.
#[derive(Debug, PartialEq)]
pub enum UserError {
    EmailTaken,
    /// Every seat the license allows is taken, or there is no license (ADR 0038, ADR 0068).
    NoSeat,
    Db(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UserError::EmailTaken => f.write_str("A user with that email already exists"),
            UserError::NoSeat => f.write_str("No seats left"),
            UserError::Db(e) => f.write_str(e),
        }
    }
}

fn constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

fn user_row(r: &Row) -> rusqlite::Result<User> {
    let role: String = r.get("role")?;
    Ok(User {
        id: r.get("id")?,
        email: r.get("email")?,
        name: r.get("display_name")?,
        role: Role::parse(&role).unwrap_or(Role::Readonly),
        status: r.get("status")?,
        idp_issuer: r.get("idp_issuer")?,
        idp_subject: r.get("idp_subject")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        last_login_at: r.get("last_login_at")?,
        last_login_method: r.get("last_login_method")?,
        last_login_idp_provider: r.get("last_login_idp_provider")?,
        tier: r.get("tier")?,
    })
}

fn session_row(r: &Row) -> rusqlite::Result<Session> {
    Ok(Session {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        kind: r.get("kind")?,
        method: r.get("method")?,
        idp_subject: r.get("idp_subject")?,
        idp_provider: r.get("idp_provider")?,
        label: r.get("label")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        created_at: r.get("created_at")?,
        last_seen_at: r.get("last_seen_at")?,
        expires_at: r.get("expires_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
        revoke_reason: r.get("revoke_reason")?,
    })
}

/// None when the sealed token doesn't open (another master key): such a device can't be reached.
fn push_device_row(r: &Row) -> rusqlite::Result<Option<PushDevice>> {
    let Some(token) = sealed::open_field(PUSH_TOKEN_CONTEXT, &r.get::<_, String>("token")?) else { return Ok(None) };
    Ok(Some(PushDevice {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        token,
        platform: r.get("platform")?,
        approvals: r.get("approvals")?,
        routines: r.get("routines")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
    }))
}

/// SQL for "this session still works": not revoked, before its absolute expiry
/// (the stored one and `created_at + max`, so lowering the setting applies to
/// existing sessions), and used within the idle window. Binds `?1` now, `?2` idle ms, `?3` max ms.
const SESSION_LIVE: &str = "s.revoked_at IS NULL AND ?1 < s.expires_at AND ?1 < s.created_at + ?3 AND ?1 < s.last_seen_at + ?2";

fn approval_row(r: &Row) -> rusqlite::Result<Approval> {
    let input: String = r.get("input")?;
    Ok(Approval {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        harness: r.get("harness")?,
        tool: r.get("tool")?,
        kind: r.get("kind")?,
        subject: r.get("subject")?,
        input: match sealed::open_field(&sealed::approval_context(&r.get::<_, String>("id")?), &input) {
            Some(input) => serde_json::from_str(&input).unwrap_or(Value::Null),
            None => serde_json::json!({ "sealed": "unreadable" }),
        },
        class: r.get("class")?,
        reason: r.get("reason")?,
        status: r.get("status")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        decided_at: r.get("decided_at")?,
        decided_by: r.get("decided_by")?,
        note: r.get("note")?,
        rule_id: r.get("rule_id")?,
        run_id: r.get("run_id")?,
        run_scope: r.get::<_, Option<String>>("run_scope")?.and_then(|s| serde_json::from_str(&s).ok()),
        scope: r.get("scope")?,
    })
}

fn rule_row(r: &Row) -> rusqlite::Result<Rule> {
    let action: String = r.get("action")?;
    Ok(Rule {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        action: if action == "allow" { Action::Allow } else { Action::Deny },
        tool: r.get("tool")?,
        pattern: r.get("pattern")?,
        note: r.get("note")?,
        created_at: r.get("created_at")?,
    })
}

fn audit_row(r: &Row) -> rusqlite::Result<AuditEvent> {
    let details: String = r.get("details")?;
    let at: i64 = r.get("at")?;
    Ok(AuditEvent {
        id: r.get("id")?,
        at,
        time: chrono::DateTime::from_timestamp_millis(at)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_default(),
        actor_kind: r.get("actor_kind")?,
        actor_id: r.get("actor_id")?,
        actor_name: r.get("actor_name")?,
        actor_subject: r.get("actor_subject")?,
        action: r.get("action")?,
        target_type: r.get("target_type")?,
        target_id: r.get("target_id")?,
        bot_id: r.get("bot_id")?,
        outcome: r.get("outcome")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        details: redact::value(serde_json::from_str(&details).unwrap_or(Value::Null)),
        actor_email: r.get("actor_email")?,
        actor_role: r.get("actor_role")?,
        auth_method: r.get("auth_method")?,
        idp: r.get("idp")?,
        idp_provider: r.get("idp_provider")?,
        session_id: r.get("session_id")?,
        on_behalf_of: r.get("on_behalf_of")?,
    })
}

/// Schema changes after the first release, in order. `PRAGMA user_version` is how many ran.
/// Each gets `fresh`: true when this database was just created.
const MIGRATIONS: [fn(&Connection, bool) -> rusqlite::Result<()>; 30] = [
    migrate_approvals,
    migrate_audit_events,
    migrate_users,
    migrate_identities,
    migrate_bot_acls,
    migrate_audit_actors,
    migrate_signups,
    migrate_last_login,
    migrate_scim,
    migrate_machines,
    migrate_tiers,
    migrate_machine_enrollment,
    migrate_machine_lockdown,
    migrate_machine_placement,
    migrate_machine_upkeep,
    migrate_billing,
    migrate_billing_customers,
    migrate_routine_authors,
    migrate_routine_pauses,
    migrate_token_usage,
    migrate_approval_runs,
    migrate_teammate_cleanups,
    migrate_bot_prompts,
    migrate_sandbox,
    migrate_machine_rebuild,
    migrate_account_removals,
    migrate_machine_backups,
    migrate_machine_recovery,
    migrate_machine_hosts,
    migrate_push_devices,
];

/// Phones that get push notifications (ADR 0080): one per session at most, and a token
/// belongs to one session only, so a phone that changes hands stops reaching the last
/// person. Ending the session removes it; so does deleting the session or the user.
fn migrate_push_devices(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS push_devices (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          token TEXT NOT NULL,
          platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
          approvals INTEGER NOT NULL DEFAULT 1,
          routines INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS push_devices_user ON push_devices(user_id, updated_at);",
    )
}

/// The hosts machines are on (ADR 0076): the certificate each was first seen with, so
/// one can't be swapped for another under the same name, and what botd last found.
/// Restores say which host they moved a machine from and to, and why.
fn migrate_machine_hosts(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_hosts (
          name TEXT PRIMARY KEY,
          url TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'up' CHECK (state IN ('up', 'down', 'lost')),
          failing_since INTEGER,
          checked_at INTEGER,
          last_error TEXT,
          down_at INTEGER,
          lost_at INTEGER,
          lost_by TEXT,
          created_at INTEGER NOT NULL
        );",
    )?;
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_restores') WHERE name = 'to_host'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machine_restores ADD COLUMN from_host TEXT;
            ALTER TABLE machine_restores ADD COLUMN to_host TEXT;
            ALTER TABLE machine_restores ADD COLUMN reason TEXT;",
        )?;
    }
    Ok(())
}

/// An Incus host machines are on (ADR 0076). `state`: `up`, `down` (it hasn't answered
/// since `failing_since`, for longer than the host-down time), or `lost` (an admin
/// said so; never called again).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineHost {
    pub name: String,
    pub url: String,
    pub fingerprint: String,
    pub state: String,
    pub failing_since: Option<i64>,
    pub checked_at: Option<i64>,
    pub last_error: Option<String>,
    pub down_at: Option<i64>,
    pub lost_at: Option<i64>,
    pub lost_by: Option<String>,
    pub created_at: i64,
}

fn machine_host_row(r: &Row) -> rusqlite::Result<MachineHost> {
    Ok(MachineHost {
        name: r.get("name")?,
        url: r.get("url")?,
        fingerprint: r.get("fingerprint")?,
        state: r.get("state")?,
        failing_since: r.get("failing_since")?,
        checked_at: r.get("checked_at")?,
        last_error: r.get("last_error")?,
        down_at: r.get("down_at")?,
        lost_at: r.get("lost_at")?,
        lost_by: r.get("lost_by")?,
        created_at: r.get("created_at")?,
    })
}

/// Off-host backups of machines and restores from them (ADR 0071). At most one backup
/// running and one restore underway per machine.
fn migrate_machine_backups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_backups (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tier TEXT NOT NULL,
          plan TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed', 'deleted')),
          object_key TEXT NOT NULL,
          encrypted INTEGER NOT NULL DEFAULT 0,
          size INTEGER,
          sha256 TEXT,
          created_by TEXT,
          error TEXT,
          created_at INTEGER NOT NULL,
          finished_at INTEGER,
          expires_at INTEGER,
          deleted_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS machine_backups_machine ON machine_backups(machine_id, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS machine_backups_running ON machine_backups(machine_id) WHERE state = 'running';
        CREATE TABLE IF NOT EXISTS machine_restores (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          backup_id TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('importing', 'replacing', 'enrolling', 'done', 'failed')),
          created_by TEXT,
          error TEXT,
          created_at INTEGER NOT NULL,
          replaced_at INTEGER,
          finished_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS machine_restores_underway ON machine_restores(machine_id)
          WHERE state IN ('importing', 'replacing', 'enrolling');",
    )
}

/// Recovery objectives (ADR 0074): each restore's tier, RTO and how long it took, and
/// each time a machine went past its RPO.
fn migrate_machine_recovery(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_restores') WHERE name = 'rto_ms'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machine_restores ADD COLUMN tier TEXT;
            ALTER TABLE machine_restores ADD COLUMN rto_ms INTEGER;
            ALTER TABLE machine_restores ADD COLUMN duration_ms INTEGER;
            ALTER TABLE machine_restores ADD COLUMN rto_exceeded_at INTEGER;",
        )?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_rpo_breaches (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tier TEXT NOT NULL,
          rpo_ms INTEGER NOT NULL,
          covered_since INTEGER NOT NULL,
          breached_at INTEGER NOT NULL,
          detected_at INTEGER NOT NULL,
          ended_at INTEGER,
          end_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS machine_rpo_breaches_at ON machine_rpo_breaches(breached_at);
        CREATE UNIQUE INDEX IF NOT EXISTS machine_rpo_breaches_open ON machine_rpo_breaches(machine_id) WHERE ended_at IS NULL;",
    )
}

/// A time a machine had no off-host backup newer than its RPO (ADR 0074). `breached_at`
/// is when that began (`covered_since` + `rpo_ms`), `detected_at` when botd saw it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRpoBreach {
    pub id: String,
    pub machine_id: String,
    pub user_id: String,
    pub tier: String,
    pub rpo_ms: i64,
    pub covered_since: i64,
    pub breached_at: i64,
    pub detected_at: i64,
    pub ended_at: Option<i64>,
    /// `backed_up`, `objective_changed`, or why the machine stopped counting
    /// (`suspended`, `destroyed`, `restoring`, ...).
    pub end_reason: Option<String>,
}

fn machine_rpo_breach_row(r: &Row) -> rusqlite::Result<MachineRpoBreach> {
    Ok(MachineRpoBreach {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        tier: r.get("tier")?,
        rpo_ms: r.get("rpo_ms")?,
        covered_since: r.get("covered_since")?,
        breached_at: r.get("breached_at")?,
        detected_at: r.get("detected_at")?,
        ended_at: r.get("ended_at")?,
        end_reason: r.get("end_reason")?,
    })
}

/// One off-host backup of a machine (ADR 0071).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineBackup {
    pub id: String,
    pub machine_id: String,
    pub user_id: String,
    pub tier: String,
    pub plan: String,
    /// `running`, `done`, `failed`, or `deleted` (past its retention).
    pub state: String,
    pub object_key: String,
    pub encrypted: bool,
    pub size: Option<i64>,
    pub sha256: Option<String>,
    /// `schedule`, or the admin who asked.
    pub created_by: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub deleted_at: Option<i64>,
}

fn machine_backup_row(r: &Row) -> rusqlite::Result<MachineBackup> {
    Ok(MachineBackup {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        tier: r.get("tier")?,
        plan: r.get("plan")?,
        state: r.get("state")?,
        object_key: r.get("object_key")?,
        encrypted: r.get("encrypted")?,
        size: r.get("size")?,
        sha256: r.get("sha256")?,
        created_by: r.get("created_by")?,
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        finished_at: r.get("finished_at")?,
        expires_at: r.get("expires_at")?,
        deleted_at: r.get("deleted_at")?,
    })
}

/// One restore of a machine from a backup (ADR 0071).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRestore {
    pub id: String,
    pub machine_id: String,
    pub backup_id: String,
    /// `importing`, `replacing`, `enrolling`, `done`, or `failed`.
    pub state: String,
    pub created_by: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    /// When the restored disk took the old one's place.
    pub replaced_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// The machine's tier and its RTO when the restore was asked for (ADR 0074).
    pub tier: Option<String>,
    pub rto_ms: Option<i64>,
    /// From the request to the machine enrolling again, once done.
    pub duration_ms: Option<i64>,
    /// When it was seen to take longer than `rto_ms`.
    pub rto_exceeded_at: Option<i64>,
    /// The hosts it was restored from and onto, where the provider has several (ADR 0076).
    pub from_host: Option<String>,
    pub to_host: Option<String>,
    /// `host_lost` when its host was declared lost; None when an admin asked.
    pub reason: Option<String>,
}

fn machine_restore_row(r: &Row) -> rusqlite::Result<MachineRestore> {
    Ok(MachineRestore {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        backup_id: r.get("backup_id")?,
        state: r.get("state")?,
        created_by: r.get("created_by")?,
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        replaced_at: r.get("replaced_at")?,
        finished_at: r.get("finished_at")?,
        tier: r.get("tier")?,
        rto_ms: r.get("rto_ms")?,
        duration_ms: r.get("duration_ms")?,
        rto_exceeded_at: r.get("rto_exceeded_at")?,
        from_host: r.get("from_host")?,
        to_host: r.get("to_host")?,
        reason: r.get("reason")?,
    })
}

/// A backup to start: `machine_backup_start`.
pub struct NewMachineBackup<'a> {
    pub id: &'a str,
    pub machine: &'a Machine,
    pub object_key: &'a str,
    pub encrypted: bool,
    pub created_by: Option<&'a str>,
}

/// A restore to start: `machine_restore_start`.
pub struct NewMachineRestore<'a> {
    pub id: &'a str,
    pub machine: &'a Machine,
    pub backup_id: &'a str,
    pub by: Option<&'a str>,
    pub rto_ms: Option<i64>,
    pub from_host: Option<&'a str>,
    pub to_host: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// Rebuilding machines enrolled before ADR 0039 with today's agent (ADR 0056).
fn migrate_machine_rebuild(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'rebuild_state'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN rebuild_state TEXT
           CHECK (rebuild_state IN ('queued', 'retrying', 'rebuilding', 'done', 'failed', 'cancelled'));
        ALTER TABLE machines ADD COLUMN rebuild_id TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_by TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_discard INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE machines ADD COLUMN rebuild_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE machines ADD COLUMN rebuild_next_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_requested_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_error TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_from TEXT;",
    )
}

/// Harness sandboxes (ADR 0055). New installs have them on (`Policy::new`); an install
/// upgrading keeps running without, as before, until an admin turns them on. Bots'
/// own overrides have no `sandbox`, so they follow the global setting.
fn migrate_sandbox(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    if fresh {
        return Ok(());
    }
    let saved: Option<String> = c.query_row("SELECT value FROM settings WHERE key = 'policy'", [], |r| r.get(0)).optional()?;
    let Some(mut policy) = saved.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()).filter(serde_json::Value::is_object) else {
        return Ok(());
    };
    policy["sandbox"] = false.into();
    c.execute("UPDATE settings SET value = ? WHERE key = 'policy'", [policy.to_string()])?;
    let details = serde_json::json!({ "sandbox": false, "reason": "existing install keeps harness sandboxes off" });
    c.execute(
        "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, target_id, outcome, details) VALUES (?, 'system', 'migration', 'policy.sandbox_initialized', 'policy', 'global', 'success', ?)",
        params![now(), details.to_string()],
    )?;
    Ok(())
}

/// Suggested prompts per Bot (ADR 0054), as a JSON array. NULL: the client's defaults.
fn migrate_bot_prompts(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('bots') WHERE name = 'prompts'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE bots ADD COLUMN prompts TEXT;")?;
    }
    Ok(())
}

/// Approve once per run (ADR 0051): the run each approval was asked in, what approving
/// it for that run would cover, and which of the two it got. The grants themselves are
/// never stored: they live with the run and end with it.
fn migrate_approval_runs(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for col in ["run_id", "run_scope", "scope"] {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('approvals') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE approvals ADD COLUMN {col} TEXT;"))?;
        }
    }
    Ok(())
}

/// Removing teammates' users from machines when they leave (ADR 0052): one row per
/// removal, `pending` until the agent has done it, then `done`, or `held` while their
/// work waits to be purged; `cancelled` if they came back or the machine went first.
/// At most one pending per machine and teammate, so queueing again changes nothing.
fn migrate_teammate_cleanups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS teammate_cleanups (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          os_user TEXT NOT NULL,
          reason TEXT NOT NULL,
          files TEXT NOT NULL CHECK (files IN ('archive', 'delete')),
          grace_days INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL CHECK (state IN ('pending', 'held', 'done', 'cancelled')),
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          tried_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          removed_at INTEGER,
          archived_to TEXT,
          purge_at INTEGER,
          done_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS teammate_cleanups_pending ON teammate_cleanups(machine_id, user_id) WHERE state = 'pending';
        CREATE INDEX IF NOT EXISTS teammate_cleanups_state ON teammate_cleanups(state, machine_id);",
    )
}

/// One teammate's removal from one machine (ADR 0052).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammateCleanup {
    pub id: String,
    pub machine_id: String,
    /// The machine's user, whose shared Bots the teammate ran.
    pub owner_id: String,
    /// The teammate.
    pub user_id: String,
    pub os_user: String,
    /// `disabled`, `deprovisioned`, `deleted`, `access_lost` or `admin`.
    pub reason: String,
    /// `archive` or `delete`: what becomes of their work folder.
    pub files: String,
    pub grace_days: i64,
    pub state: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub tried_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub removed_at: Option<i64>,
    pub archived_to: Option<String>,
    pub purge_at: Option<i64>,
    pub done_at: Option<i64>,
}

fn teammate_cleanup_row(r: &Row) -> rusqlite::Result<TeammateCleanup> {
    Ok(TeammateCleanup {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        owner_id: r.get("owner_id")?,
        user_id: r.get("user_id")?,
        os_user: r.get("os_user")?,
        reason: r.get("reason")?,
        files: r.get("files")?,
        grace_days: r.get("grace_days")?,
        state: r.get("state")?,
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
        tried_at: r.get("tried_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        removed_at: r.get("removed_at")?,
        archived_to: r.get("archived_to")?,
        purge_at: r.get("purge_at")?,
        done_at: r.get("done_at")?,
    })
}

/// A removal to queue: `teammate_cleanup_queue`.
pub struct NewTeammateCleanup<'a> {
    pub machine_id: &'a str,
    pub owner_id: &'a str,
    pub user_id: &'a str,
    pub os_user: &'a str,
    pub reason: &'a str,
    pub files: &'a str,
    pub grace_days: i64,
    pub created_by: Option<&'a str>,
}

/// Removing leaving teammates' accounts on one server (ADR 0066): one row per removal of
/// a teammate's account for one owner's Bots (`sb-t-`, ADR 0064), `pending` until the
/// root helper has done it, then `done`, or `held` while their work waits to be purged;
/// `cancelled` if they came back before it was tried. At most one pending per owner and
/// teammate, so queueing again changes nothing.
fn migrate_account_removals(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_removals (
          id TEXT PRIMARY KEY,
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          account TEXT NOT NULL,
          reason TEXT NOT NULL,
          files TEXT NOT NULL CHECK (files IN ('archive', 'delete')),
          grace_days INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL CHECK (state IN ('pending', 'held', 'done', 'cancelled')),
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          tried_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          removed_at INTEGER,
          archived_to TEXT,
          purge_at INTEGER,
          done_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS account_removals_pending ON account_removals(owner_id, user_id) WHERE state = 'pending';
        CREATE INDEX IF NOT EXISTS account_removals_state ON account_removals(state);
        CREATE TABLE IF NOT EXISTS teammate_spaces (
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          made_at INTEGER NOT NULL,
          PRIMARY KEY (owner_id, user_id)
        );",
    )?;
    // Pairs made before this table, whose accounts a recreated container may have lost
    // while keeping their folders: the audit log is the only record of them. Once only,
    // so a pair removed since is never found again.
    c.execute(
        "INSERT OR IGNORE INTO teammate_spaces (owner_id, user_id, made_at)
         SELECT target_id, json_extract(details, '$.forUser'), MIN(at) FROM audit_events
         WHERE action = 'isolation.account_created' AND target_type = 'user' AND outcome = 'success'
           AND target_id IS NOT NULL AND json_extract(details, '$.forUser') IS NOT NULL
         GROUP BY 1, 2",
        [],
    )?;
    Ok(())
}

/// One teammate's account for one owner's Bots on this server, being removed (ADR 0066).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRemoval {
    pub id: String,
    /// Whose shared Bots the teammate ran.
    pub owner_id: String,
    /// The teammate.
    pub user_id: String,
    /// `sb-t-<hash>`.
    pub account: String,
    /// `disabled`, `deprovisioned`, `deleted`, `access_lost` or `admin`.
    pub reason: String,
    /// `archive` or `delete`: what becomes of their workspace.
    pub files: String,
    pub grace_days: i64,
    pub state: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub tried_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub removed_at: Option<i64>,
    pub archived_to: Option<String>,
    pub purge_at: Option<i64>,
    pub done_at: Option<i64>,
}

fn account_removal_row(r: &Row) -> rusqlite::Result<AccountRemoval> {
    Ok(AccountRemoval {
        id: r.get("id")?,
        owner_id: r.get("owner_id")?,
        user_id: r.get("user_id")?,
        account: r.get("account")?,
        reason: r.get("reason")?,
        files: r.get("files")?,
        grace_days: r.get("grace_days")?,
        state: r.get("state")?,
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
        tried_at: r.get("tried_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        removed_at: r.get("removed_at")?,
        archived_to: r.get("archived_to")?,
        purge_at: r.get("purge_at")?,
        done_at: r.get("done_at")?,
    })
}

/// A removal to queue: `account_removal_queue`.
pub struct NewAccountRemoval<'a> {
    pub owner_id: &'a str,
    pub user_id: &'a str,
    pub account: &'a str,
    pub reason: &'a str,
    pub files: &'a str,
    pub grace_days: i64,
    pub created_by: Option<&'a str>,
}

/// Token metering (ADR 0050): the model tokens each run used, one row per model, or one
/// row with `reported = 0` when the harness didn't say. Charged to the Bot's owner, like
/// the run; `user_id` and `bot_id` have no foreign key, as `bots.owner_id` doesn't, so a
/// deleted Bot's usage stays billed. `meter_status` is for reporting to Stripe, when
/// that's on. Subscriptions keep their period's start, for billing-period usage.
fn migrate_token_usage(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('subscriptions') WHERE name = 'period_start'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE subscriptions ADD COLUMN period_start INTEGER;")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS token_usage (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL,
          bot_id TEXT NOT NULL,
          run_id TEXT NOT NULL,
          message_id INTEGER,
          harness TEXT NOT NULL,
          model TEXT,
          reported INTEGER NOT NULL CHECK (reported IN (0, 1)),
          input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
          output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
          cache_read_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
          cache_write_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
          at INTEGER NOT NULL,
          meter_status TEXT CHECK (meter_status IN ('pending', 'sent', 'failed')),
          meter_attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS token_usage_user_at ON token_usage(user_id, at);
        CREATE INDEX IF NOT EXISTS token_usage_run ON token_usage(run_id);
        CREATE INDEX IF NOT EXISTS token_usage_meter ON token_usage(id) WHERE meter_status = 'pending';",
    )
}

/// Why botd paused a routine, and for whom (ADR 0047), so it can be resumed.
fn migrate_routine_pauses(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for (col, ty) in [("paused_reason", "TEXT"), ("paused_for", "TEXT"), ("paused_at", "INTEGER")] {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('routines') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE routines ADD COLUMN {col} {ty};"))?;
        }
    }
    Ok(())
}

/// Who wrote each routine's instruction, so its runs are for them (ADR 0046). Routines
/// from before have none, and run for their Bot's owner as they did.
fn migrate_routine_authors(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('routines') WHERE name = 'author_id'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE routines ADD COLUMN author_id TEXT;")?;
    }
    Ok(())
}

/// Users linked to their payment-provider customer (ADR 0042), at most one each way;
/// customers the provider deleted, which are never linked again; and each user's open
/// checkout, closed before another is opened so only one can be paid. Subscribers from
/// before keep their portal: a user whose subscriptions name one customer, which no other
/// user's do, is linked to it.
fn migrate_billing_customers(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS billing_customers (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          provider TEXT NOT NULL,
          customer_id TEXT NOT NULL UNIQUE,
          linked_at INTEGER NOT NULL,
          linked_via TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS billing_deleted_customers (
          customer_id TEXT PRIMARY KEY,
          deleted_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS billing_checkouts (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          session_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );",
    )?;
    c.execute(
        "INSERT OR IGNORE INTO billing_customers (user_id, provider, customer_id, linked_at, linked_via)
         SELECT user_id, MIN(provider), MIN(customer_id), ?, 'migration' FROM subscriptions
         WHERE customer_id IS NOT NULL AND customer_id != ''
         GROUP BY user_id
         HAVING COUNT(DISTINCT customer_id) = 1
           AND MIN(customer_id) NOT IN (
             SELECT customer_id FROM subscriptions WHERE customer_id IS NOT NULL
             GROUP BY customer_id HAVING COUNT(DISTINCT user_id) > 1)",
        [now()],
    )?;
    Ok(())
}
/// Harness CLIs and agent upgrades on machines (ADR 0039): what each agent last said,
/// the plan sent to it, and an upgrade on its way, held, or failed.
fn migrate_machine_upkeep(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'agent_upkeep'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN agent_upkeep TEXT;
        ALTER TABLE machines ADD COLUMN harnesses_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN harnesses_sent_plan TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_hold_at INTEGER;
        ALTER TABLE machines ADD COLUMN upgrade_hold_by TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_id TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_build TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN upgrade_by TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_failed_build TEXT;",
    )
}

/// Billing v0 (ADR 0040): routine runs counted per user and UTC day, every Stripe
/// subscription with its user, and the Stripe event ids already applied, so a
/// redelivered event changes nothing.
fn migrate_billing(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS usage_daily (
          user_id TEXT NOT NULL REFERENCES users(id),
          day TEXT NOT NULL,
          routine_runs INTEGER NOT NULL DEFAULT 0,
          routine_refused INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (user_id, day)
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
          subscription_id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id),
          provider TEXT NOT NULL,
          customer_id TEXT,
          status TEXT NOT NULL,
          price_id TEXT,
          tier TEXT,
          period_end INTEGER,
          started INTEGER NOT NULL,
          event_created INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS subscriptions_user ON subscriptions (user_id);
        CREATE TABLE IF NOT EXISTS billing_events (
          event_id TEXT PRIMARY KEY,
          type TEXT NOT NULL,
          received_at INTEGER NOT NULL
        );",
    )
}
/// Machines come up firewalled and enrolled (ADR 0035): the provider firewall each is
/// behind, and when it must have enrolled by (and when it was found it hadn't).
fn migrate_machine_lockdown(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'firewall_id'",
        [],
        |r| r.get(0),
    )?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN firewall_id TEXT;
        ALTER TABLE machines ADD COLUMN enroll_by INTEGER;
        ALTER TABLE machines ADD COLUMN enroll_overdue_at INTEGER;",
    )
}
/// Placement (ADR 0036): an admin assigns a user's machine to them, and then that
/// user's Bots run there. Kept on the machine row, so a user can only be placed on
/// their own machine, and destroying it ends the placement.
fn migrate_machine_placement(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'assigned_at'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE machines ADD COLUMN assigned_at INTEGER; ALTER TABLE machines ADD COLUMN assigned_by TEXT;")?;
    }
    Ok(())
}
/// Machine enrollment (ADR 0031). Tokens are kept as SHA-256 hashes, bound to one
/// machine, and used once. Certificates are kept by fingerprint, never with their keys
/// (botd never sees a machine's key); `id` orders them, so the ones before a rotated
/// certificate can be revoked once it's in use.
fn migrate_machine_enrollment(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'enrollment'",
        [],
        |r| r.get(0),
    )?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machines ADD COLUMN enrollment TEXT NOT NULL DEFAULT 'none' CHECK (enrollment IN ('none', 'enrolled', 'held', 'revoked'));
            ALTER TABLE machines ADD COLUMN enrolled_at INTEGER;
            ALTER TABLE machines ADD COLUMN agent_seen_at INTEGER;
            ALTER TABLE machines ADD COLUMN agent_version TEXT;
            ALTER TABLE machines ADD COLUMN agent_error TEXT;",
        )?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          machine_id TEXT NOT NULL REFERENCES machines(id),
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS machine_tokens_machine ON machine_tokens(machine_id);
        CREATE TABLE IF NOT EXISTS machine_certs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fingerprint TEXT NOT NULL UNIQUE,
          serial TEXT NOT NULL UNIQUE,
          machine_id TEXT NOT NULL REFERENCES machines(id),
          user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL CHECK (status IN ('active', 'held', 'revoked')),
          issued_for TEXT NOT NULL CHECK (issued_for IN ('enrolled', 'rotated')),
          issued_at INTEGER NOT NULL,
          not_before INTEGER NOT NULL,
          not_after INTEGER NOT NULL,
          first_seen_at INTEGER,
          revoked_at INTEGER,
          revoked_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS machine_certs_machine ON machine_certs(machine_id, status);",
    )
}

/// Tiers (ADR 0033): each user's assigned tier (NULL: the configured default) and runs
/// counted per user and UTC month, for the tier's monthly limit. Keyed by user, so
/// every query names one.
fn migrate_tiers(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has_tier = c.prepare("SELECT 1 FROM pragma_table_info('users') WHERE name = 'tier'")?.exists([])?;
    if !has_tier {
        c.execute_batch("ALTER TABLE users ADD COLUMN tier TEXT;")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS usage_monthly (
          user_id TEXT NOT NULL REFERENCES users(id),
          period TEXT NOT NULL,
          runs INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (user_id, period)
        );",
    )
}

/// SCIM provisioning (ADR 0023): bearer tokens (hashes only), each in a tenant, and the
/// users a tenant provisioned. One row per user: a user belongs to at most one tenant.
/// `deleted_at` is a SCIM DELETE: the tenant can't see the user any more, but the user,
/// disabled, and its audit history stay. Its `externalId` stays reserved, so the same
/// person provisioned again gets the same user back. No ON DELETE: users are never deleted.
fn migrate_scim(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_tokens (
          id TEXT PRIMARY KEY,
          tenant TEXT NOT NULL,
          label TEXT,
          sso_provider TEXT,
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          last_used_at INTEGER,
          revoked_at INTEGER,
          revoked_by TEXT
        );
        CREATE INDEX IF NOT EXISTS scim_tokens_tenant ON scim_tokens(tenant, created_at);
        CREATE TABLE IF NOT EXISTS scim_users (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          tenant TEXT NOT NULL,
          external_id TEXT,
          user_name TEXT NOT NULL COLLATE NOCASE,
          given_name TEXT,
          family_name TEXT,
          display_name TEXT,
          formatted TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          deleted_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS scim_users_external_id ON scim_users(tenant, external_id) WHERE external_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS scim_users_user_name ON scim_users(tenant, user_name) WHERE deleted_at IS NULL;",
    )
}

/// Per-user machines from the control plane (ADR 0025). Every query names the user or
/// the machine. The partial unique index is "one machine per user": a second request
/// can't insert another while one is live. Destroyed rows are kept as history.
fn migrate_machines(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machines (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id),
          provider TEXT NOT NULL,
          provider_id TEXT,
          label TEXT NOT NULL UNIQUE,
          tag TEXT NOT NULL,
          tier TEXT NOT NULL,
          plan TEXT NOT NULL,
          region TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'running', 'suspended', 'destroying', 'destroyed', 'error')),
          provider_status TEXT,
          ipv4 TEXT,
          backups INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          create_sent_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL,
          destroyed_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS machines_one_per_user ON machines(user_id) WHERE state <> 'destroyed';
        CREATE INDEX IF NOT EXISTS machines_state ON machines(state, created_at);",
    )
}

/// Requests for access from the public sign-up form (ADR 0022). Consent is a column,
/// not a flag in a blob: no row exists without it. `user_id` has no foreign key, like
/// `bots.owner_id`: users are never deleted.
fn migrate_signups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS signups (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT NOT NULL COLLATE NOCASE,
          company TEXT NOT NULL,
          team_size TEXT NOT NULL,
          use_case TEXT NOT NULL,
          sign_in TEXT NOT NULL CHECK (sign_in IN ('microsoft', 'google', 'github', 'apple', 'other')),
          consent_at INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
          ip TEXT,
          user_agent TEXT,
          created_at INTEGER NOT NULL,
          decided_at INTEGER,
          decided_by TEXT,
          reason TEXT,
          user_id TEXT,
          role TEXT
        );
        CREATE INDEX IF NOT EXISTS signups_status ON signups(status, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS signups_one_pending ON signups(email) WHERE status = 'pending';",
    )
}

/// The actor columns the audit log gained with per-user actors (ADR 0019).
pub const AUDIT_ACTOR_COLUMNS: [&str; 7] = ["actor_email", "actor_role", "auth_method", "idp", "idp_provider", "session_id", "on_behalf_of"];

/// Per-user audit actors (ADR 0019): each event says who acted as of then (email,
/// role), how they signed in (method, SSO provider and type, session), and whom a Bot
/// acted for. Only adds nullable columns, so old rows stay as written: the log is
/// append-only, and guessing at who did something before it was recorded would be
/// rewriting history. Sessions remember their SSO provider, and queued messages who
/// asked for them, so the runs they start can be attributed.
fn migrate_audit_actors(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    for col in AUDIT_ACTOR_COLUMNS {
        c.execute_batch(&format!("ALTER TABLE audit_events ADD COLUMN {col} TEXT;"))?;
    }
    c.execute_batch(
        "CREATE INDEX audit_events_on_behalf_of ON audit_events(on_behalf_of, id) WHERE on_behalf_of IS NOT NULL;
        CREATE INDEX audit_events_session ON audit_events(session_id, id) WHERE session_id IS NOT NULL;
        ALTER TABLE sessions ADD COLUMN idp_provider TEXT;
        ALTER TABLE messages ADD COLUMN requested_by TEXT;",
    )?;
    if !fresh {
        let details = serde_json::json!({ "added": AUDIT_ACTOR_COLUMNS, "reason": "per-user actors and IdP; earlier events leave these empty" });
        c.execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, target_id, outcome, details) VALUES (?, 'system', 'migration', 'audit.schema_upgraded', 'audit', 'actors', 'success', ?)",
            params![now(), details.to_string()],
        )?;
    }
    Ok(())
}

/// The admin portal (ADR 0021): when and how each user last signed in. Sessions are
/// pruned 30 days after they end, so this lives on the user; it starts from the
/// newest session still kept.
fn migrate_last_login(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "ALTER TABLE users ADD COLUMN last_login_at INTEGER;
        ALTER TABLE users ADD COLUMN last_login_method TEXT;
        ALTER TABLE users ADD COLUMN last_login_idp_provider TEXT;
        UPDATE users SET (last_login_at, last_login_method, last_login_idp_provider) =
          (SELECT created_at, method, idp_provider FROM sessions WHERE sessions.user_id = users.id ORDER BY created_at DESC, id LIMIT 1);",
    )
}

/// Bot ACLs (ADR 0017): an owner and a visibility per Bot, and per-user grants.
/// Bots from before belong to the owner account (`operator`, break-glass) and stay
/// shared, so everyone keeps the Bots they had. No foreign key on `owner_id`: the
/// owner account is made after migrations run, and users are never deleted.
fn migrate_bot_acls(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "ALTER TABLE bots ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'operator';
        ALTER TABLE bots ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared' CHECK (visibility IN ('private', 'shared'));
        CREATE INDEX bots_owner ON bots(owner_id);
        CREATE TABLE bot_grants (
          bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          level TEXT NOT NULL CHECK (level IN ('viewer', 'operator')),
          created_at INTEGER NOT NULL,
          created_by TEXT,
          PRIMARY KEY (bot_id, user_id)
        );
        CREATE INDEX bot_grants_user ON bot_grants(user_id);",
    )?;
    let n: i64 = c.query_row("SELECT count(*) FROM bots", [], |r| r.get(0))?;
    if n > 0 {
        let details = serde_json::json!({ "bots": n, "owner": "operator", "visibility": "shared", "reason": "Bots from before ACLs" });
        c.execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, outcome, details) VALUES (?, 'system', 'migration', 'bot.acl_initialized', 'bot', 'success', ?)",
            params![now(), details.to_string()],
        )?;
    }
    Ok(())
}

/// SSO identities (ADR 0014): any number per user, each `(issuer, subject)` at most
/// once. `users.idp_issuer`/`idp_subject` become the user's first identity and are
/// kept in step with this table. Sessions remember which identity signed them in.
fn migrate_identities(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE user_identities (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          issuer TEXT NOT NULL,
          subject TEXT NOT NULL,
          tenant TEXT,
          email TEXT,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          last_login_at INTEGER,
          UNIQUE (issuer, subject)
        );
        CREATE INDEX user_identities_user ON user_identities(user_id, created_at);
        INSERT INTO user_identities (id, user_id, provider, issuer, subject, created_at)
          SELECT 'i' || lower(hex(randomblob(4))), id, 'oidc', idp_issuer, idp_subject, created_at FROM users WHERE idp_issuer IS NOT NULL;
        ALTER TABLE sessions ADD COLUMN idp_subject TEXT;",
    )
}

/// Users, sessions, and one-time sign-in codes (ADR 0012). Tables start empty; botd
/// creates the owner (`operator`, the break-glass account) on start, so an upgrade
/// keeps the shared password working.
fn migrate_users(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE users (
          id TEXT PRIMARY KEY,
          email TEXT COLLATE NOCASE UNIQUE,
          display_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'readonly')),
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
          idp_issuer TEXT,
          idp_subject TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          CHECK ((idp_issuer IS NULL) = (idp_subject IS NULL))
        );
        CREATE UNIQUE INDEX users_idp ON users(idp_issuer, idp_subject) WHERE idp_issuer IS NOT NULL;
        CREATE TABLE sessions (
          id TEXT PRIMARY KEY,
          token_hash TEXT NOT NULL UNIQUE,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          kind TEXT NOT NULL CHECK (kind IN ('cookie', 'token')),
          method TEXT NOT NULL,
          label TEXT,
          ip TEXT,
          user_agent TEXT,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked_at INTEGER,
          revoked_by TEXT,
          revoke_reason TEXT
        );
        CREATE INDEX sessions_user ON sessions(user_id, created_at);
        CREATE TABLE login_codes (
          code_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_by TEXT,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER
        );",
    )
}

/// Structured audit events (ADR 0009): actor kind and id, target type and id,
/// outcome, and request source. Copies the rows from the first audit table.
/// DELETE is refused except for rows older than `audit_retention_days`.
fn migrate_audit_events(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "DROP TRIGGER audit_events_no_update;
        DROP TRIGGER audit_events_no_delete;
        ALTER TABLE audit_events RENAME TO audit_events_v1;
        CREATE TABLE audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'bot', 'system')),
          actor_id TEXT,
          actor_name TEXT,
          actor_subject TEXT,
          action TEXT NOT NULL,
          target_type TEXT,
          target_id TEXT,
          bot_id TEXT,
          outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
          ip TEXT,
          user_agent TEXT,
          details TEXT NOT NULL DEFAULT '{}'
        );
        INSERT INTO audit_events (id, at, actor_kind, actor_id, action, target_type, target_id, bot_id, outcome, details)
        SELECT id, at,
          CASE actor WHEN 'user' THEN 'user' WHEN 'bot' THEN 'bot' ELSE 'system' END,
          CASE actor WHEN 'user' THEN 'operator' WHEN 'bot' THEN bot_id ELSE NULL END,
          action,
          CASE
            WHEN target IS NULL THEN NULL
            WHEN action LIKE 'approval.%' THEN 'approval'
            WHEN action LIKE 'rule.%' OR action IN ('policy.allowed', 'policy.denied') THEN 'rule'
            ELSE 'policy'
          END,
          target, bot_id,
          CASE WHEN action = 'policy.denied' THEN 'denied' ELSE 'success' END,
          detail
        FROM audit_events_v1 ORDER BY id;
        DROP TABLE audit_events_v1;
        CREATE INDEX audit_events_at ON audit_events(at);
        CREATE INDEX audit_events_action ON audit_events(action, id);
        CREATE INDEX audit_events_actor ON audit_events(actor_kind, actor_id, id);
        CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;",
    )?;
    c.execute_batch(&format!(
        "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
          WHEN coalesce(OLD.at >= {AUDIT_CUTOFF}, 1)
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;"
    ))
}

/// Unix ms before which audit events may be deleted, or NULL while retention is off.
/// Pruning and the delete trigger share it: SQLite's 'now' is fixed for one statement,
/// so both see the same cutoff.
const AUDIT_CUTOFF: &str = "(SELECT (CAST(strftime('%s', 'now') AS INTEGER) - CAST(value AS INTEGER) * 86400) * 1000
  FROM settings WHERE key = 'audit_retention_days' AND CAST(value AS INTEGER) > 0)";

/// Approvals and harness policy. Fresh installs ask before risky tools; existing
/// installs keep running in bypass, as before, until the operator opts in.
fn migrate_approvals(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE bot_policies (
          bot_id TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
          policy TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE policy_rules (
          id TEXT PRIMARY KEY,
          bot_id TEXT REFERENCES bots(id) ON DELETE CASCADE,
          action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
          tool TEXT NOT NULL DEFAULT '*',
          pattern TEXT NOT NULL,
          note TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE approvals (
          id TEXT PRIMARY KEY,
          bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
          harness TEXT NOT NULL,
          tool TEXT NOT NULL,
          kind TEXT NOT NULL,
          subject TEXT NOT NULL,
          input TEXT NOT NULL,
          class TEXT NOT NULL,
          reason TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          decided_at INTEGER,
          decided_by TEXT,
          note TEXT,
          rule_id TEXT
        );
        CREATE INDEX approvals_status ON approvals(status, created_at);
        CREATE TABLE audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          bot_id TEXT,
          target TEXT,
          detail TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
        CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;",
    )?;
    let policy = Policy::new(if fresh { Mode::Ask } else { Mode::Bypass });
    c.execute("INSERT INTO settings (key, value) VALUES ('policy', ?)", [serde_json::to_string(&policy).unwrap()])?;
    let detail = serde_json::json!({ "mode": policy.mode, "reason": if fresh { "fresh install" } else { "existing install keeps bypass" } });
    c.execute(
        "INSERT INTO audit_events (at, actor, action, target, detail) VALUES (?, 'system', 'policy.initialized', 'global', ?)",
        params![now(), detail.to_string()],
    )?;
    Ok(())
}

impl Db {
    pub fn open(path: &std::path::Path) -> rusqlite::Result<Db> {
        let c = Connection::open(path)?;
        let fresh: bool = c.query_row("SELECT NOT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'bots')", [], |r| r.get(0))?;
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS bots (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              color TEXT NOT NULL,
              shape TEXT NOT NULL,
              harness TEXT NOT NULL,
              model TEXT,
              session_id TEXT,
              primary_bot INTEGER NOT NULL DEFAULT 0,
              hidden INTEGER NOT NULL DEFAULT 0,
              unread INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
              role TEXT NOT NULL,
              text TEXT NOT NULL,
              question TEXT,
              error INTEGER NOT NULL DEFAULT 0,
              status TEXT,
              created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS messages_bot ON messages(bot_id, id);
            CREATE TABLE IF NOT EXISTS routines (
              id TEXT PRIMARY KEY,
              bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              cron TEXT NOT NULL,
              instruction TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              last_run_at INTEGER,
              created_at INTEGER NOT NULL
            );",
        )?;
        // Added after the first release; fails harmlessly if it already exists.
        let _ = c.execute("ALTER TABLE messages ADD COLUMN from_bot TEXT", []);
        let _ = c.execute("ALTER TABLE bots ADD COLUMN effort TEXT", []);
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, migrate) in MIGRATIONS.iter().enumerate().skip(version.max(0) as usize) {
            let tx = c.unchecked_transaction()?;
            migrate(&tx, fresh)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)?;
            tx.commit()?;
        }
        Ok(Db(Mutex::new(c), std::sync::OnceLock::new()))
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Set once, by the app, from its license (ADR 0038).
    pub fn set_seat_cap(&self, cap: SeatCap) {
        let _ = self.1.set(cap);
    }

    fn seat_cap(&self) -> Option<u32> {
        self.1.get().and_then(|f| f())
    }

    // Generic settings, for small values that need no table of their own.

    pub fn setting(&self, key: &str) -> Option<String> {
        self.c().query_row("SELECT value FROM settings WHERE key = ?", [key], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        self.c().execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [key, value]).unwrap();
    }

    // Bots

    pub fn bots(&self) -> Vec<Bot> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bots ORDER BY primary_bot DESC, created_at").unwrap();
        s.query_map([], bot_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn bot(&self, id: &str) -> Option<Bot> {
        self.c().query_row("SELECT * FROM bots WHERE id = ?", [id], bot_row).optional().ok().flatten()
    }

    /// Owned by the owner account and shared, like every Bot from before ACLs.
    pub fn create_bot(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool) -> Bot {
        self.create_bot_owned(name, color, shape, harness, model, primary, crate::users::OPERATOR, Visibility::Shared)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_bot_owned(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool, owner: &str, visibility: Visibility) -> Bot {
        self.create_bot_capped(name, color, shape, harness, model, primary, owner, visibility, None).unwrap()
    }

    /// None when the owner already has `max_bots`. Counting and inserting are one
    /// statement, so two creates racing for the last slot can't both get it.
    #[allow(clippy::too_many_arguments)]
    pub fn create_bot_capped(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool, owner: &str, visibility: Visibility, max_bots: Option<u32>) -> Option<Bot> {
        let id = crate::short_id();
        let n = self
            .c()
            .execute(
                "INSERT INTO bots (id, name, color, shape, harness, model, primary_bot, created_at, owner_id, visibility)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                 WHERE ?11 IS NULL OR (SELECT COUNT(*) FROM bots WHERE owner_id = ?9) < ?11",
                params![id, name, color, shape, harness, model, primary, now(), owner, visibility.as_str(), max_bots],
            )
            .unwrap();
        if n == 0 { None } else { self.bot(&id) }
    }

    // Bot ACLs (ADR 0017)

    /// False when the new owner already has `max_bots`; checked in the same statement.
    pub fn set_bot_owner_capped(&self, id: &str, owner: &str, max_bots: Option<u32>) -> bool {
        self.c()
            .execute(
                "UPDATE bots SET owner_id = ?1 WHERE id = ?2 AND (?3 IS NULL OR (SELECT COUNT(*) FROM bots WHERE owner_id = ?1) < ?3)",
                params![owner, id, max_bots],
            )
            .unwrap()
            > 0
    }

    pub fn set_bot_visibility(&self, id: &str, v: Visibility) {
        self.c().execute("UPDATE bots SET visibility = ? WHERE id = ?", params![v.as_str(), id]).unwrap();
    }

    pub fn grant(&self, bot_id: &str, user_id: &str) -> Option<Grant> {
        self.c()
            .query_row("SELECT * FROM bot_grants WHERE bot_id = ? AND user_id = ?", [bot_id, user_id], grant_row)
            .optional()
            .ok()
            .flatten()
            .map(|g| g.level)
    }

    /// A user's grants, by Bot id.
    pub fn user_grants(&self, user_id: &str) -> std::collections::HashMap<String, Grant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bot_grants WHERE user_id = ?").unwrap();
        s.query_map([user_id], grant_row).unwrap().filter_map(Result::ok).map(|g| (g.bot_id, g.level)).collect()
    }

    pub fn grants(&self, bot_id: &str) -> Vec<BotGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bot_grants WHERE bot_id = ? ORDER BY created_at, user_id").unwrap();
        s.query_map([bot_id], grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Adds or changes a grant. Returns the level it had before.
    pub fn set_grant(&self, bot_id: &str, user_id: &str, level: Grant, by: &str) -> Option<Grant> {
        let before = self.grant(bot_id, user_id);
        self.c()
            .execute(
                "INSERT INTO bot_grants (bot_id, user_id, level, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(bot_id, user_id) DO UPDATE SET level = ?3, created_at = ?4, created_by = ?5",
                params![bot_id, user_id, level.as_str(), now(), by],
            )
            .unwrap();
        before
    }

    /// Removes a grant. Returns its level, or None if there was none.
    pub fn remove_grant(&self, bot_id: &str, user_id: &str) -> Option<Grant> {
        let before = self.grant(bot_id, user_id)?;
        self.c().execute("DELETE FROM bot_grants WHERE bot_id = ? AND user_id = ?", [bot_id, user_id]).unwrap();
        Some(before)
    }

    pub fn update_bot(&self, id: &str, p: BotPatch) {
        let c = self.c();
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            c.execute(&format!("UPDATE bots SET {col} = ? WHERE id = ?"), params![v, id]).unwrap();
        };
        if let Some(v) = p.name { set("name", &v) }
        if let Some(v) = p.color { set("color", &v) }
        if let Some(v) = p.shape { set("shape", &v) }
        if let Some(v) = p.harness { set("harness", &v) }
        if let Some(v) = p.model { set("model", &v) }
        if let Some(v) = p.effort { set("effort", &v) }
        if let Some(v) = p.session_id { set("session_id", &v) }
        if let Some(v) = p.hidden { set("hidden", &v) }
        if let Some(v) = p.unread { set("unread", &v) }
        if let Some(v) = p.prompts { set("prompts", &v.map(|l| serde_json::to_string(&l).unwrap())) }
    }

    pub fn delete_bot(&self, id: &str) {
        self.c().execute("DELETE FROM bots WHERE id = ?", [id]).unwrap();
    }

    // Messages

    pub fn messages(&self, bot_id: &str, limit: i64) -> Vec<Message> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM (SELECT * FROM messages WHERE bot_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id")
            .unwrap();
        s.query_map(params![bot_id, limit], message_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn last_message(&self, bot_id: &str) -> Option<Message> {
        self.c()
            .query_row(
                "SELECT * FROM messages WHERE bot_id = ? AND role != 'routine' ORDER BY id DESC LIMIT 1",
                [bot_id],
                message_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The Bot's latest unanswered handoff card, unless the user wrote after it.
    pub fn open_handoff(&self, bot_id: &str) -> Option<i64> {
        self.c()
            .query_row(
                "SELECT id FROM messages WHERE bot_id = ?1 AND role = 'bot'
                   AND json_extract(question, '$.handoff') = 1 AND json_extract(question, '$.picked') IS NULL
                   AND id > COALESCE((SELECT MAX(id) FROM messages WHERE bot_id = ?1 AND role = 'user'), 0)
                 ORDER BY id DESC LIMIT 1",
                [bot_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn message(&self, id: i64) -> Option<Message> {
        self.c().query_row("SELECT * FROM messages WHERE id = ?", [id], message_row).optional().ok().flatten()
    }

    pub fn add_message(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>) -> Message {
        self.add_message_from(bot_id, role, text, question, error, status, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_message_from(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>, from_bot: Option<&str>) -> Message {
        let owners: Vec<String> = [Some(bot_id), from_bot].into_iter().flatten().filter_map(|b| self.bot_owner(b)).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        let question = question.map(|q| redact::value_for(&owners, q.clone()).to_string());
        let c = self.c();
        c.execute(
            "INSERT INTO messages (bot_id, role, text, question, error, status, from_bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![bot_id, role, redact::text_for(&owners, text), question, error, status, from_bot, now()],
        )
        .unwrap();
        let id = c.last_insert_rowid();
        drop(c);
        self.message(id).unwrap()
    }

    pub fn last_id(&self) -> i64 {
        self.c().query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |r| r.get(0)).unwrap_or(0)
    }

    /// The Bot's chat bubbles written after message `after`.
    pub fn replies_after(&self, bot_id: &str, after: i64) -> Vec<Message> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM messages WHERE bot_id = ? AND id > ? AND role = 'bot' ORDER BY id").unwrap();
        s.query_map(params![bot_id, after], message_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn set_status(&self, id: i64, status: &str) {
        self.c().execute("UPDATE messages SET status = ? WHERE id = ?", params![status, id]).unwrap();
    }

    /// Free text (name, email, user agent) is masked as `record` masks it.
    pub fn set_requested_by(&self, id: i64, who: &audit::Who) {
        let mut who = who.clone();
        for v in [&mut who.actor.name, &mut who.actor.email, &mut who.source.user_agent].into_iter().flatten() {
            *v = audit::redact_text(v);
        }
        let who = serde_json::to_value(&who).map(|v| redact::value(v).to_string()).unwrap_or_default();
        self.c().execute("UPDATE messages SET requested_by = ? WHERE id = ?", params![who, id]).unwrap();
    }

    pub fn set_question(&self, id: i64, q: &Value) {
        let owner = self.message(id).and_then(|m| self.bot_owner(&m.bot_id));
        let q = redact::value_for(owner.as_deref().as_slice(), q.clone()).to_string();
        self.c().execute("UPDATE messages SET question = ? WHERE id = ?", params![q, id]).unwrap();
    }

    /// Who owns a Bot: whose own secrets are redacted from what it writes (ADR 0029).
    pub fn bot_owner(&self, bot_id: &str) -> Option<String> {
        self.c().query_row("SELECT owner_id FROM bots WHERE id = ?", [bot_id], |r| r.get(0)).ok()
    }

    pub fn pending(&self) -> Vec<Message> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM messages WHERE status IN ('queued', 'running') ORDER BY id").unwrap();
        s.query_map([], message_row).unwrap().filter_map(Result::ok).collect()
    }

    // Routines

    pub fn routines(&self, bot_id: Option<&str>) -> Vec<Routine> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM routines WHERE ?1 IS NULL OR bot_id = ?1 ORDER BY created_at")
            .unwrap();
        s.query_map([bot_id], routine_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn routine(&self, id: &str) -> Option<Routine> {
        self.c().query_row("SELECT * FROM routines WHERE id = ?", [id], routine_row).optional().ok().flatten()
    }

    #[cfg(test)]
    pub fn add_routine(&self, bot_id: &str, name: &str, cron: &str, instruction: &str) -> Routine {
        self.add_routine_by(bot_id, name, cron, instruction, true, None)
    }

    /// A routine whose runs are for `author` (ADR 0046), written whole so the scheduler
    /// never sees it without its author.
    pub fn add_routine_by(&self, bot_id: &str, name: &str, cron: &str, instruction: &str, enabled: bool, author: Option<&str>) -> Routine {
        let id = crate::short_id();
        self.c()
            .execute(
                "INSERT INTO routines (id, bot_id, name, cron, instruction, enabled, author_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, bot_id, name, cron, instruction, enabled, author, now()],
            )
            .unwrap();
        self.routine(&id).unwrap()
    }

    /// `author`: whom its runs are for once `instruction` changes it (ADR 0046). Both
    /// change under one lock, so the scheduler never reads one without the other.
    pub fn update_routine(&self, id: &str, name: Option<&str>, cron: Option<&str>, instruction: Option<&str>, enabled: Option<bool>, author: Option<&str>) {
        let c = self.c();
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            c.execute(&format!("UPDATE routines SET {col} = ? WHERE id = ?"), params![v, id]).unwrap();
        };
        if let Some(v) = name { set("name", &v) }
        if let Some(v) = cron { set("cron", &v) }
        if let Some(v) = instruction {
            if let Some(a) = author {
                c.execute("UPDATE routines SET author_id = ? WHERE id = ? AND instruction != ?", params![a, id, v]).unwrap();
            }
            set("instruction", &v)
        }
        if let Some(v) = enabled {
            c.execute("UPDATE routines SET enabled = ?, paused_reason = NULL, paused_for = NULL, paused_at = NULL WHERE id = ?", params![v, id]).unwrap();
        }
    }

    /// Turns a routine off for a disabled user (ADR 0047). False when it was already off.
    pub fn pause_routine(&self, id: &str, reason: &str, for_user: &str, at: i64) -> bool {
        self.c()
            .execute(
                "UPDATE routines SET enabled = 0, paused_reason = ?, paused_for = ?, paused_at = ? WHERE id = ? AND enabled = 1",
                params![reason, for_user, at, id],
            )
            .unwrap()
            > 0
    }

    /// Routines botd paused for `user_id`.
    pub fn routines_paused_for(&self, user_id: &str) -> Vec<Routine> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM routines WHERE paused_for = ? AND enabled = 0 ORDER BY created_at").unwrap();
        s.query_map([user_id], routine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Turns a paused routine back on. False when it isn't paused any more.
    pub fn resume_routine(&self, id: &str) -> bool {
        self.c()
            .execute(
                "UPDATE routines SET enabled = 1, paused_reason = NULL, paused_for = NULL, paused_at = NULL WHERE id = ? AND enabled = 0 AND paused_reason IS NOT NULL",
                [id],
            )
            .unwrap()
            > 0
    }

    /// Keeps a paused routine off, now for someone else who is still disabled.
    pub fn repause_routine(&self, id: &str, reason: &str, for_user: &str) {
        self.c()
            .execute("UPDATE routines SET paused_reason = ?, paused_for = ? WHERE id = ? AND enabled = 0 AND paused_reason IS NOT NULL", params![reason, for_user, id])
            .unwrap();
    }

    /// Moves what a routine holds for `from` (its authorship, its pause) to `to`.
    pub fn hand_over_routine(&self, id: &str, from: &str, to: &str) {
        self.c()
            .execute(
                "UPDATE routines SET author_id = CASE WHEN author_id = ?1 THEN ?2 ELSE author_id END,
                   paused_for = CASE WHEN paused_for = ?1 THEN ?2 ELSE paused_for END WHERE id = ?3",
                params![from, to, id],
            )
            .unwrap();
    }

    pub fn routine_ran(&self, id: &str, at: i64) {
        self.c().execute("UPDATE routines SET last_run_at = ? WHERE id = ?", params![at, id]).unwrap();
    }

    pub fn delete_routine(&self, id: &str) {
        self.c().execute("DELETE FROM routines WHERE id = ?", [id]).unwrap();
    }

    // Harness policy

    pub fn global_policy(&self) -> Policy {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'policy'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| Policy::new(Mode::Ask))
    }

    pub fn set_global_policy(&self, p: &Policy) {
        self.c()
            .execute("INSERT INTO settings (key, value) VALUES ('policy', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [serde_json::to_string(p).unwrap()])
            .unwrap();
    }

    /// The onboarding wizard's progress (ADR 0034).
    pub fn setup_progress(&self) -> crate::setup::Progress {
        Self::read_setup(&self.c())
    }

    fn read_setup(c: &Connection) -> crate::setup::Progress {
        let v: Option<String> = c.query_row("SELECT value FROM settings WHERE key = 'setup'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    /// Changes the progress under one lock, so concurrent saves of different fields don't
    /// undo each other. Returns it before and after; nothing is written when `f` fails.
    pub fn update_setup_progress<E>(&self, f: impl FnOnce(&mut crate::setup::Progress) -> Result<(), E>) -> Result<(crate::setup::Progress, crate::setup::Progress), E> {
        let c = self.c();
        let before = Self::read_setup(&c);
        let mut after = before.clone();
        f(&mut after)?;
        if after != before {
            c.execute("INSERT INTO settings (key, value) VALUES ('setup', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [serde_json::to_string(&after).unwrap()])
                .unwrap();
        }
        Ok((before, after))
    }

    pub fn bot_override(&self, bot_id: &str) -> Option<Override> {
        let v: Option<String> = self.c().query_row("SELECT policy FROM bot_policies WHERE bot_id = ?", [bot_id], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok())
    }

    /// None: the Bot follows the global policy again.
    pub fn set_bot_override(&self, bot_id: &str, o: Option<&Override>) {
        let c = self.c();
        match o {
            Some(o) => c.execute(
                "INSERT INTO bot_policies (bot_id, policy, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(bot_id) DO UPDATE SET policy = ?2, updated_at = ?3",
                params![bot_id, serde_json::to_string(o).unwrap(), now()],
            ),
            None => c.execute("DELETE FROM bot_policies WHERE bot_id = ?", [bot_id]),
        }
        .unwrap();
    }

    pub fn effective_policy(&self, bot_id: &str) -> Policy {
        let global = self.global_policy();
        self.bot_override(bot_id).map(|o| o.apply(&global)).unwrap_or(global)
    }

    /// Rules for one Bot plus the global ones (`Some`), only global ones (`None`).
    pub fn rules(&self, bot_id: Option<&str>) -> Vec<Rule> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM policy_rules WHERE bot_id IS NULL OR bot_id = ?1 ORDER BY created_at").unwrap();
        s.query_map([bot_id], rule_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn rule(&self, id: &str) -> Option<Rule> {
        self.c().query_row("SELECT * FROM policy_rules WHERE id = ?", [id], rule_row).optional().ok().flatten()
    }

    pub fn add_rule(&self, bot_id: Option<&str>, action: Action, tool: &str, pattern: &str, note: Option<&str>) -> Rule {
        let id = crate::short_id();
        let action = if action == Action::Allow { "allow" } else { "deny" };
        self.c()
            .execute(
                "INSERT INTO policy_rules (id, bot_id, action, tool, pattern, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![id, bot_id, action, tool, pattern, note, now()],
            )
            .unwrap();
        self.rule(&id).unwrap()
    }

    pub fn delete_rule(&self, id: &str) {
        self.c().execute("DELETE FROM policy_rules WHERE id = ?", [id]).unwrap();
    }

    // Approvals

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_approval(&self, bot_id: &str, harness: &str, tool: &str, kind: &str, subject: &str, input: &Value, class: &str, reason: &str, expires_at: i64) -> Approval {
        self.add_approval_in_run(bot_id, harness, tool, kind, subject, input, class, reason, expires_at, None)
    }

    /// `add_approval` for a call from a live run: `run` is its id, and what approving the
    /// call for the rest of that run would cover (None: it can only be approved once).
    #[allow(clippy::too_many_arguments)]
    pub fn add_approval_in_run(
        &self,
        bot_id: &str,
        harness: &str,
        tool: &str,
        kind: &str,
        subject: &str,
        input: &Value,
        class: &str,
        reason: &str,
        expires_at: i64,
        run: Option<(&str, Option<&crate::policy::RunScope>)>,
    ) -> Approval {
        let id = crate::short_id();
        // Keep the row small: a huge file write is summarized by its subject anyway.
        let owner = self.bot_owner(bot_id);
        let owners: Vec<&str> = owner.as_deref().into_iter().collect();
        let owners = owners.as_slice();
        let mut input = redact::value_for(owners, input.clone()).to_string();
        if input.len() > 20_000 {
            input = serde_json::json!({ "truncated": input.chars().take(20_000).collect::<String>() }).to_string();
        }
        // Tool input can hold anything a Bot wrote (file contents, commands), so it is sealed at rest.
        let input = sealed::seal_field(&sealed::approval_context(&id), &input);
        let run_id = run.map(|(r, _)| r);
        let run_scope = run.and_then(|(_, s)| s).map(|s| {
            let covers: Vec<String> = s.covers_text().iter().map(|w| redact::text_for(owners, w).into_owned()).collect();
            serde_json::json!({ "covers": covers, "exact": s.exact.is_some() }).to_string()
        });
        self.c()
            .execute(
                "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at, run_id, run_scope)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
                params![id, bot_id, harness, tool, kind, redact::text_for(owners, subject), input, class, reason, now(), expires_at, run_id, run_scope],
            )
            .unwrap();
        self.approval(&id).unwrap()
    }

    pub fn approval(&self, id: &str) -> Option<Approval> {
        self.c().query_row("SELECT * FROM approvals WHERE id = ?", [id], approval_row).optional().ok().flatten()
    }

    /// Newest first. `status` filters, e.g. "pending".
    pub fn approvals(&self, status: Option<&str>, bot_id: Option<&str>, limit: i64) -> Vec<Approval> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM approvals WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR bot_id = ?2) ORDER BY created_at DESC, rowid DESC LIMIT ?3")
            .unwrap();
        s.query_map(params![status, bot_id, limit], approval_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Like `approvals`, but only for these Bots, so `limit` counts only their rows.
    pub fn approvals_among(&self, status: Option<&str>, bot_ids: &[String], limit: i64) -> Vec<Approval> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM approvals WHERE (?1 IS NULL OR status = ?1) AND bot_id IN (SELECT value FROM json_each(?2)) ORDER BY created_at DESC, rowid DESC LIMIT ?3")
            .unwrap();
        let ids = serde_json::to_string(bot_ids).unwrap();
        s.query_map(params![status, ids, limit], approval_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Closes a pending approval. False if it was already closed (first decision wins).
    pub fn finish_approval(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule_id: Option<&str>) -> bool {
        self.finish_approval_scoped(id, status, by, note, rule_id, (status == "approved").then_some("once"))
    }

    /// Approves a pending approval for the rest of its run (ADR 0051). False if it was
    /// already closed.
    pub fn finish_approval_for_run(&self, id: &str, by: &str, note: Option<&str>) -> bool {
        self.finish_approval_scoped(id, "approved", by, note, None, Some("run"))
    }

    fn finish_approval_scoped(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule_id: Option<&str>, scope: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE approvals SET status = ?, decided_by = ?, note = ?, rule_id = ?, scope = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                params![status, by, note, rule_id, scope, now(), id],
            )
            .unwrap()
            == 1
    }

    /// Closes a pending approval and saves its remembered rule in one transaction,
    /// so a decision that loses the race (to a timeout, a stop, or someone else) saves
    /// no rule. None if the approval was no longer pending.
    pub fn finish_approval_with_rule(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule: &NewRule) -> Option<Rule> {
        let rule_id = crate::short_id();
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let scope = (status == "approved").then_some("once");
        let closed = tx
            .execute(
                "UPDATE approvals SET status = ?, decided_by = ?, note = ?, rule_id = ?, scope = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                params![status, by, note, rule_id, scope, now(), id],
            )
            .ok()?;
        if closed != 1 {
            return None;
        }
        let action = if rule.action == Action::Allow { "allow" } else { "deny" };
        tx.execute(
            "INSERT INTO policy_rules (id, bot_id, action, tool, pattern, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![rule_id, rule.bot_id, action, rule.tool, rule.pattern, rule.note, now()],
        )
        .ok()?;
        tx.commit().ok()?;
        drop(c);
        self.rule(&rule_id)
    }

    // Users

    pub fn users(&self) -> Vec<User> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM users ORDER BY created_at, id").unwrap();
        s.query_map([], user_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn user(&self, id: &str) -> Option<User> {
        self.c().query_row("SELECT * FROM users WHERE id = ?", [id], user_row).optional().ok().flatten()
    }

    /// By id, or by email (case-insensitive) when `key` has an `@`.
    pub fn find_user(&self, key: &str) -> Option<User> {
        if key.contains('@') {
            self.c().query_row("SELECT * FROM users WHERE email = ?", [key], user_row).optional().ok().flatten()
        } else {
            self.user(key)
        }
    }

    /// Err when the email or id is taken, or no seat is free. The owner account never
    /// needs a seat: it is how an operator gets back in.
    pub fn create_user(&self, id: Option<&str>, email: Option<&str>, name: &str, role: Role) -> Result<User, UserError> {
        let id = id.map(String::from).unwrap_or_else(|| format!("u{}", crate::short_id()));
        let cap = if id == crate::users::OPERATOR { None } else { self.seat_cap() };
        {
            let c = self.c();
            if !Self::seat_free(&c, cap) {
                return Err(UserError::NoSeat);
            }
            Self::insert_user(&c, &id, email, name, role).map_err(|e| if constraint(&e) { UserError::EmailTaken } else { UserError::Db(e.to_string()) })?;
        }
        self.user(&id).ok_or_else(|| UserError::Db("user not saved".into()))
    }

    /// Active users holding a seat (ADR 0038): everyone but the owner account.
    pub fn active_seats(&self) -> u32 {
        Self::seats_used(&self.c())
    }

    fn seats_used(c: &Connection) -> u32 {
        c.query_row("SELECT COUNT(*) FROM users WHERE status = 'active' AND id != ?", [crate::users::OPERATOR], |r| r.get(0)).unwrap_or(0)
    }

    /// Whether one more active user fits under `cap`. Callers hold the one connection
    /// for the count and the write after it, so nothing can take the seat in between.
    fn seat_free(c: &Connection, cap: Option<u32>) -> bool {
        cap.is_none_or(|cap| Self::seats_used(c) < cap)
    }

    /// Whether making this existing user active takes a seat: they're disabled now.
    fn enabling(c: &Connection, user_id: &str) -> bool {
        c.query_row("SELECT status != 'active' AND id != ?2 FROM users WHERE id = ?1", [user_id, crate::users::OPERATOR], |r| r.get(0)).unwrap_or(false)
    }

    fn insert_user(c: &Connection, id: &str, email: Option<&str>, name: &str, role: Role) -> rusqlite::Result<usize> {
        let at = now();
        c.execute(
            "INSERT INTO users (id, email, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![id, email, name, role.as_str(), at, at],
        )
    }

    /// Re-enabling a disabled user needs a free seat, checked in the same transaction.
    pub fn update_user(&self, id: &str, p: UserPatch) -> Result<(), UserError> {
        let cap = self.seat_cap();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| UserError::Db(e.to_string()))?;
        if p.status == Some("active") && Self::enabling(&tx, id) && !Self::seat_free(&tx, cap) {
            return Err(UserError::NoSeat);
        }
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            tx.execute(&format!("UPDATE users SET {col} = ?, updated_at = ? WHERE id = ?"), params![v, now(), id]).map(|_| ())
        };
        let res = (|| {
            if let Some(v) = &p.email { set("email", v)? }
            if let Some(v) = &p.name { set("display_name", v)? }
            if let Some(v) = p.role { set("role", &v.as_str())? }
            if let Some(v) = p.status { set("status", &v)? }
            if let Some(v) = &p.tier { set("tier", v)? }
            Ok::<_, rusqlite::Error>(())
        })();
        match res {
            Ok(()) => tx.commit().map_err(|e| UserError::Db(e.to_string())),
            Err(e) if constraint(&e) => Err(UserError::EmailTaken),
            Err(e) => Err(UserError::Db(e.to_string())),
        }
    }

    // Tiers and usage (ADR 0033). Every query names the user.

    /// Tiers assigned to users, each once.
    pub fn assigned_tiers(&self) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT DISTINCT tier FROM users WHERE tier IS NOT NULL ORDER BY tier").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    pub fn owned_bot_count(&self, owner_id: &str) -> u32 {
        self.c().query_row("SELECT COUNT(*) FROM bots WHERE owner_id = ?", [owner_id], |r| r.get(0)).unwrap_or(0)
    }

    /// Runs counted for this user in `period` (`YYYY-MM`).
    pub fn runs_used(&self, user_id: &str, period: &str) -> u32 {
        self.c()
            .query_row("SELECT runs FROM usage_monthly WHERE user_id = ? AND period = ?", [user_id, period], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Counts one run for the user, unless that would pass `limit`. One statement, so
    /// runs racing for the last one can't both get it. Ok: runs used now; Err: the limit.
    pub fn take_run(&self, user_id: &str, period: &str, limit: Option<u32>) -> Result<u32, u32> {
        let c = self.c();
        let cap = limit.map_or(i64::MAX, i64::from);
        let taken = c
            .query_row(
                "INSERT INTO usage_monthly (user_id, period, runs) SELECT ?1, ?2, 1 WHERE ?3 >= 1
                 ON CONFLICT (user_id, period) DO UPDATE SET runs = runs + 1 WHERE runs < ?3
                 RETURNING runs",
                params![user_id, period, cap],
                |r| r.get::<_, u32>(0),
            )
            .optional()
            .ok()
            .flatten();
        taken.ok_or(limit.unwrap_or(0))
    }

    /// Gives back a run that was counted but didn't happen (it was refused).
    pub fn give_back_run(&self, user_id: &str, period: &str) {
        let _ = self.c().execute("UPDATE usage_monthly SET runs = runs - 1 WHERE user_id = ? AND period = ? AND runs > 0", [user_id, period]);
    }

    /// Routine runs counted for this user on `day` (`YYYY-MM-DD`).
    pub fn routine_runs_used(&self, user_id: &str, day: &str) -> u32 {
        self.c()
            .query_row("SELECT routine_runs FROM usage_daily WHERE user_id = ? AND day = ?", [user_id, day], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Counts one routine run for the user, unless that would pass `limit`, in one
    /// statement like `take_run`. Ok: routine runs used now; Err: the limit.
    pub fn take_routine_run(&self, user_id: &str, day: &str, limit: Option<u32>) -> Result<u32, u32> {
        let cap = limit.map_or(i64::MAX, i64::from);
        let taken = self
            .c()
            .query_row(
                "INSERT INTO usage_daily (user_id, day, routine_runs) SELECT ?1, ?2, 1 WHERE ?3 >= 1
                 ON CONFLICT (user_id, day) DO UPDATE SET routine_runs = routine_runs + 1 WHERE routine_runs < ?3
                 RETURNING routine_runs",
                params![user_id, day, cap],
                |r| r.get::<_, u32>(0),
            )
            .optional()
            .ok()
            .flatten();
        taken.ok_or(limit.unwrap_or(0))
    }

    /// Gives back a routine run that was counted but didn't happen.
    pub fn give_back_routine_run(&self, user_id: &str, day: &str) {
        let _ = self.c().execute("UPDATE usage_daily SET routine_runs = routine_runs - 1 WHERE user_id = ? AND day = ? AND routine_runs > 0", [user_id, day]);
    }

    /// Notes a refused routine run. True for the user's first refusal that day, so the
    /// Bot says so once a day instead of at every firing.
    /// Records one run's model tokens (ADR 0050), all rows or none.
    pub fn record_tokens(&self, rows: &[TokenRow]) -> rusqlite::Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        for r in rows {
            let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
            tx.execute(
                "INSERT INTO token_usage (user_id, bot_id, run_id, message_id, harness, model, reported,
                   input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, at, meter_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    r.user_id,
                    r.bot_id,
                    r.run_id,
                    r.message_id,
                    r.harness,
                    r.model,
                    r.reported,
                    n(r.input),
                    n(r.output),
                    n(r.cache_read),
                    n(r.cache_write),
                    r.at,
                    r.meter.then_some("pending")
                ],
            )?;
        }
        tx.commit()
    }

    /// Every model token a user's runs used in `[start, end)`, Unix ms.
    pub fn tokens_used(&self, user_id: &str, start: i64, end: i64) -> u64 {
        self.c()
            .query_row(
                "SELECT COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens), 0)
                 FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3",
                params![user_id, start, end],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| u64::try_from(n).unwrap_or(0))
    }

    /// A user's tokens in `[start, end)`, Unix ms: in all, per model, and per Bot.
    pub fn token_summary(&self, user_id: &str, start: i64, end: i64) -> TokenSummary {
        let c = self.c();
        let sums = "COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cache_read_tokens), 0),
                    COALESCE(SUM(cache_write_tokens), 0), COUNT(DISTINCT run_id), COUNT(DISTINCT CASE WHEN reported = 0 THEN run_id END)";
        let totals = |r: &rusqlite::Row, at: usize| -> rusqlite::Result<TokenTotals> {
            let n = |i: usize| r.get::<_, i64>(at + i).map(|v| u64::try_from(v).unwrap_or(0));
            Ok(TokenTotals { input: n(0)?, output: n(1)?, cache_read: n(2)?, cache_write: n(3)?, runs: n(4)?, unreported_runs: n(5)? })
        };
        let all = c
            .query_row(&format!("SELECT {sums} FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3"), params![user_id, start, end], |r| totals(r, 0))
            .unwrap_or_default();
        let grouped = |by: &str| -> Vec<(Option<String>, TokenTotals)> {
            let sql = format!("SELECT {by}, {sums} FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3 GROUP BY {by} ORDER BY {by}");
            let Ok(mut st) = c.prepare(&sql) else { return Vec::new() };
            st.query_map(params![user_id, start, end], |r| Ok((r.get::<_, Option<String>>(0)?, totals(r, 1)?)))
                .map(|rows| rows.filter_map(Result::ok).collect())
                .unwrap_or_default()
        };
        let by_model = grouped("model");
        let by_bot = grouped("bot_id").into_iter().filter_map(|(id, t)| Some((id?, t))).collect();
        TokenSummary { all, by_model, by_bot }
    }

    /// The oldest token rows waiting to go to Stripe.
    pub fn pending_meter(&self, limit: u32) -> Vec<MeterRow> {
        let c = self.c();
        let Ok(mut st) = c.prepare(
            "SELECT id, user_id, run_id, input_tokens + output_tokens + cache_read_tokens + cache_write_tokens, at, meter_attempts
             FROM token_usage WHERE meter_status = 'pending' ORDER BY id LIMIT ?1",
        ) else {
            return Vec::new();
        };
        st.query_map([limit], |r| {
            Ok(MeterRow { id: r.get(0)?, user_id: r.get(1)?, run_id: r.get(2)?, tokens: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0), at: r.get(4)?, attempts: r.get(5)? })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// Marks a token row `sent` or `failed` at Stripe, or counts one more try when None.
    pub fn meter_result(&self, id: i64, status: Option<&str>) {
        let _ = self.c().execute(
            "UPDATE token_usage SET meter_status = COALESCE(?2, meter_status), meter_attempts = meter_attempts + 1 WHERE id = ?1",
            params![id, status],
        );
    }

    pub fn routine_refused(&self, user_id: &str, day: &str) -> bool {
        self.c()
            .query_row(
                "INSERT INTO usage_daily (user_id, day, routine_refused) VALUES (?1, ?2, 1)
                 ON CONFLICT (user_id, day) DO UPDATE SET routine_refused = routine_refused + 1
                 RETURNING routine_refused",
                [user_id, day],
                |r| r.get::<_, i64>(0),
            )
            .is_ok_and(|n| n == 1)
    }

    // Billing (ADR 0040)

    /// The subscription that sets the user's tier (`paying_subscription`), else the one
    /// with the latest event, to show how it ended.
    pub fn subscription(&self, user_id: &str) -> Option<Subscription> {
        let c = self.c();
        paying_subscription(&c, user_id)
            .ok()
            .flatten()
            .or_else(|| c.query_row("SELECT * FROM subscriptions WHERE user_id = ? ORDER BY event_created DESC, started DESC LIMIT 1", [user_id], subscription_row).optional().ok().flatten())
    }

    pub fn subscription_by_id(&self, subscription_id: &str) -> Option<Subscription> {
        self.c().query_row("SELECT * FROM subscriptions WHERE subscription_id = ?", [subscription_id], subscription_row).optional().ok().flatten()
    }

    /// Applies one payment-provider event, in one transaction: records the event id (a
    /// redelivery is `Duplicate`), skips events older than the last one applied to the
    /// same subscription, or that would revive one cancelled for good (`Stale`; Stripe
    /// times events to the second, so an update can tie with the cancellation after
    /// it), and keeps the subscription's latest state. The
    /// user's tier is then that of their paying subscription started last (None, the
    /// default tier, when nothing pays); `users.tier` is set to it when this event
    /// changed which one that is, or is for that one. An event for any other
    /// subscription is `Superseded`. So the outcome doesn't depend on the order events
    /// arrive in: a late event for a replaced plan can't bring it back, and a new plan
    /// applies whenever the old one's cancellation arrives. `set_tier` false (a
    /// subscription not paid for yet) records it without changing any tier.
    ///
    /// The subscription's customer (ADR 0042) must not be another user's
    /// (`CustomerOfAnotherUser`); a user with no customer yet is linked to it, and the
    /// second value says how.
    pub fn apply_subscription(&self, event_id: &str, event_type: &str, sub: &Subscription, set_tier: bool) -> Result<(Applied, Option<Linked>), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok((Applied::Duplicate, None));
        }
        let by_id = tx.query_row("SELECT * FROM subscriptions WHERE subscription_id = ?", [&sub.subscription_id], subscription_row).optional().map_err(|e| e.to_string())?;
        let customer_user = |cus: &str| tx.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [cus], |r| r.get::<_, String>(0)).optional();
        let others_customer = match (&by_id, &sub.customer_id) {
            (Some(s), _) if s.user_id != sub.user_id => false,
            (_, Some(cus)) => customer_user(cus).map_err(|e| e.to_string())?.is_some_and(|u| u != sub.user_id),
            (_, None) => false,
        };
        let outcome = if by_id.as_ref().is_some_and(|s| s.user_id != sub.user_id) {
            Applied::OtherUser
        } else if others_customer {
            Applied::CustomerOfAnotherUser
        } else if by_id.as_ref().is_some_and(|s| {
            // Stripe never revives a subscription it cancelled for good. Its `created` is
            // in seconds, so two events can tie; an ended state wins the tie.
            let fin = |status: &str| crate::billing::FINAL.contains(&status);
            let ended = |status: &str| crate::billing::ENDED.contains(&status);
            sub.event_created < s.event_created
                || (fin(&s.status) && !fin(&sub.status))
                || (sub.event_created == s.event_created && ended(&s.status) && !ended(&sub.status))
        }) {
            Applied::Stale
        } else {
            let paying_id = |s: &Option<Subscription>| s.as_ref().map(|s| s.subscription_id.clone());
            let before = paying_subscription(&tx, &sub.user_id).map_err(|e| e.to_string())?;
            let tier = if set_tier { sub.tier.clone() } else { by_id.and_then(|s| s.tier) };
            tx.execute(
                "INSERT INTO subscriptions (subscription_id, user_id, provider, customer_id, status, price_id, tier, period_end, started, event_created, updated_at, period_start)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT (subscription_id) DO UPDATE SET provider = ?3, customer_id = ?4, status = ?5, price_id = ?6,
                   tier = ?7, period_end = ?8, event_created = ?10, updated_at = ?11, period_start = ?12",
                params![sub.subscription_id, sub.user_id, sub.provider, sub.customer_id, sub.status, sub.price_id, tier, sub.period_end, sub.started, sub.event_created, now(), sub.period_start],
            )
            .map_err(|e| e.to_string())?;
            let after = paying_subscription(&tx, &sub.user_id).map_err(|e| e.to_string())?;
            let moved = paying_id(&before) != paying_id(&after);
            let to = after.as_ref().and_then(|s| s.tier.clone());
            if after.as_ref().is_some_and(|s| s.subscription_id != sub.subscription_id) && !moved {
                Applied::Superseded
            } else if !set_tier && !moved {
                Applied::Unchanged
            } else {
                let from: Option<String> = tx.query_row("SELECT tier FROM users WHERE id = ?", [&sub.user_id], |r| r.get(0)).map_err(|e| e.to_string())?;
                if from != to {
                    tx.execute("UPDATE users SET tier = ?, updated_at = ? WHERE id = ?", params![to, now(), sub.user_id]).map_err(|e| e.to_string())?;
                    Applied::Changed { from, to }
                } else {
                    Applied::Unchanged
                }
            }
        };
        let linked = match (&outcome, &sub.customer_id) {
            (Applied::OtherUser | Applied::CustomerOfAnotherUser, _) | (_, None) => None,
            (_, Some(cus)) => Some(link_in(&tx, &sub.user_id, &sub.provider, cus, "subscription").map_err(|e| e.to_string())?),
        };
        tx.commit().map_err(|e| e.to_string())?;
        Ok((outcome, linked))
    }

    /// The user's payment-provider customer (ADR 0042).
    pub fn customer_of(&self, user_id: &str) -> Option<String> {
        self.c().query_row("SELECT customer_id FROM billing_customers WHERE user_id = ?", [user_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// The user a customer is linked to.
    pub fn customer_user(&self, customer_id: &str) -> Option<String> {
        self.c().query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// Links a customer to a user for one provider event, in one transaction with
    /// recording the event. None: the event was applied already.
    pub fn link_customer(&self, event_id: &str, event_type: &str, user_id: &str, provider: &str, customer_id: &str, via: &str) -> Result<Option<Linked>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        let linked = link_in(&tx, user_id, provider, customer_id, via).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(linked))
    }

    /// Drops a customer the provider deleted, for one provider event. `Ok(None)`: the
    /// event was applied already; `Ok(Some(None))`: no user had that customer.
    pub fn unlink_customer(&self, event_id: &str, event_type: &str, customer_id: &str) -> Result<Option<Option<String>>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        let user: Option<String> =
            tx.query_row("DELETE FROM billing_customers WHERE customer_id = ? RETURNING user_id", [customer_id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO billing_deleted_customers (customer_id, deleted_at) VALUES (?, ?)", params![customer_id, now()]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(user))
    }

    /// The user's checkout session that may still be open (`expires_at` in seconds, as Stripe has it).
    pub fn open_checkout(&self, user_id: &str) -> Option<String> {
        let at = now() / 1000;
        self.c().query_row("SELECT session_id FROM billing_checkouts WHERE user_id = ? AND expires_at > ?", params![user_id, at], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_open_checkout(&self, user_id: &str, session_id: &str, expires_at: i64) {
        let _ = self.c().execute(
            "INSERT INTO billing_checkouts (user_id, session_id, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET session_id = excluded.session_id, expires_at = excluded.expires_at",
            params![user_id, session_id, expires_at],
        );
    }

    /// Forgets the user's open checkout if it is `session_id` (closed, or paid).
    pub fn close_checkout(&self, user_id: &str, session_id: &str) {
        let _ = self.c().execute("DELETE FROM billing_checkouts WHERE user_id = ? AND session_id = ?", params![user_id, session_id]);
    }

    // SSO identities (ADR 0014)

    /// The identity with this key and its user, whatever the user's status.
    pub fn identity(&self, issuer: &str, subject: &str) -> Option<(Identity, User)> {
        let c = self.c();
        let i = c
            .query_row("SELECT * FROM user_identities WHERE issuer = ? AND subject = ?", [issuer, subject], identity_row)
            .optional()
            .ok()
            .flatten()?;
        let u = c.query_row("SELECT * FROM users WHERE id = ?", [&i.user_id], user_row).optional().ok().flatten()?;
        Some((i, u))
    }

    pub fn identities(&self, user_id: &str) -> Vec<Identity> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM user_identities WHERE user_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([user_id], identity_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every user's identities, keyed by user id, for the admin list.
    pub fn all_identities(&self) -> HashMap<String, Vec<Identity>> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM user_identities ORDER BY created_at, id").unwrap();
        let mut out: HashMap<String, Vec<Identity>> = HashMap::new();
        for i in s.query_map([], identity_row).unwrap().filter_map(Result::ok) {
            out.entry(i.user_id.clone()).or_default().push(i);
        }
        out
    }

    fn insert_identity(tx: &Connection, user_id: &str, i: &NewIdentity) -> rusqlite::Result<String> {
        let id = format!("i{}", crate::short_id());
        tx.execute(
            "INSERT INTO user_identities (id, user_id, provider, issuer, subject, tenant, email, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![id, user_id, i.provider, i.issuer, i.subject, i.tenant, i.email, now(), i.created_by],
        )?;
        // The first identity is also the user's own (users.idp_*).
        tx.execute(
            "UPDATE users SET idp_issuer = ?, idp_subject = ?, updated_at = ? WHERE id = ? AND idp_issuer IS NULL",
            params![i.issuer, i.subject, now(), user_id],
        )?;
        Ok(id)
    }

    fn identity_by_id(&self, id: &str) -> Option<Identity> {
        self.c().query_row("SELECT * FROM user_identities WHERE id = ?", [id], identity_row).optional().ok().flatten()
    }

    /// Err when the identity is linked already, to this user or another.
    pub fn link_identity(&self, user_id: &str, i: &NewIdentity) -> Result<Identity, String> {
        let id = {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
            let id = Self::insert_identity(&tx, user_id, i).map_err(|e| if constraint(&e) { "This identity is already linked to a user".to_string() } else { e.to_string() })?;
            tx.commit().map_err(|e| e.to_string())?;
            id
        };
        self.identity_by_id(&id).ok_or_else(|| "identity not saved".into())
    }

    /// Just-in-time sign-up: a new user and their first identity, together or not at all.
    pub fn create_sso_user(&self, email: Option<&str>, name: &str, role: Role, i: &NewIdentity) -> Result<User, JitError> {
        let id = format!("u{}", crate::short_id());
        let cap = self.seat_cap();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|_| JitError::Database)?;
            if !Self::seat_free(&tx, cap) {
                return Err(JitError::NoSeat);
            }
            let at = now();
            tx.execute(
                "INSERT INTO users (id, email, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                params![id, email, name, role.as_str(), at, at],
            )
            .map_err(|e| if constraint(&e) { JitError::EmailTaken } else { JitError::Database })?;
            Self::insert_identity(&tx, &id, i).map_err(|e| if constraint(&e) { JitError::IdentityTaken } else { JitError::Database })?;
            tx.commit().map_err(|_| JitError::Database)?;
        }
        self.user(&id).ok_or(JitError::Database)
    }

    /// Removes one of a user's identities. If it was the user's own, their next oldest takes its place.
    pub fn unlink_identity(&self, user_id: &str, id: &str) -> Option<Identity> {
        let gone = self.identity_by_id(id).filter(|i| i.user_id == user_id)?;
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        tx.execute("DELETE FROM user_identities WHERE id = ?", [id]).ok()?;
        tx.execute(
            "UPDATE users SET
               idp_issuer = (SELECT issuer FROM user_identities WHERE user_id = ?1 ORDER BY created_at, id LIMIT 1),
               idp_subject = (SELECT subject FROM user_identities WHERE user_id = ?1 ORDER BY created_at, id LIMIT 1),
               updated_at = ?4
             WHERE id = ?1 AND idp_issuer = ?2 AND idp_subject = ?3",
            params![user_id, gone.issuer, gone.subject, now()],
        )
        .ok()?;
        tx.commit().ok()?;
        Some(gone)
    }

    /// A sign-in with this identity: when, and the email the IdP sent this time.
    pub fn touch_identity(&self, id: &str, email: Option<&str>, at: i64) {
        let _ = self.c().execute("UPDATE user_identities SET last_login_at = ?, email = coalesce(?, email) WHERE id = ?", params![at, email, id]);
    }

    // Sessions and sign-in codes. Callers hash tokens; nothing here sees one.

    pub fn create_session(&self, s: &NewSession) -> Session {
        let id = format!("s{}", crate::random_hex(8));
        let at = now();
        {
            let c = self.c();
            c.execute(
                "INSERT INTO sessions (id, token_hash, user_id, kind, method, idp_subject, idp_provider, label, ip, user_agent, created_at, last_seen_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, s.token_hash, s.user_id, s.kind, s.method, s.idp_subject, s.idp_provider, s.label, s.ip, s.user_agent, at, at, s.expires_at],
            )
            .unwrap();
            let _ = c.execute(
                "UPDATE users SET last_login_at = ?, last_login_method = ?, last_login_idp_provider = ? WHERE id = ?",
                params![at, s.method, s.idp_provider, s.user_id],
            );
        }
        self.session(&id).unwrap()
    }

    pub fn session(&self, id: &str) -> Option<Session> {
        self.c().query_row("SELECT * FROM sessions WHERE id = ?", [id], session_row).optional().ok().flatten()
    }

    /// The live session with this token hash and its active user. None when it is
    /// unknown, revoked, expired (absolute or idle), or the user is disabled.
    pub fn live_session(&self, token_hash: &str, at: i64, idle_ms: i64, max_ms: i64) -> Option<(Session, User)> {
        let c = self.c();
        let s = c
            .query_row(
                &format!("SELECT s.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?4 AND u.status = 'active' AND {SESSION_LIVE}"),
                params![at, idle_ms, max_ms, token_hash],
                session_row,
            )
            .optional()
            .ok()
            .flatten()?;
        let u = c.query_row("SELECT * FROM users WHERE id = ?", [&s.user_id], user_row).optional().ok().flatten()?;
        Some((s, u))
    }

    pub fn session_is_live(&self, id: &str, at: i64, idle_ms: i64, max_ms: i64) -> bool {
        self.c()
            .query_row(
                &format!("SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?4 AND u.status = 'active' AND {SESSION_LIVE}"),
                params![at, idle_ms, max_ms, id],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// Records use, at most once a minute per session to keep writes down. The idle
    /// window is therefore up to a minute shorter than configured.
    pub fn touch_session(&self, id: &str, at: i64) {
        let _ = self.c().execute("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2 AND last_seen_at <= ?1 - 60000", params![at, id]);
    }

    /// Live sessions, newest first, optionally for one user.
    pub fn live_sessions(&self, user_id: Option<&str>, at: i64, idle_ms: i64, max_ms: i64) -> Vec<Session> {
        let c = self.c();
        let sql = format!("SELECT s.* FROM sessions s WHERE (?4 IS NULL OR s.user_id = ?4) AND {SESSION_LIVE} ORDER BY s.created_at DESC, s.id LIMIT 1000");
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(params![at, idle_ms, max_ms, user_id], session_row).unwrap().filter_map(Result::ok).collect()
    }

    /// False if it was already revoked or doesn't exist.
    /// Its push device goes with it (ADR 0080), whatever ended it.
    pub fn revoke_session(&self, id: &str, by: &str, reason: &str) -> bool {
        let c = self.c();
        let _ = c.execute("DELETE FROM push_devices WHERE session_id = ?", [id]);
        c.execute("UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL", params![now(), by, reason, id])
            .unwrap_or(0)
            == 1
    }

    /// Revokes every session of a user and drops their unused sign-in codes and push
    /// devices. Returns how many sessions.
    pub fn revoke_user_sessions(&self, user_id: &str, by: &str, reason: &str) -> usize {
        let c = self.c();
        let _ = c.execute("DELETE FROM push_devices WHERE user_id = ?", [user_id]);
        let n = c
            .execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL",
                params![now(), by, reason, user_id],
            )
            .unwrap_or(0);
        let _ = c.execute("DELETE FROM login_codes WHERE user_id = ? AND used_at IS NULL", [user_id]);
        n
    }

    pub fn add_login_code(&self, code_hash: &str, user_id: &str, created_by: &str, expires_at: i64) {
        self.c()
            .execute(
                "INSERT INTO login_codes (code_hash, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                params![code_hash, user_id, created_by, now(), expires_at],
            )
            .unwrap();
    }

    /// Adds a sign-in code in place of the user's unused ones, in one transaction so two
    /// admins replacing at once leave one working code. Returns how many it replaced.
    pub fn replace_login_codes(&self, code_hash: &str, user_id: &str, created_by: &str, expires_at: i64) -> usize {
        let mut c = self.c();
        let tx = c.transaction().unwrap();
        let n = tx.execute("DELETE FROM login_codes WHERE user_id = ? AND used_at IS NULL", [user_id]).unwrap();
        tx.execute(
            "INSERT INTO login_codes (code_hash, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![code_hash, user_id, created_by, now(), expires_at],
        )
        .unwrap();
        tx.commit().unwrap();
        n
    }

    /// Unused, unexpired codes per user: how many, and when the last of them expires.
    pub fn pending_codes(&self, at: i64) -> HashMap<String, (i64, i64)> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT user_id, count(*), max(expires_at) FROM login_codes WHERE used_at IS NULL AND ? < expires_at GROUP BY user_id")
            .unwrap();
        s.query_map([at], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?)))).unwrap().filter_map(Result::ok).collect()
    }

    // Sign-ups (ADR 0022)

    /// Saves a request for access, unless `max_pending` are pending already (one
    /// statement, so concurrent requests can't pass the cap together).
    pub fn add_signup(&self, s: &NewSignup, max_pending: i64) -> Result<Signup, AddSignup> {
        let id = format!("su{}", crate::short_id());
        let at = now();
        let res = self.c().execute(
            "INSERT INTO signups (id, name, email, company, team_size, use_case, sign_in, consent_at, ip, user_agent, created_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?8
             WHERE (SELECT count(*) FROM signups WHERE status = 'pending') < ?11",
            params![id, s.name, s.email, s.company, s.team_size, s.use_case, s.sign_in, at, s.ip, s.user_agent, max_pending],
        );
        match res {
            Ok(0) => Err(AddSignup::Full),
            Ok(_) => self.signup(&id).ok_or(AddSignup::Full),
            Err(e) if constraint(&e) => Err(AddSignup::Duplicate),
            Err(e) => panic!("save signup: {e}"),
        }
    }

    pub fn signup(&self, id: &str) -> Option<Signup> {
        self.c().query_row("SELECT * FROM signups WHERE id = ?", [id], signup_row).optional().ok().flatten()
    }

    /// Newest first. `status` None: all of them.
    pub fn signups(&self, status: Option<&str>, limit: u32) -> Vec<Signup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM signups WHERE ?1 IS NULL OR status = ?1 ORDER BY created_at DESC, id LIMIT ?2").unwrap();
        s.query_map(params![status, limit], signup_row).unwrap().filter_map(Result::ok).collect()
    }

    #[cfg(test)]
    pub fn pending_signups(&self) -> i64 {
        self.c().query_row("SELECT count(*) FROM signups WHERE status = 'pending'", [], |r| r.get(0)).unwrap_or(0)
    }

    /// Approves a pending request: its user is made in the same transaction, so a
    /// request is never approved without one, nor a user made for a closed request.
    pub fn approve_signup(&self, id: &str, role: Role, by: &str) -> Result<(Signup, User), SignupError> {
        let cap = self.seat_cap();
        let user_id = {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|e| SignupError::Db(e.to_string()))?;
            let s = tx.query_row("SELECT * FROM signups WHERE id = ?", [id], signup_row).optional().map_err(|e| SignupError::Db(e.to_string()))?;
            let s = s.ok_or(SignupError::NotFound)?;
            if s.status != "pending" {
                return Err(SignupError::Closed(s.status));
            }
            if !Self::seat_free(&tx, cap) {
                return Err(SignupError::NoSeat);
            }
            let user_id = format!("u{}", crate::short_id());
            Self::insert_user(&tx, &user_id, Some(&s.email), &s.name, role).map_err(|e| if constraint(&e) { SignupError::EmailTaken } else { SignupError::Db(e.to_string()) })?;
            tx.execute(
                "UPDATE signups SET status = 'approved', decided_at = ?, decided_by = ?, user_id = ?, role = ? WHERE id = ? AND status = 'pending'",
                params![now(), by, user_id, role.as_str(), id],
            )
            .map_err(|e| SignupError::Db(e.to_string()))?;
            tx.commit().map_err(|e| SignupError::Db(e.to_string()))?;
            user_id
        };
        Ok((self.signup(id).ok_or(SignupError::NotFound)?, self.user(&user_id).ok_or(SignupError::NotFound)?))
    }

    pub fn reject_signup(&self, id: &str, by: &str, reason: Option<&str>) -> Result<Signup, SignupError> {
        let s = self.signup(id).ok_or(SignupError::NotFound)?;
        let n = self
            .c()
            .execute(
                "UPDATE signups SET status = 'rejected', decided_at = ?, decided_by = ?, reason = ? WHERE id = ? AND status = 'pending'",
                params![now(), by, reason, id],
            )
            .map_err(|e| SignupError::Db(e.to_string()))?;
        if n != 1 {
            return Err(SignupError::Closed(s.status));
        }
        self.signup(id).ok_or(SignupError::NotFound)
    }

    // SCIM (ADR 0023). Callers hash tokens; nothing here sees one.

    /// A tenant's first token sets its SSO provider for good: a token naming another gets
    /// `Err` with the tenant's provider. Checked and written in one transaction.
    pub fn create_scim_token(&self, tenant: &str, label: Option<&str>, sso_provider: Option<&str>, token_hash: &str, by: Option<&str>) -> Result<ScimToken, Option<String>> {
        let id = format!("st{}", crate::random_hex(4));
        let c = self.c();
        let tx = c.unchecked_transaction().unwrap();
        let first: Option<Option<String>> =
            tx.query_row("SELECT sso_provider FROM scim_tokens WHERE tenant = ? ORDER BY created_at, id LIMIT 1", [tenant], |r| r.get(0)).optional().unwrap();
        if let Some(first) = first
            && first.as_deref() != sso_provider
        {
            return Err(first);
        }
        tx.execute(
            "INSERT INTO scim_tokens (id, tenant, label, sso_provider, token_hash, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, tenant, label, sso_provider, token_hash, now(), by],
        )
        .unwrap();
        let t = tx.query_row("SELECT * FROM scim_tokens WHERE id = ?", [&id], scim_token_row).unwrap();
        tx.commit().unwrap();
        Ok(t)
    }

    pub fn scim_token(&self, id: &str) -> Option<ScimToken> {
        self.c().query_row("SELECT * FROM scim_tokens WHERE id = ?", [id], scim_token_row).optional().ok().flatten()
    }

    /// Newest first, revoked ones too.
    pub fn scim_tokens(&self) -> Vec<ScimToken> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_tokens ORDER BY created_at DESC, id").unwrap();
        s.query_map([], scim_token_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The unrevoked token with this hash. Records use, at most once a minute.
    pub fn live_scim_token(&self, token_hash: &str, at: i64) -> Option<ScimToken> {
        let t = self.c().query_row("SELECT * FROM scim_tokens WHERE token_hash = ? AND revoked_at IS NULL", [token_hash], scim_token_row).optional().ok().flatten()?;
        let _ = self.c().execute("UPDATE scim_tokens SET last_used_at = ?1 WHERE id = ?2 AND coalesce(last_used_at, 0) <= ?1 - 60000", params![at, t.id]);
        Some(t)
    }

    /// The token with this hash, revoked or not: a revoked token still in use is worth an alert.
    pub fn scim_token_by_hash(&self, token_hash: &str) -> Option<ScimToken> {
        self.c().query_row("SELECT * FROM scim_tokens WHERE token_hash = ?", [token_hash], scim_token_row).optional().ok().flatten()
    }

    /// False if it was already revoked or doesn't exist.
    pub fn revoke_scim_token(&self, id: &str, by: &str) -> bool {
        self.c().execute("UPDATE scim_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL", params![now(), by, id]).unwrap_or(0) == 1
    }

    /// Which tenant manages a user, if any, deleted or not.
    pub fn scim_user_of(&self, user_id: &str) -> Option<ScimUser> {
        self.c().query_row(&format!("{SCIM_USER_SELECT} WHERE l.user_id = ?"), [user_id], scim_user_row).optional().ok().flatten()
    }

    /// A user the tenant manages and hasn't deleted.
    pub fn scim_user(&self, tenant: &str, user_id: &str) -> Option<ScimUser> {
        self.c()
            .query_row(&format!("{SCIM_USER_SELECT} WHERE l.tenant = ? AND l.user_id = ? AND l.deleted_at IS NULL"), [tenant, user_id], scim_user_row)
            .optional()
            .ok()
            .flatten()
    }

    /// By `externalId`, deleted users included (re-provisioning finds them); by `userName`, live ones only.
    pub fn scim_find(&self, tenant: &str, key: &ScimKey) -> Option<ScimUser> {
        let (clause, v) = match key {
            ScimKey::ExternalId(v) => ("l.external_id = ?2", v),
            ScimKey::UserName(v) => ("l.user_name = ?2 AND l.deleted_at IS NULL", v),
        };
        self.c().query_row(&format!("{SCIM_USER_SELECT} WHERE l.tenant = ?1 AND {clause}"), params![tenant, v], scim_user_row).optional().ok().flatten()
    }

    /// A page of the tenant's live users, oldest first, and how many match in all.
    pub fn scim_list(&self, tenant: &str, key: Option<&ScimKey>, offset: i64, limit: i64) -> (i64, Vec<ScimUser>) {
        let (col, v) = match key {
            None => ("l.user_name", None),
            Some(ScimKey::UserName(v)) => ("l.user_name", Some(v)),
            Some(ScimKey::ExternalId(v)) => ("l.external_id", Some(v)),
        };
        let c = self.c();
        let filter = format!("WHERE l.tenant = ?1 AND l.deleted_at IS NULL AND (?2 IS NULL OR {col} = ?2)");
        let total: i64 = c.query_row(&format!("SELECT count(*) FROM scim_users l {filter}"), params![tenant, v], |r| r.get(0)).unwrap_or(0);
        let mut s = c.prepare(&format!("{SCIM_USER_SELECT} {filter} ORDER BY l.created_at, l.user_id LIMIT ?3 OFFSET ?4")).unwrap();
        let list = s.query_map(params![tenant, v, limit, offset], scim_user_row).unwrap().filter_map(Result::ok).collect();
        (total, list)
    }

    /// Turning a disabled user back on takes a seat under `cap`, checked here, in the write's transaction.
    fn write_scim_user(tx: &Connection, tenant: &str, user_id: &str, f: &ScimFields, at: i64, cap: Option<u32>) -> Result<(), ScimConflict> {
        if f.active == Some(true) && Self::enabling(tx, user_id) && !Self::seat_free(tx, cap) {
            return Err(ScimConflict::NoSeat);
        }
        Self::write_scim_rows(tx, tenant, user_id, f, at).map_err(scim_conflict)
    }

    fn write_scim_rows(tx: &Connection, tenant: &str, user_id: &str, f: &ScimFields, at: i64) -> rusqlite::Result<()> {
        tx.execute(
            "UPDATE users SET email = ?, display_name = ?, status = coalesce(?, status), updated_at = ? WHERE id = ?",
            params![f.email, f.display_name, f.active.map(|on| if on { "active" } else { "disabled" }), at, user_id],
        )?;
        tx.execute(
            "INSERT INTO scim_users (user_id, tenant, external_id, user_name, given_name, family_name, display_name, formatted, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT (user_id) DO UPDATE SET external_id = ?3, user_name = ?4, given_name = ?5, family_name = ?6, display_name = ?7, formatted = ?8,
               updated_at = ?9, deleted_at = NULL",
            params![user_id, tenant, f.external_id, f.user_name, f.given_name, f.family_name, f.scim_display_name, f.formatted, at],
        )?;
        Ok(())
    }

    /// A new user made by a SCIM tenant, with its SSO identity when the tenant links one.
    /// All of it or none.
    pub fn create_scim_user(&self, tenant: &str, f: &ScimFields, role: Role, identity: Option<&NewIdentity>) -> Result<User, ScimConflict> {
        let id = format!("u{}", crate::short_id());
        let cap = self.seat_cap();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(scim_conflict)?;
            // A user provisioned inactive takes no seat until they're turned on.
            if f.active != Some(false) && !Self::seat_free(&tx, cap) {
                return Err(ScimConflict::NoSeat);
            }
            Self::insert_user(&tx, &id, f.email, f.display_name, role).map_err(scim_conflict)?;
            Self::write_scim_user(&tx, tenant, &id, f, now(), None)?;
            if let Some(i) = identity {
                Self::insert_identity(&tx, &id, i).map_err(scim_conflict)?;
            }
            tx.commit().map_err(scim_conflict)?;
        }
        self.user(&id).ok_or_else(|| ScimConflict::Db("user not saved".into()))
    }

    /// Sets what SCIM manages on an existing user. An update (`restore` false) needs the
    /// tenant's live user; `restore` also takes a user the tenant deleted, or one no tenant
    /// manages. Never another tenant's: checked in the same transaction as the write.
    pub fn save_scim_user(&self, tenant: &str, user_id: &str, f: &ScimFields, restore: bool) -> Result<(), ScimConflict> {
        let cap = self.seat_cap();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_conflict)?;
        let row: Option<(String, Option<i64>)> =
            tx.query_row("SELECT tenant, deleted_at FROM scim_users WHERE user_id = ?", [user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(scim_conflict)?;
        match row {
            Some((t, _)) if t != tenant => return Err(ScimConflict::OtherTenant),
            Some((_, None)) => {}
            _ if !restore => return Err(ScimConflict::Gone),
            _ => {}
        }
        Self::write_scim_user(&tx, tenant, user_id, f, now(), cap)?;
        tx.commit().map_err(scim_conflict)
    }

    /// A SCIM DELETE: the user is disabled and hidden from the tenant, never removed.
    pub fn delete_scim_user(&self, tenant: &str, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let n = tx.execute("UPDATE scim_users SET deleted_at = ?, updated_at = ? WHERE tenant = ? AND user_id = ? AND deleted_at IS NULL", params![at, at, tenant, user_id]).unwrap_or(0);
        let ok = n == 1 && tx.execute("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?", params![at, user_id]).is_ok();
        ok && tx.commit().is_ok()
    }

    /// Spends a sign-in code: once, before it expires, for an active user. Returns the user.
    pub fn use_login_code(&self, code_hash: &str, at: i64) -> Option<User> {
        let c = self.c();
        let user_id: String = c
            .query_row(
                "UPDATE login_codes SET used_at = ?1 WHERE code_hash = ?2 AND used_at IS NULL AND ?1 < expires_at
                   AND user_id IN (SELECT id FROM users WHERE status = 'active')
                 RETURNING user_id",
                params![at, code_hash],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        c.query_row("SELECT * FROM users WHERE id = ?", [user_id], user_row).optional().ok().flatten()
    }

    // Push devices (ADR 0080). Tokens are sealed; the hash keeps each on one session.

    /// Registers `token` for this session, in place of any it had. A token another
    /// session held moves here, so that session (and its person) stops getting it.
    #[allow(clippy::too_many_arguments)]
    pub fn put_push_device(&self, user_id: &str, session_id: &str, provider: &str, token: &str, platform: &str, approvals: bool, routines: bool) -> (PushDevice, PushPut) {
        let token_hash = crate::users::hash(token);
        let at = now();
        let mut c = self.c();
        let tx = c.transaction().unwrap();
        let mine = tx.query_row("SELECT * FROM push_devices WHERE session_id = ?", [session_id], push_device_row).optional().unwrap().flatten();
        let theirs: Option<String> =
            tx.query_row("SELECT session_id FROM push_devices WHERE token_hash = ? AND session_id <> ?", params![token_hash, session_id], |r| r.get(0)).optional().unwrap();
        let change = match &mine {
            Some(d) if d.token == token && d.provider == provider && d.platform == platform => {
                if (d.approvals, d.routines) == (approvals, routines) { PushPut::Unchanged } else { PushPut::Updated }
            }
            _ if theirs.is_some() => PushPut::Moved,
            _ => PushPut::Added,
        };
        tx.execute("DELETE FROM push_devices WHERE token_hash = ? AND session_id <> ?", params![token_hash, session_id]).unwrap();
        let id = mine.as_ref().map_or_else(|| format!("pd{}", crate::random_hex(8)), |d| d.id.clone());
        let created = mine.as_ref().map_or(at, |d| d.created_at);
        tx.execute(
            "INSERT INTO push_devices (id, user_id, session_id, provider, token_hash, token, platform, approvals, routines, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session_id) DO UPDATE SET provider = ?4, token_hash = ?5, token = ?6, platform = ?7, approvals = ?8, routines = ?9, updated_at = ?11",
            params![id, user_id, session_id, provider, token_hash, sealed::seal_field(PUSH_TOKEN_CONTEXT, token), platform, approvals, routines, created, at],
        )
        .unwrap();
        tx.execute(
            "DELETE FROM push_devices WHERE user_id = ?1 AND id NOT IN (SELECT id FROM push_devices WHERE user_id = ?1 ORDER BY updated_at DESC, id LIMIT ?2)",
            params![user_id, MAX_PUSH_DEVICES as i64],
        )
        .unwrap();
        let d = tx.query_row("SELECT * FROM push_devices WHERE id = ?", [&id], push_device_row).unwrap().expect("just sealed");
        tx.commit().unwrap();
        (d, change)
    }

    pub fn session_push_device(&self, session_id: &str) -> Option<PushDevice> {
        self.c().query_row("SELECT * FROM push_devices WHERE session_id = ?", [session_id], push_device_row).optional().ok().flatten().flatten()
    }

    /// The device this session registered, removed. None: it had none.
    pub fn delete_session_push_device(&self, session_id: &str) -> Option<PushDevice> {
        let d = self.session_push_device(session_id)?;
        (self.c().execute("DELETE FROM push_devices WHERE id = ?", [&d.id]).unwrap_or(0) == 1).then_some(d)
    }

    /// Removes devices the provider says are gone. Returns how many.
    pub fn delete_push_devices(&self, ids: &[String]) -> usize {
        let c = self.c();
        ids.iter().map(|id| c.execute("DELETE FROM push_devices WHERE id = ?", [id]).unwrap_or(0)).sum()
    }

    /// `user_id`'s devices that want `kind`, while the session that registered each is
    /// still live and theirs, and they are active. Binds the session lifetimes as
    /// `live_session` does, so an idle or expired session's phone gets nothing.
    pub fn live_push_devices(&self, user_id: &str, kind: PushKind, at: i64, idle_ms: i64, max_ms: i64) -> Vec<PushDevice> {
        let want = match kind {
            PushKind::Approvals => "d.approvals = 1",
            PushKind::Routines => "d.routines = 1",
        };
        let sql = format!(
            "SELECT d.* FROM push_devices d JOIN sessions s ON s.id = d.session_id JOIN users u ON u.id = d.user_id
             WHERE d.user_id = ?4 AND s.user_id = d.user_id AND u.status = 'active' AND {want} AND {SESSION_LIVE} ORDER BY d.created_at, d.id"
        );
        let c = self.c();
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(params![at, idle_ms, max_ms, user_id], push_device_row).unwrap().filter_map(|r| r.ok().flatten()).collect()
    }

    /// Deletes sessions and codes that stopped working before `before` (unix ms).
    pub fn prune_sessions(&self, before: i64, idle_ms: i64, max_ms: i64) -> usize {
        let c = self.c();
        let n = c
            .execute(
                "DELETE FROM sessions WHERE coalesce(revoked_at, min(expires_at, created_at + ?2, last_seen_at + ?3)) < ?1",
                params![before, max_ms, idle_ms],
            )
            .unwrap_or(0);
        let _ = c.execute("DELETE FROM login_codes WHERE coalesce(used_at, expires_at) < ?", [before]);
        n
    }

    // Audit: append-only. There is no update or delete here; triggers refuse both,
    // except retention pruning of rows older than `audit_retention_days`.

    /// Writes one event. `details` is scrubbed of secrets; free text (names, the user
    /// agent) is masked the same way; everything is clipped.
    pub fn record(&self, e: &audit::Event) {
        let o = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(s, max));
        let a = &e.actor;
        let bot_actor = matches!(a.kind, audit::ActorKind::Bot).then_some(a.id.as_deref()).flatten();
        let owners: Vec<String> = [e.bot_id.as_deref(), bot_actor].into_iter().flatten().filter_map(|b| self.bot_owner(b)).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        let text = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(&redact::text_for(&owners, &audit::redact_text(s)), max));
        let details = redact::value_for(&owners, audit::scrub(e.details.clone())).to_string();
        let res = self.c().execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, actor_name, actor_subject, action, target_type, target_id, bot_id, outcome, ip, user_agent, details,
               actor_email, actor_role, auth_method, idp, idp_provider, session_id, on_behalf_of)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                now(),
                a.kind.as_str(),
                o(&a.id, 128),
                text(&a.name, 128),
                o(&a.subject, 256),
                audit::clip(&e.action, 64),
                o(&e.target_type, 32),
                o(&e.target_id, 128),
                o(&e.bot_id, 128),
                e.outcome.as_str(),
                o(&e.source.ip, 64),
                text(&e.source.user_agent, 256),
                details,
                text(&a.email, 254),
                o(&a.role, 16),
                o(&a.method, 32),
                o(&a.idp, 32),
                o(&a.idp_provider, 64),
                o(&a.session, 64),
                o(&a.on_behalf_of, 128),
            ],
        );
        if let Err(err) = res {
            eprintln!("audit: could not record {}: {err}", e.action);
        }
    }

    /// Newest first (or oldest first with `oldest_first`), filtered, at most `limit`.
    pub fn audit_events(&self, f: &audit::Filter, limit: i64, oldest_first: bool) -> Vec<AuditEvent> {
        use rusqlite::types::Value as V;
        let mut sql = String::from("SELECT * FROM audit_events WHERE 1 = 1");
        let mut args: Vec<V> = Vec::new();
        let mut and = |clause: &str, v: Vec<V>| {
            sql.push_str(" AND ");
            sql.push_str(clause);
            args.extend(v);
        };
        if let Some(t) = f.from {
            and("at >= ?", vec![V::Integer(t)]);
        }
        if let Some(t) = f.to {
            and("at < ?", vec![V::Integer(t)]);
        }
        if !f.actions.is_empty() {
            let mut parts = Vec::new();
            let mut vals = Vec::new();
            for a in &f.actions {
                match a.strip_suffix('*') {
                    Some(prefix) => {
                        parts.push("substr(action, 1, ?) = ?");
                        vals.extend([V::Integer(prefix.len() as i64), V::Text(prefix.into())]);
                    }
                    None => {
                        parts.push("action = ?");
                        vals.push(V::Text(a.clone()));
                    }
                }
            }
            and(&format!("({})", parts.join(" OR ")), vals);
        }
        let exact = [
            ("actor_kind", &f.actor_kind),
            ("actor_id", &f.actor_id),
            ("idp", &f.idp),
            ("idp_provider", &f.idp_provider),
            ("actor_subject", &f.subject),
            ("session_id", &f.session_id),
            ("on_behalf_of", &f.on_behalf_of),
            ("outcome", &f.outcome),
            ("bot_id", &f.bot_id),
            ("target_type", &f.target_type),
            ("target_id", &f.target_id),
        ];
        for (col, v) in exact {
            if let Some(v) = v {
                and(&format!("{col} = ?"), vec![V::Text(v.clone())]);
            }
        }
        if let Some(e) = &f.actor_email {
            and("actor_email = ? COLLATE NOCASE", vec![V::Text(e.clone())]);
        }
        if !f.methods.is_empty() {
            let marks = vec!["?"; f.methods.len()].join(", ");
            and(&format!("auth_method IN ({marks})"), f.methods.iter().map(|m| V::Text(m.clone())).collect());
        }
        if let Some(id) = f.before {
            and("id < ?", vec![V::Integer(id)]);
        }
        if let Some(id) = f.after {
            and("id > ?", vec![V::Integer(id)]);
        }
        sql.push_str(if oldest_first { " ORDER BY id ASC LIMIT ?" } else { " ORDER BY id DESC LIMIT ?" });
        args.push(V::Integer(limit));
        let c = self.c();
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(rusqlite::params_from_iter(args), audit_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Whether per-user accounts were on, with their copies in order, when last saved (ADR 0037).
    pub fn isolation_was_on(&self) -> bool {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'isolation'", [], |r| r.get(0)).optional().ok().flatten();
        v.as_deref() == Some("users")
    }

    pub fn save_isolation(&self, on: bool) {
        let now = if on { "users" } else { "off" };
        self.c().execute("INSERT INTO settings (key, value) VALUES ('isolation', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [now]).unwrap();
    }

    /// Days of audit history to keep. None = forever.
    pub fn audit_retention(&self) -> Option<u32> {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'audit_retention_days'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| s.parse().ok()).filter(|d| *d > 0)
    }

    pub fn set_audit_retention(&self, days: Option<u32>) {
        let c = self.c();
        match days {
            Some(d) => c.execute(
                "INSERT INTO settings (key, value) VALUES ('audit_retention_days', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
                [d.to_string()],
            ),
            None => c.execute("DELETE FROM settings WHERE key = 'audit_retention_days'", []),
        }
        .unwrap();
    }

    /// Deletes events older than `cutoff` (unix ms). The trigger refuses any row
    /// still inside the saved retention window.
    /// Deletes events older than the saved retention window.
    pub fn prune_audit(&self) -> rusqlite::Result<usize> {
        self.c().execute(&format!("DELETE FROM audit_events WHERE at < {AUDIT_CUTOFF}"), [])
    }

    // Machines (ADR 0025)

    /// A new `pending` machine for the user, unless they have a live one already.
    pub fn add_machine(&self, n: &NewMachine) -> Result<Machine, AddMachine> {
        let id = format!("m{}", crate::short_id());
        let at = now();
        let res = self.c().execute(
            "INSERT INTO machines (id, user_id, provider, label, tag, tier, plan, region, state, created_at, created_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?9)",
            params![id, n.user_id, n.provider, format!("{}-{id}", n.label_prefix), n.label_prefix, n.tier, n.plan, n.region, at, n.created_by],
        );
        match res {
            Ok(_) => self.machine(&id).ok_or_else(|| AddMachine::Db("the new machine wasn't saved".into())),
            Err(e) if constraint(&e) => self.user_machine(n.user_id).map_or_else(|| Err(AddMachine::Db(e.to_string())), |m| Err(AddMachine::Exists(Box::new(m)))),
            Err(e) => Err(AddMachine::Db(e.to_string())),
        }
    }

    pub fn machine(&self, id: &str) -> Option<Machine> {
        self.c().query_row("SELECT * FROM machines WHERE id = ?", [id], machine_row).optional().ok().flatten()
    }

    /// The user's machine that isn't destroyed, if any.
    pub fn user_machine(&self, user_id: &str) -> Option<Machine> {
        self.c().query_row("SELECT * FROM machines WHERE user_id = ? AND state <> 'destroyed'", [user_id], machine_row).optional().ok().flatten()
    }

    /// Newest first. `state` None: every one, destroyed too.
    pub fn machines(&self, state: Option<MachineState>) -> Vec<Machine> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machines WHERE ?1 IS NULL OR state = ?1 ORDER BY created_at DESC, id").unwrap();
        s.query_map([state.map(MachineState::as_str)], machine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Writes `m` back if the stored machine is still in state `from`, so two changes
    /// can't both win. The user and label never change. Returns whether it was saved.
    pub fn save_machine(&self, m: &Machine, from: MachineState) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET provider_id = ?, tier = ?, plan = ?, region = ?, state = ?, provider_status = ?, ipv4 = ?, backups = ?,
                 last_error = ?, create_sent_at = ?, updated_at = ?, destroyed_at = ?, firewall_id = ? WHERE id = ? AND state = ?",
                params![
                    m.provider_id,
                    m.tier,
                    m.plan,
                    m.region,
                    m.state.as_str(),
                    m.provider_status,
                    m.ipv4,
                    m.backups,
                    m.last_error,
                    m.create_sent_at,
                    now(),
                    m.destroyed_at,
                    m.firewall_id,
                    m.id,
                    from.as_str()
                ],
            )
            .unwrap()
            == 1
    }

    // Machine enrollment (ADR 0031)

    /// Saves a token's hash. The machine must enroll by `enroll_by` (ADR 0035); a new
    /// token starts that clock again and clears an earlier overdue mark.
    pub fn add_machine_token(
        &self,
        machine_id: &str,
        token_hash: &str,
        expires_at: i64,
        created_by: Option<&str>,
        enroll_by: i64,
    ) -> rusqlite::Result<()> {
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO machine_tokens (machine_id, token_hash, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![machine_id, token_hash, now(), created_by, expires_at],
        )?;
        tx.execute(
            "UPDATE machines SET enroll_by = ?, enroll_overdue_at = NULL WHERE id = ?",
            params![enroll_by, machine_id],
        )?;
        tx.commit()
    }

    /// Puts back the enrollment deadline and overdue mark a token replaced, when the
    /// machine it was for never got it (a restore that failed before the swap).
    pub fn restore_enroll_by(&self, machine_id: &str, enroll_by: Option<i64>, overdue_at: Option<i64>) {
        let _ = self.c().execute(
            "UPDATE machines SET enroll_by = ?, enroll_overdue_at = ? WHERE id = ?",
            params![enroll_by, overdue_at, machine_id],
        );
    }

    /// Marks the machine overdue if it had to enroll by now and hasn't (ADR 0035).
    /// Returns whether this call marked it, so it is reported once.
    pub fn mark_enroll_overdue(&self, machine_id: &str) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE machines SET enroll_overdue_at = ?1 WHERE id = ?2 AND enroll_overdue_at IS NULL
                 AND enroll_by IS NOT NULL AND enroll_by <= ?1 AND enrollment IN ('none', 'revoked')",
                params![at, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records that the machine is behind firewall `firewall_id` at the provider.
    pub fn set_machine_firewall(&self, machine_id: &str, firewall_id: &str) {
        let _ = self.c().execute("UPDATE machines SET firewall_id = ? WHERE id = ?", params![firewall_id, machine_id]);
    }

    /// How many machines other than `except` that aren't destroyed use the firewall.
    pub fn machines_on_firewall(&self, firewall_id: &str, except: &str) -> usize {
        self.c()
            .query_row(
                "SELECT COUNT(*) FROM machines WHERE firewall_id = ? AND id <> ? AND state <> 'destroyed'",
                params![firewall_id, except],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| n as usize)
    }

    /// A token by its hash, used or not.
    pub fn machine_token(&self, token_hash: &str) -> Option<MachineToken> {
        self.c()
            .query_row("SELECT id, machine_id, expires_at, used_at, revoked_at FROM machine_tokens WHERE token_hash = ?", [token_hash], |r| {
                Ok(MachineToken { id: r.get(0)?, machine_id: r.get(1)?, expires_at: r.get(2)?, used_at: r.get(3)?, revoked_at: r.get(4)? })
            })
            .optional()
            .ok()
            .flatten()
    }

    /// Unused tokens for the machine can't be used any more. Returns how many.
    pub fn revoke_machine_tokens(&self, machine_id: &str) -> usize {
        self.c()
            .execute("UPDATE machine_tokens SET revoked_at = ? WHERE machine_id = ? AND used_at IS NULL AND revoked_at IS NULL", params![now(), machine_id])
            .unwrap_or(0)
    }

    /// Uses token `token_id` for `machine_id` and records `cert` as the machine's one
    /// active certificate, all at once. The token must be unused, unrevoked, and
    /// unexpired at this moment, so two enrollments with it can't both win. Every other
    /// unused token for the machine is revoked, and its earlier certificates too
    /// (`replaced`). Returns those certificates' fingerprints, or None if the token
    /// couldn't be used.
    pub fn enroll_machine(
        &self,
        token_id: i64,
        machine_id: &str,
        user_id: &str,
        cert: &crate::machines::pki::Issued,
    ) -> Option<Vec<String>> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let at = now();
        let used = tx
            .execute(
                "UPDATE machine_tokens SET used_at = ?1 WHERE id = ?2 AND machine_id = ?3 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
                params![at, token_id, machine_id],
            )
            .ok()?;
        if used != 1 {
            return None;
        }
        tx.execute("UPDATE machine_tokens SET revoked_at = ?1 WHERE machine_id = ?2 AND used_at IS NULL AND revoked_at IS NULL", params![at, machine_id]).ok()?;
        let replaced = revoke_where(&tx, machine_id, "1", "replaced").ok()?;
        tx.execute(
            "INSERT INTO machine_certs (fingerprint, serial, machine_id, user_id, status, issued_for, issued_at, not_before, not_after)
             VALUES (?, ?, ?, ?, 'active', 'enrolled', ?, ?, ?)",
            params![cert.fingerprint, cert.serial, machine_id, user_id, at, cert.not_before, cert.not_after],
        )
        .ok()?;
        tx.execute(
            "UPDATE machines SET enrolled_at = ?, enroll_by = NULL, enroll_overdue_at = NULL WHERE id = ?",
            params![at, machine_id],
        )
        .ok()?;
        refresh_enrollment(&tx, machine_id).ok()?;
        tx.commit().ok()?;
        Some(replaced)
    }

    pub fn machine_cert(&self, fingerprint: &str) -> Option<MachineCert> {
        self.c()
            .query_row(
                "SELECT * FROM machine_certs WHERE fingerprint = ?",
                [fingerprint],
                machine_cert_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Every certificate the machine was issued, newest first.
    pub fn machine_certs(&self, machine_id: &str) -> Vec<MachineCert> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM machine_certs WHERE machine_id = ? ORDER BY id DESC")
            .unwrap();
        s.query_map([machine_id], machine_cert_row)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    }

    /// Fingerprints of the machine's usable certificates: the only ones botd accepts
    /// from it when calling it.
    pub fn machine_pins(&self, machine_id: &str) -> Vec<String> {
        let at = now();
        self.machine_certs(machine_id)
            .into_iter()
            .filter(|c| c.usable(at))
            .map(|c| c.fingerprint)
            .collect()
    }

    /// Records `new`, issued to replace `old`. `old` stays usable until `new` is first
    /// used, so a machine that never got the answer isn't locked out. A replacement
    /// issued earlier that was never used is revoked (`superseded`); returns those.
    /// None if `old` was held or revoked, or its machine stopped, after the caller
    /// checked it: a rotation can't undo that. The check and the insert share one
    /// transaction on the one connection, so a revocation lands wholly before or after.
    pub fn add_rotated_cert(
        &self,
        old: &MachineCert,
        new: &crate::machines::pki::Issued,
    ) -> Option<Vec<String>> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let old_id: i64 = tx
            .query_row(
                "SELECT mc.id FROM machine_certs mc JOIN machines m ON m.id = mc.machine_id AND m.user_id = mc.user_id
                 WHERE mc.fingerprint = ?1 AND mc.machine_id = ?2 AND mc.status = 'active'
                   AND m.state IN ('provisioning', 'running')",
                params![old.fingerprint, old.machine_id],
                |r| r.get(0),
            )
            .ok()?;
        let filter = format!(
            "issued_for = 'rotated' AND first_seen_at IS NULL AND status = 'active' AND id > {old_id}"
        );
        let superseded = revoke_where(&tx, &old.machine_id, &filter, "superseded").ok()?;
        tx.execute(
            "INSERT INTO machine_certs (fingerprint, serial, machine_id, user_id, status, issued_for, issued_at, not_before, not_after)
             VALUES (?, ?, ?, ?, 'active', 'rotated', ?, ?, ?)",
            params![new.fingerprint, new.serial, old.machine_id, old.user_id, now(), new.not_before, new.not_after],
        )
        .ok()?;
        refresh_enrollment(&tx, &old.machine_id).ok()?;
        tx.commit().ok()?;
        Some(superseded)
    }

    /// Marks the certificate used. The first time, the machine's certificates issued
    /// before it are revoked (`rotated`); returns those.
    pub fn machine_cert_seen(&self, fingerprint: &str) -> Vec<String> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else {
            return Vec::new();
        };
        let Ok(Some((id, machine_id))) = tx
            .query_row(
                "UPDATE machine_certs SET first_seen_at = ? WHERE fingerprint = ? AND first_seen_at IS NULL AND status = 'active' RETURNING id, machine_id",
                params![now(), fingerprint],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
        else {
            return Vec::new();
        };
        let revoked =
            revoke_where(&tx, &machine_id, &format!("id < {id}"), "rotated").unwrap_or_default();
        if refresh_enrollment(&tx, &machine_id).is_err() || tx.commit().is_err() {
            return Vec::new();
        }
        revoked
    }

    /// Moves the machine's certificates from `from` to `to` (`held`, `active`, or
    /// `revoked` with `reason`). Returns the fingerprints that changed.
    pub fn set_machine_certs(
        &self,
        machine_id: &str,
        from: &[&str],
        to: &str,
        reason: Option<&str>,
    ) -> Vec<String> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else {
            return Vec::new();
        };
        let list = from
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let changed: rusqlite::Result<Vec<String>> = if to == "revoked" {
            revoke_where(
                &tx,
                machine_id,
                &format!("status IN ({list})"),
                reason.unwrap_or("revoked"),
            )
        } else {
            tx.prepare(&format!("UPDATE machine_certs SET status = ?2 WHERE machine_id = ?1 AND status IN ({list}) RETURNING fingerprint"))
                .and_then(|mut s| s.query_map(params![machine_id, to], |r| r.get(0))?.collect())
        };
        match changed {
            Ok(fps) if refresh_enrollment(&tx, machine_id).is_ok() && tx.commit().is_ok() => fps,
            _ => Vec::new(),
        }
    }

    /// Places the machine's user on it: their Bots run there (ADR 0036). Only a live
    /// machine. Returns whether it changed.
    pub fn assign_machine(&self, machine_id: &str, by: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET assigned_at = ?, assigned_by = ? WHERE id = ? AND assigned_at IS NULL AND state NOT IN ('destroying', 'destroyed')",
                params![now(), by, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Their Bots run where routing puts unassigned users again. Returns whether it changed.
    pub fn unassign_machine(&self, machine_id: &str) -> bool {
        self.c().execute("UPDATE machines SET assigned_at = NULL, assigned_by = NULL WHERE id = ? AND assigned_at IS NOT NULL", [machine_id]).unwrap_or(0) == 1
    }

    /// Forgets the harness sessions of the user's Bots: a session lives on the host
    /// that ran it, so after a move the next run starts a new one. Returns how many.
    pub fn forget_sessions_of(&self, owner_id: &str) -> usize {
        self.c().execute("UPDATE bots SET session_id = NULL WHERE owner_id = ? AND session_id IS NOT NULL", [owner_id]).unwrap_or(0)
    }

    /// When the owner's machine was assigned (None: it isn't). A run reads this as it
    /// starts and passes it to `keep_session`.
    pub fn placed_at(&self, owner_id: &str) -> Option<i64> {
        self.user_machine(owner_id).and_then(|m| m.assigned_at)
    }

    /// Saves a run's session unless the owner was assigned or unassigned since the run
    /// began (`placed_at` then), so a run on the old host can't undo `forget_sessions_of`.
    pub fn keep_session(&self, bot_id: &str, session_id: &str, placed_at: Option<i64>) -> bool {
        self.c()
            .execute(
                "UPDATE bots SET session_id = ?1 WHERE id = ?2 AND session_id IS NOT ?1
                 AND (SELECT assigned_at FROM machines WHERE user_id = bots.owner_id AND state <> 'destroyed') IS ?3",
                params![session_id, bot_id, placed_at],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records a heartbeat: `Ok(version)` when the agent answered, `Err(why)` when not.
    pub fn machine_agent_seen(&self, machine_id: &str, result: Result<&str, &str>) {
        let _ = match result {
            Ok(version) => self.c().execute(
                "UPDATE machines SET agent_seen_at = ?, agent_version = ?, agent_error = NULL WHERE id = ?",
                params![now(), version, machine_id],
            ),
            Err(why) => self.c().execute("UPDATE machines SET agent_error = ? WHERE id = ?", params![why, machine_id]),
        };
    }

    /// What the agent said of its build, harnesses and upgrades (ADR 0039), if it was
    /// still `old`. Returns whether it was, so each change is seen once.
    pub fn machine_upkeep_swap(&self, machine_id: &str, old: Option<&Value>, new: &Value) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET agent_upkeep = ? WHERE id = ? AND agent_upkeep IS ?",
                params![new.to_string(), machine_id, old.map(Value::to_string)],
            )
            .unwrap_or(0)
            == 1
    }

    /// Queues a teammate's removal from a machine, unless one is pending: returns that
    /// one then, and whether this call made it.
    pub fn teammate_cleanup_queue(&self, n: &NewTeammateCleanup) -> Option<(TeammateCleanup, bool)> {
        let c = self.c();
        let made = c
            .execute(
                "INSERT OR IGNORE INTO teammate_cleanups (id, machine_id, owner_id, user_id, os_user, reason, files, grace_days, state, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![crate::random_hex(8), n.machine_id, n.owner_id, n.user_id, n.os_user, n.reason, n.files, n.grace_days, now(), n.created_by],
            )
            .unwrap_or(0)
            == 1;
        c.query_row(
            "SELECT * FROM teammate_cleanups WHERE machine_id = ? AND user_id = ? AND state = 'pending'",
            [n.machine_id, n.user_id],
            teammate_cleanup_row,
        )
        .optional()
        .ok()
        .flatten()
        .map(|r| (r, made))
    }

    pub fn teammate_cleanup(&self, id: &str) -> Option<TeammateCleanup> {
        self.c().query_row("SELECT * FROM teammate_cleanups WHERE id = ?", [id], teammate_cleanup_row).optional().ok().flatten()
    }

    /// Newest first, in `state` (any if None), on `machine_id` (any if None).
    pub fn teammate_cleanups(&self, state: Option<&str>, machine_id: Option<&str>) -> Vec<TeammateCleanup> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT * FROM teammate_cleanups WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR machine_id = ?2)
                 ORDER BY created_at DESC, id",
            )
            .unwrap();
        s.query_map(params![state, machine_id], teammate_cleanup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// An attempt at a pending (or held, for a purge) removal failed, or is waiting on
    /// the machine (`attempt` false). Returns whether it was still in `state`.
    pub fn teammate_cleanup_failed(&self, id: &str, state: &str, error: &str, attempt: bool) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET last_error = ?, attempts = attempts + ?, tried_at = CASE WHEN ? THEN ? ELSE tried_at END
                 WHERE id = ? AND state = ?",
                params![error, attempt as i64, attempt, now(), id, state],
            )
            .unwrap_or(0)
            == 1
    }

    /// The agent removed the teammate: `held` while their work waits for `purge_at`,
    /// else done. Returns whether it was still pending, so it's recorded once.
    pub fn teammate_cleanup_removed(&self, id: &str, archived_to: Option<&str>, purge_at: Option<i64>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = CASE WHEN ?1 IS NULL THEN 'done' ELSE 'held' END, purge_at = ?1, archived_to = ?2,
                 removed_at = ?3, done_at = CASE WHEN ?1 IS NULL THEN ?3 ELSE NULL END, attempts = attempts + 1, tried_at = ?3, last_error = NULL
                 WHERE id = ?4 AND state = 'pending'",
                params![purge_at, archived_to, at, id],
            )
            .unwrap_or(0)
            == 1
    }

    #[cfg(test)]
    pub fn teammate_cleanup_due_now(&self, id: &str) {
        self.c().execute("UPDATE teammate_cleanups SET purge_at = ? WHERE id = ?", params![now() - 1, id]).unwrap();
    }

    /// Ends a removal in `from` as `to` (`done` or `cancelled`), with `note` as its
    /// last word. Returns whether it was still in `from`.
    pub fn teammate_cleanup_end(&self, id: &str, from: &str, to: &str, note: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = ?, done_at = ?, last_error = ? WHERE id = ? AND state = ?",
                params![to, now(), note, id, from],
            )
            .unwrap_or(0)
            == 1
    }

    /// An admin asked for this pending removal: it's theirs now, so it's never cancelled
    /// because the teammate is wanted again. Returns whether it changed.
    pub fn teammate_cleanup_force(&self, id: &str) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET reason = 'admin' WHERE id = ? AND state = 'pending' AND reason <> 'admin'",
                [id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Cancels a pending removal with `note`, but only if no admin asked for it and the
    /// agent was never asked. Returns whether it did.
    pub fn teammate_cleanup_cancel_unasked(&self, id: &str, note: &str) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = 'cancelled', done_at = ?, last_error = ?
                 WHERE id = ? AND state = 'pending' AND reason <> 'admin' AND attempts = 0",
                params![now(), note, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// A teammate's account and folders for an owner's Bots are on this server (ADR 0066).
    /// Kept with botd's data, so a recreated container, whose password database starts
    /// afresh while the folders stay, still knows whose folders they are.
    pub fn teammate_space_made(&self, owner_id: &str, user_id: &str) {
        let _ = self.c().execute("INSERT OR IGNORE INTO teammate_spaces (owner_id, user_id, made_at) VALUES (?, ?, ?)", params![owner_id, user_id, now()]);
    }

    /// Every `(owner, teammate)` whose account and folders may be on this server.
    pub fn teammate_spaces(&self) -> Vec<(String, String)> {
        let c = self.c();
        let mut s = c.prepare("SELECT owner_id, user_id FROM teammate_spaces ORDER BY owner_id, user_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    pub fn teammate_space_gone(&self, owner_id: &str, user_id: &str) {
        let _ = self.c().execute("DELETE FROM teammate_spaces WHERE owner_id = ? AND user_id = ?", [owner_id, user_id]);
    }

    /// Queues the removal of a teammate's account for an owner's Bots, unless one is
    /// pending: returns that one then, and whether this call made it.
    pub fn account_removal_queue(&self, n: &NewAccountRemoval) -> Option<(AccountRemoval, bool)> {
        let c = self.c();
        let made = c
            .execute(
                "INSERT OR IGNORE INTO account_removals (id, owner_id, user_id, account, reason, files, grace_days, state, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![crate::random_hex(8), n.owner_id, n.user_id, n.account, n.reason, n.files, n.grace_days, now(), n.created_by],
            )
            .unwrap_or(0)
            == 1;
        c.query_row(
            "SELECT * FROM account_removals WHERE owner_id = ? AND user_id = ? AND state = 'pending'",
            [n.owner_id, n.user_id],
            account_removal_row,
        )
        .optional()
        .ok()
        .flatten()
        .map(|r| (r, made))
    }

    pub fn account_removal(&self, id: &str) -> Option<AccountRemoval> {
        self.c().query_row("SELECT * FROM account_removals WHERE id = ?", [id], account_removal_row).optional().ok().flatten()
    }

    /// Newest first, in `state` (any if None), where `user_id` (anyone if None) is the
    /// owner or the teammate.
    pub fn account_removals(&self, state: Option<&str>, user_id: Option<&str>) -> Vec<AccountRemoval> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT * FROM account_removals WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR owner_id = ?2 OR user_id = ?2)
                 ORDER BY created_at DESC, id",
            )
            .unwrap();
        s.query_map(params![state, user_id], account_removal_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The helper is about to run for a pending (or held, for a purge) removal: counted
    /// before it starts, so one that stopped halfway is never taken for untried. Returns
    /// whether it was still in `state`.
    pub fn account_removal_tried(&self, id: &str, state: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET attempts = attempts + 1, tried_at = ? WHERE id = ? AND state = ?", params![now(), id, state])
            .unwrap_or(0)
            == 1
    }

    /// A try at a pending (or held, for a purge) removal failed. Returns whether it was
    /// still in `state`.
    pub fn account_removal_failed(&self, id: &str, state: &str, error: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET last_error = ?, tried_at = ? WHERE id = ? AND state = ?", params![error, now(), id, state])
            .unwrap_or(0)
            == 1
    }

    /// The helper removed the account: `held` while their work waits for `purge_at`,
    /// else done. Returns whether it was still pending, so it's recorded once.
    pub fn account_removal_removed(&self, id: &str, archived_to: Option<&str>, purge_at: Option<i64>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE account_removals SET state = CASE WHEN ?1 IS NULL THEN 'done' ELSE 'held' END, purge_at = ?1, archived_to = ?2,
                 removed_at = ?3, done_at = CASE WHEN ?1 IS NULL THEN ?3 ELSE NULL END, tried_at = ?3, last_error = NULL
                 WHERE id = ?4 AND state = 'pending'",
                params![purge_at, archived_to, at, id],
            )
            .unwrap_or(0)
            == 1
    }

    #[cfg(test)]
    pub fn account_removal_due_now(&self, id: &str) {
        self.c().execute("UPDATE account_removals SET purge_at = ? WHERE id = ?", params![now() - 1, id]).unwrap();
    }

    /// Ends a removal in `from` as `to` (`done` or `cancelled`), with `note` as its last
    /// word. Returns whether it was still in `from`.
    pub fn account_removal_end(&self, id: &str, from: &str, to: &str, note: Option<&str>) -> bool {
        self.c()
            .execute("UPDATE account_removals SET state = ?, done_at = ?, last_error = ? WHERE id = ? AND state = ?", params![to, now(), note, id, from])
            .unwrap_or(0)
            == 1
    }

    /// An admin asked for this pending removal: it's theirs now, so it's never cancelled
    /// because the teammate is wanted again. Returns whether it changed.
    pub fn account_removal_force(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET reason = 'admin' WHERE id = ? AND state = 'pending' AND reason <> 'admin'", [id])
            .unwrap_or(0)
            == 1
    }

    /// Cancels a pending removal with `note`, but only if no admin asked for it and the
    /// helper was never started for it. Returns whether it did.
    pub fn account_removal_cancel_unasked(&self, id: &str, note: &str) -> bool {
        self.c()
            .execute(
                "UPDATE account_removals SET state = 'cancelled', done_at = ?, last_error = ?
                 WHERE id = ? AND state = 'pending' AND reason <> 'admin' AND attempts = 0",
                params![now(), note, id],
            )
            .unwrap_or(0)
            == 1
    }

    pub fn machine_harnesses_sent(&self, machine_id: &str, plan: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET harnesses_sent_at = ?, harnesses_sent_plan = ? WHERE id = ?",
            params![now(), plan, machine_id],
        );
    }

    /// Records an upgrade as on its way, unless the machine is held or another is (one
    /// sent before `stale_before` no longer counts). Returns whether this one is.
    pub fn machine_upgrade_claim(&self, machine_id: &str, id: &str, build: &str, by: &str, stale_before: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_id = ?, upgrade_build = ?, upgrade_sent_at = ?, upgrade_by = ?
                 WHERE id = ? AND upgrade_hold_at IS NULL AND (upgrade_id IS NULL OR upgrade_sent_at < ?)",
                params![id, build, now(), by, machine_id, stale_before],
            )
            .unwrap_or(0)
            == 1
    }

    /// Ends upgrade `id`. `failed`: the build that failed, kept so it isn't tried again
    /// by itself; None clears it. Returns whether `id` was the one on its way.
    pub fn machine_upgrade_end(&self, machine_id: &str, id: &str, failed: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_id = NULL, upgrade_build = NULL, upgrade_sent_at = NULL, upgrade_by = NULL,
                 upgrade_failed_build = ? WHERE id = ? AND upgrade_id = ?",
                params![failed, machine_id, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Lets a build that failed be tried again.
    pub fn machine_upgrade_forget_failure(&self, machine_id: &str) {
        let _ = self.c().execute("UPDATE machines SET upgrade_failed_build = NULL WHERE id = ?", [machine_id]);
    }

    /// Holds the agent at its build, unless it is held already or an upgrade is on its
    /// way (one sent before `stale_before` no longer counts): a hold that is taken means
    /// no upgrade starts until it is released. Returns whether it was taken.
    pub fn machine_upgrade_hold(&self, machine_id: &str, by: Option<&str>, stale_before: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_hold_at = ?, upgrade_hold_by = ?
                 WHERE id = ? AND upgrade_hold_at IS NULL AND (upgrade_id IS NULL OR upgrade_sent_at < ?)",
                params![now(), by, machine_id, stale_before],
            )
            .unwrap_or(0)
            == 1
    }

    /// Lets a held agent go. Returns whether it was held.
    pub fn machine_upgrade_release(&self, machine_id: &str) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_hold_at = NULL, upgrade_hold_by = NULL WHERE id = ? AND upgrade_hold_at IS NOT NULL",
                [machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    // Rebuilds (ADR 0056). Each step names the rebuild and the states it may come
    // from, so a stale step, or one racing an admin's cancel, changes nothing.

    /// Queues rebuild `id`, unless the machine isn't running, its agent is held, or a
    /// rebuild is underway. Returns whether this one is queued.
    pub fn machine_rebuild_queue(&self, machine_id: &str, id: &str, by: &str, discard: bool, from: Option<&str>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE machines SET rebuild_state = 'queued', rebuild_id = ?1, rebuild_by = ?2, rebuild_discard = ?3, rebuild_attempts = 0,
                 rebuild_next_at = ?4, rebuild_requested_at = ?4, rebuild_at = ?4, rebuild_sent_at = NULL, rebuild_error = NULL, rebuild_from = ?5
                 WHERE id = ?6 AND state = 'running' AND upgrade_hold_at IS NULL
                 AND (rebuild_state IS NULL OR rebuild_state IN ('done', 'failed', 'cancelled'))",
                params![id, by, discard, at, from, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Moves rebuild `id` from one of `from` to `to`. `attempt` counts one more try;
    /// `next_at` is when to try next. Returns whether it was in `from`.
    #[allow(clippy::too_many_arguments)]
    pub fn machine_rebuild_move(
        &self,
        machine_id: &str,
        id: &str,
        from: &[&str],
        to: &str,
        attempt: bool,
        next_at: Option<i64>,
        error: Option<&str>,
    ) -> bool {
        let states = from.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(", ");
        self.c()
            .execute(
                &format!(
                    "UPDATE machines SET rebuild_state = ?1, rebuild_attempts = rebuild_attempts + ?2, rebuild_next_at = ?3, rebuild_error = ?4,
                     rebuild_at = CASE WHEN rebuild_state = ?1 THEN rebuild_at ELSE ?5 END
                     WHERE id = ?6 AND rebuild_id = ?7 AND rebuild_state IN ({states})"
                ),
                params![to, attempt as i64, next_at, error, now(), machine_id, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records rebuild `id` as sent now, from one of `from`. Returns whether it was there.
    pub fn machine_rebuild_sending(&self, machine_id: &str, id: &str, from: &[&str]) -> bool {
        let at = now();
        if !self.machine_rebuild_move(machine_id, id, from, "rebuilding", true, None, None) {
            return false;
        }
        let _ = self.c().execute("UPDATE machines SET rebuild_sent_at = ?, rebuild_at = ? WHERE id = ?", params![at, at, machine_id]);
        true
    }

    /// Forgets what the old agent said and was sent: a rebuilt machine starts afresh.
    pub fn machine_rebuilt_reset(&self, machine_id: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET agent_upkeep = NULL, harnesses_sent_at = NULL, harnesses_sent_plan = NULL, upgrade_id = NULL,
             upgrade_build = NULL, upgrade_sent_at = NULL, upgrade_by = NULL, upgrade_failed_build = NULL WHERE id = ?",
            [machine_id],
        );
    }

    // Off-host machine backups (ADR 0071)

    /// Records a backup as running, unless one of the machine's is running already.
    pub fn machine_backup_start(&self, n: &NewMachineBackup) -> Option<MachineBackup> {
        let m = n.machine;
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_backups (id, machine_id, user_id, tier, plan, state, object_key, encrypted, created_by, created_at)
                 VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)",
                params![n.id, m.id, m.user_id, m.tier, m.plan, n.object_key, n.encrypted, n.created_by, now()],
            )
            .unwrap_or(0)
            == 1;
        if made { self.machine_backup(n.id) } else { None }
    }

    pub fn machine_backup(&self, id: &str) -> Option<MachineBackup> {
        self.c().query_row("SELECT * FROM machine_backups WHERE id = ?", [id], machine_backup_row).optional().ok().flatten()
    }

    /// The machine's backups, newest first, deleted ones too.
    pub fn machine_backups(&self, machine_id: &str) -> Vec<MachineBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_backups WHERE machine_id = ? ORDER BY created_at DESC, id DESC").unwrap();
        s.query_map([machine_id], machine_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every backup in `state`, oldest first.
    pub fn machine_backups_in(&self, state: &str) -> Vec<MachineBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_backups WHERE state = ? ORDER BY created_at, id").unwrap();
        s.query_map([state], machine_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The machine's newest backup that finished.
    pub fn machine_last_backup(&self, machine_id: &str) -> Option<MachineBackup> {
        self.c()
            .query_row(
                "SELECT * FROM machine_backups WHERE machine_id = ? AND state = 'done' ORDER BY created_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_backup_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Ends a running backup as `done` (with its size, hash and expiry) or `failed`.
    pub fn machine_backup_end(&self, id: &str, done: Option<(i64, &str, i64)>, error: Option<&str>) -> bool {
        let (state, size, sha, expires) = match done {
            Some((size, sha, expires)) => ("done", Some(size), Some(sha), Some(expires)),
            None => ("failed", None, None, None),
        };
        self.c()
            .execute(
                "UPDATE machine_backups SET state = ?, size = ?, sha256 = ?, expires_at = ?, error = ?, finished_at = ? WHERE id = ? AND state = 'running'",
                params![state, size, sha, expires, error.map(|e| crate::audit::clip(e, 500)), now(), id],
            )
            .unwrap_or(0)
            == 1
    }

    /// A finished backup whose objects are gone from the store.
    pub fn machine_backup_deleted(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE machine_backups SET state = 'deleted', deleted_at = ? WHERE id = ? AND state IN ('done', 'failed')", params![now(), id])
            .unwrap_or(0)
            == 1
    }

    /// Starts a restore of the machine, unless one is underway.
    pub fn machine_restore_start(&self, n: &NewMachineRestore) -> Option<MachineRestore> {
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_restores (id, machine_id, backup_id, state, created_by, created_at, tier, rto_ms, from_host, to_host, reason)
                 VALUES (?, ?, ?, 'importing', ?, ?, ?, ?, ?, ?, ?)",
                params![n.id, n.machine.id, n.backup_id, n.by, now(), n.machine.tier, n.rto_ms, n.from_host, n.to_host, n.reason],
            )
            .unwrap_or(0)
            == 1;
        if made { self.machine_restore(n.id) } else { None }
    }

    // Hosts (ADR 0076)

    pub fn machine_hosts(&self) -> Vec<MachineHost> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_hosts ORDER BY created_at, name").unwrap();
        s.query_map([], machine_host_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn machine_host(&self, name: &str) -> Option<MachineHost> {
        self.c().query_row("SELECT * FROM machine_hosts WHERE name = ?", [name], machine_host_row).optional().ok().flatten()
    }

    /// Records a host the first time it is configured; its address may change later,
    /// its certificate may not.
    pub fn machine_host_add(&self, name: &str, url: &str, fingerprint: &str) -> MachineHost {
        let c = self.c();
        c.execute(
            "INSERT INTO machine_hosts (name, url, fingerprint, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET url = ?2",
            params![name, url, fingerprint, now()],
        )
        .unwrap();
        c.query_row("SELECT * FROM machine_hosts WHERE name = ?", [name], machine_host_row).unwrap()
    }

    /// It answered: up again, if it was down. Returns whether it was down.
    pub fn machine_host_answered(&self, name: &str) -> bool {
        let c = self.c();
        let was_down = c
            .query_row("SELECT state = 'down' FROM machine_hosts WHERE name = ?", [name], |r| r.get::<_, bool>(0))
            .unwrap_or(false);
        c.execute(
            "UPDATE machine_hosts SET state = 'up', failing_since = NULL, last_error = NULL, down_at = NULL, checked_at = ?1
             WHERE name = ?2 AND state != 'lost'",
            params![now(), name],
        )
        .unwrap();
        was_down
    }

    /// It didn't answer: since when it hasn't.
    pub fn machine_host_failed(&self, name: &str, error: &str) -> Option<i64> {
        let c = self.c();
        c.execute(
            "UPDATE machine_hosts SET failing_since = COALESCE(failing_since, ?1), last_error = ?2, checked_at = ?1
             WHERE name = ?3 AND state != 'lost'",
            params![now(), crate::audit::clip(error, 300), name],
        )
        .unwrap();
        c.query_row("SELECT failing_since FROM machine_hosts WHERE name = ?", [name], |r| r.get(0)).ok().flatten()
    }

    /// Up to down, once. Returns whether this call did it.
    pub fn machine_host_down(&self, name: &str) -> bool {
        self.c()
            .execute("UPDATE machine_hosts SET state = 'down', down_at = ? WHERE name = ? AND state = 'up' AND failing_since IS NOT NULL", params![now(), name])
            .unwrap_or(0)
            == 1
    }

    /// Declared lost, once. Returns whether this call did it.
    pub fn machine_host_lost(&self, name: &str, by: Option<&str>) -> bool {
        self.c()
            .execute("UPDATE machine_hosts SET state = 'lost', lost_at = ?, lost_by = ? WHERE name = ? AND state != 'lost'", params![now(), by, name])
            .unwrap_or(0)
            == 1
    }

    /// Gives a machine its new provider id, as after a move to another host.
    pub fn set_machine_provider_id(&self, machine_id: &str, provider_id: &str) {
        self.c().execute("UPDATE machines SET provider_id = ?, updated_at = ? WHERE id = ?", params![provider_id, now(), machine_id]).unwrap();
    }

    /// The firewall a machine is behind now, as after a move to a host that has only today's.
    pub fn set_machine_firewall_id(&self, machine_id: &str, firewall_id: Option<&str>) {
        self.c().execute("UPDATE machines SET firewall_id = ?, updated_at = ? WHERE id = ?", params![firewall_id, now(), machine_id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_host_failing_backdate(&self, name: &str, ms: i64) {
        self.c().execute("UPDATE machine_hosts SET failing_since = failing_since - ?1 WHERE name = ?2", params![ms, name]).unwrap();
    }

    pub fn machine_restore(&self, id: &str) -> Option<MachineRestore> {
        self.c().query_row("SELECT * FROM machine_restores WHERE id = ?", [id], machine_restore_row).optional().ok().flatten()
    }

    /// The machine's restore underway, if any.
    pub fn machine_restoring(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? AND state IN ('importing', 'replacing', 'enrolling')",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The machine's newest restore.
    pub fn machine_last_restore(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The machine's newest restore that finished.
    pub fn machine_last_restore_done(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? AND state = 'done' ORDER BY finished_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The newest restores of every machine, newest first.
    pub fn machine_restores_recent(&self, limit: u32) -> Vec<MachineRestore> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_restores ORDER BY created_at DESC, id DESC LIMIT ?").unwrap();
        s.query_map([limit], machine_restore_row).unwrap().filter_map(Result::ok).collect()
    }

    /// How long a finished restore took (ADR 0074).
    /// Moves an enrolling restore to done with how long it took, in one write so a restart
    /// can't leave it done without its timing. Returns whether it moved.
    pub fn machine_restore_done(&self, id: &str, duration_ms: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machine_restores SET state = 'done', finished_at = ?1, duration_ms = ?2 WHERE id = ?3 AND state = 'enrolling'",
                params![now(), duration_ms, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Marks a restore as past its RTO, once. Returns whether this call did.
    pub fn machine_restore_rto_exceeded(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE machine_restores SET rto_exceeded_at = ? WHERE id = ? AND rto_exceeded_at IS NULL", params![now(), id])
            .unwrap_or(0)
            == 1
    }

    // RPO breaches (ADR 0074)

    /// Opens a breach for the machine, unless one is open. Returns it if this call did.
    pub fn machine_rpo_breach_start(&self, id: &str, m: &Machine, rpo_ms: i64, covered_since: i64) -> Option<MachineRpoBreach> {
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_rpo_breaches (id, machine_id, user_id, tier, rpo_ms, covered_since, breached_at, detected_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, m.id, m.user_id, m.tier, rpo_ms, covered_since, covered_since + rpo_ms, now()],
            )
            .unwrap_or(0)
            == 1;
        if made { self.c().query_row("SELECT * FROM machine_rpo_breaches WHERE id = ?", [id], machine_rpo_breach_row).ok() } else { None }
    }

    /// Ends an open breach. Returns whether this call did.
    pub fn machine_rpo_breach_end(&self, id: &str, reason: &str) -> bool {
        self.c()
            .execute("UPDATE machine_rpo_breaches SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL", params![now(), reason, id])
            .unwrap_or(0)
            == 1
    }

    /// Every open breach.
    pub fn machine_rpo_breaches_open(&self) -> Vec<MachineRpoBreach> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_rpo_breaches WHERE ended_at IS NULL ORDER BY breached_at, id").unwrap();
        s.query_map([], machine_rpo_breach_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The machine's open breach, if any.
    pub fn machine_rpo_breach_open(&self, machine_id: &str) -> Option<MachineRpoBreach> {
        self.c()
            .query_row("SELECT * FROM machine_rpo_breaches WHERE machine_id = ? AND ended_at IS NULL", [machine_id], machine_rpo_breach_row)
            .ok()
    }

    /// The newest breaches, open or not, newest first.
    pub fn machine_rpo_breaches(&self, limit: u32) -> Vec<MachineRpoBreach> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_rpo_breaches ORDER BY breached_at DESC, id DESC LIMIT ?").unwrap();
        s.query_map([limit], machine_rpo_breach_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every restore in `state`.
    pub fn machine_restores_in(&self, state: &str) -> Vec<MachineRestore> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_restores WHERE state = ? ORDER BY created_at, id").unwrap();
        s.query_map([state], machine_restore_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Moves a restore from one of `from` to `to`. Returns whether it moved.
    pub fn machine_restore_move(&self, id: &str, from: &[&str], to: &str, error: Option<&str>) -> bool {
        let at = now();
        let states = from.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ");
        self.c()
            .execute(
                &format!(
                    "UPDATE machine_restores SET state = ?1, error = COALESCE(?2, error),
                     replaced_at = CASE WHEN ?1 = 'enrolling' THEN ?3 ELSE replaced_at END,
                     finished_at = CASE WHEN ?1 IN ('done', 'failed') THEN ?3 ELSE finished_at END
                     WHERE id = ?4 AND state IN ({states})"
                ),
                params![to, error.map(|e| crate::audit::clip(e, 500)), at, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Whether files that exist only on the machine may be lost if it is wiped: it is
    /// assigned, or ever was, or a Bot ever ran there (from the audit log).
    pub fn machine_may_hold_work(&self, machine_id: &str) -> bool {
        self.c()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM machines WHERE id = ?1 AND assigned_at IS NOT NULL)
                 OR EXISTS (SELECT 1 FROM audit_events WHERE action = 'placement.assigned' AND target_type = 'machine' AND target_id = ?1)
                 OR EXISTS (SELECT 1 FROM audit_events WHERE action = 'bot.run_routed' AND json_extract(details, '$.machine') = ?1)",
                [machine_id],
                |r| r.get(0),
            )
            .unwrap_or(true)
    }

    #[cfg(test)]
    pub fn machine_tokens_unused(&self, machine_id: &str) -> i64 {
        self.c()
            .query_row("SELECT COUNT(*) FROM machine_tokens WHERE machine_id = ? AND used_at IS NULL AND revoked_at IS NULL", [machine_id], |r| r.get(0))
            .unwrap()
    }

    #[cfg(test)]
    pub fn machine_rebuild_due_now(&self, machine_id: &str) {
        self.c().execute("UPDATE machines SET rebuild_next_at = ? WHERE id = ?", params![now() - 1, machine_id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_rebuild_backdate(&self, machine_id: &str, ms: i64) {
        self.c()
            .execute(
                "UPDATE machines SET rebuild_sent_at = rebuild_sent_at - ?1, rebuild_at = rebuild_at - ?1, enroll_by = enroll_by - ?1,
                 enrolled_at = enrolled_at - ?1 WHERE id = ?2",
                params![ms, machine_id],
            )
            .unwrap();
    }

    #[cfg(test)]
    pub fn machine_backup_backdate(&self, id: &str, ms: i64) {
        self.c()
            .execute("UPDATE machine_backups SET created_at = created_at - ?1, expires_at = expires_at - ?1 WHERE id = ?2", params![ms, id])
            .unwrap();
    }

    #[cfg(test)]
    pub fn machine_restore_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machine_restores SET created_at = created_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_restore_replaced_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machine_restores SET replaced_at = replaced_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_enrolled_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machines SET enrolled_at = enrolled_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machines SET created_at = created_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_upgrade_backdate(&self, machine_id: &str, ms: i64) {
        self.c()
            .execute("UPDATE machines SET upgrade_sent_at = upgrade_sent_at - ? WHERE id = ?", params![ms, machine_id])
            .unwrap();
    }
}

#[cfg(test)]
pub fn temp_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("superbot-test-{tag}-{}", crate::short_id()));
    crate::paths::root(&dir.to_string_lossy()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn all_events(db: &Db) -> Vec<AuditEvent> {
        db.audit_events(&audit::Filter::default(), 1000, false)
    }

    #[test]
    fn teammate_accounts_made_before_their_table_are_remembered_from_the_audit_log() {
        let db = Db::open(&temp_path("spaces").join("app.sqlite")).unwrap();
        let made = |owner: &str, d: Value| audit::Who::system("isolation").event("isolation.account_created").target("user", owner).details(d);
        db.record(&made("u1", json!({ "account": "sb-t-1", "forUser": "u2" })));
        db.record(&made("u1", json!({ "account": "sb-t-1", "forUser": "u2" })));
        db.record(&made("u1", json!({ "account": "sb-u-u1" })));
        db.record(&made("u3", json!({ "account": "sb-t-2", "forUser": "u4" })).outcome(audit::Outcome::Failure));
        db.c().execute("DELETE FROM teammate_spaces", []).unwrap();
        migrate_account_removals(&db.c(), false).unwrap();
        assert_eq!(db.teammate_spaces(), [("u1".to_string(), "u2".to_string())]);
    }

    #[test]
    fn push_tokens_are_sealed_one_per_session_and_capped_per_person() {
        let db = Db::open(&temp_path("push").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("push@example.com"), "P", Role::Member).unwrap();
        let other = db.create_user(None, Some("push2@example.com"), "Q", Role::Member).unwrap();
        let session = |user: &str| {
            let hash = crate::random_hex(16);
            let s = NewSession { user_id: user, token_hash: &hash, kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: now() + 60_000 };
            db.create_session(&s).id
        };
        let s1 = session(&u.id);
        let (d, change) = db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-1]", "ios", true, true);
        assert_eq!((change, d.token.as_str()), (PushPut::Added, "ExponentPushToken[t-1]"));
        let raw: String = db.c().query_row("SELECT token FROM push_devices", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("t-1"), "sealed at rest: {raw}");
        let (d2, change) = db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", true, true);
        assert_eq!((change, d2.id == d.id), (PushPut::Added, true), "a new token for the session replaces the old one");
        assert_eq!(db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", true, true).1, PushPut::Unchanged);
        assert_eq!(db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", false, true).1, PushPut::Updated);
        let s2 = session(&other.id);
        assert_eq!(db.put_push_device(&other.id, &s2, "expo", "ExponentPushToken[t-2]", "android", true, true).1, PushPut::Moved);
        assert!(db.session_push_device(&s1).is_none(), "a token lives on one session only");
        for i in 0..MAX_PUSH_DEVICES + 3 {
            let s = session(&u.id);
            db.put_push_device(&u.id, &s, "expo", &format!("ExponentPushToken[c-{i}]"), "ios", true, true);
        }
        let n: i64 = db.c().query_row("SELECT COUNT(*) FROM push_devices WHERE user_id = ?", [&u.id], |r| r.get(0)).unwrap();
        assert_eq!(n as usize, MAX_PUSH_DEVICES, "the oldest go");
        db.c().execute("DELETE FROM sessions WHERE id = ?", [&s2]).unwrap();
        assert!(db.session_push_device(&s2).is_none(), "a pruned session takes its device");
    }

    #[test]
    fn the_bot_cap_holds_under_concurrent_requests() {
        let db = std::sync::Arc::new(Db::open(&temp_path("bot-cap").join("app.sqlite")).unwrap());
        let u = db.create_user(None, Some("cap@example.com"), "Cap", Role::Member).unwrap();
        let other = db.create_user(None, Some("other@example.com"), "Other", Role::Member).unwrap();
        let theirs: Vec<String> = (0..8).map(|_| db.create_bot_owned("T", "#fff", "waddle", "claude", None, false, &other.id, Visibility::Private).id).collect();
        // Creates and transfers race for the same 3 slots.
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let (db, owner, bot) = (db.clone(), u.id.clone(), theirs[i % 8].clone());
                std::thread::spawn(move || {
                    if i < 8 {
                        db.create_bot_capped("B", "#fff", "waddle", "claude", None, false, &owner, Visibility::Private, Some(3)).is_some()
                    } else {
                        db.set_bot_owner_capped(&bot, &owner, Some(3))
                    }
                })
            })
            .collect();
        let won = threads.into_iter().map(|t| t.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!((won, db.owned_bot_count(&u.id)), (3, 3));
        assert!(db.create_bot_capped("B", "#fff", "waddle", "claude", None, false, &other.id, Visibility::Private, None).is_some());
    }

    #[test]
    fn subscription_events_end_in_the_same_tier_whatever_order_they_arrive_in() {
        fn orders(n: usize) -> Vec<Vec<usize>> {
            if n == 0 {
                return vec![vec![]];
            }
            orders(n - 1)
                .into_iter()
                .flat_map(|o| {
                    (0..n).map(move |i| {
                        let mut o = o.clone();
                        o.insert(i, n - 1);
                        o
                    })
                })
                .collect()
        }
        let db = Db::open(&temp_path("sub-order").join("app.sqlite")).unwrap();
        // Plan A (pro) started at 10, was updated at 25 and cancelled at 30. Plan B
        // (starter) started at 20, replacing it, and was cancelled at 40. Then ties:
        // A cancelled in the same second it started, an update to A in the same second
        // as its cancellation, and A paused and resumed in the same second.
        let events = [
            ("a", "active", Some("pro"), 10, 10),
            ("b", "active", Some("starter"), 20, 20),
            ("a", "active", Some("pro"), 10, 25),
            ("a", "canceled", None, 10, 30),
            ("b", "canceled", None, 20, 40),
            ("a", "canceled", None, 10, 10),
            ("a", "active", Some("pro"), 10, 30),
            ("a", "paused", None, 10, 50),
            ("a", "active", Some("pro"), 10, 50),
        ];
        let cases = [
            (&[0, 1, 2, 3][..], Some("starter")),
            (&[0, 1, 2, 3, 4][..], None),
            (&[0, 1, 2, 4][..], Some("pro")),
            (&[0, 5][..], None),
            (&[0, 3, 6][..], None),
            (&[0, 7, 8][..], None),
        ];
        for (picked, want) in cases {
            for order in orders(picked.len()) {
                let u = db.create_user(None, None, "Payer", Role::Member).unwrap();
                for (n, &i) in order.iter().enumerate() {
                    let (plan, status, tier, started, at) = events[picked[i]];
                    let s = Subscription {
                        user_id: u.id.clone(),
                        provider: "stripe".into(),
                        customer_id: None,
                        subscription_id: format!("{}-{plan}", u.id),
                        status: status.into(),
                        price_id: None,
                        tier: tier.map(String::from),
                        period_start: None,
                        period_end: None,
                        started,
                        event_created: at,
                        updated_at: 0,
                    };
                    db.apply_subscription(&format!("{}-{n}", u.id), "customer.subscription.updated", &s, true).unwrap();
                }
                assert_eq!(db.user(&u.id).unwrap().tier.as_deref(), want, "events {picked:?} in order {order:?}");
            }
        }
    }

    #[test]
    fn subscribers_from_before_customers_were_linked_keep_their_portal() {
        let db = Db::open(&temp_path("billing-backfill").join("app.sqlite")).unwrap();
        let ids: Vec<String> = (0..4).map(|_| db.create_user(None, None, "Payer", Role::Member).unwrap().id).collect();
        // One customer; two of their own; one shared with another user (ADR 0040 kept the
        // other user's subscription out, but its id may still be on record).
        let rows = [(&ids[0], "sub_a", "cus_a"), (&ids[0], "sub_a2", "cus_a"), (&ids[1], "sub_b", "cus_b"), (&ids[1], "sub_b2", "cus_b2"), (&ids[2], "sub_c", "cus_shared"), (&ids[3], "sub_d", "cus_shared")];
        {
            let c = db.c();
            c.execute("DELETE FROM billing_customers", []).unwrap();
            for (u, sub, cus) in rows {
                c.execute(
                    "INSERT INTO subscriptions (subscription_id, user_id, provider, customer_id, status, started, event_created, updated_at) VALUES (?, ?, 'stripe', ?, 'active', 1, 1, 1)",
                    params![sub, u, cus],
                )
                .unwrap();
            }
            migrate_billing_customers(&c, false).unwrap();
            migrate_billing_customers(&c, false).unwrap();
        }
        let linked: Vec<Option<String>> = ids.iter().map(|u| db.customer_of(u)).collect();
        assert_eq!(linked, [Some("cus_a".to_string()), None, None, None]);
    }

    #[test]
    fn the_pending_cap_holds_under_concurrent_requests() {
        let db = std::sync::Arc::new(Db::open(&temp_path("signup-cap").join("app.sqlite")).unwrap());
        let results: Vec<_> = (0..16)
            .map(|i| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let email = format!("p{i}@example.com");
                    let s = NewSignup { name: "P", email: &email, company: "C", team_size: "1", use_case: "U", sign_in: "other", ip: None, user_agent: None };
                    db.add_signup(&s, 3).map(|_| ())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(results.iter().all(|r| r.is_ok() || *r == Err(AddSignup::Full)));
        assert_eq!(db.pending_signups(), 3);
        let taken = db.signups(Some("pending"), 1)[0].email.to_uppercase();
        let s = NewSignup { name: "P", email: &taken, company: "C", team_size: "1", use_case: "U", sign_in: "other", ip: None, user_agent: None };
        assert_eq!(db.add_signup(&s, 10).map(|_| ()), Err(AddSignup::Duplicate), "emails match without case");
    }

    #[test]
    fn fresh_install_asks() {
        let db = Db::open(&temp_path("fresh").join("app.sqlite")).unwrap();
        assert_eq!(db.global_policy().mode, Mode::Ask);
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let e = &all_events(&db)[0];
        assert_eq!((e.action.as_str(), e.actor_kind.as_str(), e.target_type.as_deref(), e.outcome.as_str()), ("policy.initialized", "system", Some("policy"), "success"));
        assert!(e.time.ends_with('Z'), "{}", e.time);
    }

    #[test]
    fn a_held_machine_claims_no_upgrade() {
        let db = Db::open(&temp_path("upgrade-hold").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(db.machine_upgrade_hold(&m.id, Some("admin"), 0));
        assert!(!db.machine_upgrade_hold(&m.id, Some("admin"), 0), "held already");
        assert!(!db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0), "held");
        assert!(db.machine_upgrade_release(&m.id));
        assert!(!db.machine_upgrade_release(&m.id), "released already");
        assert!(db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0));
        assert!(!db.machine_upgrade_claim(&m.id, "u2", "b", "admin", 0), "one on its way");
    }

    #[test]
    fn a_rebuild_steps_only_from_the_state_it_expects() {
        let path = temp_path("rebuild-steps").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(!db.machine_rebuild_queue(&m.id, "r1", "auto", false, None), "only a running machine");
        db.c().execute("UPDATE machines SET state = 'running' WHERE id = ?", [&m.id]).unwrap();
        assert!(!db.machine_may_hold_work(&m.id));
        assert!(db.machine_rebuild_queue(&m.id, "r1", "auto", false, Some("0.3.0")));
        assert!(!db.machine_rebuild_queue(&m.id, "r2", "auto", false, None), "one at a time");
        assert!(!db.machine_rebuild_move(&m.id, "r0", &["queued"], "cancelled", false, None, None), "a stale rebuild changes nothing");
        assert!(!db.machine_rebuild_sending(&m.id, "r1", &["retrying"]), "not from another state");
        assert!(db.machine_rebuild_sending(&m.id, "r1", &["queued"]));
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_state.as_deref(), r.rebuild_attempts, r.rebuild_from.as_deref()), (Some("rebuilding"), 1, Some("0.3.0")));
        assert!(r.rebuild_sent_at.is_some());
        assert!(db.machine_rebuild_move(&m.id, "r1", &["rebuilding"], "failed", false, None, Some("no")));
        assert!(db.machine_upgrade_hold(&m.id, None, 0));
        assert!(!db.machine_rebuild_queue(&m.id, "r3", "admin", true, None), "held");
        db.machine_upgrade_release(&m.id);
        assert!(db.machine_rebuild_queue(&m.id, "r3", "admin", true, None), "again after a failure");
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_attempts, r.rebuild_error.as_deref(), r.rebuild_discard), (0, None, true));
        assert!(db.assign_machine(&m.id, None));
        assert!(db.machine_may_hold_work(&m.id), "assigned");
        assert!(db.unassign_machine(&m.id));
        let routed = audit::Event::new(audit::Actor::system("t"), "bot.run_routed").details(json!({ "machine": m.id }));
        db.record(&routed);
        assert!(db.machine_may_hold_work(&m.id), "a Bot ran there");

        // An install from before ADR 0056 gets the columns, empty.
        db.c()
            .execute_batch(
                "ALTER TABLE machines DROP COLUMN rebuild_state; ALTER TABLE machines DROP COLUMN rebuild_id;
                 ALTER TABLE machines DROP COLUMN rebuild_by; ALTER TABLE machines DROP COLUMN rebuild_discard;
                 ALTER TABLE machines DROP COLUMN rebuild_attempts; ALTER TABLE machines DROP COLUMN rebuild_next_at;
                 ALTER TABLE machines DROP COLUMN rebuild_requested_at; ALTER TABLE machines DROP COLUMN rebuild_at;
                 ALTER TABLE machines DROP COLUMN rebuild_sent_at; ALTER TABLE machines DROP COLUMN rebuild_error;
                 ALTER TABLE machines DROP COLUMN rebuild_from;",
            )
            .unwrap();
        let rebuild = MIGRATIONS.iter().position(|m| std::ptr::fn_addr_eq(*m, migrate_machine_rebuild as fn(&Connection, bool) -> rusqlite::Result<()>)).unwrap();
        db.c().execute_batch(&format!("PRAGMA user_version = {rebuild};")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_state, r.rebuild_attempts, r.rebuild_discard), (None, 0, false));
    }

    #[test]
    fn an_upgrade_on_its_way_takes_no_hold() {
        let db = Db::open(&temp_path("upgrade-claimed").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0));
        assert!(!db.machine_upgrade_hold(&m.id, Some("admin"), 0), "an upgrade is on its way");
        assert!(db.machine(&m.id).unwrap().upgrade_hold_at.is_none());
        db.machine_upgrade_backdate(&m.id, 60_000);
        assert!(db.machine_upgrade_hold(&m.id, Some("admin"), now() - 1000), "a stale one doesn't count");
        assert!(db.machine_upgrade_end(&m.id, "u1", None));
        assert!(!db.machine_upgrade_claim(&m.id, "u2", "b", "admin", 0), "held");
    }

    #[test]
    fn one_live_machine_per_user() {
        let path = temp_path("machines").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: Some("operator") };
        let m = db.add_machine(&new).unwrap();
        assert_eq!((m.state, m.label.clone(), m.provider_id.as_deref()), (MachineState::Pending, format!("superbot-{}", m.id), None));
        match db.add_machine(&new) {
            Err(AddMachine::Exists(e)) => assert_eq!(e.id, m.id),
            other => panic!("{other:?}"),
        }
        let missing = NewMachine { user_id: "u-nobody", ..new };
        assert!(matches!(db.add_machine(&missing), Err(AddMachine::Db(_))), "only for real users");

        let mut next = m.clone();
        next.state = MachineState::Provisioning;
        next.provider_id = Some("42".into());
        assert!(db.save_machine(&next, MachineState::Pending));
        assert!(!db.save_machine(&next, MachineState::Pending), "a stale change loses");
        next.state = MachineState::Destroyed;
        assert!(db.save_machine(&next, MachineState::Provisioning));
        assert!(db.user_machine(&u.id).is_none());
        let again = db.add_machine(&new).unwrap();
        assert_ne!(again.id, m.id);
        assert_eq!(db.machines(None).len(), 2);
        assert_eq!(db.machines(Some(MachineState::Destroyed))[0].provider_id.as_deref(), Some("42"));
        assert!(db.c().execute("UPDATE machines SET state = 'lost'", []).is_err(), "only known states");

        // An install from before machines (user_version 9) gets the table on upgrade.
        db.c().execute_batch("DROP TABLE machines; PRAGMA user_version = 9;").unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(db.machines(None).is_empty());
        assert!(db.add_machine(&new).is_ok());

        // An install with tiers but no enrollment (user_version 11) gets enrollment on upgrade.
        db.c().execute_batch("DROP TABLE machine_certs; DROP TABLE machine_tokens; PRAGMA user_version = 11;").unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let tables: i64 = db.c().query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('machine_certs', 'machine_tokens', 'usage_monthly')", [], |r| r.get(0)).unwrap();
        assert_eq!(tables, 3);

        // An install at main's enrollment version (12) gets the lockdown columns, and
        // its machines keep working.
        let live = db.machines(None).into_iter().find(|m| m.state != MachineState::Destroyed).unwrap();
        db.c()
            .execute_batch(
                "ALTER TABLE machines DROP COLUMN firewall_id; ALTER TABLE machines DROP COLUMN enroll_by;
                 ALTER TABLE machines DROP COLUMN enroll_overdue_at; PRAGMA user_version = 12;",
            )
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let m = db.machine(&live.id).unwrap();
        assert_eq!((m.firewall_id, m.enroll_by, m.enroll_overdue_at), (None, None, None));
        db.set_machine_firewall(&live.id, "501");
        assert_eq!(db.machines_on_firewall("501", "nobody"), 1);
        assert_eq!(db.machines_on_firewall("501", &live.id), 0, "not counting the one asked about");
    }

    #[test]
    fn existing_install_keeps_bypass() {
        let path = temp_path("existing").join("app.sqlite");
        // A database from before approvals: tables exist, user_version is 0.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE bots (id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL, shape TEXT NOT NULL,
               harness TEXT NOT NULL, model TEXT, session_id TEXT, primary_bot INTEGER NOT NULL DEFAULT 0,
               hidden INTEGER NOT NULL DEFAULT 0, unread INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
             INSERT INTO bots (id, name, color, shape, harness, created_at) VALUES ('b1', 'Old', '#fff', 'waddle', 'claude', 0);",
        )
        .unwrap();
        drop(c);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.global_policy().mode, Mode::Bypass);
        assert!(!db.global_policy().sandbox, "an upgrade keeps harness sandboxes off");
        assert_eq!(db.bots().len(), 1);
        // Reopening doesn't re-run the migrations.
        drop(db);
        let db = Db::open(&path).unwrap();
        let actions: Vec<String> = all_events(&db).into_iter().map(|e| e.action).collect();
        assert_eq!(actions, ["policy.sandbox_initialized", "audit.schema_upgraded", "bot.acl_initialized", "policy.initialized"]);
    }

    #[test]
    fn an_install_from_before_sandboxes_keeps_them_off() {
        let path = temp_path("sandbox-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        assert!(db.global_policy().sandbox, "a fresh install has them on");
        let bot = db.create_bot("Ada", "#fff", "waddle", "codex", None, false);
        db.set_bot_override(&bot.id, Some(&Override { timeout_minutes: Some(3), ..Default::default() }));
        // As saved before ADR 0055: no `sandbox` in the policy.
        let mut p = serde_json::to_value(db.global_policy()).unwrap();
        p.as_object_mut().unwrap().remove("sandbox");
        db.c().execute("UPDATE settings SET value = ? WHERE key = 'policy'", [p.to_string()]).unwrap();
        let sandbox = MIGRATIONS.iter().position(|m| std::ptr::fn_addr_eq(*m, migrate_sandbox as fn(&Connection, bool) -> rusqlite::Result<()>)).unwrap();
        db.c().execute_batch(&format!("PRAGMA user_version = {sandbox};")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(!db.global_policy().sandbox);
        assert_eq!((db.effective_policy(&bot.id).sandbox, db.effective_policy(&bot.id).timeout_minutes), (false, 3), "its Bots follow it");
        let e = all_events(&db).into_iter().find(|e| e.action == "policy.sandbox_initialized").unwrap();
        assert_eq!((e.actor_kind.as_str(), e.target_id.as_deref(), e.details["sandbox"].as_bool()), ("system", Some("global"), Some(false)));
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(all_events(&db).iter().filter(|e| e.action == "policy.sandbox_initialized").count(), 1, "once");
    }

    macro_rules! undo_audit_actors {
        () => {
            "DROP INDEX audit_events_on_behalf_of; DROP INDEX audit_events_session;
            ALTER TABLE audit_events DROP COLUMN actor_email; ALTER TABLE audit_events DROP COLUMN actor_role;
            ALTER TABLE audit_events DROP COLUMN auth_method; ALTER TABLE audit_events DROP COLUMN idp;
            ALTER TABLE audit_events DROP COLUMN idp_provider; ALTER TABLE audit_events DROP COLUMN session_id;
            ALTER TABLE audit_events DROP COLUMN on_behalf_of; ALTER TABLE sessions DROP COLUMN idp_provider;
            ALTER TABLE messages DROP COLUMN requested_by;"
        };
    }

    macro_rules! undo_last_login {
        () => {
            "ALTER TABLE users DROP COLUMN last_login_at; ALTER TABLE users DROP COLUMN last_login_method;
            ALTER TABLE users DROP COLUMN last_login_idp_provider; "
        };
    }

    /// Rewinds a database to before last sign-ins (user_version 7).
    const UNDO_LAST_LOGIN: &str = undo_last_login!();

    /// Rewinds a database to before per-user audit actors (user_version 5).
    const UNDO_AUDIT_ACTORS: &str = concat!(undo_last_login!(), undo_audit_actors!());

    /// Rewinds a database to before bot ACLs, so a test can set `user_version` lower.
    const UNDO_BOT_ACLS: &str =
        concat!(undo_last_login!(), undo_audit_actors!(), " DROP TABLE bot_grants; DROP INDEX bots_owner; ALTER TABLE bots DROP COLUMN visibility; ALTER TABLE bots DROP COLUMN owner_id;");

    #[test]
    fn upgrade_keeps_old_audit_rows_and_records_new_actors() {
        let path = temp_path("actors-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let bot = db.create_bot("Kept", "#fff", "waddle", "claude", None, true);
        let queued = db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        db.c().execute_batch(&format!("{UNDO_AUDIT_ACTORS} PRAGMA user_version = 5;")).unwrap();
        // A row as version 5 wrote it.
        db.c()
            .execute(
                "INSERT INTO audit_events (at, actor_kind, actor_id, actor_name, action, outcome, details) VALUES (1, 'user', 'operator', 'Owner', 'bot.created', 'success', '{}')",
                [],
            )
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let rows = all_events(&db);
        let upgraded = rows.iter().find(|e| e.action == "audit.schema_upgraded").unwrap();
        let old = rows.iter().find(|e| e.action == "bot.created").unwrap();
        assert_eq!((upgraded.action.as_str(), upgraded.actor_id.as_deref()), ("audit.schema_upgraded", Some("migration")));
        assert_eq!(upgraded.details["added"].as_array().map(Vec::len), Some(AUDIT_ACTOR_COLUMNS.len()));
        assert_eq!((old.actor_id.as_deref(), old.actor_name.as_deref()), (Some("operator"), Some("Owner")), "old rows stay as written");
        assert_eq!((&old.actor_email, &old.auth_method, &old.idp, &old.session_id, &old.on_behalf_of), (&None, &None, &None, &None, &None));
        let m = db.message(queued.id).unwrap();
        assert!(m.requested_by.is_none(), "messages queued before the upgrade have no requester");

        let who = audit::Who {
            actor: audit::Actor {
                email: Some("ada@example.com".into()),
                role: Some("admin".into()),
                method: Some("sso".into()),
                idp: Some("entra".into()),
                idp_provider: Some("work".into()),
                session: Some("s1".into()),
                ..audit::Actor::operator()
            },
            source: audit::Source::default(),
        };
        db.set_requested_by(m.id, &who);
        assert_eq!(db.message(m.id).unwrap().requested_by.map(|w| w.actor), Some(who.actor.clone()));
        db.record(&who.event("bot.updated"));
        let e = &all_events(&db)[0];
        assert_eq!(
            (e.actor_email.as_deref(), e.actor_role.as_deref(), e.auth_method.as_deref(), e.idp.as_deref(), e.idp_provider.as_deref(), e.session_id.as_deref()),
            (Some("ada@example.com"), Some("admin"), Some("sso"), Some("entra"), Some("work"), Some("s1"))
        );
        assert!(db.c().execute("UPDATE audit_events SET actor_email = 'x'", []).is_err(), "still append-only");
    }

    #[test]
    fn actor_text_is_scrubbed_and_clipped() {
        let db = Db::open(&temp_path("actor-scrub").join("app.sqlite")).unwrap();
        let actor = audit::Actor { name: Some("Ada password=hunter2".into()), email: Some(format!("{}@example.com", "a".repeat(300))), ..audit::Actor::operator() };
        let source = audit::Source { ip: None, user_agent: Some("curl --token sbs_0123456789abcdef0123456789".into()) };
        db.record(&audit::Who { actor, source }.event("x.y"));
        let e = &all_events(&db)[0];
        assert_eq!(e.actor_name.as_deref(), Some("Ada password=[redacted]"));
        assert!(!e.user_agent.as_deref().unwrap().contains("sbs_0123"), "{:?}", e.user_agent);
        assert_eq!(e.actor_email.as_deref().unwrap().chars().count(), 255, "254 and an ellipsis");
    }

    #[test]
    fn upgrade_takes_last_sign_ins_from_kept_sessions() {
        let path = temp_path("last-login-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let seen = db.create_user(None, None, "Seen", Role::Member).unwrap();
        let never = db.create_user(None, None, "Never", Role::Member).unwrap();
        let s = db.create_session(&NewSession { user_id: &seen.id, token_hash: "h", kind: "token", method: "sso", idp_subject: None, idp_provider: Some("work"), label: None, ip: None, user_agent: None, expires_at: now() + 1000 });
        assert_eq!(db.user(&seen.id).unwrap().last_login_at, Some(s.created_at), "a new session stamps it");
        db.c().execute_batch(&format!("{UNDO_LAST_LOGIN} PRAGMA user_version = 7;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let u = db.user(&seen.id).unwrap();
        assert_eq!((u.last_login_at, u.last_login_method.as_deref(), u.last_login_idp_provider.as_deref()), (Some(s.created_at), Some("sso"), Some("work")));
        assert_eq!(db.user(&never.id).unwrap().last_login_at, None);
    }

    #[test]
    fn upgrade_gives_existing_bots_to_the_owner_shared() {
        let path = temp_path("acl-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let old = db.create_bot("Old", "#fff", "waddle", "claude", None, true);
        db.c().execute_batch(&format!("{UNDO_BOT_ACLS} PRAGMA user_version = 4;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let b = db.bot(&old.id).unwrap();
        assert_eq!((b.owner_id.as_str(), b.visibility), ("operator", Visibility::Shared));
        let e = all_events(&db).into_iter().find(|e| e.action == "bot.acl_initialized").unwrap();
        assert_eq!((e.action.as_str(), e.actor_id.as_deref(), e.details["bots"].as_i64()), ("bot.acl_initialized", Some("migration"), Some(1)));

        // Grants: one per user and Bot, gone with the Bot, and the schema refuses unknown words.
        let u = db.create_user(None, Some("g@example.com"), "G", Role::Member).unwrap();
        let mine = db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, &u.id, Visibility::Private);
        assert_eq!((mine.owner_id.as_str(), mine.visibility), (u.id.as_str(), Visibility::Private));
        assert_eq!(db.set_grant(&old.id, &u.id, Grant::Viewer, "operator"), None);
        assert_eq!(db.set_grant(&old.id, &u.id, Grant::Operator, "operator"), Some(Grant::Viewer));
        assert_eq!(db.grants(&old.id).len(), 1);
        assert_eq!(db.user_grants(&u.id).get(&old.id), Some(&Grant::Operator));
        let c = db.c();
        assert!(c.execute("UPDATE bots SET visibility = 'public' WHERE id = ?", [&old.id]).is_err());
        assert!(c.execute("UPDATE bot_grants SET level = 'owner'", []).is_err());
        drop(c);
        db.set_bot_visibility(&old.id, Visibility::Private);
        assert!(db.set_bot_owner_capped(&old.id, &u.id, None));
        assert_eq!(db.bot(&old.id).map(|b| (b.owner_id, b.visibility)), Some((u.id.clone(), Visibility::Private)));
        assert_eq!(db.remove_grant(&old.id, &u.id), Some(Grant::Operator));
        assert_eq!(db.remove_grant(&old.id, &u.id), None);
        let other = db.create_user(None, Some("o@example.com"), "O", Role::Member).unwrap();
        db.set_grant(&mine.id, &other.id, Grant::Viewer, &u.id);
        assert_eq!(db.grants(&mine.id).len(), 1);
        db.delete_bot(&mine.id);
        assert!(db.grants(&mine.id).is_empty() && db.grant(&mine.id, &other.id).is_none());
    }

    #[test]
    fn audit_is_append_only() {
        let db = Db::open(&temp_path("audit").join("app.sqlite")).unwrap();
        db.record(&audit::Event::new(audit::Actor::operator(), "policy.updated").target("policy", "global").details(json!({ "mode": "ask" })));
        assert!(db.c().execute("UPDATE audit_events SET actor_id = 'x'", []).is_err());
        assert!(db.c().execute("UPDATE audit_events SET details = '{}' WHERE action = 'policy.updated'", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events WHERE action = 'policy.updated'", []).is_err());
        // No retention set: nothing can be deleted, however old.
        assert!(db.c().execute("DELETE FROM audit_events WHERE at < ?", [now() + 60_000]).is_err());
        assert_eq!(db.prune_audit().unwrap(), 0);
        assert_eq!(all_events(&db).len(), 2);
        let e = &all_events(&db)[0];
        assert_eq!((e.actor_kind.as_str(), e.actor_id.as_deref(), e.target_id.as_deref()), ("user", Some("operator"), Some("global")));
    }

    #[test]
    fn retention_deletes_only_rows_past_the_window() {
        let db = Db::open(&temp_path("retention").join("app.sqlite")).unwrap();
        let day = 86_400_000;
        db.c()
            .execute("INSERT INTO audit_events (at, actor_kind, action, outcome) VALUES (?, 'system', 'old.event', 'success')", [now() - 40 * day])
            .unwrap();
        assert_eq!(db.prune_audit().unwrap(), 0, "no retention saved yet");
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        db.set_audit_retention(Some(30));
        assert_eq!(db.audit_retention(), Some(30));
        // A cutoff inside the window would delete young rows, so the whole statement fails.
        assert!(db.c().execute("DELETE FROM audit_events WHERE at < ?", [now()]).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        // Rows on both sides of the cutoff, to the millisecond: pruning never trips the trigger.
        let start = now();
        let edge = start - 30 * day;
        for ms in (-2_000..=2_000).step_by(50) {
            db.c()
                .execute("INSERT INTO audit_events (at, actor_kind, action, outcome) VALUES (?, 'system', 'edge.event', 'success')", [edge + ms])
                .unwrap();
        }
        assert!(db.prune_audit().unwrap() >= 21, "the 40-day-old row and the edge rows older than a second");
        // The cutoff moves with the clock, so a slow runner ages more edge rows out.
        let late = (now() - start).max(1_000);
        let left: Vec<i64> = all_events(&db).iter().filter(|e| e.action == "edge.event").map(|e| e.at).collect();
        assert!(left.iter().all(|&at| at > edge - 1_000), "rows past the window are gone");
        let young = (-2_000..=2_000).step_by(50).filter(|&ms| ms >= late).count();
        assert_eq!(left.iter().filter(|&&at| at >= edge + late).count(), young, "rows inside the window stay");
        assert!(all_events(&db).iter().all(|e| e.action != "old.event"));
        db.set_audit_retention(None);
        assert_eq!(db.audit_retention(), None);
    }

    #[test]
    fn secrets_never_reach_the_audit_table() {
        let db = Db::open(&temp_path("scrub").join("app.sqlite")).unwrap();
        let subject = r#"mcp__chat__send {"message":"hi there","token":"hunter3"}"#;
        let e = audit::Event::new(audit::Actor::operator(), "x.y").details(json!({ "token": "abc", "cmd": "curl -u admin:hunter2 https://x", "subject": subject }));
        db.record(&e);
        let raw: String = db.c().query_row("SELECT details FROM audit_events WHERE action = 'x.y'", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("abc") && !raw.contains("hunter2") && !raw.contains("hunter3"), "{raw}");
        assert!(raw.contains("hi there"), "{raw}");
    }

    #[test]
    fn upgrades_first_audit_table() {
        let path = temp_path("upgrade").join("app.sqlite");
        // A database at schema version 1 (approvals), with audit rows in the first format.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE bots (id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL, shape TEXT NOT NULL,
               harness TEXT NOT NULL, model TEXT, session_id TEXT, primary_bot INTEGER NOT NULL DEFAULT 0,
               hidden INTEGER NOT NULL DEFAULT 0, unread INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);",
        )
        .unwrap();
        migrate_approvals(&c, true).unwrap();
        c.execute_batch(
            "INSERT INTO audit_events (at, actor, action, bot_id, target, detail) VALUES
               (1, 'user', 'policy.updated', NULL, 'global', '{\"after\":1}'),
               (2, 'bot', 'approval.requested', 'b1', 'a1', '{}'),
               (3, 'system', 'policy.denied', 'b1', NULL, '{}'),
               (4, 'user', 'rule.added', 'b1', 'r1', '{}');
             PRAGMA user_version = 1;",
        )
        .unwrap();
        drop(c);
        let db = Db::open(&path).unwrap();
        let rows = db.audit_events(&audit::Filter::default(), 10, true);
        let view: Vec<_> = rows
            .iter()
            .map(|e| (e.action.as_str(), e.actor_kind.as_str(), e.actor_id.as_deref(), e.target_type.as_deref(), e.target_id.as_deref(), e.outcome.as_str()))
            .collect();
        assert_eq!(
            view,
            [
                ("policy.initialized", "system", None, Some("policy"), Some("global"), "success"),
                ("policy.updated", "user", Some("operator"), Some("policy"), Some("global"), "success"),
                ("approval.requested", "bot", Some("b1"), Some("approval"), Some("a1"), "success"),
                ("policy.denied", "system", None, None, None, "denied"),
                ("rule.added", "user", Some("operator"), Some("rule"), Some("r1"), "success"),
                ("audit.schema_upgraded", "system", Some("migration"), Some("audit"), Some("actors"), "success"),
                ("policy.sandbox_initialized", "system", Some("migration"), Some("policy"), Some("global"), "success"),
            ]
        );
        assert_eq!(rows[1].details, json!({ "after": 1 }));
        // Still append-only, and ids keep counting up.
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        db.record(&audit::Event::new(audit::Actor::system("server"), "server.started"));
        assert!(all_events(&db)[0].id > rows.last().unwrap().id);
    }

    #[test]
    fn upgrade_adds_users_and_keeps_data() {
        let path = temp_path("users-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let bot = db.create_bot("Kept", "#fff", "waddle", "claude", None, true);
        // As a database from before users: no user tables, user_version 2.
        db.c()
            .execute_batch(&format!("{UNDO_BOT_ACLS} DROP TABLE push_devices; DROP TABLE user_identities; DROP TABLE login_codes; DROP TABLE sessions; DROP TABLE users; PRAGMA user_version = 2;"))
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.bot(&bot.id).map(|b| b.name), Some("Kept".into()));
        assert!(db.users().is_empty(), "the owner is made by botd at start, not by the migration");
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        // The schema refuses what the code never writes.
        let c = db.c();
        assert!(c.execute("INSERT INTO users (id, display_name, role, created_at, updated_at) VALUES ('x', 'X', 'root', 0, 0)", []).is_err());
        assert!(c.execute("INSERT INTO users (id, display_name, role, idp_issuer, created_at, updated_at) VALUES ('x', 'X', 'member', 'iss', 0, 0)", []).is_err());
    }

    #[test]
    fn upgrade_moves_a_users_idp_columns_into_identities() {
        let path = temp_path("identities-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, None, "Linked", Role::Member).unwrap();
        db.c()
            .execute_batch(&format!(
                "{UNDO_BOT_ACLS} DROP TABLE user_identities; ALTER TABLE sessions DROP COLUMN idp_subject;
                 UPDATE users SET idp_issuer = 'https://idp.example', idp_subject = 's1' WHERE id = '{}'; PRAGMA user_version = 3;",
                u.id
            ))
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let (i, found) = db.identity("https://idp.example", "s1").unwrap();
        assert_eq!((found.id.as_str(), i.provider.as_str()), (u.id.as_str(), "oidc"));
    }

    #[test]
    fn identities_link_once_and_keep_the_users_own_in_step() {
        let db = Db::open(&temp_path("identities").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Member).unwrap();
        let b = db.create_user(None, None, "B", Role::Member).unwrap();
        let new = |subject: &'static str| NewIdentity { provider: "entra", issuer: "https://login.example/t1/v2.0", subject, tenant: Some("t1"), email: None, created_by: Some("operator") };
        let first = db.link_identity(&a.id, &new("oid-1")).unwrap();
        let second = db.link_identity(&a.id, &new("oid-2")).unwrap();
        assert!(db.link_identity(&b.id, &new("oid-1")).is_err(), "one user per identity");
        assert!(db.link_identity(&a.id, &new("oid-1")).is_err(), "and once");
        assert_eq!(db.user(&a.id).unwrap().idp_subject.as_deref(), Some("oid-1"), "the first is the user's own");
        assert_eq!(db.identity("https://login.example/t1/v2.0", "oid-2").map(|(i, u)| (i.id, u.id)), Some((second.id.clone(), a.id.clone())));
        assert!(db.identity("https://login.example/t2/v2.0", "oid-2").is_none(), "the issuer is part of the key");
        db.touch_identity(&first.id, Some("new@example.com"), 42);
        db.touch_identity(&first.id, None, 43);
        let touched = db.identities(&a.id).into_iter().find(|i| i.id == first.id).unwrap();
        assert_eq!((touched.email.as_deref(), touched.last_login_at), (Some("new@example.com"), Some(43)));

        assert!(db.unlink_identity(&b.id, &first.id).is_none(), "only the owner's");
        assert_eq!(db.unlink_identity(&a.id, &first.id).map(|i| i.subject), Some("oid-1".into()));
        assert_eq!(db.user(&a.id).unwrap().idp_subject.as_deref(), Some("oid-2"), "the next one takes over");
        db.unlink_identity(&a.id, &second.id).unwrap();
        let u = db.user(&a.id).unwrap();
        assert_eq!((u.idp_issuer, u.idp_subject), (None, None));

        // Just in time: a user and their identity together, never merged by email.
        let jit = |email: Option<&'static str>, subject: &'static str| db.create_sso_user(email, "J", Role::Readonly, &new(subject));
        assert_eq!(jit(Some("A@example.com"), "oid-3").unwrap_err(), JitError::EmailTaken);
        assert!(db.identity("https://login.example/t1/v2.0", "oid-3").is_none(), "nothing half made");
        let j = jit(Some("j@example.com"), "oid-3").unwrap();
        assert_eq!((j.role, j.idp_subject.as_deref()), (Role::Readonly, Some("oid-3")));
        assert_eq!(jit(None, "oid-3").unwrap_err(), JitError::IdentityTaken);
    }

    #[test]
    fn audit_filters() {
        let db = Db::open(&temp_path("filters").join("app.sqlite")).unwrap();
        let ev = |actor: audit::Actor, action: &str| audit::Event::new(actor, action);
        db.record(&ev(audit::Actor::operator(), "bot.created").bot("b1"));
        db.record(&ev(audit::Actor::bot(Some("b1"), Some("A")), "routine.created").bot("b1"));
        db.record(&ev(audit::Actor::bot(Some("b2"), None), "routine.deleted").bot("b2"));
        db.record(&ev(audit::Actor::operator(), "auth.login_failed").outcome(audit::Outcome::Failure));
        let q = |f: audit::Filter| db.audit_events(&f, 100, false).into_iter().map(|e| e.action).collect::<Vec<_>>();
        let f = |k: &str, v: &str| audit::Filter::from_query(&[(k.to_string(), v.to_string())].into()).unwrap();
        assert_eq!(q(f("action", "routine.*")), ["routine.deleted", "routine.created"]);
        assert_eq!(q(f("action", "bot.created,auth.login_failed")), ["auth.login_failed", "bot.created"]);
        assert_eq!(q(f("actor", "bot:b1")), ["routine.created"]);
        assert_eq!(q(f("actor", "bot")).len(), 2);
        assert_eq!(q(f("outcome", "failure")), ["auth.login_failed"]);
        assert_eq!(q(f("bot", "b1")), ["routine.created", "bot.created"]);
        assert_eq!(q(f("to", "2000-01-01")).len(), 0);
        assert_eq!(q(f("from", "2000-01-01")).len(), 5);
        let newest = all_events(&db)[0].id;
        assert_eq!(q(audit::Filter { before: Some(newest), ..Default::default() }).len(), 4);
        let oldest_first = db.audit_events(&audit::Filter { after: Some(newest - 2), ..Default::default() }, 100, true);
        assert_eq!(oldest_first.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["routine.deleted", "auth.login_failed"]);
    }

    #[test]
    fn audit_filters_by_person_and_sign_in() {
        let db = Db::open(&temp_path("actor-filters").join("app.sqlite")).unwrap();
        let ada = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let person = |method: &str, idp: Option<&str>, session: &str| audit::Actor {
            id: Some(ada.id.clone()),
            email: Some("Ada@Example.com".into()),
            method: Some(method.into()),
            idp: idp.map(|_| "entra".into()),
            idp_provider: idp.map(String::from),
            subject: idp.map(|_| "https://login.example/t1/v2.0|oid-1".into()),
            session: Some(session.into()),
            ..audit::Actor::operator()
        };
        let mut gone = person("code", None, "s3");
        gone.id = Some("u-deleted".into());
        let ev = |actor: audit::Actor, action: &str| audit::Event::new(actor, action);
        db.record(&ev(person("sso", Some("work"), "s1"), "bot.created"));
        db.record(&ev(person("password", None, "s2"), "policy.updated"));
        db.record(&ev(audit::Actor::bot(Some("b1"), Some("A")).method("bot_token").on_behalf_of(&ada.id), "approval.requested"));
        db.record(&ev(audit::Actor::system("scheduler").on_behalf_of(&ada.id), "routine.fired"));
        db.record(&ev(gone, "auth.login"));
        let q = |f: audit::Filter| db.audit_events(&f, 100, false).into_iter().map(|e| e.action).collect::<Vec<_>>();
        let f = |k: &str, v: &str| {
            let mut f = audit::Filter::from_query(&[(k.to_string(), v.to_string())].into()).unwrap();
            f.resolve_users(|key| db.find_user(key).map(|u| u.id));
            f
        };
        assert_eq!(q(f("actor", &format!("user:{}", ada.id))), ["policy.updated", "bot.created"]);
        assert_eq!(q(f("actor", "user:ada@example.com")), ["policy.updated", "bot.created"], "an email finds the user");
        assert_eq!(q(f("actor", "user:ADA@example.com")), ["policy.updated", "bot.created"], "any case");
        let mut old_email = audit::Filter::from_query(&[("actor".into(), "user:ada@example.com".into())].into()).unwrap();
        old_email.resolve_users(|_| None);
        assert_eq!(q(old_email), ["auth.login", "policy.updated", "bot.created"], "no such user now: matches the recorded email");
        assert_eq!(q(f("method", "sso")), ["bot.created"]);
        assert_eq!(q(f("method", "password,bot_token")), ["approval.requested", "policy.updated"]);
        assert_eq!(q(f("idpProvider", "work")), ["bot.created"]);
        assert_eq!(q(f("idp", "entra")), ["bot.created"]);
        assert_eq!(q(f("subject", "https://login.example/t1/v2.0|oid-1")), ["bot.created"]);
        assert_eq!(q(f("session", "s2")), ["policy.updated"]);
        assert_eq!(q(f("onBehalfOf", &ada.id)), ["routine.fired", "approval.requested"]);
        assert_eq!(q(f("onBehalfOf", "ada@example.com")), ["routine.fired", "approval.requested"]);
    }

    #[test]
    fn bot_policy_inherits_and_overrides() {
        let db = Db::open(&temp_path("policy").join("app.sqlite")).unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let o = Override { mode: Some(Mode::Bypass), ..Default::default() };
        db.set_bot_override(&bot.id, Some(&o));
        assert_eq!(db.effective_policy(&bot.id).mode, Mode::Bypass);
        let mut g = db.global_policy();
        g.timeout_minutes = 5;
        db.set_global_policy(&g);
        assert_eq!(db.effective_policy(&bot.id).timeout_minutes, 5);
        db.set_bot_override(&bot.id, None);
        assert_eq!(db.effective_policy(&bot.id).mode, Mode::Ask);

        let global = db.add_rule(None, Action::Deny, "*", "*evil*", None);
        let mine = db.add_rule(Some(&bot.id), Action::Allow, "shell", "git push", Some("note"));
        assert_eq!(db.rules(Some(&bot.id)).len(), 2);
        assert_eq!(db.rules(None).len(), 1);
        db.delete_rule(&mine.id);
        assert_eq!(db.rules(Some(&bot.id)).iter().map(|r| r.id.clone()).collect::<Vec<_>>(), [global.id]);
    }

    #[test]
    fn first_decision_wins() {
        let db = Db::open(&temp_path("approval").join("app.sqlite")).unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let a = db.add_approval(&bot.id, "claude", "Bash", "shell", "git push", &json!({ "command": "git push" }), "git_push", "Pushes", now() + 1000);
        assert_eq!(db.approvals(Some("pending"), None, 10).len(), 1);
        assert!(db.finish_approval(&a.id, "approved", "user", None, None));
        assert!(!db.finish_approval(&a.id, "denied", "user", None, None));
        assert_eq!(db.approval(&a.id).unwrap().status, "approved");
        assert!(db.approvals(Some("pending"), None, 10).is_empty());
    }
}
