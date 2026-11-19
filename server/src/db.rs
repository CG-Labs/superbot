//! SQLite storage: Bots, messages, routines, harness policy, approvals, and the
//! append-only audit log. One connection behind a mutex; every call is short.

use crate::acl::{Grant, Visibility};
use crate::audit;
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
}

pub struct Db(Mutex<Connection>);

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
}

impl User {
    pub fn active(&self) -> bool {
        self.status == "active"
    }
}

#[derive(Default)]
pub struct UserPatch {
    pub email: Option<Option<String>>,
    pub name: Option<String>,
    pub role: Option<Role>,
    pub status: Option<&'static str>,
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

#[derive(Debug, PartialEq)]
pub enum JitError {
    /// Another user has this email. Never merged by email: ask an admin to link instead.
    EmailTaken,
    /// Another sign-in linked this identity first.
    IdentityTaken,
    Database,
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
const MIGRATIONS: [fn(&Connection, bool) -> rusqlite::Result<()>; 7] =
    [migrate_approvals, migrate_audit_events, migrate_users, migrate_identities, migrate_bot_acls, migrate_audit_actors, migrate_last_login];

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
        Ok(Db(Mutex::new(c)))
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
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
        let id = crate::short_id();
        self.c()
            .execute(
                "INSERT INTO bots (id, name, color, shape, harness, model, primary_bot, created_at, owner_id, visibility) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, name, color, shape, harness, model, primary, now(), owner, visibility.as_str()],
            )
            .unwrap();
        self.bot(&id).unwrap()
    }

    // Bot ACLs (ADR 0017)

    pub fn set_bot_owner(&self, id: &str, owner: &str) {
        self.c().execute("UPDATE bots SET owner_id = ? WHERE id = ?", params![owner, id]).unwrap();
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
        let question = question.map(|q| redact::value(q.clone()).to_string());
        let c = self.c();
        c.execute(
            "INSERT INTO messages (bot_id, role, text, question, error, status, from_bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![bot_id, role, redact::text(text), question, error, status, from_bot, now()],
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
        self.c().execute("UPDATE messages SET question = ? WHERE id = ?", params![redact::value(q.clone()).to_string(), id]).unwrap();
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

    pub fn add_routine(&self, bot_id: &str, name: &str, cron: &str, instruction: &str) -> Routine {
        let id = crate::short_id();
        self.c()
            .execute(
                "INSERT INTO routines (id, bot_id, name, cron, instruction, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                params![id, bot_id, name, cron, instruction, now()],
            )
            .unwrap();
        self.routine(&id).unwrap()
    }

    pub fn update_routine(&self, id: &str, name: Option<&str>, cron: Option<&str>, instruction: Option<&str>, enabled: Option<bool>) {
        let c = self.c();
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            c.execute(&format!("UPDATE routines SET {col} = ? WHERE id = ?"), params![v, id]).unwrap();
        };
        if let Some(v) = name { set("name", &v) }
        if let Some(v) = cron { set("cron", &v) }
        if let Some(v) = instruction { set("instruction", &v) }
        if let Some(v) = enabled { set("enabled", &v) }
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

    #[allow(clippy::too_many_arguments)]
    pub fn add_approval(&self, bot_id: &str, harness: &str, tool: &str, kind: &str, subject: &str, input: &Value, class: &str, reason: &str, expires_at: i64) -> Approval {
        let id = crate::short_id();
        // Keep the row small: a huge file write is summarized by its subject anyway.
        let mut input = redact::value(input.clone()).to_string();
        if input.len() > 20_000 {
            input = serde_json::json!({ "truncated": input.chars().take(20_000).collect::<String>() }).to_string();
        }
        // Tool input can hold anything a Bot wrote (file contents, commands), so it is sealed at rest.
        let input = sealed::seal_field(&sealed::approval_context(&id), &input);
        self.c()
            .execute(
                "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![id, bot_id, harness, tool, kind, redact::text(subject), input, class, reason, now(), expires_at],
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
        self.c()
            .execute(
                "UPDATE approvals SET status = ?, decided_by = ?, note = ?, rule_id = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                params![status, by, note, rule_id, now(), id],
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
        let closed = tx
            .execute(
                "UPDATE approvals SET status = ?, decided_by = ?, note = ?, rule_id = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                params![status, by, note, rule_id, now(), id],
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

    /// Err when the email or id is taken.
    pub fn create_user(&self, id: Option<&str>, email: Option<&str>, name: &str, role: Role) -> Result<User, String> {
        let id = id.map(String::from).unwrap_or_else(|| format!("u{}", crate::short_id()));
        let at = now();
        let res = self.c().execute(
            "INSERT INTO users (id, email, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![id, email, name, role.as_str(), at, at],
        );
        match res {
            Ok(_) => Ok(self.user(&id).unwrap()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                Err("A user with that email already exists".into())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn update_user(&self, id: &str, p: UserPatch) -> Result<(), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            tx.execute(&format!("UPDATE users SET {col} = ?, updated_at = ? WHERE id = ?"), params![v, now(), id]).map(|_| ())
        };
        let res = (|| {
            if let Some(v) = &p.email { set("email", v)? }
            if let Some(v) = &p.name { set("display_name", v)? }
            if let Some(v) = p.role { set("role", &v.as_str())? }
            if let Some(v) = p.status { set("status", &v)? }
            Ok::<_, rusqlite::Error>(())
        })();
        match res {
            Ok(()) => tx.commit().map_err(|e| e.to_string()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                Err("A user with that email already exists".into())
            }
            Err(e) => Err(e.to_string()),
        }
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
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|_| JitError::Database)?;
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
    pub fn revoke_session(&self, id: &str, by: &str, reason: &str) -> bool {
        self.c()
            .execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL",
                params![now(), by, reason, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Revokes every session of a user and drops their unused sign-in codes. Returns how many sessions.
    pub fn revoke_user_sessions(&self, user_id: &str, by: &str, reason: &str) -> usize {
        let c = self.c();
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
        let text = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(&redact::text(&audit::redact_text(s)), max));
        let details = redact::value(audit::scrub(e.details.clone())).to_string();
        let a = &e.actor;
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
        assert_eq!(db.bots().len(), 1);
        // Reopening doesn't re-run the migrations.
        drop(db);
        let db = Db::open(&path).unwrap();
        let actions: Vec<String> = all_events(&db).into_iter().map(|e| e.action).collect();
        assert_eq!(actions, ["audit.schema_upgraded", "bot.acl_initialized", "policy.initialized"]);
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

    /// Rewinds a database to before last sign-ins (user_version 6).
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
        let (upgraded, old) = (&rows[0], rows.iter().find(|e| e.action == "bot.created").unwrap());
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
        db.c().execute_batch(&format!("{UNDO_LAST_LOGIN} PRAGMA user_version = 6;")).unwrap();
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
        let e = &all_events(&db)[1];
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
        db.set_bot_owner(&old.id, &u.id);
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
            .execute_batch(&format!("{UNDO_BOT_ACLS} DROP TABLE user_identities; DROP TABLE login_codes; DROP TABLE sessions; DROP TABLE users; PRAGMA user_version = 2;"))
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
