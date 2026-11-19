//! SQLite storage: Bots, messages, routines, harness policy, approvals, and the
//! append-only audit log. One connection behind a mutex; every call is short.

use crate::audit;
use crate::policy::{Action, Mode, Override, Policy, Rule};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::Value;
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

/// One row of the audit log. See `audit.rs` and ADR 0008.
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
    /// The IdP subject, once people sign in with SSO.
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
}

fn approval_row(r: &Row) -> rusqlite::Result<Approval> {
    let input: String = r.get("input")?;
    Ok(Approval {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        harness: r.get("harness")?,
        tool: r.get("tool")?,
        kind: r.get("kind")?,
        subject: r.get("subject")?,
        input: serde_json::from_str(&input).unwrap_or(Value::Null),
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
        details: serde_json::from_str(&details).unwrap_or(Value::Null),
    })
}

/// Schema changes after the first release, in order. `PRAGMA user_version` is how many ran.
/// Each gets `fresh`: true when this database was just created.
const MIGRATIONS: [fn(&Connection, bool) -> rusqlite::Result<()>; 2] = [migrate_approvals, migrate_audit_events];

/// Structured audit events (ADR 0008): actor kind and id, target type and id,
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
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
        CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
          WHEN NOT EXISTS (
            SELECT 1 FROM settings
            WHERE key = 'audit_retention_days' AND CAST(value AS INTEGER) > 0
              AND OLD.at < (CAST(strftime('%s', 'now') AS INTEGER) - CAST(value AS INTEGER) * 86400) * 1000
          )
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;",
    )
}

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

    pub fn create_bot(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool) -> Bot {
        let id = crate::short_id();
        self.c()
            .execute(
                "INSERT INTO bots (id, name, color, shape, harness, model, primary_bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, name, color, shape, harness, model, primary, now()],
            )
            .unwrap();
        self.bot(&id).unwrap()
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

    pub fn message(&self, id: i64) -> Option<Message> {
        self.c().query_row("SELECT * FROM messages WHERE id = ?", [id], message_row).optional().ok().flatten()
    }

    pub fn add_message(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>) -> Message {
        self.add_message_from(bot_id, role, text, question, error, status, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_message_from(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>, from_bot: Option<&str>) -> Message {
        let c = self.c();
        c.execute(
            "INSERT INTO messages (bot_id, role, text, question, error, status, from_bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![bot_id, role, text, question.map(|q| q.to_string()), error, status, from_bot, now()],
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

    pub fn set_question(&self, id: i64, q: &Value) {
        self.c().execute("UPDATE messages SET question = ? WHERE id = ?", params![q.to_string(), id]).unwrap();
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
        let mut input = input.to_string();
        if input.len() > 20_000 {
            input = serde_json::json!({ "truncated": input.chars().take(20_000).collect::<String>() }).to_string();
        }
        self.c()
            .execute(
                "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![id, bot_id, harness, tool, kind, subject, input, class, reason, now(), expires_at],
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

    // Audit: append-only. There is no update or delete here; triggers refuse both,
    // except retention pruning of rows older than `audit_retention_days`.

    /// Writes one event. `details` is scrubbed of secrets; free text is clipped.
    pub fn record(&self, e: &audit::Event) {
        let o = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(s, max));
        let res = self.c().execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, actor_name, actor_subject, action, target_type, target_id, bot_id, outcome, ip, user_agent, details)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                now(),
                e.actor.kind.as_str(),
                o(&e.actor.id, 128),
                o(&e.actor.name, 128),
                o(&e.actor.subject, 256),
                audit::clip(&e.action, 64),
                o(&e.target_type, 32),
                o(&e.target_id, 128),
                o(&e.bot_id, 128),
                e.outcome.as_str(),
                o(&e.source.ip, 64),
                o(&e.source.user_agent, 256),
                audit::scrub(e.details.clone()).to_string(),
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
        for (col, v) in [("actor_kind", &f.actor_kind), ("actor_id", &f.actor_id), ("outcome", &f.outcome), ("bot_id", &f.bot_id)] {
            if let Some(v) = v {
                and(&format!("{col} = ?"), vec![V::Text(v.clone())]);
            }
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
    pub fn prune_audit(&self, cutoff: i64) -> rusqlite::Result<usize> {
        self.c().execute("DELETE FROM audit_events WHERE at < ?", [cutoff])
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
        // Reopening doesn't re-run the migration.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(all_events(&db).len(), 1);
    }

    #[test]
    fn audit_is_append_only() {
        let db = Db::open(&temp_path("audit").join("app.sqlite")).unwrap();
        db.record(&audit::Event::new(audit::Actor::operator(), "policy.updated").target("policy", "global").details(json!({ "mode": "ask" })));
        assert!(db.c().execute("UPDATE audit_events SET actor_id = 'x'", []).is_err());
        assert!(db.c().execute("UPDATE audit_events SET details = '{}' WHERE action = 'policy.updated'", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events WHERE action = 'policy.updated'", []).is_err());
        // No retention set: even pruning old rows is refused.
        assert!(db.prune_audit(now() + 60_000).is_err());
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
        assert!(db.prune_audit(now() - 30 * day).is_err(), "no retention saved yet");
        db.set_audit_retention(Some(30));
        assert_eq!(db.audit_retention(), Some(30));
        // A cutoff inside the window would delete young rows, so the whole statement fails.
        assert!(db.prune_audit(now()).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert_eq!(db.prune_audit(now() - 30 * day).unwrap(), 1);
        assert_eq!(all_events(&db).len(), 1);
        db.set_audit_retention(None);
        assert_eq!(db.audit_retention(), None);
    }

    #[test]
    fn secrets_never_reach_the_audit_table() {
        let db = Db::open(&temp_path("scrub").join("app.sqlite")).unwrap();
        let e = audit::Event::new(audit::Actor::operator(), "x.y").details(json!({ "token": "abc", "cmd": "curl -u admin:hunter2 https://x" }));
        db.record(&e);
        let raw: String = db.c().query_row("SELECT details FROM audit_events WHERE action = 'x.y'", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("abc") && !raw.contains("hunter2"), "{raw}");
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
            ]
        );
        assert_eq!(rows[1].details, json!({ "after": 1 }));
        // Still append-only, and ids keep counting up.
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        db.record(&audit::Event::new(audit::Actor::system("server"), "server.started"));
        assert!(all_events(&db)[0].id > rows.last().unwrap().id);
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
