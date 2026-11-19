//! SQLite storage: Bots, messages, routines, harness policy, approvals, and the
//! audit log. One connection behind a mutex; every call is short.

use crate::policy::{Action, Mode, Override, Policy, Rule};
use crate::secrets::{redact, sealed};
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    pub at: i64,
    /// "user", "bot", or "system"
    pub actor: String,
    pub action: String,
    pub bot_id: Option<String>,
    pub target: Option<String>,
    pub detail: Value,
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
    let detail: String = r.get("detail")?;
    Ok(AuditEvent {
        id: r.get("id")?,
        at: r.get("at")?,
        actor: r.get("actor")?,
        action: r.get("action")?,
        bot_id: r.get("bot_id")?,
        target: r.get("target")?,
        detail: redact::value(serde_json::from_str(&detail).unwrap_or(Value::Null)),
    })
}

/// Schema changes after the first release, in order. `PRAGMA user_version` is how many ran.
/// Each gets `fresh`: true when this database was just created.
const MIGRATIONS: [fn(&Connection, bool) -> rusqlite::Result<()>; 1] = [migrate_approvals];

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

    // Audit: append-only (triggers refuse UPDATE and DELETE).

    pub fn audit(&self, actor: &str, action: &str, bot_id: Option<&str>, target: Option<&str>, detail: Value) {
        let _ = self.c().execute(
            "INSERT INTO audit_events (at, actor, action, bot_id, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            params![now(), actor, action, bot_id, target, redact::value(detail).to_string()],
        );
    }

    /// Newest first, older than `before` (an event id) when given.
    pub fn audit_events(&self, limit: i64, before: Option<i64>) -> Vec<AuditEvent> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM audit_events WHERE ?1 IS NULL OR id < ?1 ORDER BY id DESC LIMIT ?2").unwrap();
        s.query_map(params![before, limit], audit_row).unwrap().filter_map(Result::ok).collect()
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

    #[test]
    fn fresh_install_asks() {
        let db = Db::open(&temp_path("fresh").join("app.sqlite")).unwrap();
        assert_eq!(db.global_policy().mode, Mode::Ask);
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        assert_eq!(db.audit_events(10, None)[0].action, "policy.initialized");
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
        assert_eq!(db.audit_events(10, None).len(), 1);
    }

    #[test]
    fn audit_is_append_only() {
        let db = Db::open(&temp_path("audit").join("app.sqlite")).unwrap();
        db.audit("user", "policy.updated", None, Some("global"), json!({ "mode": "ask" }));
        assert!(db.c().execute("UPDATE audit_events SET actor = 'x'", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert_eq!(db.audit_events(10, None).len(), 2);
        let first = db.audit_events(10, None)[1].id;
        assert_eq!(db.audit_events(10, Some(first + 1)).len(), 1);
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
