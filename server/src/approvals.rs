//! Approval queue. A Bot's harness asks before each tool call (`botctl hook`);
//! a risky call waits here until the user approves or denies it, or it times out
//! and is denied. Every outcome is written to the audit log and pushed over SSE.

use crate::adapters::short;
use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{now, Approval, Bot, NewRule};
use crate::policy::{self, glob_escape, Action, Call, Ctx, Verdict, TRUNCATED};
use crate::runner::App;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// Where a "remember" decision applies.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Remember {
    Bot,
    Global,
}

#[derive(Debug, PartialEq)]
pub enum DecideError {
    NotFound,
    /// Already approved, denied, expired, or cancelled.
    Closed(String),
    /// The call was too long to store whole, so it can't become an exact rule.
    TooLong,
}

/// Closes the approval if the waiting request goes away without an answer
/// (the harness was killed, or its hook gave up).
struct OnDrop {
    app: Arc<App>,
    id: String,
}

impl Drop for OnDrop {
    fn drop(&mut self) {
        self.app.settle(&self.id, "cancelled", &Who::system("approvals"), Some("The Bot stopped waiting"), None);
    }
}

impl App {
    /// The Bot's workspace is its owner's folder, so deleting in another user's folder
    /// counts as outside it (ADR 0029).
    pub fn policy_ctx(&self, bot: &Bot) -> Ctx {
        // A run on the owner's machine is judged by that machine's folders (ADR 0036).
        if let Some(ctx) = self.run_ctx(&bot.id) {
            return ctx;
        }
        let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| "/".into());
        // No folder of its own (an odd owner id): nothing is inside, so every delete asks.
        let workspace = self.workspace_for(&bot.owner_id).unwrap_or_else(|| self.cfg.workspace.join(crate::isolation::USERS).join(".none"));
        Ctx { workspace, home }
    }

    /// Decides one tool call. Risky calls wait for the user. Never fails open:
    /// anything other than an explicit allow comes back as a deny.
    pub async fn check(self: &Arc<Self>, bot: &Bot, harness: &str, tool: &str, input: Value, cwd: Option<PathBuf>) -> Verdict {
        let cap = self.note_hook(&bot.id);
        let p = self.db.effective_policy(&bot.id);
        let ctx = self.policy_ctx(bot);
        let call = Call::new(tool, input, cwd.unwrap_or_else(|| ctx.workspace.clone()));
        let v = policy::decide(&p, &self.db.rules(Some(&bot.id)), &call, &ctx);
        let shown = call.shown();
        let detail = || json!({ "tool": call.tool, "subject": shown, "class": v.class, "reason": v.reason, "rule": v.rule, "harness": harness });
        let verdict = |action: &str, outcome: Outcome| {
            let e = Event::new(Actor::system("policy"), action).bot(&bot.id).outcome(outcome).details(detail());
            match v.rule.as_deref() {
                Some(r) => e.target("rule", r),
                None => e,
            }
        };
        match v.action {
            Action::Allow => {
                if v.rule.is_some() {
                    self.db.record(&verdict("policy.allowed", Outcome::Success));
                }
                v
            }
            Action::Deny => {
                self.db.record(&verdict("policy.denied", Outcome::Denied));
                Verdict { reason: format!("SuperBot policy blocks this: {}. Don't try another way; tell the user what you wanted to do.", v.reason), ..v }
            }
            Action::Ask => {
                let mut wait = Duration::from_secs(p.timeout_minutes as u64 * 60);
                if let Some(cap) = cap {
                    wait = wait.min(cap);
                }
                let class = v.class.unwrap_or("");
                let a = self.db.add_approval(&bot.id, harness, &call.tool, call.kind.name(), &shown, &call.input, class, &v.reason, now() + wait.as_millis() as i64);
                let requested = Event::new(Actor::for_bot(bot), "approval.requested").target("approval", &a.id).bot(&bot.id);
                self.db.record(&requested.details(detail()));
                let (tx, rx) = oneshot::channel();
                self.approval_waiters.lock().unwrap().insert(a.id.clone(), tx);
                self.push_approval(&a);
                self.set_run_status(&bot.id, &format!("Waiting for approval: {}", short(&a.subject)));
                let guard = OnDrop { app: self.clone(), id: a.id.clone() };
                let answer = tokio::time::timeout(wait, rx).await;
                if answer.is_err() {
                    let mins = wait.as_secs().div_ceil(60);
                    self.settle(&a.id, "expired", &Who::system("approvals"), Some(&format!("No answer in {mins} minute{}", if mins == 1 { "" } else { "s" })), None);
                }
                drop(guard);
                self.set_run_status(&bot.id, "Working");
                let done = self.db.approval(&a.id).unwrap_or(a);
                let note = done.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
                let (action, reason) = match done.status.as_str() {
                    "approved" => (Action::Allow, "Approved by the user".to_string()),
                    "denied" => (Action::Deny, format!("The user denied this{note}. Don't try another way; ask the user what they want instead.")),
                    "expired" => (Action::Deny, format!("Nobody approved this in time{note}, so it was denied. Tell the user what you wanted to do and that it needs their approval.")),
                    _ => (Action::Deny, format!("This approval was cancelled{note}.")),
                };
                Verdict { action, reason, ..v }
            }
        }
    }

    /// The user's answer. `remember` saves an allow (or deny) rule for this exact call.
    pub fn decide(&self, id: &str, approve: bool, remember: Option<Remember>, note: Option<&str>, by: &Who) -> Result<Approval, DecideError> {
        let a = self.db.approval(id).ok_or(DecideError::NotFound)?;
        if a.status != "pending" {
            return Err(DecideError::Closed(a.status));
        }
        let status = if approve { "approved" } else { "denied" };
        let closed = || DecideError::Closed(self.db.approval(id).map(|a| a.status).unwrap_or_default());
        let Some(scope) = remember else {
            return self.settle(id, status, by, note, None).ok_or_else(closed);
        };
        if a.subject.ends_with(TRUNCATED) {
            return Err(DecideError::TooLong);
        }
        let bot = (scope == Remember::Bot).then_some(a.bot_id.as_str());
        let rule_note = format!("Remembered from approval {}", a.id);
        let pattern = glob_escape(&a.subject);
        let new = NewRule { bot_id: bot, action: if approve { Action::Allow } else { Action::Deny }, tool: &a.tool, pattern: &pattern, note: &rule_note };
        let r = self.db.finish_approval_with_rule(id, status, by.actor.kind.as_str(), note, &new).ok_or_else(closed)?;
        let added = by.event("rule.added").target("rule", &r.id).details(json!({ "rule": r, "from": a.id }));
        self.db.record(&match bot {
            Some(b) => added.bot(b),
            None => added,
        });
        self.after_settle(id, status, by, note, Some(&r.id)).ok_or_else(closed)
    }

    /// Closes a pending approval once, wakes its waiting hook, logs it, and tells the clients.
    pub fn settle(&self, id: &str, status: &str, by: &Who, note: Option<&str>, rule_id: Option<&str>) -> Option<Approval> {
        if !self.db.finish_approval(id, status, by.actor.kind.as_str(), note, rule_id) {
            return None;
        }
        self.after_settle(id, status, by, note, rule_id)
    }

    fn after_settle(&self, id: &str, status: &str, by: &Who, note: Option<&str>, rule_id: Option<&str>) -> Option<Approval> {
        if let Some(tx) = self.approval_waiters.lock().unwrap().remove(id) {
            let _ = tx.send(status == "approved");
        }
        let a = self.db.approval(id)?;
        let details = json!({ "subject": a.subject, "class": a.class, "tool": a.tool, "note": note, "rule": rule_id });
        self.db.record(&by.event(&format!("approval.{status}")).target("approval", id).bot(&a.bot_id).details(details));
        self.push_approval(&a);
        Some(a)
    }

    /// Cancels a Bot's pending approvals, e.g. when it is stopped or its run ends.
    pub fn cancel_approvals(&self, bot_id: &str, why: &str) {
        for a in self.db.approvals(Some("pending"), Some(bot_id), 1000) {
            self.settle(&a.id, "cancelled", &Who::system("approvals"), Some(why), None);
        }
    }

    /// After a restart nobody is waiting on old approvals: close them.
    pub fn expire_stale_approvals(&self) {
        for a in self.db.approvals(Some("pending"), None, 10_000) {
            self.settle(&a.id, "expired", &Who::system("approvals"), Some("Server restarted"), None);
        }
    }

    pub fn push_approval(&self, a: &Approval) {
        self.send(json!({ "type": "approval", "approval": a }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Mode, Override};

    fn app() -> Arc<App> {
        crate::runner::test_app()
    }

    fn user() -> Who {
        Who { actor: Actor::operator(), source: crate::audit::Source { ip: Some("192.0.2.9".into()), user_agent: None } }
    }

    fn audit_log(app: &App) -> Vec<crate::db::AuditEvent> {
        app.db.audit_events(&crate::audit::Filter::default(), 100, false)
    }

    async fn pending(app: &App) -> Approval {
        for _ in 0..200 {
            if let Some(a) = app.db.approvals(Some("pending"), None, 1).pop() {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no pending approval");
    }

    fn push(cmd: &str) -> Value {
        json!({ "command": cmd })
    }

    #[tokio::test]
    async fn safe_calls_run_without_asking() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let v = app.check(&bot, "claude", "Bash", push("ls -la"), None).await;
        assert_eq!(v.action, Action::Allow);
        assert!(app.db.approvals(None, None, 10).is_empty());
    }

    #[tokio::test]
    async fn approve_lets_the_call_run_and_is_audited() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let mut events = app.tx.subscribe();
        let task = tokio::spawn({
            let (app, bot) = (app.clone(), bot.clone());
            async move { app.check(&bot, "claude", "Bash", push("git push origin main"), None).await }
        });
        let a = pending(&app).await;
        assert_eq!((a.class.as_str(), a.subject.as_str()), ("git_push", "git push origin main"));
        let ev: Value = serde_json::from_str(&events.recv().await.unwrap()).unwrap();
        assert_eq!((ev["type"].as_str(), ev["approval"]["status"].as_str()), (Some("approval"), Some("pending")));

        let done = app.decide(&a.id, true, None, None, &user()).unwrap();
        assert_eq!(done.status, "approved");
        assert_eq!(task.await.unwrap().action, Action::Allow);
        assert!(matches!(app.decide(&a.id, false, None, None, &user()), Err(DecideError::Closed(s)) if s == "approved"));
        assert!(matches!(app.decide("nope", false, None, None, &user()), Err(DecideError::NotFound)));
        let ev = audit_log(&app);
        let (approved, requested) = (&ev[0], &ev[1]);
        assert_eq!((approved.action.as_str(), approved.actor_kind.as_str(), approved.actor_id.as_deref()), ("approval.approved", "user", Some("operator")));
        assert_eq!((approved.target_id.as_deref(), approved.ip.as_deref()), (Some(a.id.as_str()), Some("192.0.2.9")));
        assert_eq!(approved.details["subject"], "git push origin main");
        assert_eq!((requested.action.as_str(), requested.actor_kind.as_str(), requested.actor_id.as_deref()), ("approval.requested", "bot", Some(bot.id.as_str())));
    }

    #[tokio::test]
    async fn deny_and_remember() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let ask = |cmd: &'static str| {
            let (app, bot) = (app.clone(), bot.clone());
            tokio::spawn(async move { app.check(&bot, "claude", "Bash", push(cmd), None).await })
        };
        let task = ask("npm install left-pad");
        let a = pending(&app).await;
        app.decide(&a.id, false, Some(Remember::Bot), Some("not today"), &user()).unwrap();
        let v = task.await.unwrap();
        assert_eq!(v.action, Action::Deny);
        assert!(v.reason.contains("not today"));
        // The remembered deny now applies at once, without a new approval.
        assert_eq!(ask("npm install left-pad").await.unwrap().action, Action::Deny);
        assert_eq!(app.db.approvals(None, None, 10).len(), 1);

        // A remembered allow, scoped to every Bot, skips the ask for the same call.
        let task = ask("git push");
        let a = pending(&app).await;
        app.decide(&a.id, true, Some(Remember::Global), None, &user()).unwrap();
        assert_eq!(task.await.unwrap().action, Action::Allow);
        let other = app.db.create_bot("B", "#fff", "waddle", "codex", None, false);
        assert_eq!(app.check(&other, "codex", "Bash", push("git push"), None).await.action, Action::Allow);
        // Only the exact call is remembered: a different push still asks.
        let task = tokio::spawn({
            let app = app.clone();
            async move { app.check(&other, "codex", "Bash", push("git push --force"), None).await }
        });
        let a = pending(&app).await;
        assert_eq!(a.subject, "git push --force");
        app.decide(&a.id, false, None, None, &user()).unwrap();
        assert_eq!(task.await.unwrap().action, Action::Deny);
    }

    #[tokio::test]
    async fn unanswered_approvals_are_denied_after_the_timeout() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let o = Override { timeout_minutes: Some(1), ..Default::default() };
        app.db.set_bot_override(&bot.id, Some(&o));
        tokio::time::pause();
        let v = app.check(&bot, "claude", "Bash", push("git push"), None).await;
        assert_eq!(v.action, Action::Deny);
        assert!(v.reason.contains("in time"), "{}", v.reason);
        let a = app.db.approvals(None, None, 1).pop().unwrap();
        assert_eq!((a.status.as_str(), a.decided_by.as_deref()), ("expired", Some("system")));
        let expired = &audit_log(&app)[0];
        assert_eq!((expired.action.as_str(), expired.actor_kind.as_str(), expired.actor_id.as_deref()), ("approval.expired", "system", Some("approvals")));
    }

    #[tokio::test]
    async fn stopping_a_bot_cancels_its_approvals() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let task = tokio::spawn({
            let (app, bot) = (app.clone(), bot.clone());
            async move { app.check(&bot, "claude", "Bash", push("git push"), None).await }
        });
        let a = pending(&app).await;
        app.stop(&bot.id);
        assert_eq!(task.await.unwrap().action, Action::Deny);
        assert_eq!(app.db.approval(&a.id).unwrap().status, "cancelled");
    }

    #[tokio::test]
    async fn a_dropped_request_cancels_its_approval() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let task = tokio::spawn({
            let (app, bot) = (app.clone(), bot.clone());
            async move { app.check(&bot, "claude", "Bash", push("git push"), None).await }
        });
        let a = pending(&app).await;
        task.abort();
        let _ = task.await;
        assert_eq!(app.db.approval(&a.id).unwrap().status, "cancelled");
    }

    #[tokio::test]
    async fn restart_expires_old_approvals_and_bypass_skips_everything() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let a = app.db.add_approval(&bot.id, "claude", "Bash", "shell", "git push", &json!({}), "git_push", "Pushes", now() + 60_000);
        app.expire_stale_approvals();
        assert_eq!(app.db.approval(&a.id).unwrap().status, "expired");

        let o = Override { mode: Some(Mode::Bypass), ..Default::default() };
        app.db.set_bot_override(&bot.id, Some(&o));
        assert_eq!(app.check(&bot, "claude", "Bash", push("rm -rf /"), None).await.action, Action::Allow);
    }

    #[tokio::test]
    async fn deny_class_and_deny_rules_never_ask() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let mut g = app.db.global_policy();
        g.classes.insert("git_push".into(), Action::Deny);
        app.db.set_global_policy(&g);
        let v = app.check(&bot, "claude", "Bash", push("git push"), None).await;
        assert_eq!(v.action, Action::Deny);
        assert!(v.reason.starts_with("SuperBot policy blocks this"));
        app.db.add_rule(None, Action::Deny, "*", "*example.invalid*", None);
        assert_eq!(app.check(&bot, "claude", "WebFetch", json!({ "url": "https://example.invalid" }), None).await.action, Action::Deny);
        assert!(app.db.approvals(None, None, 10).is_empty());
        assert_eq!(audit_log(&app)[0].action, "policy.denied");
    }

    #[tokio::test]
    async fn a_decision_that_loses_saves_no_rule() {
        let app = app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let a = app.db.add_approval(&bot.id, "claude", "Bash", "shell", "git push", &json!({}), "git_push", "Pushes", now() + 60_000);
        // A timeout closes it between the user's read and their decision.
        assert!(app.db.finish_approval(&a.id, "expired", "system", None, None));
        assert!(app.db.finish_approval_with_rule(&a.id, "approved", "user", None, &NewRule { bot_id: Some(&bot.id), action: Action::Allow, tool: "Bash", pattern: "git push", note: "x" }).is_none());
        assert!(matches!(app.decide(&a.id, true, Some(Remember::Bot), None, &user()), Err(DecideError::Closed(s)) if s == "expired"));
        assert!(app.db.rules(Some(&bot.id)).is_empty());

        let cut = format!("git push{TRUNCATED}");
        let long = app.db.add_approval(&bot.id, "claude", "Bash", "shell", &cut, &json!({}), "git_push", "Pushes", now() + 60_000);
        assert!(matches!(app.decide(&long.id, true, Some(Remember::Bot), None, &user()), Err(DecideError::TooLong)));
        assert_eq!(app.db.approval(&long.id).unwrap().status, "pending");
        assert!(app.db.rules(Some(&bot.id)).is_empty());
    }
}
