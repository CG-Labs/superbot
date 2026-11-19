//! Approval queue. A Bot's harness asks before each tool call (`botctl hook`);
//! a risky call waits here until the user approves or denies it, or it times out
//! and is denied. Every outcome is written to the audit log and pushed over SSE.

use crate::adapters::short;
use crate::db::{now, Approval, Bot};
use crate::policy::{self, glob_escape, Action, Call, Ctx, Verdict};
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
}

/// Closes the approval if the waiting request goes away without an answer
/// (the harness was killed, or its hook gave up).
struct OnDrop {
    app: Arc<App>,
    id: String,
}

impl Drop for OnDrop {
    fn drop(&mut self) {
        self.app.settle(&self.id, "cancelled", "system", Some("The Bot stopped waiting"), None);
    }
}

impl App {
    pub fn policy_ctx(&self) -> Ctx {
        let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| "/".into());
        Ctx { workspace: self.cfg.workspace.clone(), home }
    }

    /// Decides one tool call. Risky calls wait for the user. Never fails open:
    /// anything other than an explicit allow comes back as a deny.
    pub async fn check(self: &Arc<Self>, bot: &Bot, harness: &str, tool: &str, input: Value, cwd: Option<PathBuf>) -> Verdict {
        let cap = self.note_hook(&bot.id);
        let p = self.db.effective_policy(&bot.id);
        let call = Call::new(tool, input, cwd.unwrap_or_else(|| self.cfg.workspace.clone()));
        let v = policy::decide(&p, &self.db.rules(Some(&bot.id)), &call, &self.policy_ctx());
        let detail = || json!({ "tool": call.tool, "subject": call.subject, "class": v.class, "reason": v.reason, "rule": v.rule, "harness": harness });
        match v.action {
            Action::Allow => {
                if v.rule.is_some() {
                    self.db.audit("system", "policy.allowed", Some(&bot.id), v.rule.as_deref(), detail());
                }
                v
            }
            Action::Deny => {
                self.db.audit("system", "policy.denied", Some(&bot.id), v.rule.as_deref(), detail());
                Verdict { reason: format!("SuperBot policy blocks this: {}. Don't try another way; tell the user what you wanted to do.", v.reason), ..v }
            }
            Action::Ask => {
                let mut wait = Duration::from_secs(p.timeout_minutes as u64 * 60);
                if let Some(cap) = cap {
                    wait = wait.min(cap);
                }
                let class = v.class.unwrap_or("");
                let a = self.db.add_approval(&bot.id, harness, &call.tool, call.kind.name(), &call.subject, &call.input, class, &v.reason, now() + wait.as_millis() as i64);
                self.db.audit("bot", "approval.requested", Some(&bot.id), Some(&a.id), detail());
                let (tx, rx) = oneshot::channel();
                self.approval_waiters.lock().unwrap().insert(a.id.clone(), tx);
                self.push_approval(&a);
                self.set_run_status(&bot.id, &format!("Waiting for approval: {}", short(&a.subject)));
                let guard = OnDrop { app: self.clone(), id: a.id.clone() };
                let answer = tokio::time::timeout(wait, rx).await;
                if answer.is_err() {
                    let mins = wait.as_secs().div_ceil(60);
                    self.settle(&a.id, "expired", "system", Some(&format!("No answer in {mins} minute{}", if mins == 1 { "" } else { "s" })), None);
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
    pub fn decide(&self, id: &str, approve: bool, remember: Option<Remember>, note: Option<&str>) -> Result<Approval, DecideError> {
        let a = self.db.approval(id).ok_or(DecideError::NotFound)?;
        if a.status != "pending" {
            return Err(DecideError::Closed(a.status));
        }
        let rule = remember.map(|scope| {
            let bot = (scope == Remember::Bot).then_some(a.bot_id.as_str());
            let action = if approve { Action::Allow } else { Action::Deny };
            let r = self.db.add_rule(bot, action, &a.tool, &glob_escape(&a.subject), Some(&format!("Remembered from approval {}", a.id)));
            self.db.audit("user", "rule.added", bot, Some(&r.id), json!({ "rule": r, "from": a.id }));
            r
        });
        let status = if approve { "approved" } else { "denied" };
        self.settle(id, status, "user", note, rule.as_ref().map(|r| r.id.as_str())).ok_or(DecideError::Closed("decided".into()))
    }

    /// Closes a pending approval once, wakes its waiting hook, logs it, and tells the clients.
    pub fn settle(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule_id: Option<&str>) -> Option<Approval> {
        if !self.db.finish_approval(id, status, by, note, rule_id) {
            return None;
        }
        if let Some(tx) = self.approval_waiters.lock().unwrap().remove(id) {
            let _ = tx.send(status == "approved");
        }
        let a = self.db.approval(id)?;
        self.db.audit(by, &format!("approval.{status}"), Some(&a.bot_id), Some(id), json!({ "subject": a.subject, "class": a.class, "note": note, "rule": rule_id }));
        self.push_approval(&a);
        Some(a)
    }

    /// Cancels a Bot's pending approvals, e.g. when it is stopped or its run ends.
    pub fn cancel_approvals(&self, bot_id: &str, why: &str) {
        for a in self.db.approvals(Some("pending"), Some(bot_id), 1000) {
            self.settle(&a.id, "cancelled", "system", Some(why), None);
        }
    }

    /// After a restart nobody is waiting on old approvals: close them.
    pub fn expire_stale_approvals(&self) {
        for a in self.db.approvals(Some("pending"), None, 10_000) {
            self.settle(&a.id, "expired", "system", Some("Server restarted"), None);
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

        let done = app.decide(&a.id, true, None, None).unwrap();
        assert_eq!(done.status, "approved");
        assert_eq!(task.await.unwrap().action, Action::Allow);
        assert!(matches!(app.decide(&a.id, false, None, None), Err(DecideError::Closed(s)) if s == "approved"));
        assert!(matches!(app.decide("nope", false, None, None), Err(DecideError::NotFound)));
        let actions: Vec<String> = app.db.audit_events(10, None).into_iter().map(|e| e.action).collect();
        assert_eq!(actions[..2], ["approval.approved", "approval.requested"]);
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
        app.decide(&a.id, false, Some(Remember::Bot), Some("not today")).unwrap();
        let v = task.await.unwrap();
        assert_eq!(v.action, Action::Deny);
        assert!(v.reason.contains("not today"));
        // The remembered deny now applies at once, without a new approval.
        assert_eq!(ask("npm install left-pad").await.unwrap().action, Action::Deny);
        assert_eq!(app.db.approvals(None, None, 10).len(), 1);

        // A remembered allow, scoped to every Bot, skips the ask for the same call.
        let task = ask("git push");
        let a = pending(&app).await;
        app.decide(&a.id, true, Some(Remember::Global), None).unwrap();
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
        app.decide(&a.id, false, None, None).unwrap();
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
        assert_eq!(app.db.audit_events(1, None)[0].action, "approval.expired");
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
        assert_eq!(app.db.audit_events(1, None)[0].action, "policy.denied");
    }
}
