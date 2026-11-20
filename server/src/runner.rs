//! Runs Bots: one task at a time per Bot, in order. Builds the system prompt
//! (identity, rules, memory), streams harness events to the web app, and saves replies.

use crate::adapters::{self, AbortReason, AgentEvent, Guard, RunInput};
use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{Bot, BotPatch, Db, Message};
use crate::machines::ControlPlane;
use crate::machines::route::{Job, Refusal, Target};
use crate::{isolation, paths};
use crate::policy::Mode;
use crate::screen::{self, Screens};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch};

/// How long after a guarded run's first shell tool the approval hook must have
/// called in. If it hasn't, the harness ignored the hook and the run is stopped.
const HOOK_GRACE: Duration = Duration::from_secs(5);

pub struct Config {
    pub data_dir: PathBuf,
    /// Holds one working folder per user (`users/<id>`, ADR 0029).
    pub workspace: PathBuf,
    /// The owner account's name, for Bots the operator owns.
    pub user_name: String,
    /// Added to PATH so Bots can run `botctl`.
    pub bin_dir: PathBuf,
    pub api_url: String,
    /// Signs each Bot's own `BOT_TOKEN` (`isolation::bot_token`). Made fresh at each start.
    pub bot_key: String,
    pub run_timeout: Duration,
    pub default_harness: String,
}

struct Run {
    abort: watch::Sender<AbortReason>,
    status: String,
    draft: String,
    /// Approval hook calls during this run.
    hooks: Arc<AtomicU32>,
    /// Longest an approval may wait: just under the harness's hook timeout.
    hook_wait: Option<Duration>,
}

#[derive(Default)]
struct BotState {
    queue: VecDeque<Message>,
    draining: bool,
    run: Option<Run>,
}

pub struct App {
    pub db: Db,
    pub cfg: Config,
    /// Every live update for the web app, as JSON text.
    pub tx: broadcast::Sender<String>,
    /// Each Bot's screen. None when this server has no display tools.
    pub screens: Option<Screens>,
    bots: Mutex<HashMap<String, BotState>>,
    /// Bots waiting on `botctl ask` or `botctl handoff`, by the message's id.
    waiters: Mutex<HashMap<i64, oneshot::Sender<String>>>,
    /// Tool calls waiting on the user, by approval id. true = approved.
    pub approval_waiters: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    /// Picks where each Bot runs: its owner's machine, or here (ADR 0029). Unset: here.
    pub control_plane: OnceLock<Arc<ControlPlane>>,
    closing: AtomicBool,
}

impl App {
    pub fn new(db: Db, cfg: Config, screens: Option<Screens>) -> Arc<App> {
        Arc::new(App {
            db,
            cfg,
            tx: broadcast::channel(1024).0,
            screens,
            bots: Mutex::default(),
            waiters: Mutex::default(),
            approval_waiters: Mutex::default(),
            control_plane: OnceLock::new(),
            closing: AtomicBool::new(false),
        })
    }

    /// Counts an approval hook call for the Bot's run. Returns how long an approval may wait.
    pub fn note_hook(&self, bot_id: &str) -> Option<Duration> {
        self.with_run(bot_id, |r| {
            r.hooks.fetch_add(1, Ordering::SeqCst);
            r.hook_wait
        })
    }

    pub fn set_run_status(&self, bot_id: &str, status: &str) {
        if self.with_run(bot_id, |r| { r.status = status.into(); true }) {
            self.send(json!({ "type": "status", "botId": bot_id, "working": true, "status": status }));
        }
    }

    pub fn is_running(&self, bot_id: &str) -> bool {
        self.state().get(bot_id).is_some_and(|s| s.run.is_some())
    }

    pub fn send(&self, v: Value) {
        let bot = ["/botId", "/bot/id", "/message/botId", "/approval/botId"].iter().find_map(|p| v.pointer(p).and_then(Value::as_str));
        let owner = bot.and_then(|b| self.db.bot_owner(b));
        let _ = self.tx.send(crate::secrets::redact::value_for(owner.as_deref().as_slice(), v).to_string());
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HashMap<String, BotState>> {
        self.bots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the web app sees for a Bot.
    pub fn bot_view(&self, b: &Bot) -> Value {
        let preview = self.db.last_message(&b.id).map(|m| {
            let t: String = m.text.chars().filter(|c| !"#*_`>[]".contains(*c)).collect();
            let t = adapters::short(&t);
            if t.is_empty() { m.question.and_then(|q| q["title"].as_str().map(String::from)).unwrap_or_default() } else { t }
        });
        let mut v = json!({
            "id": b.id, "name": b.name, "color": b.color, "shape": b.shape, "harness": b.harness, "model": b.model, "effort": b.effort,
            "primary": b.primary, "hidden": b.hidden, "unread": b.unread, "preview": preview.unwrap_or_default(), "working": false,
            "handoff": self.db.open_handoff(&b.id),
            "policy": self.db.effective_policy(&b.id).mode, "policyOverride": self.db.bot_override(&b.id).is_some(),
            "owner": self.db.user(&b.owner_id).map(|u| json!({ "id": u.id, "name": u.name })),
            "visibility": b.visibility,
        });
        if let Some(run) = self.state().get(&b.id).and_then(|s| s.run.as_ref()) {
            v["working"] = json!(true);
            let owner = [b.owner_id.as_str()];
            v["status"] = json!(crate::secrets::redact::text_for(&owner, &run.status));
            v["draft"] = json!(crate::secrets::redact::text_for(&owner, &run.draft));
        }
        v
    }

    pub fn push_bot(&self, id: &str) {
        if let Some(b) = self.db.bot(id) {
            self.send(json!({ "type": "bot", "bot": self.bot_view(&b) }));
        }
    }

    pub fn push_message(&self, m: &Message) {
        let bot = self.db.bot(&m.bot_id).map(|b| self.bot_view(&b));
        self.send(json!({ "type": "message", "message": m, "bot": bot }));
    }

    /// `DATA_DIR/bots/<id>`. None when the id isn't one plain folder name.
    pub fn bot_dir(&self, id: &str) -> Option<PathBuf> {
        paths::child(&paths::child(&paths::canonical(&self.cfg.data_dir)?, "bots")?, id)
    }
    fn memory_file(&self, id: &str) -> Option<PathBuf> {
        paths::child(&self.bot_dir(id)?, "MEMORY.md")
    }
    /// `DATA_DIR/users/<owner>/USER.md`: facts about one user, for that user's Bots only.
    pub fn user_file(&self, owner_id: &str) -> Option<PathBuf> {
        paths::child(&isolation::user_dir(&self.cfg.data_dir, owner_id)?, "USER.md")
    }

    /// `WORKSPACE_DIR/users/<owner>`, created: the folder every Bot of that user works in.
    pub fn workspace_for(&self, owner_id: &str) -> Option<PathBuf> {
        isolation::user_dir(&self.cfg.workspace, owner_id)
    }

    /// Who a Bot works for, by name.
    pub fn owner_name(&self, bot: &Bot) -> String {
        match self.db.user(&bot.owner_id) {
            Some(u) if u.id != crate::users::OPERATOR && !u.name.trim().is_empty() => u.name,
            _ => self.cfg.user_name.clone(),
        }
    }

    pub fn init_bot_files(&self, bot: &Bot) {
        if let Some(dir) = self.bot_dir(&bot.id) {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Some(mem) = self.memory_file(&bot.id)
            && !mem.exists()
        {
            let _ = std::fs::write(&mem, format!("# {}\n\n## Job\n\nNot set yet. Ask the user.\n\n## Rules\n\n## Work log\n", bot.name));
        }
        if let Some(user) = self.user_file(&bot.owner_id)
            && !user.exists()
        {
            let _ = std::fs::write(&user, format!("# About the user\n\n- Name: {}\n", self.owner_name(bot)));
        }
    }

    /// Where a Bot's run happens and what it gets: its owner's working folder, and
    /// the server-wide secrets plus its owner's, never another user's. `BOT_TOKEN`
    /// proves to botd which Bot is calling, so it can only act as itself.
    pub(crate) fn run_space(&self, bot: &Bot) -> Option<(PathBuf, HashMap<String, String>)> {
        let cwd = self.workspace_for(&bot.owner_id)?;
        let mut env: HashMap<String, String> =
            crate::secrets::global().harness_env_for(&bot.owner_id).into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        let token = isolation::bot_token(&self.cfg.bot_key, &bot.id, &bot.owner_id);
        crate::secrets::redact::register(&token);
        env.extend([
            ("BOT_ID".to_string(), bot.id.clone()),
            ("BOT_API".to_string(), self.cfg.api_url.clone()),
            ("BOT_TOKEN".to_string(), token),
            ("SUPERBOT_BOTCTL".to_string(), self.cfg.bin_dir.join("botctl").display().to_string()),
        ]);
        let path = std::env::var("PATH").unwrap_or_default();
        env.insert("PATH".into(), format!("{}:{path}", self.cfg.bin_dir.display()));
        Some((cwd, env))
    }

    pub fn enqueue(self: &Arc<Self>, msg: Message) {
        let bot_id = msg.bot_id.clone();
        let mut st = self.state();
        let s = st.entry(bot_id.clone()).or_default();
        s.queue.push_back(msg);
        if !s.draining {
            s.draining = true;
            tokio::spawn(self.clone().drain(bot_id));
        }
    }

    async fn drain(self: Arc<Self>, bot_id: String) {
        loop {
            if self.closing.load(Ordering::SeqCst) {
                return; // left as is: the next start picks it up
            }
            // Pop and "queue is empty, stop draining" happen under one lock, so nothing is dropped.
            let next = {
                let mut st = self.state();
                let m = st.get_mut(&bot_id).and_then(|s| s.queue.pop_front());
                if m.is_none() {
                    st.remove(&bot_id);
                }
                m
            };
            let Some(msg) = next else { break };
            let before = self.db.last_id();
            if let Some(bot) = self.db.bot(&bot_id) {
                self.run_one(bot, &msg).await;
            }
            if self.closing.load(Ordering::SeqCst) {
                return; // left "running": the next start reports it
            }
            self.db.set_status(msg.id, "done");
            if msg.role == "peer" {
                self.answer_peer(&msg, before);
            }
        }
        self.send(json!({ "type": "status", "botId": bot_id, "working": false }));
    }

    async fn run_one(self: &Arc<Self>, mut bot: Bot, msg: &Message) {
        let Some(shell_tool) = adapters::get(&bot.harness).map(|a| a.shell_tool()) else {
            return self.say(&bot.id, &format!("Unknown harness \"{}\".", bot.harness), true);
        };
        let Some(bot_dir) = self.bot_dir(&bot.id) else {
            return self.say(&bot.id, "This Bot's id isn't a safe folder name, so it can't run.", true);
        };
        let Some(space) = self.run_space(&bot) else {
            return self.say(&bot.id, "This Bot's owner id isn't a safe folder name, so it can't run.", true);
        };
        let by = self.requester(&bot, msg);
        if !self.route_here(&bot, msg, &by).await {
            return;
        }
        self.init_bot_files(&bot);
        self.db.set_status(msg.id, "running");
        let started = Instant::now();
        let from = || msg.from_bot.as_deref().and_then(|id| self.db.bot(id)).map(|b| format!("{} (id {})", b.name, b.id)).unwrap_or("another Bot".into());
        let prompt = match msg.role.as_str() {
            "routine" => format!("(Scheduled routine) {}", msg.text),
            "peer" => format!("(Message from {}, another Bot. Your reply goes back to them, not the user.)\n\n{}", from(), msg.text),
            "reply" => format!("(Reply from {} to what you asked earlier. Tell the user what matters.)\n\n{}", from(), msg.text),
            _ => msg.text.clone(),
        };

        for attempt in 0..2 {
            let (abort_tx, abort_rx) = watch::channel(None);
            // Ask mode: the harness calls `botctl hook` before every tool. Its hook timeout
            // stays above our wait, so the hook is never killed into failing open. A harness
            // that caps hook timeouts gets a shorter wait instead.
            let policy = self.db.effective_policy(&bot.id);
            let guard = (policy.mode == Mode::Ask).then(|| guard(&self.cfg.bin_dir, &bot.harness, policy.timeout_minutes));
            let hooks = Arc::new(AtomicU32::new(0));
            self.state().entry(bot.id.clone()).or_default().run = Some(Run {
                abort: abort_tx.clone(),
                status: "Thinking".into(),
                draft: String::new(),
                hooks: hooks.clone(),
                hook_wait: guard.as_ref().map(|g| g.wait),
            });
            self.send(json!({ "type": "status", "botId": bot.id, "working": true, "status": "Thinking" }));
            let timeout = self.cfg.run_timeout;
            let timer = tokio::spawn({
                let abort_tx = abort_tx.clone();
                async move {
                    tokio::time::sleep(timeout).await;
                    abort_tx.send_if_modified(|r| r.get_or_insert("timeout") == &"timeout");
                }
            });

            let (cwd, mut env) = space.clone();
            if let Some(screens) = &self.screens
                && let Some(info) = screens.ensure(&bot.id, |id| self.is_running(id)).await
            {
                env.extend(screen::bot_env(&info, &bot.id, &bot_dir));
            }
            let invoked = json!({
                "harness": bot.harness, "model": bot.model, "effort": bot.effort, "policy": policy.mode,
                "guarded": guard.is_some(), "resumed": bot.session_id.is_some(), "attempt": attempt + 1,
                "trigger": msg.role, "messageId": msg.id,
            });
            self.db.record(&by.event("harness.invoked").target("message", &msg.id.to_string()).bot(&bot.id).details(invoked));
            let input = RunInput {
                prompt: prompt.clone(),
                system: self.system_prompt(&bot),
                session_id: bot.session_id.clone(),
                cwd,
                model: bot.model.clone(),
                effort: bot.effort.clone(),
                env,
                state_dir: bot_dir.clone(),
                guard: guard.clone(),
            };

            let mut errors: Vec<String> = Vec::new();
            let mut replies = 0;
            let id = bot.id.clone();
            let mut canary: Option<tokio::task::JoinHandle<()>> = None;
            let mut saw_shell = false;
            adapters::run(adapters::get(&bot.harness).unwrap(), input, abort_rx.clone(), |e| match e {
                AgentEvent::Session(s) => {
                    if self.db.bot(&id).and_then(|b| b.session_id).as_deref() != Some(&s) {
                        self.db.update_bot(&id, BotPatch { session_id: Some(Some(s)), ..Default::default() });
                    }
                }
                AgentEvent::TextDelta(t) => {
                    let draft = self.with_run(&id, |r| { r.draft.push_str(&t); r.draft.clone() });
                    self.send(json!({ "type": "draft", "botId": id, "text": draft }));
                }
                AgentEvent::Text(t) => {
                    self.with_run(&id, |r| r.draft.clear());
                    replies += 1;
                    self.say(&id, &t, false);
                }
                AgentEvent::Tool { name, detail } => {
                    // Fail closed: a guarded harness that runs a shell tool without ever
                    // calling the hook isn't enforcing approvals, so stop it.
                    if guard.is_some() && canary.is_none() && name.eq_ignore_ascii_case(shell_tool) {
                        saw_shell = true;
                        let (hooks, abort) = (hooks.clone(), abort_tx.clone());
                        canary = Some(tokio::spawn(async move {
                            tokio::time::sleep(HOOK_GRACE).await;
                            if hooks.load(Ordering::SeqCst) == 0 {
                                abort.send_if_modified(|r| r.get_or_insert("unguarded") == &"unguarded");
                            }
                        }));
                    }
                    let status = tool_label(&name, &detail);
                    self.with_run(&id, |r| r.status = status.clone());
                    self.send(json!({ "type": "status", "botId": id, "working": true, "status": status }));
                }
                AgentEvent::Error(m) => errors.push(m),
            })
            .await;
            timer.abort();
            if let Some(c) = canary {
                c.abort();
            }
            // A run that ends before the canary fires still has to report a missing hook.
            if saw_shell && hooks.load(Ordering::SeqCst) == 0 {
                abort_tx.send_if_modified(|r| r.get_or_insert("unguarded") == &"unguarded");
            }
            self.cancel_approvals(&id, "The task ended");
            // Done running. The stream may have ended without a final block: keep what was streamed.
            let draft = self.state().get_mut(&id).and_then(|s| s.run.take()).map(|r| r.draft).unwrap_or_default();
            if !draft.trim().is_empty() {
                replies += 1;
                self.say(&id, &draft, false);
            }

            // The harness lost its session (e.g. its files were wiped): start fresh once.
            let lost = errors.iter().any(|m| {
                let m = m.to_lowercase();
                m.contains("no conversation found")
                    || m.contains("no session found")
                    || ((m.contains("session") || m.contains("conversation"))
                        && (m.contains("not found") || m.contains("no such") || m.contains("does not exist")))
            });
            if lost && bot.session_id.is_some() && replies == 0 && attempt == 0 {
                self.db.update_bot(&id, BotPatch { session_id: Some(None), ..Default::default() });
                bot.session_id = None;
                continue;
            }

            let reason = *abort_rx.borrow();
            let (result, outcome) = match reason {
                Some("shutdown") => ("interrupted", Outcome::Failure),
                Some("stopped") => ("stopped", Outcome::Failure),
                Some(r @ ("unguarded" | "policy")) => (r, Outcome::Denied),
                Some("timeout") => ("timeout", Outcome::Failure),
                _ if !errors.is_empty() => ("error", Outcome::Failure),
                _ => ("done", Outcome::Success),
            };
            let finished = json!({
                "result": result, "durationMs": started.elapsed().as_millis() as u64, "replies": replies,
                "attempts": attempt + 1, "trigger": msg.role, "messageId": msg.id,
            });
            self.db.record(&by.event("bot.run_finished").target("message", &msg.id.to_string()).bot(&bot.id).outcome(outcome).details(finished));
            match reason {
                Some("shutdown") => {}
                Some("stopped") => self.say(&id, "Stopped.", true),
                Some("unguarded") => self.say(
                    &id,
                    &format!(
                        "I stopped: {} ran a command without checking SuperBot's approval gate, so approvals aren't enforced for me. \
                         Update the {} CLI, or set my approvals to bypass (dev only).",
                        bot.harness, bot.harness
                    ),
                    true,
                ),
                Some("policy") => self.say(
                    &id,
                    "I stopped: approvals were turned on while I was working without them. Send the task again and I'll ask before risky steps.",
                    true,
                ),
                Some("timeout") => {
                    let mins = self.cfg.run_timeout.as_secs() / 60;
                    self.say(&id, &format!("I hit the {mins} minute limit for one task and stopped."), true)
                }
                _ if !errors.is_empty() => self.say(&id, &errors.join("\n\n"), true),
                _ if replies == 0 => self.say(&id, "Done.", false),
                _ => {}
            }
            return;
        }
    }

    /// True when the Bot runs on this server. Otherwise the message went to its owner's
    /// own machine, or the run was refused and the Bot said why. Never another user's
    /// machine, and never here instead when routing is on.
    async fn route_here(&self, bot: &Bot, msg: &Message, by: &Who) -> bool {
        let Some(cp) = self.control_plane.get() else { return true };
        let refused = |r: Refusal, machine: Option<&str>| {
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            self.db.record(&e.details(json!({ "reason": r.reason(), "owner": bot.owner_id, "machine": machine, "messageId": msg.id })));
            self.say(&bot.id, &r.message(), true);
            false
        };
        match cp.route(&self.db, &bot.owner_id) {
            Ok(Target::Local) => true,
            Err(r) => refused(r, None),
            Ok(Target::Machine(to)) => {
                let job = Job { bot_id: bot.id.clone(), owner_id: bot.owner_id.clone(), message_id: msg.id };
                match cp.link.dispatch(&to, job).await {
                    Ok(()) => {
                        let e = by.event("bot.run_routed").target("message", &msg.id.to_string()).bot(&bot.id);
                        self.db.record(&e.details(json!({ "owner": bot.owner_id, "machine": to.machine_id, "link": cp.link.name(), "messageId": msg.id })));
                        false
                    }
                    Err(e) => refused(Refusal::Unreachable(e), Some(&to.machine_id)),
                }
            }
        }
    }

    /// Who a run is for: whoever queued its message. Routines run as the scheduler,
    /// and replies as the Bot that answered, both for their Bot's owner; messages
    /// queued before per-user actors (ADR 0019) as the runner.
    fn requester(&self, bot: &Bot, msg: &Message) -> Who {
        if let Some(by) = &msg.requested_by {
            return by.clone();
        }
        let actor = match msg.role.as_str() {
            "routine" => Actor::system("scheduler").on_behalf_of(&bot.owner_id),
            "reply" => match msg.from_bot.as_deref().and_then(|id| self.db.bot(id)) {
                Some(b) => Actor::for_bot(&b),
                None => Actor::bot(msg.from_bot.as_deref(), None),
            },
            _ => Actor::system("runner").on_behalf_of(&bot.owner_id),
        };
        Who { actor, source: Default::default() }
    }

    fn with_run<T: Default>(&self, bot_id: &str, f: impl FnOnce(&mut Run) -> T) -> T {
        self.state().get_mut(bot_id).and_then(|s| s.run.as_mut()).map(f).unwrap_or_default()
    }

    /// Another Bot asks this one something. Resolves with the reply, or None if it
    /// takes longer than `wait`; then the reply is delivered to the asker later.
    pub async fn ask(self: &Arc<Self>, from: &Bot, to: &Bot, text: &str, wait: Duration, by: &Who) -> Option<String> {
        let mut msg = self.db.add_message_from(&to.id, "peer", text, None, false, Some("queued"), Some(&from.id));
        self.db.set_requested_by(msg.id, by);
        msg.requested_by = Some(by.clone());
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(msg.id, tx);
        self.push_message(&msg);
        self.enqueue(msg.clone());
        let reply = tokio::time::timeout(wait, rx).await.ok().and_then(Result::ok);
        if reply.is_none() {
            self.waiters.lock().unwrap().remove(&msg.id);
        }
        reply
    }

    /// The Bot needs the user on its screen (a login, 2FA, a CAPTCHA). Posts a card
    /// with "Done" and waits for the answer, or None after `wait`; then the answer
    /// reaches the Bot later as a normal message.
    pub async fn handoff(&self, bot: &Bot, text: &str, wait: Duration) -> Option<String> {
        let q = json!({ "title": text, "options": ["Done", "I can't right now"], "handoff": true });
        let m = self.db.add_message(&bot.id, "bot", "", Some(&q), false, None);
        self.db.update_bot(&bot.id, BotPatch { unread: Some(true), ..Default::default() });
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(m.id, tx);
        self.push_message(&m);
        let card = m.id.to_string();
        self.db.record(&Event::new(Actor::for_bot(bot), "handoff.requested").target("handoff", &card).bot(&bot.id));
        let answer = tokio::time::timeout(wait, rx).await.ok().and_then(Result::ok);
        if answer.is_none() && self.waiters.lock().unwrap().remove(&m.id).is_some() {
            let e = Event::new(Actor::system("handoff"), "handoff.timed_out").target("handoff", &card).bot(&bot.id);
            self.db.record(&e.details(json!({ "waitedSeconds": wait.as_secs() })));
        }
        answer
    }

    /// Takes the waiter for a handoff card, if its Bot is still waiting.
    pub fn take_handoff(&self, message_id: i64) -> Option<oneshot::Sender<String>> {
        let is_handoff = self.db.message(message_id).and_then(|m| m.question).is_some_and(|q| q["handoff"] == json!(true));
        if is_handoff { self.waiters.lock().unwrap().remove(&message_id) } else { None }
    }

    /// Sends the asked Bot's reply to whoever asked: the waiting `botctl ask`,
    /// or, if it gave up waiting, as a new message in the asker's queue.
    fn answer_peer(self: &Arc<Self>, msg: &Message, before: i64) {
        let texts: Vec<String> = self.db.replies_after(&msg.bot_id, before).into_iter().map(|m| m.text).collect();
        let reply = if texts.is_empty() { "(No reply.)".to_string() } else { texts.join("\n\n") };
        let waiter = self.waiters.lock().unwrap().remove(&msg.id);
        let unsent = match waiter {
            Some(tx) => tx.send(reply).err(),
            None => Some(reply),
        };
        if let Some(reply) = unsent {
            let Some(asker) = msg.from_bot.as_deref().filter(|id| self.db.bot(id).is_some()) else { return };
            let m = self.db.add_message_from(asker, "reply", &reply, None, false, Some("queued"), Some(&msg.bot_id));
            self.push_message(&m);
            self.enqueue(m);
        }
    }

    /// Saves one Bot chat bubble. A trailing ```question block becomes a choice card.
    pub fn say(&self, bot_id: &str, text: &str, error: bool) {
        let (text, question) = split_question(text);
        let m = self.db.add_message(bot_id, "bot", text.trim(), question.as_ref(), error, None);
        self.db.update_bot(bot_id, BotPatch { unread: Some(true), ..Default::default() });
        self.push_message(&m);
    }

    /// Stops the current task and drops queued ones.
    pub fn stop(&self, bot_id: &str) {
        {
            let mut st = self.state();
            if let Some(s) = st.get_mut(bot_id) {
                for m in s.queue.drain(..) {
                    self.db.set_status(m.id, "done");
                }
                if let Some(r) = &s.run {
                    r.abort.send_if_modified(|v| v.get_or_insert("stopped") == &"stopped");
                }
            }
        }
        self.cancel_approvals(bot_id, "The Bot was stopped");
    }

    /// After a policy change: a run that started in bypass has no approval hook, so
    /// once its Bot is in ask mode it must stop rather than keep acting unchecked.
    pub fn stop_unguarded_runs(&self) {
        let unguarded: Vec<String> = self.state().iter().filter(|(_, s)| s.run.as_ref().is_some_and(|r| r.hook_wait.is_none())).map(|(id, _)| id.clone()).collect();
        for id in unguarded {
            if self.db.effective_policy(&id).mode != Mode::Ask {
                continue;
            }
            if let Some(r) = self.state().get(&id).and_then(|s| s.run.as_ref()).filter(|r| r.hook_wait.is_none()) {
                r.abort.send_if_modified(|v| v.get_or_insert("policy") == &"policy");
            }
        }
    }

    /// Kills running agents. Queued messages run after the restart.
    pub fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        for s in self.state().values() {
            if let Some(r) = &s.run {
                r.abort.send_if_modified(|v| v.get_or_insert("shutdown") == &"shutdown");
            }
        }
    }

    pub fn is_idle(&self) -> bool {
        self.state().values().all(|s| s.run.is_none())
    }

    /// After a restart: queued messages run. Interrupted ones are reported, not
    /// re-run, because re-running could repeat actions like sending an email.
    pub fn recover(self: &Arc<Self>) {
        self.expire_stale_approvals();
        for m in self.db.pending() {
            if self.db.bot(&m.bot_id).is_none() {
                continue;
            }
            if m.status.as_deref() == Some("running") {
                self.db.set_status(m.id, "done");
                self.say(&m.bot_id, "A server restart interrupted me before I finished. Send it again if you still need it.", true);
            } else {
                self.enqueue(m);
            }
        }
    }

    pub(crate) fn system_prompt(&self, bot: &Bot) -> String {
        let read = |p: &Option<PathBuf>| p.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default().trim().to_string();
        let (mem_file, user_file) = (self.memory_file(&bot.id), self.user_file(&bot.owner_id));
        // Only the Bots its owner can see: a Bot acts for its owner (ADR 0017).
        let others: Vec<String> = crate::acl::Viewer::owner_of(&self.db, bot)
            .bots(&self.db)
            .into_iter()
            .filter(|(b, _)| b.id != bot.id)
            .map(|(b, _)| format!("- {} (id {})", b.name, b.id))
            .collect();
        let primary = if bot.primary {
            " You are their primary Bot: their main point of contact. You help them decide which Bot should own which job."
        } else {
            ""
        };
        format!(
            r#"You are {name}, an AI teammate of {user}.{primary}
They talk to you in a chat app, like messaging a coworker. Finish work end to end.

## Your computer
- You run on a Linux computer you share with {user}'s other Bots. Your working folder is {ws}; it belongs to {user}.
- Keep {user}'s work inside it, in clear project folders. Other people's folders on this computer aren't yours to open.

## Memory
- Your memory file: {mem_path}. It holds your job, the user's rules and preferences for you, and a short dated log of important work.
- Facts about {user}, shared by all of their Bots: {user_path}. Name, time zone, and similar.
- Update these files yourself when you learn something lasting, without asking. Keep them short. Never store passwords, keys, or card numbers.
- Current contents:
<memory>
{mem}
</memory>
<user>
{user_facts}
</user>

## Routines
- For recurring or scheduled work, use `{botctl}`. Run `{botctl} help` to see how.
{screen}
## Style
- Reply like a teammate in chat: short, plain English. Markdown is fine.
- Each separate text block you write is shown as its own chat bubble. Before long work, send a one-line heads-up.
- Ask before anything you can't undo: sending messages, publishing, deleting, paying.{approvals}
- To ask a multiple-choice question, end your reply with this block, and nothing after it:
```question
{{"title": "Your question?", "options": ["First", "Second", "Third"]}}
```

## Other Bots
{others}
- To ask another Bot something or hand it a task, run: {botctl} ask "<Bot name or id>" "<message>". It prints their reply. It can take minutes, so give the command a long timeout (10 minutes). If they take longer, their reply arrives later as a new message.
- Only loop in another Bot when the user asks or it clearly helps. Never ask the Bot that is asking you.

Current time: {now}."#,
            name = bot.name,
            // Full path: some harnesses run commands in a login shell that resets PATH.
            botctl = self.cfg.bin_dir.join("botctl").display(),
            screen = if self.screens.is_some() { screen_prompt(&self.cfg.bin_dir.join("botctl").display().to_string()) } else { String::new() },
            user = self.owner_name(bot),
            approvals = if self.db.effective_policy(&bot.id).mode == Mode::Ask {
                "\n- Risky actions (destructive commands, deleting outside your folder, sending messages, installing software, git push) \
                 pause until the user approves them in the app. If one is denied, don't try another way to do it; tell the user what you wanted to do."
            } else {
                ""
            },
            ws = self.workspace_for(&bot.owner_id).unwrap_or_default().display(),
            mem_path = mem_file.clone().unwrap_or_default().display(),
            user_path = user_file.clone().unwrap_or_default().display(),
            mem = read(&mem_file),
            user_facts = read(&user_file),
            others = if others.is_empty() { "None yet.".into() } else { others.join("\n") },
            now = chrono::Local::now().format("%A, %B %-d, %Y, %H:%M (UTC%:z)"),
        )
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The approval gate for one run. The hook timeout stays a minute above the wait.
fn guard(bin_dir: &Path, harness: &str, timeout_minutes: u32) -> Guard {
    let mut wait = Duration::from_secs(timeout_minutes as u64 * 60 + 60);
    if let Some(cap) = adapters::get(harness).and_then(|a| a.max_hook_secs()) {
        wait = wait.min(Duration::from_secs(cap.saturating_sub(60).max(1)));
    }
    let botctl = bin_dir.join("botctl").display().to_string();
    Guard { command: format!("{} hook {harness}", shell_quote(&botctl)), timeout_secs: wait.as_secs() + 60, wait }
}

#[cfg(test)]
pub fn test_app() -> Arc<App> {
    let dir = crate::db::temp_path("app");
    let db = Db::open(&dir.join("app.sqlite")).unwrap();
    let workspace = dir.join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    App::new(
        db,
        Config {
            data_dir: dir.clone(),
            workspace,
            user_name: "Tester".into(),
            bin_dir: dir,
            api_url: "http://127.0.0.1:1".into(),
            bot_key: crate::random_hex(16),
            run_timeout: Duration::from_secs(60),
            default_harness: "claude".into(),
        },
        None,
    )
}

/// Splits off a trailing ```question {json}``` block.
fn split_question(text: &str) -> (&str, Option<Value>) {
    let t = text.trim_end();
    let Some(start) = t.rfind("```question") else { return (text, None) };
    let Some(body) = t[start + 11..].strip_suffix("```") else { return (text, None) };
    let Ok(q) = serde_json::from_str::<Value>(body.trim()) else { return (text, None) };
    let (Some(title), Some(opts)) = (q["title"].as_str(), q["options"].as_array()) else { return (text, None) };
    let options: Vec<String> = opts.iter().take(6).map(|o| o.as_str().map(String::from).unwrap_or(o.to_string())).collect();
    (&t[..start], Some(json!({ "title": title, "options": options })))
}

fn tool_label(name: &str, detail: &str) -> String {
    let n = name.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| n.contains(w));
    let verb = if has(&["bash", "shell", "command", "terminal"]) {
        "Running".to_string()
    } else if has(&["read", "view"]) {
        "Reading".into()
    } else if has(&["write", "edit", "patch", "file_change"]) {
        "Editing".into()
    } else if has(&["search", "grep", "glob", "find"]) {
        "Searching".into()
    } else if has(&["web", "fetch", "browse"]) {
        "Browsing".into()
    } else {
        format!("Using {name}")
    };
    if detail.is_empty() { verb } else { format!("{verb}: {detail}") }
}

/// How to use the Bot's screen. Tools are plain CLIs, so this works on every harness.
fn screen_prompt(botctl: &str) -> String {
    format!(
        r#"
## Your screen
- You have your own screen with a browser. The user can watch it live and take over.
- Prefer APIs and command-line tools. Use the browser for sites that have no API.
- Websites: `agent-browser`. Before your first use in a task, run `agent-browser skills get core` and follow it, with one exception: your session and browser profile are already set for you, so never pass `--session`, `--profile`, or `--headed`, and never create other sessions. Your sign-ins persist between tasks.
- Desktop apps: `agent-desktop`. Before your first use, run `agent-desktop skills get desktop`.
- When you need the user on your screen (a login, 2FA code, CAPTCHA, or payment check), run: {botctl} handoff "<what you need, in one line>". It waits until they finish, so give the command a 10 minute timeout. Never ask for passwords in chat.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_approval_wait_fits_the_harness_hook_limit() {
        let g = guard(Path::new("/opt/it's"), "claude", 10);
        assert_eq!(g.command, r"'/opt/it'\''s/botctl' hook claude");
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(660), 720));
        // Hermes kills hooks after 300 seconds, so its wait stays under that.
        let g = guard(Path::new("/opt"), "hermes", 10);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(240), 300));
        let g = guard(Path::new("/opt"), "hermes", 1);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(120), 180));
        assert_eq!(tool_label("terminal", "ls"), "Running: ls");
    }

    #[test]
    fn bot_files_stay_in_the_data_folder() {
        let app = test_app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        app.init_bot_files(&bot);
        let dir = app.bot_dir(&bot.id).unwrap();
        assert_eq!(dir, app.cfg.data_dir.join("bots").join(&bot.id));
        assert!(app.memory_file(&bot.id).unwrap().is_file());
        assert_eq!(app.user_file(&bot.owner_id).unwrap(), app.cfg.data_dir.join("users").join(&bot.owner_id).join("USER.md"));
        assert!(app.user_file(&bot.owner_id).unwrap().is_file());
        for bad in ["", "..", "../../etc", "a/b", "/etc"] {
            assert_eq!(app.bot_dir(bad), None, "{bad:?}");
            assert_eq!(app.memory_file(bad), None, "{bad:?}");
            assert_eq!(app.user_file(bad), None, "{bad:?}");
            assert_eq!(app.workspace_for(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn each_users_bots_get_their_own_folder_facts_secrets_and_token() {
        use crate::acl::Visibility;
        use crate::rbac::Role;
        let app = test_app();
        crate::users::ensure_operator(&app.db, "Owner", None);
        let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let bea = app.db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let a = app.db.create_bot_owned("A1", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Private);
        let a2 = app.db.create_bot_owned("A2", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Shared);
        let b = app.db.create_bot_owned("B1", "#fff", "waddle", "claude", None, false, &bea.id, Visibility::Private);
        for bot in [&a, &a2, &b] {
            app.init_bot_files(bot);
        }
        let key = format!("ANTHROPIC_API_KEY_{}", crate::random_hex(3).to_uppercase());
        let ada_key = format!("sk-ant-{}", crate::random_hex(12));
        crate::secrets::global().user_put(&ada.id, &key, &ada_key).unwrap();

        let (cwd_a, env_a) = app.run_space(&a).unwrap();
        let (cwd_a2, env_a2) = app.run_space(&a2).unwrap();
        let (cwd_b, env_b) = app.run_space(&b).unwrap();
        let ws = paths::canonical(&app.cfg.workspace).unwrap();
        assert_eq!(cwd_a, ws.join("users").join(&ada.id));
        assert_eq!(cwd_a2, cwd_a, "a user's Bots share that user's folder");
        assert_eq!(cwd_b, ws.join("users").join(&bea.id));
        assert!(!cwd_a.starts_with(&cwd_b) && !cwd_b.starts_with(&cwd_a));
        assert!(cwd_a.is_dir() && cwd_b.is_dir());
        assert_eq!(app.policy_ctx(&a).workspace, cwd_a, "deleting in Bea's folder is outside Ada's Bot's workspace");

        assert_eq!(env_a.get(&key), Some(&ada_key));
        assert_eq!(env_a2.get(&key), Some(&ada_key));
        assert_eq!(env_b.get(&key), None, "Ada's key never reaches Bea's Bot");
        let token = |e: &HashMap<String, String>| e["BOT_TOKEN"].clone();
        assert_eq!(isolation::token_bot(&app.cfg.bot_key, &token(&env_a)), Some((a.id.as_str(), ada.id.as_str())));
        assert_eq!(isolation::token_bot(&app.cfg.bot_key, &token(&env_b)), Some((b.id.as_str(), bea.id.as_str())));
        assert_ne!(token(&env_a), token(&env_a2), "each Bot has its own token, even with one owner");
        assert_eq!(crate::secrets::redact::text(&token(&env_a)), crate::secrets::redact::MARK);

        let facts = |u: &str| std::fs::read_to_string(app.user_file(u).unwrap()).unwrap();
        assert!(facts(&ada.id).contains("Ada") && facts(&bea.id).contains("Bea"));
        std::fs::write(app.user_file(&ada.id).unwrap(), "# About the user\n- Name: Ada\n- Bank: ada-only-fact\n").unwrap();
        let pa = app.system_prompt(&a);
        let pb = app.system_prompt(&b);
        assert!(pa.contains("AI teammate of Ada") && pa.contains(&cwd_a.display().to_string()) && pa.contains("ada-only-fact"));
        assert!(pb.contains("AI teammate of Bea") && pb.contains(&cwd_b.display().to_string()));
        assert!(!pb.contains("ada-only-fact") && !pb.contains(&cwd_a.display().to_string()) && !pb.contains("A1"));
        assert!(!pa.contains(&cwd_b.display().to_string()) && !pa.contains("B1"));
        assert!(pb.contains("A2"), "Ada's shared Bot is one Bea can ask");
        let op = app.db.create_bot("Op", "#fff", "waddle", "claude", None, false);
        assert!(app.system_prompt(&op).contains("AI teammate of Tester"), "the owner account uses USER_NAME");
        crate::secrets::global().user_forget(&ada.id).unwrap();
        crate::secrets::redact::forget_for(&ada.id, &ada_key);
    }

    fn fake_run(app: &App, bot_id: &str, guarded: bool) -> watch::Receiver<AbortReason> {
        let (tx, rx) = watch::channel(None);
        let hook_wait = guarded.then_some(Duration::from_secs(60));
        app.state().entry(bot_id.into()).or_default().run =
            Some(Run { abort: tx, status: String::new(), draft: String::new(), hooks: Default::default(), hook_wait });
        rx
    }

    #[test]
    fn turning_on_approvals_stops_runs_without_the_hook() {
        let app = test_app();
        let a = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let b = app.db.create_bot("B", "#fff", "waddle", "claude", None, false);
        let mut p = app.db.global_policy();
        p.mode = Mode::Bypass;
        app.db.set_global_policy(&p);
        let (unguarded, guarded) = (fake_run(&app, &a.id, false), fake_run(&app, &b.id, true));

        app.stop_unguarded_runs();
        assert_eq!(*unguarded.borrow(), None, "still bypass");

        p.mode = Mode::Ask;
        app.db.set_global_policy(&p);
        app.stop_unguarded_runs();
        assert_eq!(*unguarded.borrow(), Some("policy"));
        assert_eq!(*guarded.borrow(), None);
    }
}
