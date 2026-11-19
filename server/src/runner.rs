//! Runs Bots: one task at a time per Bot, in order. Builds the system prompt
//! (identity, rules, memory), streams harness events to the web app, and saves replies.

use crate::adapters::{self, AbortReason, AgentEvent, Guard, RunInput};
use crate::db::{Bot, BotPatch, Db, Message};
use crate::paths;
use crate::policy::Mode;
use crate::screen::{self, Screens};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot, watch};

/// How long after a guarded run's first shell tool the approval hook must have
/// called in. If it hasn't, the harness ignored the hook and the run is stopped.
const HOOK_GRACE: Duration = Duration::from_secs(5);

pub struct Config {
    pub data_dir: PathBuf,
    pub workspace: PathBuf,
    pub user_name: String,
    /// Added to PATH so Bots can run `botctl`.
    pub bin_dir: PathBuf,
    pub api_url: String,
    pub bot_token: String,
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
        let _ = self.tx.send(v.to_string());
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
            "policy": self.db.effective_policy(&b.id).mode, "policyOverride": self.db.bot_override(&b.id).is_some(),
        });
        if let Some(run) = self.state().get(&b.id).and_then(|s| s.run.as_ref()) {
            v["working"] = json!(true);
            v["status"] = json!(run.status);
            v["draft"] = json!(run.draft);
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
        paths::child(&paths::child(&self.cfg.data_dir, "bots")?, id)
    }
    fn memory_file(&self, id: &str) -> Option<PathBuf> {
        paths::child(&self.bot_dir(id)?, "MEMORY.md")
    }
    fn user_file(&self) -> Option<PathBuf> {
        paths::child(&self.cfg.data_dir, "USER.md")
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
        if let Some(user) = self.user_file()
            && !user.exists()
        {
            let _ = std::fs::write(&user, format!("# About the user\n\n- Name: {}\n", self.cfg.user_name));
        }
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
        if adapters::get(&bot.harness).is_none() {
            return self.say(&bot.id, &format!("Unknown harness \"{}\".", bot.harness), true);
        }
        let Some(bot_dir) = self.bot_dir(&bot.id) else {
            return self.say(&bot.id, "This Bot's id isn't a safe folder name, so it can't run.", true);
        };
        self.init_bot_files(&bot);
        self.db.set_status(msg.id, "running");
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
            // stays above our wait, so the hook is never killed into failing open.
            let policy = self.db.effective_policy(&bot.id);
            let guard = (policy.mode == Mode::Ask).then(|| {
                let wait = Duration::from_secs(policy.timeout_minutes as u64 * 60 + 60);
                let botctl = self.cfg.bin_dir.join("botctl").display().to_string();
                Guard { command: format!("{} hook {}", shell_quote(&botctl), bot.harness), timeout_secs: wait.as_secs() + 60, wait }
            });
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

            let mut env = HashMap::from([
                ("BOT_ID".to_string(), bot.id.clone()),
                ("BOT_API".to_string(), self.cfg.api_url.clone()),
                ("BOT_TOKEN".to_string(), self.cfg.bot_token.clone()),
                ("SUPERBOT_BOTCTL".to_string(), self.cfg.bin_dir.join("botctl").display().to_string()),
            ]);
            let path = std::env::var("PATH").unwrap_or_default();
            env.insert("PATH".into(), format!("{}:{path}", self.cfg.bin_dir.display()));
            if let Some(screens) = &self.screens
                && let Some(info) = screens.ensure(&bot.id, |id| self.is_running(id)).await
            {
                env.extend(screen::bot_env(&info, &bot.id, &bot_dir));
            }
            let input = RunInput {
                prompt: prompt.clone(),
                system: self.system_prompt(&bot),
                session_id: bot.session_id.clone(),
                cwd: self.cfg.workspace.clone(),
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
                    if guard.is_some() && canary.is_none() && ["bash", "shell"].contains(&name.to_lowercase().as_str()) {
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
                    || ((m.contains("session") || m.contains("conversation"))
                        && (m.contains("not found") || m.contains("no such") || m.contains("does not exist")))
            });
            if lost && bot.session_id.is_some() && replies == 0 && attempt == 0 {
                self.db.update_bot(&id, BotPatch { session_id: Some(None), ..Default::default() });
                bot.session_id = None;
                continue;
            }

            match *abort_rx.borrow() {
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

    fn with_run<T: Default>(&self, bot_id: &str, f: impl FnOnce(&mut Run) -> T) -> T {
        self.state().get_mut(bot_id).and_then(|s| s.run.as_mut()).map(f).unwrap_or_default()
    }

    /// Another Bot asks this one something. Resolves with the reply, or None if it
    /// takes longer than `wait`; then the reply is delivered to the asker later.
    pub async fn ask(self: &Arc<Self>, from: &Bot, to: &Bot, text: &str, wait: Duration) -> Option<String> {
        let msg = self.db.add_message_from(&to.id, "peer", text, None, false, Some("queued"), Some(&from.id));
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
        let answer = tokio::time::timeout(wait, rx).await.ok().and_then(Result::ok);
        if answer.is_none() {
            self.waiters.lock().unwrap().remove(&m.id);
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

    fn system_prompt(&self, bot: &Bot) -> String {
        let read = |p: &Option<PathBuf>| p.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default().trim().to_string();
        let (mem_file, user_file) = (self.memory_file(&bot.id), self.user_file());
        let others: Vec<String> =
            self.db.bots().iter().filter(|b| b.id != bot.id).map(|b| format!("- {} (id {})", b.name, b.id)).collect();
        let primary = if bot.primary {
            " You are their primary Bot: their main point of contact. You help them decide which Bot should own which job."
        } else {
            ""
        };
        format!(
            r#"You are {name}, an AI teammate of {user}.{primary}
They talk to you in a chat app, like messaging a coworker. Finish work end to end.

## Your computer
- You run on a Linux computer shared with the user's other Bots. Your working folder is {ws}.
- Files, browser sign-ins, and credentials on it are shared by all Bots. Keep durable work in clear project folders.

## Memory
- Your memory file: {mem_path}. It holds your job, the user's rules and preferences for you, and a short dated log of important work.
- Shared facts about the user, used by every Bot: {user_path}. Name, time zone, and similar.
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
            user = self.cfg.user_name,
            approvals = if self.db.effective_policy(&bot.id).mode == Mode::Ask {
                "\n- Risky actions (destructive commands, deleting outside your folder, sending messages, installing software, git push) \
                 pause until the user approves them in the app. If one is denied, don't try another way to do it; tell the user what you wanted to do."
            } else {
                ""
            },
            ws = self.cfg.workspace.display(),
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
            bot_token: crate::random_hex(16),
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
    let verb = if has(&["bash", "shell", "command"]) {
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
    fn bot_files_stay_in_the_data_folder() {
        let app = test_app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        app.init_bot_files(&bot);
        let dir = app.bot_dir(&bot.id).unwrap();
        assert_eq!(dir, app.cfg.data_dir.join("bots").join(&bot.id));
        assert!(app.memory_file(&bot.id).unwrap().is_file());
        assert!(app.user_file().unwrap().is_file());
        for bad in ["", "..", "../../etc", "a/b", "/etc"] {
            assert_eq!(app.bot_dir(bad), None, "{bad:?}");
            assert_eq!(app.memory_file(bad), None, "{bad:?}");
        }
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
