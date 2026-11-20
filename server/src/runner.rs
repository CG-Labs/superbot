//! Runs Bots: one task at a time per Bot, in order. Builds the system prompt
//! (identity, rules, memory), streams harness events to the web app, and saves replies.

use crate::accounts::{self, Isolation, RunAs};
use crate::adapters::{self, AbortReason, AgentEvent, Guard, RunInput};
use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{Bot, BotPatch, Db, Message};
use crate::machines::ControlPlane;
use crate::machines::route::{self, Assigned, Refusal, Target};
use crate::machines::wire::{self, JobEvent};
use crate::tiers::{self, Route, Tier, Tiers};
use crate::{isolation, paths};
use crate::policy::{Ctx, Mode};
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
    /// The folders its tool calls are judged by, when it isn't on this server.
    ctx: Option<Ctx>,
}

/// Where a run happens: here, or on its owner's machine (ADR 0036).
enum Place {
    Here,
    There(Box<(Assigned, wire::Layout)>),
}

/// What a job on a machine sent back: files by path, and those too big to send.
type Back = (std::collections::BTreeMap<String, String>, Vec<String>);

/// What a run sees where it happens: its folders, environment, and tools there.
struct Spot {
    machine: Option<Assigned>,
    cwd: PathBuf,
    state_dir: PathBuf,
    memory: PathBuf,
    user_file: PathBuf,
    botctl: PathBuf,
    env: HashMap<String, String>,
    screens: bool,
    ctx: Option<Ctx>,
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
    /// Each user's plan and the models it routes to (ADR 0033). Unset: self-host only.
    pub tiers: OnceLock<Arc<Tiers>>,
    /// The self-host license, and the seats it allows (ADR 0038).
    pub license: Arc<crate::license::Licensing>,
    /// Each user's Bots on this server run as that user's own account (ADR 0037).
    /// Unset: all as botd's.
    pub isolation: OnceLock<Arc<Isolation>>,
    /// Runs on each user's machine now, by user.
    on_machines: Mutex<HashMap<String, u32>>,
    closing: AtomicBool,
}

impl App {
    pub fn new(db: Db, cfg: Config, screens: Option<Screens>) -> Arc<App> {
        let license = Arc::new(crate::license::Licensing::new(crate::license::trusted(), &cfg.data_dir));
        let seats = license.clone();
        db.set_seat_cap(Box::new(move || seats.seat_cap()));
        Arc::new(App {
            license,
            db,
            cfg,
            tx: broadcast::channel(1024).0,
            screens,
            bots: Mutex::default(),
            waiters: Mutex::default(),
            approval_waiters: Mutex::default(),
            control_plane: OnceLock::new(),
            tiers: OnceLock::new(),
            isolation: OnceLock::new(),
            on_machines: Mutex::default(),
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

    /// The folders a running Bot's tool calls are judged by, when it runs elsewhere.
    pub fn run_ctx(&self, bot_id: &str) -> Option<Ctx> {
        self.with_run(bot_id, |r| r.ctx.clone())
    }

    pub fn set_run_status(&self, bot_id: &str, status: &str) {
        if self.with_run(bot_id, |r| { r.status = status.into(); true }) {
            self.send(json!({ "type": "status", "botId": bot_id, "working": true, "status": status }));
        }
    }

    pub fn tiers(&self) -> &Tiers {
        static SELF_HOST: OnceLock<Tiers> = OnceLock::new();
        self.tiers.get().map_or_else(|| SELF_HOST.get_or_init(Tiers::self_host), |t| t.as_ref())
    }

    /// The tier a user is on: theirs, else the default.
    pub fn tier_of(&self, user_id: &str) -> &Tier {
        self.tiers().of(self.db.user(user_id).and_then(|u| u.tier).as_deref())
    }

    /// What only admins see of a Bot: the model it's set to and the route it runs on.
    pub fn bot_admin_fields(&self, b: &Bot, v: &mut Value) {
        v["model"] = json!(b.model);
        v["effort"] = json!(b.effort);
        let tier = self.tier_of(&b.owner_id);
        // Admins edit others' Bots, whose owners' tiers may offer other harnesses than theirs.
        v["harnesses"] = json!(crate::adapters::installed().into_iter().filter(|h| tier.allows_harness(h)).collect::<Vec<_>>());
        match tier.route(&b.harness, b.model.as_deref(), b.effort.as_deref()) {
            Ok(r) => v["route"] = json!(r),
            Err(e) => v["routeError"] = json!(e),
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
        // Users pick a tier, not a model: on a managed tier the model isn't theirs to see.
        let tier = self.tier_of(&b.owner_id);
        v["tier"] = json!({ "name": tier.name, "label": tier.label, "managed": tier.managed() });
        if tier.managed() {
            let o = v.as_object_mut().unwrap();
            o.remove("model");
            o.remove("effort");
        }
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
    pub fn isolation(&self) -> Option<&Isolation> {
        self.isolation.get().map(|i| i.as_ref())
    }

    /// A Bot's memory file: `DATA_DIR/bots/<id>/MEMORY.md`, or with per-user accounts
    /// `memory/<id>.md` in its owner's folder, where the run can edit it.
    pub(crate) fn memory_file(&self, bot: &Bot) -> Option<PathBuf> {
        match self.isolation() {
            Some(iso) => iso.memory_file(&bot.owner_id, &bot.id),
            None => self.data_memory_file(&bot.id),
        }
    }
    /// `DATA_DIR/bots/<id>/MEMORY.md`: botd's copy of the memory file, which runs on the
    /// owner's machine and (with per-user accounts) runs here send back.
    pub(crate) fn data_memory_file(&self, id: &str) -> Option<PathBuf> {
        paths::child(&self.bot_dir(id)?, "MEMORY.md")
    }

    /// Facts about one user, for that user's Bots only: `DATA_DIR/users/<owner>/USER.md`,
    /// or with per-user accounts `memory/USER.md` in their folder.
    pub fn user_file(&self, owner_id: &str) -> Option<PathBuf> {
        match self.isolation() {
            Some(iso) => iso.user_file(owner_id),
            None => self.data_user_file(owner_id),
        }
    }
    /// `DATA_DIR/users/<owner>/USER.md`. With per-user accounts, botd's copy.
    pub(crate) fn data_user_file(&self, owner_id: &str) -> Option<PathBuf> {
        paths::child(&isolation::user_dir(&self.cfg.data_dir, owner_id)?, "USER.md")
    }

    /// The folder every Bot of that user works in: `WORKSPACE_DIR/users/<owner>`, created,
    /// or with per-user accounts `workspace` in their folder (made with the account).
    pub fn workspace_for(&self, owner_id: &str) -> Option<PathBuf> {
        match self.isolation() {
            Some(iso) => iso.workspace(owner_id),
            None => isolation::user_dir(&self.cfg.workspace, owner_id),
        }
    }

    fn read_memory(&self, p: &Path) -> Option<String> {
        match self.isolation() {
            // The run's account can write there, so never follow a link it left.
            Some(_) => accounts::read_plain(p, accounts::MAX_FILE),
            None => std::fs::read_to_string(p).ok(),
        }
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
        if let Some(mem) = self.data_memory_file(&bot.id)
            && !mem.exists()
        {
            let _ = std::fs::write(&mem, format!("# {}\n\n## Job\n\nNot set yet. Ask the user.\n\n## Rules\n\n## Work log\n", bot.name));
        }
        if let Some(user) = self.data_user_file(&bot.owner_id)
            && !user.exists()
        {
            let _ = std::fs::write(&user, format!("# About the user\n\n- Name: {}\n", self.owner_name(bot)));
        }
        // With per-user accounts the run edits copies in its owner's folder, made from
        // botd's. Until the account exists there's no folder, and nothing is made.
        if let Some(iso) = self.isolation() {
            let pairs = [
                (iso.memory_file(&bot.owner_id, &bot.id), self.data_memory_file(&bot.id)),
                (iso.user_file(&bot.owner_id), self.data_user_file(&bot.owner_id)),
            ];
            for (copy, kept) in pairs {
                if let (Some(copy), Some(text)) = (copy, kept.and_then(|p| std::fs::read_to_string(p).ok())) {
                    let _ = accounts::seed(&copy, &text);
                }
            }
        }
    }

    /// At startup, before any run. Per-user accounts turned back on: the copies left in
    /// users' folders from the last time may be older than botd's originals, which
    /// runs changed meanwhile, so they're dropped and made again at each Bot's next run.
    /// While accounts stay on, a copy is never replaced: it may hold a running Bot's edits.
    /// Saved as on only once every copy is gone, so a cleanup cut short runs again.
    pub fn start_isolation(&self) {
        let Some(iso) = self.isolation() else {
            self.db.save_isolation(false);
            return;
        };
        if self.db.isolation_was_on() {
            return;
        }
        let bots = self.db.bots().into_iter().filter_map(|b| iso.memory_file(&b.owner_id, &b.id));
        let users = self.db.users().into_iter().filter_map(|u| iso.user_file(&u.id));
        let left: Vec<PathBuf> = bots
            .chain(users)
            .filter(|copy| {
                accounts::remove(copy);
                std::fs::symlink_metadata(copy).is_ok()
            })
            .collect();
        match left.first() {
            None => self.db.save_isolation(true),
            Some(p) => eprintln!("WARNING: couldn't remove {} old memory copies (e.g. {}); botd tries again at its next start.", left.len(), p.display()),
        }
    }

    /// With per-user accounts: copies the memory and facts a run left in its owner's
    /// folder back to `DATA_DIR`, so backups have them and memory follows the Bot.
    fn keep_memory(&self, bot: &Bot) {
        let Some(iso) = self.isolation() else { return };
        let mut pairs = vec![(iso.user_file(&bot.owner_id), self.data_user_file(&bot.owner_id))];
        // Handed over while it ran: hand_over_memory already kept the memory, and this
        // run's copy is the old owner's, so it's dropped, not copied over the Bot's.
        if self.db.bot(&bot.id).is_some_and(|now| now.owner_id == bot.owner_id) {
            pairs.push((iso.memory_file(&bot.owner_id, &bot.id), self.data_memory_file(&bot.id)));
        } else if let Some(stale) = iso.memory_file(&bot.owner_id, &bot.id) {
            accounts::remove(&stale);
        }
        for (from, to) in pairs {
            if let (Some(from), Some(to)) = (from, to)
                && let Some(text) = accounts::read_plain(&from, accounts::MAX_FILE)
                && std::fs::read_to_string(&to).ok().as_deref() != Some(text.as_str())
            {
                let _ = std::fs::write(&to, text);
            }
        }
    }

    /// A Bot changed hands. With per-user accounts its memory leaves the old owner's
    /// folder (botd keeps it) and is made again in the new owner's on its next run.
    pub fn hand_over_memory(&self, bot_id: &str, from: &str, to: &str) {
        let Some(iso) = self.isolation() else { return };
        if let (Some(old), Some(kept)) = (iso.memory_file(from, bot_id), self.data_memory_file(bot_id))
            && let Some(text) = accounts::read_plain(&old, accounts::MAX_FILE)
        {
            let _ = std::fs::write(kept, text);
        }
        for owner in [from, to] {
            if let Some(p) = iso.memory_file(owner, bot_id) {
                accounts::remove(&p);
            }
        }
    }

    /// Makes sure the user's account and folders exist (ADR 0037). A new account and a
    /// failure are audited, as done by `by`.
    pub async fn ensure_account(&self, user_id: &str, by: &Who) -> Result<RunAs, String> {
        let iso = self.isolation.get().cloned().ok_or("Per-user accounts are off (ISOLATION=users turns them on).")?;
        let run_as = iso.run_as(user_id).ok_or_else(|| format!("User id {user_id:?} can't be part of a Unix account name."))?;
        let id = user_id.to_string();
        let made = tokio::task::spawn_blocking({
            let iso = iso.clone();
            move || iso.ensure(&id)
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        let event = |action: &str| by.event(action).target("user", user_id);
        match made {
            Ok(false) => Ok(run_as),
            Ok(true) => {
                self.db.record(&event("isolation.account_created").details(json!({ "account": run_as.account, "home": iso.home(user_id) })));
                Ok(run_as)
            }
            Err(e) => {
                eprintln!("Isolation: couldn't set up a user's account (see isolation.account_failed in the audit log): {e}");
                self.db.record(&event("isolation.account_failed").outcome(Outcome::Failure).details(json!({ "account": run_as.account, "error": e })));
                Err(e)
            }
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
        let cant_run = |text: &str| {
            self.give_back_routine(&bot, msg);
            self.say(&bot.id, text, true);
        };
        let Some((shell_tool, bin)) = adapters::get(&bot.harness).map(|a| (a.shell_tool(), a.bin())) else {
            return cant_run(&format!("Unknown harness \"{}\".", bot.harness));
        };
        let Some(bot_dir) = self.bot_dir(&bot.id) else {
            return cant_run("This Bot's id isn't a safe folder name, so it can't run.");
        };
        let Some(space) = self.run_space(&bot) else {
            return cant_run("This Bot's owner id isn't a safe folder name, so it can't run.");
        };
        let by = self.requester(&bot, msg);
        let period = tiers::period(crate::db::now());
        let Some((tier, route)) = self.tier_route(&bot, msg, &by, &period) else { return };
        let placed_at = self.db.placed_at(&bot.owner_id);
        let Some(place) = self.place(&bot, msg, &by, &period, bin).await else { return };
        // The owner's own machine runs only their Bots, so only runs here need their account.
        let run_as = match place {
            Place::Here => match self.isolate(&bot, msg, &by, &period).await {
                Ok(r) => r,
                Err(()) => return,
            },
            Place::There(_) => None,
        };
        let spot = self.spot(&bot, bot_dir.clone(), space, place);
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
        let host = json!({ "host": if spot.machine.is_some() { "machine" } else { "server" }, "machine": spot.machine.as_ref().map(|m| &m.machine_id) });

        for attempt in 0..2 {
            let (abort_tx, abort_rx) = watch::channel(None);
            // Ask mode: the harness calls `botctl hook` before every tool. Its hook timeout
            // stays above our wait, so the hook is never killed into failing open. A harness
            // that caps hook timeouts gets a shorter wait instead.
            let policy = self.db.effective_policy(&bot.id);
            let guard = (policy.mode == Mode::Ask).then(|| guard(&spot.botctl, &bot.harness, policy.timeout_minutes));
            let hooks = Arc::new(AtomicU32::new(0));
            self.state().entry(bot.id.clone()).or_default().run = Some(Run {
                abort: abort_tx.clone(),
                status: "Thinking".into(),
                draft: String::new(),
                hooks: hooks.clone(),
                hook_wait: guard.as_ref().map(|g| g.wait),
                ctx: spot.ctx.clone(),
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

            let mut env = spot.env.clone();
            if spot.screens
                && let Some(screens) = &self.screens
                && let Some(info) = screens.ensure(&bot.id, |id| self.is_running(id)).await
            {
                env.extend(screen::bot_env(&info, &bot.id, &bot_dir));
            }
            let mut invoked = json!({
                "harness": bot.harness, "model": route.model, "effort": route.effort, "provider": route.provider, "tier": tier, "policy": policy.mode,
                "guarded": guard.is_some(), "resumed": bot.session_id.is_some(), "attempt": attempt + 1,
                "trigger": msg.role, "messageId": msg.id,
            });
            merge(&mut invoked, &host);
            if let Some(r) = &run_as {
                invoked["runAs"] = json!(r.account);
            }
            self.db.record(&by.event("harness.invoked").target("message", &msg.id.to_string()).bot(&bot.id).details(invoked));
            let input = RunInput {
                prompt: prompt.clone(),
                system: self.system_prompt_at(&bot, &spot),
                session_id: bot.session_id.clone(),
                cwd: spot.cwd.clone(),
                provider: route.provider.clone(),
                model: route.model.clone(),
                effort: route.effort.clone(),
                env,
                state_dir: spot.state_dir.clone(),
                guard: guard.clone(),
                run_as: run_as.clone(),
            };

            let mut errors: Vec<String> = Vec::new();
            let mut replies = 0;
            let id = bot.id.clone();
            let mut canary: Option<tokio::task::JoinHandle<()>> = None;
            let mut saw_shell = false;
            let emit = |e| match e {
                AgentEvent::Session(s) => {
                    self.db.keep_session(&id, &s, placed_at);
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
            };
            let adapter = adapters::get(&bot.harness).unwrap();
            match &spot.machine {
                None => {
                    adapters::run(adapter, input, abort_rx.clone(), emit).await;
                    self.keep_memory(&bot);
                }
                Some(to) => self.run_there(&bot, msg, &spot, to, adapter, input, abort_rx.clone(), emit).await,
            }
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
            let mut finished = json!({
                "result": result, "durationMs": started.elapsed().as_millis() as u64, "replies": replies,
                "attempts": attempt + 1, "trigger": msg.role, "messageId": msg.id,
            });
            merge(&mut finished, &host);
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

    /// Where the Bot runs: here, or its owner's machine once that machine answered a
    /// check and can run it. None: refused (the run is given back), and the Bot said
    /// why. Never another user's machine, and never here instead of an assigned one.
    async fn place(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, bin: &str) -> Option<Place> {
        let Some(cp) = self.control_plane.get() else { return Some(Place::Here) };
        let refused = |r: Refusal, machine: Option<&str>| {
            self.give_back(bot, msg, period);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            self.db.record(&e.details(json!({ "reason": r.reason(), "owner": bot.owner_id, "machine": machine, "messageId": msg.id })));
            self.say(&bot.id, &r.message(), true);
            None
        };
        let to = match cp.route(&self.db, &bot.owner_id) {
            Ok(Target::Local) => return Some(Place::Here),
            Err(r) => return refused(r, None),
            Ok(Target::Machine(to)) => to,
        };
        let checked = cp.link.check(self, &to, &[bin]).await.map_err(Refusal::Offline);
        match checked.and_then(|hb| route::fit(&hb, bin).map(|l| (l, hb.version))) {
            Err(r) => refused(r, Some(&to.machine_id)),
            Ok((layout, version)) => {
                let e = by.event("bot.run_routed").target("message", &msg.id.to_string()).bot(&bot.id);
                self.db.record(&e.details(json!({ "owner": bot.owner_id, "machine": to.machine_id, "link": cp.link.name(), "agentVersion": version, "messageId": msg.id })));
                Some(Place::There(Box::new((to, layout))))
            }
        }
    }

    /// The run's folders and environment where it happens. On a machine: the machine's
    /// folders, botctl there, and botd's API through the agent's relay; no screen yet.
    fn spot(&self, bot: &Bot, bot_dir: PathBuf, (cwd, mut env): (PathBuf, HashMap<String, String>), place: Place) -> Spot {
        let local = |p: Option<PathBuf>| p.unwrap_or_default();
        match place {
            Place::Here => Spot {
                machine: None,
                cwd,
                memory: local(self.memory_file(bot)),
                user_file: local(self.user_file(&bot.owner_id)),
                state_dir: bot_dir,
                botctl: self.cfg.bin_dir.join("botctl"),
                env,
                screens: self.screens.is_some(),
                ctx: None,
            },
            Place::There(there) => {
                let (to, layout) = *there;
                let botctl = PathBuf::from(layout.botctl.clone().unwrap_or_default());
                // HOME and PATH are the machine's own; it inherits nothing of botd's.
                env.remove("PATH");
                for (k, v) in crate::secrets::global().inherited_harness_env() {
                    env.entry(k).or_insert_with(|| v.expose().to_string());
                }
                env.insert("BOT_API".into(), layout.api.clone());
                env.insert("SUPERBOT_BOTCTL".into(), botctl.display().to_string());
                let state_dir = PathBuf::from(&layout.bots).join(&bot.id);
                Spot {
                    machine: Some(to),
                    cwd: PathBuf::from(&layout.workspace),
                    memory: state_dir.join("MEMORY.md"),
                    user_file: PathBuf::from(&layout.user_file),
                    state_dir,
                    botctl,
                    env,
                    screens: false,
                    ctx: Some(Ctx { workspace: PathBuf::from(&layout.workspace), home: PathBuf::from(&layout.home) }),
                }
            }
        }
    }

    /// Runs the harness on the owner's machine. botd keeps the Bot's memory and its
    /// owner's facts: they go with the job and come back changed. The owner's facts
    /// are sent only when none of their other Bots is running there, so one Bot's run
    /// can't undo another's edits. With per-user accounts on this server, the copies in
    /// the owner's folder there are dropped when these change, and made again from
    /// botd's at the next run here.
    #[allow(clippy::too_many_arguments)]
    async fn run_there(&self, bot: &Bot, msg: &Message, spot: &Spot, to: &Assigned, adapter: Box<dyn adapters::Adapter>, input: RunInput, abort: watch::Receiver<AbortReason>, emit: impl FnMut(AgentEvent)) {
        let Some(cp) = self.control_plane.get() else { return };
        let read = |p: Option<PathBuf>| p.and_then(|p| std::fs::read_to_string(p).ok());
        let (memory, facts) = (read(self.data_memory_file(&bot.id)), read(self.data_user_file(&bot.owner_id)));
        let alone = {
            let mut on = self.on_machines.lock().unwrap_or_else(|e| e.into_inner());
            let n = on.entry(bot.owner_id.clone()).or_default();
            *n += 1;
            *n == 1
        };
        let back: Arc<Mutex<Back>> = Arc::default();
        let (memory_at, user_at) = (spot.memory.display().to_string(), spot.user_file.display().to_string());
        let job_abort = abort.clone();
        let exec = |mut job: wire::JobRequest, tx: tokio::sync::mpsc::Sender<JobEvent>| {
            let (link, back, abort) = (cp.link.clone(), back.clone(), job_abort);
            job.job_id = format!("j{}", crate::random_hex(8));
            job.bot_id = bot.id.clone();
            job.owner_id = bot.owner_id.clone();
            job.message_id = msg.id;
            let files = [(memory_at.clone(), memory), (user_at.clone(), facts.filter(|_| alone))];
            job.files.extend(files.into_iter().filter_map(|(path, body)| Some(wire::JobFile { path, body: body? })));
            job.collect = vec![memory_at.clone(), user_at.clone()];
            async move {
                let (mid_tx, mut mid_rx) = tokio::sync::mpsc::channel::<JobEvent>(64);
                let forward = async {
                    while let Some(ev) = mid_rx.recv().await {
                        if let JobEvent::Exit { files, too_big, .. } = &ev {
                            *back.lock().unwrap_or_else(|e| e.into_inner()) = (files.clone(), too_big.clone());
                        }
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                };
                tokio::join!(link.run(to, job, abort, mid_tx), forward);
            }
        };
        adapters::run_on(adapter, input, abort, emit, exec).await;
        {
            let mut on = self.on_machines.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = on.get_mut(&bot.owner_id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    on.remove(&bot.owner_id);
                }
            }
        }
        let (back, too_big) = std::mem::take(&mut *back.lock().unwrap_or_else(|e| e.into_inner()));
        for path in &too_big {
            let name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mib = crate::machines::job::MAX_COLLECT >> 20;
            self.say(&bot.id, &format!("{name} on your machine is over {mib} MiB, so it no longer syncs back here. The machine keeps its copy; trim it to sync again."), true);
        }
        let iso = self.isolation();
        let copies = [iso.and_then(|i| i.memory_file(&bot.owner_id, &bot.id)), iso.and_then(|i| i.user_file(&bot.owner_id))];
        let kept = [(memory_at, self.data_memory_file(&bot.id)), (user_at, self.data_user_file(&bot.owner_id))];
        for ((there, here), copy) in kept.into_iter().zip(copies) {
            if let (Some(body), Some(here)) = (back.get(&there), here)
                && std::fs::read_to_string(&here).ok().as_ref() != Some(body)
            {
                let _ = std::fs::write(here, body);
                if let Some(copy) = copy {
                    accounts::remove(&copy);
                }
            }
        }
    }

    /// With per-user accounts (ADR 0037): the account this run starts as, always its
    /// owner's, made now if it's new. Ok(None): isolation is off. Err: refused, and the
    /// Bot said why; it never falls back to running as botd's account.
    async fn isolate(&self, bot: &Bot, msg: &Message, by: &Who, period: &str) -> Result<Option<RunAs>, ()> {
        if self.isolation().is_none() {
            return Ok(None);
        }
        let refused = |reason: &str, text: &str| {
            self.give_back(bot, msg, period);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            let account = accounts::account(&bot.owner_id);
            self.db.record(&e.details(json!({ "reason": reason, "owner": bot.owner_id, "account": account, "harness": bot.harness, "messageId": msg.id })));
            self.say(&bot.id, text, true);
            Err(())
        };
        if !accounts::HARNESSES.contains(&bot.harness.as_str()) {
            let text = format!(
                "This server runs each person's Bots under their own account, and {} can't run that way yet. Switch me to Claude Code or Codex in my settings.",
                bot.harness
            );
            return refused("isolation_harness", &text);
        }
        match self.ensure_account(&bot.owner_id, by).await {
            Ok(r) => Ok(Some(r)),
            Err(_) => refused("no_account", "I couldn't set up my owner's account on this server, so I didn't run. An admin can check the server log."),
        }
    }

    /// The tier this run is on and the route it takes: the Bot owner's tier picks the
    /// model, never the Bot's settings alone (ADR 0033). The run is counted for the
    /// owner, within the tier's monthly limit. None: refused, and the Bot said why.
    fn tier_route(&self, bot: &Bot, msg: &Message, by: &Who, period: &str) -> Option<(String, Route)> {
        let tier = self.tier_of(&bot.owner_id);
        let refused = |reason: &str, text: String, limit: Option<u32>| {
            self.give_back_routine(bot, msg);
            let details = json!({ "reason": reason, "owner": bot.owner_id, "tier": tier.name, "limit": limit, "period": period, "messageId": msg.id });
            self.db.record(&by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied).details(details));
            self.say(&bot.id, &text, true);
            None
        };
        let route = match tier.route(&bot.harness, bot.model.as_deref(), bot.effort.as_deref()) {
            Ok(r) => r,
            Err(e) => return refused("tier_harness", format!("{e} Switch me to one of those in my settings."), None),
        };
        if let Err(limit) = self.db.take_run(&bot.owner_id, period, tier.limits.monthly_runs) {
            let text = format!("The {} plan allows {limit} runs a month, and this month's are used up. More start on the 1st (UTC).", tier.label);
            return refused("tier_limit", text, Some(limit));
        }
        Some((tier.name.clone(), route))
    }

    /// Gives back what a refused run took: its monthly run, and for a routine, the
    /// routine run counted for the day it fired (ADR 0040).
    fn give_back(&self, bot: &Bot, msg: &Message, period: &str) {
        self.db.give_back_run(&bot.owner_id, period);
        self.give_back_routine(bot, msg);
    }

    fn give_back_routine(&self, bot: &Bot, msg: &Message) {
        self.give_back_routine_to(&bot.owner_id, msg);
    }

    /// Gives a routine message's run back to whoever it was charged to when it fired
    /// (the scheduler acts on their behalf), which is `owner` only if the Bot hasn't
    /// changed hands since.
    fn give_back_routine_to(&self, owner: &str, msg: &Message) {
        if msg.role != "routine" {
            return;
        }
        let charged = self.db.message(msg.id).and_then(|m| m.requested_by).and_then(|w| w.actor.on_behalf_of);
        self.db.give_back_routine_run(charged.as_deref().unwrap_or(owner), &tiers::day(msg.created_at));
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
        self.stop_if(bot_id, || true);
    }

    /// Like `stop`, but only once `first` returns true. It runs under the lock that
    /// queues work, so nothing is queued between it and the stop, and a false leaves
    /// the Bot's work untouched.
    pub fn stop_if(&self, bot_id: &str, first: impl FnOnce() -> bool) -> bool {
        {
            let mut st = self.state();
            let owner = self.db.bot(bot_id).map(|b| b.owner_id);
            if !first() {
                return false;
            }
            if let Some(s) = st.get_mut(bot_id) {
                for m in s.queue.drain(..) {
                    self.db.set_status(m.id, "done");
                    if let Some(o) = &owner {
                        self.give_back_routine_to(o, &m);
                    }
                }
                if let Some(r) = &s.run {
                    r.abort.send_if_modified(|v| v.get_or_insert("stopped") == &"stopped");
                }
            }
        }
        self.cancel_approvals(bot_id, "The Bot was stopped");
        true
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

    /// The prompt for a run on this server.
    #[cfg(test)]
    pub(crate) fn system_prompt(&self, bot: &Bot) -> String {
        let (cwd, env) = (self.workspace_for(&bot.owner_id).unwrap_or_default(), HashMap::new());
        let spot = self.spot(bot, self.bot_dir(&bot.id).unwrap_or_default(), (cwd, env), Place::Here);
        self.system_prompt_at(bot, &spot)
    }

    /// The prompt for a run at `spot`: its paths are where the run is. The memory and
    /// facts in it are the run's own copies here, or botd's, which runs elsewhere send back.
    fn system_prompt_at(&self, bot: &Bot, spot: &Spot) -> String {
        let read = |p: &Option<PathBuf>| p.as_deref().and_then(|p| self.read_memory(p)).unwrap_or_default().trim().to_string();
        let (mem_file, user_file) = match spot.machine {
            None => (self.memory_file(bot), self.user_file(&bot.owner_id)),
            Some(_) => (self.data_memory_file(&bot.id), self.data_user_file(&bot.owner_id)),
        };
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
- You run on a Linux computer you share with {user}'s other Bots. Your working folder is {ws}; it belongs to {user}.{own}
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
            botctl = spot.botctl.display(),
            screen = if spot.screens && self.screens.is_some() { screen_prompt(&spot.botctl.display().to_string()) } else { String::new() },
            own = if spot.machine.is_some() { format!(" It is {user}'s own computer: only their Bots run on it.", user = self.owner_name(bot)) } else { String::new() },
            user = self.owner_name(bot),
            approvals = if self.db.effective_policy(&bot.id).mode == Mode::Ask {
                "\n- Risky actions (destructive commands, deleting outside your folder, sending messages, installing software, git push) \
                 pause until the user approves them in the app. If one is denied, don't try another way to do it; tell the user what you wanted to do."
            } else {
                ""
            },
            ws = spot.cwd.display(),
            mem_path = spot.memory.display(),
            user_path = spot.user_file.display(),
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
fn guard(botctl: &Path, harness: &str, timeout_minutes: u32) -> Guard {
    let mut wait = Duration::from_secs(timeout_minutes as u64 * 60 + 60);
    if let Some(cap) = adapters::get(harness).and_then(|a| a.max_hook_secs()) {
        wait = wait.min(Duration::from_secs(cap.saturating_sub(60).max(1)));
    }
    let botctl = botctl.display().to_string();
    Guard { command: format!("{} hook {harness}", shell_quote(&botctl)), timeout_secs: wait.as_secs() + 60, wait }
}

/// Adds `extra`'s fields to the object `v`.
fn merge(v: &mut Value, extra: &Value) {
    if let (Some(v), Some(x)) = (v.as_object_mut(), extra.as_object()) {
        v.extend(x.iter().map(|(k, x)| (k.clone(), x.clone())));
    }
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
        let g = guard(Path::new("/opt/it's/botctl"), "claude", 10);
        assert_eq!(g.command, r"'/opt/it'\''s/botctl' hook claude");
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(660), 720));
        // Hermes kills hooks after 300 seconds, so its wait stays under that.
        let g = guard(Path::new("/opt/botctl"), "hermes", 10);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(240), 300));
        let g = guard(Path::new("/opt/botctl"), "hermes", 1);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(120), 180));
        assert_eq!(tool_label("terminal", "ls"), "Running: ls");
    }

    #[test]
    fn a_refused_stop_if_leaves_queued_work() {
        let app = test_app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let m = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        app.state().entry(bot.id.clone()).or_default().queue.push_back(m.clone());
        let status = || app.db.message(m.id).unwrap().status;
        assert!(!app.stop_if(&bot.id, || false));
        assert_eq!(app.state()[&bot.id].queue.len(), 1);
        assert_eq!(status().as_deref(), Some("queued"));
        assert!(app.stop_if(&bot.id, || true));
        assert!(app.state()[&bot.id].queue.is_empty());
        assert_eq!(status().as_deref(), Some("done"));
    }

    fn actions(app: &App, prefix: &str) -> Vec<crate::db::AuditEvent> {
        let f = crate::audit::Filter { actions: vec![format!("{prefix}*")], ..Default::default() };
        app.db.audit_events(&f, 100, true)
    }

    /// An app with per-user accounts on, in a scratch folder; the account helper is
    /// `sudo`, so making an account fails unless the test makes the folders itself.
    fn isolated_app(sudo: &str) -> (Arc<App>, PathBuf) {
        let app = test_app();
        let root = app.cfg.data_dir.parent().unwrap().join(format!("iso-{}", crate::short_id()));
        std::fs::create_dir_all(&root).unwrap();
        let _ = app.isolation.set(Arc::new(accounts::for_tests(&root, sudo)));
        (app, root)
    }

    #[tokio::test]
    async fn isolation_off_runs_as_before() {
        let app = test_app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "pi", None, true);
        let msg = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        assert_eq!(app.isolate(&bot, &msg, &Who::system("test"), "2026-11").await, Ok(None));
        app.init_bot_files(&bot);
        assert_eq!(app.memory_file(&bot), app.data_memory_file(&bot.id));
        assert_eq!(app.user_file(&bot.owner_id), app.data_user_file(&bot.owner_id));
        assert_eq!(app.workspace_for(&bot.owner_id), isolation::user_dir(&app.cfg.workspace, &bot.owner_id));
        assert!(actions(&app, "isolation.").is_empty());
        assert!(actions(&app, "bot.run_refused").is_empty());
    }

    #[test]
    fn isolated_bots_keep_memory_in_their_owners_folder() {
        use crate::acl::Visibility;
        use crate::rbac::Role;
        let (app, root) = isolated_app("/bin/false");
        let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let bea = app.db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let a = app.db.create_bot_owned("A1", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Private);
        assert_eq!(app.workspace_for(&ada.id), Some(root.join(&ada.id).join("workspace")));
        assert_eq!(app.memory_file(&a), Some(root.join(&ada.id).join("memory").join(format!("{}.md", a.id))));
        assert_eq!(app.user_file(&ada.id), Some(root.join(&ada.id).join("memory/USER.md")));
        for bad in ["", "..", "a/b", "U1", &"a".repeat(28)] {
            assert_eq!(app.workspace_for(bad), None, "{bad:?}");
            assert_eq!(app.user_file(bad), None, "{bad:?}");
        }

        // No account yet: botd's copies are made, nothing in the user's folder.
        app.init_bot_files(&a);
        assert!(app.data_memory_file(&a.id).unwrap().is_file());
        assert!(!app.memory_file(&a).unwrap().exists());

        // With the folder there, the run gets a copy, and what it writes comes back.
        for u in [&ada.id, &bea.id] {
            std::fs::create_dir_all(root.join(u).join("memory")).unwrap();
        }
        app.init_bot_files(&a);
        let mem = app.memory_file(&a).unwrap();
        assert!(std::fs::read_to_string(&mem).unwrap().contains("# A1"));
        std::fs::write(&mem, "# A1\n\nLearned a thing.\n").unwrap();
        app.keep_memory(&a);
        assert_eq!(std::fs::read_to_string(app.data_memory_file(&a.id).unwrap()).unwrap(), "# A1\n\nLearned a thing.\n");

        // A link left in its place is never followed, nor copied back.
        let secret = root.join("secret.txt");
        std::fs::write(&secret, "not yours").unwrap();
        std::fs::remove_file(&mem).unwrap();
        std::os::unix::fs::symlink(&secret, &mem).unwrap();
        app.keep_memory(&a);
        assert_eq!(std::fs::read_to_string(app.data_memory_file(&a.id).unwrap()).unwrap(), "# A1\n\nLearned a thing.\n");
        assert!(!app.system_prompt(&a).contains("not yours"));
        std::fs::remove_file(&mem).unwrap();
        app.init_bot_files(&a);

        // Handed to Bea: it leaves Ada's folder and starts again in Bea's.
        assert!(app.db.set_bot_owner_capped(&a.id, &bea.id, None));
        app.hand_over_memory(&a.id, &ada.id, &bea.id);
        assert!(!mem.exists());
        // Ada's run, stopped by the handover, ends after it: what it wrote is dropped.
        std::fs::write(&mem, "# A1\n\nWritten after the handover.\n").unwrap();
        app.keep_memory(&a);
        assert!(!mem.exists());
        assert!(std::fs::read_to_string(app.data_memory_file(&a.id).unwrap()).unwrap().contains("Learned a thing."));
        let b = app.db.bot(&a.id).unwrap();
        app.init_bot_files(&b);
        assert!(std::fs::read_to_string(app.memory_file(&b).unwrap()).unwrap().contains("Learned a thing."));
        assert_eq!(app.memory_file(&b).unwrap().parent().unwrap(), root.join(&bea.id).join("memory"));
    }

    #[test]
    fn isolated_copies_keep_cleared_memory_and_are_remade_after_isolation_was_off() {
        use crate::acl::Visibility;
        use crate::rbac::Role;
        let (app, root) = isolated_app("/bin/false");
        let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let a = app.db.create_bot_owned("A1", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Private);
        std::fs::create_dir_all(root.join(&ada.id).join("memory")).unwrap();
        app.init_bot_files(&a);
        let (mem, kept) = (app.memory_file(&a).unwrap(), app.data_memory_file(&a.id).unwrap());
        let read = |p: &Path| std::fs::read_to_string(p).unwrap();

        // A Bot that clears its memory keeps it cleared, as it would without accounts.
        std::fs::write(&mem, "").unwrap();
        app.keep_memory(&a);
        assert_eq!(read(&kept), "");

        // While accounts stay on, a copy is never replaced, even when botd's original was
        // written after it: another Bot's run may have saved an older snapshot meanwhile.
        let facts = app.user_file(&ada.id).unwrap();
        std::fs::write(&facts, "# About the user\n- edited by B1, still running\n").unwrap();
        std::fs::write(app.data_user_file(&ada.id).unwrap(), "# About the user\n- A1's older snapshot\n").unwrap();
        app.init_bot_files(&a);
        assert_eq!(read(&facts), "# About the user\n- edited by B1, still running\n");

        // Turned off, then on again: runs changed the originals meanwhile, so the old copies
        // are dropped at startup and made again, never copied back over the originals.
        app.db.save_isolation(false);
        std::fs::write(&mem, "# A1\n- from before\n").unwrap();
        std::fs::write(&kept, "# A1\n- learned while off\n").unwrap();
        // A copy it can't remove keeps the cleanup due at the next start.
        std::fs::remove_file(&facts).unwrap();
        std::fs::create_dir(&facts).unwrap();
        app.start_isolation();
        assert!(!mem.exists() && !app.db.isolation_was_on());
        std::fs::remove_dir(&facts).unwrap();
        std::fs::write(&mem, "# A1\n- from before\n").unwrap();
        app.start_isolation();
        assert!(!mem.exists() && app.db.isolation_was_on());
        app.init_bot_files(&a);
        assert_eq!(read(&mem), "# A1\n- learned while off\n");
        app.keep_memory(&a);
        assert_eq!(read(&kept), "# A1\n- learned while off\n");

        // The next start, still on, keeps what runs left.
        std::fs::write(&mem, "# A1\n- learned just now\n").unwrap();
        app.start_isolation();
        assert_eq!(read(&mem), "# A1\n- learned just now\n");
    }

    #[tokio::test]
    async fn isolated_runs_never_fall_back_to_botds_account() {
        let (app, _) = isolated_app("/bin/false");
        let who = Who::system("test");
        for harness in ["pi", "hermes"] {
            let bot = app.db.create_bot("P", "#fff", "waddle", harness, None, true);
            let msg = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
            assert_eq!(app.isolate(&bot, &msg, &who, "2026-11").await, Err(()), "{harness}");
            let last = app.db.messages(&bot.id, 1).pop().unwrap();
            assert!(last.error && last.text.contains("Claude Code or Codex"), "{}", last.text);
        }
        let refused = actions(&app, "bot.run_refused");
        assert!(refused.iter().all(|e| e.details["reason"] == "isolation_harness"), "{refused:?}");
        assert_eq!(refused.len(), 2);

        // The account can't be made: refused, and the failure is audited.
        let bot = app.db.create_bot("C", "#fff", "waddle", "claude", None, true);
        let msg = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        assert_eq!(app.isolate(&bot, &msg, &who, "2026-11").await, Err(()));
        let refused = actions(&app, "bot.run_refused");
        assert_eq!(refused.last().unwrap().details["reason"], "no_account");
        assert_eq!(refused.last().unwrap().details["account"], format!("sb-u-{}", bot.owner_id));
        let failed = actions(&app, "isolation.account_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].outcome, "failure");
        assert!(actions(&app, "harness.invoked").is_empty());
    }

    #[test]
    fn bot_files_stay_in_the_data_folder() {
        let app = test_app();
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        app.init_bot_files(&bot);
        let dir = app.bot_dir(&bot.id).unwrap();
        assert_eq!(dir, app.cfg.data_dir.join("bots").join(&bot.id));
        assert_eq!(app.memory_file(&bot), app.data_memory_file(&bot.id));
        assert!(app.memory_file(&bot).unwrap().is_file());
        assert_eq!(app.user_file(&bot.owner_id).unwrap(), app.cfg.data_dir.join("users").join(&bot.owner_id).join("USER.md"));
        assert!(app.user_file(&bot.owner_id).unwrap().is_file());
        for bad in ["", "..", "../../etc", "a/b", "/etc"] {
            assert_eq!(app.bot_dir(bad), None, "{bad:?}");
            assert_eq!(app.data_memory_file(bad), None, "{bad:?}");
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
            Some(Run { abort: tx, status: String::new(), draft: String::new(), hooks: Default::default(), hook_wait, ctx: None });
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
