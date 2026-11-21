//! Runs Bots: one task at a time per Bot, in order. Builds the system prompt
//! (identity, rules, memory), streams harness events to the web app, and saves replies.

use crate::accounts::{self, Isolation, RunAs, Space};
use crate::acl::{Access, SharedBots, Viewer, Visibility};
use crate::adapters::{self, AbortReason, AgentEvent, Guard, RunInput, Sandbox, Usage};
use crate::audit::{Actor, ActorKind, Event, Outcome, Who};
use crate::db::{Bot, BotPatch, Db, Message, TokenRow};
use crate::machines::ControlPlane;
use crate::machines::route::{self, Assigned, Refusal, Target};
use crate::machines::wire::{self, JobEvent};
use crate::tiers::{self, Route, Tier, Tiers, Wiring};
use crate::{isolation, paths, usage};
use crate::approvals::RunGrant;
use crate::policy::{Ctx, Mode, RunScope};
use crate::screen::{self, Screens};
use crate::slots::{self, Slot, Slots, Turn};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch, Notify};

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
    /// What this server has for harness sandboxes (`sandbox::host`).
    pub sandbox_host: crate::sandbox::Host,
    /// botd's HOME, which its own runs share, for their package caches.
    pub home: Option<PathBuf>,
}

struct Run {
    /// The run's id (`runId` in the audit log). Its hook sends it as `SUPERBOT_RUN_ID`.
    id: String,
    /// Calls people approved for the rest of this run (ADR 0051). Never stored: they end with it.
    grants: Vec<RunGrant>,
    abort: watch::Sender<AbortReason>,
    status: String,
    draft: String,
    /// Approval hook calls during this run.
    hooks: Arc<AtomicU32>,
    /// Longest an approval may wait: just under the harness's hook timeout.
    hook_wait: Option<Duration>,
    /// The folders its tool calls are judged by, when it isn't on this server.
    ctx: Option<Ctx>,
    /// The teammate whose account here it runs in (ADR 0064), if any.
    teammate: Option<String>,
}

/// Where a run happens: here, or on its owner's machine (ADR 0036).
enum Place {
    Here,
    /// The owner's machine, and the teammate's own user there the run is for (ADR 0048).
    There(Box<(Assigned, wire::Layout, Option<wire::TeammateReply>)>),
}

/// What a job on a machine sent back: files by path, and those too big to send.
type Back = (std::collections::BTreeMap<String, String>, Vec<String>);

/// What a run sees where it happens: its folders, environment, and tools there.
struct Spot {
    machine: Option<Assigned>,
    cwd: PathBuf,
    state_dir: PathBuf,
    /// Where botd writes the harness's files: `state_dir`, except with per-user accounts.
    config_dir: PathBuf,
    memory: PathBuf,
    user_file: PathBuf,
    botctl: PathBuf,
    env: HashMap<String, String>,
    screens: bool,
    ctx: Option<Ctx>,
    /// The person the run is for, when that isn't the Bot's owner and shared Bots are
    /// isolated (ADR 0046): the run gets neither the owner's own keys nor their facts.
    for_other: Option<String>,
    /// The teammate's own OS user the run is for on the machine (ADR 0048).
    teammate_user: Option<String>,
    /// What the computer the run happens on has for harness sandboxes (ADR 0055).
    /// None: a machine agent from before it said.
    sandbox_host: Option<crate::sandbox::Host>,
    /// The run's HOME there, which a sandbox keeps read-only, and its package caches,
    /// which it doesn't.
    home: Option<PathBuf>,
    caches: Vec<PathBuf>,
}

impl Spot {
    /// The sandbox a run gets, and what the audit log says of it (ADR 0055).
    fn sandbox(&self, wanted: bool, supported: bool, needs: &[&str]) -> (Option<Sandbox>, &'static str) {
        if !wanted {
            return (None, "off");
        }
        if !supported {
            return (None, "unsupported");
        }
        if self.sandbox_host.as_ref().is_some_and(|h| !h.has(needs)) {
            return (None, "unavailable");
        }
        // Its memory and facts files' folders, never HOME itself (a machine keeps USER.md
        // there). Someone else's run doesn't get the owner's facts (ADR 0046). Here each
        // must exist; on a machine the job makes the memory folder.
        let facts = self.for_other.is_none().then_some(&self.user_file);
        let mut writable: Vec<PathBuf> = Vec::new();
        for dir in [Some(&self.memory), facts].into_iter().flatten().filter_map(|p| p.parent()) {
            let usable = !dir.as_os_str().is_empty()
                && dir != self.cwd
                && self.home.as_deref() != Some(dir)
                && (self.machine.is_some() || dir.is_dir());
            if usable && !writable.iter().any(|w| w == dir) {
                writable.push(dir.to_path_buf());
            }
        }
        writable.extend(self.caches.iter().cloned());
        // An older agent can't say; the settings do no harm where the sandbox can't start.
        (Some(Sandbox { writable }), if self.sandbox_host.is_some() { "on" } else { "unverified" })
    }
}

#[derive(Default)]
struct BotState {
    queue: VecDeque<Message>,
    draining: bool,
    run: Option<Run>,
    /// Stopped while the message it took was still starting (being placed, waiting for
    /// a slot, or its harness checked), before it had a `run` to abort.
    stopped: bool,
    /// Wakes its run while it waits for a slot (ADR 0073), to see `stopped`.
    wake: Option<Arc<Notify>>,
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
    /// Asks waiting on a Bot: the asked Bot's id, then each asking Bot's (ADR 0073).
    asks: Mutex<HashMap<String, Vec<String>>>,
    /// Tool calls waiting on the user, by approval id. true = approved.
    pub approval_waiters: Mutex<HashMap<String, crate::approvals::Waiter>>,
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
    /// Runs at once on each computer, and the runs waiting their turn (ADR 0073).
    pub slots: Arc<Slots>,
    /// MAX_CONCURRENT_RUNS: runs at once on this server, and on a machine whose owner's
    /// tier sets none. None: no cap. Unset: `slots::DEFAULT_CAP`.
    pub run_cap: OnceLock<Option<u32>>,
    /// SHARED_BOTS (ADR 0046). Unset: isolated when MACHINE_ROUTING isn't off.
    pub shared_bots: OnceLock<SharedBots>,
    /// With isolated shared Bots: whom each Bot's latest run is for, by Bot. Kept after
    /// the run ends, so whatever it left running stays capped until the next run.
    askers: Mutex<HashMap<String, String>>,
    /// ROUTINES_ON_ENABLE=resume (ADR 0047): re-enabling a user resumes the routines
    /// paused when they were disabled. Unset: they stay paused until an admin resumes them.
    pub resume_routines_on_enable: OnceLock<bool>,
    /// STRIPE_METER_EVENT (ADR 0050): reports each run's tokens to a Stripe meter. Unset: off.
    pub meter: OnceLock<Arc<crate::billing::Meter>>,
    /// Email and webhook notices for pending approvals (ADR 0061). Unset: none.
    pub notifier: OnceLock<Arc<crate::notify::Notifier>>,
    /// Teammates' own harness logins for owners' shared Bots here (ADR 0064).
    pub teammate_logins: crate::teammate_logins::Local,
    /// Removals of leaving teammates' accounts here being tried now (ADR 0066).
    pub account_removals: crate::machines::offboard::Working,
    /// Teammate accounts here in use and being removed, kept apart (ADR 0066).
    pub teammate_gate: crate::teammate_removals::Gate,
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
            asks: Mutex::default(),
            approval_waiters: Mutex::default(),
            control_plane: OnceLock::new(),
            tiers: OnceLock::new(),
            isolation: OnceLock::new(),
            on_machines: Mutex::default(),
            slots: Arc::default(),
            run_cap: OnceLock::new(),
            shared_bots: OnceLock::new(),
            askers: Mutex::default(),
            resume_routines_on_enable: OnceLock::new(),
            meter: OnceLock::new(),
            notifier: OnceLock::new(),
            teammate_logins: Default::default(),
            account_removals: Default::default(),
            teammate_gate: Default::default(),
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

    /// The id of the Bot's run now, if it has one.
    pub fn live_run(&self, bot_id: &str) -> Option<String> {
        self.with_run(bot_id, |r| Some(r.id.clone()))
    }

    /// The grant in the Bot's run `run_id` that covers a call, if that run is still live.
    pub fn run_grant(&self, bot_id: &str, run_id: &str, scope: &RunScope) -> Option<RunGrant> {
        self.with_run(bot_id, |r| if r.id == run_id { r.grants.iter().find(|g| g.scope.covers(scope)).cloned() } else { None })
    }

    /// Adds a grant to the Bot's run `run_id`. False if that run has ended.
    pub fn add_run_grant(&self, bot_id: &str, run_id: &str, grant: RunGrant) -> bool {
        self.with_run(bot_id, |r| {
            if r.id != run_id {
                return false;
            }
            r.grants.push(grant);
            true
        })
    }

    pub fn set_run_status(&self, bot_id: &str, status: &str) {
        if self.with_run(bot_id, |r| { r.status = status.into(); true }) {
            self.send(json!({ "type": "status", "botId": bot_id, "working": true, "status": status }));
        }
    }

    /// How shared Bots behave for people other than their owner (ADR 0046).
    pub fn shared_bots(&self) -> SharedBots {
        self.shared_bots.get().copied().unwrap_or_else(|| match self.control_plane.get() {
            Some(cp) if cp.routing != route::Routing::Off => SharedBots::Isolated,
            _ => SharedBots::Open,
        })
    }

    /// The access a Bot acts with toward other Bots: its owner's (ADR 0017), and with
    /// isolated shared Bots no more than that of the person its latest run is for.
    pub fn bot_viewer(&self, bot: &Bot) -> Viewer {
        let owner = Viewer::owner_of(&self.db, bot);
        match self.askers.lock().unwrap_or_else(|e| e.into_inner()).get(&bot.id) {
            Some(a) if *a != bot.owner_id => owner.within(Viewer::person(&self.db, a)),
            _ => owner,
        }
    }

    /// Whom a Bot acts for now: the person its latest run is for, else its owner.
    pub fn acting_for(&self, bot: &Bot) -> String {
        self.askers.lock().unwrap_or_else(|e| e.into_inner()).get(&bot.id).cloned().unwrap_or_else(|| bot.owner_id.clone())
    }

    /// Whom a run is for (ADR 0046): the person who asked, through any number of Bots,
    /// or a routine's author; else the Bot's owner.
    fn asker_of(bot: &Bot, by: &Who) -> String {
        let a = &by.actor;
        let person = match a.kind {
            ActorKind::User => a.id.clone(),
            ActorKind::Bot => a.on_behalf_of.clone(),
            ActorKind::System => None,
        };
        a.asker.clone().or(person).unwrap_or_else(|| bot.owner_id.clone())
    }

    /// Where a Bot's runs go now, as anyone who can see it may know (ADR 0046): `server`,
    /// `machine` (its owner's) or `nowhere`. None while routing is off: always here.
    /// Whether `owner_id`'s Bots run on this server: no machines, or routing says here.
    pub fn runs_here(&self, owner_id: &str) -> bool {
        self.control_plane.get().is_none_or(|cp| matches!(cp.route(&self.db, owner_id), Ok(Target::Local)))
    }

    pub fn runs_on(&self, bot: &Bot) -> Option<&'static str> {
        let cp = self.control_plane.get().filter(|cp| cp.routing != route::Routing::Off)?;
        Some(match cp.route(&self.db, &bot.owner_id) {
            Ok(Target::Local) => "server",
            Ok(Target::Machine(_)) => "machine",
            Err(_) => "nowhere",
        })
    }

    pub fn tiers(&self) -> &Tiers {
        static SELF_HOST: OnceLock<Tiers> = OnceLock::new();
        self.tiers.get().map_or_else(|| SELF_HOST.get_or_init(Tiers::self_host), |t| t.as_ref())
    }

    /// The billing period `at` (Unix ms) falls in for a user (ADR 0050): their paid
    /// subscription's month, else the calendar month.
    pub fn billing_period(&self, user_id: &str, at: i64) -> usage::Period {
        let sub = self.db.subscription(user_id).filter(|s| s.tier.is_some());
        usage::period_at(sub.map(|s| (s.period_start, s.period_end)), at)
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

    /// Running, or with work queued or waiting for a slot: a run already holds its settings.
    pub fn is_busy(&self, bot_id: &str) -> bool {
        self.state().contains_key(bot_id)
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
            "visibility": b.visibility, "prompts": b.prompts,
        });
        let has_login = crate::machines::logins::recipe(&b.harness).is_some();
        if let Some(on) = self.runs_on(b) {
            v["runsOn"] = json!(on);
            // Teammates log in with their own account on the owner's machine (ADR 0062).
            let teammates_log_in = self.control_plane.get().and_then(|cp| cp.enrollment.as_ref()).is_some_and(|e| e.logins && e.teammate_users);
            if on == "machine" && teammates_log_in && has_login {
                v["teammateLogins"] = json!(true);
            }
        }
        // And with their own account on this server (ADR 0064).
        if has_login && crate::teammate_logins::on(self, &b.owner_id) {
            v["teammateLogins"] = json!(true);
        }
        if self.shared_bots() == SharedBots::Isolated {
            v["sharedBots"] = json!(SharedBots::Isolated);
        }
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
        } else if let Some((pool, turn)) = self.slots.waiting(&b.id) {
            v["working"] = json!(true);
            v["status"] = json!(waiting_status(&pool, turn));
            v["queued"] = queue_view(&pool, turn);
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
        self.ensure_space(Space::User(user_id), by).await
    }

    /// `ensure_account` for any space: a user's own, or a teammate's for one owner's
    /// shared Bots (ADR 0064). Audited against the owner, with `forUser` for a teammate's.
    pub async fn ensure_space(&self, space: Space<'_>, by: &Who) -> Result<RunAs, String> {
        let iso = self.isolation.get().cloned().ok_or("Per-user accounts are off (ISOLATION=users turns them on).")?;
        let run_as = iso.run_as_in(space).ok_or_else(|| format!("{space:?} can't be part of a Unix account name."))?;
        let (owner, teammate) = match space {
            Space::User(u) => (u.to_string(), None),
            Space::Teammate { owner, teammate } => (owner.to_string(), Some(teammate.to_string())),
        };
        let made = tokio::task::spawn_blocking({
            let (iso, owner, teammate) = (iso.clone(), owner.clone(), teammate.clone());
            move || iso.ensure_in(Space::of(&owner, teammate.as_deref()))
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        let event = |action: &str| by.event(action).target("user", &owner);
        let mut details = json!({ "account": run_as.account });
        if let Some(t) = &teammate {
            details["forUser"] = json!(t);
            if made.is_ok() {
                self.db.teammate_space_made(&owner, t);
            }
        }
        match made {
            Ok(false) => Ok(run_as),
            Ok(true) => {
                details["home"] = json!(iso.home_in(space));
                self.db.record(&event("isolation.account_created").details(details));
                Ok(run_as)
            }
            Err(e) => {
                eprintln!("Isolation: couldn't set up a user's account (see isolation.account_failed in the audit log): {e}");
                details["error"] = json!(e);
                self.db.record(&event("isolation.account_failed").outcome(Outcome::Failure).details(details));
                Err(e)
            }
        }
    }

    /// Whether a teammate's run of a shared Bot here uses an account of its own
    /// (`ISOLATION_TEAMMATES`, ADR 0064).
    pub fn teammate_accounts(&self) -> bool {
        self.shared_bots() == SharedBots::Isolated && self.isolation().is_some_and(|i| i.teammates)
    }

    /// Where a Bot's run happens and what it gets: its owner's working folder, and
    /// the server-wide secrets plus its owner's, never another user's. `BOT_TOKEN`
    /// proves to botd which Bot is calling, so it can only act as itself.
    #[cfg(test)]
    pub(crate) fn run_space(&self, bot: &Bot) -> Option<(PathBuf, HashMap<String, String>)> {
        self.run_space_with(bot, true)
    }

    /// `run_space`, with the owner's own secrets only if `owner_keys`: a run for someone
    /// else under isolated shared Bots gets the server-wide ones alone (ADR 0046).
    fn run_space_with(&self, bot: &Bot, owner_keys: bool) -> Option<(PathBuf, HashMap<String, String>)> {
        let cwd = self.workspace_for(&bot.owner_id)?;
        let s = crate::secrets::global();
        let keys = if owner_keys { s.harness_env_for(&bot.owner_id) } else { s.harness_env() };
        let mut env: HashMap<String, String> = keys.into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
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
                let m = st.get_mut(&bot_id).and_then(|s| {
                    s.stopped = false;
                    s.queue.pop_front()
                });
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
        let Some((bin, has_sandbox, sandbox_needs)) = adapters::get(&bot.harness).map(|a| (a.bin(), a.has_sandbox(), a.sandbox_needs())) else {
            return cant_run(&format!("Unknown harness \"{}\".", bot.harness));
        };
        let Some(bot_dir) = self.bot_dir(&bot.id) else {
            return cant_run("This Bot's id isn't a safe folder name, so it can't run.");
        };
        let by = self.requester(&bot, msg);
        // A routine queued before its owner or author was disabled doesn't run (ADR 0047).
        if msg.role == "routine"
            && let Some((reason, user)) = crate::handover::blocked(&self.db, &bot.owner_id, by.actor.asker.as_deref())
        {
            self.give_back_routine(&bot, msg);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            self.db.record(&e.details(json!({ "reason": reason, "owner": bot.owner_id, "forUser": user, "messageId": msg.id })));
            return;
        }
        let isolated = self.shared_bots() == SharedBots::Isolated;
        let for_other = Some(Self::asker_of(&bot, &by)).filter(|a| isolated && *a != bot.owner_id);
        if isolated && let Some((reason, text)) = self.wont_run(&bot, for_other.as_deref()) {
            self.give_back_routine(&bot, msg);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            self.db.record(&e.details(json!({ "reason": reason, "owner": bot.owner_id, "forUser": for_other, "messageId": msg.id })));
            // A routine of a disabled owner keeps firing; one bubble says it.
            if self.db.last_message(&bot.id).is_none_or(|m| m.text != text) {
                self.say(&bot.id, &text, true);
            }
            return;
        }
        let Some(space) = self.run_space_with(&bot, for_other.is_none()) else {
            return cant_run("This Bot's owner id isn't a safe folder name, so it can't run.");
        };
        if isolated {
            let asker = for_other.clone().unwrap_or_else(|| bot.owner_id.clone());
            self.askers.lock().unwrap_or_else(|e| e.into_inner()).insert(bot.id.clone(), asker);
        }
        // The owner's session holds their conversation, and some harnesses keep its first
        // instructions: a run for someone else starts fresh and keeps nothing.
        if for_other.is_some() {
            bot.session_id = None;
        }
        let period = self.billing_period(&bot.owner_id, crate::db::now());
        let Some((tier, route, wiring)) = self.tier_route(&bot, msg, &by, &period, &space.1) else { return };
        let placed_at = self.db.placed_at(&bot.owner_id);
        let Some(place) = self.place(&bot, msg, &by, &period.key, bin, for_other.as_deref()).await else { return };
        // Held until the run ends, however it ends: dropping it lets the next run in.
        let Some((_slot, waited)) = self.slot_for(&bot, msg, &by, &period.key, &place).await else { return };
        // The owner, a routine's author or the asker may have been turned off meanwhile.
        if waited && let Some((reason, user, text)) = self.refused_after_wait(&bot, msg, &by, for_other.as_deref()) {
            self.give_back(&bot, msg, &period.key);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            self.db.record(&e.details(json!({ "reason": reason, "owner": bot.owner_id, "forUser": user, "messageId": msg.id })));
            if let Some(text) = text {
                self.say(&bot.id, &text, true);
            }
            return;
        }
        // A teammate's run here gets an account of its own (ADR 0064), never the owner's.
        let teammate = for_other.as_deref().filter(|_| matches!(place, Place::Here) && self.teammate_accounts());
        let run_space = Space::of(&bot.owner_id, teammate);
        // Nothing starts in a teammate's account while it's being removed (ADR 0066), and
        // access is checked again once let in, so a removal never races a run past it.
        let _in_use = match teammate {
            Some(t) => {
                let entered = crate::teammate_removals::enter(self, &bot.owner_id, t);
                let refusal = match &entered {
                    None => Some(("account_being_removed", "Your account for these Bots on this server is being removed, so I didn't run. Try again in a few minutes.".to_string())),
                    Some(_) => self.wont_run(&bot, Some(t)),
                };
                if let Some((reason, text)) = refusal {
                    self.give_back(&bot, msg, &period.key);
                    let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
                    self.db.record(&e.details(json!({ "reason": reason, "owner": bot.owner_id, "forUser": t, "messageId": msg.id })));
                    self.say(&bot.id, &text, true);
                    return;
                }
                entered
            }
            None => None,
        };
        // The owner's own machine runs only their Bots, so only runs here need their account.
        let run_as = match place {
            Place::Here => match self.isolate(&bot, msg, &by, &period.key, teammate).await {
                Ok(r) => r,
                Err(()) => return,
            },
            Place::There(_) => None,
        };
        let mut spot = self.spot(&bot, bot_dir.clone(), space, place, for_other.as_deref());
        spot.for_other = for_other.clone();
        // With per-user accounts the harness keeps its state in its account's folder, and
        // reads botd's files from one it can't change (`isolate` made both).
        if run_as.is_some()
            && let Some(iso) = self.isolation()
            && let (Some(state), Some(settings)) = (iso.bot_state_in(run_space, &bot.id), iso.bot_settings_in(run_space, &bot.id))
        {
            (spot.state_dir, spot.config_dir) = (state, settings);
        }
        if let (Some(u), Some(iso)) = (teammate, self.isolation()) {
            self.in_teammate_space(&mut spot, iso, &bot, u);
        }
        if self.missing_here(&bot, msg, &by, &period.key, &spot, bin) {
            return;
        }
        if self.hooks_refused(&bot, msg, &by, &period.key, &spot, run_as.as_ref()).await {
            return;
        }
        // Caches are made as the run's user: by botd when it is that user, by
        // `superbot-run` for a per-user account, which botd can't make folders for.
        if spot.machine.is_none() {
            spot.home = match &run_as {
                Some(_) => self.isolation().and_then(|i| i.home_in(run_space)),
                None => self.cfg.home.clone(),
            };
            if self.db.effective_policy(&bot.id).sandbox && has_sandbox {
                let made = if run_as.is_some() { crate::sandbox::makeable_caches } else { crate::sandbox::ensure_caches };
                spot.caches = spot.home.as_deref().map(made).unwrap_or_default();
                // `superbot-run` makes the account's own TMPDIR there.
                if run_as.is_some()
                    && let Some(home) = &spot.home
                {
                    spot.caches.push(home.join(".tmp"));
                }
            }
        }
        let screen_for = spot.teammate_user.as_ref().and(for_other.as_deref());
        if let Some(to) = spot.machine.clone()
            && let Some(env) = crate::machines::screens::for_run(self, &bot, screen_for, &to, &spot.state_dir).await
        {
            spot.env.extend(env);
            spot.screens = true;
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
        let host = json!({ "host": if spot.machine.is_some() { "machine" } else { "server" }, "machine": spot.machine.as_ref().map(|m| &m.machine_id) });
        let run_id = format!("r{}", crate::random_hex(8));
        // Tokens every attempt reported: a retried attempt spent them too.
        let mut used: Vec<Usage> = Vec::new();
        // A retried attempt is the same task, so what was approved for it still holds.
        let mut grants: Vec<RunGrant> = Vec::new();

        for attempt in 0..2 {
            let (abort_tx, abort_rx) = watch::channel(None);
            // Ask mode: the harness calls `botctl hook` before every tool. Its hook timeout
            // stays above our wait, so the hook is never killed into failing open. A harness
            // that caps hook timeouts gets a shorter wait instead.
            let policy = self.db.effective_policy(&bot.id);
            let test_secs = match self.license.status().testing() {
                true => test_hook_secs(&std::env::var(TEST_HOOK_TIMEOUT).unwrap_or_default()).unwrap_or_default(),
                false => None,
            };
            let guard = (policy.mode == Mode::Ask).then(|| guard(&spot.botctl, &bot.harness, policy.timeout_minutes, test_secs));
            let (sandbox, sandboxed) = spot.sandbox(policy.sandbox, has_sandbox, sandbox_needs);
            let hooks = Arc::new(AtomicU32::new(0));
            {
                // Under the lock `stop_if` takes, so a stop lands here or on the run.
                let mut st = self.state();
                let s = st.entry(bot.id.clone()).or_default();
                if std::mem::take(&mut s.stopped) {
                    drop(st);
                    if attempt == 0 {
                        self.give_back(&bot, msg, &period.key);
                    }
                    self.say(&bot.id, "Stopped.", true);
                    return;
                }
                s.run = Some(Run {
                    id: run_id.clone(),
                    grants: std::mem::take(&mut grants),
                    abort: abort_tx.clone(),
                    status: "Thinking".into(),
                    draft: String::new(),
                    hooks: hooks.clone(),
                    hook_wait: guard.as_ref().map(|g| g.wait),
                    ctx: spot.ctx.clone(),
                    teammate: teammate.map(String::from),
                });
            }
            self.send(json!({ "type": "status", "botId": bot.id, "working": true, "status": "Thinking" }));
            let timeout = self.cfg.run_timeout;
            let timer = tokio::spawn({
                let abort_tx = abort_tx.clone();
                async move {
                    tokio::time::sleep(timeout).await;
                    abort_tx.send_if_modified(|r| r.get_or_insert("timeout") == &"timeout");
                }
            });

            // Made fresh from botd's for each teammate's run; kept back after it.
            if teammate.is_some() {
                self.seed_teammate_memory(&bot, &spot.memory);
            }
            let mut env = spot.env.clone();
            // Nothing botd starts inherits a tier endpoint's key, so a run routed to one
            // is given it, and only it.
            crate::adapters::withhold(self.tiers().providers().iter().map(|p| p.key_secret.clone()));
            env.retain(|k, _| !wiring.unused_keys.contains(k));
            for e in &wiring.endpoints {
                if let Some(v) = tier_key(&env, &e.key_secret) {
                    crate::secrets::redact::register(&v);
                    env.insert(e.key_secret.clone(), v);
                }
            }
            env.insert("SUPERBOT_RUN_ID".into(), run_id.clone());
            if spot.screens
                && spot.machine.is_none()
                && let Some(screens) = &self.screens
                && let Some(info) = screens.ensure(&bot.id, |id| self.is_running(id)).await
            {
                env.extend(screen::bot_env(&info, &bot.id, &bot_dir));
            }
            let mut invoked = json!({
                "harness": bot.harness, "model": route.model, "effort": route.effort, "provider": route.provider, "tier": tier, "policy": policy.mode,
                "guarded": guard.is_some(), "sandbox": sandboxed, "resumed": bot.session_id.is_some(), "attempt": attempt + 1,
                "trigger": msg.role, "messageId": msg.id, "runId": run_id,
            });
            merge(&mut invoked, &host);
            if let Some(f) = &wiring.fallback {
                invoked["fallback"] = json!(f);
            }
            if !wiring.skipped.is_empty() {
                invoked["fallbackSkipped"] = json!(wiring.skipped);
            }
            if let Some(r) = &run_as {
                invoked["runAs"] = json!(r.account);
            }
            if let Some(u) = &for_other {
                invoked["forUser"] = json!(u);
            }
            if let Some(u) = &spot.teammate_user {
                invoked["teammateUser"] = json!(u);
            }
            self.db.record(&by.event("harness.invoked").target("message", &msg.id.to_string()).bot(&bot.id).details(invoked));
            let input = RunInput {
                prompt: prompt.clone(),
                system: self.system_prompt_at(&bot, &spot),
                session_id: bot.session_id.clone(),
                cwd: spot.cwd.clone(),
                provider: route.provider.clone(),
                endpoints: wiring.endpoints.clone(),
                fallback: wiring.fallback.clone(),
                model: route.model.clone(),
                effort: route.effort.clone(),
                env,
                state_dir: spot.state_dir.clone(),
                config_dir: spot.config_dir.clone(),
                guard: guard.clone(),
                run_as: run_as.clone(),
                sandbox,
            };

            let mut errors: Vec<String> = Vec::new();
            let mut replies = 0;
            let id = bot.id.clone();
            let mut canary: Option<tokio::task::JoinHandle<()>> = None;
            let mut saw_tool = false;
            let gate = adapters::get(&bot.harness).unwrap();
            let emit = |e| {
                // Fail closed: a guarded harness that runs a tool its hook covers without
                // ever calling the hook isn't enforcing approvals, so stop it.
                if guard.is_some() && canary.is_none() && adapters::arms_canary(&*gate, &e) {
                    saw_tool = true;
                    let (hooks, abort) = (hooks.clone(), abort_tx.clone());
                    canary = Some(tokio::spawn(async move {
                        tokio::time::sleep(HOOK_GRACE).await;
                        if hooks.load(Ordering::SeqCst) == 0 {
                            abort.send_if_modified(|r| r.get_or_insert("unguarded") == &"unguarded");
                        }
                    }));
                }
                match e {
                    AgentEvent::Session(s) => {
                        if for_other.is_none() {
                            self.db.keep_session(&id, &s, placed_at);
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
                        let status = tool_label(&name, &detail);
                        self.with_run(&id, |r| r.status = status.clone());
                        self.send(json!({ "type": "status", "botId": id, "working": true, "status": status }));
                    }
                    AgentEvent::ToolRan { .. } => {}
                    AgentEvent::Error(m) => errors.push(m),
                    AgentEvent::Usage(u) => used.push(u),
                }
            };
            let adapter = adapters::get(&bot.harness).unwrap();
            match &spot.machine {
                None => {
                    adapters::run(adapter, input, abort_rx.clone(), emit).await;
                    match teammate {
                        Some(_) => self.keep_teammate_memory(&bot, &spot.memory, &by),
                        None => self.keep_memory(&bot),
                    }
                }
                Some(to) => self.run_there(&bot, msg, &spot, to, adapter, input, abort_rx.clone(), emit).await,
            }
            timer.abort();
            if let Some(c) = canary {
                c.abort();
            }
            // A run that ends before the canary fires still has to report a missing hook.
            if saw_tool && hooks.load(Ordering::SeqCst) == 0 {
                abort_tx.send_if_modified(|r| r.get_or_insert("unguarded") == &"unguarded");
            }
            self.cancel_approvals(&id, "The task ended");
            // Done running. The stream may have ended without a final block: keep what was streamed.
            let (draft, kept) = self.state().get_mut(&id).and_then(|s| s.run.take()).map(|r| (r.draft, r.grants)).unwrap_or_default();
            grants = kept;
            if !draft.trim().is_empty() {
                replies += 1;
                self.say(&id, &draft, false);
            }

            // The harness lost its session (e.g. its files were wiped) or won't resume it
            // on this route: start fresh once.
            let lost = errors.iter().any(|m| {
                if gate.resume_refused(m) {
                    return true;
                }
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
                Some("removed") => ("account_removed", Outcome::Failure),
                Some(r @ ("unguarded" | "policy")) => (r, Outcome::Denied),
                Some("timeout") => ("timeout", Outcome::Failure),
                _ if !errors.is_empty() => ("error", Outcome::Failure),
                _ => ("done", Outcome::Success),
            };
            let tokens = self.record_tokens(&bot, msg, &run_id, &route, std::mem::take(&mut used));
            let mut finished = json!({
                "result": result, "durationMs": started.elapsed().as_millis() as u64, "replies": replies,
                "attempts": attempt + 1, "trigger": msg.role, "messageId": msg.id, "runId": run_id, "usage": tokens,
            });
            merge(&mut finished, &host);
            if !grants.is_empty() {
                finished["runGrants"] = json!(grants.iter().map(|g| &g.approval_id).collect::<Vec<_>>());
            }
            self.db.record(&by.event("bot.run_finished").target("message", &msg.id.to_string()).bot(&bot.id).outcome(outcome).details(finished));
            match reason {
                Some("shutdown") => {}
                Some("stopped") => self.say(&id, "Stopped.", true),
                Some("removed") => self.say(&id, "I stopped: the account this task ran in on this server is being removed.", true),
                Some("unguarded") => self.say(
                    &id,
                    &format!(
                        "I stopped: {} used a tool without checking SuperBot's approval gate, so approvals aren't enforced for me. \
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

    /// This server's cap on runs at once (ADR 0073). None: no cap.
    pub fn server_cap(&self) -> Option<u32> {
        self.run_cap.get().copied().unwrap_or(Some(slots::DEFAULT_CAP))
    }

    /// The cap on runs at once on `owner_id`'s machine: their tier's, else the server's.
    pub fn machine_cap(&self, owner_id: &str) -> Option<u32> {
        self.tier_of(owner_id).limits.concurrent_runs.or_else(|| self.server_cap())
    }

    /// A slot on the computer the run happens on (ADR 0073): at once, or once the runs
    /// ahead of it there are done. Waiting is shown on the Bot and audited. None: it was
    /// stopped or botd shut down while it waited; the run is given back. With the slot:
    /// whether it waited for it.
    async fn slot_for(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, place: &Place) -> Option<(Slot, bool)> {
        let (pool, cap, machine) = match place {
            Place::Here => (slots::SERVER.to_string(), self.server_cap(), None),
            Place::There(t) => (t.0.machine_id.clone(), self.machine_cap(&bot.owner_id), Some(t.0.machine_id.clone())),
        };
        let mut queued = match self.slots.take(&pool, cap, &bot.id, self.lend(&bot.id, &pool)) {
            Ok(slot) => return Some((slot, false)),
            Err(q) => q,
        };
        let wake = Arc::new(Notify::new());
        self.state().entry(bot.id.clone()).or_default().wake = Some(wake.clone());
        let host = if machine.is_some() { "machine" } else { "server" };
        let since = Instant::now();
        let mut queued_at = json!({ "host": host, "machine": machine, "trigger": msg.role, "messageId": msg.id, "owner": bot.owner_id });
        merge(&mut queued_at, &queue_view(&pool, queued.turn()));
        self.db.record(&by.event("bot.run_queued").target("message", &msg.id.to_string()).bot(&bot.id).details(queued_at));
        let result = loop {
            {
                let mut st = self.state();
                let s = st.entry(bot.id.clone()).or_default();
                if self.closing.load(Ordering::SeqCst) {
                    break "shutdown";
                }
                if std::mem::take(&mut s.stopped) {
                    break "stopped";
                }
            }
            if self.lend(&bot.id, &pool) {
                break "lent";
            }
            let turn = queued.turn();
            if turn == Turn::Go {
                break "started";
            }
            self.send(json!({ "type": "status", "botId": bot.id, "working": true, "status": waiting_status(&pool, turn), "queued": queue_view(&pool, turn) }));
            tokio::select! {
                _ = queued.changed() => {}
                _ = wake.notified() => {}
            }
        };
        if let Some(s) = self.state().get_mut(&bot.id) {
            s.wake = None;
        }
        let waited = json!({
            "result": result, "waitedMs": since.elapsed().as_millis() as u64, "host": host, "machine": machine,
            "trigger": msg.role, "messageId": msg.id, "owner": bot.owner_id,
        });
        let outcome = if matches!(result, "started" | "lent") { Outcome::Success } else { Outcome::Failure };
        self.db.record(&by.event("bot.run_dequeued").target("message", &msg.id.to_string()).bot(&bot.id).outcome(outcome).details(waited));
        match result {
            "started" => queued.slot().map(|s| (s, true)),
            "lent" => Some((queued.borrow(), true)),
            "stopped" => {
                drop(queued);
                self.give_back(bot, msg, period);
                self.say(&bot.id, "Stopped.", true);
                None
            }
            // Still queued in the database, so it runs after the restart, and counts then.
            _ => {
                self.db.give_back_run(&bot.owner_id, period);
                None
            }
        }
    }

    /// Whether the Bot may run past its computer's cap: a Bot that asked it something
    /// holds a slot there and waits for the answer, so waiting would wait on that slot.
    fn lend(&self, bot_id: &str, pool: &str) -> bool {
        let asks = self.asks.lock().unwrap_or_else(|e| e.into_inner());
        asks.get(bot_id).is_some_and(|askers| askers.iter().any(|a| self.slots.holds(pool, a)))
    }

    /// Why a run that waited for a slot no longer may (ADR 0073): its owner, a routine's
    /// author or the person it is for lost access meanwhile. With who, and what to say.
    fn refused_after_wait(&self, bot: &Bot, msg: &Message, by: &Who, for_other: Option<&str>) -> Option<(&'static str, String, Option<String>)> {
        let author = by.actor.asker.as_deref().filter(|_| msg.role == "routine");
        if let Some((reason, user)) = crate::handover::blocked(&self.db, &bot.owner_id, author) {
            let text = (reason == crate::handover::OWNER_DISABLED).then(|| self.wont_run(bot, None).map(|(_, t)| t)).flatten();
            return Some((reason, user, text));
        }
        let asker = for_other?;
        self.wont_run(bot, Some(asker)).map(|(reason, text)| (reason, asker.to_string(), Some(text)))
    }

    /// Why a Bot won't run now under isolated shared Bots (ADR 0046): its owner is
    /// disabled, or the person the run is for (`for_other`) can no longer operate it.
    fn wont_run(&self, bot: &Bot, for_other: Option<&str>) -> Option<(&'static str, String)> {
        if !self.db.user(&bot.owner_id).is_some_and(|u| u.active()) {
            let text = "My owner's account is turned off, so I don't run. An admin can turn it back on, or give me to someone else.";
            return Some(("owner_disabled", text.into()));
        }
        let asker = for_other?;
        (Viewer::person(&self.db, asker).access(&self.db, bot) < Access::Operate)
            .then(|| ("asker_lost_access", "The person this task was for can no longer use me, so I didn't run it.".into()))
    }

    /// Where the Bot runs: here, or its owner's machine once that machine answered a
    /// check and can run it. None: refused (the run is given back), and the Bot said
    /// why. Never another user's machine, and never here instead of an assigned one.
    /// `for_other`: the run is for someone else, so it can't count on the owner's keys.
    async fn place(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, bin: &str, for_other: Option<&str>) -> Option<Place> {
        let Some(cp) = self.control_plane.get() else { return Some(Place::Here) };
        // Others read a shared Bot's chat: they learn whose computer it is, not its insides.
        let team = bot.visibility == Visibility::Shared || !self.db.grants(&bot.id).is_empty();
        let owner_name = self.db.user(&bot.owner_id).map(|u| u.name);
        let refused = |r: Refusal, machine: Option<&str>| {
            self.give_back(bot, msg, period);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            let detail = json!({
                "reason": r.reason(), "detail": r.detail(), "owner": bot.owner_id, "machine": machine, "forUser": for_other, "messageId": msg.id,
            });
            self.db.record(&e.details(detail));
            let text = if for_other.is_some() { r.message_for(owner_name.as_deref()) } else { r.message_in(!team) };
            self.say(&bot.id, &text, true);
            None
        };
        let to = match cp.route(&self.db, &bot.owner_id) {
            Ok(Target::Local) => return Some(Place::Here),
            Err(r) => return refused(r, None),
            Ok(Target::Machine(to)) => to,
        };
        // A teammate's run goes there as their own user (ADR 0048), never the Bots'.
        let teammate = for_other.filter(|_| cp.teammate_users());
        let checked = cp.link.check(self, &to, &[bin]).await.map_err(Refusal::Offline);
        let ready = checked.and_then(|hb| {
            let layout = route::fit(&hb, bin)?;
            let keys = if for_other.is_some() { None } else { Some(bot.owner_id.as_str()) };
            cp.ready(self, &hb, keys, &to.machine_id, bin, teammate.is_some())?;
            Ok((layout, hb.version))
        });
        let (layout, version) = match ready {
            Err(r) => return refused(r, Some(&to.machine_id)),
            Ok(ready) => ready,
        };
        let user = match teammate {
            None => None,
            Some(u) => match cp.link.teammate(&to, u).await {
                Err(e) => return refused(Refusal::TeammateUserFailed(e), Some(&to.machine_id)),
                Ok(t) => {
                    if t.created {
                        let e = by.event("machine.teammate_user_created").target("machine", &to.machine_id).bot(&bot.id);
                        self.db.record(&e.details(json!({ "owner": bot.owner_id, "forUser": u, "user": t.user, "uid": t.uid, "messageId": msg.id })));
                    }
                    crate::machines::offboard::seen(self, &to.machine_id, u);
                    // Their own login there, never the owner's (ADR 0062).
                    if let Err(r) = cp.teammate_logged_in(bin, &t) {
                        return refused(r, Some(&to.machine_id));
                    }
                    Some(t)
                }
            },
        };
        let e = by.event("bot.run_routed").target("message", &msg.id.to_string()).bot(&bot.id);
        let detail = json!({
            "owner": bot.owner_id, "machine": to.machine_id, "link": cp.link.name(), "agentVersion": version, "forUser": for_other,
            "teammateUser": user.as_ref().map(|t| &t.user), "messageId": msg.id,
        });
        self.db.record(&e.details(detail));
        Some(Place::There(Box::new((to, layout, user))))
    }

    /// Whether a run on this server is refused because its harness isn't installed here,
    /// as a machine refuses one (`harness_missing`, ADR 0079): it is given back and
    /// audited, nothing starts, and the Bot says how to fix it.
    fn missing_here(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, spot: &Spot, bin: &str) -> bool {
        let path = spot.env.get("PATH").cloned().unwrap_or_default();
        if spot.machine.is_some() || adapters::version::resolve(bin, &path, &spot.cwd).is_some() {
            return false;
        }
        self.give_back(bot, msg, period);
        let tier = self.tier_of(&bot.owner_id);
        let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
        self.db.record(&e.details(json!({
            "reason": "harness_missing", "harness": bot.harness, "host": "server", "tier": tier.name,
            "owner": bot.owner_id, "forUser": spot.for_other, "messageId": msg.id,
        })));
        let switch = if tier.harnesses().is_none_or(|h| h.len() > 1) { ", or switch me to another harness" } else { "" };
        let hint = adapters::install::server_hint(bin);
        self.say(&bot.id, &format!("I didn't run: {bin} isn't installed on this server. Ask an admin to install it ({hint}){switch}."), true);
        true
    }

    /// Whether a guarded run is refused because its harness, where the run happens, is
    /// older than the release that runs SuperBot's hook, or its version can't be read
    /// (ADR 0059). A refused run is given back and audited, and the Bot says how to fix
    /// it. Unguarded runs aren't checked. The canary still stops a harness that skips
    /// the hook anyway.
    async fn hooks_refused(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, spot: &Spot, run_as: Option<&RunAs>) -> bool {
        use adapters::version::{self, Short};
        let Some(min) = adapters::get(&bot.harness).and_then(|a| a.hooks_since()) else { return false };
        if self.db.effective_policy(&bot.id).mode != Mode::Ask {
            return false;
        }
        let bin = adapters::get(&bot.harness).map_or("", |a| a.bin());
        let (key, said) = match &spot.machine {
            None => {
                let path = spot.env.get("PATH").cloned().unwrap_or_default();
                match version::resolve(bin, &path, &spot.cwd) {
                    None => (None, Err(format!("{bin} isn't on this server's PATH"))),
                    Some(real) => {
                        let key = version::key_here(bin, &real);
                        if version::passed(&key) {
                            return false;
                        }
                        (Some(key), version::read_here(&real, &path, &spot.cwd, run_as).await)
                    }
                }
            }
            Some(to) => {
                let user = spot.teammate_user.as_ref().and(spot.for_other.as_deref()).unwrap_or(bot.owner_id.as_str());
                let key = version::key_there(bin, &to.machine_id, user, &spot.cwd.display().to_string());
                if version::passed(&key) {
                    return false;
                }
                (Some(key), self.version_there(bot, spot, to, bin).await)
            }
        };
        let short = match version::assess(min, said) {
            Ok(()) => {
                if let Some(k) = key {
                    version::pass(k);
                }
                return false;
            }
            Err(s) => s,
        };
        let machine = spot.machine.as_ref().map(|m| m.machine_id.clone());
        let place = match (&machine, &spot.for_other) {
            (None, _) => "this server",
            (Some(_), None) => "your computer",
            (Some(_), Some(_)) => "my owner's computer",
        };
        // Others read a shared Bot's chat: a machine's own words stay in the audit log.
        let team = bot.visibility == Visibility::Shared || !self.db.grants(&bot.id).is_empty();
        let (reason, found, why) = match &short {
            Short::Old(v) => ("harness_outdated", Some(v.as_str()), None),
            Short::Unknown(w) => ("harness_version_unknown", None, Some(w.as_str())),
        };
        let has = match (found, why) {
            (Some(v), _) => format!("{place} has {v}"),
            (None, Some(w)) if machine.is_none() || !team => format!("I couldn't tell which version {place} has ({w})"),
            _ => format!("I couldn't tell which version {place} has"),
        };
        let fix = match (&machine, adapters::install::server_update(bin)) {
            (Some(_), _) => format!(
                "An admin can update it: keep {bin} in MACHINE_HARNESSES at its pinned version (or {bin}@<version>, {min} or newer), then run `botctl machine harnesses <user>`."
            ),
            (None, Some(cmd)) => format!("An admin can update it on this server: `{cmd}`, or rebuild the Docker image."),
            (None, None) => "An admin can update it on this server.".into(),
        };
        self.give_back(bot, msg, period);
        let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
        self.db.record(&e.details(json!({
            "reason": reason, "harness": bot.harness, "version": found, "minimum": min, "detail": why,
            "host": if machine.is_some() { "machine" } else { "server" }, "machine": machine,
            "owner": bot.owner_id, "forUser": spot.for_other, "messageId": msg.id,
        })));
        let text = format!(
            "I didn't run: approvals need the {bin} CLI {min} or newer to check my steps before I take them, and {has}. {fix} Or set my approvals to bypass (dev only)."
        );
        self.say(&bot.id, &text, true);
        true
    }

    /// `bin --version` on the owner's machine, found as the run there would find it.
    async fn version_there(&self, bot: &Bot, spot: &Spot, to: &Assigned, bin: &str) -> Result<String, String> {
        let Some(cp) = self.control_plane.get() else { return Err("this server can't reach machines".into()) };
        let job = wire::JobRequest {
            protocol: wire::PROTOCOL,
            job_id: format!("j{}", crate::random_hex(8)),
            bot_id: bot.id.clone(),
            owner_id: bot.owner_id.clone(),
            for_user: spot.teammate_user.as_ref().and(spot.for_other.clone()),
            message_id: 0,
            bin: bin.into(),
            args: vec!["--version".into()],
            env: Default::default(),
            cwd: spot.cwd.display().to_string(),
            stdin: None,
            files: vec![],
            cleanup: None,
            collect: vec![],
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let (_abort, abort_rx) = watch::channel(None);
        let ran = async { tokio::join!(cp.link.run(to, job, abort_rx, tx), adapters::version::read_job(rx)).1 };
        let secs = adapters::version::PROBE_TIMEOUT.as_secs();
        tokio::time::timeout(adapters::version::PROBE_TIMEOUT, ran).await.unwrap_or_else(|_| Err(format!("{bin} --version didn't answer in {secs} seconds")))
    }

    /// The run's folders and environment where it happens. On a machine: the machine's
    /// folders, botctl there, and botd's API through the agent's relay; its screen
    /// there, if any, comes after (ADR 0045).
    /// A teammate's run as their own user (ADR 0048) works in that user's home, and its
    /// token is bound to them (`isolation::bot_token_for`).
    fn spot(&self, bot: &Bot, bot_dir: PathBuf, (cwd, mut env): (PathBuf, HashMap<String, String>), place: Place, for_other: Option<&str>) -> Spot {
        let local = |p: Option<PathBuf>| p.unwrap_or_default();
        match place {
            Place::Here => Spot {
                machine: None,
                cwd,
                memory: local(self.memory_file(bot)),
                user_file: local(self.user_file(&bot.owner_id)),
                config_dir: bot_dir.clone(),
                state_dir: bot_dir,
                botctl: self.cfg.bin_dir.join("botctl"),
                env,
                screens: self.screens.is_some(),
                ctx: None,
                for_other: None,
                teammate_user: None,
                sandbox_host: Some(self.cfg.sandbox_host.clone()),
                home: None,
                caches: vec![],
            },
            Place::There(there) => {
                let (to, mut layout, teammate) = *there;
                let botctl = PathBuf::from(layout.botctl.clone().unwrap_or_default());
                // HOME and PATH are the machine's own; it inherits nothing of botd's.
                env.remove("PATH");
                for (k, v) in crate::secrets::global().inherited_harness_env() {
                    env.entry(k).or_insert_with(|| v.expose().to_string());
                }
                env.insert("BOT_API".into(), layout.api.clone());
                env.insert("SUPERBOT_BOTCTL".into(), botctl.display().to_string());
                let teammate_user = match (teammate, for_other) {
                    (Some(t), Some(u)) => {
                        let token = isolation::bot_token_for(&self.cfg.bot_key, &bot.id, &bot.owner_id, u);
                        crate::secrets::redact::register(&token);
                        env.insert("BOT_TOKEN".into(), token);
                        layout.user_file = format!("{}/USER.md", t.home);
                        (layout.home, layout.workspace, layout.bots) = (t.home, t.workspace, t.bots);
                        Some(t.user)
                    }
                    _ => None,
                };
                let state_dir = PathBuf::from(&layout.bots).join(&bot.id);
                // The agent's caches are its own user's; a teammate's home has its own.
                let caches = match teammate_user {
                    Some(_) => vec![],
                    None => layout.caches.iter().filter(|c| paths::under(&layout.home, c)).map(PathBuf::from).collect(),
                };
                Spot {
                    machine: Some(to),
                    cwd: PathBuf::from(&layout.workspace),
                    memory: state_dir.join("MEMORY.md"),
                    user_file: PathBuf::from(&layout.user_file),
                    config_dir: state_dir.clone(),
                    state_dir,
                    botctl,
                    env,
                    screens: false,
                    ctx: Some(Ctx { workspace: PathBuf::from(&layout.workspace), home: PathBuf::from(&layout.home), readable: false }),
                    for_other: None,
                    teammate_user,
                    sandbox_host: layout.sandbox,
                    home: Some(PathBuf::from(&layout.home)),
                    caches,
                }
            }
        }
    }

    /// Runs the harness on the owner's machine. botd keeps the Bot's memory and its
    /// owner's facts: they go with the job and come back changed. The owner's facts
    /// are sent only when none of their other Bots is running there, so one Bot's run
    /// can't undo another's edits, and never for a run that's for someone else (ADR 0046).
    /// With per-user accounts on this server, the copies in the owner's folder there are
    /// dropped when these change, and made again from botd's at the next run here.
    #[allow(clippy::too_many_arguments)]
    async fn run_there(&self, bot: &Bot, msg: &Message, spot: &Spot, to: &Assigned, adapter: Box<dyn adapters::Adapter>, input: RunInput, abort: watch::Receiver<AbortReason>, emit: impl FnMut(AgentEvent)) {
        let Some(cp) = self.control_plane.get() else { return };
        let read = |p: Option<PathBuf>| p.and_then(|p| std::fs::read_to_string(p).ok());
        let own = spot.for_other.is_none();
        let memory = read(self.data_memory_file(&bot.id));
        let facts = if own { read(self.data_user_file(&bot.owner_id)) } else { None };
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
            job.for_user = spot.teammate_user.as_ref().and(spot.for_other.clone());
            job.message_id = msg.id;
            let files = [(memory_at.clone(), memory), (user_at.clone(), facts.filter(|_| alone))];
            job.files.extend(files.into_iter().filter_map(|(path, body)| Some(wire::JobFile { path, body: body? })));
            job.collect = if own { vec![memory_at.clone(), user_at.clone()] } else { vec![memory_at.clone()] };
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

    /// With per-user accounts (ADR 0037): the account this run starts as, its owner's,
    /// or for `teammate` under `ISOLATION_TEAMMATES` that teammate's for the owner's Bots
    /// (ADR 0064), made now if it's new. A teammate's run needs their own harness login
    /// there, or a server-wide key: it never falls back to the owner's. Ok(None):
    /// isolation is off. Err: refused, and the Bot said why; it never falls back to
    /// running as botd's account.
    async fn isolate(&self, bot: &Bot, msg: &Message, by: &Who, period: &str, teammate: Option<&str>) -> Result<Option<RunAs>, ()> {
        let Some(iso) = self.isolation.get().cloned() else { return Ok(None) };
        let space = Space::of(&bot.owner_id, teammate);
        let refused = |reason: &str, text: &str, more: Value| {
            self.give_back(bot, msg, period);
            let e = by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied);
            let mut details = json!({ "reason": reason, "owner": bot.owner_id, "account": space.account(), "harness": bot.harness, "messageId": msg.id });
            if let Some(u) = teammate {
                details["forUser"] = json!(u);
            }
            merge(&mut details, &more);
            self.db.record(&e.details(details));
            self.say(&bot.id, text, true);
            Err(())
        };
        if !accounts::HARNESSES.contains(&bot.harness.as_str()) {
            let text = format!("This server runs each person's Bots under their own account, and {} can't run that way. Switch me to another harness in my settings.", bot.harness);
            return refused("isolation_harness", &text, json!({}));
        }
        let whose = if teammate.is_some() { "an account for you" } else { "my owner's account" };
        let Ok(run_as) = self.ensure_space(space, by).await else {
            return refused("no_account", &format!("I couldn't set up {whose} on this server, so I didn't run. An admin can check the server log."), json!({}));
        };
        if let Err(e) = iso.make_bot_dirs_in(space, &bot.id) {
            eprintln!("Isolation: couldn't make a Bot's folders in its account's folder: {e}");
            return refused("no_account", &format!("I couldn't set up my folders in {whose} on this server, so I didn't run. An admin can check the server log."), json!({}));
        }
        if teammate.is_some()
            && let Some(login) = crate::machines::logins::teammate_login_needed(&bot.harness)
        {
            let home = iso.home_in(space).unwrap_or_default();
            let files: Vec<String> = login.files.iter().map(|f| f.to_string()).collect();
            let r = run_as.clone();
            let since = tokio::task::spawn_blocking(move || r.login_since(&home, &files)).await.unwrap_or_else(|e| Err(e.to_string()));
            if !matches!(since, Ok(Some(_))) {
                let owner = self.db.user(&bot.owner_id).map(|u| u.name).unwrap_or_else(|| "its owner".into());
                let h = adapters::get(&bot.harness).map_or(bot.harness.clone(), |a| a.bin().to_string());
                let text = format!(
                    "I didn't run: {h} isn't logged in for you on this server for {owner}'s Bots. Runs for teammates use their own login, never {owner}'s. \
                     Log in from my details in the app, or an admin can save a server-wide key."
                );
                return refused("teammate_not_logged_in", &text, json!({ "detail": since.err() }));
            }
        }
        Ok(Some(run_as))
    }

    /// A teammate's run here (ADR 0064) works in their account's folders for the owner's
    /// Bots: its own workspace, HOME and memory copy, with a token bound to them.
    fn in_teammate_space(&self, spot: &mut Spot, iso: &Isolation, bot: &Bot, teammate: &str) {
        let space = Space::Teammate { owner: &bot.owner_id, teammate };
        let (Some(ws), Some(home), Some(mem), Some(dir)) = (iso.workspace_in(space), iso.home_in(space), iso.memory_file_in(space, &bot.id), iso.memory_dir_in(space)) else {
            return;
        };
        spot.ctx = Some(Ctx { workspace: ws.clone(), home: home.clone(), readable: true });
        (spot.cwd, spot.home, spot.memory, spot.user_file) = (ws, Some(home), mem, dir.join("USER.md"));
        let token = isolation::bot_token_for(&self.cfg.bot_key, &bot.id, &bot.owner_id, teammate);
        crate::secrets::redact::register(&token);
        spot.env.insert("BOT_TOKEN".into(), token);
    }

    /// The memory copy a teammate's run edits, made fresh from botd's (ADR 0064). The
    /// owner's account never sees it.
    fn seed_teammate_memory(&self, bot: &Bot, copy: &Path) {
        accounts::remove(copy);
        if let Some(text) = self.data_memory_file(&bot.id).and_then(|p| std::fs::read_to_string(p).ok()) {
            let _ = accounts::seed(copy, &text);
        }
    }

    /// What a teammate's run left in its memory copy goes back to botd's, if the Bot is
    /// still its owner's. The owner's own copy is then dropped, so their next run starts
    /// from it, and the teammate's copy goes. A copy that couldn't be saved is set aside
    /// as `<bot id>.md.unsaved` (the next run's copy replaces the other), never deleted.
    fn keep_teammate_memory(&self, bot: &Bot, copy: &Path, by: &Who) {
        if self.db.bot(&bot.id).is_none_or(|now| now.owner_id != bot.owner_id) {
            accounts::remove(copy);
            return;
        }
        match self.save_teammate_memory(bot, copy) {
            Ok(()) => accounts::remove(copy),
            Err(why) => {
                let aside = copy.with_extension("md.unsaved");
                let kept = copy.parent().is_some_and(accounts::trusted_dir) && std::fs::rename(copy, &aside).is_ok();
                eprintln!("WARNING: couldn't save a teammate's run's memory for a Bot ({why}); see bot.memory_unsaved in the audit log.");
                let details = json!({ "reason": why, "owner": bot.owner_id, "keptAt": kept.then(|| aside.display().to_string()) });
                self.db.record(&by.event("bot.memory_unsaved").bot(&bot.id).outcome(Outcome::Failure).details(details));
            }
        }
    }

    fn save_teammate_memory(&self, bot: &Bot, copy: &Path) -> Result<(), String> {
        let Some(text) = accounts::read_plain(copy, accounts::MAX_FILE) else {
            // Gone, a link or not a file: nothing of the Bot's memory to keep.
            return match std::fs::symlink_metadata(copy) {
                Ok(m) if m.is_file() => Err(format!("its memory file is over {} bytes or unreadable", accounts::MAX_FILE)),
                _ => Ok(()),
            };
        };
        let to = self.data_memory_file(&bot.id).ok_or("the Bot has no memory file")?;
        if std::fs::read_to_string(&to).ok().as_deref() == Some(text.as_str()) {
            return Ok(());
        }
        std::fs::write(&to, text).map_err(|e| format!("writing the Bot's memory: {e}"))?;
        if let Some(own) = self.isolation().and_then(|i| i.memory_file(&bot.owner_id, &bot.id)) {
            accounts::remove(&own);
        }
        Ok(())
    }

    /// The tier this run is on and the route it takes: the Bot owner's tier picks the
    /// model, never the Bot's settings alone (ADR 0033). The run is counted for the
    /// owner, within the tier's runs and tokens a billing period (ADR 0050). A route
    /// whose provider is one of the tiers file's endpoints needs that endpoint's key
    /// (`tier_key`, ADR 0077). None: refused, and the Bot said why.
    fn tier_route(&self, bot: &Bot, msg: &Message, by: &Who, period: &usage::Period, env: &HashMap<String, String>) -> Option<(String, Route, Wiring)> {
        let tier = self.tier_of(&bot.owner_id);
        let refused = |reason: &str, text: String, limit: Option<u64>, used: Option<u64>, more: Value| {
            self.give_back_routine(bot, msg);
            let mut details = json!({ "reason": reason, "owner": bot.owner_id, "tier": tier.name, "limit": limit, "period": period.key, "messageId": msg.id });
            if let Some(n) = used {
                details["used"] = json!(n);
                details["periodEnd"] = json!(period.end);
            }
            if let (Some(d), Value::Object(more)) = (details.as_object_mut(), more) {
                d.extend(more);
            }
            self.db.record(&by.event("bot.run_refused").target("message", &msg.id.to_string()).bot(&bot.id).outcome(Outcome::Denied).details(details));
            // A routine keeps firing into a used-up period; one bubble says it.
            if used.is_none() || self.db.last_message(&bot.id).is_none_or(|m| m.text != text) {
                self.say(&bot.id, &text, true);
            }
            None
        };
        let license = self.license.status();
        if !license.usable() {
            return refused("unlicensed", license.run_refusal(), None, None, Value::Null);
        }
        let route = match tier.route(&bot.harness, bot.model.as_deref(), bot.effort.as_deref()) {
            Ok(r) => r,
            Err(e) => return refused("tier_harness", format!("{e} Switch me to one of those in my settings."), None, None, Value::Null),
        };
        let has_key = |k: &str| tier_key(env, k).is_some();
        let wiring = match self.tiers().wiring(&route, tier.managed(), has_key) {
            Ok(w) => w,
            Err(e) => {
                let text = format!("The {} plan's model provider isn't set up on this server yet, so I didn't run. Ask an admin to save its key.", tier.label);
                return refused("provider_key_missing", text, None, None, json!({ "provider": e.name, "keyName": e.key_secret }));
            }
        };
        let (this, more) = match period.source {
            usage::Source::Calendar => ("month", "the 1st (UTC)".to_string()),
            usage::Source::Subscription => ("billing period", format!("{} (UTC)", period.end_day())),
        };
        if let Some(limit) = tier.limits.monthly_tokens {
            let used = self.db.tokens_used(&bot.owner_id, period.start, period.end);
            if used >= limit {
                let text = format!(
                    "The {} plan allows {} model tokens a {this}, and this {this}'s are used up. More start on {more}.",
                    tier.label,
                    usage::thousands(limit)
                );
                return refused("tier_token_limit", text, Some(limit), Some(used), Value::Null);
            }
        }
        if let Err(limit) = self.db.take_run(&bot.owner_id, &period.key, tier.limits.monthly_runs) {
            let text = format!("The {} plan allows {limit} runs a {this}, and this {this}'s are used up. More start on {more}.", tier.label);
            return refused("tier_limit", text, Some(u64::from(limit)), None, Value::Null);
        }
        Some((tier.name.clone(), route, wiring))
    }

    /// Records the tokens a run used, one row per model, charged to the Bot's owner
    /// (ADR 0050). A harness that reported nothing leaves one row saying so. Audits the
    /// run that uses up the owner's tokens for the period it ends in, which its tokens
    /// count in. Returns the run's total, or None when unknown.
    fn record_tokens(&self, bot: &Bot, msg: &Message, run_id: &str, route: &Route, used: Vec<Usage>) -> Option<u64> {
        let mut models: Vec<Usage> = Vec::new();
        for u in used {
            let model = u.model.clone().or_else(|| route.model.clone());
            match models.iter_mut().find(|m| m.model == model) {
                Some(m) => {
                    m.input = m.input.saturating_add(u.input);
                    m.output = m.output.saturating_add(u.output);
                    m.cache_read = m.cache_read.saturating_add(u.cache_read);
                    m.cache_write = m.cache_write.saturating_add(u.cache_write);
                }
                None => models.push(Usage { model, ..u }),
            }
        }
        let at = crate::db::now();
        let total = models.iter().map(Usage::total).fold(0u64, u64::saturating_add);
        let meter = self.meter.get().is_some() && self.db.customer_of(&bot.owner_id).is_some();
        let row = |u: Usage, reported: bool| TokenRow {
            user_id: bot.owner_id.clone(),
            bot_id: bot.id.clone(),
            run_id: run_id.into(),
            message_id: Some(msg.id),
            harness: bot.harness.clone(),
            reported,
            meter: meter && reported && u.total() > 0,
            model: u.model,
            input: u.input,
            output: u.output,
            cache_read: u.cache_read,
            cache_write: u.cache_write,
            at,
        };
        let reported = !models.is_empty();
        let rows: Vec<TokenRow> = if reported {
            models.into_iter().map(|u| row(u, true)).collect()
        } else {
            vec![row(Usage { model: route.model.clone(), ..Default::default() }, false)]
        };
        let tier = self.tier_of(&bot.owner_id);
        let period = self.billing_period(&bot.owner_id, at);
        let before = tier.limits.monthly_tokens.map(|_| self.db.tokens_used(&bot.owner_id, period.start, period.end));
        if let Err(e) = self.db.record_tokens(&rows) {
            eprintln!("botd: couldn't record run {run_id}'s tokens: {e}");
        }
        if let (Some(limit), Some(before)) = (tier.limits.monthly_tokens, before)
            && before < limit
            && before.saturating_add(total) >= limit
        {
            let by = Who { actor: Actor::system("billing").on_behalf_of(&bot.owner_id), source: Default::default() };
            let details = json!({ "owner": bot.owner_id, "tier": tier.name, "limit": limit, "used": before.saturating_add(total), "period": period.key, "periodEnd": period.end, "runId": run_id });
            self.db.record(&by.event("usage.token_limit_reached").target("user", &bot.owner_id).bot(&bot.id).details(details));
        }
        reported.then_some(total)
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
        let _asking = Asking::new(self, &to.id, &from.id);
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
            let mut m = self.db.add_message_from(asker, "reply", &reply, None, false, Some("queued"), Some(&msg.bot_id));
            // The reply runs for whoever the question was for, not the answering Bot's owner.
            if let (Some(answered), Some(asking)) = (self.db.bot(&msg.bot_id), self.db.bot(asker)) {
                let mut actor = Actor::for_bot(&answered);
                actor.asker = Some(msg.requested_by.as_ref().map_or(asking.owner_id.clone(), |by| Self::asker_of(&asking, by)));
                let by = Who { actor, source: Default::default() };
                self.db.set_requested_by(m.id, &by);
                m.requested_by = Some(by);
            }
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
                match &s.run {
                    Some(r) => {
                        r.abort.send_if_modified(|v| v.get_or_insert("stopped") == &"stopped");
                    }
                    None => {
                        s.stopped = true;
                        if let Some(w) = &s.wake {
                            w.notify_one();
                        }
                    }
                }
            }
        }
        self.cancel_approvals(bot_id, "The Bot was stopped");
        true
    }

    /// Stops the runs going now in `teammate`'s account here for `owner`'s Bots, which is
    /// being removed (ADR 0066). Their runs elsewhere go on. Each saves its memory copy as
    /// it ends. How many.
    pub fn stop_teammate_runs(&self, owner: &str, teammate: &str) -> u32 {
        let theirs: Vec<String> = self.state().iter().filter(|(_, s)| s.run.as_ref().is_some_and(|r| r.teammate.as_deref() == Some(teammate))).map(|(id, _)| id.clone()).collect();
        let mut n = 0;
        for id in theirs.iter().filter(|id| self.db.bot(id).is_some_and(|b| b.owner_id == owner)) {
            if let Some(r) = self.state().get(id).and_then(|s| s.run.as_ref()).filter(|r| r.teammate.as_deref() == Some(teammate)) {
                r.abort.send_if_modified(|v| v.get_or_insert("removed") == &"removed");
                n += 1;
            }
        }
        n
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
            if let Some(w) = &s.wake {
                w.notify_one();
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
        let spot = self.spot(bot, self.bot_dir(&bot.id).unwrap_or_default(), (cwd, env), Place::Here, None);
        self.system_prompt_at(bot, &spot)
    }

    /// The prompt for a run at `spot`: its paths are where the run is. The memory and
    /// facts in it are the run's own copies here, or botd's, which runs elsewhere send back.
    fn system_prompt_at(&self, bot: &Bot, spot: &Spot) -> String {
        let read = |p: &Option<PathBuf>| p.as_deref().and_then(|p| self.read_memory(p)).unwrap_or_default().trim().to_string();
        let (mem_file, user_file) = match spot.machine {
            None => (Some(spot.memory.clone()), Some(spot.user_file.clone())),
            Some(_) => (self.data_memory_file(&bot.id), self.data_user_file(&bot.owner_id)),
        };
        // Only the Bots its owner can see (ADR 0017), and that whoever it runs for can (ADR 0046).
        let others: Vec<String> = self
            .bot_viewer(bot)
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
        let user = self.owner_name(bot);
        let asker = spot.for_other.as_deref().map(|id| self.db.user(id).map(|u| u.name).unwrap_or_else(|| "a teammate".into()));
        let (facts_line, facts, asking) = match &asker {
            None => (
                format!("\n- Facts about {user}, shared by all of their Bots: {}. Name, time zone, and similar.", spot.user_file.display()),
                format!("\n<user>\n{}\n</user>", read(&user_file)),
                String::new(),
            ),
            Some(a) => (
                String::new(),
                String::new(),
                format!(
                    "\n## Who's asking\n- This task is for {a}, a teammate {user} shares you with, not for {user}. Help {a} with it.\n\
                     - Don't open or pass on {user}'s private files, notes, keys, or their other Bots' folders. Ask {user} first if the task needs them.\n\
                     - Everyone who uses you sees what you write in your memory file: keep anyone's private details out of it.\n"
                ),
            ),
        };
        format!(
            r#"You are {name}, an AI teammate of {user}.{primary}
They talk to you in a chat app, like messaging a coworker. Finish work end to end.

## Your computer
- You run on a Linux computer you share with {user}'s other Bots. Your working folder is {ws}; it belongs to {user}.{own}
- Keep {user}'s work inside it, in clear project folders. Other people's folders on this computer aren't yours to open.

## Memory
- Your memory file: {mem_path}. It holds your job, the user's rules and preferences for you, and a short dated log of important work.{facts_line}
- Update these files yourself when you learn something lasting, without asking. Keep them short. Never store passwords, keys, or card numbers.
- Current contents:
<memory>
{mem}
</memory>{facts}
{asking}
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
            screen = match (spot.screens, spot.machine.is_some()) {
                (true, true) => machine_screen_prompt(&spot.botctl.display().to_string()),
                (true, false) if self.screens.is_some() => screen_prompt(&spot.botctl.display().to_string()),
                _ => String::new(),
            },
            own = if spot.machine.is_some() { format!(" It is {user}'s own computer: only their Bots run on it.") } else { String::new() },
            approvals = if self.db.effective_policy(&bot.id).mode == Mode::Ask {
                "\n- Risky actions (destructive commands, deleting outside your folder, sending messages, installing software, git push) \
                 pause until the user approves them in the app. If one is denied, don't try another way to do it; tell the user what you wanted to do."
            } else {
                ""
            },
            ws = spot.cwd.display(),
            mem_path = spot.memory.display(),
            mem = read(&mem_file),
            others = if others.is_empty() { "None yet.".into() } else { others.join("\n") },
            now = chrono::Local::now().format("%A, %B %-d, %Y, %H:%M (UTC%:z)"),
        )
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shortens every run's hook timeout to this many seconds, so a test can make a real
/// harness time its hook out in seconds, not minutes (ADR 0075). Only in testing mode:
/// a licensed server ignores it.
pub const TEST_HOOK_TIMEOUT: &str = "SUPERBOT_TEST_HOOK_TIMEOUT_SECS";

/// `TEST_HOOK_TIMEOUT`'s value: unset, or whole seconds, at least 2.
pub fn test_hook_secs(raw: &str) -> Result<Option<u64>, String> {
    match raw.trim() {
        "" => Ok(None),
        s => s.parse().ok().filter(|n| *n >= 2).map(Some).ok_or(format!("{TEST_HOOK_TIMEOUT} must be whole seconds, at least 2, not \"{s}\"")),
    }
}

/// The approval gate for one run. The hook timeout stays a minute above the wait.
/// `test_secs` (`TEST_HOOK_TIMEOUT`) only ever shortens it, and the wait stays under it.
fn guard(botctl: &Path, harness: &str, timeout_minutes: u32, test_secs: Option<u64>) -> Guard {
    let mut wait = Duration::from_secs(timeout_minutes as u64 * 60 + 60);
    if let Some(cap) = adapters::get(harness).and_then(|a| a.max_hook_secs()) {
        wait = wait.min(Duration::from_secs(cap.saturating_sub(60).max(1)));
    }
    let mut timeout_secs = wait.as_secs() + 60;
    if let Some(s) = test_secs.filter(|s| *s < timeout_secs) {
        (timeout_secs, wait) = (s, Duration::from_secs(s / 2));
    }
    let botctl = botctl.display().to_string();
    Guard { command: format!("{} hook {harness}", shell_quote(&botctl)), timeout_secs, wait }
}

/// An ask waiting on a Bot, for as long as the asker waits (ADR 0073). A run of the
/// asked Bot waiting for a slot is woken so it can borrow its asker's.
struct Asking<'a> {
    app: &'a App,
    to: String,
    from: String,
}

impl<'a> Asking<'a> {
    fn new(app: &'a App, to: &str, from: &str) -> Self {
        app.asks.lock().unwrap_or_else(|e| e.into_inner()).entry(to.to_string()).or_default().push(from.to_string());
        if let Some(wake) = app.state().get(to).and_then(|s| s.wake.clone()) {
            wake.notify_one();
        }
        Asking { app, to: to.to_string(), from: from.to_string() }
    }
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        let mut asks = self.app.asks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(askers) = asks.get_mut(&self.to) {
            if let Some(i) = askers.iter().position(|a| *a == self.from) {
                askers.remove(i);
            }
            if askers.is_empty() {
                asks.remove(&self.to);
            }
        }
    }
}

/// What a run waiting for a slot shows (ADR 0073).
fn queue_view(pool: &str, turn: Turn) -> Value {
    let host = if pool == slots::SERVER { "server" } else { "machine" };
    match turn {
        Turn::Waiting { position, running, limit } => {
            json!({ "reason": "at_capacity", "host": host, "position": position, "running": running, "limit": limit })
        }
        Turn::Go => json!({ "reason": "starting", "host": host }),
    }
}

/// The Bot's status line while it waits for a slot.
fn waiting_status(pool: &str, turn: Turn) -> String {
    let place = if pool == slots::SERVER { "this server" } else { "its computer" };
    let Turn::Waiting { position, limit, .. } = turn else { return "Starting".into() };
    let at_once = format!("{place} runs {limit} task{} at once", if limit == 1 { "" } else { "s" });
    match position {
        1 => format!("Queued, next in line: {at_once}"),
        n => format!("Queued, #{n} in line: {at_once}"),
    }
}

/// Adds `extra`'s fields to the object `v`.
fn merge(v: &mut Value, extra: &Value) {
    if let (Some(v), Some(x)) = (v.as_object_mut(), extra.as_object()) {
        v.extend(x.iter().map(|(k, x)| (k.clone(), x.clone())));
    }
}

/// A tier endpoint's key: the run's own secret of that name (its owner's, say), else
/// the server's, wherever it is kept, `.env` included. Local runs don't get secrets
/// from `.env` in `env`, since they would inherit them, but nothing inherits these.
fn tier_key(env: &HashMap<String, String>, name: &str) -> Option<String> {
    let set = |v: &String| !v.trim().is_empty();
    env.get(name).filter(|v| set(v)).cloned().or_else(|| {
        let v = crate::secrets::global().get(name).ok().flatten()?.expose().to_string();
        set(&v).then_some(v)
    })
}

#[cfg(test)]
impl App {
    /// Marks a Bot as running, as `run_one` does, with no harness. Returns the run's id.
    pub(crate) fn start_test_run(&self, bot_id: &str) -> String {
        let id = format!("r{}", crate::random_hex(8));
        let run = Run {
            id: id.clone(),
            grants: Vec::new(),
            abort: watch::channel(None).0,
            status: "Working".into(),
            draft: String::new(),
            hooks: Arc::default(),
            hook_wait: None,
            ctx: None,
            teammate: None,
        };
        self.state().entry(bot_id.into()).or_default().run = Some(run);
        id
    }

    /// Ends it, as `run_one` does when its harness exits.
    pub(crate) fn end_test_run(&self, bot_id: &str) {
        self.cancel_approvals(bot_id, "The task ended");
        self.state().remove(bot_id);
    }
}

#[cfg(test)]
pub fn test_app() -> Arc<App> {
    test_app_in(crate::db::temp_path("app"))
}

/// `test_app` on the database and folders in `dir`: a second one on the same `dir`
/// is the server after a restart.
#[cfg(test)]
pub fn test_app_in(dir: PathBuf) -> Arc<App> {
    let db = Db::open(&dir.join("app.sqlite")).unwrap();
    let workspace = dir.join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    // Tests run as the dogfood server does: testing mode on (ADR 0068).
    let app = App::new(
        db,
        Config {
            data_dir: dir.clone(),
            workspace,
            user_name: "Tester".into(),
            bin_dir: dir.clone(),
            api_url: "http://127.0.0.1:1".into(),
            bot_key: crate::random_hex(16),
            run_timeout: Duration::from_secs(60),
            default_harness: "claude".into(),
            sandbox_host: crate::sandbox::Host { namespaces: true, programs: crate::sandbox::PROGRAMS.map(String::from).into() },
            home: Some(dir.join("home")),
        },
        None,
    );
    app.license.set_testing(true);
    app
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

/// The screen on the owner's computer (ADR 0045): a display and window manager, but
/// none of this server's browser tools.
fn machine_screen_prompt(botctl: &str) -> String {
    format!(
        r#"
## Your screen
- You have your own screen on this computer: DISPLAY is set, so windows you open show there. The user can watch it live and take over.
- Prefer APIs and command-line tools. Use windowed apps only when nothing else works.
- When you need the user on your screen (a login, 2FA code, CAPTCHA, or payment check), run: {botctl} handoff "<what you need, in one line>". It waits until they finish, so give the command a 10 minute timeout. Never ask for passwords in chat.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_approval_wait_fits_the_harness_hook_limit() {
        let g = guard(Path::new("/opt/it's/botctl"), "claude", 10, None);
        assert_eq!(g.command, r"'/opt/it'\''s/botctl' hook claude");
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(660), 720));
        // Hermes kills hooks after 300 seconds, so its wait stays under that.
        let g = guard(Path::new("/opt/botctl"), "hermes", 10, None);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(240), 300));
        let g = guard(Path::new("/opt/botctl"), "hermes", 1, None);
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(120), 180));
        // A test's short hook timeout: the wait stays under it, and it never lengthens one.
        let g = guard(Path::new("/opt/botctl"), "hermes", 10, Some(4));
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(2), 4));
        let g = guard(Path::new("/opt/botctl"), "hermes", 1, Some(900));
        assert_eq!((g.wait, g.timeout_secs), (Duration::from_secs(120), 180));
        assert_eq!(test_hook_secs(""), Ok(None));
        assert_eq!(test_hook_secs(" 5 "), Ok(Some(5)));
        for bad in ["1", "0", "-3", "5s", "x"] {
            assert!(test_hook_secs(bad).unwrap_err().contains(TEST_HOOK_TIMEOUT), "{bad}");
        }
        assert_eq!(tool_label("terminal", "ls"), "Running: ls");
    }

    fn spot_at(dir: &Path) -> Spot {
        Spot {
            machine: None,
            cwd: dir.join("ws"),
            state_dir: dir.join("bots/b1"),
            config_dir: dir.join("bots/b1"),
            memory: dir.join("bots/b1/MEMORY.md"),
            user_file: dir.join("users/u1/USER.md"),
            botctl: dir.join("botctl"),
            env: HashMap::new(),
            screens: false,
            ctx: None,
            for_other: None,
            teammate_user: None,
            sandbox_host: Some(crate::sandbox::Host { namespaces: true, programs: vec!["socat".into()] }),
            home: Some(dir.join("home")),
            caches: vec![dir.join("home/.npm")],
        }
    }

    #[test]
    fn a_sandbox_writes_only_where_the_run_keeps_its_files() {
        let dir = std::env::temp_dir().join(format!("spot-{}", crate::short_id()));
        std::fs::create_dir_all(dir.join("bots/b1")).unwrap();
        let mut spot = spot_at(&dir);
        assert!(matches!(spot.sandbox(false, true, &[]), (None, "off")));
        assert!(matches!(spot.sandbox(true, false, &[]), (None, "unsupported")));
        // Facts folder missing here: Codex won't start with a writable folder that doesn't exist.
        let (s, said) = spot.sandbox(true, true, &[]);
        assert_eq!((s.unwrap().writable, said), (vec![dir.join("bots/b1"), dir.join("home/.npm")], "on"));
        std::fs::create_dir_all(dir.join("users/u1")).unwrap();
        assert_eq!(spot.sandbox(true, true, &[]).0.unwrap().writable[1], dir.join("users/u1"));
        // Someone else's run never gets the owner's facts (ADR 0046).
        spot.for_other = Some("u2".into());
        assert!(!spot.sandbox(true, true, &[]).0.unwrap().writable.contains(&dir.join("users/u1")));
        // Per-user accounts keep both files in one folder.
        spot.for_other = None;
        std::fs::create_dir_all(dir.join("mem")).unwrap();
        (spot.memory, spot.user_file) = (dir.join("mem/b1.md"), dir.join("mem/USER.md"));
        assert_eq!(spot.sandbox(true, true, &[]).0.unwrap().writable, [dir.join("mem"), dir.join("home/.npm")]);
        // A machine keeps USER.md in HOME, which stays read-only.
        spot.machine = Some(Assigned { machine_id: "m1".into(), user_id: "u1".into(), address: None, pins: vec![] });
        (spot.memory, spot.user_file) = ("/home/bots/bots/b1/MEMORY.md".into(), "/home/bots/USER.md".into());
        spot.home = Some("/home/bots".into());
        assert_eq!(spot.sandbox(true, true, &[]).0.unwrap().writable, [PathBuf::from("/home/bots/bots/b1"), dir.join("home/.npm")]);
        // Claude Code's needs bubblewrap, which this computer lacks; Codex's doesn't.
        assert!(matches!(spot.sandbox(true, true, &["bwrap", "socat"]), (None, "unavailable")));
        assert!(matches!(spot.sandbox(true, true, &["socat"]), (Some(_), "on")));
        spot.sandbox_host = None;
        assert!(matches!(spot.sandbox(true, true, &["bwrap", "socat"]), (Some(_), "unverified")));
        spot.sandbox_host = Some(crate::sandbox::Host::default());
        assert!(matches!(spot.sandbox(true, true, &[]), (None, "unavailable")));
        let _ = std::fs::remove_dir_all(&dir);
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
        assert_eq!(app.isolate(&bot, &msg, &Who::system("test"), "2026-11", None).await, Ok(None));
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
    fn a_teammates_memory_copy_is_saved_or_set_aside_never_lost() {
        use crate::acl::Visibility;
        use crate::rbac::Role;
        let (app, root) = isolated_app("/bin/false");
        let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let bea = app.db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let a = app.db.create_bot_owned("A1", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Shared);
        let iso = app.isolation().unwrap();
        let space = Space::Teammate { owner: &ada.id, teammate: &bea.id };
        for d in [iso.memory_dir_in(space).unwrap(), root.join(&ada.id).join("memory")] {
            std::fs::create_dir_all(d).unwrap();
        }
        app.init_bot_files(&a);
        let (copy, kept, own) = (iso.memory_file_in(space, &a.id).unwrap(), app.data_memory_file(&a.id).unwrap(), app.memory_file(&a).unwrap());
        let by = Who { actor: Actor { kind: ActorKind::User, id: Some(bea.id.clone()), ..Default::default() }, source: Default::default() };
        let read = |p: &Path| std::fs::read_to_string(p).unwrap();

        // Saved: back to botd's, and the owner's copy goes so their next run starts from it.
        app.seed_teammate_memory(&a, &copy);
        std::fs::write(&copy, "# A1\n- learned for Bea\n").unwrap();
        app.keep_teammate_memory(&a, &copy, &by);
        assert_eq!(read(&kept), "# A1\n- learned for Bea\n");
        assert!(!copy.exists() && !own.exists());

        // Too big to save: set aside and audited, botd's left as it was.
        app.seed_teammate_memory(&a, &copy);
        std::fs::write(&copy, "x".repeat(accounts::MAX_FILE as usize + 1)).unwrap();
        app.keep_teammate_memory(&a, &copy, &by);
        assert_eq!(read(&kept), "# A1\n- learned for Bea\n");
        let aside = copy.with_extension("md.unsaved");
        assert_eq!(read(&aside).len(), accounts::MAX_FILE as usize + 1);
        assert!(!copy.exists());
        let ev = actions(&app, "bot.memory_unsaved");
        assert_eq!(ev.len(), 1);

        // A link in its place is nothing to keep: removed, never followed.
        std::fs::write(root.join("secret.txt"), "not yours").unwrap();
        std::os::unix::fs::symlink(root.join("secret.txt"), &copy).unwrap();
        app.keep_teammate_memory(&a, &copy, &by);
        assert!(std::fs::symlink_metadata(&copy).is_err());
        assert_eq!(read(&kept), "# A1\n- learned for Bea\n");
        assert_eq!(actions(&app, "bot.memory_unsaved").len(), 1);
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
        // A harness botd doesn't know never runs as botd instead.
        let bot = app.db.create_bot("X", "#fff", "waddle", "aider", None, true);
        let msg = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        assert_eq!(app.isolate(&bot, &msg, &who, "2026-11", None).await, Err(()));
        let last = app.db.messages(&bot.id, 1).pop().unwrap();
        assert!(last.error && last.text.contains("another harness"), "{}", last.text);
        assert_eq!(actions(&app, "bot.run_refused")[0].details["reason"], "isolation_harness");

        // Every harness runs as its owner's account (ADR 0058). When the account can't be
        // made, the run is refused, and the failure is audited.
        for harness in crate::accounts::HARNESSES {
            let bot = app.db.create_bot("C", "#fff", "waddle", harness, None, true);
            let msg = app.db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
            assert_eq!(app.isolate(&bot, &msg, &who, "2026-11", None).await, Err(()), "{harness}");
            let refused = actions(&app, "bot.run_refused");
            assert_eq!(refused.last().unwrap().details["reason"], "no_account", "{harness}");
            assert_eq!(refused.last().unwrap().details["account"], format!("sb-u-{}", bot.owner_id));
        }
        let failed = actions(&app, "isolation.account_failed");
        assert_eq!(failed.len(), crate::accounts::HARNESSES.len());
        assert!(failed.iter().all(|e| e.outcome == "failure"));
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
            Some(Run { id: "r1".into(), grants: Vec::new(), abort: tx, status: String::new(), draft: String::new(), hooks: Default::default(), hook_wait, ctx: None, teammate: None });
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

    #[test]
    fn removing_a_teammates_account_stops_only_runs_in_it() {
        let app = test_app();
        let here = app.db.create_bot("Here", "#fff", "waddle", "claude", None, false);
        let there = app.db.create_bot("There", "#fff", "waddle", "claude", None, false);
        let (in_account, on_machine) = (fake_run(&app, &here.id, false), fake_run(&app, &there.id, false));
        app.state().get_mut(&here.id).and_then(|s| s.run.as_mut()).unwrap().teammate = Some("cy".into());
        for b in [&here, &there] {
            app.askers.lock().unwrap().insert(b.id.clone(), "cy".into());
        }

        assert_eq!(app.stop_teammate_runs(&here.owner_id, "cy"), 1);
        assert_eq!(*in_account.borrow(), Some("removed"));
        assert_eq!(*on_machine.borrow(), None, "a run on the owner's machine doesn't use the account");
    }
}
