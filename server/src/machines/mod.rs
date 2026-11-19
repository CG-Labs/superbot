//! The control plane: one machine per user, rented from a provider (Linode). Off
//! unless LINODE_TOKEN is set, so self-hosted servers never see it. Admins request,
//! suspend, resume, resize, and destroy a user's machine; a reconciler follows each
//! one to where it should be. Every change is audited.
//! Design: docs/adr/0025-control-plane-linode.md.

#[cfg(test)]
pub mod fake;
pub mod linode;
pub mod provider;

use crate::audit::{Actor, Event, Outcome, Source, Who};
use crate::db::{AddMachine, Machine, NewMachine, now};
use crate::rbac::Principal;
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::users::{Caller, need_user_key};
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use provider::{CreateSpec, MachineProvider, ProviderError, ProviderMachine};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub const NOT_CONFIGURED: &str = "The control plane is not configured on this server, so per-user machines are off. Set LINODE_TOKEN and MACHINE_REGIONS to turn it on.";
pub const DEFAULT_TIERS: &str = "starter=g6-standard-1,pro=g6-standard-2,max=g6-standard-4";
pub const DEFAULT_IMAGE: &str = "linode/ubuntu24.04";
const DEFAULT_RECONCILE_SECONDS: u64 = 60;
/// How long after a create that went unanswered a machine may still turn up at the
/// provider. Linode creates synchronously, so this is generous.
pub const CREATE_SETTLE_MS: i64 = 15 * 60 * 1000;
/// The audit actor for what the reconciler does on its own.
const SYSTEM: &str = "control_plane";

/// A machine's lifecycle. The provider's own status is kept beside it, not mixed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Saved; not yet at the provider.
    Pending,
    /// The provider has it and is building or booting it.
    Provisioning,
    Running,
    /// Powered off on purpose.
    Suspended,
    /// Asked to go; deleted at the provider, retried until it is.
    Destroying,
    Destroyed,
    /// The provider refused to build it, or it vanished there. Needs an admin.
    Error,
}

pub const STATES: [State; 7] = [
    State::Pending,
    State::Provisioning,
    State::Running,
    State::Suspended,
    State::Destroying,
    State::Destroyed,
    State::Error,
];

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Provisioning => "provisioning",
            State::Running => "running",
            State::Suspended => "suspended",
            State::Destroying => "destroying",
            State::Destroyed => "destroyed",
            State::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        STATES.into_iter().find(|st| st.as_str() == s)
    }
}

/// What happens to a machine. `next` is the whole state machine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    /// The provider accepted it (or we found the one it made already).
    Created,
    /// The provider says it is running.
    Ready,
    Suspend,
    Resume,
    Resize,
    Destroy,
    /// Deleted at the provider.
    Gone,
    /// Refused by the provider, or gone from it while we still wanted it.
    Fail,
    /// An admin asks again after an error.
    Retry,
}

pub fn next(from: State, step: Step) -> Option<State> {
    use State::*;
    use Step::*;
    match (from, step) {
        (Pending, Created) => Some(Provisioning),
        (Provisioning, Ready) => Some(Running),
        (Running, Suspend) => Some(Suspended),
        (Suspended, Resume) => Some(Running),
        (Running | Suspended, Resize) => Some(from),
        (Pending | Provisioning | Running | Suspended | Error, Destroy) => Some(Destroying),
        (Destroying, Gone) => Some(Destroyed),
        (Pending | Provisioning | Running | Suspended, Fail) => Some(Error),
        (Error, Retry) => Some(Pending),
        _ => None,
    }
}

/// The control plane's settings and provider. `provider` None: off.
pub struct ControlPlane {
    provider: Option<Arc<dyn MachineProvider>>,
    /// Tier name to provider plan, in order; the first is the default.
    pub tiers: Vec<(String, String)>,
    /// Allowed regions; the first is the default.
    pub regions: Vec<String>,
    pub image: String,
    /// Turn on the provider's backups for every machine.
    pub backups: bool,
    /// Starts every label and is the tag on every machine, so one account can hold
    /// machines from several control planes without them touching each other's.
    pub label_prefix: String,
    pub authorized_keys: Vec<String>,
    pub reconcile_every: Duration,
    /// One change at a time, from handlers and the reconciler alike, so two can't
    /// race on one machine. Changes are rare and admin-driven; this is cheap.
    ops: tokio::sync::Mutex<()>,
}

impl Default for ControlPlane {
    fn default() -> ControlPlane {
        ControlPlane {
            provider: None,
            tiers: parse_tiers(DEFAULT_TIERS).unwrap(),
            regions: Vec::new(),
            image: DEFAULT_IMAGE.into(),
            backups: true,
            label_prefix: "superbot".into(),
            authorized_keys: Vec::new(),
            reconcile_every: Duration::from_secs(DEFAULT_RECONCILE_SECONDS),
            ops: tokio::sync::Mutex::new(()),
        }
    }
}

/// Lowercase letters, digits, and inner dashes, as Linode plans, regions, and tags are.
fn slug(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// `tier=plan,tier=plan`, e.g. `starter=g6-standard-1,pro=g6-standard-2`.
pub fn parse_tiers(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in list(raw) {
        let (tier, plan) = pair
            .split_once('=')
            .map(|(t, p)| (t.trim(), p.trim()))
            .ok_or(format!("MACHINE_TIERS: \"{pair}\" isn't tier=plan"))?;
        if !slug(tier, 32) || !slug(plan, 64) {
            return Err(format!(
                "MACHINE_TIERS: \"{pair}\": tiers and plans are lowercase letters, digits, and dashes"
            ));
        }
        if out.iter().any(|(t, _)| t == tier) {
            return Err(format!("MACHINE_TIERS: tier \"{tier}\" is listed twice"));
        }
        out.push((tier.into(), plan.into()));
    }
    if out.is_empty() {
        return Err("MACHINE_TIERS needs at least one tier=plan".into());
    }
    Ok(out)
}

impl ControlPlane {
    /// LINODE_TOKEN (or _FILE) turns it on and then needs MACHINE_REGIONS. The rest
    /// have defaults: MACHINE_TIERS, MACHINE_IMAGE, MACHINE_BACKUPS (on),
    /// MACHINE_LABEL_PREFIX, MACHINE_AUTHORIZED_KEYS, MACHINE_RECONCILE_SECONDS.
    pub fn from_env(
        store: &dyn SecretStore,
        var: impl Fn(&str) -> String,
    ) -> Result<ControlPlane, String> {
        let Some(token) = store.get("LINODE_TOKEN").map_err(|e| e.to_string())? else {
            return Ok(ControlPlane::default());
        };
        let token = token.expose().trim().to_string();
        if token.is_empty() || token.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("LINODE_TOKEN is empty or has spaces in it".into());
        }
        crate::secrets::redact::register(&token);
        let mut cp =
            ControlPlane::configured(Arc::new(linode::Linode::new(&token, linode::API_URL)), &var)?;
        cp.regions = list(&var("MACHINE_REGIONS"));
        if cp.regions.is_empty() {
            return Err("MACHINE_REGIONS is needed with LINODE_TOKEN, e.g. gb-lon or gb-lon,de-fra-2 (the first is the default)".into());
        }
        if let Some(r) = cp.regions.iter().find(|r| !slug(r, 32)) {
            return Err(format!("MACHINE_REGIONS: \"{r}\" isn't a region id"));
        }
        Ok(cp)
    }

    fn configured(
        provider: Arc<dyn MachineProvider>,
        var: &dyn Fn(&str) -> String,
    ) -> Result<ControlPlane, String> {
        let or = |k: &str, d: &str| {
            Some(var(k))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| d.into())
        };
        let image = or("MACHINE_IMAGE", DEFAULT_IMAGE);
        if image.len() > 100
            || !image
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err(format!("MACHINE_IMAGE: \"{image}\" isn't an image id"));
        }
        let backups = match or("MACHINE_BACKUPS", "on").to_ascii_lowercase().as_str() {
            "1" | "on" | "true" | "yes" => true,
            "0" | "off" | "false" | "no" => false,
            v => return Err(format!("MACHINE_BACKUPS must be on or off, not \"{v}\"")),
        };
        let label_prefix = or("MACHINE_LABEL_PREFIX", "superbot");
        if !slug(&label_prefix, 24) || !label_prefix.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err("MACHINE_LABEL_PREFIX: up to 24 lowercase letters, digits, and dashes, starting with a letter".into());
        }
        let authorized_keys = list(&var("MACHINE_AUTHORIZED_KEYS"));
        if let Some(k) = authorized_keys.iter().find(|k| {
            !(k.starts_with("ssh-") || k.starts_with("ecdsa-") || k.starts_with("sk-"))
                || k.chars().any(char::is_control)
        }) {
            return Err(format!(
                "MACHINE_AUTHORIZED_KEYS: \"{}\" isn't an SSH public key",
                crate::audit::clip(k, 24)
            ));
        }
        let secs = or(
            "MACHINE_RECONCILE_SECONDS",
            &DEFAULT_RECONCILE_SECONDS.to_string(),
        );
        let secs = secs
            .parse::<u64>()
            .ok()
            .filter(|s| (10..=3600).contains(s))
            .ok_or("MACHINE_RECONCILE_SECONDS must be 10 to 3600")?;
        Ok(ControlPlane {
            provider: Some(provider),
            tiers: parse_tiers(&or("MACHINE_TIERS", DEFAULT_TIERS))?,
            image,
            backups,
            label_prefix,
            authorized_keys,
            reconcile_every: Duration::from_secs(secs),
            ..ControlPlane::default()
        })
    }

    #[cfg(test)]
    pub fn for_tests(provider: Arc<dyn MachineProvider>) -> ControlPlane {
        ControlPlane {
            regions: vec!["gb-lon".into(), "de-fra-2".into()],
            ..ControlPlane::configured(provider, &|_| String::new()).unwrap()
        }
    }

    pub fn enabled(&self) -> bool {
        self.provider.is_some()
    }

    /// What startup prints.
    pub fn describe(&self) -> String {
        match &self.provider {
            None => "off (set LINODE_TOKEN and MACHINE_REGIONS for one machine per user)".into(),
            Some(p) => format!(
                "{}, regions {}, tiers {}, backups {}",
                p.name(),
                self.regions.join(", "),
                self.tiers
                    .iter()
                    .map(|(t, p)| format!("{t}={p}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.backups { "on" } else { "off" }
            ),
        }
    }

    fn need(&self) -> Res<&dyn MachineProvider> {
        self.provider
            .as_deref()
            .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, NOT_CONFIGURED.into()))
    }

    fn plan(&self, tier: &str) -> Option<&str> {
        self.tiers
            .iter()
            .find(|(t, _)| t == tier)
            .map(|(_, p)| p.as_str())
    }

    fn spec(&self, m: &Machine) -> CreateSpec {
        CreateSpec {
            label: m.label.clone(),
            plan: m.plan.clone(),
            region: m.region.clone(),
            image: self.image.clone(),
            tags: vec![m.tag.clone(), format!("{}-user-{}", m.tag, m.user_id)],
            authorized_keys: self.authorized_keys.clone(),
        }
    }
}

// Lifecycle. Callers hold `ops`.

fn event(by: &Who, action: &str, m: &Machine, extra: Value) -> Event {
    let mut d = json!({ "userId": m.user_id, "tier": m.tier, "plan": m.plan, "region": m.region, "state": m.state });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    by.event(action).target("machine", &m.id).details(d)
}

/// The reconciler, acting for the machine's user.
fn system(m: &Machine) -> Who {
    Who {
        actor: Actor::system(SYSTEM).on_behalf_of(&m.user_id),
        source: Source::default(),
    }
}

fn observe(m: &mut Machine, pm: &ProviderMachine) {
    m.provider_id = Some(pm.id.clone());
    m.provider_status = Some(pm.status.clone());
    m.ipv4 = pm.ipv4.clone();
    m.backups = pm.backups;
}

/// Worth trying again by itself, unlike a refusal: rate limits, the network, timeouts,
/// and the provider's own outages (5xx).
fn transient(e: &ProviderError) -> bool {
    match e {
        ProviderError::RateLimited | ProviderError::Transport(_) => true,
        ProviderError::Api { status, .. } => *status == 408 || *status >= 500,
        ProviderError::NotFound | ProviderError::LabelTaken => false,
    }
}

/// The provider's machine with this one's label, if there is one: what a create whose
/// answer was lost left behind. Found by the tag saved with the row, not today's prefix.
async fn by_label(
    p: &dyn MachineProvider,
    m: &Machine,
) -> Result<Option<ProviderMachine>, ProviderError> {
    Ok(p.list(&m.tag)
        .await?
        .into_iter()
        .find(|x| x.label == m.label))
}

/// Sends a pending machine to the provider. The label makes it idempotent: if the
/// provider has one by that name already, that one is adopted, not a second made.
/// A transient failure leaves it pending for the reconciler; a refusal is an error.
async fn provision(
    app: &App,
    cp: &ControlPlane,
    p: &dyn MachineProvider,
    mut m: Machine,
    by: &Who,
) -> Machine {
    m.create_sent_at = Some(now());
    app.db.save_machine(&m, m.state);
    let found = match p.create(&cp.spec(&m)).await {
        Ok(pm) => Ok((pm, false)),
        Err(ProviderError::LabelTaken) => match by_label(p, &m).await {
            Ok(Some(pm)) => Ok((pm, true)),
            Ok(None) => Err(ProviderError::LabelTaken),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    let from = m.state;
    match found {
        Ok((pm, adopted)) => {
            observe(&mut m, &pm);
            if adopted {
                // Record the machine as it is, should it differ from what the row asked for.
                if pm.plan != m.plan {
                    m.tier = cp
                        .tiers
                        .iter()
                        .find(|(_, plan)| *plan == pm.plan)
                        .map_or(m.tier.clone(), |(t, _)| t.clone());
                    m.plan = pm.plan.clone();
                }
                m.region = pm.region.clone();
            }
            m.state = next(from, Step::Created).unwrap_or(from);
            m.last_error = None;
            if app.db.save_machine(&m, from) {
                app.db.record(&event(
                    by,
                    "machine.created",
                    &m,
                    json!({ "providerId": pm.id, "adopted": adopted }),
                ));
            }
        }
        Err(e) => {
            let retrying = transient(&e);
            if !retrying {
                m.state = next(from, Step::Fail).unwrap_or(from);
                if matches!(e, ProviderError::Api { .. }) {
                    // A refusal made nothing, so a delete needn't wait for it.
                    m.create_sent_at = None;
                }
            }
            m.last_error = Some(e.to_string());
            app.db.save_machine(&m, from);
            app.db.record(
                &event(
                    by,
                    "machine.create_failed",
                    &m,
                    json!({ "error": e.to_string(), "retrying": retrying }),
                )
                .outcome(Outcome::Failure),
            );
        }
    }
    m
}

/// Deletes a destroying machine at the provider. Until that works it stays
/// destroying, with the error, and the reconciler tries again. One with no provider id
/// whose create went unanswered stays too, until `CREATE_SETTLE` has passed with
/// nothing by its label, so a create that lands late is still deleted.
async fn finish_destroy(app: &App, p: &dyn MachineProvider, mut m: Machine, by: &Who) -> Machine {
    let id = match &m.provider_id {
        Some(id) => Ok(Some(id.clone())),
        None => by_label(p, &m).await.map(|f| f.map(|pm| pm.id)),
    };
    let res = match id {
        Ok(Some(id)) => p.delete(&id).await.map(|()| true),
        Ok(None) => Ok(!m
            .create_sent_at
            .is_some_and(|t| now() - t < CREATE_SETTLE_MS)),
        Err(e) => Err(e),
    };
    let from = m.state;
    match res {
        Ok(false) => {
            m.last_error = Some(
                "Waiting to be sure a create the provider didn't answer made no machine.".into(),
            );
            app.db.save_machine(&m, from);
        }
        Ok(true) => {
            m.state = next(from, Step::Gone).unwrap_or(from);
            m.destroyed_at = Some(now());
            (m.last_error, m.provider_status, m.ipv4) = (None, None, None);
            if app.db.save_machine(&m, from) {
                app.db.record(&event(
                    by,
                    "machine.destroyed",
                    &m,
                    json!({ "providerId": m.provider_id }),
                ));
            }
        }
        Err(e) => {
            m.last_error = Some(e.to_string());
            app.db.save_machine(&m, from);
            app.db.record(
                &event(
                    by,
                    "machine.destroy_failed",
                    &m,
                    json!({ "error": e.to_string() }),
                )
                .outcome(Outcome::Failure),
            );
        }
    }
    m
}

/// Brings one machine a step closer to its state: sends pending ones, notices when
/// they run or vanish, turns on backups, and finishes deletes. It never boots or
/// stops a machine to undo a change made at the provider; it records what it sees.
/// Returns whether the machine's state changed.
async fn reconcile_one(app: &App, cp: &ControlPlane, p: &dyn MachineProvider, id: &str) -> bool {
    let Some(mut m) = app.db.machine(id) else {
        return false;
    };
    let (by, from) = (system(&m), m.state);
    match from {
        State::Pending => provision(app, cp, p, m, &by).await.state != from,
        State::Destroying => finish_destroy(app, p, m, &by).await.state != from,
        State::Provisioning | State::Running | State::Suspended => {
            let Some(pid) = m.provider_id.clone() else {
                return false;
            };
            let pm = match p.get(&pid).await {
                Ok(pm) => pm,
                Err(ProviderError::NotFound) => {
                    m.state = next(from, Step::Fail).unwrap_or(from);
                    m.last_error = Some("The machine is gone at the provider.".into());
                    if app.db.save_machine(&m, from) {
                        app.db.record(
                            &event(
                                &by,
                                "machine.lost",
                                &m,
                                json!({ "providerId": pid, "was": from }),
                            )
                            .outcome(Outcome::Failure),
                        );
                    }
                    return true;
                }
                Err(e) => {
                    m.last_error = Some(e.to_string());
                    app.db.save_machine(&m, from);
                    return false;
                }
            };
            observe(&mut m, &pm);
            m.last_error = None;
            let mut events = Vec::new();
            if from == State::Provisioning && pm.running() {
                m.state = next(from, Step::Ready).unwrap_or(from);
                events.push(event(
                    &by,
                    "machine.running",
                    &m,
                    json!({ "providerId": pid, "ipv4": m.ipv4 }),
                ));
            }
            if cp.backups && !pm.backups && m.state != State::Provisioning {
                match p.enable_backups(&pid).await {
                    Ok(()) => {
                        m.backups = true;
                        events.push(event(
                            &by,
                            "machine.backups_enabled",
                            &m,
                            json!({ "providerId": pid }),
                        ));
                    }
                    Err(e) => {
                        m.last_error = Some(e.to_string());
                        events.push(
                            event(
                                &by,
                                "machine.backups_failed",
                                &m,
                                json!({ "error": e.to_string() }),
                            )
                            .outcome(Outcome::Failure),
                        );
                    }
                }
            }
            if app.db.save_machine(&m, from) {
                for e in &events {
                    app.db.record(e);
                }
            }
            m.state != from
        }
        State::Error | State::Destroyed => false,
    }
}

/// One pass over every machine that isn't settled. Each takes the lock on its own, so
/// an admin's request waits for at most one machine, not the whole pass.
pub async fn reconcile(app: &App, cp: &ControlPlane) -> Value {
    let Some(p) = cp.provider.as_deref() else {
        return json!({ "checked": 0, "changed": 0 });
    };
    let ids: Vec<String> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| !matches!(m.state, State::Destroyed | State::Error))
        .map(|m| m.id)
        .collect();
    let mut changed = 0;
    for id in &ids {
        let _g = cp.ops.lock().await;
        changed += reconcile_one(app, cp, p, id).await as usize;
    }
    json!({ "checked": ids.len(), "changed": changed })
}

/// Reconciles every MACHINE_RECONCILE_SECONDS, from startup, when the control plane is on.
pub fn start(app: AppState, cp: Arc<ControlPlane>) {
    if !cp.enabled() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(cp.reconcile_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            reconcile(&app, &cp).await;
        }
    });
}

// HTTP. `/api/machines` and `/api/users/{key}/machine` are admin-only (rbac::classify);
// `/api/machine` is the caller's own.

fn admin_view(app: &App, m: &Machine) -> Value {
    let mut v = serde_json::to_value(m).unwrap_or_default();
    v["userEmail"] = json!(app.db.user(&m.user_id).and_then(|u| u.email));
    v
}

/// What a person sees of their own machine.
fn own_view(m: &Machine) -> Value {
    json!({
        "id": m.id, "tier": m.tier, "region": m.region, "state": m.state, "providerStatus": m.provider_status,
        "ipv4": m.ipv4, "backups": m.backups, "createdAt": m.created_at, "updatedAt": m.updated_at,
    })
}

fn reply(app: &App, code: StatusCode, m: &Machine) -> Response {
    (code, Json(admin_view(app, m))).into_response()
}

/// The provider said no: 502, with the machine as it is now.
fn failed(app: &App, e: &str, m: &Machine) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": e, "machine": admin_view(app, m) })),
    )
        .into_response()
}

fn conflict(msg: String) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg)
}

/// An optional JSON object with only `fields`, each a string.
fn fields(body: &Bytes, allowed: &[&str]) -> Res<HashMap<String, String>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(HashMap::new());
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| bad(format!("Invalid JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    let mut out = HashMap::new();
    for (k, v) in obj {
        if !allowed.contains(&k.as_str()) {
            return Err(bad(format!("Unknown field: {}", crate::audit::clip(k, 40))));
        }
        let s = v.as_str().ok_or_else(|| bad(format!("{k} must be text")))?;
        out.insert(k.clone(), s.trim().to_string());
    }
    Ok(out)
}

fn need_machine(app: &App, user_id: &str) -> Res<Machine> {
    app.db
        .user_machine(user_id)
        .ok_or_else(|| not_found("Machine"))
}

fn provider_id(m: &Machine) -> Res<&str> {
    m.provider_id.as_deref().ok_or_else(|| {
        conflict(format!(
            "The machine is {} and has no provider id yet.",
            m.state.as_str()
        ))
    })
}

/// `GET /api/machines?state=`: every machine, newest first, destroyed ones too.
pub async fn list_all(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Query(q): Query<HashMap<String, String>>,
) -> Res {
    a.machines.need()?;
    let state = match q.get("state").map(String::as_str) {
        None | Some("" | "all") => None,
        Some(s) => Some(State::parse(s).ok_or_else(|| bad("state must be one of pending, provisioning, running, suspended, destroying, destroyed, error, all"))?),
    };
    Ok(Json(json!(
        app.db
            .machines(state)
            .iter()
            .map(|m| admin_view(&app, m))
            .collect::<Vec<_>>()
    )))
}

/// `GET /api/users/{key}/machine`: the user's live machine.
pub async fn get(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Path(key): Path<String>,
) -> Res {
    a.machines.need()?;
    let u = need_user_key(&app, &key)?;
    Ok(Json(admin_view(&app, &need_machine(&app, &u.id)?)))
}

/// `POST /api/users/{key}/machine` `{tier?, region?}`: gives the user a machine. Asking
/// again returns the one they have (200), so a retried request never makes a second;
/// a different tier or region is a 409 (resize instead). After an error, asking again
/// retries. 202 when one is on its way; 502 if the provider refused it.
pub async fn request(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    body: Bytes,
) -> Res<Response> {
    let cp = &a.machines;
    let p = cp.need()?;
    let f = fields(&body, &["tier", "region"])?;
    let u = need_user_key(&app, &key)?;
    if !u.active() {
        return Err(conflict(
            "This user is disabled. Enable them before giving them a machine.".into(),
        ));
    }
    let asked_tier = f.get("tier").cloned();
    if let Some(t) = &asked_tier
        && cp.plan(t).is_none()
    {
        return Err(bad(format!(
            "tier must be one of {}",
            cp.tiers
                .iter()
                .map(|(t, _)| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let asked_region = f.get("region").cloned();
    if let Some(r) = &asked_region
        && !cp.regions.contains(r)
    {
        return Err(bad(format!(
            "region must be one of {}",
            cp.regions.join(", ")
        )));
    }
    // What's asked for, else `(tier, plan, region)` as given: a new machine's defaults,
    // or what a retried machine was saved with.
    let settings = |tier: &str, plan: &str, region: &str| {
        let tier = asked_tier.clone().unwrap_or_else(|| tier.into());
        let plan = cp.plan(&tier).map_or_else(|| plan.into(), String::from);
        let region = asked_region.clone().unwrap_or_else(|| region.into());
        (tier, plan, region)
    };
    let _g = cp.ops.lock().await;
    let m = match app.db.user_machine(&u.id) {
        Some(mut m) if m.state == State::Error => {
            let (tier, plan, region) = settings(&m.tier, &m.plan, &m.region);
            // The label stays, so a machine made by an earlier create would be adopted
            // as it is. Only change what's asked for when there's none.
            if (&tier, &region) != (&m.tier, &m.region) {
                match by_label(p, &m).await {
                    Err(e) => return Ok(failed(&app, &e.to_string(), &m)),
                    Ok(Some(pm)) => {
                        return Err(conflict(format!(
                            "This user's machine still exists at the provider ({} in {}). Ask again without a tier or region and resize it once it's back, or destroy it first.",
                            pm.plan, pm.region
                        )));
                    }
                    Ok(None) => {}
                }
            }
            m.state = next(m.state, Step::Retry).unwrap_or(m.state);
            (m.tier, m.plan, m.region) = (tier, plan, region);
            (
                m.provider_id,
                m.provider_status,
                m.ipv4,
                m.last_error,
                m.backups,
            ) = (None, None, None, None, false);
            if !app.db.save_machine(&m, State::Error) {
                return Err(conflict("The machine changed meanwhile; try again.".into()));
            }
            app.db.record(&event(
                &by,
                "machine.retried",
                &m,
                json!({ "userEmail": u.email }),
            ));
            m
        }
        Some(m) if m.state == State::Destroying => {
            return Err(conflict(
                "This user's machine is being destroyed. Ask again once it's gone.".into(),
            ));
        }
        Some(m)
            if f.get("tier").is_some_and(|t| *t != m.tier)
                || f.get("region").is_some_and(|r| *r != m.region) =>
        {
            return Err(conflict(format!(
                "This user has a machine already ({} in {}). Resize it, or destroy it first.",
                m.tier, m.region
            )));
        }
        Some(m) => return Ok(reply(&app, StatusCode::OK, &m)),
        None => {
            let (default_tier, default_plan) = &cp.tiers[0];
            let (tier, plan, region) = settings(default_tier, default_plan, &cp.regions[0]);
            let new = NewMachine {
                user_id: &u.id,
                provider: p.name(),
                label_prefix: &cp.label_prefix,
                tier: &tier,
                plan: &plan,
                region: &region,
                created_by: by.actor.id.as_deref(),
            };
            match app.db.add_machine(&new) {
                Ok(m) => {
                    app.db.record(&event(
                        &by,
                        "machine.requested",
                        &m,
                        json!({ "userEmail": u.email }),
                    ));
                    m
                }
                Err(AddMachine::Exists(m)) => return Ok(reply(&app, StatusCode::OK, &m)),
                Err(AddMachine::Db(e)) => {
                    return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e));
                }
            }
        }
    };
    let m = provision(&app, cp, p, m, &by).await;
    Ok(match (m.state, &m.last_error) {
        (State::Error, Some(e)) => failed(&app, e, &m),
        _ => reply(&app, StatusCode::ACCEPTED, &m),
    })
}

/// Suspend, resume, or resize. The provider is asked how the machine is first, so a
/// call whose answer was lost, or a change made at the provider, is neither repeated
/// nor taken as done when it isn't. Repeating one that is done changes nothing.
async fn act(
    app: &AppState,
    cp: &ControlPlane,
    by: &Who,
    key: &str,
    step: Step,
    tier: Option<String>,
) -> Res<Response> {
    let p = cp.need()?;
    let u = need_user_key(app, key)?;
    let _g = cp.ops.lock().await;
    let mut m = need_machine(app, &u.id)?;
    let target = match (step, &tier) {
        (Step::Resize, Some(t)) => Some((
            t.clone(),
            cp.plan(t).ok_or_else(|| bad("Unknown tier"))?.to_string(),
        )),
        (Step::Resize, None) => return Err(bad("Unknown tier")),
        _ => None,
    };
    let from = m.state;
    let to = match step {
        Step::Suspend => State::Suspended,
        Step::Resume => State::Running,
        _ => from,
    };
    if next(from, step).is_none() && !(to == from && matches!(step, Step::Suspend | Step::Resume)) {
        let verb = match step {
            Step::Suspend => "suspend",
            Step::Resume => "resume",
            _ => "resize",
        };
        return Err(conflict(format!(
            "Can't {verb} a machine that is {}.",
            from.as_str()
        )));
    }
    let pid = provider_id(&m)?.to_string();
    let action = match step {
        Step::Suspend => "machine.suspended",
        Step::Resume => "machine.resumed",
        _ => "machine.resized",
    };
    let refused = |m: &Machine, e: ProviderError| {
        app.db.record(
            &event(
                by,
                action,
                m,
                json!({ "error": e.to_string(), "providerId": pid }),
            )
            .outcome(Outcome::Failure),
        );
        failed(app, &e.to_string(), m)
    };
    let pm = match p.get(&pid).await {
        Ok(pm) => pm,
        Err(e) => return Ok(refused(&m, e)),
    };
    // Already so at the provider; also when two tiers share a plan.
    let there = match (step, &target) {
        (Step::Suspend, _) => matches!(pm.status.as_str(), "offline" | "stopped" | "shutting_down"),
        (Step::Resume, _) => matches!(pm.status.as_str(), "running" | "booting"),
        (_, Some((_, plan))) => pm.plan == *plan,
        _ => false,
    };
    let recorded = to == from
        && target
            .as_ref()
            .is_none_or(|(t, plan)| *t == m.tier && *plan == m.plan);
    if there && recorded {
        return Ok(reply(app, StatusCode::OK, &m));
    }
    if !there {
        let res = match (step, &target) {
            (Step::Suspend, _) => p.shutdown(&pid).await,
            (Step::Resume, _) => p.boot(&pid).await,
            (_, Some((_, plan))) => p.resize(&pid, plan).await,
            _ => Ok(()),
        };
        if let Err(e) = res {
            return Ok(refused(&m, e));
        }
    }
    let mut extra = json!({ "providerCall": !there });
    if let Some((t, plan)) = &target {
        extra = json!({ "fromTier": m.tier, "toTier": t, "fromPlan": m.plan, "toPlan": plan, "providerCall": !there });
    }
    m.state = to;
    if let Some((t, plan)) = target {
        (m.tier, m.plan) = (t, plan);
    }
    m.last_error = None;
    if !app.db.save_machine(&m, from) {
        return Err(conflict("The machine changed meanwhile; try again.".into()));
    }
    app.db.record(&event(by, action, &m, extra));
    Ok(reply(app, StatusCode::OK, &m))
}

/// `POST /api/users/{key}/machine/suspend`: powers it off. Disk and address stay.
pub async fn suspend(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<Response> {
    act(&app, &a.machines, &by, &key, Step::Suspend, None).await
}

/// `POST /api/users/{key}/machine/resume`: boots it again.
pub async fn resume(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<Response> {
    act(&app, &a.machines, &by, &key, Step::Resume, None).await
}

/// `POST /api/users/{key}/machine/resize` `{tier}`: moves it to the tier's plan. The
/// provider may power-cycle it.
pub async fn resize(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    body: Bytes,
) -> Res<Response> {
    a.machines.need()?;
    let tier = fields(&body, &["tier"])?
        .remove("tier")
        .ok_or_else(|| bad("Send {\"tier\": \"...\"}."))?;
    if a.machines.plan(&tier).is_none() {
        return Err(bad(format!(
            "tier must be one of {}",
            a.machines
                .tiers
                .iter()
                .map(|(t, _)| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    act(&app, &a.machines, &by, &key, Step::Resize, Some(tier)).await
}

/// `DELETE /api/users/{key}/machine`: deletes it and its disks at the provider. 200
/// once gone; 202 while the provider hasn't confirmed (the reconciler keeps trying).
pub async fn destroy(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<Response> {
    let cp = &a.machines;
    let p = cp.need()?;
    let u = need_user_key(&app, &key)?;
    let _g = cp.ops.lock().await;
    let mut m = need_machine(&app, &u.id)?;
    if m.state != State::Destroying {
        let from = m.state;
        m.state = next(from, Step::Destroy).ok_or_else(|| {
            conflict(format!(
                "Can't destroy a machine that is {}.",
                from.as_str()
            ))
        })?;
        if !app.db.save_machine(&m, from) {
            return Err(conflict("The machine changed meanwhile; try again.".into()));
        }
        app.db.record(&event(
            &by,
            "machine.destroy_requested",
            &m,
            json!({ "was": from, "userEmail": u.email }),
        ));
    }
    let m = finish_destroy(&app, p, m, &by).await;
    Ok(reply(
        &app,
        if m.state == State::Destroyed {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        },
        &m,
    ))
}

/// `POST /api/machines/reconcile`: one pass now, instead of waiting for the timer.
pub async fn reconcile_now(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>) -> Res {
    a.machines.need()?;
    Ok(Json(reconcile(&app, &a.machines).await))
}

/// `GET /api/machine`: the caller's own machine, and only theirs.
pub async fn mine(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(c): Extension<Caller>,
) -> Res {
    a.machines.need()?;
    if c.principal == Principal::Bot {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Only a signed-in person has a machine, not a Bot.".into(),
        ));
    }
    let user = c.user.ok_or_else(|| not_found("Machine"))?;
    let m = app.db.user_machine(&user.id).ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "You don't have a machine yet.".into(),
        )
    })?;
    Ok(Json(own_view(&m)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;

    #[test]
    fn the_state_machine() {
        use State::*;
        use Step::*;
        let steps = [
            Created, Ready, Suspend, Resume, Resize, Destroy, Gone, Fail, Retry,
        ];
        let allowed = [
            (Pending, Created, Provisioning),
            (Pending, Destroy, Destroying),
            (Pending, Fail, Error),
            (Provisioning, Ready, Running),
            (Provisioning, Destroy, Destroying),
            (Provisioning, Fail, Error),
            (Running, Suspend, Suspended),
            (Running, Resize, Running),
            (Running, Destroy, Destroying),
            (Running, Fail, Error),
            (Suspended, Resume, Running),
            (Suspended, Resize, Suspended),
            (Suspended, Destroy, Destroying),
            (Suspended, Fail, Error),
            (Destroying, Gone, Destroyed),
            (Error, Destroy, Destroying),
            (Error, Retry, Pending),
        ];
        for from in STATES {
            for step in steps {
                let want = allowed
                    .iter()
                    .find(|(f, s, _)| *f == from && *s == step)
                    .map(|(_, _, to)| *to);
                assert_eq!(next(from, step), want, "{from:?} + {step:?}");
            }
        }
        assert!(
            steps.iter().all(|s| next(Destroyed, *s).is_none()),
            "destroyed is final"
        );
        for s in STATES {
            assert_eq!(State::parse(s.as_str()), Some(s));
            assert_eq!(serde_json::to_value(s).unwrap(), json!(s.as_str()));
        }
        assert_eq!(State::parse("Running"), None);
    }

    #[test]
    fn tiers_parse_strictly() {
        assert_eq!(
            parse_tiers(" a=g6-standard-1 , b=g6-standard-2 ").unwrap(),
            [
                ("a".into(), "g6-standard-1".into()),
                ("b".into(), "g6-standard-2".into())
            ]
        );
        for bad in ["", "a", "a=", "=p", "A=p", "a=p,a=q", "a=p q", "a=-p"] {
            assert!(parse_tiers(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn off_without_a_token() {
        let cp = ControlPlane::from_env(&EnvStore::fixed(&[]), |k| {
            if k == "MACHINE_REGIONS" {
                "gb-lon".into()
            } else {
                String::new()
            }
        })
        .unwrap();
        assert!(!cp.enabled());
        assert!(cp.describe().starts_with("off"));
        assert_eq!(
            cp.need().err().map(|e| (e.0, e.1)),
            Some((StatusCode::SERVICE_UNAVAILABLE, NOT_CONFIGURED.to_string()))
        );
    }

    #[test]
    fn settings() {
        let token = EnvStore::fixed(&[("LINODE_TOKEN", "settings-test-token-4f1d")]);
        let with = |vars: &'static [(&'static str, &'static str)]| {
            ControlPlane::from_env(&token, |k| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            })
        };
        assert!(
            with(&[]).err().unwrap().contains("MACHINE_REGIONS"),
            "a token alone doesn't say where"
        );
        let cp = with(&[("MACHINE_REGIONS", "gb-lon, de-fra-2")]).unwrap();
        assert!(cp.enabled());
        assert_eq!(
            (
                cp.regions.as_slice(),
                cp.tiers[0].0.as_str(),
                cp.image.as_str(),
                cp.backups
            ),
            (
                &["gb-lon".to_string(), "de-fra-2".into()][..],
                "starter",
                DEFAULT_IMAGE,
                true
            )
        );
        assert_eq!(cp.reconcile_every, Duration::from_secs(60));
        assert!(
            !cp.describe().contains("settings-test-token"),
            "{}",
            cp.describe()
        );
        let cp = with(&[
            ("MACHINE_REGIONS", "us-east"),
            ("MACHINE_TIERS", "solo=g6-nanode-1"),
            ("MACHINE_BACKUPS", "off"),
            ("MACHINE_LABEL_PREFIX", "acme"),
            ("MACHINE_AUTHORIZED_KEYS", "ssh-ed25519 AAAA ops@example"),
            ("MACHINE_RECONCILE_SECONDS", "30"),
        ])
        .unwrap();
        assert_eq!(
            (
                cp.plan("solo"),
                cp.backups,
                cp.label_prefix.as_str(),
                cp.authorized_keys.len()
            ),
            (Some("g6-nanode-1"), false, "acme", 1)
        );
        for bad in [
            &[("MACHINE_REGIONS", "GB London")][..],
            &[("MACHINE_REGIONS", "gb-lon"), ("MACHINE_BACKUPS", "maybe")],
            &[
                ("MACHINE_REGIONS", "gb-lon"),
                ("MACHINE_LABEL_PREFIX", "1x"),
            ],
            &[
                ("MACHINE_REGIONS", "gb-lon"),
                ("MACHINE_AUTHORIZED_KEYS", "hunter2"),
            ],
            &[
                ("MACHINE_REGIONS", "gb-lon"),
                ("MACHINE_RECONCILE_SECONDS", "1"),
            ],
            &[
                ("MACHINE_REGIONS", "gb-lon"),
                ("MACHINE_IMAGE", "linode/ubuntu 24"),
            ],
        ] {
            assert!(with(bad).is_err(), "{bad:?}");
        }
        assert!(
            ControlPlane::from_env(&EnvStore::fixed(&[("LINODE_TOKEN", "a b")]), |_| "gb-lon"
                .into())
            .is_err()
        );
    }
}
