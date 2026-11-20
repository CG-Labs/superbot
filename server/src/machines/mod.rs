//! The control plane: one machine per user, rented from a provider (Linode). Off
//! unless LINODE_TOKEN is set, so self-hosted servers never see it. Admins request,
//! suspend, resume, resize, and destroy a user's machine; a reconciler follows each
//! one to where it should be. Every change is audited.
//! Design: docs/adr/0025-control-plane-linode.md.
// The agent binary's code; botd only runs it in tests, and not all of it.
#[cfg(test)]
#[allow(dead_code)]
pub mod agent;
pub mod botuser;
#[cfg(test)]
pub mod display;
pub mod enroll;

#[cfg(test)]
pub mod fake;
pub mod firewall;
pub mod folder;
pub mod job;
#[cfg(test)]
pub mod landing;
pub mod linode;
pub mod logins;
pub mod offboard;
pub mod pki;
pub mod provider;
pub mod route;
pub mod runas;
pub mod screens;
pub mod teammate;
#[cfg(test)]
pub mod teammates;
#[cfg(test)]
pub mod terminal;
pub mod tools;
#[cfg(test)]
pub mod upgrade;
pub mod upkeep;
pub mod wire;

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
/// Heartbeats in flight at once; each gives up after 10 seconds.
const HEARTBEATS_AT_ONCE: usize = 16;
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
    /// MACHINE_ROUTING (ADR 0029, ADR 0036): off, the default, runs every Bot on this
    /// server; `assigned` runs assigned users' Bots on their machine and others' here;
    /// `on` runs Bots only on their owner's assigned machine.
    pub routing: route::Routing,
    /// How work reaches a user's machine: `Unenrolled` (refuses) until enrollment is
    /// on, then mutual TLS to the machine's agent (ADR 0031).
    pub link: Arc<dyn route::MachineLink>,
    /// Machine enrollment and mutual TLS (ADR 0031). None: off (MACHINE_CONTROL_URL).
    pub enrollment: Option<Arc<enroll::Enrollment>>,
    /// The provider firewall every machine sits behind (ADR 0035). None: off
    /// (MACHINE_FIREWALL). Made from `firewall_settings` once enrollment says which
    /// port to open.
    pub firewall: Option<firewall::Firewall>,
    firewall_settings: Option<firewall::Settings>,
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
            routing: route::Routing::Off,
            link: Arc::new(route::Unenrolled),
            enrollment: None,
            firewall: None,
            firewall_settings: None,
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
            let routing = route::Routing::parse(&var("MACHINE_ROUTING"))?;
            if routing != route::Routing::Off {
                return Err(format!("MACHINE_ROUTING={} needs the control plane: set LINODE_TOKEN and MACHINE_REGIONS", routing.as_str()));
            }
            if firewall::Settings::from_env(&var)?.is_some() {
                return Err("MACHINE_FIREWALL=on needs the control plane: set LINODE_TOKEN and MACHINE_REGIONS".into());
            }
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
            routing: route::Routing::parse(&var("MACHINE_ROUTING"))?,
            tiers: parse_tiers(&or("MACHINE_TIERS", DEFAULT_TIERS))?,
            image,
            backups,
            label_prefix,
            authorized_keys,
            reconcile_every: Duration::from_secs(secs),
            firewall_settings: firewall::Settings::from_env(var)?,
            ..ControlPlane::default()
        })
    }

    /// Turns on enrollment: machines get tokens at create, and routed work goes to
    /// them over mutual TLS. Needs the control plane.
    pub fn enroll_with(&mut self, e: enroll::Enrollment) -> Result<Arc<enroll::Enrollment>, String> {
        if !self.enabled() {
            return Err("MACHINE_CONTROL_URL needs the control plane: set LINODE_TOKEN and MACHINE_REGIONS".into());
        }
        if let Some(s) = &self.firewall_settings {
            self.firewall = Some(firewall::Firewall::new(
                s,
                &self.label_prefix,
                e.agent_port,
                e.host(),
            )?);
        }
        let e = Arc::new(e);
        self.link = Arc::new(enroll::Mtls(e.clone()));
        self.enrollment = Some(e.clone());
        Ok(e)
    }

    /// Puts every machine behind a firewall made from `s` (tests; `from_env` reads
    /// MACHINE_FIREWALL). Needs enrollment, for the agent's port.
    #[cfg(test)]
    pub fn firewall_with(&mut self, s: firewall::Settings) -> Result<(), String> {
        let e = self.enrollment.clone().ok_or("enroll first")?;
        self.firewall = Some(firewall::Firewall::new(
            &s,
            &self.label_prefix,
            e.agent_port,
            e.host(),
        )?);
        Ok(())
    }

    /// Whether a teammate's runs of shared Bots go to the owner's machine as the
    /// teammate's own user (MACHINE_TEAMMATE_USERS, ADR 0048).
    pub fn teammate_users(&self) -> bool {
        self.enrollment.as_ref().is_some_and(|e| e.teammate_users)
    }

    /// Where `user_id`'s Bots run (`route::target`).
    pub fn route(&self, db: &crate::db::Db, user_id: &str) -> Result<route::Target, route::Refusal> {
        route::target(db, self, user_id)
    }

    /// Whether a run of `bin` may start on `machine_id` now, beyond `route::fit`: the Bots'
    /// own user is ready there (ADR 0043), their first folder copy is done and the harness
    /// is logged in there (ADR 0041) or keyed. `keys`: whose own keys the run gets, if any.
    /// `teammate`: the run is a teammate's, as their own user (ADR 0048), which the
    /// agent must be able to do, and which only a server-wide key logs in.
    pub fn ready(&self, app: &App, hb: &wire::Heartbeat, keys: Option<&str>, machine_id: &str, bin: &str, teammate: bool) -> Result<(), route::Refusal> {
        let Some(e) = &self.enrollment else { return Ok(()) };
        botuser::check_run(e, hb)?;
        if teammate {
            teammate::fit(hb)?;
            return logins::check_teammate_run(bin);
        }
        if folder::first_copy_running(app, e, machine_id) {
            return Err(route::Refusal::FolderCopying);
        }
        logins::check_run(e, hb, keys, bin)
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
                "{}, regions {}, tiers {}, backups {}, routing {}, enrollment {}, firewall {}",
                p.name(),
                self.regions.join(", "),
                self.tiers
                    .iter()
                    .map(|(t, p)| format!("{t}={p}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.backups { "on" } else { "off" },
                match self.routing {
                    route::Routing::Off => "off (Bots run on this server)".into(),
                    r => format!("{} via {}", r.as_str(), self.link.name()),
                },
                self.enrollment.as_ref().map_or("off (set MACHINE_CONTROL_URL)".into(), |e| e.describe()),
                self.firewall.as_ref().map_or("off (set MACHINE_FIREWALL=on)".into(), |f| f.describe())
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

    fn spec(&self, m: &Machine, user_data: Option<String>) -> CreateSpec {
        CreateSpec {
            label: m.label.clone(),
            plan: m.plan.clone(),
            region: m.region.clone(),
            image: self.image.clone(),
            tags: vec![m.tag.clone(), format!("{}-user-{}", m.tag, m.user_id)],
            authorized_keys: self.authorized_keys.clone(),
            user_data,
            firewall_id: m.firewall_id.clone(),
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
    // The firewall first: a machine is never made without one, nor a token minted for
    // a create that won't be sent.
    m.firewall_id = match &cp.firewall {
        None => None,
        Some(fw) => match firewall::ensure(app, fw, p, by).await {
            Ok(id) => Some(id),
            Err(e) => return refused(app, m, by, e, "firewall"),
        },
    };
    m.create_sent_at = Some(now());
    app.db.save_machine(&m, m.state);
    // A fresh token each attempt. An earlier one stays good until it expires, in case
    // that attempt made the machine and it is adopted below.
    let user_data = match &cp.enrollment {
        None => None,
        Some(e) => match e.mint_token(app, &m.id, by.actor.id.as_deref()) {
            Ok((token, expires_at)) => {
                app.db.record(&event(by, "machine.enroll_token_issued", &m, json!({ "expiresAt": expires_at, "via": "create" })));
                Some(e.user_data(&m, &token))
            }
            Err(err) => {
                m.last_error = Some(format!("couldn't make an enrollment token: {err}"));
                app.db.save_machine(&m, m.state);
                return m;
            }
        },
    };
    let found = match p.create(&cp.spec(&m, user_data)).await {
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
        Err(e) => return refused(app, m, by, e, "create"),
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
                    json!({ "providerId": pm.id, "adopted": adopted, "firewallId": m.firewall_id }),
                ));
            }
        }
    }
    m
}

/// A create (or the firewall before it, `step`) didn't go through. A transient failure
/// leaves the machine pending for the reconciler; a refusal is an error.
fn refused(app: &App, mut m: Machine, by: &Who, e: ProviderError, step: &str) -> Machine {
    let from = m.state;
    let retrying = transient(&e);
    if !retrying {
        m.state = next(from, Step::Fail).unwrap_or(from);
        if step == "create" && matches!(e, ProviderError::Api { .. }) {
            // A refusal made nothing, so a delete needn't wait for it.
            m.create_sent_at = None;
        }
    }
    m.last_error = Some(match step {
        "firewall" => format!("The machine's firewall couldn't be set up: {e}"),
        _ => e.to_string(),
    });
    app.db.save_machine(&m, from);
    app.db.record(
        &event(
            by,
            "machine.create_failed",
            &m,
            json!({ "error": e.to_string(), "retrying": retrying, "step": step }),
        )
        .outcome(Outcome::Failure),
    );
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
                firewall::release(app, p, &m, by).await;
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
                        // If it turns up again it is not to be trusted as it was.
                        enroll::revoke_all(app, &by, &m, "lost");
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
            if let Some(e) = &cp.enrollment
                && matches!(m.state, State::Provisioning | State::Running)
                && app.db.mark_enroll_overdue(&m.id)
            {
                app.db.record(
                    &event(
                        &by,
                        "machine.enroll_timeout",
                        &m,
                        json!({ "providerId": pid, "minutes": e.enroll_timeout_ms / 60_000, "enrollBy": m.enroll_by, "enrollment": m.enrollment }),
                    )
                    .outcome(Outcome::Failure),
                );
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
    let mut out = json!({ "checked": ids.len(), "changed": changed });
    if let Some(fw) = &cp.firewall {
        let _g = cp.ops.lock().await;
        out["firewallAttached"] = firewall::sync(app, fw, p).await.into();
    }
    out
}

/// Asks every enrolled running machine's agent how it is, a few at a time, sends
/// what's due to those that answered (`upkeep`), and returns how many did. None when enrollment is off. Heartbeats change only the
/// agent columns, so they don't take the lock.
pub async fn heartbeats(app: &AppState, cp: &ControlPlane) -> Option<usize> {
    use futures_util::StreamExt;
    let e = cp.enrollment.as_ref()?;
    let enrolled = app.db.machines(Some(State::Running)).into_iter().filter(|m| m.enrollment == "enrolled");
    let answered = futures_util::stream::iter(enrolled)
        .map(|m| async move {
            let Ok(hb) = enroll::heartbeat(app, e, &m).await else {
                if let Some(m) = app.db.machine(&m.id) {
                    upkeep::expire_upgrade(app, cp, &m);
                }
                return false;
            };
            upkeep::follow_up(app, cp, e, &m.id, &hb).await;
            botuser::follow_up(app, e, &m, &hb).await;
            folder::follow_up(app, e, &m, &hb);
            true
        })
        .buffer_unordered(HEARTBEATS_AT_ONCE)
        .filter(|ok| std::future::ready(*ok))
        .count()
        .await;
    screens::reap(app).await;
    offboard::follow_up(app);
    Some(answered)
}

/// Reconciles every MACHINE_RECONCILE_SECONDS, from startup, when the control plane is on.
pub fn start(app: AppState, cp: Arc<ControlPlane>) {
    if !cp.enabled() {
        return;
    }
    let (a, c) = (app.clone(), cp.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(c.reconcile_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            reconcile(&a, &c).await;
        }
    });
    if cp.enrollment.is_none() {
        return;
    }
    // Apart from reconciling, so agents that don't answer can't hold up provider checks.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(cp.reconcile_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            heartbeats(&app, &cp).await;
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
        "enrollment": m.enrollment, "agentSeenAt": m.agent_seen_at, "enrollOverdueAt": m.enroll_overdue_at,
        "assigned": m.assigned_at.is_some(),
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

/// The machine size a user's plan gives them (ADR 0040), as `(machine tier, provider
/// plan)`: the plan's `machineType`, named by its `MACHINE_TIERS` entry if it has one,
/// else by the user's tier. None: their plan sets no size, so any `MACHINE_TIERS` entry.
pub fn size_for(app: &App, cp: &ControlPlane, user_id: &str) -> Option<(String, String)> {
    let tier = app.tier_of(user_id);
    let plan = tier.limits.machine_type.clone()?;
    let name = cp.tiers.iter().find(|(_, p)| *p == plan).map_or_else(|| tier.name.clone(), |(t, _)| t.clone());
    Some((name, plan))
}

/// The provider plan a machine tier means: the name of the size the user's plan gives
/// them, else a `MACHINE_TIERS` entry. The user's own size wins, since it may be named
/// after their tier and a `MACHINE_TIERS` entry of that name may be another plan.
fn plan_of(cp: &ControlPlane, size: &Option<(String, String)>, tier: &str) -> Option<String> {
    size.as_ref().filter(|(n, _)| n == tier).map(|(_, p)| p.clone()).or_else(|| cp.plan(tier).map(String::from))
}

fn tier_choices(cp: &ControlPlane, size: &Option<(String, String)>) -> String {
    let mut names: Vec<&str> = cp.tiers.iter().map(|(t, _)| t.as_str()).collect();
    if let Some((n, _)) = size.as_ref().filter(|(n, _)| !names.contains(&n.as_str())) {
        names.push(n);
    }
    format!("tier must be one of {}", names.join(", "))
}

/// A machine size the user's plan doesn't give them: refused, and audited.
fn refuse_size(app: &App, by: &Who, u: &crate::db::User, allowed: &(String, String), tier: &str, plan: &str, action: &str) -> ApiError {
    let user_tier = app.tier_of(&u.id);
    let details = json!({
        "reason": "tier_machine_size", "action": action, "userEmail": u.email, "userTier": user_tier.name,
        "askedTier": tier, "askedPlan": plan, "allowedTier": allowed.0, "allowedPlan": allowed.1,
    });
    app.db.record(&by.event("machine.refused").target("user", &u.id).outcome(Outcome::Denied).details(details));
    ApiError(
        StatusCode::FORBIDDEN,
        format!(
            "{}'s plan ({}) comes with {} machines, not {plan}. Ask for \"{}\" or leave the tier out, or move them to another plan first.",
            u.name, user_tier.label, allowed.1, allowed.0
        ),
    )
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
    let size = size_for(&app, cp, &u.id);
    let asked_tier = f.get("tier").cloned();
    if let Some(t) = &asked_tier {
        let plan = plan_of(cp, &size, t).ok_or_else(|| bad(tier_choices(cp, &size)))?;
        if let Some(allowed) = size.as_ref().filter(|(_, p)| *p != plan) {
            return Err(refuse_size(&app, &by, &u, allowed, t, &plan, "request"));
        }
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
    // A plan that sets a machine size (ADR 0040) gets that size unless asked otherwise,
    // and asking otherwise was refused above.
    let settings = |tier: &str, plan: &str, region: &str| {
        let (tier, plan) = match (&asked_tier, &size) {
            (Some(t), _) => (t.clone(), plan_of(cp, &size, t).unwrap_or_else(|| plan.into())),
            (None, Some(s)) => s.clone(),
            (None, None) => (tier.to_string(), cp.plan(tier).map_or_else(|| plan.into(), String::from)),
        };
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
    target: Option<(String, String)>,
) -> Res<Response> {
    let p = cp.need()?;
    let u = need_user_key(app, key)?;
    let _g = cp.ops.lock().await;
    let mut m = need_machine(app, &u.id)?;
    if step == Step::Resize && target.is_none() {
        return Err(bad("Unknown tier"));
    }
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
    match m.state {
        State::Suspended if from != State::Suspended => enroll::hold(app, by, &m),
        State::Running if from == State::Suspended => enroll::release(app, by, &m),
        _ => {}
    }
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
    let cp = &a.machines;
    cp.need()?;
    let tier = fields(&body, &["tier"])?
        .remove("tier")
        .ok_or_else(|| bad("Send {\"tier\": \"...\"}."))?;
    let u = need_user_key(&app, &key)?;
    let size = size_for(&app, cp, &u.id);
    let plan = plan_of(cp, &size, &tier).ok_or_else(|| bad(tier_choices(cp, &size)))?;
    if let Some(allowed) = size.as_ref().filter(|(_, p)| *p != plan) {
        return Err(refuse_size(&app, &by, &u, allowed, &tier, &plan, "resize"));
    }
    act(&app, cp, &by, &key, Step::Resize, Some((tier, plan))).await
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
        enroll::revoke_all(&app, &by, &m, "destroyed");
        unplace(&app, &by, &m, "destroyed");
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
    let mut out = reconcile(&app, &a.machines).await;
    if let Some(n) = heartbeats(&app, &a.machines).await {
        out["heartbeats"] = n.into();
    }
    Ok(Json(out))
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

// Placement (ADR 0036): which users' Bots run on their machine.

/// Where a user's Bots run now, and why, as admins see it.
fn placement_view(app: &App, cp: &ControlPlane, user_id: &str) -> Value {
    let m = app.db.user_machine(user_id);
    let (runs_on, reason, message) = match cp.route(&app.db, user_id) {
        Ok(route::Target::Local) => ("server", None, None),
        Ok(route::Target::Machine(_)) => ("machine", None, None),
        Err(r) => ("nowhere", Some(r.reason()), Some(r.message())),
    };
    json!({
        "userId": user_id,
        "userEmail": app.db.user(user_id).and_then(|u| u.email),
        "routing": cp.routing.as_str(),
        "assigned": m.as_ref().is_some_and(|m| m.assigned_at.is_some()),
        "runsOn": runs_on,
        "reason": reason,
        "message": message,
        "machine": m.map(|m| json!({
            "id": m.id, "state": m.state, "enrollment": m.enrollment, "assignedAt": m.assigned_at, "assignedBy": m.assigned_by,
            "agentSeenAt": m.agent_seen_at, "agentVersion": m.agent_version, "agentError": m.agent_error,
        })),
    })
}

/// Ends the machine's placement, if it had one, and says so in the audit log.
fn unplace(app: &App, by: &Who, m: &Machine, reason: &str) -> bool {
    if !app.db.unassign_machine(&m.id) {
        return false;
    }
    let forgot = app.db.forget_sessions_of(&m.user_id);
    app.db.record(&event(by, "placement.unassigned", m, json!({ "reason": reason, "sessionsReset": forgot })));
    true
}

/// `GET /api/machines/placements`: every live machine and where its user's Bots run.
pub async fn placements(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>) -> Res {
    a.machines.need()?;
    let live = app.db.machines(None).into_iter().filter(|m| m.state != State::Destroyed);
    let list: Vec<Value> = live.map(|m| placement_view(&app, &a.machines, &m.user_id)).collect();
    Ok(Json(json!({ "routing": a.machines.routing.as_str(), "placements": list })))
}

/// `GET /api/users/{key}/placement`: where the user's Bots run now, and why.
pub async fn placement(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Path(key): Path<String>,
) -> Res {
    a.machines.need()?;
    let u = need_user_key(&app, &key)?;
    Ok(Json(placement_view(&app, &a.machines, &u.id)))
}

/// `PUT /api/users/{key}/placement`: the user's Bots run on their machine from their
/// next run. The machine must be running and enrolled, so a slip can't strand them.
pub async fn assign(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let cp = &a.machines;
    cp.need()?;
    let u = need_user_key(&app, &key)?;
    let _g = cp.ops.lock().await;
    let m = app.db.user_machine(&u.id).ok_or_else(|| conflict("They don't have a machine. Request one first.".into()))?;
    if m.assigned_at.is_none() {
        if m.state != State::Running || m.enrollment != "enrolled" {
            return Err(conflict(format!(
                "Their machine is {} and its agent is {}: assign it once it's running and enrolled.",
                m.state.as_str(),
                if m.enrollment == "none" { "not enrolled" } else { m.enrollment.as_str() }
            )));
        }
        if app.db.assign_machine(&m.id, by.actor.id.as_deref()) {
            let forgot = app.db.forget_sessions_of(&u.id);
            app.db.record(&event(&by, "placement.assigned", &m, json!({ "routing": cp.routing.as_str(), "userEmail": u.email, "sessionsReset": forgot })));
            folder::assigned(&app, cp, &m, &by);
        }
    }
    Ok(Json(placement_view(&app, cp, &u.id)))
}

/// `DELETE /api/users/{key}/placement`: their Bots run where unassigned users' do.
pub async fn unassign(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let cp = &a.machines;
    cp.need()?;
    let u = need_user_key(&app, &key)?;
    let _g = cp.ops.lock().await;
    if let Some(m) = app.db.user_machine(&u.id) {
        unplace(&app, &by, &m, "admin");
    }
    Ok(Json(placement_view(&app, cp, &u.id)))
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

    #[test]
    fn routing_is_off_unless_asked_and_needs_the_control_plane() {
        let token = EnvStore::fixed(&[("LINODE_TOKEN", "routing-test-token-9e2a")]);
        let vars = |routing: &'static str| {
            move |k: &str| match k {
                "MACHINE_REGIONS" => "gb-lon".to_string(),
                "MACHINE_ROUTING" => routing.to_string(),
                _ => String::new(),
            }
        };
        use route::Routing;
        let off = ControlPlane::from_env(&token, vars("")).unwrap();
        assert!(off.routing == Routing::Off && off.describe().contains("routing off"), "{}", off.describe());
        let on = ControlPlane::from_env(&token, vars("on")).unwrap();
        assert!(on.routing == Routing::On && on.describe().contains("routing on via unenrolled"), "{}", on.describe());
        let assigned = ControlPlane::from_env(&token, vars("Assigned")).unwrap();
        assert!(assigned.routing == Routing::Assigned && assigned.describe().contains("routing assigned via"), "{}", assigned.describe());
        assert!(ControlPlane::from_env(&token, vars("sometimes")).is_err());
        for mode in ["on", "assigned"] {
            let err = ControlPlane::from_env(&EnvStore::fixed(&[]), vars(mode)).err().unwrap();
            assert!(err.contains("LINODE_TOKEN"), "routing without machines would strand every Bot: {err}");
        }
        assert!(ControlPlane::from_env(&EnvStore::fixed(&[]), vars("off")).unwrap().routing == Routing::Off);
    }

    #[test]
    fn the_firewall_is_off_unless_asked_and_needs_enrollment() {
        let token = EnvStore::fixed(&[("LINODE_TOKEN", "firewall-test-token-71c3")]);
        let vars = |fw: &'static str, url: &'static str| {
            move |k: &str| match k {
                "MACHINE_REGIONS" => "gb-lon".to_string(),
                "MACHINE_FIREWALL" => fw.to_string(),
                "MACHINE_CONTROL_URL" => url.to_string(),
                _ => String::new(),
            }
        };
        let off = ControlPlane::from_env(&token, vars("", "")).unwrap();
        assert!(off.firewall_settings.is_none() && off.firewall.is_none());
        let err = ControlPlane::from_env(&EnvStore::fixed(&[]), vars("on", "https://192.0.2.1:8443"))
            .err()
            .unwrap();
        assert!(err.contains("LINODE_TOKEN"), "{err}");
        let err = ControlPlane::from_env(&token, vars("on", "")).err().unwrap();
        assert!(err.contains("MACHINE_CONTROL_URL"), "it opens the agent's port: {err}");
        let mut cp = ControlPlane::from_env(&token, vars("on", "https://192.0.2.1:8443")).unwrap();
        assert!(cp.firewall.is_none(), "made with enrollment");
        cp.enroll_with(enroll::Enrollment::for_tests(3, 8443, 7443)).unwrap();
        let fw = cp.firewall.as_ref().unwrap();
        assert_eq!(fw.rules[0].sources, ["127.0.0.1/32"], "the control URL's address");
        assert!(cp.describe().contains("firewall"), "{}", cp.describe());
    }
}
