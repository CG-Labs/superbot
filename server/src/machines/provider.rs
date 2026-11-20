//! The seam between the control plane and whoever rents out the machines. Linode
//! today (ADR 0025); anything that can create, size, stop, start, back up, and delete
//! a VM by a unique label fits behind it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

pub type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

/// What to create. `label` is unique per provider account and is the idempotency key:
/// a second create with the same label fails with `LabelTaken`, never makes a twin.
#[derive(Clone, PartialEq)]
pub struct CreateSpec {
    pub label: String,
    pub plan: String,
    pub region: String,
    pub image: String,
    pub tags: Vec<String>,
    pub authorized_keys: Vec<String>,
    /// cloud-init user data for the first boot: the enrollment token and how to reach
    /// the control plane (ADR 0031). None when enrollment is off.
    pub user_data: Option<String>,
    /// The firewall the machine is behind from its first boot (ADR 0035).
    pub firewall_id: Option<String>,
}

/// The user data holds a live enrollment token, so it never reaches a log.
impl fmt::Debug for CreateSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CreateSpec")
            .field("label", &self.label)
            .field("plan", &self.plan)
            .field("region", &self.region)
            .field("image", &self.image)
            .field("tags", &self.tags)
            .field("authorized_keys", &self.authorized_keys.len())
            .field("user_data", &self.user_data.as_ref().map(|_| "[redacted]"))
            .field("firewall_id", &self.firewall_id)
            .finish()
    }
}

/// One inbound rule: accept TCP on `ports` from `sources` (canonical CIDRs, sorted).
/// The control plane's firewalls drop every other inbound packet and let machines
/// call out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallRule {
    pub label: String,
    pub ports: String,
    pub sources: Vec<String>,
}

/// A firewall as the provider sees it. `rules` is None when it isn't of the control
/// plane's shape (inbound drop, outbound accept, only TCP accept rules inbound), so
/// it will be set again.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderFirewall {
    pub id: String,
    pub label: String,
    pub rules: Option<Vec<FirewallRule>>,
    /// A disabled firewall filters nothing.
    pub enabled: bool,
}

/// What a firewall covers: our machines by id, and how many other devices
/// (NodeBalancers, interfaces) someone else put behind it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FirewallDevices {
    pub machines: Vec<String>,
    pub others: usize,
}

/// A machine as the provider sees it. `status` is the provider's own word for it
/// (`provisioning`, `running`, `offline`, ...); the control plane keeps its own state.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderMachine {
    pub id: String,
    pub label: String,
    pub status: String,
    pub plan: String,
    pub region: String,
    pub ipv4: Option<String>,
    pub backups: bool,
    pub tags: Vec<String>,
}

impl ProviderMachine {
    pub fn running(&self) -> bool {
        self.status == "running"
    }
}

/// Never carries the API token: messages come from the provider's error body or the
/// transport, and URLs hold no credentials.
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderError {
    NotFound,
    LabelTaken,
    RateLimited,
    Api { status: u16, message: String },
    Transport(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProviderError::NotFound => write!(f, "the machine was not found at the provider"),
            ProviderError::LabelTaken => write!(
                f,
                "a machine with this label exists at the provider already"
            ),
            ProviderError::RateLimited => {
                write!(f, "the provider is rate limiting us; try again shortly")
            }
            ProviderError::Api { status, message } => {
                write!(f, "the provider refused ({status}): {message}")
            }
            ProviderError::Transport(m) => write!(f, "couldn't reach the provider: {m}"),
        }
    }
}

pub trait MachineProvider: Send + Sync {
    /// Stored with each machine, e.g. `linode`.
    fn name(&self) -> &'static str;
    /// Creates and boots a machine.
    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine>;
    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine>;
    /// Every machine carrying `tag`.
    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>>;
    /// Moves the machine to another plan. The provider may power-cycle it.
    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()>;
    /// Powers off (suspend). The disk and IP are kept, and so is most of the bill.
    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    /// Deletes the machine and its disks. Succeeds if it is already gone.
    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;

    // Firewalls (ADR 0035). Labels are unique per account, as machines' are.

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>>;
    /// Makes a firewall covering no machines yet. `LabelTaken` if one has the label.
    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall>;
    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()>;
    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices>;
    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()>;
    /// Succeeds if the machine isn't behind it, or either is gone.
    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()>;
    /// Succeeds if it is already gone.
    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
}
