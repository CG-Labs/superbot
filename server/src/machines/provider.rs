//! The seam between the control plane and whoever rents out the machines: Linode VMs
//! (ADR 0025) or system containers on an Incus host (ADR 0065). Anything that can
//! create, size, stop, start, back up, and delete a machine by a unique label fits
//! behind it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

pub type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;
/// A backup's bytes on their way to or from the provider (ADR 0071).
pub type ByteStream = Pin<Box<dyn futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>>;

/// A file put on a restored machine's disk before it first starts.
#[derive(Clone, PartialEq)]
pub struct RestoreFile {
    pub path: String,
    pub mode: u32,
    pub content: String,
}

/// What a machine restored from a backup becomes (ADR 0071): today's size, tags,
/// keys and firewall rather than the backup's, the files that make it enroll again,
/// and the files that must go (its old identity).
#[derive(Clone, PartialEq)]
pub struct RestoreSpec {
    pub plan: String,
    pub tags: Vec<String>,
    pub authorized_keys: Vec<String>,
    pub firewall_id: Option<String>,
    pub files: Vec<RestoreFile>,
    pub remove: Vec<String>,
}

/// The files hold a live enrollment token, so they never reach a log.
impl fmt::Debug for RestoreSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RestoreSpec")
            .field("plan", &self.plan)
            .field("tags", &self.tags)
            .field("authorized_keys", &self.authorized_keys.len())
            .field("firewall_id", &self.firewall_id)
            .field("files", &self.files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>())
            .field("remove", &self.remove)
            .finish()
    }
}

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
    /// The subnet of its team's own network it joins from its first boot (ADR 0189).
    pub subnet_id: Option<String>,
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
            .field("subnet_id", &self.subnet_id)
            .finish()
    }
}

/// A team's own network at the provider (ADR 0189): a Linode VPC, and the subnet its
/// machines join; or an Incus OVN network, whose id and subnet id are its name (ADR 0212).
#[derive(Clone, Debug, PartialEq)]
pub struct TeamNetwork {
    pub id: String,
    pub label: String,
    pub region: String,
    pub subnet_id: String,
    /// The subnet's range, canonical. In a listing, empty if the VPC has lost its subnet.
    pub subnet: String,
    /// Made by this call, not found.
    pub created: bool,
}

/// One interface on a team network: the machine, and the interface's own ids, which
/// taking it off needs (on Incus, no configuration profile and the NIC's device name).
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkMember {
    pub machine: String,
    pub config: String,
    pub interface: String,
    /// The machine booted with it. An interface added to a running machine is inactive
    /// until its next boot (ADR 0202), and can be taken off while inactive.
    pub active: bool,
    /// It can be taken off only while its machine is powered off, active or not: a
    /// Linode interface (ADR 0226).
    pub needs_power_off: bool,
}

/// What to put on a machine that is wiped and reinstalled in place (ADR 0056): same
/// id, IP and firewall, fresh disks booted from `image` with `user_data`.
#[derive(Clone, PartialEq)]
pub struct RebuildSpec {
    pub image: String,
    pub authorized_keys: Vec<String>,
    pub user_data: String,
}

impl fmt::Debug for RebuildSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RebuildSpec")
            .field("image", &self.image)
            .field("authorized_keys", &self.authorized_keys.len())
            .field("user_data", &"[redacted]")
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
    /// When the provider's own backups of it last succeeded, if the provider says
    /// (`reports_backups`, ADR 0110).
    pub last_backup_at: Option<i64>,
    pub tags: Vec<String>,
    /// Its cloud-init user data (with the enrollment token) is still in its config at
    /// the provider, and `clear_user_data` removes it (ADR 0067). False where the
    /// provider can't: Linode keeps it in its metadata service (ADR 0035).
    pub user_data: bool,
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

fn unsupported() -> ProviderError {
    ProviderError::Api { status: 501, message: "this provider can't export or import machines".into() }
}

fn no_networks() -> ProviderError {
    ProviderError::Api { status: 501, message: "this provider has no team networks".into() }
}

pub trait MachineProvider: Send + Sync {
    /// Stored with each machine, e.g. `linode`.
    fn name(&self) -> &'static str;
    /// What a machine is: `vm` (its own kernel) or `container` (shares the host's).
    /// No default: a provider says which, so none is taken for a VM by omission
    /// (MACHINE_OWN_KERNEL_TIERS, ADR 0120).
    fn substrate(&self) -> &'static str;
    /// MACHINE_TIERS when it isn't set.
    fn default_tiers(&self) -> &'static str {
        super::DEFAULT_TIERS
    }
    /// MACHINE_IMAGE when it isn't set.
    fn default_image(&self) -> &'static str {
        super::DEFAULT_IMAGE
    }
    /// Whether `plan` means something to this provider, checked at startup.
    fn check_plan(&self, _plan: &str) -> Result<(), String> {
        Ok(())
    }
    /// What `plan` gives a machine, for admins, if the provider knows.
    fn plan_view(&self, _plan: &str) -> Option<serde_json::Value> {
        None
    }
    /// What `plan` takes from its host, where machines share hosts (ADR 0081).
    fn plan_resources(&self, _plan: &str) -> Option<Resources> {
        None
    }
    /// How big `plan`'s disk is, in bytes, if the provider can say (ADR 0085): what a
    /// machine resized to it must fit in.
    fn plan_disk<'a>(&'a self, plan: &'a str) -> Fut<'a, Option<u64>> {
        let bytes = self.plan_resources(plan).map(|r| r.disk_gib.saturating_mul(1 << 30));
        Box::pin(async move { Ok(bytes) })
    }
    /// The provider's own settings for admins. Never a credential.
    fn settings(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// The outbound rules the provider puts on the machines' firewall beside the
    /// inbound ones (ADR 0179), for audit events and admins. None: the provider keeps
    /// them elsewhere, or has none.
    fn firewall_egress(&self) -> Option<serde_json::Value> {
        None
    }
    /// Asks the provider whether it is set up as the control plane needs: a list of
    /// `{check, ok, detail}`.
    fn preflight<'a>(&'a self) -> Fut<'a, Vec<serde_json::Value>> {
        Box::pin(async { Ok(Vec::new()) })
    }
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
    /// Whether `enable_backups` turns on backups kept off the machine's disk that the
    /// provider restores, and `get` says when the last one succeeded (`last_backup_at`),
    /// so machines can be held to an RPO by them (ADR 0110). Not Incus's snapshots, which
    /// stay on the host.
    fn reports_backups(&self) -> bool {
        false
    }
    /// Deletes the machine and its disks. Succeeds if it is already gone.
    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    /// Wipes the machine's disks and reinstalls it from `spec`, then boots it. It keeps
    /// its id, IP and firewall. Everything on its disks is lost.
    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()>;
    /// Removes the machine's cloud-init user data from its config without restarting
    /// it, once it is spent (ADR 0067). Succeeds if there is none, or the machine is
    /// gone. Nothing to do where `ProviderMachine::user_data` is never set.
    fn clear_user_data<'a>(&'a self, _id: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    // Off-host backups (ADR 0071): a machine's whole disk exported as one file, and a
    // machine made again from one. Providers that can't say so.

    /// Whether this provider can export and import machines.
    fn exports(&self) -> bool {
        false
    }
    /// Makes a backup of the machine called `name` at the provider, without its
    /// snapshots, and waits for it.
    fn create_backup<'a>(&'a self, _id: &'a str, _name: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Err(unsupported()) })
    }
    /// The backup's bytes.
    fn export_backup<'a>(&'a self, _id: &'a str, _name: &'a str) -> Fut<'a, ByteStream> {
        Box::pin(async { Err(unsupported()) })
    }
    /// Succeeds if it is already gone.
    fn delete_backup<'a>(&'a self, _id: &'a str, _name: &'a str) -> Fut<'a, ()> {
        Box::pin(async { Err(unsupported()) })
    }
    /// Makes a stopped machine called `name` from a backup's bytes.
    fn import_backup<'a>(&'a self, _name: &'a str, _data: ByteStream) -> Fut<'a, ()> {
        Box::pin(async { Err(unsupported()) })
    }
    /// Puts the imported machine `staging` in place of machine `id`: set up as `spec`
    /// says while stopped, then the old one deleted and the new one given its name. It
    /// stays stopped until `boot`. Everything on the old one's disks is lost.
    fn replace_with<'a>(&'a self, _id: &'a str, _staging: &'a str, _spec: &'a RestoreSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async { Err(unsupported()) })
    }

    // Team networks (ADR 0189): a network of its own per team and region, which only
    // the team's machines join. Providers without them refuse.

    /// The network called `label` in `region`, made with one subnet, `subnet`, if it
    /// isn't there. One that is there must be in `region` and have that subnet.
    fn ensure_team_network<'a>(&'a self, _label: &'a str, _region: &'a str, _subnet: &'a str) -> Fut<'a, TeamNetwork> {
        Box::pin(async { Err(no_networks()) })
    }
    /// Every network whose label starts with `prefix`.
    fn team_networks<'a>(&'a self, _prefix: &'a str) -> Fut<'a, Vec<TeamNetwork>> {
        Box::pin(async { Err(no_networks()) })
    }
    /// Every interface on network `id`, on any of its subnets, whoever's machine it is.
    fn team_network_members<'a>(&'a self, _id: &'a str) -> Fut<'a, Vec<NetworkMember>> {
        Box::pin(async { Err(no_networks()) })
    }
    /// Takes the interface off its machine, which must be powered off unless the
    /// interface is inactive. Succeeds if it is gone already.
    fn leave_team_network<'a>(&'a self, _member: &'a NetworkMember) -> Fut<'a, ()> {
        Box::pin(async { Err(no_networks()) })
    }
    /// Puts existing machine `machine` on network `network`'s subnet from its next boot
    /// (ADR 0202), behind the same firewall, its public interface still the primary.
    /// Succeeds if it is on that subnet already, or will be at its next boot.
    fn join_team_network<'a>(&'a self, _machine: &'a str, _network: &'a TeamNetwork) -> Fut<'a, ()> {
        Box::pin(async { Err(no_networks()) })
    }
    /// Whether `machine` takes a team network's interface only while it is powered off,
    /// as a Linode with Linode interfaces does (ADR 0226): `join_team_network` is then
    /// called only once the provider says it is off.
    fn team_network_needs_power_off<'a>(&'a self, _machine: &'a str) -> Fut<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    /// Whether an interface on a team network goes into and comes out of a running
    /// machine at once (ADR 0212): joined members are always active, and leaving needs
    /// no power-off.
    fn team_network_hotplug(&self) -> bool {
        false
    }
    /// Whether the machine can take a team network's interface only once rebuilt, as a
    /// container made before ADR 0212 can't bring one up.
    fn team_nic_needs_rebuild<'a>(&'a self, _id: &'a str) -> Fut<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    // Firewalls (ADR 0035). Labels are unique per account, as machines' are.

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>>;
    fn get_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderFirewall>;
    /// Makes a firewall covering no machines yet. `LabelTaken` if one has the label.
    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall>;
    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()>;
    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;
    /// What firewall `id` covers. A machine is in `machines` only if the firewall covers
    /// all of it: on a Linode with Linode interfaces, every public and VPC interface.
    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices>;
    /// Whether firewall `id` covers all of `machine`, as `firewall_devices` would say,
    /// for one machine without reading every device.
    fn firewall_covers<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, bool> {
        Box::pin(async move { Ok(self.firewall_devices(id).await?.machines.iter().any(|m| m == machine)) })
    }
    /// Puts `machine` behind firewall `id`: on a Linode with Linode interfaces, each of
    /// its public and VPC interfaces that isn't yet.
    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()>;
    /// Succeeds if the machine isn't behind it, or either is gone.
    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()>;
    /// Succeeds if it is already gone.
    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()>;

    /// The hosts machines are spread over, where the provider has several to choose
    /// from (ADR 0076). None: one place, nothing to choose.
    fn hosts(&self) -> Option<&dyn Hosts> {
        None
    }
}

/// How the control plane last found a host (ADR 0076). `Down`: it hasn't answered for
/// INCUS_HOST_DOWN_MINUTES, and nothing new goes there. `Lost`: an admin said it is
/// gone for good, so its machines are made again elsewhere and it is never called.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
    Lost,
}

impl HostStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HostStatus::Up => "up",
            HostStatus::Down => "down",
            HostStatus::Lost => "lost",
        }
    }

    pub fn parse(s: &str) -> Option<HostStatus> {
        match s {
            "up" => Some(HostStatus::Up),
            "down" => Some(HostStatus::Down),
            "lost" => Some(HostStatus::Lost),
            _ => None,
        }
    }
}

/// CPUs, memory and disk: what a plan gives a machine, or what a host has to give
/// (ADR 0081).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Resources {
    pub cpus: u64,
    #[serde(rename = "memoryGiB")]
    pub memory_gib: u64,
    #[serde(rename = "diskGiB")]
    pub disk_gib: u64,
}

impl Resources {
    pub fn plus(self, o: Resources) -> Resources {
        Resources { cpus: self.cpus + o.cpus, memory_gib: self.memory_gib + o.memory_gib, disk_gib: self.disk_gib + o.disk_gib }
    }
}

/// What a host says it has and uses now (ADR 0106), as against what botd allocated on
/// it. Each part is absent when the host didn't say.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostUse {
    /// CPU threads.
    pub cpus: Option<u64>,
    /// Load averages over 1 and 5 minutes.
    pub load: Option<(f64, f64)>,
    /// Memory used and in all, in bytes.
    pub memory: Option<(u64, u64)>,
    pub disks: Vec<DiskUse>,
}

/// One disk's space used and in all, in bytes. `name` is one of a fixed few: `pool`
/// (an Incus storage pool), `data` (DATA_DIR) or `workspace` (WORKSPACE_DIR).
#[derive(Clone, Debug, PartialEq)]
pub struct DiskUse {
    pub name: &'static str,
    pub used: u64,
    pub total: u64,
}

/// How new machines are spread over hosts that have room (ADR 0081). `Spread`: the
/// least loaded host. `Fill`: the first host in the order configured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    #[default]
    Spread,
    Fill,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "spread" => Some(Policy::Spread),
            "fill" => Some(Policy::Fill),
            _ => None,
        }
    }
}

/// A configured host. Never a credential.
#[derive(Clone, Debug, PartialEq)]
pub struct HostInfo {
    pub name: String,
    pub url: String,
    /// The SHA-256 of the certificate botd pins for it.
    pub fingerprint: String,
    pub status: HostStatus,
    /// What its machines may be given in all, if set (INCUS_CAPACITY).
    pub capacity: Option<Resources>,
    /// How many machines it may have, if set (INCUS_MAX_MACHINES).
    pub max_machines: Option<u64>,
    /// The data region it is in (INCUS_REGION, ADR 0117), if hosts are tagged.
    pub region: Option<String>,
}

/// Several hosts behind one provider: machine ids say which one each is on.
pub trait Hosts: Send + Sync {
    /// Every configured host, in placement order.
    fn configured(&self) -> Vec<HostInfo>;
    /// Whether hosts are tagged with data regions (ADR 0117): every host or none is.
    fn tagged(&self) -> bool {
        self.configured().iter().any(|h| h.region.is_some())
    }
    /// The host a machine id is on.
    fn host_of(&self, id: &str) -> String;
    /// The id of the machine called `name` on `host`.
    fn id_on(&self, host: &str, name: &str) -> String;
    /// What the control plane decided about `host`, which needn't be configured: a lost
    /// host taken out of the settings is still lost.
    fn set_status(&self, host: &str, status: HostStatus);
    fn status(&self, host: &str) -> Option<HostStatus>;
    /// The first configured host that is up. Placement by load (`placement::choose`)
    /// picks the host the control plane makes a machine on; this is the fallback.
    fn placement(&self) -> Option<String>;
    /// How new machines are spread over hosts with room (INCUS_PLACEMENT).
    fn policy(&self) -> Policy {
        Policy::Spread
    }
    /// Creates and boots a machine on `host`, which must be up.
    fn create_on<'a>(&'a self, host: &'a str, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine>;
    /// `host` alone, so work for one machine there (its firewall) needn't wait on others.
    fn on(&self, host: &str) -> Option<&dyn MachineProvider>;
    /// How long a host may fail to answer before it is down.
    fn down_after_ms(&self) -> i64;
    /// Asks `host` whether it answers and trusts botd: what it said.
    fn probe<'a>(&'a self, host: &'a str) -> Fut<'a, String>;
    /// Asks `host` what it has and uses now (ADR 0106).
    fn host_use<'a>(&'a self, host: &'a str) -> Fut<'a, HostUse>;
}
