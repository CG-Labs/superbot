//! A network of its own per team (ADR 0189), on Linode: a VPC per team and region,
//! made when the team's first machine there is, with one subnet its machines join from
//! their first boot. VPCs don't route to each other, so only the team's machines (and
//! whatever the operator puts on the VPC for the team) are on it. The machines'
//! firewall still drops every inbound packet but botd's and SSH's on the VPC interface
//! too, so teammates' machines can't reach each other there; what they reach is the
//! team's own services. Their outbound rules, at the firewall and inside the machine,
//! let the subnet through before the deny list.
//!
//! A machine whose owner is no longer on the network's team is taken off it: powered
//! off, its interface removed, and powered on again if this is what powered it off.
//!
//! A machine made before its owner's team had a network, or before they joined the team,
//! joins it without a rebuild (ADR 0202): its agent lets the subnet through in its
//! egress rules first, then the machine is given an interface on the subnet, in use
//! from its next boot. With MACHINE_TEAM_NETWORK_JOIN=when-idle, botd powers it off and
//! on again once it runs nothing; with `next-boot`, the default, it waits for one.
//!
//! A Linode with Linode interfaces (ADR 0226) is given one only while it is off: with
//! `next-boot` the next time it is suspended, with `when-idle` botd powers it off once it
//! runs nothing, gives it the interface, and powers it on again.
//!
//! On Incus (ADR 0212) a team network is an isolated OVN network per team and region on
//! each host, which a team member's container joins through a second NIC behind an ACL
//! of the network's own: inbound dropped, outbound only to the subnet. Incus plugs and
//! unplugs NICs in running containers, so joining and leaving need no power-off.
//!
//! The network of a team this server deleted is removed once nothing is on it (ADR
//! 0236): its machines have left it as any leaver's do, and nothing else, ours or
//! anyone's, is on it. A team is known to be one this server deleted by its own
//! `team.deleted` events, so another control plane's networks on the same account are
//! never touched. On Incus its ACL and its name on the project's access list go too.

use super::enroll::Enrollment;
use super::provider::{MachineProvider, NetworkMember, ProviderError, TeamNetwork};
use super::wire::{self, Heartbeat, TeamNetworkReport, TeamNetworkRules};
use super::{ControlPlane, State, Step, event, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::AppState;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const DEFAULT_SUBNET: &str = "10.248.0.0/22";
/// Where Linode lets a VPC subnet be: RFC 1918, but for 192.168.128.0/17, which its
/// private network uses.
const ALLOWED_VPC: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/17"];
/// Where an OVN network's subnet may be: RFC 1918.
const ALLOWED_OVN: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
/// The longest subnet prefix: Linode's, and room on OVN for its router and a few machines.
const LONGEST: u32 = 29;
/// A VPC label's longest, and an Incus network's.
const MAX_LABEL: usize = 64;

/// What a team network is at the provider (MACHINE_TEAM_NETWORK).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A Linode VPC per team and region (ADR 0189).
    Vpc,
    /// An isolated OVN network per team and region on each Incus host (ADR 0212).
    Ovn,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Vpc => "vpc",
            Kind::Ovn => "ovn",
        }
    }

    fn allowed(self) -> (&'static [&'static str], &'static str) {
        match self {
            Kind::Vpc => (&ALLOWED_VPC, "where Linode's VPC subnets go"),
            Kind::Ovn => (&ALLOWED_OVN, "RFC 1918's private ranges"),
        }
    }
}

/// How a machine already made joins its team's network (MACHINE_TEAM_NETWORK_JOIN,
/// ADR 0202).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    /// It doesn't: only a rebuild or a new machine puts it on, as before ADR 0202.
    Off,
    /// It is given the interface, in use from its next boot.
    NextBoot,
    /// And botd powers it off and on again once it runs nothing.
    WhenIdle,
}

impl Join {
    pub fn as_str(self) -> &'static str {
        match self {
            Join::Off => "off",
            Join::NextBoot => "next-boot",
            Join::WhenIdle => "when-idle",
        }
    }

    fn parse(v: &str) -> Result<Join, String> {
        match v.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "next-boot" => Ok(Join::NextBoot),
            "off" => Ok(Join::Off),
            "when-idle" => Ok(Join::WhenIdle),
            v => Err(format!("MACHINE_TEAM_NETWORK_JOIN must be off, next-boot or when-idle, not \"{}\"", crate::audit::clip(v, 20))),
        }
    }
}

/// What becomes of the network of a team this server deleted
/// (MACHINE_TEAM_NETWORK_REMOVE, ADR 0236).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Remove {
    /// It stays until an admin removes it, as before ADR 0236.
    Off,
    /// It is removed once nothing is on it: no machine of ours, and nothing else.
    #[default]
    WhenEmpty,
}

impl Remove {
    pub fn as_str(self) -> &'static str {
        match self {
            Remove::Off => "off",
            Remove::WhenEmpty => "when-empty",
        }
    }

    fn parse(v: &str) -> Result<Remove, String> {
        match v.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "when-empty" => Ok(Remove::WhenEmpty),
            "off" => Ok(Remove::Off),
            v => Err(format!("MACHINE_TEAM_NETWORK_REMOVE must be off or when-empty, not \"{}\"", crate::audit::clip(v, 20))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub kind: Kind,
    /// The range of every team network's subnet, canonical. Every team's is the same:
    /// team networks never route to each other, so the same range on two never meets.
    pub subnet: String,
    pub join: Join,
    pub remove: Remove,
}

/// Whether `subnet` meets one of the comma-separated CIDRs in `deny`: the one it meets.
pub fn meets(subnet: &str, deny: &str) -> Option<String> {
    let (_, lo, hi) = super::incus::span(subnet)?;
    deny.split(',').map(str::trim).filter(|s| !s.is_empty()).find_map(|c| {
        let (v6, a, b) = super::firewall::cidr(c).ok().and_then(|c| super::incus::span(&c))?;
        (!v6 && a <= hi && lo <= b).then(|| c.to_string())
    })
}

impl Settings {
    /// MACHINE_TEAM_NETWORK (`off`, the default, `vpc` or `ovn`),
    /// MACHINE_TEAM_NETWORK_SUBNET and MACHINE_TEAM_NETWORK_JOIN. Whether the provider
    /// and the firewall allow it is the control plane's to check.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let raw = var("MACHINE_TEAM_NETWORK_SUBNET");
        let kind = match var("MACHINE_TEAM_NETWORK").trim().to_ascii_lowercase().as_str() {
            "" | "off" => {
                if !raw.trim().is_empty() {
                    return Err("MACHINE_TEAM_NETWORK_SUBNET needs MACHINE_TEAM_NETWORK=vpc or ovn".into());
                }
                for k in ["MACHINE_TEAM_NETWORK_JOIN", "MACHINE_TEAM_NETWORK_REMOVE"] {
                    if !var(k).trim().is_empty() {
                        return Err(format!("{k} needs MACHINE_TEAM_NETWORK=vpc or ovn"));
                    }
                }
                return Ok(None);
            }
            "vpc" => Kind::Vpc,
            "ovn" => Kind::Ovn,
            v => return Err(format!("MACHINE_TEAM_NETWORK must be off, vpc or ovn, not \"{}\"", crate::audit::clip(v, 20))),
        };
        let subnet = match raw.trim() {
            "" => DEFAULT_SUBNET.to_string(),
            r => super::firewall::cidr(r).map_err(|e| format!("MACHINE_TEAM_NETWORK_SUBNET: {e}"))?,
        };
        let span = super::incus::span(&subnet).filter(|(v6, _, _)| !v6).ok_or("MACHINE_TEAM_NETWORK_SUBNET must be an IPv4 range")?;
        let (allowed, where_) = kind.allowed();
        if !allowed.iter().filter_map(|a| super::incus::span(a)).any(|(_, lo, hi)| lo <= span.1 && span.2 <= hi) {
            return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} isn't inside {}, {where_}", allowed.join(", ")));
        }
        if subnet.rsplit('/').next().and_then(|l| l.parse::<u32>().ok()).is_none_or(|l| l > LONGEST) {
            return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} is smaller than the smallest team subnet, a /{LONGEST}"));
        }
        // An operator's own deny list wins: the team network would let it through.
        if let Some(c) = meets(&subnet, &var("MACHINE_EGRESS_DENY")) {
            return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} meets MACHINE_EGRESS_DENY's {c}; pick a range the deny list doesn't name"));
        }
        let join = Join::parse(&var("MACHINE_TEAM_NETWORK_JOIN"))?;
        let remove = Remove::parse(&var("MACHINE_TEAM_NETWORK_REMOVE"))?;
        Ok(Some(Settings { kind, subnet, join, remove }))
    }

    pub fn view(&self) -> Value {
        json!({ "kind": self.kind.as_str(), "subnet": self.subnet, "join": self.join.as_str(), "remove": self.remove.as_str() })
    }
}

/// The team's part of a network's label: its id's digest, so the label says which team
/// without naming it.
fn team_part(team_id: &str) -> String {
    Sha256::digest(team_id.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// The team part of a network label of ours, whatever MACHINE_LABEL_PREFIX was when it
/// was made: a machine keeps its network after the prefix changes.
fn team_part_of(label: &str) -> Option<&str> {
    let (i, _) = label.rmatch_indices("-team-").next()?;
    let rest = &label[i + "-team-".len()..];
    let (t, region) = rest.split_once('-')?;
    (t.len() == 12 && t.bytes().all(|b| b.is_ascii_hexdigit()) && !region.is_empty()).then_some(t)
}

/// The label of `team_id`'s network in `region`, or None if Linode wouldn't take it.
pub fn label(label_prefix: &str, team_id: &str, region: &str) -> Option<String> {
    let l = format!("{label_prefix}-team-{}-{region}", team_part(team_id));
    (l.len() <= MAX_LABEL && !l.contains("--") && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(l)
}

/// The subnet `m` is on, or would be: its owner's team's, with team networks on.
pub fn subnet_for<'a>(app: &App, cp: &'a ControlPlane, m: &Machine) -> Option<&'a str> {
    let s = cp.team_network.as_ref()?;
    app.db.team_id_of(&m.user_id).map(|_| s.subnet.as_str())
}

/// The network `m` joins at create: its owner's team's in its region, made if this is
/// the team's first machine there. None with team networks off or no team.
pub async fn ensure(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, m: &Machine, by: &Who) -> Result<Option<TeamNetwork>, ProviderError> {
    let Some(s) = &cp.team_network else { return Ok(None) };
    let Some(team) = app.db.team_id_of(&m.user_id) else { return Ok(None) };
    // One made under an earlier MACHINE_LABEL_PREFIX is still the team's, with whatever
    // the operator put on it: never a second one beside it.
    let part = team_part(&team);
    let earlier = p.team_networks("").await?.into_iter().find(|n| n.region == m.region && team_part_of(&n.label) == Some(part.as_str()));
    let label = match earlier {
        Some(n) => n.label,
        None => label(&cp.label_prefix, &team, &m.region).ok_or_else(|| ProviderError::Api {
            status: 400,
            message: format!("a team network's label in {} would be longer than Linode takes; shorten MACHINE_LABEL_PREFIX", m.region),
        })?,
    };
    let n = p.ensure_team_network(&label, &m.region, &s.subnet).await?;
    if n.created {
        app.db.record(&by.event("machine.team_network_created").target("team_network", &n.id).details(json!({
            "team": team, "label": n.label, "region": n.region, "subnet": n.subnet, "subnetId": n.subnet_id, "forMachine": m.id,
        })));
    }
    Ok(Some(n))
}

/// One pass: every machine of ours on a team network whose team its owner isn't on is
/// taken off it. Anything else on a network, the team's own services, is left alone.
/// Machines this powered off are powered on again once nothing has them to leave.
/// A deleted team's network with none of our machines left on it is removed if nothing
/// else is on it either (ADR 0236). Then, unless MACHINE_TEAM_NETWORK_JOIN=off, a team
/// member's machine on no network joins its team's (ADR 0202).
pub async fn sweep(app: &AppState, cp: &ControlPlane) -> Value {
    let (Some(s), Some(p)) = (&cp.team_network, cp.provider.as_deref()) else { return json!({}) };
    let nets: Vec<(String, TeamNetwork)> = match p.team_networks("").await {
        Ok(n) => n.into_iter().filter_map(|n| Some((team_part_of(&n.label)?.to_string(), n))).collect(),
        Err(e) => return json!({ "error": e.to_string() }),
    };
    let teams: HashMap<String, String> = app.db.teams().into_iter().map(|t| (team_part(&t.id), t.id)).collect();
    let ours: HashMap<String, Machine> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| m.state != State::Destroyed && cp.owns(m))
        .filter_map(|m| Some((m.provider_id.clone()?, m)))
        .collect();
    let (mut leaving, mut left, mut resumed, mut errors) = (0, 0, 0, 0);
    let (mut joining, mut joined, mut pending, mut restarting, mut waiting, mut awaiting_power_off) = (0, 0, 0, 0, 0, 0);
    let mut unseen = false;
    let mut still_on: HashSet<String> = HashSet::new();
    // Machines with an interface on some network, in use or not: none joins another.
    let mut on_one: HashSet<String> = HashSet::new();
    // Running on their team's network's subnet without using it yet: a boot away.
    let mut to_boot: Vec<(TeamNetwork, String, Machine)> = Vec::new();
    // Networks not read, or with a machine of ours still on them: none is removed yet.
    let mut busy: HashSet<String> = HashSet::new();
    for (part, n) in &nets {
        let team = teams.get(part).cloned();
        let members = match p.team_network_members(&n.id).await {
            Ok(m) => m,
            Err(_) => {
                errors += 1;
                unseen = true;
                busy.insert(n.id.clone());
                continue;
            }
        };
        for mem in &members {
            let Some(m) = ours.get(&mem.machine) else { continue };
            on_one.insert(m.id.clone());
            if let Some(t) = team.as_deref().filter(|t| app.db.team_id_of(&m.user_id).as_deref() == Some(*t)) {
                if mem.active {
                    if joined_now(app, cp, n, t, m) {
                        joined += 1;
                    }
                } else {
                    // Also after a restart of botd, which remembers joins only in memory.
                    joining_set(cp).insert(m.id.clone());
                    if m.state == State::Running {
                        pending += 1;
                        to_boot.push((n.clone(), t.to_string(), m.clone()));
                    }
                }
                continue;
            }
            match leave(app, cp, p, n, team.as_deref(), m, mem).await {
                Leave::Left => {
                    left += 1;
                    continue;
                }
                Leave::Leaving => leaving += 1,
                Leave::Waiting => {}
                Leave::Failed => errors += 1,
            }
            still_on.insert(m.id.clone());
            busy.insert(n.id.clone());
        }
    }
    let (mut removed, mut kept) = (0, 0);
    if s.remove == Remove::WhenEmpty {
        let gone: HashMap<String, (String, i64)> = app.db.deleted_teams().into_iter().map(|(id, at)| (team_part(&id), (id, at))).collect();
        for (part, n) in &nets {
            let Some((team, at)) = gone.get(part).filter(|_| !teams.contains_key(part) && !busy.contains(&n.id)) else { continue };
            match remove(app, cp, p, n, team, *at).await {
                Removal::Removed => removed += 1,
                Removal::Kept => kept += 1,
                Removal::Failed => errors += 1,
                Removal::Nothing => {}
            }
        }
    }
    let mut outcomes: HashMap<String, Joined> = HashMap::new();
    // A network not looked at may still have a machine to take off: never power one on
    // until every network has been. Nor join one to a network: it may be on another.
    if !unseen {
        // One powered off to join is powered on below, once it has its interface or can't.
        let held: HashSet<String> = join_off(cp).keys().cloned().collect();
        let off: Vec<String> = suspended(cp).iter().filter(|id| !still_on.contains(*id) && !held.contains(*id)).cloned().collect();
        for id in off {
            match resume(app, cp, &id).await {
                Some(true) => resumed += 1,
                Some(false) => errors += 1,
                None => {}
            }
        }
        if s.join != Join::Off {
            let off_all: Vec<&Machine> = ours.values().filter(|m| !on_one.contains(&m.id)).collect();
            for m in off_all {
                let j = join(app, cp, p, s, m).await;
                match j {
                    Joined::Joining => joining += 1,
                    Joined::Waiting | Joined::GoingOff => waiting += 1,
                    Joined::AwaitingPowerOff => awaiting_power_off += 1,
                    Joined::Restarting => restarting += 1,
                    Joined::Failed => errors += 1,
                    Joined::Nothing => {}
                }
                outcomes.insert(m.id.clone(), j);
            }
        }
        if s.join == Join::WhenIdle {
            for (n, team, m) in &to_boot {
                let d = json!({ "team": team, "networkId": n.id, "label": n.label, "subnet": n.subnet });
                match restart(app, cp, p, team, m, d, false).await {
                    Restart::Restarting => restarting += 1,
                    Restart::Waiting => {}
                    Restart::Failed => errors += 1,
                }
            }
        }
    }
    // Powered off to join: on again once given the interface, refused it, or no longer
    // due one. Just powered off, or still on its way off at the provider, it waits, but
    // not for ever, even while some network can't be read: it was on none when botd
    // powered it off. Once timed out, it waits for its owner to power it off instead.
    let at = now();
    let held: Vec<(String, i64)> = join_off(cp).iter().map(|(id, when)| (id.clone(), *when)).collect();
    for (id, since) in held {
        let not_yet = unseen || matches!(outcomes.get(&id), Some(Joined::GoingOff | Joined::Restarting));
        let timed_out = at - since >= JOIN_OFF_MS;
        if not_yet && !timed_out {
            continue;
        }
        join_off(cp).remove(&id);
        if not_yet {
            gave_up(app, cp, &id, s);
        }
        match resume(app, cp, &id).await {
            Some(true) => resumed += 1,
            Some(false) => errors += 1,
            None => {}
        }
    }
    let mut out = json!({});
    for (k, v) in [
        ("leaving", leaving),
        ("left", left),
        ("resumed", resumed),
        ("joining", joining),
        ("pending", pending),
        ("awaitingPowerOff", awaiting_power_off),
        ("restarting", restarting),
        ("joined", joined),
        ("waiting", waiting),
        ("removed", removed),
        ("kept", kept),
        ("errors", errors),
    ] {
        if v > 0 {
            out[k] = v.into();
        }
    }
    out
}

/// Records that `m`, which botd put on `n`, now uses it. Whether it did.
fn joined_now(app: &App, cp: &ControlPlane, n: &TeamNetwork, team: &str, m: &Machine) -> bool {
    if !joining_set(cp).remove(&m.id) {
        return false;
    }
    let d = json!({ "team": team, "networkId": n.id, "label": n.label, "subnet": n.subnet });
    app.db.record(&event(&system(m), "machine.team_network_joined", m, d));
    true
}

#[derive(Debug, PartialEq)]
enum Joined {
    Joining,
    Waiting,
    /// Suspended to be given its interface while off, and not off at the provider yet.
    GoingOff,
    /// Running, and given its interface only while off (ADR 0226): with `next-boot`,
    /// the next time it is suspended; with `when-idle`, once it runs nothing.
    AwaitingPowerOff,
    /// Powered off by botd to be given its interface.
    Restarting,
    Failed,
    Nothing,
}

/// How long a machine powered off to join may take to be off at the provider before
/// it is powered on again without its interface.
const JOIN_OFF_MS: i64 = 10 * 60_000;

/// Why `m` can't be put on `subnet` yet, if it can't: its egress rules must let the
/// subnet through first, or there must be none. botd knows what they let through from
/// its agent's heartbeats, the last of which still holds for a machine powered off.
pub fn rules_waiting(m: &Machine, subnet: &str) -> Option<&'static str> {
    let r = m.agent_upkeep.as_ref().map(|u| &u["teamNetwork"]).filter(|r| !r.is_null());
    let Some(r) = r else {
        return Some("its agent hasn't said what its egress rules let through; upgrade it");
    };
    match r["state"].as_str() {
        Some(wire::TEAM_RULES_NONE) => None,
        Some(wire::TEAM_RULES_ON) if r["subnet"] == subnet => None,
        Some(wire::TEAM_RULES_FAILED) => Some("its egress rules didn't take the subnet"),
        _ => Some("its egress rules don't let the subnet through yet"),
    }
}

/// Puts `m` on its owner's team's network from its next boot, if it should be on one;
/// at once where the provider plugs interfaces into running machines (Incus); and only
/// while it is off where the provider adds them only then (Linode interfaces).
async fn join(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, s: &Settings, m: &Machine) -> Joined {
    let active = |x: &Machine| matches!(x.state, State::Running | State::Suspended);
    let Some(team) = app.db.team_id_of(&m.user_id) else { return Joined::Nothing };
    let Some(pid) = m.provider_id.clone().filter(|_| active(m)) else { return Joined::Nothing };
    if rules_waiting(m, &s.subnet).is_some() || !behind_firewall(cp, p, m).await {
        return Joined::Waiting;
    }
    let while_off = match p.team_network_needs_power_off(&pid).await {
        Ok(w) => w,
        Err(_) => return Joined::Failed,
    };
    if while_off {
        if m.state == State::Running {
            // Once refused, it waits for its owner to power it off, as with next-boot,
            // rather than being powered off and on again every pass.
            if s.join != Join::WhenIdle || refusals(cp).contains_key(&m.id) {
                return Joined::AwaitingPowerOff;
            }
            return match restart(app, cp, p, &team, m, json!({ "team": team, "toJoin": true }), true).await {
                Restart::Restarting => Joined::Restarting,
                Restart::Waiting => Joined::AwaitingPowerOff,
                Restart::Failed => Joined::Failed,
            };
        }
        if !p.get(&pid).await.is_ok_and(|pm| pm.status == "offline") {
            return Joined::GoingOff;
        }
    }
    let by = system(m);
    // Under the lock team changes take: one who left the team meanwhile isn't put on,
    // nor one powered on meanwhile, if its interface goes on only while it's off.
    let _g = cp.lock_ops().await;
    let due = |x: &Machine| active(x) && (!while_off || x.state == State::Suspended) && app.db.team_id_of(&x.user_id).as_deref() == Some(team.as_str());
    let Some(m) = app.db.machine(&m.id).filter(due) else {
        return Joined::Nothing;
    };
    // Where hosts have networks of their own (Incus), the machine's host's.
    let on = p.hosts().and_then(|h| h.on(&h.host_of(&pid))).unwrap_or(p);
    let tried = match ensure(app, cp, on, &m, &by).await {
        Ok(Some(n)) => p.join_team_network(&pid, &n).await.map(|()| n),
        Ok(None) => return Joined::Nothing,
        Err(e) => Err(e),
    };
    match tried {
        Ok(n) => {
            refusals(cp).remove(&m.id);
            joining_set(cp).insert(m.id.clone());
            let d = json!({
                "team": team, "networkId": n.id, "label": n.label, "subnet": n.subnet, "join": s.join.as_str(),
                "poweredOff": m.state == State::Suspended, "atOnce": p.team_network_hotplug(), "whileOff": while_off,
            });
            app.db.record(&event(&by, "machine.team_network_joining", &m, d));
            Joined::Joining
        }
        Err(e) => {
            // Once per reason, not every pass.
            let why = e.to_string();
            if refusals(cp).insert(m.id.clone(), why.clone()).as_deref() != Some(why.as_str()) {
                let d = json!({ "team": team, "join": s.join.as_str(), "error": why });
                app.db.record(&event(&by, "machine.team_network_joining", &m, d).outcome(Outcome::Failure));
            }
            Joined::Failed
        }
    }
}

/// Whether the provider says `m` is behind the machines' firewall, whose inbound drops
/// are what keep teammates' machines apart on the VPC: all of it, every interface where
/// each has its own (ADR 0226). A machine whose firewall failed to attach waits until
/// the firewall sweep puts it behind.
async fn behind_firewall(cp: &ControlPlane, p: &dyn MachineProvider, m: &Machine) -> bool {
    let (Some(_), Some(fw), Some(pid)) = (&cp.firewall, m.firewall_id.as_deref(), m.provider_id.as_deref()) else { return false };
    p.firewall_covers(fw, pid).await.unwrap_or(false)
}

#[derive(Debug, PartialEq)]
enum Restart {
    Restarting,
    Waiting,
    Failed,
}

/// Powers off `m` once its agent says it runs nothing (MACHINE_TEAM_NETWORK_JOIN=
/// when-idle), so the sweep powers it on again on its team's network: one on the subnet
/// but not using it yet, or, `to_join`, one whose interface goes on only while it is
/// off (ADR 0226), given it first. A run that starts between that answer and the
/// power-off ends with it, as a rebuild's would.
async fn restart(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, team: &str, m: &Machine, details: Value, to_join: bool) -> Restart {
    let Some(e) = cp.enrollment.as_deref() else { return Restart::Waiting };
    if m.enrollment != "enrolled" || !behind_firewall(cp, p, m).await {
        return Restart::Waiting;
    }
    match super::enroll::heartbeat(app, e, m).await {
        Ok(hb) if hb.jobs == 0 => {}
        _ => return Restart::Waiting,
    }
    let by = system(m);
    let due = |x: &Machine| app.db.team_id_of(&x.user_id).as_deref() == Some(team);
    let still = |x: &Machine| x.id == m.id && x.state == State::Running && due(x);
    if super::act_if(app, cp, &by, &m.user_id, Step::Suspend, None, &still).await.is_err() {
        return if app.db.machine(&m.id).is_some_and(|x| still(&x)) { Restart::Failed } else { Restart::Waiting };
    }
    suspended(cp).insert(m.id.clone());
    if to_join {
        join_off(cp).insert(m.id.clone(), now());
    }
    app.db.record(&event(&by, "machine.team_network_restarting", m, details));
    Restart::Restarting
}

fn joining_set(cp: &ControlPlane) -> std::sync::MutexGuard<'_, HashSet<String>> {
    cp.network_joining.lock().unwrap_or_else(|e| e.into_inner())
}

fn refusals(cp: &ControlPlane) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
    cp.network_join_refused.lock().unwrap_or_else(|e| e.into_inner())
}

/// Records that `id`, powered off to be given its interface, wasn't off at the provider
/// in time: audited once, as a refusal, so it isn't powered off again for this.
fn gave_up(app: &AppState, cp: &ControlPlane, id: &str, s: &Settings) {
    let Some(m) = app.db.machine(id) else { return };
    let why = format!("it wasn't off at the provider within {} minutes", JOIN_OFF_MS / 60_000);
    if refusals(cp).insert(m.id.clone(), why.clone()).as_deref() != Some(why.as_str()) {
        let d = json!({ "team": app.db.team_id_of(&m.user_id), "join": s.join.as_str(), "error": why });
        app.db.record(&event(&system(&m), "machine.team_network_joining", &m, d).outcome(Outcome::Failure));
    }
}

fn join_off(cp: &ControlPlane) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
    cp.network_join_off.lock().unwrap_or_else(|e| e.into_inner())
}

/// As if every machine powered off to join had been so for `ms` longer.
#[cfg(test)]
pub fn age_held_joins(cp: &ControlPlane, ms: i64) {
    join_off(cp).values_mut().for_each(|since| *since -= ms);
}

// The team network's subnet in machines' own egress rules (ADR 0202).

/// When each machine was last sent which subnet, so a failing agent isn't sent it on
/// every heartbeat.
static SENT: Mutex<Option<HashMap<String, (Option<String>, i64)>>> = Mutex::new(None);
const RESEND_MS: i64 = 10 * 60_000;

/// What `m`'s egress rules should let through: its owner's team's subnet, or none.
/// None with team networks off, or joining off: nothing is asked of machines then.
fn wanted(app: &App, cp: &ControlPlane, m: &Machine) -> Option<Option<String>> {
    let s = cp.team_network.as_ref().filter(|s| s.join != Join::Off)?;
    Some(app.db.team_id_of(&m.user_id).map(|_| s.subnet.clone()))
}

/// After a heartbeat: sends the agent the subnet its egress rules should let through
/// if they let another through, or failed to load, at most every `RESEND_MS` for the
/// same one. A machine with no egress rules has nothing to let through.
pub async fn follow_up(app: &App, cp: &ControlPlane, e: &Enrollment, m: &Machine, hb: &Heartbeat) {
    let Some(want) = wanted(app, cp, m) else { return };
    if !hb.can.iter().any(|c| c == wire::CAN_TEAM_NETWORK) {
        return;
    }
    let Some(r) = &hb.team_network else { return };
    if r.state == wire::TEAM_RULES_NONE || (r.subnet == want && r.state == wire::TEAM_RULES_ON) {
        return;
    }
    let at = now();
    {
        let mut sent = SENT.lock().unwrap_or_else(|e| e.into_inner());
        let sent = sent.get_or_insert_with(HashMap::new);
        if sent.get(&m.id).is_some_and(|(s, when)| *s == want && at - when < RESEND_MS) {
            return;
        }
        sent.insert(m.id.clone(), (want.clone(), at));
    }
    let _ = push(app, e, m, want).await;
}

/// Sends `m`'s agent the subnet its egress rules should let through. Its answer: how
/// they stand there.
pub async fn push(app: &App, e: &Enrollment, m: &Machine, subnet: Option<String>) -> Result<TeamNetworkReport, String> {
    match e.call_agent(app, m, reqwest::Method::PUT, "/v1/team-network", &TeamNetworkRules { subnet }).await {
        Ok((200, body)) => serde_json::from_value(body).map_err(|_| "its agent's answer wasn't a report".to_string()),
        Ok((code, body)) => Err(body["error"].as_str().map_or(format!("it answered {code}"), String::from)),
        Err(e) => Err(e),
    }
}

/// Audits a change in what a machine's egress rules let through, or a failure to.
pub fn observed(app: &App, m: &Machine, by: &Who, old: Option<&Value>, new: &Value) {
    let (was, now) = (old.map(|o| &o["teamNetwork"]).filter(|w| !w.is_null()), &new["teamNetwork"]);
    if now.is_null() || was.is_some_and(|w| w["subnet"] == now["subnet"] && w["state"] == now["state"] && w["error"] == now["error"]) {
        return;
    }
    // A machine first heard from with nothing let through has nothing to say.
    if was.is_none() && now["subnet"].is_null() && now["state"] != wire::TEAM_RULES_FAILED {
        return;
    }
    let d = json!({ "subnet": now["subnet"], "from": was.map(|w| w["subnet"].clone()), "error": now["error"] });
    match now["state"].as_str() {
        Some(wire::TEAM_RULES_FAILED) => app.db.record(&event(by, "machine.team_network_rules_failed", m, d).outcome(Outcome::Failure)),
        Some(wire::TEAM_RULES_ON) => app.db.record(&event(by, "machine.team_network_rules_loaded", m, d)),
        _ => {}
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Leave {
    Leaving,
    Left,
    Waiting,
    Failed,
}

/// Takes `m` off `n`. An interface in use can only go while the machine is off, so a
/// running machine is suspended first, and the next pass, once it is off, removes it.
/// One added since it booted (ADR 0202) goes at once, unless it is a Linode interface,
/// which goes only while its machine is off (ADR 0226); and so does any where the
/// provider unplugs interfaces from running machines (Incus, ADR 0212).
pub(crate) async fn leave(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, n: &TeamNetwork, team: Option<&str>, m: &Machine, mem: &NetworkMember) -> Leave {
    let by = system(m);
    let details = || json!({ "team": team, "networkId": n.id, "label": n.label, "ownersTeam": app.db.team_id_of(&m.user_id) });
    // Checked again under `ops`, which joining a team waits on too: one who rejoined
    // since the sweep looked keeps their network.
    let due = || team.is_none() || app.db.team_id_of(&m.user_id).as_deref() != team;
    match m.state {
        State::Running if (!mem.active && !mem.needs_power_off) || p.team_network_hotplug() => {
            let _g = cp.lock_ops().await;
            if !app.db.machine(&m.id).is_some_and(|x| x.state == State::Running) || !due() {
                return Leave::Waiting;
            }
            let mut d = details();
            if let Err(e) = p.leave_team_network(mem).await {
                d["error"] = json!(e.to_string());
                app.db.record(&event(&by, "machine.team_network_left", m, d).outcome(Outcome::Failure));
                return Leave::Failed;
            }
            joining_set(cp).remove(&m.id);
            d["resuming"] = json!(false);
            d["inUse"] = json!(mem.active);
            app.db.record(&event(&by, "machine.team_network_left", m, d));
            Leave::Left
        }
        State::Running => {
            let still = |x: &Machine| x.id == m.id && x.state == State::Running && due();
            if super::act_if(app, cp, &by, &m.user_id, Step::Suspend, None, &still).await.is_err() {
                return if due() { Leave::Failed } else { Leave::Waiting };
            }
            suspended(cp).insert(m.id.clone());
            app.db.record(&event(&by, "machine.team_network_leaving", m, details()));
            Leave::Leaving
        }
        State::Suspended => {
            {
                let _g = cp.lock_ops().await;
                if !app.db.machine(&m.id).is_some_and(|x| x.state == State::Suspended) || !due() {
                    return Leave::Waiting;
                }
                if !p.get(&mem.machine).await.is_ok_and(|pm| pm.status == "offline") {
                    return Leave::Waiting;
                }
                if let Err(e) = p.leave_team_network(mem).await {
                    let mut d = details();
                    d["error"] = json!(e.to_string());
                    app.db.record(&event(&by, "machine.team_network_left", m, d).outcome(Outcome::Failure));
                    return Leave::Failed;
                }
                let mut d = details();
                d["resuming"] = json!(suspended(cp).contains(&m.id));
                app.db.record(&event(&by, "machine.team_network_left", m, d));
            }
            Leave::Left
        }
        // Being made, being destroyed or in error: once it is suspended or gone.
        _ => Leave::Waiting,
    }
}

#[derive(Debug, PartialEq)]
enum Removal {
    Removed,
    /// Something is still on it: the operator's services, or another's machines.
    Kept,
    Failed,
    Nothing,
}

/// Removes `n`, the network of `team`, which this server deleted at `deleted_at`, if
/// nothing is on it (ADR 0236). Under the lock team changes and creates take. That it
/// is kept, and why removing it failed, are audited once per reason, not every pass.
async fn remove(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, n: &TeamNetwork, team: &str, deleted_at: i64) -> Removal {
    let _g = cp.lock_ops().await;
    if app.db.team(team).is_some() {
        return Removal::Nothing;
    }
    let by = Who { actor: crate::audit::Actor::system(super::SYSTEM), source: Default::default() };
    let d = || json!({ "team": team, "label": n.label, "region": n.region, "subnet": n.subnet, "teamDeletedAt": deleted_at });
    let note = |why: &str| {
        let mut noted = cp.network_remove_noted.lock().unwrap_or_else(|e| e.into_inner());
        noted.insert(n.id.clone(), why.to_string()).as_deref() != Some(why)
    };
    match p.remove_team_network(n).await {
        Ok(true) => {
            cp.network_remove_noted.lock().unwrap_or_else(|e| e.into_inner()).remove(&n.id);
            app.db.record(&by.event("machine.team_network_removed").target("team_network", &n.id).details(d()));
            Removal::Removed
        }
        Ok(false) => {
            if note("in use") {
                let mut d = d();
                d["reason"] = json!("something is still on it");
                app.db.record(&by.event("machine.team_network_kept").target("team_network", &n.id).details(d));
            }
            Removal::Kept
        }
        Err(e) => {
            let why = e.to_string();
            if note(&why) {
                let mut d = d();
                d["error"] = json!(why);
                app.db.record(&by.event("machine.team_network_removed").target("team_network", &n.id).details(d).outcome(Outcome::Failure));
            }
            Removal::Failed
        }
    }
}

fn suspended(cp: &ControlPlane) -> std::sync::MutexGuard<'_, HashSet<String>> {
    cp.network_suspended.lock().unwrap_or_else(|e| e.into_inner())
}

/// Powers on machine `id`, which the sweep powered off and which has nothing left to
/// leave. Some(true) once on, Some(false) if that failed (kept, to try again next pass),
/// None if there was nothing to do: gone, someone else already powered it on, or it
/// has to stay off now for another reason.
async fn resume(app: &AppState, cp: &ControlPlane, id: &str) -> Option<bool> {
    let active = |user_id: &str| app.db.user(user_id).is_some_and(|u| u.active());
    let m = app.db.machine(id).filter(|m| {
        m.state == State::Suspended
            && active(&m.user_id)
            && !app.db.disable_hold(&m.id)
            && !app.db.team_machine(&m.id).is_some_and(|t| t.released_at.is_some())
    });
    let Some(m) = m else {
        suspended(cp).remove(id);
        return None;
    };
    let still = |x: &Machine| x.id == m.id && x.state == State::Suspended && active(&x.user_id);
    let _ = super::act_if(app, cp, &system(&m), &m.user_id, Step::Resume, None, &still).await;
    let on = app.db.machine(id).is_none_or(|x| x.state != State::Suspended);
    if on {
        suspended(cp).remove(id);
    }
    Some(on)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned().unwrap_or_default()
    }

    #[test]
    fn a_networks_team_is_read_from_its_label_under_any_prefix() {
        let t = team_part("team-1");
        for prefix in ["superbot", "old-team-bot", "x"] {
            let l = label(prefix, "team-1", "gb-lon").unwrap();
            assert_eq!(team_part_of(&l), Some(t.as_str()), "{l}");
        }
        for l in ["superbot-team-abc-gb-lon", "superbot-team-0123456789ab", "office-vpc", "superbot-team-0123456789ag-gb-lon"] {
            assert_eq!(team_part_of(l), None, "{l}");
        }
    }

    #[test]
    fn off_unless_vpc_with_a_subnet_linode_takes() {
        assert_eq!(Settings::from_env(&vars(&[])).unwrap(), None);
        assert_eq!(Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "off")])).unwrap(), None);
        let e = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK_SUBNET", "10.9.0.0/24")])).unwrap_err();
        assert!(e.contains("needs MACHINE_TEAM_NETWORK=vpc or ovn"), "{e}");
        let e = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "mesh")])).unwrap_err();
        assert!(e.contains("off, vpc or ovn"), "{e}");
        let on = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "VPC")])).unwrap().unwrap();
        assert_eq!(on.subnet, DEFAULT_SUBNET);
        assert_eq!(on.view(), json!({ "kind": "vpc", "subnet": DEFAULT_SUBNET, "join": "next-boot", "remove": "when-empty" }));
        let with = |s: &str| Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "vpc"), ("MACHINE_TEAM_NETWORK_SUBNET", s)]));
        assert_eq!(with("172.20.0.0/16").unwrap().unwrap().subnet, "172.20.0.0/16");
        assert_eq!(with(" 192.168.4.0/24 ").unwrap().unwrap().subnet, "192.168.4.0/24");
        for (bad, why) in [
            ("10.0.0.1/24", "bits set"),
            ("evil.example", "isn't an IP address"),
            ("fd00::/64", "IPv4"),
            ("203.0.113.0/24", "isn't inside"),
            ("192.168.200.0/24", "isn't inside"),
            ("10.248.0.8/30", "smallest team subnet"),
            ("10.248.0.4/32", "smallest team subnet"),
        ] {
            let e = with(bad).unwrap_err();
            assert!(e.starts_with("MACHINE_TEAM_NETWORK_SUBNET") && e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn ovn_takes_any_private_range() {
        let with = |s: &str| Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "ovn"), ("MACHINE_TEAM_NETWORK_SUBNET", s)]));
        let on = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "OVN")])).unwrap().unwrap();
        assert_eq!(on.view(), json!({ "kind": "ovn", "subnet": DEFAULT_SUBNET, "join": "next-boot", "remove": "when-empty" }));
        assert_eq!(with("192.168.200.0/24").unwrap().unwrap().subnet, "192.168.200.0/24", "outside Linode's VPC ranges, but private");
        assert_eq!(with("10.0.0.0/8").unwrap().unwrap().subnet, "10.0.0.0/8");
        for (bad, why) in [("203.0.113.0/24", "isn't inside"), ("100.64.0.0/24", "isn't inside"), ("10.1.0.8/30", "smallest")] {
            let e = with(bad).unwrap_err();
            assert!(e.contains(why) && (why != "isn't inside" || e.contains("RFC 1918")), "{bad}: {e}");
        }
    }

    #[test]
    fn a_deleted_teams_network_goes_once_empty_unless_turned_off() {
        let with = |v: &str| Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "vpc"), ("MACHINE_TEAM_NETWORK_REMOVE", v)]));
        assert_eq!(with("").unwrap().unwrap().remove, Remove::WhenEmpty, "the default");
        assert_eq!(with("When_Empty").unwrap().unwrap().remove, Remove::WhenEmpty);
        let off = with(" off ").unwrap().unwrap();
        assert_eq!((off.remove, off.view()["remove"].as_str()), (Remove::Off, Some("off")));
        let e = with("always").unwrap_err();
        assert!(e.contains("off or when-empty"), "{e}");
        let e = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK_REMOVE", "off")])).unwrap_err();
        assert!(e.contains("MACHINE_TEAM_NETWORK_REMOVE needs MACHINE_TEAM_NETWORK=vpc or ovn"), "{e}");
    }

    #[test]
    fn an_operators_deny_list_is_never_let_through() {
        let with = |deny: &str| Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "vpc"), ("MACHINE_EGRESS_DENY", deny)]));
        assert!(with("203.0.113.0/24, 10.9.0.0/16, fd00::/8").is_ok(), "apart from it");
        for deny in ["10.248.0.0/16", "10.248.2.7", "10.248.0.0/22"] {
            let e = with(deny).unwrap_err();
            assert!(e.contains("meets MACHINE_EGRESS_DENY"), "{deny}: {e}");
        }
    }

    #[test]
    fn labels_name_the_team_by_digest_and_the_region() {
        let l = label("superbot", "team-1", "gb-lon").unwrap();
        assert!(l.starts_with("superbot-team-") && l.ends_with("-gb-lon") && l.len() == "superbot-team-".len() + 12 + "-gb-lon".len(), "{l}");
        assert!(!l.contains("team-1"), "the team's id stays out: {l}");
        assert_ne!(l, label("superbot", "team-2", "gb-lon").unwrap());
        assert_ne!(l, label("superbot", "team-1", "de-fra-2").unwrap(), "one per region, as VPCs are");
        assert_eq!(label("superbot", "team-1", "gb-lon"), Some(l), "the same each time");
        assert_eq!(label("superbot", "t", &"x".repeat(40)), None, "longer than Linode takes");
        assert_eq!(label("superbot-", "t", "gb-lon"), None, "two dashes in a row");
    }
}
