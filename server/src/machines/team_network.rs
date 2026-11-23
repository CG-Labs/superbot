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

use super::provider::{MachineProvider, NetworkMember, ProviderError, TeamNetwork};
use super::{ControlPlane, State, Step, event, system};
use crate::audit::{Outcome, Who};
use crate::db::Machine;
use crate::runner::App;
use crate::AppState;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub const DEFAULT_SUBNET: &str = "10.248.0.0/22";
/// Where Linode lets a VPC subnet be: RFC 1918, but for 192.168.128.0/17, which its
/// private network uses.
const ALLOWED: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/17"];
/// Linode's longest subnet prefix.
const LONGEST: u32 = 29;
/// A VPC label's longest.
const MAX_LABEL: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The range of every team network's subnet, canonical. Every team's is the same:
    /// VPCs are apart, so the same range on two never meets.
    pub subnet: String,
}

impl Settings {
    /// MACHINE_TEAM_NETWORK (`off`, the default, or `vpc`) and
    /// MACHINE_TEAM_NETWORK_SUBNET. Whether the provider and the firewall allow it is
    /// the control plane's to check.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let raw = var("MACHINE_TEAM_NETWORK_SUBNET");
        match var("MACHINE_TEAM_NETWORK").trim().to_ascii_lowercase().as_str() {
            "" | "off" => {
                if !raw.trim().is_empty() {
                    return Err("MACHINE_TEAM_NETWORK_SUBNET needs MACHINE_TEAM_NETWORK=vpc".into());
                }
                return Ok(None);
            }
            "vpc" => {}
            v => return Err(format!("MACHINE_TEAM_NETWORK must be off or vpc, not \"{}\"", crate::audit::clip(v, 20))),
        }
        let subnet = match raw.trim() {
            "" => DEFAULT_SUBNET.to_string(),
            r => super::firewall::cidr(r).map_err(|e| format!("MACHINE_TEAM_NETWORK_SUBNET: {e}"))?,
        };
        let span = super::incus::span(&subnet).filter(|(v6, _, _)| !v6).ok_or("MACHINE_TEAM_NETWORK_SUBNET must be an IPv4 range")?;
        if !ALLOWED.iter().filter_map(|a| super::incus::span(a)).any(|(_, lo, hi)| lo <= span.1 && span.2 <= hi) {
            return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} isn't inside {}, where Linode's VPC subnets go", ALLOWED.join(", ")));
        }
        if subnet.rsplit('/').next().and_then(|l| l.parse::<u32>().ok()).is_none_or(|l| l > LONGEST) {
            return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} is smaller than Linode's smallest subnet, a /{LONGEST}"));
        }
        // An operator's own deny list wins: the team network would let it through.
        for c in var("MACHINE_EGRESS_DENY").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((v6, lo, hi)) = super::firewall::cidr(c).ok().and_then(|c| super::incus::span(&c))
                && !v6
                && lo <= span.2
                && span.1 <= hi
            {
                return Err(format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} meets MACHINE_EGRESS_DENY's {c}; pick a range the deny list doesn't name"));
            }
        }
        Ok(Some(Settings { subnet }))
    }

    pub fn view(&self) -> Value {
        json!({ "kind": "vpc", "subnet": self.subnet })
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
    let label = label(&cp.label_prefix, &team, &m.region).ok_or_else(|| ProviderError::Api {
        status: 400,
        message: format!("a team network's label in {} would be longer than Linode takes; shorten MACHINE_LABEL_PREFIX", m.region),
    })?;
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
pub async fn sweep(app: &AppState, cp: &ControlPlane) -> Value {
    let (Some(_), Some(p)) = (&cp.team_network, cp.provider.as_deref()) else { return json!({}) };
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
    let mut unseen = false;
    let mut still_on: HashSet<String> = HashSet::new();
    for (part, n) in &nets {
        let team = teams.get(part).cloned();
        let members = match p.team_network_members(&n.id).await {
            Ok(m) => m,
            Err(_) => {
                errors += 1;
                unseen = true;
                continue;
            }
        };
        for mem in &members {
            let Some(m) = ours.get(&mem.machine) else { continue };
            if team.is_some() && app.db.team_id_of(&m.user_id) == team {
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
        }
    }
    // A network not looked at may still have a machine to take off: never power one on
    // until every network has been.
    if !unseen {
        let waiting: Vec<String> = suspended(cp).iter().filter(|id| !still_on.contains(*id)).cloned().collect();
        for id in waiting {
            match resume(app, cp, &id).await {
                Some(true) => resumed += 1,
                Some(false) => errors += 1,
                None => {}
            }
        }
    }
    let mut out = json!({});
    for (k, v) in [("leaving", leaving), ("left", left), ("resumed", resumed), ("errors", errors)] {
        if v > 0 {
            out[k] = v.into();
        }
    }
    out
}

enum Leave {
    Leaving,
    Left,
    Waiting,
    Failed,
}

/// Takes `m` off `n`. Its interface can only go while it is off, so a running machine
/// is suspended first, and the next pass, once it is off, removes it.
async fn leave(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, n: &TeamNetwork, team: Option<&str>, m: &Machine, mem: &NetworkMember) -> Leave {
    let by = system(m);
    let details = || json!({ "team": team, "networkId": n.id, "label": n.label, "ownersTeam": app.db.team_id_of(&m.user_id) });
    match m.state {
        State::Running => {
            let still = |x: &Machine| x.id == m.id && x.state == State::Running;
            if super::act_if(app, cp, &by, &m.user_id, Step::Suspend, None, &still).await.is_err() {
                return Leave::Failed;
            }
            suspended(cp).insert(m.id.clone());
            app.db.record(&event(&by, "machine.team_network_leaving", m, details()));
            Leave::Leaving
        }
        State::Suspended => {
            {
                let _g = cp.lock_ops().await;
                if !app.db.machine(&m.id).is_some_and(|x| x.state == State::Suspended) {
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
        assert!(e.contains("needs MACHINE_TEAM_NETWORK=vpc"), "{e}");
        let e = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "ovn")])).unwrap_err();
        assert!(e.contains("off or vpc"), "{e}");
        let on = Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "VPC")])).unwrap().unwrap();
        assert_eq!(on.subnet, DEFAULT_SUBNET);
        assert_eq!(on.view(), json!({ "kind": "vpc", "subnet": DEFAULT_SUBNET }));
        let with = |s: &str| Settings::from_env(&vars(&[("MACHINE_TEAM_NETWORK", "vpc"), ("MACHINE_TEAM_NETWORK_SUBNET", s)]));
        assert_eq!(with("172.20.0.0/16").unwrap().unwrap().subnet, "172.20.0.0/16");
        assert_eq!(with(" 192.168.4.0/24 ").unwrap().unwrap().subnet, "192.168.4.0/24");
        for (bad, why) in [
            ("10.0.0.1/24", "bits set"),
            ("evil.example", "isn't an IP address"),
            ("fd00::/64", "IPv4"),
            ("203.0.113.0/24", "isn't inside"),
            ("192.168.200.0/24", "isn't inside"),
            ("10.248.0.8/30", "smallest subnet"),
            ("10.248.0.4/32", "smallest subnet"),
        ] {
            let e = with(bad).unwrap_err();
            assert!(e.starts_with("MACHINE_TEAM_NETWORK_SUBNET") && e.contains(why), "{bad}: {e}");
        }
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
