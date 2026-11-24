//! A provider firewall in front of every machine (ADR 0035). One per control plane,
//! labelled `<prefix>-fw`: inbound traffic is dropped except the agent's port from the
//! control plane's addresses, and SSH only from addresses an operator named. Machines
//! are created behind it, so none is ever open, and the reconciler puts back any that
//! left it. Off unless MACHINE_FIREWALL=on, which needs enrollment.

use super::provider::{FirewallRule, MachineProvider, ProviderError, ProviderFirewall};
use super::{SYSTEM, State, event, system};
use crate::audit::{Outcome, Who};
use crate::db::Machine;
use crate::runner::App;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

pub const AGENT_RULE: &str = "agent-from-control-plane";
pub const SSH_RULE: &str = "ssh-from-operators";

/// MACHINE_FIREWALL and its addresses. The agent's port and the control plane's host
/// come with enrollment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    /// MACHINE_FIREWALL_SOURCES: where botd calls machines from. Empty: the host in
    /// MACHINE_CONTROL_URL, if it is an address.
    pub sources: Vec<String>,
    /// MACHINE_SSH_SOURCES: who may reach port 22. Empty: nobody.
    pub ssh: Vec<String>,
}

fn flag(name: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "off" | "false" | "no" => Ok(false),
        "1" | "on" | "true" | "yes" => Ok(true),
        v => Err(format!("{name} must be on or off, not \"{v}\"")),
    }
}

/// `ip` or `ip/len` as the provider stores it: `192.0.2.7/32`, `2001:db8::/32`. The
/// address must be the network's own (no bits set past the length), so what is
/// written is what is let in.
pub fn cidr(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let bad = || format!("\"{}\" isn't an IP address or CIDR range", crate::audit::clip(raw, 50));
    let (ip, len) = match raw.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (raw, None),
    };
    let ip: IpAddr = ip.parse().map_err(|_| bad())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        None => max,
        Some(l) => l.parse::<u32>().ok().filter(|l| *l <= max).ok_or_else(bad)?,
    };
    let host_bits = match ip {
        IpAddr::V4(a) => u128::from(u32::from(a) & !u32::MAX.checked_shl(32 - len).unwrap_or(0)),
        IpAddr::V6(a) => u128::from(a) & !u128::MAX.checked_shl(128 - len).unwrap_or(0),
    };
    if host_bits != 0 {
        return Err(format!(
            "\"{raw}\" has bits set past /{len}; write the network's own address"
        ));
    }
    Ok(format!("{ip}/{len}"))
}

fn cidrs(name: &str, raw: &str) -> Result<Vec<String>, String> {
    let mut out = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| cidr(s).map_err(|e| format!("{name}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

impl Settings {
    /// None: off. Addresses given while it is off are a mistake, not a no-op.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let on = flag("MACHINE_FIREWALL", &var("MACHINE_FIREWALL"))?;
        let sources = cidrs("MACHINE_FIREWALL_SOURCES", &var("MACHINE_FIREWALL_SOURCES"))?;
        let ssh = cidrs("MACHINE_SSH_SOURCES", &var("MACHINE_SSH_SOURCES"))?;
        if !on {
            for (k, v) in [("MACHINE_FIREWALL_SOURCES", &sources), ("MACHINE_SSH_SOURCES", &ssh)] {
                if !v.is_empty() {
                    return Err(format!("{k} needs MACHINE_FIREWALL=on"));
                }
            }
            return Ok(None);
        }
        if var("MACHINE_CONTROL_URL").trim().is_empty() {
            return Err("MACHINE_FIREWALL=on needs MACHINE_CONTROL_URL: the firewall lets in only the agent's port, from the control plane".into());
        }
        Ok(Some(Settings { sources, ssh }))
    }
}

/// MACHINE_FIREWALL_EGRESS (ADR 0179): whether the provider firewall also keeps every
/// process on a machine, root included, off the machines' deny list. On unless `off`,
/// and only with MACHINE_FIREWALL=on.
pub fn egress_from_env(var: &dyn Fn(&str) -> String) -> Result<bool, String> {
    let raw = var("MACHINE_FIREWALL_EGRESS");
    let firewall = Settings::from_env(var)?.is_some();
    if raw.trim().is_empty() {
        return Ok(firewall);
    }
    let on = flag("MACHINE_FIREWALL_EGRESS", &raw)?;
    if !firewall {
        return Err("MACHINE_FIREWALL_EGRESS needs MACHINE_FIREWALL=on".into());
    }
    Ok(on)
}

/// What the provider firewall keeps machines off on the way out: the same list as the
/// harness egress rules inside them (ADR 0126), the built-in private, shared and
/// link-local ranges and MACHINE_EGRESS_DENY.
pub fn egress_deny(var: &dyn Fn(&str) -> String) -> Result<Vec<String>, String> {
    Ok(super::hardening::Settings::from_env(var)?
        .unwrap_or_else(super::hardening::Settings::default_on)
        .deny)
}

/// botd's machine address and port from MACHINE_CONTROL_URL, when it names an address.
pub fn control_from_env(var: &dyn Fn(&str) -> String) -> Option<(IpAddr, u16)> {
    let u = url::Url::parse(var("MACHINE_CONTROL_URL").trim()).ok()?;
    let ip = match u.host()? {
        url::Host::Ipv4(a) => IpAddr::V4(a),
        url::Host::Ipv6(a) => IpAddr::V6(a),
        url::Host::Domain(_) => return None,
    };
    Some((ip, u.port_or_known_default()?))
}

pub struct Firewall {
    pub label: String,
    pub tag: String,
    /// In order: the agent's port from the control plane, then SSH if any.
    pub rules: Vec<FirewallRule>,
    /// The last failure recorded for each machine it couldn't cover, so a failure that
    /// repeats every pass is audited once.
    failed: Mutex<HashMap<String, String>>,
}

impl Firewall {
    pub fn new(
        s: &Settings,
        prefix: &str,
        agent_port: u16,
        control_host: &str,
    ) -> Result<Firewall, String> {
        let sources = if s.sources.is_empty() {
            let ip: IpAddr = control_host.parse().map_err(|_| {
                "MACHINE_FIREWALL_SOURCES is needed: MACHINE_CONTROL_URL names a host, not an address, and the firewall needs the addresses botd calls machines from".to_string()
            })?;
            vec![cidr(&ip.to_string())?]
        } else {
            s.sources.clone()
        };
        let mut rules = vec![FirewallRule {
            label: AGENT_RULE.into(),
            ports: agent_port.to_string(),
            sources,
        }];
        if !s.ssh.is_empty() {
            rules.push(FirewallRule {
                label: SSH_RULE.into(),
                ports: "22".into(),
                sources: s.ssh.clone(),
            });
        }
        Ok(Firewall {
            label: format!("{prefix}-fw"),
            tag: prefix.into(),
            rules,
            failed: Mutex::default(),
        })
    }

    pub fn describe(&self) -> String {
        let ssh = self
            .rules
            .iter()
            .find(|r| r.label == SSH_RULE)
            .map_or("closed".to_string(), |r| format!("from {}", r.sources.join(", ")));
        format!(
            "on ({}: agent port {} from {}; SSH {ssh})",
            self.label,
            self.rules[0].ports,
            self.rules[0].sources.join(", ")
        )
    }
}

pub fn rules_json(rules: &[FirewallRule]) -> Value {
    json!(rules
        .iter()
        .map(|r| json!({ "label": r.label, "ports": r.ports, "from": r.sources }))
        .collect::<Vec<_>>())
}

/// A change to the firewall itself, not to one machine.
fn record(app: &App, by: &Who, action: &str, id: &str, outcome: Outcome, details: Value) {
    app.db.record(
        &by.event(action)
            .target("firewall", id)
            .outcome(outcome)
            .details(details),
    );
}

/// The firewall's id, made if there is none, its rules set back if they differ, and
/// enabled again if it was turned off.
pub async fn ensure(
    app: &App,
    fw: &Firewall,
    p: &dyn MachineProvider,
    by: &Who,
) -> Result<String, ProviderError> {
    let found = match p.find_firewall(&fw.label).await? {
        Some(f) => f,
        None => match p.create_firewall(&fw.label, std::slice::from_ref(&fw.tag), &fw.rules).await {
            Ok(f) => {
                let mut details = json!({ "label": fw.label, "rules": rules_json(&fw.rules) });
                if let Some(o) = p.firewall_egress() {
                    details["outbound"] = o;
                }
                record(app, by, "machine.firewall_created", &f.id, Outcome::Success, details);
                return Ok(f.id);
            }
            // Made meanwhile, or by a create whose answer was lost.
            Err(ProviderError::LabelTaken) => p
                .find_firewall(&fw.label)
                .await?
                .ok_or(ProviderError::LabelTaken)?,
            Err(e) => return Err(e),
        },
    };
    repair(app, fw, p, by, &found).await?;
    Ok(found.id)
}

/// Sets `found`'s rules back to ours if they differ, and enables it if it was off.
async fn repair(
    app: &App,
    fw: &Firewall,
    p: &dyn MachineProvider,
    by: &Who,
    found: &ProviderFirewall,
) -> Result<(), ProviderError> {
    if found.rules.as_deref() != Some(&fw.rules[..]) {
        p.set_firewall_rules(&found.id, &fw.rules).await?;
        let mut details = json!({ "label": found.label, "rules": rules_json(&fw.rules), "was": found.rules.as_deref().map(rules_json) });
        if let Some(o) = p.firewall_egress() {
            details["outbound"] = o;
        }
        record(app, by, "machine.firewall_updated", &found.id, Outcome::Success, details);
    }
    if !found.enabled {
        p.enable_firewall(&found.id).await?;
        record(
            app,
            by,
            "machine.firewall_updated",
            &found.id,
            Outcome::Success,
            json!({ "label": found.label, "status": "enabled", "was": "disabled" }),
        );
    }
    Ok(())
}

fn failed(app: &App, by: &Who, m: &Machine, firewall_id: &str, step: &str, e: &ProviderError) {
    app.db.record(
        &event(
            by,
            "machine.firewall_failed",
            m,
            json!({ "firewallId": firewall_id, "step": step, "error": e.to_string() }),
        )
        .outcome(Outcome::Failure),
    );
}

/// Whether `m` is on a host that is down or lost, so nothing there can be checked.
fn on_unreachable_host(p: &dyn MachineProvider, m: &Machine) -> bool {
    let (Some(h), Some(pid)) = (p.hosts(), m.provider_id.as_deref()) else { return false };
    h.status(&h.host_of(pid)).is_some_and(|s| s != super::provider::HostStatus::Up)
}

/// Keeps the firewall as configured and every machine the provider has behind it:
/// those adopted from a lost create, made before the firewall was on, or taken off it
/// at the provider. A machine still behind an older firewall of ours (e.g. from
/// before a label prefix change) stays there, since moving it would leave it open
/// for a moment, and that firewall gets our rules too. Nothing is called when there
/// are no machines. Returns how many it put back.
pub async fn sync(app: &App, fw: &Firewall, p: &dyn MachineProvider) -> usize {
    let live: Vec<Machine> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| {
            matches!(m.state, State::Provisioning | State::Running | State::Suspended)
                && m.provider_id.is_some()
                && m.provider == p.name()
                && !on_unreachable_host(p, m)
        })
        .collect();
    if live.is_empty() {
        return 0;
    }
    let id = match ensure(app, fw, p, &Who::system(SYSTEM)).await {
        Ok(id) => id,
        Err(e) => {
            crate::obs::log::log_warn!("Machine firewall: {e}");
            return 0;
        }
    };
    let mut covers: HashMap<String, Option<Vec<String>>> = HashMap::new();
    // Machines partly behind an older firewall, each interface with its own (ADR 0226):
    // the rest go behind that one, since Linode won't put an interface behind two.
    let mut partly: HashMap<String, Vec<String>> = HashMap::new();
    match p.firewall_devices(&id).await {
        Ok(c) => covers.insert(id.clone(), Some(c.machines)),
        Err(e) => {
            crate::obs::log::log_warn!("Machine firewall: {e}");
            return 0;
        }
    };
    let older: BTreeSet<String> = live
        .iter()
        .filter_map(|m| m.firewall_id.clone())
        .filter(|f| *f != id)
        .collect();
    for old in older {
        let found = async {
            let f = p.get_firewall(&old).await?;
            repair(app, fw, p, &Who::system(SYSTEM), &f).await?;
            p.firewall_devices(&old).await
        };
        match found.await {
            Ok(c) => {
                partly.insert(old.clone(), c.partly);
                covers.insert(old, Some(c.machines));
            }
            // Gone: its machines join the current one.
            Err(ProviderError::NotFound) => {}
            Err(e) => {
                crate::obs::log::log_warn!("Machine firewall {old}: {e}");
                covers.insert(old, None);
            }
        }
    }
    let mut attached = 0;
    for m in live {
        let pid = m.provider_id.as_deref().unwrap_or_default();
        let behind = |f: &str| {
            covers
                .get(f)
                .and_then(|c| c.as_ref())
                .is_some_and(|c| c.iter().any(|c| c == pid))
        };
        let saved = m.firewall_id.as_deref().filter(|f| *f != id);
        let mut tried = id.as_str();
        // Where it is behind, and whether we just put it there.
        let res = if behind(&id) {
            Ok((id.clone(), false))
        } else if let Some(old) = saved
            && behind(old)
        {
            Ok((old.to_string(), false))
        } else if let Some(old) = saved
            && matches!(covers.get(old), Some(None))
        {
            // Couldn't read it this pass; attaching would fail if it's still there.
            continue;
        } else if let Some(old) = saved
            && partly.get(old).is_some_and(|c| c.iter().any(|c| c == pid))
        {
            tried = old;
            p.attach_firewall(old, pid).await.map(|()| (old.to_string(), true))
        } else {
            p.attach_firewall(&id, pid).await.map(|()| (id.clone(), true))
        };
        match res {
            Ok((home, put_back)) => {
                fw.failed.lock().unwrap().remove(&m.id);
                if m.firewall_id.as_deref() != Some(home.as_str()) {
                    app.db.set_machine_firewall(&m.id, &home);
                }
                if put_back {
                    attached += 1;
                    app.db.record(&event(
                        &system(&m),
                        "machine.firewall_attached",
                        &m,
                        json!({ "firewallId": home, "providerId": pid }),
                    ));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                let before = fw.failed.lock().unwrap().insert(m.id.clone(), msg.clone());
                if before.as_deref() != Some(msg.as_str()) {
                    failed(app, &system(&m), &m, tried, "attach", &e);
                }
            }
        }
    }
    attached
}

/// After a machine is deleted at the provider: takes it off its firewall (the provider
/// may have already), then deletes the firewall once no machine of ours is behind it
/// and the provider says it covers nothing. A failure leaves an empty firewall, which
/// costs nothing and is reused by the next machine.
pub async fn release(app: &App, p: &dyn MachineProvider, m: &Machine, by: &Who) {
    let Some(fw) = m.firewall_id.as_deref() else {
        return;
    };
    if let Some(pid) = m.provider_id.as_deref() {
        if let Err(e) = p.detach_firewall(fw, pid).await {
            failed(app, by, m, fw, "detach", &e);
            return;
        }
        app.db.record(&event(
            by,
            "machine.firewall_detached",
            m,
            json!({ "firewallId": fw, "providerId": pid }),
        ));
    }
    if app.db.machines_on_firewall(fw, &m.id) > 0 {
        return;
    }
    match p.firewall_devices(fw).await {
        Ok(left) if left.machines.is_empty() && left.partly.is_empty() && left.others == 0 => {}
        // It covers devices this control plane doesn't know; leave it be.
        Ok(_) | Err(ProviderError::NotFound) => return,
        Err(e) => return failed(app, by, m, fw, "delete", &e),
    }
    match p.delete_firewall(fw).await {
        Ok(()) => record(
            app,
            by,
            "machine.firewall_deleted",
            fw,
            Outcome::Success,
            json!({ "lastMachine": m.id }),
        ),
        Err(e) => failed(app, by, m, fw, "delete", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_canonical_and_exact() {
        for (raw, want) in [
            ("192.0.2.7", "192.0.2.7/32"),
            (" 192.0.2.0/24 ", "192.0.2.0/24"),
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("2001:DB8::1", "2001:db8::1/128"),
            ("2001:db8::/32", "2001:db8::/32"),
            ("::/0", "::/0"),
            ("10.0.0.0/8", "10.0.0.0/8"),
        ] {
            assert_eq!(cidr(raw).as_deref(), Ok(want), "{raw}");
        }
        for bad in [
            "",
            "example.com",
            "192.0.2.7/33",
            "192.0.2.7/24",
            "2001:db8::1/64",
            "192.0.2.0/",
            "192.0.2.0/-1",
        ] {
            assert!(cidr(bad).is_err(), "{bad}");
        }
    }

    fn vars(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> String {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        }
    }

    #[test]
    fn settings_are_off_unless_asked_and_need_enrollment() {
        assert_eq!(Settings::from_env(&vars(&[])), Ok(None));
        assert_eq!(Settings::from_env(&vars(&[("MACHINE_FIREWALL", "off")])), Ok(None));
        for bad in [
            &[("MACHINE_FIREWALL", "maybe")][..],
            &[("MACHINE_SSH_SOURCES", "192.0.2.0/24")],
            &[("MACHINE_FIREWALL_SOURCES", "192.0.2.1")],
            &[("MACHINE_FIREWALL", "on")],
            &[
                ("MACHINE_FIREWALL", "on"),
                ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"),
                ("MACHINE_SSH_SOURCES", "everyone"),
            ],
        ] {
            assert!(Settings::from_env(&vars(bad)).is_err(), "{bad:?}");
        }
        let s = Settings::from_env(&vars(&[
            ("MACHINE_FIREWALL", "on"),
            ("MACHINE_CONTROL_URL", "https://cp.example:8443"),
            ("MACHINE_FIREWALL_SOURCES", "198.51.100.9, 2001:db8::9, 198.51.100.9"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            (s.sources.as_slice(), s.ssh.len()),
            (&["198.51.100.9/32".to_string(), "2001:db8::9/128".into()][..], 0)
        );
    }

    #[test]
    fn provider_egress_is_on_with_the_firewall_unless_turned_off() {
        assert_eq!(egress_from_env(&vars(&[])), Ok(false));
        assert_eq!(egress_from_env(&vars(&[("MACHINE_FIREWALL", "on"), ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443")])), Ok(true));
        assert_eq!(egress_from_env(&vars(&[("MACHINE_FIREWALL", "on"), ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"), ("MACHINE_FIREWALL_EGRESS", "on")])), Ok(true));
        assert_eq!(egress_from_env(&vars(&[("MACHINE_FIREWALL", "on"), ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"), ("MACHINE_FIREWALL_EGRESS", "off")])), Ok(false));
        let e = egress_from_env(&vars(&[("MACHINE_FIREWALL_EGRESS", "off")])).unwrap_err();
        assert!(e.contains("MACHINE_FIREWALL=on"), "{e}");
        assert!(egress_from_env(&vars(&[("MACHINE_FIREWALL", "on"), ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"), ("MACHINE_FIREWALL_EGRESS", "drop")])).is_err());
    }

    #[test]
    fn provider_egress_denies_what_the_machines_own_rules_deny() {
        let private: Vec<String> = super::super::incus::PRIVATE.iter().map(|s| s.to_string()).collect();
        assert_eq!(egress_deny(&vars(&[])).unwrap(), private);
        assert_eq!(egress_deny(&vars(&[("MACHINE_HARDENING", "off")])).unwrap(), private, "the built-in ranges either way");
        let with = egress_deny(&vars(&[("MACHINE_EGRESS_DENY", "203.0.113.0/24, 10.9.0.0/16")])).unwrap();
        assert!(with.contains(&"203.0.113.0/24".to_string()));
        assert!(!with.contains(&"10.9.0.0/16".to_string()), "inside 10/8 already: {with:?}");
        assert!(egress_deny(&vars(&[("MACHINE_EGRESS_DENY", "example.com")])).is_err());
        assert!(egress_deny(&vars(&[("MACHINE_HARDENING", "off"), ("MACHINE_EGRESS_DENY", "203.0.113.0/24")])).is_err());
    }

    #[test]
    fn the_control_plane_is_read_only_when_it_is_an_address() {
        assert_eq!(
            control_from_env(&vars(&[("MACHINE_CONTROL_URL", "https://10.1.2.3:8443")])),
            Some(("10.1.2.3".parse().unwrap(), 8443))
        );
        assert_eq!(
            control_from_env(&vars(&[("MACHINE_CONTROL_URL", "https://[fd00::7]")])),
            Some(("fd00::7".parse().unwrap(), 443))
        );
        assert_eq!(control_from_env(&vars(&[("MACHINE_CONTROL_URL", "https://cp.example:8443")])), None);
        assert_eq!(control_from_env(&vars(&[])), None);
    }

    #[test]
    fn rules_open_only_the_agent_port_to_the_control_plane() {
        let fw = Firewall::new(&Settings::default(), "superbot", 7443, "192.0.2.1").unwrap();
        assert_eq!(fw.label, "superbot-fw");
        assert_eq!(
            fw.rules,
            [FirewallRule {
                label: AGENT_RULE.into(),
                ports: "7443".into(),
                sources: vec!["192.0.2.1/32".into()],
            }],
            "no SSH unless asked"
        );
        assert!(fw.describe().contains("SSH closed"), "{}", fw.describe());
        assert!(
            Firewall::new(&Settings::default(), "superbot", 7443, "cp.example").is_err(),
            "a host name says nothing about where botd's calls come from"
        );
        let s = Settings {
            sources: vec!["198.51.100.0/24".into()],
            ssh: vec!["203.0.113.4/32".into()],
        };
        let fw = Firewall::new(&s, "acme", 7000, "cp.example").unwrap();
        assert_eq!(
            fw.rules
                .iter()
                .map(|r| (r.label.as_str(), r.ports.as_str(), r.sources.join(",")))
                .collect::<Vec<_>>(),
            [
                (AGENT_RULE, "7000", "198.51.100.0/24".to_string()),
                (SSH_RULE, "22", "203.0.113.4/32".to_string())
            ]
        );
        assert!(fw.describe().contains("SSH from 203.0.113.4/32"));
    }
}
