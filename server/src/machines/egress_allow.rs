//! Outbound allow-lists on a user's machine (ADR 0135). With an allow-list, every uid
//! but root and the OS's network daemons (the same as the deny rules of ADR 0126) may
//! reach only the list's hosts and CIDRs, and the resolvers on port 53. It is a table
//! of its own, `inet superbot_allow`, beside the deny rules' `inet superbot_egress`: a
//! packet has to pass both, so a listed address that the deny rules hold (a private
//! range, cloud metadata) stays closed.
//!
//! Hosts are resolved by the agent, as root, when the list arrives and every few
//! minutes after, so the rules follow their addresses. A host that doesn't resolve
//! adds nothing until it does. Shared by both binaries: botd checks entries with the
//! same rules the agent loads them with.

#![allow(dead_code)]

use super::wire::{EGRESS_ALLOW_LIST, EGRESS_MAX_ADDRESSES_PER_HOST, EGRESS_MAX_ENTRIES, EGRESS_OPEN};
use std::net::IpAddr;

pub const TABLE: &str = "superbot_allow";
/// The OS's network daemons that pass, as the deny rules' script names them.
pub const DAEMONS: [&str; 8] = ["systemd-resolve", "systemd-network", "systemd-timesync", "_apt", "_chrony", "chrony", "ntp", "ntpsec"];

/// One allow-list entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entry {
    /// A network's own address and prefix, e.g. `203.0.113.0/24`; an address alone is
    /// its /32 or /128.
    Net(String),
    /// A host name, lower-case, resolved on the machine.
    Host(String),
}

impl Entry {
    pub fn as_str(&self) -> &str {
        match self {
            Entry::Net(s) | Entry::Host(s) => s,
        }
    }
}

/// `s` as an entry: an IP address, a CIDR with no host bits set, or a plain host name
/// (letters, digits and hyphens between dots, with at least one dot). No wildcards, no
/// ports, no URLs.
pub fn entry(s: &str) -> Result<Entry, String> {
    let s = s.trim();
    let shown = || s.chars().take(60).collect::<String>();
    if s.is_empty() {
        return Err("an entry is empty".into());
    }
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (s, None),
    };
    if let Ok(addr) = ip.parse::<IpAddr>() {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len: u32 = match len {
            None => max,
            Some(l) => l.parse().ok().filter(|l| *l <= max).ok_or_else(|| format!("\"{}\": the prefix must be 0 to {max}", shown()))?,
        };
        let net = match addr {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
                IpAddr::from((u32::from(a) & mask).to_be_bytes())
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
                IpAddr::from((u128::from(a) & mask).to_be_bytes())
            }
        };
        if net != addr {
            return Err(format!("\"{}\" has host bits set: write {net}/{len}", shown()));
        }
        if len == 0 {
            return Err(format!("\"{}\" is the whole internet: use mode open instead", shown()));
        }
        return Ok(Entry::Net(format!("{net}/{len}")));
    }
    if len.is_some() {
        return Err(format!("\"{}\" isn't an IP address or CIDR", shown()));
    }
    let host = s.trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if host.len() > 253 || !host.contains('.') || !host.split('.').all(label_ok) || host.split('.').next_back().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())) {
        return Err(format!("\"{}\" isn't a host name, IP address or CIDR (no wildcards, ports or URLs)", shown()));
    }
    Ok(Entry::Host(host))
}

/// A whole list, checked, sorted, each entry once.
pub fn entries(list: &[String]) -> Result<Vec<Entry>, String> {
    if list.len() > EGRESS_MAX_ENTRIES {
        return Err(format!("an allow-list has at most {EGRESS_MAX_ENTRIES} entries"));
    }
    let mut out = list.iter().map(|s| entry(s)).collect::<Result<Vec<_>, _>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn mode_ok(mode: &str) -> bool {
    mode == EGRESS_OPEN || mode == EGRESS_ALLOW_LIST
}

/// Who and what passes whatever the list says: these uids, and port 53 to these
/// resolvers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exempt {
    pub uids: Vec<u32>,
    pub dns4: Vec<String>,
    pub dns6: Vec<String>,
}

/// The resolvers in a resolv.conf, as the deny rules' script reads them.
pub fn resolvers(resolv_conf: &str) -> (Vec<String>, Vec<String>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for l in resolv_conf.lines() {
        let mut w = l.split_whitespace();
        if w.next() != Some("nameserver") {
            continue;
        }
        let Some(ns) = w.next() else { continue };
        match ns.split('%').next().unwrap_or("").parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => v4.push(a.to_string()),
            Ok(IpAddr::V6(a)) => v6.push(a.to_string()),
            Err(_) => {}
        }
    }
    (v4, v6)
}

/// The nft script for an allow-list of `addrs` (CIDRs, hosts already resolved). It
/// replaces the table whole, in one transaction, so there is never a moment without it.
pub fn rules(ex: &Exempt, addrs: &[String]) -> String {
    let (v4, v6): (Vec<&str>, Vec<&str>) = addrs.iter().map(String::as_str).partition(|a| !a.contains(':'));
    let set = |name: &str, ty: &str, items: &[&str]| {
        let elements = if items.is_empty() { String::new() } else { format!(" elements = {{ {} }};", items.join(", ")) };
        format!("  set {name} {{ type {ty}; flags interval; auto-merge;{elements} }}\n")
    };
    let mut uids: Vec<String> = std::iter::once(0).chain(ex.uids.iter().copied()).map(|u| u.to_string()).collect();
    uids.sort_by_key(|u| u.parse::<u32>().unwrap_or(0));
    uids.dedup();
    let mut s = format!("table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    s.push_str(&set("allow4", "ipv4_addr", &v4));
    s.push_str(&set("allow6", "ipv6_addr", &v6));
    s.push_str("  chain output {\n    type filter hook output priority filter; policy accept;\n    oif \"lo\" accept\n");
    s.push_str(&format!("    meta skuid {{ {} }} accept\n", uids.join(", ")));
    if !ex.dns4.is_empty() {
        s.push_str(&format!("    ip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n", ex.dns4.join(", ")));
    }
    if !ex.dns6.is_empty() {
        s.push_str(&format!("    ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n", ex.dns6.join(", ")));
    }
    s.push_str("    ip daddr @allow4 accept\n    ip6 daddr @allow6 accept\n    counter reject\n  }\n}\n");
    s
}

/// The nft script that removes the table, whether or not it is there.
pub fn removal() -> String {
    format!("table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Runs `nft -f -` with `script`.
pub fn load(nft: &std::path::Path, script: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = std::process::Command::new(nft)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft didn't start: {e}"))?;
    child.stdin.take().ok_or("no stdin")?.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("nft refused the rules: {}", err.trim().lines().last().unwrap_or("no reason given")))
    }
}

/// `list`'s addresses: its CIDRs, and each host's addresses from `resolve` (at most
/// `EGRESS_MAX_ADDRESSES_PER_HOST` each, as /32 or /128). Also the hosts that gave none.
pub async fn addresses<F, Fut>(list: &[Entry], resolve: F) -> (Vec<String>, Vec<String>)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Vec<IpAddr>>,
{
    let (mut out, mut unresolved) = (Vec::new(), Vec::new());
    for e in list {
        match e {
            Entry::Net(n) => out.push(n.clone()),
            Entry::Host(h) => {
                let mut ips = resolve(h.clone()).await;
                ips.sort();
                ips.dedup();
                if ips.is_empty() {
                    unresolved.push(h.clone());
                }
                for ip in ips.into_iter().take(EGRESS_MAX_ADDRESSES_PER_HOST) {
                    out.push(match ip {
                        IpAddr::V4(a) => format!("{a}/32"),
                        IpAddr::V6(a) => format!("{a}/128"),
                    });
                }
            }
        }
    }
    out.sort();
    out.dedup();
    (out, unresolved)
}

/// The system resolver's addresses for `host`, or none within a few seconds.
pub async fn system_resolve(host: String) -> Vec<IpAddr> {
    let look = tokio::net::lookup_host((host, 443));
    match tokio::time::timeout(std::time::Duration::from_secs(5), look).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_hosts_addresses_or_networks() {
        assert_eq!(entry(" API.Anthropic.com. ").unwrap(), Entry::Host("api.anthropic.com".into()));
        assert_eq!(entry("203.0.113.7").unwrap(), Entry::Net("203.0.113.7/32".into()));
        assert_eq!(entry("2001:db8::/32").unwrap(), Entry::Net("2001:db8::/32".into()));
        assert_eq!(entry("2001:db8::1").unwrap(), Entry::Net("2001:db8::1/128".into()));
        for bad in ["", "*.example.com", "https://example.com", "example.com:443", "localhost", "10.0.0.1/8", "0.0.0.0/0", "::/0", "1.2.3.4/33", "-a.example.com", "a..b", "1.2.3.999", "ex ample.com", "host/24"] {
            assert!(entry(bad).is_err(), "{bad:?}");
        }
        assert!(entry("10.0.0.1/8").unwrap_err().contains("10.0.0.0/8"));
        let list: Vec<String> = ["b.example.com", "a.example.com", "b.example.com", "198.51.100.0/24"].map(String::from).to_vec();
        assert_eq!(
            entries(&list).unwrap(),
            vec![Entry::Net("198.51.100.0/24".into()), Entry::Host("a.example.com".into()), Entry::Host("b.example.com".into())]
        );
        assert!(entries(&vec!["a.example.com".to_string(); EGRESS_MAX_ENTRIES + 1]).is_err());
    }

    #[test]
    fn the_rules_pass_the_exempt_then_the_list_and_reject_the_rest() {
        let (dns4, dns6) = resolvers("# x\nnameserver 10.0.0.2\nnameserver fe80::1%eth0\nnameserver bogus\nsearch lan\n");
        assert_eq!((dns4.clone(), dns6.clone()), (vec!["10.0.0.2".to_string()], vec!["fe80::1".to_string()]));
        let ex = Exempt { uids: vec![101, 0], dns4, dns6 };
        let r = rules(&ex, &["203.0.113.0/24".into(), "2001:db8::1/128".into(), "198.51.100.7/32".into()]);
        assert!(r.starts_with("table inet superbot_allow\ndelete table inet superbot_allow\n"), "{r}");
        assert!(r.contains("set allow4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.0/24, 198.51.100.7/32 }; }"), "{r}");
        assert!(r.contains("elements = { 2001:db8::1/128 }"), "{r}");
        assert!(r.contains("meta skuid { 0, 101 } accept"), "{r}");
        let at = |s: &str| r.find(s).unwrap_or_else(|| panic!("{s} in {r}"));
        assert!(at("oif \"lo\" accept") < at("meta skuid") && at("meta skuid") < at("th dport 53") && at("th dport 53") < at("@allow4") && at("@allow6") < at("counter reject"), "{r}");
        assert!(!r.contains("superbot-bots") && !r.contains("superbot-t-"), "harness users never pass by name");
        // Nothing listed: empty sets, so only the exempt pass.
        let r = rules(&Exempt::default(), &[]);
        assert!(r.contains("set allow4 { type ipv4_addr; flags interval; auto-merge; }") && !r.contains("dport 53"), "{r}");
    }

    #[tokio::test]
    async fn hosts_resolve_to_their_addresses_and_unknown_ones_add_nothing() {
        let list = entries(&["api.example.com".into(), "gone.example.com".into(), "198.51.100.0/24".into()]).unwrap();
        let (addrs, unresolved) = addresses(&list, |h: String| async move {
            match h.as_str() {
                "api.example.com" => vec!["203.0.113.5".parse().unwrap(), "2001:db8::5".parse().unwrap(), "203.0.113.5".parse().unwrap()],
                _ => vec![],
            }
        })
        .await;
        assert_eq!(addrs, ["198.51.100.0/24", "2001:db8::5/128", "203.0.113.5/32"]);
        assert_eq!(unresolved, ["gone.example.com"]);
    }
}
