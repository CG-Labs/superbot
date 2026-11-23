//! A team network's subnet in a machine's harness egress rules (ADR 0202). The first
//! boot writes those rules as a script (ADR 0126) that the unit loads again on every
//! boot; a machine on its team's network (ADR 0189) has one `ip daddr <subnet> accept`
//! line before the deny lists. A machine that joins its team's network later, or whose
//! owner leaves the team, gets that line put in or taken out by its agent, which then
//! loads the script again. Shared by both binaries: botd's tests check that the script
//! this edits is exactly the one the first boot would have written.

#![allow(dead_code)]

use std::net::Ipv4Addr;

/// Where the first boot writes the egress script.
pub const EGRESS_SCRIPT: &str = "/usr/local/lib/superbot/egress";

/// Where the deny lists sit in the script: a quoted heredoc, so nothing in it expands.
const OPEN: &str = "  cat <<'DENY'\n";
const CLOSE: &str = "DENY\n";
const INDENT: &str = "    ";

/// Where a team subnet may be: RFC 1918.
const PRIVATE: [(Ipv4Addr, u8); 3] = [(Ipv4Addr::new(10, 0, 0, 0), 8), (Ipv4Addr::new(172, 16, 0, 0), 12), (Ipv4Addr::new(192, 168, 0, 0), 16)];
/// The longest prefix a team subnet has (Linode's smallest subnet, a /29).
const LONGEST: u8 = 29;

fn mask(len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

/// `s` as a team subnet, canonical: an IPv4 network with no host bits set, inside
/// RFC 1918, no smaller than a /29. Anything else is refused, so nothing but a CIDR
/// ever reaches the script.
pub fn subnet(s: &str) -> Result<String, String> {
    let shown = || s.chars().take(40).collect::<String>();
    let (ip, len) = s.trim().split_once('/').ok_or_else(|| format!("\"{}\" isn't a CIDR", shown()))?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| format!("\"{}\" isn't an IPv4 CIDR", shown()))?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 32).ok_or_else(|| format!("\"{}\" has no prefix length", shown()))?;
    if u32::from(ip) & !mask(len) != 0 {
        return Err(format!("\"{}\" has host bits set", shown()));
    }
    if len > LONGEST {
        return Err(format!("\"{}\" is smaller than a /{LONGEST}", shown()));
    }
    let inside = PRIVATE.iter().any(|(net, plen)| len >= *plen && u32::from(ip) & mask(*plen) == u32::from(*net));
    if !inside {
        return Err(format!("\"{}\" isn't inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16", shown()));
    }
    Ok(format!("{ip}/{len}"))
}

/// The line that lets `subnet` through.
pub fn accept_line(subnet: &str) -> String {
    format!("{INDENT}ip daddr {subnet} accept\n")
}

/// The subnet a line lets through, if it is a team subnet's accept line.
fn accepted(line: &str) -> Option<String> {
    let rest = line.strip_prefix(INDENT)?.strip_prefix("ip daddr ")?.strip_suffix(" accept")?;
    subnet(rest).ok().filter(|s| s == rest)
}

/// The deny lists' heredoc in `script`: where its body starts and ends.
fn body(script: &str) -> Option<(usize, usize)> {
    let start = script.find(OPEN)? + OPEN.len();
    let end = start + script[start..].find(&format!("\n{CLOSE}")).map(|i| i + 1).or_else(|| script[start..].starts_with(CLOSE).then_some(0))?;
    Some((start, end))
}

/// The team subnet `script` lets through, if any. None also when it isn't an egress
/// script of ours.
pub fn subnet_in(script: &str) -> Option<String> {
    let (start, end) = body(script)?;
    script[start..end].lines().find_map(accepted)
}

/// Whether `script` is an egress script this can edit.
pub fn editable(script: &str) -> bool {
    body(script).is_some()
}

/// `script` letting `subnet` through, and no other team subnet: the line goes first in
/// the deny lists' heredoc, before every deny. None if `script` isn't one of ours.
pub fn with_subnet(script: &str, subnet: Option<&str>) -> Option<String> {
    let (start, end) = body(script)?;
    let mut lines: String = subnet.map(accept_line).unwrap_or_default();
    for l in script[start..end].split_inclusive('\n') {
        if accepted(l.trim_end_matches('\n')).is_none() {
            lines.push_str(l);
        }
    }
    Some(format!("{}{lines}{}", &script[..start], &script[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "#!/bin/sh\n{\n  cat <<'DENY'\n    ip daddr { 10.0.0.0/8 } counter reject\n    ip6 daddr { fc00::/7 } counter reject\nDENY\n  echo \"  }\"\n} > \"$rules\"\n";

    #[test]
    fn only_private_ipv4_networks_are_team_subnets() {
        assert_eq!(subnet("10.248.0.0/22").unwrap(), "10.248.0.0/22");
        assert_eq!(subnet(" 172.20.0.0/16 ").unwrap(), "172.20.0.0/16");
        assert_eq!(subnet("192.168.4.0/24").unwrap(), "192.168.4.0/24");
        for (bad, why) in [
            ("10.248.0.1/22", "host bits"),
            ("10.248.0.0", "isn't a CIDR"),
            ("10.248.0.0/33", "prefix"),
            ("10.248.0.0/30", "smaller"),
            ("203.0.113.0/24", "isn't inside"),
            ("172.32.0.0/16", "isn't inside"),
            ("0.0.0.0/0", "isn't inside"),
            ("fd00::/64", "IPv4"),
            ("10.0.0.0/8 accept\nDENY\nreboot\n", "prefix"),
            ("10.0.0.0\nDENY\n/8", "isn't an IPv4"),
            ("10.0.0.0/8\nDENY", "prefix"),
        ] {
            let e = subnet(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn a_subnet_goes_first_in_the_deny_lists_and_only_one() {
        assert_eq!(subnet_in(SCRIPT), None);
        let on = with_subnet(SCRIPT, Some("10.248.0.0/22")).unwrap();
        assert!(on.contains("  cat <<'DENY'\n    ip daddr 10.248.0.0/22 accept\n    ip daddr { 10.0.0.0/8 } counter reject\n"), "{on}");
        assert_eq!(subnet_in(&on).as_deref(), Some("10.248.0.0/22"));
        // Another replaces it; none takes it out; the rest is as it was.
        let moved = with_subnet(&on, Some("172.20.0.0/16")).unwrap();
        assert_eq!(subnet_in(&moved).as_deref(), Some("172.20.0.0/16"));
        assert_eq!(moved.matches(" accept\n").count(), 1, "{moved}");
        assert_eq!(with_subnet(&moved, None).unwrap(), SCRIPT);
        assert_eq!(with_subnet(SCRIPT, None).unwrap(), SCRIPT);
        assert_eq!(with_subnet(&on, Some("10.248.0.0/22")).unwrap(), on, "the same again changes nothing");
    }

    #[test]
    fn scripts_that_arent_ours_are_left_alone() {
        for s in ["", "#!/bin/sh\nnft -f /etc/nftables.conf\n", "  cat <<'DENY'\n    ip daddr 10.248.0.0/22 accept\n"] {
            assert!(!editable(s) && with_subnet(s, Some("10.248.0.0/22")).is_none() && subnet_in(s).is_none(), "{s:?}");
        }
        // Lines outside the heredoc, or not exactly an accept line, are never read as one.
        let odd = SCRIPT.replace("#!/bin/sh\n", "#!/bin/sh\n    ip daddr 10.9.0.0/16 accept\n").replace("DENY\n  echo", "    ip daddr 10.7.0.0/16 accept # x\nDENY\n  echo");
        assert_eq!(subnet_in(&odd), None, "{odd}");
        assert!(with_subnet(&odd, None).unwrap().contains("10.7.0.0/16 accept # x"), "kept: not ours");
    }
}
