//! Machines hardened at first boot (ADR 0126). On by default wherever enrollment is
//! (MACHINE_CONTROL_URL); MACHINE_HARDENING=off turns it off for new machines.
//!
//! The first boot, before the agent enrolls:
//! - locks SSH down to root with keys, no forwarding (a drop-in sshd reads first);
//! - sets the kernel's hardening sysctls (a container keeps the host's kernel ones);
//! - turns on unattended security updates, never rebooting by itself;
//! - loads the harness egress rules: every uid but root and the OS's own network
//!   daemons is kept off private, shared and link-local addresses (cloud metadata
//!   included) and MACHINE_EGRESS_DENY. The rules name who may pass, so a Bot's or
//!   teammate's user made later is covered from the moment it exists. A unit loads
//!   them again before the agent on every boot.
//!
//! The agent reports each step in its heartbeat, and botd audits a change.

use super::wire::{self, Hardening};
use std::net::IpAddr;
#[cfg(test)]
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// What harness users can never reach on the machine: the built-in ranges and
    /// MACHINE_EGRESS_DENY, without ranges inside another.
    pub deny: Vec<String>,
}

impl Settings {
    /// MACHINE_HARDENING (`on`, the default, or `off`) and MACHINE_EGRESS_DENY. Only
    /// read where enrollment is on.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let extra = var("MACHINE_EGRESS_DENY");
        match var("MACHINE_HARDENING").trim() {
            "" | "on" => {}
            "off" => {
                if !extra.trim().is_empty() {
                    return Err("MACHINE_EGRESS_DENY needs MACHINE_HARDENING=on".into());
                }
                return Ok(None);
            }
            v => return Err(format!("MACHINE_HARDENING must be on or off, not \"{}\"", crate::audit::clip(v, 20))),
        }
        let mut deny = Settings::default_on().deny;
        for c in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            deny.push(super::firewall::cidr(c).map_err(|e| format!("MACHINE_EGRESS_DENY: {e}"))?);
        }
        Ok(Some(Settings { deny: outermost(deny) }))
    }

    /// The built-in ranges only.
    pub fn default_on() -> Settings {
        Settings { deny: super::incus::PRIVATE.iter().map(|s| s.to_string()).collect() }
    }

    /// The egress script with the deny lists filled in.
    #[cfg(test)]
    pub fn egress_script(&self) -> String {
        self.egress_script_on(None)
    }

    /// The egress script for a machine on its team's network (ADR 0189): `team`, the
    /// subnet, is let through before the deny lists, for every user.
    pub fn egress_script_on(&self, team: Option<&str>) -> String {
        let (v4, v6): (Vec<&str>, Vec<&str>) = self.deny.iter().map(String::as_str).partition(|c| !c.contains(':'));
        let mut lines = String::new();
        if let Some(subnet) = team {
            lines.push_str(&format!("    ip daddr {subnet} accept\n"));
        }
        if !v4.is_empty() {
            lines.push_str(&format!("    ip daddr {{ {} }} counter reject\n", v4.join(", ")));
        }
        if !v6.is_empty() {
            lines.push_str(&format!("    ip6 daddr {{ {} }} counter reject\n", v6.join(", ")));
        }
        EGRESS.replace("{deny}\n", &lines)
    }

    /// Each file the first boot writes for it: path, mode and content. `team`: the
    /// subnet of the team network it is on, if any.
    pub fn files(&self, team: Option<&str>) -> Vec<(&'static str, &'static str, String)> {
        vec![
            (SSH_PATH, "0644", SSH.to_string()),
            (SYSCTL_PATH, "0644", SYSCTL.to_string()),
            (APT_PATH, "0644", APT.to_string()),
            (EGRESS_PATH, "0755", self.egress_script_on(team)),
            (EGRESS_UNIT_PATH, "0644", EGRESS_UNIT.to_string()),
        ]
    }
}

/// `cidrs` without any that another one holds: nft refuses overlapping ranges in a set,
/// and CIDRs either nest or don't meet.
fn outermost(cidrs: Vec<String>) -> Vec<String> {
    let parsed: Vec<(IpAddr, u32)> = cidrs
        .iter()
        .filter_map(|c| {
            let (ip, len) = c.split_once('/')?;
            Some((ip.parse().ok()?, len.parse().ok()?))
        })
        .collect();
    let holds = |(a, al): (IpAddr, u32), (b, bl): (IpAddr, u32)| -> bool {
        if al > bl {
            return false;
        }
        match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl(32 - al).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX.checked_shl(128 - al).unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    };
    let mut out = Vec::new();
    for (i, c) in parsed.iter().enumerate() {
        let inside = parsed.iter().enumerate().any(|(j, o)| j != i && holds(*o, *c) && (o.1 < c.1 || j < i));
        if !inside {
            out.push(cidrs[i].clone());
        }
    }
    out
}

pub const SSH_PATH: &str = "/etc/ssh/sshd_config.d/00-superbot-hardening.conf";
/// sshd keeps the first value it reads for each keyword, and reads its drop-ins before
/// the rest of sshd_config, so this file's `00-` wins. Root with a key is how an
/// operator gets in (`MACHINE_SSH_SOURCES`, ADR 0035); no Bot's or teammate's user ever
/// logs in over SSH.
pub const SSH: &str = "# SuperBot (ADR 0126). Read first, so these win.
PermitRootLogin prohibit-password
AllowUsers root
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
";

pub const SYSCTL_PATH: &str = "/etc/sysctl.d/60-superbot-hardening.conf";
pub const SYSCTL: &str = "# SuperBot (ADR 0126). In a container the kernel.* ones are the host's.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
kernel.sysrq = 0
net.core.bpf_jit_harden = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
";

pub const APT_PATH: &str = "/etc/apt/apt.conf.d/52superbot-upgrades";
/// After the packages' own `20auto-upgrades`, so these win. The origins stay the
/// distribution's default, its security updates. A reboot would end Bots' runs, so it
/// is left to the operator; the agent reports one is waiting.
pub const APT: &str = "// SuperBot (ADR 0126).
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
Unattended-Upgrade::Automatic-Reboot \"false\";
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";
";

pub const EGRESS_PATH: &str = super::team_rules::EGRESS_SCRIPT;
/// Loads the egress rules. Root and the OS's network daemons (DNS, DHCP, time, apt)
/// pass; everyone else, the Bots' and teammates' users included, can't reach the deny
/// lists. Loopback stays open, so Bots still reach botd through the agent, and so do
/// the resolvers in resolv.conf on port 53, so names still resolve where the resolver
/// is on a private address. Run as root, at first boot and by the unit at every boot.
/// SUPERBOT_HARDENING_STATE moves its status file, for tests.
const EGRESS: &str = r#"#!/bin/sh
# SuperBot harness egress rules (ADR 0126).
set -u
state=${SUPERBOT_HARDENING_STATE:-/run/superbot-hardening}
mkdir -p -m 0755 "$state"
rm -f "$state/egress"
uids=0
for u in systemd-resolve systemd-network systemd-timesync _apt _chrony chrony ntp ntpsec; do
  if id=$(id -u "$u" 2>/dev/null); then uids="$uids, $id"; fi
done
dns4=
dns6=
for ns in $(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null); do
  case $ns in
    *[!0-9a-fA-F:.%]*) ;;
    *:*) dns6="$dns6${dns6:+, }${ns%%\%*}" ;;
    *.*) dns4="$dns4${dns4:+, }$ns" ;;
  esac
done
rules=$(mktemp) || exit 1
trap 'rm -f "$rules"' EXIT
{
  echo "table inet superbot_egress"
  echo "delete table inet superbot_egress"
  echo "table inet superbot_egress {"
  echo "  chain output {"
  echo "    type filter hook output priority filter; policy accept;"
  echo "    oif \"lo\" accept"
  echo "    meta skuid { $uids } accept"
  if [ -n "$dns4" ]; then echo "    ip daddr { $dns4 } meta l4proto { tcp, udp } th dport 53 accept"; fi
  if [ -n "$dns6" ]; then echo "    ip6 daddr { $dns6 } meta l4proto { tcp, udp } th dport 53 accept"; fi
  cat <<'DENY'
{deny}
DENY
  echo "  }"
  echo "}"
} > "$rules"
if nft -f "$rules"; then
  echo on > "$state/egress"
  echo "superbot: harness egress rules loaded"
else
  echo failed > "$state/egress"
  echo "superbot: harness egress rules didn't load" >&2
  exit 1
fi
"#;

pub const EGRESS_UNIT_PATH: &str = "/etc/systemd/system/superbot-egress.service";
const EGRESS_UNIT: &str = "[Unit]
Description=SuperBot harness egress rules
After=network-online.target
Wants=network-online.target
Before=superbot-machine.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/superbot/egress

[Install]
WantedBy=multi-user.target superbot-machine.service
";

/// The first boot's hardening, before it installs the agent: each step's outcome goes
/// to the status file, and none of them stops the machine from enrolling. Packages
/// it needs are installed only if missing.
pub const FIRSTBOOT: &str = r#"st=/etc/superbot/hardening
: > "$st"
need=
command -v nft >/dev/null 2>&1 || need="$need nftables"
command -v unattended-upgrade >/dev/null 2>&1 || need="$need unattended-upgrades"
if [ -n "$need" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null &&
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq $need >/dev/null ||
    echo "superbot: couldn't install$need" >&2
fi
if [ ! -x /usr/sbin/sshd ]; then
  echo ssh=none >> "$st"
elif /usr/sbin/sshd -t && /usr/sbin/sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'; then
  # A running sshd keeps its old settings until it reloads; one not running yet (socket
  # activation) reads the file when it starts.
  svc=
  for u in ssh sshd; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then svc=$u; break; fi
  done
  if [ -z "$svc" ] || systemctl reload "$svc" >/dev/null 2>&1; then
    echo ssh=on >> "$st"
  else
    echo ssh=failed >> "$st"
  fi
else
  rm -f /etc/ssh/sshd_config.d/00-superbot-hardening.conf
  echo ssh=failed >> "$st"
fi
if sysctl -q -p /etc/sysctl.d/60-superbot-hardening.conf >/dev/null 2>&1; then
  echo kernel=on >> "$st"
else
  echo kernel=partial >> "$st"
fi
if command -v unattended-upgrade >/dev/null 2>&1 &&
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1; then
  echo updates=on >> "$st"
else
  echo updates=failed >> "$st"
fi
systemctl daemon-reload
systemctl enable superbot-egress.service >/dev/null 2>&1 || true
systemctl start superbot-egress.service || true
"#;

/// Records what a heartbeat says of a machine's hardening, once per change:
/// `machine.hardened` when every step is done, `machine.hardening_failed` when a step
/// failed or the egress rules aren't loaded (again when what fails changes), and
/// `machine.reboot_required` when updates start waiting on a reboot.
pub fn observed(app: &crate::runner::App, m: &crate::db::Machine, by: &crate::audit::Who, old: Option<&serde_json::Value>, new: &serde_json::Value) {
    use crate::audit::Outcome;
    use serde_json::json;
    let parse = |v: &serde_json::Value| serde_json::from_value::<Hardening>(v.clone()).ok();
    let Some(now) = parse(new) else { return };
    let was = old.and_then(parse);
    let fails = failing(&now);
    let failed_before = was.as_ref().map(failing);
    let d = || json!({ "steps": now.steps, "egress": now.egress, "rebootRequired": now.reboot_required });
    if fails.is_empty() {
        if failed_before.as_ref().is_none_or(|f| !f.is_empty()) {
            app.db.record(&super::event(by, "machine.hardened", m, d()));
        }
    } else if failed_before.as_ref() != Some(&fails) {
        let mut d = d();
        d["failing"] = json!(fails);
        app.db.record(&super::event(by, "machine.hardening_failed", m, d).outcome(Outcome::Failure));
    }
    if now.reboot_required && !was.as_ref().is_some_and(|w| w.reboot_required) {
        app.db.record(&super::event(by, "machine.reboot_required", m, d()));
    }
}

/// The steps every hardened first boot reports.
pub const REQUIRED: [&str; 3] = ["ssh", "kernel", "updates"];

/// The steps that aren't done, `egress` among them when its rules aren't loaded.
/// A step the first boot must report, missing or in a state botd doesn't know, isn't
/// done either: an incomplete report never counts as hardened.
pub fn failing(h: &Hardening) -> Vec<String> {
    let done = |v: &str| [wire::HARDENING_ON, wire::HARDENING_PARTIAL, wire::HARDENING_NONE].contains(&v);
    let mut out: Vec<String> = REQUIRED
        .iter()
        .filter(|k| !h.steps.get(**k).is_some_and(|v| done(v)))
        .map(|k| k.to_string())
        .collect();
    out.extend(
        h.steps
            .iter()
            .filter(|(k, v)| !REQUIRED.contains(&k.as_str()) && !done(v))
            .map(|(k, _)| k.clone()),
    );
    if !h.egress {
        out.push("egress".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    #[test]
    fn on_by_default_off_by_choice() {
        let s = Settings::from_env(&env(&[])).unwrap().unwrap();
        assert_eq!(s, Settings::default_on());
        assert!(s.deny.iter().any(|c| c == "169.254.0.0/16"), "cloud metadata: {:?}", s.deny);
        assert_eq!(Settings::from_env(&env(&[("MACHINE_HARDENING", "on")])).unwrap(), Some(Settings::default_on()));
        assert_eq!(Settings::from_env(&env(&[("MACHINE_HARDENING", "off")])).unwrap(), None);
        let e = Settings::from_env(&env(&[("MACHINE_HARDENING", "yes")])).unwrap_err();
        assert!(e.contains("on or off"), "{e}");
        let e = Settings::from_env(&env(&[("MACHINE_HARDENING", "off"), ("MACHINE_EGRESS_DENY", "203.0.113.0/24")])).unwrap_err();
        assert!(e.contains("needs MACHINE_HARDENING=on"), "{e}");
    }

    #[test]
    fn extra_denials_are_checked_and_nested_ranges_dropped() {
        let s = Settings::from_env(&env(&[("MACHINE_EGRESS_DENY", "203.0.113.0/24, 10.1.0.0/16, 2001:db8::/32, 203.0.113.7")]))
            .unwrap()
            .unwrap();
        assert!(s.deny.contains(&"203.0.113.0/24".to_string()) && s.deny.contains(&"2001:db8::/32".to_string()), "{:?}", s.deny);
        assert!(!s.deny.iter().any(|c| c == "10.1.0.0/16" || c == "203.0.113.7/32"), "inside another: {:?}", s.deny);
        let e = Settings::from_env(&env(&[("MACHINE_EGRESS_DENY", "10.0.0.1/8")])).unwrap_err();
        assert!(e.starts_with("MACHINE_EGRESS_DENY:") && e.contains("bits set"), "{e}");
        let e = Settings::from_env(&env(&[("MACHINE_EGRESS_DENY", "evil.example")])).unwrap_err();
        assert!(e.contains("isn't an IP address"), "{e}");
        // The same range twice is kept once.
        let s = Settings::from_env(&env(&[("MACHINE_EGRESS_DENY", "198.51.100.0/24,198.51.100.0/24")])).unwrap().unwrap();
        assert_eq!(s.deny.iter().filter(|c| *c == "198.51.100.0/24").count(), 1, "{:?}", s.deny);
    }

    #[test]
    fn the_egress_script_names_who_passes_and_denies_the_rest() {
        let mut s = Settings::default_on();
        s.deny.push("203.0.113.0/24".into());
        let script = s.egress_script();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(!script.contains("{deny}"), "{script}");
        assert!(script.contains("    ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 203.0.113.0/24 } counter reject\n"), "{script}");
        assert!(script.contains("    ip6 daddr { fc00::/7, fe80::/10 } counter reject\n"), "{script}");
        // Only root and the OS's daemons by name; loopback first, so the agent's relay works.
        let lo = script.find("oif \\\"lo\\\" accept").unwrap();
        let uids = script.find("meta skuid { $uids } accept").unwrap();
        let deny = script.find("counter reject").unwrap();
        assert!(lo < uids && uids < deny, "{script}");
        assert!(script.contains("uids=0\n"), "{script}");
        assert!(!script.contains("superbot-bots") && !script.contains("superbot-t-"), "harness users never pass by name");
        // Only v6 extras: no empty v4 set.
        let s = Settings { deny: vec!["fc00::/7".into()] };
        let script = s.egress_script();
        assert!(!script.lines().any(|l| l.starts_with("    ip daddr {") && l.ends_with("counter reject")), "{script}");
        assert!(script.contains("    ip6 daddr { fc00::/7 } counter reject\n"), "{script}");
    }

    #[test]
    fn a_machine_on_its_teams_network_lets_everyone_reach_that_subnet_and_no_more() {
        let s = Settings::default_on();
        let script = s.egress_script_on(Some("10.248.0.0/22"));
        let team = script.find("    ip daddr 10.248.0.0/22 accept\n").expect(&script);
        assert!(team < script.find("counter reject").unwrap(), "before the deny lists: {script}");
        assert!(script.contains("10.0.0.0/8"), "the rest of 10/8 still denied");
        assert!(!s.egress_script().contains("10.248.0.0/22"), "off its team's network, nothing let through");
        let files = s.files(Some("10.248.0.0/22"));
        assert!(files.iter().any(|(p, _, c)| *p == EGRESS_PATH && c.contains("10.248.0.0/22 accept")));
        assert!(!s.files(None).iter().any(|(_, _, c)| c.contains("10.248.0.0/22")));
    }

    #[test]
    fn an_agent_edits_the_script_into_the_one_a_first_boot_on_the_network_writes() {
        use super::super::team_rules::{subnet_in, with_subnet};
        let mut s = Settings::default_on();
        s.deny.push("203.0.113.0/24".into());
        for deny in [s.deny.clone(), vec!["fc00::/7".into()], vec![]] {
            let s = Settings { deny };
            let (off, on) = (s.egress_script(), s.egress_script_on(Some("10.248.0.0/22")));
            assert_eq!(with_subnet(&off, Some("10.248.0.0/22")).as_deref(), Some(on.as_str()), "joining");
            assert_eq!(with_subnet(&on, None).as_deref(), Some(off.as_str()), "leaving");
            assert_eq!(with_subnet(&on, Some("172.20.0.0/16")), Some(s.egress_script_on(Some("172.20.0.0/16"))), "another team's");
            assert_eq!((subnet_in(&off), subnet_in(&on).as_deref()), (None, Some("10.248.0.0/22")));
        }
    }

    #[test]
    fn ssh_is_keys_and_root_only() {
        // A running sshd that won't reload keeps its old settings: that is a failure.
        let ssh = &FIRSTBOOT[FIRSTBOOT.find("elif /usr/sbin/sshd -t").unwrap()..FIRSTBOOT.find("if sysctl").unwrap()];
        assert!(!ssh.contains("|| true"), "{ssh}");
        let reload = ssh.find("systemctl reload \"$svc\"").unwrap();
        assert!(ssh[reload..].find("ssh=failed").unwrap() < ssh[reload..].find("\nelse\n  rm -f").unwrap(), "{ssh}");
        for line in ["PermitRootLogin prohibit-password", "AllowUsers root", "PasswordAuthentication no", "AllowTcpForwarding no", "X11Forwarding no"] {
            assert!(SSH.lines().any(|l| l == line), "{line}");
        }
        assert!(SSH_PATH.rsplit('/').next().unwrap().starts_with("00-"), "read first");
        assert!(APT.contains("Automatic-Reboot \"false\""));
        assert!(EGRESS_UNIT.contains("Before=superbot-machine.service"));
    }

    #[test]
    fn failing_steps_include_unloaded_egress() {
        let mut h = Hardening { steps: BTreeMap::new(), egress: false, reboot_required: false };
        h.steps.insert("ssh".into(), wire::HARDENING_ON.into());
        h.steps.insert("kernel".into(), wire::HARDENING_PARTIAL.into());
        h.steps.insert("updates".into(), wire::HARDENING_FAILED.into());
        assert_eq!(failing(&h), vec!["updates".to_string(), "egress".to_string()]);
        h.steps.insert("updates".into(), wire::HARDENING_ON.into());
        h.egress = true;
        assert!(failing(&h).is_empty());
        // Incomplete or unknown reports are never hardened.
        h.steps.remove("kernel");
        h.steps.insert("ssh".into(), "maybe".into());
        assert_eq!(failing(&h), vec!["ssh".to_string(), "kernel".to_string()]);
        let empty = Hardening { steps: BTreeMap::new(), egress: true, reboot_required: false };
        assert_eq!(failing(&empty), vec!["ssh".to_string(), "kernel".to_string(), "updates".to_string()]);
        h.steps.insert("kernel".into(), wire::HARDENING_ON.into());
        h.steps.insert("ssh".into(), wire::HARDENING_NONE.into());
        h.steps.insert("extra".into(), "odd".into());
        assert_eq!(failing(&h), vec!["extra".to_string()]);
    }
}
