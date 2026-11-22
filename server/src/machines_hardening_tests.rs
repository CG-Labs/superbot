//! Machines hardened at first boot (ADR 0126): what the cloud-init user data carries,
//! what botd records of each agent's report, and, as root in a network namespace of its
//! own, that the egress rules keep every uid but root and the OS's daemons off private
//! and metadata addresses, a user made after they loaded included. CI's isolation job
//! runs that last one:
//!
//! ```text
//! sudo SUPERBOT_MACHINE_BOT_USER_TEST=1 <botd tests> --ignored --exact \
//!   machines_hardening_tests::as_root_harness_users_cant_reach_private_addresses_but_root_can
//! ```

use crate::machines::enroll::{self, Enrollment};
use crate::machines::fake::Fake;
use crate::machines::hardening::Settings;
use crate::machines::provider::MachineProvider;
use crate::machines::wire::{self, Hardening, Heartbeat};
use crate::machines::{ControlPlane, upkeep};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::collections::BTreeMap;
use tokio::net::TcpListener;

const AGENT: &str = "stand-in for the superbot-machine binary";

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
}

async fn serve(hardened: bool) -> Env {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mport = listener.local_addr().unwrap().port();
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    let mut e = Enrollment::for_tests(9, mport, 7443).with_agent(AGENT.as_bytes());
    if hardened {
        e = e.with_hardening();
    }
    let e = cp.enroll_with(e).unwrap();
    let cp = Arc::new(cp);
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(listener, app.clone(), e, None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, fake }
}

async fn json_call(env: &Env, method: &str, path: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, "").await;
    (code, parse(&body))
}

async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(env.port, "GET", &format!("/api/audit?action={action}&limit=200"), &env.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn machine_for(env: &Env, email: &str) -> (String, crate::db::Machine) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine")).await;
    assert_eq!(code, 202, "{m}");
    (uid, env.app.db.machine(m["id"].as_str().unwrap()).unwrap())
}

#[tokio::test]
async fn the_first_boot_hardens_before_it_installs_or_enrolls_the_agent() {
    let env = serve(true).await;
    let (_, m) = machine_for(&env, "ada@example.com").await;
    let ud = env.fake.user_data(&m.label).unwrap();
    for path in [
        "/etc/ssh/sshd_config.d/00-superbot-hardening.conf",
        "/etc/sysctl.d/60-superbot-hardening.conf",
        "/etc/apt/apt.conf.d/52superbot-upgrades",
        "/usr/local/lib/superbot/egress",
        "/etc/systemd/system/superbot-egress.service",
    ] {
        assert!(ud.contains(&format!("  - path: {path}\n")), "{path} in {ud}");
    }
    assert!(ud.contains("      PasswordAuthentication no\n"), "{ud}");
    assert!(ud.contains("      Unattended-Upgrade::Automatic-Reboot \"false\";\n"), "{ud}");
    assert!(ud.contains("ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } counter reject"), "{ud}");
    // Hardened, egress rules loaded, then the agent: no Bot runs before the rules do.
    let at = |s: &str| ud.find(s).unwrap_or_else(|| panic!("{s} not in {ud}"));
    let (status, egress, download, enroll, start) = (
        at(": > \"$st\""),
        at("systemctl start superbot-egress.service"),
        at("/v1/agent\""),
        at("\"$bin\" enroll"),
        at("systemctl start superbot-machine\n"),
    );
    assert!(status < egress && egress < download && download < enroll && enroll < start, "{ud}");
    // The steps' own files, not the firstboot's: the token stays in its one entry.
    assert_eq!(ud.matches("sbe_").count(), 1, "{ud}");
    // Every file entry is in write_files, before runcmd.
    let runcmd = at("runcmd:\n");
    assert!(at("/etc/systemd/system/superbot-egress.service") < runcmd);

    // Both scripts are sh that parses.
    for path in ["/usr/local/lib/superbot/firstboot", "/usr/local/lib/superbot/egress"] {
        let script = file_in(&ud, path);
        assert!(script.starts_with("#!/bin/sh\n"), "{path}: {script}");
        let out = std::process::Command::new("sh").args(["-n", "-c", &script]).output().unwrap();
        assert!(out.status.success(), "{path}: {}", String::from_utf8_lossy(&out.stderr));
    }

    let off = serve(false).await;
    let (_, m) = machine_for(&off, "bea@example.com").await;
    let ud = off.fake.user_data(&m.label).unwrap();
    assert!(!ud.contains("hardening") && !ud.contains("superbot-egress"), "MACHINE_HARDENING=off: {ud}");
    assert!(ud.contains("\"$bin\" enroll"), "still enrolls: {ud}");
}

/// The content of the write_files entry for `path`, as it lands on the machine.
fn file_in(ud: &str, path: &str) -> String {
    let at = ud.find(&format!("  - path: {path}\n")).unwrap_or_else(|| panic!("{path} not in {ud}"));
    let body = &ud[at..];
    let start = body.find("    content: |\n").unwrap() + "    content: |\n".len();
    body[start..]
        .lines()
        .take_while(|l| l.starts_with("      ") || l.is_empty())
        .map(|l| format!("{}\n", l.strip_prefix("      ").unwrap_or("")))
        .collect()
}

fn hb(m: &crate::db::Machine, steps: &[(&str, &str)], egress: bool, reboot: bool) -> Heartbeat {
    Heartbeat {
        machine_id: m.id.clone(),
        user_id: m.user_id.clone(),
        version: upkeep::VERSION.into(),
        hardening: Some(Hardening {
            steps: steps.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
            egress,
            reboot_required: reboot,
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn botd_records_each_change_in_a_machines_hardening() {
    let env = serve(true).await;
    let (uid, m) = machine_for(&env, "ada@example.com").await;
    let all_on = [("ssh", wire::HARDENING_ON), ("kernel", wire::HARDENING_PARTIAL), ("updates", wire::HARDENING_ON)];

    // An agent from before says nothing: nothing is recorded.
    upkeep::observe(&env.app, &m.id, &Heartbeat { machine_id: m.id.clone(), user_id: m.user_id.clone(), ..Default::default() });
    assert!(events(&env, "machine.hardened").await.is_empty());

    // Rules not loaded yet: a failure, once, whatever the heartbeats repeat.
    upkeep::observe(&env.app, &m.id, &hb(&m, &all_on, false, false));
    upkeep::observe(&env.app, &m.id, &hb(&m, &all_on, false, false));
    let failed = events(&env, "machine.hardening_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["outcome"], "failure");
    assert_eq!(failed[0]["details"]["failing"], json!(["egress"]));
    assert_eq!(failed[0]["targetId"], m.id.as_str());

    // Loaded: hardened. A container's kernel settings being the host's isn't a failure.
    upkeep::observe(&env.app, &m.id, &hb(&m, &all_on, true, false));
    let done = events(&env, "machine.hardened").await;
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0]["details"]["steps"]["kernel"], "partial");
    assert_eq!(done[0]["details"]["egress"], true);

    // Admins see it on the machine.
    let (code, v) = json_call(&env, "GET", &format!("/api/users/{uid}/machine")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["agentUpkeep"]["hardening"]["egress"], true, "{v}");

    // Updates waiting on a reboot: recorded once.
    upkeep::observe(&env.app, &m.id, &hb(&m, &all_on, true, true));
    upkeep::observe(&env.app, &m.id, &hb(&m, &all_on, true, true));
    assert_eq!(events(&env, "machine.reboot_required").await.len(), 1);

    // Another step fails: recorded again, with what fails now.
    let ssh_failed = [("ssh", wire::HARDENING_FAILED), ("kernel", wire::HARDENING_ON), ("updates", wire::HARDENING_ON)];
    upkeep::observe(&env.app, &m.id, &hb(&m, &ssh_failed, false, true));
    let failed = events(&env, "machine.hardening_failed").await;
    assert_eq!(failed.len(), 2, "{failed:?}");
    assert_eq!(failed[0]["details"]["failing"], json!(["ssh", "egress"]));
    assert_eq!(events(&env, "machine.hardened").await.len(), 1);
}

/// Each probe's answer: refused at once, dropped (no answer, and nothing left by the
/// link), or sent (its SYN left by the link, which no one reads, and no one answered).
const PROBE: &str = r#"
left() { sed -n 's/^ *sb0: */sb0 /p' /proc/net/dev | awk '{ print $11 + $13 }'; }
probe() { # who host port
  if [ "$1" = root ]; then run=""; else run="setpriv --reuid=$1 --regid=$1 --clear-groups"; fi
  before=$(left)
  set +e
  $run timeout 2 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null
  code=$?
  set -e
  if [ $code != 124 ]; then echo refused; elif [ "$(left)" = "$before" ]; then echo dropped; else echo sent; fi
}
"#;

#[test]
#[ignore = "needs root and nft on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
fn as_root_harness_users_cant_reach_private_addresses_but_root_can() {
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: needs SUPERBOT_MACHINE_BOT_USER_TEST=1, root and nft");
        return;
    }
    assert!(crate::machines::runas::is_root(), "run as root");
    let dir = std::env::temp_dir().join(format!("sb-egress-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut s = Settings::default_on();
    s.deny.push("203.0.113.0/24".into());
    let script = dir.join("egress");
    std::fs::write(&script, s.egress_script()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let late = "sbtest-egress-late";

    // A network of its own: a tun link no one reads, with a default route, so an allowed SYN leaves
    // and is dropped, and nothing on the host is touched.
    let scenario = format!(
        r#"set -eu
{PROBE}
ip link set lo up
ip tuntap add mode tun name sb0
ip link set sb0 up
ip addr add 198.18.0.2/24 dev sb0
ip route add default dev sb0
ip -6 addr add 2001:db8::2/64 dev sb0 nodad
ip -6 addr add fe80::2/64 dev sb0 nodad
ip -6 route add default dev sb0
echo "before nobody 10.1.2.3: $(probe 65534 10.1.2.3 80)"
SUPERBOT_HARDENING_STATE={dir} {script}
echo "status: $(cat {dir}/egress)"
for host in 10.1.2.3 169.254.169.254 172.16.0.1 192.168.1.1 100.64.0.1 203.0.113.9 fd00::1 fe80::1%sb0; do
  echo "nobody $host: $(probe 65534 $host 80)"
done
echo "nobody 198.18.0.9: $(probe 65534 198.18.0.9 80)"
echo "nobody 2001:db8::9: $(probe 65534 2001:db8::9 80)"
echo "root 10.1.2.3: $(probe root 10.1.2.3 80)"
echo "root 169.254.169.254: $(probe root 169.254.169.254 80)"
useradd --system --no-create-home --shell /usr/sbin/nologin {late}
echo "late 10.1.2.3: $(probe $(id -u {late}) 10.1.2.3 80)"
echo "late 198.18.0.9: $(probe $(id -u {late}) 198.18.0.9 80)"
userdel {late}
nft list table inet superbot_egress
"#,
        dir = dir.display(),
        script = script.display(),
    );
    let out = std::process::Command::new("unshare").args(["--net", "sh", "-c", &scenario]).output().unwrap();
    let _ = std::process::Command::new("userdel").arg(late).output();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success(), "{text}");
    let said = |line: &str| assert!(text.lines().any(|l| l == line), "expected \"{line}\" in:\n{text}");
    // Controls: the probe tells the two apart, and without the rules nothing is refused.
    said("before nobody 10.1.2.3: sent");
    said("status: on");
    // A link-local reject can't route its ICMP error back, so that SYN is just dropped.
    for host in ["10.1.2.3", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "203.0.113.9", "fd00::1"] {
        said(&format!("nobody {host}: refused"));
    }
    said("nobody fe80::1%sb0: dropped");
    said("nobody 198.18.0.9: sent");
    said("nobody 2001:db8::9: sent");
    said("root 10.1.2.3: sent");
    said("root 169.254.169.254: sent");
    said("late 10.1.2.3: refused");
    said("late 198.18.0.9: sent");
    assert!(text.contains("counter packets"), "{text}");
}
