//! Machines hardened at first boot (ADR 0126): what the cloud-init user data carries,
//! what botd records of each agent's report, and, as root in a network namespace of its
//! own, that the egress rules keep every uid but root and the OS's daemons off private
//! and metadata addresses, a user made after they loaded included. Then ADR 0135's: an
//! allow-list lets them reach only its entries, and each run is held to its limits in a
//! cgroup of its own. CI's isolation job runs those three as root:
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

#[test]
#[ignore = "needs root and nft on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
fn as_root_an_allow_list_lets_harness_users_reach_only_its_entries() {
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: needs SUPERBOT_MACHINE_BOT_USER_TEST=1, root and nft");
        return;
    }
    use crate::machines::egress_allow::{self, Exempt};
    assert!(crate::machines::runas::is_root(), "run as root");
    let dir = std::env::temp_dir().join(format!("sb-allow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("egress");
    std::fs::write(&script, Settings::default_on().egress_script()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Listed: one public address, one network, and a private address ADR 0126 denies anyway.
    let list = egress_allow::entries(&["198.18.0.9".into(), "198.18.1.0/24".into(), "10.1.2.3".into(), "2001:db8::9".into()]).unwrap();
    let addrs: Vec<String> = list.iter().map(|e| e.as_str().to_string()).collect();
    std::fs::write(dir.join("allow.nft"), egress_allow::rules(&Exempt::default(), &addrs)).unwrap();
    std::fs::write(dir.join("open.nft"), egress_allow::removal()).unwrap();
    let late = "sbtest-allow-late";

    let scenario = format!(
        r#"set -eu
{PROBE}
ip link set lo up
ip tuntap add mode tun name sb0
ip link set sb0 up
ip addr add 198.18.0.2/24 dev sb0
ip route add default dev sb0
ip -6 addr add 2001:db8::2/64 dev sb0 nodad
ip -6 route add default dev sb0
SUPERBOT_HARDENING_STATE={dir} {script}
nft -f {dir}/allow.nft
nft -f {dir}/allow.nft
for host in 198.18.0.9 198.18.1.77 198.18.0.10 10.1.2.3 2001:db8::9 2001:db8::10; do
  echo "nobody $host: $(probe 65534 $host 443)"
done
echo "root 198.18.0.10: $(probe root 198.18.0.10 443)"
useradd --system --no-create-home --shell /usr/sbin/nologin {late}
echo "late 198.18.0.10: $(probe $(id -u {late}) 198.18.0.10 443)"
echo "late 198.18.0.9: $(probe $(id -u {late}) 198.18.0.9 443)"
userdel {late}
nft list table inet superbot_allow
nft -f {dir}/open.nft
echo "open nobody 198.18.0.10: $(probe 65534 198.18.0.10 443)"
echo "open nobody 10.1.2.3: $(probe 65534 10.1.2.3 443)"
nft list tables
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
    // Listed: through. Unlisted: refused, a user made after the rules loaded too.
    said("nobody 198.18.0.9: sent");
    said("nobody 198.18.1.77: sent");
    said("nobody 2001:db8::9: sent");
    said("nobody 198.18.0.10: refused");
    said("nobody 2001:db8::10: refused");
    said("late 198.18.0.10: refused");
    said("late 198.18.0.9: sent");
    // Listing a private address doesn't open it: ADR 0126's rules still deny it.
    said("nobody 10.1.2.3: refused");
    // Root is never held to the list.
    said("root 198.18.0.10: sent");
    // Open again: the table is gone, and the deny rules stay.
    said("open nobody 198.18.0.10: sent");
    said("open nobody 10.1.2.3: refused");
    assert!(text.contains("counter packets"), "{text}");
    assert!(!text.lines().any(|l| l.trim() == "table inet superbot_allow"), "{text}");
}

/// A test cgroup of its own under the root, removed after, its runs included.
struct TestCgroup(std::path::PathBuf);

impl Drop for TestCgroup {
    fn drop(&mut self) {
        for d in ["runs", "agent", ""] {
            let p = self.0.join(d);
            if let Ok(runs) = std::fs::read_dir(&p) {
                for e in runs.flatten().filter(|e| e.path().is_dir()) {
                    let _ = std::fs::remove_dir(e.path());
                }
            }
            let _ = std::fs::remove_dir(&p);
        }
    }
}

#[tokio::test]
#[ignore = "needs root and cgroup v2 on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_runs_are_held_to_their_limits_and_say_when_they_hit_them() {
    use crate::machines::cgroup::Cgroups;
    use crate::machines::job::{self, Host, Limiting};
    use crate::machines::wire::{JobEvent, JobRequest, RunLimits};
    if std::env::var("SUPERBOT_MACHINE_BOT_USER_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: needs SUPERBOT_MACHINE_BOT_USER_TEST=1, root and cgroup v2");
        return;
    }
    assert!(crate::machines::runas::is_root(), "run as root");
    let root = std::path::Path::new("/sys/fs/cgroup");
    let subtree = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap();
    for c in ["cpu", "memory", "pids"] {
        if !subtree.split_whitespace().any(|s| s == c) {
            std::fs::write(root.join("cgroup.subtree_control"), format!("+{c}")).unwrap();
        }
    }
    let base = TestCgroup(root.join(format!("sbtest-{}", std::process::id())));
    std::fs::create_dir(&base.0).unwrap();
    // One CPU and 1 GiB, as the agent would read its machine's.
    let cg = Cgroups::setup(&base.0, 1, 1 << 30).unwrap();
    assert!(cg.report().controllers.iter().any(|c| c == "memory"), "{:?}", cg.report());
    let dir = std::env::temp_dir().join(format!("sb-limits-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

    let run = |name: &'static str, script: &'static str, limits: RunLimits| {
        let started = cg.start(name, &limits).unwrap();
        let (dir, cgdir) = (dir.clone(), started.dir().to_path_buf());
        async move {
            let host = Host {
                clear_env: false,
                remove: vec![],
                env: Default::default(),
                user: Some(crate::machines::runas::Ids { uid: 65534, gid: 65534 }),
                limits: Some(Limiting::Cgroup(Arc::new(started))),
            };
            let req = JobRequest {
                protocol: wire::PROTOCOL,
                job_id: name.into(),
                bot_id: "b1".into(),
                owner_id: "u1".into(),
                for_user: None,
                message_id: 1,
                bin: "sh".into(),
                args: vec!["-c".into(), script.into()],
                env: Default::default(),
                cwd: dir.display().to_string(),
                stdin: None,
                files: vec![],
                cleanup: None,
                collect: vec![],
                limits: Some(limits),
            };
            let (tx, mut rx) = tokio::sync::mpsc::channel(256);
            job::run(&host, &req, std::future::pending(), &tx).await;
            drop(tx);
            let mut out = String::new();
            let mut exit = None;
            while let Some(ev) = rx.recv().await {
                match ev {
                    JobEvent::Exit { success, limited, .. } => exit = Some((success, limited.expect("a report on its limits"))),
                    JobEvent::Line { line } => out.push_str(&format!("{line}\n")),
                    JobEvent::Error { message } => panic!("{name}: {message}"),
                    _ => {}
                }
            }
            let (success, report) = exit.expect("an exit");
            (success, report, out, cgdir)
        }
    };
    let roomy = RunLimits { cpu_percent: 100, memory_percent: 50, pids: 256, io_weight: 100 };

    // In its own cgroup, as the Bots' user, not root, and unable to leave it.
    let (ok, r, out, cgdir) = run("j-where", "id -u; cat /proc/self/cgroup; echo 0 > /sys/fs/cgroup/cgroup.procs 2>/dev/null && echo escaped || echo stayed", roomy).await;
    assert!(ok && r.enforced, "{r:?} {out}");
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("65534"), "{out}");
    let rel = cgdir.strip_prefix(root).unwrap().display().to_string();
    assert_eq!(lines.next(), Some(format!("0::/{rel}").as_str()), "{out}");
    assert_eq!(lines.next(), Some("stayed"), "{out}");
    assert_eq!(r.applied.unwrap().memory_bytes, (1u64 << 30) / 100 * 50);
    assert!(!cgdir.exists(), "its cgroup goes once it's done");

    // Over its memory: killed, whole, and it says so.
    let tight = RunLimits { memory_percent: 10, ..roomy };
    let (ok, r, _, _) = run("j-memory", "x=$(head -c 400000000 /dev/zero | tr '\\0' a); echo survived", tight).await;
    assert!(!ok && r.oom_kills > 0, "{r:?}");

    // Past its processes: forks refused, counted.
    let few = RunLimits { pids: 16, ..roomy };
    let (_, r, _, _) = run("j-pids", "for i in $(seq 40); do sleep 2 & done 2>/dev/null; wait; echo done", few).await;
    assert!(r.pids_refused > 0 && r.oom_kills == 0, "{r:?}");

    // Over its CPU: held back, counted; and a run beside it isn't starved of memory or processes.
    let slow = RunLimits { cpu_percent: 10, ..roomy };
    let busy = run("j-cpu", "timeout 2 sh -c 'while :; do :; done'; echo done", slow);
    let beside = run("j-beside", "for i in $(seq 20); do sleep 0.1 & done; wait; echo fine", roomy);
    let ((_, busy, _, _), (ok, beside_r, out, _)) = tokio::join!(busy, beside);
    assert!(busy.cpu_throttled_ms >= 1000, "{busy:?}");
    assert!(ok && out.contains("fine") && beside_r.pids_refused == 0, "{beside_r:?} {out}");
    std::fs::remove_dir_all(&dir).unwrap();
}
