//! Machines as Incus system containers against a real Incus host (ADR 0068), not the
//! stand-in: botd's router and machine port in this process, the Incus provider built
//! from the same settings botd reads, and real containers that run cloud-init, fetch
//! the real `superbot-machine` from botd, enroll over mutual TLS, and answer heartbeats.
//!
//! Off by default. `deploy/incus-e2e-host.sh` makes a throwaway host ready and writes
//! the settings; CI's `incus-e2e` job runs it as:
//!
//! ```text
//! cargo build --bin superbot-machine
//! set -a; . <out-dir>/incus-e2e.env; set +a
//! cargo test machines_incus_e2e_tests -- --ignored --nocapture
//! ```

use crate::machines::State;
use crate::machines::enroll::{self, Enrollment};
use crate::machines::incus::{Credentials, Incus, Settings};
use crate::machines::provider::MachineProvider;
use crate::secrets::env::EnvStore;
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use reqwest::Method;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const PREFIX: &str = "sbe2e";
const STARTER: (u32, u32, u32) = (1, 1, 4);
const MAX: (u32, u32, u32) = (2, 2, 6);
/// A first create also downloads the image.
const ENROLL_WITHIN: Duration = Duration::from_secs(900);
/// A listener in user B's container, beside its agent.
const B_PORT: u16 = 8080;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    incus: Incus,
    gateway: IpAddr,
    machine_port: u16,
    /// A port on the control plane's host that isn't the machine port.
    decoy_port: u16,
    decoy_hits: Arc<AtomicUsize>,
    started: Instant,
}

impl Env {
    fn say(&self, what: &str) {
        eprintln!("[{:>4}s] {what}", self.started.elapsed().as_secs());
    }
}

/// INCUS_* from the environment (the host script's settings), everything else fixed
/// here, so nothing else on the host changes what this runs.
fn settings<'a>(fixed: &'a HashMap<&'static str, String>) -> impl Fn(&str) -> String + Clone + 'a {
    move |k: &str| match fixed.get(k) {
        Some(v) => v.clone(),
        None if k.starts_with("INCUS_") => std::env::var(k).unwrap_or_default(),
        None => String::new(),
    }
}

fn bin_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var_os("SUPERBOT_INCUS_E2E_BIN_DIR") {
        return d.into();
    }
    // The test binary sits somewhere under target/<profile>, which holds the others.
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .find(|d| d.join(enroll::AGENT_BIN).is_file())
        .unwrap_or(exe.parent().unwrap())
        .to_path_buf()
}

async fn incus_from_env() -> Incus {
    let fixed = HashMap::new();
    let var = settings(&fixed);
    Incus::new(Settings::from_env(&var).unwrap(), Credentials::from_store(&EnvStore::process()).unwrap()).unwrap()
}

/// The bridge's gateway: botd sits there, as on an Incus host running botd itself.
async fn gateway(incus: &Incus) -> IpAddr {
    let network = std::env::var("INCUS_NETWORK").unwrap_or_else(|_| "incusbr0".into());
    let n = incus.raw(Method::GET, &format!("/1.0/networks/{network}"), None, 10).await.unwrap();
    let cidr = n["config"]["ipv4.address"].as_str().expect("the bridge has an IPv4 address");
    cidr.split('/').next().unwrap().parse().unwrap()
}

/// What an earlier, failed run left behind.
async fn clean(incus: &Incus) {
    let list = incus.raw(Method::GET, "/1.0/instances", None, 10).await.unwrap();
    for url in list.as_array().into_iter().flatten().filter_map(Value::as_str) {
        let n = url.trim_start_matches("/1.0/instances/").split('?').next().unwrap();
        if n.starts_with(PREFIX) {
            incus.delete(n).await.unwrap();
        }
    }
    let acls = incus.raw(Method::GET, "/1.0/network-acls", None, 10).await.unwrap();
    for url in acls.as_array().into_iter().flatten().filter_map(Value::as_str) {
        let n = url.trim_start_matches("/1.0/network-acls/").split('?').next().unwrap();
        if n.starts_with(PREFIX) {
            incus.delete_firewall(n).await.unwrap();
        }
    }
}

async fn serve() -> Env {
    let started = Instant::now();
    let incus = incus_from_env().await;
    clean(&incus).await;
    let gateway = gateway(&incus).await;
    let machine_listener = TcpListener::bind((gateway, 0)).await.unwrap();
    let machine_port = machine_listener.local_addr().unwrap().port();
    let decoy = TcpListener::bind((gateway, 0)).await.unwrap();
    let decoy_port = decoy.local_addr().unwrap().port();
    let decoy_hits = Arc::new(AtomicUsize::new(0));
    let hits = decoy_hits.clone();
    tokio::spawn(async move {
        while decoy.accept().await.is_ok() {
            hits.fetch_add(1, Ordering::SeqCst);
        }
    });

    let tiers = format!(
        "starter=c{}-m{}-d{},max=c{}-m{}-d{}",
        STARTER.0, STARTER.1, STARTER.2, MAX.0, MAX.1, MAX.2
    );
    let fixed: HashMap<&'static str, String> = HashMap::from([
        ("MACHINE_PROVIDER", "incus".to_string()),
        ("MACHINE_CONTROL_URL", format!("https://{gateway}:{machine_port}")),
        ("MACHINE_LISTEN", format!("{gateway}:{machine_port}")),
        ("MACHINE_FIREWALL", "on".into()),
        ("MACHINE_FIREWALL_SOURCES", format!("{gateway}/32")),
        ("MACHINE_TIERS", tiers),
        ("MACHINE_LABEL_PREFIX", PREFIX.into()),
    ]);
    let var = settings(&fixed);
    let mut cp = crate::machines::ControlPlane::from_env(&EnvStore::process(), var.clone()).unwrap();
    let e = Enrollment::from_env(&var, &crate::secrets::sealed::cipher(), &bin_dir()).unwrap().unwrap();
    assert!(
        e.agent_sha256().is_some(),
        "superbot-machine must be built next to the tests ({}): cargo build --bin superbot-machine",
        bin_dir().display()
    );
    let e = cp.enroll_with(e).unwrap();
    let cp = Arc::new(cp);
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e, None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, incus, gateway, machine_port, decoy_port, decoy_hits, started }
}

async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, body).await;
    (code, parse(&body))
}

async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(env.port, "GET", &format!("/api/audit?action={action}&limit=200"), &env.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(env: &Env) -> Value {
    let (code, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(code, 200, "{r}");
    r
}

/// Reconciles every few seconds until `done` holds for every machine in `ids`.
async fn until(env: &Env, what: &str, ids: &[&str], within: Duration, done: impl Fn(&crate::db::Machine) -> bool) {
    let t = Instant::now();
    loop {
        let r = reconcile(env).await;
        let rows: Vec<_> = ids.iter().map(|id| env.app.db.machine(id).unwrap()).collect();
        if rows.iter().all(&done) {
            env.say(&format!("{what} ({}s)", t.elapsed().as_secs()));
            return;
        }
        if t.elapsed() > within {
            let seen: Vec<_> = rows
                .iter()
                .map(|m| {
                    format!(
                        "{}: {:?} {:?} enrollment={} agent_seen={:?} error={:?} agent_error={:?}",
                        m.label, m.state, m.provider_status, m.enrollment, m.agent_seen_at, m.last_error, m.agent_error
                    )
                })
                .collect();
            panic!("{what}: not within {}s; last pass {r}; {seen:#?}", within.as_secs());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn instance(env: &Env, name: &str) -> Value {
    env.incus.raw(Method::GET, &format!("/1.0/instances/{name}?recursion=1"), None, 10).await.unwrap()
}

async fn sh(env: &Env, name: &str, script: &str) -> (i64, String) {
    let (code, out, err) = env.incus.exec(name, &["sh", "-c", script]).await.unwrap();
    (code, format!("{out}{err}"))
}

/// Whether `from` opens a TCP connection to `host`:`port` within 5 seconds.
async fn reaches(env: &Env, from: &str, host: &str, port: u16) -> bool {
    let script = format!("timeout 5 bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null");
    sh(env, from, &script).await.0 == 0
}

fn address(i: &Value, family: &str) -> String {
    i["state"]["network"]["eth0"]["addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["family"] == family && a["scope"] == "global")
        .and_then(|a| a["address"].as_str())
        .unwrap_or_else(|| panic!("no global {family} address: {}", i["state"]["network"]["eth0"]))
        .to_string()
}

async fn sized(env: &Env, name: &str, (cpus, memory_gib, _): (u32, u32, u32)) {
    let (_, nproc) = sh(env, name, "nproc").await;
    assert_eq!(nproc.trim(), cpus.to_string(), "{name}: CPUs");
    let (_, mem) = sh(env, name, "cat /sys/fs/cgroup/memory.max").await;
    assert_eq!(mem.trim(), (u64::from(memory_gib) << 30).to_string(), "{name}: memory");
    let (_, pids) = sh(env, name, "cat /sys/fs/cgroup/pids.max").await;
    assert_eq!(pids.trim(), (memory_gib * 1024).max(2048).to_string(), "{name}: processes");
}

#[tokio::test]
#[ignore = "needs a real Incus host: SUPERBOT_INCUS_E2E=1 and INCUS_* (deploy/incus-e2e-host.sh), as CI's incus-e2e job runs it"]
async fn real_incus_containers_enroll_stay_apart_and_follow_the_lifecycle() {
    if std::env::var("SUPERBOT_INCUS_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: needs SUPERBOT_INCUS_E2E=1 and a real Incus host");
        return;
    }
    let env = serve().await;
    env.say(&format!("botd's machine port on {}:{}", env.gateway, env.machine_port));

    // The host is set up as the operator guide says.
    let (code, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
    assert_eq!(code, 200, "{s}");
    let checks = s["checks"].as_array().unwrap().clone();
    if std::env::var("SUPERBOT_INCUS_E2E_EXPECT").as_deref() == Ok("too-old") {
        // Such as Ubuntu 24.04's own Incus 6.0.0, which refuses ACLs on a bridged NIC.
        assert_eq!(checks[0]["ok"], false, "{checks:?}");
        assert!(checks[0]["detail"].as_str().unwrap().contains("network_bridge_acl_devices"), "{checks:?}");
        env.say(&format!("preflight refuses this Incus: {}", checks[0]["detail"]));
        return;
    }
    let pool = env.incus.raw(Method::GET, "/1.0/storage-pools/default", None, 10).await.unwrap();
    for c in &checks {
        let dir = c["check"] == "storage pool" && pool["driver"] == "dir";
        assert_eq!(c["ok"], !dir, "{c}");
    }
    env.say(&format!("preflight: {}", serde_json::to_string(&checks).unwrap()));

    // Two users' containers, made by the provider and sized by the tier.
    let mut users = Vec::new();
    for email in ["ada@example.com", "bea@example.com"] {
        let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
        let (code, m) = json_call(&env, "POST", &format!("/api/users/{uid}/machine"), "").await;
        assert_eq!(code, 202, "{m}");
        assert_eq!((m["provider"].as_str(), m["tier"].as_str()), (Some("incus"), Some("starter")), "{m}");
        users.push((uid, env.app.db.machine(m["id"].as_str().unwrap()).unwrap()));
    }
    env.say("requested two containers");
    let ids: Vec<&str> = users.iter().map(|(_, m)| m.id.as_str()).collect();
    let (a, b) = (users[0].1.label.clone(), users[1].1.label.clone());

    // cloud-init installs the agent from botd and enrolls; botd's heartbeat reaches it.
    until(&env, "both enrolled and heartbeating", &ids, ENROLL_WITHIN, |m| {
        m.state == State::Running && m.enrollment == "enrolled" && m.agent_seen_at.is_some()
    })
    .await;
    for n in [&a, &b] {
        let (code, out) = sh(&env, n, "cloud-init status --wait").await;
        assert!(code == 0 && out.contains("done"), "{n}: cloud-init: {out}");
        let (code, out) = sh(&env, n, "systemctl is-active superbot-machine").await;
        assert_eq!((code, out.trim()), (0, "active"), "{n}");
    }
    for (_, m) in &users {
        let row = env.app.db.machine(&m.id).unwrap();
        assert_eq!(row.agent_version.as_deref(), Some(crate::machines::agent::VERSION));
        assert!(row.ipv4.as_deref().is_some_and(|ip| ip.parse::<IpAddr>().is_ok()), "{:?}", row.ipv4);
    }

    // Enrolled, the token is spent: botd clears it from the config (ADR 0067), in
    // place, and only then turns on snapshots. Nothing inside keeps it either.
    until(&env, "enrollment data cleared and snapshots on", &ids, Duration::from_secs(60), |m| m.backups).await;
    for n in [&a, &b] {
        let i = instance(&env, n).await;
        let c = &i["config"];
        assert!(c.get("cloud-init.user-data").is_none(), "{n}: {c}");
        assert_eq!(c["snapshots.schedule"], "@daily", "{n}");
        assert_eq!(i["status"], "Running", "{n}: cleared without a restart");
        let (code, out) = sh(
            &env,
            n,
            "test ! -e /var/lib/cloud/seed/nocloud-net/user-data && test ! -e /var/lib/cloud/instance/user-data.txt && ! grep -rls sbe_ /var/lib/cloud /etc/superbot /var/log",
        )
        .await;
        assert_eq!(code, 0, "{n}: the token is still in {out}");
    }
    let cleared = events(&env, "machine.user_data_cleared").await;
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    assert!(cleared.iter().all(|e| e["details"]["reason"] == "enrolled"), "{cleared:?}");

    // Each container is what the tier asks for, enforced inside it.
    for n in [&a, &b] {
        sized(&env, n, STARTER).await;
        let c = &instance(&env, n).await["config"];
        for (k, v) in [("security.privileged", "false"), ("security.nesting", "false"), ("security.idmap.isolated", "true"), ("security.guestapi", "false")] {
            assert_eq!(c[k], v, "{n}: {k}");
        }
        let (_, map) = sh(&env, n, "cat /proc/self/uid_map").await;
        assert!(!map.split_whitespace().eq(["0", "0", "4294967295"]), "{n}: root in the container is root on the host: {map}");
        let (code, _) = sh(&env, n, "test -e /dev/incus").await;
        assert_ne!(code, 0, "{n}: no guest API");
    }
    let (_, ma) = sh(&env, &a, "cat /proc/self/uid_map").await;
    let (_, mb) = sh(&env, &b, "cat /proc/self/uid_map").await;
    assert_ne!(ma, mb, "each container has its own id range");

    // Isolation (M3: user A's computer and Bots cannot reach user B's). B listens
    // beside its agent; each probe has a control that shows the probe itself works.
    let (ia, ib) = (instance(&env, &a).await, instance(&env, &b).await);
    let (b4, b6, a4) = (address(&ib, "inet"), address(&ib, "inet6"), address(&ia, "inet"));
    let (code, out) = sh(&env, &b, &format!("systemd-run --unit sbe2e-listener /usr/bin/python3 -m http.server {B_PORT} --bind ::")).await;
    assert_eq!(code, 0, "{out}");
    let t = Instant::now();
    while !reaches(&env, &b, &b4, B_PORT).await {
        assert!(t.elapsed() < Duration::from_secs(30), "B's listener never came up");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(reaches(&env, &b, &b6, B_PORT).await, "control: B reaches itself over IPv6");
    let agent_port = crate::machines::enroll::DEFAULT_AGENT_PORT;
    let gw = env.gateway.to_string();
    for (host, port, why) in [
        (b4.as_str(), agent_port, "B's agent"),
        (b4.as_str(), B_PORT, "B's other port"),
        (b6.as_str(), B_PORT, "B over IPv6"),
        (gw.as_str(), env.decoy_port, "a control-plane port other than the machine port"),
        (gw.as_str(), 8443, "the Incus API"),
        (gw.as_str(), 22, "the host's SSH"),
    ] {
        assert!(!reaches(&env, &a, host, port).await, "A reached {why} at {host}:{port}");
    }
    assert_eq!(env.decoy_hits.load(Ordering::SeqCst), 0);
    let (code, out) = sh(&env, &a, &format!("ping -c 1 -W 2 {gw}")).await;
    assert_eq!(code, 0, "control: A pings the gateway: {out}");
    let (code, _) = sh(&env, &a, &format!("ping -c 1 -W 2 {b4}")).await;
    assert_ne!(code, 0, "A pinged B");
    assert!(reaches(&env, &a, &gw, env.machine_port).await, "A reaches botd's machine port");
    let internet = reaches(&env, &a, "1.1.1.1", 443).await;
    let (dns, _) = sh(&env, &a, "timeout 10 getent hosts github.com").await;
    env.say(&format!("A to the internet: tcp {internet}, dns {}", dns == 0));
    assert!(internet && dns == 0, "outbound to the internet stays open");
    // From the host itself, only the agent's port, from the firewall's sources.
    let reach_from_host = |host: String, port: u16| async move {
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((host.as_str(), port)))
            .await
            .is_ok_and(|r| r.is_ok())
    };
    assert!(reach_from_host(b4.clone(), agent_port).await, "botd reaches B's agent");
    assert!(!reach_from_host(b4.clone(), B_PORT).await, "the host reached B's other port");
    assert!(!reaches(&env, &b, &a4, agent_port).await, "B reached A's agent");
    env.say("isolation holds");

    // Suspend and resume: a stop and a start; the agent answers again.
    let (uid_a, ma) = &users[0];
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid_a}/machine/suspend"), "").await;
    assert_eq!((code, s["state"].as_str()), (200, Some("suspended")), "{s}");
    assert_eq!(instance(&env, &a).await["status"], "Stopped");
    env.say("suspended A");
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid_a}/machine/resume"), "").await;
    assert_eq!((code, s["state"].as_str()), (200, Some("running")), "{s}");
    let resumed = crate::db::now();
    until(&env, "A heartbeats after resume", &[ma.id.as_str()], Duration::from_secs(180), |m| {
        m.state == State::Running && m.agent_seen_at.is_some_and(|t| t >= resumed)
    })
    .await;

    // Resize, applied to the running container.
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid_a}/machine/resize"), r#"{"tier":"max"}"#).await;
    assert_eq!(code, 200, "{s}");
    let i = instance(&env, &a).await;
    assert_eq!(i["status"], "Running");
    assert_eq!(i["devices"]["root"]["size"], format!("{}GiB", MAX.2));
    sized(&env, &a, MAX).await;
    env.say("resized A");

    // The reconciler converges, and puts back what is changed behind its back.
    reconcile(&env).await;
    let r = reconcile(&env).await;
    assert_eq!((r["changed"].as_u64(), r["firewallAttached"].as_u64()), (Some(0), Some(0)), "{r}");
    let mut nic = i["devices"]["eth0"].clone();
    nic["security.acls.default.ingress.action"] = json!("allow");
    env.incus
        .raw(Method::PATCH, &format!("/1.0/instances/{a}"), Some(&json!({ "devices": { "eth0": nic } })), 30)
        .await
        .unwrap();
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "{r}");
    assert_eq!(instance(&env, &a).await["devices"]["eth0"]["security.acls.default.ingress.action"], "drop");
    let fw = ma.firewall_id.clone().unwrap();
    let acl = env.incus.raw(Method::GET, &format!("/1.0/network-acls/{fw}"), None, 10).await.unwrap();
    let egress = acl["egress"].clone();
    assert!(egress.as_array().is_some_and(|e| !e.is_empty()));
    env.incus
        .raw(Method::PUT, &format!("/1.0/network-acls/{fw}"), Some(&json!({ "description": acl["description"], "config": acl["config"], "ingress": acl["ingress"], "egress": [] })), 10)
        .await
        .unwrap();
    reconcile(&env).await;
    let after = env.incus.raw(Method::GET, &format!("/1.0/network-acls/{fw}"), None, 10).await.unwrap();
    assert_eq!(after["egress"], egress, "outbound rules put back");
    let r = reconcile(&env).await;
    assert_eq!((r["changed"].as_u64(), r["firewallAttached"].as_u64()), (Some(0), Some(0)), "{r}");
    assert!(!reaches(&env, &a, &b4, B_PORT).await, "still apart after the repairs");
    env.say("reconciler converged");

    // A rebuild (ADR 0056) wipes the container in place and seeds cloud-init again
    // from the new user data. The API rebuilds only pre-0039 agents, so the provider
    // is asked directly, with user data that leaves a mark.
    let t = Instant::now();
    let spec = crate::machines::provider::RebuildSpec {
        image: crate::machines::incus::DEFAULT_IMAGE.into(),
        authorized_keys: Vec::new(),
        user_data: "#cloud-config\nwrite_files:\n  - path: /root/rebuilt\n    content: \"yes\"\n".into(),
    };
    env.incus.rebuild(&a, &spec).await.unwrap();
    let (code, out) = sh(&env, &a, "cloud-init status --wait; cat /root/rebuilt; test ! -e /usr/local/lib/superbot/superbot-machine").await;
    assert!(code == 0 && out.ends_with("yes"), "the new user data ran on a wiped disk: {out}");
    let i = instance(&env, &a).await;
    assert_eq!((i["status"].as_str(), address(&i, "inet")), (Some("Running"), a4.clone()), "same address");
    assert_eq!(i["devices"]["eth0"]["security.acls"].as_str(), Some(fw.as_str()), "same firewall");
    env.say(&format!("rebuilt A ({}s to cloud-init done)", t.elapsed().as_secs()));

    // Destroyed: both containers, then the ACL with the last of them.
    for (uid, m) in &users {
        let (code, d) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"), "").await;
        assert_eq!((code, d["state"].as_str()), (200, Some("destroyed")), "{d}");
        assert_eq!(env.incus.get(&m.label).await, Err(crate::machines::provider::ProviderError::NotFound));
    }
    assert!(env.incus.find_firewall(&fw).await.unwrap().is_none(), "the ACL went with the last machine");
    assert_eq!(events(&env, "machine.firewall_deleted").await.len(), 1);
    env.say("destroyed both");
}
