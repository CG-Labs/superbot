//! Machines as Incus system containers (ADR 0065), end to end on loopback: the real
//! router, botd's machine port, the real agent, and the Incus provider talking mutual
//! TLS to a stand-in for the Incus API. Nothing here talks to a real Incus host.

use crate::db::NewMachine;
use crate::machines::agent::{self, Agent, Config};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::firewall::Settings;
use crate::machines::incus::Incus;
use crate::machines::incus_standin::StandIn;
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    incus: StandIn,
    e: Arc<Enrollment>,
    agent_listener: Option<TcpListener>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";

/// botd making machines on the stand-in, with enrollment and the firewall on.
async fn serve() -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let (mport, aport) = (
        machine_listener.local_addr().unwrap().port(),
        agent_listener.local_addr().unwrap().port(),
    );
    let incus = StandIn::start().await;
    let control = ("127.0.0.1".parse().unwrap(), mport);
    let p = Incus::new(incus.settings(Some(control)), incus.credentials()).unwrap();
    let mut cp = ControlPlane::for_tests(Arc::new(p));
    cp.regions = vec!["local".into()];
    let e = cp
        .enroll_with(Enrollment::for_tests(9, mport, aport).with_agent(AGENT.as_bytes()))
        .unwrap();
    cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    let cp = Arc::new(cp);
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e.clone(), None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, incus, e, agent_listener: Some(agent_listener) }
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

/// A member and the container just made for them: their id and the machine row.
async fn request(env: &Env, email: &str) -> (String, crate::db::Machine) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
    assert_eq!(m["provider"], "incus");
    (uid, env.app.db.machine(m["id"].as_str().unwrap()).unwrap())
}

fn token_in(user_data: &str) -> String {
    let at = user_data.find("content: \"sbe_").expect("a token in the user data") + "content: \"".len();
    user_data[at..].split('"').next().unwrap().to_string()
}

fn config(env: &Env, machine_id: &str, token: &str) -> Config {
    Config {
        control_url: env.e.url.clone(),
        machine_id: machine_id.into(),
        ca_pem: env.e.ca_pem().into(),
        state_dir: crate::db::temp_path("agent"),
        listen: SocketAddr::from(([127, 0, 0, 1], env.e.agent_port)),
        token: Some(Zeroizing::new(token.to_string())),
        token_file: None,
        home: crate::db::temp_path("agent-home"),
        api_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        botctl: std::path::PathBuf::from("/nonexistent/botctl"),
        harness_path: "/usr/bin:/bin".into(),
        max_jobs: 8,
        tools: crate::db::temp_path("agent-tools"),
        exe: crate::db::temp_path("agent-exe"),
        bot_user: crate::machines::runas::current_user().unwrap(),
        allow_own_user: true,
        screens: crate::machines_mtls_tests::no_screens(),
        teammates: crate::db::temp_path("agent-teammates"),
        teammate_stand_in: None,
        run_cgroups: false,
        nft: "/nonexistent/nft".into(),
        egress_script: "/nonexistent/egress".into(),
    }
}

#[tokio::test]
async fn a_users_machine_is_a_container_enrolled_and_reached_like_any_other() {
    let mut env = serve().await;
    let (uid, m) = request(&env, "ada@example.com").await;
    assert_eq!((m.state, m.tier.as_str(), m.plan.as_str(), m.region.as_str()), (State::Provisioning, "starter", "c1-m2-d20", "local"));
    assert_eq!(m.provider_id.as_deref(), Some(m.label.as_str()), "a container is known by its name");
    assert_eq!(m.firewall_id.as_deref(), Some("superbot-fw"));

    // Made behind the firewall, sized by the tier, carrying the enrollment token.
    let i = env.incus.instance(&m.label).unwrap();
    assert_eq!(i.project, "superbot");
    assert_eq!(i.body["config"]["limits.cpu"], "1");
    assert_eq!(i.body["config"]["limits.memory"], "2GiB");
    assert_eq!(i.body["config"]["security.privileged"], "false");
    assert_eq!(i.body["devices"]["eth0"]["security.acls"], "superbot-fw");
    assert_eq!(i.body["devices"]["eth0"]["security.port_isolation"], "true");
    let user_data = i.body["config"]["cloud-init.user-data"].as_str().unwrap().to_string();
    assert!(user_data.contains("rm -f /var/lib/cloud/instance/user-data.txt") && user_data.contains("/var/lib/cloud/seed/nocloud-net/user-data"), "the seed copy is scrubbed too");
    let acl = env.incus.w().acls["superbot-fw"].clone();
    let ingress = acl["ingress"].as_array().unwrap();
    assert_eq!(ingress.len(), 1, "{ingress:?}");
    assert_eq!(
        (ingress[0]["source"].as_str(), ingress[0]["destination_port"].as_str()),
        (Some("127.0.0.1/32"), Some(env.e.agent_port.to_string().as_str())),
        "inbound only the agent's port, from botd"
    );
    let egress = acl["egress"].as_array().unwrap();
    assert!(egress.iter().any(|r| r["action"] == "drop" && r["destination"].as_str().is_some_and(|d| d.contains("10.0.0.0/8"))));
    let mport = env.e.url.rsplit(':').next().unwrap().trim_end_matches('/').to_string();
    let to_botd = egress.iter().find(|r| r["destination"] == "127.0.0.1" && r["protocol"] == "tcp").unwrap();
    assert!(!to_botd["destination_port"].as_str().unwrap().split(',').any(|p| p == mport), "botd's machine port stays open");

    // Running with an address botd can reach, then enrolled and answering over mutual TLS.
    env.incus.w().instances.get_mut(&m.label).unwrap().ip = "127.0.0.1".into();
    reconcile(&env).await;
    let row = env.app.db.machine(&m.id).unwrap();
    assert_eq!((row.state, row.ipv4.as_deref(), row.provider_status.as_deref()), (State::Running, Some("127.0.0.1"), Some("running")));
    let i = env.incus.instance(&m.label).unwrap();
    assert_eq!(i.body["config"]["cloud-init.user-data"], user_data.as_str(), "kept until it has enrolled");
    assert!(!row.backups && i.body["config"].get("snapshots.schedule").is_none(), "no snapshot of a live token");
    let cfg = config(&env, &m.id, &token_in(&user_data));
    let id = agent::enroll(&cfg).await.unwrap();
    let agent = Agent::new(cfg, id).unwrap();
    tokio::spawn(agent::serve(env.agent_listener.take().unwrap(), agent));
    let r = reconcile(&env).await;
    assert_eq!(r["heartbeats"], 1, "{r}");
    let row = env.app.db.machine(&m.id).unwrap();
    assert_eq!((row.enrollment.as_str(), row.agent_version.as_deref()), ("enrolled", Some(agent::VERSION)));

    // Enrolled, its token is spent: it leaves the container's config in place, and
    // daily snapshots start.
    let i = env.incus.instance(&m.label).unwrap();
    assert!(i.body["config"].get("cloud-init.user-data").is_none(), "{}", i.body["config"]);
    assert!(i.body["config"]["cloud-init.vendor-data"].as_str().is_none_or(|v| !v.contains("sbe_")));
    assert_eq!((i.status.as_str(), i.boots), ("Running", 1), "not restarted");
    assert_eq!(i.body["config"]["snapshots.schedule"], "@daily");
    assert!(row.backups, "daily snapshots turned on");
    let cleared = events(&env, "machine.user_data_cleared").await;
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert_eq!((cleared[0]["details"]["reason"].as_str(), cleared[0]["details"]["providerId"].as_str()), (Some("enrolled"), Some(m.label.as_str())));
    let puts = env.incus.calls("PUT", &format!("/1.0/instances/{}", m.label)).len();
    reconcile(&env).await;
    assert_eq!(events(&env, "machine.user_data_cleared").await.len(), 1, "once");
    assert_eq!(env.incus.calls("PUT", &format!("/1.0/instances/{}", m.label)).len(), puts, "nothing more asked of Incus");

    // Suspend, resume, and resize are container stops, starts, and limits.
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/suspend"), "").await;
    assert_eq!((code, s["state"].as_str()), (200, Some("suspended")), "{s}");
    assert_eq!(env.incus.instance(&m.label).unwrap().status, "Stopped");
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/resume"), "").await;
    assert_eq!((code, s["state"].as_str()), (200, Some("running")), "{s}");
    assert_eq!(env.incus.instance(&m.label).unwrap().status, "Running");
    let (code, s) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/resize"), r#"{"tier":"max"}"#).await;
    assert_eq!((code, s["plan"].as_str()), (200, Some("c4-m8-d80")), "{s}");
    let i = env.incus.instance(&m.label).unwrap();
    assert_eq!((i.body["config"]["limits.cpu"].as_str(), i.body["devices"]["root"]["size"].as_str()), (Some("4"), Some("80GiB")));
    assert_eq!(i.body["devices"]["eth0"]["security.acls"], "superbot-fw", "still behind the firewall");

    // Destroyed: the container and, as the last machine behind it, the ACL.
    let (code, d) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!((code, d["state"].as_str()), (200, Some("destroyed")), "{d}");
    assert!(env.incus.instance(&m.label).is_none());
    assert!(env.incus.w().acls.is_empty(), "the firewall went with the last machine");
    assert_eq!(events(&env, "machine.firewall_deleted").await.len(), 1);
}

#[tokio::test]
async fn enrollment_data_goes_once_the_deadline_passes_but_not_mid_rebuild_or_before_first_boot() {
    let env = serve().await;
    let (uid, m) = request(&env, "ada@example.com").await;
    let (_, never) = request(&env, "bea@example.com").await;
    let user_data = env.incus.instance(&m.label).unwrap().body["config"]["cloud-init.user-data"].as_str().unwrap().to_string();
    env.incus.w().instances.get_mut(&never.label).unwrap().status = "Stopped".into();
    reconcile(&env).await;
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Running);

    // Late, with a rebuild queued: the rebuild may still need it.
    assert!(env.app.db.machine_rebuild_queue(&m.id, "rb1", "admin", true, None));
    for id in [&m.id, &never.id] {
        env.app.db.machine_rebuild_backdate(id, 3_600_000);
    }
    reconcile(&env).await;
    reconcile(&env).await;
    assert_eq!(events(&env, "machine.enroll_timeout").await.len(), 2);
    assert!(events(&env, "machine.user_data_cleared").await.is_empty());
    assert!(env.incus.instance(&m.label).unwrap().body["config"].get("cloud-init.user-data").is_some());

    // Without one, it goes from the running container; the one that never started
    // keeps it, since its seed isn't rendered yet.
    let (code, r) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 200, "{r}");
    reconcile(&env).await;
    let cleared = events(&env, "machine.user_data_cleared").await;
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert_eq!((cleared[0]["targetId"].as_str(), cleared[0]["details"]["reason"].as_str()), (Some(m.id.as_str()), Some("enroll_timeout")));
    let i = env.incus.instance(&m.label).unwrap();
    assert!(i.body["config"].get("cloud-init.user-data").is_none());
    assert_eq!((i.status.as_str(), i.boots), ("Running", 1));
    assert!(env.incus.instance(&never.label).unwrap().body["config"].get("cloud-init.user-data").is_some());
    assert!(!env.app.db.machine(&never.id).unwrap().backups);

    // The container has its own copy, so a late enrollment still works.
    agent::enroll(&config(&env, &m.id, &token_in(&user_data))).await.unwrap();
    assert_eq!(env.app.db.machine(&m.id).unwrap().enrollment, "enrolled");
    reconcile(&env).await;
    assert_eq!(events(&env, "machine.user_data_cleared").await.len(), 1);
}

#[tokio::test]
async fn a_failed_clear_is_audited_and_tried_again() {
    let env = serve().await;
    let (_, m) = request(&env, "ada@example.com").await;
    let user_data = env.incus.instance(&m.label).unwrap().body["config"]["cloud-init.user-data"].as_str().unwrap().to_string();
    reconcile(&env).await;
    agent::enroll(&config(&env, &m.id, &token_in(&user_data))).await.unwrap();

    env.incus.w().races = 3;
    reconcile(&env).await;
    let failed = events(&env, "machine.user_data_clear_failed").await;
    assert_eq!((failed.len(), failed[0]["outcome"].as_str()), (1, Some("failure")), "{failed:?}");
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("kept changing"), "{failed:?}");
    assert!(!env.app.db.machine(&m.id).unwrap().backups, "no snapshots yet");

    reconcile(&env).await;
    assert_eq!(events(&env, "machine.user_data_cleared").await.len(), 1);
    let c = env.incus.instance(&m.label).unwrap().body["config"].clone();
    assert!(c.get("cloud-init.user-data").is_none() && c["user.other-client"].is_string(), "{c}");
    assert!(env.app.db.machine(&m.id).unwrap().backups);
}

#[tokio::test]
async fn containers_are_cut_off_from_each_other() {
    let env = serve().await;
    let (_, a) = request(&env, "ada@example.com").await;
    let (_, b) = request(&env, "bea@example.com").await;
    let (ia, ib) = (env.incus.instance(&a.label).unwrap(), env.incus.instance(&b.label).unwrap());
    for i in [&ia, &ib] {
        let nic = &i.body["devices"]["eth0"];
        for k in ["security.port_isolation", "security.mac_filtering", "security.ipv4_filtering", "security.ipv6_filtering"] {
            assert_eq!(nic[k], "true", "{k}");
        }
        assert_eq!(nic["security.acls.default.ingress.action"], "drop");
        assert_eq!(i.body["devices"].as_object().unwrap().len(), 2, "no shared disk between them");
    }
    // Each one's address is in a range the other can't send to.
    let egress = env.incus.w().acls["superbot-fw"]["egress"].clone();
    let v4: Vec<&str> = egress.as_array().unwrap().iter().filter(|r| r["protocol"] == "tcp").filter_map(|r| r["destination"].as_str()).collect();
    assert!(ia.ip.starts_with("10.") && ib.ip.starts_with("10.") && v4.iter().any(|d| d.split(',').any(|c| c == "10.0.0.0/8")), "{v4:?}");
    assert_eq!(env.incus.w().acls.len(), 1, "one ACL for every machine");
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 0, "both were made behind it: {r}");

    // A container taken off the ACL at Incus is put back by the reconciler.
    env.incus.w().instances.get_mut(&b.label).unwrap().body["devices"]["eth0"] = json!({ "type": "nic", "network": "incusbr0" });
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "{r}");
    let nic = env.incus.instance(&b.label).unwrap().body["devices"]["eth0"].clone();
    assert_eq!((nic["security.acls"].as_str(), nic["security.port_isolation"].as_str()), (Some("superbot-fw"), Some("true")));

    // So is one opened up in place while it still names the ACL.
    env.incus.w().instances.get_mut(&a.label).unwrap().body["devices"]["eth0"]["security.acls.default.ingress.action"] = json!("allow");
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "{r}");
    assert_eq!(env.incus.instance(&a.label).unwrap().body["devices"]["eth0"]["security.acls.default.ingress.action"], "drop");

    // Loosened outbound rules are set back too.
    env.incus.w().acls.get_mut("superbot-fw").unwrap()["egress"] = json!([]);
    reconcile(&env).await;
    assert_eq!(env.incus.w().acls["superbot-fw"]["egress"], egress);
    assert!(!events(&env, "machine.firewall_updated").await.is_empty());
}

#[tokio::test]
async fn admins_see_the_substrate_and_check_the_host() {
    let env = serve().await;
    let (code, s) = json_call(&env, "GET", "/api/machines/substrate", "").await;
    assert_eq!(code, 200, "{s}");
    assert_eq!((s["provider"].as_str(), s["substrate"].as_str(), s["kernel"].as_str()), (Some("incus"), Some("container"), Some("shared")));
    assert_eq!(s["tiers"][1], json!({ "tier": "pro", "plan": "c2-m4-d40", "resources": { "cpus": 2, "memoryGiB": 4, "diskGiB": 40, "processes": 4096 }, "ownKernel": false }));
    assert_eq!(s["regions"], json!(["local"]));
    assert_eq!(s["settings"]["project"], "superbot");
    assert!(s["checks"].is_null(), "the host is asked only when asked");
    assert!(!s.to_string().contains("PRIVATE KEY"));

    let (code, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
    assert_eq!(code, 200);
    let checks = s["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 4);
    assert!(checks.iter().all(|c| c["ok"] == true), "{checks:?}");

    env.incus.w().projects.insert("superbot".into(), json!({ "restricted": "false" }));
    let (_, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
    let project = s["checks"].as_array().unwrap().iter().find(|c| c["check"] == "project").unwrap().clone();
    assert_eq!(project["ok"], false, "{project}");

    // And then no container is made, and the machine says why.
    let (uid, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (code, r) = json_call(&env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 502, "{r}");
    assert!(r["error"].as_str().unwrap().contains("isn't restricted"), "{r}");
    assert!(env.incus.calls("POST", "/1.0/instances").is_empty());

    let (_, member) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (code, _) = call(env.port, "GET", "/api/machines/substrate", &member, "").await;
    assert_eq!(code, 403);
}

#[tokio::test]
async fn machines_from_another_provider_are_left_alone() {
    let env = serve().await;
    let (uid, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let new = NewMachine { user_id: &uid, provider: "linode", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
    let mut m = env.app.db.add_machine(&new).ok().unwrap();
    m.provider_id = Some("4242".into());
    m.firewall_id = Some("777".into());
    m.state = State::Running;
    assert!(env.app.db.save_machine(&m, State::Pending));

    let r = reconcile(&env).await;
    assert_eq!(r["checked"], 0, "{r}");
    assert!(env.incus.w().calls.iter().all(|c| !c.path.contains("4242")), "never asked Incus about it");
    for (method, action, body) in [
        ("POST", "suspend", ""),
        ("POST", "resize", r#"{"tier":"pro"}"#),
        ("DELETE", "", ""),
    ] {
        let path = format!("/api/users/{uid}/machine{}", if action.is_empty() { String::new() } else { format!("/{action}") });
        let (code, r) = json_call(&env, method, &path, body).await;
        assert_eq!(code, 409, "{method} {action}: {r}");
        assert!(r["error"].as_str().unwrap().contains("at linode"), "{r}");
    }
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Running, "untouched");
}
