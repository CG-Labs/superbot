//! A network of its own per team on Incus (ADR 0212), end to end on loopback with the
//! Incus provider talking mutual TLS to the stand-in: a team's containers get a NIC on
//! an isolated OVN network made for the team, behind its own ACL; nobody else's do; one
//! whose owner leaves is unplugged while it runs; and one made earlier joins at once,
//! unless it was made before containers could bring the NIC up. Nothing here talks to
//! a real Incus host.

use crate::machines::enroll::{self, Enrollment};
use crate::machines::firewall::Settings;
use crate::machines::incus::Incus;
use crate::machines::incus_standin::StandIn;
use crate::machines::team_network;
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::net::TcpListener;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    incus: StandIn,
}

const AGENT: &str = "stand-in for the superbot-machine binary";
const SUBNET: &str = team_network::DEFAULT_SUBNET;

/// botd making containers on the stand-in with team networks on, in a project that
/// lets containers use only the networks it names.
async fn serve() -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mport = machine_listener.local_addr().unwrap().port();
    let incus = StandIn::start().await;
    incus.w().projects.insert("superbot".into(), json!({ "restricted": "true", "restricted.networks.access": "incusbr0" }));
    let control = ("127.0.0.1".parse().unwrap(), mport);
    let p = Incus::new(incus.settings(Some(control)), incus.credentials()).unwrap().with_team_subnet(SUBNET).unwrap();
    let mut cp = ControlPlane::for_tests(Arc::new(p));
    cp.regions = vec!["local".into()];
    let e = cp.enroll_with(Enrollment::for_tests(9, mport, 7443).with_agent(AGENT.as_bytes())).unwrap();
    cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    cp.team_network = Some(team_network::Settings { kind: team_network::Kind::Ovn, subnet: SUBNET.into(), join: team_network::Join::NextBoot, remove: team_network::Remove::WhenEmpty });
    let cp = Arc::new(cp);
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e, None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, incus }
}

async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, b) = call(env.port, method, path, &env.admin, body).await;
    (code, parse(&b))
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

async fn team(env: &Env, name: &str, owner: &str) -> String {
    let (code, t) = json_call(env, "POST", "/api/teams", &json!({ "name": name, "owner": owner, "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    t["id"].as_str().unwrap().to_string()
}

async fn join(env: &Env, team: &str, uid: &str) {
    let (code, v) = json_call(env, "PUT", &format!("/api/teams/{team}/members/{uid}"), r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");
}

async fn leave(env: &Env, team: &str, uid: &str) {
    let (code, v) = json_call(env, "DELETE", &format!("/api/teams/{team}/members/{uid}"), "").await;
    assert!(code == 200 || code == 204, "{code} {v}");
}

async fn ask(env: &Env, uid: &str) -> crate::db::Machine {
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
    env.app.db.machine(m["id"].as_str().unwrap()).unwrap()
}

fn devices(env: &Env, m: &crate::db::Machine) -> Value {
    env.incus.instance(&m.label).unwrap().body["devices"].clone()
}

/// As if `m`'s agent had said its egress rules let the team's subnet through.
fn rules_let_it_through(env: &Env, m: &crate::db::Machine) {
    let m = env.app.db.machine(&m.id).unwrap();
    let mut u = m.agent_upkeep.clone().unwrap_or_else(|| json!({}));
    u["teamNetwork"] = json!({ "subnet": SUBNET, "state": "on" });
    assert!(env.app.db.machine_upkeep_swap(&m.id, m.agent_upkeep.as_ref(), &u));
}

#[tokio::test]
async fn a_teams_containers_share_an_isolated_ovn_network_and_leave_it_while_running() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    let (ma, ml, mc) = (ask(&env, &ada).await, ask(&env, &al).await, ask(&env, &cy).await);

    // One isolated OVN network for the team: no uplink, no NAT, no gateway handed out.
    let nets: Vec<(String, Value)> = env.incus.w().networks.iter().filter(|(_, v)| v["type"] == "ovn").map(|(n, v)| (n.clone(), v.clone())).collect();
    assert_eq!(nets.len(), 1, "{nets:?}");
    let (net, v) = &nets[0];
    assert!(net.starts_with("superbot-team-") && net.ends_with("-local") && !net.contains(&acme), "{net}");
    let c = &v["config"];
    for (k, want) in [
        ("network", "none"),
        ("ipv4.address", "10.248.0.1/22"),
        ("ipv4.nat", "false"),
        ("ipv4.dhcp.gateway", "none"),
        ("ipv6.address", "none"),
        ("user.superbot.team-network", "true"),
        ("user.superbot.region", "local"),
    ] {
        assert_eq!(c[k], want, "{k}: {c}");
    }

    // Its ACL lets nothing in, so teammates' machines stay apart as on Linode, and lets
    // out only to the team's subnet. The project now names the network.
    let acl = env.incus.w().acls[net.as_str()].clone();
    assert_eq!(acl["ingress"], json!([]), "{acl}");
    assert_eq!((acl["egress"].as_array().unwrap().len(), acl["egress"][0]["destination"].as_str()), (1, Some(SUBNET)), "{acl}");
    assert_eq!(env.incus.w().projects["superbot"]["restricted.networks.access"], format!("incusbr0,{net}"));

    // The team's containers have a NIC on it behind that ACL, filtered; Cy's has none.
    for m in [&ma, &ml] {
        let nic = devices(&env, m)["eth1"].clone();
        assert_eq!((nic["network"].as_str(), nic["security.acls"].as_str(), nic["name"].as_str()), (Some(net.as_str()), Some(net.as_str()), Some("eth1")));
        for k in ["security.mac_filtering", "security.ipv4_filtering", "security.ipv6_filtering"] {
            assert_eq!(nic[k], "true", "{k}");
        }
        assert_eq!((nic["security.acls.default.ingress.action"].as_str(), nic["security.acls.default.egress.action"].as_str()), (Some("drop"), Some("drop")));
        assert_eq!(devices(&env, m)["eth0"]["security.acls"], "superbot-fw", "eth0 is as before");
    }
    assert!(devices(&env, &mc).get("eth1").is_none());
    for m in [&ma, &mc] {
        let config = env.incus.instance(&m.label).unwrap().body["config"].clone();
        assert!(config["cloud-init.network-config"].as_str().unwrap().contains("eth1:\n    optional: true"), "{config}");
        assert_eq!(config["user.superbot.team-nic"], "eth1", "every container can bring a team NIC up");
    }
    let made = events(&env, "machine.team_network_created").await;
    assert_eq!((made.len(), made[0]["targetId"].as_str(), made[0]["details"]["team"].as_str()), (1, Some(net.as_str()), Some(acme.as_str())), "{made:?}");

    // Running: the firewall sweep keeps the team NIC, and nothing more is done.
    for _ in 0..2 {
        let r = reconcile(&env).await;
        assert!(r.get("teamNetworks").is_none() && r["firewallAttached"] == 0, "{r}");
    }
    assert_eq!(env.app.db.machine(&ml.id).unwrap().state, State::Running);
    assert_eq!(devices(&env, &ml)["eth1"]["network"], net.as_str());

    // A NIC opened up at Incus is no team NIC: the firewall sweep takes it off.
    env.incus.w().instances.get_mut(&ml.label).unwrap().body["devices"]["eth1"]["security.acls.default.ingress.action"] = json!("allow");
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "{r}");
    assert!(devices(&env, &ml).get("eth1").is_none());
    // Rejoined (its egress rules already let the subnet through), in use at once.
    rules_let_it_through(&env, &ml);
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joining": 1 }));
    assert_eq!(devices(&env, &ml)["eth1"]["security.acls.default.ingress.action"], "drop");
    let joining = events(&env, "machine.team_network_joining").await;
    assert_eq!((joining[0]["details"]["networkId"].as_str(), joining[0]["details"]["atOnce"].as_bool()), (Some(net.as_str()), Some(true)), "{joining:?}");
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joined": 1 }));

    // Al leaves Acme: his NIC is unplugged while the container runs, never stopped.
    let boots = env.incus.instance(&ml.label).unwrap().boots;
    leave(&env, &acme, &al).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1 }));
    let i = env.incus.instance(&ml.label).unwrap();
    assert!(i.body["devices"].get("eth1").is_none(), "{}", i.body["devices"]);
    assert_eq!((i.status.as_str(), i.boots), ("Running", boots), "not restarted");
    assert_eq!(env.app.db.machine(&ml.id).unwrap().state, State::Running);
    let left = events(&env, "machine.team_network_left").await;
    assert_eq!((left.len(), left[0]["details"]["inUse"].as_bool(), left[0]["details"]["resuming"].as_bool()), (1, Some(true), Some(false)), "{left:?}");
    assert!(events(&env, "machine.team_network_leaving").await.is_empty(), "never powered off");
    assert!(reconcile(&env).await.get("teamNetworks").is_none());
    assert_eq!(devices(&env, &ma)["eth1"]["network"], net.as_str(), "Ada's stays on");

    // The ACL loosened at Incus is set back when the next teammate's container is made.
    env.incus.w().acls.get_mut(net.as_str()).unwrap()["ingress"] = json!([{ "action": "allow", "state": "enabled" }]);
    let (eve, _) = user_with(env.port, &env.admin, "eve@example.com", "member").await;
    join(&env, &acme, &eve).await;
    let me = ask(&env, &eve).await;
    assert_eq!(devices(&env, &me)["eth1"]["network"], net.as_str());
    assert_eq!(env.incus.w().acls[net.as_str()]["ingress"], json!([]));
    assert_eq!(env.incus.w().networks.values().filter(|v| v["type"] == "ovn").count(), 1, "still one network");
}

#[tokio::test]
async fn a_container_made_before_team_networks_is_refused_once_until_rebuilt() {
    let env = serve().await;
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let (mc, md) = (ask(&env, &cy).await, ask(&env, &dee).await);
    reconcile(&env).await;
    // Dee's was made before containers were given the team NIC's network config.
    env.incus.w().instances.get_mut(&md.label).unwrap().body["config"].as_object_mut().unwrap().remove("user.superbot.team-nic");
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &cy).await;
    join(&env, &acme, &dee).await;
    for m in [&mc, &md] {
        rules_let_it_through(&env, m);
    }

    // Cy's joins at once; Dee's is refused, audited once however often it is tried.
    for _ in 0..2 {
        let r = reconcile(&env).await;
        assert!(r["teamNetworks"]["errors"] == 1, "{r}");
    }
    assert!(devices(&env, &mc)["eth1"]["network"].as_str().is_some_and(|n| n.starts_with("superbot-team-")));
    assert!(devices(&env, &md).get("eth1").is_none());
    let failed: Vec<Value> = events(&env, "machine.team_network_joining").await.into_iter().filter(|e| e["outcome"] == "failure").collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("rebuild it to join"), "{failed:?}");
    assert_eq!(env.incus.instance(&md.label).unwrap().status, "Running", "left as it was");

    // A device of its own called eth1 is never replaced.
    env.incus.w().instances.get_mut(&md.label).unwrap().body["config"]["user.superbot.team-nic"] = json!("eth1");
    env.incus.w().instances.get_mut(&md.label).unwrap().body["devices"]["eth1"] = json!({ "type": "nic", "network": "incusbr0" });
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "the firewall sweep takes a NIC that isn't a team NIC off first: {r}");
    assert!(devices(&env, &md).get("eth1").is_none());
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joining": 1 }), "then it joins");
}

#[tokio::test]
async fn a_deleted_teams_network_goes_with_its_acl_and_its_name_once_its_containers_are_unplugged() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    let (ma, ml) = (ask(&env, &ada).await, ask(&env, &al).await);
    let net = devices(&env, &ma)["eth1"]["network"].as_str().unwrap().to_string();
    assert_eq!(env.incus.w().projects["superbot"]["restricted.networks.access"], format!("incusbr0,{net}"));

    // The operator's service for the team, in the default project, which botd's own
    // project doesn't list (ADR 0251).
    let mut svc = env.incus.instance(&ma.label).unwrap();
    svc.project = "default".into();
    svc.body["devices"] = json!({ "eth0": { "type": "nic", "network": net } });
    env.incus.w().instances.insert("acme-svc".into(), svc);
    let view = async || {
        let (code, v) = json_call(&env, "GET", "/api/machines/team-networks", "").await;
        assert_eq!(code, 200, "{v}");
        v["networks"].as_array().unwrap().iter().find(|n| n["id"] == net.as_str()).cloned()
    };
    let n = view().await.unwrap();
    assert_eq!((n["status"].as_str(), n["machines"].as_array().unwrap().len(), n["others"].as_i64()), (Some("team"), 2, Some(1)), "{n}");

    let (code, v) = json_call(&env, "DELETE", &format!("/api/teams/{acme}"), "").await;
    assert_eq!(code, 200, "{v}");
    // Unplugged while running; the service keeps it, and the view says so.
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 2, "kept": 1 }));
    let n = view().await.unwrap();
    assert_eq!((n["status"].as_str(), &n["machines"], n["others"].as_i64()), (Some("deleted"), &json!([]), Some(1)), "{n}");
    // Moved off, nothing is on it: it goes on the next pass.
    env.incus.w().instances.remove("acme-svc");
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "removed": 1 }));
    assert!(view().await.is_none());
    for m in [&ma, &ml] {
        let i = env.incus.instance(&m.label).unwrap();
        assert!(i.body["devices"].get("eth1").is_none() && i.status == "Running", "{}", i.body["devices"]);
    }
    {
        let w = env.incus.w();
        assert!(!w.networks.contains_key(&net) && !w.acls.contains_key(&net), "the network and its ACL");
        assert_eq!(w.projects["superbot"]["restricted.networks.access"], "incusbr0", "and its name on the access list");
        assert!(w.acls.contains_key("superbot-fw"), "the machines' firewall stays");
    }
    let removed = events(&env, "machine.team_network_removed").await;
    assert_eq!((removed.len(), removed[0]["targetId"].as_str(), removed[0]["details"]["team"].as_str()), (1, Some(net.as_str()), Some(acme.as_str())), "{removed:?}");
    assert!(reconcile(&env).await.get("teamNetworks").is_none());
}

#[tokio::test]
async fn admins_see_team_networks_checked_on_the_host() {
    let env = serve().await;
    let (code, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
    assert_eq!(code, 200, "{s}");
    assert_eq!(s["teamNetwork"]["kind"], "ovn", "{s}");
    assert_eq!(s["settings"]["teamNetwork"]["subnet"], SUBNET);
    let check = |s: &Value| s["checks"].as_array().unwrap().iter().find(|c| c["check"] == "team network").cloned().unwrap();
    assert_eq!(check(&s)["ok"], true, "{s}");

    // An Incus without isolated OVN networks or backup device overrides, or a bridge on
    // the same range, fails it.
    for x in ["network_ovn_isolated", "backup_override_config"] {
        env.incus.w().missing_extensions = vec![x.into()];
        let (_, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
        assert!(check(&s)["ok"] == false && check(&s).to_string().contains(x), "{x}: {s}");
    }
    env.incus.w().missing_extensions.clear();
    env.incus.w().networks.get_mut("incusbr0").unwrap()["config"]["ipv4.address"] = json!("10.248.1.1/24");
    let (_, s) = json_call(&env, "GET", "/api/machines/substrate?check=true", "").await;
    assert!(check(&s)["ok"] == false && check(&s).to_string().contains("10.248.1.0/24"), "{s}");

    // And then a team member's container isn't made, and the machine says why.
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    let (_, r) = json_call(&env, "POST", &format!("/api/users/{al}/machine"), "").await;
    let m = env.app.db.user_machine(&al).unwrap();
    assert!(m.last_error.as_deref().is_some_and(|e| e.contains("incusbr0")) || r.to_string().contains("incusbr0"), "{r} {:?}", m.last_error);
    assert!(env.incus.calls("POST", "/1.0/instances").is_empty());
    assert!(env.incus.calls("POST", "/1.0/networks").is_empty());
}
