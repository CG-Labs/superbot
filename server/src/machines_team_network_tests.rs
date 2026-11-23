//! A network of its own per team (ADR 0189), end to end on loopback with the
//! in-memory provider: a team's machines join its network from their first boot, one
//! network per team, made once; nobody else's do; and a machine whose owner leaves the
//! team is powered off, taken off it, and powered on again. Nothing here talks to Linode.

use crate::machines::enroll::{self, Enrollment};
use crate::machines::fake::Fake;
use crate::machines::firewall::Settings;
use crate::machines::provider::{MachineProvider, NetworkMember, TeamNetwork};
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
    fake: Arc<Fake>,
    cp: Arc<ControlPlane>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";

async fn serve() -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mport = machine_listener.local_addr().unwrap().port();
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    let e = cp.enroll_with(Enrollment::for_tests(9, mport, 7443).with_agent(AGENT.as_bytes()).with_hardening()).unwrap();
    cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    cp.team_network = Some(team_network::Settings { subnet: team_network::DEFAULT_SUBNET.into() });
    let cp = Arc::new(cp);
    let held = cp.clone();
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e, None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, fake, cp: held }
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

/// A team owned by `owner` (an email), giving no machines on joining: each member's
/// machine is their own, and goes where their team's go.
async fn team(env: &Env, name: &str, owner: &str) -> String {
    let (code, t) = json_call(env, "POST", "/api/teams", &json!({ "name": name, "owner": owner, "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    t["id"].as_str().unwrap().to_string()
}

async fn join(env: &Env, team: &str, uid: &str) {
    let (code, v) = json_call(env, "PUT", &format!("/api/teams/{team}/members/{uid}"), r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");
}

async fn ask(env: &Env, uid: &str) {
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
}

fn machine(env: &Env, uid: &str) -> crate::db::Machine {
    env.app.db.user_machine(uid).unwrap()
}

fn pid(env: &Env, uid: &str) -> String {
    machine(env, uid).provider_id.unwrap()
}

#[tokio::test]
async fn a_teams_machines_share_a_network_of_their_own_and_leave_it_with_the_team() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let (_gus, _) = user_with(env.port, &env.admin, "gus@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    let globex = team(&env, "Globex", "gus@example.com").await;
    join(&env, &acme, &al).await;
    join(&env, &globex, &dee).await;
    for uid in [&ada, &al, &cy, &dee] {
        ask(&env, uid).await;
    }

    // One network per team, each made once, in the machines' region.
    let nets = env.fake.networks();
    assert_eq!(nets.len(), 2, "{nets:?}");
    let acme_net = env.fake.network_of(&pid(&env, &ada)).expect("Ada's machine is on Acme's network");
    assert_eq!(env.fake.network_of(&pid(&env, &al)).as_deref(), Some(acme_net.as_str()), "and so is her teammate's");
    let globex_net = env.fake.network_of(&pid(&env, &dee)).unwrap();
    assert_ne!(acme_net, globex_net, "teams apart");
    assert_eq!(env.fake.network_of(&pid(&env, &cy)), None, "someone in no team is on none");
    for n in &nets {
        assert_eq!((n.region.as_str(), n.subnet.as_str()), ("gb-lon", team_network::DEFAULT_SUBNET));
        assert!(n.label.starts_with("superbot-team-") && n.label.ends_with("-gb-lon") && !n.label.contains(&acme), "{}", n.label);
    }
    let made = events(&env, "machine.team_network_created").await;
    assert_eq!(made.len(), 2, "{made:?}");
    let acme_made = made.iter().find(|e| e["details"]["team"] == acme.as_str()).unwrap();
    assert_eq!((acme_made["targetType"].as_str(), acme_made["targetId"].as_str()), (Some("team_network"), Some(acme_net.as_str())));
    assert_eq!(acme_made["details"]["subnet"], team_network::DEFAULT_SUBNET);
    let created = events(&env, "machine.created").await;
    let on = |uid: &str| created.iter().find(|e| e["details"]["userId"] == uid).unwrap()["details"]["teamNetwork"].clone();
    assert_eq!((on(&ada), on(&cy)), (json!(acme_net), Value::Null));

    // Inside, every user on a team's machine reaches the subnet; no one else's does.
    let accept = format!("ip daddr {} accept", team_network::DEFAULT_SUBNET);
    assert!(env.fake.user_data(&machine(&env, &ada).label).unwrap().contains(&accept));
    assert!(!env.fake.user_data(&machine(&env, &cy).label).unwrap().contains(&accept));

    // The substrate says so.
    let (_, s) = json_call(&env, "GET", "/api/machines/substrate", "").await;
    assert_eq!(s["teamNetwork"], json!({ "kind": "vpc", "subnet": team_network::DEFAULT_SUBNET }), "{s}");

    // Running, and the team's own service on its network: nothing to do.
    env.fake.join_network(&acme_net, "acme-database");
    for _ in 0..2 {
        let r = reconcile(&env).await;
        assert!(r.get("teamNetworks").is_none(), "{r}");
    }
    assert_eq!(machine(&env, &dee).state, State::Running);

    // Dee leaves Globex: her machine is powered off, taken off, then powered on again.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/teams/{globex}/members/{dee}"), "").await;
    assert!(code == 200 || code == 204, "{code} {v}");
    let r = reconcile(&env).await;
    assert_eq!(r["teamNetworks"], json!({ "leaving": 1 }), "{r}");
    assert_eq!(machine(&env, &dee).state, State::Suspended);
    let leaving = events(&env, "machine.team_network_leaving").await;
    assert_eq!((leaving.len(), leaving[0]["targetId"].as_str()), (1, Some(machine(&env, &dee).id.as_str())));
    assert_eq!((leaving[0]["details"]["team"].as_str(), leaving[0]["details"]["ownersTeam"].as_str()), (Some(globex.as_str()), None));
    let r = reconcile(&env).await;
    assert_eq!(r["teamNetworks"], json!({ "left": 1, "resumed": 1 }), "{r}");
    assert_eq!(env.fake.network_of(&pid(&env, &dee)), None);
    let left = events(&env, "machine.team_network_left").await;
    assert_eq!((left.len(), left[0]["details"]["resuming"].as_bool()), (1, Some(true)), "{left:?}");
    assert_eq!(machine(&env, &dee).state, State::Running, "back on, off the network");
    assert!(reconcile(&env).await.get("teamNetworks").is_none());

    // Al leaves Acme while his machine is off: taken off, and left off.
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{al}/machine/suspend"), "").await;
    assert_eq!(code, 200);
    let (code, _) = json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{al}"), "").await;
    assert!(code == 200 || code == 204);
    let r = reconcile(&env).await;
    assert_eq!(r["teamNetworks"], json!({ "left": 1 }), "{r}");
    let left = events(&env, "machine.team_network_left").await;
    assert_eq!(left[0]["details"]["resuming"], false, "{left:?}");
    assert_eq!(machine(&env, &al).state, State::Suspended, "as he left it");

    // Ada's machine and Acme's own service stay on Acme's network throughout.
    let acme_now = env.fake.networks().into_iter().find(|n| n.id == acme_net).unwrap();
    assert_eq!(acme_now.members.into_iter().collect::<Vec<_>>(), {
        let mut m = vec![pid(&env, &ada), "acme-database".to_string()];
        m.sort();
        m
    });
}

#[tokio::test]
async fn a_machine_powered_off_to_leave_is_powered_on_again_whatever_happens_meanwhile() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (bo, _) = user_with(env.port, &env.admin, "bo@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    join(&env, &acme, &bo).await;
    join(&env, &acme, &cy).await;
    for uid in [&ada, &al, &bo, &cy] {
        ask(&env, uid).await;
    }
    let net = env.fake.network_of(&pid(&env, &ada)).unwrap();
    let leave = async |uid: &str| assert!(matches!(json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{uid}"), "").await.0, 200 | 204));

    // Made under another MACHINE_LABEL_PREFIX: its machines still leave it.
    let old = env.fake.networks().into_iter().find(|n| n.id == net).unwrap().label.replacen("superbot", "oldbot", 1);
    env.fake.relabel_network(&net, &old);
    // And a new teammate's machine joins it, not a second one under the new prefix.
    let (dot, _) = user_with(env.port, &env.admin, "dot@example.com", "member").await;
    join(&env, &acme, &dot).await;
    ask(&env, &dot).await;
    assert_eq!(env.fake.network_of(&pid(&env, &dot)).as_deref(), Some(net.as_str()));
    assert_eq!(env.fake.networks().len(), 1);

    // Al rejoins before he is taken off: his machine is powered on, still on the network.
    leave(&al).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "leaving": 1 }));
    assert_eq!(machine(&env, &al).state, State::Suspended);
    join(&env, &acme, &al).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "resumed": 1 }));
    assert_eq!(machine(&env, &al).state, State::Running);
    assert_eq!(env.fake.network_of(&pid(&env, &al)).as_deref(), Some(net.as_str()));

    // Had he rejoined after the sweep looked, it backs off under the lock, on or off.
    let n = TeamNetwork { id: net.clone(), label: old.clone(), region: "gb-lon".into(), subnet_id: String::new(), subnet: String::new(), created: false };
    let mem = NetworkMember { machine: pid(&env, &al), config: "c".into(), interface: "i".into() };
    let leave_now = async || team_network::leave(&env.app, &env.cp, env.fake.as_ref(), &n, Some(&acme), &machine(&env, &al), &mem).await;
    assert_eq!(leave_now().await, team_network::Leave::Waiting);
    assert_eq!(machine(&env, &al).state, State::Running);
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{al}/machine/suspend"), "").await.0, 200);
    assert_eq!(leave_now().await, team_network::Leave::Waiting);
    assert_eq!(env.fake.network_of(&pid(&env, &al)).as_deref(), Some(net.as_str()), "still on it");
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{al}/machine/resume"), "").await.0, 200);

    // Bo's machine won't boot at first: it is tried again until it does.
    leave(&bo).await;
    reconcile(&env).await;
    env.fake.fail_next("boot", crate::machines::provider::ProviderError::Api { status: 500, message: "try later".into() });
    let r = reconcile(&env).await;
    assert_eq!(r["teamNetworks"], json!({ "left": 1, "errors": 1 }), "{r}");
    assert_eq!((machine(&env, &bo).state, env.fake.network_of(&pid(&env, &bo))), (State::Suspended, None));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "resumed": 1 }));
    assert_eq!(machine(&env, &bo).state, State::Running);
    assert!(reconcile(&env).await.get("teamNetworks").is_none(), "nothing left to do");

    // Cy's won't boot either, and she is disabled before the retry: it stays off.
    leave(&cy).await;
    reconcile(&env).await;
    env.fake.fail_next("boot", crate::machines::provider::ProviderError::Api { status: 500, message: "try later".into() });
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1, "errors": 1 }));
    env.app.db.update_user(&cy, crate::db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    for _ in 0..2 {
        assert!(reconcile(&env).await.get("teamNetworks").is_none());
    }
    assert_eq!(machine(&env, &cy).state, State::Suspended, "a disabled user's machine is never powered on");
}

#[tokio::test]
async fn a_network_that_cant_be_made_holds_the_create_back() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    team(&env, "Acme", "ada@example.com").await;
    env.fake.fail_next("ensure_team_network", crate::machines::provider::ProviderError::Api { status: 400, message: "VPC limit reached".into() });
    let (code, m) = json_call(&env, "POST", &format!("/api/users/{ada}/machine"), "").await;
    assert!(code >= 400 || m["state"] == "error", "{code} {m}");
    let m = machine(&env, &ada);
    assert_eq!((m.state, m.provider_id.as_deref()), (State::Error, None), "never made off its network");
    assert!(m.last_error.as_deref().unwrap().contains("The team's network couldn't be set up"), "{:?}", m.last_error);
    assert_eq!(env.fake.calls("create"), 0);
    let failed = events(&env, "machine.create_failed").await;
    assert_eq!(failed[0]["details"]["step"], "network");
}
