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
    serve_with(team_network::Remove::WhenEmpty).await
}

async fn serve_with(remove: team_network::Remove) -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mport = machine_listener.local_addr().unwrap().port();
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    let e = cp.enroll_with(Enrollment::for_tests(9, mport, 7443).with_agent(AGENT.as_bytes()).with_hardening()).unwrap();
    cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    cp.team_network = Some(team_network::Settings { kind: team_network::Kind::Vpc, subnet: team_network::DEFAULT_SUBNET.into(), join: team_network::Join::NextBoot, remove });
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
    assert_eq!(s["teamNetwork"], json!({ "kind": "vpc", "subnet": team_network::DEFAULT_SUBNET, "join": "next-boot", "remove": "when-empty" }), "{s}");

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

async fn delete_team(env: &Env, team: &str) {
    let (code, v) = json_call(env, "DELETE", &format!("/api/teams/{team}"), "").await;
    assert_eq!(code, 200, "{v}");
}

fn has_network(env: &Env, id: &str) -> bool {
    env.fake.networks().iter().any(|n| n.id == id)
}

#[tokio::test]
async fn a_deleted_teams_network_is_removed_once_nothing_is_on_it() {
    let env = serve().await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (_gus, _) = user_with(env.port, &env.admin, "gus@example.com", "member").await;
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    let globex = team(&env, "Globex", "gus@example.com").await;
    join(&env, &acme, &al).await;
    join(&env, &globex, &dee).await;
    for uid in [&ada, &al, &dee] {
        ask(&env, uid).await;
    }
    let acme_net = env.fake.network_of(&pid(&env, &ada)).unwrap();
    let globex_net = env.fake.network_of(&pid(&env, &dee)).unwrap();
    env.fake.join_network(&globex_net, "globex-database");
    // Empty, labelled as a team network, but for a team this server never had: another
    // control plane's on the same account. Never touched.
    let label = team_network::label("otherbot", "t-theirs", "gb-lon").unwrap();
    let theirs = env.fake.ensure_team_network(&label, "gb-lon", team_network::DEFAULT_SUBNET).await.unwrap();

    // Acme is deleted: its machines leave its network as any leaver's do, then it goes.
    delete_team(&env, &acme).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "leaving": 2 }));
    assert!(has_network(&env, &acme_net), "not while machines of ours are on it");
    assert!(events(&env, "machine.team_network_kept").await.is_empty(), "nor is it said to be kept");
    let r = reconcile(&env).await;
    assert_eq!(r["teamNetworks"], json!({ "left": 2, "resumed": 2, "removed": 1 }), "{r}");
    assert!(!has_network(&env, &acme_net));
    let removed = events(&env, "machine.team_network_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    let e = &removed[0];
    assert_eq!((e["targetType"].as_str(), e["targetId"].as_str(), e["outcome"].as_str(), e["actorKind"].as_str()), (Some("team_network"), Some(acme_net.as_str()), Some("success"), Some("system")));
    assert_eq!((e["details"]["team"].as_str(), e["details"]["region"].as_str()), (Some(acme.as_str()), Some("gb-lon")));
    assert!(e["details"]["label"].as_str().unwrap().contains("-team-") && e["details"]["teamDeletedAt"].is_i64(), "{e}");
    assert!(reconcile(&env).await.get("teamNetworks").is_none(), "nothing left to do");
    assert_eq!((machine(&env, &ada).state, machine(&env, &al).state), (State::Running, State::Running));
    assert!(has_network(&env, &globex_net) && has_network(&env, &theirs.id), "a live team's, and one not ours");

    // Globex is deleted with its own service still on its network: kept, said once.
    delete_team(&env, &globex).await;
    reconcile(&env).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1, "resumed": 1, "kept": 1 }));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "kept": 1 }));
    let kept = events(&env, "machine.team_network_kept").await;
    assert_eq!((kept.len(), kept[0]["targetId"].as_str()), (1, Some(globex_net.as_str())), "{kept:?}");
    assert_eq!(kept[0]["details"]["reason"], "something is still on it");
    assert_eq!(env.fake.networks().into_iter().find(|n| n.id == globex_net).unwrap().members.into_iter().collect::<Vec<_>>(), ["globex-database"]);

    // A failure between passes that find it kept is said once, as is that it is kept.
    for _ in 0..2 {
        env.fake.fail_next("remove_team_network", crate::machines::provider::ProviderError::Api { status: 500, message: "try later".into() });
        assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "errors": 1 }));
        assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "kept": 1 }));
    }
    assert_eq!(events(&env, "machine.team_network_kept").await.len(), 1);
    let failed: Vec<Value> = events(&env, "machine.team_network_removed").await.into_iter().filter(|e| e["outcome"] == "failure").collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("try later"), "{failed:?}");

    // Once the service is moved off it goes.
    env.fake.leave_network(&globex_net, "globex-database");
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "removed": 1 }));
    assert!(!has_network(&env, &globex_net));
    assert!(reconcile(&env).await.get("teamNetworks").is_none());
    assert!(has_network(&env, &theirs.id), "still never touched");
}

#[tokio::test]
async fn with_remove_off_a_deleted_teams_network_stays() {
    let env = serve_with(team_network::Remove::Off).await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    ask(&env, &ada).await;
    let net = env.fake.network_of(&pid(&env, &ada)).unwrap();
    delete_team(&env, &acme).await;
    reconcile(&env).await;
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1, "resumed": 1 }), "it still leaves");
    assert!(reconcile(&env).await.get("teamNetworks").is_none());
    assert!(has_network(&env, &net), "the network stays, empty");
    assert_eq!(env.fake.calls("remove_team_network"), 0);
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
    let mem = NetworkMember { machine: pid(&env, &al), config: "c".into(), interface: "i".into(), active: true, needs_power_off: false };
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

/// As if `uid`'s machine's agent had said its egress rules let `subnet` through.
fn rules_say(env: &Env, uid: &str, state: &str, subnet: Option<&str>) {
    let m = machine(env, uid);
    let mut u = m.agent_upkeep.clone().unwrap_or_else(|| json!({}));
    u["teamNetwork"] = json!({ "subnet": subnet, "state": state });
    assert!(env.app.db.machine_upkeep_swap(&m.id, m.agent_upkeep.as_ref(), &u));
}

#[tokio::test]
async fn a_machine_made_before_its_owner_joined_a_team_joins_its_network_at_its_next_boot() {
    let env = serve().await;
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    ask(&env, &cy).await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    assert!(reconcile(&env).await.get("teamNetworks").is_none(), "Cy is on no team yet");
    join(&env, &acme, &cy).await;
    let cym = pid(&env, &cy);

    // Not until her machine's egress rules let the subnet through.
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }));
    rules_say(&env, &cy, "on", None);
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }));
    rules_say(&env, &cy, "failed", Some(team_network::DEFAULT_SUBNET));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }));
    assert_eq!(env.fake.calls("join_team_network"), 0);
    rules_say(&env, &cy, "on", Some(team_network::DEFAULT_SUBNET));

    // Nor while it isn't behind the firewall, whose inbound drops keep teammates apart.
    let fw = machine(&env, &cy).firewall_id.unwrap();
    env.fake.detach_firewall(&fw, &cym).await.unwrap();
    env.fake.fail_next("attach_firewall", crate::machines::provider::ProviderError::Api { status: 500, message: "try later".into() });
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }), "put back behind it this pass, after the sweep");
    assert_eq!(env.fake.calls("join_team_network"), 0);

    // Then it is put on, in use from its next boot; botd doesn't restart it for that.
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joining": 1 }));
    let net = env.fake.joining(&cym).expect("on Acme's network from its next boot");
    assert_eq!(env.fake.network_of(&cym), None, "not in use yet");
    let joining = events(&env, "machine.team_network_joining").await;
    assert_eq!(joining.len(), 1, "{joining:?}");
    assert_eq!((joining[0]["details"]["networkId"].as_str(), joining[0]["details"]["join"].as_str()), (Some(net.as_str()), Some("next-boot")));
    for _ in 0..2 {
        assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "pending": 1 }));
    }
    assert_eq!(machine(&env, &cy).state, State::Running);

    // She leaves before it boots: taken off at once, never powered off.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{cy}"), "").await;
    assert!(code == 200 || code == 204);
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1 }));
    assert_eq!((env.fake.joining(&cym), machine(&env, &cy).state), (None, State::Running));
    let left = events(&env, "machine.team_network_left").await;
    assert_eq!((left[0]["details"]["inUse"].as_bool(), left[0]["details"]["resuming"].as_bool()), (Some(false), Some(false)), "{left:?}");
    assert!(events(&env, "machine.team_network_leaving").await.is_empty());

    // Back on the team, a refusal is audited once however often it is tried.
    join(&env, &acme, &cy).await;
    let no = || crate::machines::provider::ProviderError::Api { status: 409, message: "it has more than one configuration profile".into() };
    for _ in 0..2 {
        env.fake.fail_next("join_team_network", no());
        assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "errors": 1 }));
    }
    let failed: Vec<Value> = events(&env, "machine.team_network_joining").await.into_iter().filter(|e| e["outcome"] == "failure").collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("configuration profile"), "{failed:?}");

    // Joined, and in use once she restarts it herself.
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joining": 1 }));
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{cy}/machine/suspend"), "").await.0, 200);
    assert_eq!(reconcile(&env).await.get("teamNetworks"), None, "off: nothing to do yet");
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{cy}/machine/resume"), "").await.0, 200);
    assert_eq!(env.fake.network_of(&cym).as_deref(), Some(net.as_str()));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joined": 1 }));
    let joined = events(&env, "machine.team_network_joined").await;
    assert_eq!((joined.len(), joined[0]["details"]["networkId"].as_str()), (1, Some(net.as_str())), "{joined:?}");
    assert!(reconcile(&env).await.get("teamNetworks").is_none(), "audited once");
}

/// An egress script shaped as the first boot's (ADR 0126), whose rules go to `rules`.
fn stand_in_egress(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("egress");
    let s = format!("#!/bin/sh\nset -e\n{{\n  cat <<'DENY'\n    ip daddr {{ 10.0.0.0/8 }} counter reject\nDENY\n}} > {}/rules\n", dir.display());
    std::fs::write(&path, s).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn with_when_idle_a_machine_is_restarted_onto_its_teams_network_once_it_runs_nothing() {
    use crate::machines_mtls_tests::{self as mtls, CHAT, agent_with_config, machine_for, send};
    let mut env = mtls::serve_with_control(
        |e| e,
        |cp| {
            cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
            cp.team_network = Some(team_network::Settings { kind: team_network::Kind::Vpc, subnet: team_network::DEFAULT_SUBNET.into(), join: team_network::Join::WhenIdle, remove: team_network::Remove::WhenEmpty });
        },
        |_| {},
    )
    .await;
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (cy, mid, token) = machine_for(&env, "cy@example.com").await;
    let dir = crate::db::temp_path("egress");
    let script = stand_in_egress(&dir);
    let m = agent_with_config(&mut env, &mid, &token, CHAT, |mut c| {
        c.egress_script = script.clone();
        c
    })
    .await;
    let reconcile = async |env: &mtls::Env| {
        let (code, r) = mtls::json_call(env, "POST", "/api/machines/reconcile", "").await;
        assert_eq!(code, 200, "{r}");
        r["teamNetworks"].clone()
    };
    let rules = async |env: &mtls::Env, want: Option<&str>| {
        for _ in 0..400 {
            crate::machines::heartbeats(&env.app, &env.cp).await;
            let u = env.app.db.machine(&mid).unwrap().agent_upkeep.unwrap_or_default();
            if u["teamNetwork"]["state"] == "on" && u["teamNetwork"]["subnet"].as_str() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the rules never let {want:?} through");
    };
    let pid = env.app.db.machine(&mid).unwrap().provider_id.unwrap();
    rules(&env, None).await;
    assert!(mtls::events(&env, "machine.team_network_rules_loaded").await.is_empty(), "nothing to say yet");

    // Cy joins a team: her agent lets its subnet through first, then the machine joins.
    let (code, t) = mtls::json_call(&env, "POST", "/api/teams", &json!({ "name": "Acme", "owner": "ada@example.com", "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let acme = t["id"].as_str().unwrap().to_string();
    let (code, v) = mtls::json_call(&env, "PUT", &format!("/api/teams/{acme}/members/{cy}"), r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(reconcile(&env).await, json!({ "waiting": 1 }));
    rules(&env, Some(team_network::DEFAULT_SUBNET)).await;
    let loaded = std::fs::read_to_string(dir.join("rules")).unwrap();
    assert!(loaded.starts_with(&format!("    ip daddr {} accept\n", team_network::DEFAULT_SUBNET)), "before the denies: {loaded}");
    let ev = mtls::events(&env, "machine.team_network_rules_loaded").await;
    assert_eq!((ev.len(), ev[0]["details"]["subnet"].as_str()), (1, Some(team_network::DEFAULT_SUBNET)), "{ev:?}");
    assert_eq!(reconcile(&env).await, json!({ "joining": 1 }));
    let net = env.fake.joining(&pid).unwrap();

    // Busy: left running until the run ends.
    let bot = env.app.db.create_bot_owned("Cy's", "#fff", "waddle", "claude", None, false, &cy, crate::acl::Visibility::Shared);
    let before = send(&env, &bot.id, "hello").await;
    for _ in 0..400 {
        if m.home.join("run.env").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(m.home.join("run.env").exists(), "the run started");
    assert_eq!(reconcile(&env).await, json!({ "pending": 1 }));
    assert_eq!(env.app.db.machine(&mid).unwrap().state, State::Running);
    std::fs::write(m.home.join("go-ahead"), "hi").unwrap();
    assert!(mtls::reply_after(&env, &bot.id, before).await.contains("said=hi"));

    // Idle: powered off, then on again, on the network.
    let mut r = json!({ "pending": 1 });
    for _ in 0..100 {
        r = reconcile(&env).await;
        if r.get("restarting").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(r, json!({ "pending": 1, "restarting": 1 }));
    assert_eq!(env.app.db.machine(&mid).unwrap().state, State::Suspended);
    assert_eq!(mtls::events(&env, "machine.team_network_restarting").await.len(), 1);
    assert_eq!(reconcile(&env).await, json!({ "resumed": 1 }));
    assert_eq!(env.app.db.machine(&mid).unwrap().state, State::Running);
    assert_eq!(env.fake.network_of(&pid).as_deref(), Some(net.as_str()));
    assert_eq!(reconcile(&env).await, json!({ "joined": 1 }));
    assert_eq!(mtls::events(&env, "machine.team_network_joined").await.len(), 1);

    // She leaves: off the network, and her rules no longer let it through.
    let (code, _) = mtls::json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{cy}"), "").await;
    assert!(code == 200 || code == 204);
    assert_eq!(reconcile(&env).await, json!({ "leaving": 1 }));
    assert_eq!(reconcile(&env).await, json!({ "left": 1, "resumed": 1 }));
    rules(&env, None).await;
    assert!(!std::fs::read_to_string(dir.join("rules")).unwrap().contains("accept"));
    let ev = mtls::events(&env, "machine.team_network_rules_loaded").await;
    assert_eq!((ev.len(), &ev[0]["details"]["subnet"]), (2, &Value::Null), "{ev:?}");
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

#[tokio::test]
async fn a_machine_with_linode_interfaces_joins_its_teams_network_only_while_off() {
    let env = serve().await;
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    ask(&env, &cy).await;
    let cym = pid(&env, &cy);
    env.fake.linode_interfaces_for(&cym);
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &cy).await;
    rules_say(&env, &cy, "on", Some(team_network::DEFAULT_SUBNET));

    // Running: with next-boot it waits for her to power it off; botd doesn't.
    for _ in 0..2 {
        assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "awaitingPowerOff": 1 }));
    }
    assert_eq!((env.fake.calls("join_team_network"), machine(&env, &cy).state), (0, State::Running));

    // Suspended, but not off at the provider yet: it waits for that too.
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{cy}/machine/suspend"), "").await.0, 200);
    env.fake.set(&cym, |m| m.status = "shutting_down".into());
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "waiting": 1 }));
    assert_eq!(env.fake.calls("join_team_network"), 0);

    // Off: given its interface, and left off, as she left it.
    env.fake.set(&cym, |m| m.status = "offline".into());
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joining": 1 }));
    let net = env.fake.joining(&cym).expect("on Acme's network from its next boot");
    let joining = events(&env, "machine.team_network_joining").await;
    assert_eq!((joining[0]["details"]["whileOff"].as_bool(), joining[0]["details"]["poweredOff"].as_bool()), (Some(true), Some(true)), "{joining:?}");
    assert_eq!(machine(&env, &cy).state, State::Suspended);
    assert!(reconcile(&env).await.get("teamNetworks").is_none(), "nothing more to do while it is off");
    assert_eq!(json_call(&env, "POST", &format!("/api/users/{cy}/machine/resume"), "").await.0, 200);
    assert_eq!(env.fake.network_of(&cym).as_deref(), Some(net.as_str()));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "joined": 1 }));

    // She leaves: powered off, taken off, powered on again.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{cy}"), "").await;
    assert!(code == 200 || code == 204);
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "leaving": 1 }));
    assert_eq!(reconcile(&env).await["teamNetworks"], json!({ "left": 1, "resumed": 1 }));
    assert_eq!((env.fake.network_of(&cym), machine(&env, &cy).state), (None, State::Running));

    // A Linode interface is taken off only while off, even one not in use yet.
    let n = env.fake.networks().into_iter().find(|n| n.id == net).unwrap();
    let n = TeamNetwork { id: n.id, label: n.label, region: n.region, subnet_id: n.subnet_id, subnet: n.subnet, created: false };
    let mem = NetworkMember { machine: cym.clone(), config: String::new(), interface: format!("{cym}-vpc"), active: false, needs_power_off: true };
    let leaves = env.fake.calls("leave_team_network");
    assert_eq!(team_network::leave(&env.app, &env.cp, env.fake.as_ref(), &n, Some(&acme), &machine(&env, &cy), &mem).await, team_network::Leave::Leaving);
    assert_eq!((env.fake.calls("leave_team_network"), machine(&env, &cy).state), (leaves, State::Suspended));
}

#[tokio::test]
async fn with_when_idle_a_machine_with_linode_interfaces_is_powered_off_to_join_and_on_again_whatever_happens() {
    use crate::machines_mtls_tests::{self as mtls, CHAT, agent_with_config, machine_for};
    let mut env = mtls::serve_with_control(
        |e| e,
        |cp| {
            cp.firewall_with(Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
            cp.team_network = Some(team_network::Settings { kind: team_network::Kind::Vpc, subnet: team_network::DEFAULT_SUBNET.into(), join: team_network::Join::WhenIdle, remove: team_network::Remove::WhenEmpty });
        },
        |_| {},
    )
    .await;
    let (_ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (cy, mid, token) = machine_for(&env, "cy@example.com").await;
    let dir = crate::db::temp_path("egress");
    let script = stand_in_egress(&dir);
    let _m = agent_with_config(&mut env, &mid, &token, CHAT, |mut c| {
        c.egress_script = script.clone();
        c
    })
    .await;
    let reconcile = async |env: &mtls::Env| {
        let (code, r) = mtls::json_call(env, "POST", "/api/machines/reconcile", "").await;
        assert_eq!(code, 200, "{r}");
        r["teamNetworks"].clone()
    };
    let rules = async |env: &mtls::Env, want: Option<&str>| {
        for _ in 0..400 {
            crate::machines::heartbeats(&env.app, &env.cp).await;
            let u = env.app.db.machine(&mid).unwrap().agent_upkeep.unwrap_or_default();
            if u["teamNetwork"]["state"] == "on" && u["teamNetwork"]["subnet"].as_str() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the rules never let {want:?} through");
    };
    let state = |env: &mtls::Env| env.app.db.machine(&mid).unwrap().state;
    let pid = env.app.db.machine(&mid).unwrap().provider_id.unwrap();
    env.fake.linode_interfaces_for(&pid);
    rules(&env, None).await;
    let (code, t) = mtls::json_call(&env, "POST", "/api/teams", &json!({ "name": "Acme", "owner": "ada@example.com", "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let acme = t["id"].as_str().unwrap().to_string();
    let member = async |env: &mtls::Env, method: &str| {
        let (code, v) = mtls::json_call(env, method, &format!("/api/teams/{acme}/members/{cy}"), r#"{"role":"member"}"#).await;
        assert!(matches!(code, 200 | 204), "{code} {v}");
    };
    member(&env, "PUT").await;
    assert_eq!(reconcile(&env).await, json!({ "waiting": 1 }));
    rules(&env, Some(team_network::DEFAULT_SUBNET)).await;

    // Idle: powered off, given its interface once off at the provider, powered on.
    assert_eq!(reconcile(&env).await, json!({ "restarting": 1 }));
    assert_eq!(state(&env), State::Suspended);
    let restarting = mtls::events(&env, "machine.team_network_restarting").await;
    assert_eq!((restarting.len(), restarting[0]["details"]["toJoin"].as_bool()), (1, Some(true)), "{restarting:?}");
    env.fake.set(&pid, |m| m.status = "shutting_down".into());
    assert_eq!(reconcile(&env).await, json!({ "waiting": 1 }), "still on its way off: held off");
    assert_eq!(state(&env), State::Suspended);
    // Held off too while some other network can't be read, until it times out (below).
    let stray = team_network::label("superbot", "another-team", "gb-lon").unwrap();
    env.fake.ensure_team_network(&stray, "gb-lon", team_network::DEFAULT_SUBNET).await.unwrap();
    let unreadable = || crate::machines::provider::ProviderError::Api { status: 500, message: "try later".into() };
    env.fake.fail_next("team_network_members", unreadable());
    assert_eq!(reconcile(&env).await, json!({ "errors": 1 }));
    assert_eq!(state(&env), State::Suspended);
    env.fake.set(&pid, |m| m.status = "offline".into());
    assert_eq!(reconcile(&env).await, json!({ "joining": 1, "resumed": 1 }));
    assert_eq!(state(&env), State::Running);
    let net = env.fake.network_of(&pid).expect("in use from the boot that follows");
    assert_eq!(reconcile(&env).await, json!({ "joined": 1 }));

    // She leaves, and rejoins; this time the Linode refuses the interface.
    member(&env, "DELETE").await;
    assert_eq!(reconcile(&env).await, json!({ "leaving": 1 }));
    assert_eq!(reconcile(&env).await, json!({ "left": 1, "resumed": 1 }));
    assert_eq!(env.fake.network_of(&pid), None);
    rules(&env, None).await;
    member(&env, "PUT").await;
    rules(&env, Some(team_network::DEFAULT_SUBNET)).await;
    assert_eq!(reconcile(&env).await, json!({ "restarting": 1 }));
    let no = crate::machines::provider::ProviderError::Api { status: 409, message: "it is on another VPC; it leaves that one first".into() };
    env.fake.fail_next("join_team_network", no);
    assert_eq!(reconcile(&env).await, json!({ "errors": 1, "resumed": 1 }), "powered on again without it");
    assert_eq!((state(&env), env.fake.network_of(&pid)), (State::Running, None));

    // Refused once, it isn't powered off again for it: it waits for her to.
    for _ in 0..2 {
        assert_eq!(reconcile(&env).await, json!({ "awaitingPowerOff": 1 }));
    }
    assert_eq!(state(&env), State::Running);
    assert_eq!(mtls::events(&env, "machine.team_network_restarting").await.len(), 2);
    let (code, _) = mtls::json_call(&env, "POST", &format!("/api/users/{cy}/machine/suspend"), "").await;
    assert_eq!(code, 200);
    assert_eq!(reconcile(&env).await, json!({ "joining": 1 }), "off by her hand: given it, and left off");
    assert_eq!((state(&env), env.fake.joining(&pid).as_deref()), (State::Suspended, Some(net.as_str())));
    assert_eq!(mtls::json_call(&env, "POST", &format!("/api/users/{cy}/machine/resume"), "").await.0, 200);
    assert_eq!(reconcile(&env).await, json!({ "joined": 1 }));

    // Once more: this time it never shows as off, and a network can't be read when its
    // time is up. It is powered on again without the interface, and not powered off
    // again for it.
    member(&env, "DELETE").await;
    assert_eq!(reconcile(&env).await, json!({ "leaving": 1 }));
    assert_eq!(reconcile(&env).await, json!({ "left": 1, "resumed": 1 }));
    rules(&env, None).await;
    member(&env, "PUT").await;
    rules(&env, Some(team_network::DEFAULT_SUBNET)).await;
    assert_eq!(reconcile(&env).await, json!({ "restarting": 1 }));
    env.fake.set(&pid, |m| m.status = "shutting_down".into());
    team_network::age_held_joins(&env.cp, 11 * 60_000);
    env.fake.fail_next("team_network_members", unreadable());
    assert_eq!(reconcile(&env).await, json!({ "errors": 1, "resumed": 1 }));
    assert_eq!((state(&env), env.fake.network_of(&pid)), (State::Running, None));
    let failed: Vec<Value> = mtls::events(&env, "machine.team_network_joining").await.into_iter().filter(|e| e["outcome"] == "failure").collect();
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("wasn't off at the provider within 10 minutes"), "{failed:?}");
    for _ in 0..2 {
        assert_eq!(reconcile(&env).await, json!({ "awaitingPowerOff": 1 }));
    }
    assert_eq!(mtls::events(&env, "machine.team_network_restarting").await.len(), 3);
}
