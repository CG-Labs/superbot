//! Machines that come up locked down (ADR 0035): the control plane's firewall, the
//! first boot that enrolls, and the reconciler's checks, end to end on loopback with
//! the in-memory provider. Nothing here talks to Linode.

use crate::machines::agent::{self, Config};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::fake::Fake;
use crate::machines::firewall::Settings;
use crate::machines::provider::{FirewallRule, MachineProvider, ProviderError};
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Env {
    port: u16,
    app: AppState,
    owner: String,
    admin: String,
    fake: Arc<Fake>,
    e: Arc<Enrollment>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";

fn on() -> Option<Settings> {
    Some(Settings {
        sources: Vec::new(),
        ssh: Vec::new(),
    })
}

/// botd with the fake provider and enrollment on, the firewall as `fw`, and
/// `timeout_ms` to enroll in (the default when None).
async fn serve(fw: Option<Settings>, timeout_ms: Option<i64>) -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mport = machine_listener.local_addr().unwrap().port();
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    let mut e = Enrollment::for_tests(9, mport, 7443).with_agent(AGENT.as_bytes());
    if let Some(ms) = timeout_ms {
        e.enroll_timeout_ms = ms;
    }
    let e = cp.enroll_with(e).unwrap();
    if let Some(s) = fw {
        cp.firewall_with(s).unwrap();
    }
    let cp = Arc::new(cp);
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = cp).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e.clone(), None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env {
        port,
        app,
        owner,
        admin,
        fake,
        e,
    }
}

async fn json_call(env: &Env, method: &str, path: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, "").await;
    (code, parse(&body))
}

async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(
        env.port,
        "GET",
        &format!("/api/audit?action={action}&limit=200"),
        &env.admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(env: &Env) -> Value {
    let (code, r) = json_call(env, "POST", "/api/machines/reconcile").await;
    assert_eq!(code, 200, "{r}");
    r
}

/// A member and the machine just asked for them. Returns their id, their login, and
/// the machine row.
async fn request(env: &Env, email: &str) -> (String, String, Value) {
    let (uid, login) = user_with(env.port, &env.admin, email, "member").await;
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine")).await;
    assert_eq!(code, 202, "{m}");
    (uid, login, m)
}

fn machine(env: &Env, m: &Value) -> crate::db::Machine {
    env.app.db.machine(m["id"].as_str().unwrap()).unwrap()
}

fn agent_rule() -> FirewallRule {
    FirewallRule {
        label: "agent-from-control-plane".into(),
        ports: "7443".into(),
        sources: vec!["127.0.0.1/32".into()],
    }
}

#[tokio::test]
async fn machines_come_up_behind_one_firewall_that_lets_in_only_the_control_plane() {
    let env = serve(on(), None).await;
    let (_, _, a) = request(&env, "ada@example.com").await;
    let a = machine(&env, &a);
    let fws = env.fake.firewalls();
    assert_eq!(fws.len(), 1);
    let fw = &fws[0];
    assert_eq!(
        (fw.label.as_str(), &fw.tags[..], &fw.rules[..]),
        ("superbot-fw", &["superbot".to_string()][..], &[agent_rule()][..]),
        "inbound dropped but for the agent port from botd's address; no SSH"
    );
    let pa = a.provider_id.clone().unwrap();
    assert!(fw.machines.contains(&pa), "behind it from the first boot");
    assert_eq!(env.fake.calls("attach_firewall"), 0, "attached by the create");
    assert_eq!(a.firewall_id.as_deref(), Some(fw.id.as_str()));
    let created = events(&env, "machine.created").await;
    assert_eq!(created[0]["details"]["firewallId"], fw.id.as_str());
    let made = events(&env, "machine.firewall_created").await;
    assert_eq!(
        (made.len(), made[0]["targetType"].as_str(), made[0]["targetId"].as_str()),
        (1, Some("firewall"), Some(fw.id.as_str())),
        "{made:?}"
    );

    let (_, _, b) = request(&env, "bea@example.com").await;
    let b = machine(&env, &b);
    let fws = env.fake.firewalls();
    assert_eq!(fws.len(), 1, "one firewall per control plane");
    assert_eq!(env.fake.calls("create_firewall"), 1);
    assert!(fws[0].machines.contains(b.provider_id.as_deref().unwrap()));
    assert_eq!(b.firewall_id, a.firewall_id);

    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 0, "{r}");
    assert!(events(&env, "machine.firewall_updated").await.is_empty());
    assert!(
        events(&env, "machine.enroll_timeout").await.is_empty(),
        "not before the deadline"
    );
}

#[tokio::test]
async fn ssh_and_other_sources_only_when_configured() {
    let env = serve(
        Some(Settings {
            sources: vec!["192.0.2.0/24".into()],
            ssh: vec!["203.0.113.7/32".into()],
        }),
        None,
    )
    .await;
    request(&env, "ada@example.com").await;
    assert_eq!(
        env.fake.firewalls()[0].rules,
        [
            FirewallRule {
                sources: vec!["192.0.2.0/24".into()],
                ..agent_rule()
            },
            FirewallRule {
                label: "ssh-from-operators".into(),
                ports: "22".into(),
                sources: vec!["203.0.113.7/32".into()],
            },
        ]
    );
}

#[tokio::test]
async fn off_by_default_no_firewall_is_touched() {
    let env = serve(None, None).await;
    let (uid, _, m) = request(&env, "ada@example.com").await;
    reconcile(&env).await;
    assert_eq!(
        json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"))
            .await
            .0,
        200
    );
    assert_eq!(env.fake.firewall_calls(), 0);
    assert_eq!(machine(&env, &m).firewall_id, None);
    assert!(env.fake.firewalls().is_empty());
}

#[tokio::test]
async fn the_reconciler_puts_machines_and_rules_back() {
    let env = serve(on(), None).await;
    let (_, _, a) = request(&env, "ada@example.com").await;
    let pa = machine(&env, &a).provider_id.unwrap();
    let fw = env.fake.firewalls()[0].id.clone();

    env.fake.set_firewall(&fw, |f| {
        f.foreign = true;
        f.machines.clear();
    });
    let r = reconcile(&env).await;
    assert_eq!(r["firewallAttached"], 1, "{r}");
    let f = &env.fake.firewalls()[0];
    assert!(!f.foreign && f.machines.contains(&pa));
    let updated = events(&env, "machine.firewall_updated").await;
    assert_eq!(updated.len(), 1);
    assert!(updated[0]["details"]["was"].is_null(), "{updated:?}");
    let attached = events(&env, "machine.firewall_attached").await;
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0]["details"]["providerId"], pa.as_str());

    reconcile(&env).await;
    assert_eq!(events(&env, "machine.firewall_updated").await.len(), 1);
    assert_eq!(events(&env, "machine.firewall_attached").await.len(), 1);

    env.fake.set_firewall(&fw, |f| f.enabled = false);
    reconcile(&env).await;
    assert!(env.fake.firewalls()[0].enabled, "turned back on");
    let updated = events(&env, "machine.firewall_updated").await;
    assert_eq!(updated.len(), 2);
    assert_eq!(updated[0]["details"]["was"], "disabled", "{updated:?}");
    env.fake.set_firewall(&fw, |f| f.enabled = false);
    request(&env, "bea@example.com").await;
    assert!(env.fake.firewalls()[0].enabled, "no new machine behind a disabled firewall");

    env.fake.delete_firewall(&fw).await.unwrap();
    reconcile(&env).await;
    let now = env.fake.firewalls();
    assert_eq!(now.len(), 1, "made again");
    assert!(now[0].machines.contains(&pa));
    assert_eq!(machine(&env, &a).firewall_id.as_ref(), Some(&now[0].id));

    // Moved onto someone else's firewall: Linode allows one, so it can't be put back.
    env.fake.set_firewall(&now[0].id, |f| {
        f.machines.clear();
    });
    env.fake.insert_firewall("not-ours", &[&pa]);
    reconcile(&env).await;
    reconcile(&env).await;
    let failed = events(&env, "machine.firewall_failed").await;
    assert_eq!(failed.len(), 1, "recorded once, not every pass: {failed:?}");
    assert_eq!(
        (failed[0]["outcome"].as_str(), failed[0]["details"]["step"].as_str()),
        (Some("failure"), Some("attach"))
    );
}

/// After a label prefix change, machines stay behind the firewall they were made
/// behind, which still gets our rules, until they go.
#[tokio::test]
async fn an_older_firewall_is_kept_right_until_its_machines_go() {
    let env = serve(on(), None).await;
    let (ua, _, a) = request(&env, "ada@example.com").await;
    let pa = machine(&env, &a).provider_id.unwrap();
    let old = env.fake.firewalls()[0].id.clone();
    env.fake.set_firewall(&old, |f| f.label = "oldprefix-fw".into());

    reconcile(&env).await;
    let new = env.fake.firewalls().into_iter().find(|f| f.label == "superbot-fw").unwrap();
    assert!(new.machines.is_empty(), "not moved: moving would open it for a moment");
    assert_eq!(machine(&env, &a).firewall_id.as_deref(), Some(old.as_str()));

    env.fake.set_firewall(&old, |f| {
        f.foreign = true;
        f.enabled = false;
    });
    reconcile(&env).await;
    let o = env.fake.firewalls().into_iter().find(|f| f.id == old).unwrap();
    assert!(!o.foreign && o.enabled && o.machines.contains(&pa), "{o:?}");
    assert_eq!(o.rules, [agent_rule()]);
    assert!(events(&env, "machine.firewall_failed").await.is_empty(), "no attach tried");
    assert!(events(&env, "machine.firewall_attached").await.is_empty());

    let (_, _, b) = request(&env, "bea@example.com").await;
    assert_eq!(machine(&env, &b).firewall_id.as_deref(), Some(new.id.as_str()));
    assert_eq!(
        json_call(&env, "DELETE", &format!("/api/users/{ua}/machine")).await.0,
        200
    );
    let left: Vec<String> = env.fake.firewalls().into_iter().map(|f| f.id).collect();
    assert_eq!(left, [new.id], "the older one goes with its last machine");
}

#[tokio::test]
async fn no_firewall_no_machine() {
    let env = serve(on(), None).await;
    env.fake.fail_next("find_firewall", ProviderError::RateLimited);
    let (_, _, m) = request(&env, "ada@example.com").await;
    let row = machine(&env, &m);
    assert_eq!(row.state, State::Pending);
    assert!(row.last_error.unwrap().contains("firewall"));
    assert_eq!(env.fake.calls("create"), 0, "nothing left open");
    assert!(events(&env, "machine.enroll_token_issued").await.is_empty());
    let failed = events(&env, "machine.create_failed").await;
    assert_eq!(
        (failed[0]["details"]["step"].as_str(), failed[0]["details"]["retrying"].as_bool()),
        (Some("firewall"), Some(true))
    );
    reconcile(&env).await;
    let row = machine(&env, &m);
    assert!(row.provider_id.is_some(), "made on the next pass");
    assert!(env.fake.firewalls()[0].machines.contains(row.provider_id.as_deref().unwrap()));

    env.fake.fail_next(
        "find_firewall",
        ProviderError::Api {
            status: 403,
            message: "Your OAuth token is not authorized to use this endpoint.".into(),
        },
    );
    let (uid, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (code, m) = json_call(&env, "POST", &format!("/api/users/{uid}/machine")).await;
    assert_eq!((code, m["machine"]["state"].as_str()), (502, Some("error")), "{m}");
    assert_eq!(env.fake.calls("create"), 1);
}

#[tokio::test]
async fn the_last_machine_out_deletes_the_firewall() {
    let env = serve(on(), None).await;
    let (ua, _, _) = request(&env, "ada@example.com").await;
    let (ub, _, b) = request(&env, "bea@example.com").await;
    let fw = env.fake.firewalls()[0].id.clone();

    let del = |u: String| {
        let env = &env;
        async move {
            json_call(env, "DELETE", &format!("/api/users/{u}/machine"))
                .await
                .0
        }
    };
    assert_eq!(del(ua).await, 200);
    let left = env.fake.firewalls();
    assert_eq!(left.len(), 1, "bea's machine still needs it");
    assert_eq!(
        left[0].machines.iter().collect::<Vec<_>>(),
        [&machine(&env, &b).provider_id.unwrap()]
    );
    assert_eq!(events(&env, "machine.firewall_detached").await.len(), 1);

    env.fake.fail_next("delete_firewall", ProviderError::Transport("reset".into()));
    assert_eq!(del(ub).await, 200, "the machine goes anyway");
    assert_eq!(env.fake.firewalls().len(), 1, "an empty firewall is left");
    let failed = events(&env, "machine.firewall_failed").await;
    assert_eq!(failed[0]["details"]["step"], "delete");

    let (uc, _, c) = request(&env, "cy@example.com").await;
    assert_eq!(machine(&env, &c).firewall_id.as_deref(), Some(fw.as_str()), "reused");
    assert_eq!(env.fake.calls("create_firewall"), 1);
    env.fake.set_firewall(&fw, |f| f.others = 1);
    assert_eq!(del(uc).await, 200);
    assert_eq!(env.fake.firewalls().len(), 1, "it still covers someone's NodeBalancer");
    assert!(events(&env, "machine.firewall_deleted").await.is_empty());

    env.fake.set_firewall(&fw, |f| f.others = 0);
    let (ud, _, _) = request(&env, "di@example.com").await;
    assert_eq!(del(ud).await, 200);
    assert!(env.fake.firewalls().is_empty());
    let deleted = events(&env, "machine.firewall_deleted").await;
    assert_eq!(
        (deleted.len(), deleted[0]["targetId"].as_str()),
        (1, Some(fw.as_str()))
    );
}

fn token_in(user_data: &str) -> String {
    let at = user_data.find("content: \"sbe_").unwrap() + "content: \"".len();
    user_data[at..].split('"').next().unwrap().to_string()
}

#[tokio::test]
async fn machines_that_dont_enroll_in_time_are_reported() {
    let env = serve(None, Some(0)).await;
    let (uid, login, m) = request(&env, "ada@example.com").await;
    let mid = m["id"].as_str().unwrap().to_string();
    let row = machine(&env, &m);
    env.fake.set(row.provider_id.as_deref().unwrap(), |pm| {
        pm.ipv4 = Some("127.0.0.1".into())
    });
    let token = token_in(&env.fake.user_data(&row.label).unwrap());

    reconcile(&env).await;
    reconcile(&env).await;
    let (_, mine) = json_call(&env, "GET", &format!("/api/users/{uid}/machine")).await;
    assert!(mine["enrollOverdueAt"].as_i64().is_some(), "{mine}");
    let (_, own) = call(env.port, "GET", "/api/machine", &login, "").await;
    assert!(parse(&own)["enrollOverdueAt"].as_i64().is_some(), "{own}");
    let late = events(&env, "machine.enroll_timeout").await;
    assert_eq!(late.len(), 1, "once, not every pass");
    assert_eq!(
        (late[0]["outcome"].as_str(), late[0]["details"]["enrollment"].as_str()),
        (Some("failure"), Some("none"))
    );

    let cfg = Config {
        control_url: env.e.url.clone(),
        machine_id: mid.clone(),
        ca_pem: env.e.ca_pem().into(),
        state_dir: crate::db::temp_path("agent"),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        token: Some(Zeroizing::new(token)),
        token_file: None,
        home: crate::db::temp_path("agent-home"),
        api_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        botctl: std::path::PathBuf::from("/nonexistent/botctl"),
        harness_path: "/usr/bin:/bin".into(),
        max_jobs: 8,
        tools: crate::db::temp_path("agent-tools"),
        exe: crate::db::temp_path("agent-exe"),
    };
    agent::enroll(&cfg).await.unwrap();
    let row = env.app.db.machine(&mid).unwrap();
    assert_eq!(
        (row.enrollment.as_str(), row.enroll_overdue_at, row.enroll_by),
        ("enrolled", None, None),
        "a late enrollment still counts"
    );
    reconcile(&env).await;
    assert_eq!(events(&env, "machine.enroll_timeout").await.len(), 1);

    let (ub, _, b) = request(&env, "bea@example.com").await;
    reconcile(&env).await;
    assert!(machine(&env, &b).enroll_overdue_at.is_some());
    let (code, _) = json_call(&env, "POST", &format!("/api/users/{ub}/machine/enrollment")).await;
    assert_eq!(code, 200);
    assert_eq!(machine(&env, &b).enroll_overdue_at, None, "a new token, a new clock");
}

#[tokio::test]
async fn the_token_is_kept_nowhere_but_the_machine() {
    let env = serve(on(), None).await;
    let (uid, _, m) = request(&env, "ada@example.com").await;
    let row = machine(&env, &m);
    let token = token_in(&env.fake.user_data(&row.label).unwrap());
    assert!(token.starts_with("sbe_") && token.len() > 20);
    reconcile(&env).await;
    let (_, t) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/enrollment")).await;
    let second = t["token"].as_str().unwrap().to_string();

    for path in ["/api/audit?limit=500", "/api/machines"] {
        let (_, body) = call(env.port, "GET", path, &env.owner, "").await;
        assert!(!body.contains(&token) && !body.contains(&second), "{path}");
    }
    let data = &env.app.cfg.data_dir;
    for f in ["app.sqlite", "app.sqlite-wal"] {
        let bytes = std::fs::read(data.join(f)).unwrap_or_default();
        for t in [&token, &second] {
            assert!(
                !bytes.windows(t.len()).any(|w| w == t.as_bytes()),
                "{f} holds a token"
            );
        }
    }
}
