//! Enrollment and mutual TLS between botd and a machine agent (ADR 0031), end to end on
//! loopback: the real router, botd's machine port, and the real agent, with the
//! in-memory provider. Nothing here talks to Linode. Bot runs on a machine (ADR 0036)
//! go through the real agent too, with a stand-in harness on its PATH.

use crate::machines::agent::{self, Agent, Config, Identity};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::{Refusal, Routing, Target};
use crate::machines::{ControlPlane, State, pki, wire};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub(crate) struct Env {
    pub port: u16,
    pub app: AppState,
    pub admin: String,
    pub fake: Arc<Fake>,
    pub e: Arc<Enrollment>,
    pub cp: Arc<ControlPlane>,
    pub agent_listener: Option<TcpListener>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";

/// botd with the fake provider, routing on, and enrollment on a loopback machine port.
async fn serve() -> Env {
    serve_with(|e| e).await
}

/// `serve`, with enrollment changed by `f`.
pub(crate) async fn serve_with(f: impl FnOnce(Enrollment) -> Enrollment) -> Env {
    serve_with_auth(f, |_| {}).await
}

/// `serve_with`, with botd's auth settings changed by `tweak` too.
pub(crate) async fn serve_with_auth(f: impl FnOnce(Enrollment) -> Enrollment, tweak: impl FnOnce(&mut crate::Auth) + Send + 'static) -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let (mport, aport) = (
        machine_listener.local_addr().unwrap().port(),
        agent_listener.local_addr().unwrap().port(),
    );
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    cp.routing = Routing::On;
    let e = cp
        .enroll_with(f(Enrollment::for_tests(9, mport, aport).with_agent(AGENT.as_bytes())))
        .unwrap();
    let cp = Arc::new(cp);
    let shared = cp.clone();
    let (port, app, owner, _, router) =
        crate::tests::serve_app_and_router(move |a| {
            a.machines = shared;
            tweak(a);
        })
        .await;
    let api = enroll::Api {
        router,
        host: format!("127.0.0.1:{port}"),
    };
    tokio::spawn(enroll::serve(
        machine_listener,
        app.clone(),
        e.clone(),
        Some(api),
    ));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env {
        port,
        app,
        admin,
        fake,
        e,
        cp,
        agent_listener: Some(agent_listener),
    }
}

pub(crate) async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, body).await;
    (code, parse(&body))
}

pub(crate) async fn events(env: &Env, action: &str) -> Vec<Value> {
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

pub(crate) fn token_in(user_data: &str) -> String {
    let at = user_data
        .find("content: \"sbe_")
        .expect("a token in the user data")
        + "content: \"".len();
    user_data[at..].split('"').next().unwrap().to_string()
}

/// A member with a running machine on 127.0.0.1, assigned to them. Returns their id,
/// the machine's id, and the token its cloud-init user data carries.
pub(crate) async fn machine_for(env: &Env, email: &str) -> (String, String, String) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
    let m = env.app.db.machine(m["id"].as_str().unwrap()).unwrap();
    env.fake.set(m.provider_id.as_deref().unwrap(), |pm| {
        pm.ipv4 = Some("127.0.0.1".into())
    });
    let (code, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Running);
    assert!(env.app.db.assign_machine(&m.id, None));
    let ud = env
        .fake
        .user_data(&m.label)
        .expect("the machine was created with user data");
    assert!(
        ud.contains(env.e.ca_pem().lines().nth(1).unwrap())
            && ud.contains(&format!("SUPERBOT_MACHINE_ID={}", m.id)),
        "{ud}"
    );
    (uid, m.id, token_in(&ud))
}

pub(crate) fn config(env: &Env, machine_id: &str, token: Option<&str>) -> Config {
    Config {
        control_url: env.e.url.clone(),
        machine_id: machine_id.into(),
        ca_pem: env.e.ca_pem().into(),
        state_dir: crate::db::temp_path("agent"),
        listen: SocketAddr::from(([127, 0, 0, 1], env.e.agent_port)),
        token: token.map(|t| Zeroizing::new(t.to_string())),
        token_file: None,
        home: crate::db::temp_path("agent-home"),
        api_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        botctl: PathBuf::from("/nonexistent/botctl"),
        harness_path: "/usr/bin:/bin".into(),
        max_jobs: 8,
        tools: crate::db::temp_path("agent-tools"),
        exe: crate::db::temp_path("agent-exe"),
        // Tests can't make users: the Bots' user is whoever runs them.
        bot_user: crate::machines::runas::current_user().unwrap(),
        allow_own_user: true,
        screens: crate::machines_mtls_tests::no_screens(),
        teammates: crate::db::temp_path("agent-teammates"),
        teammate_stand_in: None,
    }
}

/// Screen settings that find none of the screen's programs.
pub(crate) fn no_screens() -> crate::machines::display::Settings {
    crate::machines::display::Settings {
        path: "/nonexistent".into(),
        tmp: crate::db::temp_path("agent-tmp"),
        ..Default::default()
    }
}

/// A call to botd's machine port, as `id` (or with no certificate).
async fn raw(
    env: &Env,
    id: Option<&Identity>,
    method: &str,
    path: &str,
    body: Value,
) -> Result<(u16, Value), String> {
    let config = pki::client_config(
        &pki::cert_der(env.e.ca_pem()).unwrap(),
        id.map(Identity::chain),
    )?;
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .unwrap();
    let req = client.request(method.parse().unwrap(), format!("{}{path}", env.e.url));
    let req = if method == "GET" {
        req
    } else {
        req.json(&body)
    };
    let r = req.send().await.map_err(|e| format!("{e:?}"))?;
    Ok((r.status().as_u16(), r.json().await.unwrap_or(Value::Null)))
}

fn reason_count(evs: &[Value], reason: &str) -> usize {
    evs.iter()
        .filter(|e| e["details"]["reason"] == reason)
        .count()
}

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn a_machine_enrolls_once_then_answers_over_mutual_tls() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    assert_eq!(env.app.db.machine(&mid).unwrap().enrollment, "none");
    assert_eq!(
        env.cp.route(&env.app.db, &uid),
        Err(Refusal::NotEnrolled),
        "running isn't enough: it must enroll"
    );

    let cfg = config(&env, &mid, Some(&token));
    let id = agent::enroll(&cfg).await.unwrap();
    assert_eq!(
        (id.user_id.as_str(), id.machine_id.as_str()),
        (uid.as_str(), mid.as_str())
    );
    assert!(
        cfg.state_dir.join("identity.pem").exists() && agent::load(&cfg).is_some(),
        "the key never left the machine"
    );
    let m = env.app.db.machine(&mid).unwrap();
    assert_eq!(
        (m.enrollment.as_str(), m.enrolled_at.is_some()),
        ("enrolled", true)
    );
    let enrolled = events(&env, "machine.enrolled").await;
    assert_eq!(enrolled.len(), 1);
    assert_eq!(
        (
            enrolled[0]["actorId"].as_str(),
            enrolled[0]["onBehalfOf"].as_str(),
            enrolled[0]["details"]["fingerprint"].as_str()
        ),
        (
            Some("machine_agent"),
            Some(uid.as_str()),
            Some(id.fingerprint.as_str())
        )
    );
    // The first enrollment says how long the machine took to come up (ADR 0119).
    let d = &enrolled[0]["details"];
    assert_eq!((d["first"].as_bool(), d["provider"].as_str(), d["tier"].as_str()), (Some(true), Some(m.provider.as_str()), Some("starter")), "{d}");
    let took = d["sinceRequestSeconds"].as_i64().unwrap_or(-1);
    assert!((0..=(crate::db::now() - m.created_at) / 1000).contains(&took), "{d}");

    let again = agent::enroll(&config(&env, &mid, Some(&token)))
        .await
        .err()
        .expect("a token works once");
    assert!(
        again.permanent && again.message.contains("401"),
        "{}",
        again.message
    );
    assert_eq!(
        reason_count(&events(&env, "machine.enroll_failed").await, "token_used"),
        1
    );
    assert_eq!(
        env.app.db.machine_certs(&mid).len(),
        1,
        "the second try got nothing"
    );

    let (code, s) = raw(
        &env,
        Some(&id),
        "GET",
        &format!("/v1/machines/{mid}"),
        Value::Null,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            code,
            s["enrollment"].as_str(),
            s["state"].as_str(),
            s["userId"].as_str()
        ),
        (200, Some("enrolled"), Some("running"), Some(uid.as_str()))
    );

    let agent = Agent::new(cfg, id).unwrap();
    let fp = agent.identity().fingerprint.clone();
    tokio::spawn(agent::serve(env.agent_listener.take().unwrap(), agent));
    let (_, r) = json_call(&env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(r["heartbeats"], 1, "{r}");
    let m = env.app.db.machine(&mid).unwrap();
    assert_eq!(
        (
            m.agent_seen_at.is_some(),
            m.agent_version.as_deref(),
            m.agent_error.as_deref()
        ),
        (true, Some(agent::VERSION), None)
    );

    let Ok(Target::Machine(to)) = env.cp.route(&env.app.db, &uid) else {
        panic!("A's machine is the target")
    };
    assert_eq!(
        (to.machine_id.as_str(), to.pins.as_slice()),
        (mid.as_str(), &[fp][..])
    );
    let hb = env
        .cp
        .link
        .check(&env.app, &to, &["sh", "no-such-harness"])
        .await
        .unwrap();
    assert_eq!(
        (hb.protocol, hb.missing.as_slice()),
        (
            wire::PROTOCOL,
            &["sh".to_string(), "no-such-harness".to_string()][..]
        ),
        "the agent runs only harnesses it knows, and says which it can't"
    );
    assert_eq!(
        crate::machines::route::fit(&hb, "claude"),
        Err(Refusal::NoBotctl),
        "no botctl there, so no approvals: it can't run Bots"
    );
}

#[tokio::test]
async fn the_agent_enrolls_from_its_token_file_and_keeps_its_key_across_restarts() {
    let mut env = serve().await;
    let (_, mid, token) = machine_for(&env, "ada@example.com").await;
    let mut cfg = config(&env, &mid, None);
    std::fs::create_dir_all(&cfg.state_dir).unwrap();
    let file = cfg.state_dir.join("enroll-token");
    std::fs::write(&file, format!("{token}\n")).unwrap();
    cfg.token_file = Some(file.clone());
    drop(env.agent_listener.take());

    let restart = cfg.clone();
    let first = tokio::spawn(agent::run(cfg));
    wait_for_heartbeat(&env).await;
    assert!(!file.exists(), "the token is deleted once used");
    first.abort();
    let _ = first.await;
    env.app.db.machine_agent_seen(&mid, Err("stopped"));

    let second = tokio::spawn(agent::run(restart));
    wait_for_heartbeat(&env).await;
    second.abort();
    assert_eq!(
        env.app.db.machine_certs(&mid).len(),
        1,
        "it came back with the same key and certificate"
    );
}

async fn wait_for_heartbeat(env: &Env) {
    for _ in 0..400 {
        let (_, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
        if r["heartbeats"] == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the agent never answered");
}

#[tokio::test]
async fn a_running_agent_takes_up_a_certificate_enrolled_by_hand() {
    let env = serve().await;
    let (_, mid, token) = machine_for(&env, "ada@example.com").await;
    let cfg = config(&env, &mid, Some(&token));
    let agent = Agent::new(cfg.clone(), agent::enroll(&cfg).await.unwrap()).unwrap();
    assert!(!agent.reload_if_changed(), "nothing new on disk");

    let (_, t) = json_call(
        &env,
        "POST",
        "/api/users/ada@example.com/machine/enrollment",
        "",
    )
    .await;
    let mut same_disk = cfg.clone();
    same_disk.token = t["token"].as_str().map(|t| Zeroizing::new(t.to_string()));
    let by_hand = agent::enroll(&same_disk).await.unwrap();
    assert!(agent.reload_if_changed());
    assert_eq!(agent.identity().fingerprint, by_hand.fingerprint);
    let enrolled = events(&env, "machine.enrolled").await;
    let first: Vec<bool> = enrolled.iter().map(|e| e["details"]["sinceRequestSeconds"].is_number()).collect();
    assert_eq!(first.iter().filter(|f| **f).count(), 1, "only the first enrollment is the machine coming up: {enrolled:?}");
    let (code, _) = raw(
        &env,
        Some(&agent.identity()),
        "GET",
        &format!("/v1/machines/{mid}"),
        Value::Null,
    )
    .await
    .unwrap();
    assert_eq!(
        code, 200,
        "the running agent signs in with the new certificate"
    );
}

#[tokio::test]
async fn new_machines_download_the_agent_botd_hashed() {
    let env = serve().await;
    let (_, mid, _) = machine_for(&env, "ada@example.com").await;
    let ud = env
        .fake
        .user_data(&env.app.db.machine(&mid).unwrap().label)
        .unwrap();
    assert!(
        ud.contains(&format!("echo \"{}  $bin.new\" | sha256sum -c -", sha(AGENT))),
        "{ud}"
    );
    let config = pki::client_config(&pki::cert_der(env.e.ca_pem()).unwrap(), None).unwrap();
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .unwrap();
    let url = format!("{}/v1/agent", env.e.url);
    let (a, b) = tokio::join!(client.get(&url).send(), client.get(&url).send());
    for r in [a.unwrap(), b.unwrap()] {
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.bytes().await.unwrap().as_ref(),
            AGENT.as_bytes(),
            "the same bytes cloud-init checks"
        );
    }
}

#[tokio::test]
async fn tokens_are_single_use_bound_to_one_machine_and_short_lived() {
    let env = serve().await;
    let (_, ma, ta) = machine_for(&env, "ada@example.com").await;
    let (_, mb, tb) = machine_for(&env, "bea@example.com").await;

    let unknown = agent::enroll(&config(&env, &ma, Some("sbe_madeup")))
        .await
        .err()
        .unwrap();
    assert!(unknown.message.contains("401"), "{}", unknown.message);
    assert!(
        events(&env, "machine.enroll_failed").await.is_empty(),
        "guesses aren't audited: anyone can reach this port"
    );

    let wrong = agent::enroll(&config(&env, &mb, Some(&ta)))
        .await
        .err()
        .unwrap();
    assert!(
        wrong.message.contains("401"),
        "A's token can't enroll B's machine: {}",
        wrong.message
    );
    assert_eq!(
        reason_count(
            &events(&env, "machine.enroll_failed").await,
            "wrong_machine"
        ),
        1
    );
    assert!(env.app.db.machine_certs(&mb).is_empty());

    env.app
        .db
        .add_machine_token(&mb, &sha("sbe_stale"), crate::db::now() - 1, None, crate::db::now())
        .unwrap();
    let stale = agent::enroll(&config(&env, &mb, Some("sbe_stale")))
        .await
        .err()
        .unwrap();
    assert!(stale.message.contains("401"), "{}", stale.message);
    assert_eq!(
        reason_count(
            &events(&env, "machine.enroll_failed").await,
            "token_expired"
        ),
        1
    );

    let bad = wire::EnrollRequest {
        machine_id: ma.clone(),
        token: ta.clone(),
        csr: "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
            .into(),
    };
    let (code, _) = raw(
        &env,
        None,
        "POST",
        "/v1/enroll",
        serde_json::to_value(&bad).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(code, 400, "a bad request doesn't use up the token");

    let (code, issued) = json_call(
        &env,
        "POST",
        "/api/users/bea@example.com/machine/enrollment",
        "",
    )
    .await;
    assert_eq!(code, 200, "{issued}");
    let t2 = issued["token"].as_str().unwrap().to_string();
    assert_eq!(
        (
            issued["machineId"].as_str(),
            issued["controlUrl"].as_str(),
            issued["ca"].as_str()
        ),
        (
            Some(mb.as_str()),
            Some(env.e.url.as_str()),
            Some(env.e.ca_pem())
        )
    );
    let issued_ev = events(&env, "machine.enroll_token_issued").await;
    assert_eq!(
        issued_ev
            .iter()
            .filter(|e| e["details"]["via"] == "create")
            .count(),
        2,
        "one per machine created"
    );
    assert_eq!(issued_ev.len(), 3);
    for t in [&ta, &tb, &t2] {
        assert!(
            !Value::Array(issued_ev.clone())
                .to_string()
                .contains(t.as_str()),
            "tokens are shown once and never recorded"
        );
    }

    let (a1, a2) = (config(&env, &ma, Some(&ta)), config(&env, &ma, Some(&ta)));
    let (r1, r2) = tokio::join!(agent::enroll(&a1), agent::enroll(&a2));
    assert_eq!(
        r1.is_ok() as u8 + r2.is_ok() as u8,
        1,
        "two enrollments with one token: exactly one wins"
    );
    assert_eq!(env.app.db.machine_certs(&ma).len(), 1);

    assert!(
        agent::enroll(&config(&env, &mb, Some(&tb))).await.is_ok(),
        "B's first token still works"
    );
    let after = agent::enroll(&config(&env, &mb, Some(&t2)))
        .await
        .err()
        .unwrap();
    assert!(
        after.message.contains("401"),
        "enrolling revoked B's other token: {}",
        after.message
    );
    assert_eq!(
        reason_count(
            &events(&env, "machine.enroll_failed").await,
            "token_revoked"
        ),
        1
    );
    assert!(
        env.app
            .db
            .machine_token(&sha(&tb))
            .unwrap()
            .used_at
            .is_some()
    );
}

#[tokio::test]
async fn unenrolled_rotated_and_revoked_certificates_are_refused() {
    let env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let cfg = config(&env, &mid, Some(&token));
    let id1 = agent::enroll(&cfg).await.unwrap();
    let path = format!("/v1/machines/{mid}");

    assert_eq!(
        raw(&env, None, "GET", &path, Value::Null).await.unwrap().0,
        401,
        "no certificate"
    );

    let (key, csr) = pki::new_request(&mid).unwrap();
    let foreign = Enrollment::for_tests(10, 1, 1).issue_unrecorded(&csr, &uid, &mid);
    let foreign = Identity::new(foreign.pem, Zeroizing::new(key.serialize_pem()), &mid).unwrap();
    assert!(
        raw(&env, Some(&foreign), "GET", &path, Value::Null)
            .await
            .is_err(),
        "another CA's certificate fails the handshake"
    );

    let (key, csr) = pki::new_request(&mid).unwrap();
    let unrecorded = env.e.issue_unrecorded(&csr, &uid, &mid);
    let unrecorded =
        Identity::new(unrecorded.pem, Zeroizing::new(key.serialize_pem()), &mid).unwrap();
    let (code, v) = raw(&env, Some(&unrecorded), "GET", &path, Value::Null)
        .await
        .unwrap();
    assert_eq!(
        code, 401,
        "our CA, but never issued to an enrolled machine: {v}"
    );

    let id2 = agent::rotate(&cfg, &id1).await.unwrap();
    assert_eq!(
        agent::load(&cfg).unwrap().fingerprint,
        id2.fingerprint,
        "the new pair replaced the old one"
    );
    let (stray, _) = pki::new_request(&mid).unwrap();
    assert!(
        Identity::new(
            id2.cert_pem.clone(),
            Zeroizing::new(stray.serialize_pem()),
            &mid
        )
        .is_err(),
        "a key that isn't the certificate's is refused"
    );
    assert_eq!(
        env.app.db.machine_pins(&mid).len(),
        2,
        "the old one works until the new one is used"
    );
    assert_eq!(
        raw(&env, Some(&id1), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        raw(&env, Some(&id2), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        env.app
            .db
            .machine_cert(&id1.fingerprint)
            .unwrap()
            .revoked_reason
            .as_deref(),
        Some("rotated")
    );
    assert_eq!(
        raw(&env, Some(&id1), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        401,
        "rotated out"
    );
    assert_eq!(events(&env, "machine.cert_rotated").await.len(), 1);

    // A rotation whose answer was lost: the agent asks again with the same certificate.
    let lost = agent::rotate(&cfg, &id2).await.unwrap();
    let id3 = agent::rotate(&cfg, &id2).await.unwrap();
    assert_eq!(
        env.app
            .db
            .machine_cert(&lost.fingerprint)
            .unwrap()
            .revoked_reason
            .as_deref(),
        Some("superseded")
    );
    assert_eq!(
        raw(&env, Some(&id3), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        env.app.db.machine_pins(&mid),
        std::slice::from_ref(&id3.fingerprint)
    );

    let (code, r) = json_call(
        &env,
        "DELETE",
        "/api/users/ada@example.com/machine/certificates",
        "",
    )
    .await;
    assert_eq!((code, r["revoked"].as_u64()), (200, Some(1)), "{r}");
    let (code, _) = raw(&env, Some(&id3), "GET", &path, Value::Null)
        .await
        .unwrap();
    assert_eq!(code, 401);
    assert!(reason_count(&events(&env, "access.denied").await, "revoked") >= 2);
    assert_eq!(env.app.db.machine(&mid).unwrap().enrollment, "revoked");
    assert_eq!(env.cp.route(&env.app.db, &uid), Err(Refusal::NotEnrolled));
    let revoked = events(&env, "machine.cert_revoked").await;
    assert!(
        revoked
            .iter()
            .any(|e| e["details"]["reason"] == "admin" && e["details"]["userId"] == uid.as_str())
    );

    let (_, t) = json_call(
        &env,
        "POST",
        "/api/users/ada@example.com/machine/enrollment",
        "",
    )
    .await;
    let again = agent::enroll(&config(&env, &mid, t["token"].as_str()))
        .await
        .unwrap();
    assert_eq!(
        raw(&env, Some(&again), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        200,
        "enrolled again with a new token"
    );
    assert_eq!(env.app.db.machine(&mid).unwrap().enrollment, "enrolled");
}

/// A rotation passes `authenticate`, then the machine is revoked or stopped before
/// `add_rotated_cert` runs: the revocation wins and nothing usable is left.
#[tokio::test]
async fn a_revocation_between_a_rotations_check_and_its_write_wins() {
    let env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let id = agent::enroll(&config(&env, &mid, Some(&token)))
        .await
        .unwrap();
    let checked = env.app.db.machine_cert(&id.fingerprint).unwrap();
    assert_eq!(checked.status, "active", "what authenticate saw");
    let (_, csr) = pki::new_request(&mid).unwrap();
    let issued = env.e.issue_unrecorded(&csr, &uid, &mid);

    let (code, r) = json_call(
        &env,
        "DELETE",
        "/api/users/ada@example.com/machine/certificates",
        "",
    )
    .await;
    assert_eq!((code, r["revoked"].as_u64()), (200, Some(1)), "{r}");

    assert_eq!(env.app.db.add_rotated_cert(&checked, &issued), None);
    assert!(
        env.app.db.machine_cert(&issued.fingerprint).is_none(),
        "the new certificate wasn't recorded"
    );
    assert!(
        env.app
            .db
            .machine_certs(&mid)
            .iter()
            .all(|c| c.status == "revoked"),
        "no valid certificate is left"
    );
    assert!(env.app.db.machine_pins(&mid).is_empty());
    assert_eq!(env.app.db.machine(&mid).unwrap().enrollment, "revoked");
    assert_eq!(env.cp.route(&env.app.db, &uid), Err(Refusal::NotEnrolled));
    assert_eq!(
        raw(
            &env,
            Some(&id),
            "GET",
            &format!("/v1/machines/{mid}"),
            Value::Null
        )
        .await
        .unwrap()
        .0,
        401
    );

    // Stopped after the check, before its certificates were revoked.
    let (ub, mb, tb) = machine_for(&env, "bea@example.com").await;
    let idb = agent::enroll(&config(&env, &mb, Some(&tb))).await.unwrap();
    let checked = env.app.db.machine_cert(&idb.fingerprint).unwrap();
    let (_, csr) = pki::new_request(&mb).unwrap();
    let issued = env.e.issue_unrecorded(&csr, &ub, &mb);
    let mut m = env.app.db.machine(&mb).unwrap();
    m.state = State::Destroying;
    assert!(env.app.db.save_machine(&m, State::Running));
    assert_eq!(env.app.db.add_rotated_cert(&checked, &issued), None);
    assert!(env.app.db.machine_cert(&issued.fingerprint).is_none());
    assert_eq!(
        env.app.db.machine_pins(&mb),
        std::slice::from_ref(&idb.fingerprint),
        "only the certificate destroy is about to revoke"
    );
}

#[tokio::test]
async fn one_users_machine_cannot_act_for_another() {
    let mut env = serve().await;
    let (ua, ma, ta) = machine_for(&env, "ada@example.com").await;
    let (ub, mb, tb) = machine_for(&env, "bea@example.com").await;
    let cfg_a = config(&env, &ma, Some(&ta));
    let a = agent::enroll(&cfg_a).await.unwrap();
    let b = agent::enroll(&config(&env, &mb, Some(&tb))).await.unwrap();

    let (code, v) = raw(
        &env,
        Some(&a),
        "GET",
        &format!("/v1/machines/{mb}"),
        Value::Null,
    )
    .await
    .unwrap();
    assert_eq!(code, 403, "{v}");
    let (code, _) = raw(
        &env,
        Some(&a),
        "POST",
        &format!("/v1/machines/{mb}/certificate"),
        json!({ "csr": pki::new_request(&mb).unwrap().1 }),
    )
    .await
    .unwrap();
    assert_eq!(code, 403, "A's certificate can't get one for B's machine");
    assert_eq!(env.app.db.machine_certs(&mb).len(), 1);
    let denied: Vec<_> = events(&env, "access.denied")
        .await
        .into_iter()
        .filter(|e| e["details"]["reason"] == "machine_mismatch")
        .collect();
    assert_eq!(denied.len(), 2);
    assert_eq!(
        (
            denied[0]["targetId"].as_str(),
            denied[0]["details"]["userId"].as_str(),
            denied[0]["details"]["askedUser"].as_str()
        ),
        (Some(ma.as_str()), Some(ua.as_str()), Some(ub.as_str()))
    );

    // A's agent answers at the address both machines have here, as if B's IP were reused.
    let agent_a = Agent::new(cfg_a, a).unwrap();
    let fp_a = agent_a.identity().fingerprint.clone();
    tokio::spawn(agent::serve(env.agent_listener.take().unwrap(), agent_a));
    let m_a = env.app.db.machine(&ma).unwrap();
    assert!(enroll::heartbeat(&env.app, &env.e, &m_a).await.is_ok());
    let m_b = env.app.db.machine(&mb).unwrap();
    let err = enroll::heartbeat(&env.app, &env.e, &m_b).await.unwrap_err();
    assert!(
        err.contains("didn't answer"),
        "botd pins B's certificate, so A's agent isn't B: {err}"
    );
    assert!(env.app.db.machine(&mb).unwrap().agent_error.is_some());
    let Ok(Target::Machine(to_b)) = env.cp.route(&env.app.db, &ub) else {
        panic!("B's machine")
    };
    assert_eq!(to_b.pins, std::slice::from_ref(&b.fingerprint));
    let err = env.cp.link.check(&env.app, &to_b, &[]).await.unwrap_err();
    assert!(
        err.contains("didn't answer"),
        "B's job never reaches A's machine: {err}"
    );

    // And B's certificate (same CA) can't call A's agent: only the control plane can.
    let (chain, key) = b.chain();
    let (config, _) = pki::pinned_client_config(vec![fp_a], chain, key).unwrap();
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .unwrap();
    let res = client
        .get(format!(
            "https://127.0.0.1:{}/v1/heartbeat",
            env.e.agent_port
        ))
        .send()
        .await;
    assert!(
        res.is_err() || !res.unwrap().status().is_success(),
        "a machine's certificate can't call another machine"
    );
}

#[tokio::test]
async fn suspend_holds_resume_releases_and_destroy_revokes() {
    let env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let id = agent::enroll(&config(&env, &mid, Some(&token)))
        .await
        .unwrap();
    let path = format!("/v1/machines/{mid}");

    assert_eq!(
        json_call(
            &env,
            "POST",
            "/api/users/ada@example.com/machine/suspend",
            ""
        )
        .await
        .0,
        200
    );
    assert_eq!(env.app.db.machine(&mid).unwrap().enrollment, "held");
    assert_eq!(
        raw(&env, Some(&id), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        403,
        "held while suspended"
    );
    assert!(
        env.app.db.machine_pins(&mid).is_empty(),
        "botd won't dial it either"
    );
    assert_eq!(
        env.cp.route(&env.app.db, &uid),
        Err(Refusal::NotReady(State::Suspended))
    );
    assert_eq!(events(&env, "machine.cert_held").await.len(), 1);

    assert_eq!(
        json_call(
            &env,
            "POST",
            "/api/users/ada@example.com/machine/resume",
            ""
        )
        .await
        .0,
        200
    );
    assert_eq!(
        raw(&env, Some(&id), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        200,
        "the same certificate works again"
    );
    assert_eq!(events(&env, "machine.cert_released").await.len(), 1);

    let (_, t) = json_call(
        &env,
        "POST",
        "/api/users/ada@example.com/machine/enrollment",
        "",
    )
    .await;
    let spare = t["token"].as_str().unwrap().to_string();
    assert_eq!(
        json_call(&env, "DELETE", "/api/users/ada@example.com/machine", "")
            .await
            .0,
        200
    );
    assert_eq!(
        raw(&env, Some(&id), "GET", &path, Value::Null)
            .await
            .unwrap()
            .0,
        401,
        "revoked for good"
    );
    let revoked = events(&env, "machine.cert_revoked").await;
    assert!(
        revoked.iter().any(|e| e["details"]["reason"] == "destroyed"
            && e["details"]["pendingEnrollments"].as_u64() >= Some(1)),
        "{revoked:?}"
    );
    assert_eq!(
        env.app.db.machine_cert(&id.fingerprint).unwrap().status,
        "revoked"
    );
    assert!(
        agent::enroll(&config(&env, &mid, Some(&spare)))
            .await
            .is_err(),
        "unused tokens go too"
    );

    // A machine that vanishes at the provider loses its certificates as well.
    let (_, mb, tb) = machine_for(&env, "bea@example.com").await;
    let b = agent::enroll(&config(&env, &mb, Some(&tb))).await.unwrap();
    env.fake.remove(
        env.app
            .db
            .machine(&mb)
            .unwrap()
            .provider_id
            .as_deref()
            .unwrap(),
    );
    json_call(&env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(
        env.app
            .db
            .machine_cert(&b.fingerprint)
            .unwrap()
            .revoked_reason
            .as_deref(),
        Some("lost")
    );
}

#[tokio::test]
async fn off_without_a_control_url() {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    cp.routing = Routing::On;
    let cp = Arc::new(cp);
    let shared = cp.clone();
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = shared).await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, m) = call(
        port,
        "POST",
        &format!("/api/users/{uid}/machine"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 202, "{m}");
    let label = parse(&m)["label"].as_str().unwrap().to_string();
    assert_eq!(fake.user_data(&label), None, "no token, no user data");
    let (code, v) = call(
        port,
        "POST",
        &format!("/api/users/{uid}/machine/enrollment"),
        &admin,
        "",
    )
    .await;
    assert_eq!(
        (code, parse(&v)["error"].as_str()),
        (503, Some(enroll::OFF))
    );
    call(port, "POST", "/api/machines/reconcile", &admin, "").await;
    let m = app.db.user_machine(&uid).unwrap();
    assert!(app.db.assign_machine(&m.id, None));
    assert_eq!(
        cp.route(&app.db, &uid),
        Err(Refusal::NotEnrolled),
        "nothing can run there without enrollment"
    );
    assert_eq!(cp.link.name(), "unenrolled");
    assert!(
        cp.describe().contains("enrollment off"),
        "{}",
        cp.describe()
    );
}

/// A stand-in Claude: it notes what botd gave it, writes to its memory, waits for the
/// test to say go, then replies with where it ran and what it was told.
pub(crate) const CHAT: &str = r#"#!/bin/sh
printf 'BOT_TOKEN=%s\nBOT_API=%s\n' "$BOT_TOKEN" "$BOT_API" > "$HOME/run.env"
echo "- learned on the machine" >> "$HOME/bots/$BOT_ID/MEMORY.md"
i=0
while [ ! -f "$HOME/go-ahead" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
said=$(cat "$HOME/go-ahead" 2>/dev/null)
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"pwd=$(pwd) said=$said\"}]}}"
"#;

/// The real agent, enrolled, with `harness` as its `claude` and a botctl.
pub(crate) struct OnMachine {
    pub home: PathBuf,
    pub server: tokio::task::JoinHandle<()>,
    pub agent: Arc<Agent>,
}

impl OnMachine {
    fn agent_api(&self) -> String {
        self.agent.cfg.layout().api
    }
}

pub(crate) async fn agent_with(env: &mut Env, mid: &str, token: &str, harness: &str) -> OnMachine {
    agent_with_config(env, mid, token, harness, |c| c).await
}

/// `agent_with`, with its settings changed by `f`.
pub(crate) async fn agent_with_config(
    env: &mut Env,
    mid: &str,
    token: &str,
    harness: &str,
    f: impl FnOnce(Config) -> Config,
) -> OnMachine {
    use std::os::unix::fs::PermissionsExt;
    let mut cfg = f(config(env, mid, Some(token)));
    let bin = cfg.home.join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (name, body) in [("claude", harness), ("botctl", "#!/bin/sh\nexit 2\n")] {
        std::fs::write(bin.join(name), body).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    cfg.botctl = bin.join("botctl");
    cfg.harness_path = format!("{}:{}", bin.display(), cfg.harness_path);
    let relay = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    cfg.api_listen = relay.local_addr().unwrap();
    let id = agent::enroll(&cfg).await.unwrap();
    let home = cfg.home.clone();
    let agent = Agent::new(cfg, id).unwrap();
    tokio::spawn(agent::serve_relay(relay, agent.clone()));
    let server = tokio::spawn(agent::serve(
        env.agent_listener.take().unwrap(),
        agent.clone(),
    ));
    OnMachine {
        home,
        server,
        agent,
    }
}

/// The Bot's next reply after message `before`.
pub(crate) async fn reply_after(env: &Env, bot: &str, before: i64) -> String {
    for _ in 0..600 {
        if let Some(m) = env.app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no reply from {bot}");
}

/// Sends as the Bot's owner, so the run is theirs (ADR 0046); as the admin if they can't sign in.
pub(crate) async fn send(env: &Env, bot: &str, text: &str) -> i64 {
    let owner = env.app.db.bot(bot).map(|b| b.owner_id).unwrap_or_default();
    let auth = crate::users_http_tests::signed_in(env.port, &env.admin, &owner).await.unwrap_or_else(|| env.admin.clone());
    let before = env.app.db.last_id();
    let body = json!({ "text": text }).to_string();
    let (code, m) = call(env.port, "POST", &format!("/api/bots/{bot}/messages"), &auth, &body).await;
    assert_eq!(code, 202, "{m}");
    before
}

pub(crate) async fn wait_for_event(env: &Env, action: &str) -> Vec<Value> {
    for _ in 0..600 {
        let evs = events(env, action).await;
        if !evs.is_empty() {
            return evs;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no {action} event");
}

async fn wait_for_file(path: &std::path::Path) -> String {
    for _ in 0..600 {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} never appeared", path.display());
}

/// A call to the agent's loopback relay, as a Bot's botctl makes it.
async fn via_relay(api: &str, auth: Option<&str>, path: &str, body: Value) -> (u16, String) {
    let req = reqwest::Client::new()
        .post(format!("{api}{path}"))
        .json(&body);
    let req = match auth {
        Some(t) => req.bearer_auth(t),
        None => req,
    };
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn a_users_bot_runs_on_their_machine_with_approvals_and_memory() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, CHAT).await;
    let (code, v) = json_call(&env, "GET", &format!("/api/users/{uid}/placement"), "").await;
    assert_eq!(
        (code, v["runsOn"].as_str(), v["routing"].as_str()),
        (200, Some("machine"), Some("on")),
        "{v}"
    );
    // Shared, so the admin's message runs as Ada's Bot: on Ada's machine.
    let bot = env.app.db.create_bot_owned(
        "Ada's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &uid,
        crate::acl::Visibility::Shared,
    );
    let before = send(&env, &bot.id, "hello").await;

    let run_env = wait_for_file(&m.home.join("run.env")).await;
    let var = |k: &str| {
        run_env
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap()
            .to_string()
    };
    let (bot_token, api) = (var("BOT_TOKEN"), var("BOT_API"));
    assert_eq!(
        api,
        m.agent_api(),
        "botctl there talks to the agent's relay"
    );
    let work = m.home.join("work").display().to_string();

    // The machine's own folders are this run's workspace for approvals.
    let check = |command: &str| {
        json!({ "from": bot.id, "harness": "claude",
            "event": { "tool_name": "Bash", "tool_input": { "command": command }, "cwd": work } })
    };
    let (code, verdict) = via_relay(
        &api,
        Some(&bot_token),
        "/api/approvals/check",
        check(&format!("rm -r {work}/old")),
    )
    .await;
    assert_eq!(code, 200);
    assert!(
        verdict.starts_with("allow"),
        "inside the machine's workspace: {verdict}"
    );

    // A risky step waits for a person, through the relay, and goes on once approved.
    let asking = tokio::spawn({
        let (api, bot_token, body) = (
            api.clone(),
            bot_token.clone(),
            check("git push origin main"),
        );
        async move { via_relay(&api, Some(&bot_token), "/api/approvals/check", body).await }
    });
    let approval = loop {
        if let Some(a) = env.app.db.approvals(Some("pending"), None, 1).pop() {
            break a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(approval.bot_id, bot.id);
    let (code, r) = json_call(
        &env,
        "POST",
        &format!("/api/approvals/{}/approve", approval.id),
        r#"{"remember":null}"#,
    )
    .await;
    assert_eq!(code, 200, "{r}");
    let (code, verdict) = asking.await.unwrap();
    assert_eq!(code, 200);
    assert!(verdict.starts_with("allow"), "{verdict}");

    std::fs::write(m.home.join("go-ahead"), "approved").unwrap();
    let said = reply_after(&env, &bot.id, before).await;
    assert_eq!(said, format!("pwd={work} said=approved"));

    // What it learned there is botd's now too, once the run is over.
    wait_for_event(&env, "bot.run_finished").await;
    let memory = std::fs::read_to_string(env.app.data_memory_file(&bot.id).unwrap()).unwrap();
    assert!(memory.contains("- learned on the machine"), "{memory}");
    // Its token ended with it (ADR 0083): what the run left on the machine can't call botd.
    let (code, _) = via_relay(&api, Some(&bot_token), "/api/bots", Value::Null).await;
    assert_eq!(code, 403, "the relay refuses a token whose run is over");

    let routed = events(&env, "bot.run_routed").await;
    assert_eq!(
        (
            routed.len(),
            routed[0]["details"]["machine"].as_str(),
            routed[0]["details"]["link"].as_str()
        ),
        (1, Some(mid.as_str()), Some("mtls"))
    );
    for action in ["harness.invoked", "bot.run_finished"] {
        let e = &events(&env, action).await[0];
        assert_eq!(
            (
                e["details"]["host"].as_str(),
                e["details"]["machine"].as_str()
            ),
            (Some("machine"), Some(mid.as_str())),
            "{e}"
        );
    }
    assert_eq!(
        events(&env, "bot.run_finished").await[0]["outcome"],
        "success"
    );

    // The machine goes quiet: the next run is refused and nothing runs here.
    m.server.abort();
    let _ = m.server.await;
    let before = send(&env, &bot.id, "again").await;
    let said = reply_after(&env, &bot.id, before).await;
    assert!(said.contains("your computer is offline"), "{said}");
    let refused = events(&env, "bot.run_refused").await;
    assert_eq!(reason_count(&refused, "machine_offline"), 1, "{refused:?}");
    assert_eq!(events(&env, "harness.invoked").await.len(), 1);
}

#[tokio::test]
async fn a_bot_on_its_owners_machine_skips_this_servers_accounts() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, CHAT).await;
    // Per-user accounts on, but no account can be made: a run here would be refused.
    let root = crate::db::temp_path("iso-machine");
    let _ = env
        .app
        .isolation
        .set(Arc::new(crate::accounts::for_tests(&root, "/bin/false")));
    let bot = env.app.db.create_bot_owned(
        "Ada's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &uid,
        crate::acl::Visibility::Shared,
    );
    env.app.init_bot_files(&bot);
    let kept = env.app.data_memory_file(&bot.id).unwrap();
    std::fs::write(&kept, "# Ada's\n- kept by botd\n").unwrap();
    let copy = env.app.memory_file(&bot).unwrap();
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, "# Ada's\n- stale copy on the server\n").unwrap();

    std::fs::write(m.home.join("go-ahead"), "hi").unwrap();
    let before = send(&env, &bot.id, "hello").await;
    let said = reply_after(&env, &bot.id, before).await;
    assert_eq!(
        said,
        format!("pwd={} said=hi", m.home.join("work").display())
    );
    let finished = wait_for_event(&env, "bot.run_finished").await;
    assert_eq!(finished[0]["outcome"], "success", "{finished:?}");
    assert!(events(&env, "bot.run_refused").await.is_empty());
    assert!(events(&env, "isolation.*").await.is_empty());
    let invoked = &events(&env, "harness.invoked").await[0];
    assert_eq!(invoked["details"]["host"], "machine");
    assert!(invoked["details"].get("runAs").is_none(), "{invoked}");

    // botd's copy went there and came back; the server's copy is out of date, so it's gone.
    let memory = std::fs::read_to_string(&kept).unwrap();
    assert!(
        memory.contains("- kept by botd") && memory.contains("- learned on the machine"),
        "{memory}"
    );
    assert!(!memory.contains("stale"), "{memory}");
    assert!(!copy.exists());
}

#[tokio::test]
async fn a_machine_runs_and_relays_only_for_its_own_user() {
    let mut env = serve().await;
    let (ua, ma, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &ma, &token, CHAT).await;
    let (ub, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let bea_bot = env.app.db.create_bot_owned(
        "Bea's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &ub,
        crate::acl::Visibility::Private,
    );
    let ada_bot = env.app.db.create_bot_owned(
        "Ada's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &ua,
        crate::acl::Visibility::Private,
    );

    // Even if botd were tricked into it, Ada's agent won't run Bea's Bot.
    let Ok(Target::Machine(to)) = env.cp.route(&env.app.db, &ua) else {
        panic!("Ada's machine")
    };
    let job: wire::JobRequest = serde_json::from_value(json!({
        "protocol": wire::PROTOCOL, "jobId": "j1", "botId": bea_bot.id, "ownerId": ub,
        "messageId": 1, "bin": "claude", "args": [], "env": {}, "cwd": m.home.join("work"),
        "stdin": null, "files": [], "cleanup": null, "collect": []
    }))
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let (_abort_tx, abort) = tokio::sync::watch::channel(None);
    env.cp.link.run(&to, job, abort, tx).await;
    match rx.recv().await {
        Some(wire::JobEvent::Error { message }) => assert!(
            message.contains("(403)") && message.contains("only its own user's Bots"),
            "{message}"
        ),
        other => panic!("refused, not {other:?}"),
    }
    assert!(!m.home.join("run.env").exists(), "nothing ran");

    // Bea's Bot token can't use Ada's machine to reach botd, and no token can't either.
    let api = m.agent_api();
    let bea = env.app.run_tokens.issue(&bea_bot.id, &ub, "r1", None, crate::db::now(), 60_000).0;
    let (code, _) = via_relay(&api, Some(&bea), "/api/bots", Value::Null).await;
    assert_eq!(code, 403);
    let (code, _) = via_relay(&api, None, "/api/bots", Value::Null).await;
    assert_eq!(code, 403);
    let denied = events(&env, "access.denied").await;
    assert_eq!(reason_count(&denied, "another_users_bot"), 1, "{denied:?}");
    assert_eq!(reason_count(&denied, "no_bot_token"), 1, "{denied:?}");
    // Ada's own Bot gets through.
    let ada = env.app.run_tokens.issue(&ada_bot.id, &ua, "r2", None, crate::db::now(), 60_000).0;
    let body = json!({ "from": ada_bot.id, "event": { "tool_name": "Bash", "tool_input": { "command": "ls" } } });
    let (code, verdict) = via_relay(&api, Some(&ada), "/api/approvals/check", body).await;
    assert_eq!(
        (code, verdict.lines().next()),
        (200, Some("allow")),
        "{verdict}"
    );
}

#[tokio::test]
async fn stopping_a_bot_ends_its_run_on_the_machine() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let slow = "#!/bin/sh\ntouch \"$HOME/run.env\"\nsleep 60\n";
    let m = agent_with(&mut env, &mid, &token, slow).await;
    let bot = env.app.db.create_bot_owned(
        "Ada's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &uid,
        crate::acl::Visibility::Shared,
    );
    let started = std::time::Instant::now();
    let before = send(&env, &bot.id, "take your time").await;
    wait_for_file(&m.home.join("run.env")).await;
    assert_eq!(m.agent.running(), 1);
    let (code, r) = json_call(&env, "POST", &format!("/api/bots/{}/stop", bot.id), "").await;
    assert!((200..300).contains(&code), "{r}");
    assert_eq!(reply_after(&env, &bot.id, before).await, "Stopped.");
    for _ in 0..200 {
        if m.agent.running() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(m.agent.running(), 0, "the job ended on the machine too");
    assert!(started.elapsed() < Duration::from_secs(30));
    let finished = &events(&env, "bot.run_finished").await[0];
    assert_eq!(finished["details"]["result"], "stopped", "{finished}");
}

/// A harness that streams until it's stopped, takes a second to stop, and whose
/// `cleanup` takes another.
const CHATTY: &str = r#"#!/bin/sh
if [ "$1" = cleanup ]; then sleep 1; touch "$HOME/cleaned"; exit 0; fi
trap 'sleep 1; touch "$HOME/stopped"; exit 0' TERM
echo $$ > "$HOME/harness.pid"
touch "$HOME/run.env"
while :; do echo '{}'; sleep 0.05; done
"#;

fn alive(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
        .is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| !r.trim_start().starts_with('Z')))
}

#[tokio::test]
async fn an_install_waits_until_a_stopped_job_has_exited_and_cleaned_up() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, CHATTY).await;
    let Ok(Target::Machine(to)) = env.cp.route(&env.app.db, &uid) else {
        panic!("Ada's machine")
    };
    // botd goes away mid-run, so its stream to the agent drops; or a Bot is stopped.
    for dropped in [true, false] {
        for f in ["harness.pid", "run.env", "stopped", "cleaned"] {
            let _ = std::fs::remove_file(m.home.join(f));
        }
        let job: wire::JobRequest = serde_json::from_value(json!({
            "protocol": wire::PROTOCOL, "jobId": format!("j-{dropped}"), "botId": "b1", "ownerId": uid,
            "messageId": 1, "bin": "claude", "args": [], "env": {}, "cwd": m.home.join("work"),
            "stdin": null, "files": [],
            "cleanup": { "whenExists": m.home.join("run.env"), "bin": "claude", "args": ["cleanup"],
                         "env": {}, "cwd": m.home.join("work"), "timeoutSecs": 10 },
            "collect": []
        }))
        .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let (abort_tx, abort) = tokio::sync::watch::channel(None);
        let (link, to) = (env.cp.link.clone(), to.clone());
        let stream = tokio::spawn(async move { link.run(&to, job, abort, tx).await });
        let pid = wait_for_file(&m.home.join("harness.pid")).await;
        assert_eq!(m.agent.running(), 1);
        if dropped {
            stream.abort();
        } else {
            abort_tx.send(Some("stopped")).unwrap();
        }
        let (tools, home) = (m.agent.tools.clone(), m.home.clone());
        let install = tokio::spawn(async move {
            let _r = tools.replacing().await;
            ["stopped", "cleaned"].map(|f| home.join(f).exists()) == [true, true] && !alive(&pid)
        });
        let waited = tokio::time::timeout(Duration::from_secs(20), install)
            .await
            .expect("the install got its turn")
            .unwrap();
        assert!(waited, "dropped {dropped}: the install waited for the harness to exit and its cleanup");
        assert_eq!(m.agent.running(), 0);
    }
}

#[tokio::test]
async fn botd_stops_listening_to_a_machine_that_floods_it() {
    let mut env = serve().await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let flood = "#!/bin/sh\nhead -c 17000000 /dev/zero | tr '\\0' a\necho\nsleep 60\n";
    let m = agent_with(&mut env, &mid, &token, flood).await;
    let bot = env.app.db.create_bot_owned(
        "Ada's",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &uid,
        crate::acl::Visibility::Shared,
    );
    let before = send(&env, &bot.id, "say a lot").await;
    let said = reply_after(&env, &bot.id, before).await;
    assert!(
        said.contains("more than 16 MiB"),
        "{}",
        &said[..said.len().min(200)]
    );
    for _ in 0..200 {
        if m.agent.running() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        m.agent.running(),
        0,
        "dropping the stream ends the job there"
    );
}

#[test]
fn agent_counts_programs_only_under_its_home_or_the_system() {
    use std::os::unix::fs::PermissionsExt;
    let home = crate::db::temp_path("roots-home");
    let elsewhere = crate::db::temp_path("roots-elsewhere");
    let bin = home.join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let exe = |p: &std::path::Path| {
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    exe(&elsewhere.join("botctl"));
    let mut cfg = Config {
        control_url: "https://127.0.0.1:1".into(),
        machine_id: "m".into(),
        ca_pem: String::new(),
        state_dir: crate::db::temp_path("roots-state"),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        token: None,
        token_file: None,
        home: home.clone(),
        api_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        botctl: elsewhere.join("botctl"),
        harness_path: "/usr/bin:/bin".into(),
        max_jobs: 1,
        tools: crate::db::temp_path("agent-tools"),
        exe: crate::db::temp_path("agent-exe"),
        bot_user: crate::machines::wire::BOT_USER.into(),
        allow_own_user: false,
        screens: crate::machines_mtls_tests::no_screens(),
        teammates: crate::db::temp_path("roots-teammates"),
        teammate_stand_in: None,
    };
    assert_eq!(cfg.layout().botctl, None, "outside the home and the system's directories");

    cfg.botctl = bin.join("botctl");
    std::os::unix::fs::symlink(elsewhere.join("botctl"), &cfg.botctl).unwrap();
    assert_eq!(cfg.layout().botctl, None, "a link is judged by where it leads");

    std::fs::remove_file(&cfg.botctl).unwrap();
    exe(&cfg.botctl);
    assert_eq!(cfg.layout().botctl.as_deref(), Some(cfg.botctl.to_str().unwrap()));

    cfg.botctl = "/bin/sh".into();
    assert_eq!(cfg.layout().botctl.as_deref(), Some("/bin/sh"), "a system program");
}

#[test]
fn the_agent_measures_its_homes_off_the_request_path_and_again_after_a_job() {
    let home = crate::db::temp_path("home-use");
    std::fs::create_dir_all(home.join("work")).unwrap();
    std::fs::write(home.join("work/a.bin"), vec![0u8; 1000]).unwrap();
    let roots = [home.clone(), crate::db::temp_path("home-use-teammates")];
    let usage = Arc::new(agent::HomeUse::default());
    let until = |want: u64| {
        for _ in 0..400 {
            if usage.latest() == Some((want, false)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("never measured {want}: {:?}", usage.latest());
    };
    // Nothing said before the first walk ends; the heartbeat that starts it doesn't wait.
    assert_eq!(usage.latest(), None);
    usage.refresh(&roots, false);
    until(1000);
    // A heartbeat soon after doesn't walk again...
    std::fs::write(home.join("work/b.bin"), vec![0u8; 500]).unwrap();
    usage.refresh(&roots, false);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(usage.latest(), Some((1000, false)));
    // ...but a job's end does, so the next heartbeat says what it wrote.
    usage.refresh(&roots, true);
    until(1500);
}
