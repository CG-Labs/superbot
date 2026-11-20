//! Enrollment and mutual TLS between botd and a machine agent (ADR 0031), end to end on
//! loopback: the real router, botd's machine port, and the real agent, with the
//! in-memory provider. Nothing here talks to Linode.

use crate::machines::agent::{self, Agent, Config, Identity};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::{Job, Refusal, Target};
use crate::machines::{ControlPlane, State, pki, wire};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
    e: Arc<Enrollment>,
    cp: Arc<ControlPlane>,
    agent_listener: Option<TcpListener>,
}

/// botd with the fake provider, routing on, and enrollment on a loopback machine port.
async fn serve() -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let (mport, aport) = (
        machine_listener.local_addr().unwrap().port(),
        agent_listener.local_addr().unwrap().port(),
    );
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let mut cp = ControlPlane::for_tests(p);
    cp.routing = true;
    let e = cp
        .enroll_with(Enrollment::for_tests(9, mport, aport))
        .unwrap();
    let cp = Arc::new(cp);
    let shared = cp.clone();
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = shared).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e.clone()));
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

async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, body).await;
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

fn token_in(user_data: &str) -> String {
    let at = user_data
        .find("content: \"sbe_")
        .expect("a token in the user data")
        + "content: \"".len();
    user_data[at..].split('"').next().unwrap().to_string()
}

/// A member with a running machine on 127.0.0.1. Returns their id, the machine's id,
/// and the token its cloud-init user data carries.
async fn machine_for(env: &Env, email: &str) -> (String, String, String) {
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

fn config(env: &Env, machine_id: &str, token: Option<&str>) -> Config {
    Config {
        control_url: env.e.url.clone(),
        machine_id: machine_id.into(),
        ca_pem: env.e.ca_pem().into(),
        state_dir: crate::db::temp_path("agent"),
        listen: SocketAddr::from(([127, 0, 0, 1], env.e.agent_port)),
        token: token.map(|t| Zeroizing::new(t.to_string())),
        token_file: None,
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
    let err = env
        .cp
        .link
        .dispatch(
            &to,
            Job {
                bot_id: "b1".into(),
                owner_id: uid.clone(),
                message_id: 1,
            },
        )
        .await
        .unwrap_err();
    assert!(
        err.contains("can't run Bots yet"),
        "the agent got the job over mTLS and turned it down: {err}"
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
    for _ in 0..100 {
        let (_, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
        if r["heartbeats"] == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the agent never answered");
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
        .add_machine_token(&mb, &sha("sbe_stale"), crate::db::now() - 1, None)
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
    // A rotation that passed its check just before the revocation can't bring it back.
    let (_, csr) = pki::new_request(&mid).unwrap();
    let late = env.e.issue_unrecorded(&csr, &uid, &mid);
    let revoked3 = env.app.db.machine_cert(&id3.fingerprint).unwrap();
    assert_eq!(env.app.db.add_rotated_cert(&revoked3, &late), None);
    assert!(
        env.app.db.machine_cert(&late.fingerprint).is_none()
            && env.app.db.machine_pins(&mid).is_empty()
    );
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
    let err = env
        .cp
        .link
        .dispatch(
            &to_b,
            Job {
                bot_id: "b".into(),
                owner_id: ub.clone(),
                message_id: 2,
            },
        )
        .await
        .unwrap_err();
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
    cp.routing = true;
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
    assert!(
        matches!(cp.route(&app.db, &uid), Ok(Target::Machine(_))),
        "routing is as before"
    );
    assert_eq!(cp.link.name(), "unenrolled");
    assert!(
        cp.describe().contains("enrollment off"),
        "{}",
        cp.describe()
    );
}
