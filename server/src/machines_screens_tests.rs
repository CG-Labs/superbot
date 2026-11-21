//! Bots' screens on their owner's machine (ADR 0045), end to end on loopback: the real
//! router, botd's machine port and the real agent over mutual TLS, with stand-ins for
//! Xvfb, openbox, dbus-daemon and voxl. The stand-in voxl answers only its token, as
//! voxl does, and says which display it shows.

use crate::machines::display;
use crate::machines::heartbeats;
use crate::machines_bot_user_tests::{owned_bot, until_ready};
use crate::machines_mtls_tests::{
    Env, OnMachine, agent_with_config, events, json_call, machine_for, no_screens, reply_after,
    send, serve_with,
};
use crate::tests::call;
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::os::unix::fs::PermissionsExt;

/// A stand-in Claude that says which display it was given, and whether its system
/// prompt told it about a screen on its computer.
const SCREEN_CLAUDE: &str = r#"#!/bin/sh
case "$*" in *"own screen on this computer"*) told=yes ;; *) told=no ;; esac
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"display=%s bus=%s told=%s"}]}}\n' "$DISPLAY" "${DBUS_SESSION_BUS_ADDRESS:+set}" "$told"
"#;

const FAKE_VOXL: &str = r#"#!/usr/bin/env python3
import http.server, os, sys, threading, urllib.parse
port = int(sys.argv[sys.argv.index('--port') + 1])
threading.Timer(120, os._exit, [0]).start()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        ok = q.get('token', [''])[0] == os.environ.get('VOXL_PASSWORD')
        body = ('voxl display=%s' % os.environ.get('DISPLAY')).encode() if ok else b'denied'
        self.send_response(200 if ok else 401)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
"#;

fn script(dir: &std::path::Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Screen settings whose programs are stand-ins in a folder of their own.
fn fake_stack() -> display::Settings {
    let root = crate::db::temp_path("screen-stack");
    let (bin, tmp) = (root.join("bin"), root.join("tmp"));
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    let x11 = tmp.join(".X11-unix");
    script(
        &bin,
        "Xvfb",
        &format!(
            "#!/bin/sh\n: > {}/X${{1#:}}\nexec sleep 120\n",
            x11.display()
        ),
    );
    script(&bin, "dbus-daemon", "#!/bin/sh\nexec sleep 120\n");
    script(&bin, "openbox", "#!/bin/sh\nexec sleep 120\n");
    script(&bin, "voxl", FAKE_VOXL);
    display::Settings {
        path: format!("{}:/usr/bin:/bin", bin.display()),
        tmp,
        display_base: 100,
        port_base: free_port() - 1,
        max: 2,
    }
}

/// botd's loopback ports for machine screens in these tests.
fn ports() -> (u16, u16) {
    let p = free_port();
    (p, p + 4)
}

async fn screen_of(env: &Env, auth: &str, bot: &str) -> (u16, Value) {
    let (code, body) = call(
        env.port,
        "GET",
        &format!("/api/bots/{bot}/screen"),
        auth,
        "",
    )
    .await;
    (code, parse(&body))
}

/// The port and token in a `/screen/<port>/?token=` link.
fn link(v: &Value) -> (u16, String) {
    let url = v["url"].as_str().unwrap_or_else(|| panic!("{v}"));
    let rest = url.strip_prefix("/screen/").unwrap();
    let (port, query) = rest.split_once("/?token=").unwrap();
    (port.parse().unwrap(), query.to_string())
}

/// What the viewer answers on botd's loopback port, as the proxy asks after stripping
/// `/screen/<port>`.
async fn view(port: u16, token: &str) -> Result<(u16, String), String> {
    let r = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/?token={token}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok((r.status().as_u16(), r.text().await.unwrap_or_default()))
}

fn reasons(evs: &[Value]) -> Vec<String> {
    evs.iter()
        .map(|e| {
            e["details"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

async fn ready_machine(
    env: &mut Env,
    email: &str,
    stack: display::Settings,
) -> (String, OnMachine) {
    let (uid, mid, token) = machine_for(env, email).await;
    let m = agent_with_config(env, &mid, &token, SCREEN_CLAUDE, |c| {
        crate::machines::agent::Config {
            screens: stack,
            ..c
        }
    })
    .await;
    (uid, m)
}

#[tokio::test]
async fn a_bots_screen_on_its_owners_machine_is_shown_through_the_agent_only() {
    let range = ports();
    let mut env = serve_with(|e| e.with_screens(range)).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    let (_, bob) = user_with(env.port, &env.admin, "bob@example.com", "member").await;

    // Until the machine runs Bots as their own user, no screen starts there, and none
    // starts here instead.
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 503, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("separate account"),
        "{v}"
    );
    assert_eq!(
        reasons(&events(&env, "machine.screen_refused").await),
        ["bot_user_pending"]
    );
    assert!(m.agent.screens.report().running.is_empty());
    until_ready(&env, &m.agent).await;

    // Shown from the machine: botd's own loopback port, piped to the agent's voxl.
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port, token) = link(&v);
    assert!((range.0..=range.1).contains(&port), "{port} in {range:?}");
    assert_eq!(token.len(), 32);
    assert_eq!(
        view(port, &token).await.unwrap(),
        (200, "voxl display=:101".into())
    );
    assert_eq!(
        view(port, "0123456789abcdef0123456789abcdef")
            .await
            .unwrap()
            .0,
        401,
        "voxl checks its own token"
    );
    assert_eq!(m.agent.screens.report().running, std::slice::from_ref(&bot));
    let started = events(&env, "machine.screen_started").await;
    assert_eq!(
        (started.len(), started[0]["details"]["for"].as_str()),
        (1, Some("viewer")),
        "{started:?}"
    );
    let opened = events(&env, "machine.screen_opened").await;
    assert_eq!(opened.len(), 1);
    assert_eq!(
        opened[0]["targetId"].as_str(),
        Some(m.agent.cfg.machine_id.as_str()),
        "{opened:?}"
    );

    // Asking again keeps the screen, its link and the audit log as they are.
    let (_, again) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(link(&again), (port, token.clone()));
    assert_eq!(events(&env, "machine.screen_opened").await.len(), 1);
    assert_eq!(events(&env, "machine.screen_started").await.len(), 1);

    // A run there gets that display, and is told of it.
    let before = send(&env, &bot, "look").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        "display=:101 bus=set told=yes"
    );

    // The admin view, and the agent's.
    heartbeats(&env.app, &env.cp).await;
    let (code, v) = json_call(
        &env,
        "GET",
        &format!("/api/users/{uid}/machine/screens"),
        "",
    )
    .await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        (
            v["on"].as_bool(),
            v["screens"][0]["botId"].as_str(),
            v["screens"][0]["port"].as_u64()
        ),
        (Some(true), Some(bot.as_str()), Some(port as u64)),
        "{v}"
    );
    assert_eq!(v["agent"]["running"][0].as_str(), Some(bot.as_str()), "{v}");
    assert_eq!(v["agent"]["missing"], json!([]), "{v}");

    // Anyone who may operate a shared Bot may view it; once it's private, they can't,
    // and the link they had stops working.
    let (code, v) = screen_of(&env, &bob, &bot).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        events(&env, "machine.screen_opened").await.len(),
        2,
        "each viewer once"
    );
    let (code, v) = json_call(
        &env,
        "PATCH",
        &format!("/api/bots/{bot}/access"),
        r#"{"visibility":"private"}"#,
    )
    .await;
    assert_eq!(code, 200, "{v}");
    let rotated = events(&env, "machine.screen_rotated").await;
    assert_eq!(
        (
            rotated.len(),
            rotated[0]["details"]["machineTold"].as_bool()
        ),
        (1, Some(true)),
        "{rotated:?}"
    );
    assert!(
        !matches!(view(port, &token).await, Ok((200, _))),
        "the old link is dead"
    );
    let (code, _) = screen_of(&env, &bob, &bot).await;
    assert!(code == 403 || code == 404, "{code}");
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port2, token2) = link(&v);
    assert_ne!(token2, token);
    assert_eq!(
        view(port2, &token2).await.unwrap(),
        (200, "voxl display=:101".into()),
        "same screen, new token"
    );
    assert_eq!(
        view(port2, &token).await.unwrap().0,
        401,
        "the machine has the new token too"
    );

    // An admin can close it; only admins can see or close screens on a machine.
    let list = format!("/api/users/{uid}/machine/screens");
    assert_eq!(call(env.port, "GET", &list, &bob, "").await.0, 403);
    assert_eq!(
        call(env.port, "DELETE", &format!("{list}/{bot}"), &bob, "")
            .await
            .0,
        403
    );
    let (code, v) = json_call(&env, "DELETE", &format!("{list}/{bot}"), "").await;
    assert_eq!(code, 204, "{v}");
    assert_eq!(
        reasons(&events(&env, "machine.screen_closed").await),
        ["closed_by_admin"]
    );
    assert!(m.agent.screens.report().running.is_empty());
    assert!(
        view(port2, &token2).await.is_err(),
        "botd stopped listening"
    );
    let (code, _) = json_call(&env, "DELETE", &format!("{list}/{bot}"), "").await;
    assert_eq!(code, 404);
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port2, token2) = link(&v);
    assert_eq!(view(port2, &token2).await.unwrap().0, 200);

    // Deleting the Bot closes its screen there.
    let (code, v) = json_call(&env, "DELETE", &format!("/api/bots/{bot}"), "").await;
    assert_eq!(code, 200, "{v}");
    let closed = events(&env, "machine.screen_closed").await;
    let mut why = reasons(&closed);
    why.sort();
    assert_eq!(why, ["bot_deleted", "closed_by_admin"]);
    assert!(
        closed
            .iter()
            .all(|c| c["details"]["machineStopped"].as_bool() == Some(true)),
        "{closed:?}"
    );
    assert!(m.agent.screens.report().running.is_empty());
    assert!(
        view(port2, &token2).await.is_err(),
        "botd stopped listening"
    );
}

#[tokio::test]
async fn machines_without_screens_refuse_them_and_never_fall_back_to_this_server() {
    // Off (the default): a Bot routed to a machine has no screen at all.
    let mut env = serve_with(|e| e.with_bot_user()).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 409, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("MACHINE_SCREENS"),
        "{v}"
    );
    assert_eq!(
        reasons(&events(&env, "machine.screen_refused").await),
        ["machine_screens_off"]
    );
    assert!(m.agent.screens.report().running.is_empty());
    let before = send(&env, &bot, "look").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        "display= bus= told=no"
    );

    // On, but the machine lacks the programs: refused, saying what's missing.
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", no_screens()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 409, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("missing Xvfb, openbox, dbus-daemon, voxl"),
        "{v}"
    );
    assert_eq!(
        reasons(&events(&env, "machine.screen_refused").await),
        ["screen_stack_missing"]
    );
    let before = send(&env, &bot, "look").await;
    assert_eq!(
        reply_after(&env, &bot, before).await,
        "display= bus= told=no",
        "the Bot runs without one"
    );

    // A routed user with no machine: refused, never shown from here.
    let (code, v) = screen_of(
        &env,
        &env.admin,
        &owned_bot(
            &env,
            &user_with(env.port, &env.admin, "cy@example.com", "member")
                .await
                .0,
        ),
    )
    .await;
    assert_eq!(code, 409, "{v}");
    assert!(
        reasons(&events(&env, "machine.screen_refused").await).contains(&"no_machine".to_string())
    );
}

#[tokio::test]
async fn the_agent_shows_screens_only_as_the_bots_user_to_its_own_user() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let a = &m.agent;
    let req = |owner: &str, token: &str| wire_req(owner, token);
    // Before botd asks for the Bots' user: refused, never run as the agent's own.
    let r = put(a, "b1", &req(&uid, &"a".repeat(32))).await;
    assert_eq!(r.0, 409, "{}", r.1);
    until_ready(&env, a).await;
    assert_eq!(
        put(a, "b1", &req("someone-else", &"a".repeat(32))).await.0,
        403
    );
    assert_eq!(put(a, "b1", &req(&uid, "short")).await.0, 400);
    assert_eq!(
        put(a, "../b1", &req(&uid, &"a".repeat(32))).await.0,
        404,
        "not a route"
    );
    let mut old = req(&uid, &"a".repeat(32));
    old.protocol = 99;
    assert_eq!(put(a, "b1", &old).await.0, 400);
    let r = put(a, "b1", &req(&uid, &"a".repeat(32))).await;
    assert_eq!(r.0, 200, "{}", r.1);
    assert_eq!(a.screens.report().running, ["b1"]);
}

fn wire_req(owner: &str, token: &str) -> crate::machines::wire::ScreenRequest {
    crate::machines::wire::ScreenRequest {
        protocol: crate::machines::wire::SCREEN_PROTOCOL,
        owner_id: owner.into(),
        token: token.into(),
        width: 800,
        height: 600,
        idle_secs: 600,
        for_user: None,
        xauth: false,
    }
}

/// `PUT /v1/screens/{bot}` on the agent's router, as botd's certificate would.
async fn put(
    a: &std::sync::Arc<crate::machines::agent::Agent>,
    bot: &str,
    r: &crate::machines::wire::ScreenRequest,
) -> (u16, String) {
    use tower::ServiceExt;
    let req = axum::http::Request::put(format!("/v1/screens/{bot}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(r).unwrap()))
        .unwrap();
    let res = crate::machines::agent::router(a.clone())
        .oneshot(req)
        .await
        .unwrap();
    let code = res.status().as_u16();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (code, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn new_machines_install_the_screen_programs_after_the_agent_starts() {
    const VOXL: &[u8] = b"voxl, botd's own build";
    let env = serve_with(|e| e.with_screens(ports()).with_voxl(VOXL)).await;
    let (_, mid, _) = machine_for(&env, "ada@example.com").await;
    let ud = env
        .fake
        .user_data(&env.app.db.machine(&mid).unwrap().label)
        .unwrap();
    let sha: String = sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(VOXL))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let order = [
        "/v1/agent",
        "systemctl start superbot-machine",
        "apt-get install -y -qq xvfb openbox dbus-daemon",
        "/v1/voxl",
        &format!("echo \"{sha}  /usr/local/bin/.voxl.new\" | sha256sum -c -"),
    ]
    .map(|s| ud.find(s).unwrap_or_else(|| panic!("{s}\n{ud}")));
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
    let config = crate::machines::pki::client_config(
        &crate::machines::pki::cert_der(env.e.ca_pem()).unwrap(),
        None,
    )
    .unwrap();
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .unwrap();
    let r = client
        .get(format!("{}/v1/voxl", env.e.url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), VOXL);

    // Without MACHINE_SCREENS, nothing of screens is installed.
    let env = serve_with(|e| e.with_bot_user().with_voxl(VOXL)).await;
    let (_, mid, _) = machine_for(&env, "ada@example.com").await;
    let ud = env
        .fake
        .user_data(&env.app.db.machine(&mid).unwrap().label)
        .unwrap();
    assert!(!ud.contains("xvfb") && !ud.contains("/v1/voxl"), "{ud}");
}

#[tokio::test]
async fn giving_the_bot_to_someone_else_closes_its_screen_on_the_old_owners_machine() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port, token) = link(&v);
    user_with(env.port, &env.admin, "bob@example.com", "member").await;

    let (code, v) = json_call(
        &env,
        "PATCH",
        &format!("/api/bots/{bot}/access"),
        r#"{"owner":"bob@example.com"}"#,
    )
    .await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        reasons(&events(&env, "machine.screen_closed").await),
        ["moved"]
    );
    assert!(
        events(&env, "machine.screen_rotated").await.is_empty(),
        "not re-keyed on the old owner's machine"
    );
    assert!(m.agent.screens.report().running.is_empty());
    assert!(view(port, &token).await.is_err());

    // Bob has no machine: refused, not shown from Ada's or from here.
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(
        reasons(&events(&env, "machine.screen_refused").await),
        ["no_machine"]
    );
    assert!(m.agent.screens.report().running.is_empty());
}

#[tokio::test]
async fn revoking_someones_sessions_or_disabling_them_changes_every_machine_screens_link() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (bob_id, bob) = user_with(env.port, &env.admin, "bob@example.com", "member").await;
    let (code, v) = screen_of(&env, &bob, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port, token) = link(&v);
    assert_eq!(view(port, &token).await.unwrap().0, 200);

    let (code, v) = json_call(&env, "DELETE", &format!("/api/users/{bob_id}/sessions"), "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(events(&env, "machine.screen_rotated").await.len(), 1);
    assert!(
        !matches!(view(port, &token).await, Ok((200, _))),
        "bob's saved link is dead"
    );
    let (code, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (port, fresh) = link(&v);
    assert_eq!(
        view(port, &token).await.unwrap().0,
        401,
        "the machine has the new token"
    );
    assert_eq!(view(port, &fresh).await.unwrap().0, 200);

    let (code, v) = json_call(
        &env,
        "PATCH",
        &format!("/api/users/{bob_id}"),
        r#"{"status":"disabled"}"#,
    )
    .await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(events(&env, "machine.screen_rotated").await.len(), 2);
    assert!(!matches!(view(port, &fresh).await, Ok((200, _))));
}

#[tokio::test]
async fn a_screen_request_waiting_out_a_revocation_gets_no_link() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (bob_id, bob) = user_with(env.port, &env.admin, "bob@example.com", "member").await;

    // Bob's request passes its first check, then waits as if a new token were under way.
    let held = crate::machines::screens::hold_for_tests(&env.e, &bot).await;
    let (port, path) = (env.port, format!("/api/bots/{bot}/screen"));
    let pending = tokio::spawn(async move { call(port, "GET", &path, &bob, "").await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!pending.is_finished(), "waiting on the Bot's lock");
    // The revocation is stored, then waits for the Bot's lock behind Bob's request.
    let (admin, path) = (env.admin.clone(), format!("/api/users/{bob_id}/sessions"));
    let revoke = tokio::spawn(async move { call(port, "DELETE", &path, &admin, "").await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(held);
    let (code, body) = pending.await.unwrap();
    assert_eq!(code, 401, "{body}");
    assert_eq!(revoke.await.unwrap().0, 200);
    assert!(
        m.agent.screens.report().running.is_empty(),
        "nothing started for it"
    );
}

/// A first start already past its access check isn't open yet: revoking sessions waits
/// for it, so the screen it opens gets a new token too.
#[tokio::test]
async fn a_bulk_revocation_waits_out_a_first_start_under_way() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let (bob_id, _) = user_with(env.port, &env.admin, "bob@example.com", "member").await;

    let held = crate::machines::screens::hold_for_tests(&env.e, &bot).await;
    let (port, admin, path) = (
        env.port,
        env.admin.clone(),
        format!("/api/users/{bob_id}/sessions"),
    );
    let revoke = tokio::spawn(async move { call(port, "DELETE", &path, &admin, "").await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!revoke.is_finished(), "waiting for the start under way");
    drop(held);
    assert_eq!(revoke.await.unwrap().0, 200);
}

#[tokio::test]
async fn a_viewer_who_lost_access_while_waiting_gets_no_link() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    let bot = owned_bot(&env, &uid);
    until_ready(&env, &m.agent).await;
    let b = env.app.db.bot(&bot).unwrap();
    let by = crate::audit::Who::system("test");
    let gone = || Err(ApiError(StatusCode::NOT_FOUND, "Bot not found".into()));
    let r = crate::machines::screens::open(&env.app, &by, &b, None, gone).await;
    assert_eq!(r.err().map(|e| e.0), Some(StatusCode::NOT_FOUND));
    assert!(
        events(&env, "machine.screen_opened").await.is_empty(),
        "no link handed out"
    );
    let r = crate::machines::screens::open(&env.app, &by, &b, None, || Ok(()))
        .await
        .unwrap();
    assert!(r.unwrap().starts_with("/screen/"));
}

async fn screen_for(env: &Env, auth: &str, bot: &str, for_user: &str) -> (u16, Value) {
    let (code, body) = call(
        env.port,
        "GET",
        &format!("/api/bots/{bot}/screen?for={for_user}"),
        auth,
        "",
    )
    .await;
    (code, parse(&body))
}

#[tokio::test]
async fn with_teammate_users_a_teammate_has_a_screen_of_their_own_that_only_they_and_admins_see() {
    let range = ports();
    let mut env = serve_with(|e| e.with_screens(range).with_teammate_users()).await;
    let me = crate::machines::runas::current_user().unwrap();
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with_config(&mut env, &mid, &token, SCREEN_CLAUDE, |c| {
        crate::machines::agent::Config {
            screens: fake_stack(),
            teammate_stand_in: Some(me),
            ..c
        }
    })
    .await;
    until_ready(&env, &m.agent).await;
    let bot = owned_bot(&env, &uid);
    let (bea_id, bea) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let ada = crate::users_http_tests::signed_in(env.port, &env.admin, &uid)
        .await
        .unwrap();

    // Ada sees her Bot's screen; Bea, who may operate it, gets one of her own.
    let (code, v) = screen_of(&env, &ada, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (ada_port, ada_token) = link(&v);
    assert_eq!(
        view(ada_port, &ada_token).await.unwrap(),
        (200, "voxl display=:101".into())
    );
    let (code, v) = screen_of(&env, &bea, &bot).await;
    assert_eq!(code, 200, "{v}");
    let (bea_port, bea_token) = link(&v);
    assert!(bea_port != ada_port && bea_token != ada_token);
    assert_eq!(
        view(bea_port, &bea_token).await.unwrap(),
        (200, "voxl display=:102".into()),
        "a display of its own"
    );
    assert_eq!(
        view(ada_port, &bea_token).await.unwrap().0,
        401,
        "Bea's link doesn't open Ada's screen"
    );
    let mut running = m.agent.screens.report().running;
    running.sort();
    assert_eq!(running, [bot.clone(), format!("{bot}@{bea_id}")]);
    let started = events(&env, "machine.screen_started").await;
    assert!(
        started
            .iter()
            .any(|e| e["details"]["forUser"] == bea_id.as_str()),
        "{started:?}"
    );
    assert!(
        started
            .iter()
            .any(|e| e["details"].get("forUser").is_none()),
        "{started:?}"
    );
    assert_eq!(events(&env, "machine.teammate_user_created").await.len(), 1);

    // Neither may ask for the other's; an admin sees Ada's, or Bea's when asking.
    assert_eq!(screen_for(&env, &bea, &bot, &uid).await.0, 403);
    assert_eq!(screen_for(&env, &ada, &bot, &bea_id).await.0, 403);
    let (_, v) = screen_of(&env, &env.admin, &bot).await;
    assert_eq!(link(&v), (ada_port, ada_token.clone()));
    let (code, v) = screen_for(&env, &env.admin, &bot, &bea_id).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(link(&v), (bea_port, bea_token.clone()));
    let (_, v) = json_call(
        &env,
        "GET",
        &format!("/api/users/{uid}/machine/screens"),
        "",
    )
    .await;
    let listed: Vec<Option<&str>> = v["screens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["forUser"].as_str())
        .collect();
    assert_eq!(listed, [None, Some(bea_id.as_str())], "{v}");

    // Bea loses the Bot: her screen closes on the machine; Ada's gets a new token.
    let (code, v) = json_call(
        &env,
        "PATCH",
        &format!("/api/bots/{bot}/access"),
        r#"{"visibility":"private"}"#,
    )
    .await;
    assert_eq!(code, 200, "{v}");
    let closed = events(&env, "machine.screen_closed").await;
    assert!(
        closed
            .iter()
            .any(|e| e["details"]["reason"] == "access_lost"
                && e["details"]["forUser"] == bea_id.as_str()
                && e["details"]["machineStopped"] == true),
        "{closed:?}"
    );
    assert_eq!(m.agent.screens.report().running, std::slice::from_ref(&bot));
    assert!(!matches!(view(bea_port, &bea_token).await, Ok((200, _))));
    let (code, _) = screen_of(&env, &bea, &bot).await;
    assert!(code == 403 || code == 404, "{code}");
    assert_eq!(
        screen_for(&env, &env.admin, &bot, &bea_id).await.0,
        404,
        "she can't use it, so it has no screen for her"
    );
    let (code, v) = screen_of(&env, &ada, &bot).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        view(link(&v).0, &link(&v).1).await.unwrap(),
        (200, "voxl display=:101".into())
    );
}

#[tokio::test]
async fn without_teammate_users_everyone_shares_the_owners_screen_as_before() {
    let mut env = serve_with(|e| e.with_screens(ports())).await;
    let (uid, m) = ready_machine(&mut env, "ada@example.com", fake_stack()).await;
    until_ready(&env, &m.agent).await;
    let bot = owned_bot(&env, &uid);
    let (bea_id, bea) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (_, a) = screen_of(&env, &env.admin, &bot).await;
    let (_, b) = screen_of(&env, &bea, &bot).await;
    assert_eq!(link(&a), link(&b));
    assert_eq!(m.agent.screens.report().running, std::slice::from_ref(&bot));
    assert_eq!(
        screen_for(&env, &env.admin, &bot, &bea_id).await.0,
        400,
        "no per-teammate screens to ask for"
    );
}
