//! Harness CLIs and agent upgrades on a user's machine (ADR 0039), end to end on
//! loopback: botd, its machine port and the real agent over mutual TLS, as in
//! `machines_mtls_tests`. Downloads come from a local HTTPS server; its Node.js is a
//! stand-in whose npm installs packages baked in beside it, so nothing here touches the
//! internet. `adapters::install`'s ignored test installs the real pins.

use crate::machines::agent::{self, Agent, Config};
use crate::machines::upkeep::{Upgrades, VERSION};
use crate::machines::wire::{Download, HarnessInstall, HarnessPlan, InstallSource, NodeRuntime};
use crate::machines::{enroll, heartbeats, pki};
use crate::machines_mtls_tests::{Env, config, events, json_call, machine_for, reply_after, send, serve_with};
use crate::*;
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use std::os::unix::fs::PermissionsExt;
use tokio::net::TcpListener;

/// A stand-in npm: `pack` hands over a package baked in beside it, as npm would fetch
/// it from the registry; `install -g --prefix` unpacks one and links its program.
const NPM: &str = r#"#!/bin/sh
set -eu
here=$(dirname "$(dirname "$(readlink -f "$0")")")
case "$1" in
pack)
  printf 'registry=%s\n' "${npm_config_registry:-}" > "$here/npm-saw"
  [ -z "${NODE_EXTRA_CA_CERTS:-}" ] || cat "$NODE_EXTRA_CA_CERTS" >> "$here/npm-saw"
  [ -z "${npm_config_userconfig:-}" ] || { printf 'userconfig %s\n' "$(stat -c %a "$npm_config_userconfig")"; cat "$npm_config_userconfig"; } >> "$here/npm-saw"
  cp "$here/pkgs/$2.tgz" "$4/$2.tgz"
  printf '[{"filename":"%s.tgz","integrity":"%s"}]\n' "$2" "$(cat "$here/pkgs/$2.sri")"
  ;;
install)
  prefix=$4
  for f; do file=$f; done
  tmp=$(mktemp -d)
  tar -xzf "$file" -C "$tmp"
  name=$(sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' "$tmp/package/package.json")
  mkdir -p "$prefix/lib/node_modules" "$prefix/bin"
  rm -rf "$prefix/lib/node_modules/$name"
  mv "$tmp/package" "$prefix/lib/node_modules/$name"
  ln -sfn "../lib/node_modules/$name/cli.sh" "$prefix/bin/$(cat "$prefix/lib/node_modules/$name/bin.txt")"
  ;;
*) exit 1 ;;
esac
"#;

/// The harness npm installs: a Claude that answers at once.
const INSTALLED_CLAUDE: &str = r#"#!/bin/sh
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ran with the installed claude"}]}}'
"#;

fn exe(p: &std::path::Path, body: &str) {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn sri(b: &[u8]) -> String {
    format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b)))
}

fn sh(dir: &std::path::Path, script: &str) {
    let out = std::process::Command::new("sh").args(["-c", script]).current_dir(dir).output().unwrap();
    assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
}

/// An npm package `name@version` whose program `bin` is `body`.
fn package(name: &str, version: &str, bin: &str, body: &str) -> Vec<u8> {
    let dir = crate::db::temp_path("pkg");
    let p = dir.join("package");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("package.json"), format!(r#"{{"name": "{name}", "version": "{version}"}}"#)).unwrap();
    std::fs::write(p.join("bin.txt"), bin).unwrap();
    exe(&p.join("cli.sh"), body);
    sh(&dir, "tar -czf pkg.tgz package");
    std::fs::read(dir.join("pkg.tgz")).unwrap()
}

/// A Node.js tarball holding the stand-in npm and `packages`.
fn node_tarball(packages: &[(&str, &[u8])]) -> Vec<u8> {
    let dir = crate::db::temp_path("node");
    let top = dir.join("node-v0.0.1-linux");
    exe(&top.join("bin/node"), "#!/bin/sh\necho v0.0.1\n");
    exe(&top.join("bin/npm"), NPM);
    std::fs::create_dir_all(top.join("pkgs")).unwrap();
    for (spec, tgz) in packages {
        std::fs::write(top.join(format!("pkgs/{spec}.tgz")), tgz).unwrap();
        std::fs::write(top.join(format!("pkgs/{spec}.sri")), sri(tgz)).unwrap();
    }
    sh(&dir, "tar -cJf node.tar.xz node-v0.0.1-linux");
    std::fs::read(dir.join("node.tar.xz")).unwrap()
}

/// Serves `body` at `/node.tar.xz` over HTTPS, with botd's control-plane certificate,
/// which agents trust through the machine CA. Returns its URL.
async fn downloads(e: &Arc<enroll::Enrollment>, body: Vec<u8>) -> String {
    let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let body = axum::body::Bytes::from(body);
    let router = axum::Router::new().route("/node.tar.xz", axum::routing::get(move || async move { body.clone() }));
    tokio::spawn(pki::serve(l, e.tls(), router, pki::lifetime));
    format!("https://127.0.0.1:{port}/node.tar.xz")
}

/// The real agent, enrolled, with only a botctl in its home: its harnesses come from
/// its tools folder. `exe` stands for its own binary.
struct Machine {
    cfg: Config,
    agent: Arc<Agent>,
    server: tokio::task::JoinHandle<()>,
}

async fn agent_on(env: &mut Env, mid: &str, token: &str, own: &str) -> Machine {
    let mut cfg = config(env, mid, Some(token));
    let bin = cfg.home.join(".local/bin");
    exe(&bin.join("botctl"), "#!/bin/sh\nexit 2\n");
    cfg.botctl = bin.join("botctl");
    cfg.harness_path = format!("{}/bin:/usr/bin:/bin", cfg.tools.display());
    cfg.exe = crate::db::temp_path("agent-lib").join("superbot-machine");
    exe(&cfg.exe, own);
    let id = agent::enroll(&cfg).await.unwrap();
    let agent = Agent::new(cfg.clone(), id).unwrap();
    let server = tokio::spawn(agent::serve(env.agent_listener.take().unwrap(), agent.clone()));
    Machine { cfg, agent, server }
}

impl Machine {
    /// Stops the agent and starts it again from its files, as systemd would.
    async fn restart(&mut self) {
        self.server.abort();
        let _ = (&mut self.server).await;
        let id = agent::load(&self.cfg).expect("its identity is on disk");
        self.agent = Agent::new(self.cfg.clone(), id).unwrap();
        let l = TcpListener::bind(self.cfg.listen).await.unwrap();
        self.server = tokio::spawn(agent::serve(l, self.agent.clone()));
    }

    async fn wait_for_restart(&self) {
        let mut r = self.agent.restarting();
        tokio::time::timeout(Duration::from_secs(20), r.wait_for(|r| *r))
            .await
            .expect("the agent asked to restart")
            .unwrap();
    }
}

/// Heartbeats until `done` holds for what botd recorded of the agent.
async fn beat_until(env: &Env, uid: &str, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..400 {
        heartbeats(&env.app, &env.cp).await;
        let (code, v) = json_call(env, "GET", &format!("/api/users/{uid}/machine/agent"), "").await;
        assert_eq!(code, 200, "{v}");
        if done(&v) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never {what}");
}

fn npm(name: &str, package: &str, version: &str, integrity: String) -> HarnessInstall {
    HarnessInstall {
        name: name.into(),
        version: version.into(),
        source: InstallSource::Npm { package: package.into(), integrity: Some(integrity) },
    }
}

/// What botd's machine CA (seed 9 in `serve_with`) would sign, before botd is up.
fn ca_twin() -> Arc<enroll::Enrollment> {
    Arc::new(enroll::Enrollment::for_tests(9, 1, 1))
}

#[tokio::test]
async fn a_new_machine_installs_the_planned_harnesses_and_runs_bots_with_them() {
    let claude = package("fake-claude", "9.9.9", "claude", INSTALLED_CLAUDE);
    let codex = package("fake-codex", "1.0.0", "codex", "#!/bin/sh\n");
    let tarball = node_tarball(&[("fake-claude@9.9.9", &claude), ("fake-codex@1.0.0", &codex)]);
    let sha = hex(&tarball);
    let wrong = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([0u8; 64]));
    let url = downloads(&ca_twin(), tarball).await;
    let plan = HarnessPlan {
        node: Some(NodeRuntime {
            version: "0.0.1".into(),
            downloads: [(std::env::consts::ARCH.to_string(), Download { url, sha256: sha })].into(),
        }),
        harnesses: vec![npm("claude", "fake-claude", "9.9.9", sri(&claude)), npm("codex", "fake-codex", "1.0.0", wrong)],
        ..Default::default()
    };
    crate::machines::tools::check(&plan).unwrap();
    let planned = plan.clone();
    let mut env = serve_with(move |mut e| {
        e.upkeep.plan = Some(planned);
        e
    })
    .await;

    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let mut m = agent_on(&mut env, &mid, &token, "#!/bin/sh\n").await;
    let bot = env.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &uid, crate::acl::Visibility::Shared);

    // Before the plan: refused, as before ADR 0039.
    let before = send(&env, &bot.id, "hello").await;
    assert!(reply_after(&env, &bot.id, before).await.contains("isn't installed"));

    let v = beat_until(&env, &uid, "claude installed and codex failed", |v| {
        let h = &v["agent"]["harnesses"];
        h["claude"]["state"] == "installed" && h["codex"]["state"] == "failed"
    })
    .await;
    assert_eq!(v["agent"]["harnesses"]["claude"]["version"], "9.9.9", "{v}");
    assert_eq!(v["agent"]["plan"].as_str(), Some(plan.id().as_str()), "{v}");
    let why = v["agent"]["harnesses"]["codex"]["error"].as_str().unwrap();
    assert!(why.contains("not the pinned"), "a package that isn't what was pinned isn't installed: {why}");
    assert!(!m.cfg.tools.join("bin/codex").exists());
    assert!(std::fs::symlink_metadata(m.cfg.tools.join("bin/node")).unwrap().is_symlink());

    let sent = events(&env, "machine.harnesses_requested").await;
    assert_eq!(sent.len(), 1, "sent once, not every heartbeat: {sent:?}");
    assert_eq!(sent[0]["details"]["harnesses"], json!(["claude@9.9.9", "codex@1.0.0"]));
    let ok = events(&env, "machine.harness_installed").await;
    assert_eq!((ok.len(), ok[0]["details"]["harness"].as_str()), (1, Some("claude")), "{ok:?}");
    let bad = events(&env, "machine.harness_install_failed").await;
    assert_eq!((bad.len(), bad[0]["outcome"].as_str()), (1, Some("failure")), "{bad:?}");

    // The same Bot runs now, with the claude the agent installed.
    let before = send(&env, &bot.id, "again").await;
    assert_eq!(reply_after(&env, &bot.id, before).await, "ran with the installed claude");
    let routed = events(&env, "bot.run_routed").await;
    assert_eq!(routed[0]["details"]["machine"].as_str(), Some(mid.as_str()));

    // A restart keeps what's installed, and nothing is sent or installed again.
    m.restart().await;
    heartbeats(&env.app, &env.cp).await;
    assert_eq!(events(&env, "machine.harness_installed").await.len(), 1);
    assert_eq!(events(&env, "machine.harnesses_requested").await.len(), 1);

    // An admin can send it again now: the failed one is tried again.
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/harnesses"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!(events(&env, "machine.harnesses_requested").await.len(), 2);
    for _ in 0..400 {
        heartbeats(&env.app, &env.cp).await;
        if events(&env, "machine.harness_install_failed").await.len() == 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("codex wasn't tried again");
}

#[tokio::test]
async fn machines_install_harnesses_from_the_operators_mirrors_with_their_own_ca() {
    use crate::machines::mirror::Mirrors;
    use crate::machines::standin_mirror::Mirror;
    let claude = package("fake-claude", "9.9.9", "claude", INSTALLED_CLAUDE);
    let tarball = node_tarball(&[("fake-claude@9.9.9", &claude)]);
    let mirror = Mirror::serve().await;
    let mut node = mirror.node("0.0.1", &tarball);
    for d in node.downloads.values_mut() {
        d.url = format!("https://nodejs.org/dist/v0.0.1/node-v0.0.1-linux-{}.tar.xz", crate::machines::standin_mirror::node_arch());
    }
    let pin = mirror.package("fake-claude", "9.9.9", &claude);
    let mirrors = Mirrors { node: Some(mirror.node_base()), npm: Some(mirror.registry()), ca: Some((mirror.ca_pem(), "/etc/superbot/mirror-ca.pem".into())), login: None };
    let plan = mirrors.apply(HarnessPlan { node: Some(node), harnesses: vec![npm("claude", "fake-claude", "9.9.9", pin)], ..Default::default() });
    assert!(plan.node.as_ref().unwrap().downloads.values().all(|d| d.url.starts_with(&mirror.url)), "{plan:?}");
    let planned = plan.clone();
    let mut env = serve_with(move |mut e| {
        e.upkeep.plan = Some(planned);
        e.upkeep.mirrors = Some(mirrors);
        e
    })
    .await;

    // Before anything is installed, the check fetches what machines would and finds
    // every pin there.
    let (code, v) = json_call(&env, "GET", "/api/machines/harness-mirror", "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["mirrors"]["caFile"], "/etc/superbot/mirror-ca.pem", "{v}");

    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_on(&mut env, &mid, &token, "#!/bin/sh\n").await;
    let v = beat_until(&env, &uid, "claude installed from the mirror", |v| v["agent"]["harnesses"]["claude"]["state"] == "installed").await;
    assert_eq!(v["agent"]["plan"].as_str(), Some(plan.id().as_str()), "{v}");

    // Node.js came from the mirror, over its CA (which the machine CA isn't), and npm
    // was pointed at the mirror's registry and told to trust that CA too.
    let node_path = format!("/node/v0.0.1/node-v0.0.1-linux-{}.tar.xz", crate::machines::standin_mirror::node_arch());
    assert!(mirror.calls().contains(&node_path), "{:?}", mirror.calls());
    let saw = std::fs::read_to_string(m.cfg.tools.join("node-0.0.1/npm-saw")).unwrap();
    assert!(saw.starts_with(&format!("registry={}\n", mirror.registry())), "{saw}");
    assert!(saw.contains(&mirror.ca_pem()), "{saw}");
    assert!(!m.cfg.tools.join(".dl").exists(), "the CA file goes with the downloads");

    // A mirror that starts serving something else is caught by the check.
    mirror.replace_tarball("fake-claude", "9.9.9", b"not claude");
    let (_, v) = json_call(&env, "GET", "/api/machines/harness-mirror", "").await;
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["items"][1]["error"].as_str().unwrap().contains("not the pinned"), "{v}");
}

#[tokio::test]
async fn machines_sign_in_to_the_operators_registry_with_botds_login() {
    use crate::machines::mirror::{Login, Mirrors};
    use crate::machines::standin_mirror::Mirror;
    let token = "e2e-registry-token-7f3a";
    let claude = package("fake-claude", "9.9.9", "claude", INSTALLED_CLAUDE);
    let tarball = node_tarball(&[("fake-claude@9.9.9", &claude)]);
    let mirror = Mirror::serve().await;
    let node = mirror.node("0.0.1", &tarball);
    let pin = mirror.package("fake-claude", "9.9.9", &claude);
    mirror.require(&format!("Bearer {token}"));
    let mirrors = Mirrors {
        node: Some(mirror.node_base()),
        npm: Some(mirror.registry()),
        ca: Some((mirror.ca_pem(), "/etc/superbot/mirror-ca.pem".into())),
        login: Some(Login::Token(zeroize::Zeroizing::new(token.into()))),
    };
    let plan = mirrors.apply(HarnessPlan { node: Some(node), harnesses: vec![npm("claude", "fake-claude", "9.9.9", pin)], ..Default::default() });
    assert!(plan.npm_login && !serde_json::to_string(&plan).unwrap().contains(token), "the plan says a login is wanted, never what it is");
    let planned = plan.clone();
    let mut env = serve_with(move |mut e| {
        e.upkeep.plan = Some(planned);
        e.upkeep.mirrors = Some(mirrors);
        e
    })
    .await;

    // The check signs in to the registry as machines will.
    let (code, v) = json_call(&env, "GET", "/api/machines/harness-mirror", "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["ok"].clone(), v["npmLogin"].clone(), v["mirrors"]["npmLogin"].clone()), (json!(true), json!("token"), json!("token")), "{v}");
    assert!(!v.to_string().contains(token), "{v}");

    // Only a machine with its certificate gets the login.
    let anyone = reqwest::Client::builder()
        .tls_backend_preconfigured(pki::client_config(&pki::cert_der(env.e.ca_pem()).unwrap(), None).unwrap())
        .build()
        .unwrap();
    assert_eq!(anyone.get(format!("{}/v1/npm-login", env.e.url)).send().await.unwrap().status(), 401);
    assert!(events(&env, "machine.npm_login_sent").await.is_empty());

    let (uid, mid, token_for_machine) = machine_for(&env, "ada@example.com").await;
    let m = agent_on(&mut env, &mid, &token_for_machine, "#!/bin/sh\n").await;
    let v = beat_until(&env, &uid, "claude installed through the login", |v| {
        assert_ne!(v["agent"]["harnesses"]["claude"]["state"], "failed", "{v}");
        v["agent"]["harnesses"]["claude"]["state"] == "installed"
    })
    .await;
    assert_eq!(v["agent"]["plan"].as_str(), Some(plan.id().as_str()), "{v}");

    // npm was handed a userconfig only root reads, naming only the plan's registry.
    let saw = std::fs::read_to_string(m.cfg.tools.join("node-0.0.1/npm-saw")).unwrap();
    let dart = crate::machines::tools::nerf_dart(&mirror.registry()).unwrap();
    assert!(saw.contains(&format!("userconfig 600\n{dart}:_authToken={token}\n")), "{saw}");
    assert!(!m.cfg.tools.join(".dl").exists(), "the login goes with the downloads");
    let state = std::fs::read_to_string(m.cfg.tools.join("state.json")).unwrap_or_default();
    assert!(!state.contains(token), "and the agent never saves it");

    let sent = events(&env, "machine.npm_login_sent").await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["details"], json!({ "userId": uid, "registry": mirror.registry(), "login": "token" }));
    let (_, audit) = json_call(&env, "GET", "/api/audit?limit=200", "").await;
    assert!(!audit.to_string().contains(token), "the audit log never holds it");
}

#[tokio::test]
async fn machines_install_hermes_from_botds_bundle_over_mutual_tls() {
    use crate::adapters::install;
    use crate::machines::hermes_bundle::standin;
    use crate::machines::hermes_serve::Bundles;
    let arch = std::env::consts::ARCH;
    let dir = crate::db::temp_path("hermes-bundles");
    std::fs::create_dir_all(&dir).unwrap();
    let body = standin::good(arch, "#!/bin/sh\necho 'Hermes Agent v0.23.3'\n");
    let file = dir.join(format!("superbot-hermes-v0.23.3-{arch}.tar.gz"));
    std::fs::write(&file, &body).unwrap();
    std::fs::write(dir.join(format!("superbot-hermes-v0.23.3-{arch}.tar.gz.sha256")), format!("{}\n", hex(&body))).unwrap();
    let setting = file.display().to_string();
    let mut env = serve_with(move |mut e| {
        let url = e.url.clone();
        let var = |k: &str| match k {
            "MACHINE_HERMES_BUNDLE" => setting.clone(),
            "MACHINE_CONTROL_URL" => url.clone(),
            _ => String::new(),
        };
        let hermes = Bundles::from_env(&var).unwrap().unwrap();
        let mut plan = hermes.apply(install::plan(vec![install::install("hermes", None, None).unwrap()])).unwrap();
        // The stand-in tree has no Hermes for hermes-share.sh to share; its own test
        // runs it.
        if let InstallSource::Bundle { after, .. } = &mut plan.harnesses[0].source {
            *after = Some("touch \"$HOME/.hermes/superbot/shared\"\n".into());
        }
        e.upkeep.plan = Some(plan);
        e.upkeep.hermes = Some(hermes);
        e
    })
    .await;
    assert_eq!(standin::COMMIT, install::install("hermes", None, None).unwrap().version, "the stand-in is the pinned commit");

    // The check reads the file again and finds the SHA-256 the plan pins.
    let (code, v) = json_call(&env, "GET", "/api/machines/harness-mirror", "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["ok"].clone(), v["items"][0]["arch"].clone()), (json!(true), json!(arch)), "{v}");
    assert!(v["items"][0]["note"].as_str().unwrap().contains("MACHINE_HERMES_BUNDLE"), "{v}");

    // Only a machine with its certificate gets it.
    let anyone = reqwest::Client::builder()
        .tls_backend_preconfigured(pki::client_config(&pki::cert_der(env.e.ca_pem()).unwrap(), None).unwrap())
        .build()
        .unwrap();
    let r = anyone.get(format!("{}/v1/hermes/{arch}", env.e.url)).send().await.unwrap();
    assert_eq!(r.status(), 401);

    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_on(&mut env, &mid, &token, "#!/bin/sh\n").await;
    m.agent.tools.set_root(dir.join("root"));
    let v = beat_until(&env, &uid, "hermes installed from the bundle", |v| {
        let s = &v["agent"]["harnesses"]["hermes"]["state"];
        assert_ne!(s, "failed", "{v}");
        s == "installed"
    })
    .await;
    assert_eq!(v["agent"]["harnesses"]["hermes"]["version"], standin::COMMIT, "{v}");
    let out = std::process::Command::new(m.cfg.tools.join("bin/hermes")).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Hermes Agent v0.23.3");
    let prefix = dir.join("root/opt/hermes");
    assert!(prefix.join(".hermes/superbot/shared").exists(), "its after script ran in the prefix");
    assert_eq!(std::fs::read_dir(dir.join("root/opt")).unwrap().count(), 1, "nothing is left beside it");
    assert_eq!(events(&env, "machine.harness_installed").await.len(), 1);

    // A file changed on disk after botd checked it is caught by the check.
    std::fs::write(&file, b"something else").unwrap();
    let (_, v) = json_call(&env, "GET", "/api/machines/harness-mirror", "").await;
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["items"][0]["error"].as_str().unwrap().contains("restart botd"), "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A build of the agent: answers `--version` as the real one does.
fn build(version: &str, tag: &str) -> &'static [u8] {
    Box::leak(format!("#!/bin/sh\n# {tag}\necho 'superbot-machine {version}'\n").into_bytes().into_boxed_slice())
}

/// The unit's guard, run before each of `n` starts, as systemd would.
fn guard(m: &Machine, n: usize) {
    for _ in 0..n {
        let out = std::process::Command::new("sh")
            .args(["-c", enroll::GUARD])
            .env("STATE_DIRECTORY", &m.cfg.state_dir)
            .env("SUPERBOT_AGENT_DIR", m.cfg.exe.parent().unwrap())
            .output()
            .unwrap();
        assert!(out.status.success());
    }
}

fn read(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn prev(p: &std::path::Path) -> std::path::PathBuf {
    p.with_file_name(format!("{}.prev", p.file_name().unwrap().to_string_lossy()))
}

#[tokio::test]
async fn an_admin_upgrades_an_agent_that_puts_the_old_one_back_if_the_new_one_fails() {
    let new = build(VERSION, "new");
    let mut env = serve_with(move |e| e.with_agent(new).with_botctl(b"new botctl")).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let old = String::from_utf8(build("0.0.9", "old").to_vec()).unwrap();
    let mut m = agent_on(&mut env, &mid, &token, &old).await;
    let ctl = m.cfg.exe.with_file_name("botctl");
    std::fs::write(&ctl, "old botctl").unwrap();
    let path = format!("/api/users/{uid}/machine/agent");

    let v = beat_until(&env, &uid, "heard from", |v| v["agent"]["build"].is_string()).await;
    assert_eq!(v["agent"]["build"].as_str(), Some(hex(old.as_bytes()).as_str()));
    assert_eq!((v["upToDate"].as_bool(), v["botd"]["build"].as_str()), (Some(false), Some(hex(new).as_str())), "{v}");
    assert!(v["agent"]["can"].as_array().unwrap().contains(&json!("upgrade")), "{v}");
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.agent_upgrade_requested").await.is_empty(), "manual by default");

    // Held, nothing upgrades it.
    let (code, v) = json_call(&env, "PUT", &format!("{path}/hold"), "").await;
    assert_eq!((code, v["hold"].is_object()), (200, true), "{v}");
    let (code, v) = json_call(&env, "POST", &format!("{path}/upgrade"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("held"), "{v}");
    let (code, _) = json_call(&env, "DELETE", &format!("{path}/hold"), "").await;
    assert_eq!(code, 200);
    assert_eq!(events(&env, "machine.agent_upgrade_held").await.len(), 1);
    assert_eq!(events(&env, "machine.agent_upgrade_released").await.len(), 1);

    // The new build won't start: the guard puts the old one back.
    let (code, v) = json_call(&env, "POST", &format!("{path}/upgrade"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!(v["upgrade"]["build"].as_str(), Some(hex(new).as_str()), "{v}");
    // On its way, it can't be called back, so it can't be held either.
    let (code, v) = json_call(&env, "PUT", &format!("{path}/hold"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("on its way"), "{v}");
    assert_eq!(events(&env, "machine.agent_upgrade_held").await.len(), 1);
    m.wait_for_restart().await;
    assert_eq!((read(&m.cfg.exe).as_bytes(), read(&ctl).as_str()), (new, "new botctl"));
    assert_eq!((read(&prev(&m.cfg.exe)), read(&prev(&ctl))), (old.clone(), "old botctl".to_string()));
    guard(&m, 4);
    assert_eq!((read(&m.cfg.exe), read(&ctl)), (old.clone(), "old botctl".to_string()));
    m.restart().await;
    let v = beat_until(&env, &uid, "rolled back", |v| v["upgrade"].is_null()).await;
    assert_eq!(v["failedBuild"].as_str(), Some(hex(new).as_str()), "{v}");
    let failed = events(&env, "machine.agent_upgrade_failed").await;
    assert_eq!((failed.len(), failed[0]["details"]["reason"].as_str()), (1, Some("rolled_back")), "{failed:?}");
    assert_eq!(failed[0]["outcome"], "failure");

    // Asked again, the new build starts and botd reaches it: it is kept.
    let (code, v) = json_call(&env, "POST", &format!("{path}/upgrade"), "").await;
    assert_eq!(code, 202, "{v}");
    m.wait_for_restart().await;
    m.restart().await;
    assert!(m.agent.upgrader.trial_deadline().is_some(), "on trial until botd reaches it");
    let v = beat_until(&env, &uid, "upgraded", |v| v["upToDate"] == true && v["upgrade"].is_null()).await;
    assert_eq!((v["failedBuild"].clone(), v["agent"]["upgrade"]["state"].clone()), (Value::Null, json!("done")), "{v}");
    assert!(!prev(&m.cfg.exe).exists() && !prev(&ctl).exists(), "the old build is let go");
    let done = events(&env, "machine.agent_upgraded").await;
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(
        (done[0]["details"]["fromBuild"].as_str(), done[0]["details"]["toBuild"].as_str()),
        (Some(hex(old.as_bytes()).as_str()), Some(hex(new).as_str()))
    );
    let asked = events(&env, "machine.agent_upgrade_requested").await;
    assert_eq!(asked.len(), 2);
    assert!(asked.iter().all(|e| e["actorKind"] == "user"), "{asked:?}");

    let (code, v) = json_call(&env, "POST", &format!("{path}/upgrade"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("already"), "{v}");
}

#[tokio::test]
async fn an_upgrade_whose_agent_goes_quiet_times_out() {
    let new = build(VERSION, "quiet");
    let mut env = serve_with(move |e| e.with_agent(new)).await;
    let (uid, mid, token) = machine_for(&env, "cy@example.com").await;
    let old = String::from_utf8(build("0.0.9", "old").to_vec()).unwrap();
    let mut m = agent_on(&mut env, &mid, &token, &old).await;
    let path = format!("/api/users/{uid}/machine/agent");
    beat_until(&env, &uid, "heard from", |v| v["agent"]["build"].is_string()).await;
    let (code, v) = json_call(&env, "POST", &format!("{path}/upgrade"), "").await;
    assert_eq!(code, 202, "{v}");
    m.wait_for_restart().await;

    // The new agent never comes up, so no heartbeat says how it went.
    m.server.abort();
    let _ = (&mut m.server).await;
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.agent_upgrade_failed").await.is_empty(), "not yet");
    env.app.db.machine_upgrade_backdate(&mid, 86_400_000 + 11 * 60_000);
    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(0), "it doesn't answer");
    let failed = events(&env, "machine.agent_upgrade_failed").await;
    assert_eq!((failed.len(), failed[0]["details"]["reason"].as_str()), (1, Some("timeout")), "{failed:?}");
    assert_eq!(failed[0]["outcome"], "failure");
    let (code, v) = json_call(&env, "GET", &path, "").await;
    assert_eq!(code, 200);
    assert_eq!((v["upgrade"].clone(), v["failedBuild"].as_str()), (Value::Null, Some(hex(new).as_str())), "{v}");
}

#[tokio::test]
async fn auto_upgrades_skip_held_machines_and_builds_that_failed() {
    let new = build(VERSION, "auto");
    let mut env = serve_with(move |mut e| {
        e.upkeep.upgrades = Upgrades::Auto;
        e.with_agent(new)
    })
    .await;
    let (uid, mid, token) = machine_for(&env, "bo@example.com").await;
    let old = String::from_utf8(build("0.0.9", "old").to_vec()).unwrap();
    let mut m = agent_on(&mut env, &mid, &token, &old).await;
    let (code, _) = json_call(&env, "PUT", &format!("/api/users/{uid}/machine/agent/hold"), "").await;
    assert_eq!(code, 200);
    heartbeats(&env.app, &env.cp).await;
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.agent_upgrade_requested").await.is_empty(), "held");

    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine/agent/hold"), "").await;
    assert_eq!(code, 200);
    heartbeats(&env.app, &env.cp).await;
    let asked = events(&env, "machine.agent_upgrade_requested").await;
    assert_eq!((asked.len(), asked[0]["details"]["by"].as_str()), (1, Some("auto")), "{asked:?}");
    m.wait_for_restart().await;
    guard(&m, 4);
    m.restart().await;
    beat_until(&env, &uid, "rolled back", |v| v["failedBuild"].is_string()).await;
    for _ in 0..3 {
        heartbeats(&env.app, &env.cp).await;
    }
    assert_eq!(events(&env, "machine.agent_upgrade_requested").await.len(), 1, "a build that failed isn't tried again by itself");
}

/// A Node.js laid out as nodejs.org's tarballs are, from the `node` and `npm` on PATH.
fn real_node_tarball(dir: &std::path::Path) -> Vec<u8> {
    use crate::machines::standin_mirror::node_arch;
    let which = |b: &str| {
        let out = std::process::Command::new("sh").args(["-c", &format!("readlink -f \"$(command -v {b})\"")]).output().unwrap();
        let p = String::from_utf8(out.stdout).unwrap().trim().to_string();
        assert!(!p.is_empty(), "{b} isn't on PATH");
        std::path::PathBuf::from(p)
    };
    // .../lib/node_modules/npm/bin/npm-cli.js, and the node beside that prefix.
    let npm_dir = which("npm").parent().unwrap().parent().unwrap().to_path_buf();
    let beside = npm_dir.join("../../../bin/node");
    let node_bin = if beside.is_file() { beside } else { which("node") };
    let top = dir.join(format!("node-v0.0.2-linux-{}", node_arch()));
    std::fs::create_dir_all(top.join("bin")).unwrap();
    std::fs::create_dir_all(top.join("lib/node_modules")).unwrap();
    std::fs::copy(&node_bin, top.join("bin/node")).unwrap();
    sh(dir, &format!("cp -a '{}' '{}/lib/node_modules/npm'", npm_dir.display(), top.display()));
    sh(&top.join("bin"), "ln -s ../lib/node_modules/npm/bin/npm-cli.js npm && ln -s ../lib/node_modules/npm/bin/npx-cli.js npx");
    sh(dir, &format!("XZ_OPT='-0 -T0' tar -cJf node.tar.xz '{}'", top.file_name().unwrap().to_str().unwrap()));
    std::fs::read(dir.join("node.tar.xz")).unwrap()
}

/// An npm package `name@1.0.0` holding `file`.
fn real_tgz(manifest: String, file: &str, body: &str) -> Vec<u8> {
    let d = crate::db::temp_path("probe");
    std::fs::create_dir_all(d.join("package")).unwrap();
    std::fs::write(d.join("package/package.json"), manifest).unwrap();
    exe(&d.join("package").join(file), body);
    sh(&d, "tar -czf probe.tgz package");
    std::fs::read(d.join("probe.tgz")).unwrap()
}

/// A probe whose `pi` and `codex` print `says` and what `@corp/mirror-dep` exports.
fn real_probe(name: &str, says: &str) -> Vec<u8> {
    let manifest = format!(r#"{{"name": "{name}", "version": "1.0.0", "bin": {{"pi": "cli.js", "codex": "cli.js"}}, "dependencies": {{"@corp/mirror-dep": "^1.0.0"}}}}"#);
    real_tgz(manifest, "cli.js", &format!("#!/usr/bin/env node\nconsole.log({says:?} + require('@corp/mirror-dep'));\n"))
}

/// Has `tools` install its plan, then what it reports of each harness.
async fn real_install(tools: &Arc<crate::machines::tools::Tools>, names: &[&str]) -> std::collections::BTreeMap<String, crate::machines::wire::HarnessStatus> {
    let worker = tokio::spawn(tools.clone().work());
    for _ in 0..1200 {
        let r = tools.report().1;
        if names.iter().all(|n| r.get(*n).is_some_and(|h| h.state == "installed" || h.state == "failed")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    worker.abort();
    tools.report().1
}

/// The real npm, in a Node.js laid out as nodejs.org's tarballs are, installs a package
/// from a stand-in registry over HTTPS with a CA of its own, through the agent's tools,
/// and refuses one that isn't what was pinned. Needs `node`, `npm` and `xz`; CI runs it
/// with no network at all (`server.yml`'s isolation job), so npm reaching anything but
/// the mirror fails it: `cargo test -- --ignored real_npm_installs_from_a_mirror`.
#[tokio::test]
#[ignore]
async fn real_npm_installs_from_a_mirror_with_no_network() {
    use crate::machines::standin_mirror::Mirror;
    use crate::machines::tools::Tools;
    let dir = crate::db::temp_path("real-npm");
    let node_tarball = real_node_tarball(&dir);
    let mirror = Mirror::serve().await;
    let node = mirror.node("0.0.2", &node_tarball);
    // Like Claude Code's and Codex's platform packages: only the mirror has it, and npm fetches it itself.
    let dep = real_tgz(r#"{"name": "@corp/mirror-dep", "version": "1.0.0", "main": "index.js"}"#.into(), "index.js", "module.exports = ', with its dependency';\n");
    mirror.package("@corp/mirror-dep", "1.0.0", &dep);
    let pin = mirror.package("@corp/mirror-probe", "1.0.0", &real_probe("@corp/mirror-probe", "from the mirror"));
    mirror.package("other-probe", "1.0.0", &real_probe("other-probe", "not pinned"));
    let wrong = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([3u8; 64]));
    let plan = mirror.plan(&node, vec![("pi", "@corp/mirror-probe", "1.0.0", Some(pin)), ("codex", "other-probe", "1.0.0", Some(wrong))]);
    crate::machines::tools::check(&plan).unwrap();

    let tools = Tools::new(dir.join("tools"), None).unwrap();
    tools.set_plan(plan).unwrap();
    let r = real_install(&tools, &["pi", "codex"]).await;
    assert_eq!(r["pi"].state, "installed", "{:?}", r["pi"]);
    assert_eq!(r["codex"].state, "failed", "{:?}", r["codex"]);
    assert!(r["codex"].error.as_deref().unwrap_or("").contains("not the pinned"), "{:?}", r["codex"]);
    let out = std::process::Command::new(tools.bin_dir().join("pi"))
        .env("PATH", format!("{}:/usr/bin:/bin", tools.bin_dir().display()))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "from the mirror, with its dependency", "{}", String::from_utf8_lossy(&out.stderr));
    let calls = mirror.calls();
    assert!(calls.iter().any(|c| c == "/npm/@corp%2fmirror-probe"), "{calls:?}");
    assert!(calls.iter().any(|c| c == "/npm/@corp/mirror-dep/-/mirror-dep-1.0.0.tgz"), "{calls:?}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The real npm signs in to a registry that wants a login (ADR 0219) with the line the
/// agent writes from what botd hands it, as a token and as a username and password, for
/// the metadata and every tarball. A wrong login fails with npm's 401, the login itself
/// taken out. Runs beside the test above, with no network:
/// `cargo test -- --ignored real_npm_signs_in_to_a_registry_that_wants_a_login`.
#[tokio::test]
#[ignore]
async fn real_npm_signs_in_to_a_registry_that_wants_a_login() {
    use crate::machines::standin_mirror::Mirror;
    use crate::machines::tools::{Tools, download_client};
    use crate::machines::wire::NpmLogin;
    let dir = crate::db::temp_path("real-npm-login");
    let node_tarball = real_node_tarball(&dir);
    let mirror = Mirror::serve().await;
    let node = mirror.node("0.0.2", &node_tarball);
    let dep = real_tgz(r#"{"name": "@corp/mirror-dep", "version": "1.0.0", "main": "index.js"}"#.into(), "index.js", "module.exports = ', signed in';\n");
    mirror.package("@corp/mirror-dep", "1.0.0", &dep);
    let pin = mirror.package("@corp/mirror-probe", "1.0.0", &real_probe("@corp/mirror-probe", "from the mirror"));
    let mut plan = mirror.plan(&node, vec![("pi", "@corp/mirror-probe", "1.0.0", Some(pin))]);
    plan.npm_login = true;
    crate::machines::tools::check(&plan).unwrap();
    let registry = mirror.registry();
    let basic = base64::engine::general_purpose::STANDARD.encode("svc-npm:p@ss:w0rd/+");
    let tries = [
        ("token", NpmLogin { registry: registry.clone(), token: Some("real-npm-token-91c2".into()), auth: None }, "Bearer real-npm-token-91c2".to_string(), true),
        ("basic", NpmLogin { registry: registry.clone(), token: None, auth: Some(basic.clone()) }, format!("Basic {basic}"), true),
        ("wrong", NpmLogin { registry: registry.clone(), token: Some("real-npm-wrong-55e0".into()), auth: None }, "Bearer real-npm-token-91c2".to_string(), false),
    ];
    for (n, (what, login, wants, ok)) in tries.into_iter().enumerate() {
        mirror.require(&wants);
        mirror.serve_login(&login);
        let tools = Tools::new(dir.join(format!("tools-{n}")), None).unwrap();
        let ca = mirror.ca_pem();
        tools.set_control(&mirror.other, Box::new(move || download_client(None, Some(&ca))));
        tools.set_plan(plan.clone()).unwrap();
        let before = mirror.authorized().len();
        let r = real_install(&tools, &["pi"]).await;
        if !ok {
            assert_eq!(r["pi"].state, "failed", "{what}: {:?}", r["pi"]);
            let err = r["pi"].error.clone().unwrap_or_default();
            assert!(err.contains("npm pack failed") && (err.contains("401") || err.contains("password")), "{what}: {err}");
            assert!(!err.contains("real-npm-wrong-55e0"), "{what}: the login is taken out of npm's errors: {err}");
            continue;
        }
        assert_eq!(r["pi"].state, "installed", "{what}: {:?}", r["pi"]);
        let out = std::process::Command::new(tools.bin_dir().join("pi"))
            .env("PATH", format!("{}:/usr/bin:/bin", tools.bin_dir().display()))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "from the mirror, signed in", "{what}: {}", String::from_utf8_lossy(&out.stderr));
        let signed: Vec<_> = mirror.authorized().split_off(before);
        for p in ["/npm/@corp%2fmirror-probe", "/npm/@corp/mirror-probe/-/mirror-probe-1.0.0.tgz", "/npm/@corp/mirror-dep/-/mirror-dep-1.0.0.tgz"] {
            assert!(signed.iter().any(|c| c.eq_ignore_ascii_case(p)), "{what}: {p} not in {signed:?}");
        }
        assert!(!dir.join(format!("tools-{n}/.dl")).exists());
    }
    let _ = std::fs::remove_dir_all(dir);
}
