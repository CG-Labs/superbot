//! The red-team scenario for per-user computer hardening (#54, ADR 0145). Each test
//! plays a Bot that tries to get out, through the same launch path the machine agent
//! uses (`job::run`: its cgroup, its user, no new privileges, its own umask and TMPDIR),
//! and asserts every attempt is blocked:
//!
//! - reading another person's files on the machine, the owner's from a teammate's run
//!   and a teammate's from the owner's, /tmp included;
//! - reading the agent's key, its records, or its process's memory and environment;
//! - raising its privileges, with a sudo rule, a setuid-root program and a program
//!   with file capabilities all there to use, and the agent refusing a user that has one;
//! - getting past the outbound allow-list and the deny rules, or changing them;
//! - exhausting the machine: a fork bomb, a memory balloon and a CPU spin, beside a run
//!   that must still finish and an agent that must still answer.
//!
//! The first test runs without root, as the user running the tests. The rest make real
//! users, cgroups and network namespaces, so they need root on a host thrown away after;
//! CI's isolation job runs each:
//!
//! ```text
//! sudo SUPERBOT_MACHINE_BOT_USER_TEST=1 <botd tests> --ignored --exact \
//!   machines_redteam_tests::as_root_red_team_a_run_cant_raise_its_privileges
//! ```

use crate::machines::agent::{self, Agent};
use crate::machines::cgroup::Cgroups;
use crate::machines::job::{self, Host, Limiting};
use crate::machines::runas::{self, Ids};
use crate::machines::wire::{self, JobEvent, JobRequest, LimitReport, RunLimits};
use crate::machines_bot_user_tests::until_ready;
use crate::machines_mtls_tests::{agent_with_config, machine_for, serve_with_auth};
use crate::machines_teammates_tests::{World, ada_auth, run as send, said, shared_pi};
use crate::users_http_tests::user_with;
use crate::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const GATE: &str = "SUPERBOT_MACHINE_BOT_USER_TEST";

fn as_root() -> bool {
    if std::env::var(GATE).as_deref() == Ok("1") && runas::is_root() {
        return true;
    }
    eprintln!("skipped: needs root and {GATE}=1, on a host thrown away after");
    false
}

fn sh(script: &str) -> std::process::Output {
    Command::new("sh").args(["-c", script]).output().unwrap()
}

fn sh_ok(script: &str) {
    let out = sh(script);
    assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A user made for one test, with a home of its own, removed with it.
struct User {
    name: String,
    ids: Ids,
    home: PathBuf,
}

impl User {
    fn new(name: &str) -> User {
        let _ = Command::new("userdel").arg(name).output();
        let home = crate::db::temp_path(&format!("rt-{name}"));
        std::fs::create_dir_all(&home).unwrap();
        let ids = runas::ensure_user_as(name, &home, "SuperBot red team").unwrap();
        std::os::unix::fs::chown(&home, Some(ids.uid), Some(ids.gid)).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        User { name: name.into(), ids, home }
    }

    /// The environment the agent gives a run as this user.
    fn host(&self) -> Host {
        let env = [
            ("HOME", self.home.display().to_string()),
            ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
            ("LANG", "C.UTF-8".into()),
            ("USER", self.name.clone()),
            ("LOGNAME", self.name.clone()),
            ("TMPDIR", self.home.display().to_string()),
        ]
        .map(|(k, v)| (k.to_string(), v))
        .into();
        Host { clear_env: true, remove: vec![], env, user: Some(self.ids), limits: None }
    }
}

impl Drop for User {
    fn drop(&mut self) {
        let _ = Command::new("pkill").args(["-KILL", "-u", &self.name]).output();
        let _ = Command::new("userdel").arg(&self.name).output();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// What a run printed, whether it succeeded, and what its cgroup saw.
struct Ran {
    ok: bool,
    out: String,
    limited: Option<LimitReport>,
}

impl Ran {
    /// The value the run printed for `key`, as `key=value`.
    fn said(&self, key: &str) -> &str {
        self.out
            .split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} in:\n{}", self.out))
    }
}

/// Runs `script` with `sh` as a job on `host`, in `cwd`, stopped after `secs`.
async fn run_job(host: &Host, script: &str, cwd: &Path, secs: u64) -> Ran {
    let req = JobRequest {
        protocol: wire::PROTOCOL,
        job_id: format!("rt{}", crate::random_hex(4)),
        bot_id: "b1".into(),
        owner_id: "u1".into(),
        for_user: None,
        message_id: 1,
        bin: "sh".into(),
        args: vec!["-c".into(), script.into()],
        env: Default::default(),
        cwd: cwd.display().to_string(),
        stdin: None,
        files: vec![],
        cleanup: None,
        collect: vec![],
        limits: None,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    job::run(host, &req, tokio::time::sleep(Duration::from_secs(secs)), &tx).await;
    drop(tx);
    let mut ran = Ran { ok: false, out: String::new(), limited: None };
    while let Some(ev) = rx.recv().await {
        match ev {
            JobEvent::Line { line } => ran.out.push_str(&format!("{line}\n")),
            JobEvent::Exit { success, limited, stderr, .. } => {
                ran.ok = success;
                ran.limited = limited;
                ran.out.push_str(&stderr);
            }
            JobEvent::Error { message } => panic!("the run didn't start: {message}"),
            _ => {}
        }
    }
    ran
}

/// `r <command>`: `read` if it worked, `denied` if not.
const R: &str = r#"r() { if "$@" >/dev/null 2>&1; then echo read; else echo denied; fi; }
"#;

#[tokio::test]
async fn a_locked_down_run_cant_gain_privileges_or_share_its_files() {
    // As the user running the tests: what holds for any user, root or not.
    // SAFETY: no arguments.
    let me = unsafe { Ids { uid: libc::geteuid(), gid: libc::getegid() } };
    let dir = crate::db::temp_path("rt-locked");
    std::fs::create_dir_all(&dir).unwrap();
    let mut host = Host { user: Some(me), ..Default::default() };
    host.env.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into());
    let script = format!(
        r#"{R}echo "nnp=$(awk '/^NoNewPrivs/ {{print $2}}' /proc/self/status)"
echo "umask=$(umask)"
touch made; echo "made=$(stat -c %a made)"
mkdir folder; echo "folder=$(stat -c %a folder)"
echo "sudo=$(r sudo -n true)"
sh -c 'echo "child=$(awk "/^NoNewPrivs/ {{print \$2}}" /proc/self/status)"'
"#
    );
    let ran = run_job(&host, &script, &dir, 30).await;
    assert!(ran.ok, "{}", ran.out);
    assert_eq!(ran.said("nnp"), "1", "{}", ran.out);
    assert_eq!(ran.said("child"), "1", "kept across every exec: {}", ran.out);
    assert_eq!((ran.said("umask"), ran.said("made"), ran.said("folder")), ("0077", "600", "700"));
    // Whether or not this user may sudo, a locked-down run can't.
    assert_eq!(ran.said("sudo"), "denied", "{}", ran.out);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
#[ignore = "needs root on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_red_team_a_run_cant_raise_its_privileges() {
    if !as_root() {
        return;
    }
    let u = User::new("sbrt-esc");
    let tag = std::process::id();
    // Every way up a careless host could leave: a sudo rule for the user, a setuid-root
    // program, and a program with a file capability that reads any file.
    let rule = format!("/etc/sudoers.d/sbrt-esc-{tag}");
    std::fs::write(&rule, format!("{} ALL=(ALL) NOPASSWD: ALL\n", u.name)).unwrap();
    std::fs::set_permissions(&rule, std::fs::Permissions::from_mode(0o440)).unwrap();
    let tools = std::env::temp_dir().join(format!("sbrt-up-{tag}"));
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::set_permissions(&tools, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (suid, capcat) = (tools.join("id"), tools.join("cat"));
    std::fs::copy("/usr/bin/id", &suid).unwrap();
    std::fs::set_permissions(&suid, std::fs::Permissions::from_mode(0o4755)).unwrap();
    std::fs::copy("/usr/bin/cat", &capcat).unwrap();
    sh_ok(&format!("setcap cap_dac_read_search+ep {}", capcat.display()));

    // Each one works for the user when nothing holds it back, so each probe means something.
    let plain = |cmd: &str| {
        let out = Command::new("runuser").args(["-u", &u.name, "--", "sh", "-c", cmd]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(plain("sudo -n id -u"), "0", "the sudo rule works without the lock");
    assert_eq!(plain(&format!("{} -u", suid.display())), "0", "the setuid program works without the lock");
    assert_eq!(plain(&format!("{} /etc/shadow >/dev/null && echo read", capcat.display())), "read", "the capability works without the lock");

    let script = format!(
        r#"{R}echo "uid=$(id -u) gid=$(id -g) groups=$(id -G | tr ' ' ,)"
echo "sudo=$(r sudo -n true)"
echo "sudoid=$(sudo -n id -u 2>/dev/null || echo none)"
echo "su=$(r su -c true root </dev/null)"
echo "suid=$({suid} -u)"
echo "capcat=$(r {capcat} /etc/shadow)"
echo "shadow=$(r head -c1 /etc/shadow)"
echo "passwd=$(r sh -c 'echo x >> /etc/passwd')"
echo "sudoers=$(r sh -c 'echo x >> /etc/sudoers.d/sbrt')"
echo "nft=$(r nft list ruleset)"
echo "kill1=$(r kill -0 1)"
echo "environ1=$(r head -c1 /proc/1/environ)"
echo "chown=$(r chown root {home})"
echo "nnp=$(awk '/^NoNewPrivs/ {{print $2}}' /proc/self/status)"
echo "caps=$(awk '/^CapEff/ {{print $2}}' /proc/self/status)"
echo "amb=$(awk '/^CapAmb/ {{print $2}}' /proc/self/status)"
"#,
        suid = suid.display(),
        capcat = capcat.display(),
        home = u.home.display(),
    );
    let ran = run_job(&u.host(), &script, &u.home, 60).await;
    let _ = std::fs::remove_file(&rule);
    let _ = std::fs::remove_dir_all(&tools);
    let uid = u.ids.uid.to_string();
    assert_eq!(ran.said("uid"), uid, "{}", ran.out);
    assert_eq!(ran.said("groups"), u.ids.gid.to_string(), "no extra groups: {}", ran.out);
    for blocked in ["sudo", "su", "capcat", "shadow", "passwd", "sudoers", "nft", "kill1", "environ1", "chown"] {
        assert_eq!(ran.said(blocked), "denied", "{blocked}: {}", ran.out);
    }
    assert_eq!(ran.said("sudoid"), "none", "{}", ran.out);
    assert_eq!(ran.said("suid"), uid, "a setuid program runs as the user: {}", ran.out);
    assert_eq!(ran.said("nnp"), "1", "{}", ran.out);
    assert_eq!((ran.said("caps"), ran.said("amb")), ("0000000000000000", "0000000000000000"), "{}", ran.out);

    // And the agent never runs anyone as a user with a way up (ADR 0145).
    std::fs::write(&rule, format!("{} ALL=(ALL) NOPASSWD: ALL\n", u.name)).unwrap();
    let why = runas::privileged(&u.name, u.ids);
    let _ = std::fs::remove_file(&rule);
    assert_eq!(why.as_deref(), Some(format!("has a sudo rule in {rule}").as_str()));
    assert_eq!(runas::privileged(&u.name, u.ids), None, "once the rule is gone");
    sh_ok(&format!("usermod -aG adm {}", u.name));
    assert_eq!(runas::privileged(&u.name, u.ids).as_deref(), Some("is in the adm group"));
}

/// The stand-in Pi of the machine test: a Bot that tries everything, as whichever user
/// it runs as, and says what it got. `@...@` are filled in by `probe`.
const MACHINE_PROBE: &str = r#"#!/bin/sh
r() { if "$@" >/dev/null 2>&1; then echo read; else echo denied; fi; }
me=$(id -u)
drop=/tmp/sbrt-drop-@TAG@-$me
echo private > "$drop"
o=none
for f in /tmp/sbrt-drop-@TAG@-*; do
  [ "$f" = "$drop" ] && continue
  [ -e "$f" ] || continue
  if head -c1 "$f" >/dev/null 2>&1; then o=read; elif [ "$o" = none ]; then o=denied; fi
done
out="uid=$me user=$USER"
out="$out owner=$(r head -c1 @HOME@/.claude/.credentials.json)"
out="$out work=$(r ls @HOME@/work)"
out="$out bots=$(r ls @HOME@/bots)"
out="$out mate=$(r head -c1 @MATE@/secret)"
out="$out matehome=$(r ls @MATE@)"
out="$out key=$(r head -c1 @STATE@/identity.pem)"
out="$out record=$(r head -c1 @STATE@/bot-user.json)"
out="$out roster=$(r head -c1 @STATE@/teammates.json)"
out="$out state=$(r ls @STATE@)"
out="$out environ=$(r head -c1 /proc/@PID@/environ)"
out="$out maps=$(r head -c1 /proc/@PID@/maps)"
out="$out signal=$(r kill -0 @PID@)"
out="$out sudo=$(r sudo -n true)"
out="$out suid=$(@SUID@ -u 2>/dev/null || echo none)"
out="$out nnp=$(awk '/^NoNewPrivs/ {print $2}' /proc/self/status)"
out="$out umask=$(umask)"
out="$out tmp=$(stat -c %u:%a "$TMPDIR" 2>/dev/null || echo none)"
out="$out drop=$(stat -c %a "$drop") others=$o"
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"%s"}]}}\n' "$out"
"#;

#[tokio::test]
#[ignore = "needs root: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_red_team_bots_cant_reach_another_persons_files_or_the_agents_secrets() {
    if !as_root() {
        return;
    }
    const USER: &str = "sbrt-bots";
    let _ = Command::new("userdel").arg(USER).output();
    let tag = std::process::id();
    let state = crate::db::temp_path("rt-agent");
    let suid_dir = std::env::temp_dir().join(format!("sbrt-suid-{tag}"));
    std::fs::create_dir_all(&suid_dir).unwrap();
    std::fs::set_permissions(&suid_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let suid = suid_dir.join("id");
    std::fs::copy("/usr/bin/id", &suid).unwrap();
    std::fs::set_permissions(&suid, std::fs::Permissions::from_mode(0o4755)).unwrap();

    // Ada's machine, with teammates' own users on; Bea is a member of her team.
    let mut env = serve_with_auth(|e| e.with_teammate_users(), |_| {}).await;
    let (ada, mid, token) = machine_for(&env, "ada@example.com").await;
    let (bea_id, bea) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let mate_user = wire::teammate_user(&bea_id);
    let _ = Command::new("userdel").arg(&mate_user).output();
    let mate = state.join("teammates").join(&mate_user);
    let m = agent_with_config(&mut env, &mid, &token, "#!/bin/sh\nexit 3\n", |c| {
        let bin = c.tools.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let probe = MACHINE_PROBE
            .replace("@TAG@", &tag.to_string())
            .replace("@HOME@", &c.home.display().to_string())
            .replace("@MATE@", &mate.display().to_string())
            .replace("@STATE@", &state.display().to_string())
            .replace("@PID@", &tag.to_string())
            .replace("@SUID@", &suid.display().to_string());
        std::fs::write(bin.join("pi"), probe).unwrap();
        std::fs::set_permissions(bin.join("pi"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        agent::Config {
            harness_path: format!("{}:{}", bin.display(), c.harness_path),
            state_dir: state.clone(),
            bot_user: USER.into(),
            allow_own_user: false,
            teammates: state.join("teammates"),
            ..c
        }
    })
    .await;
    let home = m.agent.cfg.home.clone();
    let login = home.join(".claude/.credentials.json");
    std::fs::create_dir_all(login.parent().unwrap()).unwrap();
    std::fs::write(&login, "ada's login").unwrap();
    until_ready(&env, &m.agent).await;
    let (bots, _) = runas::lookup(USER).expect("the agent made the Bots' user");
    std::os::unix::fs::chown(&login, Some(bots.uid), Some(bots.gid)).unwrap();
    std::fs::set_permissions(&login, std::fs::Permissions::from_mode(0o600)).unwrap();
    let w = World { env, m, ada, bea_id, bea, secret: login };
    let team = shared_pi(&w);
    let ada_auth = ada_auth(&w).await;

    // Without the agent's lock, the setuid program would make a Bot root.
    let plain = Command::new("runuser").args(["-u", USER, "--", &suid.display().to_string(), "-u"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&plain.stdout).trim(), "0");

    // What every run, the owner's or a teammate's, is held to.
    let held = |reply: &str, uid: u32| {
        for k in ["key", "record", "roster", "state", "environ", "maps", "signal", "sudo"] {
            assert_eq!(said(reply, k), "denied", "{k}: {reply}");
        }
        assert_eq!(said(reply, "uid"), uid.to_string(), "{reply}");
        assert_eq!(said(reply, "suid"), uid.to_string(), "no way up: {reply}");
        assert_eq!(said(reply, "nnp"), "1", "{reply}");
        assert_eq!(said(reply, "umask"), "0077", "{reply}");
        assert_eq!(said(reply, "tmp"), format!("{uid}:700"), "its own TMPDIR: {reply}");
        assert_eq!(said(reply, "drop"), "600", "{reply}");
    };

    // Ada's Bot reads her own login and folder, nothing of the agent's.
    let first = send(&w, &ada_auth, &team, "go").await;
    held(&first, bots.uid);
    assert_eq!((said(&first, "owner"), said(&first, "work"), said(&first, "bots")), ("read", "read", "read"), "{first}");

    // Bea's run is her own user: nothing of Ada's, nor Ada's Bot's file in /tmp.
    let theirs = send(&w, &w.bea, &team, "go").await;
    let (them, _) = runas::lookup(&mate_user).expect("the agent made Bea's user");
    assert!(them.uid != bots.uid && them.gid != bots.gid);
    held(&theirs, them.uid);
    for k in ["owner", "work", "bots"] {
        assert_eq!(said(&theirs, k), "denied", "{k}: {theirs}");
    }
    assert_eq!(said(&theirs, "others"), "denied", "Ada's Bot's file in /tmp: {theirs}");

    // Bea keeps something in her home; Ada's Bot can't read it, or her file in /tmp.
    let secret = mate.join("secret");
    std::fs::write(&secret, "bea's").unwrap();
    std::os::unix::fs::chown(&secret, Some(them.uid), Some(them.gid)).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let again = send(&w, &ada_auth, &team, "again").await;
    held(&again, bots.uid);
    assert_eq!((said(&again, "mate"), said(&again, "matehome"), said(&again, "others")), ("denied", "denied", "denied"), "{again}");

    // A Bots' user that gains a way up is refused at the agent's next start, and with
    // it every run: never run as it.
    let cfg = w.m.agent.cfg.clone();
    let check = |why: &str| {
        let a = Agent::new(cfg.clone(), agent::load(&cfg).unwrap()).unwrap();
        let st = a.bot_user().unwrap();
        assert_eq!(st.state, wire::BOT_USER_FAILED, "{st:?}");
        assert!(st.error.as_deref().is_some_and(|e| e.contains(why)), "{why}: {st:?}");
    };
    let rule = format!("/etc/sudoers.d/sbrt-bots-{tag}");
    std::fs::write(&rule, format!("{USER} ALL=(ALL) NOPASSWD: ALL\n")).unwrap();
    std::fs::set_permissions(&rule, std::fs::Permissions::from_mode(0o440)).unwrap();
    check("has a sudo rule");
    std::fs::remove_file(&rule).unwrap();
    sh_ok(&format!("usermod -aG docker {USER} 2>/dev/null || (groupadd -f docker && usermod -aG docker {USER})"));
    check("is in the docker group");
    sh_ok(&format!("gpasswd -d {USER} docker >/dev/null"));
    let back = Agent::new(cfg.clone(), agent::load(&cfg).unwrap()).unwrap();
    assert_eq!(back.bot_user().unwrap().state, wire::BOT_USER_READY, "{:?}", back.bot_user());

    let _ = std::fs::remove_dir_all(&suid_dir);
    for f in std::fs::read_dir(std::env::temp_dir()).unwrap().flatten() {
        if f.file_name().to_string_lossy().starts_with(&format!("sbrt-drop-{tag}-")) {
            let _ = std::fs::remove_file(f.path());
        }
    }
    for u in [mate_user.as_str(), USER] {
        let _ = Command::new("pkill").args(["-KILL", "-u", u]).output();
        let _ = Command::new("userdel").arg(u).output();
    }
}

#[test]
#[ignore = "needs root and nft on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
fn as_root_red_team_a_run_cant_get_past_or_change_the_allow_list() {
    use crate::machines::egress_allow::{self, Exempt};
    if !as_root() {
        return;
    }
    let u = User::new("sbrt-net");
    let dir = crate::db::temp_path("rt-egress");
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("egress");
    std::fs::write(&script, crate::machines::hardening::Settings::default_on().egress_script()).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let list = egress_allow::entries(&["198.18.0.9".into(), "10.1.2.3".into()]).unwrap();
    let addrs: Vec<String> = list.iter().map(|e| e.as_str().to_string()).collect();
    std::fs::write(dir.join("allow.nft"), egress_allow::rules(&Exempt::default(), &addrs)).unwrap();
    let setup = format!(
        "set -eu
ip link set lo up
ip tuntap add mode tun name sb0
ip link set sb0 up
ip addr add 198.18.0.2/24 dev sb0
ip route add default dev sb0
ip -6 addr add 2001:db8::2/64 dev sb0 nodad
ip -6 route add default dev sb0
SUPERBOT_HARDENING_STATE={dir} {script}
nft -f {dir}/allow.nft
",
        dir = dir.display(),
        script = script.display(),
    );
    let probe = format!(
        r#"{R}left() {{ sed -n 's/^ *sb0: */sb0 /p' /proc/net/dev | awk '{{ print $11 + $13 }}'; }}
tcp() {{
  before=$(left)
  timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
  code=$?
  if [ $code != 124 ]; then echo refused; elif [ "$(left)" = "$before" ]; then echo dropped; else echo sent; fi
}}
udp() {{
  before=$(left)
  timeout 2 bash -c "echo x > /dev/udp/$1/$2" 2>/dev/null
  sleep 0.3
  if [ "$(left)" = "$before" ]; then echo refused; else echo sent; fi
}}
echo "listed=$(tcp 198.18.0.9 443)"
echo "unlisted=$(tcp 198.18.0.10 443)"
echo "unlisted6=$(tcp 2001:db8::10 443)"
echo "private=$(tcp 10.1.2.3 443)"
echo "metadata=$(tcp 169.254.169.254 80)"
echo "dns=$(udp 198.18.0.53 53)"
echo "udp=$(udp 198.18.0.10 443)"
echo "raw=$(r python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)')"
echo "flush=$(r nft flush ruleset)"
echo "drop=$(r nft delete table inet superbot_allow)"
echo "link=$(r ip link set sb0 down)"
echo "route=$(r ip route replace default dev lo)"
echo "netns=$(r unshare --net true)"
"#
    );
    let (host, cwd) = (u.host(), u.home.clone());
    // A network namespace for this thread alone: the run, which it starts, is in it too.
    let (ran, after) = std::thread::spawn(move || {
        // SAFETY: unsharing this thread's network namespace touches no memory.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", std::io::Error::last_os_error());
        sh_ok(&setup);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let ran = rt.block_on(run_job(&host, &probe, &cwd, 60));
        let root = sh(&format!(
            "{}\nleft() {{ sed -n 's/^ *sb0: */sb0 /p' /proc/net/dev | awk '{{ print $11 + $13 }}'; }}
before=$(left); timeout 2 bash -c 'exec 3<>/dev/tcp/198.18.0.10/443' 2>/dev/null; [ \"$(left)\" != \"$before\" ] && echo root=sent || echo root=held
echo \"table=$(r nft list table inet superbot_allow)\"
echo \"egress=$(r nft list table inet superbot_egress)\"
echo \"up=$(ip -o link show sb0 | grep -c ',UP')\"",
            R
        ));
        (ran, String::from_utf8_lossy(&root.stdout).into_owned())
    })
    .join()
    .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    // Only the list's own public entry is reached.
    assert_eq!(ran.said("listed"), "sent", "{}", ran.out);
    for k in ["unlisted", "unlisted6", "private", "metadata", "dns", "udp"] {
        assert_eq!(ran.said(k), "refused", "{k}: {}", ran.out);
    }
    // No raw sockets, and no changing the rules, the link or the routes.
    for k in ["raw", "flush", "drop", "link", "route", "netns"] {
        assert_eq!(ran.said(k), "denied", "{k}: {}", ran.out);
    }
    let said = |k: &str| after.split_whitespace().find_map(|w| w.strip_prefix(&format!("{k}="))).unwrap_or_else(|| panic!("{k} in {after}"));
    assert_eq!((said("root"), said("table"), said("egress"), said("up")), ("sent", "read", "read", "1"), "the rules and the link are as they were: {after}");
}

#[tokio::test]
#[ignore = "needs root and cgroup v2 on a throwaway host: SUPERBOT_MACHINE_BOT_USER_TEST=1, as CI's isolation job runs it"]
async fn as_root_red_team_a_run_cant_exhaust_the_machine() {
    if !as_root() {
        return;
    }
    let root = Path::new("/sys/fs/cgroup");
    let subtree = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap();
    for c in ["cpu", "memory", "pids"] {
        if !subtree.split_whitespace().any(|s| s == c) {
            std::fs::write(root.join("cgroup.subtree_control"), format!("+{c}")).unwrap();
        }
    }
    struct Base(PathBuf);
    impl Drop for Base {
        fn drop(&mut self) {
            for d in ["runs", "agent", ""] {
                let p = self.0.join(d);
                for e in std::fs::read_dir(&p).into_iter().flatten().flatten().filter(|e| e.path().is_dir()) {
                    let _ = std::fs::write(e.path().join("cgroup.kill"), "1");
                    std::thread::sleep(Duration::from_millis(100));
                    let _ = std::fs::remove_dir(e.path());
                }
                let _ = std::fs::remove_dir(&p);
            }
        }
    }
    let base = Base(root.join(format!("sbrt-{}", std::process::id())));
    std::fs::create_dir(&base.0).unwrap();
    let cg = Cgroups::setup(&base.0, 1, 1 << 30).unwrap();
    let u = User::new("sbrt-hog");
    let limited = |name: &str, limits: RunLimits| {
        let mut h = u.host();
        h.limits = Some(Limiting::Cgroup(Arc::new(cg.start(name, &limits).unwrap())));
        h
    };
    let roomy = RunLimits { cpu_percent: 100, memory_percent: 40, pids: 256, io_weight: 100 };

    // The agent keeps its own pace while the runs try to take the machine.
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let pace = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        let mut last = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                _ = stop_rx.changed() => break,
            }
            worst = worst.max(last.elapsed());
            last = tokio::time::Instant::now();
        }
        worst
    });

    let bomb = limited("rt-bomb", RunLimits { pids: 64, ..roomy });
    let balloon = limited("rt-balloon", RunLimits { memory_percent: 10, ..roomy });
    let spin = limited("rt-spin", RunLimits { cpu_percent: 10, ..roomy });
    let beside = limited("rt-beside", roomy);
    let escape = limited("rt-escape", roomy);
    let (b, m, s, ok, out) = tokio::join!(
        run_job(&bomb, "b() { b | b & }; b; sleep 30", &u.home, 6),
        run_job(&balloon, "x=$(head -c 400000000 /dev/zero | tr '\\0' a); echo survived", &u.home, 60),
        run_job(&spin, "timeout 3 sh -c 'while :; do :; done'; echo done", &u.home, 60),
        run_job(&beside, "for i in $(seq 20); do sleep 0.1 & done; wait; echo fine", &u.home, 60),
        run_job(
            &escape,
            r#"cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
w() { if sh -c "echo $2 > $1" 2>/dev/null; then echo raised; else echo held; fi; }
echo "memory=$(w $cg/memory.max max)"
echo "pids=$(w $cg/pids.max max)"
echo "cpu=$(w $cg/cpu.max max)"
echo "leave=$(w $cg/../cgroup.procs $$)"
echo "top=$(w /sys/fs/cgroup/cgroup.procs $$)"
echo "child=$(if mkdir $cg/sub 2>/dev/null; then echo raised; else echo held; fi)"
echo "oom=$(w /proc/self/oom_score_adj -1000)"
echo "score=$(cat /proc/self/oom_score_adj)"
"#,
            &u.home,
            60
        ),
    );
    let _ = stop_tx.send(true);
    let worst = pace.await.unwrap();

    let report = |r: &Ran| r.limited.clone().expect("a report on its limits");
    let b = report(&b);
    assert!(b.enforced && b.pids_refused > 0, "the fork bomb ran out of processes: {b:?}");
    let m_r = report(&m);
    assert!(!m.ok && m_r.oom_kills > 0, "the balloon was killed, whole: {m_r:?} {}", m.out);
    assert!(report(&s).cpu_throttled_ms >= 1000, "the spin was held back: {:?}", report(&s));
    assert!(ok.ok && ok.out.contains("fine") && report(&ok).pids_refused == 0, "the run beside finished: {:?} {}", report(&ok), ok.out);
    for k in ["memory", "pids", "cpu", "leave", "top", "child", "oom"] {
        assert_eq!(out.said(k), "held", "{k}: {}", out.out);
    }
    assert_eq!(out.said("score"), "500", "a run is the first to go when memory runs out: {}", out.out);
    assert!(worst < Duration::from_secs(2), "the agent kept its pace: its worst gap was {worst:?}");
}
