//! superbot-machine: the agent on each user's machine (ADR 0031). It enrolls with the
//! control plane using a one-time token, then answers botd over mutual TLS.
//!
//!   superbot-machine run      enroll if needed, then serve (systemd runs this)
//!   superbot-machine enroll   enroll now and exit (a token from an admin, by hand)
//!   superbot-machine status   ask the control plane how it sees this machine
//!
//! `run` returns after an upgrade (ADR 0039) so systemd starts the new binary.
//!
//! Settings come from the environment; see `machines/agent.rs`.

#[path = "../machines/agent.rs"]
mod agent;
#[path = "../machines/cgroup.rs"]
mod cgroup;
#[path = "../machines/display.rs"]
mod display;
#[path = "../machines/egress_allow.rs"]
mod egress_allow;
#[path = "../machines/job.rs"]
mod job;
#[path = "../machines/landing.rs"]
mod landing;
#[path = "../machines/pki.rs"]
mod pki;
#[path = "../sandbox.rs"]
#[allow(dead_code)]
mod sandbox;
#[path = "../machines/runas.rs"]
mod runas;
#[path = "../machines/teammates.rs"]
mod teammates;
#[path = "../machines/terminal.rs"]
mod terminal;
#[path = "../machines/tools.rs"]
mod tools;
#[path = "../machines/upgrade.rs"]
mod upgrade;
#[path = "../sweep.rs"]
mod sweep;
#[path = "../walk.rs"]
mod walk;
#[path = "../machines/wire.rs"]
mod wire;

fn fail(msg: &str) -> ! {
    eprintln!("superbot-machine: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if matches!(cmd.as_str(), "-V" | "--version" | "version") {
        println!("superbot-machine {}", agent::VERSION);
        return;
    }
    if !matches!(cmd.as_str(), "run" | "enroll" | "status") {
        eprintln!("usage: superbot-machine run | enroll | status | --version");
        std::process::exit(2);
    }
    let cfg = agent::Config::from_env().unwrap_or_else(|e| fail(&e));
    match cmd.as_str() {
        "enroll" => match agent::enroll(&cfg).await {
            Ok(id) => println!(
                "Enrolled machine {}; certificate {} saved in {}.",
                id.machine_id,
                &id.fingerprint[..16],
                cfg.state_dir.display()
            ),
            Err(f) => fail(&f.message),
        },
        "status" => {
            let id = agent::load(&cfg).unwrap_or_else(|| fail("not enrolled"));
            match agent::status(&cfg, &id).await {
                Ok(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default()),
                Err(f) => fail(&f.message),
            }
        }
        _ => agent::run(cfg).await.unwrap_or_else(|e| fail(&e)),
    }
}
