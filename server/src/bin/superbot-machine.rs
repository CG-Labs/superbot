//! superbot-machine: the agent on each user's machine (ADR 0031). It enrolls with the
//! control plane using a one-time token, then answers botd over mutual TLS.
//!
//!   superbot-machine run      enroll if needed, then serve (systemd runs this)
//!   superbot-machine enroll   enroll now and exit (a token from an admin, by hand)
//!   superbot-machine status   ask the control plane how it sees this machine
//!
//! Settings come from the environment; see `machines/agent.rs`.

#[path = "../machines/agent.rs"]
mod agent;
#[path = "../machines/job.rs"]
mod job;
#[path = "../machines/pki.rs"]
mod pki;
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
