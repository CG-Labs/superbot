# Architecture

SuperBot gives each person AI teammates ("Bots") that work on a computer. SuperBot does not have its own agent loop: each Bot runs an existing agent CLI (a "harness"), and SuperBot decides who may run what, where, and with which approvals.

Part of the [security pack](README.md). Data stored by each part: [data flows](data-flows.md).

## Components

| Component | What it is | Where it runs |
|-----------|-----------|---------------|
| **botd** | The server (Rust, one binary). Users, sign-in, Bots, chats, routines, approvals, policy, secrets, audit log, billing, and, when on, the control plane for managed machines. Stores its data in SQLite. | The operator's server. |
| **Caddy** | Reverse proxy. Terminates HTTPS, serves the web client at `/app/` and the landing page, and forwards everything else to botd on port 3000, which is never public ([ADR 0013](../adr/0013-serve-web-client.md)). With the systemd install, botd listens only on `127.0.0.1:3000`. With Docker Compose, botd listens on `0.0.0.0:3000` inside its container; that port is not published to the host, and the only other container on its network is Caddy ([ADR 0006](../adr/0006-docker-compose.md), [`docker-compose.yml`](../../deploy/docker/docker-compose.yml)). | Same server, in front of botd ([`deploy/install.sh`](../../deploy/install.sh), [`deploy/docker/`](../../deploy/docker/)). |
| **Client app** | Expo app for iOS, Android, web and desktop (Electron). Chat, approvals, Bot screens, settings, admin views. Talks to botd only, over HTTPS (REST plus server-sent events) ([ADR 0004](../adr/0004-client-expo.md), [ADR 0027](../adr/0027-expo-primary-hermes-default.md)). | The person's device. |
| **Admin console** | A minimal admin page served by botd at `/console/`, for admins only ([ADR 0032](../adr/0032-console-admin-only.md)). | Browser. |
| **Harnesses** | The agent CLIs a Bot runs: Claude Code, Codex, Pi and Hermes Agent. One adapter each in botd ([`server/src/adapters/`](../../server/src/adapters/)); nothing else in SuperBot knows which harness runs. Hermes Agent is the default on managed plans ([ADR 0079](../adr/0079-hermes-default-for-managed-tiers.md)). | Wherever the Bot's owner's runs go: the botd server, or the owner's machine. |
| **botctl** | CLI for operators and for Bots (routines, ask, handoff, approval checks). Talks to botd's API. | The server, and each machine. |
| **superbot-run** | Small helper that starts a harness as the user's own Unix account on the server ([ADR 0037](../adr/0037-per-user-unix-accounts.md), [ADR 0058](../adr/0058-harness-os-user-by-default.md)). | The botd server. |
| **Machine agent** (`superbot-machine`) | Runs on each user's managed machine. Enrolls once, then takes jobs from botd over mutual TLS: run a harness, install or upgrade harnesses, harness logins, folder copy, screens, teammates' OS users ([ADR 0031](../adr/0031-machine-enrollment-mtls.md), [ADR 0036](../adr/0036-bots-on-the-users-machine.md)). | Each user's machine. |
| **Screens** | A Bot's own Linux desktop: Xvfb, Openbox, Chromium and the voxl viewer, which needs a per-Bot token ([ADR 0003](../adr/0003-computer.md), [ADR 0008](../adr/0008-client-screen-auth.md), [ADR 0045](../adr/0045-screens-on-machines.md)). The viewer listens on loopback, except under Docker Compose, where it listens on the unpublished container network so Caddy can reach it (`SCREEN_ADDR=0.0.0.0`). Screens on the server are off while per-user accounts are on ([ADR 0084](../adr/0084-published-image-with-computer-use.md)). | The botd server, or the owner's machine (`MACHINE_SCREENS=on`, which needs `MACHINE_BOT_USER=on`). |
| **Per-user machines** | One computer per user: a Linode VM ([ADR 0025](../adr/0025-control-plane-linode.md)) or an unprivileged Incus system container ([ADR 0065](../adr/0065-incus-container-machines.md)), placed across several Incus hosts by load ([ADR 0081](../adr/0081-placing-machines-by-host-load.md)). | The operator's Linode account, or the operator's Incus hosts. |
| **superbot-license** | Offline tool that signs self-host licence keys ([ADR 0038](../adr/0038-self-host-license-key.md)). | CG-Labs only. Never on a customer server. |

## Deployment modes

### One server (self-host)

Everything runs on one Linux server, installed with [`deploy/install.sh`](../../deploy/install.sh) (systemd) or [Docker Compose](../../deploy/docker/). Each user's Bots run as that user's own Unix account (`sb-u-<user id>`), which can't read botd's files, the database or the master key ([ADR 0058](../adr/0058-harness-os-user-by-default.md); on by default for new installs, both systemd and Compose).

Compose pulls published images (`ghcr.io/cg-labs/superbot` and `ghcr.io/cg-labs/superbot-caddy`, amd64 and arm64), or builds them from the checkout. CI builds the published images from this repository and smoke-tests them on both architectures before pushing them. CI scans each image for known vulnerabilities, signs each published image keylessly with cosign and attaches signed build provenance and an SBOM, which operators can verify ([ADR 0101](../adr/0101-image-scanning-and-signing.md), [verifying the images](../../deploy/README.md#verifying-the-images)). Containers drop all Linux capabilities except the few each needs (botd: those that start per-user runs; Caddy: binding ports 80 and 443), and sudo is the image's only setuid program. Chromium's own sandbox is off inside the container, because Docker's seccomp profile blocks it; a run's browser can do no more than the run itself ([ADR 0084](../adr/0084-published-image-with-computer-use.md)).

```mermaid
flowchart LR
  subgraph Device["Person's device"]
    App["Client app<br/>iOS / Android / web / desktop"]
  end
  subgraph Server["Operator's server"]
    Caddy["Caddy<br/>HTTPS :443"]
    Botd["botd :3000<br/>not public"]
    DB[("SQLite<br/>DATA_DIR")]
    WS[("Workspace<br/>WORKSPACE_DIR/users/&lt;id&gt;")]
    H["Harness processes<br/>as sb-u-&lt;user id&gt;"]
    Scr["Screens<br/>Xvfb + voxl, token per Bot"]
  end
  Model["Model provider"]
  App -- "HTTPS: REST + SSE" --> Caddy --> Botd
  Botd --> DB
  Botd -- "starts, per run" --> H
  H --> WS
  H -- "approval checks, botctl" --> Botd
  H -- "HTTPS (operator-set URL)" --> Model
  Caddy -- "/screen/…?token" --> Scr
```

### Managed (control plane and one machine per user)

The same botd, with the control plane turned on (`LINODE_TOKEN`, or `MACHINE_PROVIDER=incus`; off by default). botd creates one machine per user, and with `MACHINE_ROUTING` on, each Bot runs on its **owner's** machine and nowhere else. A run that can't go there is refused, never run on the server instead ([ADR 0036](../adr/0036-bots-on-the-users-machine.md)).

```mermaid
flowchart LR
  subgraph Device["Person's device"]
    App["Client app"]
  end
  subgraph CP["Control plane (operator)"]
    Caddy["Caddy HTTPS"]
    Botd["botd"]
    DB[("SQLite: org data")]
    MPort["Machine port<br/>MACHINE_CONTROL_URL<br/>mTLS"]
  end
  subgraph MA["Ada's machine (Linode VM or Incus container)"]
    AgentA["superbot-machine<br/>:7443 mTLS"]
    HA["Harness runs<br/>as superbot-bots<br/>(MACHINE_BOT_USER=on)"]
    DA[("Work folder, Bot memory,<br/>harness logins")]
    SA["Screens"]
  end
  subgraph MB["Bea's machine"]
    AgentB["superbot-machine"]
  end
  Prov["Linode API / Incus API"]
  Model["Model provider"]
  App -- "HTTPS" --> Caddy --> Botd --> DB
  Botd -- "create / suspend / destroy" --> Prov
  Botd -- "jobs, heartbeats, screens<br/>(botd dials the agent)" --> AgentA
  AgentA -- "enroll, certificate rotation" --> MPort
  HA -- "Bot API calls with its run token" --> MPort
  AgentA --> HA --> DA
  HA -- "HTTPS (operator-set URL)" --> Model
  AgentA --> SA
  Botd --> AgentB
```

Key points:

- **The control plane decides; the machine does.** Who may see or run a Bot, approvals, policy, secrets, billing and the audit log stay in botd. A compromised machine can harm only its own user ([ADR 0029](../adr/0029-per-user-isolation.md)).
- **botd dials the agent.** Jobs, heartbeats, logins and screens go from botd to the agent's port (default 7443). The agent calls botd only to enroll, to rotate its certificate, and to relay a running Bot's own API calls.
- **Runs as an unprivileged user, once turned on.** `MACHINE_BOT_USER` is off by default. With it on, the agent (which stays root) runs every harness as the unprivileged `superbot-bots` user. Without it, Bots run as root, like the agent, and can read the agent's key ([ADR 0043](../adr/0043-bots-own-os-user-on-machines.md)). `MACHINE_TEAMMATE_USERS` (off by default; needs `MACHINE_BOT_USER=on`) runs a teammate's runs of a shared Bot as that teammate's own OS user. Without it, those runs share the owner's Bots' user and home, so their tools can read the owner's folder and harness logins ([ADR 0048](../adr/0048-teammates-own-os-user-on-machines.md)). Screens need `MACHINE_BOT_USER=on`.
- **No harness code on the agent.** botd's adapters build each run's command and send it as data; the agent runs it ([ADR 0036](../adr/0036-bots-on-the-users-machine.md)).

## Trust boundaries

```mermaid
flowchart TB
  subgraph Internet
    Dev["People's devices"]
    Ext["Model providers, Stripe, Expo push,<br/>IdPs, SMTP, webhooks"]
  end
  subgraph TB1["Boundary 1: the operator's server"]
    Botd["botd + SQLite + master key"]
  end
  subgraph TB2["Boundary 2: one user's Unix account or machine"]
    Run["Harness run with a per-run token"]
  end
  subgraph TB3["Boundary 3: another user's account or machine"]
    Run2["Their runs"]
  end
  Dev -- "HTTPS, session or SSO" --> Botd
  Botd -- "mTLS (machines) or sudo superbot-run (one server)" --> Run
  Botd --> Run2
  Run -.-|no access| Run2
  Run -- "API, own run token only" --> Botd
  Botd -- "HTTPS, outbound" --> Ext
  Run -- "HTTPS, outbound" --> Ext
```

| Boundary | What crosses it | How it is guarded |
|----------|-----------------|-------------------|
| Device to server | People's requests | HTTPS at Caddy; session cookie (`__Host-`, HttpOnly, Secure, SameSite=Strict) or bearer token; same-origin check on writes; sign-in rate limit; roles and Bot permissions on every route ([access control](access-control.md)). |
| Server to a run | A run's command, environment and secrets | One server: the run is the user's own Unix account, started through `sudo superbot-run`. Machines: mutual TLS with pinned certificates from botd's own CA. |
| A run back to the server | A Bot's API calls (botctl, approval checks) | A token for that run only, revoked when the run ends; a Bot can do no more than its owner ([ADR 0083](../adr/0083-per-run-tokens.md)). |
| User to user | Nothing | Separate folders, Unix accounts or machines; ACL checks in botd; isolation tests in CI ([`deploy/test-isolation.sh`](../../deploy/test-isolation.sh)). |
| Machine to network | Inbound and outbound traffic | Linode: only with `MACHINE_FIREWALL=on` (off by default), a Cloud Firewall drops all inbound except botd to the agent port (SSH only if the operator lists sources). Without it, a new Linode is open to the internet (SSH, the agent port, anything listening); the agent port still requires mutual TLS ([ADR 0035](../adr/0035-machine-firewall-auto-enroll.md)). Incus: botd refuses to start without `MACHINE_FIREWALL=on`, and containers can't reach each other, the host, or private and link-local ranges ([ADR 0065](../adr/0065-incus-container-machines.md)). |
| Server to outside services | API calls | HTTPS with certificate checks; each service is off until its setting is set ([subprocessors](subprocessors.md)). |

## Planned

- Per-user cgroup and egress limits for harness runs, and per-user egress allowlists (M5, [roadmap](../ROADMAP.md)).
- Native SAML without a broker (M5, [ADR 0020](../adr/0020-saml-bridge.md)).
- A tamper-evident (hash-chained) audit log (M5, [ADR 0009](../adr/0009-audit-events.md)).
- A read-only root filesystem for the containers ([ADR 0084](../adr/0084-published-image-with-computer-use.md)).
