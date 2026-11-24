# 0219: npm registry logins for machines' harness installs

## Status

Accepted (24 Nov 2026). Eighth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on harness CLIs on machines ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)), harness installs from mirrors ([ADR 0186](0186-harness-installs-from-internal-mirrors.md)), botd's secrets ([ADR 0010](0010-secrets.md), [ADR 0125](0125-external-secrets-backend-vault.md)) and Hermes from botd's bundle ([ADR 0210](0210-hermes-agent-on-air-gapped-machines.md)).

0219 was reserved for this work.

## Context

ADR 0186 lets users' machines install Node.js and the npm harnesses from the operator's mirrors. Many internal registries (Artifactory, Nexus, GitLab, Verdaccio with `htpasswd`) ask for a login even for reads. ADR 0186 left these out, "through the secrets store", and ADR 0210 listed them as not covered. Until now, such networks had to open an anonymous read path on their registry, or leave the npm harnesses out.

The login is a secret. It must not end up where Bots can read it:

- The plan is saved in the agent's `state.json`, in its tools folder, which Bot users can read and run from ([ADR 0043](0043-bots-own-os-user-on-machines.md)).
- Bot runs on botd's own server must not inherit it from botd's environment.
- botd's logs, its audit log and the mirror check's output must not show it.

## Decision

### Settings: from botd's secrets

One of:

- `MACHINE_NPM_TOKEN`: a registry token, which npm sends as `Bearer` (`_authToken`);
- `MACHINE_NPM_USERNAME` and `MACHINE_NPM_PASSWORD`, which npm sends as `Basic` (`_auth`, base64 of `user:password`).

The token and the password are read through botd's secrets store: the environment, `<NAME>_FILE`, or an external store such as Vault or a cloud secret manager (ADR 0125, ADR 0136). The username is a plain setting. Both secrets are in `SERVER_SECRETS`, so no Bot run inherits them, under either name.

botd won't start, and says why, if:

- a login is set, in the environment, a file or an external store, without `MACHINE_NPM_REGISTRY` (botd sends a login only to the operator's own registry, never npm's) or without `MACHINE_CONTROL_URL`;
- both kinds are set, or a username without a password, or the reverse;
- the token isn't 1 to 4096 letters, digits and `- . _ ~ + / = :`. Registry tokens are. This keeps out newlines, `;` and `#` comments, quotes and `${...}`, which npm's ini parser would read as something else. A password can hold anything but control characters, since it goes in base64.

botd registers each value with its redactor at start.

### The plan only says a login is needed

The plan gains `npmLogin: true` when it names the operator's registry, has npm harnesses, and botd has a login. It never holds the login. Without one, the field is left out, so the plan and its id stay as they were and no machine installs anything again. Rotating the token doesn't change the plan either.

Agents from before this ignore the field and would fail with npm's 401. So agents now say `harness_mirror_login`, and botd sends such a plan only to those. `botctl machine harnesses <user>` says to upgrade first. Agents upgrade from botd itself.

### The agent fetches it for each install

`GET /v1/npm-login` on the machine port answers an enrolled machine with `{registry, token}` or `{registry, auth}`. It checks the machine's certificate as every other machine call does. Each answer is recorded as `machine.npm_login_sent`, with the user, the registry and the login's kind (`token` or `basic`), never the value. Without a login, the route answers 404.

For each npm install, the agent:

1. fetches the login from botd over mutual TLS, and refuses one for a registry other than its plan's, or one with characters outside the set above;
2. writes one line, `//<host>[:port]/<path>/:_authToken=<token>` (or `:_auth=`), to a new file, `npmrc`, readable by root alone (0600), in a folder only root opens (0700) beside its tools folder (`<tools>.login`). Not in the tools folder: the agent opens everything there to Bot users (ADR 0043), whenever it makes or loads the Bots' user, even while npm runs;
3. points npm at it with `npm_config_userconfig`, beside `npm_config_registry` and the CA;
4. takes the login's value out of npm's errors before reporting them;
5. removes that folder when the install ends, failed or not, before the next one, and when the agent starts, so one a restart cut short is gone before anything opens the tools again.

The key is npm's own "nerf dart" for the registry, so npm sends the login to the registry and to tarball URLs under it, and nowhere else. The login is never saved by the agent, and never passed on the command line or in an environment variable a Bot could read.

### `botctl machine mirror` signs in too

`GET /api/machines/harness-mirror` fetches each package document and tarball with the login, as npm would. It sends it only to URLs under the registry, and not across a redirect to another host or port. A 401 or 403 from the registry says to check `MACHINE_NPM_TOKEN` or the username and password. A 401 with no login set says the registry wants one. Its output names the login's kind (`npmLogin`), never its value.

### Considered

- **The login in the plan.** Simplest, but the plan is saved in a folder Bot users read, and it would change the plan's id on each rotation.
- **npm's environment config (`npm_config_//host/:_authToken`).** npm turns `_` into `-` in environment keys, so `_authToken` doesn't survive. And it would sit in the install's environment.
- **A file on the machine the operator provisions.** That is one more thing to put on every machine and rotate there. botd already has the secrets store and an authenticated channel to every machine.
- **Sending the login with the plan, over the heartbeat.** Plans are sent once and persisted, while the login is fetched only when npm runs and lives only as long as the install.
- **Any registry, not just MACHINE_NPM_REGISTRY.** botd would then hand its login to whatever registry a plan named. A login is for the operator's own registry only.

## Consequences

- An air-gapped network's machines install the npm harnesses from a registry that asks for a login, with the login kept in botd's secrets and rotated there.
- Rotating the login needs a botd restart, as other settings do, but no new plan and no reinstall.
- Each machine install fetches the login once and records it in the audit log.
- A machine whose agent is older fails nothing new: botd doesn't send it the plan until it is upgraded.
- Tested:
  - `mirror`: the settings' forms, the token trimmed, `_FILE`, a password with any characters, the refusals above, redaction and the masked `Debug`; the plan flag and its id; the check signing in only under the registry and not across a redirect, its hints for a missing or wrong login.
  - `tools`: the nerf dart, the `.npmrc` line and the characters it allows, refusing a login for another registry, scrubbing npm's errors, and the agent writing the file 0600 in a 0700 folder outside its tools, which stays so when the tools are opened mid-install, removing it after and at start, and never saving it.
  - Upkeep: only agents that say `harness_mirror_login` are sent the plan, and nothing changes without a login. Enrollment: the settings need `MACHINE_CONTROL_URL`. Adapters: no Bot run inherits the secrets.
  - End to end on loopback: botd with a token and a registry that wants it. The check passes, a caller without a machine certificate is refused, the real agent fetches the login over mutual TLS and npm gets a 0600 userconfig, in a 0700 folder outside the tools, with only the registry's line, and the audit log records the kind but never the token.
  - With the real npm: installs from a registry that wants a login, as a token and as a username and password, for the package document and every tarball, and a wrong login fails without showing it. CI runs this with no network.
- Not covered:
  - A login for `MACHINE_NODE_MIRROR`. Node.js tarballs are usually on a plain web server, and the agent's own downloads don't sign in.
  - Per-machine or per-team logins: every machine gets the same one.
  - Logins that expire within a botd run, such as short-lived OIDC tokens. botd reads the login at start.
