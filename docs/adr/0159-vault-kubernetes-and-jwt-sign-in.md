# 0159: Vault's Kubernetes and JWT sign-in, and a namespace for logins

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Adds `Auth` cases to the HashiCorp Vault provider ([ADR 0125](0125-external-secrets-backend-vault.md)), which left "Kubernetes, JWT and cloud IAM sign-in" to follow. Nothing else about the external store changes ([ADR 0136](0136-cloud-secret-managers.md), [ADR 0146](0146-aws-secrets-manager.md)).

Numbered 0159 because 0147, 0152, 0156 and 0157 are held by open PRs and 0158 is reserved.

## Context

botd signs in to Vault with a token or AppRole (ADR 0125). Both mean a long-lived credential on botd's disk: a token kept fresh by Vault Agent, or a SecretID someone has to deliver and rotate. Enterprises running botd on Kubernetes don't want either. Their Vault already trusts the cluster: Vault's `kubernetes` auth method checks a pod's service account token with the cluster's TokenReview API. Teams off Kubernetes, or with several clusters, use Vault's `jwt` method instead: Vault checks the token's signature against an issuer it trusts (a cluster's OIDC issuer, GitHub Actions, SPIFFE, a cloud's workload identity). Either way, the platform proves who botd is, and no secret is handed over.

On Vault Enterprise and HCP Vault, auth methods are often mounted in a parent namespace (`admin`), while each team's secrets are in a child (`admin/team-a`). botd sent every request, logins included, to `VAULT_NAMESPACE`, so it couldn't log in through a method mounted in another namespace.

The roadmap listed "Vault's Kubernetes and JWT sign-in" as remaining on #55. The other candidates were left for later: the setup report and `botctl secrets backend` already say which backend botd uses, how it signs in, and whether it answers (ADR 0136); per-secret version pinning would make rotations a config change, which ADR 0125's cache was chosen to avoid.

## Options

1. **Leave it to Vault Agent**: a sidecar logs in with Kubernetes auth and writes a token to a file, which `VAULT_TOKEN_FILE` already reads. This works today and stays supported. But it is one more container to run, patch and watch, and botd only learns its token is bad when Vault refuses it.
2. **A Vault client library** (`vaultrs`). More dependencies for two POST requests; ADR 0125 already talks to Vault over `reqwest`.
3. **Two more `Auth` cases in botd's own client.** Both methods take the same login, `POST auth/<mount>/login` with `{"role", "jwt"}`, and return a token with a lease, the same reply as AppRole. Chosen.

## Decision

### Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `VAULT_AUTH` | `token` | Now also `kubernetes` or `jwt` |
| `VAULT_KUBERNETES_ROLE` | (required) | The Vault role botd logs in as |
| `VAULT_KUBERNETES_MOUNT` | `kubernetes` | Where the method is mounted |
| `VAULT_KUBERNETES_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | The service account token, or a projected one with Vault's audience |
| `VAULT_JWT_ROLE` | the mount's `default_role` | The Vault role botd logs in as |
| `VAULT_JWT_MOUNT` | `jwt` | Where the method is mounted |
| `VAULT_JWT_FILE` | (required) | The file the platform writes the JWT to |
| `VAULT_AUTH_NAMESPACE` | `VAULT_NAMESPACE` | The namespace logins are sent to; `root` (or `/`) for none. For AppRole too. |

Role names are letters, digits, `.`, `_`, `-` and `@`; mounts and namespaces are Vault paths, as before. Everything is checked when botd starts, and both folders are listed, so botd doesn't start on a role, file or namespace Vault won't accept. `VAULT_AUTH_NAMESPACE` with `VAULT_AUTH=token` is an error: a token needs no login.

### Logging in

The JWT is read from its file **at each login**, never kept: the kubelet rotates projected tokens (hourly by default), and so do other platforms. botd logs in when it starts, again two thirds of the way through the Vault token's lease, and again whenever Vault refuses the token. That is the same as AppRole, and the same code.

Before a JWT is sent, botd checks that the file holds one (three base64url parts, with JSON claims) and that its `exp` hasn't passed. A wrong path (a CA file, an empty file), or a token the platform stopped renewing, then fails with the setting's name and the file's path, without asking Vault. Errors never quote the file, and Vault's replies are reported by status only, as for AppRole: Vault's error text can echo what was sent.

Logins are sent to `VAULT_AUTH_NAMESPACE` if it is set, or else to `VAULT_NAMESPACE`. Reads stay in `VAULT_NAMESPACE`. A token from a parent namespace can read a child's secrets if its policy allows, which is how HCP Vault's `admin` namespace is meant to be used.

### Audit and redaction

Logins are still `secret.vault_login` (actor `system` / `secrets`, target the mount). The details are `method` (`approle`, `kubernetes` or `jwt`), `role` for Kubernetes and JWT (not for AppRole, whose RoleID is a credential), `namespace` when the login carried one, and `error`'s kind on failure. Never the JWT or the Vault token. Reads are audited as before (`secret.read`). Neither the JWT nor Vault's token is registered with the redactor, as with AppRole and Azure's federated token: they never enter botd's environment, and Bots don't get them (below).

### Keeping the JWT from Bots

`VAULT_JWT_FILE` and `VAULT_KUBERNETES_TOKEN_FILE` are removed from every harness, screen and job botd starts. `VAULT_JWT` and `VAULT_KUBERNETES_TOKEN` are reserved names, because botd offers `NAME_FILE` to Bots as `NAME`, read from the file. They can't be saved as Bot secrets and aren't listed or handed out.

## Consequences

- No change unless `VAULT_AUTH` is `kubernetes` or `jwt`, or `VAULT_AUTH_NAMESPACE` is set. Token and AppRole sign-in work as before; AppRole's audit details gain `namespace` when one is used.
- On Kubernetes, botd needs no Vault credential at all: the role binds to its service account and namespace, and rotation is the platform's job.
- Threat model: the token file is as strong as the pod's isolation. Bots running locally as botd's own user could read the default service account token. Use a projected token with Vault's audience, readable only by botd, and run Bots as locked-down run users ([ADR 0145](0145-locked-down-run-users-and-red-team.md)) or on their own machines. Give the role a policy that reads only `<prefix>/*`, as ADR 0125 says, and bind it to botd's service account and namespace only.
- Tested against the stand-in Vault in `server/src/secrets/vault.rs`: Kubernetes login, the token file read again after a rotation, the JWT method's default role, logins in another namespace or the root one, files that can't be used failing before anything is sent, and settings. `server/src/vault_auth_http_tests.rs` checks, on the real router, that admins see the logins and reads in the audit log, with no JWT, token or value, and that members can't. No cluster, Vault or network.
- Remaining on #55: per-user secrets in the external store, and short-lived (dynamic) credentials handed to each run.
- Ops guide: [docs/ops/vault.md](../ops/vault.md#kubernetes-and-jwt-sign-in).
