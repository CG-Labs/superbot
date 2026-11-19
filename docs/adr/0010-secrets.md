# 0010: Secrets: env first, sealed SQLite, and redaction

## Status

Accepted

## Context

M1 asks for "secrets via env/Vault interface (not plaintext in SQLite)". An audit of where secrets actually lived before this change:

| Secret | Where | Plaintext? |
|---|---|---|
| `AUTH_PASSWORD` | `.env` (0600), process env; installer copy in `~/.superbot-admin-password` (0600) | Yes, on disk, owner-only. Stripped from harness env. |
| Bots' `BOT_TOKEN` | Memory only, random per start | Never on disk. Visible to Bots by design. |
| Screen (voxl) tokens | Memory only, random per screen | Never on disk. Returned to the signed-in person by `/api/bots/:id/screen`. |
| Harness logins (Claude, Codex) | The harness's own files in the service user's home | Yes; owned by the harness CLIs, not botd. |
| API keys (`ANTHROPIC_API_KEY`, ...) | `.env`, inherited by harnesses | Yes, owner-only. |
| SQLite `approvals.input` | Full tool input of every risky call, e.g. a file write's content | **Yes, in the database and every backup.** |
| SQLite `messages`, `approvals.subject`, `audit_events.detail` | Chat text, commands, policy changes | Anything a Bot echoed, including keys. |

SQLite had no secret columns, but the approval queue stored raw tool input, which often holds credentials (a `.env` write, a `curl -H "Authorization: ..."`). Backups copy `DATA_DIR`, so that data left the machine with every backup. There was also no supported way to give Bots an API key except editing `.env` and restarting.

## Decision

**A small `SecretStore` trait, an env provider by default, an encrypted SQLite provider for saved secrets and sensitive fields, and value-based redaction.** Code lives in `server/src/secrets/`.

- **Trait** (`SecretStore`: `get`, `names`, `put`, `delete`, `writable`). The `Secrets` facade asks stores in order; the first hit wins. Writes go to the first writable store. Today the order is env, then sealed.
- **`EnvStore`** (default, read-only): `NAME`, or `NAME_FILE` naming a file (Docker/Kubernetes secrets, systemd credentials). Setting both is an error. Works unchanged with the installer's `.env` and Compose `env_file`. `AUTH_PASSWORD` is read through it, so `AUTH_PASSWORD_FILE` now works too; the login flow is otherwise unchanged.
- **`SealedStore`**: a `secrets` table (`name`, `value`, timestamps). Values are sealed with **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`): random 24-byte nonce per write, format `sb1:` + base64(nonce ‖ ciphertext ‖ tag). The associated data names the slot (`superbot/secrets/<NAME>`, `superbot/approvals.input/<id>`), so a ciphertext copied to another row fails to open. Operators save secrets with `botctl secret set NAME < file` or `PUT /api/secrets/{name}`; values never come back out of the API (`GET /api/secrets` lists names, the store, and whether env shadows it). Bots get stored secrets as environment variables at the start of each run; env wins on conflict. Names are environment-variable shaped; `PATH`, `HOME`, `AUTH_PASSWORD`, `SUPERBOT_*`, `BOT_*`, `LD_*`, and similar are reserved.
- **Sealed fields**: `approvals.input` is sealed under the same key. Reading an approval opens it; one that won't open reads as `{"sealed":"unreadable"}` rather than failing the list.
- **Redaction** (`redact.rs`): botd registers every value it knows (sealed and env secrets that look generated, `AUTH_PASSWORD`, the Bots' token, screen tokens, the master key in hex and base64). Registered values become `[redacted]` in saved chat text and choice cards, approval subjects and inputs (before sealing), audit details (on write and on read, since `audit_events` is append-only), and every SSE event. Env values found only by name (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, ...) are registered only when they look generated (12+ characters, a digit, no spaces, not a path), so a setting like `KEYBOARD=standard` can't erase a word from chats. This complements pattern-based scrubbing of audit events (PR #8): patterns catch secrets botd was never told about; value matching catches the ones it was.
- **Trait seam for M5**: Vault, Azure Key Vault, or GCP Secret Manager is one more `SecretStore` in the list (read-only or writable). Nothing else changes.

### Key management

- **Source**, in order: `SUPERBOT_MASTER_KEY` (64 hex chars or base64 of 32 bytes), else the file in `SUPERBOT_MASTER_KEY_FILE`, else `$XDG_CONFIG_HOME/superbot/master.key` (`~/.config/superbot/master.key`). Both variables set is an error. A key file must not be readable or writable by group or others; botd refuses it otherwise.
- **Never in `DATA_DIR`**: the key sits in the service user's config folder (installer) or `deploy/docker/.env` on the host (Compose), so a database backup alone can't be decrypted.
- **Creation**: the VPS installer creates the key as the service user (0600, folder 0700, `mv -n` so it never replaces one) after writing `.env` and before (re)starting botd, on fresh installs and `--upgrade`. Compose's `init.sh` writes a random key into `.env` once, and Compose refuses to start without it. If neither ran, botd creates the default key file itself on first start, but only when the database holds nothing sealed.
- **Checks at start**: a sealed known value in `settings` (`secrets_key_check`) tells a wrong key from a right one. Missing key with sealed data, wrong key, loose file permissions, or both variables set: botd prints why and exits before serving anything. It never generates a key over existing sealed data. The installer refuses the same case before botd starts.
- **Lost key**: start once with `SUPERBOT_FORGET_SEALED=1`. Only values the current key can't open are dropped (saved secrets deleted, approval inputs replaced by a marker); the rest of the database stays. With a working key the flag does nothing, so leaving it set is harmless.
- **Rotation**: not built yet (follow-up): re-seal every row under a new key in one transaction, keeping the old key until it commits.

### Migration (upgrade from earlier versions)

On every start, after `Db::open` and before serving: plaintext `approvals.input` rows (anything without the `sb1:` prefix) are redacted and sealed under their own ids, in one transaction. Already-sealed rows are skipped, so it is idempotent and safe to interrupt; nothing is deleted. Saved chat text, choice cards, and approval subjects are scrubbed of registered values with `replace()` (also idempotent). The `secrets` table is created with `CREATE TABLE IF NOT EXISTS` by the secrets module, not by `MIGRATIONS`, because sealing needs the key, which `Db::open` doesn't have. Forward-only: an older botd can't read sealed inputs (approval history would show the ciphertext string), so downgrade means restoring a pre-upgrade backup.

## Threat model

Protects against:
- **Database or backup exfiltration** (a copied `app.sqlite`, a leaked backup archive, a lost disk image of `DATA_DIR`): saved secrets and approval inputs are ciphertext; the key isn't there.
- **Tampering or row swapping** in the database: AEAD with per-slot associated data; anything altered fails to open.
- **Accidental disclosure**: values never returned by the API, not printed by `Debug`, redacted from events, chat history, and audit details; `botctl secret set` reads the value from stdin so it stays out of shell history and `ps`.
- **Bots approving their own actions or reading the key from env**: `AUTH_PASSWORD(_FILE)`, `SUPERBOT_PASSWORD`, and `SUPERBOT_MASTER_KEY(_FILE)` are removed from harness and screen process environments; Bots can't list or set secrets (the API refuses the Bot token).

Does not protect against:
- **Code running as the service user**. Bots run as the same OS user as botd ([ADR 0007](0007-approvals.md)), so a determined Bot can read the key file and the database, and it receives stored secrets in its environment by design. Separate OS users per harness, or a broker that hands out short-lived credentials, are the fix (M5 sandboxing, M5 vault).
- **Root on the host**, memory dumps of botd, or a compromised harness CLI.
- **Secrets botd was never told about** and that don't match PR #8's patterns: redaction is exact-value matching.
- **Split streaming**: a secret split across two streamed text deltas can reach a live client unredacted; the saved message is redacted.

## Alternatives considered

- **SQLCipher (whole-database encryption)**: protects everything, but needs a C dependency and a custom SQLite build, complicates the `sqlite3 .backup` scripts and the installer, and gives no protection from code running as the service user either. Field-level sealing covers the sensitive data with a pure-Rust crate.
- **AES-256-GCM**: equally fine with a nonce counter; XChaCha20's 192-bit nonce makes random nonces safe without any state, and it is fast without AES-NI.
- **Key in `DATA_DIR`**: simplest, but every backup would carry the key next to the data it protects.
- **Derive the key from `AUTH_PASSWORD`**: rotating the login password would then need a re-seal, and a weak password weakens the key.
- **Vault/KMS now**: needs a service most self-hosters don't run. The trait keeps the door open (M5).

## Consequences

- Operators must keep the master key and back it up separately from database backups; losing it loses saved secrets and approval inputs (only).
- Upgrades seal old approval inputs automatically; a downgrade needs a pre-upgrade backup.
- Compose users upgrading from an earlier release run `./init.sh` once to add `SUPERBOT_MASTER_KEY`; Compose says so if they don't.
- New API surface: `GET /api/secrets`, `PUT|DELETE /api/secrets/{name}`; `botctl secrets`, `secret set`, `secret rm`. `secret.set` and `secret.deleted` audit events carry the name only.
