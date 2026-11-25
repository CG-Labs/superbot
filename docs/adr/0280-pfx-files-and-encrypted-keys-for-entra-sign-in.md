# 0280: botd reads PFX files and encrypted keys for Entra certificate sign-in

## Status

Accepted (25 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Extends the certificate sign-in of [ADR 0269](0269-azure-certificate-credentials.md), which Azure Key Vault ([ADR 0136](0136-cloud-secret-managers.md)), Vault's `azure` sign-in ([ADR 0260](0260-vault-cloud-sign-in.md)) and the Azure Monitor audit sink ([ADR 0217](0217-audit-export-to-azure-monitor.md)) share. ADR 0269 left "PFX files and encrypted keys" for later.

Numbered 0280 because it is the number reserved for this slice; 0277 to 0279 and 0281 are held by parallel work.

## Context

ADR 0269 says a file and settings that work with the Azure SDKs work with botd. That held only for PEM files with an unencrypted key. The SDKs' `AZURE_CLIENT_CERTIFICATE_PATH` also takes a PFX (PKCS#12) file, opened with `AZURE_CLIENT_CERTIFICATE_PASSWORD`, and botd refused that setting at startup. PFX is how most enterprises get these certificates:

- Windows certificate stores and AD Certificate Services export PFX files.
- Key Vault-issued certificates download as PFX files.
- Many corporate CAs and PKI portals issue only PFX files.

Converting with `openssl pkcs12 -nodes` works, but it leaves an unencrypted key on disk. Some security policies forbid that. ADR 0269 argued that a password next to the file protects nothing the file's mode doesn't. That's true when both sit in one directory. It's not true when the password is delivered apart from the file: a systemd credential, a Kubernetes secret mounted on its own, or a secrets manager. Then a copy of the certificate file alone (from a backup, an image layer or a misplaced `scp`) can't sign in.

## Options

1. **Keep refusing them.** Operators keep converting. The SDK compatibility claim stays false, and policies that forbid unencrypted keys can't use certificates.
2. **OpenSSL through the `openssl` crate.** OpenSSL is already in the build for SQLCipher. But it would be a second crypto stack for one file format. OpenSSL 3 also needs its legacy provider loaded at runtime for RC2, which many existing PFX files use for their certificates.
3. **Pure-Rust parsers: `p12-keystore` for PKCS#12 and `pkcs8` (RustCrypto) for encrypted PKCS#8.** Chosen. Both decode in memory with no system libraries. `p12-keystore` already uses the `x509-parser` and `sha2` versions botd uses. The key still goes to `aws-lc-rs` for signing, as before.

## Decision

### Configuration

| Setting | Meaning |
|---------|---------|
| `AZURE_CLIENT_CERTIFICATE_PATH` | A PEM file as before, or a PFX file. botd tells them apart by content: a text file with PEM blocks is PEM, and a DER file is PFX |
| `AZURE_CLIENT_CERTIFICATE_PASSWORD` or `AZURE_CLIENT_CERTIFICATE_PASSWORD_FILE` | The password that opens the PFX file, or the PEM file's `ENCRYPTED PRIVATE KEY`. Read through botd's secret stores like `AZURE_CLIENT_SECRET`, so `_FILE` works |

The names are the Azure SDKs'. `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN` is still refused, as ADR 0269 decided.

### Reading the file

- **PFX.** The MAC is checked, with SHA-1 or SHA-2 HMACs. Bags are opened with PBES2 (PBKDF2 and AES, OpenSSL 3's default and Windows' `AES256-SHA256`) or the older PKCS#12 schemes (3DES, RC2-40). Keys may sit in shrouded or plain key bags. With no password set, botd uses the empty password, as `openssl pkcs12 -passout pass:` writes it.
- **Encrypted PEM keys.** PKCS#8 `ENCRYPTED PRIVATE KEY` with PBES2 (PBKDF2 or scrypt, AES-CBC or AES-GCM), as `openssl pkcs8 -topk8 -v2` writes it. Legacy `Proc-Type: 4,ENCRYPTED` keys and PBES1 PKCS#8 are refused. The error gives the command to convert them.
- After opening, the checks are ADR 0269's: exactly one private key, RSA; a certificate for that key among the file's certificates, in any order; valid now.

### Failing closed

Errors name the setting and what's wrong, and never quote the file or the password:

- A password that doesn't open the file: "AZURE_CLIENT_CERTIFICATE_PASSWORD doesn't open it". A MAC failure, a padding failure and a PBES2 decryption failure all count.
- A PFX file that needs a password when none is set: "it is a PFX file with a password; set AZURE_CLIENT_CERTIFICATE_PASSWORD".
- A password set for a PEM file whose key isn't encrypted is refused. A wrong file isn't quietly taken for the right one, and a stale password setting doesn't linger.
- Schemes botd doesn't read, and files that are neither PEM nor PKCS#12, are refused, with how to export them again.

As in ADR 0269, the file is read and checked at startup and again at every sign-in. A file that can no longer be opened fails the sign-in before Entra is asked. botd never falls back to the key it read before.

The password is read once, at startup, like `AZURE_CLIENT_SECRET`. A renewed file must keep the password, or botd must restart. Re-reading it at each sign-in would mean holding a handle to the secret stores in the Entra client. That isn't worth it for a value that changes only when the file's issuer changes.

### Keeping the password from Bots

- `AZURE_CLIENT_CERTIFICATE_PASSWORD` is reserved, like `AZURE_CLIENT_SECRET`. No stored secret can take the name, it is never read from the external store's folders, and it is never offered to Bots.
- It and its `_FILE` are removed from everything botd starts.
- Its value is registered with the redactor, so it is masked in Bots' output and botd's logs.
- Audit events are unchanged: `method: client-certificate`, never the key, the assertion or the password.

## Consequences

- No change for PEM files with an unencrypted key and no password setting. A password setting that ADR 0269 refused is now accepted.
- Certificates from Windows, Key Vault and corporate PKI work as issued, with no unencrypted key on disk. The Azure SDK compatibility claim of ADR 0269 now holds for PFX files.
- Threat model: with the password delivered apart, a copy of the file alone can't sign in. With both in one place it's as before: anyone who can read both can sign in as the app until the certificate expires or is removed. botd's process holds the decrypted key in memory while it signs, as before.
- Limits: a PFX written with a *null* password (no bytes, which some Windows and .NET tools write) is not the same as an empty one to PKCS#12's key derivation, and `p12-keystore` only derives from a string. botd then reports a PFX file with a password. The guide shows how to write it again with OpenSSL. PBMAC1 (RFC 9579) MACs are refused as an unsupported scheme until the crate reads them.
- Dependencies: `p12-keystore` 0.4 (with RustCrypto's `pkcs12`, `pkcs5`, `cms`, `des`, `rc2`, `aes` and `cbc`) and `pkcs8` 0.11 with `encryption`. They are pure Rust and audited by `cargo audit` with the rest. `pkcs12` and `cms` are pre-release versions of RustCrypto's crates, pinned by `Cargo.lock`. The PFX code is used only to decode a file the operator chose, never on network input.
- Tested in `server/src/secrets/azure.rs` against the stand-in Entra, which checks every assertion's signature. Key Vault reads work with a PFX file and its password from `AZURE_CLIENT_CERTIFICATE_PASSWORD_FILE`. A renewed file is read at the next sign-in in each PFX scheme (AES-256, 3DES, RC2) and as an encrypted PEM key. A wrong password, a wrong encrypted key and a password for an unencrypted key each fail closed before Entra is asked, with the failure audited and no password in errors or audit. An empty-password PFX needs no setting. The file checks cover a missing password, a wrong one, two keys, a certificate for another key, an EC key, no certificate, an expired certificate, a chain in any order, truncated and non-PKCS#12 DER, and both password settings at once. A further test reads files the `openssl` command writes (PFX in its default and legacy schemes, with and without a password, and an encrypted PKCS#8 key) when OpenSSL is installed, as it is on CI. The password and its `_FILE` are reserved and kept from local jobs. No Azure account or network is used.
- Remaining on #55: nothing the issue names. The ideas still open, each for an issue of its own if asked for: subject name and issuer sign-in (ADR 0269), null-password and PBMAC1 PFX files (this ADR), Vault's `aws` `ec2` and GCP's `gce` sign-in types, and AliCloud or OCI sign-in (ADR 0260). Also workload identity federation for each Bot (ADR 0203), per-secret version pinning (ADR 0159), and harness logins kept in the external store.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#a-pfx-file-or-an-encrypted-key).
