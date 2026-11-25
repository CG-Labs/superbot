//! Warning before a native SAML provider's certificates expire (ADR 0198).
//!
//! A provider depends on four kinds of certificate: botd's own signing and encryption
//! certificates, which the IdP was given; the IdP's signing certificates, from its metadata;
//! and the certificates its metadata is signed by, when that is checked. botd never refuses a
//! signature for a certificate's dates (SAML trusts the key the metadata names, not the
//! certificate's validity), so an expiry doesn't stop botd. It stops the other side: some IdPs
//! refuse an SP certificate past its end, and an IdP replaces its own certificate when it ends,
//! which signs nobody in until botd has the new one, unless botd reads its metadata from a URL.
//!
//! Each certificate in use is judged on its own: `expiring` within [`WARN_DAYS`] of its end,
//! then `expired`. A certificate is *covered* when another of the same kind isn't ending: an
//! IdP's next certificate already in its metadata, or botd's next key. Each notice is audited
//! once per certificate, claimed in the transaction that records it.

use super::provider::{Kind, Provider};
use super::saml_keys::{self, Stage};
use super::saml_sp::{Encryption, KeyUse};
use super::xmldsig::Cert;
use crate::AppState;
use crate::audit::{Actor, Event, Outcome};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// How long before its end a certificate is audited as `sso.saml_certificate_expiring`. IdP
/// admins need time to give or take a certificate, and Entra ID warns at 60, 30 and 7 days.
pub const WARN_DAYS: i64 = 30;
const DAY_MS: i64 = 86_400_000;
/// How often certificates are looked at. They change over days, not minutes.
const CHECK_EVERY: Duration = Duration::from_secs(3600);

/// What a certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// botd's, published in its metadata: the IdP checks AuthnRequests and logout messages with it.
    SpSigning,
    /// botd's, published in its metadata: the IdP encrypts assertions to it.
    SpEncryption,
    /// The IdP's, from its metadata: botd checks assertions and logout messages with it.
    IdpSigning,
    /// `SSO_<ID>_METADATA_SIGNING_CERT_FILE`'s: botd checks the IdP's metadata with it.
    MetadataSigning,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::SpSigning => "sp_signing",
            Role::SpEncryption => "sp_encryption",
            Role::IdpSigning => "idp_signing",
            Role::MetadataSigning => "metadata_signing",
        }
    }
}

/// A certificate a provider uses now.
#[derive(Clone, Debug)]
pub struct InUse {
    pub role: Role,
    /// For a key botd made: its rollover stage (ADR 0181), current or next.
    pub stage: Option<Stage>,
    /// Where it comes from: `generated` or `secret` for botd's; the metadata's source for the
    /// IdP's (`url`, `file`, `botctl`); `file` for a metadata signing certificate.
    pub from: &'static str,
    /// For the IdP's: which IdP's metadata lists it (ADR 0282).
    pub idp: Option<String>,
    pub cert: Cert,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Ok,
    Expiring,
    Expired,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Expiring => "expiring",
            State::Expired => "expired",
        }
    }
}

/// Where a certificate ending at `not_after` (seconds) stands at `now` (ms).
pub fn state(not_after: i64, now: i64) -> State {
    let end = not_after.saturating_mul(1000);
    if end <= now {
        State::Expired
    } else if end - now <= WARN_DAYS * DAY_MS {
        State::Expiring
    } else {
        State::Ok
    }
}

/// Whole days left, rounded up; 0 once it has ended.
pub fn days_left(not_after: i64, now: i64) -> i64 {
    ((not_after.saturating_mul(1000) - now).max(0) + DAY_MS - 1) / DAY_MS
}

/// A certificate that is expiring or has expired.
#[derive(Debug)]
pub struct Finding<'a> {
    pub cert: &'a InUse,
    pub state: State,
    pub days_left: i64,
    /// Another certificate of the same role, and the same IdP's, that isn't ending (its
    /// SHA-256), if any.
    pub replacement: Option<&'a str>,
}

/// The certificates in `certs` that need a notice at `now`, in order.
pub fn findings(certs: &[InUse], now: i64) -> Vec<Finding<'_>> {
    certs
        .iter()
        .filter_map(|c| {
            let s = state(c.cert.not_after, now);
            if s == State::Ok {
                return None;
            }
            let replacement = certs.iter().find(|o| o.role == c.role && o.idp == c.idp && o.cert.sha256 != c.cert.sha256 && state(o.cert.not_after, now) == State::Ok).map(|o| o.cert.sha256.as_str());
            Some(Finding { cert: c, state: s, days_left: days_left(c.cert.not_after, now), replacement })
        })
        .collect()
}

/// botd's own certificates for `u` that the SP metadata publishes, read as they're kept. A key
/// botd hasn't made yet has no certificate: nothing here makes one.
fn sp_certs(app: &AppState, p: &Provider, u: KeyUse, role: Role, out: &mut Vec<InUse>) {
    if let Some(cert) = p.sp_cert_for(u) {
        match Cert::from_base64(cert) {
            Ok(cert) => out.push(InUse { role, stage: None, from: "secret", idp: None, cert }),
            Err(e) => crate::obs::log::log_warn!("SSO {}: the configured SP {} certificate: {e}", p.id, u.as_str()),
        }
        return;
    }
    // Both stages are read under one lock: a promotion between two reads would show the old
    // current certificate with no next one to cover it, and its notice is recorded only once.
    let stages = [Stage::Current, Stage::Next];
    let kept: Vec<Option<String>> = app
        .db
        .with_conn(|c| stages.iter().map(|&stage| c.query_row("SELECT value FROM settings WHERE key = ?", [saml_keys::settings(&p.id, u, stage).1], |r| r.get(0)).optional().ok().flatten()).collect());
    for (stage, cert) in stages.into_iter().zip(kept) {
        let Some(cert) = cert else {
            continue;
        };
        match Cert::from_base64(&cert) {
            Ok(cert) => out.push(InUse { role, stage: Some(stage), from: "generated", idp: None, cert }),
            Err(e) => crate::obs::log::log_warn!("SSO {}: the generated SP {} certificate ({}): {e}", p.id, u.as_str(), stage.as_str()),
        }
    }
}

/// Every certificate native SAML provider `p` uses now. The IdP's are from the metadata in
/// use, so none until it's loaded.
pub fn certificates(app: &AppState, p: &Provider) -> Vec<InUse> {
    let Kind::SamlSp { source, encryption, metadata_trust, .. } = &p.kind else {
        return Vec::new();
    };
    let mut out = Vec::new();
    sp_certs(app, p, KeyUse::Signing, Role::SpSigning, &mut out);
    if *encryption != Encryption::Off {
        sp_certs(app, p, KeyUse::Encryption, Role::SpEncryption, &mut out);
    }
    for m in p.idps().iter().filter_map(|e| p.idp_loaded_for(e)) {
        out.extend(m.certs.iter().map(|c| InUse { role: Role::IdpSigning, stage: None, from: source.name(), idp: Some(m.entity_id.clone()), cert: c.clone() }));
    }
    if let Some(t) = metadata_trust {
        out.extend(t.certs.iter().map(|c| InUse { role: Role::MetadataSigning, stage: None, from: "file", idp: None, cert: c.clone() }));
    }
    // Metadata may list a certificate twice; it's still one certificate to warn about.
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert((c.role, c.idp.clone(), c.cert.sha256.clone())));
    out
}

/// What an admin does about `f`, in a sentence.
pub fn action(p: &Provider, f: &Finding) -> String {
    let id = &p.id;
    let up = id.to_ascii_uppercase();
    let c = f.cert;
    let key_use = if c.role == Role::SpEncryption { "encryption" } else { "signing" };
    match c.role {
        Role::SpSigning | Role::SpEncryption if c.from == "secret" => {
            let (file, key) = if c.role == Role::SpSigning { ("SP_CERT_FILE", "PRIVATE_KEY") } else { ("SP_ENCRYPTION_CERT_FILE", "ENCRYPTION_PRIVATE_KEY") };
            format!("Make a new key and certificate, give the IdP the new certificate first, then set SSO_{up}_{file} and SSO_{up}_{key} and restart botd.")
        }
        Role::SpSigning | Role::SpEncryption => match (c.stage, f.replacement) {
            (Some(Stage::Current), Some(_)) => format!("The next {key_use} key is published: once the IdP has it, promote it (botctl sso saml {id} key promote {key_use})."),
            (Some(Stage::Next), _) => format!("Replace this next key: botctl sso saml {id} key cancel {key_use}, then key next {key_use}."),
            _ => format!("Roll it over: botctl sso saml {id} key next {key_use}, give the IdP SuperBot's metadata again, then promote it."),
        },
        Role::IdpSigning => match (f.replacement, c.from) {
            (Some(r), _) => format!("The IdP's metadata already has a newer certificate (SHA-256 {r}): nothing to do unless the IdP keeps signing with this one."),
            (None, "mdq") => "Renew it at the IdP, and have the IdP's operators publish its new certificate in the federation's metadata. botd asks the MDQ server again daily and takes it by itself; nothing to import.".into(),
            (None, "url") => "Renew it at the IdP. Its metadata URL lists no newer certificate yet; botd reads it again daily and takes the new one by itself.".into(),
            (None, "file") => format!("Renew it at the IdP, then put its new metadata (listing both certificates) in SSO_{up}_IDP_METADATA_FILE and restart botd, before the IdP switches."),
            (None, _) => format!("Renew it at the IdP, then import its new metadata (listing both certificates) before the IdP switches: botctl sso saml {id} import < metadata.xml."),
        },
        Role::MetadataSigning => match f.replacement {
            Some(r) => format!("Another trusted certificate (SHA-256 {r}) outlives it in SSO_{up}_METADATA_SIGNING_CERT_FILE."),
            None => format!("Add the IdP's or federation's next metadata signing certificate to SSO_{up}_METADATA_SIGNING_CERT_FILE and restart botd, before it switches."),
        },
    }
}

/// `certificateWarnings` for `GET /api/sso/{id}/saml`: every certificate that is expiring or
/// has expired, with what to do.
pub fn warnings(app: &AppState, p: &Provider, now: i64) -> Vec<Value> {
    let certs = certificates(app, p);
    findings(&certs, now)
        .iter()
        .map(|f| {
            let mut v = details(p, f);
            v["action"] = json!(action(p, f));
            v
        })
        .collect()
}

fn details(p: &Provider, f: &Finding) -> Value {
    let c = f.cert;
    json!({
        "provider": p.id, "role": c.role.as_str(), "stage": c.stage.map(Stage::as_str), "from": c.from, "entityId": c.idp,
        "certificate": c.cert.sha256, "subject": crate::audit::clip(&c.cert.subject, 256), "notAfter": c.cert.not_after.saturating_mul(1000),
        "state": f.state.as_str(), "daysLeft": f.days_left, "replacement": f.replacement,
    })
}

/// Audits each certificate of `providers` that is expiring or has expired at `now`, once per
/// notice: `sso.saml_certificate_expiring`, then `sso.saml_certificate_expired`. An expired
/// certificate nothing replaces is a failure; one with a replacement is a success, as is a
/// warning. IdP metadata from a URL is refreshed first when it's due, so a certificate the IdP
/// already replaced there isn't reported. Returns how many were recorded.
pub async fn check(app: &AppState, providers: &[Arc<Provider>], http: &reqwest::Client, gap: Duration, now: i64) -> usize {
    let mut n = 0;
    for p in providers.iter().filter(|p| p.saml_sp()) {
        if matches!(&p.kind, Kind::SamlSp { source, .. } if source.fetched()) {
            for entity in p.idps() {
                if let Err(e) = p.idp_metadata_for(http, gap, entity).await {
                    crate::obs::log::log_warn!("SSO {}: IdP {entity} metadata: {e}", p.id);
                }
            }
            for (entity, e) in p.take_metadata_refusals() {
                app.db.record(&super::metadata_refused(p, &entity, &e));
            }
        }
        let certs = certificates(app, p);
        for f in findings(&certs, now) {
            let (name, notice) = match f.state {
                State::Expired => ("sso.saml_certificate_expired", "expired"),
                _ => ("sso.saml_certificate_expiring", "expiring"),
            };
            let outcome = if f.state == State::Expired && f.replacement.is_none() { Outcome::Failure } else { Outcome::Success };
            let e = Event::new(Actor::system("sso"), name).target("sso_provider", &p.id).outcome(outcome);
            let c = f.cert;
            let recorded = app.db.record_with(&e, |db, _, _| {
                if !crate::db::claim_saml_cert_notice(db, &p.id, c.role.as_str(), &c.cert.sha256, notice, now)? {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                Ok(details(p, &f))
            });
            match recorded {
                Ok(_) => {
                    n += 1;
                    // The certificate and what to do are in the audit event: CodeQL reads any
                    // `sha256` in a log line as a secret.
                    let when = if f.state == State::Expired { "has expired".to_string() } else { format!("expires in {} day(s)", f.days_left) };
                    crate::obs::log::log_warn!("SSO {}: a {} certificate {when}; see `botctl sso saml {}`", p.id, c.role.as_str(), p.id);
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(err) => crate::obs::log::log_warn!("SSO {}: could not record {name}: {err}; it stays owed", p.id),
            }
        }
    }
    n
}

/// Checks now and every hour.
pub fn start(auth: Arc<crate::Auth>) {
    if !auth.sso.providers.iter().any(|p| p.saml_sp()) {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        loop {
            tick.tick().await;
            if let Some(app) = auth.app.as_ref() {
                check(app, &auth.sso.providers, auth.sso.http(), auth.sso.refresh_gap, crate::db::now()).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::xmldsig::test_signer::signers;

    fn cert(sha: &str, not_after: i64) -> Cert {
        let mut c = signers()[0].cert();
        (c.sha256, c.not_after) = (sha.into(), not_after);
        c
    }

    fn in_use(role: Role, sha: &str, not_after: i64) -> InUse {
        InUse { role, stage: None, from: "url", idp: None, cert: cert(sha, not_after) }
    }

    const NOW: i64 = 1_800_000_000_000;
    const S: i64 = NOW / 1000;

    #[test]
    fn a_certificate_is_expiring_within_thirty_days_and_expired_at_its_end() {
        let day = 86_400;
        assert_eq!(state(S + 31 * day, NOW), State::Ok);
        assert_eq!(state(S + 30 * day, NOW), State::Expiring, "the 30th day counts");
        assert_eq!(state(S + 1, NOW), State::Expiring);
        assert_eq!(state(S, NOW), State::Expired, "at its end, it's over");
        assert_eq!(state(S - 1, NOW), State::Expired);
        assert_eq!((days_left(S + 30 * day, NOW), days_left(S + 1, NOW), days_left(S - day, NOW)), (30, 1, 0), "rounded up, never below 0");
        assert_eq!(state(i64::MAX, NOW), State::Ok, "no overflow on a far end");
    }

    #[test]
    fn a_certificate_is_covered_only_by_another_of_its_role_that_isnt_ending() {
        let day = 86_400;
        let certs = [
            in_use(Role::IdpSigning, "old", S + 5 * day),
            in_use(Role::IdpSigning, "new", S + 400 * day),
            in_use(Role::MetadataSigning, "anchor", S - day),
            in_use(Role::SpSigning, "sp", S + 10 * day),
            in_use(Role::SpEncryption, "enc", S + 900 * day),
        ];
        let f = findings(&certs, NOW);
        let got: Vec<(&str, State, Option<&str>)> = f.iter().map(|f| (f.cert.cert.sha256.as_str(), f.state, f.replacement)).collect();
        assert_eq!(got, [("old", State::Expiring, Some("new")), ("anchor", State::Expired, None), ("sp", State::Expiring, None)], "the encryption key doesn't cover the signing one");

        let both_ending = [in_use(Role::IdpSigning, "a", S + 5 * day), in_use(Role::IdpSigning, "b", S + 20 * day)];
        assert!(findings(&both_ending, NOW).iter().all(|f| f.replacement.is_none()), "a certificate that's ending covers nothing");
        assert!(findings(&[in_use(Role::IdpSigning, "fine", S + 365 * day)], NOW).is_empty());
    }

    #[test]
    fn every_finding_says_what_to_do_for_where_the_certificate_comes_from() {
        let vars = [
            ("SSO_PROVIDERS", "corp"),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            ("SSO_CORP_TYPE", "saml"),
            ("SSO_CORP_IDP_ENTITY_ID", "https://idp.example/saml"),
            ("SSO_CORP_IDP_METADATA_URL", "https://idp.example/metadata"),
        ];
        let s = crate::sso::Sso::from_vars(&|k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())).unwrap();
        let p = &s.providers[0];
        let day = 86_400;
        let say = |role: Role, stage: Option<Stage>, from: &'static str, replaced: bool| {
            let mut certs = vec![InUse { role, stage, from, idp: None, cert: cert("ending", S + day) }];
            if replaced {
                certs.push(InUse { role, stage: Some(Stage::Next), from, idp: None, cert: cert("after", S + 900 * day) });
            }
            action(p, &findings(&certs, NOW)[0])
        };
        assert!(say(Role::SpSigning, Some(Stage::Current), "generated", false).contains("botctl sso saml corp key next signing"));
        assert!(say(Role::SpEncryption, Some(Stage::Current), "generated", true).contains("key promote encryption"));
        assert!(say(Role::SpEncryption, Some(Stage::Next), "generated", false).contains("key cancel encryption"));
        assert!(say(Role::SpSigning, None, "secret", false).contains("SSO_CORP_SP_CERT_FILE and SSO_CORP_PRIVATE_KEY"));
        assert!(say(Role::SpEncryption, None, "secret", false).contains("SSO_CORP_SP_ENCRYPTION_CERT_FILE and SSO_CORP_ENCRYPTION_PRIVATE_KEY"));
        assert!(say(Role::IdpSigning, None, "url", false).contains("reads it again daily"));
        assert!(say(Role::IdpSigning, None, "file", false).contains("SSO_CORP_IDP_METADATA_FILE"));
        let mdq = say(Role::IdpSigning, None, "mdq", false);
        assert!(mdq.contains("federation's metadata") && !mdq.contains("import <"), "{mdq}");
        assert!(say(Role::IdpSigning, None, "botctl", false).contains("botctl sso saml corp import"));
        assert!(say(Role::IdpSigning, None, "url", true).contains("already has a newer certificate (SHA-256 after)"));
        assert!(say(Role::MetadataSigning, None, "file", false).contains("SSO_CORP_METADATA_SIGNING_CERT_FILE"));
    }
}
