//! Rolling over botd's own SAML SP keys without an outage (ADR 0181).
//!
//! A native provider's generated signing and encryption keys (ADR 0137, 0150) are kept in
//! settings, sealed. Beside the key in use, each use may have:
//!
//! - a **next** key, made by an admin: published in our metadata after the one in use, so the
//!   IdP can take it up before it matters, and tried when decrypting. It never signs.
//! - a **previous** encryption key, the one a promotion replaced: no longer published, but still
//!   tried when decrypting, so an IdP that hasn't taken up our new metadata yet still signs
//!   people in. An admin retires it. A replaced signing key goes at once: nothing botd
//!   receives is checked against it.
//!
//! Promoting makes the next key the one in use, in one transaction. Each key's last use since
//! botd started shows which one the IdP encrypts to, so an admin can see when each step is safe.
//! Configured keys (`SP_CERT_FILE`, `SP_ENCRYPTION_CERT_FILE`) are rolled over in `.env`.

use super::provider::{Kind, Provider};
use super::saml_sp::{Encryption, KeyUse, SpKey};
use crate::audit::{Event, Who};
use crate::secrets::sealed::{self, SAML_SP_CERT_SETTING, SAML_SP_KEY_SETTING};
use crate::{ApiError, AppState};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, MutexGuard};

/// Where a generated key stands in a rollover.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Stage {
    /// In use: signs, or is the encryption certificate IdPs are asked to use.
    Current,
    /// Published and decrypting, waiting to be promoted.
    Next,
    /// A replaced encryption key, decrypting until retired.
    Previous,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Current => "current",
            Stage::Next => "next",
            Stage::Previous => "previous",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Stage::Current => "",
            Stage::Next => "_next",
            Stage::Previous => "_previous",
        }
    }
}

/// The settings a generated key and its certificate are kept in: the provider id, `_encryption`
/// for the encryption key, then the stage's suffix. Ids have no `_`, so one provider's names are
/// never another's, and sealing, master-key rotation and `SUPERBOT_FORGET_SEALED` treat every
/// stage alike.
pub(crate) fn settings(provider: &str, u: KeyUse, stage: Stage) -> (String, String) {
    let suffix = match u {
        KeyUse::Signing => "",
        KeyUse::Encryption => "_encryption",
    };
    let at = format!("{provider}{suffix}{}", stage.suffix());
    (format!("{SAML_SP_KEY_SETTING}{at}"), format!("{SAML_SP_CERT_SETTING}{at}"))
}

/// A provider's generated keys for one use, as kept in settings.
pub struct Held {
    pub current: Arc<SpKey>,
    pub next: Option<Arc<SpKey>>,
    pub previous: Option<Arc<SpKey>>,
    /// When each key last decrypted an assertion or NameID that checked out (ms), by certificate
    /// SHA-256; 0 for not yet. Kept per key, not per stage, and handed on to the next `Held` when
    /// a rollover step reloads the keys, so a promoted or replaced key keeps its history and a
    /// sign-in that began before the step still counts.
    used: HashMap<String, Arc<AtomicI64>>,
}

impl Held {
    fn new(current: Arc<SpKey>, next: Option<Arc<SpKey>>, previous: Option<Arc<SpKey>>, before: Option<&Held>) -> Held {
        let used = std::iter::once(&current)
            .chain(next.as_ref())
            .chain(previous.as_ref())
            .map(|k| {
                let sha = k.info.sha256.clone();
                let kept = before.and_then(|b| b.used.get(&sha).cloned());
                (sha, kept.unwrap_or_default())
            })
            .collect();
        Held { current, next, previous, used }
    }

    fn at(&self, stage: Stage) -> Option<&Arc<SpKey>> {
        match stage {
            Stage::Current => Some(&self.current),
            Stage::Next => self.next.as_ref(),
            Stage::Previous => self.previous.as_ref(),
        }
    }

    fn counter(&self, stage: Stage) -> Option<&AtomicI64> {
        self.at(stage).and_then(|k| self.used.get(&k.info.sha256)).map(|c| c.as_ref())
    }

    /// The keys tried when decrypting, in order: the one in use, the next, the previous.
    pub fn decrypting(&self) -> Vec<(Stage, Arc<SpKey>)> {
        let mut keys = vec![(Stage::Current, self.current.clone())];
        keys.extend(self.next.clone().map(|k| (Stage::Next, k)));
        keys.extend(self.previous.clone().map(|k| (Stage::Previous, k)));
        keys
    }

    /// The keys our metadata publishes, in order: the one in use, then the next.
    pub fn published(&self) -> Vec<Arc<SpKey>> {
        std::iter::once(self.current.clone()).chain(self.next.clone()).collect()
    }

    /// Notes that `stage`'s key decrypted something at `at`.
    pub fn used(&self, stage: Stage, at: i64) {
        if let Some(c) = self.counter(stage) {
            c.fetch_max(at, Ordering::Relaxed);
        }
    }

    /// When `stage`'s key last decrypted something, if it has since botd loaded it.
    pub fn last_used(&self, stage: Stage) -> Option<i64> {
        self.counter(stage).map(|c| c.load(Ordering::Relaxed)).filter(|&t| t > 0)
    }
}

fn slot(p: &Provider, u: KeyUse) -> MutexGuard<'_, Option<Arc<Held>>> {
    let i = match u {
        KeyUse::Signing => 0,
        KeyUse::Encryption => 1,
    };
    p.held[i].lock().unwrap_or_else(|e| e.into_inner())
}

/// The provider's generated keys for `u`, loaded once. The key in use is made the first time
/// it's needed, and audited.
pub(crate) fn held(app: &AppState, p: &Provider, u: KeyUse) -> Result<Arc<Held>, String> {
    let mut slot = slot(p, u);
    if let Some(h) = slot.as_ref() {
        return Ok(h.clone());
    }
    let h = Arc::new(load(app, p, u, None)?);
    *slot = Some(h.clone());
    Ok(h)
}

/// The sealed key and certificate kept for `stage`, opened.
fn opened(app: &AppState, p: &Provider, u: KeyUse, stage: Stage) -> Result<Option<(zeroize::Zeroizing<Vec<u8>>, String)>, String> {
    let (key_name, cert_name) = settings(&p.id, u, stage);
    let (Some(sealed), Some(cert)) = (app.db.setting(&key_name), app.db.setting(&cert_name)) else { return Ok(None) };
    let der = sealed::cipher().open(&sealed::setting_context(&key_name), &sealed).map_err(|e| format!("the generated SP {} key ({}): {e}", u.as_str(), stage.as_str()))?;
    Ok(Some((der, cert)))
}

fn key_at(app: &AppState, p: &Provider, u: KeyUse, stage: Stage) -> Result<Option<SpKey>, String> {
    opened(app, p, u, stage)?.map(|(der, cert)| SpKey::from_der(&der, &cert)).transpose()
}

fn load(app: &AppState, p: &Provider, u: KeyUse, before: Option<&Held>) -> Result<Held, String> {
    let current = match key_at(app, p, u, Stage::Current)? {
        Some(k) => k,
        None => make(app, p, u, Stage::Current, &Who::system("sso"))?,
    };
    // A next or previous key that no longer opens is left out rather than stop sign-ins.
    let beside = |stage| {
        key_at(app, p, u, stage).unwrap_or_else(|e| {
            crate::obs::log::log_warn!("SSO {}: left out: {e}", p.id);
            None
        })
    };
    Ok(Held::new(Arc::new(current), beside(Stage::Next).map(Arc::new), beside(Stage::Previous).map(Arc::new), before))
}

/// Makes a key for `stage`, keeps it sealed with its certificate, and audits it.
fn make(app: &AppState, p: &Provider, u: KeyUse, stage: Stage, by: &Who) -> Result<SpKey, String> {
    let subject = match u {
        KeyUse::Signing => format!("SuperBot SAML SP ({})", p.id),
        KeyUse::Encryption => format!("SuperBot SAML SP encryption ({})", p.id),
    };
    let (key, der) = SpKey::generate(&subject)?;
    let (key_name, cert_name) = settings(&p.id, u, stage);
    let sealed = sealed::cipher().seal(&sealed::setting_context(&key_name), &der);
    if !app.db.write_settings(&[(&key_name, Some(&sealed)), (&cert_name, Some(&key.cert))]) {
        return Err(format!("couldn't keep the new SP {} key", u.as_str()));
    }
    let details = json!({ "provider": p.id, "use": u.as_str(), "stage": stage.as_str(), "certificate": key.info.sha256, "notAfter": key.info.not_after * 1000 });
    app.db.record(&by.event("sso.saml_sp_key_created").target("sso_provider", &p.id).details(details));
    Ok(key)
}

/// What an admin does to a provider's generated key for one use.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Change {
    /// Make a next key.
    Next,
    /// Put the next key in use.
    Promote,
    /// Drop the next key before it's promoted.
    Cancel,
    /// Drop the previous encryption key.
    Retire,
}

fn conflict(m: String) -> ApiError {
    ApiError(StatusCode::CONFLICT, m)
}

fn sha(k: &SpKey) -> &str {
    &k.info.sha256
}

/// Applies `c` to `p`'s generated key for `u`, under the lock its keys are loaded under, so a
/// sign-in sees the keys before or after, never half of it. Refused (409) for a configured key,
/// an encryption key the provider doesn't use, or a step that doesn't fit the rollover's stage.
pub(crate) fn change(app: &AppState, p: &Provider, u: KeyUse, c: Change, by: &Who) -> Result<(), ApiError> {
    let up = p.id.to_ascii_uppercase();
    let Kind::SamlSp { encryption, .. } = &p.kind else { return Err(crate::bad("not a native SAML provider")) };
    if p.sp_cert_for(u).is_some() {
        let file = if u == KeyUse::Signing { "SP_CERT_FILE" } else { "SP_ENCRYPTION_CERT_FILE" };
        return Err(conflict(format!("SSO_{up}_{file} sets this {} key: roll it over there, giving the IdP the new certificate first.", u.as_str())));
    }
    if u == KeyUse::Encryption && *encryption == Encryption::Off {
        return Err(conflict(format!("SSO_{up}_ENCRYPTED_ASSERTIONS is off: there is no encryption key to roll over.")));
    }
    let mut slot = slot(p, u);
    let h = match slot.as_ref() {
        Some(h) => h.clone(),
        None => Arc::new(load(app, p, u, None).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?),
    };
    let id = &p.id;
    let use_ = u.as_str();
    let failed = |what: &str| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("couldn't {what} the {use_} key"));
    match c {
        Change::Next => {
            if let Some(n) = &h.next {
                return Err(conflict(format!("There is already a next {use_} key (SHA-256 {}): promote it or cancel it first.", sha(n))));
            }
            make(app, p, u, Stage::Next, by).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
        Change::Promote => {
            let Some(next) = &h.next else {
                return Err(conflict(format!("There is no next {use_} key: make one with `botctl sso saml {id} key next {use_}`, give the IdP SuperBot's metadata again, then promote it.")));
            };
            if let Some(prev) = &h.previous {
                return Err(conflict(format!("The previous {use_} key (SHA-256 {}) still decrypts: retire it first (`botctl sso saml {id} key retire {use_}`).", sha(prev))));
            }
            let (Some((next_der, next_cert)), Some((old_der, old_cert))) = (opened(app, p, u, Stage::Next).ok().flatten(), opened(app, p, u, Stage::Current).ok().flatten()) else {
                return Err(failed("open"));
            };
            let cipher = sealed::cipher();
            let [(cur_key, cur_cert), (next_key, next_cert_name), (prev_key, prev_cert)] = [Stage::Current, Stage::Next, Stage::Previous].map(|s| settings(id, u, s));
            let new_current = cipher.seal(&sealed::setting_context(&cur_key), &next_der);
            // Only an encryption key is kept: the IdP may still encrypt to it for a while.
            let kept = (u == KeyUse::Encryption).then(|| cipher.seal(&sealed::setting_context(&prev_key), &old_der));
            let writes = [
                (cur_key.as_str(), Some(new_current.as_str())),
                (cur_cert.as_str(), Some(next_cert.as_str())),
                (next_key.as_str(), None),
                (next_cert_name.as_str(), None),
                (prev_key.as_str(), kept.as_deref()),
                (prev_cert.as_str(), kept.as_ref().map(|_| old_cert.as_str())),
            ];
            if !app.db.write_settings(&writes) {
                return Err(failed("promote"));
            }
            let details = json!({ "provider": id, "use": use_, "certificate": sha(next), "replaced": sha(&h.current), "previousKept": kept.is_some() });
            app.db.record(&by.event("sso.saml_sp_key_promoted").target("sso_provider", id).details(details));
        }
        Change::Cancel | Change::Retire => {
            let stage = if c == Change::Cancel { Stage::Next } else { Stage::Previous };
            let Some(gone) = (if c == Change::Cancel { &h.next } else { &h.previous }) else {
                return Err(conflict(format!("There is no {} {use_} key.", stage.as_str())));
            };
            let (key_name, cert_name) = settings(id, u, stage);
            if !app.db.write_settings(&[(&key_name, None), (&cert_name, None)]) {
                return Err(failed("remove"));
            }
            app.db.record(&retired(p, u, stage, gone, by));
        }
    }
    *slot = Some(Arc::new(load(app, p, u, Some(&h)).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?));
    Ok(())
}

fn retired(p: &Provider, u: KeyUse, stage: Stage, k: &SpKey, by: &Who) -> Event {
    by.event("sso.saml_sp_key_retired").target("sso_provider", &p.id).details(json!({ "provider": p.id, "use": u.as_str(), "stage": stage.as_str(), "certificate": sha(k) }))
}

/// A next or previous key for `GET /api/sso/{id}/saml`: its certificate, and when it last
/// decrypted something (encryption keys only).
pub(crate) fn view(h: &Held, u: KeyUse, stage: Stage, now: i64, cert: impl Fn(&super::xmldsig::Cert) -> Value) -> Value {
    let Some(k) = h.at(stage) else { return Value::Null };
    let mut v = json!({ "certificate": cert(&k.info) });
    if u == KeyUse::Encryption {
        v["lastUsedSecondsAgo"] = json!(h.last_used(stage).map(|t| (now - t).max(0) / 1000));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stage_has_settings_of_its_own_that_sealing_covers() {
        let names: Vec<(String, String)> = [KeyUse::Signing, KeyUse::Encryption].iter().flat_map(|&u| [Stage::Current, Stage::Next, Stage::Previous].map(|s| settings("corp", u, s))).collect();
        assert_eq!(names[0], ("sso_saml_sp_key_corp".into(), "sso_saml_sp_cert_corp".into()), "where keys from before rollovers are");
        assert_eq!(names[4], ("sso_saml_sp_key_corp_encryption_next".into(), "sso_saml_sp_cert_corp_encryption_next".into()));
        let mut keys: Vec<&String> = names.iter().map(|(k, _)| k).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 6);
        for (key, cert) in &names {
            assert!(key.starts_with(SAML_SP_KEY_SETTING) && *cert == key.replacen(SAML_SP_KEY_SETTING, SAML_SP_CERT_SETTING, 1), "{key}");
        }
    }

    #[test]
    fn decrypting_tries_the_key_in_use_first_and_publishes_only_it_and_the_next() {
        let k = || Arc::new(SpKey::generate("k").unwrap().0);
        let (current, next, previous) = (k(), k(), k());
        let h = Held::new(current.clone(), Some(next.clone()), Some(previous.clone()), None);
        let order: Vec<(Stage, String)> = h.decrypting().into_iter().map(|(s, k)| (s, k.info.sha256.clone())).collect();
        assert_eq!(order, [(Stage::Current, current.info.sha256.clone()), (Stage::Next, next.info.sha256.clone()), (Stage::Previous, previous.info.sha256.clone())]);
        let published: Vec<String> = h.published().iter().map(|k| k.info.sha256.clone()).collect();
        assert_eq!(published, [current.info.sha256.clone(), next.info.sha256.clone()], "never the previous key");
        assert_eq!(h.last_used(Stage::Next), None);
        h.used(Stage::Next, 2_000);
        h.used(Stage::Next, 1_000);
        assert_eq!((h.last_used(Stage::Next), h.last_used(Stage::Current)), (Some(2_000), None), "the latest use");
        let alone = Held::new(current.clone(), None, None, None);
        assert_eq!((alone.decrypting().len(), alone.published().len()), (1, 1));

        // Promoted: each key keeps its history under its new stage, and a sign-in still holding
        // the keys from before the step counts toward it.
        h.used(Stage::Current, 3_000);
        let promoted = Held::new(next.clone(), None, Some(current.clone()), Some(&h));
        assert_eq!((promoted.last_used(Stage::Current), promoted.last_used(Stage::Previous)), (Some(2_000), Some(3_000)));
        h.used(Stage::Current, 4_000);
        assert_eq!(promoted.last_used(Stage::Previous), Some(4_000));
        let fresh = Held::new(previous, None, None, Some(&promoted));
        assert_eq!(fresh.last_used(Stage::Current), None, "a key that's new to it starts with none");
    }
}
