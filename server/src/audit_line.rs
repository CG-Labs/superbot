//! An exported audit event checked against nothing but itself (ADR 0199).
//!
//! Every event the export writes carries `chainDigest`, and `chainSalt` when the line
//! says everything the salted digest covers, so its `chainHash` can be worked out again
//! from the line alone: the fields no erasure may change, `chainPrev` and the digest give
//! the hash, and the salt with the fields an erasure may rewrite gives the digest. A copy
//! kept anywhere (the write-once archive, a SIEM, a file an auditor downloaded) can then
//! be checked after botd's retention has deleted the row, and without botd at all.
//!
//! Shared by botd (the export and the archive check) and botctl (`botctl audit
//! verify-lines`), so it uses nothing from botd's crate.

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "superbot.audit.v1";
/// The link before the first event of a log that has never been pruned.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const CHECKPOINT: &str = "audit.checkpoint";
const CHAIN: &str = "superbot-audit-chain-v1";
const SIGNED: &str = "superbot-audit-checkpoint-v1";
/// Problems a report lists; it counts them all.
const MAX_LISTED: usize = 20;

/// The chain's columns nothing may change (`audit_chain::FIXED`), as the export names them.
pub const FIXED_FIELDS: [&str; 11] = ["id", "at", "actorKind", "action", "targetType", "botId", "outcome", "actorRole", "authMethod", "idp", "idpProvider"];
/// The columns an erasure may rewrite (`audit_chain::ERASABLE`), as the export names them.
pub const ERASABLE_FIELDS: [&str; 10] = ["actorId", "actorName", "actorSubject", "targetId", "ip", "userAgent", "details", "actorEmail", "sessionId", "onBehalfOf"];

/// SHA-256 of the parts joined by newlines, in hex: how the chain hashes.
pub fn sha(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(p.as_bytes());
    }
    hex(&h.finalize())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// The fields no erasure may change as the chain hashes them: a JSON array of the values
/// as stored, which the line has as they are.
fn fixed(line: &Value) -> String {
    Value::Array(FIXED_FIELDS.iter().map(|f| line.get(*f).cloned().unwrap_or(Value::Null)).collect()).to_string()
}

/// The fields an erasure may rewrite, likewise. `details` is stored as the text of its
/// JSON, which is what the line holds, written out the same way.
fn erasable(line: &Value) -> String {
    let value = |f: &str| match (f, line.get(f)) {
        ("details", Some(d)) => Value::String(d.to_string()),
        (_, v) => v.cloned().unwrap_or(Value::Null),
    };
    Value::Array(ERASABLE_FIELDS.iter().map(|f| value(f)).collect()).to_string()
}

/// `chain_digest` as the line's fields give it under `salt`.
pub fn digest(salt: &str, line: &Value) -> String {
    sha(&[CHAIN, "erasable", salt, &erasable(line)])
}

/// `chain_hash` as the line's fields give it, linked to `prev` with `digest`.
pub fn link(prev: &str, line: &Value, digest: &str) -> String {
    sha(&[CHAIN, prev, &fixed(line), digest])
}

/// How much of an event its line's own hash vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// Every field the chain covers: the line has its salt.
    All,
    /// The fields no erasure may change: no salt, as the event was erased, or redacted on
    /// the way out, before it was exported.
    Fixed,
    /// Nothing: no `chainDigest`, as exported before ADR 0199.
    None,
}

/// Works the line's `chainHash` out again from what it says. An error names what doesn't follow.
pub fn check(line: &Value) -> Result<Bound, String> {
    let s = |k: &str| line.get(k).and_then(Value::as_str);
    let (Some(prev), Some(hash)) = (s("chainPrev"), s("chainHash")) else { return Err("it has no chainPrev or chainHash".into()) };
    let digest_of = match line.get("chainDigest") {
        None | Some(Value::Null) => return Ok(Bound::None),
        Some(Value::String(d)) => d,
        Some(_) => return Err("its chainDigest isn't text".into()),
    };
    if link(prev, line, digest_of) != hash {
        return Err("its chainHash isn't the hash of its chainPrev, its chainDigest and the fields no erasure may change: one of them was changed".into());
    }
    match line.get("chainSalt") {
        None | Some(Value::Null) => Ok(Bound::Fixed),
        Some(Value::String(salt)) if digest(salt, line) == *digest_of => Ok(Bound::All),
        Some(Value::String(_)) => Err("its chainDigest isn't the digest of its chainSalt and the fields an erasure may rewrite: one of them was changed".into()),
        Some(_) => Err("its chainSalt isn't text".into()),
    }
}

/// What a checkpoint signs (ADR 0149).
pub fn statement(seq: i64, hash: &str, at: i64, key: &str) -> String {
    format!("{SIGNED}\nseq={seq}\nhash={hash}\nat={at}\nkey={key}")
}

/// A key's id: the first 8 bytes of its SHA-256, hex.
pub fn key_id(public: &[u8]) -> String {
    hex(&Sha256::digest(public)[..8])
}

/// Whether `signature` (hex) is `public`'s Ed25519 signature over `message`.
pub fn signed(public: &[u8], message: &str, signature: &str) -> bool {
    unhex(signature).is_some_and(|s| UnparsedPublicKey::new(&ED25519, public).verify(message.as_bytes(), &s).is_ok())
}

/// An Ed25519 public key, as 64 hex digits.
pub fn parse_public_key(s: &str) -> Result<Vec<u8>, String> {
    match unhex(s.trim()) {
        Some(k) if k.len() == 32 => Ok(k),
        _ => Err(format!("a key is an Ed25519 public key in 64 hex digits, not \"{}\"", s.chars().take(80).collect::<String>())),
    }
}

/// Checks a checkpoint's details: it signs `prev`, the head it is sealed onto (and is
/// numbered for `before`, the event before it, when that's known), its key id is its
/// key's, one of `keys` signed it (with None, the key it carries), and the signature
/// holds. Returns the key's id, or a reason (`malformed`, `head`, `key`, `signature`)
/// and why.
pub fn check_checkpoint(prev: Option<&str>, d: Option<&Value>, before: Option<i64>, keys: Option<&[Vec<u8>]>) -> Result<String, (&'static str, String)> {
    let malformed = || ("malformed", "the checkpoint's details are missing a field".to_string());
    let d = d.ok_or_else(malformed)?;
    let s = |k: &str| d[k].as_str().ok_or_else(malformed);
    let n = |k: &str| d[k].as_i64().ok_or_else(malformed);
    let (seq, hash, at, kid, public, signature) = (n("seq")?, s("hash")?, n("at")?, s("keyId")?, s("publicKey")?, s("signature")?);
    if Some(hash) != prev || before.is_some_and(|b| b != seq) {
        return Err(("head", format!("it signs event {seq}'s hash, not the head it is sealed onto")));
    }
    let public = parse_public_key(public).map_err(|e| ("malformed", e))?;
    if key_id(&public) != kid {
        return Err(("key", format!("its key id {kid} isn't its key's")));
    }
    if keys.is_some_and(|k| !k.contains(&public)) {
        return Err(("key", format!("signed by key {kid}, which isn't trusted")));
    }
    if !signed(&public, &statement(seq, hash, at, kid), signature) {
        return Err(("signature", "its signature doesn't verify".into()));
    }
    Ok(kid.to_string())
}

/// Something in the lines that doesn't hold: `unreadable` (a line that names the schema
/// but isn't one of its events), `digest` (its hash doesn't follow from what it says),
/// `unbound` (no `chainDigest`, after an event that had one: every event botd exports
/// after the first with one has one), `conflict` (two copies of an event with different
/// links), `link` (an event doesn't link to the one before: events are missing, or
/// aren't botd's) or `checkpoint`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub id: Option<i64>,
    /// The file and line, as given.
    pub at: String,
    pub reason: &'static str,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Head {
    pub id: i64,
    pub hash: String,
}

/// One host's chain, as the lines hold it.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub host: String,
    pub ok: bool,
    /// Distinct events, and every copy of them read.
    pub events: u64,
    pub copies: u64,
    pub first: Option<i64>,
    /// What the first event links to: the genesis hash for a log never pruned.
    pub first_prev: Option<String>,
    pub head: Option<Head>,
    /// Copies whose every field their hash vouches for, only the fields no erasure may
    /// change, or none (exported before ADR 0199).
    pub bound: u64,
    pub bound_fixed: u64,
    pub unbound: u64,
    /// Signed checkpoints that hold, and the keys that signed them.
    pub checkpoints: u64,
    pub checkpoint_keys: Vec<String>,
    pub problems: u64,
    pub first_problems: Vec<Problem>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub ok: bool,
    /// Lines read, and those that aren't this schema's events (another source's, blank).
    pub lines: u64,
    pub ignored: u64,
    /// The checkpoint keys trusted, by id; empty when none were given.
    pub keys: Vec<String>,
    pub hosts: Vec<Host>,
    /// Lines that couldn't be read as events, so no host is known for them.
    pub unreadable: u64,
    pub first_unreadable: Vec<Problem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Copy {
    id: i64,
    prev: String,
    hash: String,
    has_digest: bool,
    bound: Result<Bound, String>,
    /// An `audit.checkpoint`'s details.
    checkpoint: Option<Value>,
    at: String,
}

/// Exported events read from any number of files, in any order, with copies, checked
/// against themselves alone: each line against its hash, the copies of each event
/// against each other, the chain from event to event, and the signed checkpoints.
pub struct Lines {
    keys: Option<Vec<Vec<u8>>>,
    hosts: BTreeMap<String, Vec<Copy>>,
    lines: u64,
    ignored: u64,
    unreadable: Vec<Problem>,
}

impl Lines {
    /// `keys`: the checkpoint keys to trust. None: any, so a checkpoint only shows the
    /// lines are consistent with whoever signed it.
    pub fn new(keys: Option<Vec<Vec<u8>>>) -> Lines {
        Lines { keys, hosts: BTreeMap::new(), lines: 0, ignored: 0, unreadable: Vec::new() }
    }

    /// One line, `at` saying where it came from. The event starts at its first `{`, so
    /// a syslog line, with RFC 5424's header before it, is read too.
    pub fn line(&mut self, text: &str, at: &str) {
        self.lines += 1;
        let text = text.trim();
        let Some(start) = text.find('{') else {
            self.ignored += 1;
            return;
        };
        let unreadable = |why: &str| Problem { id: None, at: at.to_string(), reason: "unreadable", error: format!("{at} {why}") };
        let v: Value = match serde_json::from_str(&text[start..]) {
            Ok(v) => v,
            Err(_) if text.contains(SCHEMA) => return self.unreadable.push(unreadable("names the schema but isn't JSON")),
            Err(_) => {
                self.ignored += 1;
                return;
            }
        };
        if v.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            self.ignored += 1;
            return;
        }
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        let (Some(id), Some(prev), Some(hash)) = (v.get("id").and_then(Value::as_i64), s("chainPrev"), s("chainHash")) else {
            return self.unreadable.push(unreadable("has no id, chainPrev or chainHash"));
        };
        let checkpoint = (v.get("action").and_then(Value::as_str) == Some(CHECKPOINT)).then(|| v.get("details").cloned().unwrap_or(Value::Null));
        let has_digest = v.get("chainDigest").is_some_and(|d| !d.is_null());
        let copy = Copy { id, prev, hash, has_digest, bound: check(&v), checkpoint, at: at.to_string() };
        self.hosts.entry(s("host").unwrap_or_default()).or_default().push(copy);
    }

    pub fn finish(self) -> Report {
        let keys = self.keys.as_deref();
        let hosts: Vec<Host> = self.hosts.into_iter().map(|(host, copies)| walk(host, copies, keys)).collect();
        let mut unreadable = self.unreadable;
        let error = hosts.is_empty().then(|| format!("no {SCHEMA} events in the {} lines read", self.lines));
        let ok = error.is_none() && unreadable.is_empty() && hosts.iter().all(|h| h.ok);
        let count = unreadable.len() as u64;
        unreadable.truncate(MAX_LISTED);
        Report {
            ok,
            lines: self.lines,
            ignored: self.ignored,
            keys: keys.unwrap_or_default().iter().map(|k| key_id(k)).collect(),
            hosts,
            unreadable: count,
            first_unreadable: unreadable,
            error,
        }
    }
}

fn walk(host: String, mut copies: Vec<Copy>, keys: Option<&[Vec<u8>]>) -> Host {
    copies.sort_by_key(|c| c.id);
    let mut h = Host { host, copies: copies.len() as u64, ..Default::default() };
    let mut problems: Vec<Problem> = Vec::new();
    let mut problem = |c: &Copy, reason: &'static str, error: String| problems.push(Problem { id: Some(c.id), at: c.at.clone(), reason, error });
    // botd exports every event after the first it gave a digest with one, to every sink.
    let digests_from = copies.iter().find(|c| c.has_digest).map(|c| c.id);
    let mut keys_seen = BTreeSet::new();
    let mut checkpoints = BTreeSet::new();
    let mut before: Option<&Copy> = None;
    for (i, c) in copies.iter().enumerate() {
        match &c.bound {
            Ok(Bound::All) => h.bound += 1,
            Ok(Bound::Fixed) => h.bound_fixed += 1,
            Ok(Bound::None) => h.unbound += 1,
            Err(e) => problem(c, "digest", format!("event {}: {e}", c.id)),
        }
        if let Some(from) = digests_from.filter(|&f| c.id >= f && !c.has_digest) {
            problem(c, "unbound", format!("event {} has no chainDigest, though every event from {from} on was exported with one: it was taken out, or this isn't botd's", c.id));
        }
        let first_copy = i == 0 || copies[i - 1].id != c.id;
        if !first_copy {
            let original = before.expect("an earlier copy");
            if (original.prev.as_str(), original.hash.as_str()) != (c.prev.as_str(), c.hash.as_str()) {
                problem(c, "conflict", format!("this copy of event {} has another chainPrev or chainHash than the one at {}", c.id, original.at));
            }
        }
        // The event before this one, when this links to it.
        let linked = match (first_copy, before) {
            (true, Some(b)) if b.hash != c.prev => {
                problem(c, "link", format!("event {} doesn't link to event {} before it: events between them are missing here, or these aren't botd's", c.id, b.id));
                None
            }
            (true, Some(b)) => Some(b.id),
            (true, None) => None,
            (false, _) => copies[..i].iter().rev().find(|p| p.id != c.id).filter(|p| p.hash == c.prev).map(|p| p.id),
        };
        if let Some(d) = &c.checkpoint {
            match check_checkpoint(Some(&c.prev), Some(d), linked, keys) {
                Ok(kid) => {
                    keys_seen.insert(kid);
                    checkpoints.insert(c.id);
                }
                Err((reason, e)) => problem(c, "checkpoint", format!("checkpoint {} ({reason}): {e}", c.id)),
            }
        }
        if first_copy {
            h.events += 1;
            before = Some(c);
        }
    }
    // A checkpoint counts once every copy of it holds.
    let failed: BTreeSet<i64> = problems.iter().filter(|p| p.reason == "checkpoint").filter_map(|p| p.id).collect();
    h.checkpoints = checkpoints.difference(&failed).count() as u64;
    h.checkpoint_keys = keys_seen.into_iter().collect();
    h.first = copies.first().map(|c| c.id);
    h.first_prev = copies.first().map(|c| c.prev.clone());
    h.head = copies.last().map(|c| Head { id: c.id, hash: c.hash.clone() });
    h.problems = problems.len() as u64;
    h.ok = problems.is_empty();
    problems.sort_by_key(|p| p.id);
    problems.truncate(MAX_LISTED);
    h.first_problems = problems;
    h
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    /// A line as the export writes it, sealed onto `prev` with `salt`.
    fn sealed(id: i64, prev: &str, details: Value, salt: Option<&str>) -> Value {
        let mut v = json!({
            "schema": SCHEMA, "host": "h1", "id": id, "at": 1_795_000_000_000i64 + id, "time": "x", "actorKind": "user", "actorId": "u1",
            "actorName": null, "actorSubject": null, "action": "test.x", "targetType": null, "targetId": null, "botId": null, "outcome": "success",
            "ip": "192.0.2.1", "userAgent": null, "details": details, "actorEmail": "ada@example.com", "actorRole": "admin", "authMethod": "sso",
            "idp": null, "idpProvider": null, "sessionId": null, "onBehalfOf": null, "chainPrev": prev,
        });
        let d = digest(salt.unwrap_or("s"), &v);
        v["chainHash"] = json!(link(prev, &v, &d));
        v["chainDigest"] = json!(d);
        if let Some(s) = salt {
            v["chainSalt"] = json!(s);
        }
        v
    }

    pub fn chain(n: i64) -> Vec<Value> {
        let mut prev = GENESIS.to_string();
        (1..=n)
            .map(|id| {
                let v = sealed(id, &prev, json!({ "n": id }), Some(&format!("salt{id}")));
                prev = v["chainHash"].as_str().unwrap().to_string();
                v
            })
            .collect()
    }

    fn report(lines: &[Value], keys: Option<Vec<Vec<u8>>>) -> Report {
        let mut l = Lines::new(keys);
        for (n, v) in lines.iter().enumerate() {
            l.line(&v.to_string(), &format!("f:{}", n + 1));
        }
        l.finish()
    }

    fn reasons(r: &Report) -> Vec<&'static str> {
        r.hosts.iter().flat_map(|h| h.first_problems.iter().map(|p| p.reason)).collect()
    }

    #[test]
    fn a_line_is_its_own_proof() {
        let v = sealed(1, GENESIS, json!({ "name": "Scout", "nested": { "b": [1, 2.5, null] } }), Some("ab12"));
        assert_eq!(check(&v), Ok(Bound::All));
        // Any field an erasure may rewrite, changed: the digest no longer follows.
        for (field, value) in [("actorEmail", json!("eve@example.com")), ("details", json!({ "name": "Other" })), ("ip", Value::Null)] {
            let mut forged = v.clone();
            forged[field] = value;
            assert!(check(&forged).unwrap_err().contains("chainDigest isn't the digest"), "{field}");
        }
        // Any field none may change, or the link: the hash no longer follows.
        for (field, value) in [("action", json!("test.y")), ("outcome", json!("failure")), ("at", json!(1)), ("id", json!("1")), ("chainPrev", json!("1".repeat(64)))] {
            let mut forged = v.clone();
            forged[field] = value;
            assert!(check(&forged).unwrap_err().contains("chainHash isn't the hash"), "{field}");
        }
        // Without its salt, only the fields no erasure may change are vouched for.
        let mut unsalted = v.clone();
        unsalted.as_object_mut().unwrap().remove("chainSalt");
        assert_eq!(check(&unsalted), Ok(Bound::Fixed));
        unsalted["actorEmail"] = json!("x-pseudonym");
        assert_eq!(check(&unsalted), Ok(Bound::Fixed));
        unsalted["action"] = json!("test.y");
        assert!(check(&unsalted).is_err());
        // Fields botd doesn't hash, such as the time as text and the host, don't count.
        let mut extra = v.clone();
        extra["time"] = json!("later");
        extra["checkpoint"] = json!({ "any": 1 });
        assert_eq!(check(&extra), Ok(Bound::All));
        let mut old = v;
        for k in ["chainDigest", "chainSalt"] {
            old.as_object_mut().unwrap().remove(k);
        }
        assert_eq!(check(&old), Ok(Bound::None), "exported before ADR 0199");
    }

    #[test]
    fn lines_in_any_order_with_copies_hold() {
        let mut lines = chain(5);
        lines.reverse();
        lines.push(lines[2].clone());
        let r = report(&lines, None);
        assert!(r.ok, "{r:?}");
        let h = &r.hosts[0];
        assert_eq!((h.events, h.copies, h.bound, h.first, h.head.as_ref().map(|h| h.id)), (5, 6, 6, Some(1), Some(5)));
        assert_eq!(h.first_prev.as_deref(), Some(GENESIS));
        // Another source's lines, and blank ones, are left alone; a syslog header is fine.
        let mut l = Lines::new(None);
        l.line("", "a:1");
        l.line("not an event", "a:2");
        l.line(r#"{"other":"schema"}"#, "a:3");
        l.line(&format!("<110>1 2026-11-23T00:00:00.000Z h1 superbot 1 test.x - {}", chain(1)[0]), "a:4");
        let r = l.finish();
        assert_eq!((r.ok, r.lines, r.ignored, r.hosts[0].events), (true, 4, 3, 1), "{r:?}");
        // Nothing to check is a failure, not a pass.
        let r = report(&[], None);
        assert!(!r.ok && r.error.unwrap().contains("no superbot.audit.v1 events"));
    }

    #[test]
    fn a_changed_missing_or_stripped_event_is_named() {
        let lines = chain(6);
        let mut changed = lines.clone();
        changed[2]["details"] = json!({ "n": 99 });
        let r = report(&changed, None);
        assert_eq!((r.ok, reasons(&r), r.hosts[0].first_problems[0].id), (false, vec!["digest"], Some(3)), "{r:?}");
        assert_eq!(r.hosts[0].first_problems[0].at, "f:3");
        let mut gone = lines.clone();
        gone.remove(3);
        assert_eq!(reasons(&report(&gone, None)), ["link"]);
        // Copies that disagree: a fork, whichever is read first.
        let mut forked = lines.clone();
        forked.push(sealed(4, "1".repeat(64).as_str(), json!({}), Some("x")));
        assert_eq!(reasons(&report(&forked, None)), ["conflict"]);
        // Taking the digest out of a copy, to change it unseen, once events carry one.
        let mut stripped = lines.clone();
        let mut copy = lines[4].clone();
        copy.as_object_mut().unwrap().remove("chainDigest");
        copy["details"] = json!({ "n": "forged" });
        stripped.insert(0, copy);
        let r = report(&stripped, None);
        assert_eq!((reasons(&r), r.hosts[0].unbound), (vec!["unbound"], 1), "{r:?}");
        // Events from before digests were exported have none, and that's fine.
        let mut older = lines;
        for v in &mut older[..2] {
            v.as_object_mut().unwrap().remove("chainDigest");
            v.as_object_mut().unwrap().remove("chainSalt");
        }
        let r = report(&older, None);
        assert_eq!((r.ok, r.hosts[0].unbound, r.hosts[0].bound), (true, 2, 4), "{r:?}");
        // A line naming the schema that isn't one of its events.
        let mut l = Lines::new(None);
        l.line(r#"{"schema":"superbot.audit.v1","id":1}"#, "g:1");
        l.line(r#"{"schema":"superbot.audit.v1", broken"#, "g:2");
        let r = l.finish();
        assert_eq!((r.ok, r.unreadable), (false, 2), "{r:?}");
    }

    #[test]
    fn hosts_are_chains_of_their_own() {
        let mut lines = chain(3);
        let mut other = chain(2);
        for v in &mut other {
            v["host"] = json!("h2");
        }
        lines.extend(other);
        let r = report(&lines, None);
        assert!(r.ok, "{r:?}");
        assert_eq!(r.hosts.iter().map(|h| (h.host.as_str(), h.events)).collect::<Vec<_>>(), [("h1", 3), ("h2", 2)]);
    }

    fn checkpoint(id: i64, prev: &Value, pair: &aws_lc_rs::signature::Ed25519KeyPair) -> Value {
        use aws_lc_rs::signature::KeyPair;
        let public = pair.public_key().as_ref().to_vec();
        let (kid, seq, hash, at) = (key_id(&public), prev["id"].as_i64().unwrap(), prev["chainHash"].as_str().unwrap(), 1_795_000_000_000i64);
        let sig = hex(pair.sign(statement(seq, hash, at, &kid).as_bytes()).as_ref());
        let mut v = sealed(id, hash, json!({ "seq": seq, "hash": hash, "at": at, "keyId": kid, "publicKey": hex(&public), "signature": sig }), Some("cp"));
        v["action"] = json!(CHECKPOINT);
        let d = digest("cp", &v);
        v["chainHash"] = json!(link(hash, &v, &d));
        v["chainDigest"] = json!(d);
        v
    }

    #[test]
    fn checkpoints_hold_under_the_keys_trusted() {
        let pair = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        use aws_lc_rs::signature::KeyPair;
        let public = pair.public_key().as_ref().to_vec();
        let mut lines = chain(3);
        lines.push(checkpoint(4, &lines[2], &pair));
        let r = report(&lines, None);
        assert_eq!((r.ok, r.hosts[0].checkpoints, r.hosts[0].checkpoint_keys.clone()), (true, 1, vec![key_id(&public)]), "{r:?}");
        let r = report(&lines, Some(vec![public.clone()]));
        assert_eq!((r.ok, r.keys.clone()), (true, vec![key_id(&public)]), "{r:?}");
        let r = report(&lines, Some(vec![vec![1; 32]]));
        assert_eq!(reasons(&r), ["checkpoint"]);
        assert!(r.hosts[0].first_problems[0].error.contains("(key)"), "{r:?}");
        // Numbered for an event other than the one before it.
        let mut wrong = chain(3);
        let mut cp = checkpoint(4, &wrong[1], &pair);
        cp["chainPrev"] = wrong[2]["chainHash"].clone();
        wrong.push(cp);
        let r = report(&wrong, None);
        assert!(reasons(&r).contains(&"checkpoint"), "{r:?}");
        assert!(check_checkpoint(Some("x"), None, None, None).unwrap_err().0 == "malformed");
    }

    #[test]
    fn keys_parse() {
        assert_eq!(parse_public_key(&"ab".repeat(32)).unwrap(), vec![0xab; 32]);
        for bad in ["ab", "zz".repeat(32).as_str(), "ab".repeat(33).as_str()] {
            assert!(parse_public_key(bad).is_err(), "{bad}");
        }
    }
}
