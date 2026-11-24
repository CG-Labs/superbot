//! An exported audit event checked against nothing but itself (ADR 0199).
//!
//! Every event the export writes carries `chainDigest`, and `chainSalt` when the line
//! says everything the salted digest covers, so its `chainHash` can be worked out again
//! from the line alone: the fields no erasure may change, `chainPrev` and the digest give
//! the hash, and the salt with the fields an erasure may rewrite gives the digest. A copy
//! kept anywhere (the write-once archive, a SIEM, a file an auditor downloaded) can then
//! be checked after botd's retention has deleted the row, and without botd at all.
//!
//! A checkpoint's RFC 3161 timestamp is checked from its line too (ADR 0207): the token
//! the line carries must be the one its event recorded, stamp that checkpoint's signed
//! statement, and verify under the TSA's certificate, at the time its event says.
//!
//! Shared by botd (the export and the archive check) and botctl (`botctl audit
//! verify-lines`), so it uses nothing from botd's crate but [`crate::tsa`], which both build.

use crate::tsa;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "superbot.audit.v1";
/// A piece of a line too long for where it went whole (ADR 0217), as [`parts`] writes it.
pub const PART_SCHEMA: &str = "superbot.audit.part.v1";
/// The most pieces a line is read back from.
const MAX_PARTS: u64 = 10_000;
/// The link before the first event of a log that has never been pruned.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const CHECKPOINT: &str = "audit.checkpoint";
pub const TIMESTAMPED: &str = "audit.checkpoint_timestamped";
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

/// Whether `bytes` begin as gzip does (RFC 1952).
pub fn gzipped(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

/// `bytes` gzipped, as the export compresses request bodies and archive objects (ADR 0227).
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::with_capacity(bytes.len() / 4), flate2::Compression::default());
    gz.write_all(bytes).and_then(|()| gz.finish()).expect("gzip into memory")
}

/// `bytes` gunzipped, every member in turn (`cat a.gz b.gz` too), at most `max` bytes of
/// them: more, or anything after a member that isn't another, is an error.
pub fn gunzip(bytes: &[u8], max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(bytes).take(max.saturating_add(1)).read_to_end(&mut out).map_err(|e| format!("it isn't gzip, or is cut short ({e})"))?;
    if out.len() as u64 > max {
        return Err(format!("it holds more than {max} bytes uncompressed"));
    }
    Ok(out)
}

/// `text`, the exported line of event `id` from `host`, as pieces of at most `size` bytes
/// of it each, split between characters, every piece a JSON object of its own:
/// `{"schema":"superbot.audit.part.v1","id":..,"host":..,"part":1,"parts":n,"text":..}`.
/// [`Lines`] joins the texts in order and reads the line they make.
pub fn parts(id: i64, host: &str, text: &str, size: usize) -> Vec<String> {
    let mut texts = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = size.min(rest.len()).max(1);
        while !rest.is_char_boundary(end) {
            end += 1;
        }
        let (piece, more) = rest.split_at(end);
        texts.push(piece);
        rest = more;
    }
    let n = texts.len();
    texts.iter().enumerate().map(|(i, t)| serde_json::json!({ "schema": PART_SCHEMA, "id": id, "host": host, "part": i + 1, "parts": n, "text": t }).to_string()).collect()
}

/// The pieces of one line read so far.
struct Pieces {
    parts: u64,
    texts: BTreeMap<u64, String>,
    at: String,
    /// Two pieces disagree: the same piece with other text, or another count.
    differ: bool,
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

/// What a checkpoint's RFC 3161 token stamps: SHA-256 of its statement, `\nsig=` and its
/// signature (ADR 0149).
pub fn imprint(statement: &str, signature: &str) -> [u8; 32] {
    Sha256::digest(format!("{statement}\nsig={signature}").as_bytes()).into()
}

/// What an `audit.checkpoint_timestamped` line's token says, once it holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Stamped {
    pub checkpoint: i64,
    /// The TSA's time, unix ms.
    pub time: i64,
    /// Whether the TSA's certificate chains to the CAs given; None when none were.
    pub trusted: Option<bool>,
}

/// Checks an `audit.checkpoint_timestamped` line's token (ADR 0207). Its `details`, which
/// its hash covers, name the checkpoint and record the token's SHA-256 and time; its
/// `checkpoint` object, which the export adds and no hash covers, carries the token. The
/// token must be the one recorded, stamp the checkpoint's statement and signature, and
/// verify under the TSA's certificate (chaining to `trust`, when set) at the time recorded.
/// `signed` is the checkpoint's own event's details when that was read; otherwise the
/// statement and signature come from the record the line carries, which must then be
/// signed by one of `keys` (with None, the key it names). Errors are a reason (`malformed`,
/// `token`, `record`, a checkpoint's `key` or `signature`, or the token's own: `imprint`,
/// `signature`, `certificate`, `untrusted`, ...) and why.
pub fn check_timestamp(line: &Value, signed: Option<&Value>, keys: Option<&[Vec<u8>]>, trust: &tsa::Trust) -> Result<Stamped, (&'static str, String)> {
    let malformed = |what: &str| ("malformed", format!("its {what} is missing"));
    let d = line.get("details").filter(|d| d.is_object()).ok_or_else(|| malformed("details"))?;
    let id = d["checkpoint"].as_i64().ok_or_else(|| malformed("checkpoint id"))?;
    let (seq, hash) = (d["seq"].as_i64().ok_or_else(|| malformed("seq"))?, d["hash"].as_str().ok_or_else(|| malformed("hash"))?);
    let time = d["time"].as_i64().ok_or_else(|| malformed("time"))?;
    let recorded = d["timestampSha256"].as_str().ok_or_else(|| malformed("timestampSha256"))?;
    let record = line.get("checkpoint").filter(|c| c.is_object()).ok_or(("token", "it carries no token: the export sends the checkpoint's record, with it, as `checkpoint`".to_string()))?;
    if record["id"].as_i64() != Some(id) || record["seq"].as_i64() != Some(seq) || record["hash"].as_str() != Some(hash) {
        return Err(("record", format!("the record it carries isn't checkpoint {id}'s, which signs event {seq}")));
    }
    const SIGNED_FIELDS: [&str; 6] = ["seq", "hash", "at", "keyId", "publicKey", "signature"];
    if let Some(s) = signed
        && SIGNED_FIELDS.iter().any(|f| s.get(*f) != record.get(*f))
    {
        return Err(("record", format!("the record it carries differs from checkpoint {id}'s own event")));
    }
    let c = signed.unwrap_or(record);
    check_checkpoint(Some(hash), Some(c), None, keys).map_err(|(r, e)| (r, format!("checkpoint {id}: {e}")))?;
    let (at, kid, signature) = (c["at"].as_i64().unwrap_or_default(), c["keyId"].as_str().unwrap_or_default(), c["signature"].as_str().unwrap_or_default());
    let stamp = &record["timestamp"];
    let token = stamp["token"].as_str().and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok()).ok_or(("token", "the token it carries is missing or isn't base64".to_string()))?;
    if hex(&Sha256::digest(&token)) != recorded {
        return Err(("record", "the token it carries isn't the one its event recorded".into()));
    }
    let nonce = stamp["nonce"].as_str().and_then(unhex);
    let s = tsa::verify(&token, &imprint(&statement(seq, hash, at, kid), signature), nonce.as_deref(), trust).map_err(|e| (e.code, e.message))?;
    if s.time != time {
        return Err(("record", "the token's time isn't the one its event recorded".into()));
    }
    if d.get("tsaCert").and_then(Value::as_str).is_some_and(|c| c != s.tsa_cert) {
        return Err(("record", "the token's TSA certificate isn't the one its event recorded".into()));
    }
    Ok(Stamped { checkpoint: id, time: s.time, trusted: s.trusted })
}

/// Something in the lines that doesn't hold: `unreadable` (a line that names the schema
/// but isn't one of its events), `digest` (its hash doesn't follow from what it says),
/// `unbound` (no `chainDigest`, after an event that had one: every event botd exports
/// after the first with one has one), `conflict` (two copies of an event with different
/// links), `link` (an event doesn't link to the one before: events are missing, or
/// aren't botd's), `checkpoint` or `timestamp`.
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

/// The newest timestamp that holds: its event, the checkpoint it stamps, and the TSA's time.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastStamp {
    pub id: i64,
    pub checkpoint: i64,
    pub time: i64,
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
    /// RFC 3161 timestamps whose token holds (ADR 0207), those whose TSA chains to the CAs
    /// given (None when none were), and the newest.
    pub timestamps: u64,
    pub trusted_timestamps: Option<u64>,
    pub last_timestamp: Option<LastStamp>,
    /// Checkpoints made with a TSA set whose timestamp isn't among the lines: still waiting
    /// for one, or stamped after the last line read. Not a failure.
    pub unstamped: u64,
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
    /// The CA certificates a timestamp's TSA must chain to; 0 when none were given.
    pub timestamp_cas: usize,
    /// The `digestsAfter` given, if any.
    pub digests_after: Option<i64>,
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
    /// An `audit.checkpoint_timestamped`'s whole line: its details and the token it carries.
    timestamp: Option<Value>,
    at: String,
}

/// Exported events read from any number of files, in any order, with copies, checked
/// against themselves alone: each line against its hash, the copies of each event
/// against each other, the chain from event to event, the signed checkpoints and their
/// timestamps.
pub struct Lines {
    keys: Option<Vec<Vec<u8>>>,
    trust: tsa::Trust,
    digests_after: Option<i64>,
    hosts: BTreeMap<String, Vec<Copy>>,
    /// Pieces of long lines ([`parts`]), by host and event.
    pieces: BTreeMap<(String, i64), Pieces>,
    lines: u64,
    ignored: u64,
    unreadable: Vec<Problem>,
}

impl Lines {
    /// `keys`: the checkpoint keys to trust. None: any, so a checkpoint only shows the
    /// lines are consistent with whoever signed it.
    pub fn new(keys: Option<Vec<Vec<u8>>>) -> Lines {
        Lines { keys, trust: tsa::Trust::default(), digests_after: None, hosts: BTreeMap::new(), pieces: BTreeMap::new(), lines: 0, ignored: 0, unreadable: Vec::new() }
    }

    /// The CAs a timestamp's TSA must chain to. Without any, a token is checked as far as
    /// it can be, and counted as neither trusted nor not.
    pub fn trust(mut self, trust: tsa::Trust) -> Lines {
        self.trust = trust;
        self
    }

    /// Where botd's events start carrying `chainDigest` (`digestsAfter`), kept apart from
    /// the lines. Without it, that is worked out from the first line with one, so lines
    /// stripped of every digest bind nothing and still pass.
    pub fn digests_after(mut self, after: Option<i64>) -> Lines {
        self.digests_after = after;
        self
    }

    /// One line, `at` saying where it came from. The event starts at its first `{`, so
    /// a syslog line, with RFC 5424's header before it, is read too.
    pub fn line(&mut self, text: &str, at: &str) {
        self.lines += 1;
        self.read(text, at);
    }

    fn read(&mut self, text: &str, at: &str) {
        let text = text.trim();
        let Some(start) = text.find('{') else {
            self.ignored += 1;
            return;
        };
        let unreadable = |why: &str| Problem { id: None, at: at.to_string(), reason: "unreadable", error: format!("{at} {why}") };
        let v: Value = match serde_json::from_str(&text[start..]) {
            Ok(v) => v,
            Err(_) if text.contains(SCHEMA) || text.contains(PART_SCHEMA) => return self.unreadable.push(unreadable("names the schema but isn't JSON")),
            Err(_) => {
                self.ignored += 1;
                return;
            }
        };
        if v.get("schema").and_then(Value::as_str) == Some(PART_SCHEMA) {
            return self.piece(&v, at);
        }
        if v.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            self.ignored += 1;
            return;
        }
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        let (Some(id), Some(prev), Some(hash)) = (v.get("id").and_then(Value::as_i64), s("chainPrev"), s("chainHash")) else {
            return self.unreadable.push(unreadable("has no id, chainPrev or chainHash"));
        };
        let action = v.get("action").and_then(Value::as_str);
        let checkpoint = (action == Some(CHECKPOINT)).then(|| v.get("details").cloned().unwrap_or(Value::Null));
        let has_digest = v.get("chainDigest").is_some_and(|d| !d.is_null());
        let bound = check(&v);
        let host = s("host").unwrap_or_default();
        let timestamp = (action == Some(TIMESTAMPED)).then_some(v);
        let copy = Copy { id, prev, hash, has_digest, bound, checkpoint, timestamp, at: at.to_string() };
        self.hosts.entry(host).or_default().push(copy);
    }

    /// One piece of a long line, kept until [`Lines::finish`] has them all. Copies of a
    /// piece, as a retried delivery leaves, count once.
    fn piece(&mut self, v: &Value, at: &str) {
        let (id, host, part, parts, text) = (v["id"].as_i64(), v["host"].as_str(), v["part"].as_u64(), v["parts"].as_u64(), v["text"].as_str());
        let (Some(id), Some(host), Some(part), Some(parts), Some(text)) = (id, host, part, parts, text) else {
            return self.unreadable.push(Problem { id: None, at: at.to_string(), reason: "unreadable", error: format!("{at} is a piece of a line without its id, host, part, parts or text") });
        };
        if !(1..=MAX_PARTS).contains(&parts) || !(1..=parts).contains(&part) {
            return self.unreadable.push(Problem { id: Some(id), at: at.to_string(), reason: "unreadable", error: format!("{at} is piece {part} of {parts} of event {id}'s line") });
        }
        let p = self.pieces.entry((host.to_string(), id)).or_insert_with(|| Pieces { parts, texts: BTreeMap::new(), at: at.to_string(), differ: false });
        p.differ |= p.parts != parts;
        match p.texts.get(&part) {
            Some(t) => p.differ |= t != text,
            None => {
                p.texts.insert(part, text.to_string());
            }
        }
    }

    pub fn finish(mut self) -> Report {
        for ((_, id), p) in std::mem::take(&mut self.pieces) {
            let problem = |error: String| Problem { id: Some(id), at: p.at.clone(), reason: "unreadable", error };
            if p.differ {
                self.unreadable.push(problem(format!("{} has pieces of event {id}'s line that disagree", p.at)));
            } else if p.texts.len() as u64 != p.parts {
                self.unreadable.push(problem(format!("{} has {} of the {} pieces of event {id}'s line", p.at, p.texts.len(), p.parts)));
            } else {
                let whole: String = p.texts.into_values().collect();
                self.read(&whole, &p.at);
            }
        }
        let keys = self.keys.as_deref();
        let after = self.digests_after;
        let trust = &self.trust;
        let hosts: Vec<Host> = self.hosts.into_iter().map(|(host, copies)| walk(host, copies, keys, trust, after)).collect();
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
            timestamp_cas: trust.len(),
            digests_after: after,
            hosts,
            unreadable: count,
            first_unreadable: unreadable,
            error,
        }
    }
}

fn walk(host: String, mut copies: Vec<Copy>, keys: Option<&[Vec<u8>]>, trust: &tsa::Trust, after: Option<i64>) -> Host {
    copies.sort_by_key(|c| c.id);
    let mut h = Host { host, copies: copies.len() as u64, ..Default::default() };
    let mut problems: Vec<Problem> = Vec::new();
    let mut problem = |c: &Copy, reason: &'static str, error: String| problems.push(Problem { id: Some(c.id), at: c.at.clone(), reason, error });
    // botd exports every event after the marker with a digest, to every sink.
    let inferred = copies.iter().find(|c| c.has_digest).map(|c| c.id - 1);
    let digests_after = match (after, inferred) {
        (Some(a), Some(i)) => Some(a.min(i)),
        (a, i) => a.or(i),
    };
    let mut keys_seen = BTreeSet::new();
    let mut checkpoints = BTreeSet::new();
    // Each checkpoint's details as its first copy has them, those made with a TSA set,
    // the checkpoints a timestamp names, and each timestamp that holds.
    let mut signed: BTreeMap<i64, &Value> = BTreeMap::new();
    let mut asked: BTreeSet<i64> = BTreeSet::new();
    let mut named: BTreeSet<i64> = BTreeSet::new();
    let mut stamps: BTreeMap<i64, Stamped> = BTreeMap::new();
    // The last event read, and the one before it, for the copies after the first.
    let (mut before, mut prior): (Option<&Copy>, Option<&Copy>) = (None, None);
    for (i, c) in copies.iter().enumerate() {
        match &c.bound {
            Ok(Bound::All) => h.bound += 1,
            Ok(Bound::Fixed) => h.bound_fixed += 1,
            Ok(Bound::None) => h.unbound += 1,
            Err(e) => problem(c, "digest", format!("event {}: {e}", c.id)),
        }
        if let Some(after) = digests_after.filter(|&a| c.id > a && !c.has_digest) {
            problem(c, "unbound", format!("event {} has no chainDigest, though every event after {after} was exported with one: it was taken out, or this isn't botd's", c.id));
        }
        let first_copy = i == 0 || copies[i - 1].id != c.id;
        if first_copy {
            prior = before;
        }
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
            (false, _) => prior.filter(|p| p.hash == c.prev).map(|p| p.id),
        };
        if let Some(d) = &c.checkpoint {
            match check_checkpoint(Some(&c.prev), Some(d), linked, keys) {
                Ok(kid) => {
                    keys_seen.insert(kid);
                    checkpoints.insert(c.id);
                }
                Err((reason, e)) => problem(c, "checkpoint", format!("checkpoint {} ({reason}): {e}", c.id)),
            }
            if first_copy {
                signed.insert(c.id, d);
                if d.get("timestamp").and_then(Value::as_str) == Some("pending") {
                    asked.insert(c.id);
                }
            }
        }
        // A checkpoint comes before its timestamp, so its own event, if read, is in `signed`.
        if let Some(line) = &c.timestamp {
            let cp = line.get("details").and_then(|d| d.get("checkpoint")).and_then(Value::as_i64);
            named.extend(cp);
            match check_timestamp(line, cp.and_then(|id| signed.get(&id).copied()), keys, trust) {
                Ok(s) => {
                    stamps.entry(c.id).or_insert(s);
                }
                Err((reason, e)) => problem(c, "timestamp", format!("timestamp {} ({reason}): {e}", c.id)),
            }
        }
        if first_copy {
            h.events += 1;
            before = Some(c);
        }
    }
    // A checkpoint, or a timestamp, counts once every copy of it holds.
    let failed = |reason: &str| -> BTreeSet<i64> { problems.iter().filter(|p| p.reason == reason).filter_map(|p| p.id).collect() };
    let (failed_checkpoints, failed_stamps) = (failed("checkpoint"), failed("timestamp"));
    h.checkpoints = checkpoints.difference(&failed_checkpoints).count() as u64;
    h.checkpoint_keys = keys_seen.into_iter().collect();
    stamps.retain(|id, _| !failed_stamps.contains(id));
    h.timestamps = stamps.len() as u64;
    h.trusted_timestamps = trust.is_set().then(|| stamps.values().filter(|s| s.trusted == Some(true)).count() as u64);
    h.last_timestamp = stamps.iter().next_back().map(|(id, s)| LastStamp { id: *id, checkpoint: s.checkpoint, time: s.time });
    h.unstamped = asked.difference(&named).count() as u64;
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

    /// 16 random bytes as hex, as each row's salt is.
    fn fresh_salt() -> String {
        let mut b = [0u8; 16];
        aws_lc_rs::rand::fill(&mut b).unwrap();
        hex(&b)
    }

    /// A line as the export writes it, sealed onto `prev` under a fresh salt, which it
    /// carries when `salted`.
    fn sealed(id: i64, prev: &str, details: Value, salted: bool) -> Value {
        let mut v = json!({
            "schema": SCHEMA, "host": "h1", "id": id, "at": 1_795_000_000_000i64 + id, "time": "x", "actorKind": "user", "actorId": "u1",
            "actorName": null, "actorSubject": null, "action": "test.x", "targetType": null, "targetId": null, "botId": null, "outcome": "success",
            "ip": "192.0.2.1", "userAgent": null, "details": details, "actorEmail": "ada@example.com", "actorRole": "admin", "authMethod": "sso",
            "idp": null, "idpProvider": null, "sessionId": null, "onBehalfOf": null, "chainPrev": prev,
        });
        reseal(&mut v, prev, &fresh_salt(), salted);
        v
    }

    fn reseal(v: &mut Value, prev: &str, salt: &str, salted: bool) {
        let d = digest(salt, v);
        v["chainHash"] = json!(link(prev, v, &d));
        v["chainDigest"] = json!(d);
        if salted {
            v["chainSalt"] = json!(salt);
        }
    }

    pub fn chain(n: i64) -> Vec<Value> {
        let mut prev = GENESIS.to_string();
        (1..=n)
            .map(|id| {
                let v = sealed(id, &prev, json!({ "n": id }), true);
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
    fn gzip_comes_back_whole_and_no_bigger_than_allowed() {
        let text = "{\"schema\":\"superbot.audit.v1\"}\n".repeat(100);
        let gz = gzip(text.as_bytes());
        assert!(gzipped(&gz) && !gzipped(text.as_bytes()) && gz.len() * 10 < text.len(), "{} bytes", gz.len());
        assert_eq!(gunzip(&gz, text.len() as u64).unwrap(), text.as_bytes());
        let mut two = gz.clone();
        two.extend(gzip(b"more\n"));
        assert_eq!(gunzip(&two, u64::MAX).unwrap(), format!("{text}more\n").as_bytes(), "every member, in turn");
        let e = gunzip(&gz, text.len() as u64 - 1).unwrap_err();
        assert!(e.contains(&format!("more than {} bytes uncompressed", text.len() - 1)), "{e}");
        assert!(gunzip(b"plain text", u64::MAX).unwrap_err().contains("isn't gzip"));
        assert!(gunzip(&[], u64::MAX).unwrap_err().contains("isn't gzip"), "an empty object holds no gzip member");
    }

    #[test]
    fn a_line_is_its_own_proof() {
        let v = sealed(1, GENESIS, json!({ "name": "Scout", "nested": { "b": [1, 2.5, null] } }), true);
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
        forked.push(sealed(4, "1".repeat(64).as_str(), json!({}), true));
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
        // Every digest taken out, and an event changed: nothing in the lines says they
        // had any, so only `digestsAfter` kept apart from them catches it.
        let mut bare = chain(6);
        for v in &mut bare {
            v.as_object_mut().unwrap().remove("chainDigest");
            v.as_object_mut().unwrap().remove("chainSalt");
        }
        bare[3]["details"] = json!({ "n": "forged" });
        assert!(report(&bare, None).ok, "the limit --digests-after closes");
        let mut l = Lines::new(None).digests_after(Some(2));
        for (n, v) in bare.iter().enumerate() {
            l.line(&v.to_string(), &format!("f:{}", n + 1));
        }
        let r = l.finish();
        assert_eq!((r.ok, r.digests_after, r.hosts[0].problems, reasons(&r)[0]), (false, Some(2), 4, "unbound"), "{r:?}");
        assert_eq!(r.hosts[0].first_problems[0].id, Some(3), "{r:?}");
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
        let details = json!({ "seq": seq, "hash": hash, "at": at, "keyId": kid, "publicKey": hex(&public), "signature": sig, "trigger": "schedule", "timestamp": "pending" });
        let mut v = sealed(id, hash, details, false);
        v["action"] = json!(CHECKPOINT);
        reseal(&mut v, hash, &fresh_salt(), true);
        v
    }

    /// The `audit.checkpoint_timestamped` line the export writes for checkpoint `cp`, with
    /// a token from `tsa` at `time`, sealed onto `prev`.
    pub fn timestamped(id: i64, cp: &Value, prev: &str, tsa: &tsa::fake::FakeTsa, time: i64) -> Value {
        let d = &cp["details"];
        let (seq, hash, at, kid, sig) = (d["seq"].as_i64().unwrap(), d["hash"].as_str().unwrap(), d["at"].as_i64().unwrap(), d["keyId"].as_str().unwrap(), d["signature"].as_str().unwrap());
        let st = statement(seq, hash, at, kid);
        let stamped = imprint(&st, sig);
        let nonce = [0x41u8; 8];
        let token = tsa.token(&stamped, Some(&nonce), time);
        let details = json!({
            "checkpoint": cp["id"], "seq": seq, "hash": hash, "tsa": "tsa.example", "time": time, "serial": "01", "policy": "1.2.3.4.1",
            "tsaCert": hex(&Sha256::digest(&tsa.leaf)), "tsaSubject": "CN=Test TSA", "trusted": null, "timestampSha256": hex(&Sha256::digest(&token)),
        });
        let mut v = sealed(id, prev, details, false);
        v["action"] = json!(TIMESTAMPED);
        reseal(&mut v, prev, &fresh_salt(), true);
        v["checkpoint"] = json!({
            "id": cp["id"], "seq": seq, "hash": hash, "at": at, "keyId": kid, "publicKey": d["publicKey"], "signature": sig, "statement": st, "algorithm": "Ed25519",
            "timestamp": { "status": "stamped", "tsa": "tsa.example", "time": time, "token": base64::engine::general_purpose::STANDARD.encode(&token), "nonce": hex(&nonce), "imprint": hex(&stamped) },
        });
        v
    }

    /// The key [`stamped_chain`] signs its checkpoint with.
    pub fn checkpoint_key() -> aws_lc_rs::signature::Ed25519KeyPair {
        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    pub const STAMPED_AT: i64 = 1_795_000_060_000;

    /// Three events, a checkpoint of them (4), another event, and the checkpoint's timestamp (6).
    pub fn stamped_chain(tsa: &tsa::fake::FakeTsa) -> Vec<Value> {
        let mut lines = chain(3);
        lines.push(checkpoint(4, &lines[2], &checkpoint_key()));
        lines.push(sealed(5, lines[3]["chainHash"].as_str().unwrap(), json!({ "n": 5 }), true));
        let ts = timestamped(6, &lines[3], lines[4]["chainHash"].as_str().unwrap(), tsa, STAMPED_AT);
        lines.push(ts);
        lines
    }

    fn report_with(lines: &[Value], keys: Option<Vec<Vec<u8>>>, trust: tsa::Trust) -> Report {
        let mut l = Lines::new(keys).trust(trust);
        for (n, v) in lines.iter().enumerate() {
            l.line(&v.to_string(), &format!("f:{}", n + 1));
        }
        l.finish()
    }

    #[test]
    fn timestamps_are_checked_from_their_lines() {
        use aws_lc_rs::signature::KeyPair;
        use tsa::fake::FakeTsa;
        let fake = FakeTsa::new();
        let public = checkpoint_key().public_key().as_ref().to_vec();
        let keys = || Some(vec![public.clone()]);
        let lines = stamped_chain(&fake);
        let first = |r: &Report| r.hosts[0].first_problems.first().map(|p| p.error.clone()).unwrap_or_default();

        // No CA given: the token holds under the certificate it carries, and isn't called trusted.
        let r = report(&lines, keys());
        let h = &r.hosts[0];
        assert!(r.ok, "{r:?}");
        assert_eq!((h.checkpoints, h.timestamps, h.trusted_timestamps, h.unstamped, r.timestamp_cas), (1, 1, None, 0, 0), "{r:?}");
        assert_eq!(h.last_timestamp, Some(LastStamp { id: 6, checkpoint: 4, time: STAMPED_AT }));
        // The TSA's CA: trusted. Another TSA's: not.
        let r = report_with(&lines, keys(), tsa::Trust::from_pem(&fake.ca_pem).unwrap());
        assert_eq!((r.ok, r.hosts[0].trusted_timestamps, r.timestamp_cas), (true, Some(1), 1), "{r:?}");
        let r = report_with(&lines, keys(), tsa::Trust::from_pem(&FakeTsa::new().ca_pem).unwrap());
        assert_eq!((reasons(&r), r.hosts[0].timestamps), (vec!["timestamp"], 0), "{r:?}");
        assert!(first(&r).contains("(untrusted)"), "{r:?}");

        // No hash covers the token the line carries, but its event recorded its SHA-256.
        let mut swapped = lines.clone();
        swapped[5]["checkpoint"]["timestamp"]["token"] = json!(base64::engine::general_purpose::STANDARD.encode(fake.token(&[0; 32], None, STAMPED_AT)));
        let r = report(&swapped, keys());
        assert_eq!(reasons(&r), ["timestamp"]);
        assert!(first(&r).contains("(record)") && first(&r).contains("isn't the one its event recorded"), "{r:?}");
        let mut stripped = lines.clone();
        stripped[5].as_object_mut().unwrap().remove("checkpoint");
        assert!(first(&report(&stripped, keys())).contains("(token)"));
        let mut other = lines.clone();
        other[5]["checkpoint"]["signature"] = json!("00".repeat(64));
        assert!(first(&report(&other, keys())).contains("differs from checkpoint 4's own event"));

        // A line forged whole, with a real token from a TSA of the forger's own: it holds
        // together, so only the TSA's CA tells it apart.
        let mut forged = lines.clone();
        forged[5] = timestamped(6, &lines[3], lines[4]["chainHash"].as_str().unwrap(), &FakeTsa::new(), STAMPED_AT);
        assert!(report(&forged, keys()).ok);
        let r = report_with(&forged, keys(), tsa::Trust::from_pem(&fake.ca_pem).unwrap());
        assert!(first(&r).contains("(untrusted)"), "{r:?}");
        // The time recorded must be the token's.
        let mut late = lines.clone();
        late[5]["details"]["time"] = json!(STAMPED_AT + 1);
        reseal(&mut late[5], lines[4]["chainHash"].as_str().unwrap(), &fresh_salt(), true);
        assert!(first(&report(&late, keys())).contains("the token's time isn't the one its event recorded"), "{:?}", report(&late, keys()));

        // Without the checkpoint's own event, the record the line carries must be signed by a key trusted.
        let only = vec![lines[5].clone()];
        let r = report(&only, keys());
        assert_eq!((r.ok, r.hosts[0].timestamps), (true, 1), "{r:?}");
        let r = report(&only, Some(vec![vec![1; 32]]));
        assert!(first(&r).contains("(key)"), "{r:?}");
        // A checkpoint made with a TSA whose timestamp isn't among the lines: counted, not a failure.
        let r = report(&lines[..5], keys());
        assert_eq!((r.ok, r.hosts[0].timestamps, r.hosts[0].unstamped), (true, 0, 1), "{r:?}");
        // A timestamp counts once, however many copies, and only if every copy holds.
        let mut copies = lines.clone();
        copies.push(lines[5].clone());
        assert_eq!(report(&copies, keys()).hosts[0].timestamps, 1);
        copies.push(swapped[5].clone());
        let r = report(&copies, keys());
        assert_eq!((r.ok, r.hosts[0].timestamps), (false, 0), "{r:?}");
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
