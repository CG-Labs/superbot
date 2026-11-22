//! Tamper evidence for the audit log (ADR 0122): every row is sealed onto a SHA-256
//! hash chain as it is written, so changing, removing, adding or reordering a row
//! breaks the chain from there, and `GET /api/audit/verify` names the first break.
//!
//! A row's `chain_hash` covers the hash before it (`chain_prev`), the columns nothing
//! may change, and `chain_digest`: a digest, under a random per-row salt, of the columns
//! erasing a user may rewrite (ADR 0102). An erasure clears the salt with the person's
//! data, so the chain still verifies and the digest no longer says anything about them.
//! Pruning deletes a run from the start of the log and keeps the last pruned row's
//! hash as the anchor the first row left must link to.
//!
//! The chain has no secret key: whoever can write `app.sqlite` can rebuild it. What
//! catches that is a copy of the hashes somewhere else, which the SIEM export and the
//! daily checkpoint (`audit.verified`, with the head's hash) provide.

use crate::db::{now, Db};
use crate::runner::App;
use rusqlite::types::Value as Sql;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

/// The link before the first row of a log that has never been pruned.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Columns nothing may change once written (the update trigger refuses it), hashed as stored.
pub const FIXED: [&str; 11] = ["id", "at", "actor_kind", "action", "target_type", "bot_id", "outcome", "actor_role", "auth_method", "idp", "idp_provider"];

/// Columns an erasure may rewrite or clear, hashed into the salted digest.
pub const ERASABLE: [&str; 10] = ["actor_id", "actor_name", "actor_subject", "target_id", "ip", "user_agent", "details", "actor_email", "session_id", "on_behalf_of"];

/// The columns the chain adds to `audit_events`.
pub const COLUMNS: [&str; 4] = ["chain_prev", "chain_hash", "chain_salt", "chain_digest"];

/// Settings key: the last pruned row, `{"id": n, "hash": "..."}`.
pub const ANCHOR: &str = "audit_chain_anchor";

const DOMAIN: &str = "superbot-audit-chain-v1";
const BATCH: i64 = 2_000;
/// How often botd checks its own chain and records the head as a checkpoint.
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

fn sha(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(p.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Values as a JSON array: unambiguous, with no raw newline in it.
fn canonical(values: &[Sql]) -> String {
    Value::Array(
        values
            .iter()
            .map(|v| match v {
                Sql::Null => Value::Null,
                Sql::Integer(i) => json!(i),
                Sql::Real(f) => json!(f),
                Sql::Text(s) => json!(s),
                Sql::Blob(b) => json!(b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
            })
            .collect(),
    )
    .to_string()
}

pub fn digest(salt: &str, erasable: &[Sql]) -> String {
    sha(&[DOMAIN, "erasable", salt, &canonical(erasable)])
}

pub fn link(prev: &str, fixed: &[Sql], digest: &str) -> String {
    sha(&[DOMAIN, prev, &canonical(fixed), digest])
}

#[derive(Clone, Debug, PartialEq)]
pub struct Seal {
    pub prev: String,
    pub hash: String,
    pub salt: String,
    pub digest: String,
}

pub fn seal(prev: &str, fixed: &[Sql], erasable: &[Sql]) -> Seal {
    let salt: String = crate::random_bytes(16).iter().map(|b| format!("{b:02x}")).collect();
    let digest = digest(&salt, erasable);
    Seal { prev: prev.into(), hash: link(prev, fixed, &digest), salt, digest }
}

/// A row of the chain, by id and hash.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Link {
    pub id: i64,
    pub hash: String,
}

impl Link {
    /// `<id>:<hash>`, as `verify?pin=` takes it.
    pub fn parse(s: &str) -> Result<Link, String> {
        let bad = || format!("A pin is <event id>:<64 hex digits>, not \"{s}\"");
        let (id, hash) = s.trim().split_once(':').ok_or_else(bad)?;
        let id = id.parse::<i64>().map_err(|_| bad())?;
        let hash = hash.to_ascii_lowercase();
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad());
        }
        Ok(Link { id, hash })
    }
}

pub fn anchor(c: &Connection) -> rusqlite::Result<Option<Link>> {
    let v: Option<String> = c.query_row("SELECT value FROM settings WHERE key = ?", [ANCHOR], |r| r.get(0)).optional()?;
    Ok(v.and_then(|v| serde_json::from_str::<Value>(&v).ok()).and_then(|v| Some(Link { id: v["id"].as_i64()?, hash: v["hash"].as_str()?.to_string() })))
}

pub fn set_anchor(c: &Connection, a: &Link) -> rusqlite::Result<()> {
    let v = json!({ "id": a.id, "hash": a.hash }).to_string();
    c.execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [ANCHOR, &v])?;
    Ok(())
}

/// Text columns hold text: SQLite would store an integer given to one as text anyway,
/// and the hash must cover what is stored.
fn stored(name: &str, v: Sql) -> Sql {
    match v {
        Sql::Integer(i) if name != "id" && name != "at" => Sql::Text(i.to_string()),
        v => v,
    }
}

/// Writes one audit row, sealed onto the end of the chain, and returns its id. `cols`
/// names columns with their values; any not named are NULL, and `details` is `{}`.
/// Rows get in no other way: a trigger refuses one without a seal. Outside a
/// transaction it takes the write lock first, so two writers can't fork the chain.
pub fn insert(c: &Connection, cols: &[(&str, Sql)]) -> rusqlite::Result<i64> {
    let tx = if c.is_autocommit() { Some(rusqlite::Transaction::new_unchecked(c, TransactionBehavior::Immediate)?) } else { None };
    let last: Option<(i64, Option<String>)> =
        c.query_row("SELECT id, chain_hash FROM audit_events ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let seq: i64 = c.query_row("SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), 0)", [], |r| r.get(0))?;
    let id = seq.max(last.as_ref().map_or(0, |l| l.0)) + 1;
    let prev = match last {
        Some((_, Some(h))) => h,
        _ => anchor(c)?.map_or_else(|| GENESIS.to_string(), |a| a.hash),
    };
    let get = |name: &str| -> Sql {
        match cols.iter().find(|(k, _)| *k == name) {
            Some((_, v)) => stored(name, v.clone()),
            None if name == "details" => Sql::Text("{}".into()),
            None => Sql::Null,
        }
    };
    let fixed: Vec<Sql> = FIXED.iter().map(|n| if *n == "id" { Sql::Integer(id) } else { get(n) }).collect();
    let erasable: Vec<Sql> = ERASABLE.iter().map(|n| get(n)).collect();
    let s = seal(&prev, &fixed, &erasable);
    let names: Vec<&str> = FIXED.iter().chain(ERASABLE.iter()).chain(COLUMNS.iter()).copied().collect();
    let marks = vec!["?"; names.len()].join(", ");
    let mut values = fixed;
    values.extend(erasable);
    values.extend([s.prev, s.hash, s.salt, s.digest].map(Sql::Text));
    c.execute(&format!("INSERT INTO audit_events ({}) VALUES ({marks})", names.join(", ")), rusqlite::params_from_iter(values))?;
    if let Some(tx) = tx {
        tx.commit()?;
    }
    Ok(id)
}

/// A system event written straight to the database, for code with only a connection
/// (migrations, master key rotation).
pub fn insert_system(c: &Connection, part: &str, action: &str, target: (&str, &str), details: &Value) -> rusqlite::Result<i64> {
    insert(
        c,
        &[
            ("at", Sql::Integer(now())),
            ("actor_kind", Sql::Text("system".into())),
            ("actor_id", Sql::Text(part.into())),
            ("action", Sql::Text(action.into())),
            ("target_type", Sql::Text(target.0.into())),
            ("target_id", Sql::Text(target.1.into())),
            ("outcome", Sql::Text("success".into())),
            ("details", Sql::Text(details.to_string())),
        ],
    )
}

/// The event an erasure writes, in its own transaction, naming the rows whose salt it
/// cleared. An erased row that no such event names fails verification.
pub const ERASED: &str = "audit.erased";

/// Records which rows an erasure cleared the salt of, as `[first, last]` id ranges.
pub fn insert_erased(c: &Connection, pseudonym: &str, ids: &[i64]) -> rusqlite::Result<i64> {
    insert_system(c, "erasure", ERASED, ("user", pseudonym), &json!({ "rows": ranges(ids) }))
}

fn ranges(ids: &[i64]) -> Vec<[i64; 2]> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let mut out: Vec<[i64; 2]> = Vec::new();
    for id in ids {
        match out.last_mut() {
            Some(r) if r[1] + 1 == id => r[1] = id,
            _ => out.push([id, id]),
        }
    }
    out
}

/// One row as the chain sees it.
#[derive(Clone, Debug)]
pub struct Row {
    pub id: i64,
    pub fixed: Vec<Sql>,
    pub erasable: Vec<Sql>,
    pub prev: Option<String>,
    pub hash: Option<String>,
    pub salt: Option<String>,
    pub digest: Option<String>,
}

/// `SELECT` list for [`Row`]s, in the order [`read_row`] reads them.
pub fn select_list() -> String {
    FIXED.iter().chain(ERASABLE.iter()).chain(COLUMNS.iter()).copied().collect::<Vec<_>>().join(", ")
}

/// Reads any value SQLite holds: a seal that isn't text counts as no seal.
pub fn read_row(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    let val = |i: usize| r.get::<_, Sql>(i);
    let text = |i: usize| -> rusqlite::Result<Option<String>> {
        Ok(match val(i)? {
            Sql::Text(t) => Some(t),
            _ => None,
        })
    };
    let fixed = (0..FIXED.len()).map(val).collect::<rusqlite::Result<Vec<_>>>()?;
    let erasable = (FIXED.len()..FIXED.len() + ERASABLE.len()).map(val).collect::<rusqlite::Result<Vec<_>>>()?;
    let n = FIXED.len() + ERASABLE.len();
    Ok(Row { id: r.get(0)?, fixed, erasable, prev: text(n)?, hash: text(n + 1)?, salt: text(n + 2)?, digest: text(n + 3)? })
}

/// Seals rows written before the chain, in id order, each onto the one before; rows
/// already sealed are left as they are. Returns how many it sealed and the last id.
/// Only for the migration, which lifts the update trigger around it.
pub fn seal_existing(c: &Connection) -> rusqlite::Result<(usize, i64)> {
    let (mut after, mut prev, mut sealed) = (i64::MIN, GENESIS.to_string(), 0);
    loop {
        let rows: Vec<Row> = {
            let mut s = c.prepare(&format!("SELECT {} FROM audit_events WHERE id > ? ORDER BY id LIMIT ?", select_list()))?;
            s.query_map(rusqlite::params![after, BATCH], read_row)?.collect::<rusqlite::Result<_>>()?
        };
        let Some(last) = rows.last() else { break };
        after = last.id;
        for r in rows {
            prev = match r.hash {
                Some(h) => h,
                None => {
                    let s = seal(&prev, &r.fixed, &r.erasable);
                    c.execute(
                        "UPDATE audit_events SET chain_prev = ?2, chain_hash = ?3, chain_salt = ?4, chain_digest = ?5 WHERE id = ?1",
                        rusqlite::params![r.id, s.prev, s.hash, s.salt, s.digest],
                    )?;
                    sealed += 1;
                    s.hash
                }
            };
        }
    }
    Ok((sealed, after))
}

/// The first row that breaks the chain, and why: `unsealed` (no seal), `link` (its
/// link to the row before doesn't match: a row before it was removed, added or
/// changed), `contents` (the row itself changed), `erased` (its salt is gone but no
/// erasure names it, so its erasable fields can't be checked), or `pin` (it differs
/// from, or lacks, a hash pinned from a copy kept elsewhere).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Broken {
    pub id: i64,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pinned {
    pub id: i64,
    pub hash: String,
    /// `match`, `mismatch`, `gone` (pruned by retention since) or `missing` (not there,
    /// and newer than anything retention deleted: a failure).
    pub result: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub ok: bool,
    pub checked: u64,
    /// Rows whose salt an erasure cleared: their digest is taken as written.
    pub erased: u64,
    /// Rows that break the chain. Each is judged against the row before it as stored,
    /// so one changed row counts once.
    pub broken: u64,
    pub first_broken: Option<Broken>,
    pub first: Option<i64>,
    /// The newest row and its hash: compare it with a copy kept elsewhere.
    pub head: Option<Link>,
    /// The last pruned row, which the first row left must link to.
    pub anchor: Option<Link>,
    pub pins: Vec<Pinned>,
    /// Set when the log couldn't be read to the end; the check then fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Report {
    /// Counts a break, keeping the lowest id as the first.
    fn broke(&mut self, id: i64, reason: &'static str) {
        self.broken += 1;
        if self.first_broken.as_ref().is_none_or(|b| id < b.id) {
            self.first_broken = Some(Broken { id, reason });
        }
    }
}

/// Walks the chain one row at a time, oldest first.
pub struct Verifier {
    report: Report,
    expected: Option<String>,
    pins: Vec<(Link, Option<&'static str>)>,
    /// Erased rows not yet named by an `audit.erased` event after them.
    unexplained: std::collections::BTreeSet<i64>,
}

impl Verifier {
    pub fn new(anchor: Option<Link>, pins: Vec<Link>) -> Verifier {
        Verifier { report: Report { anchor, ..Default::default() }, expected: None, pins: pins.into_iter().map(|p| (p, None)).collect(), unexplained: Default::default() }
    }

    pub fn feed(&mut self, r: &Row) {
        let rep = &mut self.report;
        rep.checked += 1;
        let expected = match self.expected.take() {
            Some(e) => e,
            None => {
                rep.first = Some(r.id);
                rep.anchor.as_ref().map_or_else(|| GENESIS.to_string(), |a| a.hash.clone())
            }
        };
        let reason = match (&r.prev, &r.hash, &r.digest) {
            (Some(prev), Some(hash), Some(digest)) => {
                if r.salt.is_none() {
                    rep.erased += 1;
                }
                if *prev != expected {
                    Some("link")
                } else if r.salt.as_deref().is_some_and(|s| crate::audit_chain::digest(s, &r.erasable) != *digest) || link(prev, &r.fixed, digest) != *hash {
                    Some("contents")
                } else {
                    None
                }
            }
            _ => Some("unsealed"),
        };
        let mut pinned_wrong = false;
        for (pin, result) in self.pins.iter_mut().filter(|(p, _)| p.id == r.id) {
            let same = r.hash.as_deref() == Some(pin.hash.as_str());
            *result = Some(if same { "match" } else { "mismatch" });
            pinned_wrong |= !same;
        }
        let reason = reason.or(pinned_wrong.then_some("pin"));
        if let Some(reason) = reason {
            self.report.broke(r.id, reason);
        } else {
            if r.salt.is_none() {
                self.unexplained.insert(r.id);
            }
            if r.fixed.get(3) == Some(&Sql::Text(ERASED.into())) {
                self.explain(r);
            }
        }
        if let Some(h) = &r.hash {
            self.report.head = Some(Link { id: r.id, hash: h.clone() });
        }
        self.expected = Some(r.hash.clone().unwrap_or(expected));
    }

    /// An intact `audit.erased` row: the erased rows it names are accounted for.
    fn explain(&mut self, r: &Row) {
        let details = ERASABLE.iter().position(|c| *c == "details").and_then(|i| r.erasable.get(i));
        let Some(Sql::Text(details)) = details else { return };
        let Ok(v) = serde_json::from_str::<Value>(details) else { return };
        for range in v["rows"].as_array().into_iter().flatten() {
            let (Some(a), Some(b)) = (range[0].as_i64(), range[1].as_i64()) else { continue };
            if a > b {
                continue;
            }
            let named: Vec<i64> = self.unexplained.range(a..=b).copied().collect();
            for id in named {
                self.unexplained.remove(&id);
            }
        }
    }

    /// The log couldn't be read past here.
    pub fn fail(&mut self, error: String) {
        self.report.error = Some(error);
    }

    pub fn finish(mut self) -> Report {
        let rep = &mut self.report;
        for id in std::mem::take(&mut self.unexplained) {
            rep.broke(id, "erased");
        }
        for (p, result) in self.pins {
            let result = result.unwrap_or_else(|| match &rep.anchor {
                // The last pruned row is gone, but its hash is kept as the anchor.
                Some(a) if a.id == p.id && a.hash == p.hash => "match",
                Some(a) if a.id == p.id => {
                    rep.broke(p.id, "pin");
                    "mismatch"
                }
                Some(a) if p.id < a.id => "gone",
                // Never pruned, yet not there: deleted, or a restore from before it.
                _ => {
                    rep.broke(p.id, "pin");
                    "missing"
                }
            });
            rep.pins.push(Pinned { id: p.id, hash: p.hash, result });
        }
        rep.ok = rep.broken == 0 && rep.error.is_none();
        self.report
    }
}

/// Checks the whole chain, a batch at a time, so other writers aren't held up long.
/// Retention may prune between batches and move the anchor; a check that fails then is
/// run again, so pruning never looks like tampering.
pub fn verify(db: &Db, pins: Vec<Link>) -> Report {
    let mut tries = 0;
    loop {
        let anchor = db.audit_chain_anchor();
        let r = walk(db, anchor.clone(), pins.clone());
        tries += 1;
        if r.ok || tries == 3 || db.audit_chain_anchor() == anchor {
            return r;
        }
    }
}

fn walk(db: &Db, anchor: Option<Link>, pins: Vec<Link>) -> Report {
    let mut v = Verifier::new(anchor, pins);
    let mut after = i64::MIN;
    loop {
        let rows = match db.audit_chain_rows(after, BATCH) {
            Ok(rows) => rows,
            Err(e) => {
                v.fail(format!("couldn't read the audit log after event {after}: {e}"));
                break;
            }
        };
        let Some(last) = rows.last() else { break };
        after = last.id;
        for r in &rows {
            v.feed(r);
        }
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    v.finish()
}

/// What `audit.verified` records: the result and the head, never row contents.
pub fn summary(r: &Report) -> Value {
    json!({ "ok": r.ok, "checked": r.checked, "erased": r.erased, "broken": r.broken, "firstBroken": r.first_broken, "head": r.head, "anchor": r.anchor, "pins": r.pins, "error": r.error })
}

/// Checks the chain once a day and records `audit.verified` with the head's hash: a
/// checkpoint that the SIEM export carries off the host.
pub fn start(app: Arc<App>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let a = app.clone();
            if let Ok(r) = tokio::task::spawn_blocking(move || verify(&a.db, Vec::new())).await {
                checked(&app, &crate::audit::Who::system("audit"), &r);
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Records a check's result, and warns when the chain is broken.
pub fn checked(app: &App, by: &crate::audit::Who, r: &Report) {
    use crate::audit::Outcome;
    if let Some(e) = &r.error {
        crate::obs::log::log_warn!("WARNING: the audit log's hash chain couldn't be checked: {e}");
    }
    if let Some(b) = &r.first_broken {
        crate::obs::log::log_warn!("WARNING: the audit log's hash chain is broken at event {} ({}); see docs/ops/audit-export.md.", b.id, b.reason);
    }
    let outcome = if r.ok { Outcome::Success } else { Outcome::Failure };
    app.db.record(&by.event("audit.verified").target("audit", "chain").outcome(outcome).details(summary(r)));
}

/// `GET /api/audit/verify[?pin=<id>:<hash>,...]`: checks the chain, and each pinned
/// hash, from a SIEM or an earlier check, against the row there now. Admins only.
pub async fn get(
    axum::extract::State(app): axum::extract::State<Arc<App>>,
    axum::Extension(by): axum::Extension<crate::audit::Who>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<Report>, (axum::http::StatusCode, String)> {
    let bad = |m: String| (axum::http::StatusCode::BAD_REQUEST, m);
    let pins: Vec<Link> = q.get("pin").map(|p| p.split(',').filter(|s| !s.trim().is_empty()).map(Link::parse).collect()).transpose().map_err(bad)?.unwrap_or_default();
    if pins.len() > 100 {
        return Err(bad("At most 100 pins".into()));
    }
    let a = app.clone();
    let r = tokio::task::spawn_blocking(move || verify(&a.db, pins)).await.map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    checked(&app, &by, &r);
    Ok(axum::Json(r))
}

/// What someone who can write `app.sqlite` could do after changing a row: re-seal every
/// row from `from` on so the chain holds again. Only a hash kept elsewhere shows it.
/// Needs the update trigger dropped first.
#[cfg(test)]
pub fn reseal_from(db: &Db, from: i64) -> usize {
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for r in db.audit_chain_rows(i64::MIN, i64::MAX).unwrap() {
        if r.id >= from {
            let s = seal(&prev, &r.fixed, &r.erasable);
            db.execute_raw(&format!(
                "UPDATE audit_events SET chain_prev = '{}', chain_hash = '{}', chain_salt = '{}', chain_digest = '{}' WHERE id = {}",
                s.prev, s.hash, s.salt, s.digest, r.id
            ))
            .unwrap();
            n += 1;
            prev = s.hash;
        } else {
            prev = r.hash.unwrap_or_default();
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, prev: &str, action: &str) -> (Row, Seal) {
        row_with(id, prev, action, "{}")
    }

    fn row_with(id: i64, prev: &str, action: &str, details: &str) -> (Row, Seal) {
        let fixed = vec![Sql::Integer(id), Sql::Integer(1_000 + id), Sql::Text("system".into()), Sql::Text(action.into())];
        let mut erasable = vec![Sql::Null; ERASABLE.len()];
        erasable[0] = Sql::Text("u1".into());
        erasable[6] = Sql::Text(details.into());
        let s = seal(prev, &fixed, &erasable);
        (Row { id, fixed, erasable, prev: Some(s.prev.clone()), hash: Some(s.hash.clone()), salt: Some(s.salt.clone()), digest: Some(s.digest.clone()) }, s)
    }

    fn chain(n: i64) -> Vec<Row> {
        let mut prev = GENESIS.to_string();
        (1..=n)
            .map(|id| {
                let (r, s) = row(id, &prev, "x.y");
                prev = s.hash;
                r
            })
            .collect()
    }

    fn check(rows: &[Row], anchor: Option<Link>, pins: Vec<Link>) -> Report {
        let mut v = Verifier::new(anchor, pins);
        rows.iter().for_each(|r| v.feed(r));
        v.finish()
    }

    #[test]
    fn hashes_are_stable_and_cover_every_part() {
        let fixed = [Sql::Integer(1), Sql::Text("a".into()), Sql::Null];
        let d = digest("00", &[Sql::Text("b".into())]);
        assert_eq!(d, digest("00", &[Sql::Text("b".into())]));
        assert_ne!(d, digest("01", &[Sql::Text("b".into())]), "the salt counts");
        assert_ne!(digest("00", &[Sql::Null]), digest("00", &[Sql::Text(String::new())]), "NULL isn't an empty string");
        assert_ne!(digest("00", &[Sql::Integer(1)]), digest("00", &[Sql::Text("1".into())]));
        let h = link(GENESIS, &fixed, &d);
        assert_eq!(h.len(), 64);
        assert_ne!(h, link(&"1".repeat(64), &fixed, &d));
        assert_ne!(h, link(GENESIS, &fixed[..2], &d));
        assert_ne!(h, link(GENESIS, &fixed, &digest("00", &[Sql::Text("c".into())])));
        // Fields can't run into each other.
        assert_ne!(canonical(&[Sql::Text("a,b".into())]), canonical(&[Sql::Text("a".into()), Sql::Text("b".into())]));
        assert!(!canonical(&[Sql::Text("a\nb".into())]).contains('\n'));
        let s = seal(GENESIS, &fixed, &[]);
        assert_ne!(s.salt, seal(GENESIS, &fixed, &[]).salt, "a fresh salt per row");
    }

    #[test]
    fn a_whole_chain_verifies_and_reports_its_head() {
        let rows = chain(5);
        let r = check(&rows, None, vec![]);
        assert!(r.ok, "{r:?}");
        assert_eq!((r.checked, r.first, r.head.as_ref().map(|h| h.id)), (5, Some(1), Some(5)));
        assert_eq!(r.head.unwrap().hash, *rows[4].hash.as_ref().unwrap());
        assert!(check(&[], None, vec![]).ok, "an empty log is whole");
    }

    #[test]
    fn the_first_broken_link_is_named() {
        let rows = chain(6);
        // Changed contents, kept or erasable.
        let mut changed = rows.clone();
        changed[2].fixed[3] = Sql::Text("y.z".into());
        assert_eq!(check(&changed, None, vec![]).first_broken, Some(Broken { id: 3, reason: "contents" }));
        let mut changed = rows.clone();
        changed[2].erasable[0] = Sql::Text("u2".into());
        let r = check(&changed, None, vec![]);
        assert_eq!((r.first_broken, r.broken), (Some(Broken { id: 3, reason: "contents" }), 1), "judged against the row as stored, the next link holds");
        // A row taken out, or two swapped.
        let mut gone = rows.clone();
        gone.remove(3);
        assert_eq!(check(&gone, None, vec![]).first_broken, Some(Broken { id: 5, reason: "link" }));
        let mut swapped = rows.clone();
        swapped.swap(1, 2);
        assert_eq!(check(&swapped, None, vec![]).first_broken.unwrap().id, 2, "the lowest id that breaks");
        // Rebuilt from a changed row on: every link holds, but a pinned hash doesn't.
        let mut rebuilt = rows[..2].to_vec();
        let mut prev = rebuilt[1].hash.clone().unwrap();
        for id in 3..=6 {
            let (r, s) = row(id, &prev, if id == 3 { "forged" } else { "x.y" });
            prev = s.hash;
            rebuilt.push(r);
        }
        assert!(check(&rebuilt, None, vec![]).ok);
        let pin = Link { id: 4, hash: rows[3].hash.clone().unwrap() };
        let r = check(&rebuilt, None, vec![pin.clone()]);
        assert_eq!((r.ok, r.first_broken.clone(), r.pins[0].result), (false, Some(Broken { id: 4, reason: "pin" }), "mismatch"));
        assert_eq!(check(&rows, None, vec![pin]).pins[0].result, "match");
        // A row with no seal.
        let mut bare = rows.clone();
        bare[4].hash = None;
        assert_eq!(check(&bare, None, vec![]).first_broken, Some(Broken { id: 5, reason: "unsealed" }));
        // Rows cut from the start without an anchor.
        assert_eq!(check(&rows[2..], None, vec![]).first_broken, Some(Broken { id: 3, reason: "link" }));
    }

    #[test]
    fn pruned_logs_start_at_the_anchor_and_erased_rows_still_verify() {
        let rows = chain(6);
        let anchor = Link { id: 2, hash: rows[1].hash.clone().unwrap() };
        let r = check(&rows[2..], Some(anchor.clone()), vec![Link { id: 2, hash: anchor.hash.clone() }, Link { id: 1, hash: GENESIS.into() }]);
        assert!(r.ok, "{r:?}");
        assert_eq!((r.first, r.pins[0].result, r.pins[1].result), (Some(3), "match", "gone"));
        // A pinned row newer than anything pruned that isn't there fails: deleted, or
        // a backup from before it restored.
        let pin = Link { id: 6, hash: rows[5].hash.clone().unwrap() };
        let r = check(&rows[2..5], Some(anchor.clone()), vec![pin.clone()]);
        assert_eq!((r.ok, r.pins[0].result, r.first_broken.clone()), (false, "missing", Some(Broken { id: 6, reason: "pin" })));
        assert_eq!(check(&rows[..5], None, vec![pin]).pins[0].result, "missing", "nothing pruned, so nothing is gone");
        let wrong = Link { id: 2, hash: GENESIS.into() };
        assert_eq!(check(&rows[2..], Some(wrong), vec![]).first_broken, Some(Broken { id: 3, reason: "link" }));
        // Erased: the person's fields are gone with the salt, and the digest stands for
        // them, once an erasure after it names the row.
        let mut erased = rows.clone();
        erased[3].erasable[0] = Sql::Text("x-pseudonym".into());
        erased[3].salt = None;
        let r = check(&erased, None, vec![]);
        assert_eq!((r.ok, r.erased, r.first_broken), (false, 1, Some(Broken { id: 4, reason: "erased" })), "a salt cleared by hand");
        let (named, _) = row_with(7, erased[5].hash.as_ref().unwrap(), ERASED, r#"{"rows":[[2,2],[4,5]]}"#);
        erased.push(named.clone());
        let r = check(&erased, None, vec![]);
        assert_eq!((r.ok, r.erased, r.checked), (true, 1, 7), "{r:?}");
        // Only an intact erasure event counts.
        let mut forged = erased.clone();
        forged[6].erasable[6] = Sql::Text(r#"{"rows":[[1,6]]}"#.into());
        forged[3].salt = None;
        assert_eq!(check(&forged, None, vec![]).first_broken, Some(Broken { id: 4, reason: "erased" }));
        let (other, _) = row_with(7, erased[5].hash.as_ref().unwrap(), ERASED, r#"{"rows":[[5,6]]}"#);
        let mut wrong = erased[..6].to_vec();
        wrong.push(other);
        assert_eq!(check(&wrong, None, vec![]).first_broken, Some(Broken { id: 4, reason: "erased" }), "it must name this row");
        // A salt kept with changed fields is a change, not an erasure.
        let mut kept = rows;
        kept[3].erasable[0] = Sql::Text("x-pseudonym".into());
        assert!(!check(&kept, None, vec![]).ok);
    }

    #[test]
    fn erasures_are_recorded_as_ranges() {
        assert_eq!(ranges(&[9, 3, 4, 5, 7, 4]), vec![[3, 5], [7, 7], [9, 9]]);
        assert!(ranges(&[]).is_empty());
    }

    #[test]
    fn pins_parse() {
        let h = "a".repeat(64);
        assert_eq!(Link::parse(&format!("12:{}", h.to_uppercase())).unwrap(), Link { id: 12, hash: h.clone() });
        for bad in ["12".to_string(), format!("x:{h}"), format!("12:{}", &h[1..]), format!("12:{}g", &h[1..])] {
            assert!(Link::parse(&bad).is_err(), "{bad}");
        }
    }
}
