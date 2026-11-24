//! Pinned people's chats, routines and approvals in a database in their region (ADR 0215,
//! ADR 0228), the first part of splitting botd's database by region. Each region in
//! REGION_DATA_DIRS has a SQLite file of its own (`chats.sqlite`, keyed like botd's
//! database), attached to botd's connection. A Bot's messages, routines and approvals are
//! kept in the store of its owner's residency pin (their team's, else their own, as
//! `residency::of_user`), or in botd's own database when that region has no store or the
//! owner isn't pinned.
//!
//! Reads see every place at once: a TEMP view per table (`messages`, `routines`,
//! `approvals`) puts botd's own table and each store's together, and unqualified names
//! find TEMP objects first. Writes name the table they change: new rows go where their
//! Bot's data belongs, and updates and deletes by id run on each place. Ids stay unique
//! across all of them: a store's messages take the next id after botd's own sequence and
//! every store's highest, and bump that sequence, so botd's table never hands the same id
//! out again; a routine's or approval's id is drawn again while any place has it.
//!
//! `place_chats` moves rows whose Bot belongs elsewhere now (a pin made or ended, a
//! member joining or leaving a pinned team, a Bot given away): copied and committed, then
//! deleted from where they were in a second transaction, with freed pages zeroed. A
//! transaction across attached WAL files commits each file on its own, so one transaction
//! could commit the delete without the copy; two can at worst leave a copy in both places,
//! and the next pass deletes the one in the wrong place.

use super::{Db, now};
use crate::database_encryption::{self, Format};
use crate::secrets::sealed::{self, Cipher, StoreApprovals};
use rusqlite::{Connection, OptionalExtension, ToSql, params};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

/// A table whose rows are kept, by Bot, in the store of its owner's pin.
struct Kept {
    name: &'static str,
    /// The indexes a store's copy gets, as `(name, columns)`.
    indexes: &'static [(&'static str, &'static str)],
    /// Reads order by its rowid, which a view has only as a column of that name.
    rowid: bool,
}

const KEPT: [Kept; 3] = [
    Kept { name: "messages", indexes: &[("messages_bot", "bot_id, id"), ("messages_created", "created_at")], rowid: false },
    Kept { name: "routines", indexes: &[("routines_bot", "bot_id")], rowid: false },
    Kept { name: "approvals", indexes: &[("approvals_status", "status, created_at"), ("approvals_bot", "bot_id")], rowid: true },
];
const MESSAGES: usize = 0;
const APPROVALS: usize = 2;

/// The token for `table` in a statement run on every place (`on_places`): `{messages}`,
/// `{routines}` or `{approvals}`.
fn token(table: &str) -> String {
    format!("{{{table}}}")
}

/// botd's record of each store it has kept chats in, so a store that goes missing (an
/// unmounted volume, a dropped setting) stops botd instead of hiding those chats; and of
/// when each Bot's rows last left a store, as that store's earlier backups still hold them
/// until botd clears them out of those backups (`cleared_at`, ADR 0238).
const RECORDS: &str = "CREATE TABLE IF NOT EXISTS main.chat_stores (
  region TEXT PRIMARY KEY,
  store_id TEXT NOT NULL,
  path TEXT NOT NULL,
  added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS main.chat_moves_out (
  bot_id TEXT NOT NULL,
  region TEXT NOT NULL,
  moved_at INTEGER NOT NULL,
  cleared_at INTEGER,
  PRIMARY KEY (bot_id, region)
);";

/// A region's chat store, attached to botd's connection as `schema`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatStore {
    pub region: String,
    pub schema: String,
    pub path: PathBuf,
    /// Written into the store when it was made, and recorded in botd's database.
    pub id: String,
}

#[derive(Debug, Default)]
pub(super) struct ChatStores {
    stores: Vec<ChatStore>,
    /// Each kept table's columns, quoted, in the order botd's own table has them.
    cols: Vec<String>,
    /// A checkpoint after rows left a place was blocked by a reader, so their zeroed pages
    /// may not have replaced the old ones in its file yet. Each pass tries again.
    unflushed: std::sync::atomic::AtomicBool,
}

/// What attaching the stores did, for the startup log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Attached {
    /// Regions whose store was made on this start.
    pub created: Vec<String>,
    /// Stores no longer in REGION_DATA_DIRS that held nothing (or whose file is gone),
    /// as `(region, path)`: botd stopped recording them.
    pub forgotten: Vec<(String, String)>,
}

/// How many rows of each kept table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Held {
    pub messages: i64,
    pub routines: i64,
    pub approvals: i64,
}

impl Held {
    fn of(n: [i64; 3]) -> Held {
        Held { messages: n[0], routines: n[1], approvals: n[2] }
    }

    pub fn total(&self) -> i64 {
        self.messages + self.routines + self.approvals
    }

    pub fn add(&mut self, o: Held) {
        self.messages += o.messages;
        self.routines += o.routines;
        self.approvals += o.approvals;
    }

    /// "3 chat messages, 1 routine and 2 approvals", leaving out tables with none.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = [(self.messages, "chat message"), (self.routines, "routine"), (self.approvals, "approval")]
            .into_iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| format!("{n} {what}{}", if n == 1 { "" } else { "s" }))
            .collect();
        match parts.as_slice() {
            [] => "nothing".into(),
            [one] => one.clone(),
            [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        }
    }
}

/// What one pass moved between two places. `None`: botd's own database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMove {
    pub from: Option<String>,
    pub to: Option<String>,
    pub bots: usize,
    pub messages: usize,
    pub routines: usize,
    pub approvals: usize,
}

/// One place chats are kept, and what of theirs is there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatCount {
    /// None: botd's own database.
    pub region: Option<String>,
    pub held: Held,
}

struct Col {
    name: String,
    ty: String,
    notnull: bool,
    default: Option<String>,
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn columns(c: &Connection, schema: &str, table: &str) -> rusqlite::Result<Vec<Col>> {
    let mut s = c.prepare(&format!("SELECT name, type, \"notnull\", dflt_value FROM pragma_table_info({}, {})", literal(table), literal(schema)))?;
    s.query_map([], |r| Ok(Col { name: r.get(0)?, ty: r.get(1)?, notnull: r.get(2)?, default: r.get(3)? }))?.collect()
}

/// Makes the store's copy of `k` match botd's own table: the same columns, `id` its primary
/// key (without AUTOINCREMENT: message ids come from botd's sequence), and its indexes. No
/// foreign key to `bots`, which is in another file: deleting a Bot deletes its rows here.
fn ensure_table(c: &Connection, schema: &str, k: &Kept, main: &[Col]) -> rusqlite::Result<()> {
    let def = |col: &Col, adding: bool| {
        if col.name == "id" {
            return format!("\"id\" {} PRIMARY KEY", col.ty);
        }
        let default = col.default.as_ref().map(|d| format!(" DEFAULT {d}")).unwrap_or_default();
        // A column added to a table with rows can be NOT NULL only with a default.
        let notnull = if col.notnull && (!adding || col.default.is_some()) { " NOT NULL" } else { "" };
        format!("{} {}{notnull}{default}", quote(&col.name), col.ty)
    };
    let defs: Vec<String> = main.iter().map(|col| def(col, false)).collect();
    c.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {schema}.{} ({})", k.name, defs.join(", ")))?;
    let have: Vec<String> = columns(c, schema, k.name)?.into_iter().map(|c| c.name).collect();
    for col in main.iter().filter(|col| !have.contains(&col.name)) {
        c.execute_batch(&format!("ALTER TABLE {schema}.{} ADD COLUMN {}", k.name, def(col, true)))?;
    }
    for (index, cols) in k.indexes {
        c.execute_batch(&format!("CREATE INDEX IF NOT EXISTS {schema}.{index} ON {}({cols})", k.name))?;
    }
    Ok(())
}

/// Raises botd's own sequence for messages to at least `id`, so its table never reuses it.
fn bump_sequence(c: &Connection, id: i64) -> rusqlite::Result<()> {
    let n = c.execute("UPDATE main.sqlite_sequence SET seq = ?1 WHERE name = 'messages' AND seq < ?1", [id])?;
    if n == 0 {
        c.execute("INSERT INTO main.sqlite_sequence (name, seq) SELECT 'messages', ?1 WHERE NOT EXISTS (SELECT 1 FROM main.sqlite_sequence WHERE name = 'messages')", [id])?;
    }
    Ok(())
}

fn not_a_store(path: &Path, e: &rusqlite::Error) -> String {
    match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase) => format!(
            "{} doesn't open with botd's database key: it was encrypted under another master key, or isn't a database (ADR 0215)",
            path.display()
        ),
        _ => format!("{}: {e}", path.display()),
    }
}

/// The places chats are kept, by schema: botd's own first.
fn schemas(stores: &[ChatStore]) -> impl Iterator<Item = &str> {
    std::iter::once("main").chain(stores.iter().map(|s| s.schema.as_str()))
}

fn region_of<'a>(stores: &'a [ChatStore], schema: &str) -> Option<&'a str> {
    stores.iter().find(|s| s.schema == schema).map(|s| s.region.as_str())
}

/// The region of `bot`'s owner's pin, their team's first, from botd's own tables. `bot` is
/// an SQL expression for the Bot's id.
fn pinned_region(bot: &str) -> String {
    format!(
        "COALESCE(
           (SELECT p.region FROM main.team_members tm JOIN main.residency_pins p ON p.subject_type = 'team' AND p.subject_id = tm.team_id
             WHERE tm.user_id = (SELECT owner_id FROM main.bots WHERE id = {bot})),
           (SELECT p.region FROM main.residency_pins p WHERE p.subject_type = 'user' AND p.subject_id = (SELECT owner_id FROM main.bots WHERE id = {bot})))"
    )
}

/// How many rows of each kept table in `schema` (where they exist) match `filter`, an SQL
/// condition on the table's columns.
fn held_in(c: &Connection, schema: &str, filter: &str, p: &[&dyn ToSql]) -> rusqlite::Result<Held> {
    let mut n = [0; 3];
    for (i, k) in KEPT.iter().enumerate() {
        let exists: bool = c.query_row(&format!("SELECT COUNT(*) > 0 FROM {schema}.sqlite_master WHERE type = 'table' AND name = ?1"), [k.name], |r| r.get(0))?;
        if exists {
            n[i] = c.query_row(&format!("SELECT COUNT(*) FROM {schema}.{} WHERE {filter}", k.name), p, |r| r.get(0))?;
        }
    }
    Ok(Held::of(n))
}

/// Checkpoints `schema`'s WAL into its file and empties it, so the zeroed pages replace
/// the old ones there. False when a reader blocked it.
fn flush(c: &Connection, schema: &str) -> bool {
    c.query_row(&format!("PRAGMA {schema}.wal_checkpoint(TRUNCATE)"), [], |r| r.get::<_, i64>(0)).is_ok_and(|busy| busy == 0)
}

/// Runs `f` with `secure_delete` on for every attached file, so what it deletes or
/// overwrites is zeroed rather than left in free pages, then sets it back.
fn zeroing<T>(c: &Connection, f: impl FnOnce() -> rusqlite::Result<T>) -> rusqlite::Result<T> {
    let was: i64 = c.query_row("PRAGMA main.secure_delete", [], |r| r.get(0))?;
    c.execute_batch("PRAGMA secure_delete = ON")?;
    let r = f();
    let _ = c.execute_batch(&format!("PRAGMA secure_delete = {}", if was == 2 { "FAST".to_string() } else { was.to_string() }));
    r
}

impl Db {
    pub(super) fn chat_stores_set(&self) -> &[ChatStore] {
        self.5.get().map_or(&[], |s| s.stores.as_slice())
    }

    /// The regions' chat stores attached now (ADR 0215).
    pub fn chat_stores(&self) -> Vec<ChatStore> {
        self.chat_stores_set().to_vec()
    }

    /// Checks botd's record of chat stores against `dirs` (each region's `chats.sqlite`) and
    /// attaches them, keyed with `key` (SQLCipher's raw key; None: plain, as botd's own
    /// database). Called once at startup, with no stores too, so a store that held chats and
    /// was dropped from REGION_DATA_DIRS stops botd. Refuses a recorded store whose file is
    /// missing or isn't the one recorded, rather than start an empty one in its place. A
    /// dropped store whose file is gone is forgotten only when named in `forget`
    /// (REGION_DATA_FORGET): nothing shows whether it still held chats.
    pub fn attach_chat_stores(&self, dirs: &[(String, PathBuf)], forget: &[String], key: Option<&str>) -> Result<Attached, String> {
        if self.5.get().is_some() {
            return Err("chat stores are attached once, at startup".into());
        }
        let c = self.c();
        let e = |err: rusqlite::Error| format!("chat stores: {err}");
        c.execute_batch(RECORDS).map_err(e)?;
        if !columns(&c, "main", "chat_moves_out").map_err(e)?.iter().any(|col| col.name == "cleared_at") {
            c.execute_batch("ALTER TABLE main.chat_moves_out ADD COLUMN cleared_at INTEGER").map_err(e)?;
        }
        let recorded: Vec<(String, String, String)> = {
            let mut s = c.prepare("SELECT region, store_id, path FROM main.chat_stores ORDER BY region").map_err(e)?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(e)?.collect::<rusqlite::Result<_>>().map_err(e)?
        };
        let mut out = Attached::default();
        // Forgotten only once every store checks out, so a start that fails changes nothing.
        for (region, id, path) in recorded.iter().filter(|(r, _, _)| !dirs.iter().any(|(d, _)| d == r)) {
            let p = Path::new(path);
            if database_encryption::format(p)? == Format::Missing {
                if !forget.contains(region) {
                    return Err(format!(
                        "REGION_DATA_DIRS no longer names {region}, and its chat store (store {id}, last at {path}) is gone, so nothing shows whether it still held chats. \
                         Put {region}=<its folder> back with the volume mounted. If its chats are lost for good, add {region} to REGION_DATA_FORGET (ADR 0215)."
                    ));
                }
            } else {
                c.execute("ATTACH DATABASE ?1 AS chats_dropped KEY ?2", params![path, key.unwrap_or("")]).map_err(|err| not_a_store(p, &err))?;
                let held = held_in(&c, "chats_dropped", "1", &[]);
                let has = c.query_row("SELECT COUNT(*) FROM chats_dropped.sqlite_master WHERE type = 'table' AND name = 'chat_store'", [], |r| r.get::<_, i64>(0)).map(|n| n > 0);
                let own: rusqlite::Result<Option<String>> = match has {
                    Ok(true) => c.query_row("SELECT id FROM chats_dropped.chat_store LIMIT 1", [], |r| r.get(0)).optional(),
                    Ok(false) => Ok(None),
                    Err(err) => Err(err),
                };
                c.execute("DETACH DATABASE chats_dropped", []).map_err(e)?;
                let (held, own) = (held.map_err(|err| not_a_store(p, &err))?, own.map_err(|err| not_a_store(p, &err))?);
                if own.as_deref() != Some(id.as_str()) && !forget.contains(region) {
                    return Err(format!(
                        "REGION_DATA_DIRS no longer names {region}, and {path} isn't its chat store (store {id}) any more, so nothing shows whether that still held chats. \
                         Put {region}=<its folder> back with the store in it. If its chats are lost for good, add {region} to REGION_DATA_FORGET (ADR 0215)."
                    ));
                }
                if held.total() > 0 {
                    return Err(format!(
                        "REGION_DATA_DIRS no longer names {region}, but its chat store ({path}) still holds {} of pinned people's Bots. \
                         Put {region}=<its folder> back. To retire a store, end the pins in {region} first, let botd move their data back, then remove it (ADR 0215, ADR 0228).",
                        held.describe()
                    ));
                }
            }
            out.forgotten.push((region.clone(), path.clone()));
        }
        let mains: Vec<Vec<Col>> = KEPT.iter().map(|k| columns(&c, "main", k.name)).collect::<rusqlite::Result<_>>().map_err(e)?;
        let cols: Vec<String> = mains.iter().map(|m| m.iter().map(|col| quote(&col.name)).collect::<Vec<_>>().join(", ")).collect();
        let mut stores = Vec::new();
        for (i, (region, dir)) in dirs.iter().enumerate() {
            let path = dir.join("chats.sqlite");
            let shown = path.display().to_string();
            let schema = format!("chats_{i}");
            let rec = recorded.iter().find(|(r, _, _)| r == region);
            let missing = database_encryption::format(&path)? == Format::Missing;
            if let (true, Some((_, id, was))) = (missing, rec) {
                return Err(format!(
                    "{region}'s chat store (store {id}, last at {was}) isn't at {shown}. Is its volume mounted? botd won't start an empty store in its place: \
                     restore it from its folder's backups/ or its bucket with `botd chat-store restore {region} newest` (ADR 0215, ADR 0256)."
                ));
            }
            let path_str = path.to_str().ok_or_else(|| format!("{shown}: path is not UTF-8"))?;
            c.execute(&format!("ATTACH DATABASE ?1 AS {schema} KEY ?2"), params![path_str, key.unwrap_or("")]).map_err(|err| not_a_store(&path, &err))?;
            let tables: Vec<String> = {
                let mut s = c.prepare(&format!("SELECT name FROM {schema}.sqlite_master WHERE type = 'table'")).map_err(|err| not_a_store(&path, &err))?;
                s.query_map([], |r| r.get(0)).map_err(|err| not_a_store(&path, &err))?.collect::<rusqlite::Result<_>>().map_err(|err| not_a_store(&path, &err))?
            };
            let own: Option<(String, String)> = if tables.iter().any(|t| t == "chat_store") {
                c.query_row(&format!("SELECT id, region FROM {schema}.chat_store LIMIT 1"), [], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(e)?
            } else {
                None
            };
            let id = match own {
                Some((_, r)) if r != *region => return Err(format!("{shown} is {r}'s chat store, not {region}'s (REGION_DATA_DIRS, ADR 0215).")),
                Some((id, _)) => match rec {
                    Some((_, was, _)) if *was != id => {
                        return Err(format!("{shown} is chat store {id}, but botd keeps {region}'s chats in store {was}. Point REGION_DATA_DIRS at that one (ADR 0215)."));
                    }
                    _ => id,
                },
                None if !tables.is_empty() => return Err(format!("{shown} isn't a SuperBot chat store: it already holds other tables (ADR 0215).")),
                None => {
                    if let Some((_, was, at)) = rec {
                        return Err(format!("{shown} is an empty database, but botd keeps {region}'s chats in store {was} (last at {at}). Is its volume mounted? (ADR 0215)"));
                    }
                    let id = crate::random_hex(16);
                    c.execute_batch(&format!("CREATE TABLE {schema}.chat_store (id TEXT NOT NULL, region TEXT NOT NULL, created_at INTEGER NOT NULL)")).map_err(e)?;
                    c.execute(&format!("INSERT INTO {schema}.chat_store (id, region, created_at) VALUES (?1, ?2, ?3)"), params![id, region, now()]).map_err(e)?;
                    out.created.push(region.clone());
                    id
                }
            };
            c.query_row(&format!("PRAGMA {schema}.journal_mode = WAL"), [], |_| Ok(())).map_err(e)?;
            c.execute(
                "INSERT INTO main.chat_stores (region, store_id, path, added_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(region) DO UPDATE SET store_id = ?2, path = ?3",
                params![region, id, path_str, now()],
            )
            .map_err(e)?;
            for (k, main) in KEPT.iter().zip(&mains) {
                ensure_table(&c, &schema, k, main).map_err(e)?;
            }
            let top: i64 = c.query_row(&format!("SELECT COALESCE(MAX(id), 0) FROM {schema}.messages"), [], |r| r.get(0)).map_err(e)?;
            bump_sequence(&c, top).map_err(e)?;
            stores.push(ChatStore { region: region.clone(), schema, path, id });
        }
        for (region, _) in &out.forgotten {
            c.execute("DELETE FROM main.chat_stores WHERE region = ?1", [region]).map_err(e)?;
        }
        if !stores.is_empty() {
            for (k, cols) in KEPT.iter().zip(&cols) {
                // A move stopped between its copy and its delete leaves a row in two places
                // until the next pass; each id is read from the first place that has it, so
                // the scheduler doesn't run a routine twice (updates by id keep both alike).
                let rowid = if k.rowid { ", rowid AS rowid" } else { "" };
                let places: Vec<&str> = schemas(&stores).collect();
                let parts: Vec<String> = places
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let t = k.name;
                        let earlier: Vec<String> = places[..i].iter().map(|e| format!(" AND NOT EXISTS (SELECT 1 FROM {e}.{t} WHERE id = x.id)")).collect();
                        format!("SELECT {cols}{rowid} FROM {s}.{t} AS x WHERE true{}", earlier.concat())
                    })
                    .collect();
                c.execute_batch(&format!("CREATE TEMP VIEW {} AS {}", k.name, parts.join(" UNION ALL "))).map_err(e)?;
            }
        }
        let _ = self.5.set(ChatStores { stores, cols, unflushed: Default::default() });
        Ok(out)
    }

    /// The schema a new row of `bot_id`'s goes to.
    fn place_for(&self, c: &Connection, bot_id: &str) -> rusqlite::Result<&str> {
        let stores = self.chat_stores_set();
        if stores.is_empty() {
            return Ok("main");
        }
        let region: Option<String> = c.query_row(&format!("SELECT {}", pinned_region("?1")), [bot_id], |r| r.get(0))?;
        Ok(region.and_then(|r| stores.iter().find(|s| s.region == r)).map_or("main", |s| s.schema.as_str()))
    }

    /// Inserts a message into the place `bot_id`'s chat belongs: `cols` and `vals` without
    /// the id. Its id.
    pub(super) fn insert_chat_message(&self, c: &Connection, bot_id: &str, cols: &[&str], vals: &[&dyn ToSql]) -> rusqlite::Result<i64> {
        let schema = self.place_for(c, bot_id)?;
        let marks = vec!["?"; vals.len()].join(", ");
        if schema == "main" {
            c.execute(&format!("INSERT INTO main.messages ({}) VALUES ({marks})", cols.join(", ")), vals)?;
            return Ok(c.last_insert_rowid());
        }
        c.execute_batch("SAVEPOINT chat_insert")?;
        let r = (|| {
            let mut top: i64 = c.query_row("SELECT COALESCE((SELECT seq FROM main.sqlite_sequence WHERE name = 'messages'), 0)", [], |r| r.get(0))?;
            for s in schemas(self.chat_stores_set()) {
                top = top.max(c.query_row(&format!("SELECT COALESCE(MAX(id), 0) FROM {s}.messages"), [], |r| r.get(0))?);
            }
            let id = top + 1;
            let mut all: Vec<&dyn ToSql> = vec![&id];
            all.extend_from_slice(vals);
            c.execute(&format!("INSERT INTO {schema}.messages (id, {}) VALUES (?, {marks})", cols.join(", ")), all.as_slice())?;
            bump_sequence(c, id)?;
            Ok(id)
        })();
        match r {
            Ok(id) => c.execute_batch("RELEASE chat_insert").map(|_| id),
            Err(err) => {
                let _ = c.execute_batch("ROLLBACK TO chat_insert; RELEASE chat_insert");
                Err(err)
            }
        }
    }

    /// Inserts a row of `table` (`routines` or `approvals`, whose ids are text) into the place
    /// `bot_id`'s data belongs (ADR 0228).
    pub(super) fn insert_kept(&self, c: &Connection, table: &str, bot_id: &str, cols: &[&str], vals: &[&dyn ToSql]) -> rusqlite::Result<()> {
        let schema = self.place_for(c, bot_id)?;
        let marks = vec!["?"; vals.len()].join(", ");
        c.execute(&format!("INSERT INTO {schema}.{table} ({}) VALUES ({marks})", cols.join(", ")), vals).map(|_| ())
    }

    /// A new id for a row of `table` that no place uses: each place's primary key holds only
    /// its own rows, and updates by id run on every place.
    pub(super) fn unused_id(&self, c: &Connection, table: &str) -> rusqlite::Result<String> {
        loop {
            let id = crate::short_id();
            let used: bool = c.query_row(&format!("SELECT EXISTS (SELECT 1 FROM {table} WHERE id = ?1)"), [&id], |r| r.get(0))?;
            if !used {
                return Ok(id);
            }
        }
    }

    /// Runs `sql`, which names kept tables as `{messages}`, `{routines}` or `{approvals}`, on
    /// every place they are kept. The rows it changed, together.
    pub(super) fn on_places(&self, c: &Connection, sql: &str, p: &[&dyn ToSql]) -> rusqlite::Result<usize> {
        let mut n = 0;
        for s in schemas(self.chat_stores_set()) {
            let q = KEPT.iter().fold(sql.to_string(), |q, k| q.replace(&token(k.name), &format!("{s}.{}", k.name)));
            n += c.execute(&q, p)?;
        }
        Ok(n)
    }

    /// The highest message id anywhere.
    pub(super) fn top_message_id(&self, c: &Connection) -> i64 {
        schemas(self.chat_stores_set())
            .filter_map(|s| c.query_row(&format!("SELECT COALESCE(MAX(id), 0) FROM {s}.messages"), [], |r| r.get::<_, i64>(0)).ok())
            .max()
            .unwrap_or(0)
    }

    /// Moves every Bot's messages, routines and approvals to where they belong now, and
    /// deletes store rows whose Bot is gone (botd's own tables lose them with the Bot). What
    /// moved, per pair of places. The rows deleted from where they were are zeroed in the file
    /// (`secure_delete`), and its WAL emptied, so no copy is left in a place's free pages.
    pub fn place_chats(&self) -> rusqlite::Result<Vec<ChatMove>> {
        let Some(set) = self.5.get().filter(|s| !s.stores.is_empty()) else {
            return Ok(Vec::new());
        };
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        let case: String = set.stores.iter().map(|s| format!(" WHEN {} THEN {}", literal(&s.region), literal(&s.schema))).collect();
        tx.execute_batch(&format!(
            "CREATE TEMP TABLE IF NOT EXISTS chat_place (bot_id TEXT PRIMARY KEY, schema TEXT NOT NULL);
             DELETE FROM temp.chat_place;
             INSERT INTO temp.chat_place (bot_id, schema) SELECT b.id, CASE {}{case} ELSE 'main' END FROM main.bots b;",
            pinned_region("b.id")
        ))?;
        let here = |to: &str| format!("bot_id IN (SELECT bot_id FROM temp.chat_place WHERE schema = {})", literal(to));
        let pairs: Vec<(&str, &str)> = schemas(&set.stores).flat_map(|to| schemas(&set.stores).filter(move |f| *f != to).map(move |from| (from, to))).collect();
        for &(from, to) in &pairs {
            let here = here(to);
            for (k, cols) in KEPT.iter().zip(&set.cols) {
                tx.execute(&format!("INSERT OR IGNORE INTO {to}.{t} ({cols}) SELECT {cols} FROM {from}.{t} WHERE {here} ORDER BY rowid", t = k.name), [])?;
            }
        }
        tx.commit()?;
        #[cfg(test)]
        if tests::CRASH_AFTER_COPY.with(|c| c.replace(false)) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let moves = zeroing(&c, || {
            let tx = c.unchecked_transaction()?;
            let mut moves = Vec::new();
            let at = now();
            for &(from, to) in &pairs {
                let copied = |t: &str| format!("{} AND id IN (SELECT id FROM {to}.{t})", here(to));
                let theirs = KEPT.iter().map(|k| format!("SELECT bot_id FROM {from}.{t} WHERE {w}", t = k.name, w = copied(k.name))).collect::<Vec<_>>().join(" UNION ");
                let bots: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM ({theirs})"), [], |r| r.get(0))?;
                if bots == 0 {
                    continue;
                }
                let from_region = region_of(&set.stores, from).map(str::to_string);
                if let Some(r) = &from_region {
                    tx.execute(
                        &format!(
                            "INSERT INTO main.chat_moves_out (bot_id, region, moved_at) SELECT bot_id, ?1, ?2 FROM ({theirs}) WHERE true
                             ON CONFLICT(bot_id, region) DO UPDATE SET moved_at = excluded.moved_at, cleared_at = NULL"
                        ),
                        params![r, at],
                    )?;
                }
                let mut n = [0; 3];
                for (i, k) in KEPT.iter().enumerate() {
                    n[i] = tx.execute(&format!("DELETE FROM {from}.{} WHERE {}", k.name, copied(k.name)), [])?;
                }
                let to = region_of(&set.stores, to).map(str::to_string);
                moves.push(ChatMove { from: from_region, to, bots: bots as usize, messages: n[0], routines: n[1], approvals: n[2] });
            }
            for s in &set.stores {
                for k in &KEPT {
                    tx.execute(&format!("DELETE FROM {}.{} WHERE bot_id NOT IN (SELECT id FROM main.bots)", s.schema, k.name), [])?;
                }
            }
            tx.commit()?;
            Ok(moves)
        })?;
        if !moves.is_empty() || set.unflushed.load(Ordering::Relaxed) {
            let done = schemas(&set.stores).fold(true, |done, s| flush(&c, s) && done);
            set.unflushed.store(!done, Ordering::Relaxed);
        }
        Ok(moves)
    }

    /// True while rows that left a place may still be readable in its file, because a
    /// reader blocked the checkpoint after the move. The next pass tries again.
    pub fn chat_stores_unflushed(&self) -> bool {
        self.5.get().is_some_and(|s| s.unflushed.load(Ordering::Relaxed))
    }

    /// What of the Bots `owners` own is in each place: botd's own database first, then each
    /// store, places with none left out.
    pub fn chat_counts(&self, owners: &[String]) -> Vec<ChatCount> {
        let owners = serde_json::to_string(owners).unwrap_or_else(|_| "[]".into());
        let c = self.c();
        let stores = self.chat_stores_set();
        let theirs = "bot_id IN (SELECT id FROM main.bots WHERE owner_id IN (SELECT value FROM json_each(?1)))";
        schemas(stores)
            .filter_map(|s| {
                let held = held_in(&c, s, theirs, &[&owners]).ok()?;
                (held.total() > 0).then(|| ChatCount { region: region_of(stores, s).map(str::to_string), held })
            })
            .collect()
    }

    /// When the chats of Bots `owners` own last left each store other than `except`'s, as
    /// `(region, moved_at)`: that store's backups from before then still hold them, until
    /// botd has cleared them out of those backups (ADR 0238).
    pub fn chat_moves_out(&self, owners: &[String], except: &str) -> Vec<(String, i64)> {
        let owners = serde_json::to_string(owners).unwrap_or_else(|_| "[]".into());
        let c = self.c();
        let Ok(mut s) = c.prepare(
            "SELECT region, MAX(moved_at) FROM main.chat_moves_out WHERE region != ?2 AND cleared_at IS NULL
             AND bot_id IN (SELECT id FROM main.bots WHERE owner_id IN (SELECT value FROM json_each(?1))) GROUP BY region ORDER BY region",
        ) else {
            return Vec::new();
        };
        s.query_map(params![owners, except], |r| Ok((r.get(0)?, r.get(1)?))).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// The Bots whose rows left `store` and that its backups may still hold, as `(bot_id,
    /// moved_at)` (ADR 0238): not yet cleared, kept somewhere else now (or deleted since),
    /// and with nothing of theirs left in the store itself, so a move still pending never
    /// takes the only other copy.
    pub fn moves_out_to_clear(&self, store: &ChatStore) -> rusqlite::Result<Vec<(String, i64)>> {
        let none_left: String = KEPT.iter().map(|k| format!(" AND NOT EXISTS (SELECT 1 FROM {}.{} WHERE bot_id = m.bot_id)", store.schema, k.name)).collect();
        let c = self.c();
        let mut s = c.prepare(&format!(
            "SELECT m.bot_id, m.moved_at FROM main.chat_moves_out m
             WHERE m.region = ?1 AND m.cleared_at IS NULL AND ({}) IS NOT ?1{none_left}
             ORDER BY m.bot_id",
            pinned_region("m.bot_id")
        ))?;
        s.query_map([&store.region], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    /// Records that `region`'s backups no longer hold the rows of these moves (from
    /// `moves_out_to_clear`). A Bot that moved out again since keeps its newer move. How
    /// many were recorded.
    pub fn moves_out_cleared(&self, region: &str, moves: &[(String, i64)], at: i64) -> rusqlite::Result<usize> {
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        let mut n = 0;
        for (bot, moved_at) in moves {
            n += tx.execute(
                "UPDATE main.chat_moves_out SET cleared_at = ?4 WHERE region = ?1 AND bot_id = ?2 AND moved_at = ?3 AND cleared_at IS NULL",
                params![region, bot, moved_at, at],
            )?;
        }
        tx.commit()?;
        Ok(n)
    }

    /// Every store and what it holds.
    pub fn chat_store_counts(&self) -> Vec<(ChatStore, Held)> {
        let c = self.c();
        self.chat_stores_set().iter().map(|s| (s.clone(), held_in(&c, &s.schema, "1", &[]).unwrap_or_default())).collect()
    }

    /// Redacts known secrets from the stores' chats and approval subjects, as startup does
    /// for botd's own (`redact::scrub_rows`). How many rows changed.
    pub fn scrub_chat_stores(&self) -> rusqlite::Result<usize> {
        let stores = self.chat_stores_set();
        if stores.is_empty() {
            return Ok(0);
        }
        let table = |k: usize| stores.iter().map(|s| format!("{}.{}", s.schema, KEPT[k].name)).collect::<Vec<_>>();
        let (messages, approvals) = (table(MESSAGES), table(APPROVALS));
        let (messages, approvals): (Vec<&str>, Vec<&str>) = (messages.iter().map(String::as_str).collect(), approvals.iter().map(String::as_str).collect());
        crate::secrets::redact::scrub_rows_in(&self.c(), &messages, &approvals)
    }

    /// Brings the stores' approval inputs under the master key `current`, as startup does
    /// botd's own (ADR 0228): those sealed under `previous` (mid-rotation) are sealed again,
    /// plaintext is sealed, and with `forget` (SUPERBOT_FORGET_SEALED=1) those neither key
    /// opens are dropped. The values replaced are zeroed and the store's WAL emptied, so they
    /// don't linger in its free pages. Refuses when an input opens with neither key and
    /// nothing says what to do about it.
    pub fn seal_store_approvals(&self, current: &Cipher, previous: Option<&Cipher>, forget: bool) -> Result<StoreApprovals, String> {
        let c = self.c();
        let mut done = StoreApprovals::default();
        for s in self.chat_stores_set() {
            let table = format!("{}.approvals", s.schema);
            let r = zeroing(&c, || Ok(sealed::approvals_in(&c, &table, current, previous, forget)))
                .map_err(|e| e.to_string())
                .and_then(|r| r)
                .map_err(|e| format!("{}'s chat store: {e}", s.region))?;
            if r.sealed + r.resealed + r.discarded > 0 && !flush(&c, &s.schema) {
                if let Some(set) = self.5.get() {
                    set.unflushed.store(true, Ordering::Relaxed);
                }
            }
            done.add(&r);
        }
        Ok(done)
    }

    /// Which place row `id` of `table` is in: None for botd's own database.
    #[cfg(test)]
    pub fn place_of(&self, table: &str, id: &dyn ToSql) -> Option<Option<String>> {
        let c = self.c();
        let stores = self.chat_stores_set();
        schemas(stores)
            .find(|s| c.query_row(&format!("SELECT 1 FROM {s}.{table} WHERE id = ?1"), [id], |_| Ok(())).is_ok())
            .map(|s| region_of(stores, s).map(str::to_string))
    }

    /// Which place message `id` is in: None for botd's own database.
    #[cfg(test)]
    pub fn chat_place_of(&self, id: i64) -> Option<Option<String>> {
        self.place_of("messages", &id)
    }
}


/// How many rows of `bots` a copy of a store opened on `c` (one of its backups) holds.
pub fn held_in_copy(c: &Connection, bots: &[String]) -> rusqlite::Result<Held> {
    let bots = serde_json::to_string(bots).unwrap_or_else(|_| "[]".into());
    held_in(c, "main", "bot_id IN (SELECT value FROM json_each(?1))", &[&bots])
}

/// Deletes the rows of `bots` from a copy of a store opened on `c`, zeroing them
/// (`secure_delete`), and rebuilds the file so no page of theirs is left in it (ADR 0238).
/// What was deleted.
pub fn drop_from_copy(c: &Connection, bots: &[String]) -> rusqlite::Result<Held> {
    let held = delete_in_copy(c, "IN", bots)?;
    c.execute_batch("VACUUM")?;
    Ok(held)
}

/// Deletes the rows of every Bot but `keep` from a copy of a store opened on `c`, zeroing
/// them (`secure_delete`), for a backup about to be restored (ADR 0256): rows of Bots kept
/// elsewhere now, or deleted, would otherwise come back. The caller VACUUMs. What was deleted.
pub fn keep_only_in_copy(c: &Connection, keep: &[String]) -> rusqlite::Result<Held> {
    delete_in_copy(c, "NOT IN", keep)
}

fn delete_in_copy(c: &Connection, op: &str, bots: &[String]) -> rusqlite::Result<Held> {
    let list = serde_json::to_string(bots).unwrap_or_else(|_| "[]".into());
    c.execute_batch("PRAGMA secure_delete = ON")?;
    let tx = c.unchecked_transaction()?;
    let mut n = [0; 3];
    for (i, k) in KEPT.iter().enumerate() {
        let exists: bool = tx.query_row("SELECT COUNT(*) > 0 FROM main.sqlite_master WHERE type = 'table' AND name = ?1", [k.name], |r| r.get(0))?;
        if exists {
            n[i] = tx.execute(&format!("DELETE FROM main.{} WHERE bot_id {op} (SELECT value FROM json_each(?1))", k.name), [&list])? as i64;
        }
    }
    tx.commit()?;
    Ok(Held::of(n))
}

/// Brings a copy of a store opened on `c` (a backup from an older botd, perhaps without
/// routines or approvals, ADR 0228) to the tables botd keeps now, from botd's own database
/// attached as `botd`, as attaching the store does.
pub fn upgrade_copy(c: &Connection, botd: &str) -> rusqlite::Result<()> {
    for k in KEPT.iter() {
        let main = columns(c, botd, k.name)?;
        ensure_table(c, "main", k, &main)?;
    }
    Ok(())
}

/// The Bots whose chats, routines and approvals belong in `region`'s store: those whose
/// owner's pin (their team's, else their own) is in it. `c` is botd's own database.
pub fn bots_kept_in(c: &Connection, region: &str) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare(&format!("SELECT b.id FROM main.bots b WHERE ({}) = ?1 ORDER BY b.id", pinned_region("b.id")))?;
    s.query_map([region], |r| r.get(0))?.collect()
}

/// What a copy of a store opened on `c` holds that the store attached as `schema` doesn't
/// (it would come back), and what that store holds that the copy doesn't (it would go),
/// by id.
pub fn compare_copy(c: &Connection, schema: &str) -> rusqlite::Result<(Held, Held)> {
    let (mut back, mut gone) = ([0; 3], [0; 3]);
    for (i, k) in KEPT.iter().enumerate() {
        let t = k.name;
        back[i] = c.query_row(&format!("SELECT COUNT(*) FROM main.{t} WHERE id NOT IN (SELECT id FROM {schema}.{t})"), [], |r| r.get(0))?;
        gone[i] = c.query_row(&format!("SELECT COUNT(*) FROM {schema}.{t} WHERE id NOT IN (SELECT id FROM main.{t})"), [], |r| r.get(0))?;
    }
    Ok((Held::of(back), Held::of(gone)))
}

/// A temporary folder for tests, removed when dropped.
#[cfg(test)]
pub(crate) struct Scratch(PathBuf);

#[cfg(test)]
impl Scratch {
    pub(crate) fn new() -> Self {
        let d = std::env::temp_dir().join(format!("superbot-chats-{}", crate::short_id()));
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Visibility;
    use crate::db::{NewRule, PinOn};
    use crate::rbac::Role;
    use std::cell::Cell;

    thread_local! {
        /// Stops the next `place_chats` between its copy and its delete, as a crash would.
        pub(super) static CRASH_AFTER_COPY: Cell<bool> = const { Cell::new(false) };
    }

    struct Dirs {
        dir: super::Scratch,
        lon: PathBuf,
        fra: PathBuf,
    }

    impl Dirs {
        fn new() -> Dirs {
            let dir = super::Scratch::new();
            let (lon, fra) = (dir.path().join("lon"), dir.path().join("fra"));
            std::fs::create_dir_all(&lon).unwrap();
            std::fs::create_dir_all(&fra).unwrap();
            Dirs { dir, lon, fra }
        }

        fn db(&self) -> Db {
            Db::open(&self.dir.path().join("app.sqlite")).unwrap()
        }

        fn both(&self) -> Vec<(String, PathBuf)> {
            vec![("gb-lon".into(), self.lon.clone()), ("de-fra-2".into(), self.fra.clone())]
        }

        /// botd with both stores, as at startup.
        fn up(&self) -> Db {
            let db = self.db();
            db.attach_chat_stores(&self.both(), &[], None).unwrap();
            db
        }
    }

    fn user(db: &Db, name: &str) -> String {
        db.create_user(None, Some(&format!("{name}@example.com")), name, Role::Member).unwrap().id
    }

    fn bot_of(db: &Db, owner: &str) -> String {
        db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, owner, Visibility::Private).id
    }

    fn mv(from: Option<&str>, to: Option<&str>, bots: usize, n: [usize; 3]) -> ChatMove {
        ChatMove { from: from.map(str::to_string), to: to.map(str::to_string), bots, messages: n[0], routines: n[1], approvals: n[2] }
    }

    fn rows_in(path: &Path) -> i64 {
        let c = Connection::open(path).unwrap();
        c.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn without_stores_everything_stays_in_botds_own_table() {
        let d = Dirs::new();
        let db = d.db();
        assert_eq!(db.attach_chat_stores(&[], &[], None).unwrap(), Attached::default());
        let u = user(&db, "ada");
        db.pin_residency(PinOn::User, &u, "gb-lon", "DPA-1", None).unwrap();
        let m = db.add_message(&bot_of(&db, &u), "user", "hi", None, false, None);
        assert_eq!(db.chat_place_of(m.id), Some(None));
        assert!(db.place_chats().unwrap().is_empty() && db.chat_stores().is_empty());
        assert!(db.attach_chat_stores(&[], &[], None).unwrap_err().contains("once"));
    }

    #[test]
    fn a_pinned_owners_chat_is_kept_in_their_regions_store_and_reads_see_every_place() {
        let d = Dirs::new();
        let db = d.db();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let (ada_bot, cy_bot) = (bot_of(&db, &ada), bot_of(&db, &cy));
        let before = db.add_message(&ada_bot, "user", "before the store", None, false, None);
        assert_eq!(db.attach_chat_stores(&d.both(), &[], None).unwrap().created, vec!["gb-lon", "de-fra-2"]);
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();

        let m = db.add_message(&ada_bot, "user", "in London", None, false, Some("queued"));
        let other = db.add_message(&cy_bot, "user", "not pinned", None, false, None);
        assert_eq!(db.chat_place_of(m.id), Some(Some("gb-lon".into())));
        assert_eq!(db.chat_place_of(other.id), Some(None));
        assert!(m.id > before.id && other.id > m.id, "ids stay unique and rising across places: {} {} {}", before.id, m.id, other.id);
        // Reads see both places; updates by id reach the store.
        assert_eq!(db.messages(&ada_bot, 10).iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), vec!["before the store", "in London"]);
        assert_eq!(db.pending().len(), 1);
        db.set_status(m.id, "done");
        assert_eq!(db.message(m.id).unwrap().status.as_deref(), Some("done"));
        assert!(db.pending().is_empty());
        assert_eq!(db.last_id(), other.id);

        // A pass moves the older message to London too, once.
        assert_eq!(db.place_chats().unwrap(), vec![mv(None, Some("gb-lon"), 1, [1, 0, 0])]);
        assert!(db.place_chats().unwrap().is_empty());
        assert_eq!((rows_in(&d.lon.join("chats.sqlite")), rows_in(&d.fra.join("chats.sqlite"))), (2, 0));
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), held: Held { messages: 2, ..Held::default() } }]);
        assert_eq!(db.chat_counts(std::slice::from_ref(&cy)), vec![ChatCount { region: None, held: Held { messages: 1, ..Held::default() } }]);
        assert_eq!(db.messages(&ada_bot, 10).len(), 2, "no copy left behind");

        // Unpinned, it comes back to botd's own table, ids unchanged.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![mv(Some("gb-lon"), None, 1, [2, 0, 0])]);
        assert_eq!(db.chat_place_of(m.id), Some(None));
        // botd's own table never hands out an id a store used.
        assert!(db.add_message(&cy_bot, "user", "next", None, false, None).id > other.id);
    }

    #[test]
    fn a_team_pin_holds_its_members_chats_and_a_member_leaving_takes_theirs_out() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let t = db.create_team("Acme", None);
        assert!(db.add_team_member(&t.id, &ada, "member", None));
        db.pin_residency(PinOn::Team, &t.id, "de-fra-2", "MSA-1", None).unwrap();
        let m = db.add_message(&bot_of(&db, &ada), "user", "x", None, false, None);
        assert_eq!(db.chat_place_of(m.id), Some(Some("de-fra-2".into())));
        assert!(db.remove_team_member(&t.id, &ada, false));
        assert_eq!(db.place_chats().unwrap(), vec![mv(Some("de-fra-2"), None, 1, [1, 0, 0])]);
    }

    #[test]
    fn writes_by_id_retention_and_deleting_a_bot_reach_the_store() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let m = db.add_message(&bot, "bot", "q", None, false, None);
        db.set_question(m.id, &serde_json::json!({ "title": "pick" }));
        assert_eq!(db.message(m.id).unwrap().question.unwrap()["title"], "pick");
        db.set_requested_by(m.id, &crate::audit::Who::system("test"));
        assert!(db.message(m.id).unwrap().requested_by.is_some());
        db.add_messages_at(&bot, 3, now() - 10 * 86_400_000, None);
        assert_eq!(db.message_count(&bot), 4);
        let (gone, _) = db.prune_chat_batch(now() - 86_400_000, None, 100).unwrap();
        assert_eq!((gone, db.message_count(&bot)), (3, 1));
        assert_eq!(rows_in(&d.lon.join("chats.sqlite")), 1);
        // A Bot deleted from botd's own table takes its chat in the store with it.
        assert!(db.delete_bot_unless_held(&bot));
        assert_eq!(rows_in(&d.lon.join("chats.sqlite")), 0);
        let other = bot_of(&db, &ada);
        db.add_message(&other, "user", "y", None, false, None);
        db.delete_bot(&other);
        db.place_chats().unwrap();
        assert_eq!(rows_in(&d.lon.join("chats.sqlite")), 0, "a pass deletes what a Bot deleted another way left");
    }

    #[test]
    fn a_copy_left_in_both_places_by_a_crash_is_cleared_by_the_next_pass() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let bot = bot_of(&db, &ada);
        let m = db.add_message(&bot, "user", "x", None, false, None);
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        // As if the store's commit landed and botd's own didn't.
        db.c().execute("INSERT INTO chats_0.messages SELECT * FROM main.messages WHERE id = ?1", [m.id]).unwrap();
        assert_eq!((count(&db, "main", "messages"), count(&db, "chats_0", "messages")), (1, 1));
        assert_eq!(db.message_count(&bot), 1, "read once meanwhile");
        db.place_chats().unwrap();
        assert_eq!((db.message_count(&bot), db.chat_place_of(m.id)), (1, Some(Some("gb-lon".into()))));
    }

    #[test]
    fn a_move_stopped_between_copy_and_delete_loses_nothing() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let bot = bot_of(&db, &ada);
        let m = db.add_message(&bot, "user", "x", None, false, None);
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!(rows_in(&d.lon.join("chats.sqlite")), 1, "the copy is committed first");
        assert_eq!(db.c().query_row("SELECT COUNT(*) FROM main.messages WHERE id = ?1", [m.id], |r| r.get::<_, i64>(0)).unwrap(), 1, "and the original is still there");
        let moves = db.place_chats().unwrap();
        assert_eq!((moves[0].messages, db.message_count(&bot), db.chat_place_of(m.id)), (1, 1, Some(Some("gb-lon".into()))));
    }

    #[test]
    fn a_chat_leaving_a_store_is_recorded_for_that_stores_earlier_backups() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.add_message(&bot_of(&db, &ada), "user", "x", None, false, None);
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        db.place_chats().unwrap();
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "gb-lon").is_empty(), "moving out of botd's own database isn't a store's");
        db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        let out = db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2");
        assert!(out.len() == 1 && out[0].0 == "gb-lon" && now() - out[0].1 < 60_000, "{out:?}");
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "gb-lon").is_empty(), "not a copy outside a pin back to gb-lon");
    }

    #[test]
    fn move_records_from_before_clearing_backups_gain_its_column() {
        let d = Dirs::new();
        let ada = {
            let db = d.up();
            let ada = user(&db, "ada");
            db.add_message(&bot_of(&db, &ada), "user", "x", None, false, None);
            db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
            db.place_chats().unwrap();
            db.unpin_residency(PinOn::User, &ada).unwrap();
            db.place_chats().unwrap();
            ada
        };
        Connection::open(d.dir.path().join("app.sqlite")).unwrap().execute_batch("ALTER TABLE chat_moves_out DROP COLUMN cleared_at").unwrap();
        let db = d.up();
        assert_eq!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "an older move is still an earlier copy");
        let lon = db.chat_stores()[0].clone();
        let moves = db.moves_out_to_clear(&lon).unwrap();
        assert_eq!(db.moves_out_cleared("gb-lon", &moves, now()).unwrap(), 1);
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").is_empty());
    }

    #[test]
    fn a_store_that_goes_missing_or_isnt_the_one_recorded_stops_botd() {
        let d = Dirs::new();
        {
            let db = d.up();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
            db.add_message(&bot_of(&db, &ada), "user", "x", None, false, None);
        }
        let start = |dirs: &[(String, PathBuf)]| d.db().attach_chat_stores(dirs, &[], None);

        // Dropped from REGION_DATA_DIRS while it holds chats.
        let e = start(&d.both()[1..]).unwrap_err();
        assert!(e.contains("no longer names gb-lon") && e.contains("still holds 1 chat message of pinned"), "{e}");
        // Its file gone (an unmounted volume): no empty store is made in its place.
        let (lon, kept) = (d.lon.join("chats.sqlite"), d.dir.path().join("kept.sqlite"));
        std::fs::rename(&lon, &kept).unwrap();
        let e = start(&d.both()).unwrap_err();
        assert!(e.contains("gb-lon's chat store") && e.contains("Is its volume mounted"), "{e}");
        assert!(!lon.exists());
        // Another region's store, or another store for this region.
        let e = start(&[("gb-lon".into(), d.fra.clone()), ("de-fra-2".into(), d.fra.clone())]).unwrap_err();
        assert!(e.contains("de-fra-2's chat store, not gb-lon's"), "{e}");
        let other = super::Scratch::new();
        Db::open(&other.path().join("app.sqlite")).unwrap().attach_chat_stores(&[("gb-lon".into(), other.path().to_path_buf())], &[], None).unwrap();
        std::fs::copy(other.path().join("chats.sqlite"), &lon).unwrap();
        let e = start(&d.both()).unwrap_err();
        assert!(e.contains("but botd keeps gb-lon's chats in store"), "{e}");
        // A file that isn't a store.
        std::fs::remove_file(&lon).unwrap();
        Connection::open(&lon).unwrap().execute_batch("CREATE TABLE t (x)").unwrap();
        let e = start(&d.both()).unwrap_err();
        assert!(e.contains("isn't a SuperBot chat store"), "{e}");
        // Back in place, botd starts and reads it; the failed starts changed nothing.
        std::fs::remove_file(&lon).unwrap();
        std::fs::rename(&kept, &lon).unwrap();
        let db = d.db();
        assert_eq!(db.attach_chat_stores(&d.both(), &[], None).unwrap(), Attached::default());
        assert_eq!(db.chat_store_counts().iter().map(|(s, n)| (s.region.as_str(), n.messages)).collect::<Vec<_>>(), vec![("gb-lon", 1), ("de-fra-2", 0)]);
    }

    #[test]
    fn an_empty_store_dropped_from_the_settings_is_forgotten() {
        let d = Dirs::new();
        drop(d.up());
        let a = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap();
        assert_eq!(a.forgotten.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), vec!["de-fra-2"]);
        assert!(a.created.is_empty());
        // Named again later, its old file is adopted.
        assert_eq!(d.db().attach_chat_stores(&d.both(), &[], None).unwrap(), Attached::default());

        // Dropped with its file gone, or another file in its place: nothing shows it was
        // empty, so it is forgotten only when named in REGION_DATA_FORGET.
        let fra = d.fra.join("chats.sqlite");
        std::fs::rename(&fra, d.dir.path().join("fra-kept.sqlite")).unwrap();
        let e = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap_err();
        assert!(e.contains("no longer names de-fra-2, and its chat store") && e.contains("REGION_DATA_FORGET"), "{e}");
        Connection::open(&fra).unwrap().execute_batch("CREATE TABLE t (x)").unwrap();
        let e = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap_err();
        assert!(e.contains("isn't its chat store"), "{e}");
        std::fs::remove_file(&fra).unwrap();
        let a = d.db().attach_chat_stores(&d.both()[..1], &["de-fra-2".into()], None).unwrap();
        assert_eq!(a.forgotten.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), vec!["de-fra-2"]);
    }

    #[test]
    fn a_store_gets_the_columns_botds_table_gained_since() {
        let d = Dirs::new();
        drop(d.up());
        Connection::open(d.lon.join("chats.sqlite")).unwrap().execute_batch("ALTER TABLE messages DROP COLUMN requested_by").unwrap();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let m = db.add_message(&bot_of(&db, &ada), "user", "x", None, false, None);
        db.set_requested_by(m.id, &crate::audit::Who::system("test"));
        assert!(db.message(m.id).unwrap().requested_by.is_some());
    }

    #[test]
    fn a_store_is_encrypted_with_botds_own_key() {
        use crate::database_encryption::{DbKey, format};
        use crate::secrets::key::MasterKey;
        let dir = super::Scratch::new();
        let key = DbKey::derive(&MasterKey::generate());
        let here = [("gb-lon".to_string(), dir.path().to_path_buf())];
        {
            let db = Db::open_keyed(&dir.path().join("app.sqlite"), &key);
            db.attach_chat_stores(&here, &[], Some(key.raw())).unwrap();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
            let m = db.add_message(&bot_of(&db, &ada), "user", "secret chat", None, false, None);
            assert_eq!(db.message(m.id).unwrap().text, "secret chat");
        }
        let store = dir.path().join("chats.sqlite");
        assert_eq!(format(&store).unwrap(), Format::Encrypted);
        assert!(!std::fs::read(&store).unwrap().windows(11).any(|w| w == b"secret chat"));
        let other = DbKey::derive(&MasterKey::generate());
        let e = Db::open_keyed(&dir.path().join("app.sqlite"), &key).attach_chat_stores(&here, &[], Some(other.raw())).unwrap_err();
        assert!(e.contains("doesn't open with botd's database key"), "{e}");
    }

    #[test]
    fn startup_brings_a_store_under_botds_key_and_changes_no_other_file() {
        use crate::database_encryption::{DbKey, format, opens, prepare_store};
        use crate::secrets::key::MasterKey;
        let dir = super::Scratch::new();
        let (old, new) = (DbKey::derive(&MasterKey::generate()), DbKey::derive(&MasterKey::generate()));
        let here = [("gb-lon".to_string(), dir.path().to_path_buf())];
        Db::open(&dir.path().join("app.sqlite")).unwrap().attach_chat_stores(&here, &[], None).unwrap();
        let store = dir.path().join("chats.sqlite");
        assert!(!prepare_store(&store, None, None).unwrap(), "plain stays plain without a key");

        // A plain store is encrypted once botd's database is, then re-keyed mid-rotation.
        assert!(prepare_store(&store, Some(&old), None).unwrap());
        assert!(format(&store).unwrap() == Format::Encrypted && opens(&store, &old));
        assert!(!prepare_store(&store, Some(&old), None).unwrap(), "already under the key");
        assert!(prepare_store(&store, Some(&new), Some(&old)).unwrap());
        assert!(opens(&store, &new) && !opens(&store, &old));
        let e = prepare_store(&store, Some(&old), None).unwrap_err();
        assert!(e.contains("doesn't open with botd's database key"), "{e}");
        assert!(prepare_store(&store, None, None).unwrap_err().contains("is encrypted but botd's database isn't"));

        // Some other plain file in the folder is refused, untouched.
        let foreign = dir.path().join("other.sqlite");
        Connection::open(&foreign).unwrap().execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);").unwrap();
        let before = std::fs::read(&foreign).unwrap();
        let e = prepare_store(&foreign, Some(&new), None).unwrap_err();
        assert!(e.contains("isn't a chat store botd made"), "{e}");
        assert_eq!(std::fs::read(&foreign).unwrap(), before);
    }

    fn approve(db: &Db, bot: &str, subject: &str) -> String {
        db.add_approval(bot, "claude", "Bash", "command", subject, &serde_json::json!({ "command": subject }), "write", "asks", now() + 60_000).id
    }

    fn count(db: &Db, schema: &str, table: &str) -> i64 {
        db.c().query_row(&format!("SELECT COUNT(*) FROM {schema}.{table}"), [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_pinned_owners_routines_and_approvals_are_kept_with_their_chat() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let (bot, other) = (bot_of(&db, &ada), bot_of(&db, &cy));
        let before = db.add_routine(&bot, "before", "0 9 * * *", "made before the pin");
        let asked = approve(&db, &bot, "ls before");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();

        // New rows go straight to London; others' stay in botd's own database.
        let r = db.add_routine_by(&bot, "daily", "0 9 * * *", "summarise the contract", true, Some(&ada));
        let a = approve(&db, &bot, "cat contract.txt");
        let theirs = db.add_routine(&other, "x", "0 9 * * *", "not pinned");
        assert_eq!(db.place_of("routines", &r.id), Some(Some("gb-lon".into())));
        assert_eq!(db.place_of("approvals", &a), Some(Some("gb-lon".into())));
        assert_eq!(db.place_of("routines", &theirs.id), Some(None));

        // Reads see every place; the sealed input still opens where it is kept.
        assert_eq!(db.routines(None).len(), 3);
        assert_eq!(db.routines(Some(&bot)).iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["before", "daily"]);
        assert_eq!(db.approval(&a).unwrap().input["command"], "cat contract.txt");
        assert_eq!(db.approvals(Some("pending"), None, 10).len(), 2);
        assert_eq!(db.approvals_among(None, std::slice::from_ref(&bot), 10).len(), 2);
        assert_eq!(db.approvals_pending().0, 2);

        // Writes by id reach the store.
        db.update_routine(&r.id, Some("weekly"), Some("0 9 * * 1"), Some("summarise it again"), None, Some(&cy));
        assert!(db.pause_routine(&r.id, "owner_disabled", &ada, now()));
        assert_eq!(db.routines_paused_for(&ada).len(), 1);
        assert!(db.resume_routine(&r.id));
        db.routine_ran(&r.id, 42);
        let got = db.routine(&r.id).unwrap();
        assert_eq!((got.name.as_str(), got.instruction.as_str(), got.author_id.as_deref(), got.last_run_at), ("weekly", "summarise it again", Some(cy.as_str()), Some(42)));
        assert!(db.finish_approval(&a, "approved", "ada", Some("fine"), None));
        assert!(!db.finish_approval(&a, "denied", "cy", None, None), "first decision wins");
        assert_eq!(db.approval(&a).unwrap().status, "approved");
        let rule = NewRule { bot_id: Some(&bot), action: crate::policy::Action::Allow, tool: "Bash", pattern: "ls before", note: "ok" };
        assert!(db.finish_approval_with_rule(&asked, "approved", "ada", None, &rule).is_some(), "the rule is saved with a decision in the store");

        // A pass moves what was made before the pin; unpinned, all of it comes back.
        let moves = db.place_chats().unwrap();
        assert_eq!(moves, vec![mv(None, Some("gb-lon"), 1, [0, 1, 1])]);
        assert_eq!((count(&db, "chats_0", "routines"), count(&db, "chats_0", "approvals"), count(&db, "main", "routines")), (2, 2, 1));
        assert_eq!(db.routine(&before.id).unwrap().instruction, "made before the pin");
        assert_eq!(db.approval(&asked).unwrap().input["command"], "ls before", "sealed by its id, so it opens wherever it is kept");
        let held = db.chat_counts(std::slice::from_ref(&ada));
        assert_eq!(held, vec![ChatCount { region: Some("gb-lon".into()), held: Held { messages: 0, routines: 2, approvals: 2 } }]);
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![mv(Some("gb-lon"), None, 1, [0, 2, 2])]);
        assert_eq!((count(&db, "chats_0", "routines"), count(&db, "chats_0", "approvals")), (0, 0));
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").iter().any(|(r, _)| r == "gb-lon"), "London's earlier backups still hold them");
        assert_eq!(db.routines(None).len(), 3);
    }

    #[test]
    fn approvals_are_newest_first_with_ties_in_the_order_they_were_asked() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let ids: Vec<String> = (0..4).map(|i| approve(&db, &bot, &format!("cmd {i}"))).collect();
        db.c().execute("UPDATE chats_0.approvals SET created_at = 1000", []).unwrap();
        let listed: Vec<String> = db.approvals(None, Some(&bot), 10).into_iter().map(|a| a.id).collect();
        assert_eq!(listed, ids.iter().rev().cloned().collect::<Vec<_>>(), "the view keeps each place's rowid for the tie-break");
    }

    #[test]
    fn deleting_a_bot_takes_its_routines_and_approvals_out_of_the_store_at_once() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        db.add_routine(&bot, "daily", "0 9 * * *", "x");
        approve(&db, &bot, "ls");
        assert!(db.delete_bot_unless_held(&bot));
        assert_eq!((count(&db, "chats_0", "routines"), count(&db, "chats_0", "approvals")), (0, 0), "the scheduler never sees a routine whose Bot is gone");
        // One deleted another way is cleared by the next pass.
        let other = bot_of(&db, &ada);
        db.add_routine(&other, "daily", "0 9 * * *", "x");
        approve(&db, &other, "ls");
        db.delete_bot(&other);
        db.place_chats().unwrap();
        assert_eq!((count(&db, "chats_0", "routines"), count(&db, "chats_0", "approvals")), (0, 0));
    }

    #[test]
    fn erasing_someone_reaches_routines_and_approvals_in_a_store() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let r = db.add_routine_by(&bot, "cy's", "0 9 * * *", "written by cy", true, Some(&cy));
        let a = approve(&db, &bot, "ls");
        assert!(db.finish_approval(&a, "approved", &cy, Some("cy's note"), None));
        let out = db.erase_user(&cy, "erased-1", None, &[]).unwrap();
        assert_eq!((out.routines, out.approvals), (1, 1));
        assert!(db.routine(&r.id).is_none());
        let after = db.approval(&a).unwrap();
        assert_eq!((after.decided_by.as_deref(), after.note), (Some("erased-1"), None));
    }

    #[test]
    fn a_move_of_routines_and_approvals_stopped_between_copy_and_delete_loses_nothing() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let bot = bot_of(&db, &ada);
        let r = db.add_routine(&bot, "daily", "0 9 * * *", "x");
        let a = approve(&db, &bot, "ls");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!((count(&db, "chats_0", "routines"), count(&db, "main", "routines")), (1, 1), "copied, original kept");
        assert_eq!((db.routines(None).len(), db.approvals(None, None, 10).len()), (1, 1), "each read once, so the scheduler doesn't run it twice");
        // A decision meanwhile reaches both copies, so neither is stale.
        assert!(db.finish_approval(&a, "denied", "ada", None, None));
        assert_eq!(db.place_chats().unwrap(), vec![mv(None, Some("gb-lon"), 1, [0, 1, 1])]);
        assert_eq!((db.place_of("routines", &r.id), db.approval(&a).unwrap().status.as_str()), (Some(Some("gb-lon".into())), "denied"));
        assert_eq!(db.routines(None).len(), 1, "no copy left behind");
    }

    #[test]
    fn moved_rows_leave_no_copy_in_the_files_they_left() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let bot = bot_of(&db, &ada);
        let words = ["chat-4e1d6a-contract", "routine-93bc07-instruction", "approval-c5f2e8-subject"];
        db.add_message(&bot, "user", words[0], None, false, None);
        db.add_routine(&bot, "daily", "0 9 * * *", words[1]);
        approve(&db, &bot, words[2]);
        let holds = |path: &Path, w: &str| std::fs::read(path).is_ok_and(|b| b.windows(w.len()).any(|x| x == w.as_bytes()));
        let app = d.dir.path().join("app.sqlite");
        let wal = d.dir.path().join("app.sqlite-wal");
        assert!(words.iter().all(|w| holds(&app, w) || holds(&wal, w)), "written to botd's own database first");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![mv(None, Some("gb-lon"), 1, [1, 1, 1])]);
        for w in words {
            assert!(!holds(&app, w) && !holds(&wal, w), "{w} left in botd's own database's free pages or WAL");
        }
        assert_eq!(db.c().query_row("PRAGMA main.secure_delete", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "set back after the move");
        // And moving back out of London leaves nothing in its store either.
        let lon = d.lon.join("chats.sqlite");
        db.unpin_residency(PinOn::User, &ada).unwrap();
        db.place_chats().unwrap();
        for w in words {
            assert!(!holds(&lon, w) && !holds(&d.lon.join("chats.sqlite-wal"), w), "{w} left in London's store");
        }
    }

    #[test]
    fn a_checkpoint_a_reader_blocked_is_tried_again_on_the_next_pass() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let bot = bot_of(&db, &ada);
        let word = "routine-7a41d9-instruction";
        db.add_routine(&bot, "daily", "0 9 * * *", word);
        db.c().query_row("PRAGMA main.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        let app = d.dir.path().join("app.sqlite");
        let holds = || std::fs::read(&app).is_ok_and(|b| b.windows(word.len()).any(|x| x == word.as_bytes()));
        assert!(holds());
        let reader = Connection::open(&app).unwrap();
        reader.execute_batch("BEGIN; SELECT COUNT(*) FROM bots;").unwrap();
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.place_chats().unwrap().len(), 1);
        assert!(db.chat_stores_unflushed() && holds(), "the old page is still in the file");
        reader.execute_batch("COMMIT").unwrap();
        assert_eq!(db.place_chats().unwrap(), Vec::new());
        assert!(!db.chat_stores_unflushed() && !holds(), "a pass with nothing to move finishes it");
    }

    #[test]
    fn a_dropped_store_holding_routines_or_approvals_stops_botd() {
        let d = Dirs::new();
        {
            let db = d.up();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-1", None).unwrap();
            let bot = bot_of(&db, &ada);
            db.add_routine(&bot, "daily", "0 9 * * *", "x");
            approve(&db, &bot, "ls");
            approve(&db, &bot, "pwd");
        }
        let e = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap_err();
        assert!(e.contains("still holds 1 routine and 2 approvals of pinned people's Bots"), "{e}");
    }

    #[test]
    fn a_store_gets_the_routine_and_approval_columns_botds_tables_gained_since() {
        let d = Dirs::new();
        drop(d.up());
        Connection::open(d.lon.join("chats.sqlite")).unwrap().execute_batch("ALTER TABLE approvals DROP COLUMN scope; ALTER TABLE routines DROP COLUMN paused_at;").unwrap();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let a = approve(&db, &bot, "ls");
        assert!(db.finish_approval_for_run(&a, "ada", None));
        assert_eq!(db.approval(&a).unwrap().scope.as_deref(), Some("run"));
        let r = db.add_routine(&bot, "daily", "0 9 * * *", "x");
        assert!(db.pause_routine(&r.id, "owner_disabled", &ada, 7));
        assert_eq!(db.routine(&r.id).unwrap().paused_at, Some(7));
    }

    #[test]
    fn startup_seals_a_stores_approvals_under_the_current_master_key() {
        use crate::secrets::key::MasterKey;
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let (old, fresh) = (approve(&db, &bot, "under the old key"), approve(&db, &bot, "under the current key"));
        let current = sealed::cipher();
        let previous = Cipher::new(&MasterKey::generate());
        let ctx = sealed::approval_context(&old);
        let stale = previous.seal(&ctx, br#"{"command":"under the old key"}"#);
        db.c().execute("UPDATE chats_0.approvals SET input = ?1 WHERE id = ?2", params![stale, old]).unwrap();
        assert_eq!(db.approval(&old).unwrap().input["sealed"], "unreadable");
        // Outside a rotation, a value the key doesn't open refuses, changing nothing.
        let e = db.seal_store_approvals(&current, None, false).unwrap_err();
        assert!(e.contains("gb-lon's chat store: 1 saved tool inputs of approvals in it don't open with the master key") && e.contains("SUPERBOT_FORGET_SEALED=1"), "{e}");
        // Mid-rotation it is sealed again under the new key, once.
        let done = db.seal_store_approvals(&current, Some(&previous), false).unwrap();
        assert_eq!(done, StoreApprovals { resealed: 1, ..Default::default() });
        assert_eq!(db.approval(&old).unwrap().input["command"], "under the old key");
        assert_eq!(db.approval(&fresh).unwrap().input["command"], "under the current key");
        assert_eq!(db.seal_store_approvals(&current, Some(&previous), false).unwrap(), StoreApprovals::default());
        // Neither key: left as it was during a rotation, dropped when told to forget.
        let lost = Cipher::new(&MasterKey::generate()).seal(&ctx, b"{}");
        db.c().execute("UPDATE chats_0.approvals SET input = ?1 WHERE id = ?2", params![lost, old]).unwrap();
        assert_eq!(db.seal_store_approvals(&current, Some(&previous), false).unwrap(), StoreApprovals { unreadable: 1, ..Default::default() });
        assert_eq!(db.seal_store_approvals(&current, None, true).unwrap(), StoreApprovals { discarded: 1, ..Default::default() });
        assert_eq!(db.approval(&old).unwrap().input, serde_json::json!({ "sealed": "discarded" }));
        // Plaintext (from a copy made by hand) is redacted and sealed.
        db.c().execute("UPDATE chats_0.approvals SET input = '{\"command\":\"ls\"}' WHERE id = ?1", [&fresh]).unwrap();
        assert_eq!(db.seal_store_approvals(&current, None, false).unwrap(), StoreApprovals { sealed: 1, ..Default::default() });
        let raw: String = db.c().query_row("SELECT input FROM chats_0.approvals WHERE id = ?1", [&fresh], |r| r.get(0)).unwrap();
        assert!(sealed::is_sealed(&raw) && db.approval(&fresh).unwrap().input["command"] == "ls");
    }
}
