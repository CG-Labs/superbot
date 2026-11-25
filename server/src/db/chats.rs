//! Pinned people's chats, routines, approvals, Bots' memory, owners' facts, sign-in
//! sessions, own secrets and second factors in a database in their region (ADR 0215, ADR
//! 0228, ADR 0276, ADR 0277, ADR 0283, ADR 0293, ADR 0299), the first part of splitting
//! botd's database by region. Each region in REGION_DATA_DIRS has a SQLite file of its own
//! (`chats.sqlite`, keyed like botd's database), attached to botd's connection. A Bot's
//! messages, routines, approvals and memory are kept in the store of its owner's residency
//! pin (their team's, else their own, as `residency::of_user`), and a person's facts,
//! sessions (with each session's SAML sign-in and push device), own secrets and second
//! factor (with its recovery codes) in the store of their own pin by the same rule, or in
//! botd's own database when that region has no store or the person isn't pinned.
//! Their secrets are read and written on the users' secrets' own connection, which attaches
//! the stores too (`attach_to`, `secrets::sealed::UserSecrets`). botd's own copy of a
//! Bot's memory is a file in DATA_DIR (`DATA_DIR/bots/<id>/MEMORY.md`), and of a person's
//! facts too (`DATA_DIR/users/<id>/USER.md`); its `memories` and `facts` tables only hold
//! one on its way between that file and a store (`machines::chat_stores::place`).
//!
//! Reads see every place at once: a TEMP view per table (`messages`, `routines`,
//! `approvals`, `memories`, `facts`, `sessions`, `saml_sessions`, `push_devices`,
//! `user_mfa`, `mfa_recovery_codes`) puts
//! botd's own table and each store's together, and unqualified names find TEMP objects
//! first. Writes name the table they change: new rows go where their Bot's or person's data
//! belongs (a session's SAML sign-in and push device where the session is), and updates
//! and deletes by id run on each place. Ids stay unique
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

/// What a kept table's rows are kept by: their Bot (in the store of its owner's pin), or
/// their person (in the store of their own pin, ADR 0277).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Bot,
    User,
}

impl Key {
    fn column(self) -> &'static str {
        match self {
            Key::Bot => "bot_id",
            Key::User => "user_id",
        }
    }
}

/// A table whose rows are kept in the store of a pin.
struct Kept {
    name: &'static str,
    key: Key,
    /// Its primary key, unique across places: a column, or several (`"a, b"`).
    pk: &'static str,
    /// The indexes a store's copy gets, as `(name, columns)`.
    indexes: &'static [(&'static str, &'static str)],
    /// The unique indexes a store's copy gets, for the constraints botd's own table has.
    unique: &'static [(&'static str, &'static str)],
    /// The row of another kept table each row belongs to, as `(column, table)`: always in
    /// the same place. botd's own table deletes it with that row; a store's, on each pass.
    parent: Option<(&'static str, &'static str)>,
    /// Reads order by its rowid, which a view has only as a column of that name.
    rowid: bool,
}

/// A parent comes before the tables that point at it, so a move into botd's own database
/// copies it first, and deletes run in reverse.
const KEPT: [Kept; 11] = [
    Kept { name: "messages", key: Key::Bot, pk: "id", indexes: &[("messages_bot", "bot_id, id"), ("messages_created", "created_at")], unique: &[], parent: None, rowid: false },
    Kept { name: "routines", key: Key::Bot, pk: "id", indexes: &[("routines_bot", "bot_id")], unique: &[], parent: None, rowid: false },
    Kept { name: "approvals", key: Key::Bot, pk: "id", indexes: &[("approvals_status", "status, created_at"), ("approvals_bot", "bot_id")], unique: &[], parent: None, rowid: true },
    Kept { name: "memories", key: Key::Bot, pk: "id", indexes: &[("memories_bot", "bot_id")], unique: &[], parent: None, rowid: false },
    Kept { name: "facts", key: Key::User, pk: "id", indexes: &[("facts_user", "user_id")], unique: &[], parent: None, rowid: false },
    Kept { name: "sessions", key: Key::User, pk: "id", indexes: &[("sessions_user", "user_id, created_at")], unique: &[("sessions_token", "token_hash")], parent: None, rowid: false },
    Kept {
        name: "saml_sessions",
        key: Key::User,
        pk: "session_id",
        indexes: &[("saml_sessions_user", "user_id")],
        unique: &[],
        parent: Some(("session_id", "sessions")),
        rowid: false,
    },
    Kept {
        name: "push_devices",
        key: Key::User,
        pk: "id",
        indexes: &[("push_devices_user", "user_id, updated_at")],
        unique: &[("push_devices_session", "session_id"), ("push_devices_token", "token_hash")],
        parent: Some(("session_id", "sessions")),
        rowid: false,
    },
    Kept { name: "user_secrets", key: Key::User, pk: "user_id, name", indexes: &[], unique: &[], parent: None, rowid: false },
    Kept { name: "user_mfa", key: Key::User, pk: "user_id", indexes: &[], unique: &[], parent: None, rowid: false },
    Kept { name: "mfa_recovery_codes", key: Key::User, pk: "user_id, code_hash", indexes: &[], unique: &[], parent: Some(("user_id", "user_mfa")), rowid: false },
];
const N: usize = KEPT.len();
const MESSAGES: usize = 0;
const APPROVALS: usize = 2;
const PUSH_DEVICES: usize = 7;
const USER_SECRETS: usize = 8;
const SECOND_FACTORS: usize = 9;
const RECOVERY_CODES: usize = 10;

/// The tables of a person's sign-ins (ADR 0283): their sessions, and each one's SAML
/// sign-in and push device.
const SIGN_INS: [&str; 3] = ["sessions", "saml_sessions", "push_devices"];

/// The table of each person's own secrets (ADR 0029, ADR 0293).
pub const SECRETS: &str = "user_secrets";

/// The tables of each person's second factor (ADR 0094, ADR 0299): its sealed TOTP secret,
/// and its recovery codes' keyed hashes.
pub const SECOND_FACTOR: &str = "user_mfa";
pub const RECOVERY_CODE: &str = "mfa_recovery_codes";

/// Tables a restore takes from the store it replaces, but keeps from the backup when that
/// store is gone, as the only copy left (ADR 0293, ADR 0299).
const KEPT_WHEN_GONE: [&str; 3] = [SECRETS, SECOND_FACTOR, RECOVERY_CODE];

fn kept(table: &str) -> Option<&'static Kept> {
    KEPT.iter().find(|k| k.name == table)
}

/// The columns of a primary key `pk` (`"a, b"`).
fn pk_cols(pk: &str) -> impl Iterator<Item = &str> {
    pk.split(',').map(str::trim)
}

/// `pk` of the row in `a` equals `pk` of the row in `b`: `a.x = b.x AND ...`.
fn same_key(pk: &str, a: &str, b: &str) -> String {
    pk_cols(pk).map(|c| format!("{a}.{c} = {b}.{c}")).collect::<Vec<_>>().join(" AND ")
}

/// botd's table for Bots' memory on its way between a store and the Bot's file in DATA_DIR
/// (ADR 0276): one row per Bot, whose id is the Bot's.
pub(super) const MEMORIES: &str = "CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);";

/// botd's table for people's facts on their way between a store and their file in
/// DATA_DIR (ADR 0277): one row per person, whose id is theirs.
pub(super) const FACTS: &str = "CREATE TABLE IF NOT EXISTS facts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);";

/// A text botd keeps as a file in DATA_DIR, and as a row while a pin keeps it in a store:
/// a Bot's memory (ADR 0276) or a person's facts (ADR 0277).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Doc {
    Memory,
    Facts,
}

impl Doc {
    fn table(self) -> &'static str {
        match self {
            Doc::Memory => "memories",
            Doc::Facts => "facts",
        }
    }

    fn key(self) -> Key {
        match self {
            Doc::Memory => Key::Bot,
            Doc::Facts => Key::User,
        }
    }

    /// botd's table of what a row is kept by.
    fn owners(self) -> &'static str {
        match self {
            Doc::Memory => "main.bots",
            Doc::Facts => "main.users",
        }
    }
}

/// The token for `table` in a statement run on every place (`on_places`): `{messages}`,
/// `{routines}`, `{approvals}`, `{memories}` or `{facts}`.
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
);
CREATE TABLE IF NOT EXISTS main.facts_moves_out (
  user_id TEXT NOT NULL,
  region TEXT NOT NULL,
  moved_at INTEGER NOT NULL,
  cleared_at INTEGER,
  PRIMARY KEY (user_id, region)
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
    pub memories: i64,
    pub facts: i64,
    pub sessions: i64,
    pub saml_sessions: i64,
    pub push_devices: i64,
    /// Secrets a person saved for their own Bots (ADR 0029, ADR 0293). Named so in JSON
    /// because the audit log hides the values of keys naming secrets.
    #[serde(rename = "personalKeys")]
    pub user_secrets: i64,
    /// People's second factors (ADR 0094, ADR 0299), each with its sealed TOTP secret.
    pub second_factors: i64,
    /// Their recovery codes, as keyed hashes.
    pub recovery_codes: i64,
}

impl Held {
    fn of(n: [i64; N]) -> Held {
        Held {
            messages: n[0],
            routines: n[1],
            approvals: n[2],
            memories: n[3],
            facts: n[4],
            sessions: n[5],
            saml_sessions: n[6],
            push_devices: n[7],
            user_secrets: n[USER_SECRETS],
            second_factors: n[SECOND_FACTORS],
            recovery_codes: n[RECOVERY_CODES],
        }
    }

    fn each(&self) -> [i64; N] {
        [
            self.messages,
            self.routines,
            self.approvals,
            self.memories,
            self.facts,
            self.sessions,
            self.saml_sessions,
            self.push_devices,
            self.user_secrets,
            self.second_factors,
            self.recovery_codes,
        ]
    }

    pub fn total(&self) -> i64 {
        self.each().iter().sum()
    }

    pub fn add(&mut self, o: Held) {
        let (a, b) = (self.each(), o.each());
        *self = Held::of(std::array::from_fn(|i| a[i] + b[i]));
    }

    /// What of it is kept by Bot: all but people's facts, sign-ins and own secrets.
    pub fn of_bots(&self) -> Held {
        Held { messages: self.messages, routines: self.routines, approvals: self.approvals, memories: self.memories, ..Held::default() }
    }

    /// A person's sign-ins (ADR 0283): their sessions, with each one's SAML sign-in and
    /// push device.
    pub fn sign_ins(&self) -> Held {
        Held { sessions: self.sessions, saml_sessions: self.saml_sessions, push_devices: self.push_devices, ..Held::default() }
    }

    /// A person's second factor (ADR 0299), with its recovery codes.
    pub fn second_factor(&self) -> Held {
        Held { second_factors: self.second_factors, recovery_codes: self.recovery_codes, ..Held::default() }
    }

    /// "3 chat messages, 1 routine, 2 approvals, 1 Bot memory and 1 person's facts", leaving
    /// out tables with none.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = [
            (self.messages, "chat message", "chat messages"),
            (self.routines, "routine", "routines"),
            (self.approvals, "approval", "approvals"),
            (self.memories, "Bot memory", "Bot memories"),
            (self.facts, "person's facts", "people's facts"),
            (self.sessions, "sign-in session", "sign-in sessions"),
            (self.saml_sessions, "SAML sign-in", "SAML sign-ins"),
            (self.push_devices, "push device", "push devices"),
            (self.user_secrets, "personal secret", "personal secrets"),
            (self.second_factors, "second factor", "second factors"),
            (self.recovery_codes, "recovery code", "recovery codes"),
        ]
        .into_iter()
        .filter(|(n, _, _)| *n > 0)
        .map(|(n, one, many)| format!("{n} {}", if n == 1 { one } else { many }))
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
    pub memories: usize,
    /// People whose facts moved (one row each).
    pub facts: usize,
    /// Sign-in sessions, and their SAML sign-ins and push devices (ADR 0283).
    pub sessions: usize,
    pub saml_sessions: usize,
    pub push_devices: usize,
    /// Secrets people saved for their own Bots (ADR 0293).
    pub user_secrets: usize,
    /// Second factors, and their recovery codes (ADR 0299).
    pub second_factors: usize,
    pub recovery_codes: usize,
}

impl ChatMove {
    /// What moved, as counts.
    pub fn held(&self) -> Held {
        let n = [
            self.messages,
            self.routines,
            self.approvals,
            self.memories,
            self.facts,
            self.sessions,
            self.saml_sessions,
            self.push_devices,
            self.user_secrets,
            self.second_factors,
            self.recovery_codes,
        ];
        Held::of(n.map(|n| n as i64))
    }
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

/// Makes the store's copy of `k` match botd's own table: the same columns, its primary key
/// (without AUTOINCREMENT: message ids come from botd's sequence), and its indexes. No
/// foreign key to `bots` or `users`, which are in another file: deleting a Bot deletes its
/// rows here, and each pass deletes those of people gone and of sessions gone.
fn ensure_table(c: &Connection, schema: &str, k: &Kept, main: &[Col]) -> rusqlite::Result<()> {
    let composite = k.pk.contains(',');
    let def = |col: &Col, adding: bool| {
        if col.name == k.pk {
            return format!("{} {} PRIMARY KEY", quote(&col.name), col.ty);
        }
        let default = col.default.as_ref().map(|d| format!(" DEFAULT {d}")).unwrap_or_default();
        // A column added to a table with rows can be NOT NULL only with a default.
        let notnull = if col.notnull && (!adding || col.default.is_some()) { " NOT NULL" } else { "" };
        format!("{} {}{notnull}{default}", quote(&col.name), col.ty)
    };
    let mut defs: Vec<String> = main.iter().map(|col| def(col, false)).collect();
    if composite {
        defs.push(format!("PRIMARY KEY ({})", k.pk));
    }
    c.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {schema}.{} ({})", k.name, defs.join(", ")))?;
    let have: Vec<String> = columns(c, schema, k.name)?.into_iter().map(|c| c.name).collect();
    for col in main.iter().filter(|col| !have.contains(&col.name)) {
        c.execute_batch(&format!("ALTER TABLE {schema}.{} ADD COLUMN {}", k.name, def(col, true)))?;
    }
    for (index, cols) in k.indexes {
        c.execute_batch(&format!("CREATE INDEX IF NOT EXISTS {schema}.{index} ON {}({cols})", k.name))?;
    }
    for (index, cols) in k.unique {
        c.execute_batch(&format!("CREATE UNIQUE INDEX IF NOT EXISTS {schema}.{index} ON {}({cols})", k.name))?;
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
    pinned_region_of(&format!("(SELECT owner_id FROM main.bots WHERE id = {bot})"))
}

/// The region of `user`'s pin, their team's first, from botd's own tables. `user` is an
/// SQL expression for the person's id.
fn pinned_region_of(user: &str) -> String {
    format!(
        "COALESCE(
           (SELECT p.region FROM main.team_members tm JOIN main.residency_pins p ON p.subject_type = 'team' AND p.subject_id = tm.team_id
             WHERE tm.user_id = {user}),
           (SELECT p.region FROM main.residency_pins p WHERE p.subject_type = 'user' AND p.subject_id = {user}))"
    )
}

/// Makes the TEMP view of kept table `k` that puts each place's rows together (`cols`, quoted,
/// as botd's own table has them). A move stopped between its copy and its delete leaves a row
/// in two places until the next pass; each key is read from the first place that has it, so
/// the scheduler doesn't run a routine twice (updates by id keep both alike).
fn create_view(c: &Connection, stores: &[ChatStore], k: &Kept, cols: &str) -> rusqlite::Result<()> {
    let rowid = if k.rowid { ", rowid AS rowid" } else { "" };
    let places: Vec<&str> = schemas(stores).collect();
    let t = k.name;
    let parts: Vec<String> = places
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let earlier: Vec<String> = places[..i].iter().map(|e| format!(" AND NOT EXISTS (SELECT 1 FROM {e}.{t} AS y WHERE {})", same_key(k.pk, "y", "x"))).collect();
            format!("SELECT {cols}{rowid} FROM {s}.{t} AS x WHERE true{}", earlier.concat())
        })
        .collect();
    c.execute_batch(&format!("CREATE TEMP VIEW {t} AS {}", parts.join(" UNION ALL ")))
}

/// The schema of `stores` a new row kept by `key` `id` (a Bot's, or a person's) goes to:
/// its pin region's store, else `main`.
fn place_in<'a>(c: &Connection, stores: &'a [ChatStore], key: Key, id: &str) -> rusqlite::Result<&'a str> {
    if stores.is_empty() {
        return Ok("main");
    }
    let region = match key {
        Key::Bot => pinned_region("?1"),
        Key::User => pinned_region_of("?1"),
    };
    let region: Option<String> = c.query_row(&format!("SELECT {region}"), [id], |r| r.get(0))?;
    Ok(region.and_then(|r| stores.iter().find(|s| s.region == r)).map_or("main", |s| s.schema.as_str()))
}

/// Attaches `stores` (as `Db::chat_stores` has them) to `c`, another connection to botd's
/// database, keyed with `key` as botd's connection attached them, and makes its view of kept
/// `table` across them, so `c` reads and writes that table as botd's connection does: the
/// users' secrets' own (ADR 0293).
pub fn attach_to(c: &Connection, stores: &[ChatStore], key: Option<&str>, table: &str) -> Result<(), String> {
    let Some(k) = kept(table) else { return Err(format!("{table} isn't kept in chat stores")) };
    if stores.is_empty() {
        return Ok(());
    }
    for s in stores {
        let path = s.path.to_str().ok_or_else(|| format!("{}: path is not UTF-8", s.path.display()))?;
        c.execute(&format!("ATTACH DATABASE ?1 AS {} KEY ?2", s.schema), params![path, key.unwrap_or("")]).map_err(|err| not_a_store(&s.path, &err))?;
    }
    let e = |err: rusqlite::Error| format!("chat stores: {err}");
    let cols = columns(c, "main", table).map_err(e)?.iter().map(|col| quote(&col.name)).collect::<Vec<_>>().join(", ");
    create_view(c, stores, k, &cols).map_err(e)
}

/// The schemas of `stores` attached to a connection (`attach_to`), botd's own first.
pub fn places(stores: &[ChatStore]) -> Vec<&str> {
    schemas(stores).collect()
}

/// The schema of `stores` a new row of `user_id`'s goes to: their pin region's store, else
/// `main` (ADR 0293).
pub fn user_place<'a>(c: &Connection, stores: &'a [ChatStore], user_id: &str) -> rusqlite::Result<&'a str> {
    place_in(c, stores, Key::User, user_id)
}

/// Deletes the rows of kept tables in `schema` whose parent row isn't there (ADR 0283).
/// How many.
fn orphans_in(c: &Connection, schema: &str) -> rusqlite::Result<usize> {
    let mut n = 0;
    for k in KEPT.iter() {
        if let Some((col, parent)) = k.parent {
            let pk = kept(parent).map_or("id", |p| p.pk);
            n += c.execute(&format!("DELETE FROM {schema}.{} WHERE {col} NOT IN (SELECT {pk} FROM {schema}.{parent})", k.name), [])?;
        }
    }
    Ok(n)
}

/// An SQL condition on a kept table's columns, with its parameters.
#[derive(Clone, Copy)]
struct Filter<'a>(&'a str, &'a [&'a dyn ToSql]);

const ALL: Filter<'static> = Filter("1", &[]);

/// How many rows of each kept table in `schema` (where they exist) match `bots` (tables kept
/// by Bot) or `users` (kept by person).
fn held_in(c: &Connection, schema: &str, bots: Filter, users: Filter) -> rusqlite::Result<Held> {
    let mut n = [0; N];
    for (i, k) in KEPT.iter().enumerate() {
        let Filter(filter, p) = if k.key == Key::Bot { bots } else { users };
        if has_table(c, schema, k.name)? {
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
        // The secrets' own connection makes their tables; a store copies their columns.
        c.execute_batch(crate::secrets::sealed::SCHEMA).map_err(e)?;
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
                let held = held_in(&c, "chats_dropped", ALL, ALL);
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
                        "REGION_DATA_DIRS no longer names {region}, but its chat store ({path}) still holds {} of pinned people and their Bots. \
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
                create_view(&c, &stores, k, cols).map_err(e)?;
            }
        }
        let _ = self.5.set(ChatStores { stores, cols, unflushed: Default::default() });
        Ok(out)
    }

    /// The schema a new row of `bot_id`'s goes to.
    fn place_for(&self, c: &Connection, bot_id: &str) -> rusqlite::Result<&str> {
        self.place_by(c, Key::Bot, bot_id)
    }

    /// The schema a new row kept by `key` `id` (a Bot's, or a person's) goes to.
    fn place_by(&self, c: &Connection, key: Key, id: &str) -> rusqlite::Result<&str> {
        place_in(c, self.chat_stores_set(), key, id)
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

    /// The schema a new row of `user_id`'s sign-ins goes to (ADR 0283).
    pub(super) fn place_for_user(&self, c: &Connection, user_id: &str) -> rusqlite::Result<&str> {
        self.place_by(c, Key::User, user_id)
    }

    /// The schemas holding row `id` of kept `table`, botd's own first: two while a move cut
    /// off between its copy and its delete waits for the next pass, which keeps either copy.
    pub(super) fn places_holding(&self, c: &Connection, table: &str, id: &str) -> rusqlite::Result<Vec<&str>> {
        let pk = kept(table).map_or("id", |k| k.pk);
        let mut out = Vec::new();
        for s in schemas(self.chat_stores_set()) {
            if c.query_row(&format!("SELECT 1 FROM {s}.{table} WHERE {pk} = ?1"), [id], |_| Ok(())).optional()?.is_some() {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Runs `sql` (with `RETURNING`, naming kept tables as `on_places` does) on every place,
    /// and reads the rows it returned with `f`, together.
    pub(super) fn returning_on_places<T>(&self, c: &Connection, sql: &str, p: &[&dyn ToSql], f: impl Fn(&rusqlite::Row) -> rusqlite::Result<T>) -> rusqlite::Result<Vec<T>> {
        let mut out = Vec::new();
        for s in schemas(self.chat_stores_set()) {
            let q = KEPT.iter().fold(sql.to_string(), |q, k| q.replace(&token(k.name), &format!("{s}.{}", k.name)));
            let mut st = c.prepare(&q)?;
            out.extend(st.query_map(p, &f)?.collect::<rusqlite::Result<Vec<T>>>()?);
        }
        Ok(out)
    }

    /// Deletes the rows of a store whose parent row (a session) isn't in it any more, as
    /// botd's own tables do by their foreign keys (ADR 0283). How many.
    pub(super) fn drop_orphans(&self, c: &Connection) -> rusqlite::Result<usize> {
        let mut n = 0;
        for s in self.chat_stores_set() {
            n += orphans_in(c, &s.schema)?;
        }
        Ok(n)
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
             INSERT INTO temp.chat_place (bot_id, schema) SELECT b.id, CASE {}{case} ELSE 'main' END FROM main.bots b;
             CREATE TEMP TABLE IF NOT EXISTS user_place (user_id TEXT PRIMARY KEY, schema TEXT NOT NULL);
             DELETE FROM temp.user_place;
             INSERT INTO temp.user_place (user_id, schema) SELECT u.id, CASE {}{case} ELSE 'main' END FROM main.users u;",
            pinned_region("b.id"),
            pinned_region_of("u.id")
        ))?;
        let here = |k: &Kept, to: &str| match k.key {
            Key::Bot => format!("bot_id IN (SELECT bot_id FROM temp.chat_place WHERE schema = {})", literal(to)),
            Key::User => format!("user_id IN (SELECT user_id FROM temp.user_place WHERE schema = {})", literal(to)),
        };
        let pairs: Vec<(&str, &str)> = schemas(&set.stores).flat_map(|to| schemas(&set.stores).filter(move |f| *f != to).map(move |from| (from, to))).collect();
        for &(from, to) in &pairs {
            for (k, cols) in KEPT.iter().zip(&set.cols) {
                tx.execute(&format!("INSERT OR IGNORE INTO {to}.{t} ({cols}) SELECT {cols} FROM {from}.{t} WHERE {here} ORDER BY rowid", t = k.name, here = here(k, to)), [])?;
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
                let copied = |k: &Kept| format!("{} AND ({pk}) IN (SELECT {pk} FROM {to}.{t})", here(k, to), t = k.name, pk = k.pk);
                // Whose rows move, by key: the Bots' (`chat_moves_out`) and the people's (`facts_moves_out`).
                let theirs = |key: Key| {
                    let col = key.column();
                    KEPT.iter().filter(|k| k.key == key).map(|k| format!("SELECT {col} FROM {from}.{t} WHERE {w}", t = k.name, w = copied(k))).collect::<Vec<_>>().join(" UNION ")
                };
                let (bot_rows, user_rows) = (theirs(Key::Bot), theirs(Key::User));
                let bots: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM ({bot_rows})"), [], |r| r.get(0))?;
                let users: i64 = tx.query_row(&format!("SELECT COUNT(*) FROM ({user_rows})"), [], |r| r.get(0))?;
                if bots == 0 && users == 0 {
                    continue;
                }
                let from_region = region_of(&set.stores, from).map(str::to_string);
                if let Some(r) = &from_region {
                    for (table, col, rows) in [("chat_moves_out", "bot_id", &bot_rows), ("facts_moves_out", "user_id", &user_rows)] {
                        tx.execute(
                            &format!(
                                "INSERT INTO main.{table} ({col}, region, moved_at) SELECT {col}, ?1, ?2 FROM ({rows}) WHERE true
                                 ON CONFLICT({col}, region) DO UPDATE SET moved_at = excluded.moved_at, cleared_at = NULL"
                            ),
                            params![r, at],
                        )?;
                    }
                }
                // Children first: botd's own tables would delete them with their session
                // otherwise, uncounted.
                let mut n = [0; N];
                for (i, k) in KEPT.iter().enumerate().rev() {
                    n[i] = tx.execute(&format!("DELETE FROM {from}.{} WHERE {}", k.name, copied(k)), [])?;
                }
                let to = region_of(&set.stores, to).map(str::to_string);
                moves.push(ChatMove {
                    from: from_region,
                    to,
                    bots: bots as usize,
                    messages: n[0],
                    routines: n[1],
                    approvals: n[2],
                    memories: n[3],
                    facts: n[4],
                    sessions: n[5],
                    saml_sessions: n[6],
                    push_devices: n[PUSH_DEVICES],
                    user_secrets: n[USER_SECRETS],
                    second_factors: n[SECOND_FACTORS],
                    recovery_codes: n[RECOVERY_CODES],
                });
            }
            for s in &set.stores {
                for k in &KEPT {
                    let (col, owners) = match k.key {
                        Key::Bot => ("bot_id", "main.bots"),
                        Key::User => ("user_id", "main.users"),
                    };
                    tx.execute(&format!("DELETE FROM {}.{} WHERE {col} NOT IN (SELECT id FROM {owners})", s.schema, k.name), [])?;
                }
                orphans_in(&tx, &s.schema)?;
            }
            tx.commit()?;
            Ok(moves)
        })?;
        if !moves.is_empty() || set.unflushed.load(Ordering::Relaxed) {
            self.flush_places(&c);
        }
        Ok(moves)
    }

    /// Checkpoints every place after rows were deleted from it, remembering when a reader
    /// blocked that so the next pass tries again.
    fn flush_places(&self, c: &Connection) {
        let done = schemas(self.chat_stores_set()).fold(true, |done, s| flush(c, s) && done);
        if let Some(set) = self.5.get() {
            set.unflushed.store(!done, Ordering::Relaxed);
        }
    }

    /// botd's copy of `bot_id`'s memory where a row holds it (ADR 0276): in its store, or in
    /// botd's own table on its way between a store and its file. None: it is in its file in
    /// DATA_DIR, if anywhere.
    pub fn memory(&self, bot_id: &str) -> Option<String> {
        self.doc(Doc::Memory, bot_id)
    }

    /// Whether `bot_id`'s memory belongs in a store (its owner's pin region has one), rather
    /// than in its file in DATA_DIR.
    pub fn memory_in_store(&self, bot_id: &str) -> bool {
        self.doc_in_store(Doc::Memory, bot_id)
    }

    /// Saves `bot_id`'s memory, which belongs in a store (`memory_in_store`).
    pub fn set_memory(&self, bot_id: &str, text: &str) -> rusqlite::Result<()> {
        self.set_doc(Doc::Memory, bot_id, text)
    }

    /// `user_id`'s facts where a row holds them (ADR 0277), as `memory` for a Bot's memory.
    pub fn facts(&self, user_id: &str) -> Option<String> {
        self.doc(Doc::Facts, user_id)
    }

    /// Whether `user_id`'s facts belong in a store (their pin region has one).
    pub fn facts_in_store(&self, user_id: &str) -> bool {
        self.doc_in_store(Doc::Facts, user_id)
    }

    /// Saves `user_id`'s facts, which belong in a store (`facts_in_store`).
    pub fn set_facts(&self, user_id: &str, text: &str) -> rusqlite::Result<()> {
        self.set_doc(Doc::Facts, user_id, text)
    }

    /// Deletes every row of `user_id`'s facts, zeroed: once their file holds them, or when
    /// they are erased. How many.
    pub fn delete_facts(&self, user_id: &str) -> rusqlite::Result<usize> {
        self.delete_doc(Doc::Facts, user_id)
    }

    /// botd's copy of `doc` kept by `id` where a row holds it: in a store, or in botd's own
    /// table on its way between a store and its file. None: it is in its file, if anywhere.
    pub fn doc(&self, doc: Doc, id: &str) -> Option<String> {
        self.c().query_row(&format!("SELECT text FROM {} WHERE id = ?1", doc.table()), [id], |r| r.get(0)).optional().ok().flatten()
    }

    /// Whether `doc` kept by `id` belongs in a store, rather than in its file in DATA_DIR.
    pub fn doc_in_store(&self, doc: Doc, id: &str) -> bool {
        let c = self.c();
        self.place_by(&c, doc.key(), id).is_ok_and(|s| s != "main")
    }

    /// Saves `doc` kept by `id`, which belongs in a store: every row of it changed, else a
    /// row made where it belongs.
    pub fn set_doc(&self, doc: Doc, id: &str, text: &str) -> rusqlite::Result<()> {
        let c = self.c();
        let at = now();
        let t = doc.table();
        if self.on_places(&c, &format!("UPDATE {{{t}}} SET text = ?1, updated_at = ?2 WHERE id = ?3"), params![text, at, id])? == 0 {
            let schema = self.place_by(&c, doc.key(), id)?;
            c.execute(&format!("INSERT INTO {schema}.{t} (id, {}, text, updated_at) VALUES (?1, ?1, ?2, ?3)", doc.key().column()), params![id, text, at])?;
        }
        Ok(())
    }

    /// Deletes every row of `doc` kept by `id`, zeroed in its file and the WAL emptied. How many.
    pub fn delete_doc(&self, doc: Doc, id: &str) -> rusqlite::Result<usize> {
        let c = self.c();
        let n = zeroing(&c, || self.on_places(&c, &format!("DELETE FROM {{{}}} WHERE id = ?1", doc.table()), &[&id]))?;
        if n > 0 {
            self.flush_places(&c);
        }
        Ok(n)
    }

    /// The Bots (memory) or people (facts) whose `doc` belongs in a store now.
    pub fn with_doc_in_stores(&self, doc: Doc) -> rusqlite::Result<Vec<String>> {
        let stores = self.chat_stores_set();
        if stores.is_empty() {
            return Ok(Vec::new());
        }
        let c = self.c();
        let sql = match doc.key() {
            Key::Bot => format!("SELECT b.id, {} FROM main.bots b ORDER BY b.id", pinned_region("b.id")),
            Key::User => format!("SELECT u.id, {} FROM main.users u ORDER BY u.id", pinned_region_of("u.id")),
        };
        let mut s = c.prepare(&sql)?;
        let rows: Vec<(String, Option<String>)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows.into_iter().filter(|(_, r)| r.as_ref().is_some_and(|r| stores.iter().any(|s| s.region == *r))).map(|(id, _)| id).collect())
    }

    /// Takes `doc` kept by `id` from its file into botd's own table, for the next
    /// `place_chats` to move to its store, unless a row of it is kept somewhere already: that
    /// one is newer, as it is saved there while it belongs in a store. Whether it was.
    pub fn doc_from_file(&self, doc: Doc, id: &str, text: &str) -> rusqlite::Result<bool> {
        let t = doc.table();
        let n = self.c().execute(
            &format!(
                "INSERT INTO main.{t} (id, {}, text, updated_at) SELECT ?1, ?1, ?2, ?3
                 WHERE EXISTS (SELECT 1 FROM {} WHERE id = ?1) AND NOT EXISTS (SELECT 1 FROM {t} WHERE id = ?1)",
                doc.key().column(),
                doc.owners()
            ),
            params![id, text, now()],
        )?;
        Ok(n > 0)
    }

    /// The rows of `doc` in botd's own table that belong in their file now (unpinned, or
    /// their region without a store), as `(id, text)`, for `machines::chat_stores::place`
    /// to write to the file and then delete.
    pub fn docs_for_files(&self, doc: Doc) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.c();
        let rows: Vec<(String, String)> = {
            let mut s = c.prepare(&format!("SELECT id, text FROM main.{} ORDER BY id", doc.table()))?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        let mut out = Vec::new();
        for (id, text) in rows {
            if self.place_by(&c, doc.key(), &id)? == "main" {
                out.push((id, text));
            }
        }
        Ok(out)
    }

    /// True while rows that left a place may still be readable in its file, because a
    /// reader blocked the checkpoint after the move. The next pass tries again.
    pub fn chat_stores_unflushed(&self) -> bool {
        self.5.get().is_some_and(|s| s.unflushed.load(Ordering::Relaxed))
    }

    /// What of the Bots `owners` own, and of their own facts, is in each place: botd's own
    /// database first, then each store, places with none left out.
    pub fn chat_counts(&self, owners: &[String]) -> Vec<ChatCount> {
        let owners = serde_json::to_string(owners).unwrap_or_else(|_| "[]".into());
        let c = self.c();
        let stores = self.chat_stores_set();
        let bots = "bot_id IN (SELECT id FROM main.bots WHERE owner_id IN (SELECT value FROM json_each(?1)))";
        let users = "user_id IN (SELECT value FROM json_each(?1))";
        schemas(stores)
            .filter_map(|s| {
                let held = held_in(&c, s, Filter(bots, &[&owners]), Filter(users, &[&owners])).ok()?;
                (held.total() > 0).then(|| ChatCount { region: region_of(stores, s).map(str::to_string), held })
            })
            .collect()
    }

    /// When the chats of Bots `owners` own, or their own facts (ADR 0277), last left each
    /// store other than `except`'s, as `(region, moved_at)`: that store's backups from before
    /// then still hold them, until botd has cleared them out of those backups (ADR 0238).
    pub fn chat_moves_out(&self, owners: &[String], except: &str) -> Vec<(String, i64)> {
        let owners = serde_json::to_string(owners).unwrap_or_else(|_| "[]".into());
        let c = self.c();
        let Ok(mut s) = c.prepare(
            "SELECT region, MAX(moved_at) FROM (
               SELECT region, moved_at FROM main.chat_moves_out WHERE region != ?2 AND cleared_at IS NULL
                 AND bot_id IN (SELECT id FROM main.bots WHERE owner_id IN (SELECT value FROM json_each(?1)))
               UNION ALL
               SELECT region, moved_at FROM main.facts_moves_out WHERE region != ?2 AND cleared_at IS NULL
                 AND user_id IN (SELECT value FROM json_each(?1))
             ) GROUP BY region ORDER BY region",
        ) else {
            return Vec::new();
        };
        s.query_map(params![owners, except], |r| Ok((r.get(0)?, r.get(1)?))).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// The Bots and people whose rows left `store` and that its backups may still hold
    /// (ADR 0238, ADR 0277): not yet cleared, kept somewhere else now (or deleted since), and
    /// with nothing of theirs left in the store itself, so a move still pending never takes
    /// the only other copy.
    pub fn moves_out_to_clear(&self, store: &ChatStore) -> rusqlite::Result<MovesOut> {
        let c = self.c();
        let mut out = MovesOut::default();
        for (key, table, list) in [(Key::Bot, "chat_moves_out", &mut out.bots), (Key::User, "facts_moves_out", &mut out.users)] {
            let col = key.column();
            let none_left: String =
                KEPT.iter().filter(|k| k.key == key).map(|k| format!(" AND NOT EXISTS (SELECT 1 FROM {}.{} WHERE {col} = m.{col})", store.schema, k.name)).collect();
            let region = match key {
                Key::Bot => pinned_region("m.bot_id"),
                Key::User => pinned_region_of("m.user_id"),
            };
            let mut s = c.prepare(&format!(
                "SELECT m.{col}, m.moved_at FROM main.{table} m
                 WHERE m.region = ?1 AND m.cleared_at IS NULL AND ({region}) IS NOT ?1{none_left}
                 ORDER BY m.{col}"
            ))?;
            *list = s.query_map([&store.region], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        }
        Ok(out)
    }

    /// Records that `region`'s backups no longer hold the rows of these moves (from
    /// `moves_out_to_clear`). A Bot or person that moved out again since keeps its newer
    /// move. How many were recorded.
    pub fn moves_out_cleared(&self, region: &str, moves: &MovesOut, at: i64) -> rusqlite::Result<usize> {
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        let mut n = 0;
        for (table, col, list) in [("chat_moves_out", "bot_id", &moves.bots), ("facts_moves_out", "user_id", &moves.users)] {
            for (id, moved_at) in list {
                n += tx.execute(
                    &format!("UPDATE main.{table} SET cleared_at = ?4 WHERE region = ?1 AND {col} = ?2 AND moved_at = ?3 AND cleared_at IS NULL"),
                    params![region, id, moved_at, at],
                )?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Every store and what it holds.
    pub fn chat_store_counts(&self) -> Vec<(ChatStore, Held)> {
        let c = self.c();
        self.chat_stores_set().iter().map(|s| (s.clone(), held_in(&c, &s.schema, ALL, ALL).unwrap_or_default())).collect()
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

    /// Redacts known secrets from saved rows in botd's own database and every store, as
    /// startup does each before the users' secrets attach the stores (ADR 0293): run again
    /// once they have, for values only a store holds. How many rows changed.
    pub fn scrub_saved_rows(&self) -> rusqlite::Result<usize> {
        let own = crate::secrets::redact::scrub_rows(&self.c())?;
        Ok(own + self.scrub_chat_stores()?)
    }

    /// Brings the stores' approval inputs under the master key `current`, as startup does
    /// botd's own (ADR 0228): those sealed under `previous` (mid-rotation) are sealed again,
    /// plaintext is sealed, and with `forget` (SUPERBOT_FORGET_SEALED=1) those neither key
    /// opens are dropped. The values replaced are zeroed and the store's WAL emptied, so they
    /// don't linger in its free pages. Refuses when an input opens with neither key and
    /// nothing says what to do about it.
    pub fn seal_store_approvals(&self, current: &Cipher, previous: Option<&Cipher>, forget: bool) -> Result<StoreApprovals, String> {
        self.seal_in_stores("approvals", |c, table| sealed::approvals_in(c, table, current, previous, forget))
    }

    /// Brings the push tokens in the stores' devices (ADR 0283) under the master key, as
    /// `seal_store_approvals` does approvals' inputs; with `forget`, a device whose token
    /// neither key opens is deleted, so its phone registers again.
    pub fn seal_store_push_tokens(&self, current: &Cipher, previous: Option<&Cipher>, forget: bool) -> Result<StoreApprovals, String> {
        self.seal_in_stores("push_devices", |c, table| sealed::push_tokens_in(c, table, current, previous, forget))
    }

    /// Brings people's own secrets in the stores (ADR 0293) under the master key, as
    /// `seal_store_approvals` does approvals' inputs; with `forget`, a secret neither key
    /// opens is deleted, so its owner saves it again.
    pub fn seal_store_user_secrets(&self, current: &Cipher, previous: Option<&Cipher>, forget: bool) -> Result<StoreApprovals, String> {
        self.seal_in_stores(SECRETS, |c, table| sealed::user_secrets_in(c, table, current, previous, forget))
    }

    /// Brings people's second factors in the stores (ADR 0299) under the master key, as
    /// `seal_store_approvals` does approvals' inputs; with `forget`, a second factor neither
    /// key opens is deleted with its recovery codes, so its owner sets it up again. With
    /// `new_derived_keys` (a rotation that renews them, ADR 0096), the recovery codes of a
    /// second factor sealed again are deleted, as botd's own are: their keyed hashes no
    /// longer match.
    pub fn seal_store_second_factors(&self, current: &Cipher, previous: Option<&Cipher>, forget: bool, new_derived_keys: bool) -> Result<StoreApprovals, String> {
        self.seal_in_stores(SECOND_FACTOR, |c, table| {
            let codes = table.replacen(SECOND_FACTOR, RECOVERY_CODE, 1);
            sealed::second_factors_in(c, table, &codes, current, previous, forget, new_derived_keys)
        })
    }

    fn seal_in_stores(&self, table: &str, seal: impl Fn(&Connection, &str) -> Result<StoreApprovals, String>) -> Result<StoreApprovals, String> {
        let c = self.c();
        let mut done = StoreApprovals::default();
        for s in self.chat_stores_set() {
            let table = format!("{}.{table}", s.schema);
            let r = zeroing(&c, || Ok(seal(&c, &table)))
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


/// Bots and people, whose rows a copy of a store holds by their ids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Whose {
    pub bots: Vec<String>,
    pub users: Vec<String>,
}

impl Whose {
    fn lists(&self) -> (String, String) {
        let list = |ids: &[String]| serde_json::to_string(ids).unwrap_or_else(|_| "[]".into());
        (list(&self.bots), list(&self.users))
    }
}

/// The moves out of a store whose rows its backups may still hold, as `(id, moved_at)`:
/// Bots' (ADR 0238) and people's facts (ADR 0277).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MovesOut {
    pub bots: Vec<(String, i64)>,
    pub users: Vec<(String, i64)>,
}

impl MovesOut {
    pub fn len(&self) -> usize {
        self.bots.len() + self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn whose(&self) -> Whose {
        let ids = |l: &[(String, i64)]| l.iter().map(|(id, _)| id.clone()).collect();
        Whose { bots: ids(&self.bots), users: ids(&self.users) }
    }
}

/// How many rows of `whose` a copy of a store opened on `c` (one of its backups) holds.
pub fn held_in_copy(c: &Connection, whose: &Whose) -> rusqlite::Result<Held> {
    let (bots, users) = whose.lists();
    held_in(c, "main", Filter("bot_id IN (SELECT value FROM json_each(?1))", &[&bots]), Filter("user_id IN (SELECT value FROM json_each(?1))", &[&users]))
}

/// Deletes the rows of `whose` from a copy of a store opened on `c`, zeroing them
/// (`secure_delete`), and rebuilds the file so no page of theirs is left in it (ADR 0238).
/// What was deleted.
pub fn drop_from_copy(c: &Connection, whose: &Whose) -> rusqlite::Result<Held> {
    let held = delete_in_copy(c, "IN", whose)?;
    c.execute_batch("VACUUM")?;
    Ok(held)
}

/// Deletes the rows of every Bot and person but `keep` from a copy of a store opened on
/// `c`, zeroing them (`secure_delete`), for a backup about to be restored (ADR 0256): rows
/// of Bots and people kept elsewhere now, or deleted, would otherwise come back. The caller
/// VACUUMs. What was deleted.
pub fn keep_only_in_copy(c: &Connection, keep: &Whose) -> rusqlite::Result<Held> {
    delete_in_copy(c, "NOT IN", keep)
}

fn delete_in_copy(c: &Connection, op: &str, whose: &Whose) -> rusqlite::Result<Held> {
    let (bots, users) = whose.lists();
    c.execute_batch("PRAGMA secure_delete = ON")?;
    let tx = c.unchecked_transaction()?;
    let mut n = [0; N];
    for (i, k) in KEPT.iter().enumerate() {
        let list = if k.key == Key::Bot { &bots } else { &users };
        if has_table(&tx, "main", k.name)? {
            n[i] = tx.execute(&format!("DELETE FROM main.{} WHERE {} {op} (SELECT value FROM json_each(?1))", k.name, k.key.column()), [list])? as i64;
        }
    }
    tx.commit()?;
    Ok(Held::of(n))
}

/// Puts the sign-ins (ADR 0283) and own secrets (ADR 0293) of the people in `keep` from the
/// store attached as `now` (None: it is missing or unreadable) into a copy of it opened on
/// `c`, a backup about to be restored, in place of the copy's own: a session revoked after
/// the backup was made would otherwise work again, and one made since would end; a secret
/// deleted since would come back, and one replaced since would turn back to its old value.
/// Second factors and their recovery codes (ADR 0299) go as secrets do: one turned off or
/// reset since, or a recovery code spent since, would otherwise come back.
/// Without `now`, the copy's sessions are dropped (their people sign in again) and its
/// secrets and second factors kept, the only copy of them left. The caller has
/// `secure_delete` on and VACUUMs. What of the copy's own was dropped, and what was taken
/// from `now`.
pub fn sign_ins_from(c: &Connection, now: Option<&str>, keep: &Whose) -> rusqlite::Result<(Held, Held)> {
    let users = keep.lists().1;
    let tx = c.unchecked_transaction()?;
    let (mut dropped, mut taken) = ([0; N], [0; N]);
    for (i, k) in KEPT.iter().enumerate().filter(|(_, k)| SIGN_INS.contains(&k.name) || KEPT_WHEN_GONE.contains(&k.name)) {
        let t = k.name;
        if !has_table(&tx, "main", t)? {
            continue;
        }
        // A store from before ADR 0293 (secrets) or ADR 0299 (second factors) has none to put
        // in place of the copy's.
        let replaced = now.map(|now| has_table(&tx, now, t)).transpose()?.unwrap_or(false);
        if KEPT_WHEN_GONE.contains(&t) && !replaced {
            continue;
        }
        dropped[i] = tx.execute(&format!("DELETE FROM main.{t}"), [])? as i64;
        let Some(now) = now else { continue };
        if !replaced {
            continue;
        }
        let theirs: Vec<String> = columns(&tx, now, t)?.into_iter().map(|col| col.name).collect();
        let cols: Vec<String> = columns(&tx, "main", t)?.into_iter().filter(|col| theirs.contains(&col.name)).map(|col| quote(&col.name)).collect();
        let cols = cols.join(", ");
        taken[i] = tx.execute(&format!("INSERT INTO main.{t} ({cols}) SELECT {cols} FROM {now}.{t} WHERE user_id IN (SELECT value FROM json_each(?1))"), [&users])? as i64;
    }
    tx.commit()?;
    Ok((Held::of(dropped), Held::of(taken)))
}

/// Brings a copy of a store opened on `c` (a backup from an older botd, perhaps without
/// routines or approvals, ADR 0228) to the tables botd keeps now, from botd's own database
/// attached as `botd`, as attaching the store does.
pub fn upgrade_copy(c: &Connection, botd: &str) -> rusqlite::Result<()> {
    for k in KEPT.iter() {
        let main = columns(c, botd, k.name)?;
        // A database from before botd kept this table (a restore run before it starts).
        if !main.is_empty() {
            ensure_table(c, "main", k, &main)?;
        }
    }
    Ok(())
}

/// The Bots whose chats, routines, approvals and memory belong in `region`'s store (those
/// whose owner's pin, their team's else their own, is in it), and the people whose facts
/// do (their own pin is). `c` is botd's own database.
pub fn kept_in_region(c: &Connection, region: &str) -> rusqlite::Result<Whose> {
    let mut s = c.prepare(&format!("SELECT b.id FROM main.bots b WHERE ({}) = ?1 ORDER BY b.id", pinned_region("b.id")))?;
    let bots = s.query_map([region], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    let mut s = c.prepare(&format!("SELECT u.id FROM main.users u WHERE ({}) = ?1 ORDER BY u.id", pinned_region_of("u.id")))?;
    let users = s.query_map([region], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(Whose { bots, users })
}

/// What a copy of a store opened on `c` holds that the store attached as `schema` doesn't
/// (it would come back), and what that store holds that the copy doesn't (it would go),
/// by id. Either may be from before botd kept a table.
pub fn compare_copy(c: &Connection, schema: &str) -> rusqlite::Result<(Held, Held)> {
    let (mut back, mut gone) = ([0; N], [0; N]);
    for (i, k) in KEPT.iter().enumerate() {
        let (t, pk) = (k.name, k.pk);
        let count = |from: &str, other: Option<&str>| {
            let not_in = other.map(|o| format!(" WHERE ({pk}) NOT IN (SELECT {pk} FROM {o}.{t})")).unwrap_or_default();
            c.query_row(&format!("SELECT COUNT(*) FROM {from}.{t}{not_in}"), [], |r| r.get(0))
        };
        match (has_table(c, "main", t)?, has_table(c, schema, t)?) {
            (true, true) => (back[i], gone[i]) = (count("main", Some(schema))?, count(schema, Some("main"))?),
            (true, false) => back[i] = count("main", None)?,
            (false, true) => gone[i] = count(schema, None)?,
            (false, false) => {}
        }
    }
    Ok((Held::of(back), Held::of(gone)))
}

/// The rows of Bots and people other than `kept` in the store attached as `schema` (rows a
/// restore would leave behind in a backup, ADR 0256).
pub fn held_apart_from(c: &Connection, schema: &str, kept: &Whose) -> rusqlite::Result<Held> {
    let (bots, users) = kept.lists();
    held_in(c, schema, Filter("bot_id NOT IN (SELECT value FROM json_each(?1))", &[&bots]), Filter("user_id NOT IN (SELECT value FROM json_each(?1))", &[&users]))
}

fn has_table(c: &Connection, schema: &str, table: &str) -> rusqlite::Result<bool> {
    c.query_row(&format!("SELECT COUNT(*) > 0 FROM {schema}.sqlite_master WHERE type = 'table' AND name = ?1"), [table], |r| r.get(0))
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
        ChatMove {
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            bots,
            messages: n[0],
            routines: n[1],
            approvals: n[2],
            memories: 0,
            facts: 0,
            sessions: 0,
            saml_sessions: 0,
            push_devices: 0,
            user_secrets: 0,
            second_factors: 0,
            recovery_codes: 0,
        }
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
        assert_eq!(held, vec![ChatCount { region: Some("gb-lon".into()), held: Held { messages: 0, routines: 2, approvals: 2, ..Default::default() } }]);
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
        assert!(e.contains("still holds 1 routine and 2 approvals of pinned people and their Bots"), "{e}");
    }

    fn memory_move(from: Option<&str>, to: Option<&str>) -> ChatMove {
        ChatMove { memories: 1, ..mv(from, to, 1, [0, 0, 0]) }
    }

    #[test]
    fn a_pinned_owners_bot_memory_is_kept_in_their_store_and_moves_with_the_pin() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let (bot, other) = (bot_of(&db, &ada), bot_of(&db, &cy));
        let word = "memory-58b1e0-the-plan";
        assert!(db.with_doc_in_stores(Doc::Memory).unwrap().is_empty() && !db.memory_in_store(&bot));
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.with_doc_in_stores(Doc::Memory).unwrap(), vec![bot.clone()]);
        assert!(db.memory_in_store(&bot) && !db.memory_in_store(&other));

        // Taken from its file into botd's own table, then moved to the store like any row.
        assert!(db.doc_from_file(Doc::Memory, &bot, word).unwrap());
        assert!(!db.doc_from_file(Doc::Memory, &bot, "older").unwrap(), "a row kept already is newer than a file");
        assert!(!db.doc_from_file(Doc::Memory, "no-such-bot", "x").unwrap());
        assert_eq!(db.place_chats().unwrap(), vec![memory_move(None, Some("gb-lon"))]);
        assert_eq!((count(&db, "main", "memories"), count(&db, "chats_0", "memories")), (0, 1));
        assert_eq!(db.memory(&bot).as_deref(), Some(word));
        assert!(db.docs_for_files(Doc::Memory).unwrap().is_empty());
        let app = d.dir.path().join("app.sqlite");
        let holds = |path: &Path| std::fs::read(path).is_ok_and(|b| b.windows(word.len()).any(|x| x == word.as_bytes()));
        assert!(!holds(&app) && !holds(&d.dir.path().join("app.sqlite-wal")), "no copy left in botd's own database");

        // Saved where it is kept, once.
        db.set_memory(&bot, "updated").unwrap();
        assert_eq!((db.memory(&bot).as_deref(), count(&db, "chats_0", "memories")), (Some("updated"), 1));
        // A Bot whose memory belongs in a store and has no row yet gets one there.
        db.pin_residency(PinOn::User, &cy, "de-fra-2", "DPA-2", None).unwrap();
        db.set_memory(&other, "cy's").unwrap();
        assert_eq!(count(&db, "chats_1", "memories"), 1);
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), held: Held { memories: 1, ..Held::default() } }]);

        // Unpinned, it comes back to botd's own table on its way to its file.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![memory_move(Some("gb-lon"), None)]);
        assert_eq!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "recorded for the store's earlier backups");
        assert_eq!(db.docs_for_files(Doc::Memory).unwrap(), vec![(bot.clone(), "updated".to_string())]);
        assert_eq!(db.delete_doc(Doc::Memory, &bot).unwrap(), 1);
        assert_eq!((db.memory(&bot), db.docs_for_files(Doc::Memory).unwrap()), (None, Vec::new()));
        assert!(!holds(&d.lon.join("chats.sqlite")) && !holds(&app));
        // Deleting a Bot deletes its memory in a store.
        assert!(db.delete_bot_unless_held(&other));
        assert_eq!(count(&db, "chats_1", "memories"), 0);
    }

    #[test]
    fn a_dropped_store_holding_a_bots_memory_stops_botd() {
        let d = Dirs::new();
        {
            let db = d.up();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-1", None).unwrap();
            db.set_memory(&bot_of(&db, &ada), "x").unwrap();
        }
        let e = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap_err();
        assert!(e.contains("still holds 1 Bot memory of pinned people and their Bots"), "{e}");
    }

    #[test]
    fn a_store_from_before_bots_memory_gains_its_table() {
        let d = Dirs::new();
        drop(d.up());
        Connection::open(d.lon.join("chats.sqlite")).unwrap().execute_batch("DROP TABLE memories").unwrap();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        db.set_memory(&bot, "kept").unwrap();
        assert_eq!((db.memory(&bot).as_deref(), count(&db, "chats_0", "memories")), (Some("kept"), 1));
    }

    #[test]
    fn describing_what_a_place_holds_names_bots_memory() {
        assert_eq!(Held { memories: 1, ..Held::default() }.describe(), "1 Bot memory");
        assert_eq!(Held { messages: 2, memories: 3, ..Held::default() }.describe(), "2 chat messages and 3 Bot memories");
        assert_eq!(Held { memories: 1, facts: 1, ..Held::default() }.describe(), "1 Bot memory and 1 person's facts");
        assert_eq!(Held { facts: 2, ..Held::default() }.describe(), "2 people's facts");
        assert_eq!(Held { messages: 1, facts: 2, ..Held::default() }.of_bots(), Held { messages: 1, ..Held::default() });
    }

    fn facts_move(from: Option<&str>, to: Option<&str>) -> ChatMove {
        ChatMove { facts: 1, ..mv(from, to, 0, [0, 0, 0]) }
    }

    #[test]
    fn a_pinned_persons_facts_are_kept_in_their_store_and_move_with_the_pin() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let word = "facts-58c2f1-ada-banks-here";
        assert!(db.with_doc_in_stores(Doc::Facts).unwrap().is_empty() && !db.facts_in_store(&ada));
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.with_doc_in_stores(Doc::Facts).unwrap(), vec![ada.clone()]);
        assert!(db.facts_in_store(&ada) && !db.facts_in_store(&cy));

        // Taken from the file into botd's own table, then moved to the store with no Bot.
        assert!(db.doc_from_file(Doc::Facts, &ada, word).unwrap());
        assert!(!db.doc_from_file(Doc::Facts, &ada, "older").unwrap(), "a row kept already is newer than a file");
        assert!(!db.doc_from_file(Doc::Facts, "no-such-user", "x").unwrap());
        assert_eq!(db.place_chats().unwrap(), vec![facts_move(None, Some("gb-lon"))]);
        assert_eq!((count(&db, "main", "facts"), count(&db, "chats_0", "facts")), (0, 1));
        assert_eq!(db.facts(&ada).as_deref(), Some(word));
        assert!(db.docs_for_files(Doc::Facts).unwrap().is_empty());
        let app = d.dir.path().join("app.sqlite");
        let holds = |path: &Path| std::fs::read(path).is_ok_and(|b| b.windows(word.len()).any(|x| x == word.as_bytes()));
        assert!(!holds(&app) && !holds(&d.dir.path().join("app.sqlite-wal")), "no copy left in botd's own database");
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), held: Held { facts: 1, ..Held::default() } }]);

        // Saved where they are kept; someone pinned with no row yet gets one in their store.
        db.set_facts(&ada, "updated").unwrap();
        assert_eq!((db.facts(&ada).as_deref(), count(&db, "chats_0", "facts")), (Some("updated"), 1));
        db.pin_residency(PinOn::User, &cy, "de-fra-2", "DPA-2", None).unwrap();
        db.set_facts(&cy, "cy's").unwrap();
        assert_eq!(count(&db, "chats_1", "facts"), 1);

        // Unpinned, they come back to botd's own table on their way to the file, and the
        // move is recorded for the store's earlier backups.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![facts_move(Some("gb-lon"), None)]);
        assert_eq!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "recorded for the store's earlier backups");
        let lon = db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert_eq!(db.moves_out_to_clear(&lon).unwrap().whose(), Whose { bots: Vec::new(), users: vec![ada.clone()] });
        assert_eq!(db.docs_for_files(Doc::Facts).unwrap(), vec![(ada.clone(), "updated".to_string())]);
        assert_eq!(db.delete_facts(&ada).unwrap(), 1);
        assert_eq!((db.facts(&ada), db.docs_for_files(Doc::Facts).unwrap()), (None, Vec::new()));
        assert!(!holds(&d.lon.join("chats.sqlite")) && !holds(&app));
        let moves = db.moves_out_to_clear(&lon).unwrap();
        assert_eq!(db.moves_out_cleared("gb-lon", &moves, now()).unwrap(), 1);
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").is_empty());
    }

    #[test]
    fn a_team_pin_keeps_its_members_facts_and_a_member_leaving_takes_theirs_out() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let t = db.create_team("Acme", None);
        assert!(db.add_team_member(&t.id, &ada, "member", None));
        db.pin_residency(PinOn::User, &cy, "gb-lon", "DPA-1", None).unwrap();
        db.pin_residency(PinOn::Team, &t.id, "de-fra-2", "MSA-1", None).unwrap();
        db.set_facts(&ada, "ada's").unwrap();
        assert_eq!(db.place_of("facts", &ada), Some(Some("de-fra-2".into())));
        assert_eq!(kept_in_region(&db.c(), "de-fra-2").unwrap(), Whose { bots: Vec::new(), users: vec![ada.clone()] });
        assert!(db.remove_team_member(&t.id, &ada, false));
        assert_eq!(db.place_chats().unwrap(), vec![facts_move(Some("de-fra-2"), None)]);
        assert_eq!(db.docs_for_files(Doc::Facts).unwrap(), vec![(ada.clone(), "ada's".to_string())]);
    }

    #[test]
    fn a_dropped_store_holding_a_persons_facts_stops_botd() {
        let d = Dirs::new();
        {
            let db = d.up();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-1", None).unwrap();
            db.set_facts(&ada, "x").unwrap();
        }
        let e = d.db().attach_chat_stores(&d.both()[..1], &[], None).unwrap_err();
        assert!(e.contains("still holds 1 person's facts of pinned people and their Bots"), "{e}");
    }

    #[test]
    fn a_store_from_before_owners_facts_gains_its_table() {
        let d = Dirs::new();
        drop(d.up());
        Connection::open(d.lon.join("chats.sqlite")).unwrap().execute_batch("DROP TABLE facts").unwrap();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        db.set_facts(&ada, "kept").unwrap();
        assert_eq!((db.facts(&ada).as_deref(), count(&db, "chats_0", "facts")), (Some("kept"), 1));
    }

    #[test]
    fn copies_of_a_store_are_cleared_and_kept_by_person_as_well_as_by_bot() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        for u in [&ada, &cy] {
            db.pin_residency(PinOn::User, u, "gb-lon", "DPA-1", None).unwrap();
            db.set_facts(u, &format!("{u}'s facts")).unwrap();
        }
        let bot = bot_of(&db, &ada);
        db.set_memory(&bot, "memory").unwrap();
        signed_in(&db, &ada, "ua-1");
        let copy = d.dir.path().join("copy.sqlite");
        db.c().query_row("PRAGMA chats_0.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        std::fs::copy(d.lon.join("chats.sqlite"), &copy).unwrap();
        let c = Connection::open(&copy).unwrap();
        let only_cy = Whose { bots: Vec::new(), users: vec![cy.clone()] };
        assert_eq!(held_in_copy(&c, &only_cy).unwrap(), Held { facts: 1, ..Held::default() });
        assert_eq!(held_apart_from(&db.c(), "chats_0", &only_cy).unwrap(), Held { memories: 1, facts: 1, sessions: 1, ..Held::default() });
        assert_eq!(keep_only_in_copy(&c, &Whose { bots: vec![bot.clone()], users: vec![ada.clone()] }).unwrap(), Held { facts: 1, ..Held::default() });
        assert_eq!(drop_from_copy(&c, &Whose { bots: vec![bot], users: vec![ada.clone()] }).unwrap(), Held { memories: 1, facts: 1, sessions: 1, ..Held::default() });
        assert_eq!(held_in_copy(&c, &Whose { bots: Vec::new(), users: vec![ada, cy] }).unwrap(), Held::default());
    }

    #[test]
    fn an_erasure_deletes_a_persons_facts_in_a_store_and_in_copies_of_it() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        db.set_facts(&ada, "erase me").unwrap();
        let copy = d.dir.path().join("copy.sqlite");
        db.c().query_row("PRAGMA chats_0.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        std::fs::copy(d.lon.join("chats.sqlite"), &copy).unwrap();
        let c = Connection::open(&copy).unwrap();
        assert_eq!(crate::db::erase_in_copy(&c, &ada, "erased-00", &[]).unwrap().facts, 1);
        db.erase_user(&ada, "erased-00", None, &[]).unwrap();
        assert_eq!((db.facts(&ada), count(&db, "chats_0", "facts")), (None, 0));
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

    const LONG: i64 = 30 * 86_400_000;

    fn signed_in(db: &Db, user: &str, ua: &str) -> String {
        let s = crate::db::NewSession {
            user_id: user,
            token_hash: ua,
            kind: "cookie",
            method: "password",
            idp_subject: None,
            idp_provider: None,
            label: None,
            ip: Some("192.0.2.58"),
            user_agent: Some(ua),
            expires_at: now() + LONG,
            mfa: None,
        };
        db.create_session(&s).id
    }

    fn saml(index: &str) -> crate::db::SamlLogin {
        crate::db::SamlLogin { name_id: "ada@idp".into(), format: None, name_qualifier: None, sp_name_qualifier: None, session_index: Some(index.into()) }
    }

    fn sign_ins_move(from: Option<&str>, to: Option<&str>, n: [usize; 3]) -> ChatMove {
        ChatMove { sessions: n[0], saml_sessions: n[1], push_devices: n[2], ..mv(from, to, 0, [0, 0, 0]) }
    }

    fn sign_ins(db: &Db, schema: &str) -> [i64; 3] {
        SIGN_INS.map(|t| count(db, schema, t))
    }

    #[test]
    fn a_pinned_persons_sessions_saml_sign_ins_and_push_devices_are_kept_in_their_store_and_move_with_the_pin() {
        use crate::db::PushPut;
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let ua = "ua-58d1-adas-phone";
        let s1 = signed_in(&db, &ada, ua);
        db.add_saml_session(&s1, &saml("idx-1"));
        db.put_push_device(&ada, &s1, "fcm", "push-58e2-adas-token", "android", true, true);
        assert_eq!(sign_ins(&db, "main"), [1, 1, 1]);

        // Pinned, they move to the store together; the session still signs Ada in.
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![sign_ins_move(None, Some("gb-lon"), [1, 1, 1])]);
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([0, 0, 0], [1, 1, 1]));
        let (s, u) = db.live_session(ua, now(), LONG, LONG).unwrap();
        assert_eq!((s.id.as_str(), u.id.as_str(), s.ip.as_deref()), (s1.as_str(), ada.as_str(), Some("192.0.2.58")));
        assert_eq!(db.session_push_device(&s1).unwrap().token, "push-58e2-adas-token");
        assert_eq!(db.saml_session(&s1).unwrap().session_index.as_deref(), Some("idx-1"));
        let app = d.dir.path().join("app.sqlite");
        let holds = |path: &Path, w: &str| std::fs::read(path).is_ok_and(|b| b.windows(w.len()).any(|x| x == w.as_bytes()));
        assert!(!holds(&app, ua) && !holds(&d.dir.path().join("app.sqlite-wal"), ua), "no copy left in botd's own database");

        // Made, touched and revoked where they are kept; someone unpinned stays in botd's own.
        let s2 = signed_in(&db, &ada, "ua-58f3-adas-laptop");
        db.add_saml_session(&s2, &saml("idx-2"));
        let (_, put) = db.put_push_device(&ada, &s2, "fcm", "push-58e2-adas-token", "android", true, false);
        assert_eq!(put, PushPut::Moved, "the token moves from the first session to the second");
        assert_eq!(sign_ins(&db, "chats_0"), [2, 2, 1]);
        let later = now() + 120_000;
        db.touch_session(&s2, later);
        assert_eq!(db.session(&s2).unwrap().last_seen_at, later);
        let cys = signed_in(&db, &cy, "ua-58a4-cys");
        assert_eq!(sign_ins(&db, "main"), [1, 0, 0]);
        assert!(db.revoke_session(&s1, &ada, "signed_out"));
        assert!(db.session(&s1).unwrap().revoked_at.is_some() && db.live_session(ua, now(), LONG, LONG).is_none());
        assert!(!db.revoke_session(&s1, &ada, "signed_out"), "already revoked");
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), held: Held { sessions: 2, saml_sessions: 2, push_devices: 1, ..Held::default() } }]);

        // Unpinned, they come back, and the move is recorded for the store's earlier backups.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![sign_ins_move(Some("gb-lon"), None, [2, 2, 1])]);
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([3, 2, 1], [0, 0, 0]));
        let lon = db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert_eq!(db.moves_out_to_clear(&lon).unwrap().whose(), Whose { bots: Vec::new(), users: vec![ada.clone()] });
        assert!(!holds(&d.lon.join("chats.sqlite"), ua));
        let revoked = db.revoke_user_sessions(&ada, "ops", "offboarded");
        assert_eq!(revoked.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), [s2.as_str()]);
        assert!(db.session(&cys).unwrap().revoked_at.is_none());
    }

    #[test]
    fn sessions_in_a_store_are_pruned_and_erased_with_their_saml_sign_ins_and_push_devices() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let s1 = signed_in(&db, &ada, "ua-1");
        db.add_saml_session(&s1, &saml("idx-1"));
        db.put_push_device(&ada, &s1, "fcm", "push-1", "ios", true, true);
        assert_eq!(sign_ins(&db, "chats_0"), [1, 1, 1]);
        assert!(db.revoke_session(&s1, &ada, "signed_out"));
        assert_eq!(sign_ins(&db, "chats_0"), [1, 1, 0], "its push device goes with it");
        // A store has no foreign keys, so pruning sweeps what a deleted session leaves.
        assert_eq!(db.prune_sessions(now() + 1, LONG, LONG), 1);
        assert_eq!(sign_ins(&db, "chats_0"), [0, 0, 0]);

        let s2 = signed_in(&db, &ada, "ua-2");
        db.add_saml_session(&s2, &saml("idx-2"));
        db.put_push_device(&ada, &s2, "fcm", "push-2", "ios", true, true);
        let copy = d.dir.path().join("copy.sqlite");
        db.c().query_row("PRAGMA chats_0.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        std::fs::copy(d.lon.join("chats.sqlite"), &copy).unwrap();
        let c = Connection::open(&copy).unwrap();
        let erased = crate::db::erase_in_copy(&c, &ada, "erased-01", &[]).unwrap();
        assert_eq!((erased.sessions, erased.saml_sessions, erased.push_devices), (1, 1, 1));
        let out = db.erase_user(&ada, "erased-01", None, &[]).unwrap();
        assert_eq!(out.sessions, 1);
        assert_eq!(sign_ins(&db, "chats_0"), [0, 0, 0]);
    }

    #[test]
    fn a_move_cut_off_after_its_copy_keeps_sign_in_changes_and_revokes_once() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        let s = signed_in(&db, &ada, "ua-1");
        db.put_push_device(&ada, &s, "fcm", "push-1", "ios", true, true);
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([1, 0, 1], [1, 0, 1]), "in both places");
        // Changes meanwhile reach both copies, so the next pass keeps them whichever it keeps.
        db.put_push_device(&ada, &s, "fcm", "push-2", "ios", true, false);
        db.add_saml_session(&s, &saml("idx-1"));
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([1, 1, 1], [1, 1, 1]));
        assert_eq!(db.place_chats().unwrap(), vec![sign_ins_move(None, Some("gb-lon"), [1, 1, 1])]);
        let d = db.session_push_device(&s).unwrap();
        assert_eq!((d.token.as_str(), d.routines, db.saml_session(&s).is_some()), ("push-2", false, true));
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([0, 0, 0], [1, 1, 1]));

        // Unpinned and cut off again, revoking reaches both copies and tells the IdP once.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!(db.revoke_user_sessions(&ada, "ops", "offboarded").len(), 1, "told to the IdP once");
        assert_eq!(db.place_chats().unwrap(), vec![sign_ins_move(Some("gb-lon"), None, [1, 1, 0])]);
        assert_eq!((sign_ins(&db, "main"), sign_ins(&db, "chats_0")), ([1, 1, 0], [0, 0, 0]));
        assert!(db.session(&s).unwrap().revoked_at.is_some());
    }

    #[test]
    fn startup_seals_a_stores_push_tokens_under_the_current_master_key() {
        use crate::secrets::key::MasterKey;
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let s = signed_in(&db, &ada, "ua-1");
        let (dev, _) = db.put_push_device(&ada, &s, "fcm", "push-under-the-old-key", "ios", true, true);
        let (current, previous) = (sealed::cipher(), Cipher::new(&MasterKey::generate()));
        let stale = previous.seal(crate::db::PUSH_TOKEN_CONTEXT, b"push-under-the-old-key");
        db.c().execute("UPDATE chats_0.push_devices SET token = ?1 WHERE id = ?2", params![stale, dev.id]).unwrap();
        assert!(db.session_push_device(&s).is_none(), "a token the key doesn't open isn't sent to");
        let e = db.seal_store_push_tokens(&current, None, false).unwrap_err();
        assert!(e.contains("gb-lon's chat store") && e.contains("SUPERBOT_FORGET_SEALED=1"), "{e}");
        assert_eq!(db.seal_store_push_tokens(&current, Some(&previous), false).unwrap(), StoreApprovals { resealed: 1, ..Default::default() });
        assert_eq!(db.session_push_device(&s).unwrap().token, "push-under-the-old-key");
        assert_eq!(db.seal_store_push_tokens(&current, Some(&previous), false).unwrap(), StoreApprovals::default());
        let lost = Cipher::new(&MasterKey::generate()).seal(crate::db::PUSH_TOKEN_CONTEXT, b"x");
        db.c().execute("UPDATE chats_0.push_devices SET token = ?1 WHERE id = ?2", params![lost, dev.id]).unwrap();
        assert_eq!(db.seal_store_push_tokens(&current, Some(&previous), false).unwrap(), StoreApprovals { unreadable: 1, ..Default::default() });
        assert_eq!(db.seal_store_push_tokens(&current, None, true).unwrap(), StoreApprovals { discarded: 1, ..Default::default() });
        assert_eq!(count(&db, "chats_0", "push_devices"), 0, "the phone registers again");
        let (dev, _) = db.put_push_device(&ada, &s, "fcm", "push-2", "ios", true, true);
        db.c().execute("UPDATE chats_0.push_devices SET token = 'push-plain' WHERE id = ?1", [&dev.id]).unwrap();
        assert_eq!(db.seal_store_push_tokens(&current, None, false).unwrap(), StoreApprovals { sealed: 1, ..Default::default() });
        let raw: String = db.c().query_row("SELECT token FROM chats_0.push_devices WHERE id = ?1", [&dev.id], |r| r.get(0)).unwrap();
        assert!(sealed::is_sealed(&raw) && db.session_push_device(&s).unwrap().token == "push-plain");
    }

    #[test]
    fn a_store_gains_unique_indexes_for_sessions_and_push_devices() {
        let d = Dirs::new();
        let db = d.up();
        let unique: Vec<String> = {
            let c = db.c();
            let mut s = c.prepare("SELECT name FROM chats_0.sqlite_master WHERE type = 'index' AND sql LIKE 'CREATE UNIQUE%' ORDER BY name").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
        };
        assert_eq!(unique, ["push_devices_session", "push_devices_token", "sessions_token"]);
    }

    /// People's own secrets on a connection of their own, as botd runs them, with the stores
    /// botd's database attached.
    fn own_secrets(d: &Dirs, db: &Db) -> sealed::UserSecrets {
        let s = sealed::UserSecrets::new(sealed::connect(&d.dir.path().join("app.sqlite")).unwrap(), sealed::cipher());
        s.attach_stores(&db.chat_stores(), None).unwrap();
        s
    }

    fn secrets_move(from: Option<&str>, to: Option<&str>, n: usize) -> ChatMove {
        ChatMove { user_secrets: n, ..mv(from, to, 0, [0, 0, 0]) }
    }

    fn secret(s: &sealed::UserSecrets, user: &str, name: &str) -> Option<String> {
        s.get(user, name).unwrap().map(|v| v.expose().to_string())
    }

    #[test]
    fn a_pinned_persons_own_secrets_are_kept_in_their_store_and_move_with_the_pin() {
        let d = Dirs::new();
        let db = d.up();
        let s = own_secrets(&d, &db);
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        assert!(!s.put(&ada, "OPENAI_API_KEY", "sk-0293-adas-first").unwrap());
        assert_eq!(count(&db, "main", SECRETS), 1);

        // Pinned, it moves to the store and still opens there.
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![secrets_move(None, Some("gb-lon"), 1)]);
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (0, 1));
        assert_eq!(secret(&s, &ada, "OPENAI_API_KEY").as_deref(), Some("sk-0293-adas-first"));

        // Saved, changed and deleted where it is kept; someone unpinned stays in botd's own.
        assert!(!s.put(&ada, "GITHUB_TOKEN", "ghp-0293-adas").unwrap());
        assert!(s.put(&ada, "OPENAI_API_KEY", "sk-0293-adas-second").unwrap());
        assert!(!s.put(&cy, "GITHUB_TOKEN", "ghp-0293-cys").unwrap());
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (1, 2));
        assert_eq!(secret(&s, &ada, "OPENAI_API_KEY").as_deref(), Some("sk-0293-adas-second"));
        assert_eq!(s.names(&ada).unwrap().into_iter().map(|(n, ..)| n).collect::<Vec<_>>(), ["GITHUB_TOKEN", "OPENAI_API_KEY"]);
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), held: Held { user_secrets: 2, ..Held::default() } }]);
        let mut values: Vec<(String, String)> = s.all_values().into_iter().map(|(u, v)| (u, v.expose().to_string())).collect();
        values.sort();
        assert_eq!(values.len(), 3, "the redactor learns the store's as well: {values:?}");
        assert!(s.delete(&ada, "GITHUB_TOKEN").unwrap());
        assert!(!s.delete(&ada, "GITHUB_TOKEN").unwrap());
        assert_eq!(count(&db, "chats_0", SECRETS), 1);

        // Unpinned, it comes back, and the move is recorded for the store's earlier backups.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![secrets_move(Some("gb-lon"), None, 1)]);
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (2, 0));
        let lon = db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert_eq!(db.moves_out_to_clear(&lon).unwrap().whose(), Whose { bots: Vec::new(), users: vec![ada.clone()] });
        assert_eq!(secret(&s, &ada, "OPENAI_API_KEY").as_deref(), Some("sk-0293-adas-second"));
        assert_eq!(secret(&s, &cy, "GITHUB_TOKEN").as_deref(), Some("ghp-0293-cys"));
    }

    #[test]
    fn a_move_cut_off_after_its_copy_keeps_secret_changes_and_deletes() {
        let d = Dirs::new();
        let db = d.up();
        let s = own_secrets(&d, &db);
        let ada = user(&db, "ada");
        s.put(&ada, "A", "one").unwrap();
        s.put(&ada, "B", "two").unwrap();
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (2, 2), "in both places");
        // Read once, and changes meanwhile reach both copies, so the next pass keeps them whichever it keeps.
        assert_eq!(s.names(&ada).unwrap().len(), 2);
        assert!(s.put(&ada, "A", "one-changed").unwrap());
        assert!(s.delete(&ada, "B").unwrap());
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (1, 1));
        assert_eq!(db.place_chats().unwrap(), vec![secrets_move(None, Some("gb-lon"), 1)]);
        assert_eq!((count(&db, "main", SECRETS), count(&db, "chats_0", SECRETS)), (0, 1));
        assert_eq!(secret(&s, &ada, "A").as_deref(), Some("one-changed"));
        assert_eq!(secret(&s, &ada, "B"), None);
    }

    #[test]
    fn startup_seals_a_stores_own_secrets_under_the_current_master_key() {
        use crate::secrets::key::MasterKey;
        let d = Dirs::new();
        let db = d.up();
        let s = own_secrets(&d, &db);
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        s.put(&ada, "K", "under-the-old-key").unwrap();
        let (current, previous) = (sealed::cipher(), Cipher::new(&MasterKey::generate()));
        let context = sealed::user_context(&ada, "K");
        let set = |v: &str| db.c().execute("UPDATE chats_0.user_secrets SET value = ?1 WHERE user_id = ?2", params![v, ada]).unwrap();
        set(&previous.seal(&context, b"under-the-old-key"));
        assert!(s.get(&ada, "K").is_err(), "a value the key doesn't open isn't handed out");
        let e = db.seal_store_user_secrets(&current, None, false).unwrap_err();
        assert!(e.contains("gb-lon's chat store") && e.contains("SUPERBOT_FORGET_SEALED=1") && e.contains("ADR 0293"), "{e}");
        assert_eq!(db.seal_store_user_secrets(&current, Some(&previous), false).unwrap(), StoreApprovals { resealed: 1, ..Default::default() });
        assert_eq!(secret(&s, &ada, "K").as_deref(), Some("under-the-old-key"));
        assert_eq!(db.seal_store_user_secrets(&current, Some(&previous), false).unwrap(), StoreApprovals::default());
        set(&Cipher::new(&MasterKey::generate()).seal(&context, b"x"));
        assert_eq!(db.seal_store_user_secrets(&current, Some(&previous), false).unwrap(), StoreApprovals { unreadable: 1, ..Default::default() });
        assert_eq!(db.seal_store_user_secrets(&current, None, true).unwrap(), StoreApprovals { discarded: 1, ..Default::default() });
        assert_eq!(count(&db, "chats_0", SECRETS), 0, "its owner saves it again");
        s.put(&ada, "K", "x").unwrap();
        set("plain-0293");
        assert_eq!(db.seal_store_user_secrets(&current, None, false).unwrap(), StoreApprovals { sealed: 1, ..Default::default() });
        let raw: String = db.c().query_row("SELECT value FROM chats_0.user_secrets", [], |r| r.get(0)).unwrap();
        assert!(sealed::is_sealed(&raw) && secret(&s, &ada, "K").as_deref() == Some("plain-0293"));
    }

    #[test]
    fn an_erasure_deletes_a_persons_own_secrets_in_copies_of_a_store() {
        let d = Dirs::new();
        let db = d.up();
        let s = own_secrets(&d, &db);
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        for u in [&ada, &cy] {
            db.pin_residency(PinOn::User, u, "gb-lon", "DPA-1", None).unwrap();
            s.put(u, "K", "v").unwrap();
        }
        assert_eq!(count(&db, "chats_0", SECRETS), 2);
        db.c().query_row("PRAGMA chats_0.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        let copy = d.dir.path().join("copy.sqlite");
        std::fs::copy(d.lon.join("chats.sqlite"), &copy).unwrap();
        let c = Connection::open(&copy).unwrap();
        assert_eq!(crate::db::erase_in_copy(&c, &ada, "erased-01", &[]).unwrap().user_secrets, 1);
        let left: Vec<String> = c.prepare("SELECT user_id FROM user_secrets").unwrap().query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(left, [cy]);
    }

    #[test]
    fn saved_rows_are_scrubbed_again_of_secrets_only_a_store_holds() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let bot = bot_of(&db, &ada);
        let value = "sk-0293-known-only-once-the-store-is-read";
        db.add_message(&bot, "user", &format!("use {value} please"), None, false, None);
        crate::secrets::redact::register_for(&ada, value);
        assert!(db.scrub_saved_rows().unwrap() >= 1);
        let text: String = db.c().query_row("SELECT text FROM chats_0.messages WHERE bot_id = ?1", [&bot], |r| r.get(0)).unwrap();
        assert_eq!(text, format!("use {} please", crate::secrets::redact::MARK));
    }

    #[test]
    fn describing_what_a_place_holds_names_own_secrets() {
        assert_eq!(Held { sessions: 1, user_secrets: 2, ..Held::default() }.describe(), "1 sign-in session and 2 personal secrets");
        assert_eq!(Held { sessions: 1, user_secrets: 2, ..Held::default() }.sign_ins(), Held { sessions: 1, ..Held::default() });
        assert_eq!(Held { messages: 1, user_secrets: 2, ..Held::default() }.of_bots(), Held { messages: 1, ..Held::default() });
    }

    fn factor_move(from: Option<&str>, to: Option<&str>, codes: usize) -> ChatMove {
        ChatMove { second_factors: 1, recovery_codes: codes, ..mv(from, to, 0, [0, 0, 0]) }
    }

    /// Second factors and recovery codes in `schema`.
    fn factors(db: &Db, schema: &str) -> [i64; 2] {
        [count(db, schema, SECOND_FACTOR), count(db, schema, RECOVERY_CODE)]
    }

    fn codes(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_pinned_persons_second_factor_and_recovery_codes_are_kept_in_their_store_and_move_with_the_pin() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let secret = "sb1:totp-0299-adas-first";
        assert!(db.mfa_begin(&ada, secret));
        assert!(db.mfa_confirm(&ada, secret, 10, &codes(&["h1", "h2"])));
        assert_eq!(factors(&db, "main"), [1, 2]);

        // Pinned, they move to the store together, and still check a code.
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![factor_move(None, Some("gb-lon"), 2)]);
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([0, 0], [1, 2]));
        let row = db.mfa(&ada).unwrap();
        assert_eq!((row.secret.as_str(), row.confirmed_at.is_some(), row.last_step), (secret, true, 10));
        assert!(db.mfa_use_step(&ada, 11) && !db.mfa_use_step(&ada, 11), "a step works once");
        assert!(db.mfa_use_recovery(&ada, "h1") && !db.mfa_use_recovery(&ada, "h1"), "a code works once");
        assert_eq!(db.mfa_recovery_left(&ada), 1);
        assert!(db.mfa_replace_recovery(&ada, &codes(&["h3", "h4", "h5"])));
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([0, 0], [1, 3]));
        assert!(!db.mfa_begin(&ada, "sb1:other"), "a confirmed one must be turned off first");
        assert_eq!(
            db.chat_counts(std::slice::from_ref(&ada)),
            vec![ChatCount { region: Some("gb-lon".into()), held: Held { second_factors: 1, recovery_codes: 3, ..Held::default() } }]
        );

        // Turned off and set up again where it is kept; someone unpinned stays in botd's own.
        assert!(db.mfa_delete(&ada));
        assert_eq!(factors(&db, "chats_0"), [0, 0]);
        assert!(db.mfa_begin(&ada, "sb1:pending") && db.mfa_begin(&ada, "sb1:pending-again"));
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([0, 0], [1, 0]));
        assert!(db.mfa_enable(&ada, "sb1:totp-0299-adas-second", 20, &codes(&["h6"])));
        assert_eq!(factors(&db, "chats_0"), [1, 1]);
        assert_eq!(db.mfa(&ada).unwrap().secret, "sb1:totp-0299-adas-second");
        assert!(db.mfa_enable(&cy, "sb1:totp-0299-cys", 5, &codes(&["c1"])));
        assert!(!db.mfa_enable(&cy, "sb1:again", 6, &[]));
        assert_eq!(factors(&db, "main"), [1, 1]);
        let mut on: Vec<String> = db.mfa_enabled().into_keys().collect();
        on.sort();
        let mut both = vec![ada.clone(), cy.clone()];
        both.sort();
        assert_eq!(on, both);

        // A store has no foreign keys, so a pass sweeps recovery codes whose second factor is gone.
        db.c().execute("INSERT INTO chats_0.mfa_recovery_codes (user_id, code_hash, created_at) VALUES ('gone', 'h', 0)", []).unwrap();
        db.place_chats().unwrap();
        assert_eq!(factors(&db, "chats_0"), [1, 1]);

        // Unpinned, they come back, and the move is recorded for the store's earlier backups.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![factor_move(Some("gb-lon"), None, 1)]);
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([2, 2], [0, 0]));
        let lon = db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert_eq!(db.moves_out_to_clear(&lon).unwrap().whose(), Whose { bots: Vec::new(), users: vec![ada.clone()] });
        assert!(db.mfa_use_recovery(&ada, "h6"));
    }

    #[test]
    fn a_move_cut_off_after_its_copy_keeps_second_factor_changes() {
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        assert!(db.mfa_enable(&ada, "sb1:t", 10, &codes(&["h1", "h2"])));
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([1, 2], [1, 2]), "in both places");
        // Spent once, and changes meanwhile reach both copies, so the next pass keeps them whichever it keeps.
        assert_eq!(db.mfa_recovery_left(&ada), 2, "read once");
        assert!(db.mfa_use_step(&ada, 11) && !db.mfa_use_step(&ada, 11));
        assert!(db.mfa_use_recovery(&ada, "h1") && !db.mfa_use_recovery(&ada, "h1"));
        assert_eq!(db.place_chats().unwrap(), vec![factor_move(None, Some("gb-lon"), 2)]);
        assert_eq!((db.mfa(&ada).unwrap().last_step, db.mfa_recovery_left(&ada)), (11, 1));
        assert!(!db.mfa_use_recovery(&ada, "h1"), "a spent code stays spent");

        // Cut off again on the way back, new codes and turning it off reach both copies.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        CRASH_AFTER_COPY.with(|c| c.set(true));
        assert!(db.place_chats().is_err());
        assert!(db.mfa_replace_recovery(&ada, &codes(&["h3"])));
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([1, 1], [1, 1]));
        assert!(db.mfa_delete(&ada));
        assert_eq!((factors(&db, "main"), factors(&db, "chats_0")), ([0, 0], [0, 0]));
        assert!(db.mfa(&ada).is_none());
    }

    #[test]
    fn startup_seals_a_stores_second_factors_under_the_current_master_key() {
        use crate::secrets::key::MasterKey;
        let d = Dirs::new();
        let db = d.up();
        let ada = user(&db, "ada");
        db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        let (current, previous) = (sealed::cipher(), Cipher::new(&MasterKey::generate()));
        let context = sealed::mfa_context(&ada);
        let set = |v: &str| db.c().execute("UPDATE chats_0.user_mfa SET secret = ?1 WHERE user_id = ?2", params![v, ada]).unwrap();
        let open = || current.open_text(&context, &db.mfa(&ada).unwrap().secret).ok().map(|s| s.expose().to_string());
        assert!(db.mfa_enable(&ada, &previous.seal(&context, b"JBSWY3DP-old"), 1, &codes(&["h1"])));
        let e = db.seal_store_second_factors(&current, None, false, false).unwrap_err();
        assert!(e.contains("gb-lon's chat store") && e.contains("SUPERBOT_FORGET_SEALED=1") && e.contains("ADR 0299"), "{e}");
        assert_eq!(db.seal_store_second_factors(&current, Some(&previous), false, false).unwrap(), StoreApprovals { resealed: 1, ..Default::default() });
        assert_eq!((open().as_deref(), factors(&db, "chats_0")), (Some("JBSWY3DP-old"), [1, 1]), "derived keys kept: the codes stay");
        assert_eq!(db.seal_store_second_factors(&current, Some(&previous), false, true).unwrap(), StoreApprovals::default());
        assert_eq!(factors(&db, "chats_0"), [1, 1], "already under the new key: nothing to drop");
        // A rotation that renews derived keys drops the recovery codes it seals again, as botd's own.
        set(&previous.seal(&context, b"JBSWY3DP-old"));
        assert_eq!(db.seal_store_second_factors(&current, Some(&previous), false, true).unwrap(), StoreApprovals { resealed: 1, ..Default::default() });
        assert_eq!((open().as_deref(), factors(&db, "chats_0")), (Some("JBSWY3DP-old"), [1, 0]));
        assert!(db.mfa_replace_recovery(&ada, &codes(&["h2"])));
        set(&Cipher::new(&MasterKey::generate()).seal(&context, b"x"));
        assert_eq!(db.seal_store_second_factors(&current, Some(&previous), false, false).unwrap(), StoreApprovals { unreadable: 1, ..Default::default() });
        assert_eq!(db.seal_store_second_factors(&current, None, true, false).unwrap(), StoreApprovals { discarded: 1, ..Default::default() });
        assert_eq!(factors(&db, "chats_0"), [0, 0], "dropped with its codes; its owner sets it up again");
        assert!(db.mfa_enable(&ada, "JBSWY3DP-plain", 1, &[]));
        assert_eq!(db.seal_store_second_factors(&current, None, false, false).unwrap(), StoreApprovals { sealed: 1, ..Default::default() });
        assert!(sealed::is_sealed(&db.mfa(&ada).unwrap().secret) && open().as_deref() == Some("JBSWY3DP-plain"));
    }

    #[test]
    fn an_erasure_deletes_a_persons_second_factor_in_the_store_and_in_copies_of_it() {
        let d = Dirs::new();
        let db = d.up();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        for u in [&ada, &cy] {
            db.pin_residency(PinOn::User, u, "gb-lon", "DPA-1", None).unwrap();
            assert!(db.mfa_enable(u, "sb1:t", 1, &codes(&["h1", "h2"])));
        }
        assert_eq!(factors(&db, "chats_0"), [2, 4]);
        db.c().query_row("PRAGMA chats_0.wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).unwrap();
        let copy = d.dir.path().join("copy.sqlite");
        std::fs::copy(d.lon.join("chats.sqlite"), &copy).unwrap();
        let c = Connection::open(&copy).unwrap();
        let erased = crate::db::erase_in_copy(&c, &ada, "erased-01", &[]).unwrap();
        assert_eq!((erased.second_factors, erased.recovery_codes), (1, 2));
        let left: Vec<String> = c.prepare("SELECT user_id FROM user_mfa").unwrap().query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(left, [cy.clone()]);
        let out = db.erase_user(&ada, "erased-01", None, &[]).unwrap();
        assert_eq!((out.mfa, out.recovery_codes), (true, 2));
        assert_eq!(factors(&db, "chats_0"), [1, 2]);
    }

    #[test]
    fn describing_what_a_place_holds_names_second_factors() {
        assert_eq!(Held { user_secrets: 1, second_factors: 1, recovery_codes: 2, ..Held::default() }.describe(), "1 personal secret, 1 second factor and 2 recovery codes");
        assert_eq!(Held { sessions: 1, second_factors: 1, recovery_codes: 2, ..Held::default() }.second_factor(), Held { second_factors: 1, recovery_codes: 2, ..Held::default() });
        assert_eq!(Held { second_factors: 1, ..Held::default() }.sign_ins(), Held::default());
    }

    #[test]
    fn describing_what_a_place_holds_names_sign_ins() {
        assert_eq!(Held { sessions: 2, saml_sessions: 1, push_devices: 1, ..Held::default() }.describe(), "2 sign-in sessions, 1 SAML sign-in and 1 push device");
        assert_eq!(Held { messages: 1, sessions: 1, ..Held::default() }.sign_ins(), Held { sessions: 1, ..Held::default() });
        assert_eq!(Held { messages: 1, sessions: 1, ..Held::default() }.of_bots(), Held { messages: 1, ..Held::default() });
    }
}
