//! Pinned people's chats in a database in their region (ADR 0215), the first part of
//! splitting botd's database by region. Each region in REGION_DATA_DIRS has a SQLite file
//! of its own (`chats.sqlite`, keyed like botd's database), attached to botd's connection.
//! A Bot's messages are kept in the store of its owner's residency pin (their team's,
//! else their own, as `residency::of_user`), or in botd's own database when that region
//! has no store or the owner isn't pinned.
//!
//! Reads see every place at once: a TEMP view named `messages` puts botd's own table and
//! each store's together, and unqualified names find TEMP objects first. Writes name the
//! table they change: new messages go where their Bot's chat belongs, and updates and
//! deletes by id run on each place. Ids stay unique across all of them: a store's rows
//! take the next id after botd's own sequence and every store's highest, and bump that
//! sequence, so botd's table never hands the same id out again.
//!
//! `place_chats` moves rows whose Bot belongs elsewhere now (a pin made or ended, a
//! member joining or leaving a pinned team, a Bot given away): copied, then deleted from
//! where they were, in one transaction. A crash mid-commit can leave a copy in both
//! places; the next pass deletes the one in the wrong place.

use super::{Db, now};
use crate::database_encryption::{self, Format};
use rusqlite::{Connection, OptionalExtension, ToSql, params};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The token a statement run on every place chats are kept writes for the table.
pub(super) const TABLE: &str = "{messages}";

/// botd's record of each store it has kept chats in, so a store that goes missing (an
/// unmounted volume, a dropped setting) stops botd instead of hiding those chats.
const RECORDS: &str = "CREATE TABLE IF NOT EXISTS main.chat_stores (
  region TEXT PRIMARY KEY,
  store_id TEXT NOT NULL,
  path TEXT NOT NULL,
  added_at INTEGER NOT NULL
)";

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
    /// The messages table's columns, quoted, in the order botd's own table has them.
    cols: String,
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

/// Chats one pass moved between two places. `None`: botd's own database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMove {
    pub from: Option<String>,
    pub to: Option<String>,
    pub bots: usize,
    pub messages: usize,
}

/// One place chats are kept, and how many messages are there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatCount {
    /// None: botd's own database.
    pub region: Option<String>,
    pub messages: i64,
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

fn columns(c: &Connection, schema: &str) -> rusqlite::Result<Vec<Col>> {
    let mut s = c.prepare(&format!("SELECT name, type, \"notnull\", dflt_value FROM pragma_table_info('messages', {})", literal(schema)))?;
    s.query_map([], |r| Ok(Col { name: r.get(0)?, ty: r.get(1)?, notnull: r.get(2)?, default: r.get(3)? }))?.collect()
}

/// Makes the store's messages table match botd's own: the same columns, `id` its primary
/// key without AUTOINCREMENT (ids come from botd's sequence), and the same indexes.
fn ensure_messages(c: &Connection, schema: &str, main: &[Col]) -> rusqlite::Result<()> {
    let def = |col: &Col, adding: bool| {
        if col.name == "id" {
            return "\"id\" INTEGER PRIMARY KEY".to_string();
        }
        let default = col.default.as_ref().map(|d| format!(" DEFAULT {d}")).unwrap_or_default();
        // A column added to a table with rows can be NOT NULL only with a default.
        let notnull = if col.notnull && (!adding || col.default.is_some()) { " NOT NULL" } else { "" };
        format!("{} {}{notnull}{default}", quote(&col.name), col.ty)
    };
    let defs: Vec<String> = main.iter().map(|col| def(col, false)).collect();
    c.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {schema}.messages ({})", defs.join(", ")))?;
    let have: Vec<String> = columns(c, schema)?.into_iter().map(|c| c.name).collect();
    for col in main.iter().filter(|col| !have.contains(&col.name)) {
        c.execute_batch(&format!("ALTER TABLE {schema}.messages ADD COLUMN {}", def(col, true)))?;
    }
    c.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS {schema}.messages_bot ON messages(bot_id, id);
         CREATE INDEX IF NOT EXISTS {schema}.messages_created ON messages(created_at);"
    ))
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
    /// missing or isn't the one recorded, rather than start an empty one in its place.
    pub fn attach_chat_stores(&self, dirs: &[(String, PathBuf)], key: Option<&str>) -> Result<Attached, String> {
        if self.5.get().is_some() {
            return Err("chat stores are attached once, at startup".into());
        }
        let c = self.c();
        let e = |err: rusqlite::Error| format!("chat stores: {err}");
        c.execute_batch(RECORDS).map_err(e)?;
        let recorded: Vec<(String, String, String)> = {
            let mut s = c.prepare("SELECT region, store_id, path FROM main.chat_stores ORDER BY region").map_err(e)?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(e)?.collect::<rusqlite::Result<_>>().map_err(e)?
        };
        let mut out = Attached::default();
        // Forgotten only once every store checks out, so a start that fails changes nothing.
        for (region, _, path) in recorded.iter().filter(|(r, _, _)| !dirs.iter().any(|(d, _)| d == r)) {
            let p = Path::new(path);
            if database_encryption::format(p)? != Format::Missing {
                c.execute("ATTACH DATABASE ?1 AS chats_dropped KEY ?2", params![path, key.unwrap_or("")]).map_err(|err| not_a_store(p, &err))?;
                let n = c.query_row(
                    "SELECT CASE WHEN EXISTS (SELECT 1 FROM chats_dropped.sqlite_master WHERE type = 'table' AND name = 'messages') THEN (SELECT COUNT(*) FROM chats_dropped.messages) ELSE 0 END",
                    [],
                    |r| r.get::<_, i64>(0),
                );
                c.execute("DETACH DATABASE chats_dropped", []).map_err(e)?;
                let n = n.map_err(|err| not_a_store(p, &err))?;
                if n > 0 {
                    return Err(format!(
                        "REGION_DATA_DIRS no longer names {region}, but its chat store ({path}) still holds {n} messages of pinned people's chats. \
                         Put {region}=<its folder> back. To retire a store, end the pins in {region} first, let botd move their chats back, then remove it (ADR 0215)."
                    ));
                }
            }
            out.forgotten.push((region.clone(), path.clone()));
        }
        let main = columns(&c, "main").map_err(e)?;
        let cols = main.iter().map(|col| quote(&col.name)).collect::<Vec<_>>().join(", ");
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
                     restore it from its folder's backups/ (ADR 0215)."
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
            ensure_messages(&c, &schema, &main).map_err(e)?;
            let top: i64 = c.query_row(&format!("SELECT COALESCE(MAX(id), 0) FROM {schema}.messages"), [], |r| r.get(0)).map_err(e)?;
            bump_sequence(&c, top).map_err(e)?;
            stores.push(ChatStore { region: region.clone(), schema, path, id });
        }
        for (region, _) in &out.forgotten {
            c.execute("DELETE FROM main.chat_stores WHERE region = ?1", [region]).map_err(e)?;
        }
        if !stores.is_empty() {
            let parts: Vec<String> = schemas(&stores).map(|s| format!("SELECT {cols} FROM {s}.messages")).collect();
            c.execute_batch(&format!("CREATE TEMP VIEW messages AS {}", parts.join(" UNION ALL "))).map_err(e)?;
        }
        let _ = self.5.set(ChatStores { stores, cols });
        Ok(out)
    }

    /// The schema a new message in `bot_id`'s chat goes to.
    fn chat_schema_for(&self, c: &Connection, bot_id: &str) -> rusqlite::Result<&str> {
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
        let schema = self.chat_schema_for(c, bot_id)?;
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

    /// Runs `sql`, which names the messages table as `{messages}`, on every place chats are
    /// kept. The rows it changed, together.
    pub(super) fn on_chats(&self, c: &Connection, sql: &str, p: &[&dyn ToSql]) -> rusqlite::Result<usize> {
        let mut n = 0;
        for s in schemas(self.chat_stores_set()) {
            n += c.execute(&sql.replace(TABLE, &format!("{s}.messages")), p)?;
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

    /// Moves every Bot's chat to where it belongs now, and deletes store rows whose Bot is
    /// gone (botd's own table loses them with the Bot). What moved, per pair of places.
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
        let cols = &set.cols;
        let mut moves = Vec::new();
        for to in schemas(&set.stores) {
            for from in schemas(&set.stores).filter(|s| *s != to) {
                let here = format!("bot_id IN (SELECT bot_id FROM temp.chat_place WHERE schema = {})", literal(to));
                let bots: i64 = tx.query_row(&format!("SELECT COUNT(DISTINCT bot_id) FROM {from}.messages WHERE {here}"), [], |r| r.get(0))?;
                if bots == 0 {
                    continue;
                }
                tx.execute(&format!("INSERT OR IGNORE INTO {to}.messages ({cols}) SELECT {cols} FROM {from}.messages WHERE {here}"), [])?;
                let messages = tx.execute(&format!("DELETE FROM {from}.messages WHERE {here} AND id IN (SELECT id FROM {to}.messages)"), [])?;
                moves.push(ChatMove { from: region_of(&set.stores, from).map(str::to_string), to: region_of(&set.stores, to).map(str::to_string), bots: bots as usize, messages });
            }
        }
        for s in &set.stores {
            tx.execute(&format!("DELETE FROM {}.messages WHERE bot_id NOT IN (SELECT id FROM main.bots)", s.schema), [])?;
        }
        tx.commit()?;
        Ok(moves)
    }

    /// How many messages of the chats of Bots `owners` own are in each place: botd's own
    /// database first, then each store, places with none left out.
    pub fn chat_counts(&self, owners: &[String]) -> Vec<ChatCount> {
        let owners = serde_json::to_string(owners).unwrap_or_else(|_| "[]".into());
        let c = self.c();
        let stores = self.chat_stores_set();
        schemas(stores)
            .filter_map(|s| {
                let n: i64 = c
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {s}.messages WHERE bot_id IN (SELECT id FROM main.bots WHERE owner_id IN (SELECT value FROM json_each(?1)))"),
                        [&owners],
                        |r| r.get(0),
                    )
                    .ok()?;
                (n > 0).then(|| ChatCount { region: region_of(stores, s).map(str::to_string), messages: n })
            })
            .collect()
    }

    /// Every store and how many messages it holds.
    pub fn chat_store_counts(&self) -> Vec<(ChatStore, i64)> {
        let c = self.c();
        self.chat_stores_set()
            .iter()
            .map(|s| (s.clone(), c.query_row(&format!("SELECT COUNT(*) FROM {}.messages", s.schema), [], |r| r.get(0)).unwrap_or(0)))
            .collect()
    }

    /// Redacts known secrets from the stores' chats, as startup does for botd's own
    /// (`redact::scrub_rows`). How many rows changed.
    pub fn scrub_chat_stores(&self) -> rusqlite::Result<usize> {
        let tables: Vec<String> = self.chat_stores_set().iter().map(|s| format!("{}.messages", s.schema)).collect();
        if tables.is_empty() {
            return Ok(0);
        }
        let tables: Vec<&str> = tables.iter().map(String::as_str).collect();
        crate::secrets::redact::scrub_rows_in(&self.c(), &tables, false)
    }

    /// Which place message `id` is in: None for botd's own database.
    #[cfg(test)]
    pub fn chat_place_of(&self, id: i64) -> Option<Option<String>> {
        let c = self.c();
        let stores = self.chat_stores_set();
        schemas(stores)
            .find(|s| c.query_row(&format!("SELECT 1 FROM {s}.messages WHERE id = ?1"), [id], |_| Ok(())).is_ok())
            .map(|s| region_of(stores, s).map(str::to_string))
    }
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
    use crate::db::PinOn;
    use crate::rbac::Role;

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
            db.attach_chat_stores(&self.both(), None).unwrap();
            db
        }
    }

    fn user(db: &Db, name: &str) -> String {
        db.create_user(None, Some(&format!("{name}@example.com")), name, Role::Member).unwrap().id
    }

    fn bot_of(db: &Db, owner: &str) -> String {
        db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, owner, Visibility::Private).id
    }

    fn rows_in(path: &Path) -> i64 {
        let c = Connection::open(path).unwrap();
        c.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn without_stores_everything_stays_in_botds_own_table() {
        let d = Dirs::new();
        let db = d.db();
        assert_eq!(db.attach_chat_stores(&[], None).unwrap(), Attached::default());
        let u = user(&db, "ada");
        db.pin_residency(PinOn::User, &u, "gb-lon", "DPA-1", None).unwrap();
        let m = db.add_message(&bot_of(&db, &u), "user", "hi", None, false, None);
        assert_eq!(db.chat_place_of(m.id), Some(None));
        assert!(db.place_chats().unwrap().is_empty() && db.chat_stores().is_empty());
        assert!(db.attach_chat_stores(&[], None).unwrap_err().contains("once"));
    }

    #[test]
    fn a_pinned_owners_chat_is_kept_in_their_regions_store_and_reads_see_every_place() {
        let d = Dirs::new();
        let db = d.db();
        let (ada, cy) = (user(&db, "ada"), user(&db, "cy"));
        let (ada_bot, cy_bot) = (bot_of(&db, &ada), bot_of(&db, &cy));
        let before = db.add_message(&ada_bot, "user", "before the store", None, false, None);
        assert_eq!(db.attach_chat_stores(&d.both(), None).unwrap().created, vec!["gb-lon", "de-fra-2"]);
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
        assert_eq!(db.place_chats().unwrap(), vec![ChatMove { from: None, to: Some("gb-lon".into()), bots: 1, messages: 1 }]);
        assert!(db.place_chats().unwrap().is_empty());
        assert_eq!((rows_in(&d.lon.join("chats.sqlite")), rows_in(&d.fra.join("chats.sqlite"))), (2, 0));
        assert_eq!(db.chat_counts(std::slice::from_ref(&ada)), vec![ChatCount { region: Some("gb-lon".into()), messages: 2 }]);
        assert_eq!(db.chat_counts(std::slice::from_ref(&cy)), vec![ChatCount { region: None, messages: 1 }]);
        assert_eq!(db.messages(&ada_bot, 10).len(), 2, "no copy left behind");

        // Unpinned, it comes back to botd's own table, ids unchanged.
        db.unpin_residency(PinOn::User, &ada).unwrap();
        assert_eq!(db.place_chats().unwrap(), vec![ChatMove { from: Some("gb-lon".into()), to: None, bots: 1, messages: 2 }]);
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
        assert_eq!(db.place_chats().unwrap(), vec![ChatMove { from: Some("de-fra-2".into()), to: None, bots: 1, messages: 1 }]);
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
        assert_eq!(db.message_count(&bot), 2);
        db.place_chats().unwrap();
        assert_eq!((db.message_count(&bot), db.chat_place_of(m.id)), (1, Some(Some("gb-lon".into()))));
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
        let start = |dirs: &[(String, PathBuf)]| d.db().attach_chat_stores(dirs, None);

        // Dropped from REGION_DATA_DIRS while it holds chats.
        let e = start(&d.both()[1..]).unwrap_err();
        assert!(e.contains("no longer names gb-lon") && e.contains("still holds 1 messages"), "{e}");
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
        Db::open(&other.path().join("app.sqlite")).unwrap().attach_chat_stores(&[("gb-lon".into(), other.path().to_path_buf())], None).unwrap();
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
        assert_eq!(db.attach_chat_stores(&d.both(), None).unwrap(), Attached::default());
        assert_eq!(db.chat_store_counts().iter().map(|(s, n)| (s.region.as_str(), *n)).collect::<Vec<_>>(), vec![("gb-lon", 1), ("de-fra-2", 0)]);
    }

    #[test]
    fn an_empty_store_dropped_from_the_settings_is_forgotten() {
        let d = Dirs::new();
        drop(d.up());
        let a = d.db().attach_chat_stores(&d.both()[..1], None).unwrap();
        assert_eq!(a.forgotten.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), vec!["de-fra-2"]);
        assert!(a.created.is_empty());
        // Named again later, its old file is adopted.
        assert_eq!(d.db().attach_chat_stores(&d.both(), None).unwrap(), Attached::default());
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
            db.attach_chat_stores(&here, Some(key.raw())).unwrap();
            let ada = user(&db, "ada");
            db.pin_residency(PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
            let m = db.add_message(&bot_of(&db, &ada), "user", "secret chat", None, false, None);
            assert_eq!(db.message(m.id).unwrap().text, "secret chat");
        }
        let store = dir.path().join("chats.sqlite");
        assert_eq!(format(&store).unwrap(), Format::Encrypted);
        assert!(!std::fs::read(&store).unwrap().windows(11).any(|w| w == b"secret chat"));
        let other = DbKey::derive(&MasterKey::generate());
        let e = Db::open_keyed(&dir.path().join("app.sqlite"), &key).attach_chat_stores(&here, Some(other.raw())).unwrap_err();
        assert!(e.contains("doesn't open with botd's database key"), "{e}");
    }
}
