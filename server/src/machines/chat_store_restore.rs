//! `botd chat-store` (ADR 0256): lists a regional chat store's backups (ADR 0215), in its
//! folder and in its bucket (ADR 0246), and restores one as the store, on the server with
//! botd stopped, as `botd database` and `botd support check` run (ADR 0187).
//!
//! A restore is checked before anything changes: the backup must be this store (botd's
//! record of its id and region), open with the master key (or the previous one, mid-
//! rotation) and pass its integrity check, and a bucket copy must match the SHA-256 in its
//! name. It is prepared in a work file in the store's own folder, never the host's temp
//! folder: rows of Bots and people that aren't kept in the region now (moved out, or deleted) are
//! taken out, and erasures made since are run on it again, so a restore never brings back
//! what a move or an erasure took out. The store it replaces is kept as a backup made now,
//! so it is cleared and copied off the host like any other and the restore can be undone.
//! Without `--yes` it only says what a restore would do. botd audits the restore at its
//! next start (`residency.chat_store_restored`), from a note left in the folder.

use super::chat_store_copies::{self, Copies, copy_name};
use super::chat_stores;
use crate::audit::{Who, clip};
use crate::database_encryption::{self, DbKey, Format};
use crate::db::{ChatStore, Db, ERASED_BOTS, Held};
use crate::secrets::sealed::{self, Cipher};
use crate::support_check::Settings;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const RESTORED: &str = "residency.chat_store_restored";
/// Notes left in the store's folder by restores (`restored-<time>.json`), one each, for
/// botd to audit at its next start.
const NOTE: &str = "restored-";
/// Work files of a restore in the store's folder; a restore that was cut off leaves them.
const WORK: &str = ".restore-";
const ACTOR: &str = "residency";
const DOC: &str = "docs/support/runbook-residency.md#restoring-a-regional-chat-store";

const USAGE: &str = "Usage: botd chat-store list <region> [--home <dir> | --env-file <file>]
       botd chat-store restore <region> <backup | newest> [--identity <file>] [--replace-unreadable] [--second-factors-from-backup] [--yes]
                               [--home <dir> | --env-file <file>]

Run on the server with botd stopped, as the user botd runs as (the owner of DATA_DIR and
the region's folder): sudo -u superbot botd chat-store ...
  <backup>              a backup in the region's folder (chats-<time>.sqlite) or a copy in its
                        bucket (chats-<time>-<sha256>.sqlite[.age]), as `list` shows them;
                        newest: the folder's newest backup, else the bucket's newest copy
  --identity <file>     the age identity that opens the bucket's encrypted copies
  --replace-unreadable  delete a store that doesn't open, rather than refuse
  --second-factors-from-backup  with the store missing or not opening, take people's second
                        factors from the backup though one set up since is lost, rather than refuse
  --yes                 restore; without it, say what a restore would do and change nothing
  --home <dir>          the installer's layout: settings from <dir>/superbot/.env
  --env-file <file>     settings from this file, over botd's environment
Docs: docs/support/runbook-residency.md#restoring-a-regional-chat-store";

/// One region's store, as botd's settings and database say.
pub struct Place {
    region: String,
    store: ChatStore,
    db_path: PathBuf,
    /// The master keys' database keys: the current one, then the previous one.
    keys: Vec<DbKey>,
    /// Whether botd's own database is encrypted, which its stores must match.
    encrypted: bool,
    db_key: Option<DbKey>,
    /// What seals approvals' tool inputs: the current master key, then the previous one.
    ciphers: Vec<Arc<Cipher>>,
    /// SUPERBOT_FORGET_SEALED=1: botd drops at start the inputs neither key opens.
    forget_sealed: bool,
    /// The region's bucket. Err: its settings are wrong, said only when it is needed.
    copies: Result<Option<Copies>, String>,
}

fn io(p: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("{}: {e}", p.display())
}

/// REGION_DATA_DIRS's entries, as `<region>=<folder>`.
fn region_dirs(raw: &str) -> Vec<(String, PathBuf)> {
    raw.split(',').filter_map(|e| e.split_once('=')).map(|(r, d)| (r.trim().to_string(), PathBuf::from(d.trim()))).filter(|(r, _)| !r.is_empty()).collect()
}

impl Place {
    /// `region`'s store, from botd's settings `s`: its folder (REGION_DATA_DIRS), botd's
    /// database and its record of the store, the master keys, and the region's bucket.
    pub fn locate(s: &Settings, region: &str) -> Result<Place, String> {
        let dirs = region_dirs(&s.get(chat_stores::SETTING));
        let Some((_, folder)) = dirs.iter().find(|(r, _)| r == region) else {
            let named: Vec<&str> = dirs.iter().map(|(r, _)| r.as_str()).collect();
            return Err(format!("{} doesn't name {region} (it names {})", chat_stores::SETTING, if named.is_empty() { "none".to_string() } else { named.join(", ") }));
        };
        if !folder.is_dir() {
            return Err(format!("{region}'s folder {} isn't there. Mount the region's volume first: botd keeps the store on storage in the region (ADR 0215)", folder.display()));
        }
        let data_dir = s.data_dir();
        let db_path = data_dir.join("app.sqlite");
        let masters = crate::support_check::master_keys(s, &data_dir)?;
        let keys: Vec<DbKey> = masters.iter().map(DbKey::derive).collect();
        let (encrypted, db_key) = match database_encryption::format(&db_path)? {
            Format::Missing => {
                return Err(format!("no botd database at {}. Restore botd's own server backup first (docs/support/runbook-server-restore.md)", db_path.display()));
            }
            Format::Plain => (false, None),
            Format::Encrypted => match keys.iter().find(|k| database_encryption::opens(&db_path, k)) {
                Some(k) => (true, Some(k.clone())),
                None if keys.is_empty() => return Err(format!("{} is encrypted and no master key was found (SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE)", db_path.display())),
                None => return Err(format!("{}: the master key doesn't open it (wrong key)", db_path.display())),
            },
        };
        let c = database_encryption::open_read_only(&db_path, db_key.as_ref()).map_err(|e| format!("{}: {e}", db_path.display()))?;
        let rec: Option<(String, String)> = c.query_row("SELECT store_id, path FROM chat_stores WHERE region = ?1", [region], |r| Ok((r.get(0)?, r.get(1)?))).optional().unwrap_or(None);
        let Some((id, was)) = rec else {
            return Err(format!("botd has no chat store recorded for {region}, so there is no store to restore (ADR 0215)"));
        };
        let here = folder.join("chats.sqlite");
        if let (Format::Missing, Some(moved)) = (database_encryption::format(&here)?, crate::db::moved_to(&was, &here)?) {
            return Err(format!(
                "{region}'s chat store was moved to {} while botd ran, with its backups. Set {} to {region}={} first (ADR 0309)",
                moved.display(),
                chat_stores::SETTING,
                moved.display()
            ));
        }
        let store = ChatStore { region: region.to_string(), schema: String::new(), path: folder.join("chats.sqlite"), id };
        drop(c);
        let sealed = masters.iter().filter_map(|k| {
            let c = database_encryption::open_read_only(&db_path, db_key.as_ref()).ok()?;
            Some(crate::secrets::sealed::SealedStore::new(c, Arc::new(Cipher::new(k))))
        });
        let copies = bucket(s, region, folder, Sealed(sealed.collect()));
        let ciphers = masters.iter().map(|k| Arc::new(Cipher::new(k))).collect();
        let forget_sealed = s.get("SUPERBOT_FORGET_SEALED") == "1";
        Ok(Place { region: region.to_string(), store, db_path, keys, encrypted, db_key, ciphers, forget_sealed, copies })
    }

    fn db(&self) -> Result<Connection, String> {
        database_encryption::open_read_only(&self.db_path, self.db_key.as_ref()).map_err(|e| format!("{}: {e}", self.db_path.display()))
    }

    fn folder(&self) -> &Path {
        self.store.path.parent().unwrap_or(Path::new("/"))
    }

    fn copies(&self) -> Result<Option<&Copies>, String> {
        self.copies.as_ref().map(Option::as_ref).map_err(|e| format!("{}'s bucket: {e}", self.region))
    }
}

/// botd's saved server secrets, opened with each master key in turn (the current one, then
/// the previous one), since a rotation cut short leaves some sealed under the previous one.
struct Sealed(Vec<crate::secrets::sealed::SealedStore>);

impl crate::secrets::SecretStore for Sealed {
    fn kind(&self) -> &'static str {
        "sealed"
    }

    fn get(&self, name: &str) -> Result<Option<crate::secrets::Secret>, crate::secrets::Error> {
        let mut failed = None;
        for s in &self.0 {
            match s.get(name) {
                Ok(Some(v)) => return Ok(Some(v)),
                Ok(None) => return Ok(None),
                Err(e) => failed = Some(e),
            }
        }
        failed.map_or(Ok(None), Err)
    }

    fn names(&self) -> Result<Vec<String>, crate::secrets::Error> {
        self.0.first().map_or(Ok(Vec::new()), |s| s.names())
    }
}

/// `region`'s bucket (ADR 0246), with its keys from the settings, or else from botd's saved
/// server secrets. Only that region's: another region's broken bucket mustn't block it.
fn bucket(s: &Settings, region: &str, folder: &Path, sealed: Sealed) -> Result<Option<Copies>, String> {
    let vars: HashMap<String, String> = s.vars().into_iter().collect();
    let var = |k: &str| vars.get(k).cloned().unwrap_or_default();
    if var(&format!("{}_BUCKET", chat_store_copies::store_name(region))).trim().is_empty() {
        return Ok(None);
    }
    let env = crate::secrets::env::EnvStore::vars(vars.clone());
    let store = crate::secrets::external::Layered(vec![&env, &sealed]);
    let dirs = chat_stores::Settings { dirs: vec![(region.to_string(), folder.to_path_buf())], ..chat_stores::Settings::default() };
    chat_store_copies::Settings::from_env(&store, &var, &dirs, &[region.to_string()])?.map(Copies::new).transpose()
}

/// Holds botd's data lock and the store's, as botd does while it runs, so nothing changes
/// either while a restore reads and writes them.
struct Locks(#[allow(dead_code)] database_encryption::DataDirLock, #[allow(dead_code)] database_encryption::DataDirLock);

fn lock(place: &Place) -> Result<Locks, String> {
    let stopped = |e: String| format!("{e}. botd must be stopped for a restore (sudo systemctl stop superbot; Compose: docker compose stop botd)");
    let data = database_encryption::lock_data_dir(&place.db_path).map_err(stopped)?;
    let store = database_encryption::lock_data_dir(&place.store.path).map_err(stopped)?;
    Ok(Locks(data, store))
}

/// Deletes what a restore that was cut off left in a store's `folder`: its work files, which
/// may hold rows of Bots that have since left the store, and a backup that is still a link
/// to the store itself, which writes to the store would change. At botd's start, before it
/// opens the store; one that can't be deleted stops botd.
pub fn drop_leftovers(folder: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(store) = std::fs::metadata(folder.join("chats.sqlite")) {
        for entry in std::fs::read_dir(folder.join("backups")).into_iter().flatten().flatten() {
            let p = entry.path();
            if std::fs::metadata(&p).is_ok_and(|m| m.dev() == store.dev() && m.ino() == store.ino()) {
                std::fs::remove_file(&p).map_err(|e| format!("{}: {e}; a restore that was cut off left it, a link to the store itself (ADR 0256)", p.display()))?;
            }
        }
    }
    let entries = match std::fs::read_dir(folder) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(folder)(e)),
    };
    for entry in entries {
        let entry = entry.map_err(io(folder))?;
        if entry.file_name().to_string_lossy().starts_with(WORK) {
            let p = entry.path();
            std::fs::remove_file(&p).map_err(|e| format!("{}: {e}; a restore that was cut off left it, and it may hold chats that left the store (ADR 0256)", p.display()))?;
        }
    }
    Ok(())
}

/// At botd's start: audits each restore made while it was stopped, oldest first, from the
/// notes it left in the store's folder, as `residency.chat_store_restored` by botd itself,
/// then deletes them. A note is written before the store is replaced, so one whose file is
/// neither the store nor one of its backups is of a restore cut off before it replaced the
/// store: it is only logged. Lines for the startup log.
pub fn audit_restores(db: &Db, dirs: &[(String, PathBuf)]) -> Vec<String> {
    let mut lines = Vec::new();
    for (region, dir) in dirs {
        let mut notes: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(NOTE) && n.ends_with(".json")))
            .map(|e| e.path())
            .collect();
        notes.sort();
        let kept = |path: &Path, e: String| format!("Regional chat stores: a restore's note {} couldn't be checked ({e}); it is kept for the next start (ADR 0256).", path.display());
        let files = match inodes(dir) {
            Ok(f) => f,
            Err(e) => {
                lines.extend(notes.iter().map(|p| kept(p, e.clone())));
                continue;
            }
        };
        for path in notes {
            // A note is synced before the store is replaced, so one that doesn't parse was
            // cut off before that; one that can't be read may be of a restore that happened.
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    lines.push(kept(&path, e.to_string()));
                    continue;
                }
            };
            let note: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let backup = note["backup"].as_str().map_or("a backup".to_string(), |b| clip(b, 200));
            if note["file"].as_u64().is_some_and(|f| files.contains(&f)) {
                let mut details = json!({ "region": region });
                for k in [
                    "storeId",
                    "backup",
                    "from",
                    "backupAt",
                    "restoredAt",
                    "kept",
                    "replacedUnreadable",
                    "held",
                    "dropped",
                    "erased",
                    "signInsReplaced",
                    "signedIn",
                    "meterHeldBack",
                    "back",
                    "gone",
                    "uid",
                ] {
                    match &note[k] {
                        Value::String(v) => details[k] = json!(clip(v, 200)),
                        Value::Null => {}
                        v => details[k] = v.clone(),
                    }
                }
                // Named on the chain before the restore is audited: a start cut off in between
                // names them again, which changes nothing (ADR 0316).
                let lost: Vec<[i64; 2]> = serde_json::from_value(note["auditDetailsLost"].clone()).unwrap_or_default();
                if !lost.is_empty() {
                    details["auditDetailsLost"] = json!(lost.iter().map(|[a, b]| b - a + 1).sum::<i64>());
                    if let Err(e) = db.with_conn(|c| crate::audit_chain::insert_erased_ranges(c, ACTOR, ("chat_store", region), &lost)) {
                        lines.push(format!(
                            "Regional chat stores: the audit events whose details {region}'s store lost in the restore from {backup} couldn't be named on the chain ({e}); its note {} is kept for the next start (ADR 0316).",
                            path.display()
                        ));
                        continue;
                    }
                }
                if let Err(e) = db.try_record(&Who::system(ACTOR).event(RESTORED).target("chat_store", region).details(details)) {
                    lines.push(format!("Regional chat stores: the restore of {region}'s store from {backup} couldn't be audited ({e}); its note {} is kept for the next start (ADR 0256).", path.display()));
                    continue;
                }
                lines.push(format!("Regional chat stores: {region}'s store was restored from {backup} while botd was stopped; audited as {RESTORED} (ADR 0256)."));
            } else {
                lines.push(format!("Regional chat stores: a restore of {region}'s store from {backup} was cut off before it replaced the store, so nothing was restored (ADR 0256)."));
            }
            if let Err(e) = std::fs::remove_file(&path) {
                lines.push(format!("Regional chat stores: {} couldn't be deleted ({e}), so it will be read again at the next start; delete it (ADR 0256).", path.display()));
            }
        }
    }
    lines
}

/// The inodes of a store's file and its backups, which a restore's note names. Err when
/// they can't all be checked, which isn't proof the note's file is gone.
fn inodes(dir: &Path) -> Result<Vec<u64>, String> {
    use std::os::unix::fs::MetadataExt;
    let missing = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let mut paths = vec![dir.join("chats.sqlite")];
    let backups = dir.join("backups");
    match std::fs::read_dir(&backups) {
        Ok(entries) => {
            for e in entries {
                paths.push(e.map_err(|e| format!("{}: {e}", backups.display()))?.path());
            }
        }
        Err(e) if missing(&e) => {}
        Err(e) => return Err(format!("{}: {e}", backups.display())),
    }
    let mut out = Vec::new();
    for p in paths {
        match std::fs::metadata(&p) {
            Ok(m) => out.push(m.ino()),
            Err(e) if missing(&e) => {}
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Ok(out)
}

// Listing

/// What `botd chat-store list` prints: the store, its backups and its bucket's copies.
pub async fn list(place: &Place) -> Result<String, String> {
    let mut out = String::new();
    let p = &place.store.path;
    let file = match std::fs::metadata(p) {
        Ok(m) => format!("{} ({})", p.display(), size(m.len())),
        Err(_) => format!("{}: missing", p.display()),
    };
    out.push_str(&format!("{}'s chat store {}: {file}\n", place.region, place.store.id));
    let copies = match place.copies() {
        Ok(Some(c)) => Some(c.list_copies(&place.store).await.unwrap_or_else(|| Ok(Vec::new()))),
        Ok(None) => None,
        Err(e) => Some(Err(e)),
    };
    let copied: Vec<String> = copies.iter().flatten().flatten().filter_map(|n| copy_name(n).map(|c| c.backup)).collect();
    let local = chat_stores::backups_strictly(&place.store)?;
    out.push_str(&format!("Backups in {} (newest first): {}\n", chat_stores::backups_dir(&place.store).display(), local.len()));
    for (_, path) in &local {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let off = if copied.iter().any(|c| *c == name) { "  copy in the bucket" } else { "" };
        out.push_str(&format!("  {name}  {}{off}\n", size(bytes)));
    }
    match copies {
        None => out.push_str(&format!("No bucket for {} ({}_BUCKET): its backups are only on the store's volume (ADR 0246).\n", place.region, chat_store_copies::store_name(&place.region))),
        Some(Err(e)) => out.push_str(&format!("Its bucket couldn't be listed: {e}\n")),
        Some(Ok(names)) => {
            let dest = place.copies().ok().flatten().and_then(|c| c.destination(&place.store)).unwrap_or_default();
            out.push_str(&format!("Copies in {dest} (newest first): {}\n", names.len()));
            for n in names.iter().rev() {
                out.push_str(&format!("  {n}\n"));
            }
        }
    }
    Ok(out)
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1 << 20) as f64),
        b => format!("{} KB", b.div_ceil(1024)),
    }
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(String::new, |t| t.format("%Y-%m-%d %H:%M UTC").to_string())
}

// Restoring

/// Where a backup is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    /// In the store's folder's `backups/`.
    Folder(PathBuf),
    /// A copy in the region's bucket, by name.
    Bucket(String),
}

/// The backup a restore puts back.
#[derive(Clone, Debug)]
struct Chosen {
    /// `chats-<time>.sqlite`.
    name: String,
    at: i64,
    source: Source,
}

/// The backup `wanted` names (or the newest), in the folder or the bucket.
async fn choose(place: &Place, wanted: &str) -> Result<Chosen, String> {
    let local = chat_stores::backups_strictly(&place.store)?;
    let folder = |at: i64, path: &PathBuf| Chosen { name: path.file_name().unwrap_or_default().to_string_lossy().into_owned(), at, source: Source::Folder(path.clone()) };
    let from_bucket = |name: &str| copy_name(name).and_then(|c| chat_stores::backup_time(&c.backup).map(|at| Chosen { name: c.backup, at, source: Source::Bucket(name.to_string()) }));
    let listed = || async {
        match place.copies()? {
            Some(c) => c.list_copies(&place.store).await.unwrap_or_else(|| Ok(Vec::new())),
            None => Err(format!("{} has no bucket ({}_BUCKET)", place.region, chat_store_copies::store_name(&place.region))),
        }
    };
    if wanted == "newest" {
        if let Some((at, path)) = local.first() {
            return Ok(folder(*at, path));
        }
        let names = listed().await.map_err(|e| format!("{}'s folder has no backups, and {e}", place.region))?;
        return names.iter().filter_map(|n| from_bucket(n)).max_by_key(|c| c.at).ok_or_else(|| format!("{}'s folder has no backups and its bucket has no copies", place.region));
    }
    if chat_stores::backup_time(wanted).is_some() {
        return local.iter().find(|(_, p)| p.file_name().is_some_and(|n| n == wanted)).map(|(at, p)| folder(*at, p)).ok_or_else(|| format!("{wanted} isn't in {}", chat_stores::backups_dir(&place.store).display()));
    }
    if copy_name(wanted).is_some() {
        let names = listed().await?;
        return names.iter().find(|n| *n == wanted).and_then(|n| from_bucket(n)).ok_or_else(|| format!("{wanted} isn't in {}'s bucket", place.region));
    }
    Err(format!("\"{}\" isn't a backup's name (chats-<time>.sqlite) or a copy's (chats-<time>-<sha256>.sqlite[.age]); `botd chat-store list {}` shows them", clip(wanted, 80), place.region))
}

/// Puts the backup in a work file in the store's folder, decrypted and checked against the
/// SHA-256 in its name when it comes from the bucket.
async fn fetch(place: &Place, chosen: &Chosen, identities: &[age::x25519::Identity]) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let work = place.folder().join(format!("{WORK}{}", chosen.name));
    let _ = std::fs::remove_file(&work);
    match &chosen.source {
        Source::Folder(path) => {
            std::fs::copy(path, &work).map_err(io(&work))?;
            std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o600)).map_err(io(&work))?;
        }
        Source::Bucket(name) => {
            let c = place.copies()?.ok_or_else(|| format!("{} has no bucket", place.region))?;
            let parsed = copy_name(name).ok_or_else(|| format!("{name} isn't a copy's name"))?;
            let download = place.folder().join(format!("{WORK}{name}.download"));
            let _ = std::fs::remove_file(&download);
            let r = async {
                c.download(&place.store, name, &download).await?;
                if parsed.encrypted {
                    decrypt(&download, &work, identities)?;
                    std::fs::remove_file(&download).map_err(io(&download))?;
                } else {
                    std::fs::rename(&download, &work).map_err(io(&work))?;
                }
                let sha = sha256(&work)?;
                if sha != parsed.sha {
                    return Err(format!("{name} doesn't match its SHA-256 once downloaded{}; nothing was changed", if parsed.encrypted { " and decrypted" } else { "" }));
                }
                Ok(())
            }
            .await;
            if let Err(e) = r {
                let _ = std::fs::remove_file(&download);
                let _ = std::fs::remove_file(&work);
                return Err(e);
            }
        }
    }
    Ok(work)
}

fn decrypt(from: &Path, to: &Path, identities: &[age::x25519::Identity]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    if identities.is_empty() {
        return Err("the copy is age-encrypted: give the identity that opens it with --identity <file>".into());
    }
    let f = std::fs::File::open(from).map_err(io(from))?;
    let d = age::Decryptor::new(std::io::BufReader::new(f)).map_err(|e| format!("{}: not an age file: {e}", from.display()))?;
    let mut r = d.decrypt(identities.iter().map(|i| i as &dyn age::Identity)).map_err(|_| "the identity given doesn't open this copy (REGION_DATA_AGE_RECIPIENTS names others)".to_string())?;
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(to).map_err(io(to))?;
    std::io::copy(&mut r, &mut out).map_err(|e| format!("decrypting {}: {e}", from.display()))?;
    out.sync_all().map_err(io(to))
}

fn sha256(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(io(path))?;
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(io(path))?;
        if n == 0 {
            return Ok(crate::sigv4::hex(ctx.finish().as_ref()));
        }
        ctx.update(&buf[..n]);
    }
}

/// The store as it is now.
#[derive(Debug)]
enum Current {
    Missing,
    /// It opens, with this key, and passes its integrity check.
    Readable(Option<DbKey>),
    Unreadable(String),
}

/// The key of `keys` that opens the database at `path`. None: it is plain.
fn key_for(path: &Path, keys: &[DbKey]) -> Result<Option<DbKey>, String> {
    match database_encryption::format(path)? {
        Format::Missing => Err(format!("{} is empty", path.display())),
        Format::Plain => Ok(None),
        Format::Encrypted => keys.iter().find(|k| database_encryption::opens(path, k)).cloned().map(Some).ok_or_else(|| {
            format!("{} doesn't open with the master key or the previous one: it was made under a master key botd no longer has, or isn't a database", path.display())
        }),
    }
}

fn current(place: &Place) -> Current {
    let p = &place.store.path;
    match database_encryption::format(p) {
        Ok(Format::Missing) => return Current::Missing,
        Err(e) => return Current::Unreadable(e),
        Ok(_) => {}
    }
    let key = match key_for(p, &place.keys) {
        Ok(k) => k,
        Err(e) => return Current::Unreadable(e),
    };
    let check = database_encryption::open_read_only(p, key.as_ref()).and_then(|c| c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0)));
    match check {
        Ok(ok) if ok == "ok" => Current::Readable(key),
        Ok(bad) => Current::Unreadable(format!("{} fails its integrity check ({})", p.display(), clip(&bad, 200))),
        Err(e) => Current::Unreadable(format!("{}: {e}", p.display())),
    }
}

/// What a restore does, worked out on the work file before anything else changes.
#[derive(Debug, Default)]
pub struct Plan {
    /// What the restored store holds.
    held: Held,
    /// Rows of Bots and people kept elsewhere now, or deleted, taken out of it.
    dropped: Held,
    /// What erasures made since rewrote or deleted in it.
    erased: Held,
    /// Its own sign-ins (ADR 0283), replaced by `signed_in`.
    sign_ins_replaced: Held,
    /// The sign-ins of the people kept in it, from the store now (none: it is missing or unreadable).
    signed_in: Held,
    /// Against the store now (None: it is missing or unreadable): what comes back, what goes.
    back: Option<Held>,
    gone: Option<Held>,
    /// The store now doesn't open, and is deleted rather than kept.
    unreadable: Option<String>,
    /// Approvals' saved tool inputs neither master key opens, which botd drops at start.
    unopened: usize,
    /// People's own secrets kept from it (the store now missing, ADR 0293) that neither
    /// master key opens, which botd drops at start.
    unopened_secrets: usize,
    /// People's second factors kept from it (the store now missing, ADR 0299) that neither
    /// master key opens, which botd drops at start.
    unopened_factors: usize,
    /// People kept in it with no second factor in the backup, counted only when the store
    /// now is missing or doesn't open: one they set up since is lost (ADR 0299).
    without_factor: usize,
    /// Usage records kept from it (the store now missing or not opening, ADR 0304) that were
    /// still waiting for Stripe's meter, marked failed rather than sent again.
    meter_held_back: usize,
    /// Audit events whose details only the store held and it doesn't (made since, or an
    /// erasure since rewrote them), the store now missing or not opening (ADR 0316): their
    /// rows in botd's log are named as erased when botd starts.
    audit_lost: Vec<i64>,
}

/// Erasures the copy must have run again: each erased person and pseudonym, and the Bots
/// erasures deleted, from botd's database. An erasure deletes a person's Bots before it
/// erases what those Bots wrote in others' chats, so a backup made in between holds that,
/// and the `bot.deleted` events from before it may be pruned. So for a person erased after
/// the backup, their Bots come from what the erasure kept (`erased_bots:<user>`). Refused
/// for an erasure from an earlier botd that kept nothing, unless it deleted no Bots.
fn erasures(c: &Connection, backup_at: i64) -> Result<(Vec<(String, String)>, Vec<String>), String> {
    let db = |e: rusqlite::Error| format!("botd's database: {e}");
    let people: Vec<(String, String, i64)> = {
        let mut s = c.prepare("SELECT id, COALESCE(erased_as, ''), erased_at FROM users WHERE erased_at IS NOT NULL ORDER BY erased_at").map_err(db)?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(db)?.collect::<rusqlite::Result<_>>().map_err(db)?
    };
    let mut bots: Vec<String> = {
        let mut s = c
            .prepare("SELECT DISTINCT target_id FROM audit_events WHERE action = 'bot.deleted' AND target_id IS NOT NULL AND json_valid(details) AND json_extract(details, '$.reason') = 'user_erased'")
            .map_err(db)?;
        s.query_map([], |r| r.get(0)).map_err(db)?.collect::<rusqlite::Result<_>>().map_err(db)?
    };
    // What each erasure kept, whenever it was: a `bot.deleted` event's details may be in a
    // regional store this connection doesn't attach (ADR 0316).
    for (id, pseudonym, at) in &people {
        let kept: Option<String> = c.query_row("SELECT value FROM settings WHERE key = ?1", [format!("{ERASED_BOTS}{id}")], |r| r.get(0)).optional().map_err(db)?;
        if let Some(kept) = kept {
            let ids: Vec<String> = serde_json::from_str(&kept).map_err(|e| format!("botd's database: {ERASED_BOTS}{id}: {e}"))?;
            bots.extend(ids);
            continue;
        }
        if *at < backup_at {
            continue;
        }
        let counted: Option<String> = c
            .query_row("SELECT details FROM audit_events WHERE action = 'user.erased' AND target_id = ?1 ORDER BY at DESC LIMIT 1", [pseudonym], |r| r.get(0))
            .optional()
            .map_err(db)?;
        if counted.and_then(|d| serde_json::from_str::<Value>(&d).ok()).and_then(|d| d["bots"].as_u64()) != Some(0) {
            return Err(format!(
                "{pseudonym} was erased {}, after this backup was made ({}), by an earlier botd that didn't keep which Bots it deleted, so what those Bots wrote can't all be found. Restore a backup made after their erasure (ADR 0256)",
                date(*at),
                date(backup_at)
            ));
        }
    }
    bots.sort();
    bots.dedup();
    Ok((people.into_iter().map(|(id, p, _)| (id, p)).collect(), bots))
}

/// Prepares the work file to be the store: checks it is this store, takes out the rows of
/// Bots that aren't kept in the region now, runs erasures again, puts the store's sign-ins
/// now in place of its own, rebuilds it so nothing taken out is left in its pages, and
/// compares it with the store now.
fn prepare(place: &Place, work: &Path, at: i64, current: &Current) -> Result<Plan, String> {
    let shown = work.display().to_string();
    let key = key_for(work, &place.keys)?;
    if key.is_some() && !place.encrypted {
        return Err(format!("{shown} is encrypted but botd's database isn't; a chat store is kept like botd's own database (ADR 0215)"));
    }
    let err = |e: rusqlite::Error| format!("{shown}: {e}");
    let c = database_encryption::open_with(work, key.as_ref()).map_err(err)?;
    // Nothing of it may be written outside the region's folder (VACUUM's copy, a journal).
    c.execute_batch("PRAGMA temp_store = MEMORY").map_err(err)?;
    c.query_row("PRAGMA journal_mode = MEMORY", [], |_| Ok(())).map_err(err)?;
    let check = |c: &Connection| -> Result<(), String> {
        let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(err)?;
        if ok != "ok" {
            return Err(format!("{shown} fails its integrity check ({}); restore another backup", clip(&ok, 200)));
        }
        Ok(())
    };
    check(&c)?;
    let own: Option<(String, String)> = c.query_row("SELECT id, region FROM chat_store LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional().unwrap_or(None);
    match own {
        None => return Err(format!("{shown} isn't a SuperBot chat store")),
        Some((_, r)) if r != place.region => return Err(format!("that backup is {r}'s chat store, not {}'s", place.region)),
        Some((id, _)) if id != place.store.id => {
            return Err(format!("that backup is of chat store {id}, but botd keeps {}'s chats in store {} (ADR 0215)", place.region, place.store.id));
        }
        Some(_) => {}
    }
    let db_path = place.db_path.to_str().ok_or_else(|| format!("{}: path is not UTF-8", place.db_path.display()))?;
    c.execute("ATTACH DATABASE ?1 AS botd KEY ?2", rusqlite::params![db_path, place.db_key.as_ref().map_or("", |k| k.raw())]).map_err(err)?;
    crate::db::upgrade_copy(&c, "botd").map_err(err)?;
    c.execute("DETACH DATABASE botd", []).map_err(err)?;
    let db = place.db()?;
    let kept = crate::db::kept_in_region(&db, &place.region).map_err(|e| format!("botd's database: {e}"))?;
    let (people, bots) = erasures(&db, at)?;
    drop(db);
    c.execute_batch("PRAGMA secure_delete = ON").map_err(err)?;
    let mut plan = Plan::default();
    for (i, (user, pseudonym)) in people.iter().enumerate() {
        let theirs: &[String] = if i == 0 { &bots } else { &[] };
        plan.erased.add(crate::db::erase_in_copy(&c, user, pseudonym, theirs).map_err(err)?);
    }
    plan.dropped = crate::db::keep_only_in_copy(&c, &kept).map_err(err)?;
    let attach_now = |c: &Connection, k: &Option<DbKey>| -> Result<(), String> {
        let p = place.store.path.to_str().ok_or_else(|| format!("{}: path is not UTF-8", place.store.path.display()))?;
        c.execute("ATTACH DATABASE ?1 AS now_store KEY ?2", rusqlite::params![p, k.as_ref().map_or("", |k| k.raw())]).map_err(err)?;
        Ok(())
    };
    // A session revoked since the backup must not work again (ADR 0283).
    let now = if let Current::Readable(k) = current {
        attach_now(&c, k)?;
        Some("now_store")
    } else {
        None
    };
    (plan.sign_ins_replaced, plan.signed_in, plan.meter_held_back) = crate::db::sign_ins_from(&c, now, &kept).map_err(err)?;
    if now.is_some() {
        c.execute("DETACH DATABASE now_store", []).map_err(err)?;
    } else {
        // Audit events' details are kept from the backup as the only copy left, but not
        // those an erasure since rewrote; any botd's log says the store held that the copy
        // doesn't are lost (ADR 0316).
        c.execute("ATTACH DATABASE ?1 AS botd KEY ?2", rusqlite::params![db_path, place.db_key.as_ref().map_or("", |k| k.raw())]).map_err(err)?;
        let lost = crate::db::audit_lost_in_copy(&c, "botd", &place.region, at);
        c.execute("DETACH DATABASE botd", []).map_err(err)?;
        let (erased, elsewhere, lost) = lost.map_err(err)?;
        plan.erased.audit_events += erased;
        plan.dropped.audit_events += elsewhere;
        plan.audit_lost = lost;
    }
    c.execute_batch("VACUUM").map_err(err)?;
    check(&c)?;
    plan.held = crate::db::held_in_copy(&c, &kept).map_err(err)?;
    plan.unopened = unopened(&c, &place.ciphers).map_err(err)?;
    if plan.unopened > 0 && !place.forget_sealed {
        return Err(format!(
            "{} saved tool inputs of approvals in that backup don't open with the master key or the previous one, so botd wouldn't start with it. \
             Set SUPERBOT_MASTER_KEY_PREVIOUS to the key they were sealed under; if it's lost for good, set SUPERBOT_FORGET_SEALED=1 so botd drops them at start (ADR 0228)",
            plan.unopened
        ));
    }
    plan.unopened_secrets = unopened_secrets(&c, &place.ciphers).map_err(err)?;
    if plan.unopened_secrets > 0 && !place.forget_sealed {
        return Err(format!(
            "{} people's own secrets in that backup don't open with the master key or the previous one, so botd wouldn't start with it. \
             Set SUPERBOT_MASTER_KEY_PREVIOUS to the key they were sealed under; if it's lost for good, set SUPERBOT_FORGET_SEALED=1 so botd drops them at start and their owners save them again (ADR 0293)",
            plan.unopened_secrets
        ));
    }
    plan.unopened_factors = unopened_factors(&c, &place.ciphers).map_err(err)?;
    if !matches!(current, Current::Readable(_)) {
        plan.without_factor = without_factor(&c, &kept.users).map_err(err)?;
    }
    if plan.unopened_factors > 0 && !place.forget_sealed {
        return Err(format!(
            "{} people's second factors in that backup don't open with the master key or the previous one, so botd wouldn't start with it. \
             Set SUPERBOT_MASTER_KEY_PREVIOUS to the key they were sealed under; if it's lost for good, set SUPERBOT_FORGET_SEALED=1 so botd drops them at start and their owners set them up again (ADR 0299)",
            plan.unopened_factors
        ));
    }
    match current {
        Current::Readable(k) => {
            attach_now(&c, k)?;
            let waiting = crate::db::held_apart_from(&c, "now_store", &kept).map_err(err)?;
            if waiting.total() > 0 {
                return Err(format!(
                    "the store now holds {} of Bots or people kept elsewhere now that botd hasn't moved yet, which a restore would leave behind in a backup. Start botd, let it move them, stop it, then restore",
                    waiting.describe()
                ));
            }
            let (back, gone) = crate::db::compare_copy(&c, "now_store").map_err(err)?;
            c.execute("DETACH DATABASE now_store", []).map_err(err)?;
            (plan.back, plan.gone) = (Some(back), Some(gone));
        }
        Current::Unreadable(e) => plan.unreadable = Some(e.clone()),
        Current::Missing => {}
    }
    drop(c);
    std::fs::File::open(work).and_then(|f| f.sync_all()).map_err(io(work))?;
    Ok(plan)
}

/// How many approvals' saved tool inputs are sealed under a key none of `ciphers` is, which
/// botd refuses at start (ADR 0228). Plaintext ones it seals then.
fn unopened(c: &Connection, ciphers: &[Arc<Cipher>]) -> rusqlite::Result<usize> {
    let mut s = c.prepare("SELECT id, input FROM approvals")?;
    let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut n = 0;
    for row in rows {
        let (id, input) = row?;
        let context = sealed::approval_context(&id);
        if sealed::is_sealed(&input) && !ciphers.iter().any(|k| k.open(&context, &input).is_ok()) {
            n += 1;
        }
    }
    Ok(n)
}

/// How many people's own secrets (ADR 0293) are sealed under a key none of `ciphers` is,
/// which botd refuses at start. None in a backup from before them.
fn unopened_secrets(c: &Connection, ciphers: &[Arc<Cipher>]) -> rusqlite::Result<usize> {
    let has: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?1)", [crate::db::SECRETS], |r| r.get(0))?;
    if !has {
        return Ok(0);
    }
    let mut s = c.prepare("SELECT user_id, name, value FROM main.user_secrets")?;
    let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
    let mut n = 0;
    for row in rows {
        let (user, name, value) = row?;
        let context = sealed::user_context(&user, &name);
        if sealed::is_sealed(&value) && !ciphers.iter().any(|k| k.open(&context, &value).is_ok()) {
            n += 1;
        }
    }
    Ok(n)
}

/// How many people's second factors (ADR 0299) are sealed under a key none of `ciphers` is,
/// which botd refuses at start. None in a backup from before them.
fn unopened_factors(c: &Connection, ciphers: &[Arc<Cipher>]) -> rusqlite::Result<usize> {
    let has: bool = c.query_row("SELECT EXISTS (SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?1)", [crate::db::SECOND_FACTOR], |r| r.get(0))?;
    if !has {
        return Ok(0);
    }
    let mut s = c.prepare("SELECT user_id, secret FROM main.user_mfa")?;
    let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut n = 0;
    for row in rows {
        let (user, secret) = row?;
        let context = sealed::mfa_context(&user);
        if sealed::is_sealed(&secret) && !ciphers.iter().any(|k| k.open(&context, &secret).is_ok()) {
            n += 1;
        }
    }
    Ok(n)
}

/// How many of `users` (the people kept in the store) have no confirmed second factor in
/// the copy on `c`, whose tables `upgrade_copy` has made.
fn without_factor(c: &Connection, users: &[String]) -> rusqlite::Result<usize> {
    let mut s = c.prepare("SELECT EXISTS (SELECT 1 FROM main.user_mfa WHERE user_id = ?1 AND confirmed_at IS NOT NULL)")?;
    let mut n = 0;
    for u in users {
        if !s.query_row([u], |r| r.get::<_, bool>(0))? {
            n += 1;
        }
    }
    Ok(n)
}

fn people_without(n: usize) -> String {
    if n == 1 { "1 person kept in it has".to_string() } else { format!("{n} people kept in it have") }
}

/// Keeps the store now as a backup made at `at` in its folder's `backups/`, as one file,
/// so it is cleared and copied off the host like any other: a second link to it, so the
/// store stays in place until the restored one replaces it in one rename. Its name.
fn keep_current(place: &Place, key: Option<&DbKey>, at: i64) -> Result<String, String> {
    let p = &place.store.path;
    let err = |e: rusqlite::Error| format!("{}: {e}", p.display());
    let c = database_encryption::open_with(p, key).map_err(err)?;
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())).map_err(err)?;
    let mode: String = c.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0)).map_err(err)?;
    if mode != "delete" {
        return Err(format!("{} stayed in {mode} mode; is botd running?", p.display()));
    }
    drop(c);
    let dir = chat_stores::backups_dir(&place.store);
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    let mut t = at;
    loop {
        let stamp = chrono::DateTime::from_timestamp_millis(t).unwrap_or_default().format("%Y%m%d-%H%M%S");
        let name = format!("chats-{stamp}.sqlite");
        let dest = dir.join(&name);
        if std::fs::symlink_metadata(&dest).is_err() {
            std::fs::hard_link(p, &dest).map_err(io(&dest))?;
            sync_dir(&dir);
            return Ok(name);
        }
        t += 1000;
    }
}

fn sync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|f| f.sync_all());
}

fn remove_sidecars(path: &Path) -> Result<(), String> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut s = path.as_os_str().to_os_string();
        s.push(suffix);
        let p = PathBuf::from(s);
        match std::fs::remove_file(&p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(&p)(e)),
            _ => {}
        }
    }
    Ok(())
}

/// What `restore` was asked to do.
#[derive(Default)]
pub struct Options<'a> {
    pub backup: &'a str,
    pub identities: Vec<age::x25519::Identity>,
    pub replace_unreadable: bool,
    /// With the store missing or not opening, restore even though people kept in it have
    /// no second factor in the backup (ADR 0299).
    pub second_factors_from_backup: bool,
    pub yes: bool,
}

/// What a restore did, or would do.
#[derive(Debug)]
pub struct Restore {
    chosen: Chosen,
    plan: Plan,
    /// The store now, kept as this backup. None: it was missing or unreadable.
    kept: Option<String>,
    done: bool,
}

/// Restores `place`'s store from the backup `o.backup` (only says what it would do
/// without `o.yes`), holding botd's locks, so botd must be stopped. Nothing changes unless
/// every check passes; the work file is deleted when one fails.
pub async fn restore(place: &Place, o: &Options<'_>, at: i64) -> Result<Restore, String> {
    same_user(&[place.db_path.parent().unwrap_or(Path::new("/")), place.folder()], euid())?;
    let _locks = lock(place)?;
    drop_leftovers(place.folder())?;
    let chosen = choose(place, o.backup).await?;
    let now = current(place);
    if let (Current::Unreadable(e), false) = (&now, o.replace_unreadable) {
        return Err(format!("the store now doesn't open: {e}. To replace it anyway, add --replace-unreadable; it is deleted, not kept"));
    }
    let work = fetch(place, &chosen, &o.identities).await?;
    let r = (|| {
        let plan = prepare(place, &work, chosen.at, &now)?;
        if plan.without_factor > 0 && !o.second_factors_from_backup {
            return Err(format!(
                "the store now is missing or doesn't open, so nothing says who set up a second factor since the backup, and {} none in the backup: \
                 restored, anyone who set one up since would sign in without it. Restore a newer backup, or add --second-factors-from-backup and ask them to check theirs in Settings (ADR 0299)",
                people_without(plan.without_factor)
            ));
        }
        if !o.yes {
            std::fs::remove_file(&work).map_err(io(&work))?;
            return Ok(Restore { chosen: chosen.clone(), plan, kept: None, done: false });
        }
        let kept = match &now {
            Current::Readable(k) => Some(keep_current(place, k.as_ref(), at)?),
            _ => None,
        };
        let r = Restore { chosen: chosen.clone(), plan, kept, done: true };
        let mut note = None;
        let swapped = (|| {
            note = Some(write_note(place, &r, &work, at)?);
            remove_sidecars(&place.store.path)?;
            std::fs::rename(&work, &place.store.path).map_err(io(&place.store.path))?;
            sync_dir(place.folder());
            Ok::<_, String>(())
        })();
        if let Err(e) = swapped {
            let _ = note.map(std::fs::remove_file);
            let _ = r.kept.as_ref().map(|k| std::fs::remove_file(chat_stores::backups_dir(&place.store).join(k)));
            return Err(e);
        }
        Ok(r)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&work);
    }
    r
}

/// Leaves a note of the restore `r` for botd to audit, naming the restored file `work`
/// by its inode. Its path.
fn write_note(place: &Place, r: &Restore, work: &Path, at: i64) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let note = json!({
        "storeId": place.store.id,
        "backup": r.chosen.name,
        "from": match &r.chosen.source { Source::Folder(_) => "folder", Source::Bucket(_) => "bucket" },
        "backupAt": r.chosen.at,
        "restoredAt": at,
        "kept": r.kept,
        "replacedUnreadable": r.plan.unreadable.is_some(),
        "held": r.plan.held,
        "dropped": r.plan.dropped,
        "erased": r.plan.erased,
        "signInsReplaced": r.plan.sign_ins_replaced,
        "signedIn": r.plan.signed_in,
        "meterHeldBack": r.plan.meter_held_back,
        "auditDetailsLost": crate::audit_chain::ranges(&r.plan.audit_lost),
        "back": r.plan.back,
        "gone": r.plan.gone,
        "uid": euid(),
        "file": std::fs::metadata(work).map_err(io(work))?.ino(),
    });
    let mut t = at;
    loop {
        let path = place.folder().join(format!("{NOTE}{t}.json"));
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(mut f) => {
                let wrote = f.write_all(note.to_string().as_bytes()).and_then(|_| f.sync_all());
                if let Err(e) = wrote {
                    let _ = std::fs::remove_file(&path);
                    return Err(io(&path)(e));
                }
                sync_dir(place.folder());
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => t += 1,
            Err(e) => return Err(io(&path)(e)),
        }
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid can't fail.
    unsafe { libc::geteuid() }
}

/// Refuses unless `uid` owns each of `dirs` (DATA_DIR and the store's folder): files a
/// restore makes as another user, root included, would keep botd from opening the store.
fn same_user(dirs: &[&Path], uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for d in dirs {
        let owner = std::fs::metadata(d).map_err(io(d))?.uid();
        if owner != uid {
            return Err(format!(
                "{} belongs to uid {owner}, and this runs as uid {uid}. Run it as the user botd runs as, so botd can open what it writes: sudo -u \"$(stat -c %U {})\" botd chat-store ...",
                d.display(),
                d.display()
            ));
        }
    }
    Ok(())
}

impl Restore {
    /// For the terminal.
    pub fn text(&self, region: &str) -> String {
        let p = &self.plan;
        let from = match &self.chosen.source {
            Source::Folder(_) => "in its folder".to_string(),
            Source::Bucket(n) => format!("in its bucket ({n})"),
        };
        let mut out = format!("{} {region}'s chat store from {} {from}, made {}:\n", if self.done { "Restored" } else { "Would restore" }, self.chosen.name, date(self.chosen.at));
        out.push_str(&format!("  It holds {} of the Bots and people kept in {region} now.\n", p.held.describe()));
        if p.dropped.total() > 0 {
            out.push_str(&format!("  Taken out of it: {} of Bots and people kept elsewhere now, or deleted since.\n", p.dropped.describe()));
        }
        if p.erased.total() > 0 {
            out.push_str(&format!("  Erased in it again: {} of people erased since.\n", p.erased.describe()));
        }
        let none_if_empty = |h: &Held| if h.total() > 0 { h.describe() } else { "none".to_string() };
        let (replaced, signed_in) = (p.sign_ins_replaced.sign_ins(), p.signed_in.sign_ins());
        match (replaced.total(), p.back.is_some()) {
            (0, _) => {}
            (_, true) => out.push_str(&format!(
                "  Its sign-ins ({}) are replaced by the store's now ({}), so a session revoked since stays revoked (ADR 0283).\n",
                replaced.describe(),
                none_if_empty(&signed_in)
            )),
            (_, false) => out.push_str(&format!("  Its sign-ins ({}) are dropped, so their people sign in again (ADR 0283).\n", replaced.describe())),
        }
        let secrets = |n: i64| Held { user_secrets: n, ..Held::default() };
        if p.sign_ins_replaced.user_secrets + p.signed_in.user_secrets > 0 {
            out.push_str(&format!(
                "  Its people's own secrets ({}) are replaced by the store's now ({}), so a secret deleted or changed since stays so (ADR 0293).\n",
                none_if_empty(&secrets(p.sign_ins_replaced.user_secrets)),
                none_if_empty(&secrets(p.signed_in.user_secrets))
            ));
        }
        let (replaced, now) = (p.sign_ins_replaced.second_factor(), p.signed_in.second_factor());
        if replaced.total() + now.total() > 0 {
            out.push_str(&format!(
                "  Its people's second factors ({}) are replaced by the store's now ({}), so one turned off or reset since stays so, and a recovery code spent since stays spent (ADR 0299).\n",
                none_if_empty(&replaced),
                none_if_empty(&now)
            ));
        }
        let (replaced, now) = (p.sign_ins_replaced.usage(), p.signed_in.usage());
        if replaced.total() + now.total() > 0 {
            out.push_str(&format!(
                "  Its model usage records ({}) are replaced by the store's now ({}), so none recorded since is lost and none metered since is sent to Stripe again (ADR 0304).\n",
                none_if_empty(&replaced),
                none_if_empty(&now)
            ));
        }
        if p.meter_held_back > 0 {
            out.push_str(&format!(
                "  Model usage records in it still waiting for Stripe's meter: {}. With the store now gone nothing says whether they were sent since, so they are marked failed, not sent again. Check them against Stripe (ADR 0304).\n",
                p.meter_held_back
            ));
        }
        if !p.audit_lost.is_empty() {
            out.push_str(&format!(
                "  Audit events whose details only the store held, and the backup doesn't: {}. Their rows stay in botd's log, sealed; botd names them as erased (audit.erased) when it starts, so the log still verifies (ADR 0316).\n",
                p.audit_lost.len()
            ));
        }
        if p.unopened > 0 {
            out.push_str(&format!("  {} saved tool inputs of approvals in it don't open with the master key; botd drops them at start (SUPERBOT_FORGET_SEALED=1).\n", p.unopened));
        }
        if p.unopened_secrets > 0 {
            out.push_str(&format!(
                "  {} people's own secrets in it don't open with the master key; botd drops them at start and their owners save them again (SUPERBOT_FORGET_SEALED=1).\n",
                p.unopened_secrets
            ));
        }
        if p.without_factor > 0 {
            out.push_str(&format!(
                "  {} no second factor in it, and with the store now gone nothing says who set one up since; ask them to check theirs in Settings (--second-factors-from-backup).\n",
                people_without(p.without_factor)
            ));
        }
        if p.unopened_factors > 0 {
            out.push_str(&format!(
                "  {} people's second factors in it don't open with the master key; botd drops them at start with their recovery codes, and their owners set them up again (SUPERBOT_FORGET_SEALED=1).\n",
                p.unopened_factors
            ));
        }
        match (&p.back, &p.gone, &p.unreadable) {
            (Some(back), Some(gone), _) => {
                out.push_str(&format!("  Against the store now: {} come back, and {} made since the backup go.\n", back.describe(), gone.describe()));
            }
            (_, _, Some(e)) => out.push_str(&format!("  The store now doesn't open ({e}); it {} deleted, not kept.\n", if self.done { "was" } else { "is" })),
            _ => out.push_str("  The store is missing, so nothing in it is lost.\n"),
        }
        if p.back.map_or(p.held.routines, |b| b.routines) > 0 {
            out.push_str("  Routines that come back run on their schedule again once botd starts; check them.\n");
        }
        match (&self.kept, self.done) {
            (Some(k), _) => out.push_str(&format!("  The store as it was is kept as backups/{k}, so this can be undone.\n")),
            (None, false) if p.back.is_some() => out.push_str("  The store as it is would be kept as a backup made now, so this can be undone.\n"),
            _ => {}
        }
        if self.done {
            out.push_str(&format!(
                "Start botd: it audits this as {RESTORED}, moves anything else to where it belongs, and backs the store up and copies it off the host on its first check. Docs: {DOC}\n"
            ));
        } else {
            out.push_str("Nothing was changed. Run it again with --yes to restore.\n");
        }
        out
    }
}

// The command line

#[derive(Debug, Default, PartialEq)]
struct Args<'a> {
    cmd: &'a str,
    region: &'a str,
    backup: &'a str,
    identity: Option<&'a str>,
    replace_unreadable: bool,
    second_factors_from_backup: bool,
    yes: bool,
    home: Option<&'a str>,
    env_file: Option<&'a str>,
}

fn parse<'a>(args: &[&'a str]) -> Result<Args<'a>, String> {
    let mut a = Args::default();
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value\n{USAGE}"));
        match arg {
            "--identity" => a.identity = Some(value()?),
            "--replace-unreadable" => a.replace_unreadable = true,
            "--second-factors-from-backup" => a.second_factors_from_backup = true,
            "--yes" => a.yes = true,
            "--home" => a.home = Some(value()?),
            "--env-file" => a.env_file = Some(value()?),
            o if o.starts_with('-') => return Err(format!("Unknown option {o}\n{USAGE}")),
            p => positional.push(p),
        }
    }
    match positional.as_slice() {
        ["list", region] => (a.cmd, a.region) = ("list", region),
        ["restore", region, backup] => (a.cmd, a.region, a.backup) = ("restore", region, backup),
        _ => return Err(USAGE.to_string()),
    }
    if a.cmd == "list" && (a.identity.is_some() || a.replace_unreadable || a.second_factors_from_backup || a.yes) {
        return Err(format!("list takes only --home or --env-file\n{USAGE}"));
    }
    if a.home.is_some() && a.env_file.is_some() {
        return Err(format!("Use --home or --env-file, not both\n{USAGE}"));
    }
    Ok(a)
}

/// `botd chat-store <list|restore> ...`: prints the result and returns the exit code: 0,
/// 1 when it failed, 2 for a usage error.
pub async fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let a = match parse(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    match run(&a).await {
        Ok(text) => {
            print!("{text}");
            0
        }
        Err(e) => {
            eprintln!("botd chat-store: {e}");
            1
        }
    }
}

async fn run(a: &Args<'_>) -> Result<String, String> {
    let s = Settings::load(a.home, a.env_file)?;
    let place = Place::locate(&s, a.region)?;
    if a.cmd == "list" {
        return list(&place).await;
    }
    let identities = match a.identity {
        Some(f) => super::backup::identities(&std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?)?,
        None => Vec::new(),
    };
    let o = Options { backup: a.backup, identities, replace_unreadable: a.replace_unreadable, second_factors_from_backup: a.second_factors_from_backup, yes: a.yes };
    restore(&place, &o, crate::db::now()).await.map(|r| r.text(&place.region))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{PinOn, Scratch, now};
    use crate::machines::chat_stores::backup_pass;
    use crate::machines::s3_standin::{self, StandIn};
    use crate::secrets::SecretStore;
    use std::collections::BTreeMap;

    const DAY: i64 = 86_400_000;

    struct World {
        t: Scratch,
        lon: PathBuf,
        fra: PathBuf,
        app: PathBuf,
    }

    impl World {
        fn new() -> (World, Db) {
            let t = Scratch::new();
            let (lon, fra, data) = (t.path().join("lon"), t.path().join("fra"), t.path().join("data"));
            for d in [&lon, &fra, &data] {
                std::fs::create_dir_all(d).unwrap();
            }
            let app = data.join("app.sqlite");
            let db = Db::open(&app).unwrap();
            let w = World { t, lon, fra, app };
            db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
            (w, db)
        }

        fn dirs(&self) -> Vec<(String, PathBuf)> {
            vec![("gb-lon".into(), self.lon.clone()), ("de-fra-2".into(), self.fra.clone())]
        }

        fn settings(&self, extra: &[(&str, &str)]) -> Settings {
            let mut p: BTreeMap<String, String> = BTreeMap::new();
            p.insert("DATA_DIR".into(), self.app.parent().unwrap().display().to_string());
            p.insert("REGION_DATA_DIRS".into(), format!("gb-lon={},de-fra-2={}", self.lon.display(), self.fra.display()));
            for (k, v) in extra {
                p.insert(k.to_string(), v.to_string());
            }
            Settings::new(None, Some(self.t.path().join("home")), p)
        }

        /// With the key tests seal approvals under, which the settings don't name.
        fn place(&self) -> Place {
            let mut p = Place::locate(&self.settings(&[]), "gb-lon").unwrap();
            p.ciphers.push(sealed::cipher());
            p
        }

        fn store(&self) -> PathBuf {
            self.lon.join("chats.sqlite")
        }
    }

    fn pinned_bot(db: &Db, name: &str, region: &str) -> (String, String) {
        let u = db.create_user(None, Some(&format!("{name}@example.com")), name, crate::rbac::Role::Member).unwrap().id;
        db.pin_residency(PinOn::User, &u, region, "DPA-1", None).unwrap();
        let bot = db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &u, crate::acl::Visibility::Private).id;
        (u, bot)
    }

    fn holds(p: &Path, w: &str) -> bool {
        let b = std::fs::read(p).unwrap();
        b.windows(w.len()).any(|x| x == w.as_bytes())
    }

    fn texts(store: &Path) -> Vec<String> {
        let c = Connection::open(store).unwrap();
        let mut s = c.prepare("SELECT text FROM messages ORDER BY id").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
    }

    fn opts(backup: &str, yes: bool) -> Options<'_> {
        Options { backup, yes, ..Options::default() }
    }

    /// `opts`, for a store that is gone, whose people have no second factor to keep.
    fn opts_gone(backup: &str, yes: bool) -> Options<'_> {
        Options { second_factors_from_backup: true, ..opts(backup, yes) }
    }

    fn notes(dir: &Path) -> Vec<PathBuf> {
        let mut n: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(NOTE)).collect();
        n.sort();
        n
    }

    fn work_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with(WORK)).collect()
    }

    #[tokio::test]
    async fn a_backup_in_the_folder_comes_back_without_the_chats_of_bots_that_moved_and_the_store_it_replaces_is_kept() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, bobs) = pinned_bot(&db, "bob", "gb-lon");
        db.add_message(&ada, "user", "chat-1a-from-the-backup", None, false, None);
        db.add_message(&bobs, "user", "chat-2b-moved-to-frankfurt", None, false, None);
        let at = now() - DAY;
        backup_pass(&db, 7, at);
        db.add_message(&ada, "user", "chat-3c-after-the-backup", None, false, None);
        db.pin_residency(PinOn::User, &bob, "de-fra-2", "DPA-2", None).unwrap();

        // Bob's chats are still in London: a restore would strand them in a backup.
        let place = w.place();
        let e = restore(&place, &opts("newest", false), now()).await.unwrap_err();
        assert!(e.contains("hasn't moved yet") && e.contains("1 chat message"), "{e}");
        assert!(work_files(&w.lon).is_empty());
        db.place_chats().unwrap();
        drop(db);

        let before = std::fs::read(w.store()).unwrap();
        let r = restore(&place, &opts("newest", false), now()).await.unwrap();
        let text = r.text("gb-lon");
        assert!(!r.done && text.starts_with("Would restore gb-lon's chat store from chats-") && text.contains("Nothing was changed"), "{text}");
        assert_eq!((r.plan.held.messages, r.plan.dropped.messages, r.plan.erased.total()), (1, 1, 0), "{r:?}");
        assert_eq!((r.plan.back.unwrap().total(), r.plan.gone.unwrap().messages), (0, 1), "{r:?}");
        assert!(text.contains("1 chat message made since the backup go"), "{text}");
        assert_eq!(std::fs::read(w.store()).unwrap(), before, "a dry run changes nothing");
        assert!(work_files(&w.lon).is_empty() && notes(&w.lon).is_empty());

        std::fs::write(w.lon.join(format!("{WORK}cut-off.sqlite")), "chat-2b-moved-to-frankfurt").unwrap();
        let link = chat_stores::backups_dir(&place.store).join("chats-20200102-000000.sqlite");
        std::fs::hard_link(w.store(), &link).unwrap();
        let restored_at = now();
        let r = restore(&place, &opts("newest", true), restored_at).await.unwrap();
        assert!(r.done && r.text("gb-lon").starts_with("Restored"), "{}", r.text("gb-lon"));
        assert_eq!(texts(&w.store()), ["chat-1a-from-the-backup"]);
        assert!(!holds(&w.store(), "chat-2b-moved") && !holds(&w.store(), "chat-3c"), "no page of the moved Bot's chat is left in it");
        assert!(work_files(&w.lon).is_empty(), "a cut-off restore's work file is gone");
        assert!(!link.exists(), "and its backup that was still a link to the store");
        let kept = chat_stores::backups_dir(&place.store).join(r.kept.as_deref().unwrap());
        assert!(texts(&kept).contains(&"chat-3c-after-the-backup".to_string()), "the store it replaced is a backup, so this can be undone");
        assert_eq!(chat_stores::backups_strictly(&place.store).unwrap().len(), 2);
        let note: Value = serde_json::from_str(&std::fs::read_to_string(&notes(&w.lon)[0]).unwrap()).unwrap();
        assert_eq!((note["from"].as_str(), note["restoredAt"].as_i64(), note["dropped"]["messages"].as_i64()), (Some("folder"), Some(restored_at), Some(1)), "{note}");

        // Undone before botd starts: the store as it was comes back, and both are noted.
        let undo = restore(&place, &opts(r.kept.as_deref().unwrap(), true), restored_at + 5000).await.unwrap();
        assert_eq!(texts(&w.store()), ["chat-1a-from-the-backup", "chat-3c-after-the-backup"]);
        assert_eq!(undo.plan.back.unwrap().messages, 1);
        // A note of a restore cut off before it replaced the store names no file there.
        std::fs::write(w.lon.join(format!("{NOTE}1.json")), json!({ "backup": "chats-20200101-000000.sqlite", "file": 1 }).to_string()).unwrap();
        // One that can't be read is kept: it may be of a restore that happened.
        let unread = w.lon.join(format!("{NOTE}9.json"));
        std::fs::create_dir(&unread).unwrap();
        assert_eq!(notes(&w.lon).len(), 4);

        // botd's next start audits each once, oldest first, before it touches the store.
        let db = Db::open(&w.app).unwrap();
        let settings = chat_stores::Settings { dirs: w.dirs(), ..chat_stores::Settings::default() };
        let cipher = crate::secrets::sealed::cipher();
        let opened =
            chat_stores::open(&db, &settings, w.app.parent().unwrap(), None, chat_stores::Keys { current: &cipher, previous: None, forget: false, new_derived_keys: false })
                .unwrap();
        let lines: Vec<&String> = opened.lines.iter().filter(|l| l.contains("restore")).collect();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains("was cut off before it replaced the store, so nothing was restored"), "{lines:?}");
        assert!(lines[1].contains("gb-lon's store was restored from chats-") && lines[2].contains(r.kept.as_deref().unwrap()), "{lines:?}");
        assert!(lines[3].contains("couldn't be checked") && lines[3].contains("kept for the next start"), "{lines:?}");
        assert_eq!(notes(&w.lon), [unread.clone()]);
        std::fs::remove_dir(&unread).unwrap();
        assert!(audit_restores(&db, &w.dirs()).is_empty());
        let f = crate::audit::Filter { actions: vec![RESTORED.into()], ..Default::default() };
        let events: Vec<Value> = db.audit_events(&f, 10, true).iter().map(|e| serde_json::to_value(e).unwrap()).collect();
        assert_eq!(events.len(), 2, "the cut-off one isn't audited: {events:?}");
        let d = &events[0]["details"];
        assert_eq!((d["region"].as_str(), d["storeId"].as_str(), d["held"]["messages"].as_i64(), events[0]["actorId"].as_str()), (Some("gb-lon"), Some(place.store.id.as_str()), Some(1), Some(ACTOR)), "{events:?}");
        assert_eq!(events[1]["details"]["backup"].as_str(), r.kept.as_deref());
        assert_eq!(db.chat_store_counts().iter().find(|(s, _)| s.region == "gb-lon").unwrap().1.messages, 2, "botd opens the restored store");
    }

    #[tokio::test]
    async fn erasures_made_since_the_backup_are_run_on_it_again() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, bobs) = pinned_bot(&db, "bob", "gb-lon");
        db.add_routine_by(&ada, "bobs-routine", "0 9 * * *", "chat-4d-bobs-routine", true, Some(&bob));
        db.add_message_from(&ada, "user", "chat-5e-from-bobs-bot", None, false, None, Some(&bobs));
        db.add_message(&ada, "user", "chat-6f-adas-own", None, false, None);
        let approval = db.add_approval(&ada, "claude", "Bash", "tool", "ls", &json!({}), "read", "why", now() + DAY);
        let at = now() + 2000;
        backup_pass(&db, 7, at);
        let backup = chat_stores::backups_strictly(&w.place().store).unwrap()[0].1.clone();
        Connection::open(&backup).unwrap().execute("UPDATE approvals SET decided_by = ?1, note = 'chat-7g-bobs-note' WHERE id = ?2", rusqlite::params![bob, approval.id]).unwrap();

        assert!(db.delete_bot_unless_held(&bobs));
        db.record(&Who::system("t").event("bot.deleted").target("bot", &bobs).details(json!({ "reason": "user_erased" })));
        db.erase_user(&bob, "erased-7f3a", None, std::slice::from_ref(&bobs)).unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!(r.plan.erased, Held { messages: 1, routines: 1, approvals: 1, ..Default::default() }, "{r:?}");
        assert!(r.text("gb-lon").contains("Erased in it again: 1 chat message, 1 routine and 1 approval"), "{}", r.text("gb-lon"));
        assert_eq!(texts(&w.store()), ["[erased]", "chat-6f-adas-own"]);
        let c = Connection::open(w.store()).unwrap();
        let (routines, decided): (i64, String) =
            c.query_row("SELECT (SELECT COUNT(*) FROM routines), (SELECT decided_by FROM approvals)", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((routines, decided.as_str()), (0, "erased-7f3a"));
        for w_ in ["chat-4d", "chat-5e", "chat-7g", &bob] {
            assert!(!holds(&w.store(), w_), "{w_} is gone from every page");
        }
    }

    #[tokio::test]
    async fn bots_erased_after_the_backup_come_from_what_the_erasure_kept_not_pruned_events() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, bobs) = pinned_bot(&db, "bob", "gb-lon");
        let many: Vec<String> = (0..150).map(|i| format!("bot-{i:03}")).chain([bobs.clone()]).collect();
        db.add_message_from(&ada, "user", "chat-8h-from-bobs-bot", None, false, None, Some(&bobs));
        db.add_message(&ada, "user", "chat-9i-adas-own", None, false, None);
        backup_pass(&db, 7, now() - 30 * DAY);
        db.erase_user(&bob, "erased-91b0", None, &many).unwrap();
        db.record(&Who::system("t").event("user.erased").target("user", "erased-91b0").details(json!({ "bots": many.len() })));
        drop(db);
        let before = std::fs::read(w.store()).unwrap();
        let app = Connection::open(&w.app).unwrap();
        let key = format!("{ERASED_BOTS}{bob}");
        let kept: String = app.query_row("SELECT value FROM settings WHERE key = ?1", [&key], |r| r.get(0)).unwrap();
        assert_eq!(serde_json::from_str::<Vec<String>>(&kept).unwrap(), many);

        app.execute("DELETE FROM settings WHERE key = ?1", [&key]).unwrap();
        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("erased-91b0 was erased") && e.contains("earlier botd that didn't keep which Bots") && e.contains("Restore a backup made after"), "{e}");
        assert_eq!(std::fs::read(w.store()).unwrap(), before);
        assert!(work_files(&w.lon).is_empty() && notes(&w.lon).is_empty());

        app.execute("INSERT INTO settings (key, value) VALUES (?1, ?2)", [&key, &kept]).unwrap();
        drop(app);
        restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!(texts(&w.store()), ["[erased]", "chat-9i-adas-own"], "the Bot after the first 100 still counts");
    }

    #[tokio::test]
    async fn a_backup_with_approvals_sealed_under_a_lost_key_is_refused_unless_botd_drops_them() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let lost = db.add_approval(&ada, "claude", "Bash", "tool", "ls", &json!({}), "read", "why", now() + DAY).id;
        db.add_approval(&ada, "claude", "Bash", "tool", "pwd", &json!({}), "read", "why", now() + DAY);
        backup_pass(&db, 7, now() - DAY);
        drop(db);
        let (_, backup) = chat_stores::backups_strictly(&w.place().store).unwrap().pop().unwrap();
        let under_lost_key = Cipher::new(&crate::secrets::key::MasterKey::generate()).seal(&sealed::approval_context(&lost), br#"{"command":"ls"}"#);
        Connection::open(&backup).unwrap().execute("UPDATE approvals SET input = ?1 WHERE id = ?2", rusqlite::params![under_lost_key, lost]).unwrap();
        let before = std::fs::read(w.store()).unwrap();

        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("1 saved tool inputs of approvals in that backup don't open") && e.contains("SUPERBOT_MASTER_KEY_PREVIOUS") && e.contains("SUPERBOT_FORGET_SEALED=1"), "{e}");
        assert_eq!(std::fs::read(w.store()).unwrap(), before);
        assert!(work_files(&w.lon).is_empty() && notes(&w.lon).is_empty());

        let place = Place { forget_sealed: true, ..w.place() };
        let r = restore(&place, &opts("newest", true), now()).await.unwrap();
        assert_eq!(r.plan.unopened, 1);
        assert!(r.text("gb-lon").contains("1 saved tool inputs of approvals in it don't open with the master key; botd drops them at start"), "{}", r.text("gb-lon"));
    }

    #[tokio::test]
    async fn an_age_encrypted_copy_in_the_bucket_comes_back_after_the_volume_is_lost() {
        let (w, db) = World::new();
        let s3 = StandIn::start().await;
        let master = crate::secrets::key::MasterKey::generate();
        let sealed = crate::secrets::sealed::SealedStore::new(crate::secrets::sealed::connect(&w.app).unwrap(), std::sync::Arc::new(crate::secrets::sealed::Cipher::new(&master)));
        sealed.put("REGION_DATA_S3_GB_LON_SECRET_ACCESS_KEY", s3_standin::SECRET).unwrap();
        drop(sealed);
        let id = age::x25519::Identity::generate();
        let (public, key) = (id.to_public().to_string(), master.base64());
        let s = w.settings(&[
            ("SUPERBOT_MASTER_KEY", key.as_str()),
            ("REGION_DATA_S3_GB_LON_BUCKET", s3_standin::BUCKET),
            ("REGION_DATA_S3_GB_LON_ENDPOINT", s3.url.as_str()),
            ("REGION_DATA_S3_GB_LON_ACCESS_KEY_ID", s3_standin::ACCESS_KEY),
            ("REGION_DATA_AGE_RECIPIENTS", public.as_str()),
            ("REGION_DATA_S3_DE_FRA_2_BUCKET", "fra-chats-with-no-endpoint"),
        ]);
        let place = Place::locate(&s, "gb-lon").unwrap();
        assert!(Place::locate(&s, "de-fra-2").unwrap().copies().err().unwrap().contains("ENDPOINT"), "Frankfurt's broken bucket is Frankfurt's alone");
        // Mid-rotation, the bucket's saved key is still sealed under the previous master key.
        let next = crate::secrets::key::MasterKey::generate().base64();
        let rotated = |previous: &[(&str, &str)]| {
            let mut vars: Vec<(String, String)> = s.vars().into_iter().filter(|(k, _)| k.starts_with("REGION_DATA") || k == "DATA_DIR").collect();
            vars.push(("SUPERBOT_MASTER_KEY".into(), next.to_string()));
            vars.extend(previous.iter().map(|(k, v)| (k.to_string(), v.to_string())));
            Settings::new(None, Some(w.t.path().join("home")), vars.into_iter().collect())
        };
        assert!(Place::locate(&rotated(&[]), "gb-lon").unwrap().copies().is_err(), "the new key alone doesn't open it");
        assert!(Place::locate(&rotated(&[("SUPERBOT_MASTER_KEY_PREVIOUS", key.as_str())]), "gb-lon").unwrap().copies().unwrap().is_some());
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        db.add_message(&ada, "user", "chat-9i-off-the-host", None, false, None);
        db.add_routine_by(&ada, "daily", "0 9 * * *", "chat-9i-daily", true, None);
        backup_pass(&db, 7, now() - DAY);
        let copies = place.copies().unwrap().expect("the bucket, its secret key from botd's saved secrets");
        assert_eq!(copies.pass(&db, now()).await["gb-lon"].as_ref().map(|c| c.uploaded), Ok(1));
        drop(db);

        // The volume is lost: a new, empty one is mounted at the folder.
        std::fs::remove_dir_all(&w.lon).unwrap();
        std::fs::create_dir_all(&w.lon).unwrap();
        let listed = list(&place).await.unwrap();
        assert!(listed.contains("chats.sqlite: missing") && listed.contains("Copies in") && listed.contains(".sqlite.age"), "{listed}");
        assert!(!listed.contains(s3_standin::SECRET));

        let e = restore(&place, &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("--identity"), "{e}");
        let wrong = Options { identities: vec![age::x25519::Identity::generate()], ..opts("newest", true) };
        let e = restore(&place, &wrong, now()).await.unwrap_err();
        assert!(e.contains("doesn't open this copy"), "{e}");
        assert!(!w.store().exists() && work_files(&w.lon).is_empty(), "nothing changed, nothing left");

        let right = Options { identities: vec![id], second_factors_from_backup: true, ..opts("newest", true) };
        let r = restore(&place, &right, now()).await.unwrap();
        assert!(matches!(r.chosen.source, Source::Bucket(_)) && r.kept.is_none(), "{r:?}");
        let text = r.text("gb-lon");
        assert!(text.contains("The store is missing, so nothing in it is lost") && text.contains("Routines that come back run on their schedule"), "{text}");
        assert_eq!(texts(&w.store()), ["chat-9i-off-the-host"]);
        assert!(work_files(&w.lon).is_empty());
    }

    #[tokio::test]
    async fn a_restore_is_refused_while_botd_runs_or_when_the_backup_isnt_this_store() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (_, fritz) = pinned_bot(&db, "fritz", "de-fra-2");
        db.add_message(&ada, "user", "chat-10j", None, false, None);
        db.add_message(&fritz, "user", "chat-11k", None, false, None);
        backup_pass(&db, 7, now() - DAY);
        drop(db);
        let place = w.place();

        let lock = database_encryption::lock_data_dir(&w.store()).unwrap();
        let e = restore(&place, &opts("newest", false), now()).await.unwrap_err();
        assert!(e.contains("botd must be stopped"), "{e}");
        drop(lock);

        // Frankfurt's backup, put among London's.
        let fra = chat_stores::backups_strictly(&Place::locate(&w.settings(&[]), "de-fra-2").unwrap().store).unwrap()[0].1.clone();
        let name = "chats-20200101-000000.sqlite";
        std::fs::copy(&fra, chat_stores::backups_dir(&place.store).join(name)).unwrap();
        let e = restore(&place, &opts(name, true), now()).await.unwrap_err();
        assert!(e.contains("de-fra-2's chat store, not gb-lon's"), "{e}");
        std::fs::write(chat_stores::backups_dir(&place.store).join(name), b"not a database at all, just some bytes").unwrap();
        assert!(restore(&place, &opts(name, true), now()).await.is_err());
        assert!(restore(&place, &opts("chats-20200102-000000.sqlite", true), now()).await.unwrap_err().contains("isn't in"));
        assert!(restore(&place, &opts("../app.sqlite", true), now()).await.unwrap_err().contains("isn't a backup's name"));
        assert!(work_files(&w.lon).is_empty());

        // A store that doesn't open is replaced only when asked.
        std::fs::write(w.store(), vec![7u8; 8192]).unwrap();
        let e = restore(&place, &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("--replace-unreadable"), "{e}");
        let o = Options { replace_unreadable: true, second_factors_from_backup: true, ..opts("newest", true) };
        let r = restore(&place, &o, now()).await.unwrap();
        assert!(r.plan.unreadable.is_some() && r.kept.is_none() && r.text("gb-lon").contains("was deleted, not kept"), "{r:?}");
        assert_eq!(texts(&w.store()), ["chat-10j"]);

        let e = Place::locate(&w.settings(&[]), "us-east").err().unwrap();
        assert!(e.contains("doesn't name us-east (it names gb-lon, de-fra-2)"), "{e}");
        std::fs::remove_dir_all(&w.fra).unwrap();
        assert!(Place::locate(&w.settings(&[]), "de-fra-2").err().unwrap().contains("Mount the region's volume"));
        let unrecorded = Scratch::new();
        let mut s = w.settings(&[("REGION_DATA_DIRS", &format!("gb-lon={}", unrecorded.path().display()))]);
        s = Settings::new(None, None, s.vars().into_iter().map(|(k, v)| if k == "DATA_DIR" { (k, unrecorded.path().join("data").display().to_string()) } else { (k, v) }).collect());
        assert!(Place::locate(&s, "gb-lon").err().unwrap().contains("no botd database"));
    }

    #[test]
    fn a_store_moved_while_botd_ran_is_found_only_once_the_settings_name_its_new_folder() {
        let (w, db) = World::new();
        let lon2 = w.t.path().join("lon-2");
        std::fs::create_dir_all(&lon2).unwrap();
        db.move_chat_store("gb-lon", &lon2.join("chats.sqlite"), None, None).unwrap();
        drop(db);
        crate::db::remove_store_files(&w.store());
        let e = Place::locate(&w.settings(&[]), "gb-lon").err().unwrap();
        assert!(e.contains(&format!("was moved to {} while botd ran", lon2.display())) && e.contains("ADR 0309"), "{e}");
        let s = w.settings(&[("REGION_DATA_DIRS", &format!("gb-lon={},de-fra-2={}", lon2.display(), w.fra.display()))]);
        assert_eq!(Place::locate(&s, "gb-lon").unwrap().store.path, lon2.join("chats.sqlite"));
    }

    #[tokio::test]
    async fn a_backup_from_before_routines_and_approvals_were_in_the_store_is_brought_up_to_date() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        db.add_message(&ada, "user", "chat-12l-older-botd", None, false, None);
        db.add_routine_by(&ada, "daily", "0 9 * * *", "chat-13m-newer", true, None);
        db.set_memory(&ada, "memory-14n-newer").unwrap();
        let at = now() + 2000;
        backup_pass(&db, 7, at);
        let backup = chat_stores::backups_strictly(&w.place().store).unwrap()[0].1.clone();
        Connection::open(&backup).unwrap().execute_batch("DROP TABLE routines; DROP TABLE approvals; DROP TABLE memories; ALTER TABLE messages DROP COLUMN from_bot; VACUUM").unwrap();
        db.erase_user(&bob, "erased-c41d", None, &[]).unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        let gone = r.plan.gone.unwrap();
        assert_eq!((r.plan.held.messages, gone.routines, gone.memories), (1, 1, 1), "{r:?}");
        let c = Connection::open(w.store()).unwrap();
        let n: i64 = c
            .query_row("SELECT (SELECT COUNT(*) FROM routines) + (SELECT COUNT(*) FROM approvals) + (SELECT COUNT(*) FROM memories) + (SELECT COUNT(from_bot) FROM messages)", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "the tables and columns botd keeps now, empty");
        assert_eq!(texts(&w.store()), ["chat-12l-older-botd"]);
    }

    #[tokio::test]
    async fn a_restored_backup_keeps_bots_memory_only_for_bots_still_kept_in_the_store() {
        let (w, db) = World::new();
        let (_, ada) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, bobs) = pinned_bot(&db, "bob", "gb-lon");
        db.set_memory(&ada, "memory-15p-adas").unwrap();
        db.set_memory(&bobs, "memory-16q-moved-to-frankfurt").unwrap();
        backup_pass(&db, 7, now() - DAY);
        db.set_memory(&ada, "memory-17r-after-the-backup").unwrap();
        db.pin_residency(PinOn::User, &bob, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.memories, r.plan.dropped.memories), (1, 1), "{r:?}");
        assert!(holds(&w.store(), "memory-15p-adas") && !holds(&w.store(), "memory-16q-moved") && !holds(&w.store(), "memory-17r"), "no page of the moved Bot's memory is left in it");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!((db.memory(&ada).as_deref(), db.memory(&bobs).as_deref()), (Some("memory-15p-adas"), Some("memory-16q-moved-to-frankfurt")));
    }

    #[tokio::test]
    async fn a_restored_backup_keeps_facts_only_of_people_still_kept_in_the_store_and_none_of_the_erased() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        let (cy, _) = pinned_bot(&db, "cy", "gb-lon");
        db.set_facts(&ada, "facts-21a-adas").unwrap();
        db.set_facts(&bob, "facts-22b-moved-to-frankfurt").unwrap();
        db.set_facts(&cy, "facts-23c-erased-since").unwrap();
        backup_pass(&db, 7, now() - DAY);
        db.set_facts(&ada, "facts-24d-after-the-backup").unwrap();
        db.pin_residency(PinOn::User, &bob, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        db.delete_facts(&cy).unwrap();
        db.erase_user(&cy, "erased-f00d", None, &[]).unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.facts, r.plan.dropped.facts, r.plan.erased.facts), (1, 1, 1), "{r:?}");
        for gone in ["facts-22b", "facts-23c", "facts-24d"] {
            assert!(!holds(&w.store(), gone), "no page of {gone} is left in it");
        }
        assert!(holds(&w.store(), "facts-21a-adas"));
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!((db.facts(&ada).as_deref(), db.facts(&bob).as_deref(), db.facts(&cy)), (Some("facts-21a-adas"), Some("facts-22b-moved-to-frankfurt"), None));
    }

    fn signed_in(db: &Db, user: &str, ua: &str) -> String {
        let s = crate::db::NewSession {
            user_id: user,
            token_hash: ua,
            kind: "cookie",
            method: "password",
            idp_subject: None,
            idp_provider: None,
            label: None,
            ip: None,
            user_agent: Some(ua),
            expires_at: now() + 30 * DAY,
            mfa: None,
        };
        db.create_session(&s).id
    }

    #[tokio::test]
    async fn a_restored_backup_takes_its_sign_ins_from_the_store_it_replaces_so_a_revoked_session_stays_revoked() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        let old = signed_in(&db, &ada, "ua-31a-revoked-since");
        let bobs = signed_in(&db, &bob, "ua-33c-moved-to-frankfurt");
        backup_pass(&db, 7, now() - DAY);
        assert!(db.revoke_session(&old, "ada", "signed_out"));
        let new = signed_in(&db, &ada, "ua-32b-made-since");
        db.pin_residency(PinOn::User, &bob, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.dropped.sessions, r.plan.sign_ins_replaced.sessions, r.plan.signed_in.sessions), (1, 1, 2), "{r:?}");
        assert_eq!((r.plan.back.unwrap().sessions, r.plan.gone.unwrap().sessions), (0, 0), "nobody is signed out or back in: {r:?}");
        let text = r.text("gb-lon");
        assert!(text.contains("Its sign-ins (1 sign-in session) are replaced by the store's now (2 sign-in sessions), so a session revoked since stays revoked"), "{text}");
        assert!(!holds(&w.store(), "ua-33c"), "no page of a session kept elsewhere now is left in it");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert!(db.session(&old).unwrap().revoked_at.is_some(), "a session revoked after the backup doesn't work again");
        assert!(db.session(&new).unwrap().revoked_at.is_none(), "one made since still works");
        assert!(db.session(&bobs).is_some());
        backup_pass(&db, 8, now());
        drop(db);

        // With the store gone, the backup's own sign-ins are dropped rather than trusted.
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }
        let r = restore(&w.place(), &opts_gone("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.sign_ins_replaced.sessions, r.plan.signed_in.total()), (2, 0), "{r:?}");
        assert!(r.text("gb-lon").contains("Its sign-ins (2 sign-in sessions) are dropped, so their people sign in again"), "{}", r.text("gb-lon"));
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert!(db.session(&old).is_none() && db.session(&new).is_none());
    }

    fn own_secrets(w: &World, db: &Db) -> sealed::UserSecrets {
        let s = sealed::UserSecrets::new(sealed::connect(&w.app).unwrap(), sealed::cipher());
        s.attach_stores(&db.chat_stores(), None).unwrap();
        s
    }

    #[tokio::test]
    async fn a_restored_backup_takes_its_own_secrets_from_the_store_it_replaces_or_keeps_them_when_it_is_gone() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        let s = own_secrets(&w, &db);
        s.put(&ada, "A", "deleted-since").unwrap();
        s.put(&ada, "B", "old-value").unwrap();
        s.put(&bob, "C", "moved-to-frankfurt").unwrap();
        backup_pass(&db, 7, now() - DAY);
        assert!(s.delete(&ada, "A").unwrap());
        s.put(&ada, "B", "new-value").unwrap();
        db.pin_residency(PinOn::User, &bob, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        drop((s, db));

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.user_secrets, r.plan.dropped.user_secrets), (1, 1), "what it holds once replaced: {r:?}");
        assert_eq!((r.plan.sign_ins_replaced.user_secrets, r.plan.signed_in.user_secrets), (2, 1), "{r:?}");
        let text = r.text("gb-lon");
        assert!(text.contains("Its people's own secrets (2 personal secrets) are replaced by the store's now (1 personal secret), so a secret deleted or changed since stays so"), "{text}");
        assert!(!text.contains("Its sign-ins"), "it had no sign-ins: {text}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        let s = own_secrets(&w, &db);
        let get = |u: &str, n: &str| s.get(u, n).unwrap().map(|v| v.expose().to_string());
        assert_eq!((get(&ada, "A"), get(&ada, "B").as_deref(), get(&bob, "C").as_deref()), (None, Some("new-value"), Some("moved-to-frankfurt")));
        backup_pass(&db, 8, now());
        drop((s, db));

        // With the store gone, the backup's are the only copy left, so they are kept.
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }
        let r = restore(&w.place(), &opts_gone("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.user_secrets, r.plan.sign_ins_replaced.user_secrets, r.plan.signed_in.user_secrets), (1, 0, 0), "{r:?}");
        assert!(!r.text("gb-lon").contains("own secrets"), "{}", r.text("gb-lon"));
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        let s = own_secrets(&w, &db);
        assert_eq!(s.get(&ada, "B").unwrap().map(|v| v.expose().to_string()).as_deref(), Some("new-value"));
    }

    #[tokio::test]
    async fn a_backup_keeping_own_secrets_sealed_under_a_lost_key_is_refused_unless_botd_drops_them() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let s = own_secrets(&w, &db);
        s.put(&ada, "K", "v").unwrap();
        backup_pass(&db, 7, now() - DAY);
        drop((s, db));
        let (_, backup) = chat_stores::backups_strictly(&w.place().store).unwrap().pop().unwrap();
        let under_lost_key = Cipher::new(&crate::secrets::key::MasterKey::generate()).seal(&sealed::user_context(&ada, "K"), b"v");
        Connection::open(&backup).unwrap().execute("UPDATE user_secrets SET value = ?1", [under_lost_key]).unwrap();
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }

        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("1 people's own secrets in that backup don't open") && e.contains("SUPERBOT_MASTER_KEY_PREVIOUS") && e.contains("SUPERBOT_FORGET_SEALED=1"), "{e}");
        assert!(!w.store().exists() && work_files(&w.lon).is_empty() && notes(&w.lon).is_empty());

        let place = Place { forget_sealed: true, ..w.place() };
        let r = restore(&place, &opts_gone("newest", true), now()).await.unwrap();
        assert_eq!(r.plan.unopened_secrets, 1);
        assert!(r.text("gb-lon").contains("1 people's own secrets in it don't open with the master key; botd drops them at start"), "{}", r.text("gb-lon"));
    }

    fn used(db: &Db, user: &str, bot: &str, run: &str) {
        let row = crate::db::TokenRow {
            user_id: user.into(),
            bot_id: bot.into(),
            run_id: run.into(),
            message_id: None,
            harness: "claude".into(),
            model: None,
            reported: true,
            input: 10,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            at: now(),
            meter: Some("cus_0304".into()),
        };
        db.record_tokens(&[row]).unwrap();
    }

    fn waiting(db: &Db) -> Vec<String> {
        db.pending_meter(10).into_iter().map(|m| m.run_id).collect()
    }

    #[tokio::test]
    async fn a_restored_backup_takes_its_usage_records_from_the_store_it_replaces_or_holds_its_unsent_ones_back() {
        let (w, db) = World::new();
        let (ada, adas) = pinned_bot(&db, "ada", "gb-lon");
        used(&db, &ada, &adas, "run-sent-since");
        backup_pass(&db, 7, now() - DAY);
        let sent = db.pending_meter(10)[0].id;
        db.meter_result(sent, Some("sent"));
        used(&db, &ada, &adas, "run-made-since");
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.sign_ins_replaced.usage_records, r.plan.signed_in.usage_records, r.plan.meter_held_back), (1, 2, 0), "{r:?}");
        let text = r.text("gb-lon");
        assert!(
            text.contains("Its model usage records (1 model usage record) are replaced by the store's now (2 model usage records), so none recorded since is lost and none metered since is sent to Stripe again"),
            "{text}"
        );
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!(db.tokens_used(&ada, 0, i64::MAX), 20, "one recorded since is kept");
        assert_eq!(waiting(&db), ["run-made-since"], "one metered since isn't sent again");
        backup_pass(&db, 8, now());
        drop(db);

        // With the store gone, the backup's are the only copy left: kept, but one still waiting
        // may have been sent since, so it is held back from the meter rather than sent twice.
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }
        let r = restore(&w.place(), &opts_gone("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.sign_ins_replaced.usage_records, r.plan.signed_in.usage_records, r.plan.meter_held_back), (0, 0, 1), "{r:?}");
        let text = r.text("gb-lon");
        assert!(!text.contains("Its model usage records") && text.contains("Model usage records in it still waiting for Stripe's meter: 1."), "{text}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!(db.tokens_used(&ada, 0, i64::MAX), 20);
        assert!(waiting(&db).is_empty());
    }

    /// An event `user` made from `ip`, about `about` if given.
    fn acted(db: &Db, user: &str, ip: &str, about: Option<&str>) -> i64 {
        let actor = crate::audit::Actor { kind: crate::audit::ActorKind::User, id: Some(user.into()), ..Default::default() };
        let e = Who { actor, source: crate::audit::Source { ip: Some(ip.into()), user_agent: None } }.event("bot.updated");
        db.try_record(&about.map_or(e.clone(), |p| e.target("user", p))).unwrap()
    }

    fn ip_of(db: &Db, id: i64) -> Option<String> {
        db.audit_events(&crate::audit::Filter::default(), 1000, true).into_iter().find(|e| e.id == id).unwrap().ip
    }

    #[tokio::test]
    async fn a_restored_backup_takes_audit_details_from_the_store_it_replaces_or_names_those_lost_with_it() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        let (cy, _) = pinned_bot(&db, "cy", "gb-lon");
        let first = acted(&db, &ada, "192.0.2.71", None);
        let about_bob = acted(&db, &cy, "192.0.2.72", Some(&bob));
        backup_pass(&db, 7, now() - DAY);
        let name = chat_stores::backups_strictly(&w.place().store).unwrap()[0].1.file_name().unwrap().to_string_lossy().into_owned();
        let since = acted(&db, &ada, "192.0.2.73", None);
        db.erase_user(&bob, "erased-0316", None, &[]).unwrap();
        db.place_chats().unwrap();
        drop(db);

        // With the store there, its details replace the backup's: none made since is lost, none rewritten comes back.
        let r = restore(&w.place(), &opts(&name, true), now()).await.unwrap();
        assert_eq!((r.plan.sign_ins_replaced.audit_events, r.plan.signed_in.audit_events, r.plan.audit_lost.len()), (2, 3, 0), "{r:?}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!(ip_of(&db, since).as_deref(), Some("192.0.2.73"));
        assert!(crate::audit_chain::verify(&db, vec![]).ok);
        drop(db);

        // With it gone, the backup's are the only copy, but not one an erasure since rewrote; the rest are named lost.
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }
        let r = restore(&w.place(), &opts_gone(&name, true), now()).await.unwrap();
        assert_eq!((r.plan.erased.audit_events, r.plan.audit_lost.clone()), (1, vec![about_bob, since]), "{r:?}");
        let text = r.text("gb-lon");
        assert!(text.contains("Audit events whose details only the store held, and the backup doesn't: 2.") && text.contains("1 audit event's details of people erased since"), "{text}");
        assert!(!holds(&w.store(), &bob), "the erased person's id is gone from every page");
        let db = Db::open(&w.app).unwrap();
        assert!(audit_restores(&db, &w.dirs()).iter().all(|l| !l.contains("couldn't")));
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!((ip_of(&db, first).as_deref(), ip_of(&db, since)), (Some("192.0.2.71"), None));
        let f = crate::audit::Filter { actions: vec![RESTORED.into()], ..Default::default() };
        let restored = db.audit_events(&f, 10, true);
        assert_eq!(restored.last().unwrap().details["auditDetailsLost"], 2);
        let r = crate::audit_chain::verify(&db, vec![]);
        assert!(r.ok, "the lost ones are named: {r:?}");
    }

    #[tokio::test]
    async fn a_restore_waits_for_audit_details_of_someone_unpinned_to_go_home_first() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let id = acted(&db, &ada, "192.0.2.75", None);
        backup_pass(&db, 7, now() - DAY);
        let name = chat_stores::backups_strictly(&w.place().store).unwrap()[0].1.file_name().unwrap().to_string_lossy().into_owned();
        db.unpin_residency(PinOn::User, &ada).unwrap();
        drop(db);
        let refused = restore(&w.place(), &opts(&name, true), now()).await.unwrap_err();
        assert!(refused.contains("1 audit event's details of Bots or people kept elsewhere now"), "{refused}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        db.place_chats().unwrap();
        drop(db);
        let r = restore(&w.place(), &opts(&name, true), now()).await.unwrap();
        assert_eq!(r.plan.audit_lost.len(), 0, "{r:?}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert_eq!(ip_of(&db, id).as_deref(), Some("192.0.2.75"), "home in botd's log");
        let r = crate::audit_chain::verify(&db, vec![]);
        assert!(r.ok && r.erased == 0, "{r:?}");
    }

    fn factor(user: &str, secret: &str) -> String {
        sealed::cipher().seal(&sealed::mfa_context(user), secret.as_bytes())
    }

    fn hashes(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn a_restored_backup_takes_its_second_factors_from_the_store_it_replaces_or_keeps_them_when_it_is_gone() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (bob, _) = pinned_bot(&db, "bob", "gb-lon");
        let (cy, _) = pinned_bot(&db, "cy", "gb-lon");
        assert!(db.mfa_enable(&ada, &factor(&ada, "totp-ada"), 1, &hashes(&["a1", "a2"])));
        assert!(db.mfa_enable(&bob, &factor(&bob, "totp-bob-reset-since"), 1, &hashes(&["b1"])));
        assert!(db.mfa_enable(&cy, &factor(&cy, "totp-cy-moved"), 1, &[]));
        backup_pass(&db, 7, now() - DAY);
        assert!(db.mfa_use_recovery(&ada, "a1"));
        assert!(db.mfa_delete(&bob));
        db.pin_residency(PinOn::User, &cy, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        drop(db);

        let r = restore(&w.place(), &opts("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.second_factors, r.plan.held.recovery_codes), (1, 2), "what it holds once replaced: {r:?}");
        assert_eq!((r.plan.sign_ins_replaced.second_factors, r.plan.sign_ins_replaced.recovery_codes), (2, 3), "{r:?}");
        assert_eq!((r.plan.signed_in.second_factors, r.plan.signed_in.recovery_codes), (1, 2), "a spent code is kept as spent: {r:?}");
        let text = r.text("gb-lon");
        assert!(
            text.contains("Its people's second factors (2 second factors and 3 recovery codes) are replaced by the store's now (1 second factor and 2 recovery codes), so one turned off or reset since stays so"),
            "{text}"
        );
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert!(!db.mfa_use_recovery(&ada, "a1"), "a code spent since stays spent");
        assert_eq!(db.mfa_recovery_left(&ada), 1);
        assert!(db.mfa(&bob).is_none(), "a second factor turned off since stays off");
        assert!(db.mfa(&cy).is_some(), "one moved since is where it was moved");
        backup_pass(&db, 8, now());
        drop(db);

        // With the store gone, the backup's are the only copy left, so they are kept. But
        // nothing says whether bob, with none in it, set one up since, so that needs saying.
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }
        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("1 person kept in it has none in the backup") && e.contains("--second-factors-from-backup"), "{e}");
        assert!(!w.store().exists() && work_files(&w.lon).is_empty(), "nothing changed");
        let r = restore(&w.place(), &opts_gone("newest", true), now()).await.unwrap();
        assert_eq!((r.plan.held.second_factors, r.plan.sign_ins_replaced.second_factors, r.plan.signed_in.second_factors, r.plan.without_factor), (1, 0, 0, 1), "{r:?}");
        let text = r.text("gb-lon");
        assert!(!text.contains("Its people's second factors") && text.contains("1 person kept in it has no second factor in it"), "{text}");
        let db = Db::open(&w.app).unwrap();
        db.attach_chat_stores(&w.dirs(), &[], None).unwrap();
        assert!(db.mfa(&ada).is_some() && db.mfa_recovery_left(&ada) == 1);
    }

    #[tokio::test]
    async fn a_backup_from_before_second_factors_were_kept_is_refused_with_the_store_gone() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        backup_pass(&db, 7, now() - DAY);
        assert!(db.mfa_enable(&ada, &factor(&ada, "totp"), 1, &hashes(&["a1"])));
        drop(db);
        let (_, backup) = chat_stores::backups_strictly(&w.place().store).unwrap().pop().unwrap();
        Connection::open(&backup).unwrap().execute_batch("DROP TABLE mfa_recovery_codes; DROP TABLE user_mfa;").unwrap();
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }

        // Her second factor was only in the store; restored as it is, she'd sign in without one.
        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("1 person kept in it has none in the backup"), "{e}");
        assert!(!w.store().exists());
    }

    #[tokio::test]
    async fn a_backup_keeping_second_factors_sealed_under_a_lost_key_is_refused_unless_botd_drops_them() {
        let (w, db) = World::new();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        assert!(db.mfa_enable(&ada, &factor(&ada, "totp"), 1, &hashes(&["a1"])));
        backup_pass(&db, 7, now() - DAY);
        drop(db);
        let (_, backup) = chat_stores::backups_strictly(&w.place().store).unwrap().pop().unwrap();
        let under_lost_key = Cipher::new(&crate::secrets::key::MasterKey::generate()).seal(&sealed::mfa_context(&ada), b"totp");
        Connection::open(&backup).unwrap().execute("UPDATE user_mfa SET secret = ?1", [under_lost_key]).unwrap();
        for f in ["chats.sqlite", "chats.sqlite-wal", "chats.sqlite-shm"] {
            let _ = std::fs::remove_file(w.lon.join(f));
        }

        let e = restore(&w.place(), &opts("newest", true), now()).await.unwrap_err();
        assert!(e.contains("1 people's second factors in that backup don't open") && e.contains("SUPERBOT_MASTER_KEY_PREVIOUS") && e.contains("SUPERBOT_FORGET_SEALED=1"), "{e}");
        assert!(!w.store().exists() && work_files(&w.lon).is_empty() && notes(&w.lon).is_empty());

        let place = Place { forget_sealed: true, ..w.place() };
        let r = restore(&place, &opts("newest", true), now()).await.unwrap();
        assert_eq!(r.plan.unopened_factors, 1);
        assert!(r.text("gb-lon").contains("1 people's second factors in it don't open with the master key; botd drops them at start"), "{}", r.text("gb-lon"));
    }

    #[test]
    fn only_the_user_botd_runs_as_restores() {
        let t = Scratch::new();
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata(t.path()).unwrap().uid();
        assert!(same_user(&[t.path()], me).is_ok());
        let e = same_user(&[t.path()], me + 1).unwrap_err();
        assert!(e.contains(&format!("belongs to uid {me}")) && e.contains("sudo -u"));
    }

    #[test]
    fn the_command_line_is_parsed_strictly() {
        let p = parse;
        assert_eq!(p(&["list", "gb-lon"]).unwrap(), Args { cmd: "list", region: "gb-lon", ..Args::default() });
        let a = p(&["restore", "gb-lon", "newest", "--identity", "/k", "--yes", "--home", "/h"]).unwrap();
        assert_eq!((a.backup, a.identity, a.yes, a.home, a.replace_unreadable, a.second_factors_from_backup), ("newest", Some("/k"), true, Some("/h"), false, false));
        assert!(p(&["restore", "gb-lon", "newest", "--second-factors-from-backup"]).unwrap().second_factors_from_backup);
        for bad in [&["restore", "gb-lon"][..], &["list"], &["list", "gb-lon", "--yes"], &["list", "gb-lon", "--second-factors-from-backup"], &["restore", "a", "b", "--home", "x", "--env-file", "y"], &["restore", "a", "b", "--force"], &["restore", "a", "b", "--identity"]] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        assert!(p(&[]).unwrap_err().starts_with("Usage: botd chat-store"));
        let sha = "a".repeat(64);
        assert_eq!(copy_name(&format!("chats-20261101-030000-{sha}.sqlite")).map(|c| (c.backup, c.encrypted)), Some(("chats-20261101-030000.sqlite".into(), false)));
        assert!(copy_name(&format!("chats-20261101-030000-{sha}.0123456789abcdef.sqlite.age")).is_some_and(|c| c.encrypted && c.sha == sha));
        for bad in ["chats-20261101-030000.sqlite".to_string(), format!("chats-20261101-030000-{}.sqlite", "A".repeat(64)), format!("../chats-20261101-030000-{sha}.sqlite"), format!("chats-20261101-030000-{sha}.short.sqlite.age")] {
            assert!(copy_name(&bad).is_none(), "{bad}");
        }
    }
}
