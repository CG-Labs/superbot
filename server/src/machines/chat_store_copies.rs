//! Off-host copies of regional chat stores' backups (ADR 0246). Each store's daily
//! backups (ADR 0215) are on the same volume as the store, so losing that volume loses
//! both. With `REGION_DATA_S3_<REGION>_BUCKET` and its endpoint and keys, botd keeps a copy
//! of every backup in `<folder>/backups/` in that bucket, which the operator states is in
//! the region, as for machine backups' region stores (ADR 0117). Never to a bucket set for
//! another region or none.
//!
//! The bucket mirrors the folder: each backup is one object whose key carries the SHA-256
//! of the file, so a backup rewritten without the rows of Bots that left the store (ADR
//! 0238) is a new object, and objects no backup in the folder matches (pruned, or rewritten)
//! are deleted, every version of them in a bucket that keeps versions. A move out of a store
//! is recorded as cleared only once its copies match its rewritten backups, so reports
//! list the earlier copies until the bucket no longer holds them either.

use super::backup;
use super::chat_stores;
use super::s3::{self, S3};
use crate::audit::{Outcome, Who, clip};
use crate::db::{ChatStore, Db};
use crate::obs::log::{log_info, log_warn};
use crate::secrets::SecretStore;
use aws_lc_rs::digest;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The settings' names start with this.
pub const NAME: &str = "REGION_DATA_S3";
const RECIPIENTS: &str = "REGION_DATA_AGE_RECIPIENTS";
pub const COPIED: &str = "residency.chat_store_backups_copied";
pub const FORGOTTEN: &str = "residency.chat_store_copies_forgotten";
const FORGET: &str = "REGION_DATA_S3_FORGET";
const ACTOR: &str = "residency";

/// The settings' names for region `region`'s bucket: `REGION_DATA_S3_GB_LON`.
pub fn store_name(region: &str) -> String {
    format!("{NAME}_{}", region.to_ascii_uppercase().replace('-', "_"))
}

/// The regions `keys` (setting names) give a bucket: REGION_DATA_S3_<REGION>_BUCKET, back
/// to the region's id.
pub fn named(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = keys
        .into_iter()
        .filter_map(|k| {
            let r = k.strip_prefix(&format!("{NAME}_"))?.strip_suffix("_BUCKET")?.to_string();
            let ok = !r.is_empty() && !r.starts_with('_') && !r.ends_with('_') && r.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            ok.then(|| r.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Each region's bucket, the key prefix, and who can read the copies.
#[derive(Debug)]
pub struct Settings {
    pub stores: Vec<(String, s3::Settings)>,
    /// Starts every key, ending in `/` unless empty.
    pub prefix: String,
    pub recipients: Vec<age::x25519::Recipient>,
}

impl Settings {
    /// `REGION_DATA_S3_<REGION>_BUCKET`, `_ENDPOINT`, `_REGION` (us-east-1) and the keys
    /// from the secret store (`_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY`, or `_FILE`), for any
    /// region in REGION_DATA_DIRS; `REGION_DATA_S3_PREFIX` (`superbot/`) and
    /// `REGION_DATA_AGE_RECIPIENTS` (or `_FILE`) are shared. `named`: the regions whose
    /// bucket is set (`named`), each of which must have a store. None: no bucket is set.
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String, dirs: &chat_stores::Settings, named: &[String]) -> Result<Option<Settings>, String> {
        let set = |r: &str| !var(&format!("{}_BUCKET", store_name(r))).trim().is_empty();
        if let Some(r) = named.iter().find(|r| set(r) && !dirs.dirs.iter().any(|(d, _)| d == *r)) {
            return Err(format!("{}_BUCKET is set, but {} gives {r} no chat store to copy (ADR 0246)", store_name(r), chat_stores::SETTING));
        }
        let mut stores = Vec::new();
        for (r, _) in &dirs.dirs {
            if set(r) {
                stores.push((r.clone(), s3::Settings::from_env_named(&store_name(r), store, var)?));
            }
        }
        if stores.is_empty() {
            let stray = [format!("{NAME}_PREFIX"), RECIPIENTS.to_string(), format!("{RECIPIENTS}_FILE")];
            if let Some(k) = stray.iter().find(|k| !var(k).trim().is_empty()) {
                return Err(format!("{k} is set, but no region's chat store backups are copied off the host: set {NAME}_<REGION>_BUCKET or unset {k}"));
            }
            return Ok(None);
        }
        let prefix = backup::prefix(&format!("{NAME}_PREFIX"), &var(&format!("{NAME}_PREFIX")))?;
        let recipients = backup::recipients_from_env(RECIPIENTS, var)?;
        Ok(Some(Settings { stores, prefix, recipients }))
    }
}

/// What one pass did to a store's copies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Copied {
    /// Backups copied up.
    pub uploaded: usize,
    /// Objects deleted, every version of them: of pruned or rewritten backups.
    pub deleted: usize,
    /// Backups the bucket now holds a copy of: all of the folder's.
    pub copies: usize,
}

/// The last pass over one store, for views.
#[derive(Clone, Debug, Default)]
struct Status {
    /// When its copies last matched its backups, and the newest of those backups.
    copied_at: Option<i64>,
    newest: Option<i64>,
    /// The oldest backup the bucket may hold a copy of: the folder's oldest when its copies
    /// last matched it, since a failed pass may leave copies of backups pruned since.
    oldest: Option<i64>,
    copies: usize,
    /// Why the last pass failed, and since when passes have.
    error: Option<String>,
    failing_since: Option<i64>,
}

/// A backup file's SHA-256, kept while the file is the same one (size, time, inode).
type Hashed = (u64, i64, i64, u64, String);

/// Off-host copies, on: the buckets and what passes found.
pub struct Copies {
    s: Settings,
    clients: Vec<(String, S3)>,
    hashes: Mutex<HashMap<PathBuf, Hashed>>,
    /// By store id.
    status: Mutex<HashMap<String, Status>>,
}

impl Copies {
    pub fn new(s: Settings) -> Result<Copies, String> {
        let clients = s.stores.iter().map(|(r, st)| Ok((r.clone(), S3::new(st.clone())?.called("the chat store's backup bucket")))).collect::<Result<_, String>>()?;
        Ok(Copies { s, clients, hashes: Mutex::default(), status: Mutex::default() })
    }

    pub fn settings(&self) -> &Settings {
        &self.s
    }

    /// Where `store`'s copies go: endpoint, bucket and key prefix. None: its region has no
    /// bucket.
    pub fn destination(&self, store: &ChatStore) -> Option<String> {
        let b = self.bucket(&store.region)?;
        Some(format!("{}/{}/{}", b.endpoint.trim_end_matches('/'), b.bucket, self.store_prefix(store)))
    }

    /// For the startup log.
    pub fn describe(&self) -> String {
        let each: Vec<String> = self.s.stores.iter().map(|(r, st)| format!("{r} to {}/{}", st.endpoint, st.bucket)).collect();
        let enc = if self.s.recipients.is_empty() { "not age-encrypted".to_string() } else { format!("age-encrypted to {} recipients", self.s.recipients.len()) };
        format!("{}; {enc}", each.join(", "))
    }

    fn client(&self, region: &str) -> Option<&S3> {
        self.clients.iter().find(|(r, _)| r == region).map(|(_, s)| s)
    }

    fn bucket(&self, region: &str) -> Option<&s3::Settings> {
        self.s.stores.iter().find(|(r, _)| r == region).map(|(_, s)| s)
    }

    /// Where `store`'s copies go, ending in `/`: its region and its id, so a store made
    /// again in the region never mixes with an earlier one's.
    fn store_prefix(&self, store: &ChatStore) -> String {
        format!("{}region-data/{}/{}/", self.s.prefix, store.region, store.id)
    }

    /// The key of the copy of the backup named `name` whose SHA-256 is `sha`.
    fn key(&self, store: &ChatStore, name: &str, sha: &str) -> String {
        let stem = name.strip_suffix(".sqlite").unwrap_or(name);
        format!("{}{stem}-{sha}.sqlite{}", self.store_prefix(store), if self.s.recipients.is_empty() { "" } else { ".age" })
    }

    async fn sha(&self, path: &Path) -> Result<String, String> {
        use std::os::unix::fs::MetadataExt;
        let io = |e: std::io::Error| format!("{}: {e}", path.display());
        let m = std::fs::metadata(path).map_err(io)?;
        let id = (m.len(), m.mtime(), m.mtime_nsec(), m.ino());
        if let Some((.., sha)) = self.hashes.lock().unwrap().get(path).filter(|h| (h.0, h.1, h.2, h.3) == id) {
            return Ok(sha.clone());
        }
        let p = path.to_path_buf();
        let sha = tokio::task::spawn_blocking(move || -> Result<String, std::io::Error> {
            use std::io::Read;
            let mut f = std::fs::File::open(&p)?;
            let mut ctx = digest::Context::new(&digest::SHA256);
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    return Ok(crate::sigv4::hex(ctx.finish().as_ref()));
                }
                ctx.update(&buf[..n]);
            }
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(io)?;
        self.hashes.lock().unwrap().insert(path.to_path_buf(), (id.0, id.1, id.2, id.3, sha.clone()));
        Ok(sha)
    }

    /// Makes `store`'s bucket hold a copy of each backup in its folder and nothing else
    /// under its prefix. None: its region has no bucket.
    pub async fn copy(&self, store: &ChatStore, at: i64) -> Option<Result<Copied, String>> {
        let s3 = self.client(&store.region)?;
        let r = self.sync(s3, store, at).await;
        let mut status = self.status.lock().unwrap();
        let st = status.entry(store.id.clone()).or_default();
        match &r {
            Ok((c, newest, oldest)) => {
                *st = Status { copied_at: Some(at), newest: *newest, oldest: *oldest, copies: c.copies, error: None, failing_since: None };
            }
            Err(e) => {
                st.error = Some(clip(e, 500));
                st.failing_since.get_or_insert(at);
            }
        }
        Some(r.map(|(c, ..)| c))
    }

    async fn sync(&self, s3: &S3, store: &ChatStore, at: i64) -> Result<(Copied, Option<i64>, Option<i64>), String> {
        let prefix = self.store_prefix(store);
        // An upload cut off by a restart may hold rows that have since left the store.
        s3.abort_unfinished_under(&prefix, at).await?;
        let local = chat_stores::backups_strictly(store)?;
        let mut want: Vec<(String, PathBuf, String)> = Vec::new();
        for (_, path) in &local {
            let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| format!("{}: not a backup's name", path.display()))?;
            let sha = self.sha(path).await?;
            want.push((self.key(store, name, &sha), path.clone(), sha));
        }
        let versioned = s3.versioned().await?;
        let (current, all): (Vec<String>, Vec<(String, String)>) = if versioned {
            let v = s3.object_versions(&prefix).await?;
            (v.iter().filter(|v| v.latest && !v.marker).map(|v| v.key.clone()).collect(), v.into_iter().map(|v| (v.key, v.version)).collect())
        } else {
            let keys = s3.list(&prefix).await?;
            (keys.clone(), keys.into_iter().map(|k| (k, String::new())).collect())
        };
        let mut done = Copied { copies: want.len(), ..Copied::default() };
        for (key, path, sha) in &want {
            if current.contains(key) {
                continue;
            }
            self.upload(s3, path, key, sha).await?;
            done.uploaded += 1;
        }
        let stale: Vec<&(String, String)> = all.iter().filter(|(key, _)| !want.iter().any(|(k, _, _)| k == key)).collect();
        // A lost volume (or one mounted empty) must not empty the bucket: its copies are
        // then the only ones.
        let hold = match (store.path.exists(), want.is_empty()) {
            (false, _) => Some(format!("the store {} is missing", store.path.display())),
            (true, true) => Some("its folder holds no backups".to_string()),
            _ => None,
        };
        if let Some(why) = hold.filter(|_| !stale.is_empty()) {
            return Err(format!("nothing deleted from its bucket while {why}"));
        }
        let mut gone: Vec<&str> = Vec::new();
        for (key, version) in stale {
            match versioned {
                true => s3.delete_version(key, version).await?,
                false => s3.delete(key).await?,
            }
            if !gone.contains(&key.as_str()) {
                gone.push(key);
            }
        }
        done.deleted = gone.len();
        Ok((done, local.first().map(|(t, _)| *t), local.last().map(|(t, _)| *t)))
    }

    async fn upload(&self, s3: &S3, path: &Path, key: &str, sha: &str) -> Result<(), String> {
        let f = tokio::fs::File::open(path).await.map_err(|e| format!("{}: {e}", path.display()))?;
        let (_, stored) = backup::send(s3, &self.s.recipients, file_stream(f), key, "the chat store's backup").await?;
        if self.s.recipients.is_empty() && stored != sha {
            let _ = s3.delete(key).await;
            return Err(format!("{} changed while it was copied off the host", path.display()));
        }
        Ok(())
    }

    /// Copies each store whose region has a bucket, each pass audited as
    /// `residency.chat_store_backups_copied` when it changed the bucket or failed. By region.
    pub async fn pass(&self, db: &Db, at: i64) -> HashMap<String, Result<Copied, String>> {
        let mut out = HashMap::new();
        for store in db.chat_stores() {
            let Some(r) = self.copy(&store, at).await else { continue };
            let bucket = self.bucket(&store.region).map(|b| b.bucket.clone());
            match &r {
                Ok(c) if c.uploaded + c.deleted > 0 => {
                    log_info!("Regional chat stores: {}'s backups copied off the host: {} copied, {} deleted, {} held (ADR 0246).", store.region, c.uploaded, c.deleted, c.copies);
                    db.record(&Who::system(ACTOR).event(COPIED).details(json!({ "region": store.region, "bucket": bucket, "uploaded": c.uploaded, "deleted": c.deleted, "copies": c.copies })));
                }
                Ok(_) => {}
                Err(e) => {
                    log_warn!("Regional chat stores: {}'s backups couldn't all be copied off the host; the next check tries again: {e} (ADR 0246).", store.region);
                    db.record(&Who::system(ACTOR).event(COPIED).outcome(Outcome::Failure).details(json!({ "region": store.region, "bucket": bucket, "error": clip(e, 500) })));
                }
            }
            out.insert(store.region.clone(), r);
        }
        out
    }

    /// For admins (`GET /api/regions`): where `store`'s copies go and the last pass. None:
    /// its region has no bucket. No credentials.
    pub fn view(&self, store: &ChatStore) -> Option<Value> {
        let b = self.bucket(&store.region)?;
        let st = self.status.lock().unwrap().get(&store.id).cloned().unwrap_or_default();
        Some(json!({
            "endpoint": b.endpoint, "bucket": b.bucket, "encrypted": !self.s.recipients.is_empty(),
            "copies": st.copies, "newestCopyAt": st.newest, "lastCopiedAt": st.copied_at, "error": st.error, "failingSince": st.failing_since,
        }))
    }

    /// For residency reports on a pin to `store`'s region: no endpoint or bucket.
    pub fn report_view(&self, store: &ChatStore) -> Option<Value> {
        let v = self.view(store)?;
        Some(json!({ "copies": v["copies"], "newestCopyAt": v["newestCopyAt"], "lastCopiedAt": v["lastCopiedAt"], "failing": !v["error"].is_null() }))
    }

    /// Whether `store`'s bucket may still hold a copy of a backup made by `at`: its region
    /// has a bucket and no pass has shown it holds none (one that matched the folder, whose
    /// oldest backup is later). For reports' earlier copies, which local backups pruned
    /// while the bucket refused deletes no longer show.
    pub fn may_hold(&self, store: &ChatStore, at: i64) -> bool {
        self.bucket(&store.region).is_some()
            && match self.status.lock().unwrap().get(&store.id) {
                Some(st) if st.copied_at.is_some() => st.oldest.is_some_and(|o| o <= at),
                _ => true,
            }
    }

    /// Warnings for admins: stores whose last pass failed.
    pub fn warnings(&self, stores: &[ChatStore]) -> Vec<String> {
        let status = self.status.lock().unwrap();
        stores
            .iter()
            .filter(|s| self.bucket(&s.region).is_some())
            .filter_map(|s| status.get(&s.id).filter(|st| st.error.is_some()).map(|_| s))
            .map(|s| format!("{}'s chat store's backups couldn't all be copied off the host to its bucket in {}; check botd's log for {COPIED} failures (ADR 0246).", s.region, s.region))
            .collect()
    }
}

fn recorded(store: &ChatStore) -> String {
    format!("chat_store_copies.{}", store.id)
}

/// At startup: each store's copies must go where they went before, since botd only ever
/// deletes copies (of rows that left the store) where it copies to now. A store whose
/// bucket or prefix changed, or was unset, stops botd until the operator, having deleted the
/// earlier copies (or kept them as theirs to answer for), names its region in
/// REGION_DATA_S3_FORGET; each is then audited as `residency.chat_store_copies_forgotten`.
/// The first destination of each store is recorded. Warnings for the log.
pub fn check_destinations(db: &Db, copies: Option<&Copies>, var: &dyn Fn(&str) -> String) -> Result<Vec<String>, String> {
    let forget: Vec<String> = var(FORGET).split(',').map(str::trim).filter(|r| !r.is_empty()).map(str::to_string).collect();
    let mut warnings = Vec::new();
    for store in db.chat_stores() {
        let (key, now) = (recorded(&store), copies.and_then(|c| c.destination(&store)));
        let before = db.setting(&key);
        if before == now {
            if forget.contains(&store.region) {
                warnings.push(format!("{FORGET} names {}, whose chat store's backups are copied where they were before, so nothing was forgotten. Remove it from the setting (ADR 0246).", store.region));
            }
            continue;
        }
        if let Some(b) = &before {
            if !forget.contains(&store.region) {
                let to = now.as_deref().map_or("nowhere".to_string(), |n| format!("to {n}"));
                return Err(format!(
                    "{}'s chat store's backups were copied to {b}, and are now copied {to}. botd only deletes copies of rows that left the store where it copies now, so the earlier ones may still hold them. Delete them (or put the setting back), then start botd with {FORGET}={} (ADR 0246)",
                    store.region, store.region
                ));
            }
            db.record(&Who::system(ACTOR).event(FORGOTTEN).details(json!({ "region": store.region, "previous": b, "now": now })));
            warnings.push(format!("{}'s chat store's earlier copies at {b} are forgotten, as {FORGET} says; botd no longer looks after them. Remove {} from the setting (ADR 0246).", store.region, store.region));
        }
        match &now {
            Some(n) => db.set_setting(&key, n),
            None => db.clear_setting(&key),
        }
    }
    Ok(warnings)
}

/// `f`'s bytes, a megabyte at a time.
fn file_stream(f: tokio::fs::File) -> super::provider::ByteStream {
    use tokio::io::AsyncReadExt;
    Box::pin(futures_util::stream::unfold(Some(f), |f| async move {
        let mut f = f?;
        let mut buf = vec![0u8; 1 << 20];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(axum::body::Bytes::from(buf)), Some(f)))
            }
            Err(e) => Some((Err(e), None)),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Held, PinOn, now};
    use crate::machines::chat_stores::{backup_pass, clear_backups, finish_clearing};
    use crate::machines::s3_standin::StandIn;
    use crate::secrets::env::EnvStore;

    const DAY: i64 = 86_400_000;

    fn dirs(t: &Path) -> chat_stores::Settings {
        let (lon, fra) = (t.join("lon"), t.join("fra"));
        std::fs::create_dir_all(&lon).unwrap();
        std::fs::create_dir_all(&fra).unwrap();
        chat_stores::Settings { dirs: vec![("gb-lon".into(), lon), ("de-fra-2".into(), fra)], ..chat_stores::Settings::default() }
    }

    #[test]
    fn each_region_with_a_store_may_name_a_bucket_and_no_other() {
        let t = crate::db::Scratch::new();
        let d = dirs(t.path());
        let keys = EnvStore::fixed(&[("REGION_DATA_S3_GB_LON_ACCESS_KEY_ID", "AKID"), ("REGION_DATA_S3_GB_LON_SECRET_ACCESS_KEY", "s3cret-lon")]);
        let with = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            let named = named(vars.iter().map(|(k, _)| k.clone()));
            Settings::from_env(&keys, &move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default(), &d, &named)
        };
        assert!(with(&[]).unwrap().is_none());
        assert!(with(&[("REGION_DATA_S3_US_EAST_BUCKET", " ")]).unwrap().is_none(), "an empty setting is none");
        assert!(crate::secrets::server_secret("REGION_DATA_S3_GB_LON_SECRET_ACCESS_KEY"), "botd's own, never a Bot's");
        assert!(!crate::secrets::server_secret("REGION_DATA_S3_GB_LON_BUCKET"));
        assert_eq!(named(["REGION_DATA_S3_GB_LON_BUCKET".to_string(), "REGION_DATA_S3_PREFIX".into(), "REGION_DATA_S3__BUCKET".into(), "MACHINE_BACKUP_S3_GB_LON_BUCKET".into()]), ["gb-lon"]);
        let lon = [("REGION_DATA_S3_GB_LON_BUCKET", "lon-chats"), ("REGION_DATA_S3_GB_LON_ENDPOINT", "https://gb-lon-1.linodeobjects.com")];
        let s = with(&lon).unwrap().unwrap();
        assert_eq!((s.stores.len(), s.stores[0].0.as_str(), s.stores[0].1.bucket.as_str(), s.prefix.as_str(), s.recipients.len()), (1, "gb-lon", "lon-chats", "superbot/", 0));
        let c = Copies::new(s).unwrap();
        assert!(c.describe().starts_with("gb-lon to https://gb-lon-1.linodeobjects.com/lon-chats; not age-encrypted"), "{}", c.describe());
        assert!(!c.describe().contains("s3cret"));
        let id = age::x25519::Identity::generate();
        let public = id.to_public().to_string();
        let s = with(&[lon[0], lon[1], ("REGION_DATA_S3_PREFIX", "acme/eu"), (RECIPIENTS, public.as_str())]).unwrap().unwrap();
        assert_eq!((s.prefix.as_str(), s.recipients.len()), ("acme/eu/", 1));

        for (vars, want) in [
            (&[("REGION_DATA_S3_US_EAST_BUCKET", "b-1")][..], "REGION_DATA_S3_US_EAST_BUCKET is set, but REGION_DATA_DIRS gives us-east no chat store to copy"),
            (&[("REGION_DATA_S3_PREFIX", "x")][..], "REGION_DATA_S3_PREFIX is set, but no region's chat store backups are copied off the host"),
            (&[lon[0]][..], "REGION_DATA_S3_GB_LON_ENDPOINT is needed"),
            (&[("REGION_DATA_S3_DE_FRA_2_BUCKET", "fra-chats"), ("REGION_DATA_S3_DE_FRA_2_ENDPOINT", "https://de-fra-1.linodeobjects.com")][..], "REGION_DATA_S3_DE_FRA_2_SECRET_ACCESS_KEY (or REGION_DATA_S3_DE_FRA_2_SECRET_ACCESS_KEY_FILE) is needed"),
            (&[lon[0], lon[1], (RECIPIENTS, "nope")][..], "isn't an age public key"),
        ] {
            let e = with(vars).unwrap_err();
            assert!(e.contains(want), "{vars:?}: {e}");
        }
    }

    struct World {
        _t: crate::db::Scratch,
        db: Db,
        lon: PathBuf,
        s3: StandIn,
    }

    async fn world() -> World {
        let t = crate::db::Scratch::new();
        let db = Db::open(&t.path().join("app.sqlite")).unwrap();
        let d = dirs(t.path());
        db.attach_chat_stores(&d.dirs, &[], None).unwrap();
        let lon = d.dirs[0].1.clone();
        World { _t: t, db, lon, s3: StandIn::start().await }
    }

    fn copies(s3: &StandIn, recipients: Vec<age::x25519::Recipient>) -> Copies {
        Copies::new(Settings { stores: vec![("gb-lon".into(), s3.settings())], prefix: "t/".into(), recipients }).unwrap()
    }

    fn pinned_bot(db: &Db, name: &str, region: &str) -> (String, String) {
        let u = db.create_user(None, Some(&format!("{name}@example.com")), name, crate::rbac::Role::Member).unwrap().id;
        db.pin_residency(PinOn::User, &u, region, "DPA-1", None).unwrap();
        let bot = db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &u, crate::acl::Visibility::Private).id;
        (u, bot)
    }

    fn audited(db: &Db) -> Vec<Value> {
        let f = crate::audit::Filter { actions: vec![COPIED.into()], ..Default::default() };
        db.audit_events(&f, 100, false).iter().map(|e| serde_json::to_value(e).unwrap()).collect()
    }

    fn holds(b: &[u8], w: &str) -> bool {
        b.windows(w.len()).any(|x| x == w.as_bytes())
    }

    fn start() -> i64 {
        chrono::DateTime::parse_from_rfc3339("2026-11-01T03:00:00Z").unwrap().timestamp_millis()
    }

    #[tokio::test]
    async fn each_backup_is_copied_once_into_its_regions_bucket_and_pruned_ones_go() {
        let w = world().await;
        let c = copies(&w.s3, Vec::new());
        let (_, bot) = pinned_bot(&w.db, "ada", "gb-lon");
        w.db.add_message(&bot, "user", "chat-77c1-kept-in-london", None, false, None);
        backup_pass(&w.db, 2, start());
        backup_pass(&w.db, 2, start() + DAY);
        let lon = w.db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert!(c.view(&lon).unwrap()["lastCopiedAt"].is_null(), "not copied before the first pass");

        let r = c.pass(&w.db, now()).await;
        assert_eq!(r.len(), 1, "Frankfurt has no bucket: {r:?}");
        assert_eq!(r["gb-lon"], Ok(Copied { uploaded: 2, deleted: 0, copies: 2 }));
        let keys = w.s3.keys();
        let prefix = format!("t/region-data/gb-lon/{}/", lon.id);
        for (key, name) in keys.iter().zip(["chats-20261101-030000", "chats-20261102-030000"]) {
            let file = std::fs::read(w.lon.join("backups").join(format!("{name}.sqlite"))).unwrap();
            assert_eq!(key, &format!("{prefix}{name}-{}.sqlite", s3::sha256_hex(&file)), "named by the file's SHA-256");
            assert_eq!(w.s3.w().objects[key], file, "the backup as it is: the store, under botd's key");
        }
        let v = c.view(&lon).unwrap();
        assert_eq!((v["copies"].as_i64(), v["bucket"].as_str(), v["error"].is_null()), (Some(2), Some(crate::machines::s3_standin::BUCKET), true), "{v}");
        assert_eq!(v["newestCopyAt"].as_i64(), Some(start() + DAY));
        assert!(!v.to_string().contains(crate::machines::s3_standin::SECRET));
        let rv = c.report_view(&lon).unwrap();
        assert_eq!(rv, json!({ "copies": 2, "newestCopyAt": start() + DAY, "lastCopiedAt": v["lastCopiedAt"], "failing": false }), "no endpoint or bucket for customers");

        let before = w.s3.w().calls.len();
        assert_eq!(c.pass(&w.db, now()).await["gb-lon"], Ok(Copied { uploaded: 0, deleted: 0, copies: 2 }), "nothing again");
        assert!(w.s3.w().calls[before..].iter().all(|c| c.starts_with("GET ")), "only listed: {:?}", &w.s3.w().calls[before..]);

        // The folder keeps the newest two; the bucket follows it.
        backup_pass(&w.db, 2, start() + 2 * DAY);
        assert_eq!(c.pass(&w.db, now()).await["gb-lon"], Ok(Copied { uploaded: 1, deleted: 1, copies: 2 }));
        let keys = w.s3.keys();
        assert!(keys.iter().all(|k| !k.contains("20261101")) && keys.iter().any(|k| k.contains("20261103")), "{keys:?}");
        let copied = audited(&w.db);
        assert_eq!(copied.len(), 2, "audited when the bucket changed, not when it didn't: {copied:?}");
        assert_eq!((copied[0]["details"]["uploaded"].as_i64(), copied[0]["details"]["deleted"].as_i64(), copied[0]["actorId"].as_str()), (Some(1), Some(1), Some(ACTOR)), "{copied:?}");
    }

    #[tokio::test]
    async fn copies_are_age_encrypted_to_the_recipients_when_set() {
        let w = world().await;
        let id = age::x25519::Identity::generate();
        let c = copies(&w.s3, vec![id.to_public()]);
        let (_, bot) = pinned_bot(&w.db, "ada", "gb-lon");
        let word = "chat-4e0a-sealed-for-ops";
        w.db.add_message(&bot, "user", word, None, false, None);
        backup_pass(&w.db, 7, start());
        assert_eq!(c.pass(&w.db, now()).await["gb-lon"].as_ref().map(|c| c.uploaded), Ok(1));
        let (key, body) = w.s3.w().objects.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        assert!(key.ends_with(".sqlite.age") && !holds(&body, word), "{key}");
        use std::io::Read;
        let d = age::Decryptor::new(&body[..]).unwrap();
        let mut plain = Vec::new();
        d.decrypt(std::iter::once(&id as &dyn age::Identity)).unwrap().read_to_end(&mut plain).unwrap();
        let local = std::fs::read(chat_stores::backups_strictly(&w.db.chat_stores()[0]).unwrap()[0].1.clone()).unwrap();
        assert_eq!(plain, local, "the backup, decrypted with the operator's identity");
        assert!(key.contains(&s3::sha256_hex(&local)), "named by the plain file's SHA-256");
    }

    #[tokio::test]
    async fn a_rewritten_backup_replaces_its_copy_every_version_of_the_old_one_goes_and_only_then_is_the_move_cleared() {
        let w = world().await;
        w.s3.w().versioning = Some("Enabled");
        let c = copies(&w.s3, Vec::new());
        let (ada, bot) = pinned_bot(&w.db, "ada", "gb-lon");
        let (_, cys) = pinned_bot(&w.db, "cy", "gb-lon");
        let word = "chat-9b31-leaves-london";
        w.db.add_message(&bot, "user", word, None, false, None);
        w.db.add_message(&cys, "user", "cy-stays", None, false, None);
        backup_pass(&w.db, 7, start());
        c.pass(&w.db, now()).await;
        let old = w.s3.keys();
        assert!(old.len() == 1 && holds(&w.s3.w().objects[&old[0]], word));

        w.db.unpin_residency(PinOn::User, &ada).unwrap();
        w.db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-2", None).unwrap();
        w.db.place_chats().unwrap();

        // The bucket refuses: London's backup is rewritten, but the move stays uncleared.
        let cleared = clear_backups(&w.db);
        w.s3.w().fail = Some(("POST".into(), 500));
        let r = c.pass(&w.db, now()).await;
        assert!(r["gb-lon"].as_ref().is_err_and(|e| e.contains("refused (500)")), "{r:?}");
        let done = finish_clearing(&w.db, cleared, &r, now());
        assert!(done[0].1.as_ref().is_err_and(|e| e.starts_with("the backups' copies off the host: ")), "{done:?}");
        assert_eq!(w.db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "still an earlier copy: the bucket holds her rows");
        let lon = w.db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert!(c.warnings(std::slice::from_ref(&lon))[0].contains("gb-lon's chat store's backups couldn't all be copied off the host"));
        assert_eq!(c.report_view(&lon).unwrap()["failing"], json!(true));
        let failed = audited(&w.db);
        assert_eq!(failed[0]["outcome"].as_str(), Some("failure"), "{failed:?}");
        assert!(w.s3.unfinished().is_empty(), "a failed upload leaves no parts");

        // Next hour: the rewritten backup is copied, every version of the old copy deleted,
        // and the move recorded as cleared.
        let cleared = clear_backups(&w.db);
        let r = c.pass(&w.db, now()).await;
        assert_eq!(r["gb-lon"], Ok(Copied { uploaded: 1, deleted: 1, copies: 1 }));
        assert_eq!(finish_clearing(&w.db, cleared, &r, now())[0].1.as_ref().map(|c| c.held), Ok(Held::default()), "already cleared locally");
        assert!(w.db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").is_empty());
        let keys = w.s3.keys();
        assert!(keys.len() == 1 && keys != old, "{keys:?}");
        let s3 = w.s3.w();
        assert!(!holds(&s3.objects[&keys[0]], word) && holds(&s3.objects[&keys[0]], "cy-stays"));
        assert!(s3.old.iter().all(|(k, _, _)| *k != old[0]), "no old version or delete marker of the old copy is left: {:?}", s3.old);
        assert!(c.warnings(std::slice::from_ref(&lon)).is_empty());
    }

    #[tokio::test]
    async fn uploads_a_crash_cut_off_are_aborted_and_a_folder_botd_cant_list_empties_nothing() {
        let w = world().await;
        let c = copies(&w.s3, Vec::new());
        let (_, bot) = pinned_bot(&w.db, "ada", "gb-lon");
        w.db.add_message(&bot, "user", "x", None, false, None);
        backup_pass(&w.db, 7, start());
        c.pass(&w.db, now()).await;
        let lon = w.db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        for n in 0..3 {
            w.s3.leave_unfinished(&format!("t/region-data/gb-lon/{}/chats-2026103{n}-030000-abc.sqlite", lon.id), 60_000);
        }
        w.s3.leave_unfinished("t/machines/m1/b1.incus", 60_000);
        w.s3.w().page = Some(1);
        assert_eq!(c.pass(&w.db, now()).await["gb-lon"].as_ref().map(|c| c.uploaded), Ok(0));
        assert_eq!(w.s3.unfinished(), ["t/machines/m1/b1.incus"], "only the store's own, on every page");
        w.s3.w().page = None;

        let dir = w.lon.join("backups");
        std::fs::rename(&dir, w.lon.join("aside")).unwrap();
        std::fs::write(&dir, b"not a folder").unwrap();
        assert!(c.pass(&w.db, now()).await["gb-lon"].is_err());
        assert_eq!(w.s3.keys().len(), 1, "the copy is kept");
    }

    #[tokio::test]
    async fn a_store_whose_copies_go_somewhere_else_now_stops_botd_until_the_earlier_ones_are_forgotten() {
        let w = world().await;
        let c = copies(&w.s3, Vec::new());
        let none = |_: &str| String::new();
        assert_eq!(check_destinations(&w.db, None, &none), Ok(Vec::new()), "no bucket, nothing recorded");
        assert_eq!(check_destinations(&w.db, Some(&c), &none), Ok(Vec::new()), "the first destination is recorded");
        assert_eq!(check_destinations(&w.db, Some(&c), &none), Ok(Vec::new()));

        let moved = Copies::new(Settings { stores: vec![("gb-lon".into(), w.s3.settings())], prefix: "elsewhere/".into(), recipients: Vec::new() }).unwrap();
        for now in [Some(&moved), None] {
            let e = check_destinations(&w.db, now, &none).unwrap_err();
            assert!(e.starts_with("gb-lon's chat store's backups were copied to ") && e.contains("/t/region-data/gb-lon/") && e.contains("REGION_DATA_S3_FORGET=gb-lon"), "{e}");
        }
        assert!(check_destinations(&w.db, None, &none).unwrap_err().contains("are now copied nowhere"));

        let forget = |k: &str| if k == FORGET { "gb-lon".to_string() } else { String::new() };
        let warned = check_destinations(&w.db, Some(&moved), &forget).unwrap();
        assert!(warned[0].contains("earlier copies at ") && warned[0].contains("are forgotten"), "{warned:?}");
        let f = crate::audit::Filter { actions: vec![FORGOTTEN.into()], ..Default::default() };
        let e = serde_json::to_value(&w.db.audit_events(&f, 10, false)[0]).unwrap();
        assert!(e["details"]["previous"].as_str().unwrap().contains("/t/region-data/gb-lon/"), "{e}");
        assert!(e["details"]["now"].as_str().unwrap().contains("/elsewhere/region-data/gb-lon/"), "{e}");
        assert_eq!(check_destinations(&w.db, Some(&moved), &none), Ok(Vec::new()), "the new one is recorded");
        assert!(check_destinations(&w.db, Some(&moved), &forget).unwrap()[0].contains("nothing was forgotten. Remove it"));
    }

    #[tokio::test]
    async fn a_lost_store_or_an_empty_folder_never_empties_the_bucket() {
        let w = world().await;
        let c = copies(&w.s3, Vec::new());
        let (_, bot) = pinned_bot(&w.db, "ada", "gb-lon");
        w.db.add_message(&bot, "user", "x", None, false, None);
        backup_pass(&w.db, 7, start());
        c.pass(&w.db, now()).await;
        let lon = w.db.chat_stores().into_iter().find(|s| s.region == "gb-lon").unwrap();
        assert!(!c.may_hold(&lon, start() - 1) && c.may_hold(&lon, start()), "the bucket holds the backup from start() on");

        // The volume is gone: botd's next backup fails and the folder is empty.
        let (dir, aside) = (w.lon.join("backups"), w.lon.join("aside"));
        std::fs::rename(&dir, &aside).unwrap();
        std::fs::rename(&lon.path, w.lon.join("gone.sqlite")).unwrap();
        assert!(backup_pass(&w.db, 7, start() + DAY).iter().any(|(r, b)| r == "gb-lon" && b.is_err()));
        let r = c.pass(&w.db, now()).await;
        assert!(r["gb-lon"].as_ref().is_err_and(|e| e.contains("nothing deleted from its bucket while the store") && e.contains("is missing")), "{r:?}");
        assert_eq!(w.s3.keys().len(), 1, "the only copy left is kept");
        assert!(c.may_hold(&lon, start()), "still held");

        std::fs::rename(w.lon.join("gone.sqlite"), &lon.path).unwrap();
        let r = c.pass(&w.db, now()).await;
        assert!(r["gb-lon"].as_ref().is_err_and(|e| e.contains("while its folder holds no backups")), "{r:?}");
        assert_eq!(w.s3.keys().len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::rename(&aside, &dir).unwrap();
        assert_eq!(c.pass(&w.db, now()).await["gb-lon"], Ok(Copied { uploaded: 0, deleted: 0, copies: 1 }));
    }
}
