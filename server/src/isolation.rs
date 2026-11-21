//! Per-user isolation on one host (ADR 0029). A user's Bots share that user's folders
//! and secrets, and nobody else's: `WORKSPACE_DIR/users/<user>` is their working folder,
//! `DATA_DIR/users/<user>/USER.md` their facts. Each Bot run carries a token only that
//! run has, so a Bot can't claim to be another user's Bot, and nothing a run leaves
//! behind can act once it ends (ADR 0083). On managed hosting the same
//! split moves onto the user's own machine (`machines::route`).

use crate::paths;
use aws_lc_rs::hmac;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Starts every per-Bot token, so a leaked one is easy to spot and redact.
pub const BOT_TOKEN_PREFIX: &str = "sbb_";
/// The folder under each root that holds one folder per user.
pub const USERS: &str = "users";
/// Marks a workspace that has the per-user layout. Holds `moving` while it's being set up.
const LAYOUT: &str = ".superbot-layout";
const LAYOUT_TMP: &str = ".superbot-layout.tmp";
const DONE: &str = "per-user 1";
/// Where an old shared workspace's files wait on their way to the owner's folder.
const STAGING: &str = ".superbot-owner-files";

fn signed(bot_id: &str, token_id: &str) -> String {
    format!("superbot-run-token/v1/{bot_id}/{token_id}")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// What botd knows of one live run token (ADR 0083). Only botd holds it: the token
/// itself names the Bot and this entry's id, nothing it could widen.
#[derive(Clone, Debug, PartialEq)]
pub struct RunToken {
    /// Names the entry in the token and the audit log (`jti`), never the secret.
    pub id: String,
    pub bot: String,
    /// The Bot's owner when the run started. A token outlives no change of hands.
    pub owner: String,
    pub run: String,
    /// The teammate a run of a shared Bot is for, in their own account or OS user
    /// (ADR 0048, 0064): the token acts with no more than their access.
    pub for_user: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Why a Bot token was refused, as `auth.login_failed` gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Forged, mangled, or signed by an earlier start of botd.
    BadToken,
    /// Its run is over: revoked when the run ended, or never issued by this start.
    RunOver,
    /// Past its expiry, though its run hadn't said it was over.
    Expired,
}

impl Refused {
    pub fn reason(self) -> &'static str {
        match self {
            Refused::BadToken => "bad_token",
            Refused::RunOver => "run_over",
            Refused::Expired => "token_expired",
        }
    }
}

/// Every Bot token botd has issued and not yet revoked (ADR 0083). A run gets one when
/// it starts and loses it when it ends, however it ends, and each lives no longer than
/// the run may. Tokens are signed with botd's key, made fresh at each start, so none
/// outlives the process either.
pub struct RunTokens {
    key: hmac::Key,
    live: std::sync::Mutex<std::collections::HashMap<String, RunToken>>,
}

impl RunTokens {
    pub fn new(key: &str) -> RunTokens {
        RunTokens { key: hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes()), live: Default::default() }
    }

    fn live(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, RunToken>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new token for one run of `bot`: `sbb_<bot id>.<token id>.<HMAC-SHA256>`, live
    /// from `now` (Unix ms) for `ttl_ms` or until `revoke`, whichever comes first.
    pub fn issue(&self, bot: &str, owner: &str, run: &str, for_user: Option<&str>, now: i64, ttl_ms: i64) -> (String, RunToken) {
        let id = crate::random_hex(16);
        let tag = hmac::sign(&self.key, signed(bot, &id).as_bytes());
        let token = format!("{BOT_TOKEN_PREFIX}{bot}.{id}.{}", hex(tag.as_ref()));
        let entry = RunToken {
            id: id.clone(),
            bot: bot.into(),
            owner: owner.into(),
            run: run.into(),
            for_user: for_user.map(String::from),
            issued_at: now,
            expires_at: now.saturating_add(ttl_ms.max(0)),
        };
        self.live().insert(id, entry.clone());
        (token, entry)
    }

    /// The live entry a token was issued as. Constant time in the MAC, which is checked
    /// before anything is looked up. The caller still checks the Bot exists, has the same
    /// owner, and that the owner may act.
    pub fn check(&self, token: &str, now: i64) -> Result<RunToken, Refused> {
        let (bot, id) = self.verify(token).ok_or(Refused::BadToken)?;
        let mut live = self.live();
        let entry = live.get(id).filter(|e| e.bot == bot).cloned().ok_or(Refused::RunOver)?;
        if now >= entry.expires_at {
            live.remove(id);
            return Err(Refused::Expired);
        }
        Ok(entry)
    }

    /// The Bot and token id a token names, if this start of botd signed it.
    fn verify<'a>(&self, token: &'a str) -> Option<(&'a str, &'a str)> {
        let parts: Vec<&str> = token.strip_prefix(BOT_TOKEN_PREFIX)?.split('.').collect();
        let [bot, id, tag] = parts[..] else { return None };
        if !plain_id(bot) || !plain_id(id) || tag.len() != 64 {
            return None;
        }
        hmac::verify(&self.key, signed(bot, id).as_bytes(), &unhex(tag)?).ok().map(|_| (bot, id))
    }

    /// Ends a token now. The entry, if it was still live.
    pub fn revoke(&self, id: &str) -> Option<RunToken> {
        self.live().remove(id)
    }

    /// How many of a Bot's tokens are live, expired ones not yet seen included.
    #[cfg(test)]
    pub fn live_for(&self, bot: &str) -> usize {
        self.live().values().filter(|e| e.bot == bot).count()
    }

    /// Whether a token id is still live at `now`.
    pub fn is_live(&self, id: &str, now: i64) -> bool {
        self.live().get(id).is_some_and(|e| now < e.expires_at)
    }
}

/// `root/users/<user>`, created. None when the id isn't one plain folder name.
pub fn user_dir(root: &Path, user_id: &str) -> Option<PathBuf> {
    let dir = paths::child(&paths::child(&paths::canonical(root)?, USERS)?, user_id)?;
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Moves a shared workspace from before per-user folders into the owner's folder
/// (`users/<owner>`), once. Every Bot then belonged to the owner account (ADR 0017), so
/// its files go there; an admin can hand files to others. Renames only, inside the root,
/// so nothing is copied or lost, and a start interrupted halfway finishes on the next.
/// `data` (botd's `DATA_DIR`, with the open database) never moves, even when it's
/// inside `root`; when it is `root`, nothing moves. Returns how many top-level entries moved.
pub fn migrate_workspace(root: &Path, owner: &str, data: &Path) -> io::Result<usize> {
    let root = std::fs::canonicalize(root)?;
    let data = std::fs::canonicalize(data).unwrap_or_else(|_| data.to_path_buf());
    if data == root {
        return Ok(0);
    }
    let marker = root.join(LAYOUT);
    let staging = root.join(STAGING);
    let tmp = root.join(LAYOUT_TMP);
    // Bots could write anything in the old shared workspace. botd never makes these
    // paths links, so a link there is dropped rather than followed (into DATA_DIR, say).
    for p in [&marker, &staging, &tmp] {
        if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
            std::fs::remove_file(p)?;
        }
    }
    let mark = |state: &str| -> io::Result<()> {
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(format!("{state}\n").as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &marker)
    };
    let state = std::fs::read_to_string(&marker).ok();
    let mut moved = 0;
    if state.is_none() {
        let entries: Vec<_> = std::fs::read_dir(&root)?.collect::<io::Result<_>>()?;
        let entries: Vec<_> = entries.into_iter().filter(|e| !data.starts_with(e.path()) && ![STAGING, LAYOUT_TMP].iter().any(|n| e.file_name() == *n)).collect();
        if entries.is_empty() && !staging.exists() {
            mark(DONE)?;
            return Ok(0);
        }
        std::fs::create_dir_all(&staging)?;
        for e in entries {
            std::fs::rename(e.path(), staging.join(e.file_name()))?;
            moved += 1;
        }
        mark("moving")?;
    } else if !staging.exists() {
        // Done, or a crash after the last move: either way nothing is left to move.
        if state.as_deref().map(str::trim) != Some(DONE) {
            mark(DONE)?;
        }
        return Ok(0);
    }
    // Anything still staged, whatever the marker says, finishes moving.
    let users = root.join(USERS);
    std::fs::create_dir_all(&users)?;
    let dest = paths::child(&users, owner).ok_or_else(|| io::Error::other(format!("{owner} isn't a folder name")))?;
    if staging.exists() {
        if dest.exists() {
            for e in std::fs::read_dir(&staging)? {
                let e = e?;
                std::fs::rename(e.path(), dest.join(e.file_name()))?;
            }
            std::fs::remove_dir(&staging)?;
        } else {
            std::fs::rename(&staging, &dest)?;
        }
    }
    mark(DONE)?;
    Ok(moved)
}

/// Moves `DATA_DIR/USER.md` (from when all Bots shared one) to the owner's folder. True if it moved.
pub fn migrate_user_file(data: &Path, owner: &str) -> io::Result<bool> {
    let old = data.join("USER.md");
    let dir = user_dir(data, owner).ok_or_else(|| io::Error::other(format!("{owner} isn't a folder name")))?;
    let new = dir.join("USER.md");
    if !old.is_file() || new.exists() {
        return Ok(false);
    }
    std::fs::rename(old, new)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_tokens_name_one_run_of_one_bot_and_end_with_it() {
        let tokens = RunTokens::new(&crate::random_hex(24));
        let (t, e) = tokens.issue("b1", "u1", "r1", None, 1_000, 60_000);
        let id = e.id.clone();
        assert!(t.starts_with(&format!("sbb_b1.{id}.")) && t.len() == format!("sbb_b1.{id}.").len() + 64, "{t}");
        assert_eq!(tokens.check(&t, 1_000), Ok(e.clone()));
        assert_eq!((e.bot.as_str(), e.owner.as_str(), e.run.as_str(), e.for_user.as_deref()), ("b1", "u1", "r1", None));

        let (again, e2) = tokens.issue("b1", "u1", "r2", None, 1_000, 60_000);
        assert_ne!(again, t, "each run gets its own");
        assert_ne!(e2.id, id);
        let (bound, eb) = tokens.issue("b1", "u1", "r3", Some("u2"), 1_000, 60_000);
        assert_eq!(tokens.check(&bound, 1_000).map(|e| e.for_user), Ok(Some("u2".into())));

        assert_eq!(tokens.revoke(&id).map(|e| e.run), Some("r1".into()));
        assert_eq!(tokens.check(&t, 1_000), Err(Refused::RunOver), "revoked when its run ends");
        assert_eq!(tokens.revoke(&id), None);
        assert!(tokens.check(&again, 1_000).is_ok(), "other runs' tokens are untouched");

        assert_eq!(tokens.check(&again, 61_000), Err(Refused::Expired), "never past its expiry");
        assert!(!tokens.is_live(&e2.id, 61_000));
        assert_eq!(tokens.check(&again, 1_000), Err(Refused::RunOver), "and gone once seen expired");
        tokens.revoke(&eb.id);

        let other = RunTokens::new(&crate::random_hex(24));
        let (theirs, _) = other.issue("b1", "u1", "r1", None, 1_000, 60_000);
        assert_eq!(tokens.check(&theirs, 1_000), Err(Refused::BadToken), "another start's key");

        let (t, e) = tokens.issue("b1", "u1", "r4", None, 1_000, 60_000);
        let mac = t.rsplit_once('.').unwrap().1;
        let (b2, e_b2) = tokens.issue("b2", "u1", "r5", None, 1_000, 60_000);
        let mac_b2 = b2.rsplit_once('.').unwrap().1;
        for forged in [
            format!("sbb_b2.{}.{mac}", e.id),
            format!("sbb_b1.{}.{mac_b2}", e_b2.id),
            format!("sbb_b2.{}.{mac_b2}", e.id),
            format!("sbb_b1.{mac}"),
            format!("sbb_b1.{}.{}", e.id, "0".repeat(64)),
            format!("sbb_b1.{}.{}", e.id, &mac[..62]),
            format!("sbb_b1.{}.{}x", e.id, &mac[..63]),
            format!("sbb_b1/x.{}.{mac}", e.id),
            format!("sbb_b1.u1.{}.{mac}", e.id),
            format!("sbb_.{}.{mac}", e.id),
            t.replace("sbb_", "sbx_"),
            t.replace('.', ""),
        ] {
            assert_eq!(tokens.check(&forged, 1_000), Err(Refused::BadToken), "{forged}");
        }
        assert!(tokens.check(&t, 1_000).is_ok() && tokens.check(&b2, 1_000).is_ok());
    }

    #[test]
    fn user_dirs_stay_under_their_root() {
        let root = crate::db::temp_path("user-dirs");
        let d = user_dir(&root, "u1").unwrap();
        assert!(d.is_dir() && d.ends_with("users/u1"), "{}", d.display());
        for bad in ["", "..", "../u2", "a/b", "/etc"] {
            assert_eq!(user_dir(&root, bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_shared_workspace_moves_to_the_owner_once() {
        let root = crate::db::temp_path("ws-migrate");
        let elsewhere = crate::db::temp_path("ws-migrate-data");
        std::fs::create_dir_all(root.join("project/src")).unwrap();
        std::fs::write(root.join("project/src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(root.join("notes.md"), "hi").unwrap();
        // A user folder from before is just a file of the owner's.
        std::fs::create_dir_all(root.join("users")).unwrap();
        assert_eq!(migrate_workspace(&root, "operator", &elsewhere).unwrap(), 3);
        let owner = root.join("users/operator");
        assert_eq!(std::fs::read_to_string(owner.join("project/src/main.rs")).unwrap(), "fn main() {}");
        assert!(owner.join("notes.md").is_file() && owner.join("users").is_dir());
        assert!(!root.join("notes.md").exists() && !root.join(STAGING).exists());
        assert_eq!(migrate_workspace(&root, "operator", &elsewhere).unwrap(), 0, "once");
        std::fs::write(root.join("later.md"), "x").unwrap();
        assert_eq!(migrate_workspace(&root, "operator", &elsewhere).unwrap(), 0);
        assert!(root.join("later.md").is_file(), "files made after the move stay put");
    }

    #[test]
    fn an_interrupted_move_finishes() {
        let root = crate::db::temp_path("ws-resume");
        let elsewhere = crate::db::temp_path("ws-resume-data");
        std::fs::create_dir_all(root.join(STAGING)).unwrap();
        std::fs::write(root.join(STAGING).join("a.txt"), "a").unwrap();
        std::fs::write(root.join(LAYOUT), "moving\n").unwrap();
        std::fs::create_dir_all(root.join("users/operator")).unwrap();
        std::fs::write(root.join("users/operator/b.txt"), "b").unwrap();
        migrate_workspace(&root, "operator", &elsewhere).unwrap();
        assert!(root.join("users/operator/a.txt").is_file() && root.join("users/operator/b.txt").is_file());
        assert!(!root.join(STAGING).exists());
        assert_eq!(std::fs::read_to_string(root.join(LAYOUT)).unwrap().trim(), "per-user 1");

        // A marker cut short (empty) with files still staged: they still move.
        let cut = crate::db::temp_path("ws-cut");
        std::fs::create_dir_all(cut.join(STAGING)).unwrap();
        std::fs::write(cut.join(STAGING).join("c.txt"), "c").unwrap();
        std::fs::write(cut.join(LAYOUT), "").unwrap();
        migrate_workspace(&cut, "operator", &elsewhere).unwrap();
        assert!(cut.join("users/operator/c.txt").is_file() && !cut.join(STAGING).exists());
        assert_eq!(std::fs::read_to_string(cut.join(LAYOUT)).unwrap().trim(), DONE);
        let cut = crate::db::temp_path("ws-cut-done");
        std::fs::write(cut.join(LAYOUT), "").unwrap();
        std::fs::write(cut.join("later.md"), "x").unwrap();
        assert_eq!(migrate_workspace(&cut, "operator", &elsewhere).unwrap(), 0);
        assert!(cut.join("later.md").is_file(), "nothing staged: the move had finished");
        assert_eq!(std::fs::read_to_string(cut.join(LAYOUT)).unwrap().trim(), DONE);

        let fresh = crate::db::temp_path("ws-fresh");
        assert_eq!(migrate_workspace(&fresh, "operator", &elsewhere).unwrap(), 0);
        assert!(fresh.join(LAYOUT).is_file() && !fresh.join("users/operator").exists(), "nothing to move");
    }

    #[test]
    fn the_data_folder_never_moves() {
        let root = crate::db::temp_path("ws-data-inside");
        let data = root.join("state/data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("app.sqlite"), "db").unwrap();
        std::fs::write(root.join("notes.md"), "hi").unwrap();
        assert_eq!(migrate_workspace(&root, "operator", &data).unwrap(), 1);
        assert!(data.join("app.sqlite").is_file(), "the folder holding DATA_DIR stays put");
        assert!(root.join("users/operator/notes.md").is_file());

        let same = crate::db::temp_path("ws-data-same");
        std::fs::write(same.join("app.sqlite"), "db").unwrap();
        assert_eq!(migrate_workspace(&same, "operator", &same).unwrap(), 0);
        assert!(same.join("app.sqlite").is_file() && !same.join(LAYOUT).exists(), "DATA_DIR as the workspace: nothing moves");
    }

    #[test]
    fn links_planted_in_the_old_workspace_are_never_followed() {
        use std::os::unix::fs::symlink;
        let root = crate::db::temp_path("ws-links");
        let data = crate::db::temp_path("ws-links-data");
        std::fs::write(data.join("app.sqlite"), "db").unwrap();
        std::fs::write(root.join("notes.md"), "hi").unwrap();
        symlink(data.join("app.sqlite"), root.join(LAYOUT_TMP)).unwrap();
        symlink(&data, root.join(STAGING)).unwrap();
        assert_eq!(migrate_workspace(&root, "operator", &data).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(data.join("app.sqlite")).unwrap(), "db", "the database is untouched");
        assert!(!data.join("notes.md").exists(), "nothing moved into DATA_DIR");
        let owner = root.join("users/operator");
        assert!(!std::fs::symlink_metadata(&owner).unwrap().file_type().is_symlink() && owner.join("notes.md").is_file());
        assert_eq!(std::fs::read_to_string(root.join(LAYOUT)).unwrap().trim(), DONE);
        assert!(!root.join(LAYOUT_TMP).exists());

        let root = crate::db::temp_path("ws-link-marker");
        std::fs::write(data.join("fake"), "per-user 1\n").unwrap();
        std::fs::write(root.join("notes.md"), "hi").unwrap();
        symlink(data.join("fake"), root.join(LAYOUT)).unwrap();
        assert_eq!(migrate_workspace(&root, "operator", &data).unwrap(), 1, "a linked marker doesn't count");
        assert_eq!(std::fs::read_to_string(data.join("fake")).unwrap(), "per-user 1\n");
    }

    #[test]
    fn the_shared_user_file_moves_to_the_owner() {
        let data = crate::db::temp_path("user-file");
        std::fs::write(data.join("USER.md"), "# About the user\n- Name: Ada\n").unwrap();
        assert!(migrate_user_file(&data, "operator").unwrap());
        assert!(!data.join("USER.md").exists());
        assert!(std::fs::read_to_string(data.join("users/operator/USER.md")).unwrap().contains("Ada"));
        assert!(!migrate_user_file(&data, "operator").unwrap());
    }
}
