//! Per-user isolation on one host (ADR 0029). A user's Bots share that user's folders
//! and secrets, and nobody else's: `WORKSPACE_DIR/users/<user>` is their working folder,
//! `DATA_DIR/users/<user>/USER.md` their facts. Each Bot run carries a token only that
//! Bot has, so a Bot can't claim to be another user's Bot. On managed hosting the same
//! split moves onto the user's own machine (`machines::route`).

use crate::paths;
use aws_lc_rs::hmac;
use std::io;
use std::path::{Path, PathBuf};

/// Starts every per-Bot token, so a leaked one is easy to spot and redact.
pub const BOT_TOKEN_PREFIX: &str = "sbb_";
/// The folder under each root that holds one folder per user.
pub const USERS: &str = "users";
/// Marks a workspace that has the per-user layout. Holds `moving` while it's being set up.
const LAYOUT: &str = ".superbot-layout";
/// Where an old shared workspace's files wait on their way to the owner's folder.
const STAGING: &str = ".superbot-owner-files";

fn signed(bot_id: &str, owner_id: &str) -> String {
    format!("superbot-bot-token/{bot_id}/{owner_id}")
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

/// The token one Bot's runs carry: `sbb_<bot id>.<owner id>.<HMAC-SHA256>`. `key` is
/// botd's, made fresh at each start, so every token dies with the process that issued
/// it. The owner is signed in, so a token stops working when the Bot changes hands.
pub fn bot_token(key: &str, bot_id: &str, owner_id: &str) -> String {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes()), signed(bot_id, owner_id).as_bytes());
    format!("{BOT_TOKEN_PREFIX}{bot_id}.{owner_id}.{}", hex(tag.as_ref()))
}

/// The Bot a token was issued to and its owner then, if botd issued it with this key.
/// Constant time in the MAC. The caller checks the Bot still exists and has that owner.
pub fn token_bot<'a>(key: &str, token: &'a str) -> Option<(&'a str, &'a str)> {
    let mut parts = token.strip_prefix(BOT_TOKEN_PREFIX)?.split('.');
    let (id, owner, tag) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || key.is_empty() || !plain_id(id) || !plain_id(owner) || tag.len() != 64 {
        return None;
    }
    let tag = unhex(tag)?;
    let k = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
    hmac::verify(&k, signed(id, owner).as_bytes(), &tag).ok().map(|_| (id, owner))
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
    let state = std::fs::read_to_string(&marker).ok();
    let mut moved = 0;
    if state.is_none() {
        let entries: Vec<_> = std::fs::read_dir(&root)?.collect::<io::Result<_>>()?;
        let entries: Vec<_> = entries.into_iter().filter(|e| !data.starts_with(e.path())).collect();
        let old = entries.iter().filter(|e| e.file_name() != STAGING).count();
        if old == 0 && !staging.exists() {
            std::fs::write(&marker, "per-user 1\n")?;
            return Ok(0);
        }
        std::fs::create_dir_all(&staging)?;
        for e in entries.into_iter().filter(|e| e.file_name() != STAGING) {
            std::fs::rename(e.path(), staging.join(e.file_name()))?;
            moved += 1;
        }
        std::fs::write(&marker, "moving\n")?;
    } else if state.as_deref().map(str::trim) != Some("moving") {
        return Ok(0);
    }
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
    std::fs::write(&marker, "per-user 1\n")?;
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
    fn bot_tokens_name_their_bot_and_nothing_else() {
        let key = crate::random_hex(24);
        let t = bot_token(&key, "b1", "u1");
        assert!(t.starts_with("sbb_b1.u1.") && t.len() == "sbb_b1.u1.".len() + 64, "{t}");
        assert_eq!(token_bot(&key, &t), Some(("b1", "u1")));
        assert_eq!(bot_token(&key, "b1", "u1"), t, "the same for every run of a Bot until botd restarts");
        assert_ne!(bot_token(&key, "b1", "u2"), t, "or until it changes hands");
        assert_eq!(token_bot(&crate::random_hex(24), &t), None, "another start's key");
        assert_eq!(token_bot("", &t), None);
        let mac = t.rsplit_once('.').unwrap().1;
        for forged in [
            format!("sbb_b2.u1.{mac}"),
            format!("sbb_b1.u2.{mac}"),
            format!("sbb_b1.{mac}"),
            format!("sbb_b1.u1.{}", "0".repeat(64)),
            format!("sbb_b1.u1.{}", &mac[..62]),
            format!("sbb_b1.u1.{}x", &mac[..63]),
            format!("sbb_b1/x.u1.{mac}"),
            format!("sbb_b1.u1.x.{mac}"),
            format!("sbb_.u1.{mac}"),
            t.replace("sbb_", "sbx_"),
            t.replace('.', ""),
        ] {
            assert_eq!(token_bot(&key, &forged), None, "{forged}");
        }
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
    fn the_shared_user_file_moves_to_the_owner() {
        let data = crate::db::temp_path("user-file");
        std::fs::write(data.join("USER.md"), "# About the user\n- Name: Ada\n").unwrap();
        assert!(migrate_user_file(&data, "operator").unwrap());
        assert!(!data.join("USER.md").exists());
        assert!(std::fs::read_to_string(data.join("users/operator/USER.md")).unwrap().contains("Ada"));
        assert!(!migrate_user_file(&data, "operator").unwrap());
    }
}
