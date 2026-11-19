//! The master key: 32 random bytes that seal the secrets botd keeps in SQLite.
//!
//! Comes from `SUPERBOT_MASTER_KEY` (64 hex characters or base64), or the file named by
//! `SUPERBOT_MASTER_KEY_FILE`, else `$XDG_CONFIG_HOME/superbot/master.key`
//! (`~/.config/superbot/master.key`). A key file must be readable by its owner only.
//! It never lives in `DATA_DIR`, so a database backup doesn't carry the key that opens it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(super::redact::MARK)
    }
}

impl MasterKey {
    pub fn generate() -> MasterKey {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut k = Zeroizing::new([0u8; 32]);
        chacha20poly1305::aead::OsRng.fill_bytes(&mut k[..]);
        MasterKey(k)
    }

    /// 64 hex characters, or base64 of 32 bytes (`openssl rand -base64 32`). Whitespace around it is ignored.
    pub fn parse(text: &str) -> Result<MasterKey, String> {
        let t = text.trim();
        let bytes = if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            Zeroizing::new((0..32).map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>())
        } else {
            Zeroizing::new(B64.decode(t).map_err(|_| "not hex or base64".to_string())?)
        };
        if bytes.len() != 32 {
            return Err("must be 32 bytes: 64 hex characters or base64 (openssl rand -base64 32)".into());
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&bytes);
        Ok(MasterKey(k))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base64(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(&self.0[..]))
    }

    /// The forms an operator might paste somewhere: base64 and hex.
    pub fn register_redactions(&self) {
        super::redact::register(&self.base64());
        let hex: Zeroizing<String> = Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect());
        super::redact::register(&hex);
    }
}

/// Reads a key file. Refuses one that group or others can read or write.
pub fn read_file(path: &Path) -> Result<MasterKey, String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a file"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{shown} must be readable by its owner only: chmod 600 {shown}"));
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?);
    MasterKey::parse(&text).map_err(|e| format!("{shown}: {e}"))
}

/// Makes a new key file (0600, folder 0700). Never replaces an existing file or follows a symlink.
pub fn write_new(path: &Path) -> Result<MasterKey, String> {
    let shown = path.display();
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let key = MasterKey::generate();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{shown}: {e}"))?;
    let line = Zeroizing::new(format!("{}\n", key.base64().as_str()));
    f.write_all(line.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("{shown}: {e}"))?;
    Ok(key)
}

fn var(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

pub fn default_path() -> Option<PathBuf> {
    let base = var("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| var("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("superbot").join("master.key"))
}

/// `path` with symlinks resolved as far as it exists.
fn resolve(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut at = path;
    loop {
        if let Ok(real) = std::fs::canonicalize(at) {
            return rest.iter().rev().fold(real, |p, part| p.join(part));
        }
        match (at.file_name(), at.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                at = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Refuses a key path inside `data_dir`: backups copy that folder, and must not carry the key.
fn check_outside(path: &Path, data_dir: &Path) -> Result<(), String> {
    let shown = path.display();
    if path.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(format!("{shown}: use a key path without '..'"));
    }
    let abs = |p: &Path| if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(p) };
    if resolve(&abs(path)).starts_with(resolve(&abs(data_dir))) {
        return Err(format!("{shown} is inside DATA_DIR ({}), which backups copy. Keep the master key elsewhere.", data_dir.display()));
    }
    Ok(())
}

/// Where the key file is, or would be created.
fn file_path(data_dir: &Path) -> Result<PathBuf, String> {
    let path = match var("SUPERBOT_MASTER_KEY_FILE") {
        Some(p) => PathBuf::from(p),
        None => default_path().ok_or("set SUPERBOT_MASTER_KEY_FILE (HOME is not set)")?,
    };
    check_outside(&path, data_dir)?;
    Ok(path)
}

/// The configured key and where it came from, or None if there is none yet.
pub fn locate(data_dir: &Path) -> Result<Option<(MasterKey, String)>, String> {
    if let Some(text) = var("SUPERBOT_MASTER_KEY") {
        if var("SUPERBOT_MASTER_KEY_FILE").is_some() {
            return Err("set SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE, not both".into());
        }
        let text = Zeroizing::new(text);
        return MasterKey::parse(&text).map(|k| Some((k, "SUPERBOT_MASTER_KEY".into()))).map_err(|e| format!("SUPERBOT_MASTER_KEY: {e}"));
    }
    let path = file_path(data_dir)?;
    // symlink_metadata: a dangling symlink still counts as "there", so it is never replaced.
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    read_file(&path).map(|k| Some((k, path.display().to_string())))
}

/// A new key at SUPERBOT_MASTER_KEY_FILE, or the default path.
pub fn create(data_dir: &Path) -> Result<(MasterKey, String), String> {
    let path = file_path(data_dir)?;
    write_new(&path).map(|k| (k, path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        crate::db::temp_path("key")
    }

    #[test]
    fn parses_hex_and_base64_only_of_32_bytes() {
        let k = MasterKey::generate();
        let hex: String = k.bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(MasterKey::parse(&format!(" {hex}\n")).unwrap().bytes(), k.bytes());
        assert_eq!(MasterKey::parse(&format!("{}\n", k.base64().as_str())).unwrap().bytes(), k.bytes());
        for bad in ["", "abc", &hex[..62], &B64.encode([1u8; 16]), "not base64 at all!!"] {
            assert!(MasterKey::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(format!("{k:?}"), "[redacted]");
    }

    #[test]
    fn new_key_files_are_private_and_never_replaced() {
        let path = dir().join("sub").join("master.key");
        let k = write_new(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(read_file(&path).unwrap().bytes(), k.bytes());
        assert!(write_new(&path).is_err(), "an existing key is never overwritten");
        assert_eq!(read_file(&path).unwrap().bytes(), k.bytes());

        let link = path.with_file_name("link.key");
        std::os::unix::fs::symlink(path.with_file_name("nowhere"), &link).unwrap();
        assert!(write_new(&link).is_err(), "a symlink is never followed when creating");
        assert!(!path.with_file_name("nowhere").exists());
    }

    #[test]
    fn keys_stay_out_of_the_data_dir() {
        let root = dir();
        let data = root.join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::os::unix::fs::symlink(&data, root.join("alias")).unwrap();
        for inside in [data.join("master.key"), data.join("new/master.key"), root.join("alias/master.key"), data.clone()] {
            assert!(check_outside(&inside, &data).is_err(), "{}", inside.display());
        }
        assert!(check_outside(&root.join("other/../data/master.key"), &data).is_err(), "'..' is refused");
        assert!(check_outside(&root.join("config/master.key"), &data).is_ok());
        assert!(check_outside(&root.join("data2/master.key"), &data).is_ok(), "a sibling with the same prefix is fine");
    }

    #[test]
    fn loose_permissions_are_refused() {
        let path = dir().join("master.key");
        write_new(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_file(&path).unwrap_err();
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_file(&path).is_ok());
    }
}
