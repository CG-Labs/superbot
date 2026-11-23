//! OCI image layouts on disk: `oci-layout`, `index.json`, `blobs/sha256/<hex>`.
//! In a `signatures/` layout, each `index.json` entry says what it is in `dev.superbot.oci.role`:
//! `index` (the signed index the image came from), `attestation` (an attestation manifest that
//! index lists for the image), `referrer` (a signature or attestation whose `subject` is one of
//! those), or `tag` (a cosign tag, `sha256-<hex>.sig`, `.att` or `.sbom`, named by
//! `org.opencontainers.image.ref.name`).

use crate::{digest_ok, sha256_digest};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const ROLE: &str = "dev.superbot.oci.role";
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";

fn blob_path(dir: &Path, digest: &str) -> Result<PathBuf, String> {
    if !digest_ok(digest) {
        return Err(format!("{digest} isn't a sha256 digest"));
    }
    Ok(dir.join("blobs/sha256").join(&digest["sha256:".len()..]))
}

pub struct Writer {
    dir: PathBuf,
    entries: Vec<Value>,
}

impl Writer {
    /// A new layout in DIR, which must not exist yet or be empty.
    pub fn create(dir: &Path) -> Result<Writer, String> {
        if dir.exists() && std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.next().is_some() {
            return Err(format!("{} isn't empty", dir.display()));
        }
        std::fs::create_dir_all(dir.join("blobs/sha256")).map_err(|e| format!("{}: {e}", dir.display()))?;
        std::fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Writer { dir: dir.to_path_buf(), entries: Vec::new() })
    }

    pub fn blob_path(&self, digest: &str) -> Result<PathBuf, String> {
        blob_path(&self.dir, digest)
    }

    pub fn has(&self, digest: &str) -> bool {
        blob_path(&self.dir, digest).is_ok_and(|p| p.is_file())
    }

    pub fn put(&self, digest: &str, bytes: &[u8]) -> Result<(), String> {
        if sha256_digest(bytes) != digest {
            return Err(format!("refusing to store {} as {digest}", sha256_digest(bytes)));
        }
        let p = self.blob_path(digest)?;
        std::fs::write(&p, bytes).map_err(|e| format!("{}: {e}", p.display()))
    }

    /// Adds an `index.json` entry: DESCRIPTOR (media type, digest, size, and whatever else the
    /// registry said about it) with its role.
    pub fn add(&mut self, mut descriptor: Value, role: &str, tag: Option<&str>) {
        let a = descriptor.as_object_mut().expect("a descriptor").entry("annotations").or_insert_with(|| json!({}));
        a[ROLE] = json!(role);
        if let Some(t) = tag {
            a[REF_NAME] = json!(t);
        }
        self.entries.push(descriptor);
    }

    pub fn finish(self) -> Result<(), String> {
        let index = json!({ "schemaVersion": 2, "mediaType": crate::registry::OCI_INDEX, "manifests": self.entries });
        let p = self.dir.join("index.json");
        std::fs::write(&p, serde_json::to_vec(&index).expect("json")).map_err(|e| format!("{}: {e}", p.display()))
    }
}

pub struct Layout {
    pub dir: PathBuf,
    pub entries: Vec<Value>,
}

impl Layout {
    pub fn open(dir: &Path) -> Result<Layout, String> {
        let at = |f: &str| dir.join(f);
        let layout: Value = std::fs::read(at("oci-layout")).ok().and_then(|b| serde_json::from_slice(&b).ok()).ok_or(format!("{} isn't an OCI image layout", dir.display()))?;
        if layout["imageLayoutVersion"] != "1.0.0" {
            return Err(format!("{} isn't an OCI image layout 1.0.0", dir.display()));
        }
        let index: Value = std::fs::read(at("index.json"))
            .map_err(|e| format!("{}: {e}", at("index.json").display()))
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", at("index.json").display())))?;
        let entries = index["manifests"].as_array().cloned().ok_or(format!("{} lists no manifests", at("index.json").display()))?;
        for e in &entries {
            if !e["digest"].as_str().is_some_and(digest_ok) {
                return Err(format!("{} has an entry without a sha256 digest", at("index.json").display()));
            }
        }
        Ok(Layout { dir: dir.to_path_buf(), entries })
    }

    /// A blob that is there and has its digest.
    pub fn path(&self, digest: &str) -> Result<PathBuf, String> {
        let p = blob_path(&self.dir, digest)?;
        if !p.is_file() {
            return Err(format!("{} has no blob {digest}", self.dir.display()));
        }
        Ok(p)
    }

    /// A blob's bytes, checked against its digest.
    pub fn read(&self, digest: &str) -> Result<Vec<u8>, String> {
        let b = std::fs::read(self.path(digest)?).map_err(|e| e.to_string())?;
        if sha256_digest(&b) != digest {
            return Err(format!("{}'s blob {digest} doesn't match its digest", self.dir.display()));
        }
        Ok(b)
    }

    pub fn role(e: &Value) -> &str {
        e["annotations"][ROLE].as_str().unwrap_or_default()
    }

    pub fn digest(e: &Value) -> &str {
        e["digest"].as_str().unwrap_or_default()
    }
}
