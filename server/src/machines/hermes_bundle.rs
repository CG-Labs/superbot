//! Hermes bundles (ADR 0200) on users' machines (ADR 0210). botd reads each one it
//! serves at start, and an agent unpacks the one botd sends, with the checks
//! `deploy/install.sh` makes before it installs one on a server. Shared by the agent
//! binary and botd, so it uses nothing of botd's.
//!
//! A bundle is a gzipped tar of one `superbot-hermes-<tag>-<arch>/` folder holding
//! `MANIFEST`, `SHA256SUMS` and `hermes.tar`: Hermes Agent as its own installer left it
//! with HOME=/opt/hermes, in one `hermes/` folder. Its tree runs there and only there.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The largest bundle: a release's is about 1 GB.
pub const MAX_BUNDLE: u64 = 4 << 30;
/// The most a bundle's tree may unpack to: a release's is about 2.7 GB.
const MAX_TREE: u64 = 16 << 30;
/// The most files, folders and links in one tree.
const MAX_ENTRIES: usize = 2_000_000;
/// MANIFEST and SHA256SUMS are a few lines each.
const MAX_SMALL: u64 = 64 << 10;
/// Links followed resolving one link's target, as the kernel's limit.
const MAX_HOPS: usize = 40;
/// The folder everything in `hermes.tar` is in.
pub const TOP: &str = "hermes";
pub const ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// What a bundle's MANIFEST says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub tag: String,
    pub commit: String,
    /// Where its tree was installed, and so the only place it runs.
    pub prefix: String,
    pub arch: String,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, String> {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };
        if get("format") != "1" {
            return Err("its MANIFEST isn't format=1".into());
        }
        if get("kind") != "hermes" {
            return Err("its MANIFEST isn't a Hermes bundle's (kind=hermes)".into());
        }
        let commit = get("hermes_commit");
        if commit.len() != 40 || !commit.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(format!("hermes_commit \"{commit}\" isn't a full commit"));
        }
        let arch = get("arch");
        if !ARCHES.contains(&arch.as_str()) {
            return Err(format!("arch \"{arch}\" isn't x86_64 or aarch64"));
        }
        let prefix = get("prefix");
        if !prefix.starts_with('/') || prefix.len() < 2 || prefix.ends_with('/') || Path::new(&prefix).components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
            return Err(format!("prefix \"{prefix}\" isn't a folder"));
        }
        Ok(Manifest { tag: get("hermes_tag"), commit, prefix, arch })
    }
}

fn hex(d: impl AsRef<[u8]>) -> String {
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Hashes what is read through it.
struct Hashing<R> {
    inner: R,
    hash: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// `p` as a path in `hermes.tar` may be: `hermes`, or relative under it, with no `..`.
fn inside(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for (i, c) in p.components().enumerate() {
        match c {
            Component::Normal(s) if i > 0 || s == TOP => out.push(s),
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Reads the bundle at `file`, checking that it is one `superbot-hermes-*` folder of
/// `MANIFEST`, `SHA256SUMS` and `hermes.tar`, each file matching `SHA256SUMS`, and
/// `hermes.tar` holding only files, folders and links under `hermes/`, none setuid or
/// setgid, with hard links only to its own files. With `into` (an empty folder), it
/// also unpacks the tree there, as `into/hermes`. Answers its MANIFEST and the SHA-256
/// of the whole file. The symbolic links' targets are checked once unpacked
/// (`tree_ok`).
pub fn read(file: &Path, into: Option<&Path>) -> Result<(Manifest, String), String> {
    let f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let raw = Hashing { inner: io::BufReader::new(f), hash: Sha256::new() };
    let mut outer = tar::Archive::new(flate2::read::GzDecoder::new(raw));
    let not_one = || "it isn't a Hermes bundle (one superbot-hermes-* folder of plain files)".to_string();
    let mut top: Option<String> = None;
    let mut got: BTreeMap<String, String> = BTreeMap::new();
    let (mut manifest, mut sums) = (None, None);
    let entries = outer.entries().map_err(|e| format!("it can't be read: {e}"))?;
    for e in entries {
        let mut e = e.map_err(|e| format!("it can't be read: {e}"))?;
        let path = e.path().map_err(|_| not_one())?.into_owned();
        let parts: Vec<String> = path
            .components()
            .map(|c| match c {
                Component::Normal(s) => s.to_str().map(String::from).ok_or_else(not_one),
                _ => Err(not_one()),
            })
            .collect::<Result<_, _>>()?;
        let Some(first) = parts.first() else { return Err(not_one()) };
        if !first.starts_with("superbot-hermes-") || top.as_ref().is_some_and(|t| t != first) {
            return Err(not_one());
        }
        top = Some(first.clone());
        match (parts.len(), e.header().entry_type()) {
            (1, tar::EntryType::Directory) => continue,
            (2, tar::EntryType::Regular) => {}
            _ => return Err(not_one()),
        }
        let name = parts[1].clone();
        if got.contains_key(&name) {
            return Err(format!("it holds {name} twice"));
        }
        let sum = match name.as_str() {
            "hermes.tar" => {
                let mut h = Hashing { inner: &mut e, hash: Sha256::new() };
                unpack(&mut h, into).map_err(|e| format!("hermes.tar {e}"))?;
                io::copy(&mut h, &mut io::sink()).map_err(|e| format!("hermes.tar can't be read: {e}"))?;
                hex(h.hash.finalize())
            }
            "MANIFEST" | "SHA256SUMS" => {
                let mut b = Vec::new();
                (&mut e).take(MAX_SMALL + 1).read_to_end(&mut b).map_err(|e| format!("{name} can't be read: {e}"))?;
                if b.len() as u64 > MAX_SMALL {
                    return Err(format!("its {name} is over {} KiB", MAX_SMALL >> 10));
                }
                let sum = hex(Sha256::digest(&b));
                let text = String::from_utf8(b).map_err(|_| format!("its {name} isn't text"))?;
                if name == "MANIFEST" { manifest = Some(text) } else { sums = Some(text) }
                sum
            }
            _ => return Err(format!("it holds {name}, which a Hermes bundle doesn't")),
        };
        got.insert(name, sum);
    }
    let mut raw = outer.into_inner().into_inner();
    io::copy(&mut raw, &mut io::sink()).map_err(|e| format!("it can't be read: {e}"))?;
    let whole = hex(raw.hash.finalize());
    let sums = sums.ok_or("it has no SHA256SUMS")?;
    let manifest = manifest.ok_or("it has no MANIFEST")?;
    if !got.contains_key("hermes.tar") {
        return Err("it has no hermes.tar".into());
    }
    let mut listed = BTreeMap::new();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (sum, name) = line.split_once(char::is_whitespace).ok_or("its SHA256SUMS can't be read")?;
        let name = name.trim_start().trim_start_matches('*');
        listed.insert(name.to_string(), sum.to_string());
    }
    for (name, sum) in got.iter().filter(|(n, _)| *n != "SHA256SUMS") {
        match listed.remove(name) {
            Some(want) if want == *sum => {}
            Some(want) => return Err(format!("its {name} has SHA-256 {sum}, not the {want} its SHA256SUMS lists")),
            None => return Err(format!("its SHA256SUMS doesn't list {name}")),
        }
    }
    if let Some(name) = listed.keys().next() {
        return Err(format!("its SHA256SUMS lists {name}, which it doesn't hold"));
    }
    Ok((Manifest::parse(&manifest)?, whole))
}

/// Makes each folder of `rel` under `root` that is missing, and fails if one there
/// already is anything but a folder, so nothing is written through a link.
fn real_dirs(root: &Path, rel: &Path) -> io::Result<()> {
    let mut at = root.to_path_buf();
    for c in rel.components() {
        at.push(c);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => return Err(io::Error::other(format!("{} isn't a folder", rel.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::DirBuilder::new().mode(0o700).create(&at)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Checks each entry of `hermes.tar`, and with `into`, writes it there. Links are made
/// last, hard links first, so no path is ever resolved through a link this made; and
/// folders get their own modes once everything in them is written.
fn unpack(r: impl Read, into: Option<&Path>) -> Result<(), String> {
    let mut a = tar::Archive::new(r);
    let (mut hard, mut soft, mut dirs) = (Vec::new(), Vec::new(), Vec::new());
    let (mut size, mut count) = (0u64, 0usize);
    let failed = |e: io::Error| format!("can't be unpacked: {e}");
    for e in a.entries().map_err(|e| format!("can't be read: {e}"))? {
        let mut e = e.map_err(|e| format!("can't be read: {e}"))?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(format!("holds over {MAX_ENTRIES} entries"));
        }
        let path = e.path().map_err(|e| format!("can't be read: {e}"))?.into_owned();
        let rel = inside(&path).ok_or("holds files outside one hermes/ folder, or a path with ..")?;
        let mode = e.header().mode().map_err(|e| format!("can't be read: {e}"))?;
        if mode & 0o6000 != 0 {
            return Err(format!("holds a setuid or setgid file: {}", rel.display()));
        }
        let kind = e.header().entry_type();
        let link = match kind {
            tar::EntryType::Link | tar::EntryType::Symlink => {
                Some(e.link_name().map_err(|e| format!("can't be read: {e}"))?.ok_or("holds a link with no target")?.into_owned())
            }
            tar::EntryType::Regular | tar::EntryType::Directory => None,
            _ => return Err("holds devices, pipes or other special files".into()),
        };
        if kind == tar::EntryType::Link && link.as_deref().and_then(inside).is_none() {
            return Err(format!("holds a hard link to a file outside it: {}", rel.display()));
        }
        let Some(root) = into else { continue };
        let to = root.join(&rel);
        match kind {
            tar::EntryType::Directory => {
                real_dirs(root, &rel).map_err(failed)?;
                dirs.push((to, mode & 0o777));
            }
            tar::EntryType::Regular => {
                size += e.size();
                if size > MAX_TREE {
                    return Err(format!("unpacks to over {} GiB", MAX_TREE >> 30));
                }
                real_dirs(root, rel.parent().unwrap_or(Path::new(""))).map_err(failed)?;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode & 0o777).open(&to).map_err(failed)?;
                io::copy(&mut e, &mut f).map_err(failed)?;
                if let Ok(t) = e.header().mtime() {
                    let _ = f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t));
                }
            }
            tar::EntryType::Link => hard.push((rel, link.and_then(|l| inside(&l)).unwrap_or_default())),
            _ => soft.push((rel, link.unwrap_or_default())),
        }
    }
    if count == 0 {
        return Err("holds nothing".into());
    }
    let Some(root) = into else { return Ok(()) };
    for (rel, target) in hard {
        let from = root.join(&target);
        if !std::fs::symlink_metadata(&from).is_ok_and(|m| m.file_type().is_file()) {
            return Err(format!("holds a hard link {} to {}, which isn't a file before it", rel.display(), target.display()));
        }
        real_dirs(root, rel.parent().unwrap_or(Path::new(""))).map_err(failed)?;
        std::fs::hard_link(&from, root.join(&rel)).map_err(failed)?;
    }
    for (rel, target) in soft {
        real_dirs(root, rel.parent().unwrap_or(Path::new(""))).map_err(failed)?;
        std::os::unix::fs::symlink(&target, root.join(&rel)).map_err(failed)?;
    }
    for (d, mode) in dirs.iter().rev() {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(*mode)).map_err(failed)?;
    }
    Ok(())
}

/// Each entry under `dir` (not following links), with its path relative to `base`.
fn walk(base: &Path, dir: &Path, f: &mut dyn FnMut(&Path, &Path, &Metadata) -> Result<(), String>) -> Result<(), String> {
    let list = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in list {
        let p = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        let m = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let rel = p.strip_prefix(base).unwrap_or(&p).to_path_buf();
        f(&p, &rel, &m)?;
        if m.file_type().is_dir() {
            walk(base, &p, f)?;
        }
    }
    Ok(())
}

/// `t` as a path under `prefix`, if it is `prefix` or under it.
fn under<'a>(prefix: &str, t: &'a str) -> Option<&'a str> {
    if t == prefix {
        return Some("");
    }
    t.strip_prefix(prefix).filter(|r| r.starts_with('/'))
}

/// Whether the link target `target`, in folder `dir` of `root` (a tree to live at
/// `prefix`), stays inside it, following every link on the way as the kernel would
/// once the tree is at `prefix`: a link that is fine read alone (`b -> a/../x`) can
/// still leave through another (`a -> .`).
fn stays_inside(root: &Path, prefix: &str, dir: &[String], target: &str) -> bool {
    let split = |s: &str| s.split('/').map(String::from).collect::<Vec<_>>();
    let mut kept: Vec<String> = Vec::new();
    let mut todo: std::collections::VecDeque<String> = match target.strip_prefix('/') {
        Some(_) => match under(prefix, target) {
            Some(r) => split(r).into(),
            None => return false,
        },
        None => {
            kept = dir.to_vec();
            split(target).into()
        }
    };
    let mut hops = 0;
    while let Some(part) = todo.pop_front() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                if kept.pop().is_none() {
                    return false;
                }
                continue;
            }
            _ => {}
        }
        let next: PathBuf = kept.iter().chain([&part]).fold(root.to_path_buf(), |p, s| p.join(s));
        if std::fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink()) {
            hops += 1;
            let Some(t) = std::fs::read_link(&next).ok().and_then(|t| t.to_str().map(String::from)) else { return false };
            if hops > MAX_HOPS {
                return false;
            }
            let more = if t.starts_with('/') {
                let Some(r) = under(prefix, &t) else { return false };
                kept.clear();
                split(r)
            } else {
                split(&t)
            };
            for m in more.into_iter().rev() {
                todo.push_front(m);
            }
        } else {
            kept.push(part);
        }
    }
    true
}

/// `root`, a Hermes tree unpacked to live at `prefix`: files, folders and links only,
/// none setuid or setgid, and every link pointing inside it (absolute ones into
/// `prefix`), so nothing in it reaches the rest of the machine or a path from the one
/// that built it.
pub fn tree_ok(root: &Path, prefix: &str) -> Result<(), String> {
    walk(root, root, &mut |p, rel, m| {
        let t = m.file_type();
        if !(t.is_file() || t.is_dir() || t.is_symlink()) {
            return Err(format!("it holds a special file: {}", rel.display()));
        }
        if !t.is_symlink() && m.mode() & 0o6000 != 0 {
            return Err(format!("it holds a setuid or setgid file: {}", rel.display()));
        }
        if t.is_symlink() {
            let target = std::fs::read_link(p).map_err(|e| format!("{}: {e}", rel.display()))?;
            let target = target.to_str().ok_or(format!("the link {} has a target that isn't UTF-8", rel.display()))?;
            if target.contains('\n') {
                return Err(format!("the link {} has a newline in its target", rel.display()));
            }
            let dir: Vec<String> = rel.parent().map_or(vec![], |d| d.components().filter_map(|c| c.as_os_str().to_str().map(String::from)).collect());
            if !stays_inside(root, prefix, &dir, target) {
                return Err(format!("the link {} points outside {prefix}, to {target}", rel.display()));
            }
        }
        Ok(())
    })
}

fn chmod(p: &Path, m: &Metadata, mode: u32) -> Result<(), String> {
    if m.mode() & 0o7777 == mode {
        return Ok(());
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: {e}", p.display()))
}

/// Makes `root` writable by its owner only, and what other accounts run readable by
/// them: each folder in `readable` with everything in it, and the folders on the way
/// to those and to `bin`. Hermes writes some files every run reads as 0600, and its
/// own data root stays closed but for the way through it.
pub fn open_up(root: &Path, readable: &[String], bin: &str) -> Result<(), String> {
    walk(root, root, &mut |p, _, m| if m.file_type().is_symlink() { Ok(()) } else { chmod(p, m, m.mode() & 0o7777 & !0o022) })?;
    let meta = |p: &Path| std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()));
    chmod(root, &meta(root)?, 0o755)?;
    let mut ways: Vec<&Path> = Vec::new();
    for r in readable {
        let dir = root.join(r);
        if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_dir()) {
            continue;
        }
        chmod(&dir, &meta(&dir)?, meta(&dir)?.mode() & 0o7777 | 0o555)?;
        walk(&dir, &dir, &mut |p, _, m| {
            let mode = m.mode() & 0o7777;
            if m.file_type().is_dir() {
                chmod(p, m, mode | 0o555)
            } else if m.file_type().is_file() {
                chmod(p, m, mode | 0o444 | if mode & 0o111 != 0 { 0o111 } else { 0 })
            } else {
                Ok(())
            }
        })?;
        ways.extend(Path::new(r).ancestors().skip(1));
    }
    ways.extend(Path::new(bin).ancestors().skip(1));
    for w in ways.into_iter().filter(|w| !w.as_os_str().is_empty()) {
        let d = root.join(w);
        if std::fs::symlink_metadata(&d).is_ok_and(|m| m.file_type().is_dir()) {
            chmod(&d, &meta(&d)?, meta(&d)?.mode() & 0o7777 | 0o055)?;
        }
    }
    Ok(())
}

/// Bundles for tests, as `deploy/offline-bundle.sh hermes` packs them.
#[cfg(test)]
pub mod standin {
    use super::*;
    use std::io::Write;

    pub const COMMIT: &str = "caafe5389ae585ef77387a962aee05b1bcf17029";

    /// One entry of a stand-in `hermes.tar`.
    pub enum Item<'a> {
        Dir(&'a str, u32),
        File(&'a str, u32, &'a [u8]),
        Symlink(&'a str, &'a str),
        Hard(&'a str, &'a str),
        Fifo(&'a str),
    }

    /// Names are written as given, `..` and all, as a hostile tar would hold them.
    pub fn tar(items: &[Item]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for i in items {
            let mut h = tar::Header::new_gnu();
            h.set_mtime(1_700_000_000);
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(0);
            let (kind, path, mode, link, body): (_, &str, u32, &str, &[u8]) = match i {
                Item::Dir(p, mode) => (tar::EntryType::Directory, p, *mode, "", b""),
                Item::File(p, mode, body) => (tar::EntryType::Regular, p, *mode, "", body),
                Item::Symlink(p, t) => (tar::EntryType::Symlink, p, 0o777, t, b""),
                Item::Hard(p, t) => (tar::EntryType::Link, p, 0o644, t, b""),
                Item::Fifo(p) => (tar::EntryType::Fifo, p, 0o644, "", b""),
            };
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_size(body.len() as u64);
            let gnu = h.as_gnu_mut().unwrap();
            gnu.name[..path.len()].copy_from_slice(path.as_bytes());
            gnu.linkname[..link.len()].copy_from_slice(link.as_bytes());
            h.set_cksum();
            b.append(&h, body).unwrap();
        }
        b.into_inner().unwrap()
    }

    pub fn manifest(commit: &str, arch: &str, prefix: &str) -> String {
        format!("format=1\nkind=hermes\nhermes_tag=v0.23.3\nhermes_commit={commit}\nprefix={prefix}\narch={arch}\ncommit=unknown\n")
    }

    /// A bundle of `files` (name, body), with a SHA256SUMS of `listed` (or of all of
    /// them but itself).
    pub fn bundle(top: &str, files: &[(&str, Vec<u8>)], listed: Option<&str>) -> Vec<u8> {
        let sums = listed.map(String::from).unwrap_or_else(|| {
            files.iter().map(|(n, b)| format!("{}  {n}\n", hex(Sha256::digest(b)))).collect()
        });
        let mut all: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (n.to_string(), b.clone())).collect();
        all.push(("SHA256SUMS".into(), sums.into_bytes()));
        all.sort();
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, format!("{top}/"), io::empty()).unwrap();
        for (n, body) in all {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            b.append_data(&mut h, format!("{top}/{n}"), body.as_slice()).unwrap();
        }
        let mut gz = b.into_inner().unwrap();
        gz.flush().unwrap();
        gz.finish().unwrap()
    }

    /// A Hermes tree as the installer leaves it, in small: a checkout, an environment
    /// with absolute and relative links, a hard link, and Hermes's 0600 files.
    pub fn tree(bin: &str) -> Vec<u8> {
        tar(&[
            Item::Dir("hermes", 0o755),
            Item::Dir("hermes/.hermes", 0o700),
            Item::Dir("hermes/.hermes/hermes-agent", 0o755),
            Item::File("hermes/.hermes/hermes-agent/HEAD", 0o644, COMMIT.as_bytes()),
            Item::Dir("hermes/.hermes/installs", 0o700),
            Item::Dir("hermes/.hermes/installs/k", 0o700),
            Item::File("hermes/.hermes/installs/k/facts.json", 0o600, b"{\"environment\": \"/opt/hermes/.hermes/installs/k/env\"}"),
            Item::Dir("hermes/.hermes/superbot", 0o700),
            Item::File("hermes/.hermes/superbot/hermes", 0o755, bin.as_bytes()),
            Item::Dir("hermes/.local", 0o755),
            Item::Dir("hermes/.local/share", 0o755),
            Item::Dir("hermes/.local/share/uv", 0o700),
            Item::File("hermes/.local/share/uv/python3", 0o700, b"#!/bin/sh\n"),
            Item::Hard("hermes/.local/share/uv/python3.12", "hermes/.local/share/uv/python3"),
            Item::Symlink("hermes/.local/share/uv/python", "python3"),
            Item::Symlink("hermes/.hermes/installs/k/python", "/opt/hermes/.local/share/uv/python3"),
            Item::File("hermes/.hermes/state.db", 0o600, b"the install's own"),
        ])
    }

    pub fn good(arch: &str, bin: &str) -> Vec<u8> {
        bundle(
            &format!("superbot-hermes-v0.23.3-{arch}"),
            &[("MANIFEST", manifest(COMMIT, arch, "/opt/hermes").into_bytes()), ("hermes.tar", tree(bin))],
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::standin::*;
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("superbot-hb-{name}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn file(dir: &Path, body: &[u8]) -> PathBuf {
        let f = dir.join("bundle.tar.gz");
        std::fs::write(&f, body).unwrap();
        f
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn a_bundle_is_read_and_unpacked_as_it_was_packed() {
        let dir = temp("good");
        let body = good("x86_64", "#!/bin/sh\necho hermes\n");
        let f = file(&dir, &body);
        let (m, sha) = read(&f, None).unwrap();
        assert_eq!(m, Manifest { tag: "v0.23.3".into(), commit: COMMIT.into(), prefix: "/opt/hermes".into(), arch: "x86_64".into() });
        assert_eq!(sha, hex(Sha256::digest(&body)), "the SHA-256 of the whole file");
        assert!(!dir.join("hermes").exists(), "nothing is written without a folder");

        let into = dir.join("into");
        std::fs::create_dir(&into).unwrap();
        read(&f, Some(&into)).unwrap();
        let t = into.join("hermes");
        assert_eq!(std::fs::read(t.join(".hermes/superbot/hermes")).unwrap(), b"#!/bin/sh\necho hermes\n");
        assert_eq!(mode(&t.join(".hermes/installs/k/facts.json")), 0o600);
        assert_eq!(mode(&t.join(".hermes")), 0o700, "folders keep their modes");
        assert_eq!(std::fs::read_link(t.join(".local/share/uv/python")).unwrap(), Path::new("python3"));
        assert_eq!(std::fs::read_link(t.join(".hermes/installs/k/python")).unwrap(), Path::new("/opt/hermes/.local/share/uv/python3"));
        let ino = |p: &str| std::fs::metadata(t.join(p)).unwrap().ino();
        assert_eq!(ino(".local/share/uv/python3.12"), ino(".local/share/uv/python3"), "a hard link stays one");
        let mtime = std::fs::metadata(t.join(".hermes/state.db")).unwrap().mtime();
        assert_eq!(mtime, 1_700_000_000, "Hermes compares its stamps' times");
        tree_ok(&t, "/opt/hermes").unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bundles_that_arent_what_they_say_are_refused() {
        let dir = temp("bad");
        let top = "superbot-hermes-v0.23.3-x86_64";
        let m = || manifest(COMMIT, "x86_64", "/opt/hermes").into_bytes();
        let refused = |body: Vec<u8>, why: &str| {
            let f = file(&dir, &body);
            let err = read(&f, None).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
            let into = dir.join("into");
            let _ = std::fs::remove_dir_all(&into);
            std::fs::create_dir(&into).unwrap();
            assert!(read(&f, Some(&into)).is_err(), "{why}, unpacking");
        };
        let with = |items: &[Item]| bundle(top, &[("MANIFEST", m()), ("hermes.tar", tar(items))], None);
        let dir_ = Item::Dir("hermes", 0o755);
        refused(with(&[dir_, Item::File("hermes/x", 0o4755, b"")]), "setuid");
        refused(with(&[Item::Dir("hermes", 0o755), Item::File("hermes/x", 0o2755, b"")]), "setuid or setgid");
        refused(with(&[Item::Dir("hermes", 0o755), Item::Fifo("hermes/p")]), "special files");
        refused(with(&[Item::File("other/x", 0o644, b"")]), "outside one hermes/ folder");
        refused(with(&[Item::File("hermes/../x", 0o644, b"")]), "a path with ..");
        refused(with(&[Item::File("./hermes/x", 0o644, b"")]), "outside one hermes/ folder");
        refused(with(&[Item::Dir("hermes", 0o755), Item::Hard("hermes/x", "/etc/shadow")]), "hard link to a file outside");
        refused(with(&[Item::Dir("hermes", 0o755), Item::Hard("hermes/x", "hermes/../../etc/shadow")]), "hard link to a file outside");
        refused(with(&[]), "holds nothing");

        let changed = bundle(top, &[("MANIFEST", m()), ("hermes.tar", tree("a"))], Some(&format!("{}  hermes.tar\n{}  MANIFEST\n", "0".repeat(64), hex(Sha256::digest(m())))));
        refused(changed, "not the 0000");
        let tar_ = tree("a");
        refused(bundle(top, &[("MANIFEST", m()), ("hermes.tar", tar_.clone())], Some(&format!("{}  MANIFEST\n", hex(Sha256::digest(m()))))), "doesn't list hermes.tar");
        refused(bundle(top, &[("MANIFEST", m()), ("hermes.tar", tar_.clone()), ("extra", vec![])], None), "holds extra");
        refused(bundle(top, &[("MANIFEST", m())], None), "no hermes.tar");
        refused(bundle(top, &[("hermes.tar", tar_.clone())], None), "no MANIFEST");
        refused(bundle("superbot-v1-x86_64", &[("MANIFEST", m()), ("hermes.tar", tar_.clone())], None), "isn't a Hermes bundle");
        let kind = manifest(COMMIT, "x86_64", "/opt/hermes").replace("kind=hermes", "kind=superbot").into_bytes();
        refused(bundle(top, &[("MANIFEST", kind), ("hermes.tar", tar_.clone())], None), "kind=hermes");
        refused(bundle(top, &[("MANIFEST", manifest("main", "x86_64", "/opt/hermes").into_bytes()), ("hermes.tar", tar_.clone())], None), "isn't a full commit");
        refused(bundle(top, &[("MANIFEST", manifest(COMMIT, "riscv64", "/opt/hermes").into_bytes()), ("hermes.tar", tar_.clone())], None), "isn't x86_64 or aarch64");
        refused(bundle(top, &[("MANIFEST", manifest(COMMIT, "x86_64", "opt/hermes").into_bytes()), ("hermes.tar", tar_)], None), "isn't a folder");
        refused(b"not gzip".to_vec(), "can't be read");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unpacking_never_writes_through_a_link() {
        let dir = temp("through");
        let outside = dir.join("outside");
        std::fs::create_dir(&outside).unwrap();
        let top = "superbot-hermes-v0.23.3-x86_64";
        let m = manifest(COMMIT, "x86_64", "/opt/hermes").into_bytes();
        let out = outside.display().to_string();
        for items in [
            vec![Item::Dir("hermes", 0o755), Item::Symlink("hermes/a", &out), Item::Symlink("hermes/a/b", "x")],
            vec![Item::Dir("hermes", 0o755), Item::Symlink("hermes/a", &out), Item::File("hermes/a/b", 0o644, b"x")],
            vec![Item::Dir("hermes", 0o755), Item::Symlink("hermes/a", &out), Item::Hard("hermes/a/b", "hermes/c"), Item::File("hermes/c", 0o644, b"")],
        ] {
            let f = file(&dir, &bundle(top, &[("MANIFEST", m.clone()), ("hermes.tar", tar(&items))], None));
            let into = dir.join("into");
            let _ = std::fs::remove_dir_all(&into);
            std::fs::create_dir(&into).unwrap();
            let res = read(&f, Some(&into)).and_then(|_| tree_ok(&into.join("hermes"), "/opt/hermes"));
            assert!(res.is_err());
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing was written outside");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn every_link_must_stay_inside_the_prefix() {
        let dir = temp("links");
        let check = |links: &[(&str, &str)]| {
            let t = dir.join("hermes");
            let _ = std::fs::remove_dir_all(&t);
            std::fs::create_dir_all(t.join("a/b")).unwrap();
            std::fs::write(t.join("a/b/f"), "").unwrap();
            for (l, target) in links {
                std::os::unix::fs::symlink(target, t.join(l)).unwrap();
            }
            tree_ok(&t, "/opt/hermes")
        };
        for ok in [
            vec![("a/up", "../a/b/f")],
            vec![("abs", "/opt/hermes/a/b/f")],
            vec![("root", "/opt/hermes")],
            vec![("a/b/here", ".")],
            vec![("x", "a"), ("y", "x/b/f")],
        ] {
            check(&ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for (bad, why) in [
            (vec![("etc", "/etc")], "an absolute link out"),
            (vec![("a/b/out", "../../..")], "climbs out"),
            (vec![("other", "/opt/hermes2/x")], "another folder"),
            (vec![("dotdot", "/opt/hermes/../etc")], "out through the prefix's .."),
            (vec![("dot", "."), ("b", "dot/../x")], "out only through another link"),
            (vec![("a/abs", "/opt/hermes"), ("c", "a/abs/../x")], "out through an absolute link"),
            (vec![("l1", "l2"), ("l2", "l1")], "a loop"),
        ] {
            assert!(check(&bad).is_err(), "{why}");
        }
        let t = dir.join("hermes");
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        std::fs::write(t.join("s"), "").unwrap();
        std::fs::set_permissions(t.join("s"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(tree_ok(&t, "/opt/hermes").unwrap_err().contains("setuid"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn what_other_accounts_run_is_opened_to_them_and_nothing_else() {
        let dir = temp("open");
        let f = file(&dir, &good("x86_64", "#!/bin/sh\n"));
        let into = dir.join("into");
        std::fs::create_dir(&into).unwrap();
        read(&f, Some(&into)).unwrap();
        let t = into.join("hermes");
        std::fs::set_permissions(t.join(".local/share"), std::fs::Permissions::from_mode(0o777)).unwrap();
        open_up(&t, &[".hermes/installs".into(), ".local/share/uv".into(), ".hermes/tools".into()], ".hermes/superbot/hermes").unwrap();
        assert_eq!(mode(&t), 0o755);
        assert_eq!(mode(&t.join(".hermes")), 0o755, "the way through the data root");
        assert_eq!(mode(&t.join(".hermes/state.db")), 0o600, "but not what is in it");
        assert_eq!(mode(&t.join(".hermes/installs/k")), 0o755);
        assert_eq!(mode(&t.join(".hermes/installs/k/facts.json")), 0o644);
        assert_eq!(mode(&t.join(".local/share/uv/python3")), 0o755);
        assert_eq!(mode(&t.join(".local/share")), 0o755, "nothing stays writable by others");
        assert_eq!(mode(&t.join(".hermes/superbot")), 0o755, "the folder of the program Bots run");
        assert_eq!(mode(&t.join(".hermes/superbot/hermes")), 0o755);
        let _ = std::fs::remove_dir_all(dir);
    }
}
