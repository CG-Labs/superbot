//! Deleting old harness session files and archived teammates' work (ADR 0112). Shared by
//! botd, `botctl sweep` (run as a per-user account through `superbot-run`) and the
//! machine agent, so it uses nothing of botd's.
//!
//! A session is every entry in a session folder whose name holds the same UUID (Claude
//! Code's `<id>.jsonl` and `<id>/`, Codex's `rollout-<time>-<id>.jsonl` and its `.zst`,
//! Pi's `<time>_s-<id>.jsonl`). It goes whole, once everything in it last changed before
//! the cutoff; a name without a UUID (Claude Code's `memory/`) is never touched.
//!
//! Bots can change these folders while they're swept, and the agent sweeps as root, so
//! each folder is opened from its already-open parent refusing links (`walk::Dir`) and
//! each name is removed relative to it: a folder swapped for a link can't lead the sweep
//! outside, and a link is removed as itself, never followed.

// Shared by three binaries, each of which uses only part of it.
#![allow(dead_code)]

use crate::walk::Dir;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};

/// Entries one sweep looks at, at most; past it, the rest wait for the next pass.
pub const MAX_ENTRIES: u64 = 500_000;
/// Errors a reply names, at most.
const MAX_ERRORS: usize = 5;

/// What to delete.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sweep {
    /// Unix ms: a session whose files all last changed before this goes.
    pub before: i64,
    #[serde(default)]
    pub roots: Vec<Root>,
    /// Sessions that stay whatever their age (a held or running Bot's), by id.
    #[serde(default)]
    pub keep: Vec<String>,
    /// Set: only sessions one of these ids names may go; the rest stay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only: Option<Vec<String>>,
    /// Of these session ids, `Swept::gone` says which went.
    #[serde(default)]
    pub report: Vec<String>,
    /// Folders to delete whole, whatever their age.
    #[serde(default)]
    pub folders: Vec<Folder>,
}

/// A folder of sessions: `path` under `base`, with sessions `depth` folders down
/// (Claude Code's `.claude/projects/<project>/<session>` is 2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    /// A folder the caller trusts: a HOME, a Bot's state folder.
    pub base: String,
    /// Plain names under `base`, joined with `/`.
    pub path: String,
    pub depth: u32,
    /// It holds the sessions' transcripts: only a session deleted here counts as gone in
    /// `Swept::gone`, not one whose side files elsewhere went while its transcript stays.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transcript: bool,
}

/// A folder to delete: `path` under `base`, as for `Root`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Folder {
    pub base: String,
    pub path: String,
}

/// What a sweep did.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Swept {
    /// Sessions deleted.
    pub sessions: u64,
    /// Files (and links) deleted, in sessions and folders.
    pub files: u64,
    pub bytes: u64,
    /// Of `Sweep::folders`, those deleted.
    pub folders: u64,
    /// Of `Sweep::folders`, those that weren't there.
    #[serde(default)]
    pub missing: u64,
    /// Of `Sweep::report`, the ids whose sessions went.
    #[serde(default)]
    pub gone: Vec<String>,
    /// Things it couldn't read or delete: they stay until a later pass.
    #[serde(default)]
    pub errors: Vec<String>,
    /// It stopped at `MAX_ENTRIES`, or couldn't read everything.
    #[serde(default)]
    pub partial: bool,
}

impl Swept {
    fn error(&mut self, e: String) {
        self.partial = true;
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(e);
        }
    }

    /// Adds another sweep's counts to these.
    pub fn add(&mut self, o: Swept) {
        self.sessions += o.sessions;
        self.files += o.files;
        self.bytes += o.bytes;
        self.folders += o.folders;
        self.missing += o.missing;
        self.partial |= o.partial;
        for g in o.gone {
            if !self.gone.contains(&g) {
                self.gone.push(g);
            }
        }
        for e in o.errors {
            if self.errors.len() < MAX_ERRORS {
                self.errors.push(e);
            }
        }
    }
}

/// Whether `p` is plain names joined with `/`: no `.`, `..`, empty or absolute parts.
pub fn plain_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 1024
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != ".." && s.len() <= 255 && !s.contains('\0') && !s.contains('\\'))
}

/// The UUIDs (8-4-4-4-12 hex digits) in `s`, lowercased, in order.
pub fn uuids(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 36 <= b.len() {
        let w = &b[i..i + 36];
        let ok = w.iter().enumerate().all(|(j, c)| if matches!(j, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() });
        if ok {
            out.push(String::from_utf8_lossy(w).to_ascii_lowercase());
            i += 36;
        } else {
            i += 1;
        }
    }
    out
}

/// Runs a sweep. Blocking.
pub fn run(s: &Sweep) -> Swept {
    let mut out = Swept::default();
    let mut budget = MAX_ENTRIES;
    let ids = |v: &[String]| v.iter().flat_map(|id| uuids(id)).collect::<Vec<_>>();
    let mut rules = Rules {
        transcript: false,
        before: s.before,
        keep: ids(&s.keep),
        only: s.only.as_deref().map(ids),
        report: s.report.iter().filter_map(|id| Some((uuids(id).into_iter().next()?, id.clone()))).collect(),
    };
    for r in &s.roots {
        if r.depth == 0 || r.depth > 8 {
            out.error(format!("{}: a session folder's depth is 1 to 8", r.path));
            continue;
        }
        match open(&r.base, &r.path) {
            Ok(Some(dir)) => {
                rules.transcript = r.transcript;
                sweep_dir(&dir, r.depth, &rules, &mut budget, &mut out)
            }
            Ok(None) => {}
            Err(e) => out.error(format!("{}: {e}", r.path)),
        }
    }
    for f in &s.folders {
        delete_folder(f, &mut budget, &mut out);
    }
    out
}

struct Rules {
    /// The root being swept holds transcripts.
    transcript: bool,
    before: i64,
    keep: Vec<String>,
    only: Option<Vec<String>>,
    /// The UUID of each id to report, and the id.
    report: Vec<(String, String)>,
}

impl Rules {
    fn may_go(&self, ids: &[String]) -> bool {
        !ids.iter().any(|i| self.keep.contains(i)) && self.only.as_ref().is_none_or(|o| ids.iter().any(|i| o.contains(i)))
    }
}

fn cstr(name: &str) -> std::io::Result<CString> {
    CString::new(name).map_err(|_| std::io::Error::other("a name with a NUL in it"))
}

/// Opens `path` under `base`, one name at a time. None: it isn't there.
fn open(base: &str, path: &str) -> std::io::Result<Option<Dir>> {
    if !base.starts_with('/') || !plain_path(path) {
        return Err(std::io::Error::other("not a plain path under an absolute folder"));
    }
    let mut dir = match Dir::open(std::path::Path::new(base)) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for part in path.split('/') {
        dir = match dir.child(&cstr(part)?) {
            Ok(d) => d,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
    }
    Ok(Some(dir))
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn mtime_ms(st: &libc::stat) -> i64 {
    #[allow(clippy::unnecessary_cast)]
    let (s, ns) = (st.st_mtime as i64, st.st_mtime_nsec as i64);
    s.saturating_mul(1000).saturating_add(ns / 1_000_000)
}

/// Lists `dir`, taking from the budget. None: it couldn't, and said so.
fn list(dir: &Dir, what: &str, budget: &mut u64, out: &mut Swept) -> Option<Vec<(CString, Option<libc::stat>)>> {
    if *budget == 0 {
        out.partial = true;
        return None;
    }
    match dir.entries(*budget) {
        Ok(e) => {
            *budget = budget.saturating_sub(e.len() as u64);
            if *budget == 0 {
                out.partial = true;
            }
            Some(e)
        }
        Err(e) => {
            out.error(format!("{what}: {e}"));
            None
        }
    }
}

/// Sweeps sessions `depth` folders down; folders it empties on the way go too.
fn sweep_dir(dir: &Dir, depth: u32, rules: &Rules, budget: &mut u64, out: &mut Swept) {
    let Some(entries) = list(dir, "a session folder", budget, out) else { return };
    if depth > 1 {
        for (name, st) in entries {
            if !st.is_some_and(|st| is_dir(&st)) {
                continue;
            }
            let Ok(child) = dir.child(&name) else { continue };
            let before = out.sessions;
            sweep_dir(&child, depth - 1, rules, budget, out);
            drop(child);
            // Only a folder this sweep emptied; ENOTEMPTY leaves it.
            if out.sessions > before {
                let _ = dir.remove(&name, true);
            }
        }
        return;
    }
    // Group by the first UUID in each name.
    let mut sessions: Vec<(String, Vec<(CString, libc::stat)>)> = Vec::new();
    for (name, st) in entries {
        let Some(st) = st else { continue };
        let Some(first) = uuids(&name.to_string_lossy()).into_iter().next() else { continue };
        match sessions.iter_mut().find(|(k, _)| *k == first) {
            Some((_, v)) => v.push((name, st)),
            None => sessions.push((first, vec![(name, st)])),
        }
    }
    for (key, parts) in sessions {
        let names: Vec<String> = parts.iter().flat_map(|(n, _)| uuids(&n.to_string_lossy())).collect();
        if !rules.may_go(&names) {
            continue;
        }
        // The newest change anywhere in it, or None when some of it couldn't be read.
        let mut newest = i64::MIN;
        let mut readable = true;
        for (name, st) in &parts {
            newest = newest.max(mtime_ms(st));
            if is_dir(st) {
                match dir.child(name).ok().and_then(|d| newest_in(&d, budget, 6)) {
                    Some(n) => newest = newest.max(n),
                    None => readable = false,
                }
            }
        }
        if !readable {
            out.error(format!("session {key}: couldn't read all of it"));
            continue;
        }
        if newest >= rules.before {
            continue;
        }
        let mut whole = true;
        for (name, st) in &parts {
            let gone = if is_dir(st) { remove_tree(dir, name, budget, out) } else { remove_file(dir, name, st, out) };
            whole &= gone;
        }
        if whole {
            out.sessions += 1;
            for (uuid, id) in rules.report.iter().filter(|_| rules.transcript) {
                if names.contains(uuid) && !out.gone.contains(id) {
                    out.gone.push(id.clone());
                }
            }
        }
    }
}

/// The newest change in `dir` and everything under it, `depth` folders down at most.
/// None: some of it couldn't be read, or it is deeper or bigger than allowed.
fn newest_in(dir: &Dir, budget: &mut u64, depth: u32) -> Option<i64> {
    if depth == 0 || *budget == 0 {
        return None;
    }
    let entries = dir.entries(*budget).ok()?;
    *budget = budget.saturating_sub(entries.len() as u64);
    let mut newest = i64::MIN;
    for (name, st) in entries {
        let st = st?;
        newest = newest.max(mtime_ms(&st));
        if is_dir(&st) {
            newest = newest.max(newest_in(&dir.child(&name).ok()?, budget, depth - 1)?);
        }
    }
    Some(newest)
}

fn remove_file(dir: &Dir, name: &CStr, st: &libc::stat, out: &mut Swept) -> bool {
    match dir.remove(name, false) {
        Ok(()) => {
            out.files += 1;
            if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                out.bytes += st.st_size.max(0) as u64;
            }
            true
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => true,
        Err(e) => {
            out.error(format!("{}: {e}", name.to_string_lossy()));
            false
        }
    }
}

/// Deletes the folder `name` in `parent` and everything in it. Whether it's gone.
fn remove_tree(parent: &Dir, name: &CStr, budget: &mut u64, out: &mut Swept) -> bool {
    let dir = match parent.child(name) {
        Ok(d) => d,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return true,
        Err(e) => {
            out.error(format!("{}: {e}", name.to_string_lossy()));
            return false;
        }
    };
    let Some(entries) = list(&dir, &name.to_string_lossy(), budget, out) else { return false };
    let mut all = true;
    for (child, st) in entries {
        all &= match st {
            Some(st) if is_dir(&st) => remove_tree(&dir, &child, budget, out),
            Some(st) => remove_file(&dir, &child, &st, out),
            None => false,
        };
    }
    drop(dir);
    if !all {
        return false;
    }
    match parent.remove(name, true) {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => true,
        Err(e) => {
            out.error(format!("{}: {e}", name.to_string_lossy()));
            false
        }
    }
}

fn delete_folder(f: &Folder, budget: &mut u64, out: &mut Swept) {
    let (opened, last) = match f.path.rsplit_once('/') {
        Some((parent, last)) => (open(&f.base, parent), last),
        None => (open_base(&f.base), f.path.as_str()),
    };
    let dir = match opened {
        Ok(Some(d)) if plain_path(last) => d,
        Ok(None) => {
            out.missing += 1;
            return;
        }
        Ok(Some(_)) => return out.error(format!("{}: not a plain path", f.path)),
        Err(e) => return out.error(format!("{}: {e}", f.path)),
    };
    let Ok(name) = cstr(last) else { return out.error(format!("{}: not a plain path", f.path)) };
    match dir.child(&name) {
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => out.missing += 1,
        Err(e) => out.error(format!("{}: {e}", f.path)),
        Ok(_) => {
            if remove_tree(&dir, &name, budget, out) {
                out.folders += 1;
            }
        }
    }
}

fn open_base(base: &str) -> std::io::Result<Option<Dir>> {
    if !base.starts_with('/') {
        return Err(std::io::Error::other("not an absolute folder"));
    }
    match Dir::open(std::path::Path::new(base)) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const A: &str = "0b9d2f6e-3c1a-4e8b-9f00-1a2b3c4d5e6f";
    const B: &str = "1c8e3a7f-4d2b-4f9c-8e11-2b3c4d5e6f70";
    const C: &str = "2d7f4b80-5e3c-4a0d-9f22-3c4d5e6f7081";
    const DAY: i64 = 86_400_000;

    fn temp(name: &str) -> PathBuf {
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let p = std::env::temp_dir().join(format!("superbot-sweep-{name}-{}-{at}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn now() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
    }

    /// Writes `path` and sets its last change `days` ago.
    fn file(path: &Path, days: i64) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x".repeat(10)).unwrap();
        age(path, days);
    }

    fn age(path: &Path, days: i64) {
        let at = std::time::SystemTime::now() - std::time::Duration::from_millis((days * DAY) as u64);
        std::fs::File::open(path).unwrap().set_modified(at).unwrap();
    }

    fn root(base: &Path, path: &str, depth: u32) -> Root {
        Root { base: base.display().to_string(), path: path.into(), depth, transcript: path != ".claude/debug" }
    }

    #[test]
    fn finds_uuids() {
        assert_eq!(uuids(&format!("rollout-2026-01-02T03-04-05-{A}.jsonl.zst")), [A]);
        assert_eq!(uuids(&format!("{}_{}", A.to_uppercase(), B)), [A, B]);
        assert_eq!(uuids(&format!("s-{A}")), [A]);
        assert!(uuids("memory").is_empty() && uuids("0b9d2f6e-3c1a-4e8b-9f00-1a2b3c4d5e6").is_empty());
        assert!(plain_path(".claude/projects") && !plain_path("../x") && !plain_path("/etc") && !plain_path("a//b") && !plain_path(""));
    }

    #[test]
    fn old_sessions_go_whole_and_nothing_else_does() {
        let home = temp("claude");
        let proj = home.join(".claude/projects/-work-u1");
        // A: old, with its folder of subagents: goes whole.
        file(&proj.join(format!("{A}.jsonl")), 40);
        file(&proj.join(format!("{A}/subagents/agent-1.jsonl")), 40);
        age(&proj.join(format!("{A}/subagents")), 40);
        age(&proj.join(A), 40);
        // B: old transcript, but a tool result written yesterday: stays whole.
        file(&proj.join(format!("{B}.jsonl")), 40);
        file(&proj.join(format!("{B}/tool-results/r1.txt")), 1);
        // C: recent. Auto memory and other names without a UUID are never touched.
        file(&proj.join(format!("{C}.jsonl")), 2);
        file(&proj.join("memory/MEMORY.md"), 400);
        file(&home.join(".claude/projects/-work-u2/notes.txt"), 400);
        let s = Sweep { before: now() - 30 * DAY, roots: vec![root(&home, ".claude/projects", 2)], report: vec![A.into(), B.into()], ..Default::default() };
        let out = run(&s);
        assert_eq!((out.sessions, out.files, out.bytes, out.gone.clone(), out.partial), (1, 2, 20, vec![A.to_string()], false), "{out:?}");
        assert!(!proj.join(format!("{A}.jsonl")).exists() && !proj.join(A).exists());
        for kept in [format!("{B}.jsonl"), format!("{B}/tool-results/r1.txt"), format!("{C}.jsonl"), "memory/MEMORY.md".into()] {
            assert!(proj.join(&kept).exists(), "{kept}");
        }
        // C's old debug log goes, but C isn't gone: its transcript is recent.
        file(&home.join(format!(".claude/debug/{C}.txt")), 40);
        let debug = run(&Sweep { before: now() - 30 * DAY, roots: vec![root(&home, ".claude/debug", 1)], report: vec![C.into()], ..Default::default() });
        assert_eq!((debug.sessions, debug.gone.len()), (1, 0), "{debug:?}");
        // A root that isn't there is nothing.
        let none = run(&Sweep { roots: vec![root(&home, ".codex/sessions", 4)], before: now(), ..Default::default() });
        assert_eq!(none, Swept::default());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn kept_and_only_ids_and_emptied_folders() {
        let home = temp("codex");
        let day = home.join(".codex/sessions/2026/01/02");
        file(&day.join(format!("rollout-2026-01-02T03-04-05-{A}.jsonl")), 90);
        file(&day.join(format!("rollout-2026-01-02T03-04-05-{A}.jsonl.zst")), 90);
        let other = home.join(".codex/sessions/2026/02/03");
        file(&other.join(format!("rollout-2026-02-03T03-04-05-{B}.jsonl")), 90);
        file(&other.join(format!("rollout-2026-02-03T03-04-05-{C}.jsonl")), 90);
        let roots = vec![root(&home, ".codex/sessions", 4)];
        // Only A's may go, and C is kept: B isn't named, so it stays too.
        let out = run(&Sweep { before: now() - DAY, roots: roots.clone(), keep: vec![format!("s-{C}")], only: Some(vec![A.into(), C.into()]), ..Default::default() });
        assert_eq!((out.sessions, out.files), (1, 2), "{out:?}");
        assert!(!home.join(".codex/sessions/2026/01").exists(), "the folders it emptied went");
        assert!(other.join(format!("rollout-2026-02-03T03-04-05-{B}.jsonl")).exists() && other.join(format!("rollout-2026-02-03T03-04-05-{C}.jsonl")).exists());
        // Without `only`, everything not kept goes; the root itself stays.
        let out = run(&Sweep { before: now() - DAY, roots, keep: vec![C.into()], ..Default::default() });
        assert_eq!(out.sessions, 1, "{out:?}");
        assert!(other.join(format!("rollout-2026-02-03T03-04-05-{C}.jsonl")).exists());
        assert!(home.join(".codex/sessions").is_dir());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn links_are_removed_as_links_and_never_followed() {
        let home = temp("links");
        let theirs = temp("links-theirs");
        file(&theirs.join("precious.txt"), 400);
        file(&theirs.join(format!("{B}.jsonl")), 400);
        let pi = home.join("bots/b1/pi-sessions");
        std::fs::create_dir_all(&pi).unwrap();
        // A session folder that is a link to someone else's files, and a session that is one.
        std::os::unix::fs::symlink(&theirs, pi.join(A)).unwrap();
        std::os::unix::fs::symlink(&theirs, home.join("bots/b2")).unwrap();
        let out = run(&Sweep {
            before: now() + DAY,
            roots: vec![root(&home, "bots/b1/pi-sessions", 1), root(&home, "bots/b2", 1)],
            folders: vec![Folder { base: home.display().to_string(), path: "bots/b2/x".into() }],
            ..Default::default()
        });
        assert_eq!((out.sessions, out.files), (1, 1), "{out:?}");
        assert!(std::fs::symlink_metadata(pi.join(A)).is_err(), "the link went");
        assert!(theirs.join("precious.txt").exists() && theirs.join(format!("{B}.jsonl")).exists(), "what it pointed at didn't");
        assert!(out.partial, "a root through a link is refused: {out:?}");
        // Paths that aren't plain are refused.
        let bad = run(&Sweep { before: now(), roots: vec![root(&home, "../x", 1)], folders: vec![Folder { base: "relative".into(), path: "a".into() }], ..Default::default() });
        assert_eq!((bad.errors.len(), bad.files), (2, 0), "{bad:?}");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&theirs);
    }

    #[test]
    fn folders_go_whole() {
        let home = temp("folders");
        let archive = home.join("work/from-teammates/bea-2026-01-02");
        file(&archive.join("notes.txt"), 0);
        file(&archive.join("deep/er/plan.md"), 0);
        let f = |p: &str| Folder { base: home.display().to_string(), path: p.into() };
        let out = run(&Sweep { folders: vec![f("work/from-teammates/bea-2026-01-02"), f("work/from-teammates/gone")], ..Default::default() });
        assert_eq!((out.folders, out.missing, out.files, out.partial), (1, 1, 2, false), "{out:?}");
        assert!(!archive.exists() && home.join("work/from-teammates").is_dir());
        let _ = std::fs::remove_dir_all(&home);
    }
}
