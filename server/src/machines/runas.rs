//! The Bots' own OS user on a machine (ADR 0043). The agent stays root, for upgrades
//! and its key; everything a Bot can touch runs as an unprivileged user instead:
//! harnesses, logins and cleanups get its uid and gid, and every file the agent reads
//! or writes in the Bots' home goes through `as_user`, so a link a Bot left there can't
//! turn root's write into a write elsewhere, or root's read into a leak of the key.
//! Shared by the agent binary and botd's tests, so it uses nothing of botd's.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A user and group to run as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

/// An OS user name useradd takes: lower case, at most 32 bytes.
pub fn plain_user(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// `name`'s uid, gid and home, if the user exists.
pub fn lookup(name: &str) -> Option<(Ids, std::path::PathBuf)> {
    let c = CString::new(name).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 << 10];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the result points into `buf`.
    let r = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getpwnam_r succeeded, so pw_dir is a C string in `buf`.
    let home = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some((
        Ids {
            uid: pw.pw_uid,
            gid: pw.pw_gid,
        },
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes())),
    ))
}

/// The user this process runs as, by name: tests stand it in for the Bots' user.
pub fn current_user() -> Option<String> {
    // SAFETY: no arguments.
    name_of(unsafe { libc::geteuid() })
}

/// The name of the user with `uid`, if there is one.
pub fn name_of(uid: u32) -> Option<String> {
    // getpwuid's static storage is shared by every thread, so another lookup can change
    // the name while it's read; the _r form reads into a buffer of our own.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 << 10];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the result points into `buf`.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name is a C string in `buf`.
    Some(unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned())
}

/// For `pre_exec`, once a process is a Bot's or a teammate's user (ADR 0145): no
/// setuid program or file capability raises it again (sudo, su, pkexec, newgrp), and
/// what it makes, in /tmp too, is its own alone. Only async-signal-safe calls.
pub fn lock_down() -> io::Result<()> {
    // SAFETY: umask can't fail.
    unsafe { libc::umask(0o077) };
    no_new_privs()
}

/// The OOM score a Bot's or teammate's process starts at (ADR 0145): above the
/// agent's and the OS's daemons', so a machine short of memory loses a run first.
/// Set while root, it's also the lowest the run can take itself back down to.
pub const RUN_OOM_SCORE_ADJ: &[u8] = b"500";

/// For `pre_exec`, while still root: set the OOM score floor, then become `uid`/`gid`
/// with no other groups. Only async-signal-safe calls.
pub fn become_user(uid: u32, gid: u32) -> io::Result<()> {
    let last = io::Error::last_os_error;
    // SAFETY: plain syscalls on a static path, a static buffer and this process's ids.
    unsafe {
        let fd = libc::open(c"/proc/self/oom_score_adj".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(last());
        }
        let n = RUN_OOM_SCORE_ADJ.len();
        let wrote = libc::write(fd, RUN_OOM_SCORE_ADJ.as_ptr().cast(), n);
        libc::close(fd);
        if wrote != n as isize {
            return Err(last());
        }
        if (libc::geteuid() == 0 && libc::setgroups(0, std::ptr::null()) != 0)
            || libc::setgid(gid) != 0
            || libc::setuid(uid) != 0
        {
            return Err(last());
        }
    }
    Ok(())
}

/// `lock_down` without the umask, for programs that set their files' modes as they
/// need (X's sockets). Async-signal-safe.
pub fn no_new_privs() -> io::Result<()> {
    // SAFETY: a plain prctl on this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Groups that give root, or another user's files, one way or another: through sudo
/// or polkit (`sudo`, `wheel`, `admin`), a daemon's socket (`docker`, `lxd`, `incus`,
/// `libvirt`), raw disks, password hashes or every log. A Bot's or teammate's user is
/// in none of them.
pub const PRIVILEGED_GROUPS: [&str; 14] = [
    "root",
    "sudo",
    "wheel",
    "admin",
    "adm",
    "docker",
    "lxd",
    "incus",
    "incus-admin",
    "libvirt",
    "disk",
    "shadow",
    "systemd-journal",
    "staff",
];

/// Where sudo reads its rules.
const SUDOERS: &str = "/etc/sudoers";
const SUDOERS_D: &str = "/etc/sudoers.d";
const SUDO_BINS: [&str; 2] = ["/usr/bin/sudo", "/bin/sudo"];

/// Why `name` (with `ids`) isn't an unprivileged user, if it isn't: root's uid or
/// group, one of `PRIVILEGED_GROUPS`, or a sudo rule for it, one of its groups, or
/// everyone. Sudo itself is asked when it's installed (rules from any source it reads);
/// its files are read too, in case it can't answer.
pub fn privileged(name: &str, ids: Ids) -> Option<String> {
    let groups = group_list(name, ids.gid);
    let found = privileged_in(name, ids, &groups, &sudoers());
    if found.is_some() {
        return found;
    }
    sudo_allows(name).then(|| "has a sudo rule (sudo -l lists commands it may run)".into())
}

/// Whether `sudo -l -U name` says `name` may run anything. Needs root; false when sudo
/// isn't installed or doesn't answer.
fn sudo_allows(name: &str) -> bool {
    let Some(bin) = SUDO_BINS.iter().find(|b| Path::new(b).exists()) else { return false };
    std::process::Command::new(bin)
        .args(["-n", "-l", "-U", name])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("may run the following commands"))
}

/// Sudo's files: /etc/sudoers, /etc/sudoers.d, and whatever they include.
fn sudoers() -> Vec<(String, String)> {
    sudoers_from(vec![PathBuf::from(SUDOERS), PathBuf::from(SUDOERS_D)])
}

fn sudoers_from(mut todo: Vec<PathBuf>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    todo.reverse();
    while let Some(p) = todo.pop() {
        if out.len() >= 256 || out.iter().any(|(q, _)| Path::new(q) == p) {
            continue;
        }
        if p.is_dir() {
            let Ok(dir) = std::fs::read_dir(&p) else { continue };
            let mut files: Vec<_> = dir.flatten().map(|e| e.path()).collect();
            files.sort();
            // sudo skips files with a dot or ending in `~` in an included folder.
            todo.extend(files.into_iter().rev().filter(|f| {
                f.file_name().and_then(|n| n.to_str()).is_some_and(|n| !n.contains('.') && !n.ends_with('~'))
            }));
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let here = p.parent().unwrap_or(Path::new("/")).to_path_buf();
        for line in joined(&text) {
            let mut w = line.split_whitespace();
            if let (Some("@include" | "#include" | "@includedir" | "#includedir"), Some(to)) = (w.next(), w.next()) {
                let to = Path::new(to);
                todo.push(if to.is_absolute() { to.to_path_buf() } else { here.join(to) });
            }
        }
        out.push((p.display().to_string(), text));
    }
    out
}

/// A sudoers file's lines, with `\`-continued lines joined.
fn joined(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        match line.strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(line);
                out.push(std::mem::take(&mut cur).trim().to_string());
            }
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// A list's entries, with the spaces sudo allows around its commas.
fn list(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').map(str::trim).filter(|e| !e.is_empty())
}

/// `privileged`, given `name`'s groups (id, name) and sudo's files (path, text).
pub fn privileged_in(name: &str, ids: Ids, groups: &[(u32, String)], sudoers: &[(String, String)]) -> Option<String> {
    if ids.uid == 0 {
        return Some("is root".into());
    }
    if ids.gid == 0 || groups.iter().any(|(g, _)| *g == 0) {
        return Some("is in root's group".into());
    }
    if let Some((_, g)) = groups.iter().find(|(_, g)| PRIVILEGED_GROUPS.contains(&g.as_str())) {
        return Some(format!("is in the {g} group"));
    }
    let files: Vec<(&str, Vec<String>)> = sudoers.iter().map(|(p, t)| (p.as_str(), joined(t))).collect();
    // `User_Alias NAME = a, b : OTHER = c`, nested in any order: the aliases naming the
    // user count as it.
    let mut aliases: Vec<String> = Vec::new();
    let named = |who: &str, aliases: &[String]| {
        let who = who.trim();
        who == "ALL"
            || who == name
            || who == format!("#{}", ids.uid)
            || aliases.iter().any(|a| a == who)
            || who
                .strip_prefix('%')
                .map(|g| g.trim_start_matches(':'))
                .is_some_and(|g| groups.iter().any(|(id, n)| n == g || g == format!("#{id}")))
    };
    loop {
        let before = aliases.len();
        for line in files.iter().flat_map(|(_, l)| l) {
            let Some(defs) = line.strip_prefix("User_Alias") else { continue };
            for def in defs.split(':') {
                if let Some((alias, members)) = def.split_once('=') {
                    let alias = alias.trim().to_string();
                    if !aliases.contains(&alias) && list(members).any(|m| named(m, &aliases)) {
                        aliases.push(alias);
                    }
                }
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    for (path, lines) in &files {
        for line in lines {
            // `#` starts a comment, unless a uid follows it (`#1001 ALL=...`).
            let comment = line.starts_with('#') && !line[1..].starts_with(|c: char| c.is_ascii_digit());
            let first = line.split_whitespace().next().unwrap_or("");
            if first.is_empty() || comment || line.starts_with('@') || first.starts_with("Defaults") || first.ends_with("_Alias") {
                continue;
            }
            // A rule: `<users> <hosts> = ...`. The users are a list whose commas may have
            // spaces around them, so they end at the first word not joined to it by one.
            let Some((head, _)) = line.split_once('=') else { continue };
            let mut users = String::new();
            let mut words = head.split_whitespace().peekable();
            while let Some(w) = words.next() {
                users.push_str(w);
                let more = w.ends_with(',') || words.peek().is_some_and(|n| n.starts_with(','));
                if !more {
                    break;
                }
            }
            if list(&users).any(|u| !u.starts_with('!') && named(u, &aliases)) {
                return Some(format!("has a sudo rule in {path}"));
            }
        }
    }
    None
}

/// `name`'s groups, its primary `gid` included, by id and name.
fn group_list(name: &str, gid: u32) -> Vec<(u32, String)> {
    let Ok(c) = CString::new(name) else { return vec![(gid, String::new())] };
    let mut n: libc::c_int = 64;
    let mut gids: Vec<libc::gid_t> = vec![0; n as usize];
    // SAFETY: `gids` holds `n` entries; getgrouplist says how many it needs if not.
    while unsafe { libc::getgrouplist(c.as_ptr(), gid, gids.as_mut_ptr(), &mut n) } < 0 {
        if n as usize <= gids.len() || n > 65536 {
            break;
        }
        gids.resize(n as usize, 0);
    }
    gids.truncate(n.max(0) as usize);
    if !gids.contains(&gid) {
        gids.push(gid);
    }
    gids.into_iter().map(|g| (g, group_name(g).unwrap_or_default())).collect()
}

fn group_name(gid: u32) -> Option<String> {
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 64 << 10];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; the result points into `buf`.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getgrgid_r succeeded, so gr_name is a C string in `buf`.
    Some(unsafe { CStr::from_ptr(gr.gr_name) }.to_string_lossy().into_owned())
}

pub fn is_root() -> bool {
    // SAFETY: no arguments, no failure.
    unsafe { libc::geteuid() == 0 }
}

/// useradd's arguments for the Bots' user: a system user with its own group, no
/// login shell, `home` as its home, which the agent made.
pub fn useradd_args(name: &str, home: &Path) -> Vec<String> {
    useradd_args_as(name, home, "SuperBot Bots")
}

fn useradd_args_as(name: &str, home: &Path, comment: &str) -> Vec<String> {
    ["--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "--comment", comment, "--home-dir"]
        .iter()
        .map(|s| s.to_string())
        .chain([home.display().to_string(), name.to_string()])
        .collect()
}

fn run(program: &str, args: &[String]) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("couldn't start {program}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "{program} failed ({}): {}",
        out.status,
        why.trim().lines().last().unwrap_or("")
    ))
}

/// Makes the user if it isn't there. An agent from before ADR 0043 runs in a unit that
/// can't write /etc, so when useradd fails there, systemd runs it outside the unit.
pub fn ensure_user(name: &str, home: &Path) -> Result<Ids, String> {
    ensure_user_as(name, home, "SuperBot Bots")
}

/// Removes a user this agent just made (not its home), like `ensure_user_as` going
/// through systemd when the unit can't write /etc.
pub fn remove_user(name: &str) -> Result<(), String> {
    let args = vec![name.to_string()];
    if let Err(direct) = run("userdel", &args) {
        let mut outside: Vec<String> = ["--quiet", "--wait", "--collect", "--", "userdel"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        outside.extend(args);
        if let Err(via) = run("systemd-run", &outside) {
            return Err(format!("{direct}; through systemd: {via}"));
        }
    }
    Ok(())
}

/// `ensure_user`, with `comment` as the user's description.
pub fn ensure_user_as(name: &str, home: &Path, comment: &str) -> Result<Ids, String> {
    if let Some((ids, _)) = lookup(name) {
        return Ok(ids);
    }
    let args = useradd_args_as(name, home, comment);
    if let Err(direct) = run("useradd", &args) {
        let mut outside = vec![
            "--quiet".into(),
            "--wait".into(),
            "--collect".into(),
            "--".into(),
            "useradd".into(),
        ];
        outside.extend(args);
        if let Err(via) = run("systemd-run", &outside) {
            return Err(format!("{direct}; through systemd: {via}"));
        }
    }
    lookup(name)
        .map(|(ids, _)| ids)
        .ok_or_else(|| format!("useradd made no user {name}"))
}

fn raw(call: libc::c_long, a: libc::c_long, b: libc::c_long) -> libc::c_long {
    // SAFETY: the credential syscalls below take plain integers or a valid buffer.
    unsafe { libc::syscall(call, a, b) }
}

/// This thread's supplementary groups.
fn groups() -> io::Result<Vec<libc::gid_t>> {
    let n = raw(libc::SYS_getgroups, 0, 0);
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut g = vec![0 as libc::gid_t; n as usize];
    let n = raw(libc::SYS_getgroups, n, g.as_mut_ptr() as libc::c_long);
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    g.truncate(n as usize);
    Ok(g)
}

fn set_groups(g: &[libc::gid_t]) -> io::Result<()> {
    // The raw call changes this thread only; glibc's would change every thread.
    if raw(
        libc::SYS_setgroups,
        g.len() as libc::c_long,
        g.as_ptr() as libc::c_long,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// setfsuid and setfsgid return the old value and can't fail loudly: asking with -1
/// changes nothing and says what it is.
fn fsuid(id: u32) -> u32 {
    raw(libc::SYS_setfsuid, id as libc::c_long, 0) as u32
}

fn fsgid(id: u32) -> u32 {
    raw(libc::SYS_setfsgid, id as libc::c_long, 0) as u32
}

/// This thread's file identity, put back when dropped.
struct Switched {
    uid: u32,
    gid: u32,
    groups: Option<Vec<libc::gid_t>>,
}

impl Drop for Switched {
    fn drop(&mut self) {
        fsuid(self.uid);
        fsgid(self.gid);
        if let Some(g) = &self.groups {
            let _ = set_groups(g);
        }
    }
}

fn switch(ids: Ids) -> io::Result<Switched> {
    let groups = if is_root() {
        let g = groups()?;
        set_groups(&[ids.gid])?;
        Some(g)
    } else {
        None
    };
    let s = Switched {
        gid: fsgid(ids.gid),
        uid: fsuid(ids.uid),
        groups,
    };
    if fsuid(u32::MAX) != ids.uid || fsgid(u32::MAX) != ids.gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "couldn't take on the Bots' user",
        ));
    }
    Ok(s)
}

/// Runs `f` with this thread's file access as `ids` (the Bots' user), or as itself
/// when `None`. Only file permission checks change, and only on this thread, for the
/// length of `f`, which must not yield to other tasks.
pub fn as_user<T>(ids: Option<Ids>, f: impl FnOnce() -> T) -> io::Result<T> {
    let Some(ids) = ids else {
        return Ok(f());
    };
    let _s = switch(ids)?;
    Ok(f())
}

fn last<T>(r: libc::c_int, ok: T) -> io::Result<T> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ok)
    }
}

fn open_at(dir: libc::c_int, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a valid C string; the descriptor is owned on success.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    last(fd, ()).map(|()| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: an open descriptor and a buffer for the answer.
    let r = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    last(r, st)
}

fn lstat_at(dir: &OwnedFd, name: &CStr) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above, never following a link.
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    last(r, st)
}

/// The names in an open folder, without `.` and `..`.
fn names(dir: &OwnedFd) -> io::Result<Vec<CString>> {
    // SAFETY: a new descriptor for the folder, owned by the DIR stream, closed with it.
    unsafe {
        let fd = libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let d = libc::fdopendir(fd);
        if d.is_null() {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }
        libc::rewinddir(d);
        let mut out = Vec::new();
        loop {
            let e = libc::readdir(d);
            if e.is_null() {
                break;
            }
            let name = CStr::from_ptr((*e).d_name.as_ptr());
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                out.push(name.to_owned());
            }
        }
        libc::closedir(d);
        Ok(out)
    }
}

/// What a hand-over did.
#[derive(Debug, Default, PartialEq)]
pub struct Handed {
    pub changed: u64,
    /// Files with other hard links, devices, pipes and sockets: left as they were.
    pub skipped: u64,
}

const MAX_DEPTH: usize = 256;
const SETID: u32 = libc::S_ISUID | libc::S_ISGID;

fn give(fd: &OwnedFd, st: &libc::stat, ids: Ids, mode: Option<u32>) -> io::Result<()> {
    // SAFETY: an open descriptor; chown and chmod act on what it is, not on a name.
    unsafe {
        last(libc::fchown(fd.as_raw_fd(), ids.uid, ids.gid), ())?;
        let want = mode.unwrap_or(st.st_mode & 0o7777 & !SETID);
        if want != st.st_mode & 0o7777 {
            last(libc::fchmod(fd.as_raw_fd(), want), ())?;
        }
    }
    Ok(())
}

fn walk(dir: &OwnedFd, ids: Ids, depth: usize, out: &mut Handed) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(io::Error::other("folders nested too deep"));
    }
    for name in names(dir)? {
        let Ok(st) = lstat_at(dir, &name) else {
            continue;
        };
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let sub = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let st = fstat(&sub)?;
                give(&sub, &st, ids, None)?;
                out.changed += 1;
                walk(&sub, ids, depth + 1, out)?;
            }
            libc::S_IFREG => {
                let Ok(f) = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NONBLOCK)
                else {
                    out.skipped += 1;
                    continue;
                };
                let st = fstat(&f)?;
                if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink > 1 {
                    out.skipped += 1;
                    continue;
                }
                give(&f, &st, ids, None)?;
                out.changed += 1;
            }
            libc::S_IFLNK => {
                // SAFETY: changes the link itself, never what it points to.
                let r = unsafe {
                    libc::fchownat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        ids.uid,
                        ids.gid,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                last(r, ())?;
                out.changed += 1;
            }
            _ => out.skipped += 1,
        }
    }
    Ok(())
}

/// Gives `root` (made 0700) and everything under it to `ids`, never following a link,
/// and drops setuid and setgid bits. A file with another hard link may be someone
/// else's file, so it is left alone; so are devices, pipes and sockets.
pub fn hand_over(root: &Path, ids: Ids) -> io::Result<Handed> {
    let c = CString::new(root.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let top = open_at(libc::AT_FDCWD, &c, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let st = fstat(&top)?;
    give(&top, &st, ids, Some(0o700))?;
    let mut out = Handed {
        changed: 1,
        skipped: 0,
    };
    walk(&top, ids, 0, &mut out)?;
    Ok(out)
}

/// Lets everyone read `root` and run what its owner can, as for programs in
/// /usr: the tools the Bots' user runs. Links are left alone.
pub fn open_up(root: &Path) -> io::Result<()> {
    fn walk(dir: &OwnedFd, depth: usize) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("folders nested too deep"));
        }
        for name in names(dir)? {
            let Ok(st) = lstat_at(dir, &name) else {
                continue;
            };
            let kind = st.st_mode & libc::S_IFMT;
            if kind != libc::S_IFDIR && kind != libc::S_IFREG {
                continue;
            }
            let flags = if kind == libc::S_IFDIR {
                libc::O_RDONLY | libc::O_DIRECTORY
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK
            };
            let Ok(fd) = open_at(dir.as_raw_fd(), &name, flags) else {
                continue;
            };
            readable(&fd)?;
            if kind == libc::S_IFDIR {
                walk(&fd, depth + 1)?;
            }
        }
        Ok(())
    }
    fn readable(fd: &OwnedFd) -> io::Result<()> {
        let st = fstat(fd)?;
        let mode = st.st_mode & 0o7777;
        let x = if mode & 0o100 != 0 || st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            0o011
        } else {
            0
        };
        let want = mode | 0o044 | x;
        if want != mode {
            // SAFETY: an open descriptor.
            last(
                unsafe { libc::fchmod(fd.as_raw_fd(), want as libc::mode_t) },
                (),
            )?;
        }
        Ok(())
    }
    let c = CString::new(root.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let top = open_at(libc::AT_FDCWD, &c, libc::O_RDONLY | libc::O_DIRECTORY)?;
    readable(&top)?;
    walk(&top, 0)
}

/// Sets `p`'s mode, refusing a link.
pub fn chmod_dir(p: &Path, mode: u32) -> io::Result<()> {
    let c = CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let fd = open_at(libc::AT_FDCWD, &c, libc::O_RDONLY | libc::O_DIRECTORY)?;
    // SAFETY: an open descriptor.
    last(
        unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) },
        (),
    )
}

/// Moves `from` to `<base>/<under>.../<name>`, making the folders under `base` as `ids`
/// where they're missing. Nothing below `base` is followed if it's a link, and each
/// folder there must be `ids`', so whoever owns them can't steer the move elsewhere. A
/// name that's taken becomes `<name>-2`, `<name>-3`... Returns where it went.
pub fn move_into(
    from: &Path,
    base: &Path,
    under: &[&str],
    name: &str,
    ids: Ids,
) -> io::Result<std::path::PathBuf> {
    let c = |b: &[u8]| CString::new(b).map_err(io::Error::other);
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let (Some(parent), Some(leaf)) = (from.parent(), from.file_name()) else {
        return Err(io::Error::other("nothing to move"));
    };
    let leaf = c(leaf.as_bytes())?;
    let src = open_at(libc::AT_FDCWD, &c(parent.as_os_str().as_bytes())?, dir_flags)?;
    let mut dir = open_at(libc::AT_FDCWD, &c(base.as_os_str().as_bytes())?, dir_flags)?;
    let mut to = base.to_path_buf();
    for part in under {
        let p = c(part.as_bytes())?;
        to.push(part);
        // SAFETY: an open descriptor and a C string.
        let r = as_user(Some(ids), || unsafe { libc::mkdirat(dir.as_raw_fd(), p.as_ptr(), 0o700) })?;
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EEXIST) {
                return Err(e);
            }
        }
        let next = open_at(dir.as_raw_fd(), &p, dir_flags)?;
        if fstat(&next)?.st_uid != ids.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} isn't the Bots' user's", to.display()),
            ));
        }
        dir = next;
    }
    let mut across = false;
    for n in 1..=100 {
        let tried = if n == 1 { name.to_string() } else { format!("{name}-{n}") };
        let t = c(tried.as_bytes())?;
        if !across {
            // SAFETY: open descriptors and C strings; never replaces what's there.
            let r = unsafe {
                libc::renameat2(
                    src.as_raw_fd(),
                    leaf.as_ptr(),
                    dir.as_raw_fd(),
                    t.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if r == 0 {
                return Ok(to.join(tried));
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EEXIST) => continue,
                Some(libc::EXDEV) => across = true,
                _ => return Err(e),
            }
        }
        // On another filesystem: copied as `ids` into a folder made for it, then the
        // original deleted.
        // SAFETY: an open descriptor and a C string.
        let r = as_user(Some(ids), || unsafe { libc::mkdirat(dir.as_raw_fd(), t.as_ptr(), 0o700) })?;
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(e);
        }
        let made = to.join(&tried);
        let copied = (|| {
            let from_fd = open_at(src.as_raw_fd(), &leaf, dir_flags)?;
            let into = open_at(dir.as_raw_fd(), &t, dir_flags)?;
            as_user(Some(ids), || copy_tree(&from_fd, &into, 0))?
        })();
        if let Err(e) = copied {
            let _ = as_user(Some(ids), || std::fs::remove_dir_all(&made));
            return Err(e);
        }
        std::fs::remove_dir_all(from)?;
        return Ok(made);
    }
    Err(io::Error::other(format!("{name} and the next 99 names are taken")))
}

/// Copies what's in `src` into `dst`, never following a link: folders, regular files
/// (each a new file, never another link to the old one) and links. Devices, pipes and
/// sockets are left out.
fn copy_tree(src: &OwnedFd, dst: &OwnedFd, depth: usize) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(io::Error::other("folders nested too deep"));
    }
    for name in names(src)? {
        let Ok(st) = lstat_at(src, &name) else {
            continue;
        };
        let mode = st.st_mode & 0o777;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                // SAFETY: an open descriptor and a C string.
                last(unsafe { libc::mkdirat(dst.as_raw_fd(), name.as_ptr(), 0o700) }, ())?;
                let from = open_at(src.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let into = open_at(dst.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                copy_tree(&from, &into, depth + 1)?;
                // SAFETY: an open descriptor.
                last(unsafe { libc::fchmod(into.as_raw_fd(), mode as libc::mode_t) }, ())?;
            }
            libc::S_IFREG => {
                // What `hand_over` left someone else's stays out.
                let Ok(from) = open_at(src.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NONBLOCK) else {
                    continue;
                };
                copy_file(&from, dst, &name, mode)?;
            }
            libc::S_IFLNK => {
                let mut buf = vec![0u8; libc::PATH_MAX as usize];
                // SAFETY: an open descriptor, a C string and a buffer of that length.
                let n = unsafe { libc::readlinkat(src.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                buf.truncate(n as usize);
                let target = CString::new(buf).map_err(io::Error::other)?;
                // SAFETY: two C strings and an open descriptor; the link is made, not followed.
                last(unsafe { libc::symlinkat(target.as_ptr(), dst.as_raw_fd(), name.as_ptr()) }, ())?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Copies the open regular file `s` to a new file `to` in `dst` with `mode`. A name
/// that's taken is `AlreadyExists`, and left alone; a copy that fails partway is deleted.
fn copy_file(s: &OwnedFd, dst: &OwnedFd, to: &CStr, mode: u32) -> io::Result<()> {
    if fstat(s)?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(());
    }
    // SAFETY: an open descriptor and a C string; the descriptor is owned on success.
    let fd = unsafe {
        libc::openat(
            dst.as_raw_fd(),
            to.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    let d = last(fd, ()).map(|()| unsafe { OwnedFd::from_raw_fd(fd) })?;
    let filled = (|| {
        // SAFETY: an open descriptor.
        last(unsafe { libc::fchmod(d.as_raw_fd(), (mode & !SETID) as libc::mode_t) }, ())?;
        let (mut r, mut w) = (std::fs::File::from(s.try_clone()?), std::fs::File::from(d));
        io::copy(&mut r, &mut w)?;
        w.sync_all()
    })();
    if filled.is_err() {
        // SAFETY: an open descriptor and a C string; removes only the name made above.
        unsafe { libc::unlinkat(dst.as_raw_fd(), to.as_ptr(), 0) };
    }
    filled
}

/// Gives each regular file under `root` that's `uid`'s and has another hard link a copy
/// of its own in its place, so `hand_over` can give it away without touching the other
/// link. Someone else's file is never read: it may be one `uid` could link but not read.
/// Only for a tree no one else can change meanwhile. How many it copied.
pub fn unshare_links(root: &Path, uid: u32) -> io::Result<u64> {
    fn walk(dir: &OwnedFd, uid: u32, depth: usize, n: &mut u64) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("folders nested too deep"));
        }
        for name in names(dir)? {
            let Ok(st) = lstat_at(dir, &name) else {
                continue;
            };
            match st.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let sub = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    walk(&sub, uid, depth + 1, n)?;
                }
                libc::S_IFREG if st.st_nlink > 1 => {
                    let from = open_at(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
                    let st = fstat(&from)?;
                    if st.st_uid != uid || st.st_nlink < 2 {
                        continue;
                    }
                    // Their own files may have any name, so the first free one is used.
                    let mut tmp = None;
                    for k in 0..1000 {
                        let t = CString::new(format!(".superbot-unlinked-{k}")).map_err(io::Error::other)?;
                        match copy_file(&from, dir, &t, st.st_mode & 0o777) {
                            Ok(()) => {
                                tmp = Some(t);
                                break;
                            }
                            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    let tmp = tmp.ok_or_else(|| io::Error::other("no free name for a copy"))?;
                    // SAFETY: an open descriptor and two C strings; replaces the link only.
                    last(unsafe { libc::renameat(dir.as_raw_fd(), tmp.as_ptr(), dir.as_raw_fd(), name.as_ptr()) }, ())?;
                    *n += 1;
                }
                _ => {}
            }
        }
        Ok(())
    }
    let c = CString::new(root.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let top = open_at(libc::AT_FDCWD, &c, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut n = 0;
    walk(&top, uid, 0, &mut n)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "superbot-runas-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn me() -> Ids {
        // SAFETY: no arguments.
        unsafe {
            Ids {
                uid: libc::geteuid(),
                gid: libc::getegid(),
            }
        }
    }

    #[test]
    fn user_names_are_plain() {
        for ok in ["superbot-bots", "_x", "a1"] {
            assert!(plain_user(ok), "{ok}");
        }
        for no in ["", "Root", "1a", "a b", "a/b", "-a", &"a".repeat(33)] {
            assert!(!plain_user(no), "{no}");
        }
        let a = useradd_args("superbot-bots", Path::new("/var/lib/superbot-machine/home"));
        assert_eq!(a.last().unwrap(), "superbot-bots");
        assert!(
            a.windows(2)
                .any(|w| w == ["--home-dir", "/var/lib/superbot-machine/home"])
        );
        assert!(a.iter().any(|s| s == "--system") && a.iter().any(|s| s == "--no-create-home"));
    }

    #[test]
    fn a_locked_down_process_cant_gain_privileges_and_keeps_its_files_to_itself() {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "grep NoNewPrivs /proc/self/status; umask"]);
        // SAFETY: lock_down makes only async-signal-safe calls.
        unsafe { c.pre_exec(lock_down) };
        let out = String::from_utf8(c.output().unwrap().stdout).unwrap();
        let mut lines = out.lines();
        assert_eq!(lines.next().map(|l| l.split_whitespace().collect::<Vec<_>>()), Some(vec!["NoNewPrivs:", "1"]), "{out}");
        assert_eq!(lines.next(), Some("0077"), "{out}");
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "grep NoNewPrivs /proc/self/status"]);
        // SAFETY: as above.
        unsafe { c.pre_exec(no_new_privs) };
        assert!(String::from_utf8(c.output().unwrap().stdout).unwrap().contains('1'));
    }

    #[test]
    fn a_run_starts_with_the_oom_score_floor() {
        use std::os::unix::process::CommandExt;
        // SAFETY: getuid and getgid can't fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let mut c = std::process::Command::new("cat");
        c.arg("/proc/self/oom_score_adj");
        // SAFETY: become_user makes only async-signal-safe calls.
        unsafe { c.pre_exec(move || become_user(uid, gid)) };
        let out = c.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim().as_bytes(), RUN_OOM_SCORE_ADJ);
    }

    #[test]
    fn sudo_files_include_what_they_include() {
        let d = scratch("sudoers");
        let w = |p: &str, t: &str| {
            let p = d.join(p);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        };
        w("sudoers", "root ALL=(ALL) ALL\n@include extra\n#includedir /nonexistent\n@includedir more\n");
        w("extra", "@include sudoers\n");
        w("more/a", "x ALL=(ALL) ALL\n");
        w("more/b.bak", "y ALL=(ALL) ALL\n");
        w("more/c~", "z ALL=(ALL) ALL\n");
        let names: Vec<_> = sudoers_from(vec![d.join("sudoers")])
            .into_iter()
            .map(|(p, _)| Path::new(&p).strip_prefix(&d).unwrap().display().to_string())
            .collect();
        assert_eq!(names, ["sudoers", "more/a", "extra"]);
    }

    #[test]
    fn privileged_users_groups_and_sudo_rules_are_found() {
        let ids = Ids { uid: 990, gid: 990 };
        let own = vec![(990, "superbot-bots".to_string())];
        let none: Vec<(String, String)> = vec![];
        assert_eq!(privileged_in("superbot-bots", ids, &own, &none), None);
        assert_eq!(privileged_in("x", Ids { uid: 0, gid: 990 }, &own, &none).as_deref(), Some("is root"));
        assert_eq!(privileged_in("x", Ids { uid: 990, gid: 0 }, &own, &none).as_deref(), Some("is in root's group"));
        for g in PRIVILEGED_GROUPS {
            let with = [own.clone(), vec![(27, g.to_string())]].concat();
            assert!(privileged_in("superbot-bots", ids, &with, &none).is_some(), "{g}");
        }
        // Harmless groups pass.
        let with = [own.clone(), vec![(100, "users".to_string())]].concat();
        assert_eq!(privileged_in("superbot-bots", ids, &with, &none), None);

        let rule = |text: &str| vec![("/etc/sudoers.d/x".to_string(), text.to_string())];
        let found = |text: &str| privileged_in("superbot-bots", ids, &own, &rule(text));
        for text in [
            "superbot-bots ALL=(ALL) NOPASSWD: ALL",
            "ops,superbot-bots ALL=(ALL) ALL",
            "%superbot-bots ALL=(root) /bin/true",
            "%#990 ALL=(ALL) ALL",
            "#990 ALL=(ALL) ALL",
            "ALL ALL=(ALL) NOPASSWD: ALL",
            "User_Alias BOTS = ops, superbot-bots\nBOTS ALL=(ALL) ALL",
            "ops, superbot-bots ALL=(ALL) NOPASSWD: ALL",
            "ops ,superbot-bots ALL=(ALL) ALL",
            "ops , superbot-bots\tALL = (ALL) ALL",
            "ops, \\\n  superbot-bots ALL=(ALL) ALL",
            "User_Alias INNER = superbot-bots\nUser_Alias OUTER = ops, INNER\nOUTER ALL=(ALL) ALL",
            "User_Alias OUTER = ops, INNER\nUser_Alias INNER = superbot-bots\nOUTER ALL=(ALL) ALL",
            "%:superbot-bots ALL=(ALL) ALL",
        ] {
            assert_eq!(found(text).as_deref(), Some("has a sudo rule in /etc/sudoers.d/x"), "{text}");
        }
        for text in [
            "# superbot-bots ALL=(ALL) ALL",
            "Defaults:superbot-bots !requiretty",
            "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL",
            "@includedir /etc/sudoers.d",
            "superbot ALL=(sb-u-1) NOPASSWD: /usr/local/bin/superbot-run",
            "User_Alias OPS = ops\nOPS ALL=(ALL) ALL",
            "ops ALL=(superbot-bots) ALL",
            "ops, admins ALL=(ALL) ALL",
            "!superbot-bots, ops ALL=(ALL) ALL",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
    }

    #[test]
    fn the_current_user_is_found_and_a_missing_one_is_not() {
        let name = current_user().unwrap();
        assert_eq!(lookup(&name).unwrap().0.uid, me().uid);
        assert!(lookup("superbot-no-such-user").is_none());
        assert_eq!(
            ensure_user(&name, Path::new("/nonexistent")).unwrap().uid,
            me().uid
        );
    }

    #[test]
    fn as_user_switches_this_thread_and_puts_it_back() {
        let ids = me();
        let got = as_user(Some(ids), || (fsuid(u32::MAX), fsgid(u32::MAX))).unwrap();
        assert_eq!(got, (ids.uid, ids.gid));
        assert_eq!(fsuid(u32::MAX), ids.uid);
        assert_eq!(as_user(None, || 7).unwrap(), 7);
        if !is_root() {
            // Someone else's uid can't be taken without root: refused, not ignored.
            let other = Ids {
                uid: ids.uid + 1,
                gid: ids.gid,
            };
            assert!(as_user(Some(other), || ()).is_err());
            assert_eq!(fsuid(u32::MAX), ids.uid);
        }
    }

    #[test]
    fn a_hand_over_never_follows_links_and_drops_setid_bits() {
        let d = scratch("hand");
        let home = d.join("home");
        std::fs::create_dir_all(home.join("a/b")).unwrap();
        std::fs::write(home.join("a/b/f"), "x").unwrap();
        std::fs::set_permissions(home.join("a/b/f"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let outside = d.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::os::unix::fs::symlink(&outside, home.join("link")).unwrap();
        std::os::unix::fs::symlink(&d, home.join("a/up")).unwrap();
        std::fs::hard_link(&outside, home.join("hard")).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();

        let r = hand_over(&home, me()).unwrap();
        assert_eq!(r.skipped, 1, "the hard link");
        assert_eq!(r.changed, 6);
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(&home.join("a/b/f")), 0o755);
        assert_eq!(
            mode(&outside),
            0o4755,
            "never through a link or a hard link"
        );
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(
            hand_over(&home.join("link"), me()).is_err(),
            "the top can't be a link"
        );

        std::fs::set_permissions(home.join("a"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(home.join("a/b/f"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        open_up(&home).unwrap();
        assert_eq!(mode(&home), 0o755);
        assert_eq!(mode(&home.join("a")), 0o755);
        assert_eq!(mode(&home.join("a/b/f")), 0o755);
        chmod_dir(&home, 0o711).unwrap();
        assert_eq!(mode(&home), 0o711);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_move_into_a_home_never_follows_links_and_never_replaces() {
        let d = scratch("move");
        let (base, outside) = (d.join("home"), d.join("outside"));
        std::fs::create_dir_all(base.join("work")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let staged = |n: &str| {
            let p = d.join(n);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("notes.md"), n).unwrap();
            p
        };

        let to = move_into(&staged("a"), &base, &["work", "from-teammates"], "bea", me()).unwrap();
        assert_eq!(to, base.join("work/from-teammates/bea"));
        assert_eq!(std::fs::read_to_string(to.join("notes.md")).unwrap(), "a");
        assert_eq!(std::fs::symlink_metadata(base.join("work/from-teammates")).unwrap().mode() & 0o777, 0o700);
        let again = move_into(&staged("b"), &base, &["work", "from-teammates"], "bea", me()).unwrap();
        assert_eq!(again, base.join("work/from-teammates/bea-2"), "never over what's there");
        assert_eq!(std::fs::read_to_string(to.join("notes.md")).unwrap(), "a");

        // A folder on the way that's a link is refused, and nothing lands where it points.
        std::fs::remove_dir_all(base.join("work")).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("work")).unwrap();
        let c = staged("c");
        assert!(move_into(&c, &base, &["work", "from-teammates"], "bea", me()).is_err());
        assert!(c.join("notes.md").is_file(), "left where it was");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hard_links_are_given_copies_of_their_own_before_a_hand_over() {
        let d = scratch("unshare");
        let (home, outside) = (d.join("home"), d.join("outside"));
        std::fs::create_dir_all(home.join("a")).unwrap();
        std::fs::write(&outside, "theirs").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&outside, home.join("a/hard")).unwrap();
        std::fs::write(home.join("plain"), "mine").unwrap();
        std::fs::write(home.join("a/.superbot-unlinked-0"), "a file of theirs").unwrap();

        assert_eq!(unshare_links(&home, me().uid + 1).unwrap(), 0, "someone else's: never read");
        assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 2);
        assert_eq!(unshare_links(&home, me().uid).unwrap(), 1);
        let copy = std::fs::metadata(home.join("a/hard")).unwrap();
        assert_eq!((copy.nlink(), copy.mode() & 0o777), (1, 0o640));
        assert_eq!(std::fs::read_to_string(home.join("a/hard")).unwrap(), "theirs");
        assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 1);
        assert_eq!(hand_over(&home, me()).unwrap().skipped, 0);
        let mut names: Vec<_> = std::fs::read_dir(home.join("a")).unwrap().flatten().map(|e| e.file_name()).collect();
        names.sort();
        assert_eq!(names, [".superbot-unlinked-0", "hard"], "no copy left behind");
        assert_eq!(std::fs::read_to_string(home.join("a/.superbot-unlinked-0")).unwrap(), "a file of theirs", "a name that's taken is left alone");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_move_into_a_home_on_another_disk_copies_then_deletes() {
        let shm = Path::new("/dev/shm");
        let d = scratch("across");
        let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev());
        if dev(shm).is_err() || dev(shm).ok() == dev(&d).ok() {
            eprintln!("no second filesystem here; skipped");
            return;
        }
        let from = shm.join(d.file_name().unwrap());
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::write(from.join("sub/notes.md"), "a").unwrap();
        std::fs::set_permissions(from.join("sub/notes.md"), std::fs::Permissions::from_mode(0o4750)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", from.join("link")).unwrap();
        std::fs::hard_link(from.join("sub/notes.md"), from.join("hard")).unwrap();
        let base = d.join("home");
        std::fs::create_dir_all(base.join("work/from-teammates/bea")).unwrap();

        let to = move_into(&from, &base, &["work", "from-teammates"], "bea", me()).unwrap();
        assert_eq!(to, base.join("work/from-teammates/bea-2"), "never over what's there");
        assert_eq!(std::fs::read_to_string(to.join("sub/notes.md")).unwrap(), "a");
        let m = std::fs::metadata(to.join("sub/notes.md")).unwrap();
        assert_eq!((m.mode() & 0o7777, m.nlink()), (0o750, 1), "no setuid, no shared links");
        assert_eq!(std::fs::read_link(to.join("link")).unwrap(), Path::new("/etc/passwd"));
        assert_eq!(std::fs::read_to_string(to.join("hard")).unwrap(), "a");
        assert!(std::fs::symlink_metadata(&from).is_err(), "the original is gone");
        let _ = std::fs::remove_dir_all(&d);
    }
}
