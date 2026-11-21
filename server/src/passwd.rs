//! Local accounts from the password database. Shared by botd and `superbot-run`, which
//! each use part of it.
#![allow(dead_code)]

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub struct Account {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

pub fn by_name(name: &str) -> Option<Account> {
    let c = CString::new(name).ok()?;
    // SAFETY: every pointer is valid for the call; getpwnam_r writes only into `pw` and `buf`.
    lookup(|pw, buf, len, res| unsafe { libc::getpwnam_r(c.as_ptr(), pw, buf, len, res) })
}

pub fn by_uid(uid: u32) -> Option<Account> {
    // SAFETY: as in `by_name`.
    lookup(|pw, buf, len, res| unsafe { libc::getpwuid_r(uid, pw, buf, len, res) })
}

fn lookup(
    call: impl Fn(*mut libc::passwd, *mut libc::c_char, usize, *mut *mut libc::passwd) -> libc::c_int,
) -> Option<Account> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: passwd is plain data; all-zero is a valid value to be overwritten.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res = std::ptr::null_mut();
        let rc = call(&mut pw, buf.as_mut_ptr(), buf.len(), &mut res);
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || res.is_null() {
            return None;
        }
        // SAFETY: on success the fields point to NUL-terminated strings inside `buf`.
        let bytes = |p: *const libc::c_char| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
        return Some(Account {
            name: String::from_utf8(bytes(pw.pw_name)).ok()?,
            uid: pw.pw_uid,
            home: PathBuf::from(OsStr::from_bytes(&bytes(pw.pw_dir))),
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_root_and_not_a_made_up_account() {
        let root = super::by_uid(0).unwrap();
        assert_eq!((root.name.as_str(), root.uid), ("root", 0));
        assert_eq!(super::by_name("root").unwrap().home, root.home);
        assert!(super::by_name("sb-u-no-such-account-here").is_none());
        assert!(super::by_name("a\0b").is_none());
    }
}
