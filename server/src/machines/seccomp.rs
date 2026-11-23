//! A seccomp filter for every process run as a Bot's or teammate's user (ADR 0156).
//! It refuses the system calls a run never needs and kernel exploits often start from:
//! keyrings, eBPF, perf events, userfaultfd, io_uring, file handles, the kernel log,
//! and calls that only an administrator makes (modules, kexec, reboot, swap, the clock).
//! Everything else passes, so harnesses, their sandboxes (user namespaces, mounts inside
//! them, their own seccomp filters) and browsers work as before. A system call made
//! through another ABI (i386 or x32 on x86_64, which a filter for x86_64 can't read)
//! kills the process.
//!
//! The program is built at compile time, so installing it in `pre_exec` allocates
//! nothing. It needs no new privileges set first, which `runas::lock_down` does.
//! Shared by the agent, botd and `superbot-run`, so it uses nothing but libc.

// Shared by several binaries, each of which uses only part of it.
#![allow(dead_code)]

use std::io;

const EPERM: u32 = libc::EPERM as u32;
const ENOSYS: u32 = libc::ENOSYS as u32;

/// A refused call, its number on this architecture and the error it gets.
#[derive(Clone, Copy, Debug)]
pub struct Refused {
    pub name: &'static str,
    pub nr: u32,
    pub errno: u32,
}

const fn eperm(name: &'static str, nr: libc::c_long) -> Refused {
    Refused { name, nr: nr as u32, errno: EPERM }
}

/// io_uring gets ENOSYS, as on a kernel without it, because that's what programs that
/// can do without it (libuv, and so Node) look for before falling back.
const fn enosys(name: &'static str, nr: libc::c_long) -> Refused {
    Refused { name, nr: nr as u32, errno: ENOSYS }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::{Refused, eperm};
    /// `AUDIT_ARCH_X86_64`.
    pub const AUDIT_ARCH: u32 = 0xc000_003e;
    /// x32 calls are x86_64's numbers with this bit set.
    pub const X32_BIT: Option<u32> = Some(0x4000_0000);
    pub const KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;
    pub const ONLY_HERE: [Refused; 4] = [
        eperm("iopl", libc::SYS_iopl),
        eperm("ioperm", libc::SYS_ioperm),
        eperm("uselib", libc::SYS_uselib),
        eperm("_sysctl", libc::SYS__sysctl),
    ];
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::Refused;
    /// `AUDIT_ARCH_AARCH64`.
    pub const AUDIT_ARCH: u32 = 0xc000_00b7;
    pub const X32_BIT: Option<u32> = None;
    /// The generic table's number; musl's libc has no constant for it here.
    pub const KEXEC_FILE_LOAD: libc::c_long = 294;
    pub const ONLY_HERE: [Refused; 0] = [];
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod filter {
    use super::*;

    const COMMON: [Refused; 27] = [
        // Keyrings: long a source of kernel bugs, and a run keeps no keys there.
        eperm("keyctl", libc::SYS_keyctl),
        eperm("add_key", libc::SYS_add_key),
        eperm("request_key", libc::SYS_request_key),
        // Kernel interfaces exploits lean on; unprivileged eBPF and perf are off where
        // the sysctls reach, but a container's sysctls are its host's (ADR 0126).
        eperm("bpf", libc::SYS_bpf),
        eperm("perf_event_open", libc::SYS_perf_event_open),
        eperm("userfaultfd", libc::SYS_userfaultfd),
        enosys("io_uring_setup", libc::SYS_io_uring_setup),
        enosys("io_uring_enter", libc::SYS_io_uring_enter),
        enosys("io_uring_register", libc::SYS_io_uring_register),
        // Opening files by handle gets past the folders above them.
        eperm("open_by_handle_at", libc::SYS_open_by_handle_at),
        eperm("lookup_dcookie", libc::SYS_lookup_dcookie),
        eperm("fanotify_init", libc::SYS_fanotify_init),
        // The kernel log can hold addresses and other users' traces.
        eperm("syslog", libc::SYS_syslog),
        // An administrator's: they need capabilities a run hasn't got, refused here too
        // in case a kernel bug ever gives one.
        eperm("kexec_load", libc::SYS_kexec_load),
        eperm("kexec_file_load", arch::KEXEC_FILE_LOAD),
        eperm("init_module", libc::SYS_init_module),
        eperm("finit_module", libc::SYS_finit_module),
        eperm("delete_module", libc::SYS_delete_module),
        eperm("reboot", libc::SYS_reboot),
        eperm("swapon", libc::SYS_swapon),
        eperm("swapoff", libc::SYS_swapoff),
        eperm("acct", libc::SYS_acct),
        eperm("quotactl", libc::SYS_quotactl),
        eperm("quotactl_fd", libc::SYS_quotactl_fd),
        eperm("settimeofday", libc::SYS_settimeofday),
        eperm("clock_settime", libc::SYS_clock_settime),
        eperm("clock_adjtime", libc::SYS_clock_adjtime),
    ];

    const N: usize = COMMON.len() + arch::ONLY_HERE.len();

    const fn refused() -> [Refused; N] {
        let mut out = [eperm("", 0); N];
        let mut i = 0;
        while i < COMMON.len() {
            out[i] = COMMON[i];
            i += 1;
        }
        let mut j = 0;
        while j < arch::ONLY_HERE.len() {
            out[i + j] = arch::ONLY_HERE[j];
            j += 1;
        }
        out
    }

    pub const REFUSED: [Refused; N] = refused();

    // Classic BPF, as seccomp takes it.
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    /// `struct seccomp_data`: the call's number, then its architecture.
    const NR: u32 = 0;
    const ARCH: u32 = 4;

    const fn op(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    const X32: usize = if arch::X32_BIT.is_some() { 1 } else { 0 };
    /// Load the arch, check it, load the number, (x32 check), one test per call, then
    /// four returns: allow, EPERM, ENOSYS, kill.
    pub const LEN: usize = 3 + X32 + N + 4;

    const fn program() -> [libc::sock_filter; LEN] {
        let allow = LEN - 4;
        let (to_eperm, to_enosys, to_kill) = (allow + 1, allow + 2, allow + 3);
        // A jump's offset counts from the instruction after it.
        const fn hop(from: usize, to: usize) -> u8 {
            let d = to - from - 1;
            assert!(d <= u8::MAX as usize, "the filter is too long for its jumps");
            d as u8
        }
        let mut p = [op(RET_K, 0, 0, 0); LEN];
        p[0] = op(LD_W_ABS, 0, 0, ARCH);
        p[1] = op(JEQ_K, 0, hop(1, to_kill), arch::AUDIT_ARCH);
        p[2] = op(LD_W_ABS, 0, 0, NR);
        let mut at = 3;
        if let Some(bit) = arch::X32_BIT {
            p[at] = op(JGE_K, hop(at, to_kill), 0, bit);
            at += 1;
        }
        let mut i = 0;
        while i < N {
            let r = REFUSED[i];
            let to = if r.errno == ENOSYS { to_enosys } else { to_eperm };
            p[at] = op(JEQ_K, hop(at, to), 0, r.nr);
            at += 1;
            i += 1;
        }
        p[allow] = op(RET_K, 0, 0, libc::SECCOMP_RET_ALLOW);
        p[to_eperm] = op(RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | EPERM);
        p[to_enosys] = op(RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | ENOSYS);
        p[to_kill] = op(RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS);
        p
    }

    pub static PROGRAM: [libc::sock_filter; LEN] = program();
    pub const AUDIT_ARCH: u32 = arch::AUDIT_ARCH;
    pub const X32_BIT: Option<u32> = arch::X32_BIT;
}

/// Whether this build has a filter for its architecture. The agent says so in its
/// heartbeat (`wire::CAN_SECCOMP`).
pub const SUPPORTED: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

/// The calls refused, for reports and tests.
pub fn refused() -> &'static [Refused] {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        &filter::REFUSED
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        &[]
    }
}

/// For `pre_exec`, after no new privileges: installs the filter on this process, for
/// its whole life and every exec. Only async-signal-safe calls. On an architecture
/// without a filter it does nothing; the heartbeat says so.
pub fn install() -> io::Result<()> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let prog = libc::sock_fprog {
            len: filter::LEN as libc::c_ushort,
            filter: filter::PROGRAM.as_ptr().cast_mut(),
        };
        // SAFETY: a valid program that the kernel copies; nothing is kept of `prog`.
        let r = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const libc::sock_fprog as libc::c_ulong,
                0,
                0,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::filter::{AUDIT_ARCH, LEN, PROGRAM, X32_BIT};
    use super::*;

    /// Runs the program as the kernel would, on a call's number and architecture.
    fn verdict(nr: u32, arch: u32) -> u32 {
        let (mut acc, mut pc) = (0u32, 0usize);
        loop {
            let i = PROGRAM[pc];
            match i.code {
                0x20 => acc = if i.k == 0 { nr } else { arch },
                0x15 | 0x35 => {
                    let taken = if i.code == 0x15 { acc == i.k } else { acc >= i.k };
                    pc += if taken { i.jt } else { i.jf } as usize;
                }
                0x06 => return i.k,
                c => panic!("unexpected op {c:#x}"),
            }
            pc += 1;
            assert!(pc < LEN, "ran off the end");
        }
    }

    #[test]
    fn the_filter_refuses_its_list_and_passes_everything_else() {
        let errno = |e: u32| libc::SECCOMP_RET_ERRNO | e;
        let listed: Vec<u32> = refused().iter().map(|r| r.nr).collect();
        for r in refused() {
            assert_eq!(verdict(r.nr, AUDIT_ARCH), errno(r.errno), "{}", r.name);
        }
        for name in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
            assert_eq!(refused().iter().find(|r| r.name == name).unwrap().errno, ENOSYS);
        }
        assert!(refused().iter().filter(|r| !r.name.starts_with("io_uring")).all(|r| r.errno == EPERM));
        // What harnesses, sandboxes and browsers use passes.
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_unshare,
            libc::SYS_mount,
            libc::SYS_pivot_root,
            libc::SYS_seccomp,
            libc::SYS_prctl,
            libc::SYS_ptrace,
            libc::SYS_landlock_create_ruleset,
            libc::SYS_exit_group,
        ] {
            assert!(!listed.contains(&(nr as u32)), "{nr}");
            assert_eq!(verdict(nr as u32, AUDIT_ARCH), libc::SECCOMP_RET_ALLOW, "{nr}");
        }
        for nr in (0..500u32).filter(|nr| !listed.contains(nr)) {
            assert_eq!(verdict(nr, AUDIT_ARCH), libc::SECCOMP_RET_ALLOW, "{nr}");
        }
        // Another ABI is killed, whatever the call.
        const I386: u32 = 0x4000_0003;
        const ARM: u32 = 0x4000_0028;
        for arch in [I386, ARM, 0] {
            assert_eq!(verdict(libc::SYS_read as u32, arch), libc::SECCOMP_RET_KILL_PROCESS);
        }
        if let Some(bit) = X32_BIT {
            assert_eq!(verdict(bit | libc::SYS_read as u32, AUDIT_ARCH), libc::SECCOMP_RET_KILL_PROCESS);
        }
        let mut names: Vec<_> = refused().iter().map(|r| r.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), refused().len(), "each call once");
    }

    #[test]
    fn a_filtered_process_is_refused_the_calls_and_keeps_working() {
        use std::os::unix::process::CommandExt;
        // In the child, after the filter: each refused call fails with its error, and a
        // call that isn't refused still answers. A mismatch fails the spawn with EILSEQ.
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status; ls / >/dev/null && echo works"]);
        // SAFETY: prctl, install and raw syscalls only, which are async-signal-safe.
        unsafe {
            c.pre_exec(|| {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                install()?;
                let fails_with = |nr: libc::c_long, e: libc::c_int| {
                    let r = libc::syscall(nr, 0, 0, 0, 0, 0);
                    r == -1 && *libc::__errno_location() == e
                };
                let ok = fails_with(libc::SYS_keyctl, libc::EPERM)
                    && fails_with(libc::SYS_add_key, libc::EPERM)
                    && fails_with(libc::SYS_bpf, libc::EPERM)
                    && fails_with(libc::SYS_perf_event_open, libc::EPERM)
                    && fails_with(libc::SYS_userfaultfd, libc::EPERM)
                    && fails_with(libc::SYS_syslog, libc::EPERM)
                    && fails_with(libc::SYS_io_uring_setup, libc::ENOSYS)
                    && libc::syscall(libc::SYS_getpid) > 0;
                if !ok {
                    return Err(io::Error::from_raw_os_error(libc::EILSEQ));
                }
                Ok(())
            });
        }
        let out = c.output().expect("the filtered child runs");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{out:?}");
        let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).map(str::trim).unwrap_or("");
        assert_eq!(field("Seccomp:"), "2", "{text}");
        assert_eq!(field("NoNewPrivs:"), "1", "{text}");
        assert!(text.contains("works"), "{text}");
    }
}
