//! Script files and inline code a Bot runs (ADR 0053). Reads a script from the Bot's
//! workspace without following links out of it, and scans code in languages other
//! than shell for calls that run commands, run hidden code, delete files, or send
//! email. Shell scripts are parsed by `crate::shell` like any command line.
//!
//! The scan errs towards asking: a call it can't read in full (a command built at run
//! time, an alias it can't follow) is reported as unknown, never as harmless.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Biggest script file SuperBot reads. Anything bigger asks.
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
/// Most script files read for one call, counting scripts that run other scripts.
pub const MAX_FILES: usize = 32;

pub const SHELLS: [&str; 8] = ["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Shell,
    Python,
    Js,
    Ruby,
    Perl,
    Php,
}

impl Lang {
    /// The language an interpreter reads, by its program name (`python3.12`, `node`).
    pub fn of(prog: &str) -> Option<Lang> {
        let base = prog.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        Some(match base {
            p if SHELLS.contains(&p) => Lang::Shell,
            "python" | "pypy" => Lang::Python,
            "node" | "nodejs" | "deno" | "bun" | "tsx" | "ts-node" => Lang::Js,
            "ruby" => Lang::Ruby,
            "perl" => Lang::Perl,
            "php" => Lang::Php,
            _ => return None,
        })
    }
}

/// What reading a script file found.
#[derive(Debug, PartialEq)]
pub enum Source {
    Text(String),
    /// A compiled program, not a script.
    Binary,
    Missing,
    TooBig,
    Unreadable(&'static str),
    /// A link to this place outside the workspace. It isn't read.
    LinksOutside(PathBuf),
}

/// Reads the script at `path` (absolute, inside `workspace` as written). Links are
/// followed only while they stay inside the workspace; FIFOs, devices, and folders
/// aren't opened.
pub fn read(workspace: &Path, path: &Path) -> Source {
    let Ok(ws) = std::fs::canonicalize(workspace) else { return Source::Unreadable("the workspace isn't on this server") };
    let real = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Source::Missing,
        Err(_) => return Source::Unreadable("it can't be opened"),
    };
    let Ok(rel) = real.strip_prefix(&ws) else { return Source::LinksOutside(real) };
    let Some(file) = open_under(&ws, rel) else { return Source::Unreadable("it changed while SuperBot read it, or can't be opened") };
    let Ok(meta) = file.metadata() else { return Source::Unreadable("it can't be opened") };
    if !meta.is_file() {
        return Source::Unreadable("it isn't a regular file");
    }
    if meta.len() > MAX_SCRIPT_BYTES as u64 {
        return Source::TooBig;
    }
    let mut bytes = Vec::new();
    if file.take(MAX_SCRIPT_BYTES as u64 + 1).read_to_end(&mut bytes).is_err() {
        return Source::Unreadable("it can't be read");
    }
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Source::TooBig;
    }
    if is_binary(&bytes) {
        return Source::Binary;
    }
    Source::Text(String::from_utf8_lossy(&bytes).into_owned())
}

/// Opens `rel` under the folder `ws` one name at a time, never through a link, so a
/// folder swapped for a link after the path was checked can't lead outside.
fn open_under(ws: &Path, rel: &Path) -> Option<std::fs::File> {
    use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};
    use std::os::unix::ffi::OsStrExt;
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let root = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(ws).ok()?;
    let mut dir: OwnedFd = root.into();
    let names: Vec<_> = rel.components().collect();
    let (last, folders) = names.split_last()?;
    for name in folders {
        let std::path::Component::Normal(n) = name else { return None };
        let c = std::ffi::CString::new(n.as_bytes()).ok()?;
        // SAFETY: `dir` is an open folder and `c` a NUL-terminated name.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), dir_flags | libc::O_NOFOLLOW) };
        if fd < 0 {
            return None;
        }
        // SAFETY: openat returned a new descriptor that nothing else owns.
        dir = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    let std::path::Component::Normal(n) = last else { return None };
    let c = std::ffi::CString::new(n.as_bytes()).ok()?;
    // SAFETY: as above.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    // SAFETY: as above.
    (fd >= 0).then(|| unsafe { std::fs::File::from_raw_fd(fd) })
}

/// A compiled program: an ELF or Mach-O header, or, as bash decides before running a
/// file as a script, a NUL in its first line within the first 80 bytes.
fn is_binary(b: &[u8]) -> bool {
    const MAGIC: [&[u8]; 6] = [b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"];
    if b.starts_with(b"#!") {
        return false;
    }
    MAGIC.iter().any(|m| b.starts_with(m)) || b.iter().take(80).take_while(|c| **c != b'\n').any(|c| *c == 0)
}

/// The program a `#!` line runs, with `env` and its options skipped. None when there
/// is no `#!` line (the file then runs as a shell script) or it names nothing.
pub fn shebang(text: &str) -> Option<Option<String>> {
    let line = text.strip_prefix("#!")?.lines().next().unwrap_or_default();
    let mut words = line.split_whitespace();
    let base = |w: &str| w.rsplit('/').next().unwrap_or(w).to_string();
    let Some(first) = words.next() else { return Some(None) };
    if base(first) != "env" {
        return Some(Some(base(first)));
    }
    while let Some(w) = words.next() {
        if w == "-u" || w == "--unset" {
            words.next();
        } else if !w.starts_with('-') && !w.contains('=') {
            return Some(Some(base(w)));
        }
    }
    Some(None)
}

/// What code in a language other than shell does, as far as a scan can tell.
#[derive(Debug, Default, PartialEq)]
pub struct Found {
    /// Commands it runs, written out in full, as shell text.
    pub commands: Vec<String>,
    /// Paths it deletes, written out in full.
    pub deletes: Vec<String>,
    /// Risky things it does that can only be asked about: (class, reason).
    pub asks: Vec<(&'static str, String)>,
    /// Its plain strings, for the caller's own checks (messaging hosts).
    pub strings: Vec<String>,
}

/// One kind of call: its name and, when the name alone is too common, words that must
/// appear somewhere in the code for it to count (an import, a module name).
type Spec = (&'static str, &'static [&'static str]);

struct Apis {
    spawn: &'static [Spec],
    /// Spawns whose arguments aren't the command line (`os.execvp(path, argv)`): always unknown.
    spawn_opaque: &'static [Spec],
    eval: &'static [&'static str],
    /// Loads code by a name given at run time, unless the name is a plain string.
    load: &'static [&'static str],
    decode: &'static [&'static str],
    delete: &'static [Spec],
    mail: &'static [&'static str],
    /// Calls may leave out the parentheses (`system "git push"`).
    bare_calls: bool,
    /// `obj.eval()` is a method of something else, not the language's eval.
    dotted_eval_is_other: bool,
}

const CP: &[&str] = &["child_process", "execa", "shelljs", "zx"];
const FS: &[&str] = &["'fs'", "\"fs\"", "node:fs", "fs/promises", "fs-extra", "Deno.remove"];

const PYTHON: Apis = Apis {
    spawn: &[
        ("system", &[]),
        ("popen", &[]),
        ("Popen", &[]),
        ("run", &["subprocess"]),
        ("call", &["subprocess"]),
        ("check_call", &[]),
        ("check_output", &[]),
        ("getoutput", &[]),
        ("getstatusoutput", &[]),
        ("create_subprocess_shell", &[]),
        ("create_subprocess_exec", &[]),
        ("spawn", &["pty"]),
    ],
    spawn_opaque: &[
        ("execl", &[]),
        ("execle", &[]),
        ("execlp", &[]),
        ("execlpe", &[]),
        ("execv", &[]),
        ("execve", &[]),
        ("execvp", &[]),
        ("execvpe", &[]),
        ("spawnl", &[]),
        ("spawnle", &[]),
        ("spawnlp", &[]),
        ("spawnlpe", &[]),
        ("spawnv", &[]),
        ("spawnve", &[]),
        ("spawnvp", &[]),
        ("spawnvpe", &[]),
        ("posix_spawn", &[]),
        ("posix_spawnp", &[]),
        ("startfile", &[]),
    ],
    eval: &["eval", "exec", "run_path", "run_module"],
    load: &["__import__", "import_module"],
    decode: &["b64decode", "b32decode", "b16decode", "b85decode", "a85decode", "decodebytes", "unhexlify", "fromhex", "codecs.decode", "decompress", "rot13", "rot_13", "marshal.loads"],
    delete: &[("rmtree", &[]), ("removedirs", &[]), ("remove", &["os.remove", "from os"]), ("unlink", &["os.unlink", "from os", "Path"]), ("rmdir", &["os.rmdir", "from os", "Path"])],
    mail: &["smtplib", "yagmail"],
    bare_calls: false,
    dotted_eval_is_other: true,
};

const JS: Apis = Apis {
    spawn: &[
        ("execSync", &[]),
        ("execFileSync", &[]),
        ("spawnSync", &[]),
        ("exec", CP),
        ("execFile", CP),
        ("spawn", &["child_process", "Bun"]),
        ("execa", &[]),
        ("execaSync", &[]),
        ("execaCommand", &[]),
        ("execaCommandSync", &[]),
    ],
    spawn_opaque: &[("fork", CP), ("Command", &["Deno"]), ("run", &["Deno.run"])],
    eval: &["eval", "Function", "runInNewContext", "runInThisContext", "runInContext", "compileFunction"],
    load: &["require", "import"],
    decode: &["atob", "'base64'", "\"base64\"", "'hex'", "\"hex\"", "fromCharCode", "inflateSync", "gunzipSync", "inflateRawSync", "brotliDecompressSync"],
    delete: &[
        ("rimraf", &[]),
        ("rm", FS),
        ("rmSync", FS),
        ("unlink", FS),
        ("unlinkSync", FS),
        ("rmdir", FS),
        ("rmdirSync", FS),
        ("remove", FS),
        ("removeSync", FS),
        ("emptyDir", FS),
        ("emptyDirSync", FS),
    ],
    mail: &["nodemailer", "@sendgrid/mail", "sendMail("],
    bare_calls: false,
    dotted_eval_is_other: true,
};

const RUBY: Apis = Apis {
    spawn: &[("system", &[]), ("exec", &[]), ("spawn", &[]), ("popen", &[]), ("capture2", &[]), ("capture2e", &[]), ("capture3", &[]), ("popen2", &[]), ("popen3", &[]), ("pipeline", &["Open3"])],
    spawn_opaque: &[],
    eval: &["eval", "instance_eval", "class_eval", "module_eval"],
    load: &[],
    decode: &["decode64", "unpack", "Zlib::Inflate"],
    delete: &[
        ("rm", &["FileUtils"]),
        ("rm_r", &[]),
        ("rm_rf", &[]),
        ("rm_f", &[]),
        ("remove_dir", &[]),
        ("remove_entry", &[]),
        ("remove_entry_secure", &[]),
        ("rmtree", &[]),
        ("rmdir", &["FileUtils", "Dir.", "Pathname"]),
        ("delete", &["File.delete", "Dir.delete", "Pathname"]),
        ("unlink", &["File.unlink", "Dir.unlink", "Pathname"]),
    ],
    mail: &["Net::SMTP", "Mail.deliver", "ActionMailer", "Pony.mail"],
    bare_calls: true,
    dotted_eval_is_other: false,
};

const PERL: Apis = Apis {
    spawn: &[("system", &[]), ("exec", &[])],
    spawn_opaque: &[],
    eval: &["eval"],
    load: &[],
    decode: &["decode_base64", "unpack", "pack(", "uncompress"],
    delete: &[("unlink", &[]), ("rmdir", &[]), ("remove_tree", &[]), ("rmtree", &[])],
    mail: &["Net::SMTP", "MIME::Lite", "Email::Sender", "Mail::Sendmail", "/sendmail"],
    bare_calls: true,
    dotted_eval_is_other: false,
};

const PHP: Apis = Apis {
    spawn: &[("system", &[]), ("exec", &[]), ("shell_exec", &[]), ("passthru", &[]), ("proc_open", &[]), ("popen", &[])],
    spawn_opaque: &[("pcntl_exec", &[])],
    eval: &["eval", "assert", "create_function"],
    load: &[],
    decode: &["base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin", "convert_uudecode"],
    delete: &[("unlink", &[]), ("rmdir", &[])],
    mail: &["mail(", "PHPMailer", "Swift_Mailer"],
    bare_calls: false,
    dotted_eval_is_other: true,
};

/// Scans `code` in `lang` (anything but shell). `name` is how the reasons name it.
pub fn scan(lang: Lang, code: &str, name: &str) -> Found {
    let apis = match lang {
        Lang::Shell => return Found::default(),
        Lang::Python => &PYTHON,
        Lang::Js => &JS,
        Lang::Ruby => &RUBY,
        Lang::Perl => &PERL,
        Lang::Php => &PHP,
    };
    let toks = tokens(lang, code);
    let mut f = Found::default();
    let gated = |spec: &Spec| spec.1.is_empty() || spec.1.iter().any(|g| code.contains(g));
    let unknown_cmd = |api: &str| ("shell_destructive", format!("Runs commands only known when it runs ({api} in {name})"));

    for spec in apis.spawn.iter().filter(|s| gated(s)) {
        let sites = call_sites(&toks, spec.0, apis.bare_calls);
        let mut unknown = false;
        // `platform.system()`: a call with nothing to run is another API of the same name.
        for args in sites.iter().filter(|a| !a.is_empty()) {
            match command_of(args) {
                Some(cmd) => f.commands.push(cmd),
                None => unknown = true,
            }
        }
        if unknown || raw_calls(code, spec.0, apis.bare_calls, false) > sites.len() {
            f.asks.push(unknown_cmd(spec.0));
        }
    }
    for spec in apis.spawn_opaque.iter().filter(|s| gated(s)) {
        if raw_calls(code, spec.0, apis.bare_calls, false) > 0 {
            f.asks.push(unknown_cmd(spec.0));
        }
    }
    // A risky API under another name (`from subprocess import run as r`, `f = os.system`,
    // `getattr(os, 'system')`) can't be followed to its calls.
    for spec in apis.spawn.iter().chain(apis.spawn_opaque).chain(apis.delete).filter(|s| gated(s)) {
        if let Some(how) = renamed(&toks, spec.0, apis.bare_calls) {
            f.asks.push(("shell_destructive", format!("Uses {} {how}, so SuperBot can't follow what it runs ({} in {name})", spec.0, spec.0)));
        }
    }
    if lang == Lang::Php && toks.windows(2).any(|w| matches!(w, [Tok::Ident(v), Tok::Punct('(')] if v.starts_with('$'))) {
        f.asks.push(unknown_cmd("a function named by a variable"));
    }
    // Command literals: backticks in Ruby, Perl, and PHP, and zx's $`…` in JavaScript.
    for (k, t) in toks.iter().enumerate() {
        let Tok::Str { text, dynamic, backtick: true } = t else { continue };
        let zx = lang == Lang::Js && k > 0 && toks[k - 1] == Tok::Ident("$".into());
        if lang == Lang::Js && !zx {
            continue;
        }
        if *dynamic {
            f.asks.push(unknown_cmd("`…`"));
        } else {
            f.commands.push(text.clone());
        }
    }
    let quoted_cmd = (lang == Lang::Ruby && has_quote_op(code, "%x")) || (lang == Lang::Perl && has_quote_op(code, "qx"));
    if quoted_cmd {
        f.asks.push(unknown_cmd(if lang == Lang::Ruby { "%x" } else { "qx" }));
    }
    if lang == Lang::Perl && toks.iter().any(|t| matches!(t, Tok::Str { text, .. } if text.starts_with('|') || text.ends_with('|'))) {
        f.asks.push(unknown_cmd("open with a pipe"));
    }

    let decodes = apis.decode.iter().find(|d| code.contains(*d));
    for e in apis.eval {
        if raw_calls(code, e, apis.bare_calls, apis.dotted_eval_is_other) > 0 {
            let why = match decodes {
                Some(d) => format!("Decodes hidden code and runs it ({} and {e} in {name})", d.trim_matches(['\'', '"', '('])),
                None => format!("Runs code only known when it runs ({e} in {name})"),
            };
            f.asks.push(("shell_destructive", why));
        }
    }
    for l in apis.load {
        let sites = call_sites(&toks, l, false);
        let fixed = sites.iter().filter(|a| matches!(a.as_slice(), [Arg::Lit(_)])).count();
        if raw_calls(code, l, false, true) > fixed {
            f.asks.push(("shell_destructive", format!("Loads code chosen when it runs ({l} in {name})")));
        }
    }

    for spec in apis.delete.iter().filter(|s| gated(s)) {
        let sites = call_sites(&toks, spec.0, apis.bare_calls);
        let mut unknown = false;
        for args in &sites {
            if args.iter().all(|a| matches!(a, Arg::Opt(_))) {
                unknown = true;
            }
            for a in args {
                match a {
                    Arg::Lit(p) => f.deletes.push(p.clone()),
                    Arg::List(ps) => f.deletes.extend(ps.iter().cloned()),
                    Arg::Opt(keys) if keys.iter().any(|k| k == "dir_fd" || CHANGES_RUN.contains(&k.as_str())) => unknown = true,
                    Arg::Opt(_) => {}
                    Arg::Dynamic => unknown = true,
                }
            }
        }
        if unknown || raw_calls(code, spec.0, apis.bare_calls, false) > sites.len() {
            f.asks.push(("file_delete", format!("Deletes files at paths only known when it runs ({} in {name})", spec.0)));
        }
    }
    if let Some(m) = apis.mail.iter().find(|m| code.contains(*m)) {
        f.asks.push(("outbound_message", format!("Sends email ({} in {name})", m.trim_end_matches('('))));
    }
    f.strings = toks.into_iter().filter_map(|t| if let Tok::Str { text, dynamic: false, .. } = t { Some(text) } else { None }).collect();
    f
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str { text: String, dynamic: bool, backtick: bool },
    Punct(char),
}

fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// A rough tokenizer: names, strings (with interpolation marked dynamic), and single
/// punctuation characters. Comments are dropped. Escapes that hide characters (`\x67`)
/// make a string dynamic, so a command spelled with them is unknown, not harmless.
fn tokens(lang: Lang, code: &str) -> Vec<Tok> {
    let s: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let hash_comments = matches!(lang, Lang::Python | Lang::Ruby | Lang::Perl | Lang::Php);
    let slash_comments = matches!(lang, Lang::Js | Lang::Php);
    while i < s.len() {
        let c = s[i];
        let next = s.get(i + 1).copied();
        let hash = c == '#' && hash_comments && !(lang == Lang::Perl && i > 0 && s[i - 1] == '$');
        if hash || (c == '/' && slash_comments && next == Some('/')) {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && slash_comments && next == Some('*') {
            i += 2;
            while i < s.len() && !(s[i] == '*' && s.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if c == '\'' || c == '"' || (c == '`' && lang != Lang::Python) {
            let prefix = match out.last() {
                Some(Tok::Ident(p)) if lang == Lang::Python && i > 0 && ident_char(s[i - 1]) && p.len() <= 2 && p.chars().all(|c| "rRbBuUfF".contains(c)) => {
                    let p = p.clone();
                    out.pop();
                    p
                }
                _ => String::new(),
            };
            let triple = lang == Lang::Python && next == Some(c) && s.get(i + 2) == Some(&c);
            i += if triple { 3 } else { 1 };
            let mut text = String::new();
            let mut hidden = false;
            while i < s.len() {
                if triple && s[i] == c && s.get(i + 1) == Some(&c) && s.get(i + 2) == Some(&c) {
                    i += 3;
                    break;
                }
                if !triple && s[i] == c {
                    i += 1;
                    break;
                }
                if s[i] == '\\' && i + 1 < s.len() && !prefix.contains(['r', 'R']) {
                    i += 1;
                    match s[i] {
                        'n' => text.push('\n'),
                        't' => text.push('\t'),
                        e @ ('\\' | '\'' | '"' | '`' | '$' | ' ') => text.push(e),
                        '\n' => {}
                        e => {
                            hidden = true;
                            text.push('\\');
                            text.push(e);
                        }
                    }
                } else {
                    text.push(s[i]);
                }
                i += 1;
            }
            let interpolates = match (lang, c) {
                (Lang::Python, _) => prefix.contains(['f', 'F']) && text.contains('{'),
                (Lang::Js, '`') => text.contains("${"),
                (Lang::Ruby, '"' | '`') => text.contains("#{"),
                (Lang::Perl | Lang::Php, '"' | '`') => text.contains('$') || (lang == Lang::Perl && text.contains('@')),
                _ => false,
            };
            out.push(Tok::Str { text, dynamic: hidden || interpolates, backtick: c == '`' });
        } else if ident_char(c) {
            let start = i;
            while i < s.len() && ident_char(s[i]) {
                i += 1;
            }
            out.push(Tok::Ident(s[start..i].iter().collect()));
        } else {
            if !c.is_whitespace() || c == '\n' {
                out.push(Tok::Punct(c));
            }
            i += 1;
        }
    }
    out
}

/// How `name` is used other than by calling it: renamed on import, assigned, passed
/// along, or named in a string. Importing it under its own name is fine.
fn renamed(toks: &[Tok], name: &str, bare: bool) -> Option<&'static str> {
    // Names too common as plain words to count in strings.
    const COMMON: [&str; 6] = ["run", "call", "remove", "delete", "rm", "spawn"];
    for (k, t) in toks.iter().enumerate() {
        match t {
            Tok::Str { text, .. } if text == name && !COMMON.contains(&name) => return Some("by a name in a string"),
            Tok::Ident(n) if n == name => {}
            _ => continue,
        }
        let next = toks.get(k + 1);
        let called = match next {
            Some(Tok::Punct('(')) => true,
            Some(Tok::Str { .. } | Tok::Ident(_) | Tok::Punct('[')) if bare => !matches!(next, Some(Tok::Ident(a)) if a == "as"),
            _ => false,
        };
        if called {
            continue;
        }
        if matches!(next, Some(Tok::Ident(a)) if a == "as") || matches!(next, Some(Tok::Punct(':'))) && !matches!(toks.get(k + 2), Some(Tok::Punct(':'))) {
            return Some("under another name");
        }
        // The statement it is in: an import or require naming it as itself is fine.
        let start = toks[..k].iter().rposition(|t| matches!(t, Tok::Punct('\n' | ';'))).map_or(0, |p| p + 1);
        let end = toks[k..].iter().position(|t| matches!(t, Tok::Punct('\n' | ';'))).map_or(toks.len(), |p| k + p);
        let import = toks[start..end].iter().any(|t| matches!(t, Tok::Ident(w) if ["import", "require", "use"].contains(&w.as_str())));
        if import {
            continue;
        }
        // `def system(…)` / `function exec(…)` define their own, called like the real one.
        if matches!(toks.get(k.wrapping_sub(1)), Some(Tok::Ident(d)) if ["def", "function", "sub"].contains(&d.as_str())) {
            continue;
        }
        return Some("without calling it directly");
    }
    None
}

/// One argument of a call.
#[derive(Debug, PartialEq)]
enum Arg {
    Lit(String),
    List(Vec<String>),
    /// A keyword argument or options object, with the option names it sets.
    Opt(Vec<String>),
    Dynamic,
}

/// The arguments of each call of `name` in `toks`: `name(…)`, or with `bare`,
/// `name "…"` up to the end of the line.
fn call_sites(toks: &[Tok], name: &str, bare: bool) -> Vec<Vec<Arg>> {
    let mut out = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if *t != Tok::Ident(name.into()) {
            continue;
        }
        let (start, paren) = match toks.get(k + 1) {
            Some(Tok::Punct('(')) => (k + 2, true),
            Some(Tok::Str { .. } | Tok::Ident(_) | Tok::Punct('[')) if bare => (k + 1, false),
            _ => continue,
        };
        let mut depth = 0usize;
        let mut args = vec![Vec::new()];
        for t in &toks[start..] {
            match t {
                Tok::Punct('(' | '[' | '{') => depth += 1,
                Tok::Punct(')') if depth == 0 && paren => break,
                Tok::Punct(')' | ']' | '}') if depth > 0 => depth -= 1,
                Tok::Punct('\n' | ';' | ')' | '}') if depth == 0 && !paren => break,
                Tok::Punct(',') if depth == 0 => {
                    args.push(Vec::new());
                    continue;
                }
                Tok::Punct('\n') => continue,
                _ => {}
            }
            if let Some(a) = args.last_mut() {
                a.push(t.clone());
            }
        }
        out.push(args.into_iter().filter(|a| !a.is_empty()).map(|a| arg(&a)).collect());
    }
    out
}

fn arg(toks: &[Tok]) -> Arg {
    let lit = |t: &Tok| match t {
        Tok::Str { text, dynamic: false, backtick: false } => Some(text.clone()),
        _ => None,
    };
    match toks {
        [t] if lit(t).is_some() => Arg::Lit(lit(t).unwrap_or_default()),
        [Tok::Ident(k), Tok::Punct('=' | ':'), ..] => Arg::Opt(vec![k.clone()]),
        [Tok::Punct('{'), inner @ ..] => {
            // Every name or string before a `:`, `=>`, or `=` names an option (or, for a
            // Ruby env hash, a variable); nested values are named too, which only asks more.
            let keys = inner.windows(2).filter_map(|w| match w {
                [Tok::Ident(k) | Tok::Str { text: k, .. }, Tok::Punct(':' | '=')] => Some(k.clone()),
                _ => None,
            });
            Arg::Opt(keys.collect())
        }
        [Tok::Punct('['), inner @ .., Tok::Punct(']')] => {
            let items: Option<Vec<String>> = inner.iter().filter(|t| **t != Tok::Punct(',')).map(lit).collect();
            items.map(Arg::List).unwrap_or(Arg::Dynamic)
        }
        _ => Arg::Dynamic,
    }
}

/// The command line a spawn call runs, when every part of it is written out.
fn command_of(args: &[Arg]) -> Option<String> {
    let mut words = Vec::new();
    let mut lits = 0;
    for a in args {
        match a {
            Arg::Lit(s) => {
                lits += 1;
                words.push(s.clone());
            }
            Arg::List(l) => words.extend(l.iter().cloned()),
            // Options that change where or what it runs make the command unknown here.
            Arg::Opt(keys) if keys.iter().any(|k| CHANGES_RUN.contains(&k.as_str())) => return None,
            Arg::Opt(_) => {}
            Arg::Dynamic => return None,
        }
    }
    match (lits, words.len()) {
        (_, 0) => None,
        // One string is a whole command line (`os.system("git push")`, `execSync("…")`).
        (1, 1) => words.pop(),
        _ => Some(words.iter().map(|w| shell_quote(w)).collect::<Vec<_>>().join(" ")),
    }
}

/// Spawn options that change the folder, the program, or its environment (PATH).
const CHANGES_RUN: [&str; 7] = ["cwd", "chdir", "executable", "argv0", "env", "PATH", "unsetenv_others"];

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// How many times `name` appears as a call in the raw text, strings and comments
/// included: a whole word followed by `(`, or with `bare`, by a space and an argument.
/// With `skip_dotted`, `x.name(` is a method of something else and doesn't count.
fn raw_calls(code: &str, name: &str, bare: bool, skip_dotted: bool) -> usize {
    code.match_indices(name)
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            if before.is_some_and(ident_char) || (skip_dotted && before == Some('.')) {
                return false;
            }
            let rest = &code[at + name.len()..];
            let trimmed = rest.trim_start_matches([' ', '\t']);
            if rest.starts_with(ident_char) {
                return false;
            }
            trimmed.starts_with('(') || (bare && trimmed.len() < rest.len() && trimmed.starts_with(|c: char| "\"'`$[:%".contains(c) || c.is_alphabetic()))
        })
        .count()
}

/// Ruby's `%x(…)` or Perl's `qx(…)`, with any delimiter.
fn has_quote_op(code: &str, op: &str) -> bool {
    code.match_indices(op).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + op.len()..].trim_start_matches(' ').chars().next();
        !before.is_some_and(ident_char) && after.is_some_and(|c| !c.is_alphanumeric() && !c.is_whitespace() && c != '_' && c != '=' && c != ',' && c != ';')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(lang: Lang, code: &str) -> Vec<String> {
        scan(lang, code, "x").commands
    }

    fn asks(lang: Lang, code: &str) -> Vec<String> {
        scan(lang, code, "x").asks.into_iter().map(|(_, why)| why).collect()
    }

    #[test]
    fn languages_by_program() {
        for (p, l) in [("python3.12", Lang::Python), ("python", Lang::Python), ("node", Lang::Js), ("bash", Lang::Shell), ("zsh", Lang::Shell), ("ruby", Lang::Ruby), ("perl5", Lang::Perl), ("php8.2", Lang::Php)] {
            assert_eq!(Lang::of(p), Some(l), "{p}");
        }
        assert_eq!(Lang::of("awk"), None);
        assert_eq!(Lang::of("git"), None);
    }

    #[test]
    fn shebangs() {
        assert_eq!(shebang("#!/bin/bash\necho"), Some(Some("bash".into())));
        assert_eq!(shebang("#!/usr/bin/env python3\n"), Some(Some("python3".into())));
        assert_eq!(shebang("#!/usr/bin/env -S -u X A=b node --flag\n"), Some(Some("node".into())));
        assert_eq!(shebang("#!\n"), Some(None));
        assert_eq!(shebang("echo hi\n"), None);
    }

    #[test]
    fn binaries_are_not_scripts() {
        assert!(is_binary(b"\x7fELF\x02\x01"));
        assert!(is_binary(b"ab\0cd\nmore"));
        assert!(!is_binary(b"echo hi\n\0later"));
        assert!(!is_binary(b"#!/bin/sh\n\0"));
        assert!(!is_binary("echo caf\u{e9}".as_bytes()));
    }

    #[test]
    fn written_out_commands_are_found() {
        assert_eq!(cmds(Lang::Python, "import os\nos.system('git push origin main')"), ["git push origin main"]);
        assert_eq!(cmds(Lang::Python, "import subprocess\nsubprocess.run(['git', 'push'], check=True)"), ["'git' 'push'"]);
        assert_eq!(cmds(Lang::Python, "import subprocess as sp\nsp.check_output(\"rm -rf /tmp/x\", shell=True)"), ["rm -rf /tmp/x"]);
        assert_eq!(cmds(Lang::Js, "const { execSync } = require('child_process');\nexecSync('git push', { stdio: 'inherit' })"), ["git push"]);
        assert_eq!(cmds(Lang::Js, "const cp = require('child_process'); cp.spawn('git', ['push', '--force'])"), ["'git' 'push' '--force'"]);
        assert_eq!(cmds(Lang::Js, "import { $ } from 'zx'; await $`git push`"), ["git push"]);
        assert_eq!(cmds(Lang::Ruby, "system \"git push\"\nputs 1"), ["git push"]);
        assert_eq!(cmds(Lang::Ruby, "out = `git push`"), ["git push"]);
        assert_eq!(cmds(Lang::Perl, "system('git', 'push');"), ["'git' 'push'"]);
        assert_eq!(cmds(Lang::Php, "<?php shell_exec('git push');"), ["git push"]);
        assert!(asks(Lang::Python, "import os\nos.system('git push')").is_empty());
    }

    #[test]
    fn harmless_code_asks_nothing() {
        for (lang, code) in [
            (Lang::Python, "import json\nprint(json.dumps({'a': 1}))"),
            (Lang::Python, "import re\nre.compile(r'\\d+').match('1')\nmodel.eval()\nitems.remove(3)"),
            (Lang::Js, "const fs = require('fs');\nconsole.log(fs.readFileSync('a.txt', 'utf8'))\n/x/.exec('y')"),
            (Lang::Js, "const m = require('./lib'); import('./mod.js')"),
            (Lang::Ruby, "h = {}\nh.delete(:a)\nputs 'hi'"),
            (Lang::Perl, "my $x = eval { 1 };\nprint \"ok\\n\";"),
            (Lang::Php, "<?php echo 'hi';"),
        ] {
            let f = scan(lang, code, "x");
            assert!(f.asks.is_empty() && f.commands.is_empty() && f.deletes.is_empty(), "{code}: {f:?}");
        }
    }

    #[test]
    fn commands_built_at_run_time_ask() {
        for (lang, code) in [
            (Lang::Python, "import os\nos.system(cmd)"),
            (Lang::Python, "import os\nos.system('git ' + 'push')"),
            (Lang::Python, "import os\nos.system(f'git {verb}')"),
            (Lang::Python, "import os\nos.system('\\x67it push')"),
            (Lang::Python, "import os\nos.execvp('git', ['git', 'push'])"),
            (Lang::Js, "require('child_process').exec(`git ${verb}`)"),
            (Lang::Js, "const cp = require('child_process'); cp.fork('./worker.js')"),
            (Lang::Js, "new Deno.Command('git', { args: ['push'] })"),
            (Lang::Ruby, "system(\"git #{verb}\")"),
            (Lang::Ruby, "x = %x(git push)"),
            (Lang::Perl, "my $o = qx{git push};"),
            (Lang::Perl, "open(my $fh, '|-', 'git push');"),
            (Lang::Perl, "system(\"git $verb\");"),
            (Lang::Php, "<?php system($cmd);"),
        ] {
            let a = asks(lang, code);
            assert!(a.iter().any(|w| w.starts_with("Runs commands only known when it runs")), "{code}: {a:?}");
        }
    }

    #[test]
    fn renamed_apis_ask() {
        for (lang, code) in [
            (Lang::Python, "import os\nf = os.system\nf('git push')"),
            (Lang::Python, "from subprocess import run as r\nr(['git', 'push'])"),
            (Lang::Python, "import os\ngetattr(os, 'system')('git push')"),
            (Lang::Python, "import subprocess\nlist(map(subprocess.check_output, cmds))"),
            (Lang::Js, "const { execSync: x } = require('child_process'); x('git push')"),
            (Lang::Js, "import { execSync as x } from 'child_process'; x('git push')"),
            (Lang::Js, "const cp = require('child_process'); cp['execSync']('git push')"),
            (Lang::Ruby, "m = method(:system)\nm.call('git push')"),
            (Lang::Php, "<?php $f = 'sys' . 'tem'; $f('git push');"),
        ] {
            let a = asks(lang, code);
            assert!(!a.is_empty(), "{code}: {a:?}");
        }
        // Importing under its own name is not renaming.
        assert!(asks(Lang::Python, "from subprocess import run, PIPE\nrun(['ls'], stdout=PIPE)").is_empty());
        assert!(asks(Lang::Js, "const { execSync } = require('child_process'); execSync('ls')").is_empty());
    }

    #[test]
    fn options_that_change_the_run_and_every_deleted_path() {
        assert!(!asks(Lang::Python, "import subprocess\nsubprocess.run(['rm', '-rf', 'build'], cwd='/tmp')").is_empty());
        assert!(!asks(Lang::Js, "require('child_process').execSync('rm -rf build', { cwd: '/tmp' })").is_empty());
        assert!(!asks(Lang::Ruby, "system('rm -rf build', chdir: '/tmp')").is_empty());
        assert_eq!(cmds(Lang::Python, "import subprocess\nsubprocess.run(['ls'], check=True, text=True)"), ["'ls'"]);
        assert_eq!(scan(Lang::Ruby, "File.delete('local.tmp', '/tmp/important.txt')", "x").deletes, ["local.tmp", "/tmp/important.txt"]);
        assert_eq!(scan(Lang::Perl, "unlink 'local.tmp', '/tmp/important.txt';", "x").deletes, ["local.tmp", "/tmp/important.txt"]);
        assert!(!scan(Lang::Perl, "unlink 'a', $b;", "x").asks.is_empty());
        assert!(!scan(Lang::Python, "from pathlib import Path\nPath(p).unlink()", "x").asks.is_empty());
    }

    #[test]
    fn hidden_code_is_flagged() {
        let a = asks(Lang::Python, "import base64\nexec(base64.b64decode('Z2l0IHB1c2g='))");
        assert_eq!(a, ["Decodes hidden code and runs it (b64decode and exec in x)"]);
        assert_eq!(asks(Lang::Python, "eval(input())"), ["Runs code only known when it runs (eval in x)"]);
        assert!(asks(Lang::Js, "eval(atob('Z2l0'))")[0].starts_with("Decodes hidden code and runs it"));
        assert!(asks(Lang::Js, "new Function(Buffer.from(s, 'base64').toString())()")[0].starts_with("Decodes hidden code"));
        assert!(asks(Lang::Ruby, "eval(Base64.decode64(s))")[0].starts_with("Decodes hidden code"));
        assert!(asks(Lang::Perl, "eval decode_base64($s);")[0].starts_with("Decodes hidden code"));
        assert!(asks(Lang::Php, "<?php eval(base64_decode($s));")[0].starts_with("Decodes hidden code"));
        assert_eq!(asks(Lang::Python, "m = __import__(name)"), ["Loads code chosen when it runs (__import__ in x)"]);
        assert_eq!(asks(Lang::Js, "require(name)"), ["Loads code chosen when it runs (require in x)"]);
    }

    #[test]
    fn deletes_and_mail() {
        let f = scan(Lang::Python, "import shutil, os\nshutil.rmtree('/etc/x')\nos.remove(path)", "x");
        assert_eq!(f.deletes, ["/etc/x"]);
        assert_eq!(f.asks, [("file_delete", "Deletes files at paths only known when it runs (remove in x)".to_string())]);
        assert_eq!(scan(Lang::Js, "const fs = require('fs'); fs.rmSync('/tmp/a', { recursive: true })", "x").deletes, ["/tmp/a"]);
        assert_eq!(scan(Lang::Perl, "unlink '/etc/passwd';", "x").deletes, ["/etc/passwd"]);
        assert_eq!(asks(Lang::Python, "import smtplib\ns = smtplib.SMTP('h')"), ["Sends email (smtplib in x)"]);
        assert!(scan(Lang::Python, "requests.post('https://hooks.slack.com/services/x')", "x").strings.contains(&"https://hooks.slack.com/services/x".to_string()));
    }

    #[test]
    fn reading_stays_in_the_workspace() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("superbot-scripts-{}", crate::short_id()));
        let ws = root.join("ws");
        std::fs::create_dir_all(ws.join("sub")).unwrap();
        std::fs::write(ws.join("a.sh"), "git push\n").unwrap();
        std::fs::write(root.join("outside.sh"), "rm -rf /\n").unwrap();
        symlink(root.join("outside.sh"), ws.join("out.sh")).unwrap();
        symlink(ws.join("a.sh"), ws.join("sub/in.sh")).unwrap();
        std::fs::write(ws.join("big.sh"), "#".repeat(MAX_SCRIPT_BYTES + 1)).unwrap();
        std::fs::write(ws.join("app"), b"\x7fELF\x02\x01\x01\0").unwrap();
        assert_eq!(read(&ws, &ws.join("a.sh")), Source::Text("git push\n".into()));
        assert_eq!(read(&ws, &ws.join("sub/in.sh")), Source::Text("git push\n".into()));
        assert_eq!(read(&ws, &ws.join("out.sh")), Source::LinksOutside(std::fs::canonicalize(root.join("outside.sh")).unwrap()));
        assert_eq!(read(&ws, &ws.join("nope.sh")), Source::Missing);
        assert_eq!(read(&ws, &ws.join("big.sh")), Source::TooBig);
        assert_eq!(read(&ws, &ws.join("sub")), Source::Unreadable("it isn't a regular file"));
        assert_eq!(read(&ws, &ws.join("app")), Source::Binary);
        assert_eq!(read(&root.join("gone"), &ws.join("a.sh")), Source::Unreadable("the workspace isn't on this server"));
        let fifo = ws.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read(&ws, &fifo), Source::Unreadable("it isn't a regular file"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
