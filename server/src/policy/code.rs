//! Code a command runs besides itself (ADR 0053): script files, `-c` strings,
//! here-documents, text piped into an interpreter, and decoded payloads. Script files
//! are read from the workspace and classified like the command line that runs them;
//! code SuperBot can't see before it runs asks, one call at a time.

use super::{
    Ctx, Cwds, DOWNLOADED_SCRIPT, MESSAGING_HOSTS, Script, UNREADABLE, Walk, classify_program,
    classify_shell, deletion, program, quote, strip_wrappers, unreadable,
};
use crate::scripts::{self, Lang, Source};
use crate::shell::{Command, Input, Word};
use std::path::Path;

type Out = Vec<(&'static str, String)>;

/// One parsed command line, with what it needs to classify its commands.
pub(super) struct Level<'a> {
    pub s: &'a Script,
    /// Every folder its commands may run in.
    pub cwds: &'a Cwds,
    /// The same, for commands that run before any `source` here.
    pub unsourced: &'a Cwds,
    pub ctx: &'a Ctx,
    pub depth: usize,
    /// Its standard input may carry code from outside it.
    pub input: bool,
}

/// Where an interpreter gets its code.
enum Code {
    /// `-c '…'`, `-e '…'`: the code itself.
    Inline(Word, &'static str),
    File(Word),
    Stdin,
    /// `python -m name`: a module, read when it is a file in the workspace.
    Module(Word),
    /// A subcommand, not a file SuperBot reads.
    Nothing,
}

/// Programs whose risk depends on their arguments, so arguments `xargs` adds can't be checked.
const ARGUMENT_SENSITIVE: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "srm",
    "trash",
    "trash-put",
    "find",
    "git",
    "gh",
    "curl",
    "wget",
    "http",
    "xh",
    "sudo",
    "doas",
    "su",
    "env",
    "eval",
    "source",
    ".",
    "chmod",
    "chown",
    "dd",
    "docker",
    "systemctl",
    "sendmail",
    "mail",
    "npm",
    "pip",
    "pip3",
    "cargo",
    "apt-get",
];

/// Programs that only read a file they name, so naming the script doesn't change it.
const READS_ONLY: &[&str] = &[
    "chmod",
    "ls",
    "cat",
    "test",
    "[",
    "stat",
    "file",
    "head",
    "tail",
    "wc",
    "less",
    "echo",
    "printf",
    "grep",
    "diff",
    "sha256sum",
    "md5sum",
    "realpath",
    "readlink",
    "shellcheck",
];

const DOWNLOADERS: [&str; 2] = ["curl", "wget"];

/// At most this much of a command is quoted in a reason.
const DETAIL_MAX: usize = 60;

impl Level<'_> {
    pub fn classify(&self, w: &mut Walk, out: &mut Out) {
        self.note_changes(w, out);
        for (k, (c, eval)) in self.s.cmds.iter().zip(&self.s.evals).enumerate() {
            let (words, xargs) = strip_wrappers(&c.argv, out);
            let Some(first) = words.first() else { continue };
            let fed = self.fed(c);
            if first.dynamic {
                self.unknown_code("a command", &first.text, out);
                continue;
            }
            let mut prog = program(&first.text);
            if xargs && (Lang::of(&prog).is_some() || ARGUMENT_SENSITIVE.contains(&prog.as_str())) {
                out.push((
                    "shell_destructive",
                    format!("Runs {prog} with arguments from xargs, which SuperBot can't check"),
                ));
            }
            if let Some((how, code)) = runs_string(&prog, &words[1..]) {
                match code {
                    Some(code) if !code.dynamic => {
                        classify_shell(&code.text, self.cwds, self.ctx, self.depth + 1, w, fed, out)
                    }
                    _ => self.unknown_code("a script", &how, out),
                }
                continue;
            }
            if prog == "eval" {
                match eval {
                    Some(Ok(inner)) => Level {
                        s: inner,
                        depth: self.depth + 1,
                        input: fed,
                        ..*self
                    }
                    .classify(w, out),
                    Some(Err(e)) => unreadable(e, out),
                    None => {
                        let substituted = words[1..]
                            .iter()
                            .any(|a| a.text.contains("$(") || a.text.contains('`'));
                        self.unknown_code(
                            "code",
                            if substituted { "eval $(…)" } else { "eval" },
                            out,
                        )
                    }
                }
                continue;
            }
            if prog == "alias" {
                for value in words[1..]
                    .iter()
                    .filter_map(|a| a.text.split_once('=').map(|(_, v)| v))
                {
                    let mut found = Vec::new();
                    classify_shell(
                        value,
                        self.cwds,
                        self.ctx,
                        self.depth + 1,
                        w,
                        fed,
                        &mut found,
                    );
                    out.extend(found.into_iter().filter(|(c, _)| *c != UNREADABLE));
                }
                continue;
            }
            if prog == "source" || prog == "." {
                if let Some(file) = words[1..].iter().find(|a| a.text != "--") {
                    self.run_file(file, Some(Lang::Shell), k, w, out);
                }
                continue;
            }
            if first.text.contains('/') {
                match self.run_file(first, None, k, w, out) {
                    Some(name) => prog = name,
                    None => continue,
                }
            }
            let args: Vec<&str> = words[1..].iter().map(|w| w.text.as_str()).collect();
            if let Some(lang) = Lang::of(&prog) {
                let mut preloads = Vec::new();
                let code = code_arg(lang, &prog, &words[1..], &mut preloads);
                for p in preloads.iter().filter(|p| {
                    p.dynamic
                        || p.text.starts_with(['.', '/', '~'])
                        || script_ext(Path::new(&p.text))
                }) {
                    self.run_file(p, Some(lang), k, w, out);
                }
                match code {
                    Code::Inline(code, flag) if lang == Lang::Shell => match code.dynamic {
                        true => self.unknown_code(
                            "a script",
                            &format!("{prog} {flag} {}", code.text),
                            out,
                        ),
                        false => classify_shell(
                            &code.text,
                            self.cwds,
                            self.ctx,
                            self.depth + 1,
                            w,
                            fed,
                            out,
                        ),
                    },
                    Code::Inline(code, flag) => match code.dynamic {
                        true => {
                            self.unknown_code("code", &format!("{prog} {flag} {}", code.text), out)
                        }
                        false => {
                            self.code(lang, &code.text, &format!("{prog} {flag}"), w, fed, out)
                        }
                    },
                    Code::File(file) => {
                        self.run_file(&file, Some(lang), k, w, out);
                    }
                    Code::Stdin => self.stdin(k, lang, &prog, w, out),
                    Code::Module(m) => self.module(&m, k, w, out),
                    Code::Nothing => {}
                }
                if lang == Lang::Shell {
                    continue;
                }
            }
            if prog == "find" {
                self.find_exec(&args, w, fed, out);
            }
            classify_program(&prog, &args, self.cwds, self.ctx, out);
        }
    }

    /// `python -m name`: runs `name.py` or `name/__main__.py` when one is in a folder
    /// the command may run in; otherwise it is an installed module, as before.
    fn module(&self, m: &Word, k: usize, w: &mut Walk, out: &mut Out) {
        if m.dynamic {
            return self.unknown_code("code", &format!("python -m {}", m.text), out);
        }
        let base = m.text.replace('.', "/");
        for file in [format!("{base}.py"), format!("{base}/__main__.py")] {
            let here = self.unsourced.resolve(self.ctx, &file).unwrap_or_default();
            if here
                .iter()
                .any(|p| p.starts_with(&self.ctx.workspace) && p.exists())
            {
                self.run_file(
                    &Word {
                        text: file,
                        dynamic: false,
                    },
                    Some(Lang::Python),
                    k,
                    w,
                    out,
                );
                return;
            }
        }
    }

    /// Notes, for the whole call, the files this level may change: what it writes to and
    /// what other programs name. Scripts read later that it names ask, and so does naming a
    /// script already read, since one script may rewrite another before it runs.
    fn note_changes(&self, w: &mut Walk, out: &mut Out) {
        const RUNS_OTHERS: [&str; 5] = ["find", "watch", "flock", "script", "make"];
        let base = file_name;
        let mut named = Vec::new();
        for c in &self.s.cmds {
            for target in &c.writes {
                match target.dynamic {
                    true => w.wild_writes = true,
                    false => named.push(base(&target.text)),
                }
            }
            let words = strip_wrappers(&c.argv, &mut Vec::new()).0;
            let Some(first) = words
                .first()
                .filter(|f| !f.dynamic && !f.text.contains('/'))
            else {
                continue;
            };
            let prog = program(&first.text);
            if READS_ONLY.contains(&prog.as_str())
                || RUNS_OTHERS.contains(&prog.as_str())
                || Lang::of(&prog).is_some()
                || ["source", ".", "cd"].contains(&prog.as_str())
            {
                continue;
            }
            named.extend(
                words[1..]
                    .iter()
                    .filter(|a| !a.dynamic && !a.text.starts_with('-'))
                    .map(|a| base(&a.text)),
            );
        }
        note_named(named, w, out);
    }

    /// Whether this command's standard input may carry code from outside the command line.
    fn fed(&self, c: &Command) -> bool {
        self.input || c.pipe_from.is_some() || c.stdin.is_some()
    }

    /// Any command at this level decodes data (`base64 -d`, `xxd -r`, ...).
    fn decodes(&self) -> Option<String> {
        self.s.cmds.iter().find_map(|c| {
            let words = strip_wrappers(&c.argv, &mut Vec::new()).0;
            let args: Vec<&str> = words.iter().skip(1).map(|w| w.text.as_str()).collect();
            words
                .first()
                .filter(|w| !w.dynamic)
                .and_then(|w| decoder(&program(&w.text), &args))
        })
    }

    fn downloads(&self) -> bool {
        self.s.cmds.iter().any(|c| {
            c.argv
                .iter()
                .any(|w| !w.dynamic && DOWNLOADERS.contains(&program(&w.text).as_str()))
        })
    }

    /// Runs `kind` ("a command", "code", "a script") only known when it runs, as `detail`
    /// shows it. Says so when this command line decodes data, runs a command's output,
    /// or downloads something, since that is what it most likely runs.
    fn unknown_code(&self, kind: &str, detail: &str, out: &mut Out) {
        let detail: String = match detail.chars().count() > DETAIL_MAX {
            true => detail.chars().take(DETAIL_MAX).collect::<String>() + "…",
            false => detail.to_string(),
        };
        let why = match self.decodes() {
            Some(d) => format!("Decodes hidden code and runs it ({d}, then {detail})"),
            None if detail.contains("$(") || detail.contains('`') => {
                format!("Runs the output of a command as code ({detail})")
            }
            None => format!("Runs {kind} only known when it runs ({detail})"),
        };
        out.push(("shell_destructive", why));
        if self.downloads() {
            out.push(("network_install", DOWNLOADED_SCRIPT.into()));
        }
    }

    /// Classifies `code` in `lang`, which came from `label` (a file name, "the
    /// here-document", `python3 -c`). What it finds is said to be in `label`; code that
    /// can't be read asks instead of being refused.
    fn code(&self, lang: Lang, code: &str, label: &str, w: &mut Walk, fed: bool, out: &mut Out) {
        let mut found = Vec::new();
        if lang == Lang::Shell {
            classify_shell(
                code,
                self.cwds,
                self.ctx,
                self.depth + 1,
                w,
                fed,
                &mut found,
            );
        } else {
            let f = scripts::scan(lang, code, label);
            let moved = Cwds {
                dirs: self.cwds.dirs.clone(),
                unknown: true,
            };
            let cwds = if f.moves { &moved } else { self.cwds };
            // Any string naming a file may be a file it writes (`open('deploy.sh', 'w')`),
            // except as a word of a command it runs.
            let mut named: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for s in &f.strings {
                *named.entry(file_name(s)).or_default() += 1;
            }
            for word in f.commands.iter().flat_map(|c| c.split_whitespace()) {
                if let Some(n) = named.get_mut(&file_name(word.trim_matches(['\'', '"']))) {
                    *n = n.saturating_sub(1);
                }
            }
            note_named(
                named
                    .into_iter()
                    .filter(|(_, n)| *n > 0)
                    .map(|(s, _)| s)
                    .collect(),
                w,
                &mut found,
            );
            for cmd in &f.commands {
                classify_shell(cmd, cwds, self.ctx, self.depth + 1, w, false, &mut found);
            }
            for p in &f.deletes {
                deletion(self.ctx, cwds, p, &mut |c, why| found.push((c, why)));
            }
            for host in MESSAGING_HOSTS.iter().filter(|h| {
                f.strings
                    .iter()
                    .any(|s| s.to_ascii_lowercase().contains(*h))
            }) {
                found.push((
                    "outbound_message",
                    format!("Sends a message through {}", host.trim_end_matches("://")),
                ));
            }
            found.extend(f.asks);
        }
        let tag = format!("in {label})");
        for (c, why) in found {
            out.push(match c {
                UNREADABLE => (
                    "shell_destructive",
                    format!(
                        "Can't fully check {label}: {}",
                        why.trim_start_matches("Can't check this command safely: ")
                    ),
                ),
                // Kept as is: a downloaded script is approved one call at a time (ADR 0051).
                _ if why.ends_with(&tag) || why == DOWNLOADED_SCRIPT => (c, why),
                _ => (c, format!("{why} ({tag}")),
            });
        }
    }

    /// Runs the script `file` names, with `lang` when an interpreter was named. Reads it
    /// from the workspace and classifies it. Some(program) when it is a program, not a
    /// script SuperBot reads: the caller classifies it by that name, as before.
    fn run_file(
        &self,
        file: &Word,
        lang: Option<Lang>,
        k: usize,
        w: &mut Walk,
        out: &mut Out,
    ) -> Option<String> {
        let ask = |out: &mut Out, why: String| out.push(("shell_destructive", why));
        let name = file.text.as_str();
        if file.dynamic {
            self.unknown_code("a script", name, out);
            return None;
        }
        let sourced = self.s.cmds[..k].iter().any(|c| {
            let words = strip_wrappers(&c.argv, &mut Vec::new()).0;
            words
                .first()
                .is_some_and(|w| w.dynamic || ["source", "."].contains(&program(&w.text).as_str()))
        });
        let cwds = if sourced { self.cwds } else { self.unsourced };
        let Some(places) = cwds.resolve(self.ctx, name) else {
            ask(
                out,
                format!("Runs {name} from a folder SuperBot can't tell, so it can't check it"),
            );
            return None;
        };
        let outside = |p: &Path| lang.is_some() || scratch(p) || script_ext(p);
        let mut program_name = None;
        let mut asked_outside = false;
        // A place where it is missing only fails to run, unless it is missing everywhere.
        let (mut missing, mut found) = (false, false);
        for place in places {
            if !place.starts_with(&self.ctx.workspace) {
                if outside(&place) {
                    asked_outside = true;
                } else {
                    program_name = Some(program(name));
                }
                continue;
            }
            if !self.ctx.readable {
                ask(
                    out,
                    format!("Runs {name} on the Bot's machine, where SuperBot can't read it"),
                );
                continue;
            }
            let base = name.rsplit('/').next().unwrap_or(name).to_string();
            if self.changes(k, name) || w.wild_writes || w.changed.contains(&base) {
                ask(
                    out,
                    format!(
                        "Runs {name} after this same command may change it, so SuperBot can't check what will run"
                    ),
                );
                continue;
            }
            // The same script run again may get other input, so it is checked again. One
            // that runs itself, directly or through others, isn't followed round.
            if w.files.contains(&place) {
                ask(
                    out,
                    format!("Runs {name} from inside itself, which SuperBot doesn't follow"),
                );
                continue;
            }
            if w.reads >= scripts::MAX_FILES {
                ask(
                    out,
                    "Runs more scripts than SuperBot checks in one call".into(),
                );
                continue;
            }
            w.reads += 1;
            w.ran.insert(base.clone());
            let source = scripts::read(&self.ctx.workspace, &place);
            missing |= matches!(source, Source::Missing);
            found |= !matches!(source, Source::Missing);
            match source {
                // Bytecode (`.pyc`) passes bash's binary test but isn't text an interpreter reads as source.
                Source::Text(text) if lang.is_some() && text.contains(['\0', '\u{FFFD}']) => ask(
                    out,
                    format!("Runs {name}, compiled code SuperBot can't read"),
                ),
                Source::Text(text) => {
                    let lang = match (lang, scripts::shebang(&text)) {
                        (Some(l), _) => Some(l),
                        (None, None) => Some(Lang::Shell),
                        (None, Some(Some(i))) => match Lang::of(&i) {
                            Some(l) => Some(l),
                            None => {
                                ask(
                                    out,
                                    format!("Runs {name} with {i}, which SuperBot can't read"),
                                );
                                None
                            }
                        },
                        (None, Some(None)) => {
                            ask(out, format!("Runs {name}, whose #! line names no program"));
                            None
                        }
                    };
                    if let Some(l) = lang {
                        let fed = self.fed(&self.s.cmds[k]);
                        // Named the same however it was typed, so a run grant covers `./x.sh` and `bash x.sh` alike.
                        let label = place
                            .strip_prefix(&self.ctx.workspace)
                            .map_or(name.into(), |p| p.to_string_lossy().into_owned());
                        w.files.push(place.clone());
                        self.code(l, &text, &label, w, fed, out);
                        w.files.pop();
                    }
                }
                Source::Binary if lang.is_none() => program_name = Some(program(name)),
                Source::Binary => ask(
                    out,
                    format!("Runs {name}, compiled code SuperBot can't read"),
                ),
                Source::Missing => {}
                Source::TooBig => ask(
                    out,
                    format!(
                        "Runs {name}, which is too big for SuperBot to check (over {} KB)",
                        scripts::MAX_SCRIPT_BYTES / 1024
                    ),
                ),
                Source::Unreadable(why) => ask(
                    out,
                    format!("Runs {name}, which SuperBot can't read ({why})"),
                ),
                Source::LinksOutside(real) if outside(&real) => ask(
                    out,
                    format!(
                        "Runs {name}, which links outside the workspace, so SuperBot doesn't read it"
                    ),
                ),
                Source::LinksOutside(real) => program_name = Some(program(&real.to_string_lossy())),
            }
        }
        if missing && !found && !asked_outside && program_name.is_none() {
            ask(
                out,
                format!("Runs {name}, which doesn't exist yet, so SuperBot can't check it"),
            );
        }
        if asked_outside {
            ask(
                out,
                format!("Runs {name}, a script outside the workspace that SuperBot doesn't read"),
            );
        }
        program_name
    }

    /// Whether another part of this command line may write the script `name` before it
    /// runs: it is named outside the command that runs it (other than by programs that
    /// only read it), or something writes to a file only known when it runs.
    fn changes(&self, k: usize, name: &str) -> bool {
        let base = name.rsplit('/').next().unwrap_or(name);
        if base.is_empty() {
            return true;
        }
        let count = |t: &str| t.matches(base).count();
        let mut excused = 0;
        for (j, c) in self.s.cmds.iter().enumerate() {
            if c.writes.iter().any(|w| w.dynamic) {
                return true;
            }
            let words = strip_wrappers(&c.argv, &mut Vec::new()).0;
            let prog = words
                .first()
                .filter(|w| !w.dynamic)
                .map(|w| program(&w.text))
                .unwrap_or_default();
            let interpreter = Lang::of(&prog).is_some() || prog == "source" || prog == ".";
            let runs_it = words.first().is_some_and(|w| w.text == name)
                || (interpreter && words.iter().any(|w| w.text == name));
            if j == k || runs_it || READS_ONLY.contains(&prog.as_str()) {
                excused += c.argv.iter().map(|w| count(&w.text)).sum::<usize>();
            }
            if let (true, Some(Input::File(f))) = (j == k, &c.stdin) {
                excused += count(&f.text);
            }
        }
        count(&self.s.src) > excused
    }

    /// An interpreter reading its code from standard input: a here-document, here-string,
    /// file, or the commands piped into it.
    fn stdin(&self, k: usize, lang: Lang, prog: &str, w: &mut Walk, out: &mut Out) {
        let c = &self.s.cmds[k];
        if let Some(input) = &c.stdin {
            self.input_code(input, lang, prog, k, w, out);
            return;
        }
        let Some(j) = c.pipe_from else {
            if self.input || self.s.src.contains(['|', '<']) {
                out.push((
                    "shell_destructive",
                    format!("Runs {prog} reading code from its input, which SuperBot can't follow"),
                ));
            }
            return;
        };
        let chain: Vec<&Command> = std::iter::successors(Some(j), |&j| self.s.cmds[j].pipe_from)
            .map(|j| &self.s.cmds[j])
            .collect();
        let progs: Vec<(String, Vec<String>)> = chain
            .iter()
            .map(|c| {
                let words = strip_wrappers(&c.argv, &mut Vec::new()).0;
                let p = words
                    .first()
                    .map(|w| {
                        if w.dynamic {
                            w.text.clone()
                        } else {
                            program(&w.text)
                        }
                    })
                    .unwrap_or_default();
                (p, words.iter().skip(1).map(|w| w.text.clone()).collect())
            })
            .collect();
        let mut opaque = false;
        if progs.iter().any(|(p, _)| DOWNLOADERS.contains(&p.as_str())) {
            out.push(("network_install", DOWNLOADED_SCRIPT.into()));
            opaque = true;
        }
        if let Some(d) = progs
            .iter()
            .find_map(|(p, a)| decoder(p, &a.iter().map(String::as_str).collect::<Vec<_>>()))
        {
            out.push((
                "shell_destructive",
                format!("Decodes hidden code and runs it ({d} | {prog})"),
            ));
            opaque = true;
        }
        if !opaque {
            self.feed(j, lang, prog, w, out);
        }
    }

    /// What command `j` writes to an interpreter's standard input, checked as its code.
    fn feed(&self, j: usize, lang: Lang, prog: &str, w: &mut Walk, out: &mut Out) {
        let src = &self.s.cmds[j];
        let words = strip_wrappers(&src.argv, &mut Vec::new()).0;
        let name = words
            .first()
            .map(|w| {
                if w.dynamic {
                    w.text.clone()
                } else {
                    program(&w.text)
                }
            })
            .unwrap_or_default();
        let args = &words[1.min(words.len())..];
        let piped = |out: &mut Out| {
            out.push((
                "shell_destructive",
                format!("Runs the output of {name} as code ({name} | {prog})"),
            ))
        };
        match name.as_str() {
            "cat" | "tee" if words.iter().all(|w| !w.dynamic) => {
                let files: Vec<&Word> = args
                    .iter()
                    .filter(|a| !a.text.starts_with('-') || a.text == "-")
                    .collect();
                if name == "cat" && !files.is_empty() {
                    for f in files {
                        self.run_file(f, Some(lang), j, w, out);
                    }
                } else if let Some(input) = &src.stdin {
                    self.input_code(input, lang, prog, j, w, out);
                } else if let Some(i) = src.pipe_from {
                    self.feed(i, lang, prog, w, out);
                } else {
                    piped(out);
                }
            }
            "echo" | "printf" => match echoed(&name, args) {
                Echo::Text(t) => self.code(
                    lang,
                    &t,
                    &format!("the text piped into {prog}"),
                    w,
                    false,
                    out,
                ),
                Echo::Decoded => out.push((
                    "shell_destructive",
                    format!("Decodes hidden code and runs it ({name} | {prog})"),
                )),
                Echo::Dynamic => self.unknown_code("code", &format!("{name} … | {prog}"), out),
                Echo::Opaque => piped(out),
            },
            _ => piped(out),
        }
    }

    fn input_code(
        &self,
        input: &Input,
        lang: Lang,
        prog: &str,
        k: usize,
        w: &mut Walk,
        out: &mut Out,
    ) {
        match input {
            Input::Heredoc { body, expand }
                if *expand && lang != Lang::Shell && body.contains(['$', '`']) =>
            {
                self.unknown_code("code", &format!("a here-document with $… into {prog}"), out)
            }
            Input::Heredoc { body, .. } => {
                self.code(lang, body, "the here-document", w, false, out)
            }
            Input::HereString(word) if word.dynamic => {
                self.unknown_code("code", &format!("{prog} <<< {}", word.text), out)
            }
            Input::HereString(word) => {
                self.code(lang, &word.text, "the here-string", w, false, out)
            }
            Input::File(file) => {
                self.run_file(file, Some(lang), k, w, out);
            }
            Input::Other => out.push((
                "shell_destructive",
                format!("Runs {prog} reading code from an input SuperBot can't read"),
            )),
        }
    }

    /// `find … -exec cmd {} ;`: each command it runs, with `{}` a path under each place it searches.
    fn find_exec(&self, args: &[&str], w: &mut Walk, fed: bool, out: &mut Out) {
        let mut roots: Vec<&str> = args
            .iter()
            .copied()
            .take_while(|a| !a.starts_with('-') && !a.starts_with('(') && !a.starts_with('!'))
            .collect();
        if roots.is_empty() {
            roots.push(".");
        }
        let mut i = 0;
        while i < args.len() {
            if ["-exec", "-execdir", "-ok", "-okdir"].contains(&args[i]) {
                let end = args[i + 1..]
                    .iter()
                    .position(|a| *a == ";" || *a == "+")
                    .map_or(args.len(), |p| i + 1 + p);
                for root in &roots {
                    let found = format!("{}/found", root.trim_end_matches('/'));
                    let text: Vec<String> = args[i + 1..end]
                        .iter()
                        .map(|a| quote(&a.replace("{}", &found)))
                        .collect();
                    if !text.is_empty() {
                        classify_shell(
                            &text.join(" "),
                            self.cwds,
                            self.ctx,
                            self.depth + 1,
                            w,
                            fed,
                            out,
                        );
                    }
                }
                i = end;
            }
            i += 1;
        }
    }
}

fn file_name(t: &str) -> String {
    t.rsplit('/').next().unwrap_or(t).to_string()
}

/// Notes files something in the call may change. Naming a script already read asks;
/// scripts read later that are named ask when they run.
fn note_named(named: Vec<String>, w: &mut Walk, out: &mut Out) {
    for n in named.into_iter().filter(|n| !n.is_empty()) {
        if w.ran.contains(&n) {
            out.push(("shell_destructive", format!("May change {n}, which this call also runs, so SuperBot can't check what will run")));
        }
        w.changed.insert(n);
    }
}

/// Temporary folders anyone can write to: a file there may be anything.
fn scratch(p: &Path) -> bool {
    ["/tmp", "/var/tmp", "/dev/shm"]
        .iter()
        .any(|d| p.starts_with(d))
}

fn script_ext(p: &Path) -> bool {
    const EXT: [&str; 16] = [
        "sh", "bash", "zsh", "ksh", "py", "js", "mjs", "cjs", "ts", "mts", "rb", "pl", "pm", "php",
        "fish", "command",
    ];
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXT.contains(&e.to_ascii_lowercase().as_str()))
}

/// Wrappers that run a string as a command line: `env -S '…'`, `watch '…'`,
/// `script -c '…'`, `flock f -c '…'` or `flock f cmd …`. The string, or None
/// when part of it is only known when it runs.
fn runs_string(prog: &str, args: &[Word]) -> Option<(String, Option<Word>)> {
    let joined = |ws: &[Word], quoted: bool| {
        let dynamic = ws.iter().any(|w| w.dynamic);
        let text = ws
            .iter()
            .map(|w| {
                if quoted {
                    quote(&w.text)
                } else {
                    w.text.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        (!dynamic).then_some(Word {
            text,
            dynamic: false,
        })
    };
    // The value of `-x v`, `-qxv`, `--long v`, or `--long=v`, and the index of the word it is in.
    let value_of = |short: char, long: &str| -> Option<(usize, Option<Word>)> {
        args.iter().enumerate().find_map(|(i, a)| {
            let t = a.text.as_str();
            let known = |v: &str| {
                (!a.dynamic).then(|| Word {
                    text: v.into(),
                    dynamic: false,
                })
            };
            let next = || Some((i + 1, args.get(i + 1).filter(|w| !w.dynamic).cloned()));
            if t == long {
                next()
            } else if let Some(v) = t.strip_prefix(long).and_then(|v| v.strip_prefix('=')) {
                Some((i, known(v)))
            } else if let Some(cluster) = t.strip_prefix('-').filter(|c| !c.starts_with('-')) {
                let at = cluster.find(short)?;
                match &cluster[at + 1..] {
                    "" => next(),
                    v => Some((i, known(v))),
                }
            } else {
                None
            }
        })
    };
    match prog {
        "env" => {
            let (at, value) = value_of('S', "--split-string")?;
            let rest = joined(args.get(at + 1..).unwrap_or_default(), true);
            let code = value.zip(rest).map(|(v, r)| Word {
                text: format!("{} {}", v.text, r.text),
                dynamic: false,
            });
            Some(("env -S".into(), code))
        }
        "script" => value_of('c', "--command").map(|(_, v)| ("script -c".into(), v)),
        "watch" => {
            let mut i = 0;
            let mut exec = false;
            while let Some(a) = args.get(i).filter(|a| a.text.starts_with('-')) {
                exec |= a.text == "-x" || a.text == "--exec";
                i += if a.text == "-n" || a.text == "--interval" {
                    2
                } else {
                    1
                };
            }
            Some((
                "watch".into(),
                joined(args.get(i..).unwrap_or_default(), exec),
            ))
        }
        "flock" => {
            if let Some((_, v)) = value_of('c', "--command") {
                return Some(("flock -c".into(), v));
            }
            let mut i = 0;
            while let Some(a) = args.get(i).filter(|a| a.text.starts_with('-')) {
                i += if ["-w", "--timeout", "-E", "--conflict-exit-code"].contains(&a.text.as_str())
                {
                    2
                } else {
                    1
                };
            }
            let rest = args.get(i + 1..).unwrap_or_default();
            (!rest.is_empty()).then(|| ("flock".into(), joined(rest, true)))
        }
        _ => None,
    }
}

/// Where an interpreter called with `args` gets its code.
/// Files that options load before the code runs (`node --require x.js`, `ruby -r ./x`)
/// go in `preloads`.
fn code_arg(lang: Lang, prog: &str, args: &[Word], preloads: &mut Vec<Word>) -> Code {
    let base = prog.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let mut args = args;
    match base {
        "deno" => match args.first().map(|a| a.text.as_str()) {
            Some("run") => args = &args[1..],
            Some("eval") => {
                return args
                    .get(1)
                    .map_or(Code::Nothing, |c| Code::Inline(c.clone(), "eval"));
            }
            _ => return Code::Nothing,
        },
        "bun" => {
            if args.first().is_some_and(|a| a.text == "run") {
                args = &args[1..];
            }
            if let Some(i) = args
                .iter()
                .position(|a| a.text == "-e" || a.text == "--eval")
            {
                return args
                    .get(i + 1)
                    .map_or(Code::Nothing, |c| Code::Inline(c.clone(), "-e"));
            }
            return match args.iter().find(|a| !a.text.starts_with('-')) {
                Some(f) if f.dynamic || script_ext(Path::new(&f.text)) => Code::File(f.clone()),
                _ => Code::Nothing,
            };
        }
        _ => {}
    }
    let o = options(lang);
    let mut i = 0;
    let mut stdin_mode = false;
    // A shell's `-c` makes its first operand the code; other languages take the next word.
    let mut shell_code: Option<&'static str> = None;
    let mut code: Vec<Word> = Vec::new();
    let mut code_flag = "";
    let mut add = |w: Option<Word>, flag: &'static str| {
        code_flag = flag;
        code.push(w.unwrap_or_default());
    };
    while i < args.len() {
        let a = &args[i];
        let t = a.text.as_str();
        if a.dynamic {
            break;
        }
        if t == "--" {
            i += 1;
            break;
        }
        if t == "-" {
            stdin_mode = true;
            break;
        }
        if let Some(long) = t.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(""));
            match (o.code_long.iter().find(|f| **f == name), t.split_once('=')) {
                (Some(f), Some((_, v))) => add(
                    Some(Word {
                        text: v.into(),
                        dynamic: false,
                    }),
                    f,
                ),
                (Some(f), None) => {
                    add(args.get(i + 1).cloned(), f);
                    i += 1;
                }
                (None, None) if o.value_long.contains(&name.as_str()) => {
                    if o.preload_long.contains(&name.as_str()) {
                        preloads.extend(args.get(i + 1).cloned());
                    }
                    i += 1
                }
                (None, Some((_, v))) if o.preload_long.contains(&name.as_str()) => {
                    preloads.push(Word {
                        text: v.into(),
                        dynamic: a.dynamic,
                    })
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        if (t.starts_with('-') || (lang == Lang::Shell && t.starts_with('+'))) && t.len() > 1 {
            let flags: Vec<char> = t[1..].chars().collect();
            let mut taken = false;
            for (n, ch) in flags.iter().enumerate() {
                let rest: String = flags[n + 1..].iter().collect();
                if t.starts_with('-') && o.code_short.contains(ch) {
                    let flag = ["-c", "-e", "-E", "-p", "-r"]
                        .into_iter()
                        .find(|f| f.ends_with(*ch))
                        .unwrap_or("-c");
                    if lang == Lang::Shell {
                        shell_code = Some(flag);
                        continue;
                    }
                    taken = rest.is_empty();
                    add(
                        if taken {
                            args.get(i + 1).cloned()
                        } else {
                            Some(Word {
                                text: rest,
                                dynamic: false,
                            })
                        },
                        flag,
                    );
                    break;
                }
                let value = || {
                    if rest.is_empty() {
                        args.get(i + 1).cloned()
                    } else {
                        Some(Word {
                            text: rest.clone(),
                            dynamic: false,
                        })
                    }
                };
                if *ch == 'm' && lang == Lang::Python {
                    return value().map_or(Code::Nothing, Code::Module);
                }
                if o.attached.contains(ch) {
                    break;
                }
                if o.value_short.contains(ch) {
                    let v = value();
                    if o.preload_short.contains(ch) {
                        preloads.extend(v);
                    } else if let Some(file) = v
                        .as_ref()
                        .filter(|_| lang == Lang::Php && *ch == 'd')
                        .and_then(|v| {
                            let (key, file) = v.text.split_once('=')?;
                            ["auto_prepend_file", "auto_append_file"]
                                .contains(&key.trim())
                                .then(|| Word {
                                    text: file.into(),
                                    dynamic: v.dynamic,
                                })
                        })
                    {
                        preloads.push(file);
                    }
                    taken = rest.is_empty();
                    break;
                }
                if lang == Lang::Shell && *ch == 's' {
                    stdin_mode = true;
                }
            }
            i += if taken { 2 } else { 1 };
            continue;
        }
        break;
    }
    if !code.is_empty() {
        let dynamic = code.iter().any(|w| w.dynamic);
        let text = code
            .into_iter()
            .map(|w| w.text)
            .collect::<Vec<_>>()
            .join("\n");
        return Code::Inline(Word { text, dynamic }, code_flag);
    }
    if stdin_mode {
        return Code::Stdin;
    }
    match (args.get(i), shell_code) {
        (Some(code), Some(flag)) => Code::Inline(code.clone(), flag),
        (None, Some(_)) => Code::Nothing,
        (Some(file), None) => Code::File(file.clone()),
        (None, None) => Code::Stdin,
    }
}

/// How an interpreter's options read.
struct Options {
    /// Short options whose value is code.
    code_short: &'static [char],
    /// Short options that take a value, attached or as the next word.
    value_short: &'static [char],
    /// Short options whose value is only ever attached (`perl -MFoo`).
    attached: &'static [char],
    code_long: &'static [&'static str],
    value_long: &'static [&'static str],
    /// Options among those that load a file or module before the code.
    preload_short: &'static [char],
    preload_long: &'static [&'static str],
}

fn options(lang: Lang) -> Options {
    let none: Options = Options {
        code_short: &[],
        value_short: &[],
        attached: &[],
        code_long: &[],
        value_long: &[],
        preload_short: &[],
        preload_long: &[],
    };
    match lang {
        Lang::Shell => Options {
            code_short: &['c'],
            value_short: &['o', 'O'],
            code_long: &["--command"],
            value_long: &["--rcfile", "--init-file"],
            ..none
        },
        Lang::Python => Options {
            code_short: &['c'],
            value_short: &['W', 'X', 'Q'],
            value_long: &["--check-hash-based-pycs"],
            ..none
        },
        Lang::Js => Options {
            code_short: &['e', 'p'],
            value_short: &['r', 'C'],
            code_long: &["--eval", "--print"],
            value_long: &[
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--input-type",
                "--conditions",
            ],
            preload_short: &['r'],
            preload_long: &["--require", "--import", "--loader", "--experimental-loader"],
            ..none
        },
        Lang::Ruby => Options {
            code_short: &['e'],
            value_short: &['r', 'I', 'C', 'E', 'F'],
            preload_short: &['r'],
            ..none
        },
        Lang::Perl => Options {
            code_short: &['e', 'E'],
            attached: &['M', 'm', 'I', 'x', 'd', 'D', 'i', 'C', '0', 'l'],
            ..none
        },
        Lang::Php => Options {
            code_short: &['r'],
            value_short: &['d', 'c', 'z'],
            ..none
        },
    }
}

/// A command that turns encoded data back into text or code. Its name as shown.
fn decoder(prog: &str, args: &[&str]) -> Option<String> {
    let short = |c: char| {
        args.iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains(c))
    };
    let has = |f: &str| args.contains(&f);
    let yes = match prog {
        "base64" | "base32" | "basenc" => short('d') || short('D') || has("--decode"),
        "xxd" => short('r') || has("--revert"),
        "openssl" => has("-d"),
        "uudecode" | "gunzip" | "zcat" | "bzcat" | "xzcat" | "unxz" | "unzstd" | "zstdcat"
        | "lz4cat" | "uncompress" | "rev" | "tr" => true,
        "gzip" | "bzip2" | "xz" | "zstd" | "lz4" => {
            short('d') || has("--decompress") || has("--uncompress")
        }
        "printf" => args
            .first()
            .is_some_and(|f| hidden_escapes(f) || f.contains("%b")),
        "echo" => short('e') && args.iter().any(|a| hidden_escapes(a)),
        _ => false,
    };
    let shown = match prog {
        "base64" | "base32" | "basenc" | "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "openssl" => {
            format!("{prog} -d")
        }
        "xxd" => "xxd -r".into(),
        "echo" => "echo -e".into(),
        _ => prog.into(),
    };
    yes.then_some(shown)
}

/// Escapes that spell characters by number (`\x67`, `\147`, `\u0067`).
fn hidden_escapes(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(2)
        .any(|w| w[0] == b'\\' && (matches!(w[1], b'x' | b'u' | b'U') || w[1].is_ascii_digit()))
}

enum Echo {
    Text(String),
    Decoded,
    Dynamic,
    /// Formatting SuperBot doesn't redo (`printf '%s' …`).
    Opaque,
}

/// The text `echo` or `printf` with these arguments writes.
fn echoed(prog: &str, args: &[Word]) -> Echo {
    if args.iter().any(|a| a.dynamic) {
        return Echo::Dynamic;
    }
    let texts: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
    if decoder(prog, &texts).is_some() {
        return Echo::Decoded;
    }
    if prog == "printf" {
        return match texts.as_slice() {
            [f] if !f.contains('%') && !f.contains('\\') => Echo::Text(f.to_string()),
            [f] if !f.contains('%') => Echo::Text(f.replace("\\n", "\n").replace("\\t", "\t")),
            _ => Echo::Opaque,
        };
    }
    let words: Vec<&str> = texts
        .iter()
        .copied()
        .skip_while(|a| {
            a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "neE".contains(c))
        })
        .collect();
    Echo::Text(words.join(" "))
}

#[cfg(test)]
mod tests;
