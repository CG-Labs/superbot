//! Reads a shell command line the way `sh`/`bash` would, to find every simple
//! command it runs. Nothing is executed. Covers quotes (`'…'`, `"…"`, `$'…'`),
//! escapes, `; && || | |& &` and newlines, `( … )` and `{ …; }` groups,
//! `$( … )`, backticks, `<( … )`, `$(( … ))`, `${ … }`, here-documents (whose
//! bodies expand), `case`, `for`, function definitions, and redirections.
//!
//! Anything it can't read for certain is an [`Error`]: callers must treat that as
//! a refusal, not as "no commands". Input size, nesting depth, and command count
//! are bounded, so hostile input can't exhaust the stack or memory.

use std::fmt;

/// Longest command line we read, in characters.
pub const MAX_LEN: usize = 1 << 20;
/// Deepest nesting of substitutions, groups, and `sh -c` scripts.
pub const MAX_DEPTH: usize = 16;
/// Most simple commands in one call.
pub const MAX_COMMANDS: usize = 10_000;
/// Most code parsed for one call, counting each nested `eval` or `sh -c` again.
pub const MAX_TOTAL: usize = 4 * MAX_LEN;

/// One shell word after quote removal. Expansions stay in the text as written
/// (`$HOME/x`) or as a marker (`$(…)`), and make the word `dynamic`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Word {
    pub text: String,
    /// Part of it is only known when the shell runs (a variable or substitution).
    pub dynamic: bool,
}

/// A simple command: its words without redirections and leading reserved words.
#[derive(Clone, Debug, PartialEq)]
pub struct Command {
    pub argv: Vec<Word>,
    /// Index of the command whose output is piped into this one.
    pub pipe_from: Option<usize>,
    /// Where its standard input comes from, when a redirection says (the last one wins).
    pub stdin: Option<Input>,
    /// Files its output redirections write to (`> f`, `>> f`, `&> f`, `<> f`).
    pub writes: Vec<Word>,
}

/// A command's standard input, from a redirection.
#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    /// `<<EOF`: the body as written. `expand` when the delimiter isn't quoted, so the
    /// shell expands `$…` and backticks in it first.
    Heredoc { body: String, expand: bool },
    /// `<<< word`
    HereString(Word),
    /// `< file`
    File(Word),
    /// Anything else, like `<&3`.
    Other,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    TooLong,
    TooDeep,
    TooMany,
    /// Nested code (`eval`, `sh -c`) parsed for one call went over MAX_TOTAL.
    TooMuch,
    Unterminated(&'static str),
    Unexpected(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::TooLong => write!(f, "it is over {MAX_LEN} characters"),
            Error::TooDeep => write!(f, "it nests more than {MAX_DEPTH} levels deep"),
            Error::TooMany => write!(f, "it runs more than {MAX_COMMANDS} commands"),
            Error::TooMuch => write!(f, "its nested code is over {MAX_TOTAL} characters in all"),
            Error::Unterminated(what) => write!(f, "it has an unclosed {what}"),
            Error::Unexpected(c) => write!(f, "it has an unexpected {c:?}"),
        }
    }
}

/// Every simple command in `src`, substitutions before the command that uses them.
/// `depth` is how deeply `src` itself is nested (for `sh -c` scripts).
pub fn parse(src: &str, depth: usize) -> Result<Vec<Command>, Error> {
    if src.len() > MAX_LEN {
        return Err(Error::TooLong);
    }
    if depth > MAX_DEPTH {
        return Err(Error::TooDeep);
    }
    let mut p = Parser::new(src.chars().collect(), depth, Vec::new());
    p.list(false)?;
    Ok(p.out)
}

/// Words that open or close a compound command. They don't name a program.
const RESERVED: [&str; 14] = ["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "time", "esac"];

struct Heredoc {
    id: usize,
    delim: String,
    expand: bool,
    strip_tabs: bool,
    /// The command it is standard input of, once that command ends.
    feeds: Option<usize>,
}

/// Redirections of the simple command being read.
#[derive(Default)]
struct Pending {
    stdin: Option<Input>,
    /// The id of the here-document that is its standard input, if it is one.
    heredoc: Option<usize>,
    writes: Vec<Word>,
    /// The fd digits written right before a redirection (`2>`).
    fd: Option<String>,
}

struct Parser {
    s: Vec<char>,
    i: usize,
    depth: usize,
    out: Vec<Command>,
    heredocs: Vec<Heredoc>,
    next_heredoc: usize,
    pending: Pending,
}

fn is_name(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Parser {
    fn new(s: Vec<char>, depth: usize, out: Vec<Command>) -> Parser {
        Parser { s, i: 0, depth, out, heredocs: Vec::new(), next_heredoc: 0, pending: Pending::default() }
    }

    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn peek_at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.i += 1;
        }
        c
    }

    fn eat(&mut self, c: char) -> bool {
        let yes = self.peek() == Some(c);
        if yes {
            self.i += 1;
        }
        yes
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) || (self.peek() == Some('\\') && self.peek_at(1) == Some('\n')) {
            self.i += if self.peek() == Some('\\') { 2 } else { 1 };
        }
    }

    /// Runs `f` one level deeper, failing past MAX_DEPTH. The commands inside keep their
    /// own redirections apart from the command around them.
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.depth += 1;
        let outer = std::mem::take(&mut self.pending);
        let r = f(self);
        self.pending = outer;
        self.depth -= 1;
        r
    }

    /// Parses `text` (a backtick body or an expanding here-document) as its own
    /// source, one level deeper, adding its commands to ours.
    fn sub(&mut self, text: String, heredoc_body: bool) -> Result<(), Error> {
        self.nested(|p| {
            let mut q = Parser::new(text.chars().collect(), p.depth, std::mem::take(&mut p.out));
            let r = if heredoc_body { q.text(None, &mut Word::default()) } else { q.list(false) };
            p.out = q.out;
            r
        })
    }

    /// Ends the current simple command. Returns its index if it names a program.
    fn end_command(&mut self, argv: &mut Vec<Word>, pipe_from: &mut Option<usize>) -> Result<Option<usize>, Error> {
        let from = pipe_from.take();
        let pending = std::mem::take(&mut self.pending);
        let mut words = std::mem::take(argv);
        let skip = words.iter().take_while(|w| !w.dynamic && RESERVED.contains(&w.text.as_str())).count();
        words.drain(..skip);
        // Loop headers and `function f` name no program; their substitutions are already recorded.
        let header = words.first().is_some_and(|w| !w.dynamic && ["for", "select", "function"].contains(&w.text.as_str()));
        if words.is_empty() || header {
            return Ok(None);
        }
        if self.out.len() >= MAX_COMMANDS {
            return Err(Error::TooMany);
        }
        let idx = self.out.len();
        if let Some(h) = pending.heredoc.and_then(|id| self.heredocs.iter_mut().find(|h| h.id == id)) {
            h.feeds = Some(idx);
        }
        self.out.push(Command { argv: words, pipe_from: from, stdin: pending.stdin, writes: pending.writes });
        Ok(Some(idx))
    }

    /// A command list, up to the end of input or (when `close`) a `)`.
    fn list(&mut self, close: bool) -> Result<(), Error> {
        let mut argv: Vec<Word> = Vec::new();
        let mut pipe_from: Option<usize> = None;
        let mut cases = 0usize;
        let mut want_pattern = false;
        loop {
            if want_pattern {
                self.skip_space_and_comments();
                if self.at_word("esac") {
                    self.i += 4;
                    cases -= 1;
                    want_pattern = false;
                    continue;
                }
                self.case_pattern()?;
                want_pattern = false;
                continue;
            }
            let Some(c) = self.peek() else { break };
            match c {
                ' ' | '\t' => self.i += 1,
                '\\' if self.peek_at(1) == Some('\n') => self.i += 2,
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                '\n' => {
                    self.i += 1;
                    self.end_command(&mut argv, &mut pipe_from)?;
                    self.read_heredocs()?;
                }
                ';' => {
                    self.i += 1;
                    if self.eat(';') || self.eat('&') {
                        self.eat('&');
                        if cases == 0 {
                            return Err(Error::Unexpected(';'));
                        }
                        want_pattern = true;
                    }
                    self.end_command(&mut argv, &mut pipe_from)?;
                }
                '&' if self.peek_at(1) == Some('>') => {
                    self.i += 1;
                    self.redirect(&mut argv)?;
                }
                '&' => {
                    self.i += 1;
                    self.eat('&');
                    self.end_command(&mut argv, &mut pipe_from)?;
                }
                '|' => {
                    self.i += 1;
                    let pipe = !self.eat('|');
                    if pipe {
                        self.eat('&');
                    }
                    let idx = self.end_command(&mut argv, &mut pipe_from)?;
                    if pipe {
                        pipe_from = idx;
                    }
                }
                '(' => {
                    let reserved = |w: &Word| !w.dynamic && RESERVED.contains(&w.text.as_str());
                    let loop_head = matches!(argv.as_slice(), [w] if !w.dynamic && (w.text == "for" || w.text == "select"));
                    if (argv.len() <= 8 && argv.iter().all(reserved)) || loop_head {
                        self.i += 1;
                        if self.eat('(') {
                            self.arith()?;
                        } else {
                            self.nested(|p| p.list(true))?;
                        }
                    } else if self.function_parens(&argv) {
                        argv.clear();
                    } else {
                        return Err(Error::Unexpected('('));
                    }
                }
                ')' if close => {
                    self.i += 1;
                    self.end_command(&mut argv, &mut pipe_from)?;
                    return Ok(());
                }
                ')' => return Err(Error::Unexpected(')')),
                '<' | '>' => self.redirect(&mut argv)?,
                _ => {
                    let w = self.word()?;
                    // `2>file`: digits right before a redirection are its fd, not a word.
                    if matches!(self.peek(), Some('<' | '>')) && !w.dynamic && !w.text.is_empty() && w.text.chars().all(|c| c.is_ascii_digit()) {
                        self.pending.fd = Some(w.text);
                        continue;
                    }
                    let test = !w.dynamic && w.text == "[[" && argv.iter().all(|w| !w.dynamic && RESERVED.contains(&w.text.as_str()));
                    argv.push(w);
                    if test {
                        self.condition()?;
                        argv.push(Word { text: "]]".into(), dynamic: false });
                    }
                    // Headers are short; checking only short commands keeps this linear.
                    if argv.len() <= 8 {
                        let head: Vec<&Word> = argv.iter().skip_while(|w| !w.dynamic && RESERVED.contains(&w.text.as_str())).collect();
                        let plain = |k: usize, s: &str| head.get(k).is_some_and(|w| !w.dynamic && w.text == s);
                        if head.len() == 3 && plain(0, "case") && plain(2, "in") {
                            argv.clear();
                            cases += 1;
                            want_pattern = true;
                        } else if head.len() == 1 && plain(0, "esac") && cases > 0 {
                            argv.clear();
                            cases -= 1;
                        } else if head.len() == 3 && plain(0, "function") && plain(2, "{") {
                            argv.clear();
                        }
                    }
                }
            }
        }
        if close {
            return Err(Error::Unterminated("("));
        }
        self.end_command(&mut argv, &mut pipe_from)?;
        Ok(())
    }

    fn skip_space_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\n') => self.i += 1,
                Some('\\') if self.peek_at(1) == Some('\n') => self.i += 2,
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// The plain word `w` starts here and ends at a separator.
    fn at_word(&self, w: &str) -> bool {
        let n = w.chars().count();
        w.chars().enumerate().all(|(k, c)| self.peek_at(k) == Some(c))
            && self.peek_at(n).is_none_or(|c| c.is_whitespace() || ";&|()<>".contains(c))
    }

    /// The rest of `[[ … ]]`, where `( ) | & < >` are operands, not operators.
    fn condition(&mut self) -> Result<(), Error> {
        loop {
            self.skip_blanks();
            match self.peek() {
                None => return Err(Error::Unterminated("[[")),
                _ if self.at_word("]]") => {
                    self.i += 2;
                    return Ok(());
                }
                Some(';') => return Err(Error::Unexpected(';')),
                Some(c) if "()|&<>\n".contains(c) => self.i += 1,
                Some(_) => {
                    self.word()?;
                }
            }
        }
    }

    /// `name ( )` or `function name ( )`: consumes the parentheses if present.
    fn function_parens(&mut self, argv: &[Word]) -> bool {
        let named = match argv {
            [n] => is_name(&n.text) && !n.dynamic,
            [f, n] => f.text == "function" && !n.dynamic,
            _ => false,
        };
        let mut k = 1;
        while matches!(self.peek_at(k), Some(' ' | '\t')) {
            k += 1;
        }
        if named && self.peek_at(k) == Some(')') {
            self.i += k + 1;
            return true;
        }
        false
    }

    /// One `case` pattern list up to its `)`. Patterns expand, so their
    /// substitutions are recorded.
    fn case_pattern(&mut self) -> Result<(), Error> {
        self.eat('(');
        loop {
            self.skip_blanks();
            match self.peek() {
                None => return Err(Error::Unterminated("case")),
                Some(')') => {
                    self.i += 1;
                    return Ok(());
                }
                Some('|') => self.i += 1,
                Some(c) if c.is_whitespace() || ";&(<>".contains(c) => return Err(Error::Unexpected(c)),
                Some(_) => {
                    self.word()?;
                }
            }
        }
    }

    /// A redirection starting at `<` or `>`. Its target is read (it may expand)
    /// but is not an argument. `<(…)` and `>(…)` are process substitutions.
    fn redirect(&mut self, argv: &mut Vec<Word>) -> Result<(), Error> {
        let stdin = self.pending.fd.take().is_none_or(|fd| fd == "0");
        let c = self.bump().unwrap_or('>');
        if self.peek() == Some('(') {
            self.i += 1;
            self.nested(|p| p.list(true))?;
            argv.push(Word { text: format!("{c}(…)"), dynamic: true });
            return Ok(());
        }
        let (mut here_string, mut read_write) = (false, false);
        if c == '<' && self.eat('<') {
            if !self.eat('<') {
                let strip_tabs = self.eat('-');
                self.skip_blanks();
                let start = self.i;
                let w = self.word()?;
                let raw: String = self.s[start..self.i].iter().collect();
                if raw.is_empty() {
                    return Err(Error::Unterminated("here-document"));
                }
                let (id, expand) = (self.next_heredoc, !raw.contains(['\'', '"', '\\']));
                self.next_heredoc += 1;
                self.heredocs.push(Heredoc { id, delim: w.text, expand, strip_tabs, feeds: None });
                if stdin {
                    self.pending.stdin = Some(Input::Heredoc { body: String::new(), expand });
                    self.pending.heredoc = Some(id);
                }
                return Ok(());
            }
            here_string = true;
        } else if c == '>' {
            let _ = self.eat('>') || self.eat('|');
        } else {
            read_write = self.eat('>');
        }
        let dup = self.eat('&');
        self.skip_blanks();
        let target = match self.peek() {
            None => return Err(Error::Unterminated("redirection")),
            Some(c) if c.is_whitespace() || ";&|()<>".contains(c) => return Err(Error::Unexpected(c)),
            Some(_) => self.word()?,
        };
        let fd_dup = dup && !target.dynamic && (target.text == "-" || target.text.chars().all(|c| c.is_ascii_digit()));
        if c == '>' && !fd_dup || read_write {
            self.pending.writes.push(target.clone());
        }
        if c == '<' && stdin {
            self.pending.heredoc = None;
            self.pending.stdin = Some(match () {
                _ if dup => Input::Other,
                _ if here_string => Input::HereString(target),
                _ => Input::File(target),
            });
        }
        Ok(())
    }

    /// Here-document bodies, which start after the line that opened them.
    fn read_heredocs(&mut self) -> Result<(), Error> {
        for h in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            while self.peek().is_some() {
                let start = self.i;
                while self.peek().is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                let line: String = self.s[start..self.i].iter().collect();
                self.eat('\n');
                let l = if h.strip_tabs { line.trim_start_matches('\t') } else { &line };
                if l == h.delim {
                    break;
                }
                body.push_str(l);
                body.push('\n');
            }
            if let Some(Command { stdin: Some(Input::Heredoc { body: b, .. }), .. }) = h.feeds.and_then(|i| self.out.get_mut(i)) {
                b.clone_from(&body);
            }
            if h.expand && body.contains(['$', '`']) {
                self.sub(body, true)?;
            }
        }
        Ok(())
    }

    /// One word, up to a blank or an operator. Unquoted globs (`gi?`, `[g]it`) and
    /// brace lists (`{a,b}`, `{1..3}`) make it dynamic: the shell picks the words.
    fn word(&mut self) -> Result<Word, Error> {
        let mut w = Word::default();
        let (mut bracket, mut brace, mut list) = (false, false, false);
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | ')' => break,
                '(' if w.text.ends_with('=') && is_name(w.text.trim_end_matches(['=', '+'])) && !w.dynamic => {
                    self.i += 1;
                    self.array()?;
                    w.text.push_str("(…)");
                    w.dynamic = true;
                }
                '(' => break,
                '\\' => {
                    self.i += 1;
                    match self.bump() {
                        Some('\n') | None => {}
                        Some(c) => w.text.push(c),
                    }
                }
                '\'' => {
                    self.i += 1;
                    self.single(&mut w)?;
                }
                '"' => {
                    self.i += 1;
                    self.text(Some('"'), &mut w)?;
                }
                '`' => {
                    self.i += 1;
                    self.backtick()?;
                    w.text.push_str("`…`");
                    w.dynamic = true;
                }
                '$' => {
                    self.i += 1;
                    self.dollar(&mut w, false)?;
                }
                c => {
                    self.i += 1;
                    match c {
                        '*' | '?' => w.dynamic = true,
                        '[' => bracket = true,
                        ']' if bracket => w.dynamic = true,
                        '{' => (brace, list) = (true, false),
                        ',' if brace => list = true,
                        '.' if brace && w.text.ends_with('.') => list = true,
                        '}' if brace && list => w.dynamic = true,
                        _ => {}
                    }
                    w.text.push(c);
                }
            }
        }
        Ok(w)
    }

    /// `name=( … )`: an array's words, which may expand.
    fn array(&mut self) -> Result<(), Error> {
        self.nested(|p| loop {
            p.skip_space_and_comments();
            match p.peek() {
                None => return Err(Error::Unterminated("(")),
                Some(')') => {
                    p.i += 1;
                    return Ok(());
                }
                Some(c) if ";&|(<>".contains(c) => return Err(Error::Unexpected(c)),
                Some(_) => {
                    p.word()?;
                }
            }
        })
    }

    fn single(&mut self, w: &mut Word) -> Result<(), Error> {
        loop {
            match self.bump() {
                None => return Err(Error::Unterminated("'")),
                Some('\'') => return Ok(()),
                Some(c) => w.text.push(c),
            }
        }
    }

    /// `$'…'`: decodes backslash escapes the way bash does. Escapes give bytes, so
    /// `\xc3\xa9` is one character; text that isn't UTF-8 makes the word dynamic, and
    /// a NUL ends the string, as in bash.
    fn ansi(&mut self, w: &mut Word) -> Result<(), Error> {
        let mut bytes = Vec::new();
        let push = |bytes: &mut Vec<u8>, c: char| bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        loop {
            match self.bump() {
                None => return Err(Error::Unterminated("$'")),
                Some('\'') => break,
                Some('\\') => match self.bump() {
                    None => return Err(Error::Unterminated("$'")),
                    Some(c @ ('\\' | '\'' | '"' | '?')) => push(&mut bytes, c),
                    Some('a') => bytes.push(0x07),
                    Some('b') => bytes.push(0x08),
                    Some('e' | 'E') => bytes.push(0x1b),
                    Some('f') => bytes.push(0x0c),
                    Some('n') => bytes.push(b'\n'),
                    Some('r') => bytes.push(b'\r'),
                    Some('t') => bytes.push(b'\t'),
                    Some('v') => bytes.push(0x0b),
                    Some(c @ '0'..='7') => {
                        let n = self.digits(8, 2, c.to_digit(8).unwrap_or(0));
                        bytes.push((n & 0xff) as u8);
                    }
                    Some(c @ ('x' | 'u' | 'U')) => {
                        let max = match c {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let start = self.i;
                        let n = self.digits(16, max, 0);
                        match (c, self.i > start) {
                            (_, false) => bytes.extend_from_slice(&[b'\\', c as u8]),
                            ('x', true) => bytes.push(n as u8),
                            (_, true) => match char::from_u32(n) {
                                Some(ch) => push(&mut bytes, ch),
                                None => w.dynamic = true,
                            },
                        }
                    }
                    Some('c') => match self.bump() {
                        None => return Err(Error::Unterminated("$'")),
                        Some(c) if c.is_ascii() => bytes.push(c.to_ascii_uppercase() as u8 ^ 0x40),
                        Some(_) => w.dynamic = true,
                    },
                    Some(c) => {
                        bytes.push(b'\\');
                        push(&mut bytes, c);
                    }
                },
                Some(c) => push(&mut bytes, c),
            }
        }
        if let Some(nul) = bytes.iter().position(|b| *b == 0) {
            bytes.truncate(nul);
        }
        match String::from_utf8(bytes) {
            Ok(s) => w.text.push_str(&s),
            Err(e) => {
                w.text.push_str(&String::from_utf8_lossy(e.as_bytes()));
                w.dynamic = true;
            }
        }
        Ok(())
    }

    /// Up to `max` more digits in `radix`, after `n`.
    fn digits(&mut self, radix: u32, max: usize, mut n: u32) -> u32 {
        for _ in 0..max {
            let Some(d) = self.peek().and_then(|c| c.to_digit(radix)) else { break };
            n = n * radix + d;
            self.i += 1;
        }
        n
    }

    /// Double-quoted text up to `close`, or (None) an expanding here-document body.
    fn text(&mut self, close: Option<char>, w: &mut Word) -> Result<(), Error> {
        loop {
            match self.bump() {
                None if close.is_none() => return Ok(()),
                None => return Err(Error::Unterminated("\"")),
                Some(c) if Some(c) == close => return Ok(()),
                Some('\\') => match self.bump() {
                    Some('\n') => {}
                    Some(c @ ('$' | '`' | '"' | '\\')) => w.text.push(c),
                    Some(c) => {
                        w.text.push('\\');
                        w.text.push(c);
                    }
                    None => w.text.push('\\'),
                },
                Some('`') => {
                    self.backtick()?;
                    w.text.push_str("`…`");
                    w.dynamic = true;
                }
                Some('$') => self.dollar(w, true)?,
                Some(c) => w.text.push(c),
            }
        }
    }

    /// After `$`: a substitution, parameter, or a literal `$`.
    fn dollar(&mut self, w: &mut Word, quoted: bool) -> Result<(), Error> {
        match self.peek() {
            Some('(') => {
                self.i += 1;
                w.dynamic = true;
                if self.eat('(') {
                    w.text.push_str("$((…))");
                    self.arith()
                } else {
                    w.text.push_str("$(…)");
                    self.nested(|p| p.list(true))
                }
            }
            Some('{') => {
                self.i += 1;
                w.dynamic = true;
                w.text.push_str("${");
                self.param(w, quoted)
            }
            Some('\'') if !quoted => {
                self.i += 1;
                self.ansi(w)
            }
            Some('"') if !quoted => {
                // `$"…"` may be swapped for a translation, so its text isn't known.
                self.i += 1;
                w.dynamic = true;
                self.text(Some('"'), w)
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                w.dynamic = true;
                w.text.push('$');
                while let Some(c) = self.peek().filter(|c| c.is_ascii_alphanumeric() || *c == '_') {
                    w.text.push(c);
                    self.i += 1;
                }
                Ok(())
            }
            Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                self.i += 1;
                w.dynamic = true;
                w.text.push('$');
                w.text.push(c);
                Ok(())
            }
            _ => {
                w.text.push('$');
                Ok(())
            }
        }
    }

    /// `${ … }` after the `${`. Its operands may hold substitutions.
    fn param(&mut self, w: &mut Word, quoted: bool) -> Result<(), Error> {
        self.nested(|p| {
            let mut braces = 0;
            loop {
                match p.bump() {
                    None => return Err(Error::Unterminated("${")),
                    Some('}') if braces == 0 => {
                        w.text.push('}');
                        return Ok(());
                    }
                    Some(c @ ('{' | '}')) => {
                        braces += if c == '{' { 1 } else { -1 };
                        w.text.push(c);
                    }
                    Some('\\') => {
                        p.bump();
                    }
                    Some('\'') if !quoted => p.single(&mut Word::default())?,
                    Some('"') => p.text(Some('"'), &mut Word::default())?,
                    Some('$') => p.dollar(&mut Word::default(), true)?,
                    Some('`') => p.backtick()?,
                    Some(c) => w.text.push(c),
                }
            }
        })
    }

    /// `$(( … ))` or `(( … ))` after the opening parentheses.
    fn arith(&mut self) -> Result<(), Error> {
        self.nested(|p| {
            let mut parens = 0;
            loop {
                match p.bump() {
                    None => return Err(Error::Unterminated("((")),
                    Some('(') => parens += 1,
                    Some(')') if parens > 0 => parens -= 1,
                    Some(')') if p.eat(')') => return Ok(()),
                    Some(')') => return Err(Error::Unexpected(')')),
                    Some('\'') => p.single(&mut Word::default())?,
                    Some('"') => p.text(Some('"'), &mut Word::default())?,
                    Some('$') => p.dollar(&mut Word::default(), true)?,
                    Some('`') => p.backtick()?,
                    Some(_) => {}
                }
            }
        })
    }

    /// A backtick substitution after its opening backtick.
    fn backtick(&mut self) -> Result<(), Error> {
        let mut inner = String::new();
        loop {
            match self.bump() {
                None => return Err(Error::Unterminated("`")),
                Some('`') => break,
                Some('\\') => match self.bump() {
                    None => return Err(Error::Unterminated("`")),
                    Some(c @ ('`' | '\\' | '$')) => inner.push(c),
                    Some(c) => {
                        inner.push('\\');
                        inner.push(c);
                    }
                },
                Some(c) => inner.push(c),
            }
        }
        self.sub(inner, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(src: &str) -> Vec<Vec<String>> {
        parse(src, 0).unwrap().into_iter().map(|c| c.argv.into_iter().map(|w| w.text).collect()).collect()
    }

    fn progs(src: &str) -> Vec<String> {
        cmds(src).into_iter().map(|c| c[0].clone()).collect()
    }

    #[test]
    fn words_and_quotes() {
        assert_eq!(cmds(r#"echo 'a b' "c $HOME" d\ e $'f\'g'"#), [["echo", "a b", "c $HOME", "d e", "f'g"]]);
        assert_eq!(cmds("echo a\\\nb"), [["echo", "ab"]]);
        assert_eq!(cmds("echo {a,b} x#y # comment"), [["echo", "{a,b}", "x#y"]]);
    }

    fn word(src: &str) -> Word {
        parse(&format!("echo {src}"), 0).unwrap().remove(0).argv.remove(1)
    }

    #[test]
    fn ansi_quotes_decode_like_bash() {
        for (src, text) in [
            (r"$'g\x69t'", "git"),
            (r"$'\147\151\164'", "git"),
            (r"$'\u0067it'", "git"),
            (r"$'\U0001F600'", "😀"),
            (r"$'\xc3\xa9'", "é"),
            (r#"$'a\tb\nc\\d\'e\"f\?g'"#, "a\tb\nc\\d'e\"f?g"),
            (r"$'\a\b\e\E\f\r\v'", "\x07\x08\x1b\x1b\x0c\r\x0b"),
            (r"$'\cA\c['", "\x01\x1b"),
            (r"$'\q\x'", "\\q\\x"),
            (r"$'git\0push'", "git"),
            (r"$'\1010'", "A0"),
        ] {
            let w = word(src);
            assert_eq!((w.text.as_str(), w.dynamic), (text, false), "{src}");
        }
        for src in [r"$'\xff'", r"$'\U110000'", r"$'\uD800'"] {
            assert!(word(src).dynamic, "{src}");
        }
        assert_eq!(parse(r"echo $'\'", 0).unwrap_err(), Error::Unterminated("$'"));
    }

    #[test]
    fn globs_and_brace_lists_are_dynamic() {
        for src in ["gi?", "g*", "[g]it", "{git,x}", "{1..3}", "a{b,c}d", "$\"x\""] {
            assert!(word(src).dynamic, "{src}");
        }
        for src in ["[", "a[[", "]", "{", "}", "{}", "{x}", "a,b", "'g*'", "\"gi?\"", r"g\*", "a.b", "{a.b}"] {
            assert!(!word(src).dynamic, "{src}");
        }
    }

    #[test]
    fn separators_and_pipes() {
        assert_eq!(progs("a; b && c || d & e\nf"), ["a", "b", "c", "d", "e", "f"]);
        let p = parse("curl -fsSL x | sh", 0).unwrap();
        assert_eq!((p[1].argv[0].text.as_str(), p[1].pipe_from), ("sh", Some(0)));
        assert_eq!(parse("a || b", 0).unwrap()[1].pipe_from, None);
    }

    #[test]
    fn substitutions_run_too() {
        assert_eq!(progs("echo $(git push)"), ["git", "echo"]);
        assert_eq!(progs(r#"echo "$(git push origin main)""#), ["git", "echo"]);
        assert_eq!(progs("echo \"today: `git push`\""), ["git", "echo"]);
        assert_eq!(progs("echo \"$(echo \"$(rm -rf /)\")\""), ["rm", "echo", "echo"]);
        assert_eq!(progs("diff <(git push) >(rm x)"), ["git", "rm", "diff"]);
        assert_eq!(progs("echo ${x:-$(git push)} $((1 + $(rm y)))"), ["git", "rm", "echo"]);
        assert_eq!(progs("echo `echo \\`git push\\``"), ["git", "echo", "echo"]);
        assert_eq!(progs("echo '$(git push)' \"\\$(git push)\""), ["echo"]);
        assert_eq!(progs("x=$(git push) y=(a $(rm z))"), ["git", "rm", "x=$(…)"]);
    }

    #[test]
    fn compound_commands() {
        assert_eq!(progs("if git pull; then rm -rf /; else echo; fi"), ["git", "rm", "echo"]);
        assert_eq!(progs("for f in $(ls); do rm \"$f\"; done"), ["ls", "rm"]);
        assert_eq!(progs("while true; do git push; done"), ["true", "git"]);
        assert_eq!(progs("(cd /; rm -rf x) && { git push; }"), ["cd", "rm", "git"]);
        assert_eq!(progs("f() { rm -rf /; }; f"), ["rm", "f"]);
        assert_eq!(progs("function g { git push; }"), ["git"]);
        assert_eq!(progs("case $1 in a|b) rm x;; (c) git push;; *) echo;; esac; ls"), ["rm", "git", "echo", "ls"]);
        assert_eq!(progs("echo $(case x in y) git push;; esac)"), ["git", "echo"]);
        assert_eq!(progs("for ((i=0; i<3; i++)); do echo; done"), ["echo"]);
        assert_eq!(progs("! git push"), ["git"]);
    }

    #[test]
    fn redirections_are_not_arguments() {
        assert_eq!(cmds("echo hi >out 2>&1 &>>log < in"), [["echo", "hi"]]);
        assert_eq!(cmds("cat > $(git push)"), [vec!["git", "push"], vec!["cat"]]);
        assert_eq!(cmds("cat <<< \"$(rm x)\""), [vec!["rm", "x"], vec!["cat"]]);
    }

    #[test]
    fn heredocs() {
        assert_eq!(progs("cat <<EOF > f\nhello $(git push)\nEOF\nls"), ["cat", "git", "ls"]);
        assert_eq!(progs("cat <<'EOF'\n$(git push) `rm x`\nEOF\nls"), ["cat", "ls"]);
        assert_eq!(progs("cat <<-\"EOF\"\n\t$(git push)\n\tEOF\nls"), ["cat", "ls"]);
        assert_eq!(progs("cat <<A <<B; rm x\na\nA\n`git push`\nB\nls"), ["cat", "rm", "git", "ls"]);
    }

    #[test]
    fn everyday_commands_parse() {
        for ok in [
            "cd /srv/ws && npm test 2>&1 | tail -20",
            "cat > app.py << 'EOF'\nprint(\"hi $USER\")\nEOF",
            "python3 -c \"import json; print(json.dumps({'a': 1}))\"",
            "find . -name '*.rs' -exec grep -l foo {} \\;",
            "for i in {1..3}; do echo $i; done",
            "awk '{print $1}' f | sort | uniq -c",
            "[ -f x ] && echo yes || echo no",
            "[[ -n \"$X\" && $Y =~ ^(a|b)$ ]] && echo ok",
            "x=$(date +%s); echo ${x}",
            "arr=(a b c); printf '%s\\n' \"${arr[@]}\" ${#arr[@]}",
            "trap 'rm -f $tmp' EXIT",
            "jq '.[] | select(.a == \"b\")' f.json",
            "{ echo a; echo b; } > out 2>/dev/null",
            "while IFS= read -r line; do echo \"$line\"; done < file",
            "cat <<EOF | python3\nprint(1)\nEOF",
            "git commit -m \"fix: handle (parens) and \\\"quotes\\\"\"",
            "if [ \"$(uname)\" = \"Linux\" ]; then echo l; fi",
            "echo hi | tee >(cat) > /dev/null",
            "(( count++ )) || true",
            "nohup ./server > log 2>&1 &",
            "export PATH=\"$HOME/bin:$PATH\"",
            "IFS=, read -ra parts <<< \"$s\"",
            "case \"$1\" in\n  start) run;;\n  *) echo usage;;\nesac",
            "echo it\\'s $'tab\\there' $((2 * 3))",
            "docker run --rm -v \"$PWD\":/w ubuntu bash -c \"ls /w\"",
        ] {
            assert!(parse(ok, 0).is_ok(), "{ok:?}: {:?}", parse(ok, 0));
        }
    }

    #[test]
    fn unreadable_input_is_an_error() {
        for bad in ["echo 'x", "echo \"x", "echo $(x", "echo `x", "echo ${x", "echo $((1", "a )", "echo >", "a (b)", ";;", "cat <<"] {
            assert!(parse(bad, 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hostile_input_is_bounded() {
        let deep = "$(".repeat(10_000) + &")".repeat(10_000);
        assert_eq!(parse(&format!("echo \"{deep}\""), 0), Err(Error::TooDeep));
        assert_eq!(parse(&"( ".repeat(100_000), 0), Err(Error::TooDeep));
        assert_eq!(parse(&"`".repeat(3), MAX_DEPTH), Err(Error::TooDeep));
        assert_eq!(parse(&"a".repeat(MAX_LEN + 1), 0), Err(Error::TooLong));
        assert_eq!(parse(&"a;".repeat(MAX_COMMANDS + 1), 0), Err(Error::TooMany));
        assert_eq!(parse("x", MAX_DEPTH + 1), Err(Error::TooDeep));
        let wide = "a ".repeat(MAX_LEN / 2 - 1);
        let t = std::time::Instant::now();
        assert_eq!(parse(&wide, 0).unwrap()[0].argv.len(), MAX_LEN / 2 - 1);
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "linear time");
    }

    fn one(src: &str) -> Command {
        parse(src, 0).unwrap().pop().unwrap()
    }

    #[test]
    fn standard_input_and_writes() {
        let lit = |s: &str| Word { text: s.into(), dynamic: false };
        assert_eq!(one("sh < cmds.txt").stdin, Some(Input::File(lit("cmds.txt"))));
        assert_eq!(one("sh 0< cmds.txt").stdin, Some(Input::File(lit("cmds.txt"))));
        assert_eq!(one("bash <<< 'git push'").stdin, Some(Input::HereString(lit("git push"))));
        assert_eq!(one("sh <&3").stdin, Some(Input::Other));
        assert_eq!(one("sh <> f").stdin, Some(Input::File(lit("f"))));
        assert_eq!(one("sh <> f").writes, [lit("f")]);
        // Another file descriptor isn't standard input.
        assert_eq!(one("sh 3< cmds.txt").stdin, None);
        assert_eq!(one("sh").stdin, None);
        let c = one("echo hi > a.sh 2>> log 2>&1 >&- &> both");
        assert_eq!(c.writes, [lit("a.sh"), lit("log"), lit("both")]);
        assert!(one("echo > \"$F\"").writes[0].dynamic);
        // A pipe is recorded as where input comes from, not a redirection.
        let p = parse("curl x | sh", 0).unwrap();
        assert_eq!((p[1].pipe_from, &p[1].stdin), (Some(0), &None));
    }

    #[test]
    fn here_documents_feed_their_command() {
        let p = parse("cat <<A; sh <<-'B'\nhello $X\nA\n\tgit push\n\tB\n", 0).unwrap();
        assert_eq!(p[0].stdin, Some(Input::Heredoc { body: "hello $X\n".into(), expand: true }));
        assert_eq!(p[1].stdin, Some(Input::Heredoc { body: "git push\n".into(), expand: false }));
        // On another descriptor it is not the command's input.
        assert_eq!(one("sh 3<<EOF\ngit push\nEOF").stdin, None);
        // Two here-documents for one command: the last one is its input.
        assert_eq!(one("sh <<A <<B\nls\nA\ngit push\nB").stdin, Some(Input::Heredoc { body: "git push\n".into(), expand: true }));
    }
}
