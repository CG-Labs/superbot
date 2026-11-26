//! A federation's signed metadata aggregate, read as it streams (ADR 0301).
//!
//! InCommon's and eduGAIN's aggregates are 60 to 100 MB: every member's `EntityDescriptor` in
//! one `EntitiesDescriptor`, signed once at its root. botd reads one as it downloads and never
//! holds it: a small tokenizer (no DTDs, no processing instructions) feeds Exclusive C14N
//! straight into the digest the root's signature names, while the `EntityDescriptor`s of the
//! provider's IdPs are copied out. Once the root's signature verifies, each copy is parsed again
//! with `roxmltree`, as all other metadata is, and canonicalized again (`saml_sp::
//! load_aggregate_entity`): it is used only if both readers agree on every byte of it, so
//! nothing that reads one way here and another way there gets past the signature.

use super::jwt::Invalid;
use super::saml_sp::{MDQ_MAX_VALIDITY_MS, METADATA, MetadataRefused, instant, time};
use super::xmldsig::{self, Cert, Hasher, Signature, escape_attr, escape_text, prefix};
use std::io::Read;
use std::ops::Range;
use std::rc::Rc;

/// The largest aggregate read, after decompression. eduGAIN's, the largest, is about 100 MB.
pub const MAX_AGGREGATE: u64 = 256 * 1024 * 1024;
/// The longest tag, run of text, comment or CDATA section: a logo inlined as a data URI is the
/// biggest real one, well under this.
const MAX_TOKEN: usize = 4 * 1024 * 1024;
/// The largest `EntityDescriptor` copied out, as for metadata from anywhere else.
const MAX_ENTITY: usize = super::saml_sp::MAX_METADATA;
const MAX_SIGNATURE: usize = 64 * 1024;
/// The most text before the root's signature, held until it's read: metadata has only a line
/// break there.
const MAX_HELD: usize = 64 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_ATTRIBUTES: usize = 256;
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

#[derive(Debug)]
pub enum Error {
    /// The download broke off, or its compression didn't read.
    Io(String),
    Refused(MetadataRefused),
}

fn bad(message: impl Into<String>) -> Error {
    Error::Refused(MetadataRefused { reason: "bad_metadata", message: message.into() })
}

fn refused(reason: &'static str, message: impl Into<String>) -> Error {
    Error::Refused(MetadataRefused { reason, message: message.into() })
}

/// An IdP's `EntityDescriptor` from a verified aggregate: `xml`, its text as it came, inside an
/// element declaring the namespaces in scope there; `sha256`, of its Exclusive C14N as the
/// stream read it; and the earliest `validUntil` of the descriptors around it.
#[derive(Debug)]
pub struct Found {
    pub entity_id: String,
    pub xml: String,
    pub sha256: Vec<u8>,
    pub valid_until: i64,
}

/// What a verified aggregate holds for the IdPs asked for. An IdP in neither list isn't in it.
#[derive(Debug)]
pub struct Aggregate {
    pub found: Vec<Found>,
    /// IdPs listed but not usable, with why: listed twice, or too big.
    pub problems: Vec<(String, String)>,
}

enum Tok {
    Start(Start),
    End(String),
    Text(String),
    /// A comment, or the XML declaration.
    Other,
}

struct Start {
    name: String,
    attrs: Vec<(String, String)>,
    empty: bool,
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn utf8(b: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(b).map_err(|_| bad("the aggregate isn't UTF-8"))
}

/// A name as XML writes one, near enough: what the stricter parser sees is checked against it.
fn check_name(n: &str) -> Result<(), Error> {
    let ok = !n.is_empty()
        && !n.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '.' || c == ':')
        && !n.ends_with(':')
        && n.matches(':').count() <= 1
        && !n.contains(|c: char| is_ws(c) || "<>&\"'=/!?;#()[]{},`|\\".contains(c) || c.is_control());
    if ok { Ok(()) } else { Err(bad(format!("the aggregate has a tag or attribute name XML doesn't allow ({})", n.chars().take(40).collect::<String>()))) }
}

/// Text or an attribute value as XML reads it: line ends as `\n`, references replaced, and in
/// an attribute, literal tabs and line ends as spaces (there's no DTD to say otherwise).
fn decode(raw: &str, attr: bool) -> Result<String, Error> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(if attr { ' ' } else { '\n' });
            }
            '\n' | '\t' if attr => out.push(' '),
            '&' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some(';') => break,
                        Some(c) if name.len() < 12 => name.push(c),
                        _ => return Err(bad("the aggregate has an unfinished & reference")),
                    }
                }
                let ch = match name.as_str() {
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    n => match (n.strip_prefix("#x"), n.strip_prefix('#')) {
                        (Some(h), _) if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) => u32::from_str_radix(h, 16).ok().and_then(char::from_u32),
                        (None, Some(d)) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()) => d.parse::<u32>().ok().and_then(char::from_u32),
                        _ => return Err(bad(format!("the aggregate has an entity reference SuperBot doesn't read (&{name};): it reads no DTD"))),
                    },
                };
                match ch.filter(|c| xml_char(*c)) {
                    Some(c) => out.push(c),
                    None => return Err(bad(format!("the aggregate refers to a character XML doesn't allow (&{name};)"))),
                }
            }
            c if xml_char(c) => out.push(c),
            _ => return Err(bad("the aggregate has a character XML doesn't allow")),
        }
    }
    Ok(out)
}

/// A CDATA section's text: line ends as `\n`, nothing else replaced.
fn cdata(raw: &str) -> Result<String, Error> {
    if !raw.chars().all(xml_char) {
        return Err(bad("the aggregate has a character XML doesn't allow"));
    }
    Ok(raw.replace("\r\n", "\n").replace('\r', "\n"))
}

/// The inside of a start tag, between `<` and `>`.
fn start_tag(s: &str) -> Result<Start, Error> {
    let empty = s.ends_with('/');
    let s = if empty { &s[..s.len() - 1] } else { s };
    let name_end = s.find(is_ws).unwrap_or(s.len());
    let name = &s[..name_end];
    check_name(name)?;
    let mut rest = &s[name_end..];
    let mut attrs: Vec<(String, String)> = Vec::new();
    loop {
        let trimmed = rest.trim_start_matches(is_ws);
        if trimmed.is_empty() {
            break;
        }
        if trimmed.len() == rest.len() {
            return Err(bad(format!("the aggregate's <{name}> has attributes with no space between them")));
        }
        let eq = trimmed.find('=').ok_or_else(|| bad(format!("the aggregate's <{name}> has an attribute without a value")))?;
        let an = trimmed[..eq].trim_end_matches(is_ws);
        check_name(an)?;
        let after = trimmed[eq + 1..].trim_start_matches(is_ws);
        let q = after.chars().next().filter(|q| *q == '"' || *q == '\'').ok_or_else(|| bad(format!("the aggregate's <{name}> has an unquoted attribute")))?;
        let close = after[1..].find(q).ok_or_else(|| bad(format!("the aggregate's <{name}> has an unfinished attribute")))? + 1;
        let raw = &after[1..close];
        if raw.contains('<') {
            return Err(bad(format!("the aggregate's <{name}> has a < in an attribute")));
        }
        if attrs.iter().any(|(a, _)| a == an) {
            return Err(bad(format!("the aggregate's <{name}> has {an} twice")));
        }
        attrs.push((an.to_string(), decode(raw, true)?));
        if attrs.len() > MAX_ATTRIBUTES {
            return Err(bad(format!("the aggregate's <{name}> has over {MAX_ATTRIBUTES} attributes")));
        }
        rest = &after[close + 1..];
    }
    Ok(Start { name: name.to_string(), attrs, empty })
}

/// Splits a document into tokens as it is read, holding only the token being read.
struct Lexer<R> {
    r: R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    read: u64,
    began: bool,
}

enum Head {
    Comment,
    Cdata,
    Doctype,
    Pi,
    End,
    Start,
}

impl<R: Read> Lexer<R> {
    fn new(r: R) -> Lexer<R> {
        Lexer { r, buf: Vec::new(), pos: 0, eof: false, read: 0, began: false }
    }

    fn fill(&mut self) -> Result<bool, Error> {
        if self.eof {
            return Ok(false);
        }
        let mut chunk = [0u8; 64 * 1024];
        let n = loop {
            match self.r.read(&mut chunk) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e.to_string())),
            }
        };
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.read += n as u64;
        if self.read > MAX_AGGREGATE {
            return Err(bad(format!("the aggregate is over {} MB", MAX_AGGREGATE >> 20)));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// More of the token being read, which must fit in `MAX_TOKEN` and not be cut short.
    fn grow(&mut self) -> Result<(), Error> {
        if self.buf.len() - self.pos > MAX_TOKEN {
            return Err(bad(format!("a tag, text or comment in the aggregate is over {} MB", MAX_TOKEN >> 20)));
        }
        if self.fill()? { Ok(()) } else { Err(bad("the aggregate ends in the middle of a tag")) }
    }

    /// Where `pat` starts, at or after `from`.
    fn find(&mut self, from: usize, pat: &[u8]) -> Result<usize, Error> {
        let mut at = from;
        loop {
            if let Some(i) = self.buf[at..].windows(pat.len()).position(|w| w == pat) {
                return Ok(at + i);
            }
            at = self.buf.len().saturating_sub(pat.len() - 1).max(from);
            self.grow()?;
        }
    }

    /// The `>` that ends the tag begun before `from`, outside quoted attribute values.
    fn tag_end(&mut self, from: usize) -> Result<usize, Error> {
        let mut i = from;
        let mut quote: Option<u8> = None;
        loop {
            while i < self.buf.len() {
                let b = self.buf[i];
                match quote {
                    Some(q) if b == q => quote = None,
                    Some(_) => {}
                    None if b == b'"' || b == b'\'' => quote = Some(b),
                    None if b == b'>' => return Ok(i),
                    None if b == b'<' => return Err(bad("the aggregate has a < inside a tag")),
                    None => {}
                }
                i += 1;
            }
            self.grow()?;
        }
    }

    fn raw(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    /// The next token and where its text is in `raw`, until the next call. None at the end.
    fn next(&mut self) -> Result<Option<(Tok, Range<usize>)>, Error> {
        if self.pos >= 1 << 20 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if self.pos == self.buf.len() && !self.fill()? {
            return Ok(None);
        }
        if !self.began {
            while self.buf.len() < 3 && self.fill()? {}
            if self.buf.starts_with(b"\xEF\xBB\xBF") {
                self.pos = 3;
            }
            if self.pos == self.buf.len() && !self.fill()? {
                return Ok(None);
            }
        }
        let start = self.pos;
        let began = std::mem::replace(&mut self.began, true);
        if self.buf[start] != b'<' {
            let mut at = start;
            let end = loop {
                if let Some(i) = self.buf[at..].iter().position(|b| *b == b'<') {
                    break at + i;
                }
                at = self.buf.len();
                if self.buf.len() - self.pos > MAX_TOKEN {
                    return Err(bad(format!("a run of text in the aggregate is over {} MB", MAX_TOKEN >> 20)));
                }
                if !self.fill()? {
                    break self.buf.len();
                }
            };
            self.pos = end;
            let text = decode(utf8(&self.buf[start..end])?, false)?;
            return Ok(Some((Tok::Text(text), start..end)));
        }
        while self.buf.len() < start + 9 && self.fill()? {}
        let head = &self.buf[start..self.buf.len().min(start + 9)];
        let kind = if head.starts_with(b"<!--") {
            Head::Comment
        } else if head.starts_with(b"<![CDATA[") {
            Head::Cdata
        } else if head.starts_with(b"<!") {
            Head::Doctype
        } else if head.starts_with(b"<?") {
            Head::Pi
        } else if head.starts_with(b"</") {
            Head::End
        } else {
            Head::Start
        };
        let (tok, end) = match kind {
            Head::Comment => {
                let e = self.find(start + 4, b"-->")?;
                let body = &self.buf[start + 4..e];
                if body.windows(2).any(|w| w == b"--") || body.ends_with(b"-") {
                    return Err(bad("the aggregate has a comment with -- in it"));
                }
                utf8(body)?;
                (Tok::Other, e + 3)
            }
            Head::Cdata => {
                let e = self.find(start + 9, b"]]>")?;
                (Tok::Text(cdata(utf8(&self.buf[start + 9..e])?)?), e + 3)
            }
            Head::Doctype => return Err(bad("the aggregate has a DTD, which SuperBot doesn't read")),
            Head::Pi => {
                let e = self.find(start + 2, b"?>")?;
                let decl = self.buf[start..e].starts_with(b"<?xml") && self.buf.get(start + 5).is_some_and(|b| b.is_ascii_whitespace());
                if began || !decl {
                    return Err(bad("the aggregate has a processing instruction, which SuperBot doesn't read"));
                }
                (Tok::Other, e + 2)
            }
            Head::End => {
                let e = self.tag_end(start + 2)?;
                let name = utf8(&self.buf[start + 2..e])?.trim_end_matches(is_ws);
                check_name(name)?;
                (Tok::End(name.to_string()), e + 1)
            }
            Head::Start => {
                let e = self.tag_end(start + 1)?;
                (Tok::Start(start_tag(utf8(&self.buf[start + 1..e])?)?), e + 1)
            }
        };
        self.pos = end;
        Ok(Some((tok, start..end)))
    }
}

/// Bindings in scope: a prefix (`""` for the default) and its namespace.
type Bindings = Rc<Vec<(String, String)>>;

/// An element's own declarations: a prefix and its namespace, None for `xmlns=""`.
type Declarations = Vec<(String, Option<String>)>;

/// The namespace declarations of each open element.
#[derive(Default)]
struct Scope {
    /// Each open element's declarations, and every binding in scope there.
    frames: Vec<(Declarations, Bindings)>,
}

impl Scope {
    fn lookup(&self, p: &str) -> Option<&str> {
        if p == "xml" {
            return Some(XML_NS);
        }
        for (decls, _) in self.frames.iter().rev() {
            if let Some((_, u)) = decls.iter().find(|(q, _)| q == p) {
                return u.as_deref();
            }
        }
        None
    }

    fn push(&mut self, decls: Declarations) {
        let visible = match self.frames.last() {
            Some((_, v)) if decls.is_empty() => v.clone(),
            parent => {
                let mut v: Vec<(String, String)> = parent.map(|(_, v)| v.as_ref().clone()).unwrap_or_default();
                for (p, u) in &decls {
                    v.retain(|(q, _)| q != p);
                    if let Some(u) = u {
                        v.push((p.clone(), u.clone()));
                    }
                }
                Rc::new(v)
            }
        };
        self.frames.push((decls, visible));
    }

    fn pop(&mut self) {
        self.frames.pop();
    }
}

struct Attr {
    ns: String,
    local: String,
    qname: String,
    value: String,
}

/// A start tag with its namespaces resolved, as canonicalization needs it.
#[derive(Clone)]
struct Element {
    qname: String,
    ns: String,
    local: String,
    attrs: Rc<Vec<Attr>>,
    /// Every binding in scope, `xml` aside, as `roxmltree`'s `Node::namespaces` gives them.
    scope: Bindings,
}

impl Element {
    fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }

    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.ns.is_empty() && a.local == name).map(|a| a.value.as_str())
    }
}

fn split(qname: &str) -> (&str, &str) {
    qname.split_once(':').unwrap_or(("", qname))
}

/// Opens `s` in `scope`, its own declarations first, as namespaces-in-XML says.
fn resolve(scope: &mut Scope, s: Start) -> Result<Element, Error> {
    let mut decls: Declarations = Vec::new();
    let mut plain = Vec::new();
    for (q, v) in s.attrs {
        let declared = if q == "xmlns" {
            Some(String::new())
        } else {
            q.strip_prefix("xmlns:").map(String::from)
        };
        let Some(p) = declared else {
            plain.push((q, v));
            continue;
        };
        if p == "xml" && v == XML_NS {
            continue;
        }
        if p == "xmlns" || p == "xml" || v == XML_NS || v == XMLNS_NS || (!p.is_empty() && v.is_empty()) {
            return Err(bad(format!("the aggregate's <{}> declares a namespace XML doesn't allow ({q})", s.name)));
        }
        decls.push((p, (!v.is_empty()).then_some(v)));
    }
    scope.push(decls);
    let (p, local) = split(&s.name);
    let ns = match scope.lookup(p) {
        Some(u) => u.to_string(),
        None if p.is_empty() => String::new(),
        None => return Err(bad(format!("the aggregate's <{}> uses a prefix it doesn't declare", s.name))),
    };
    let mut attrs: Vec<Attr> = Vec::with_capacity(plain.len());
    for (q, value) in plain {
        let (ap, al) = split(&q);
        let ans = if ap.is_empty() {
            String::new()
        } else {
            scope.lookup(ap).ok_or_else(|| bad(format!("the aggregate's <{}> has an attribute with a prefix it doesn't declare ({q})", s.name)))?.to_string()
        };
        if attrs.iter().any(|a| a.ns == ans && a.local == al) {
            return Err(bad(format!("the aggregate's <{}> has {q} twice", s.name)));
        }
        attrs.push(Attr { ns: ans, local: al.to_string(), qname: q.clone(), value });
    }
    let scope = scope.frames.last().map(|(_, v)| v.clone()).unwrap_or_default();
    Ok(Element { local: local.to_string(), qname: s.name, ns, attrs: Rc::new(attrs), scope })
}

/// Exclusive XML Canonicalization 1.0, without comments, fed one event at a time into a
/// digest: the same output as `xmldsig::exc_c14n` over a parsed document.
struct C14n {
    inclusive: Vec<String>,
    rendered: Vec<Bindings>,
    out: Hasher,
    scratch: String,
}

impl C14n {
    fn new(inclusive: Vec<String>, out: Hasher) -> C14n {
        C14n { inclusive, rendered: Vec::new(), out, scratch: String::new() }
    }

    fn start(&mut self, e: &Element) {
        let bound = |p: &str| e.scope.iter().find(|(q, _)| q == p).map(|(_, u)| u.as_str());
        let mut used: Vec<&str> = vec![prefix(&e.qname)];
        for a in e.attrs.iter() {
            let ap = prefix(&a.qname);
            if !ap.is_empty() && ap != "xml" {
                used.push(ap);
            }
        }
        for p in &self.inclusive {
            let p = if p == "#default" { "" } else { p.as_str() };
            if bound(p).is_some() {
                used.push(p);
            }
        }
        used.sort_unstable();
        used.dedup();
        let before: Bindings = self.rendered.last().cloned().unwrap_or_default();
        let mut decls: Vec<(&str, &str)> = Vec::new();
        for p in used {
            let uri = bound(p).unwrap_or("");
            if uri != before.iter().find(|(q, _)| q == p).map_or("", |(_, u)| u.as_str()) {
                decls.push((p, uri));
            }
        }
        let now = if decls.is_empty() {
            before
        } else {
            let mut v = before.as_ref().clone();
            for (p, uri) in &decls {
                v.retain(|(q, _)| q != p);
                v.push((p.to_string(), uri.to_string()));
            }
            Rc::new(v)
        };
        let mut attrs: Vec<&Attr> = e.attrs.iter().collect();
        attrs.sort_by(|a, b| (&a.ns, &a.local).cmp(&(&b.ns, &b.local)));
        let out = &mut self.scratch;
        out.clear();
        out.push('<');
        out.push_str(&e.qname);
        for (p, uri) in decls {
            out.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
            out.push_str(p);
            out.push_str("=\"");
            escape_attr(uri, out);
            out.push('"');
        }
        for a in attrs {
            out.push(' ');
            out.push_str(&a.qname);
            out.push_str("=\"");
            escape_attr(&a.value, out);
            out.push('"');
        }
        out.push('>');
        self.out.update(self.scratch.as_bytes());
        self.rendered.push(now);
    }

    fn text(&mut self, t: &str) {
        self.scratch.clear();
        escape_text(t, &mut self.scratch);
        self.out.update(self.scratch.as_bytes());
    }

    fn end(&mut self, qname: &str) {
        self.rendered.pop();
        self.out.update(b"</");
        self.out.update(qname.as_bytes());
        self.out.update(b">");
    }
}

enum Copying {
    /// The root's `ds:Signature`, which the digest leaves out.
    Signature,
    /// A listed IdP's `EntityDescriptor`, canonicalized on its own as well.
    Entity { entity_id: String, side: Box<C14n>, wrapper: String, valid_until: Option<i64> },
}

/// The text of one element as it streams by, opened at depth `depth`.
struct Copy {
    what: Copying,
    depth: usize,
    raw: Vec<u8>,
    too_big: bool,
}

impl Copy {
    fn push(&mut self, raw: &[u8], max: usize) {
        if self.raw.len() + raw.len() > max {
            self.too_big = true;
        } else if !self.too_big {
            self.raw.extend_from_slice(raw);
        }
    }
}

/// An element that declares its namespaces in `scope` around `inner`, so it reads alone as it
/// read in the aggregate.
fn wrap(scope: &[(String, String)], inner: &str) -> String {
    let mut w = String::from("<w");
    for (p, u) in scope {
        w.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
        w.push_str(p);
        w.push_str("=\"");
        escape_attr(u, &mut w);
        w.push('"');
    }
    w.push('>');
    w.push_str(inner);
    w.push_str("</w>");
    w
}

fn signature_refused(Invalid(reason): Invalid) -> Error {
    refused(reason, format!("its signature isn't by the metadata signing certificate ({reason})"))
}

/// What lies before the root's signature, held until the signature says how to digest it.
enum Held {
    Start(Element),
    Text(String),
}

/// Reads the aggregate in `r` as it comes, and returns the `EntityDescriptor`s of `wanted`
/// once its root's signature verifies against `certs` and its `validUntil` holds at `now_ms`.
///
/// It must be an `EntitiesDescriptor` signed by an enveloped signature that is its first
/// child, as metadata's schema has it, over its `ID` or the whole document (`URI=""`), with a
/// `validUntil` no more than `MDQ_MAX_VALIDITY_MS` ahead, as an MDQ answer's.
pub fn read(r: impl Read, wanted: &[String], certs: &[Cert], now_ms: i64) -> Result<Aggregate, Error> {
    let mut lx = Lexer::new(r);
    let mut scope = Scope::default();
    // Each open element's name, and the validUntil of each EntitiesDescriptor among them.
    let mut open: Vec<(String, Option<i64>)> = Vec::new();
    let mut root: Option<Element> = None;
    let mut held: Vec<Held> = Vec::new();
    let mut held_len = 0;
    let mut main: Option<C14n> = None;
    let mut signature: Option<Signature> = None;
    let mut copy: Option<Copy> = None;
    let mut closed = false;
    let mut found: Vec<Found> = Vec::new();
    let mut problems: Vec<(String, String)> = Vec::new();
    let unsigned = || refused("unsigned", "the aggregate isn't signed at its root: every one must be, by the certificate in SSO_<ID>_METADATA_SIGNING_CERT_FILE");

    while let Some((tok, range)) = lx.next()? {
        match tok {
            Tok::Other => {
                if let Some(c) = copy.as_mut() {
                    c.push(lx.raw(range), MAX_ENTITY);
                }
            }
            Tok::Text(t) => {
                if open.is_empty() {
                    if !t.chars().all(is_ws) {
                        return Err(bad("the aggregate has text outside its root"));
                    }
                    continue;
                }
                let in_signature = matches!(copy, Some(Copy { what: Copying::Signature, .. }));
                if let Some(c) = copy.as_mut() {
                    c.push(lx.raw(range), if in_signature { MAX_SIGNATURE } else { MAX_ENTITY });
                    if let Copying::Entity { side, .. } = &mut c.what {
                        side.text(&t);
                    }
                }
                if !in_signature {
                    match main.as_mut() {
                        Some(m) => m.text(&t),
                        None => {
                            held_len += t.len();
                            if held_len > MAX_HELD {
                                return Err(bad("the aggregate has too much text before its signature"));
                            }
                            held.push(Held::Text(t));
                        }
                    }
                }
            }
            Tok::Start(s) => {
                if closed {
                    return Err(bad("the aggregate has more than one root"));
                }
                if open.len() >= MAX_DEPTH {
                    return Err(bad("the aggregate nests deeper than any metadata does"));
                }
                let empty = s.empty;
                let e = resolve(&mut scope, s)?;
                let depth = open.len();
                let signing = e.is(xmldsig::DSIG, "Signature");
                if depth == 0 {
                    if !e.is(METADATA, "EntitiesDescriptor") {
                        return Err(bad(format!("the aggregate's root is <{}>, not an EntitiesDescriptor: check SSO_<ID>_IDP_AGGREGATE_URL is the federation's aggregate", e.qname)));
                    }
                    if empty {
                        return Err(unsigned());
                    }
                    held.push(Held::Start(e.clone()));
                    root = Some(e.clone());
                } else if depth == 1 && main.is_none() && copy.is_none() {
                    if !signing {
                        return Err(unsigned());
                    }
                    copy = Some(Copy { what: Copying::Signature, depth, raw: Vec::new(), too_big: false });
                } else if depth == 1 && signing {
                    return Err(refused("wrapped", "the aggregate has a second signature at its root"));
                }
                let in_signature = matches!(copy, Some(Copy { what: Copying::Signature, .. }));
                if let Some(m) = main.as_mut().filter(|_| !in_signature) {
                    m.start(&e);
                }
                if copy.is_none() && e.is(METADATA, "EntityDescriptor") {
                    let entity_id = e.attr("entityID").unwrap_or_default().to_string();
                    if wanted.contains(&entity_id) {
                        if found.iter().any(|f| f.entity_id == entity_id) || problems.iter().any(|(p, _)| *p == entity_id) {
                            found.retain(|f| f.entity_id != entity_id);
                            problems.retain(|(p, _)| *p != entity_id);
                            problems.push((entity_id, "the aggregate lists it twice".into()));
                        } else {
                            let valid_until = open.iter().filter_map(|(_, u)| *u).min();
                            let side = Box::new(C14n::new(Vec::new(), xmldsig::DigestAlg::Sha256.hasher()));
                            let wrapper = wrap(&e.scope, "");
                            copy = Some(Copy { what: Copying::Entity { entity_id, side, wrapper, valid_until }, depth, raw: Vec::new(), too_big: false });
                        }
                    }
                }
                let max = if in_signature { MAX_SIGNATURE } else { MAX_ENTITY };
                if let Some(c) = copy.as_mut() {
                    c.push(lx.raw(range), max);
                    if let Copying::Entity { side, .. } = &mut c.what {
                        side.start(&e);
                    }
                }
                let until = match e.attr("validUntil").filter(|_| e.is(METADATA, "EntitiesDescriptor")) {
                    Some(v) => Some(time(v).map_err(|_| bad(format!("the aggregate's validUntil ({v}) isn't a date")))?),
                    None => None,
                };
                open.push((e.qname.clone(), until));
                if empty {
                    close(&mut open, &mut scope, &mut main, &mut copy, &mut found, &mut problems, &mut signature, &mut held, root.as_ref())?;
                    closed = open.is_empty();
                }
            }
            Tok::End(name) => {
                if open.last().map(|(q, _)| q.as_str()) != Some(name.as_str()) {
                    return Err(bad(format!("the aggregate's </{name}> doesn't close the element open there")));
                }
                if let Some(c) = copy.as_mut() {
                    let max = if matches!(c.what, Copying::Signature) { MAX_SIGNATURE } else { MAX_ENTITY };
                    c.push(lx.raw(range), max);
                }
                close(&mut open, &mut scope, &mut main, &mut copy, &mut found, &mut problems, &mut signature, &mut held, root.as_ref())?;
                closed = open.is_empty();
            }
        }
    }
    if !closed {
        return Err(bad(if root.is_none() { "the aggregate is empty" } else { "the aggregate ends before its root closes" }));
    }
    let (Some(signature), Some(main)) = (signature, main) else { return Err(unsigned()) };
    signature.verify(&main.out.finish(), certs).map_err(signature_refused)?;
    let root = root.expect("closed");
    let valid_until = match root.attr("validUntil") {
        None => return Err(refused("no_valid_until", "the aggregate has no validUntil, so a copy of it would vouch for its IdPs forever")),
        Some(v) => time(v).map_err(|_| bad(format!("the aggregate's validUntil ({v}) isn't a date")))?,
    };
    if valid_until <= now_ms {
        return Err(refused("expired", format!("the aggregate expired at {} (validUntil): the federation must publish a fresh one", instant(valid_until))));
    }
    if valid_until > now_ms.saturating_add(MDQ_MAX_VALIDITY_MS) {
        return Err(refused("valid_too_long", format!("the aggregate is valid until {}, more than {} days ahead", instant(valid_until), MDQ_MAX_VALIDITY_MS / 86_400_000)));
    }
    for f in &mut found {
        f.valid_until = f.valid_until.min(valid_until);
    }
    Ok(Aggregate { found, problems })
}

/// Closes the innermost open element: in the digest, in the copy being made, and when that is
/// the root's signature or a listed IdP, finishes it.
#[allow(clippy::too_many_arguments)]
fn close(
    open: &mut Vec<(String, Option<i64>)>,
    scope: &mut Scope,
    main: &mut Option<C14n>,
    copy: &mut Option<Copy>,
    found: &mut Vec<Found>,
    problems: &mut Vec<(String, String)>,
    signature: &mut Option<Signature>,
    held: &mut Vec<Held>,
    root: Option<&Element>,
) -> Result<(), Error> {
    let (qname, _) = open.pop().expect("an open element");
    let depth = open.len();
    let root_scope = root.map(|r| r.scope.clone()).unwrap_or_default();
    scope.pop();
    match copy.as_mut() {
        Some(Copy { what: Copying::Signature, depth: d, .. }) if *d == depth => {
            let c = copy.take().expect("copying");
            if c.too_big {
                return Err(bad("the aggregate's signature is too big"));
            }
            let raw = String::from_utf8(c.raw).map_err(|_| bad("the aggregate isn't UTF-8"))?;
            let xml = wrap(&root_scope, &raw);
            let doc = xmldsig::parse(&xml).map_err(|_| refused("bad_signature", "the aggregate's signature isn't XML SuperBot reads"))?;
            let sig = doc.root_element().first_element_child().ok_or_else(unsigned_signature)?;
            let s = Signature::read(sig).map_err(signature_refused)?;
            let id = root.and_then(|r| r.attr("ID"));
            if !(s.uri.is_empty() || id.is_some_and(|id| s.uri == format!("#{id}"))) {
                return Err(refused("wrapped", "the aggregate's signature covers something other than the aggregate"));
            }
            let mut m = C14n::new(s.prefixes.clone(), s.digest.hasher());
            for h in held.drain(..) {
                match h {
                    Held::Start(e) => m.start(&e),
                    Held::Text(t) => m.text(&t),
                }
            }
            *main = Some(m);
            *signature = Some(s);
            return Ok(());
        }
        Some(Copy { what: Copying::Signature, .. }) => return Ok(()),
        _ => {}
    }
    match main.as_mut() {
        Some(m) => m.end(&qname),
        None => return Err(refused("unsigned", "the aggregate isn't signed at its root: every one must be, by the certificate in SSO_<ID>_METADATA_SIGNING_CERT_FILE")),
    }
    if let Some(Copy { what: Copying::Entity { side, .. }, .. }) = copy.as_mut() {
        side.end(&qname);
    }
    if matches!(copy, Some(Copy { what: Copying::Entity { .. }, depth: d, .. }) if *d == depth) {
        let Some(Copy { what: Copying::Entity { entity_id, side, wrapper, valid_until }, raw, too_big, .. }) = copy.take() else { unreachable!() };
        if too_big {
            problems.push((entity_id, format!("its EntityDescriptor is over {} MB", MAX_ENTITY >> 20)));
            return Ok(());
        }
        let raw = String::from_utf8(raw).map_err(|_| bad("the aggregate isn't UTF-8"))?;
        let xml = format!("{}{raw}</w>", wrapper.trim_end_matches("</w>"));
        found.push(Found { entity_id, xml, sha256: side.out.finish(), valid_until: valid_until.unwrap_or(i64::MAX) });
    }
    Ok(())
}

fn unsigned_signature() -> Error {
    refused("bad_signature", "the aggregate's signature is empty")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::saml_sp::test_idp::{aggregate, metadata_with, signed_aggregate};
    use crate::sso::saml_sp::{IdpMetadata, MAX_METADATA, RequestBinding, ResponseBinding, load_aggregate_entity};
    use crate::sso::xmldsig::DigestAlg;
    use crate::sso::xmldsig::test_signer::{Signer, signer, signers};

    const NOW: i64 = 1_800_000_000_000;
    const DAY: i64 = 86_400_000;
    const A: &str = "https://idp.uni-a.example/idp";
    const B: &str = "https://login.uni-b.example/saml";

    /// The streamed canonical form of a whole document's root, digested.
    fn streamed(xml: &str, inclusive: &[&str]) -> Result<Vec<u8>, String> {
        let mut lx = Lexer::new(xml.as_bytes());
        let mut scope = Scope::default();
        let mut c = C14n::new(inclusive.iter().map(|s| s.to_string()).collect(), DigestAlg::Sha256.hasher());
        let mut open: Vec<String> = Vec::new();
        let mut done = false;
        let msg = |e: Error| match e {
            Error::Refused(r) => r.message,
            Error::Io(m) => m,
        };
        while let Some((tok, _)) = lx.next().map_err(msg)? {
            match tok {
                Tok::Start(s) => {
                    if done {
                        return Err("two roots".into());
                    }
                    let empty = s.empty;
                    let e = resolve(&mut scope, s).map_err(msg)?;
                    c.start(&e);
                    if empty {
                        scope.pop();
                        c.end(&e.qname);
                        done = open.is_empty();
                    } else {
                        open.push(e.qname);
                    }
                }
                Tok::End(n) => {
                    if open.pop().as_deref() != Some(n.as_str()) {
                        return Err("mismatched".into());
                    }
                    scope.pop();
                    c.end(&n);
                    done = open.is_empty();
                }
                Tok::Text(t) if !open.is_empty() => c.text(&t),
                Tok::Text(t) if !t.chars().all(is_ws) => return Err("text outside".into()),
                Tok::Text(_) | Tok::Other => {}
            }
        }
        if !done {
            return Err("unfinished".into());
        }
        Ok(c.out.finish())
    }

    fn dom(xml: &str, inclusive: &[&str]) -> Vec<u8> {
        let opt = roxmltree::ParsingOptions { allow_dtd: false, ..Default::default() };
        let doc = roxmltree::Document::parse_with_options(xml.trim_start_matches('\u{feff}'), opt).unwrap();
        let inc: Vec<String> = inclusive.iter().map(|s| s.to_string()).collect();
        DigestAlg::Sha256.digest(xmldsig::exc_c14n(doc.root_element(), None, &inc).unwrap().as_bytes())
    }

    #[test]
    fn streamed_canonical_form_is_the_parsed_documents() {
        let cases: &[(&str, &[&str])] = &[
            (r#"<r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:e b:z="1" y='2' a:x="3" xmlns:c="urn:c">t &amp; &lt; &gt; "q"</a:e></r>"#, &[]),
            (r#"<r xmlns="urn:d"><e><f/></e></r>"#, &[]),
            (r#"<r xmlns="urn:d"><e xmlns=""><f/></e></r>"#, &[]),
            (r#"<r><e xmlns="urn:d"><f xmlns=""/></e></r>"#, &[]),
            (r#"<r xmlns=""><e/></r>"#, &[]),
            (r#"<r xmlns:xs="urn:xs" xmlns:xsi="urn:xsi"><v xsi:type="xs:string">a</v></r>"#, &["xs"]),
            (r#"<r xmlns="urn:d"><e/></r>"#, &["#default"]),
            (r#"<r xmlns:p="urn:p"><p:e><p:f xmlns:p="urn:p"/><p:g xmlns:p="urn:other"/></p:e></r>"#, &[]),
            (r#"<r xmlns:a="urn:a"><a:x><b xmlns:a="urn:a2"><a:y/></b></a:x></r>"#, &[]),
            (r#"<r xmlns:p="urn:p" xml:lang="en" p:b="2" a="1"><p:c xmlns:q="urn:q" q:z="" xmlns="urn:d"><d/></p:c></r>"#, &[]),
            ("<r><e a=\"x&#9;y&#10;z&#13;\">l1\r\nl2&#13;</e></r>", &[]),
            ("<r a=\"x\ty\r\nz\rw\">a\rb\r\nc</r>", &[]),
            ("\u{feff}<?xml version=\"1.0\"?>\n<!-- c --><r a='say \"hi\"' b=\"1 > 0\"><![CDATA[<x> & ]]>\r\n&#x41;&#65;<!-- in --></r >\n", &[]),
            ("<r t=\"é€😀\">ü&#x1F600;&quot;&apos;</r>", &[]),
            ("<r>\n  <e/>\n  <e >x</e>\n</r>", &[]),
        ];
        for (xml, inc) in cases {
            assert_eq!(streamed(xml, inc), Ok(dom(xml, inc)), "{xml}");
        }
    }

    #[test]
    fn the_tokenizer_refuses_what_metadata_never_has() {
        for bad in [
            "<!DOCTYPE r><r/>",
            r#"<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>"#,
            "<r><?pi x?></r>",
            " <?xml version=\"1.0\"?><r/>",
            "<r>&ent;</r>",
            "<r>&#0;</r>",
            "<r>&#xD800;</r>",
            "<r>&amp</r>",
            "<r>\u{1}</r>",
            "<r><!-- a -- b --></r>",
            "<r><!-- a ---></r>",
            "<p:r/>",
            r#"<r a:b="1"/>"#,
            "<r><e></r></e>",
            r#"<r a="<"/>"#,
            r#"<r a="1" a="2"/>"#,
            r#"<r xmlns:a="urn:a" xmlns:b="urn:a" a:x="1" b:x="2"/>"#,
            r#"<r a="1"b="2"/>"#,
            "<r a=1/>",
            r#"<r xmlns:xml="urn:x"/>"#,
            r#"<r xmlns:p=""/>"#,
            r#"<r xmlns:xmlns="urn:x"/>"#,
            "<r>",
            "<r/><r/>",
            "<r/>x",
            "<1r/>",
        ] {
            assert!(streamed(bad, &[]).is_err(), "{bad}");
        }
    }

    fn anchor() -> &'static Signer {
        signer(1)
    }

    fn entity(id: &str, key: usize) -> String {
        metadata_with(id, &[signer(key)], "")
    }

    fn read_as(xml: &str, wanted: &[&str], certs: &[Cert]) -> Result<Aggregate, String> {
        let wanted: Vec<String> = wanted.iter().map(|s| s.to_string()).collect();
        read(xml.as_bytes(), &wanted, certs, NOW).map_err(|e| match e {
            Error::Refused(r) => r.reason.to_string(),
            Error::Io(m) => format!("io: {m}"),
        })
    }

    fn read_ok(xml: &str, wanted: &[&str]) -> Result<Aggregate, String> {
        read_as(xml, wanted, &[anchor().cert()])
    }

    fn load(f: &Found) -> Result<IdpMetadata, &'static str> {
        load_aggregate_entity(f, false, RequestBinding::Auto, ResponseBinding::Post, NOW).map_err(|e| e.reason)
    }

    fn ids(a: &Aggregate) -> Vec<&str> {
        a.found.iter().map(|f| f.entity_id.as_str()).collect()
    }

    #[test]
    fn reads_the_listed_idps_from_a_signed_aggregate_over_1_mb() {
        let mut all: Vec<String> = (0..1200).map(|i| entity(&format!("https://idp{i}.member.example/idp"), 0)).collect();
        all.insert(600, entity(A, 0));
        all.push(entity(B, 2));
        let xml = signed_aggregate(&aggregate(&all, NOW + 7 * DAY), anchor(), "#_agg");
        assert!(xml.len() > MAX_METADATA, "{}", xml.len());
        let agg = read_ok(&xml, &[A, B, "https://not-a-member.example/idp"]).unwrap();
        assert_eq!((ids(&agg), agg.problems.len()), (vec![A, B], 0), "one not in it is neither found nor a problem");
        let a = load(&agg.found[0]).unwrap();
        assert_eq!((a.entity_id.as_str(), a.certs[0].sha256.clone(), a.valid_until), (A, signer(0).cert().sha256, Some(NOW + 7 * DAY)));
        assert_eq!(load(&agg.found[1]).unwrap().certs[0].sha256, signer(2).cert().sha256);
        assert_eq!(read_as(&xml, &[A], &[signers()[0].cert(), anchor().cert()]).map(|a| a.found.len()), Ok(1), "any anchor, for rollover");
    }

    #[test]
    fn a_whole_document_reference_and_small_reads_verify_too() {
        let xml = signed_aggregate(&aggregate(&[entity(A, 0), entity(B, 3)], NOW + DAY), signer(3), "");
        let agg = read_as(&xml, &[B], &[signer(3).cert()]).unwrap();
        assert_eq!(ids(&agg), [B]);
        assert!(load(&agg.found[0]).is_ok());

        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(buf.len()).min(7);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let agg = read(Trickle(xml.as_bytes()), &[A.to_string()], &[signer(3).cert()], NOW).unwrap();
        assert_eq!(ids(&agg), [A], "tokens split across reads");

        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("connection reset"))
            }
        }
        assert!(matches!(read(Broken, &[], &[], NOW), Err(Error::Io(m)) if m.contains("reset")));
    }

    #[test]
    fn namespaces_declared_on_the_root_carry_into_each_copy() {
        let bare = |id: &str| entity(id, 0).replacen(&format!(r#" xmlns:md="{METADATA}" xmlns:ds="{}""#, xmldsig::DSIG), "", 1).replace("md:", "");
        let xml = aggregate(&[bare(A)], NOW + DAY).replace("md:", "").replace("xmlns:md=", &format!(r#"xmlns:ds="{}" xmlns="#, xmldsig::DSIG));
        let xml = signed_aggregate(&xml, anchor(), "#_agg");
        let agg = read_ok(&xml, &[A]).unwrap();
        assert!(agg.found[0].xml.starts_with("<w xmlns:ds="), "{}", &agg.found[0].xml[..80]);
        assert_eq!(load(&agg.found[0]).unwrap().certs[0].sha256, signer(0).cert().sha256);
    }

    #[test]
    fn anything_changed_or_added_after_signing_is_refused() {
        let good = signed_aggregate(&aggregate(&[entity(A, 0), entity(B, 0)], NOW + DAY), anchor(), "#_agg");
        let swap = |from: &str, to: &str| {
            let s = good.replacen(from, to, 1);
            assert_ne!(s, good, "{from}");
            read_ok(&s, &[A]).map(|a| load(&a.found[0]).map(|_| ()).map_err(String::from)).and_then(|r| r)
        };
        assert_eq!(swap("https://idp.example/saml/sso", "https://evil.example/sso"), Err("bad_signature".into()));
        let evil = entity("https://evil.example/idp", 0);
        assert_eq!(swap("\n</md:EntitiesDescriptor>", &format!("{}\n</md:EntitiesDescriptor>", evil.trim_start_matches(r#"<?xml version="1.0"?>"#))), Err("bad_signature".into()), "an IdP slipped in");
        assert_eq!(swap(&format!(r#"entityID="{B}""#), r#"entityID="https://evil.example/idp""#), Err("bad_signature".into()));
        assert_eq!(swap("<md:IDPSSODescriptor", "<!-- a note --><md:IDPSSODescriptor"), Ok(()), "comments aren't signed, and the copy reads the same");
        assert_eq!(swap("</md:EntitiesDescriptor>\n", "</md:EntitiesDescriptor>\n\n<!-- end -->"), Ok(()), "nor anything outside the root");
        assert_eq!(swap(r#"xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID"#, r#"xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:x="urn:x" ID"#), Ok(()), "unused namespaces don't count");
        assert_eq!(swap(r#"Algorithm="http://www.w3.org/2001/04/xmlenc#sha256""#, r#"Algorithm="http://www.w3.org/2000/09/xmldsig#sha1""#), Err("weak_algorithm".into()));
        assert_eq!(swap("<ds:SignatureValue>", "<ds:SignatureValue>AAAA"), Err("bad_signature".into()));
        assert_eq!(swap("<ds:Signature ", "<md:Extensions/><ds:Signature "), Err("unsigned".into()), "the signature must come first");
        assert_eq!(swap("<ds:Signature ", &format!("{}<ds:Signature ", "  \n<!---->".repeat(30_000))), Err("bad_metadata".into()), "only so much text is held for it");
        assert_eq!(swap("\n</md:EntitiesDescriptor>", &format!("<ds:Signature xmlns:ds=\"{}\"/>\n</md:EntitiesDescriptor>", xmldsig::DSIG)), Err("wrapped".into()), "a second signature");
        assert_eq!(swap(r#"ID="_agg""#, r#"ID="_other""#), Err("wrapped".into()), "a signature over something else");
        assert_eq!(read_ok(&good[..good.len() / 2], &[A]).err().as_deref(), Some("bad_metadata"), "cut short");
        assert_eq!(read_ok("", &[A]).err().as_deref(), Some("bad_metadata"));

        let unsigned = aggregate(&[entity(A, 0)], NOW + DAY);
        assert_eq!(read_ok(&unsigned, &[A]).err().as_deref(), Some("unsigned"));
        assert_eq!(read_ok(&signed_aggregate(&unsigned, &signers()[0], "#_agg"), &[A]).err().as_deref(), Some("bad_signature"), "signed by another key");
        assert_eq!(read_ok(&signed_aggregate(&unsigned, anchor(), "#_elsewhere"), &[A]).err().as_deref(), Some("wrapped"));
        let one = crate::sso::saml_sp::test_idp::signed_metadata(&entity(A, 0), anchor());
        assert_eq!(read_ok(&one, &[A]).err().as_deref(), Some("bad_metadata"), "an EntityDescriptor isn't an aggregate");
    }

    #[test]
    fn copies_must_read_the_same_to_both_parsers() {
        let good = signed_aggregate(&aggregate(&[entity(A, 0)], NOW + DAY), anchor(), "#_agg");
        let found = read_ok(&good, &[A]).unwrap().found.remove(0);
        let changed = |xml: String| load(&Found { xml, entity_id: found.entity_id.clone(), sha256: found.sha256.clone(), valid_until: found.valid_until }).err();
        assert_eq!(changed(found.xml.clone()), None);
        assert_eq!(changed(found.xml.replace("https://idp.example/saml/sso", "https://evil.example/sso")), Some("ambiguous"));
        assert_eq!(changed(found.xml.replace("</w>", &format!("{}</w>", entity(B, 0).trim_start_matches(r#"<?xml version="1.0"?>"#)))), Some("ambiguous"));
        assert_eq!(changed(found.xml.replacen(&format!(r#"entityID="{A}""#), r#"entityID="https://evil.example/idp""#, 1)), Some("ambiguous"));
    }

    #[test]
    fn validity_is_the_roots_and_the_earliest_around_each_idp() {
        let signed = |xml: &str| signed_aggregate(xml, anchor(), "#_agg");
        let plain = aggregate(&[entity(A, 0)], NOW + 7 * DAY);
        let until = format!(r#" validUntil="{}""#, instant(NOW + 7 * DAY));
        assert_eq!(read_ok(&signed(&plain.replacen(&until, "", 1)), &[A]).err().as_deref(), Some("no_valid_until"));
        assert_eq!(read_ok(&signed(&aggregate(&[entity(A, 0)], NOW)), &[A]).err().as_deref(), Some("expired"));
        assert_eq!(read_ok(&signed(&aggregate(&[entity(A, 0)], NOW + 31 * DAY)), &[A]).err().as_deref(), Some("valid_too_long"));
        assert_eq!(read_ok(&signed(&plain.replacen(&until, r#" validUntil="soon""#, 1)), &[A]).err().as_deref(), Some("bad_metadata"));

        let nested = |inner: i64| {
            let a = entity(A, 0);
            let a = a.trim_start_matches(r#"<?xml version="1.0"?>"#);
            let wrapped = format!(r#"<md:EntitiesDescriptor validUntil="{}">{a}</md:EntitiesDescriptor>"#, instant(inner));
            let xml = signed(&plain.replacen(a, &wrapped, 1));
            let f = read_ok(&xml, &[A]).unwrap().found.remove(0);
            (f.valid_until, load(&f).map(|m| m.valid_until))
        };
        assert_eq!(nested(NOW + DAY), (NOW + DAY, Ok(Some(NOW + DAY))), "a group inside the aggregate ends sooner");
        assert_eq!(nested(NOW + 30 * DAY), (NOW + 7 * DAY, Ok(Some(NOW + 7 * DAY))), "but never outlives it");
        assert_eq!(nested(NOW - 1).1, Err("expired"));

        let own = |ms: i64| {
            let a = entity(A, 0).replacen("<md:EntityDescriptor ", &format!(r#"<md:EntityDescriptor validUntil="{}" "#, instant(ms)), 1);
            load(&read_ok(&signed(&aggregate(&[a], NOW + 7 * DAY)), &[A]).unwrap().found[0]).map(|m| m.valid_until)
        };
        assert_eq!(own(NOW + DAY), Ok(Some(NOW + DAY)));
        assert_eq!(own(NOW - 1), Err("expired"));
    }

    #[test]
    fn an_idp_listed_twice_is_used_from_neither() {
        let xml = signed_aggregate(&aggregate(&[entity(A, 0), entity(B, 0), entity(A, 2)], NOW + DAY), anchor(), "#_agg");
        let agg = read_ok(&xml, &[A, B]).unwrap();
        assert_eq!(ids(&agg), [B]);
        assert_eq!(agg.problems, [(A.to_string(), "the aggregate lists it twice".to_string())]);
    }
}
