//! A small SMTP client for notification email (ADR 0059): STARTTLS (the default),
//! implicit TLS, or plain text to a relay on this machine; AUTH PLAIN or LOGIN; one
//! message per recipient so nobody sees the others' addresses. Settings come from
//! botd's environment; the password from the secrets store (`SMTP_PASSWORD`, ADR 0010),
//! read at each send so saving it takes no restart.

use base64::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// The secret holding the SMTP password. botd's own: no Bot gets it.
pub const PASSWORD: &str = "SMTP_PASSWORD";
/// One SMTP reply line, at most.
const MAX_LINE: u64 = 4096;
/// Each step of a session, and connecting.
const STEP: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls {
    /// Plain connect, then `STARTTLS`, which the server must offer. Port 587 by default.
    StartTls,
    /// TLS from the first byte. Port 465 by default.
    Implicit,
    /// No encryption: only to a relay on this machine. Port 25 by default.
    None,
}

impl Tls {
    pub fn as_str(self) -> &'static str {
        match self {
            Tls::StartTls => "starttls",
            Tls::Implicit => "tls",
            Tls::None => "none",
        }
    }
}

/// An address with an optional display name, as in `SuperBot <bots@example.com>`.
#[derive(Clone, Debug, PartialEq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub addr: String,
}

impl Mailbox {
    pub fn parse(s: &str) -> Result<Mailbox, String> {
        let s = s.trim();
        let (name, addr) = match (s.rfind('<'), s.strip_suffix('>')) {
            (Some(i), Some(_)) => (Some(s[..i].trim().trim_matches('"').trim()), &s[i + 1..s.len() - 1]),
            _ => (None, s),
        };
        let addr = addr.trim();
        if !address_ok(addr) {
            return Err(format!("\"{s}\" isn't an email address, like SuperBot <bots@example.com>"));
        }
        let name = name.filter(|n| !n.is_empty()).map(|n| clean_header(n));
        Ok(Mailbox { name, addr: addr.to_string() })
    }

    fn header(&self) -> String {
        match &self.name {
            Some(n) => format!("{} <{}>", encode_word(n), self.addr),
            None => self.addr.clone(),
        }
    }

    pub fn domain(&self) -> &str {
        self.addr.rsplit_once('@').map_or("localhost", |(_, d)| d)
    }
}

/// An address SMTP can carry as-is: no spaces, brackets, quotes or control characters.
pub fn address_ok(a: &str) -> bool {
    crate::users::valid_email(a) && a.is_ascii() && !a.contains(['<', '>', '"', '(', ')', ',', ';', '\\', '[', ']'])
}

/// One message to one person. The body is plain text.
#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Clone)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub username: Option<String>,
    pub from: Mailbox,
    tls_config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for Smtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smtp").field("host", &self.host).field("port", &self.port).field("tls", &self.tls).field("from", &self.from).finish()
    }
}

fn loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

impl Smtp {
    /// `SMTP_HOST` turns email on and then needs `SMTP_FROM`. `SMTP_TLS` is `starttls`
    /// (default), `tls`, or `none` (a relay on this machine only); `SMTP_PORT` defaults by
    /// it; `SMTP_USERNAME` with the `SMTP_PASSWORD` secret signs in.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Smtp>, String> {
        let host = var("SMTP_HOST").trim().to_string();
        let from = var("SMTP_FROM");
        if host.is_empty() {
            if !from.trim().is_empty() {
                return Err("SMTP_FROM needs SMTP_HOST, the mail server to send through".into());
            }
            return Ok(None);
        }
        if host.contains(|c: char| c.is_whitespace() || c == '/' || c == '@') {
            return Err(format!("SMTP_HOST must be a host name or address, like smtp.example.com, not {host}"));
        }
        let tls = match var("SMTP_TLS").trim().to_ascii_lowercase().as_str() {
            "" | "starttls" => Tls::StartTls,
            "tls" | "ssl" | "implicit" => Tls::Implicit,
            "none" | "off" => Tls::None,
            other => return Err(format!("SMTP_TLS must be starttls, tls, or none, not {other}")),
        };
        if tls == Tls::None && !loopback(&host) {
            return Err("SMTP_TLS=none sends mail unencrypted, so it's only for a relay on this machine (SMTP_HOST=127.0.0.1); use starttls or tls".into());
        }
        let port = match var("SMTP_PORT").trim() {
            "" => match tls {
                Tls::StartTls => 587,
                Tls::Implicit => 465,
                Tls::None => 25,
            },
            p => p.parse::<u16>().ok().filter(|p| *p > 0).ok_or(format!("SMTP_PORT must be a port number, not {p}"))?,
        };
        if from.trim().is_empty() {
            return Err("SMTP_HOST needs SMTP_FROM, the address notifications come from, like SuperBot <bots@example.com>".into());
        }
        let from = Mailbox::parse(&from).map_err(|e| format!("SMTP_FROM: {e}"))?;
        let username = Some(var("SMTP_USERNAME").trim().to_string()).filter(|u| !u.is_empty());
        if username.as_deref().is_some_and(|u| u.contains(['\r', '\n', '\0'])) {
            return Err("SMTP_USERNAME has a line break in it".into());
        }
        Ok(Some(Smtp { host, port, tls, username, from, tls_config: platform_tls()? }))
    }

    /// Trusts only `roots`, for tests against a local server.
    #[cfg(test)]
    pub fn for_test(host: &str, port: u16, tls: Tls, username: Option<&str>, roots: Option<rustls::RootCertStore>) -> Smtp {
        let tls_config = match roots {
            Some(r) => Arc::new(rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(r).with_no_client_auth()),
            None => platform_tls().unwrap(),
        };
        Smtp { host: host.into(), port, tls, username: username.map(String::from), from: Mailbox::parse("SuperBot <bots@example.com>").unwrap(), tls_config }
    }

    /// What startup and the settings show: never the password.
    pub fn describe(&self) -> String {
        let auth = match &self.username {
            Some(u) => format!(", signing in as {u}"),
            None => String::new(),
        };
        format!("{}:{} ({}{auth}), from {}", self.host, self.port, self.tls.as_str(), self.from.addr)
    }

    /// Sends each message in one session. The outer error means none went (connecting,
    /// TLS, signing in); otherwise each message has its own result, as a server may
    /// refuse one recipient and take the others.
    pub async fn send(&self, password: Option<&str>, mails: &[Mail]) -> Result<Vec<Result<(), String>>, String> {
        if self.username.is_some() && password.is_none() {
            return Err(format!("SMTP_USERNAME is set but the {PASSWORD} secret isn't"));
        }
        let budget = STEP * (4 + 2 * mails.len() as u32);
        tokio::time::timeout(budget, self.session(password, mails)).await.map_err(|_| format!("{} took too long", self.host))?
    }

    async fn session(&self, password: Option<&str>, mails: &[Mail]) -> Result<Vec<Result<(), String>>, String> {
        let addr = format!("{}:{}", self.host.trim_start_matches('[').trim_end_matches(']'), self.port);
        let tcp = step(TcpStream::connect(&addr)).await?.map_err(|e| format!("couldn't connect to {}:{}: {e}", self.host, self.port))?;
        match self.tls {
            Tls::Implicit => {
                let tls = self.wrap(tcp).await?;
                let mut c = Conn::new(tls);
                c.expect(220).await?;
                c.ehlo(self.from.domain()).await?;
                c.run(self, true, password, mails).await
            }
            Tls::StartTls => {
                let mut c = Conn::new(tcp);
                c.expect(220).await?;
                let caps = c.ehlo(self.from.domain()).await?;
                if !caps.iter().any(|l| l.eq_ignore_ascii_case("STARTTLS")) {
                    return Err(format!("{} doesn't offer STARTTLS; set SMTP_TLS=tls if it takes TLS on connect", self.host));
                }
                c.cmd("STARTTLS", 220).await?;
                let tls = self.wrap(c.into_inner()?).await?;
                let mut c = Conn::new(tls);
                c.ehlo(self.from.domain()).await?;
                c.run(self, true, password, mails).await
            }
            Tls::None => {
                let mut c = Conn::new(tcp);
                c.expect(220).await?;
                c.ehlo(self.from.domain()).await?;
                c.run(self, loopback(&self.host), password, mails).await
            }
        }
    }

    async fn wrap(&self, tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let name = rustls::pki_types::ServerName::try_from(self.host.trim_start_matches('[').trim_end_matches(']').to_string()).map_err(|e| format!("SMTP_HOST: {e}"))?;
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        step(connector.connect(name, tcp)).await?.map_err(|e| format!("TLS with {} failed: {e}", self.host))
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The system's trusted roots, as browsers and reqwest use them.
fn platform_tls() -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let b = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?;
    Ok(Arc::new(b.with_platform_verifier().map_err(|e| format!("TLS: {e}"))?.with_no_client_auth()))
}

async fn step<F: std::future::Future>(f: F) -> Result<F::Output, String> {
    tokio::time::timeout(STEP, f).await.map_err(|_| "the mail server stopped answering".to_string())
}

struct Conn<S> {
    s: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    fn new(s: S) -> Conn<S> {
        Conn { s: BufReader::new(s) }
    }

    /// The stream under the reader, for STARTTLS. Anything the server sent early would be
    /// read as if encrypted later, so that's refused.
    fn into_inner(self) -> Result<S, String> {
        if !self.s.buffer().is_empty() {
            return Err("the mail server sent data before TLS started".into());
        }
        Ok(self.s.into_inner())
    }

    /// One reply: its code and its lines' text.
    async fn reply(&mut self) -> Result<(u16, Vec<String>), String> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = step((&mut self.s).take(MAX_LINE).read_line(&mut line)).await?.map_err(|e| format!("reading from the mail server: {e}"))?;
            if n == 0 {
                return Err("the mail server closed the connection".into());
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let code = line.get(..3).and_then(|c| c.parse::<u16>().ok()).ok_or_else(|| format!("odd reply from the mail server: {}", short(line)))?;
            lines.push(line.get(4..).unwrap_or("").to_string());
            if line.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, lines));
            }
            if lines.len() > 100 {
                return Err("the mail server's reply is too long".into());
            }
        }
    }

    async fn expect(&mut self, want: u16) -> Result<Vec<String>, String> {
        let (code, lines) = self.reply().await?;
        if code != want {
            return Err(format!("the mail server said {code} {}", short(&lines.join(" "))));
        }
        Ok(lines)
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), String> {
        step(async {
            self.s.write_all(data).await?;
            self.s.flush().await
        })
        .await?
        .map_err(|e| format!("writing to the mail server: {e}"))
    }

    async fn cmd(&mut self, line: &str, want: u16) -> Result<Vec<String>, String> {
        self.write(format!("{line}\r\n").as_bytes()).await?;
        self.expect(want).await
    }

    /// EHLO, and what the server offers (one extension per line, without the greeting).
    async fn ehlo(&mut self, name: &str) -> Result<Vec<String>, String> {
        let lines = self.cmd(&format!("EHLO {name}"), 250).await?;
        Ok(lines.into_iter().skip(1).collect())
    }

    async fn run(&mut self, smtp: &Smtp, secure: bool, password: Option<&str>, mails: &[Mail]) -> Result<Vec<Result<(), String>>, String> {
        if let (Some(user), Some(pass)) = (&smtp.username, password) {
            if !secure {
                return Err("won't send the SMTP password unencrypted".into());
            }
            let caps = self.ehlo(smtp.from.domain()).await?;
            self.auth(&caps, user, pass).await?;
        }
        let mut out = Vec::new();
        for m in mails {
            let r = self.one(smtp, m).await;
            if r.is_err() {
                // A refused recipient leaves the transaction open; a broken session fails the rest.
                if self.cmd("RSET", 250).await.is_err() {
                    out.push(r);
                    out.extend(std::iter::repeat_n(Err("the session ended early".to_string()), mails.len() - out.len()));
                    return Ok(out);
                }
            }
            out.push(r);
        }
        let _ = self.cmd("QUIT", 221).await;
        Ok(out)
    }

    async fn auth(&mut self, caps: &[String], user: &str, pass: &str) -> Result<(), String> {
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let mechs: Vec<String> = caps.iter().filter_map(|l| l.strip_prefix("AUTH ").or_else(|| l.strip_prefix("AUTH="))).flat_map(|m| m.split_whitespace().map(str::to_ascii_uppercase)).collect();
        let failed = |e: String| format!("signing in to the mail server failed: {e}");
        if mechs.iter().any(|m| m == "PLAIN") {
            let token = zeroize::Zeroizing::new(b64(&format!("\0{user}\0{pass}")));
            self.write(format!("AUTH PLAIN {}\r\n", token.as_str()).as_bytes()).await?;
            self.expect(235).await.map_err(failed)?;
        } else if mechs.iter().any(|m| m == "LOGIN") {
            self.cmd("AUTH LOGIN", 334).await.map_err(failed)?;
            self.cmd(&b64(user), 334).await.map_err(failed)?;
            let token = zeroize::Zeroizing::new(b64(pass));
            self.write(format!("{}\r\n", token.as_str()).as_bytes()).await?;
            self.expect(235).await.map_err(failed)?;
        } else {
            return Err("the mail server offers no sign-in SuperBot knows (PLAIN or LOGIN)".into());
        }
        Ok(())
    }

    async fn one(&mut self, smtp: &Smtp, m: &Mail) -> Result<(), String> {
        if !address_ok(&m.to) {
            return Err("not an email address".into());
        }
        self.cmd(&format!("MAIL FROM:<{}>", smtp.from.addr), 250).await?;
        self.cmd(&format!("RCPT TO:<{}>", m.to), 250).await.map_err(|e| format!("refused: {e}"))?;
        self.cmd("DATA", 354).await?;
        self.write(&message(&smtp.from, m)).await?;
        self.expect(250).await.map(|_| ())
    }
}

fn short(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// A header value with no line breaks or other control characters.
fn clean_header(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_string()
}

/// RFC 2047: non-ASCII header text as UTF-8 base64 words.
fn encode_word(s: &str) -> String {
    let s = clean_header(s);
    if s.is_ascii() {
        return s;
    }
    let mut out = Vec::new();
    let mut chunk = String::new();
    for c in s.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            out.push(std::mem::take(&mut chunk));
        }
        chunk.push(c);
    }
    out.push(chunk);
    out.iter().map(|c| format!("=?UTF-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(c))).collect::<Vec<_>>().join("\r\n ")
}

/// The DATA section, ending with the lone dot. The body is base64, so no line of it can
/// be a dot or run past SMTP's line limit whatever text it holds.
fn message(from: &Mailbox, m: &Mail) -> Vec<u8> {
    let id = format!("<{}@{}>", crate::random_hex(12), from.domain());
    let body = base64::engine::general_purpose::STANDARD.encode(m.body.replace("\r\n", "\n").replace('\n', "\r\n"));
    let mut lines = vec![
        format!("From: {}", from.header()),
        format!("To: <{}>", m.to),
        format!("Subject: {}", encode_word(&m.subject)),
        format!("Date: {}", chrono::Utc::now().to_rfc2822()),
        format!("Message-ID: {id}"),
        "MIME-Version: 1.0".into(),
        "Content-Type: text/plain; charset=utf-8".into(),
        "Content-Transfer-Encoding: base64".into(),
        "Auto-Submitted: auto-generated".into(),
        "X-Auto-Response-Suppress: All".into(),
        String::new(),
    ];
    lines.extend(body.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()));
    let mut out = String::new();
    for l in lines {
        if l.starts_with('.') {
            out.push('.');
        }
        out.push_str(&l);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out.into_bytes()
}

#[cfg(test)]
pub mod fake {
    //! A tiny SMTP server for tests: takes every message and remembers it decoded.
    use super::*;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[derive(Clone, Debug, Default)]
    pub struct Received {
        pub from: String,
        pub to: Vec<String>,
        pub headers: String,
        pub body: String,
        /// The decoded AUTH PLAIN token, if the client signed in.
        pub auth: Option<String>,
        pub tls: bool,
    }

    #[derive(Default)]
    pub struct Options {
        /// Offer STARTTLS with this certificate and key.
        pub tls: Option<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)>,
        /// Ask for AUTH PLAIN.
        pub auth: bool,
        /// RCPT addresses containing this are refused with 550.
        pub refuse: Option<String>,
    }

    pub struct Server {
        pub port: u16,
        pub got: Arc<Mutex<Vec<Received>>>,
    }

    pub async fn start(opts: Options) -> Server {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        let got: Arc<Mutex<Vec<Received>>> = Arc::default();
        let store = got.clone();
        let opts = Arc::new(opts);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let (store, opts) = (store.clone(), opts.clone());
                tokio::spawn(async move {
                    let _ = serve(tcp, store, opts).await;
                });
            }
        });
        Server { port, got }
    }

    async fn serve(tcp: TcpStream, store: Arc<Mutex<Vec<Received>>>, opts: Arc<Options>) -> std::io::Result<()> {
        let mut c = BufReader::new(tcp);
        c.write_all(b"220 fake ESMTP\r\n").await?;
        let mut auth = None;
        if let Some((cert, key)) = &opts.tls {
            // Plain until STARTTLS.
            loop {
                let mut line = String::new();
                if c.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                let up = line.trim().to_ascii_uppercase();
                if up.starts_with("EHLO") {
                    c.write_all(b"250-fake\r\n250 STARTTLS\r\n").await?;
                } else if up == "STARTTLS" {
                    c.write_all(b"220 go ahead\r\n").await?;
                    break;
                } else {
                    c.write_all(b"530 STARTTLS first\r\n").await?;
                }
            }
            let cfg = rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![cert.clone()], key.clone_key()).unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(c.into_inner()).await?;
            return session(BufReader::new(tls), store, &opts, &mut auth, true).await;
        }
        session(c, store, &opts, &mut auth, false).await
    }

    async fn session<S: AsyncRead + AsyncWrite + Unpin>(mut c: BufReader<S>, store: Arc<Mutex<Vec<Received>>>, opts: &Options, auth: &mut Option<String>, tls: bool) -> std::io::Result<()> {
        let mut cur = Received { tls, ..Default::default() };
        loop {
            let mut line = String::new();
            if c.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            let l = line.trim_end().to_string();
            let up = l.to_ascii_uppercase();
            if up.starts_with("EHLO") {
                let caps = if opts.auth { "250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n" } else { "250-fake\r\n250 8BITMIME\r\n" };
                c.write_all(caps.as_bytes()).await?;
            } else if let Some(t) = l.strip_prefix("AUTH PLAIN ") {
                let raw = base64::engine::general_purpose::STANDARD.decode(t.trim()).unwrap_or_default();
                *auth = Some(String::from_utf8_lossy(&raw).into_owned());
                c.write_all(b"235 ok\r\n").await?;
            } else if opts.auth && auth.is_none() && up.starts_with("MAIL") {
                c.write_all(b"530 sign in first\r\n").await?;
            } else if let Some(f) = up.strip_prefix("MAIL FROM:") {
                cur = Received { tls, from: f.trim_matches(['<', '>']).to_ascii_lowercase(), auth: auth.clone(), ..Default::default() };
                c.write_all(b"250 ok\r\n").await?;
            } else if let Some(t) = l.get(8..).filter(|_| up.starts_with("RCPT TO:")) {
                let to = t.trim_matches(['<', '>']).to_string();
                if opts.refuse.as_deref().is_some_and(|r| to.contains(r)) {
                    c.write_all(b"550 no such user\r\n").await?;
                } else {
                    cur.to.push(to);
                    c.write_all(b"250 ok\r\n").await?;
                }
            } else if up == "DATA" {
                c.write_all(b"354 go\r\n").await?;
                let mut data = String::new();
                loop {
                    let mut d = String::new();
                    if c.read_line(&mut d).await? == 0 {
                        return Ok(());
                    }
                    if d == ".\r\n" {
                        break;
                    }
                    data.push_str(d.strip_prefix('.').unwrap_or(&d));
                }
                let (headers, body) = data.split_once("\r\n\r\n").unwrap_or((&data, ""));
                let raw = base64::engine::general_purpose::STANDARD.decode(body.replace("\r\n", "")).unwrap_or_default();
                cur.headers = headers.to_string();
                cur.body = String::from_utf8_lossy(&raw).replace("\r\n", "\n");
                store.lock().unwrap().push(std::mem::take(&mut cur));
                c.write_all(b"250 queued\r\n").await?;
            } else if up == "RSET" {
                cur = Received { tls, ..Default::default() };
                c.write_all(b"250 ok\r\n").await?;
            } else if up == "QUIT" {
                c.write_all(b"221 bye\r\n").await?;
                return Ok(());
            } else {
                c.write_all(b"500 what\r\n").await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> String {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default()
    }

    #[test]
    fn settings_from_the_environment() {
        assert!(Smtp::from_env(&vars(&[])).unwrap().is_none(), "off without SMTP_HOST");
        let s = Smtp::from_env(&vars(&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "SuperBot <bots@example.com>"), ("SMTP_USERNAME", "bots")])).unwrap().unwrap();
        assert_eq!((s.port, s.tls, s.from.addr.as_str(), s.from.name.as_deref()), (587, Tls::StartTls, "bots@example.com", Some("SuperBot")));
        assert_eq!(s.describe(), "smtp.example.com:587 (starttls, signing in as bots), from bots@example.com");
        let s = Smtp::from_env(&vars(&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "bots@example.com"), ("SMTP_TLS", "tls")])).unwrap().unwrap();
        assert_eq!((s.port, s.tls), (465, Tls::Implicit));
        for (bad, why) in [
            (&[("SMTP_FROM", "bots@example.com")][..], "SMTP_HOST"),
            (&[("SMTP_HOST", "smtp.example.com")][..], "SMTP_FROM"),
            (&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "bots@example.com"), ("SMTP_TLS", "none")][..], "this machine"),
            (&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "bots@example.com"), ("SMTP_TLS", "maybe")][..], "SMTP_TLS"),
            (&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "not an address")][..], "SMTP_FROM"),
            (&[("SMTP_HOST", "smtp.example.com"), ("SMTP_FROM", "bots@example.com"), ("SMTP_PORT", "0")][..], "SMTP_PORT"),
        ] {
            let pairs: &'static [(&'static str, &'static str)] = Box::leak(bad.to_vec().into_boxed_slice());
            let e = Smtp::from_env(&vars(pairs)).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        let local = Smtp::from_env(&vars(&[("SMTP_HOST", "127.0.0.1"), ("SMTP_FROM", "bots@example.com"), ("SMTP_TLS", "none")])).unwrap().unwrap();
        assert_eq!(local.port, 25);
    }

    #[test]
    fn headers_cannot_be_injected() {
        let from = Mailbox::parse("Super\r\nBcc: x@example.com <bots@example.com>").unwrap();
        let m = Mail { to: "a@example.com".into(), subject: "Hi\r\nBcc: evil@example.com".into(), body: ".\nline\n".into() };
        let data = String::from_utf8(message(&from, &m)).unwrap();
        let headers = data.split("\r\n\r\n").next().unwrap();
        assert!(!headers.lines().any(|l| l.starts_with("Bcc")), "{headers}");
        assert!(data.ends_with("\r\n.\r\n"));
        assert!(!address_ok("a@example.com>\r\nRCPT TO:<b@example.com"));
        assert!(Mailbox::parse("<a b@example.com>").is_err());
        assert_eq!(encode_word("Bot ✓"), "=?UTF-8?B?Qm90IOKckw==?=");
    }

    #[tokio::test]
    async fn sends_one_message_per_recipient_and_reports_refusals() {
        let srv = fake::start(fake::Options { refuse: Some("nobody".into()), ..Default::default() }).await;
        let smtp = Smtp::for_test("127.0.0.1", srv.port, Tls::None, None, None);
        let mails = ["a@example.com", "nobody@example.com", "b@example.com"].map(|to| Mail { to: to.into(), subject: "Approval ✓".into(), body: "Line one\n.\nhttps://x/app/".into() });
        let r = smtp.send(None, &mails).await.unwrap();
        assert!(r[0].is_ok() && r[2].is_ok(), "{r:?}");
        assert!(r[1].as_ref().unwrap_err().contains("550"), "{r:?}");
        let got = srv.got.lock().unwrap().clone();
        assert_eq!(got.iter().map(|g| g.to.clone()).collect::<Vec<_>>(), [vec!["a@example.com".to_string()], vec!["b@example.com".to_string()]]);
        assert_eq!(got[0].body, "Line one\n.\nhttps://x/app/");
        assert!(got[0].headers.contains("Subject: =?UTF-8?B?"), "{}", got[0].headers);
        assert!(got[0].headers.contains("To: <a@example.com>") && !got[0].headers.contains("b@example.com"));
    }

    #[tokio::test]
    async fn starttls_then_signs_in() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
        let srv = fake::start(fake::Options { tls: Some((cert.clone(), key)), auth: true, ..Default::default() }).await;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let smtp = Smtp::for_test("localhost", srv.port, Tls::StartTls, Some("bots"), Some(roots));
        let mail = Mail { to: "a@example.com".into(), subject: "s".into(), body: "b".into() };
        assert!(smtp.send(None, std::slice::from_ref(&mail)).await.unwrap_err().contains(PASSWORD), "no password, no session");
        let r = smtp.send(Some("hunter2-pw"), std::slice::from_ref(&mail)).await.unwrap();
        assert!(r[0].is_ok(), "{r:?}");
        let got = srv.got.lock().unwrap().clone();
        assert_eq!((got[0].tls, got[0].auth.as_deref()), (true, Some("\0bots\0hunter2-pw")));

        // A server without STARTTLS is refused rather than used in the clear.
        let plain = fake::start(fake::Options::default()).await;
        let smtp = Smtp::for_test("127.0.0.1", plain.port, Tls::StartTls, None, None);
        assert!(smtp.send(None, &[mail]).await.unwrap_err().contains("STARTTLS"));
        assert!(plain.got.lock().unwrap().is_empty());
    }
}
