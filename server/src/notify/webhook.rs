//! Outgoing webhooks for notifications (ADR 0061): a Slack-compatible incoming-webhook
//! body (`{"text": …}`, which Slack, Mattermost, Rocket.Chat, and Discord's `/slack`
//! endpoint take), or SuperBot's own JSON for anything else, optionally signed. The URL
//! is a secret (`NOTIFY_WEBHOOK_URL`, a Bot's `NOTIFY_WEBHOOK_URL_BOT_<ID>`): Slack's
//! carries its token in the path, so it's never shown, logged, or put in an error.

use super::{Notice, NoticeKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// The secret holding the global webhook's URL.
pub const URL: &str = "NOTIFY_WEBHOOK_URL";
/// Signs SuperBot JSON bodies when set (HMAC-SHA256).
pub const SIGNING: &str = "NOTIFY_WEBHOOK_SECRET";
pub const MAX_URL: usize = 2048;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// `{"text": "…"}` with Slack's mrkdwn links.
    #[default]
    Slack,
    /// SuperBot's JSON: the notice's fields.
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s {
            "slack" => Some(Format::Slack),
            "json" => Some(Format::Json),
            _ => None,
        }
    }
}

/// The secret for one Bot's own webhook. Bot ids are short hex; anything else is folded
/// into the characters a secret name may hold.
pub fn bot_secret(bot_id: &str) -> String {
    let id: String = bot_id.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    format!("{URL}_BOT_{id}")
}

/// An https address, or http to this machine (a local relay or a test). No user or
/// password in it: those belong in the path or a header the receiver gives.
pub fn check_url(raw: &str) -> Result<url::Url, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_URL {
        return Err(format!("The webhook URL must be 1 to {MAX_URL} characters"));
    }
    let u = url::Url::parse(raw).map_err(|_| "The webhook URL isn't a web address, like https://hooks.slack.com/services/…".to_string())?;
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if !(u.scheme() == "https" || (u.scheme() == "http" && loopback)) || u.host_str().is_none() {
        return Err("The webhook URL must be https (http only to this machine)".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("The webhook URL can't hold a user name or password".into());
    }
    Ok(u)
}

/// What the settings show of a URL: its host, never the path, which may be a token.
pub fn host_of(raw: &str) -> Option<String> {
    url::Url::parse(raw.trim()).ok().and_then(|u| u.host_str().map(String::from))
}

/// Slack mrkdwn: `&`, `<` and `>` are control characters there.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn body(format: Format, n: &Notice) -> Value {
    if let (NoticeKind::Alert, Some(a)) = (n.kind, &n.alert) {
        return match format {
            Format::Slack => json!({ "text": alert_text(n, a) }),
            Format::Json => json!({ "type": a.event, "alert": a, "text": n.summary(), "sentAt": crate::db::now() }),
        };
    }
    match format {
        Format::Slack => json!({ "text": slack_text(n) }),
        Format::Json => json!({
            "type": match n.kind {
                NoticeKind::Approval => "approval.requested",
                NoticeKind::Digest => "approval.digest",
                NoticeKind::Test => "notification.test",
                NoticeKind::Alert => "alert",
            },
            "bot": { "id": n.bot_id, "name": n.bot_name },
            "approvals": n.items,
            "more": n.more,
            "text": n.summary(),
            "sentAt": crate::db::now(),
        }),
    }
}

fn alert_text(n: &Notice, a: &super::Alert) -> String {
    let mut out = format!("*{}*", esc(&n.summary()));
    for l in &a.lines {
        out.push_str(&format!("\n• {}", esc(l)));
    }
    if let Some(l) = &a.link {
        out.push_str(&format!("\n<{l}|Open the console>"));
    }
    out
}

fn slack_text(n: &Notice) -> String {
    let mut out = format!("*{}*", esc(&n.summary()));
    for i in &n.items {
        out.push_str(&format!("\n• {}", esc(&i.class_label)));
        if let Some(r) = &i.reason {
            out.push_str(&format!(": {}", esc(r)));
        }
        out.push_str(&format!(" ({})", esc(&i.tool)));
        if let Some(s) = &i.subject {
            out.push_str(&format!("\n```{}```", esc(&s.replace("```", "'''"))));
        }
        if n.kind != NoticeKind::Test {
            out.push_str(&format!("\nDenied <!date^{}^{{time}}|at {}> unless someone answers.", i.expires_at / 1000, super::clock(i.expires_at)));
        }
        let links: Vec<String> = [i.link.as_deref().map(|l| format!("<{l}|Open in SuperBot>")), i.console_link.as_deref().map(|l| format!("<{l}|Audit log>"))].into_iter().flatten().collect();
        if !links.is_empty() {
            out.push_str(&format!("\n{}", links.join(" · ")));
        }
    }
    if n.more > 0 {
        out.push_str(&format!("\n…and {} more.", n.more));
    }
    out
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("reqwest client")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `X-SuperBot-Signature: sha256=<hex>` over `<timestamp>.<body>`, with the timestamp
/// in `X-SuperBot-Timestamp`, so a receiver can check it and refuse replays.
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    use aws_lc_rs::hmac;
    let mut msg = format!("{timestamp}.").into_bytes();
    msg.extend_from_slice(body);
    format!("sha256={}", hex(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()), &msg).as_ref()))
}

/// Posts the notice. Errors never hold the URL.
pub async fn post(http: &reqwest::Client, url: &str, format: Format, n: &Notice, signing: Option<&str>) -> Result<u16, String> {
    check_url(url)?;
    let body = serde_json::to_vec(&body(format, n)).map_err(|e| e.to_string())?;
    let mut req = http.post(url).header(reqwest::header::CONTENT_TYPE, "application/json").header(reqwest::header::USER_AGENT, concat!("SuperBot/", env!("CARGO_PKG_VERSION")));
    if let (Format::Json, Some(secret)) = (format, signing) {
        let ts = chrono::Utc::now().timestamp();
        req = req.header("X-SuperBot-Timestamp", ts.to_string()).header("X-SuperBot-Signature", signature(secret, ts, &body));
    }
    let res = req.body(body).send().await.map_err(|e| {
        let e = e.without_url();
        if e.is_timeout() { "the webhook didn't answer in time".to_string() } else { format!("couldn't reach the webhook: {e}") }
    })?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("the webhook answered HTTP {}", status.as_u16()));
    }
    Ok(status.as_u16())
}

#[cfg(test)]
pub mod fake {
    //! A webhook receiver for tests: answers each POST with `status` and keeps it.
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    pub struct Hit {
        pub path: String,
        pub headers: HeaderMap,
        pub body: serde_json::Value,
        pub raw: Vec<u8>,
    }

    pub struct Receiver {
        pub url: String,
        pub hits: Arc<Mutex<Vec<Hit>>>,
        pub status: Arc<Mutex<u16>>,
    }

    pub async fn start(path: &str) -> Receiver {
        type S = (Arc<Mutex<Vec<Hit>>>, Arc<Mutex<u16>>);
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
        let status = Arc::new(Mutex::new(200u16));
        let app = axum::Router::new().route(
            "/{*path}",
            post(|State((hits, status)): State<S>, uri: axum::http::Uri, headers: HeaderMap, body: axum::body::Bytes| async move {
                let body_json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                hits.lock().unwrap().push(Hit { path: uri.path().to_string(), headers, body: body_json, raw: body.to_vec() });
                StatusCode::from_u16(*status.lock().unwrap()).unwrap()
            }),
        );
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://127.0.0.1:{}{path}", l.local_addr().unwrap().port());
        tokio::spawn(axum::serve(l, app.with_state((hits.clone(), status.clone()))).into_future());
        Receiver { url, hits, status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Item;

    fn notice() -> Notice {
        Notice {
            kind: NoticeKind::Approval,
            bot_id: "b1".into(),
            bot_name: "Ops <bot> & co".into(),
            items: vec![Item {
                approval_id: "a1".into(),
                tool: "Bash".into(),
                class: "git_push".into(),
                class_label: "Pushes to a git remote".into(),
                reason: Some("Pushes to a git remote".into()),
                subject: Some("git push origin main".into()),
                expires_at: 1_800_000_000_000,
                link: Some("https://bots.example.com/app/home?approval=a1".into()),
                console_link: Some("https://bots.example.com/console/#audit?target=approval:a1".into()),
            }],
            more: 0,
            alert: None,
        }
    }

    #[test]
    fn alerts_carry_their_event_and_lines() {
        let a = crate::notify::Alert {
            event: "machine.rpo_breached".into(),
            title: "ada@example.com's machine is past its RPO".into(),
            lines: vec!["Tier: pro <fast>".into()],
            target_type: "machine".into(),
            target_id: "m1".into(),
            link: Some("https://bots.example.com/console/#machines".into()),
            ..Default::default()
        };
        let n = Notice { kind: NoticeKind::Alert, bot_id: String::new(), bot_name: String::new(), items: vec![], more: 0, alert: Some(a) };
        let t = body(Format::Slack, &n)["text"].as_str().unwrap().to_string();
        assert!(t.starts_with("*ada@example.com's machine is past its RPO*") && t.contains("• Tier: pro &lt;fast&gt;"), "{t}");
        assert!(t.contains("<https://bots.example.com/console/#machines|Open the console>"), "{t}");
        let j = body(Format::Json, &n);
        assert_eq!((j["type"].as_str(), j["alert"]["targetId"].as_str()), (Some("machine.rpo_breached"), Some("m1")));
        assert!(n.email_body(None).contains("Console (admins): https://bots.example.com/console/#machines"));
        assert_eq!(n.email_subject(), "[SuperBot] ada@example.com's machine is past its RPO");
    }

    #[test]
    fn urls_are_checked_and_never_shown_whole() {
        assert!(check_url("https://hooks.slack.com/services/T0/B0/xyz").is_ok());
        assert!(check_url("http://127.0.0.1:9/hook").is_ok());
        for bad in ["http://hooks.example.com/x", "ftp://example.com", "https://user:pw@example.com/x", "not a url", ""] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        assert_eq!(host_of("https://hooks.slack.com/services/T0/B0/xyz").as_deref(), Some("hooks.slack.com"));
        assert_eq!(bot_secret("a1b2c3d4"), "NOTIFY_WEBHOOK_URL_BOT_A1B2C3D4");
        assert_eq!(bot_secret("x-y"), "NOTIFY_WEBHOOK_URL_BOT_X_Y");
    }

    #[test]
    fn slack_text_escapes_and_links() {
        let t = body(Format::Slack, &notice())["text"].as_str().unwrap().to_string();
        assert!(t.contains("Ops &lt;bot&gt; &amp; co"), "{t}");
        assert!(t.contains("<https://bots.example.com/app/home?approval=a1|Open in SuperBot>"), "{t}");
        assert!(t.contains("```git push origin main```"), "{t}");
        let j = body(Format::Json, &notice());
        assert_eq!((j["type"].as_str(), j["approvals"][0]["approvalId"].as_str()), (Some("approval.requested"), Some("a1")));
    }

    #[test]
    fn signatures_are_hmac_sha256() {
        // Checked against `printf '%s' '1700000000.{}' | openssl dgst -sha256 -hmac k`.
        assert_eq!(signature("k", 1_700_000_000, b"{}"), "sha256=c6ef4734033cee2367414a0939385eca0397754aa7a59716da7463a9298b5146");
        assert_ne!(signature("k", 1, b"{}"), signature("k", 2, b"{}"));
    }

    #[tokio::test]
    async fn posts_and_keeps_the_url_out_of_errors() {
        let r = fake::start("/services/T0/B0/token-9c1f").await;
        assert_eq!(post(&client(), &r.url, Format::Slack, &notice(), None).await, Ok(200));
        assert_eq!(r.hits.lock().unwrap()[0].path, "/services/T0/B0/token-9c1f");
        *r.status.lock().unwrap() = 500;
        let e = post(&client(), &r.url, Format::Json, &notice(), Some("s3cret")).await.unwrap_err();
        assert_eq!(e, "the webhook answered HTTP 500");
        let hit = r.hits.lock().unwrap()[1].clone();
        let ts: i64 = hit.headers["x-superbot-timestamp"].to_str().unwrap().parse().unwrap();
        assert_eq!(hit.headers["x-superbot-signature"].to_str().unwrap(), signature("s3cret", ts, &hit.raw));
        let gone = "http://127.0.0.1:1/services/T0/B0/token-9c1f".to_string();
        let e = post(&client(), &gone, Format::Slack, &notice(), None).await.unwrap_err();
        assert!(!e.contains("token-9c1f"), "{e}");
    }
}
