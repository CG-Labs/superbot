//! Published plans (ADR 0121): `GET /api/plans` (JSON) and `GET /pricing` (HTML), open to
//! anyone, built from the same tiers file botd enforces, so the page, the app's Plan
//! screen and the limits are one configuration. A tier is listed when it is sold: it has
//! a Stripe price or a published one. Prices are only what the operator wrote in
//! `publishedPrices`; botd never asks Stripe for them, and a tier without one says
//! "Contact us". Enterprise is listed when `PLANS_CONTACT_URL` gives somewhere to ask.
//!
//! Both pages show only what a buyer may see: labels, published prices, limits, machine
//! sizes, own kernels where botd holds tiers to them (ADR 0120) and the operator's
//! feature lines. Never a Stripe price id, route, model, provider, machine plan id, user
//! or count. `PLANS_PAGE` turns them on (`on`), off
//! (`off`), or on only while billing is (`auto`, the default), so a self-hosted server
//! with billing off publishes nothing unless its operator asks it to.

use crate::machines::provider::Resources;
use crate::status::esc;
use crate::tiers::{ListPrice, Tier, Tiers};
use crate::AppState;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::fmt::Write;

pub const JSON_PATH: &str = "/api/plans";
pub const PAGE_PATH: &str = "/pricing";
/// Where the app's Plan screen is, for people who can buy there (ADR 0042).
const BUY_PATH: &str = crate::billing::RETURN_PATH;
const SIGNUP_PATH: &str = "/get-started";
pub const MAX_CONTACT_URL: usize = 300;

/// `PLANS_PAGE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Published while billing is on (`BILLING=on` and a webhook secret).
    #[default]
    Auto,
    On,
    Off,
}

impl Mode {
    pub fn parse(raw: &str) -> Result<Mode, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Mode::Auto),
            "1" | "on" | "true" | "yes" => Ok(Mode::On),
            "0" | "off" | "false" | "no" => Ok(Mode::Off),
            _ => Err(format!("PLANS_PAGE must be auto, on or off, not \"{}\"", crate::audit::clip(raw.trim(), 20))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::On => "on",
            Mode::Off => "off",
        }
    }
}

/// `PLANS_CONTACT_URL`: an https page or a mailto: address where Enterprise buyers ask.
/// It goes into a public page's links, so nothing else.
pub fn contact_url(raw: &str) -> Result<Option<String>, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let fits = s.len() <= MAX_CONTACT_URL && !s.chars().any(|c| c.is_whitespace() || c.is_control());
    let ok = fits
        && url::Url::parse(s).ok().is_some_and(|u| match u.scheme() {
            "https" => u.host_str().is_some_and(|h| !h.is_empty()) && u.username().is_empty() && u.password().is_none(),
            "mailto" => u.path().split_once('@').is_some_and(|(user, host)| !user.is_empty() && host.contains('.') && !host.contains('@')),
            _ => false,
        });
    match ok {
        true => Ok(Some(s.to_string())),
        false => Err(format!(
            "PLANS_CONTACT_URL must be an https:// page or a mailto: address of up to {MAX_CONTACT_URL} characters, like https://example.com/contact or mailto:sales@example.com"
        )),
    }
}

/// What the pages publish, settled at startup.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub mode: Mode,
    /// Whether the pages answer. Unset settings (tests, before startup): off.
    pub published: bool,
    pub contact: Option<String>,
    /// People can buy a plan in the app (checkout is on).
    pub checkout: bool,
    /// The "Get started" form takes requests.
    pub signups: bool,
}

impl Settings {
    /// `PLANS_PAGE` and `PLANS_CONTACT_URL`, given whether billing, checkout and sign-ups are on.
    pub fn from_env(var: &dyn Fn(&str) -> String, billing: bool, checkout: bool, signups: bool) -> Result<Settings, String> {
        let mode = Mode::parse(&var("PLANS_PAGE"))?;
        let contact = contact_url(&var("PLANS_CONTACT_URL"))?;
        let published = match mode {
            Mode::Auto => billing,
            Mode::On => true,
            Mode::Off => false,
        };
        Ok(Settings { mode, published, contact, checkout, signups })
    }

    /// The startup line, and what an operator should fix. Names tiers, never prices or ids.
    pub fn describe(&self, tiers: &Tiers) -> (String, Vec<String>) {
        if !self.published {
            let why = match self.mode {
                Mode::Auto => "PLANS_PAGE=auto and billing is off",
                _ => "PLANS_PAGE=off",
            };
            return (format!("off ({why}; /pricing and /api/plans answer 404)"), Vec::new());
        }
        let sold: Vec<&Tier> = tiers.all().iter().filter(|t| t.published()).collect();
        let names: Vec<&str> = sold.iter().map(|t| t.name.as_str()).collect();
        let listed = match names.is_empty() {
            true => "no tier (none has stripePrices or publishedPrices)".to_string(),
            false => names.join(", "),
        };
        let enterprise = match self.contact {
            Some(_) => "Enterprise with a contact link",
            None => "no Enterprise entry (set PLANS_CONTACT_URL)",
        };
        let line = format!("on at {PAGE_PATH} and {JSON_PATH} (PLANS_PAGE={}): {listed}; {enterprise}", self.mode.as_str());
        let unpriced: Vec<&str> = sold.iter().filter(|t| t.published_prices.is_empty()).map(|t| t.name.as_str()).collect();
        let mut warnings = Vec::new();
        if !unpriced.is_empty() {
            warnings.push(format!(
                "the pricing page shows no price for {} (\"Contact us\"): add publishedPrices to the tiers file to publish one.",
                unpriced.join(", ")
            ));
        }
        (line, warnings)
    }
}

fn group(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `£29 / month`, `€9.50 / month`, `CHF 290 / year`, `KWD 1.500 / month`, each at its
/// currency's own scale (`tiers::CURRENCIES`).
pub fn display(p: &ListPrice) -> String {
    let decimals = crate::tiers::currency_decimals(&p.currency).unwrap_or(2);
    let scale = 10u64.pow(decimals);
    let n = match p.amount.is_multiple_of(scale) {
        true => group(p.amount / scale),
        false => format!("{}.{:0width$}", group(p.amount / scale), p.amount % scale, width = decimals as usize),
    };
    let amount = match p.currency.as_str() {
        "gbp" => format!("£{n}"),
        "eur" => format!("€{n}"),
        "usd" => format!("${n}"),
        c => format!("{} {n}", c.to_ascii_uppercase()),
    };
    format!("{amount} / {}", p.interval)
}

/// One sold tier, as anyone may see it. Every limit is what botd enforces; null is no
/// limit. `machine_cap`: Some(`MAX_CONCURRENT_RUNS`) while Bots run on their owners'
/// machines, where `concurrentRuns` is the tier's, else that cap. None: Bots run on
/// this server, whose cap is shared by everyone, so it's no plan's to publish and
/// `concurrentRuns` is left out. `machine` is the size of the tier's `machineType` when
/// the provider knows it. `own_kernel`: botd holds the tier's machines to a kernel of
/// their own (MACHINE_OWN_KERNEL_TIERS, ADR 0120), so the page may promise it.
fn plan(t: &Tier, machine_cap: Option<Option<u32>>, machine: &dyn Fn(&str) -> Option<Resources>, own_kernel: &dyn Fn(&Tier) -> bool) -> Value {
    let l = &t.limits;
    let mut v = json!({
        "name": t.name,
        "label": t.label,
        "prices": t.published_prices.iter().map(|p| json!({ "amount": p.amount, "currency": p.currency, "interval": p.interval, "display": display(p) })).collect::<Vec<_>>(),
        "limits": {
            "maxBots": l.max_bots,
            "monthlyRuns": l.monthly_runs,
            "monthlyTokens": l.monthly_tokens,
            "dailyRoutineRuns": l.daily_routine_runs,
            "maxStorageMb": l.max_storage_mb,
        },
        "machine": l.machine_type.as_deref().and_then(machine),
        "ownKernel": own_kernel(t),
        "features": t.features,
    });
    if let Some(cap) = machine_cap {
        v["limits"]["concurrentRuns"] = json!(l.concurrent_runs.or(cap));
    }
    v
}

/// Everything both pages show.
pub fn snapshot(
    tiers: &Tiers,
    s: &Settings,
    machine_cap: Option<Option<u32>>,
    machine: &dyn Fn(&str) -> Option<Resources>,
    own_kernel: &dyn Fn(&Tier) -> bool,
) -> Value {
    json!({
        "plans": tiers.all().iter().filter(|t| t.published()).map(|t| plan(t, machine_cap, machine, own_kernel)).collect::<Vec<_>>(),
        "enterprise": s.contact.as_ref().map(|u| json!({ "label": "Enterprise", "contactUrl": u })),
        "contactUrl": s.contact,
        "perPerson": true,
        "checkout": s.checkout,
        "buyUrl": s.checkout.then_some(BUY_PATH),
        "signupUrl": s.signups.then_some(SIGNUP_PATH),
    })
}

fn current(app: &AppState) -> Option<Value> {
    let s = app.plans.get().filter(|s| s.published)?;
    let cp = app.control_plane.get().filter(|cp| cp.enabled());
    let machine = |plan: &str| cp.and_then(|cp| cp.plan_resources(plan));
    let own_kernel = |t: &Tier| cp.is_some_and(|cp| cp.own_kernel_for(t));
    let on_machines = cp.is_some_and(|cp| cp.routing != crate::machines::route::Routing::Off);
    Some(snapshot(app.tiers(), s, on_machines.then(|| app.server_cap()), &machine, &own_kernel))
}

fn off() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "Plans aren't published on this server (PLANS_PAGE)." }))).into_response()
}

fn public_headers(res: &mut Response, csp: &'static str) {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
}

/// `GET /api/plans`: open to anyone, 404 while plans aren't published.
pub async fn json_page(State(app): State<AppState>) -> Response {
    let Some(v) = current(&app) else { return off() };
    let mut res = Json(v).into_response();
    public_headers(&mut res, "default-src 'none'; frame-ancestors 'none'");
    res
}

/// `GET /pricing`: the same, as a page with no script.
pub async fn html_page(State(app): State<AppState>) -> Response {
    let Some(v) = current(&app) else { return off() };
    let mut res = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_html(&v, app.status.enabled())).into_response();
    public_headers(&mut res, "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res
}

const STYLE: &str = ".plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}\
.plan{background:#fff;border:1px solid #e5e5e5;border-radius:10px;padding:16px 18px;display:flex;flex-direction:column}\
.plan h2{margin:0 0 6px}.price{font-size:20px;font-weight:600;margin:0}.price+.price{font-size:15px;font-weight:500;color:#525252}\
.plan ul{margin:12px 0 0;padding-left:18px;font-size:15px}.plan li{margin:3px 0}.cta{margin:24px 0 0;display:flex;gap:16px;flex-wrap:wrap}\
a{color:#1d4ed8}@media(prefers-color-scheme:dark){.plan{background:#1a1a1a;border-color:#2a2a2a}.price+.price{color:#a3a3a3}a{color:#93c5fd}}";

/// `n thing(s) <rest>`, or `unlimited` text when there's no limit.
fn limit(n: Option<u64>, one: &str, many: &str, none: &str) -> String {
    match n {
        Some(1) => format!("1 {one}"),
        Some(n) => format!("{} {many}", group(n)),
        None => none.to_string(),
    }
}

fn plan_html(h: &mut String, p: &Value, contact: Option<&str>) {
    let _ = write!(h, "<section class=\"plan\"><h2>{}</h2>", esc(p["label"].as_str().unwrap_or_default()));
    let prices: Vec<&str> = p["prices"].as_array().into_iter().flatten().filter_map(|x| x["display"].as_str()).collect();
    if prices.is_empty() {
        match contact {
            Some(u) => {
                let _ = write!(h, "<p class=\"price\"><a href=\"{}\">Contact us</a></p>", esc(u));
            }
            None => h.push_str("<p class=\"price\">Contact us</p>"),
        }
    }
    for d in prices {
        let _ = write!(h, "<p class=\"price\">{}</p>", esc(d));
    }
    let l = &p["limits"];
    let n = |k: &str| l[k].as_u64();
    let mut items = vec![
        limit(n("maxBots"), "Bot", "Bots", "Unlimited Bots"),
        limit(n("monthlyRuns"), "Bot run a month", "Bot runs a month", "Unlimited Bot runs"),
        limit(n("monthlyTokens"), "model token a month", "model tokens a month", "No monthly token limit"),
        limit(n("dailyRoutineRuns"), "routine run a day", "routine runs a day", "Unlimited routine runs"),
    ];
    if l.get("concurrentRuns").is_some() {
        items.push(limit(n("concurrentRuns"), "run at once on your machine", "runs at once on your machine", "No limit on runs at once"));
    }
    items.push(match n("maxStorageMb") {
        Some(mb) => format!("{} of storage", crate::storage::human(mb.saturating_mul(1_000_000))),
        None => "No storage limit".into(),
    });
    let m = &p["machine"];
    let kernel = p["ownKernel"] == true;
    match (m["cpus"].as_u64(), m["memoryGiB"].as_u64(), m["diskGiB"].as_u64()) {
        (Some(c), Some(mem), Some(disk)) => items.push(format!(
            "Own machine: {} CPU{}, {mem} GiB memory, {disk} GiB disk{}",
            c,
            if c == 1 { "" } else { "s" },
            if kernel { ", with its own kernel" } else { "" }
        )),
        _ if kernel => items.push("Own machine with its own kernel".into()),
        _ => {}
    }
    items.extend(p["features"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).map(String::from));
    h.push_str("<ul>");
    for i in items {
        let _ = write!(h, "<li>{}</li>", esc(&i));
    }
    h.push_str("</ul></section>");
}

pub fn render_html(v: &Value, status_page: bool) -> String {
    let contact = v["contactUrl"].as_str();
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>SuperBot plans</title><style>{}{STYLE}</style></head><body><main><h1>SuperBot plans</h1><div class=\"plans\">",
        crate::status::STYLE
    );
    let plans = v["plans"].as_array().cloned().unwrap_or_default();
    for p in &plans {
        plan_html(&mut h, p, contact);
    }
    if let Some(u) = v["enterprise"]["contactUrl"].as_str() {
        let _ = write!(
            h,
            "<section class=\"plan\"><h2>Enterprise</h2><p class=\"price\"><a href=\"{}\">Contact sales</a></p>\
             <ul><li>Limits, machines and terms agreed with you</li></ul></section>",
            esc(u)
        );
    }
    h.push_str("</div>");
    if plans.is_empty() && v["enterprise"].is_null() {
        h.push_str("<p class=\"muted\">No plans are published yet.</p>");
    }
    if !plans.is_empty() {
        h.push_str("<p class=\"muted\">Prices are per person. A team pays for one seat per member.</p>");
    }
    let mut cta = Vec::new();
    if let Some(u) = v["buyUrl"].as_str() {
        cta.push(format!("<a href=\"{}\">Choose a plan</a>", esc(u)));
    }
    if let Some(u) = v["signupUrl"].as_str() {
        cta.push(format!("<a href=\"{}\">Get started</a>", esc(u)));
    }
    if status_page {
        cta.push("<a href=\"/status\">Service status</a>".into());
    }
    cta.push(format!("<a href=\"{JSON_PATH}\">JSON</a>"));
    let _ = write!(h, "<p class=\"cta\">{}</p></main></body></html>", cta.join(""));
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRICED: &str = r#"{
      "default": "starter",
      "tiers": [
        { "name": "starter", "label": "Starter", "routes": [{ "harness": "hermes", "provider": "openrouter", "model": "secret/model-name" }],
          "limits": { "maxBots": 3, "monthlyRuns": 300, "dailyRoutineRuns": 24, "machineType": "c2-m4-d40", "maxStorageMb": 5000 },
          "stripePrices": ["price_starter_monthly_id"],
          "publishedPrices": [{ "amount": 1250, "currency": "gbp", "interval": "month" }, { "amount": 12000, "currency": "gbp", "interval": "year" }],
          "features": ["Email support"] },
        { "name": "pro", "label": "Pro", "routes": "any", "limits": { "maxBots": 10, "monthlyTokens": 20000000, "concurrentRuns": 8 },
          "stripePrices": ["price_pro_monthly_id"] },
        { "name": "legacy", "routes": "any" }
      ]
    }"#;

    fn sizes(plan: &str) -> Option<Resources> {
        (plan == "c2-m4-d40").then_some(Resources { cpus: 2, memory_gib: 4, disk_gib: 40 })
    }

    fn no_kernel(_: &Tier) -> bool {
        false
    }

    fn on(contact: Option<&str>) -> Settings {
        Settings { mode: Mode::On, published: true, contact: contact.map(String::from), checkout: true, signups: false }
    }

    #[test]
    fn the_mode_follows_billing_unless_set() {
        let s = |page: &str, contact: &str, billing: bool| {
            let (page, contact) = (page.to_string(), contact.to_string());
            Settings::from_env(&|k| if k == "PLANS_PAGE" { page.clone() } else if k == "PLANS_CONTACT_URL" { contact.clone() } else { String::new() }, billing, false, true)
        };
        assert!(!s("", "", false).unwrap().published, "self-host with billing off publishes nothing");
        assert!(s("", "", true).unwrap().published, "auto: on with billing");
        assert!(s("on", "", false).unwrap().published, "the operator can publish without billing");
        assert!(!s("off", "", true).unwrap().published);
        assert!(!Settings::default().published, "unset settings publish nothing");
        assert!(s("maybe", "", true).unwrap_err().contains("auto, on or off"));
        assert_eq!(s("on", " https://example.com/contact?from=pricing ", false).unwrap().contact.as_deref(), Some("https://example.com/contact?from=pricing"));
        assert_eq!(s("on", "mailto:sales@example.com", false).unwrap().contact.as_deref(), Some("mailto:sales@example.com"));
        for bad in ["http://example.com", "javascript:alert(1)", "https://me:pw@example.com", "mailto:nobody", "example.com", "https://exa mple.com", "data:text/html,hi"] {
            assert!(s("on", bad, false).unwrap_err().contains("PLANS_CONTACT_URL"), "{bad}");
        }
        assert!(contact_url(&format!("https://example.com/{}", "a".repeat(300))).is_err());
    }

    #[test]
    fn prices_read_as_people_write_them() {
        let p = |amount: u64, currency: &str, interval: &str| display(&ListPrice { amount, currency: currency.into(), interval: interval.into() });
        assert_eq!(p(2900, "gbp", "month"), "£29 / month");
        assert_eq!(p(950, "eur", "month"), "€9.50 / month");
        assert_eq!(p(123456705, "usd", "year"), "$1,234,567.05 / year");
        assert_eq!(p(29000, "chf", "year"), "CHF 290 / year");
        assert_eq!(p(3000, "jpy", "month"), "JPY 3,000 / month", "zero-decimal currencies are whole units");
        assert_eq!(p(1500, "kwd", "month"), "KWD 1.500 / month", "three-decimal currencies keep their scale");
        assert_eq!(p(12000, "kwd", "month"), "KWD 12 / month");
        assert_eq!(p(1005, "bhd", "year"), "BHD 1.005 / year");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
    }

    #[test]
    fn sold_tiers_are_listed_with_limits_and_no_secrets() {
        let tiers = Tiers::parse(PRICED, None).unwrap();
        let v = snapshot(&tiers, &on(Some("mailto:sales@example.com")), Some(Some(8)), &sizes, &no_kernel);
        let names: Vec<&str> = v["plans"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["starter", "pro"], "a tier nobody can buy isn't listed: {v}");
        let starter = &v["plans"][0];
        assert_eq!(starter["prices"][0], json!({ "amount": 1250, "currency": "gbp", "interval": "month", "display": "£12.50 / month" }));
        assert_eq!(starter["limits"], json!({ "maxBots": 3, "monthlyRuns": 300, "monthlyTokens": null, "dailyRoutineRuns": 24, "concurrentRuns": 8, "maxStorageMb": 5000 }));
        assert_eq!(starter["machine"], json!({ "cpus": 2, "memoryGiB": 4, "diskGiB": 40 }));
        assert_eq!(starter["features"], json!(["Email support"]));
        let pro = &v["plans"][1];
        assert_eq!((pro["prices"].clone(), pro["limits"]["concurrentRuns"].clone(), pro["machine"].clone()), (json!([]), json!(8), Value::Null));
        assert_eq!(snapshot(&tiers, &on(None), Some(None), &sizes, &no_kernel)["plans"][0]["limits"]["concurrentRuns"], Value::Null, "no cap anywhere");
        // Bots on this server share its cap with everyone: no plan's to publish.
        let local = snapshot(&tiers, &on(None), None, &sizes, &no_kernel);
        assert!(local["plans"].as_array().unwrap().iter().all(|p| p["limits"].get("concurrentRuns").is_none()), "{local}");
        assert!(!render_html(&local, false).contains("at once"), "the page leaves it out too");
        assert_eq!(v["enterprise"], json!({ "label": "Enterprise", "contactUrl": "mailto:sales@example.com" }));
        assert_eq!((v["buyUrl"].as_str(), v["signupUrl"].as_str()), (Some("/app/plan"), None));
        let raw = v.to_string();
        for secret in ["price_", "secret/model-name", "openrouter", "hermes", "c2-m4-d40", "machineType", "routes", "legacy"] {
            assert!(!raw.contains(secret), "{secret} leaked: {raw}");
        }
        assert_eq!(snapshot(&tiers, &on(None), None, &sizes, &no_kernel)["enterprise"], Value::Null);
    }

    #[test]
    fn the_page_shows_prices_or_contact_us_and_escapes() {
        let tiers = Tiers::parse(PRICED, None).unwrap();
        let h = render_html(&snapshot(&tiers, &on(Some("https://example.com/sales?a=1&b=2")), Some(Some(8)), &sizes, &no_kernel), true);
        assert!(h.contains("<h2>Starter</h2>") && h.contains("£12.50 / month") && h.contains("£120 / year"), "{h}");
        assert!(h.contains("3 Bots") && h.contains("300 Bot runs a month") && h.contains("No monthly token limit") && h.contains("5 GB of storage"), "{h}");
        assert!(h.contains("Own machine: 2 CPUs, 4 GiB memory, 40 GiB disk"), "{h}");
        assert!(h.contains("20,000,000 model tokens a month") && h.contains("8 runs at once on your machine"), "{h}");
        assert!(h.contains("<a href=\"https://example.com/sales?a=1&amp;b=2\">Contact us</a>"), "Pro has no published price: {h}");
        assert!(h.contains("Contact sales") && h.contains("href=\"/app/plan\"") && h.contains("href=\"/status\""), "{h}");
        assert!(!h.contains("<script") && !h.contains("price_"), "{h}");
        // Labels and feature lines come from the operator's file, so they are escaped.
        let v = json!({ "plans": [{ "label": "<b>Pro</b>", "prices": [], "limits": {}, "machine": null, "features": ["<script>x</script>"] }], "enterprise": null, "contactUrl": null });
        let h = render_html(&v, false);
        assert!(h.contains("&lt;b&gt;Pro&lt;/b&gt;") && h.contains("&lt;script&gt;") && !h.contains("<script>"), "{h}");
        assert!(h.contains("<p class=\"price\">Contact us</p>") && !h.contains("/status\""), "{h}");
        let empty = render_html(&json!({ "plans": [], "enterprise": null }), false);
        assert!(empty.contains("No plans are published yet."), "{empty}");
    }

    #[test]
    fn own_kernel_is_promised_only_where_it_is_held_to() {
        let tiers = Tiers::parse(PRICED, None).unwrap();
        let starter_only = |t: &Tier| t.name == "starter";
        let v = snapshot(&tiers, &on(None), None, &sizes, &starter_only);
        assert_eq!((v["plans"][0]["ownKernel"].clone(), v["plans"][1]["ownKernel"].clone()), (json!(true), json!(false)), "{v}");
        let h = render_html(&v, false);
        assert!(h.contains("Own machine: 2 CPUs, 4 GiB memory, 40 GiB disk, with its own kernel"), "{h}");
        assert_eq!(h.matches("own kernel").count(), 1, "Pro isn't held to it: {h}");
        let pro_only = |t: &Tier| t.name == "pro";
        let h = render_html(&snapshot(&tiers, &on(None), None, &sizes, &pro_only), false);
        assert!(h.contains("<li>Own machine with its own kernel</li>") && h.contains("40 GiB disk</li>"), "no size known for Pro: {h}");
        let none = snapshot(&tiers, &on(None), None, &sizes, &no_kernel);
        assert!(none["plans"].as_array().unwrap().iter().all(|p| p["ownKernel"] == false) && !render_html(&none, false).contains("kernel"), "{none}");
    }

    #[test]
    fn startup_names_what_is_listed_and_what_has_no_price() {
        let tiers = Tiers::parse(PRICED, None).unwrap();
        let (line, warnings) = on(None).describe(&tiers);
        assert!(line.starts_with("on at /pricing and /api/plans (PLANS_PAGE=on): starter, pro; no Enterprise entry"), "{line}");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("no price for pro") && !warnings[0].contains("price_"), "{}", warnings[0]);
        let (off, w) = Settings::default().describe(&tiers);
        assert!(off.starts_with("off (PLANS_PAGE=auto and billing is off") && w.is_empty(), "{off}");
        let (line, _) = on(None).describe(&Tiers::self_host());
        assert!(line.contains("no tier (none has stripePrices or publishedPrices)"), "{line}");
    }
}
