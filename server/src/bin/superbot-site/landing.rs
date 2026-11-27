//! The marketing landing page. Managed plans and their limits come from the tiers file
//! SuperBot ships (`deploy/tiers.example.json`); prices aren't published yet, so the
//! page names the plans and says so rather than showing any. The licensed self-host plan
//! says what botd's `/pricing` says (`license/offer.rs`, ADR 0348), and "Pricing" links
//! to that page when the site is given its address.

use serde_json::Value;

use crate::layout::{Shell, esc, page, pricing_href};
use crate::offer;

#[derive(Debug, PartialEq)]
pub struct Plan {
    pub label: String,
    pub limits: Vec<String>,
}

fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn decimal(n: f64) -> String {
    let s = format!("{n:.1}");
    s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

/// The managed plans in a tiers file: every tier with `limits`, in order, each limit in words.
/// Limits a tier doesn't set aren't mentioned. Tiers without limits (self-host) are left out.
pub fn plans(tiers: &str) -> Result<Vec<Plan>, String> {
    let v: Value = serde_json::from_str(tiers).map_err(|e| format!("tiers file: {e}"))?;
    let tiers = v["tiers"].as_array().ok_or("tiers file: no `tiers` list")?;
    let mut out = Vec::new();
    for t in tiers {
        let Some(l) = t["limits"].as_object() else { continue };
        let label = t["label"].as_str().or(t["name"].as_str()).ok_or("tiers file: a tier without a name")?;
        let n = |k: &str| l.get(k).and_then(Value::as_u64);
        let mut limits = Vec::new();
        if let Some(b) = n("maxBots") {
            limits.push(format!("{} Bots", count(b)));
        }
        if let Some(r) = n("concurrentRuns") {
            limits.push(format!("{} runs at once", count(r)));
        }
        if let Some(r) = n("monthlyRuns") {
            limits.push(format!("{} runs a month", count(r)));
        }
        if let Some(r) = n("dailyRoutineRuns") {
            limits.push(format!("{} routine runs a day", count(r)));
        }
        if let Some(t) = n("monthlyTokens") {
            limits.push(format!("{} million model tokens a month", decimal(t as f64 / 1e6)));
        }
        if let Some(mb) = n("maxStorageMb") {
            limits.push(format!("{} GB of storage", decimal(mb as f64 / 1000.0)));
        }
        out.push(Plan { label: label.to_string(), limits });
    }
    Ok(out)
}

fn plan_card(label: &str, kind: &str, lede: &str, items: &[String], price: &str, cta: &str) -> String {
    let items: String = items.iter().map(|i| format!("              <li>{}</li>\n", esc(i))).collect();
    format!(
        r#"          <li class="card plan">
            <p class="plan-kind">{kind}</p>
            <h3>{label}</h3>
            <p>{lede}</p>
            <ul class="plan-limits">
{items}            </ul>
            <p class="plan-price">{price}</p>
            {cta}
          </li>
"#,
        label = esc(label),
    )
}

/// The block of the server's landing page (`site/index.html`) between
/// `<!-- shared:{name}:start -->` and `<!-- shared:{name}:end -->`, with its `/site/` asset
/// paths pointed at this site's `assets/`, so both landing pages say the same things.
pub fn shared(index: &str, name: &str) -> Result<String, String> {
    let (start, end) = (format!("<!-- shared:{name}:start -->\n"), format!("<!-- shared:{name}:end -->"));
    let from = index.find(&start).ok_or(format!("site/index.html: no {start:?} marker"))? + start.len();
    let to = index[from..].find(&end).ok_or(format!("site/index.html: no {end:?} marker"))? + from;
    Ok(index[from..to].replace("\"/site/", "\"assets/"))
}

/// The public landing page. `index` is the server's landing page, whose product picture,
/// value rows, feature grid and security strip it shares. `pricing_url` is a managed
/// server's `/pricing`, when there is one to link to.
pub fn landing(plans: &[Plan], index: &str, contact_url: &str, pricing_url: Option<&str>, repo_url: &str) -> Result<String, String> {
    let contact = esc(contact_url);
    let sales = format!(r#"<a class="btn btn-ghost btn-small" href="{contact}">Contact sales</a>"#);
    let license = format!(r#"<a class="btn btn-ghost btn-small" href="{contact}">Get a license</a>"#);
    let mut includes = vec![offer::SEATS.to_string()];
    includes.extend(offer::INCLUDES.iter().map(|i| i.to_string()));
    let mut cards = plan_card(
        offer::LABEL,
        &esc(&offer::kind()),
        "Run SuperBot on your own servers, with a license key for your seats.",
        &includes,
        "Pricing to be published",
        &license,
    );
    for p in plans {
        cards.push_str(&plan_card(
            &p.label,
            "Managed, per user",
            "Hosted for you, with an always-on computer for each person.",
            &p.limits,
            "Pricing to be published",
            &sales,
        ));
    }
    cards.push_str(&plan_card(
        "Enterprise",
        "Custom",
        "For larger teams with security, procurement and support needs.",
        &[
            "Self-host or managed".into(),
            "Uptime commitment by agreement".into(),
            "Security pack for your review".into(),
        ],
        "Contact sales",
        &sales,
    ));
    let main = format!(
        r##"  <main id="main">
    <section class="hero" aria-labelledby="hero-title">
      <div class="wrap">
        <p class="eyebrow">AI teammates with their own computer</p>
        <h1 id="hero-title">Your <span class="nowrap">always-on</span> AI team.</h1>
        <p class="lede">Every person gets AI agents that work on their own always-on computer. They browse, write, run tools and finish real tasks, then hand back to you when they need a human.</p>
        <div class="cta">
          <a class="btn btn-primary" href="docs/install.html">Get started</a>
          <a class="link-arrow" href="#plans">See plans</a>
        </div>
        <p class="fine">Open source. Self-host it with a license, or let us run it for you.</p>
{shot}      </div>
    </section>

{values}
    <section id="plans" class="band" aria-labelledby="plans-title">
      <div class="wrap">
        <div class="section-head">
          <h2 id="plans-title">Plans</h2>
          <p class="lede">Run SuperBot yourself with a license, or have it managed for you on a plan per person. Every deployment is on a paid plan; there is no free tier.</p>
        </div>
        <ul class="plans">
{cards}        </ul>
        <p class="fine plans-note">Managed plan limits are those of the plans SuperBot ships with (<a href="{repo}/blob/main/deploy/tiers.example.json">tiers file</a>). {prices} Uptime targets are in the <a href="docs/slo.html">SLO</a>.</p>
      </div>
    </section>

    <section id="docs" aria-labelledby="docs-title">
      <div class="wrap">
        <div class="section-head">
          <h2 id="docs-title">Documentation</h2>
          <p class="lede">Install it, connect your sign-in, run it and review it.</p>
        </div>
        <ul class="grid">
          <li class="card"><h3><a href="docs/install.html">Install</a></h3><p>Set up a server with the installer or Docker Compose.</p></li>
          <li class="card"><h3><a href="docs/install.html#air-gapped-no-internet">Air-gapped installs</a></h3><p>Install and upgrade from an offline bundle, with nothing downloaded.</p></li>
          <li class="card"><h3><a href="docs/index.html#single-sign-on">Single sign-on</a></h3><p>Entra ID, Google, GitHub, Apple, OIDC, SAML and SCIM.</p></li>
          <li class="card"><h3><a href="docs/security/index.html">Security pack</a></h3><p>Policies, controls and evidence for your security review.</p></li>
          <li class="card"><h3><a href="docs/index.html#operations">Operations</a></h3><p>Backups and restores, key rotation and machines.</p></li>
          <li class="card"><h3><a href="docs/index.html#decisions">Decisions</a></h3><p>Every design decision, as an ADR.</p></li>
        </ul>
      </div>
    </section>

    <section class="closing" aria-labelledby="closing-title">
      <div class="wrap">
        <div class="closing-card">
          <h2 id="closing-title">Put an AI team to work</h2>
          <p>Talk to us about a license, a managed plan or Enterprise.</p>
          <div class="cta"><a class="btn btn-primary" href="{contact}">Contact sales</a></div>
        </div>
      </div>
    </section>
  </main>
"##,
        shot = shared(index, "shot")?,
        values = shared(index, "values")?,
        repo = esc(repo_url),
        prices = match pricing_url {
            Some(_) => format!(r#"Current prices are on the <a href="{}">pricing page</a>."#, pricing_href(pricing_url, "")),
            None => "Prices are not published yet.".into(),
        },
    );
    Ok(page(
        &Shell {
            out: "index.html",
            title: "SuperBot · Your always-on AI team",
            description: "SuperBot gives every person on your team always-on AI agents that work on their own computer. Self-host it with a license, even air-gapped, or choose a managed plan per person.",
            repo_url,
            pricing_url,
            docs: false,
        },
        &main,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_come_from_the_tiers_file() {
        let tiers = r#"{"tiers": [
            {"name": "starter", "label": "Starter", "limits": {"maxBots": 3, "monthlyRuns": 3000, "maxStorageMb": 5000, "concurrentRuns": 3}},
            {"name": "pro", "limits": {"monthlyTokens": 20000000, "dailyRoutineRuns": 200, "maxStorageMb": 2500, "machineType": "g6"}},
            {"name": "self-host", "label": "Self-host", "routes": "any"}
        ]}"#;
        assert_eq!(
            plans(tiers).unwrap(),
            [
                Plan { label: "Starter".into(), limits: vec!["3 Bots".into(), "3 runs at once".into(), "3,000 runs a month".into(), "5 GB of storage".into()] },
                Plan { label: "pro".into(), limits: vec!["200 routine runs a day".into(), "20 million model tokens a month".into(), "2.5 GB of storage".into()] },
            ]
        );
        assert!(plans("{}").is_err());
        assert!(plans("not json").is_err());
    }

    #[test]
    fn the_shipped_plans_are_shown_without_prices() {
        let shipped = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/tiers.example.json")).unwrap();
        let plans = plans(&shipped).unwrap();
        let labels: Vec<&str> = plans.iter().map(|p| p.label.as_str()).collect();
        assert_eq!(labels, ["Starter", "Pro", "Max"]);
        let index = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../site/index.html")).unwrap();
        let html = landing(&plans, &index, "https://example.com/contact", None, "https://github.com/o/r").unwrap();
        for label in ["Self-host", "Starter", "Pro", "Max", "Enterprise", "Contact sales", "Pricing to be published", "3 Bots"] {
            assert!(html.contains(label), "{label}");
        }
        assert!(html.contains(r#"<a href="index.html#plans">Pricing</a>"#) && html.contains(r#"id="plans""#), "Pricing is the plans here");
        assert!(html.contains("Prices are not published yet."));
        for price in ["$", "€", "£", "/month", "per month", "free trial"] {
            assert!(!html.contains(price), "{price}");
        }
        assert!(html.contains(r#"href="https://example.com/contact""#));
        for shared in ["An AI computer for every person", "Run it on your servers, even air-gapped", "Built to do the work", "Signed releases", r#"src="assets/mark.svg""#] {
            assert!(html.contains(shared), "{shared}");
        }
        assert!(!html.contains("\"/site/"));
    }

    #[test]
    fn the_self_host_license_says_what_the_server_says_and_pricing_links_to_the_server() {
        let index = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../site/index.html")).unwrap();
        let html = landing(&[], &index, "mailto:sales@example.com", Some("https://app.example.com/pricing"), "https://github.com/o/r").unwrap();
        assert!(html.contains(r#"<p class="plan-kind">Licensed, business edition</p>"#), "{html}");
        for line in std::iter::once(offer::SEATS).chain(offer::INCLUDES.iter().copied()) {
            assert!(html.contains(&format!("<li>{}</li>", esc(line))), "{line}");
        }
        assert!(html.contains(r#"<a class="btn btn-ghost btn-small" href="mailto:sales@example.com">Get a license</a>"#));
        assert_eq!(html.matches(r#"<a href="https://app.example.com/pricing">Pricing</a>"#).count(), 2, "nav and footer");
        assert!(html.contains(r#"Current prices are on the <a href="https://app.example.com/pricing">pricing page</a>."#));
        for price in ["$", "€", "£", "/month", "per month", "free trial"] {
            assert!(!html.contains(price), "{price}");
        }
    }

    #[test]
    fn shared_blocks_come_from_the_server_landing_page() {
        let index = "a\n<!-- shared:x:start -->\n<img src=\"/site/mark.svg\" />\n<!-- shared:x:end -->\nb";
        assert_eq!(shared(index, "x").unwrap(), "<img src=\"assets/mark.svg\" />\n");
        assert!(shared(index, "y").unwrap_err().contains("no \"<!-- shared:y:start -->\\n\" marker"));
        assert!(shared("<!-- shared:x:start -->\n", "x").unwrap_err().contains("shared:x:end"));
    }
}
