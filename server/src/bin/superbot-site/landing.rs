//! The marketing landing page. Managed plans and their limits come from the tiers file
//! SuperBot ships (`deploy/tiers.example.json`); prices aren't published yet, so the
//! page names the plans and says so rather than showing any.

use serde_json::Value;

use crate::layout::{Shell, esc, page};

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

pub fn landing(plans: &[Plan], contact_url: &str, repo_url: &str) -> String {
    let contact = esc(contact_url);
    let sales = format!(r#"<a class="btn btn-ghost btn-small" href="{contact}">Contact sales</a>"#);
    let mut cards = plan_card(
        "Self-host",
        "Licensed",
        "Run SuperBot on your own servers, with a license key for your seats.",
        &[
            "Your servers and your data".into(),
            "Any harness: Claude Code, Codex, Pi or Hermes Agent".into(),
            "Single sign-on, SCIM, approvals and audit".into(),
        ],
        "Pricing to be published",
        &sales,
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
    <section class="hero">
      <div class="wrap hero-grid">
        <div>
          <p class="eyebrow">AI teammates with their own computer</p>
          <h1>Your always-on AI team.</h1>
          <p class="lede">SuperBot gives every person a team of AI agents that keep working when you don't. They work on their own always-on computer, so they can browse, write, run tools and finish real tasks, then hand back to you when they need a human.</p>
          <div class="cta">
            <a class="btn btn-primary" href="docs/index.html">Read the docs</a>
            <a class="btn btn-ghost" href="#plans">See plans</a>
          </div>
          <p class="fine">Open source. Self-host it with a license, or let us run it for you.</p>
        </div>
        <div class="hero-art" aria-hidden="true">
          <div class="window">
            <div class="window-bar"><span></span><span></span><span></span></div>
            <ul class="chat">
              <li class="msg you">Every weekday at 8:00, brief me on our top accounts.</li>
              <li class="msg bot"><img src="assets/mark.svg" alt="" width="22" height="22" /><span>Done. Routine "Morning brief" runs weekdays at 08:00. I'll post it here and flag anything that needs you.</span></li>
              <li class="msg bot"><img src="assets/mark.svg" alt="" width="22" height="22" /><span>The vendor portal wants a sign-in. Can you take over my screen for a minute?</span></li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section id="features" class="band" aria-labelledby="features-title">
      <div class="wrap">
        <h2 id="features-title">Built to do the work, not just talk about it</h2>
        <ul class="features">
          <li class="card">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></svg>
            <h3>A real computer, always on</h3>
            <p>Your agents work on an always-on server with real apps and a real browser. Each one gets its own screen, and you can watch or take over at any time.</p>
          </li>
          <li class="card">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="9" r="3" /><circle cx="17" cy="10" r="2.5" /><path d="M3 19c0-3 2.5-5 5-5s5 2 5 5M14 19c0-2.2 1.4-3.8 3-3.8s3 1.6 3 3.8" /></svg>
            <h3>Personal and team bots</h3>
            <p>Keep private bots for your own work, and share team bots so everyone builds on the same knowledge. You choose who can see and run each one.</p>
          </li>
          <li class="card">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8" /><path d="M12 7v5l3 2" /></svg>
            <h3>Routines that run themselves</h3>
            <p>Schedule briefings, reports, checks and follow-ups in plain words. Results land in your chat, and bots can ask each other for help.</p>
          </li>
          <li class="card">
            <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" /><path d="M9 12l2 2 4-4" /></svg>
            <h3>You stay in control</h3>
            <p>Risky actions wait for your approval. Every action is recorded in an audit log, and secrets are encrypted at rest.</p>
          </li>
        </ul>
      </div>
    </section>

    <section id="plans" aria-labelledby="plans-title">
      <div class="wrap">
        <h2 id="plans-title">Plans</h2>
        <p class="lede">Run SuperBot yourself with a license, or have it managed for you on a plan per person. Every deployment is on a paid plan; there is no free tier.</p>
        <ul class="plans">
{cards}        </ul>
        <p class="fine">Managed plan limits are those of the plans SuperBot ships with (<a href="{repo}/blob/main/deploy/tiers.example.json">tiers file</a>). Prices are not published yet. Uptime targets are in the <a href="docs/slo.html">SLO</a>.</p>
      </div>
    </section>

    <section id="security" class="band" aria-labelledby="security-title">
      <div class="wrap security">
        <div>
          <h2 id="security-title">Enterprise sign-in from day one</h2>
          <p>Sign in with Microsoft Entra ID, Google, GitHub, Apple, any OpenID Connect provider, or SAML 2.0 through a broker. Roles, approvals and a full audit trail keep your admins in charge. Buyers can read the <a href="docs/security/index.html">security pack</a>.</p>
        </div>
        <ul class="badges" aria-label="Supported sign-in providers">
          <li>Microsoft Entra ID</li>
          <li>Google</li>
          <li>GitHub</li>
          <li>Apple</li>
          <li>OpenID Connect</li>
          <li>SAML 2.0</li>
        </ul>
      </div>
    </section>

    <section id="docs" aria-labelledby="docs-title">
      <div class="wrap">
        <h2 id="docs-title">Documentation</h2>
        <ul class="features">
          <li class="card"><h3><a href="docs/install.html">Install</a></h3><p>Set up a server with the installer or Docker Compose.</p></li>
          <li class="card"><h3><a href="docs/index.html#single-sign-on">Single sign-on</a></h3><p>Entra ID, Google, GitHub, Apple, OIDC, SAML and SCIM.</p></li>
          <li class="card"><h3><a href="docs/index.html#operations">Operations</a></h3><p>Backups and restores, key rotation and machines.</p></li>
          <li class="card"><h3><a href="docs/index.html#decisions">Decisions</a></h3><p>Every design decision, as an ADR.</p></li>
        </ul>
      </div>
    </section>

    <section class="closing band" aria-labelledby="closing-title">
      <div class="wrap">
        <h2 id="closing-title">Put an AI team to work</h2>
        <p>Talk to us about a license, a managed plan or Enterprise.</p>
        <a class="btn btn-primary" href="{contact}">Contact sales</a>
      </div>
    </section>
  </main>
"##,
        repo = esc(repo_url),
    );
    page(
        &Shell {
            out: "index.html",
            title: "SuperBot · Your always-on AI team",
            description: "SuperBot gives every person on your team always-on AI agents that work on a real computer. Self-host it with a license, or choose a managed plan per person.",
            repo_url,
            docs: false,
        },
        &main,
    )
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
        let html = landing(&plans, "https://example.com/contact", "https://github.com/o/r");
        for label in ["Self-host", "Starter", "Pro", "Max", "Enterprise", "Contact sales", "Pricing to be published", "3 Bots"] {
            assert!(html.contains(label), "{label}");
        }
        for price in ["$", "€", "£", "/month", "per month", "free trial"] {
            assert!(!html.contains(price), "{price}");
        }
        assert!(html.contains(r#"href="https://example.com/contact""#));
    }
}
