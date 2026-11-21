//! Tiers (ADR 0033): what a user's plan allows. A tier lists the harness and model
//! routes its users' Bots may run on, and simple limits. Users pick a tier, not a model:
//! a tier with routes is *managed*, so the server picks each run's model from the Bot
//! owner's tier, nobody can set a Bot to a model outside it, and only admins see model
//! names. Without `TIERS_FILE` there is one tier, `self-host`: any harness and model,
//! no limits, which is what every install did before tiers.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const SELF_HOST: &str = "self-host";

/// One allowed way to run: a harness, and the provider, model, and effort it gets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub harness: String,
    /// For harnesses that take one (Hermes's `--provider`). None: the server's setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// None: the harness's own default model.
    #[serde(default)]
    pub model: Option<String>,
    /// None: the harness's default effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

/// Unset is unlimited.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Limits {
    /// Bots one user may own.
    #[serde(default)]
    pub max_bots: Option<u32>,
    /// Bot runs a billing period, counted for the Bot's owner: their paid subscription's
    /// month, else the calendar month (UTC) (ADR 0050).
    #[serde(default)]
    pub monthly_runs: Option<u32>,
    /// Model tokens a billing period, as harnesses report them, counted for the Bot's
    /// owner (ADR 0050). Runs whose harness reports nothing don't count.
    #[serde(default)]
    pub monthly_tokens: Option<u64>,
    /// Routine runs a day (UTC), counted for the Bot's owner when a routine fires (ADR 0040).
    #[serde(default)]
    pub daily_routine_runs: Option<u32>,
    /// The provider plan (a Linode type, e.g. `g6-standard-2`) this tier's users' machines
    /// get, and the only one the control plane gives them (ADR 0040). Unset: any.
    #[serde(default)]
    pub machine_type: Option<String>,
    /// Bot runs at once on one of this tier's users' machines (ADR 0073); more wait their
    /// turn. Unset: `MAX_CONCURRENT_RUNS`. Runs on this server share its own cap instead.
    #[serde(default)]
    pub concurrent_runs: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Tier {
    pub name: String,
    pub label: String,
    /// None: any harness and model. Some: only these, never empty.
    pub routes: Option<Vec<Route>>,
    pub limits: Limits,
    /// Stripe price ids that pay for this tier (ADR 0040). Admins only see them.
    pub stripe_prices: Vec<String>,
}

impl Tier {
    /// Users of a managed tier get the tier's models and never pick or see one.
    pub fn managed(&self) -> bool {
        self.routes.is_some()
    }

    pub fn allows_harness(&self, harness: &str) -> bool {
        self.routes.as_ref().is_none_or(|r| r.iter().any(|r| r.harness == harness))
    }

    /// The tier's harnesses, in order, once each. None: any.
    pub fn harnesses(&self) -> Option<Vec<&str>> {
        let mut out: Vec<&str> = Vec::new();
        for r in self.routes.as_ref()? {
            if !out.contains(&r.harness.as_str()) {
                out.push(&r.harness);
            }
        }
        Some(out)
    }

    /// The route a Bot with these settings runs on. A managed tier keeps the Bot's
    /// model only if it is one of the tier's for that harness, else the harness's first
    /// route, and always uses the route's provider and effort. Err when the tier has
    /// no route for the harness: the Bot can't run until it's moved to one that does.
    pub fn route(&self, harness: &str, model: Option<&str>, effort: Option<&str>) -> Result<Route, String> {
        let Some(routes) = &self.routes else {
            return Ok(Route { harness: harness.into(), provider: None, model: model.map(String::from), effort: effort.map(String::from) });
        };
        let mut of = routes.iter().filter(|r| r.harness == harness);
        let first = of.clone().next().ok_or_else(|| self.harness_error(harness))?;
        Ok(of.find(|r| model.is_some() && r.model.as_deref() == model).unwrap_or(first).clone())
    }

    /// Whether a Bot owned by this tier's user may be set to these. Leaving the model
    /// or effort out is always fine: the tier picks. `current` is the Bot's model when
    /// the model isn't changing, so an effort is checked against that model's route.
    pub fn check(&self, harness: &str, model: Option<&str>, effort: Option<&str>, current: Option<&str>) -> Result<(), String> {
        if !self.managed() {
            return Ok(());
        }
        let route = self.route(harness, model.or(current), effort)?;
        if model.is_some() && route.model.as_deref() != model {
            return Err(format!("The {} plan doesn't include that model. The plan picks the model.", self.label));
        }
        if effort.is_some() && route.effort.as_deref() != effort {
            return Err(format!("The {} plan sets the reasoning effort.", self.label));
        }
        Ok(())
    }

    fn harness_error(&self, harness: &str) -> String {
        let names = self.harnesses().unwrap_or_default().join(", ");
        format!("The {} plan doesn't include the {harness} harness. It includes: {names}.", self.label)
    }

    /// What anyone may see: no routes, so no model names.
    pub fn view(&self) -> Value {
        json!({ "name": self.name, "label": self.label, "managed": self.managed(), "limits": self.limits })
    }

    /// For admins: the routes too.
    pub fn admin_view(&self) -> Value {
        let mut v = self.view();
        v["routes"] = self.routes.as_ref().map_or(json!("any"), |r| json!(r));
        v["stripePrices"] = json!(self.stripe_prices);
        v
    }
}

/// Every configured tier, and which one users without their own get.
#[derive(Clone, Debug)]
pub struct Tiers {
    list: Vec<Tier>,
    default: usize,
    /// "built-in", or the file they came from.
    pub source: String,
}

impl Default for Tiers {
    fn default() -> Self {
        Tiers::self_host()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCfg {
    #[serde(default)]
    default: Option<String>,
    tiers: Vec<TierCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TierCfg {
    name: String,
    #[serde(default)]
    label: Option<String>,
    routes: Value,
    #[serde(default)]
    limits: Limits,
    #[serde(default, rename = "stripePrices")]
    stripe_prices: Vec<String>,
}

fn slug(s: &str) -> bool {
    slug_of(s, 32)
}

pub(crate) fn slug_of(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// A provider, model, or effort name. They become command-line arguments, so no
/// spaces and nothing a harness could read as a flag.
fn word(what: &str, s: &Option<String>) -> Result<Option<String>, String> {
    let Some(s) = s else { return Ok(None) };
    let s = s.trim();
    let ok = (1..=100).contains(&s.len())
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:/@+-".contains(c));
    if !ok {
        return Err(format!("{what} \"{s}\" must be 1 to 100 letters, digits, or . _ : / @ + -, not starting with -"));
    }
    Ok(Some(s.to_string()))
}

impl Tiers {
    /// The built-in tier: any harness and model, no limits.
    pub fn self_host() -> Tiers {
        let t = Tier { name: SELF_HOST.into(), label: "Self-host".into(), routes: None, limits: Limits::default(), stripe_prices: Vec::new() };
        Tiers { list: vec![t], default: 0, source: "built-in".into() }
    }

    /// `{"default"?: name, "tiers": [{name, label?, routes: "any" | [route, ...], limits?}]}`.
    /// `default` (here, or `DEFAULT_TIER` over it) else the first tier is the default.
    pub fn parse(raw: &str, default: Option<&str>) -> Result<Tiers, String> {
        let cfg: FileCfg = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        if cfg.tiers.is_empty() {
            return Err("list at least one tier".into());
        }
        let mut list: Vec<Tier> = Vec::new();
        for t in cfg.tiers {
            let name = t.name.trim().to_string();
            if !slug(&name) {
                return Err(format!("tier \"{name}\": names are up to 32 lowercase letters, digits, and dashes"));
            }
            if list.iter().any(|x| x.name == name) {
                return Err(format!("tier \"{name}\" is listed twice"));
            }
            let routes = match &t.routes {
                Value::String(s) if s == "any" => None,
                Value::Array(_) => {
                    let raw: Vec<Route> = serde_json::from_value(t.routes.clone()).map_err(|e| format!("tier \"{name}\": routes: {e}"))?;
                    if raw.is_empty() {
                        return Err(format!("tier \"{name}\": list at least one route, or \"any\""));
                    }
                    let mut routes: Vec<Route> = Vec::new();
                    for r in raw {
                        let at = |e: String| format!("tier \"{name}\": {e}");
                        let harness = r.harness.trim().to_string();
                        let Some(adapter) = crate::adapters::get(&harness) else {
                            return Err(at(format!("harness \"{harness}\" must be one of {}", crate::adapters::NAMES.join(", "))));
                        };
                        let route = Route {
                            provider: word("provider", &r.provider).map_err(at)?,
                            model: word("model", &r.model).map_err(at)?,
                            effort: word("effort", &r.effort).map_err(at)?,
                            harness,
                        };
                        if route.provider.is_some() && !adapter.supports_provider() {
                            return Err(at(format!("the {} harness doesn't take a provider", route.harness)));
                        }
                        if routes.iter().any(|x| x.harness == route.harness && x.model == route.model) {
                            return Err(at(format!("{} {} is listed twice", route.harness, route.model.as_deref().unwrap_or("(default model)"))));
                        }
                        routes.push(route);
                    }
                    Some(routes)
                }
                _ => return Err(format!("tier \"{name}\": routes must be \"any\" or a list of routes")),
            };
            let label = t.label.map(|l| l.trim().chars().filter(|c| !c.is_control()).take(40).collect::<String>()).filter(|l| !l.is_empty());
            let mut limits = t.limits;
            if let Some(m) = &limits.machine_type {
                let m = m.trim().to_string();
                if !slug_of(&m, 64) {
                    return Err(format!("tier \"{name}\": machineType \"{m}\" must be a provider plan id: lowercase letters, digits, and dashes"));
                }
                limits.machine_type = Some(m);
            }
            if limits.concurrent_runs == Some(0) {
                return Err(format!("tier \"{name}\": concurrentRuns must be at least 1 (leave it out for the server's default)"));
            }
            let mut prices = Vec::new();
            for p in t.stripe_prices {
                let p = p.trim().to_string();
                let ok = p.starts_with("price_") && (7..=100).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !ok {
                    return Err(format!("tier \"{name}\": stripePrices: \"{p}\" isn't a Stripe price id (price_...)"));
                }
                if prices.contains(&p) || list.iter().any(|x| x.stripe_prices.contains(&p)) {
                    return Err(format!("tier \"{name}\": Stripe price \"{p}\" is listed twice"));
                }
                prices.push(p);
            }
            list.push(Tier { label: label.unwrap_or_else(|| name.clone()), name, routes, limits, stripe_prices: prices });
        }
        let default = match default.or(cfg.default.as_deref()).map(str::trim) {
            None => 0,
            Some(d) => list.iter().position(|t| t.name == d).ok_or_else(|| format!("the default tier \"{d}\" isn't listed"))?,
        };
        Ok(Tiers { list, default, source: "inline".into() })
    }

    /// `TIERS_FILE` (a JSON file as `parse` reads it) and `DEFAULT_TIER`.
    pub fn from_env(get: impl Fn(&str) -> String) -> Result<Tiers, String> {
        let file = get("TIERS_FILE");
        let file = file.trim();
        let default = get("DEFAULT_TIER");
        let default = Some(default.trim()).filter(|d| !d.is_empty());
        if file.is_empty() {
            return match default {
                Some(d) if d != SELF_HOST => Err(format!("DEFAULT_TIER is \"{d}\", but without TIERS_FILE the only tier is {SELF_HOST}")),
                _ => Ok(Tiers::self_host()),
            };
        }
        let raw = std::fs::read_to_string(file).map_err(|e| format!("TIERS_FILE {file}: {e}"))?;
        let mut t = Tiers::parse(&raw, default).map_err(|e| format!("TIERS_FILE {file}: {e}"))?;
        t.source = file.into();
        Ok(t)
    }

    pub fn all(&self) -> &[Tier] {
        &self.list
    }

    pub fn get(&self, name: &str) -> Option<&Tier> {
        self.list.iter().find(|t| t.name == name)
    }

    pub fn default_tier(&self) -> &Tier {
        &self.list[self.default]
    }

    /// The tier a Stripe price pays for.
    pub fn by_stripe_price(&self, price: &str) -> Option<&Tier> {
        self.list.iter().find(|t| t.stripe_prices.iter().any(|p| p == price))
    }

    /// A user's tier: the one assigned to them, else the default. One assigned but no
    /// longer configured is the default too; botd warns about those at startup.
    pub fn of(&self, assigned: Option<&str>) -> &Tier {
        assigned.and_then(|n| self.get(n)).unwrap_or_else(|| self.default_tier())
    }

    pub fn describe(&self) -> String {
        let names: Vec<String> = self
            .list
            .iter()
            .map(|t| {
                let routes = t.routes.as_ref().map_or("any model".to_string(), |r| format!("{} routes", r.len()));
                let default = if t.name == self.default_tier().name { ", default" } else { "" };
                format!("{} ({routes}{default})", t.name)
            })
            .collect();
        format!("{} from {}", names.join(", "), self.source)
    }

    pub fn admin_view(&self) -> Value {
        json!({ "default": self.default_tier().name, "source": self.source, "tiers": self.list.iter().map(Tier::admin_view).collect::<Vec<_>>() })
    }
}

/// The usage month a time falls in, as `YYYY-MM` in UTC.
pub fn period(at_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(at_ms).unwrap_or_default().format("%Y-%m").to_string()
}

/// The routine-run day a time falls in, as `YYYY-MM-DD` in UTC.
pub fn day(at_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(at_ms).unwrap_or_default().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
pub(crate) const EXAMPLE: &str = r#"{
  "default": "starter",
  "tiers": [
    { "name": "starter", "label": "Starter",
      "routes": [{ "harness": "claude", "model": "claude-haiku-4-5", "effort": "low" }],
      "limits": { "maxBots": 2, "monthlyRuns": 3, "dailyRoutineRuns": 2, "machineType": "g6-standard-1", "concurrentRuns": 3 },
      "stripePrices": ["price_starter_monthly"] },
    { "name": "pro", "label": "Pro",
      "stripePrices": ["price_pro_monthly", "price_pro_yearly"],
      "routes": [
        { "harness": "claude", "model": "claude-sonnet-4-5" },
        { "harness": "claude", "model": "claude-opus-4-1", "effort": "high" },
        { "harness": "hermes", "provider": "openrouter", "model": "anthropic/claude-sonnet-4.5" }
      ],
      "limits": { "maxBots": 10, "monthlyTokens": 5000000 } },
    { "name": "self-host", "routes": "any" }
  ]
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn tiers() -> Tiers {
        Tiers::parse(EXAMPLE, None).unwrap()
    }

    #[test]
    fn without_a_file_there_is_one_open_tier() {
        let t = Tiers::from_env(|_| String::new()).unwrap();
        assert_eq!(t.all().len(), 1);
        let d = t.default_tier();
        assert_eq!((d.name.as_str(), d.managed()), (SELF_HOST, false));
        assert_eq!(d.limits, Limits::default());
        assert!(d.allows_harness("codex"));
        // Anything goes, exactly as the Bot is set: today's behaviour.
        let r = d.route("codex", Some("gpt-5-codex"), Some("high")).unwrap();
        assert_eq!(r, Route { harness: "codex".into(), provider: None, model: Some("gpt-5-codex".into()), effort: Some("high".into()) });
        assert!(d.check("pi", Some("anything/at-all"), Some("max"), None).is_ok());
        assert!(Tiers::from_env(|k| if k == "DEFAULT_TIER" { "self-host".into() } else { String::new() }).is_ok());
        let e = Tiers::from_env(|k| if k == "DEFAULT_TIER" { "pro".into() } else { String::new() }).unwrap_err();
        assert!(e.contains("without TIERS_FILE"), "{e}");
    }

    #[test]
    fn the_file_is_read_and_checked() {
        let t = tiers();
        assert_eq!(t.default_tier().name, "starter");
        assert_eq!(t.get("self-host").unwrap().label, "self-host");
        assert_eq!(t.get("pro").unwrap().harnesses().unwrap(), ["claude", "hermes"]);
        assert_eq!(t.get("pro").unwrap().limits.monthly_tokens, Some(5_000_000));
        assert_eq!(Tiers::parse(EXAMPLE, Some("pro")).unwrap().default_tier().name, "pro");

        let dir = crate::db::temp_path("tiers");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.json");
        std::fs::write(&path, EXAMPLE).unwrap();
        let p = path.display().to_string();
        let t = Tiers::from_env(|k| if k == "TIERS_FILE" { p.clone() } else { String::new() }).unwrap();
        assert_eq!(t.source, p);
        assert!(t.describe().contains("starter (1 routes, default)"), "{}", t.describe());
        // The example operators copy must stay valid.
        let shipped = Tiers::parse(include_str!("../../deploy/tiers.example.json"), None).unwrap();
        assert_eq!(shipped.default_tier().name, "starter");
        assert!(shipped.all().iter().any(|t| !t.managed()));
        let missing = Tiers::from_env(|k| if k == "TIERS_FILE" { "/nonexistent/tiers.json".into() } else { String::new() }).unwrap_err();
        assert!(missing.starts_with("TIERS_FILE /nonexistent/tiers.json"), "{missing}");

        let bad = |raw: &str| Tiers::parse(raw, None).unwrap_err();
        let one = |tier: &str| format!(r#"{{"tiers":[{tier}]}}"#);
        assert!(bad(r#"{"tiers":[]}"#).contains("at least one tier"));
        assert!(bad(&one(r#"{"name":"Pro","routes":"any"}"#)).contains("lowercase"));
        assert!(bad(r#"{"tiers":[{"name":"a","routes":"any"},{"name":"a","routes":"any"}]}"#).contains("twice"));
        assert!(bad(&one(r#"{"name":"a","routes":"all"}"#)).contains("\"any\" or a list"));
        assert!(bad(&one(r#"{"name":"a","routes":[]}"#)).contains("at least one route"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"gpt"}]}"#)).contains("must be one of"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","provider":"openrouter"}]}"#)).contains("doesn't take a provider"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","model":"--dangerously-skip-permissions"}]}"#)).contains("not starting with -"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","model":"a b"}]}"#)).contains("model"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude"},{"harness":"claude"}]}"#)).contains("twice"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","modle":"x"}]}"#)).contains("unknown field"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"maxBot":1}}"#)).contains("unknown field"));
        assert!(bad(&format!(r#"{{"default":"gold","tiers":[{}]}}"#, r#"{"name":"a","routes":"any"}"#)).contains("\"gold\" isn't listed"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"machineType":"G6 Standard"}}"#)).contains("machineType"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"concurrentRuns":0}}"#)).contains("concurrentRuns must be at least 1"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","stripePrices":["prod_123"]}"#)).contains("isn't a Stripe price id"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","stripePrices":["price_1","price_1"]}"#)).contains("twice"));
        assert!(bad(r#"{"tiers":[{"name":"a","routes":"any","stripePrices":["price_1"]},{"name":"b","routes":"any","stripePrices":["price_1"]}]}"#).contains("twice"));
    }

    #[test]
    fn limits_for_routines_machines_and_prices() {
        let t = tiers();
        let starter = t.get("starter").unwrap();
        assert_eq!((starter.limits.daily_routine_runs, starter.limits.machine_type.as_deref()), (Some(2), Some("g6-standard-1")));
        let pro = t.get("pro").unwrap();
        assert_eq!((pro.limits.daily_routine_runs, pro.limits.machine_type.as_deref()), (None, None));
        assert_eq!(t.by_stripe_price("price_pro_yearly").unwrap().name, "pro");
        assert_eq!(t.by_stripe_price("price_starter_monthly").unwrap().name, "starter");
        assert!(t.by_stripe_price("price_unknown").is_none());
        // Prices are for admins; everyone sees the limits.
        assert!(starter.view().get("stripePrices").is_none());
        assert_eq!(starter.view()["limits"]["dailyRoutineRuns"], 2);
        assert_eq!(starter.admin_view()["stripePrices"], json!(["price_starter_monthly"]));
        // The built-in tier limits nothing.
        let open = Tiers::self_host();
        let l = &open.default_tier().limits;
        assert_eq!((l.daily_routine_runs, l.machine_type.as_deref(), open.by_stripe_price("price_x").is_none()), (None, None, true));
        assert_eq!(l.concurrent_runs, None);
    }

    #[test]
    fn concurrent_runs_per_tier_follow_the_footprint() {
        assert_eq!(tiers().get("starter").unwrap().limits.concurrent_runs, Some(3));
        assert_eq!(tiers().get("pro").unwrap().limits.concurrent_runs, None);
        assert_eq!(tiers().get("starter").unwrap().view()["limits"]["concurrentRuns"], 3);
        // The shipped plans: Hermes Agent's measured fit (ADR 0070), less one run's room.
        let shipped = Tiers::parse(include_str!("../../deploy/tiers.example.json"), None).unwrap();
        let cap = |n: &str| shipped.get(n).unwrap().limits.concurrent_runs;
        assert_eq!((cap("starter"), cap("pro"), cap("max"), cap("self-host")), (Some(3), Some(8), Some(16), None));
    }

    #[test]
    fn days_are_utc() {
        assert_eq!(day(0), "1970-01-01");
        assert_eq!(day(1_796_083_199_999), "2026-11-30");
        assert_eq!(day(1_796_083_200_000), "2026-12-01");
    }

    #[test]
    fn a_managed_tier_picks_the_route() {
        let t = tiers();
        let pro = t.get("pro").unwrap();
        // No model, or one outside the tier: the harness's first route.
        assert_eq!(pro.route("claude", None, None).unwrap().model.as_deref(), Some("claude-sonnet-4-5"));
        assert_eq!(pro.route("claude", Some("claude-mythos-9"), Some("max")).unwrap().model.as_deref(), Some("claude-sonnet-4-5"));
        // One of the tier's: that one, with the route's effort, not the Bot's.
        let opus = pro.route("claude", Some("claude-opus-4-1"), Some("low")).unwrap();
        assert_eq!((opus.model.as_deref(), opus.effort.as_deref()), (Some("claude-opus-4-1"), Some("high")));
        let hermes = pro.route("hermes", None, None).unwrap();
        assert_eq!(hermes.provider.as_deref(), Some("openrouter"));
        // A harness outside the tier doesn't run at all.
        let e = pro.route("codex", None, None).unwrap_err();
        assert!(e.contains("doesn't include the codex harness") && e.contains("claude, hermes"), "{e}");
        assert!(!pro.allows_harness("codex"));

        assert!(pro.check("claude", None, None, None).is_ok());
        assert!(pro.check("claude", Some("claude-opus-4-1"), Some("high"), None).is_ok());
        assert!(pro.check("claude", Some("claude-mythos-9"), None, None).unwrap_err().contains("doesn't include that model"));
        assert!(pro.check("claude", Some("claude-opus-4-1"), Some("max"), None).unwrap_err().contains("sets the reasoning effort"));
        assert!(pro.check("codex", None, None, None).is_err());
        // An effort alone is checked against the route of the model the Bot keeps.
        assert!(pro.check("claude", None, Some("high"), Some("claude-opus-4-1")).is_ok());
        assert!(pro.check("claude", None, Some("high"), Some("claude-sonnet-4-5")).is_err());
        assert!(t.get("starter").unwrap().check("claude", Some("claude-sonnet-4-5"), None, None).is_err());
    }

    #[test]
    fn users_get_their_tier_or_the_default() {
        let t = tiers();
        assert_eq!(t.of(Some("pro")).name, "pro");
        assert_eq!(t.of(None).name, "starter");
        assert_eq!(t.of(Some("retired")).name, "starter");
    }

    #[test]
    fn only_admins_see_routes() {
        let t = tiers();
        let v = t.get("pro").unwrap().view();
        assert_eq!(v["managed"], true);
        assert_eq!(v["limits"]["maxBots"], 10);
        assert!(v.get("routes").is_none() && !v.to_string().contains("sonnet"), "{v}");
        assert!(t.get("pro").unwrap().admin_view()["routes"].to_string().contains("sonnet"));
        assert_eq!(t.get("self-host").unwrap().admin_view()["routes"], "any");
    }

    #[test]
    fn periods_are_utc_months() {
        assert_eq!(period(0), "1970-01");
        // 2026-11-30T23:59:59.999Z and a millisecond later.
        assert_eq!(period(1_796_083_199_999), "2026-11");
        assert_eq!(period(1_796_083_200_000), "2026-12");
    }
}
