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
    /// What the harness tries, in order, when the provider fails (rate limits, server
    /// errors, auth, ...), for harnesses that take a provider (ADR 0077). Nothing else.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<Fallback>,
}

/// One step of a route's fallback: another provider and model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fallback {
    pub provider: String,
    pub model: String,
}

/// The wire protocol a model endpoint speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Anthropic's Messages API (`/v1/messages`).
    AnthropicMessages,
    /// OpenAI's Chat Completions API (`/chat/completions`).
    OpenaiChat,
    /// OpenAI's Responses API (`/responses`), the only one Codex speaks (ADR 0192).
    OpenaiResponses,
}

impl Protocol {
    /// As the tiers file writes it.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::AnthropicMessages => "anthropic-messages",
            Protocol::OpenaiChat => "openai-chat",
            Protocol::OpenaiResponses => "openai-responses",
        }
    }
}

/// A model endpoint the tiers file names, which routes and fallbacks use as their
/// provider (ADR 0077). The key stays in the secrets store; the file names its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(skip)]
    pub name: String,
    pub protocol: Protocol,
    /// No trailing slash.
    pub base_url: String,
    pub key_secret: String,
    /// The data regions (`MACHINE_REGIONS` ids) the operator says this endpoint
    /// processes in, so runs of data pinned there may use it (ADR 0139). Empty: none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
}

impl Endpoint {
    pub fn serves(&self, region: &str) -> bool {
        self.regions.iter().any(|r| r == region)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EndpointCfg {
    protocol: Protocol,
    base_url: String,
    key_secret: String,
    #[serde(default)]
    regions: Vec<String>,
}

/// A route held to pinned data regions (ADR 0139): its own provider serves every one,
/// and only fallbacks that do too are kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Held {
    pub route: Route,
    /// The regions it is held to.
    pub regions: Vec<String>,
    /// Fallbacks left out because their provider doesn't serve every region.
    pub outside: Vec<Fallback>,
    /// The Bot's own route, when it was outside and another of the tier's was taken.
    pub instead_of: Option<Route>,
}

const MAX_ENDPOINT_REGIONS: usize = 16;

/// What a run on a route needs from the tiers file besides the route: the endpoints
/// it and its fallbacks name, and the fallbacks it may take.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Wiring {
    pub endpoints: Vec<Endpoint>,
    /// None: the harness's own settings (an open tier). Some: exactly these.
    pub fallback: Option<Vec<Fallback>>,
    /// Fallbacks left out because their endpoint's key isn't saved.
    pub skipped: Vec<Fallback>,
    /// The keys of the file's other endpoints: kept out of the run, so each key goes
    /// only to runs routed to its endpoint.
    pub unused_keys: Vec<String>,
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
    /// Storage one user's files may take, in MB (10^6 bytes): their folder and what botd
    /// keeps for them and their Bots (ADR 0082). Past it, new runs are refused. Unset: any.
    #[serde(default)]
    pub max_storage_mb: Option<u64>,
    /// What one Bot run may take of its machine (ADR 0135), held by a cgroup of its own
    /// there. Each part left out takes the safe default (`RunLimitsSpec::resolve`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_limits: Option<RunLimitsSpec>,
}

/// A tier's limits for one Bot run on a user's machine (ADR 0135), as shares of the
/// machine, so they hold whatever its size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunLimitsSpec {
    /// Of all the machine's CPUs, 1 to 100.
    #[serde(default)]
    pub cpu_percent: Option<u32>,
    /// Of the memory runs may use, 1 to 100.
    #[serde(default)]
    pub memory_percent: Option<u32>,
    /// Processes and threads at once, 16 to 65536.
    #[serde(default)]
    pub pids: Option<u32>,
    /// Disk share against other runs, 1 to 10000 (100 is even).
    #[serde(default)]
    pub io_weight: Option<u32>,
}

impl RunLimitsSpec {
    /// The limits sent with a run: these, the defaults where unset.
    pub fn resolve(spec: Option<&RunLimitsSpec>) -> crate::machines::wire::RunLimits {
        let d = crate::machines::cgroup::DEFAULT;
        let s = spec.copied().unwrap_or_default();
        crate::machines::wire::RunLimits {
            cpu_percent: s.cpu_percent.unwrap_or(d.cpu_percent),
            memory_percent: s.memory_percent.unwrap_or(d.memory_percent),
            pids: s.pids.unwrap_or(d.pids),
            io_weight: s.io_weight.unwrap_or(d.io_weight),
        }
    }

    fn check(&self) -> Result<(), String> {
        let within = |v: Option<u32>, lo: u32, hi: u32, name: &str| match v {
            Some(v) if !(lo..=hi).contains(&v) => Err(format!("runLimits.{name} must be {lo} to {hi} (leave it out for the default)")),
            _ => Ok(()),
        };
        within(self.cpu_percent, 1, 100, "cpuPercent")?;
        within(self.memory_percent, 1, 100, "memoryPercent")?;
        within(self.pids, 16, 65_536, "pids")?;
        within(self.io_weight, 1, 10_000, "ioWeight")
    }
}

/// One published price (ADR 0121): an amount in the currency's smallest unit, as Stripe's
/// `unit_amount` counts it (2900 is £29.00 in `gbp`), per person, per month or year.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPrice {
    pub amount: u64,
    /// ISO 4217, lowercase, as Stripe writes it.
    pub currency: String,
    /// `month` or `year`.
    pub interval: String,
}

/// The currencies a published price may be in, with how many decimal places their
/// smallest unit has, as Stripe counts `unit_amount` (ADR 0121). A fixed list, so a typo
/// (`gpb`) is refused at start and every amount is shown at its real scale.
pub const CURRENCIES: &[(&str, u32)] = &[
    ("aed", 2), ("aud", 2), ("bgn", 2), ("brl", 2), ("cad", 2), ("chf", 2), ("cny", 2), ("czk", 2), ("dkk", 2),
    ("eur", 2), ("gbp", 2), ("hkd", 2), ("huf", 2), ("ils", 2), ("inr", 2), ("mxn", 2), ("myr", 2), ("nok", 2),
    ("nzd", 2), ("php", 2), ("pln", 2), ("ron", 2), ("sar", 2), ("sek", 2), ("sgd", 2), ("thb", 2), ("try", 2),
    ("twd", 2), ("usd", 2), ("zar", 2),
    // Zero-decimal: the amount is already whole units.
    ("bif", 0), ("clp", 0), ("djf", 0), ("gnf", 0), ("jpy", 0), ("kmf", 0), ("krw", 0), ("mga", 0), ("pyg", 0),
    ("rwf", 0), ("ugx", 0), ("vnd", 0), ("vuv", 0), ("xaf", 0), ("xof", 0), ("xpf", 0),
    // Three-decimal: 1500 is 1.500.
    ("bhd", 3), ("jod", 3), ("kwd", 3), ("omr", 3), ("tnd", 3),
];

/// Decimal places in `currency`'s smallest unit. None: not a currency prices may use.
pub fn currency_decimals(currency: &str) -> Option<u32> {
    CURRENCIES.iter().find(|(c, _)| *c == currency).map(|(_, d)| *d)
}

pub const MAX_PUBLISHED_PRICES: usize = 4;
/// Ten million in the largest currency unit is far past any per-person plan.
pub const MAX_PRICE_AMOUNT: u64 = 1_000_000_000;
pub const MAX_FEATURES: usize = 10;
pub const MAX_FEATURE_CHARS: usize = 120;

/// How often a checkout's price bills (ADR 0346).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interval {
    Month,
    Year,
}

impl Interval {
    pub fn as_str(self) -> &'static str {
        match self {
            Interval::Month => "month",
            Interval::Year => "year",
        }
    }

    pub fn parse(raw: &str) -> Option<Interval> {
        match raw.trim() {
            "month" => Some(Interval::Month),
            "year" => Some(Interval::Year),
            _ => None,
        }
    }
}

/// Who a checkout is for: a person's own plan, or a team's (ADR 0093).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Buyer {
    Person,
    Team,
}

/// `checkoutPrices` (ADR 0346): which of the tier's `stripePrices` each checkout sells.
/// People buy `month` or `year`; teams buy `teamMonth` or `teamYear` when either is
/// named, else the same as people. Naming only team prices sells the tier to teams only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckoutPrices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_year: Option<String>,
}

impl CheckoutPrices {
    fn team(&self) -> bool {
        self.team_month.is_some() || self.team_year.is_some()
    }
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
    /// Which of `stripe_prices` checkout sells, by buyer and interval (ADR 0346). None:
    /// people and teams both buy the first of `stripe_prices`, as before.
    pub checkout_prices: Option<CheckoutPrices>,
    /// What the pricing page says the tier costs (ADR 0121), as the operator wrote it.
    /// Stripe's price decides what's charged; botd never asks Stripe for amounts.
    pub published_prices: Vec<ListPrice>,
    /// Short public lines the pricing page lists under the tier, such as its model
    /// access, in the operator's words (ADR 0121). The routes themselves stay hidden.
    pub features: Vec<String>,
    /// The harness new Bots of this tier's users get when none is asked for (ADR 0079):
    /// the file's `defaultHarness`, else the first route's. None on an open tier, whose
    /// new Bots get `DEFAULT_HARNESS`.
    pub default_harness: Option<String>,
}

impl Tier {
    /// Users of a managed tier get the tier's models and never pick or see one.
    pub fn managed(&self) -> bool {
        self.routes.is_some()
    }

    /// The harness a new Bot gets when none is asked for: the plan's on a managed tier,
    /// `server` (`DEFAULT_HARNESS`) on an open one.
    pub fn new_bot_harness<'a>(&'a self, server: &'a str) -> &'a str {
        self.default_harness.as_deref().unwrap_or(server)
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
            return Ok(Route { harness: harness.into(), provider: None, model: model.map(String::from), effort: effort.map(String::from), fallback: Vec::new() });
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
        let mut v = json!({ "name": self.name, "label": self.label, "managed": self.managed(), "limits": self.limits });
        if !self.published_prices.is_empty() {
            v["publishedPrices"] = json!(self.published_prices);
        }
        if !self.features.is_empty() {
            v["features"] = json!(self.features);
        }
        v
    }

    /// Sold, so on the pricing page (ADR 0121): it has a Stripe price or a published one.
    pub fn published(&self) -> bool {
        !self.stripe_prices.is_empty() || !self.published_prices.is_empty()
    }

    /// The Stripe price a checkout by `buyer`, billed every `interval`, sells (ADR 0346).
    /// None: the tier isn't sold to them at that interval.
    pub fn checkout_price(&self, buyer: Buyer, interval: Interval) -> Option<&str> {
        let Some(c) = &self.checkout_prices else {
            return match interval {
                Interval::Month => self.stripe_prices.first().map(String::as_str),
                Interval::Year => None,
            };
        };
        let (month, year) = match buyer {
            Buyer::Team if c.team() => (&c.team_month, &c.team_year),
            _ => (&c.month, &c.year),
        };
        match interval {
            Interval::Month => month.as_deref(),
            Interval::Year => year.as_deref(),
        }
    }

    /// The intervals `buyer` can check out this tier at, monthly first. Empty: not sold to them.
    pub fn checkout_intervals(&self, buyer: Buyer) -> Vec<Interval> {
        [Interval::Month, Interval::Year].into_iter().filter(|i| self.checkout_price(buyer, *i).is_some()).collect()
    }

    /// Sold to teams, and not to people (ADR 0346).
    pub fn team_only(&self) -> bool {
        self.checkout_intervals(Buyer::Person).is_empty() && !self.checkout_intervals(Buyer::Team).is_empty()
    }

    /// `view()` for a plan on sale to `buyer`: with `checkoutPrices`, the intervals it's
    /// sold at, so the apps offer each. Never a price id.
    pub fn sale_view(&self, buyer: Buyer) -> Value {
        let mut v = self.view();
        if self.checkout_prices.is_some() {
            v["intervals"] = json!(self.checkout_intervals(buyer).iter().map(|i| i.as_str()).collect::<Vec<_>>());
        }
        v
    }

    /// For admins: the routes too.
    pub fn admin_view(&self) -> Value {
        let mut v = self.view();
        v["routes"] = self.routes.as_ref().map_or(json!("any"), |r| json!(r));
        v["stripePrices"] = json!(self.stripe_prices);
        if let Some(c) = &self.checkout_prices {
            v["checkoutPrices"] = json!(c);
        }
        v["defaultHarness"] = json!(self.default_harness);
        v
    }
}

/// Every configured tier, and which one users without their own get.
#[derive(Clone, Debug)]
pub struct Tiers {
    list: Vec<Tier>,
    default: usize,
    /// The file's named endpoints, by name.
    providers: Vec<Endpoint>,
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
    #[serde(default)]
    providers: std::collections::BTreeMap<String, EndpointCfg>,
    tiers: Vec<TierCfg>,
}

const MAX_FALLBACKS: usize = 3;

/// Why a model provider's `http://` URL is refused (ADR 0097).
pub const PLAIN_HTTP: &str =
    "must use https://: plain http:// would send prompts and the API key unencrypted, so it is allowed only to this computer (localhost, 127.0.0.0/8, ::1)";

/// Whether prompts and keys sent to `u` are encrypted on the wire or never leave this
/// computer: `https`, or `http` to a loopback address. Only an IP literal or the name
/// `localhost` counts as loopback; any other name could resolve anywhere.
pub fn encrypted_or_loopback(u: &url::Url) -> bool {
    match u.scheme() {
        "https" => true,
        "http" => match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

/// A named endpoint, checked: its URL is handed to the harness and its key secret is
/// read from the secrets store, so neither may be anything else.
fn endpoint(name: &str, e: EndpointCfg) -> Result<Endpoint, String> {
    let at = |e: String| format!("provider \"{name}\": {e}");
    if !slug(name) {
        return Err(at("names are up to 32 lowercase letters, digits, and dashes".into()));
    }
    let url = e.base_url.trim().trim_end_matches('/').to_string();
    let parsed = url::Url::parse(&url).ok().filter(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some_and(|h| !h.is_empty())
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
    });
    let ok = parsed.is_some() && url.len() <= 200 && !url.chars().any(|c| c.is_whitespace() || c.is_control());
    let Some(parsed) = parsed.filter(|_| ok) else {
        return Err(at(format!("baseUrl \"{url}\" must be an http(s) URL with a host, of up to 200 characters, without a user, password, query or fragment")));
    };
    if !encrypted_or_loopback(&parsed) {
        return Err(at(format!("baseUrl \"{url}\" {PLAIN_HTTP} (ADR 0097)")));
    }
    let key = e.key_secret.trim().to_string();
    crate::secrets::check_name(&key).map_err(|e| at(format!("keySecret: {e}")))?;
    if crate::secrets::server_secret(&key) || crate::adapters::secret_env().contains(&key) {
        return Err(at(format!("keySecret: {key} is one of botd's own secrets")));
    }
    if e.regions.len() > MAX_ENDPOINT_REGIONS {
        return Err(at(format!("regions: list at most {MAX_ENDPOINT_REGIONS}")));
    }
    let mut regions: Vec<String> = Vec::new();
    for r in e.regions {
        let r = r.trim().to_string();
        if !slug_of(&r, 32) {
            return Err(at(format!("regions: \"{r}\" must be a data region id, as MACHINE_REGIONS lists them (lowercase letters, digits, and dashes)")));
        }
        if regions.contains(&r) {
            return Err(at(format!("regions: {r} is listed twice")));
        }
        regions.push(r);
    }
    Ok(Endpoint { name: name.into(), protocol: e.protocol, base_url: url, key_secret: key, regions })
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
    #[serde(default, rename = "checkoutPrices")]
    checkout_prices: Option<CheckoutPrices>,
    #[serde(default, rename = "defaultHarness")]
    default_harness: Option<String>,
    #[serde(default, rename = "publishedPrices")]
    published_prices: Vec<ListPrice>,
    #[serde(default)]
    features: Vec<String>,
}

/// `publishedPrices`, checked: whole positive amounts, a currency code, month or year,
/// each currency and interval once.
fn published_prices(raw: Vec<ListPrice>) -> Result<Vec<ListPrice>, String> {
    if raw.len() > MAX_PUBLISHED_PRICES {
        return Err(format!("publishedPrices: list at most {MAX_PUBLISHED_PRICES}"));
    }
    let mut out: Vec<ListPrice> = Vec::new();
    for p in raw {
        let currency = p.currency.trim().to_ascii_lowercase();
        if currency_decimals(&currency).is_none() {
            return Err(format!(
                "publishedPrices: currency \"{}\" must be one of {} (ISO 4217, as Stripe writes it)",
                crate::audit::clip(p.currency.trim(), 10),
                CURRENCIES.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(", ")
            ));
        }
        let interval = p.interval.trim().to_string();
        if !["month", "year"].contains(&interval.as_str()) {
            return Err(format!("publishedPrices: interval \"{interval}\" must be month or year"));
        }
        if p.amount == 0 || p.amount > MAX_PRICE_AMOUNT {
            return Err(format!(
                "publishedPrices: amount must be 1 to {MAX_PRICE_AMOUNT} in the currency's smallest unit (2900 is 29.00); SuperBot has no free tier (ADR 0068)"
            ));
        }
        if out.iter().any(|o| o.currency == currency && o.interval == interval) {
            return Err(format!("publishedPrices: {currency} per {interval} is listed twice"));
        }
        out.push(ListPrice { amount: p.amount, currency, interval });
    }
    Ok(out)
}

/// `checkoutPrices`, checked: each names one of the tier's `stripePrices` (so the webhook
/// places what it sells), at least one is named, and an interval's price isn't also the
/// other interval's for the same buyer.
fn checkout_prices(raw: CheckoutPrices, prices: &[String]) -> Result<CheckoutPrices, String> {
    let clean = |field: &str, p: Option<String>| -> Result<Option<String>, String> {
        let Some(p) = p.map(|p| p.trim().to_string()) else { return Ok(None) };
        match prices.contains(&p) {
            true => Ok(Some(p)),
            false => Err(format!("checkoutPrices.{field}: \"{}\" must be one of the tier's stripePrices", crate::audit::clip(&p, 100))),
        }
    };
    let c = CheckoutPrices {
        month: clean("month", raw.month)?,
        year: clean("year", raw.year)?,
        team_month: clean("teamMonth", raw.team_month)?,
        team_year: clean("teamYear", raw.team_year)?,
    };
    if c == CheckoutPrices::default() {
        return Err("checkoutPrices: name at least one of month, year, teamMonth and teamYear, or leave it out to sell the first of stripePrices".into());
    }
    for (who, m, y) in [("month and year", &c.month, &c.year), ("teamMonth and teamYear", &c.team_month, &c.team_year)] {
        if m.is_some() && m == y {
            return Err(format!("checkoutPrices: {who} name the same price; a Stripe price bills at one interval"));
        }
    }
    Ok(c)
}

fn features(raw: Vec<String>) -> Result<Vec<String>, String> {
    if raw.len() > MAX_FEATURES {
        return Err(format!("features: list at most {MAX_FEATURES}"));
    }
    raw.into_iter()
        .map(|f| {
            let f = f.trim().to_string();
            match (1..=MAX_FEATURE_CHARS).contains(&f.chars().count()) && !f.chars().any(char::is_control) {
                true => Ok(f),
                false => Err(format!("features: each is 1 to {MAX_FEATURE_CHARS} characters on one line")),
            }
        })
        .collect()
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
        let t = Tier {
            name: SELF_HOST.into(),
            label: "Self-host".into(),
            routes: None,
            limits: Limits::default(),
            stripe_prices: Vec::new(),
            checkout_prices: None,
            published_prices: Vec::new(),
            features: Vec::new(),
            default_harness: None,
        };
        Tiers { list: vec![t], default: 0, providers: Vec::new(), source: "built-in".into() }
    }

    /// `{"default"?: name, "providers"?: {name: endpoint}, "tiers": [{name, label?,
    /// routes: "any" | [route, ...], limits?}]}`. `default` (here, or `DEFAULT_TIER`
    /// over it) else the first tier is the default.
    pub fn parse(raw: &str, default: Option<&str>) -> Result<Tiers, String> {
        let cfg: FileCfg = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        if cfg.tiers.is_empty() {
            return Err("list at least one tier".into());
        }
        let providers = cfg.providers.into_iter().map(|(name, e)| endpoint(&name, e)).collect::<Result<Vec<_>, _>>()?;
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
                        let mut route = Route {
                            provider: word("provider", &r.provider).map_err(at)?,
                            model: word("model", &r.model).map_err(at)?,
                            effort: word("effort", &r.effort).map_err(at)?,
                            harness,
                            fallback: Vec::new(),
                        };
                        let speaks = adapter.endpoint_protocols();
                        let harness = route.harness.clone();
                        // An endpoint the harness can't speak to, or (for harnesses with no
                        // providers of their own) a name that isn't one of the file's.
                        let usable = |p: &str| -> Result<(), String> {
                            match providers.iter().find(|e| e.name == p) {
                                Some(e) if speaks.contains(&e.protocol) => Ok(()),
                                Some(_) if speaks.is_empty() => Err(format!("the {harness} harness doesn't take a provider")),
                                Some(e) => {
                                    let takes: Vec<&str> = speaks.iter().map(|p| p.name()).collect();
                                    Err(format!("provider {p} speaks {}, and the {harness} harness takes only {} endpoints (ADR 0192)", e.protocol.name(), takes.join(" or ")))
                                }
                                None if adapter.supports_provider() => Ok(()),
                                None if speaks.is_empty() => Err(format!("the {harness} harness doesn't take a provider")),
                                None => Err(format!("provider {p} isn't one of the file's providers, and the {harness} harness takes only those (ADR 0192)")),
                            }
                        };
                        if let Some(p) = &route.provider {
                            usable(p).map_err(at)?;
                        }
                        if !r.fallback.is_empty() && !adapter.supports_provider() {
                            let why = if speaks.is_empty() { "doesn't take a provider" } else { "has no fallback chain: name one provider (ADR 0192)" };
                            return Err(at(format!("the {harness} harness {why}")));
                        }
                        if r.fallback.len() > MAX_FALLBACKS {
                            return Err(at(format!("a route has at most {MAX_FALLBACKS} fallbacks")));
                        }
                        for f in &r.fallback {
                            let f = Fallback {
                                provider: word("fallback provider", &Some(f.provider.clone())).map_err(at)?.unwrap_or_default(),
                                model: word("fallback model", &Some(f.model.clone())).map_err(at)?.unwrap_or_default(),
                            };
                            let primary = route.provider.as_deref() == Some(f.provider.as_str()) && route.model.as_deref() == Some(f.model.as_str());
                            if primary || route.fallback.contains(&f) {
                                return Err(at(format!("fallback {} {} is listed twice", f.provider, f.model)));
                            }
                            usable(&f.provider).map_err(at)?;
                            route.fallback.push(f);
                        }
                        // The same model may be on two providers, such as an in-region one for
                        // pinned data (ADR 0192); a Bot set to it gets the first.
                        if routes.iter().any(|x| x.harness == route.harness && x.model == route.model && x.provider == route.provider) {
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
            if limits.max_storage_mb.is_some_and(|m| m == 0 || m > crate::storage::MAX_MB) {
                return Err(format!("tier \"{name}\": maxStorageMb must be 1 to {} (leave it out for no limit)", crate::storage::MAX_MB));
            }
            if let Some(r) = &limits.run_limits {
                r.check().map_err(|e| format!("tier \"{name}\": {e}"))?;
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
            let default_harness = match (&routes, t.default_harness.as_deref().map(str::trim)) {
                (None, None) => None,
                (None, Some(_)) => {
                    return Err(format!("tier \"{name}\": defaultHarness is for tiers with routes; new Bots on an open tier get DEFAULT_HARNESS"));
                }
                (Some(r), None) => Some(r[0].harness.clone()),
                (Some(r), Some(h)) if r.iter().any(|r| r.harness == h) => Some(h.to_string()),
                (Some(_), Some(h)) => return Err(format!("tier \"{name}\": defaultHarness \"{h}\" must be one of the tier's routes' harnesses")),
            };
            let checkout_prices = t.checkout_prices.map(|c| checkout_prices(c, &prices)).transpose().map_err(|e| format!("tier \"{name}\": {e}"))?;
            let published_prices = published_prices(t.published_prices).map_err(|e| format!("tier \"{name}\": {e}"))?;
            let features = features(t.features).map_err(|e| format!("tier \"{name}\": {e}"))?;
            list.push(Tier {
                label: label.unwrap_or_else(|| name.clone()),
                name,
                routes,
                limits,
                stripe_prices: prices,
                checkout_prices,
                published_prices,
                features,
                default_harness,
            });
        }
        let default = match default.or(cfg.default.as_deref()).map(str::trim) {
            None => 0,
            Some(d) => list.iter().position(|t| t.name == d).ok_or_else(|| format!("the default tier \"{d}\" isn't listed"))?,
        };
        Ok(Tiers { list, default, providers, source: "inline".into() })
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

    /// The managed tiers' default harnesses, once each, in the file's order.
    pub fn managed_defaults(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for h in self.list.iter().filter_map(|t| t.default_harness.as_deref()) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
        out
    }

    /// What botd says at startup about the harness new Bots get (ADR 0079): one line when
    /// any tier is managed, and a warning for each managed default that can't run where
    /// its users' Bots run. `here`: the harnesses installed on this server, when some
    /// Bots run here; `machines`: those users' machines get, when some run there.
    pub fn default_harness_notes(&self, server: &str, here: Option<&[&str]>, machines: Option<&[&str]>) -> (Option<String>, Vec<String>) {
        let defaults = self.managed_defaults();
        if defaults.is_empty() {
            return (None, Vec::new());
        }
        let plans = |h: &str| {
            let names: Vec<&str> = self.list.iter().filter(|t| t.default_harness.as_deref() == Some(h)).map(|t| t.name.as_str()).collect();
            format!("{} plan{}", names.join(", "), if names.len() == 1 { "" } else { "s" })
        };
        let mut said: Vec<String> = defaults.iter().map(|h| format!("{h} on the {}", plans(h))).collect();
        if self.list.iter().any(|t| !t.managed()) {
            said.push(format!("{server} on open tiers (DEFAULT_HARNESS)"));
        }
        let mut warnings = Vec::new();
        for h in &defaults {
            if here.is_some_and(|i| !i.contains(h)) {
                let hint = crate::adapters::get(h).map(|a| crate::adapters::install::server_hint(a.bin())).unwrap_or_default();
                warnings.push(format!("new Bots on the {} run on {h}, which isn't installed on this server, so their runs here are refused until it is ({hint}).", plans(h)));
            }
            if machines.is_some_and(|m| !m.contains(h)) {
                warnings.push(format!(
                    "new Bots on the {} run on {h}, which MACHINE_HARNESSES doesn't install on users' machines, so their runs there are refused until it is. Add {h} to MACHINE_HARNESSES, or leave it unset.",
                    plans(h)
                ));
            }
        }
        (Some(format!("New Bots: {} (ADR 0079).", said.join("; "))), warnings)
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
        let providers = match self.providers.len() {
            0 => String::new(),
            1 => ", 1 provider".into(),
            n => format!(", {n} providers"),
        };
        format!("{}{providers} from {}", names.join(", "), self.source)
    }

    pub fn providers(&self) -> &[Endpoint] {
        &self.providers
    }

    fn endpoint(&self, name: &str) -> Option<&Endpoint> {
        self.providers.iter().find(|e| e.name == name)
    }

    /// Whether `provider` is one of this file's endpoints and serves every region.
    fn serves_all(&self, provider: Option<&str>, regions: &[String]) -> bool {
        provider.and_then(|p| self.endpoint(p)).is_some_and(|e| regions.iter().all(|r| e.serves(r)))
    }

    /// `route` held to pinned `regions` (ADR 0139): kept if its provider serves them all,
    /// else the first of the tier's routes for the same harness that does. Fallbacks
    /// whose provider doesn't are left out. A harness's built-in provider has no data
    /// region, so only the file's endpoints count. Err: why none of the tier's do.
    pub fn held(&self, tier: &Tier, route: &Route, regions: &[String]) -> Result<Held, String> {
        let same = tier.routes.iter().flatten().filter(|r| r.harness == route.harness && *r != route);
        let Some(pick) = std::iter::once(route).chain(same).find(|r| self.serves_all(r.provider.as_deref(), regions)) else {
            let into = regions.join(" and ");
            let why = match route.provider.as_deref() {
                None => format!("the {} route names no provider from the tiers file, so nothing shows where its model calls are processed", route.harness),
                Some(p) => match self.endpoint(p) {
                    None => format!("its provider {p} is the harness's own, which has no data region"),
                    Some(e) if e.regions.is_empty() => format!("its provider {p} has no regions in the tiers file"),
                    Some(e) => format!("its provider {p} is marked as in {}, not {into}", e.regions.join(", ")),
                },
            };
            return Err(format!("The {} plan has no {} route whose provider is marked as in {into}: {why} (ADR 0139).", tier.label, route.harness));
        };
        let (fallback, outside) = pick.fallback.iter().cloned().partition(|f| self.serves_all(Some(&f.provider), regions));
        Ok(Held { route: Route { fallback, ..pick.clone() }, regions: regions.to_vec(), outside, instead_of: (pick != route).then(|| route.clone()) })
    }

    /// What of `tier` can't run for data pinned to `region` (ADR 0139). None: every
    /// harness it offers has a route there.
    pub fn residency_gap(&self, tier: &Tier, region: &str) -> Option<String> {
        let Some(routes) = &tier.routes else {
            return Some(format!("the {} plan has open routing, so no model route is held to {region}", tier.label));
        };
        let regions = [region.to_string()];
        let mut missing: Vec<&str> = Vec::new();
        for r in routes {
            if !missing.contains(&r.harness.as_str()) && self.held(tier, r, &regions).is_err() {
                missing.push(&r.harness);
            }
        }
        (!missing.is_empty()).then(|| format!("the {} plan has no model route in {region} for {}", tier.label, missing.join(", ")))
    }

    /// Regions the file's endpoints name that aren't offered (`offered`: MACHINE_REGIONS).
    pub fn unknown_regions(&self, offered: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for e in &self.providers {
            for r in e.regions.iter().filter(|r| !offered.contains(r)) {
                out.push(format!("provider {} names data region {r}, which isn't one of MACHINE_REGIONS", e.name));
            }
        }
        out
    }

    /// What a run on `route` gets, given which secrets it has. A provider this file
    /// doesn't name is the harness's own (a built-in, keyed from the harness's usual
    /// env). Err: the endpoint the route's own provider names, whose key isn't saved.
    /// A fallback whose key isn't saved is left out. `managed`: pin the fallbacks to the
    /// route's, so the harness's own settings can't add another provider.
    pub fn wiring(&self, route: &Route, managed: bool, has_key: impl Fn(&str) -> bool) -> Result<Wiring, Endpoint> {
        let mut w = Wiring::default();
        let mut uses: Vec<&Endpoint> = Vec::new();
        if let Some(e) = route.provider.as_deref().and_then(|p| self.endpoint(p)) {
            if !has_key(&e.key_secret) {
                return Err(e.clone());
            }
            uses.push(e);
        }
        let mut fallback = Vec::new();
        for f in &route.fallback {
            match self.endpoint(&f.provider) {
                Some(e) if !has_key(&e.key_secret) => w.skipped.push(f.clone()),
                Some(e) => {
                    uses.push(e);
                    fallback.push(f.clone());
                }
                None => fallback.push(f.clone()),
            }
        }
        for e in uses {
            if !w.endpoints.contains(e) {
                w.endpoints.push(e.clone());
            }
        }
        for e in &self.providers {
            if !w.endpoints.iter().any(|u| u.key_secret == e.key_secret) && !w.unused_keys.contains(&e.key_secret) {
                w.unused_keys.push(e.key_secret.clone());
            }
        }
        w.fallback = managed.then_some(fallback);
        Ok(w)
    }

    pub fn admin_view(&self) -> Value {
        let providers: serde_json::Map<String, Value> = self.providers.iter().map(|e| (e.name.clone(), json!(e))).collect();
        json!({
            "default": self.default_tier().name,
            "source": self.source,
            "providers": providers,
            "tiers": self.list.iter().map(Tier::admin_view).collect::<Vec<_>>(),
        })
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
        assert_eq!(r, Route { harness: "codex".into(), provider: None, model: Some("gpt-5-codex".into()), effort: Some("high".into()), fallback: Vec::new() });
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
        assert_eq!(shipped.providers().iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["anthropic-api", "openai-api"]);
        let max = shipped.get("max").unwrap().route("hermes", None, None).unwrap();
        let w = shipped.wiring(&max, true, |_| false).unwrap();
        assert_eq!((w.fallback, w.skipped.len()), (Some(Vec::new()), 2), "unsaved fallback keys leave the route as it was");
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
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","provider":"openrouter"}]}"#)).contains("isn't one of the file's providers"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"pi","provider":"openrouter"}]}"#)).contains("doesn't take a provider"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","model":"--dangerously-skip-permissions"}]}"#)).contains("not starting with -"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","model":"a b"}]}"#)).contains("model"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude"},{"harness":"claude"}]}"#)).contains("twice"));
        assert!(bad(&one(r#"{"name":"a","routes":[{"harness":"claude","modle":"x"}]}"#)).contains("unknown field"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"maxBot":1}}"#)).contains("unknown field"));
        assert!(bad(&format!(r#"{{"default":"gold","tiers":[{}]}}"#, r#"{"name":"a","routes":"any"}"#)).contains("\"gold\" isn't listed"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"machineType":"G6 Standard"}}"#)).contains("machineType"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"concurrentRuns":0}}"#)).contains("concurrentRuns must be at least 1"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"maxStorageMb":0}}"#)).contains("maxStorageMb must be 1 to"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"maxStorageMb":1000000000000}}"#)).contains("maxStorageMb must be 1 to"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"runLimits":{"cpuPercent":0}}}"#)).contains("runLimits.cpuPercent must be 1 to 100"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"runLimits":{"pids":8}}}"#)).contains("runLimits.pids must be 16 to"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","limits":{"runLimits":{"cpu":50}}}"#)).contains("unknown field"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","stripePrices":["prod_123"]}"#)).contains("isn't a Stripe price id"));
        assert!(bad(&one(r#"{"name":"a","routes":"any","stripePrices":["price_1","price_1"]}"#)).contains("twice"));
        assert!(bad(r#"{"tiers":[{"name":"a","routes":"any","stripePrices":["price_1"]},{"name":"b","routes":"any","stripePrices":["price_1"]}]}"#).contains("twice"));
    }

    #[test]
    fn checkout_prices_sell_yearly_and_team_only_plans() {
        let raw = r#"{"tiers":[
          { "name": "pro", "routes": "any",
            "stripePrices": ["price_pro_m", "price_pro_y", "price_pro_team_m", "price_pro_old"],
            "checkoutPrices": { "month": " price_pro_m ", "year": "price_pro_y", "teamMonth": "price_pro_team_m" } },
          { "name": "yearly", "routes": "any", "stripePrices": ["price_yearly_y"], "checkoutPrices": { "year": "price_yearly_y" } },
          { "name": "business", "label": "Business", "routes": "any",
            "stripePrices": ["price_biz_m", "price_biz_y"], "checkoutPrices": { "teamMonth": "price_biz_m", "teamYear": "price_biz_y" } }
        ]}"#;
        let t = Tiers::parse(raw, None).unwrap();
        let (pro, yearly, biz) = (t.get("pro").unwrap(), t.get("yearly").unwrap(), t.get("business").unwrap());
        // People buy month or year; teams their own price, and only at the intervals it's named for.
        assert_eq!((pro.checkout_price(Buyer::Person, Interval::Month), pro.checkout_price(Buyer::Person, Interval::Year)), (Some("price_pro_m"), Some("price_pro_y")));
        assert_eq!((pro.checkout_price(Buyer::Team, Interval::Month), pro.checkout_price(Buyer::Team, Interval::Year)), (Some("price_pro_team_m"), None));
        assert_eq!((pro.checkout_intervals(Buyer::Person), pro.checkout_intervals(Buyer::Team)), (vec![Interval::Month, Interval::Year], vec![Interval::Month]));
        // Without team prices, teams buy what people do.
        assert_eq!((yearly.checkout_intervals(Buyer::Team), yearly.checkout_price(Buyer::Team, Interval::Year)), (vec![Interval::Year], Some("price_yearly_y")));
        // Only team prices: sold to teams only.
        assert!(biz.team_only() && !pro.team_only() && !yearly.team_only());
        assert!(biz.checkout_intervals(Buyer::Person).is_empty());
        // Every listed price still sets the tier, sold or not.
        assert_eq!(t.by_stripe_price("price_pro_old").unwrap().name, "pro");
        // People see the intervals, never the ids; admins see which price sells.
        assert_eq!(pro.sale_view(Buyer::Person)["intervals"], json!(["month", "year"]));
        assert_eq!(pro.sale_view(Buyer::Team)["intervals"], json!(["month"]));
        assert!(!pro.sale_view(Buyer::Person).to_string().contains("price_"));
        assert_eq!(pro.admin_view()["checkoutPrices"], json!({ "month": "price_pro_m", "year": "price_pro_y", "teamMonth": "price_pro_team_m" }));
        assert!(pro.view().get("intervals").is_none(), "the pricing page's view is unchanged");

        let bad = |c: &str| Tiers::parse(&format!(r#"{{"tiers":[{{"name":"a","routes":"any","stripePrices":["price_1","price_2"],"checkoutPrices":{c}}}]}}"#), None).unwrap_err();
        assert!(bad(r#"{"year":"price_3"}"#).contains("checkoutPrices.year: \"price_3\" must be one of the tier's stripePrices"));
        assert!(bad(r#"{"teamMonth":"price_9"}"#).starts_with("tier \"a\": checkoutPrices.teamMonth"));
        assert!(bad("{}").contains("name at least one"));
        assert!(bad(r#"{"month":"price_1","year":"price_1"}"#).contains("month and year name the same price"));
        assert!(bad(r#"{"teamMonth":"price_2","teamYear":"price_2"}"#).contains("teamMonth and teamYear"));
        assert!(bad(r#"{"monthly":"price_1"}"#).contains("unknown field"));
        let same = r#"{"tiers":[{"name":"a","routes":"any","stripePrices":["price_1","price_2"],"checkoutPrices":{"month":"price_1","year":"price_2","teamMonth":"price_1"}}]}"#;
        assert!(Tiers::parse(same, None).is_ok(), "a team may buy the people's price");
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
        assert_eq!((l.concurrent_runs, l.max_storage_mb), (None, None));
        // Without checkoutPrices, people and teams buy the first price, monthly, as before.
        for b in [Buyer::Person, Buyer::Team] {
            assert_eq!((pro.checkout_price(b, Interval::Month), pro.checkout_price(b, Interval::Year)), (Some("price_pro_monthly"), None));
            assert_eq!(pro.checkout_intervals(b), [Interval::Month]);
            assert!(open.default_tier().checkout_intervals(b).is_empty());
        }
        assert!(!pro.team_only() && pro.sale_view(Buyer::Person).get("intervals").is_none() && pro.admin_view().get("checkoutPrices").is_none());
    }

    #[test]
    fn run_limits_fill_in_the_defaults() {
        let t = Tiers::parse(r#"{"tiers":[{"name":"a","routes":"any","limits":{"runLimits":{"cpuPercent":50,"pids":256}}}]}"#, None).unwrap();
        let r = RunLimitsSpec::resolve(t.get("a").unwrap().limits.run_limits.as_ref());
        let d = crate::machines::cgroup::DEFAULT;
        assert_eq!((r.cpu_percent, r.pids, r.memory_percent, r.io_weight), (50, 256, d.memory_percent, d.io_weight));
        assert_eq!(RunLimitsSpec::resolve(None), d);
    }

    #[test]
    fn published_prices_and_features_are_checked() {
        let one = |extra: &str| format!(r#"{{"tiers":[{{"name":"a","routes":"any"{extra}}}]}}"#);
        let raw = one(r#","publishedPrices":[{"amount":2900,"currency":" GBP ","interval":"month"},{"amount":29000,"currency":"gbp","interval":"year"}],"features":[" Claude Sonnet "]"#);
        let t = Tiers::parse(&raw, None).unwrap();
        let a = t.get("a").unwrap();
        assert_eq!(a.published_prices[0], ListPrice { amount: 2900, currency: "gbp".into(), interval: "month".into() });
        assert_eq!((a.published_prices.len(), a.features.as_slice()), (2, &["Claude Sonnet".to_string()][..]));
        assert!(a.published());
        assert_eq!(a.view()["publishedPrices"][1]["amount"], 29000);
        assert_eq!(a.view()["features"], json!(["Claude Sonnet"]));
        // Nothing new in the view of a tier that sets neither, and not sold.
        let plain = Tiers::parse(&one(""), None).unwrap();
        let p = plain.get("a").unwrap();
        assert!(p.view().get("publishedPrices").is_none() && p.view().get("features").is_none() && !p.published());
        assert!(tiers().get("starter").unwrap().published(), "a Stripe price is enough");

        let bad = |extra: &str| Tiers::parse(&one(extra), None).unwrap_err();
        let price = |p: &str| bad(&format!(r#","publishedPrices":[{p}]"#));
        assert!(price(r#"{"amount":0,"currency":"gbp","interval":"month"}"#).contains("no free tier"));
        assert!(price(r#"{"amount":1000000001,"currency":"gbp","interval":"month"}"#).contains("amount must be"));
        assert!(price(r#"{"amount":-5,"currency":"gbp","interval":"month"}"#).contains("invalid value"));
        assert!(price(r#"{"amount":29.5,"currency":"gbp","interval":"month"}"#).contains("invalid type"));
        assert!(price(r#"{"amount":100,"currency":"pounds","interval":"month"}"#).contains("ISO 4217"));
        assert!(price(r#"{"amount":100,"currency":"g1p","interval":"month"}"#).contains("ISO 4217"));
        assert!(price(r#"{"amount":100,"currency":"gpb","interval":"month"}"#).contains("must be one of"), "a three-letter typo");
        assert_eq!((currency_decimals("kwd"), currency_decimals("jpy"), currency_decimals("gbp"), currency_decimals("gpb")), (Some(3), Some(0), Some(2), None));
        assert!(price(r#"{"amount":100,"currency":"gbp","interval":"week"}"#).contains("month or year"));
        assert!(price(r#"{"amount":100,"currency":"gbp","interval":"month","stripe":"price_1"}"#).contains("unknown field"));
        assert!(price(r#"{"amount":100,"currency":"gbp","interval":"month"},{"amount":200,"currency":"GBP","interval":"month"}"#).contains("listed twice"));
        let five = [r#"{"amount":1,"currency":"gbp","interval":"month"}"#, r#"{"amount":1,"currency":"eur","interval":"month"}"#, r#"{"amount":1,"currency":"usd","interval":"month"}"#, r#"{"amount":1,"currency":"chf","interval":"month"}"#, r#"{"amount":1,"currency":"sek","interval":"month"}"#];
        assert!(price(&five.join(",")).contains("at most 4"));
        assert!(bad(r#","features":[""]"#).contains("1 to 120"));
        assert!(bad(r#","features":["two\nlines"]"#).contains("one line"));
        assert!(bad(&format!(r#","features":["{}"]"#, "x".repeat(121))).contains("1 to 120"));
        assert!(bad(&format!(r#","features":[{}]"#, [r#""x""#; 11].join(","))).contains("at most 10"));
        assert!(bad(r#","publishedPrices":[{"amount":0,"currency":"gbp","interval":"month"}]"#).starts_with("tier \"a\": publishedPrices"));
    }

    #[test]
    fn storage_caps_are_per_tier_and_optional() {
        let raw = r#"{"tiers":[{"name":"small","routes":"any","limits":{"maxStorageMb":500}},{"name":"open","routes":"any"}]}"#;
        let t = Tiers::parse(raw, None).unwrap();
        assert_eq!(t.get("small").unwrap().limits.max_storage_mb, Some(500));
        assert_eq!(t.get("small").unwrap().view()["limits"]["maxStorageMb"], 500);
        assert_eq!(t.get("open").unwrap().limits.max_storage_mb, None);
        let shipped = Tiers::parse(include_str!("../../deploy/tiers.example.json"), None).unwrap();
        let cap = |n: &str| shipped.get(n).unwrap().limits.max_storage_mb;
        assert_eq!((cap("starter"), cap("pro"), cap("max"), cap("self-host")), (Some(5_000), Some(25_000), Some(100_000), None));
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

    const TWO_PROVIDERS: &str = r#"{
      "providers": {
        "claude-api": { "protocol": "anthropic-messages", "baseUrl": "https://api.anthropic.example/", "keySecret": "TIER_ANTHROPIC_KEY" },
        "gpt-api": { "protocol": "openai-chat", "baseUrl": "https://api.openai.example/v1", "keySecret": "TIER_OPENAI_KEY" }
      },
      "tiers": [
        { "name": "basic", "routes": [{ "harness": "hermes", "provider": "gpt-api", "model": "gpt-5-mini",
            "fallback": [{ "provider": "claude-api", "model": "claude-haiku-4-5" }, { "provider": "openrouter", "model": "x/y" }] }] },
        { "name": "plus", "routes": [{ "harness": "hermes", "provider": "claude-api", "model": "claude-sonnet-4-5" }] },
        { "name": "own", "routes": [{ "harness": "hermes" }] },
        { "name": "open", "routes": "any" }
      ]
    }"#;

    #[test]
    fn routes_name_providers_and_fallbacks() {
        let t = Tiers::parse(TWO_PROVIDERS, None).unwrap();
        let claude = t.endpoint("claude-api").unwrap();
        assert_eq!((claude.protocol, claude.base_url.as_str(), claude.key_secret.as_str()), (Protocol::AnthropicMessages, "https://api.anthropic.example", "TIER_ANTHROPIC_KEY"));
        assert_eq!(t.endpoint("gpt-api").unwrap().protocol, Protocol::OpenaiChat);
        let basic = t.get("basic").unwrap().route("hermes", None, None).unwrap();
        assert_eq!(basic.fallback.len(), 2);

        // Every key saved: the endpoints the route uses, once each, and its whole chain.
        let all = t.wiring(&basic, true, |_| true).unwrap();
        assert_eq!(all.endpoints.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["gpt-api", "claude-api"]);
        assert_eq!(all.fallback.as_deref(), Some(basic.fallback.as_slice()));
        assert!(all.skipped.is_empty() && all.unused_keys.is_empty());
        // A fallback without its key is left out; the route's own provider without its key refuses.
        let no_claude = t.wiring(&basic, true, |k| k != "TIER_ANTHROPIC_KEY").unwrap();
        assert_eq!(no_claude.fallback.unwrap(), [Fallback { provider: "openrouter".into(), model: "x/y".into() }]);
        assert_eq!(no_claude.skipped[0].provider, "claude-api");
        assert_eq!(t.wiring(&basic, true, |k| k != "TIER_OPENAI_KEY").unwrap_err().name, "gpt-api");
        // No fallback listed: none on a managed tier; the harness's own on an open one.
        // Keys of endpoints a route doesn't use stay out of its runs.
        let plus = t.get("plus").unwrap().route("hermes", None, None).unwrap();
        let w = t.wiring(&plus, true, |_| true).unwrap();
        assert_eq!((w.fallback, w.unused_keys), (Some(Vec::new()), vec!["TIER_OPENAI_KEY".to_string()]));
        let both = ["TIER_ANTHROPIC_KEY", "TIER_OPENAI_KEY"].map(String::from).to_vec();
        let own = t.get("own").unwrap().route("hermes", None, None).unwrap();
        assert_eq!(t.wiring(&own, true, |_| false).unwrap(), Wiring { fallback: Some(Vec::new()), unused_keys: both.clone(), ..Default::default() });
        let open = t.get("open").unwrap().route("hermes", Some("m"), None).unwrap();
        assert_eq!(t.wiring(&open, false, |_| false).unwrap(), Wiring { unused_keys: both, ..Default::default() });

        // Admins see endpoints by name, with the key's secret name, never a key.
        let v = t.admin_view();
        assert_eq!(v["providers"]["gpt-api"], json!({ "protocol": "openai-chat", "baseUrl": "https://api.openai.example/v1", "keySecret": "TIER_OPENAI_KEY" }));
        assert_eq!(v["tiers"][0]["routes"][0]["fallback"][0], json!({ "provider": "claude-api", "model": "claude-haiku-4-5" }));
        assert!(!t.get("basic").unwrap().view().to_string().contains("gpt-api"));
        assert!(t.describe().contains("2 providers"), "{}", t.describe());
        assert!(tiers().admin_view()["providers"].as_object().unwrap().is_empty());

        let bad = |raw: String| Tiers::parse(&raw, None).unwrap_err();
        let provider = |p: &str| bad(format!(r#"{{"providers":{{{p}}},"tiers":[{{"name":"a","routes":"any"}}]}}"#));
        let endpoint = |name: &str, url: &str, key: &str| provider(&format!(r#""{name}":{{"protocol":"openai-chat","baseUrl":"{url}","keySecret":"{key}"}}"#));
        assert!(endpoint("Gpt", "https://x.example", "K").contains("lowercase"));
        for url in ["ftp://x.example", "https://", "https://:443", "https://me:pw@x.example", "https://x.example/a b", "x.example", "https://x.example/v1?k=1", "https://x.example/#f"] {
            assert!(endpoint("p", url, "K").contains("baseUrl"), "{url}");
        }
        assert!(endpoint("p", &format!("https://x.example/{}", "a".repeat(200)), "K").contains("baseUrl"));
        assert!(endpoint("p", "https://x.example", "lower").contains("keySecret"));
        for own in ["SUPERBOT_MASTER_KEY", "BOT_TOKEN", "AUTH_PASSWORD", "SMTP_PASSWORD", "SSO_GITHUB_CLIENT_SECRET"] {
            assert!(endpoint("p", "https://x.example", own).contains("keySecret"), "{own}");
        }
        assert!(provider(r#""p":{"protocol":"grpc","baseUrl":"https://x.example","keySecret":"K"}"#).contains("unknown variant"));
        assert!(provider(r#""p":{"protocol":"openai-chat","baseUrl":"https://x.example","keySecret":"K","apiKey":"sk"}"#).contains("unknown field"));
        assert!(provider(r#""p":{"protocol":"openai-chat","baseUrl":"https://x.example"}"#).contains("keySecret"));

        let route = |r: &str| bad(format!(r#"{{"tiers":[{{"name":"a","routes":[{r}]}}]}}"#));
        assert!(route(r#"{"harness":"claude","fallback":[{"provider":"p","model":"m"}]}"#).contains("claude harness has no fallback chain"));
        assert!(route(r#"{"harness":"pi","fallback":[{"provider":"p","model":"m"}]}"#).contains("doesn't take a provider"));
        assert!(route(r#"{"harness":"hermes","fallback":[{"provider":"p"}]}"#).contains("model"));
        assert!(route(r#"{"harness":"hermes","fallback":[{"provider":"p","model":"--yolo"}]}"#).contains("not starting with -"));
        assert!(route(r#"{"harness":"hermes","provider":"p","model":"m","fallback":[{"provider":"p","model":"m"}]}"#).contains("twice"));
        assert!(route(r#"{"harness":"hermes","fallback":[{"provider":"p","model":"m"},{"provider":"p","model":"m"}]}"#).contains("twice"));
        let four = r#"{"provider":"p","model":"a"},{"provider":"p","model":"b"},{"provider":"p","model":"c"},{"provider":"p","model":"d"}"#;
        assert!(route(&format!(r#"{{"harness":"hermes","fallback":[{four}]}}"#)).contains("at most 3"));
    }

    const HARNESS_ENDPOINTS: &str = r#"{
      "providers": {
        "uk-claude": { "protocol": "anthropic-messages", "baseUrl": "https://uk.claude.example", "keySecret": "TIER_UK_KEY", "regions": ["gb-lon"] },
        "eu-gpt": { "protocol": "openai-chat", "baseUrl": "https://eu.gpt.example/v1", "keySecret": "TIER_EU_KEY", "regions": ["de-fra-2"] },
        "eu-responses": { "protocol": "openai-responses", "baseUrl": "https://eu.responses.example/v1", "keySecret": "TIER_EU_RESPONSES_KEY", "regions": ["de-fra-2"] }
      },
      "tiers": [
        { "name": "pro", "label": "Pro", "routes": [
            { "harness": "claude", "model": "claude-sonnet-5-5" },
            { "harness": "claude", "provider": "uk-claude", "model": "claude-sonnet-5-5" },
            { "harness": "codex", "model": "gpt-6-codex" },
            { "harness": "codex", "provider": "eu-responses", "model": "gpt-6-codex" }
        ] }
      ]
    }"#;

    #[test]
    fn claude_code_and_codex_take_endpoints_they_speak() {
        let t = Tiers::parse(HARNESS_ENDPOINTS, None).unwrap();
        assert_eq!(t.endpoint("eu-responses").unwrap().protocol, Protocol::OpenaiResponses);
        assert_eq!(t.admin_view()["providers"]["eu-responses"]["protocol"], "openai-responses");
        let pro = t.get("pro").unwrap();
        // The same model on two providers: a Bot set to it gets the first.
        assert_eq!(pro.route("claude", Some("claude-sonnet-5-5"), None).unwrap().provider, None);
        assert_eq!(pro.route("codex", None, None).unwrap().provider, None);
        // A route to an endpoint wires only its key, and no fallback.
        let uk = &pro.routes.as_ref().unwrap()[1];
        let w = t.wiring(uk, true, |_| true).unwrap();
        assert_eq!(w.endpoints.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["uk-claude"]);
        assert_eq!((w.fallback, w.unused_keys.len()), (Some(Vec::new()), 2));

        let bad = |providers: &str, r: &str| {
            Tiers::parse(&format!(r#"{{"providers":{{{providers}}},"tiers":[{{"name":"a","routes":[{r}]}}]}}"#), None).unwrap_err()
        };
        let p = |name: &str, protocol: &str| format!(r#""{name}":{{"protocol":"{protocol}","baseUrl":"https://{name}.example","keySecret":"K_{}"}}"#, name.to_ascii_uppercase());
        let (anthropic, chat, responses) = (p("a", "anthropic-messages"), p("chat", "openai-chat"), p("resp", "openai-responses"));
        let all = [anthropic.as_str(), &chat, &responses].join(",");
        // Each harness takes only the endpoints it speaks to, and Claude Code and Codex only the file's.
        let e = bad(&all, r#"{"harness":"claude","provider":"chat"}"#);
        assert!(e.contains("provider chat speaks openai-chat, and the claude harness takes only anthropic-messages endpoints"), "{e}");
        let e = bad(&all, r#"{"harness":"codex","provider":"chat"}"#);
        assert!(e.contains("the codex harness takes only openai-responses endpoints"), "{e}");
        assert!(bad(&all, r#"{"harness":"codex","provider":"a"}"#).contains("takes only openai-responses"));
        let e = bad(&all, r#"{"harness":"claude","provider":"openrouter"}"#);
        assert!(e.contains("provider openrouter isn't one of the file's providers, and the claude harness takes only those"), "{e}");
        assert!(bad(&all, r#"{"harness":"codex","provider":"resp","fallback":[{"provider":"resp","model":"m"}]}"#).contains("codex harness has no fallback chain"));
        // Hermes takes no Responses endpoint, as its provider or a fallback.
        assert!(bad(&all, r#"{"harness":"hermes","provider":"resp"}"#).contains("the hermes harness takes only anthropic-messages or openai-chat endpoints"));
        assert!(bad(&all, r#"{"harness":"hermes","provider":"a","fallback":[{"provider":"resp","model":"m"}]}"#).contains("provider resp speaks openai-responses"));
        // Pi takes none at all.
        assert!(bad(&all, r#"{"harness":"pi","provider":"a"}"#).contains("the pi harness doesn't take a provider"));
        // Two routes of one harness, model and provider are still one too many.
        assert!(bad(&all, r#"{"harness":"claude","provider":"a","model":"m"},{"harness":"claude","provider":"a","model":"m"}"#).contains("claude m is listed twice"));
        let ok = Tiers::parse(&format!(r#"{{"providers":{{{all}}},"tiers":[{{"name":"a","routes":[{{"harness":"claude","provider":"a"}},{{"harness":"codex","provider":"resp"}},{{"harness":"hermes","provider":"chat","fallback":[{{"provider":"a","model":"m"}}]}}]}}]}}"#), None);
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[test]
    fn pinned_claude_code_and_codex_runs_hold_to_in_region_endpoints() {
        let t = Tiers::parse(HARNESS_ENDPOINTS, None).unwrap();
        let pro = t.get("pro").unwrap();
        // The Bot's own route has no endpoint: the tier's in-region route for the harness instead.
        let claude = pro.route("claude", None, None).unwrap();
        let h = t.held(pro, &claude, &["gb-lon".into()]).unwrap();
        assert_eq!((h.route.provider.as_deref(), h.route.model.as_deref()), (Some("uk-claude"), Some("claude-sonnet-5-5")));
        assert_eq!(h.instead_of.as_ref().map(|r| r.provider.is_none()), Some(true));
        let codex = pro.route("codex", None, None).unwrap();
        assert_eq!(t.held(pro, &codex, &["de-fra-2".into()]).unwrap().route.provider.as_deref(), Some("eu-responses"));
        // Each region has only one of them, so the plan has a gap for the other.
        let e = t.held(pro, &codex, &["gb-lon".into()]).unwrap_err();
        assert!(e.contains("no codex route whose provider is marked as in gb-lon"), "{e}");
        assert_eq!(t.residency_gap(pro, "gb-lon").as_deref(), Some("the Pro plan has no model route in gb-lon for codex"));
        assert_eq!(t.residency_gap(pro, "de-fra-2").as_deref(), Some("the Pro plan has no model route in de-fra-2 for claude"));
    }

    const REGIONAL: &str = r#"{
      "providers": {
        "uk-claude": { "protocol": "anthropic-messages", "baseUrl": "https://uk.claude.example", "keySecret": "TIER_UK_KEY", "regions": [" gb-lon "] },
        "eu-gpt": { "protocol": "openai-chat", "baseUrl": "https://eu.gpt.example/v1", "keySecret": "TIER_EU_KEY", "regions": ["de-fra-2", "gb-lon"] },
        "us-gpt": { "protocol": "openai-chat", "baseUrl": "https://us.gpt.example/v1", "keySecret": "TIER_US_KEY" }
      },
      "tiers": [
        { "name": "pro", "label": "Pro", "routes": [
            { "harness": "hermes", "provider": "us-gpt", "model": "gpt-5",
              "fallback": [{ "provider": "eu-gpt", "model": "gpt-5" }, { "provider": "openrouter", "model": "x/y" }] },
            { "harness": "hermes", "provider": "uk-claude", "model": "claude-sonnet-4-5",
              "fallback": [{ "provider": "us-gpt", "model": "gpt-5" }, { "provider": "eu-gpt", "model": "gpt-5-mini" }] },
            { "harness": "claude", "model": "claude-sonnet-4-5" }
        ] },
        { "name": "us", "label": "US", "routes": [{ "harness": "hermes", "provider": "us-gpt", "model": "gpt-5" }] },
        { "name": "open", "label": "Open", "routes": "any" }
      ]
    }"#;

    #[test]
    fn pinned_runs_hold_to_routes_whose_providers_are_in_the_region() {
        let t = Tiers::parse(REGIONAL, None).unwrap();
        let pro = t.get("pro").unwrap();
        let gb = ["gb-lon".to_string()];
        // The Bot's route is outside: the tier's first hermes route in the region instead,
        // with only its in-region fallbacks.
        let us = pro.route("hermes", Some("gpt-5"), None).unwrap();
        let h = t.held(pro, &us, &gb).unwrap();
        assert_eq!((h.route.provider.as_deref(), h.route.model.as_deref()), (Some("uk-claude"), Some("claude-sonnet-4-5")));
        assert_eq!(h.route.fallback, [Fallback { provider: "eu-gpt".into(), model: "gpt-5-mini".into() }]);
        assert_eq!(h.outside, [Fallback { provider: "us-gpt".into(), model: "gpt-5".into() }]);
        assert_eq!(h.instead_of.as_ref().and_then(|r| r.provider.as_deref()), Some("us-gpt"));
        assert_eq!(h.regions, gb);
        // Already in the region: kept as it is, less the fallbacks outside it.
        let uk = pro.route("hermes", Some("claude-sonnet-4-5"), None).unwrap();
        let h = t.held(pro, &uk, &gb).unwrap();
        assert_eq!((h.route.model.as_deref(), h.instead_of.is_none(), h.outside.len()), (Some("claude-sonnet-4-5"), true, 1));
        // Its wiring takes only in-region endpoints and keys, and the harness adds no fallback.
        let w = t.wiring(&h.route, true, |_| true).unwrap();
        assert_eq!(w.endpoints.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["uk-claude", "eu-gpt"]);
        assert_eq!((w.fallback.as_ref().map(Vec::len), w.unused_keys.as_slice()), (Some(1), &["TIER_US_KEY".to_string()][..]));
        // Frankfurt: only eu-gpt serves it, and no route has it as its own provider.
        let e = t.held(pro, &uk, &["de-fra-2".into()]).unwrap_err();
        assert!(e.contains("The Pro plan has no hermes route") && e.contains("uk-claude is marked as in gb-lon, not de-fra-2"), "{e}");
        // Held to two regions: a provider must serve both.
        let both = ["gb-lon".to_string(), "de-fra-2".to_string()];
        let e = t.held(pro, &us, &both).unwrap_err();
        assert!(e.contains("marked as in gb-lon and de-fra-2: its provider us-gpt has no regions"), "{e}");
        // A harness's built-in provider, or none, has no data region.
        let claude = pro.route("claude", None, None).unwrap();
        assert!(t.held(pro, &claude, &gb).unwrap_err().contains("names no provider from the tiers file"));
        let us_tier = t.get("us").unwrap();
        let e = t.held(us_tier, &us_tier.route("hermes", None, None).unwrap(), &gb).unwrap_err();
        assert!(e.contains("us-gpt has no regions"), "{e}");
        let open = t.get("open").unwrap();
        assert!(t.held(open, &open.route("hermes", Some("m"), None).unwrap(), &gb).is_err());
        let built_in = Tiers::parse(r#"{"tiers":[{"name":"a","routes":[{"harness":"hermes","provider":"openrouter","model":"m"}]}]}"#, None).unwrap();
        let a = built_in.get("a").unwrap();
        assert!(built_in.held(a, &a.route("hermes", None, None).unwrap(), &gb).unwrap_err().contains("openrouter is the harness's own"));

        // What admins are warned about, per plan.
        assert_eq!(t.residency_gap(pro, "gb-lon").as_deref(), Some("the Pro plan has no model route in gb-lon for claude"));
        assert_eq!(t.residency_gap(pro, "de-fra-2").as_deref(), Some("the Pro plan has no model route in de-fra-2 for hermes, claude"));
        assert!(t.residency_gap(open, "gb-lon").unwrap().contains("open routing"));
        let only = Tiers::parse(r#"{"providers":{"uk":{"protocol":"openai-chat","baseUrl":"https://uk.example","keySecret":"K","regions":["gb-lon"]}},"tiers":[{"name":"a","routes":[{"harness":"hermes","provider":"uk"}]}]}"#, None).unwrap();
        assert_eq!(only.residency_gap(only.get("a").unwrap(), "gb-lon"), None);
        assert_eq!(t.unknown_regions(&["gb-lon".into()]), ["provider eu-gpt names data region de-fra-2, which isn't one of MACHINE_REGIONS"]);
        assert!(t.unknown_regions(&["gb-lon".into(), "de-fra-2".into()]).is_empty());

        // Admins see the regions; endpoints without any say nothing new.
        let v = t.admin_view();
        assert_eq!((v["providers"]["uk-claude"]["regions"].clone(), v["providers"]["us-gpt"].get("regions")), (json!(["gb-lon"]), None));
    }

    #[test]
    fn endpoint_regions_are_checked() {
        let bad = |regions: &str| {
            Tiers::parse(&format!(r#"{{"providers":{{"p":{{"protocol":"openai-chat","baseUrl":"https://x.example","keySecret":"K","regions":{regions}}}}},"tiers":[{{"name":"a","routes":"any"}}]}}"#), None)
                .unwrap_err()
        };
        assert!(bad(r#"["GB-LON"]"#).contains("must be a data region id"));
        assert!(bad(r#"[""]"#).contains("must be a data region id"));
        assert!(bad(r#"["gb-lon","gb-lon"]"#).contains("listed twice"));
        assert!(bad(r#""gb-lon""#).contains("invalid type"));
        let many: Vec<String> = (0..17).map(|i| format!("\"r{i}\"")).collect();
        assert!(bad(&format!("[{}]", many.join(","))).contains("at most 16"));
    }

    #[test]
    fn providers_are_reached_over_https_or_loopback_only() {
        let parse = |url: &str| Tiers::parse(&format!(r#"{{"providers":{{"local":{{"protocol":"openai-chat","baseUrl":"{url}","keySecret":"K"}}}},"tiers":[{{"name":"a","routes":"any"}}]}}"#), None);
        for url in [
            "https://api.openai.example/v1",
            "HTTPS://API.OPENAI.EXAMPLE/v1",
            "https://10.0.0.5:8443",
            "http://127.0.0.1:11434/v1",
            "http://127.8.9.10",
            "http://localhost:8080/v1",
            "HTTP://LocalHost:8080",
            "http://[::1]:8000/v1",
            "http://[0:0:0:0:0:0:0:1]",
            // The URL parser reads these as 127.0.0.1.
            "http://2130706433",
            "http://0x7f.0.0.1",
        ] {
            assert!(parse(url).is_ok(), "{url}: {:?}", parse(url).err());
        }
        for url in [
            "http://api.openai.example/v1",
            "HTTP://API.OPENAI.EXAMPLE",
            "http://10.0.0.5:8000",
            "http://192.168.1.20",
            "http://172.16.0.1",
            "http://169.254.169.254",
            "http://0.0.0.0:8080",
            "http://[::]:8080",
            "http://[fd00::1]",
            "http://[::ffff:127.0.0.1]",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://localhost.",
            "http://evil.example#@127.0.0.1",
            "http://evil.example?@localhost",
        ] {
            let e = parse(url).unwrap_err();
            assert!(e.starts_with("provider \"local\": baseUrl") && (e.contains("https://") || e.contains("without a user")), "{url}: {e}");
        }
        // Userinfo never names the host, and is refused whatever the scheme.
        for url in ["http://127.0.0.1@evil.example", "http://localhost:x@evil.example", "https://127.0.0.1@evil.example", "http://user@127.0.0.1"] {
            assert!(parse(url).unwrap_err().contains("without a user, password"), "{url}");
        }
        let e = parse("http://models.internal.example:8000/v1").unwrap_err();
        assert!(e.contains("must use https://") && e.contains("unencrypted") && e.contains("ADR 0097"), "{e}");

        // From a file: the error names the file and the provider, and botd won't start.
        let dir = crate::db::temp_path("tiers-http");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiers.json");
        std::fs::write(&path, r#"{"providers":{"lan":{"protocol":"openai-chat","baseUrl":"http://192.168.1.20:8000/v1","keySecret":"K"}},"tiers":[{"name":"a","routes":"any"}]}"#).unwrap();
        let p = path.display().to_string();
        let e = Tiers::from_env(|k| if k == "TIERS_FILE" { p.clone() } else { String::new() }).unwrap_err();
        assert!(e.starts_with(&format!("TIERS_FILE {p}: provider \"lan\": baseUrl \"http://192.168.1.20:8000/v1\" must use https://")), "{e}");
    }

    #[test]
    fn new_bots_on_a_managed_tier_get_its_harness_not_the_servers() {
        // The plan's first route's harness, whatever DEFAULT_HARNESS is; an open tier keeps it.
        let t = tiers();
        assert_eq!(t.get("pro").unwrap().default_harness.as_deref(), Some("claude"));
        assert_eq!(t.get("pro").unwrap().new_bot_harness("hermes"), "claude");
        assert_eq!(t.get("self-host").unwrap().default_harness, None);
        assert_eq!(t.get("self-host").unwrap().new_bot_harness("codex"), "codex");
        assert_eq!(Tiers::self_host().default_tier().new_bot_harness("claude"), "claude");
        assert!(Tiers::self_host().managed_defaults().is_empty());
        assert_eq!(t.get("pro").unwrap().admin_view()["defaultHarness"], "claude");
        assert_eq!(t.get("self-host").unwrap().admin_view()["defaultHarness"], Value::Null);
        assert!(t.get("pro").unwrap().view().get("defaultHarness").is_none());

        // `defaultHarness` picks another of the tier's harnesses.
        let one = |extra: &str| format!(r#"{{"tiers":[{{"name":"a","routes":[{{"harness":"claude"}},{{"harness":"hermes"}}]{extra}}},{{"name":"b","routes":"any"}}]}}"#);
        let picked = Tiers::parse(&one(r#","defaultHarness":"hermes""#), None).unwrap();
        assert_eq!(picked.get("a").unwrap().new_bot_harness("claude"), "hermes");
        assert_eq!(picked.managed_defaults(), ["hermes"]);
        let bad = |raw: &str| Tiers::parse(raw, None).unwrap_err();
        assert!(bad(&one(r#","defaultHarness":"codex""#)).contains("must be one of the tier's routes' harnesses"));
        assert!(bad(r#"{"tiers":[{"name":"a","routes":"any","defaultHarness":"hermes"}]}"#).contains("open tier get DEFAULT_HARNESS"));

        // The shipped plans: Hermes Agent on every managed one (ADR 0027), the open one as the server says.
        let shipped = Tiers::parse(include_str!("../../deploy/tiers.example.json"), None).unwrap();
        for name in ["starter", "pro", "max"] {
            assert_eq!(shipped.get(name).unwrap().new_bot_harness("claude"), "hermes", "{name}");
        }
        assert_eq!(shipped.get("self-host").unwrap().new_bot_harness("claude"), "claude");
        assert_eq!(shipped.managed_defaults(), ["hermes"]);
    }

    #[test]
    fn startup_says_which_harness_new_bots_get_and_warns_when_it_cant_run() {
        let shipped = Tiers::parse(include_str!("../../deploy/tiers.example.json"), None).unwrap();
        let (line, warnings) = shipped.default_harness_notes("claude", Some(&["claude", "hermes"]), Some(&["hermes"]));
        assert_eq!(line.as_deref(), Some("New Bots: hermes on the starter, pro, max plans; claude on open tiers (DEFAULT_HARNESS) (ADR 0079)."));
        assert!(warnings.is_empty(), "{warnings:?}");
        let (_, warnings) = shipped.default_harness_notes("claude", Some(&["claude"]), Some(&[]));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("isn't installed on this server") && warnings[0].contains("--with-hermes"), "{}", warnings[0]);
        assert!(warnings[1].contains("MACHINE_HARNESSES doesn't install"), "{}", warnings[1]);
        // Not checked where it doesn't apply: no local runs, no enrolled machines.
        assert!(shipped.default_harness_notes("claude", None, None).1.is_empty());
        // Self-host: nothing to say.
        assert_eq!(Tiers::self_host().default_harness_notes("claude", Some(&[]), Some(&[])), (None, Vec::new()));
    }

    #[test]
    fn periods_are_utc_months() {
        assert_eq!(period(0), "1970-01");
        // 2026-11-30T23:59:59.999Z and a millisecond later.
        assert_eq!(period(1_796_083_199_999), "2026-11");
        assert_eq!(period(1_796_083_200_000), "2026-12");
    }
}
