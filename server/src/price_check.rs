//! Published prices checked against Stripe's (ADR 0350). `/pricing`, `/api/plans` and the
//! Plan screen show each tier's `publishedPrices`, written by the operator (ADR 0121);
//! checkout charges the Stripe prices `checkoutPrices` names, else the first of its
//! `stripePrices` (ADR 0346). This reads those Stripe prices with botd's own Stripe
//! client and says where the two differ: a published price no active Stripe price of the
//! tier charges (amount, currency, month or year), an interval the page shows that
//! checkout doesn't sell, or a price checkout sells that is archived, has no fixed
//! amount, isn't billed at the interval it's sold at, or charges what the page doesn't
//! show. A separate team price may differ from the page, which shows people's prices.
//!
//! It runs once at startup, in the background, when checkout is on (a warning per
//! problem; botd starts either way), and on demand at `GET /api/tiers/stripe-check`
//! (billing.manage), which `botctl plans check-stripe` reads and exits non-zero on drift.
//! Without `STRIPE_SECRET_KEY` it calls nothing and says billing is off. It only reads
//! prices (`GET /v1/prices/{id}`): nothing is created or charged. Reports carry price
//! ids, amounts and Stripe's error type and code, never the key.

use crate::stripe::{self, Stripe};
use crate::tiers::{Buyer, Interval, ListPrice, Tier, Tiers};
use crate::{AppState, Auth};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use std::sync::Arc;

/// The limiter key for on-demand checks: shared by every caller, so the route can't be
/// used to flood Stripe (the checkout limiter's 10 a minute).
const LIMIT_KEY: &str = "price-check";

/// How one Stripe price renews, as far as a published price can say it.
#[derive(Clone, Debug, PartialEq)]
pub enum Cadence {
    /// `month` or `year`: licensed, recurring every one of them.
    Every(String),
    /// Anything else, in words: "every 3 months", "one-time", "metered per month".
    Other(String),
}

/// What Stripe says one price charges.
#[derive(Clone, Debug, PartialEq)]
pub struct StripePrice {
    pub id: String,
    pub active: bool,
    pub cadence: Cadence,
    /// Its own currency first, then any `currency_options`, each with its `unit_amount`;
    /// None where the amount isn't fixed per seat (tiered, quantity transformed, or
    /// chosen by the customer): team checkout sends one seat per member as the quantity.
    pub amounts: Vec<(String, Option<u64>)>,
}

impl StripePrice {
    /// From a Stripe Price object, read with `expand[]=currency_options`.
    pub fn parse(v: &Value) -> Result<StripePrice, String> {
        let id = v["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Stripe's answer has no price id")?
            .to_string();
        let currency = v["currency"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| format!("{id}: Stripe's answer has no currency"))?;
        let per_seat = v["transform_quantity"].is_null();
        let fixed = |o: &Value| match o["billing_scheme"].as_str() {
            Some("tiered") => None,
            _ => o["unit_amount"].as_u64().filter(|_| per_seat),
        };
        let mut amounts = vec![(currency.clone(), fixed(v))];
        if let Some(opts) = v["currency_options"].as_object() {
            let mut more: Vec<(String, Option<u64>)> = opts
                .iter()
                .map(|(c, o)| (c.to_ascii_lowercase(), fixed(o)))
                .filter(|(c, _)| *c != currency)
                .collect();
            more.sort();
            amounts.extend(more);
        }
        let r = &v["recurring"];
        let cadence = match (
            v["type"].as_str(),
            r["interval"].as_str(),
            r["interval_count"].as_u64().unwrap_or(1),
            r["usage_type"].as_str(),
        ) {
            (Some("recurring"), Some(i), _, Some("metered")) => {
                Cadence::Other(format!("metered per {i}"))
            }
            (Some("recurring"), Some(i @ ("month" | "year")), 1, _) => Cadence::Every(i.into()),
            (Some("recurring"), Some(i), 1, _) => Cadence::Other(format!("every {i}")),
            (Some("recurring"), Some(i), n, _) => Cadence::Other(format!("every {n} {i}s")),
            (Some("one_time"), _, _, _) => Cadence::Other("one-time".into()),
            (t, _, _, _) => Cadence::Other(t.unwrap_or("unknown").replace('_', " ")),
        };
        Ok(StripePrice {
            id,
            active: v["active"].as_bool().unwrap_or(false),
            cadence,
            amounts,
        })
    }

    fn interval(&self) -> Option<&str> {
        match &self.cadence {
            Cadence::Every(i) => Some(i),
            Cadence::Other(_) => None,
        }
    }

    /// `£29 / month`, `$35 every 3 months`, or `no fixed amount, one-time`.
    fn charges(&self, currency: &str, amount: Option<u64>) -> String {
        match (amount, &self.cadence) {
            (Some(a), Cadence::Every(i)) => crate::plans::display(&ListPrice {
                amount: a,
                currency: currency.into(),
                interval: i.clone(),
            }),
            (Some(a), Cadence::Other(o)) => format!("{} {o}", money(currency, a)),
            (None, c) => format!(
                "no fixed amount in {}, {}",
                currency.to_ascii_uppercase(),
                cadence_words(c)
            ),
        }
    }

    fn own(&self) -> &(String, Option<u64>) {
        &self.amounts[0]
    }
}

fn money(currency: &str, amount: u64) -> String {
    crate::plans::amount(&ListPrice {
        amount,
        currency: currency.into(),
        interval: String::new(),
    })
}

fn cadence_words(c: &Cadence) -> String {
    match c {
        Cadence::Every(i) => format!("per {i}"),
        Cadence::Other(o) => o.clone(),
    }
}

/// Why a price couldn't be read.
#[derive(Clone, Debug, PartialEq)]
pub enum Unread {
    /// Stripe has no such price: drift as much as a wrong amount.
    Missing,
    /// No answer, or a refusal that says nothing about the price (a bad key, a rate limit).
    Failed(String),
}

/// A price checkout sells (ADR 0346): who buys it, at which interval when
/// `checkoutPrices` names one, and whether the page's prices are held to it.
struct Sold<'a> {
    id: &'a str,
    /// Some: `checkoutPrices` sells it at this interval, so Stripe must bill it so.
    /// None: the tier's first price, sold at whatever interval Stripe bills.
    interval: Option<Interval>,
    /// The page's prices are this buyer's: people's, or teams' on a team-only tier.
    /// A separate team price on a tier people buy may cost something else per seat.
    held: bool,
    team: bool,
}

impl Sold<'_> {
    fn who(&self) -> &'static str {
        if self.team {
            "team checkout"
        } else {
            "checkout"
        }
    }
}

/// Every price the tier's checkouts sell, once per interval.
fn sold(t: &Tier) -> Vec<Sold<'_>> {
    let page = if t.team_only() {
        Buyer::Team
    } else {
        Buyer::Person
    };
    let mut out: Vec<Sold> = Vec::new();
    for buyer in [Buyer::Person, Buyer::Team] {
        for i in [Interval::Month, Interval::Year] {
            let Some(id) = t.checkout_price(buyer, i) else {
                continue;
            };
            let interval = t.checkout_prices.is_some().then_some(i);
            match out
                .iter_mut()
                .find(|s| s.id == id && s.interval == interval)
            {
                Some(s) => s.held |= buyer == page,
                None => out.push(Sold {
                    id,
                    interval,
                    held: buyer == page,
                    team: buyer == Buyer::Team,
                }),
            }
        }
    }
    out
}

/// One tier's result: what was read, what is wrong, and what is worth knowing.
#[derive(Debug, Default)]
pub struct TierReport {
    pub name: String,
    pub label: String,
    pub prices: Vec<Value>,
    /// Drift: the page and checkout disagree, or checkout can't sell the price.
    pub problems: Vec<String>,
    /// Prices that couldn't be read for another reason, so the tier isn't fully checked.
    pub unchecked: Vec<String>,
    pub notes: Vec<String>,
}

/// Compares one tier's published prices with what Stripe said of its `stripePrices`.
pub fn compare(t: &Tier, read: &[(String, Result<StripePrice, Unread>)]) -> TierReport {
    let mut r = TierReport {
        name: t.name.clone(),
        label: t.label.clone(),
        ..Default::default()
    };
    let sold = sold(t);
    let is_sold = |id: &str| sold.iter().any(|s| s.id == id);
    let mut got: Vec<&StripePrice> = Vec::new();
    for (id, res) in read {
        let mut line = json!({ "id": id, "soldAtCheckout": is_sold(id), "active": null, "charges": null, "error": null });
        match res {
            Ok(p) => {
                line["active"] = json!(p.active);
                line["charges"] = json!(
                    p.amounts
                        .iter()
                        .map(|(c, a)| p.charges(c, *a))
                        .collect::<Vec<_>>()
                );
                got.push(p);
            }
            Err(Unread::Missing) => {
                line["error"] = json!("no such price");
                r.problems.push(format!("Stripe has no price {id}: it may be in another Stripe account, or a live price id read with a test key"));
            }
            Err(Unread::Failed(e)) => {
                line["error"] = json!(e);
                r.unchecked
                    .push(format!("couldn't read {id} from Stripe ({e})"));
            }
        }
        r.prices.push(line);
    }
    let published = &t.published_prices;
    let shown = |currency: &str, interval: &str| {
        published
            .iter()
            .find(|p| p.currency == currency && p.interval == interval)
    };
    // (currency, interval) pairs a sold price already has a problem for, so the
    // published-price pass doesn't say the same thing twice.
    let mut flagged: Vec<(String, String)> = Vec::new();
    // Intervals the page's buyer can check out at, as Stripe bills them.
    let mut sold_at: Vec<String> = Vec::new();
    for s in &sold {
        let Some(p) = got.iter().find(|p| p.id == s.id) else {
            continue;
        };
        let (who, (currency, amount)) = (s.who(), p.own());
        // A sold price with a problem of its own: the page's prices at the interval it is
        // sold at (every interval, when that's unknown) aren't reported again.
        let mut claim = |at: Option<&str>| {
            if !s.held {
                return;
            }
            for l in published
                .iter()
                .filter(|l| at.is_none_or(|i| l.interval == i))
            {
                sold_at.push(l.interval.clone());
                flagged.push((l.currency.clone(), l.interval.clone()));
            }
        };
        let want = s.interval.map(Interval::as_str);
        let Some(interval) = p.interval() else {
            r.problems.push(format!(
                "{who} sells {}, which charges {}, not per month or year",
                p.id,
                p.charges(currency, *amount)
            ));
            claim(want);
            continue;
        };
        if let Some(want) = want.filter(|w| *w != interval) {
            r.problems.push(format!(
                "checkoutPrices sells {} per {want}, but Stripe bills it per {interval}",
                p.id
            ));
            claim(Some(want));
            continue;
        }
        if !p.active {
            r.problems.push(format!(
                "{who} sells {}, which is archived at Stripe, so that checkout fails",
                p.id
            ));
            claim(Some(interval));
            continue;
        }
        if amount.is_none() {
            r.problems.push(format!("{who} sells {}, which has no fixed amount per person (tiered, quantity transformed, or chosen by the customer)", p.id));
            claim(Some(interval));
            continue;
        }
        if s.held {
            sold_at.push(interval.into());
        }
        if published.is_empty() {
            r.notes.push(format!(
                "no publishedPrices, so the page says \"Contact us\"; {who} charges {} ({})",
                p.charges(currency, *amount),
                p.id
            ));
            continue;
        }
        for (i, (c, a)) in p.amounts.iter().enumerate() {
            match (shown(c, interval), a) {
                (Some(l), Some(a)) if l.amount == *a => {}
                (Some(l), _) if !s.held => r.notes.push(format!("teams pay {} a seat ({}), not the published {}: the page shows people's prices", p.charges(c, *a), p.id, crate::plans::display(l))),
                (Some(l), _) => {
                    r.problems.push(format!("the page shows {}, but {who} charges {} ({})", crate::plans::display(l), p.charges(c, *a), p.id));
                    flagged.push((c.clone(), interval.into()));
                }
                (None, _) if !s.held => {}
                // Its own currency is what checkout charges by default; another of its
                // currency_options the page leaves out is only what some buyers see.
                (None, _) if i == 0 => r.problems.push(format!("{who} charges {} ({}), which the page doesn't show", p.charges(c, *a), p.id)),
                (None, _) => r.notes.push(format!("{who} may also charge {} ({}, one of its currency options), which the page doesn't show", p.charges(c, *a), p.id)),
            }
        }
    }
    let complete = read.iter().all(|(_, res)| res.is_ok());
    let mut unsold: Vec<&str> = Vec::new();
    for l in published {
        if !complete || t.stripe_prices.is_empty() {
            break;
        }
        if !sold_at.contains(&l.interval) {
            if !unsold.contains(&l.interval.as_str()) {
                unsold.push(&l.interval);
                let buyers = if t.team_only() { "teams" } else { "people" };
                match t.checkout_prices.is_some() {
                    true => r.problems.push(format!("the page shows a price per {}, but checkoutPrices sells {buyers} none at that interval", l.interval)),
                    false => r.notes.push(format!("the page shows a price per {}, but checkout sells only the first of stripePrices; checkoutPrices sells more than one interval (ADR 0346)", l.interval)),
                }
            }
            if t.checkout_prices.is_some() {
                continue;
            }
        }
        let at: Vec<(&StripePrice, Option<u64>)> = got
            .iter()
            .filter(|p| p.interval() == Some(l.interval.as_str()))
            .filter_map(|p| {
                p.amounts
                    .iter()
                    .find(|(c, _)| *c == l.currency)
                    .map(|(_, a)| (*p, *a))
            })
            .collect();
        if at.iter().any(|(p, a)| p.active && *a == Some(l.amount))
            || flagged.contains(&(l.currency.clone(), l.interval.clone()))
        {
            continue;
        }
        let page = crate::plans::display(l);
        match at.is_empty() {
            true => r.problems.push(format!(
                "the page shows {page}, but none of the tier's Stripe prices charges {} per {}",
                l.currency.to_ascii_uppercase(),
                l.interval
            )),
            false => {
                let found: Vec<String> = at
                    .iter()
                    .map(|(p, a)| {
                        format!(
                            "{} {}{}",
                            p.id,
                            p.charges(&l.currency, *a),
                            if p.active { "" } else { " (archived)" }
                        )
                    })
                    .collect();
                r.problems.push(format!(
                    "the page shows {page}, but no active Stripe price of the tier charges it: {}",
                    found.join(", ")
                ));
            }
        }
    }
    for p in got.iter().filter(|p| !is_sold(&p.id)) {
        let (currency, amount) = p.own();
        let differs = p
            .interval()
            .and_then(|i| shown(currency, i))
            .is_some_and(|l| Some(l.amount) != *amount);
        match (p.active, differs) {
            (false, _) => r.notes.push(format!("{} is archived at Stripe; checkout doesn't sell it, and subscribers already on it keep the plan", p.id)),
            (true, true) => r.notes.push(format!("{} charges {}, not the published price; checkout doesn't sell it, so only subscribers already on it pay that", p.id, p.charges(currency, *amount))),
            (true, false) => {}
        }
    }
    if t.stripe_prices.is_empty() && !published.is_empty() {
        r.notes
            .push("no stripePrices: not sold through Stripe, so there is nothing to check".into());
    }
    r
}

/// The whole check's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// No Stripe key: nothing was called.
    Off,
    Ok,
    Drift,
    /// No drift found, but some prices couldn't be read.
    Unchecked,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Off => "off",
            Status::Ok => "ok",
            Status::Drift => "drift",
            Status::Unchecked => "unchecked",
        }
    }
}

pub struct Report {
    pub status: Status,
    pub detail: String,
    pub tiers: Vec<TierReport>,
}

impl Report {
    pub fn off(detail: &str) -> Report {
        Report {
            status: Status::Off,
            detail: detail.into(),
            tiers: Vec::new(),
        }
    }

    fn of(tiers: Vec<TierReport>) -> Report {
        let checked: usize = tiers.iter().map(|t| t.prices.len()).sum();
        let problems: usize = tiers.iter().map(|t| t.problems.len()).sum();
        let unread: usize = tiers.iter().map(|t| t.unchecked.len()).sum();
        let (status, detail) = if checked == 0 {
            (Status::Ok, "No tier lists stripePrices: nothing is sold through Stripe, so there is nothing to check.".to_string())
        } else if problems > 0 {
            (
                Status::Drift,
                format!(
                    "{problems} {} between the published prices and Stripe's.",
                    if problems == 1 {
                        "difference"
                    } else {
                        "differences"
                    }
                ),
            )
        } else if unread > 0 {
            (
                Status::Unchecked,
                format!(
                    "{unread} of {checked} Stripe prices couldn't be read, so the check is incomplete. Try again in a minute."
                ),
            )
        } else {
            (
                Status::Ok,
                format!(
                    "Every published price matches Stripe's ({checked} Stripe {} read).",
                    if checked == 1 { "price" } else { "prices" }
                ),
            )
        };
        Report {
            status,
            detail,
            tiers,
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "detail": self.detail,
            "tiers": self.tiers.iter().map(|t| json!({
                "name": t.name,
                "label": t.label,
                "prices": t.prices,
                "problems": t.problems,
                "unchecked": t.unchecked,
                "notes": t.notes,
            })).collect::<Vec<_>>(),
        })
    }

    /// Log lines for startup: one when all is well, else one warning per finding.
    pub fn lines(&self) -> (Option<String>, Vec<String>) {
        let mut warnings = Vec::new();
        for t in &self.tiers {
            for p in t.problems.iter().chain(&t.unchecked) {
                warnings.push(format!("published prices: tier \"{}\": {p}.", t.name));
            }
        }
        match self.status {
            Status::Ok | Status::Off => (
                Some(format!("{} (ADR 0350)", self.detail.trim_end_matches('.'))),
                warnings,
            ),
            Status::Drift | Status::Unchecked => {
                warnings.push(format!("published prices: {} Fix the tiers file or the Stripe prices, then run botctl plans check-stripe (ADR 0350).", self.detail));
                (None, warnings)
            }
        }
    }
}

/// Reads one price, with its other currencies.
async fn read(s: &Stripe, id: &str) -> Result<StripePrice, Unread> {
    match s
        .get(&format!("/v1/prices/{id}?expand%5B%5D=currency_options"))
        .await
    {
        Ok(v) => StripePrice::parse(&v).map_err(Unread::Failed),
        Err(stripe::Error::Refused { status: 404, .. }) => Err(Unread::Missing),
        Err(e) => Err(Unread::Failed(e.to_string())),
    }
}

/// Reads every tier's Stripe prices at once and compares them with its published ones.
pub async fn check(s: &Stripe, tiers: &Tiers) -> Report {
    let ids: Vec<&str> = tiers
        .all()
        .iter()
        .flat_map(|t| t.stripe_prices.iter().map(String::as_str))
        .collect();
    let answers = futures_util::future::join_all(ids.iter().map(|id| read(s, id))).await;
    let mut by_id: std::collections::HashMap<&str, Result<StripePrice, Unread>> =
        ids.into_iter().zip(answers).collect();
    let reports = tiers
        .all()
        .iter()
        .filter(|t| t.published())
        .map(|t| {
            let read: Vec<(String, Result<StripePrice, Unread>)> = t
                .stripe_prices
                .iter()
                .map(|id| {
                    (
                        id.clone(),
                        by_id
                            .remove(id.as_str())
                            .unwrap_or(Err(Unread::Failed("not read".into()))),
                    )
                })
                .collect();
            compare(t, &read)
        })
        .collect();
    Report::of(reports)
}

/// Why there is nothing to check, given billing's state.
fn off_detail(a: &Auth) -> &'static str {
    match a.payments.enabled() {
        false => {
            "Billing is off (BILLING and STRIPE_WEBHOOK_SECRET aren't both set), so botd has no Stripe key and checks nothing."
        }
        true => {
            "Billing is on without STRIPE_SECRET_KEY, so botd can't read Stripe's prices and checks nothing."
        }
    }
}

/// The check, for whoever asks: off without a Stripe key.
pub async fn run(a: &Auth, tiers: &Tiers) -> Report {
    match a.payments.checkout() {
        Some(co) => check(&co.stripe, tiers).await,
        None => Report::off(off_detail(a)),
    }
}

/// At startup, with checkout on and something sold through Stripe: checks in the
/// background and logs what it finds. botd starts either way.
pub fn start(a: Arc<Auth>, app: AppState) {
    if a.payments.checkout().is_none()
        || app.tiers().all().iter().all(|t| t.stripe_prices.is_empty())
    {
        return;
    }
    tokio::spawn(async move {
        let report = run(&a, app.tiers()).await;
        let (line, warnings) = report.lines();
        if let Some(l) = line {
            crate::obs::log::log_info!("Published prices: {l}.");
        }
        for w in warnings {
            crate::obs::log::log_warn!("WARNING: {w}");
        }
    });
}

/// `GET /api/tiers/stripe-check` (billing.manage): the check, now. 200 with its `status`
/// (`off` without a Stripe key), so a caller tells drift from a failed request.
pub async fn handler(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Response {
    if let Some(co) = a.payments.checkout()
        && !crate::billing::may_start(co, LIMIT_KEY)
    {
        return crate::billing::reply(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "error": "Too many price checks at once. Try again in a minute." }),
        );
    }
    crate::billing::reply(StatusCode::OK, run(&a, app.tiers()).await.json())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIERS: &str = r#"{ "default": "pro", "tiers": [
      { "name": "pro", "label": "Pro", "routes": "any",
        "stripePrices": ["price_pro_monthly", "price_pro_yearly", "price_pro_old"],
        "checkoutPrices": { "month": "price_pro_monthly", "year": "price_pro_yearly" },
        "publishedPrices": [{ "amount": 2900, "currency": "gbp", "interval": "month" }, { "amount": 29000, "currency": "gbp", "interval": "year" }] },
      { "name": "max", "label": "Max", "routes": "any", "stripePrices": ["price_max_monthly"] },
      { "name": "self-host", "label": "Self-host", "routes": "any", "publishedPrices": [{ "amount": 4000, "currency": "gbp", "interval": "year" }] }
    ] }"#;

    fn tiers() -> Tiers {
        Tiers::parse(TIERS, None).unwrap()
    }

    fn price(id: &str, amount: u64, currency: &str, interval: &str) -> Value {
        json!({ "id": id, "object": "price", "active": true, "currency": currency, "unit_amount": amount, "billing_scheme": "per_unit", "type": "recurring",
                "recurring": { "interval": interval, "interval_count": 1, "usage_type": "licensed" } })
    }

    fn ok(v: Value) -> Result<StripePrice, Unread> {
        Ok(StripePrice::parse(&v).unwrap())
    }

    fn pro(read: Vec<Result<StripePrice, Unread>>) -> TierReport {
        let t = tiers();
        let tier = t.get("pro").unwrap();
        compare(
            tier,
            &tier
                .stripe_prices
                .iter()
                .cloned()
                .zip(read)
                .collect::<Vec<_>>(),
        )
    }

    fn good() -> Vec<Result<StripePrice, Unread>> {
        vec![
            ok(price("price_pro_monthly", 2900, "gbp", "month")),
            ok(price("price_pro_yearly", 29000, "gbp", "year")),
            ok(price("price_pro_old", 1900, "gbp", "month")),
        ]
    }

    #[test]
    fn stripe_prices_are_read_as_checkout_charges_them() {
        let p = StripePrice::parse(&price("price_1", 2900, "GBP", "month")).unwrap();
        assert_eq!(
            (p.active, p.cadence.clone(), p.amounts.clone()),
            (
                true,
                Cadence::Every("month".into()),
                vec![("gbp".into(), Some(2900))]
            )
        );
        let mut v = price("price_1", 900, "usd", "month");
        v["recurring"]["interval_count"] = json!(3);
        assert_eq!(
            StripePrice::parse(&v).unwrap().cadence,
            Cadence::Other("every 3 months".into())
        );
        v["recurring"]["interval_count"] = json!(1);
        v["recurring"]["interval"] = json!("week");
        assert_eq!(
            StripePrice::parse(&v).unwrap().cadence,
            Cadence::Other("every week".into())
        );
        v["recurring"]["usage_type"] = json!("metered");
        assert_eq!(
            StripePrice::parse(&v).unwrap().cadence,
            Cadence::Other("metered per week".into())
        );
        let one = json!({ "id": "price_2", "active": false, "currency": "eur", "unit_amount": 500, "type": "one_time", "recurring": null });
        let p = StripePrice::parse(&one).unwrap();
        assert_eq!(
            (p.active, p.cadence),
            (false, Cadence::Other("one-time".into()))
        );
        let mut tiered = price("price_3", 0, "gbp", "month");
        tiered["billing_scheme"] = json!("tiered");
        tiered["unit_amount"] = Value::Null;
        assert_eq!(
            StripePrice::parse(&tiered).unwrap().amounts,
            vec![("gbp".into(), None)]
        );
        let mut multi = price("price_4", 2900, "gbp", "month");
        multi["currency_options"] = json!({ "usd": { "unit_amount": 3500 }, "gbp": { "unit_amount": 2900 }, "eur": { "unit_amount": 3300 } });
        assert_eq!(
            StripePrice::parse(&multi).unwrap().amounts,
            vec![
                ("gbp".into(), Some(2900)),
                ("eur".into(), Some(3300)),
                ("usd".into(), Some(3500))
            ]
        );
        multi["transform_quantity"] = json!({ "divide_by": 5, "round": "up" });
        assert_eq!(
            StripePrice::parse(&multi).unwrap().amounts,
            vec![
                ("gbp".into(), None),
                ("eur".into(), None),
                ("usd".into(), None)
            ]
        );
        assert!(StripePrice::parse(&json!({ "object": "price" })).is_err());
    }

    #[test]
    fn matching_prices_are_no_problem() {
        let r = pro(good());
        assert!(
            r.problems.is_empty() && r.unchecked.is_empty(),
            "{:?}",
            r.problems
        );
        assert_eq!(
            r.notes,
            [
                "price_pro_old charges £19 / month, not the published price; checkout doesn't sell it, so only subscribers already on it pay that"
            ]
        );
        assert_eq!(
            r.prices[0],
            json!({ "id": "price_pro_monthly", "soldAtCheckout": true, "active": true, "charges": ["£29 / month"], "error": null })
        );
        assert_eq!(
            (
                r.prices[1]["soldAtCheckout"].clone(),
                r.prices[2]["soldAtCheckout"].clone()
            ),
            (json!(true), json!(false))
        );
    }

    #[test]
    fn a_different_amount_currency_or_interval_is_drift() {
        let mut read = good();
        read[0] = ok(price("price_pro_monthly", 2500, "gbp", "month"));
        let r = pro(read);
        assert_eq!(
            r.problems,
            ["the page shows £29 / month, but checkout charges £25 / month (price_pro_monthly)"],
            "said once"
        );

        let mut read = good();
        read[1] = ok(price("price_pro_yearly", 30000, "gbp", "year"));
        assert_eq!(
            pro(read).problems,
            ["the page shows £290 / year, but checkout charges £300 / year (price_pro_yearly)"]
        );

        let mut read = good();
        read[0] = ok(price("price_pro_monthly", 2900, "usd", "month"));
        let r = pro(read);
        assert_eq!(
            r.problems,
            [
                "checkout charges $29 / month (price_pro_monthly), which the page doesn't show",
                "the page shows £29 / month, but no active Stripe price of the tier charges it: price_pro_old £19 / month"
            ]
        );

        let mut read = good();
        read[1] = ok(price("price_pro_yearly", 29000, "gbp", "month"));
        let r = pro(read);
        assert_eq!(
            r.problems,
            ["checkoutPrices sells price_pro_yearly per year, but Stripe bills it per month"],
            "said once"
        );
    }

    #[test]
    fn a_published_price_only_an_archived_price_charges_is_drift() {
        // Before checkoutPrices: checkout sells only the first price.
        let src = r#"{ "tiers": [{ "name": "pro", "routes": "any", "stripePrices": ["price_m", "price_y"],
            "publishedPrices": [{ "amount": 2900, "currency": "gbp", "interval": "month" }, { "amount": 29000, "currency": "gbp", "interval": "year" }] }] }"#;
        let t = Tiers::parse(src, None).unwrap();
        let mut y = price("price_y", 29000, "gbp", "year");
        y["active"] = json!(false);
        let r = compare(
            t.get("pro").unwrap(),
            &[
                ("price_m".into(), ok(price("price_m", 2900, "gbp", "month"))),
                ("price_y".into(), ok(y)),
            ],
        );
        assert_eq!(
            r.problems,
            [
                "the page shows £290 / year, but no active Stripe price of the tier charges it: price_y £290 / year (archived)"
            ]
        );
        assert_eq!(
            r.notes,
            [
                "the page shows a price per year, but checkout sells only the first of stripePrices; checkoutPrices sells more than one interval (ADR 0346)",
                "price_y is archived at Stripe; checkout doesn't sell it, and subscribers already on it keep the plan"
            ]
        );
    }

    #[test]
    fn checkout_prices_are_held_to_the_page_for_the_buyers_it_shows() {
        let src = r#"{ "tiers": [
          { "name": "pro", "routes": "any", "stripePrices": ["price_pro_m", "price_pro_team_m"],
            "checkoutPrices": { "month": "price_pro_m", "teamMonth": "price_pro_team_m" },
            "publishedPrices": [{ "amount": 2900, "currency": "gbp", "interval": "month" }, { "amount": 29000, "currency": "gbp", "interval": "year" }] },
          { "name": "business", "routes": "any", "stripePrices": ["price_biz_team_m"], "checkoutPrices": { "teamMonth": "price_biz_team_m" },
            "publishedPrices": [{ "amount": 4900, "currency": "gbp", "interval": "month" }] }
        ] }"#;
        let t = Tiers::parse(src, None).unwrap();
        let pro = t.get("pro").unwrap();
        let r = compare(
            pro,
            &[
                (
                    "price_pro_m".into(),
                    ok(price("price_pro_m", 2900, "gbp", "month")),
                ),
                (
                    "price_pro_team_m".into(),
                    ok(price("price_pro_team_m", 2500, "gbp", "month")),
                ),
            ],
        );
        assert_eq!(
            r.problems,
            [
                "the page shows a price per year, but checkoutPrices sells people none at that interval"
            ]
        );
        assert_eq!(
            r.notes,
            [
                "teams pay £25 / month a seat (price_pro_team_m), not the published £29 / month: the page shows people's prices"
            ]
        );
        assert_eq!(
            (
                r.prices[0]["soldAtCheckout"].clone(),
                r.prices[1]["soldAtCheckout"].clone()
            ),
            (json!(true), json!(true))
        );

        // A team-only plan's page price is the team's seat price.
        let biz = t.get("business").unwrap();
        let r = compare(
            biz,
            &[(
                "price_biz_team_m".into(),
                ok(price("price_biz_team_m", 4500, "gbp", "month")),
            )],
        );
        assert_eq!(
            r.problems,
            [
                "the page shows £49 / month, but team checkout charges £45 / month (price_biz_team_m)"
            ]
        );
        let r = compare(
            biz,
            &[(
                "price_biz_team_m".into(),
                ok(price("price_biz_team_m", 4900, "gbp", "month")),
            )],
        );
        assert!(
            r.problems.is_empty() && r.notes.is_empty(),
            "{:?} {:?}",
            r.problems,
            r.notes
        );

        // Team checkout's quantity is the member count, so a transformed quantity
        // (five members billed as one unit) doesn't charge the page's seat price.
        let mut packed = price("price_biz_team_m", 4900, "gbp", "month");
        packed["transform_quantity"] = json!({ "divide_by": 5, "round": "up" });
        let r = compare(biz, &[("price_biz_team_m".into(), ok(packed))]);
        assert_eq!(
            r.problems,
            [
                "team checkout sells price_biz_team_m, which has no fixed amount per person (tiered, quantity transformed, or chosen by the customer)"
            ]
        );
    }

    #[test]
    fn a_sold_price_checkout_cant_sell_is_drift() {
        let mut read = good();
        let mut m = price("price_pro_monthly", 2900, "gbp", "month");
        m["active"] = json!(false);
        read[0] = ok(m);
        let r = pro(read);
        assert_eq!(
            r.problems,
            [
                "checkout sells price_pro_monthly, which is archived at Stripe, so that checkout fails"
            ],
            "said once"
        );

        let mut read = good();
        read[0] = ok(
            json!({ "id": "price_pro_monthly", "active": true, "currency": "gbp", "unit_amount": 2900, "type": "one_time" }),
        );
        let r = pro(read);
        assert_eq!(
            r.problems,
            ["checkout sells price_pro_monthly, which charges £29 one-time, not per month or year"],
            "said once"
        );

        let mut read = good();
        let mut tiered = price("price_pro_monthly", 0, "gbp", "month");
        tiered["billing_scheme"] = json!("tiered");
        read[0] = ok(tiered);
        assert_eq!(
            pro(read).problems,
            [
                "checkout sells price_pro_monthly, which has no fixed amount per person (tiered, quantity transformed, or chosen by the customer)"
            ]
        );
    }

    #[test]
    fn currency_options_count_where_the_page_shows_them() {
        let src = r#"{ "tiers": [{ "name": "pro", "routes": "any", "stripePrices": ["price_pro"],
            "publishedPrices": [{ "amount": 2900, "currency": "gbp", "interval": "month" }, { "amount": 3500, "currency": "usd", "interval": "month" }] }] }"#;
        let t = Tiers::parse(src, None).unwrap();
        let tier = t.get("pro").unwrap();
        let mut p = price("price_pro", 2900, "gbp", "month");
        p["currency_options"] =
            json!({ "usd": { "unit_amount": 3500 }, "eur": { "unit_amount": 3300 } });
        let r = compare(tier, &[("price_pro".into(), ok(p.clone()))]);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert_eq!(
            r.notes,
            [
                "checkout may also charge €33 / month (price_pro, one of its currency options), which the page doesn't show"
            ]
        );
        p["currency_options"]["usd"]["unit_amount"] = json!(3600);
        assert_eq!(
            compare(tier, &[("price_pro".into(), ok(p))]).problems,
            ["the page shows $35 / month, but checkout charges $36 / month (price_pro)"]
        );
    }

    #[test]
    fn missing_prices_are_drift_and_unreadable_ones_leave_it_unchecked() {
        let mut read = good();
        read[1] = Err(Unread::Missing);
        let r = pro(read);
        assert_eq!(
            r.problems,
            [
                "Stripe has no price price_pro_yearly: it may be in another Stripe account, or a live price id read with a test key"
            ]
        );
        assert_eq!(r.prices[1]["error"], "no such price");

        let mut read = good();
        read[1] = Err(Unread::Failed("HTTP 401 invalid_request_error".into()));
        let r = pro(read);
        assert!(
            r.problems.is_empty(),
            "the yearly price might be the unreadable one: {:?}",
            r.problems
        );
        assert_eq!(
            r.unchecked,
            ["couldn't read price_pro_yearly from Stripe (HTTP 401 invalid_request_error)"]
        );
    }

    #[test]
    fn tiers_without_published_prices_or_stripe_prices_say_so() {
        let t = tiers();
        let max = t.get("max").unwrap();
        let r = compare(
            max,
            &[(
                "price_max_monthly".into(),
                ok(price("price_max_monthly", 9900, "eur", "month")),
            )],
        );
        assert!(r.problems.is_empty());
        assert_eq!(
            r.notes,
            [
                "no publishedPrices, so the page says \"Contact us\"; checkout charges €99 / month (price_max_monthly)"
            ]
        );
        let r = compare(t.get("self-host").unwrap(), &[]);
        assert!(r.problems.is_empty() && r.prices.is_empty());
        assert_eq!(
            r.notes,
            ["no stripePrices: not sold through Stripe, so there is nothing to check"]
        );
    }

    #[test]
    fn the_report_says_drift_before_unchecked_and_logs_without_secrets() {
        let drift = TierReport {
            name: "pro".into(),
            prices: vec![json!({})],
            problems: vec!["x".into()],
            unchecked: vec!["y".into()],
            ..Default::default()
        };
        let r = Report::of(vec![drift]);
        assert_eq!(
            (r.status, r.detail.as_str()),
            (
                Status::Drift,
                "1 difference between the published prices and Stripe's."
            )
        );
        let (line, warnings) = r.lines();
        assert!(line.is_none());
        assert_eq!(
            warnings[..2],
            [
                "published prices: tier \"pro\": x.",
                "published prices: tier \"pro\": y."
            ]
        );
        assert!(
            warnings[2].contains("botctl plans check-stripe"),
            "{warnings:?}"
        );

        let unread = TierReport {
            name: "pro".into(),
            prices: vec![json!({}), json!({})],
            unchecked: vec!["y".into()],
            ..Default::default()
        };
        assert_eq!(Report::of(vec![unread]).status, Status::Unchecked);
        let fine = Report::of(vec![TierReport {
            prices: vec![json!({})],
            ..Default::default()
        }]);
        assert_eq!(
            (fine.status, fine.lines().0.unwrap()),
            (
                Status::Ok,
                "Every published price matches Stripe's (1 Stripe price read) (ADR 0350)"
                    .to_string()
            )
        );
        assert_eq!(
            Report::of(vec![]).status,
            Status::Ok,
            "nothing sold through Stripe"
        );
        assert_eq!(
            Report::off("Billing is off.").json(),
            json!({ "status": "off", "detail": "Billing is off.", "tiers": [] })
        );
    }
}
