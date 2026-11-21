//! Billing emails (ADR 0091): plain-text emails to the person a plan is for when Stripe
//! changes it, a payment fails, a plan is set to end or ends, a plan change leaves
//! their computer waiting on them or failing to resize, and, unless they turn these
//! off, when they near or reach their plan's model tokens or storage.
//!
//! On only while billing is (`BILLING=on` with the webhook, ADR 0040, 0068) and botd has
//! an SMTP server (ADR 0061), unless `BILLING_EMAILS=off`; otherwise nothing is queued
//! and nothing sends, so self-hosted servers are unchanged. Each email has a key that
//! names what asked for it (a Stripe event, a billing period's limit, a resize), stored
//! with it, so it's queued once however often Stripe redelivers. A subscription event's
//! emails are queued in the same transaction that records the event. A sender sends
//! what's queued, tries a failed send again with a backoff, and audits every send,
//! skip and failure. Emails say what changed and link to the Plan screen. They never
//! carry a Stripe id, a price, a portal link or anything else from the provider.

use crate::audit::{Actor, Outcome, Who};
use crate::db::{Applied, Change, Subscription};
use crate::notify::smtp;
use crate::runner::App;
use crate::tiers::{Tier, Tiers};
use crate::users::Caller;
use crate::{ApiError, AppState, Res, bad};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// `BILLING_EMAILS`: on (the default) while billing and SMTP are, or off.
pub const ENV: &str = "BILLING_EMAILS";
/// Emails one pass sends at most.
const BATCH: u32 = 20;
/// Tries before an email is given up on.
pub const MAX_ATTEMPTS: i64 = 5;
/// How often the sender looks for emails due, besides being woken when one is queued.
const EVERY: Duration = Duration::from_secs(30);
/// The share of a plan's model tokens that sends "running low".
pub const TOKENS_WARN_PERCENT: u64 = 80;
/// How long a Stripe event's emails wait for the webhook to follow the event (ask for
/// a resize) before they're due anyway, if it never says it has.
pub const HOLD_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PlanStarted,
    PlanChanged,
    PaymentFailed,
    PlanEnding,
    PlanEnded,
    /// A plan change's resize waits until the user deletes files (`storage_over`).
    ResizeWaiting,
    ResizeFailed,
    TokensLow,
    TokensUsedUp,
    StorageLow,
    StorageFull,
}

pub const KINDS: [Kind; 11] = [
    Kind::PlanStarted,
    Kind::PlanChanged,
    Kind::PaymentFailed,
    Kind::PlanEnding,
    Kind::PlanEnded,
    Kind::ResizeWaiting,
    Kind::ResizeFailed,
    Kind::TokensLow,
    Kind::TokensUsedUp,
    Kind::StorageLow,
    Kind::StorageFull,
];

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::PlanStarted => "plan_started",
            Kind::PlanChanged => "plan_changed",
            Kind::PaymentFailed => "payment_failed",
            Kind::PlanEnding => "plan_ending",
            Kind::PlanEnded => "plan_ended",
            Kind::ResizeWaiting => "resize_waiting",
            Kind::ResizeFailed => "resize_failed",
            Kind::TokensLow => "tokens_low",
            Kind::TokensUsedUp => "tokens_used_up",
            Kind::StorageLow => "storage_low",
            Kind::StorageFull => "storage_full",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        KINDS.into_iter().find(|k| k.as_str() == s)
    }

    /// About what the person pays for or their computer: always sent. Usage emails
    /// (near or at a limit) can be turned off.
    pub fn essential(self) -> bool {
        !matches!(self, Kind::TokensLow | Kind::TokensUsedUp | Kind::StorageLow | Kind::StorageFull)
    }
}

/// What a template says: plan labels, dates and numbers. Never a provider id.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Facts {
    /// The plan it's about, by its label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// The plan before a change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_plan: Option<String>,
    /// The plan that follows one ending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_plan: Option<String>,
    /// When the plan renews or ends, or the billing period does: Unix ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Tokens, or bytes for storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// `unpaid`: the plan ended because payments failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// A resize's wait, in the words the user sees in the app.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The team whose plan it is (ADR 0093), by name: told to its owners and admins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

/// An email to queue.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEmail {
    /// What asked for it; a second email with the same key isn't queued.
    pub key: String,
    pub user_id: String,
    pub kind: Kind,
    pub facts: Facts,
    /// The Stripe event that asked for it.
    pub event_id: Option<String>,
}

/// A queued email, as stored.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Queued {
    pub id: i64,
    pub key: String,
    pub user_id: String,
    pub kind: String,
    pub facts: Facts,
    pub event_id: Option<String>,
    /// `pending`, `sent`, `skipped` or `failed`.
    pub state: String,
    pub attempts: i64,
    pub next_at: i64,
    pub created_at: i64,
    pub done_at: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rendered {
    pub subject: String,
    pub body: String,
}

/// `14 December 2026`, UTC.
pub fn day(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%-d %B %Y").to_string()).unwrap_or_default()
}

fn percent(used: u64, limit: u64) -> u64 {
    if limit == 0 { 100 } else { (u128::from(used) * 100 / u128::from(limit)).min(999) as u64 }
}

/// An email's subject and body. Pure: `link` is the Plan screen (None without a public
/// address), `computer` what the person's computer is doing about the change.
pub fn render(kind: Kind, f: &Facts, link: Option<&str>, computer: Option<&str>) -> Rendered {
    if let Some(team) = &f.team {
        return render_team(kind, f, team, link);
    }
    let plan = f.plan.as_deref().unwrap_or("your");
    let next = f.next_plan.as_deref().unwrap_or("default");
    let open = |what: &str| match link {
        Some(l) => format!("{what}:\n  {l}\n"),
        None => format!("{what}: open Plan in SuperBot.\n"),
    };
    let tokens = |n: Option<u64>| crate::usage::thousands(n.unwrap_or(0));
    let bytes = |n: Option<u64>| crate::storage::human(n.unwrap_or(0));
    let until = f.until.map(day);
    let mut body = String::new();
    let subject = match kind {
        Kind::PlanStarted => {
            body.push_str(&format!("Thanks for subscribing. You're on the {plan} plan now, and its limits apply from today.\n"));
            if let Some(d) = &until {
                body.push_str(&format!("It renews on {d}.\n"));
            }
            format!("Your {plan} plan has started")
        }
        Kind::PlanChanged => {
            let from = f.from_plan.as_deref().unwrap_or("your old");
            body.push_str(&format!("Your plan changed from {from} to {plan}. The {plan} plan's limits apply now.\n"));
            format!("Your plan changed to {plan}")
        }
        Kind::PaymentFailed => {
            body.push_str(&format!(
                "The payment for your {plan} plan didn't go through. You keep the plan while it's tried again over the next few days; if it keeps failing, the plan ends.\n\n"
            ));
            body.push_str(&open("To update your card, choose Manage billing on your plan"));
            format!("Your payment for the {plan} plan didn't go through")
        }
        Kind::PlanEnding => {
            let d = until.as_deref().unwrap_or("the end of this billing period");
            body.push_str(&format!("Your {plan} plan is set to end on {d}. Nothing changes until then; after that you move to the {next} plan.\n\n"));
            body.push_str(&open("To keep it, choose Manage billing on your plan"));
            format!("Your {plan} plan ends on {d}")
        }
        Kind::PlanEnded => {
            match f.why.as_deref() {
                Some("unpaid") => body.push_str(&format!("Your {plan} plan has ended because its payment didn't go through. ")),
                _ => body.push_str(&format!("Your {plan} plan has ended. ")),
            }
            body.push_str(&format!("You're on the {next} plan now, with its limits.\n"));
            format!("Your {plan} plan has ended")
        }
        Kind::ResizeWaiting => {
            body.push_str(&format!("Your plan changed to {plan}, so your computer is moving to that plan's size. It's waiting first:\n\n"));
            body.push_str(&format!("  {}\n", f.message.as_deref().unwrap_or("It moves once that's safe.")));
            format!("Your computer is waiting to move to the {plan} size")
        }
        Kind::ResizeFailed => {
            body.push_str(&format!(
                "Your plan changed to {plan}, but your computer couldn't be moved to that plan's size. The plan applies anyway, and an admin has been told.\n"
            ));
            format!("Your computer couldn't move to the {plan} size")
        }
        Kind::TokensLow => {
            let p = percent(f.used.unwrap_or(0), f.limit.unwrap_or(0));
            let d = until.as_deref().unwrap_or("the next billing period");
            body.push_str(&format!(
                "You've used {} of the {plan} plan's {} model tokens this billing period ({p}%). Once they're used up, Bots won't start new tasks until {d}.\n\n",
                tokens(f.used),
                tokens(f.limit)
            ));
            body.push_str(&open("For more now, move to a bigger plan"));
            format!("You've used {p}% of this period's model tokens")
        }
        Kind::TokensUsedUp => {
            let d = until.as_deref().unwrap_or("the next billing period");
            body.push_str(&format!(
                "You've used all {} of the {plan} plan's model tokens this billing period, so Bots won't start new tasks until {d}. Tasks already running finish.\n\n",
                tokens(f.limit)
            ));
            body.push_str(&open("To keep going now, move to a bigger plan"));
            "You've used this period's model tokens".to_string()
        }
        Kind::StorageLow => {
            let p = percent(f.used.unwrap_or(0), f.limit.unwrap_or(0));
            body.push_str(&format!(
                "Your files take {} of the {plan} plan's {} ({p}%). At 100%, Bots stop taking new tasks until files are deleted or the plan grows.\n\n",
                bytes(f.used),
                bytes(f.limit)
            ));
            body.push_str(&open("Delete files from the workspace, or see bigger plans"));
            format!("Your storage is {p}% full")
        }
        Kind::StorageFull => {
            body.push_str(&format!(
                "Your files take {} of the {plan} plan's {}, so Bots won't take new tasks. Delete files from the workspace, or move to a bigger plan, then ask again.\n\n",
                bytes(f.used),
                bytes(f.limit)
            ));
            body.push_str(&open("See your plan"));
            "Your storage is full".to_string()
        }
    };
    if let Some(c) = computer {
        body.push_str(&format!("\n{c}\n"));
    }
    if matches!(kind, Kind::PlanStarted | Kind::PlanChanged | Kind::PlanEnded | Kind::ResizeWaiting | Kind::ResizeFailed) {
        body.push('\n');
        body.push_str(&open("See your plan and its use"));
    }
    body.push_str("\n--\n");
    if kind.essential() {
        body.push_str("SuperBot sends this when your plan, its billing or your computer changes.\n");
    } else {
        body.push_str("SuperBot sends this when you near a limit of your plan. To stop these, turn off usage emails on your plan");
        body.push_str(&match link {
            Some(l) => format!(": {l}\n"),
            None => " in SuperBot.\n".into(),
        });
    }
    Rendered { subject: format!("[SuperBot] {}", one_line(&subject)), body }
}

/// A team plan's email (ADR 0093), to the team's owners and admins; `link` is the Team
/// screen. Only plan kinds are ever about a team.
fn render_team(kind: Kind, f: &Facts, team: &str, link: Option<&str>) -> Rendered {
    let plan = f.plan.as_deref().unwrap_or("its");
    let next = f.next_plan.as_deref().unwrap_or("default");
    let open = |what: &str| match link {
        Some(l) => format!("{what}:\n  {l}\n"),
        None => format!("{what}: open Team in SuperBot.\n"),
    };
    let until = f.until.map(day);
    let mut body = String::new();
    let subject = match kind {
        Kind::PlanStarted => {
            body.push_str(&format!("Thanks for subscribing. {team} is on the {plan} plan now: every teammate gets its limits from today, and you pay a seat for each.\n"));
            if let Some(d) = &until {
                body.push_str(&format!("It renews on {d}.\n"));
            }
            format!("{team}'s {plan} plan has started")
        }
        Kind::PlanChanged => {
            let from = f.from_plan.as_deref().unwrap_or("its old");
            body.push_str(&format!("{team}'s plan changed from {from} to {plan}. The {plan} plan's limits apply to every teammate now.\n"));
            format!("{team}'s plan changed to {plan}")
        }
        Kind::PaymentFailed => {
            body.push_str(&format!(
                "The payment for {team}'s {plan} plan didn't go through. The team keeps the plan while it's tried again over the next few days; if it keeps failing, the plan ends for every teammate.\n\n"
            ));
            body.push_str(&open("To update the card, choose Manage billing on the team's plan"));
            format!("{team}'s payment for the {plan} plan didn't go through")
        }
        Kind::PlanEnding => {
            let d = until.as_deref().unwrap_or("the end of this billing period");
            body.push_str(&format!("{team}'s {plan} plan is set to end on {d}. Nothing changes until then; after that teammates move to their own plans, or the {next} plan.\n\n"));
            body.push_str(&open("To keep it, choose Manage billing on the team's plan"));
            format!("{team}'s {plan} plan ends on {d}")
        }
        _ => {
            match f.why.as_deref() {
                Some("unpaid") => body.push_str(&format!("{team}'s {plan} plan has ended because its payment didn't go through. ")),
                _ => body.push_str(&format!("{team}'s {plan} plan has ended. ")),
            }
            body.push_str("Teammates are on their own plans now, or the default plan, with its limits.\n");
            format!("{team}'s {plan} plan has ended")
        }
    };
    if !matches!(kind, Kind::PaymentFailed | Kind::PlanEnding) {
        body.push('\n');
        body.push_str(&open("See the team's plan and seats"));
    }
    body.push_str("\n--\nSuperBot sends this to a team's owners and admins when its plan or billing changes.\n");
    Rendered { subject: format!("[SuperBot] {}", one_line(&subject)), body }
}

/// A header can't hold a line break, and plan labels come from the tiers file.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A Stripe subscription event, as the emails need it.
pub struct SubEvent<'a> {
    pub event_id: &'a str,
    /// The subscription as the event left it.
    pub row: &'a Subscription,
    /// When Stripe will end it, Unix seconds: `cancel_at`, or the period's end with
    /// `cancel_at_period_end`.
    pub cancel_at: Option<i64>,
    /// The event ends it (`deleted`, or an ending status).
    pub ending: bool,
}

/// A subscription event as the plan emails read it, whoever pays: a person or a team.
struct PlanEvent<'a> {
    event_id: &'a str,
    applied: &'a Applied,
    subscription: &'a str,
    /// The tier the subscription pays for as the event left it.
    tier: Option<&'a str>,
    status: &'a str,
    period_end: Option<i64>,
    cancel_at: Option<i64>,
    ending: bool,
    /// Whether a subscription paid for the plan before the event, and for which tier.
    paid_before: bool,
    paid_tier: Option<&'a str>,
    /// This subscription pays for the plan after the event.
    pays_after: bool,
    /// Its status before the event; None: botd hadn't seen it.
    status_before: Option<&'a str>,
    /// The tier of what pays once this one ends.
    next: Option<&'a str>,
}

/// Each email a subscription event asks for: its kind, key and facts. Pure.
fn plan_emails(p: &PlanEvent, tiers: &Tiers) -> Vec<(Kind, String, Facts)> {
    let label = |t: Option<&str>| tiers.of(t).label.clone();
    let per_event = |kind: Kind| format!("stripe:{}:{}", p.event_id, kind.as_str());
    let mut out = Vec::new();
    match p.applied {
        Applied::Duplicate | Applied::Stale | Applied::OtherUser | Applied::CustomerOfAnotherUser => return out,
        Applied::Changed { from, to: Some(to) } => {
            let kind = if p.paid_before { Kind::PlanChanged } else { Kind::PlanStarted };
            let until = (p.tier == Some(to.as_str())).then_some(p.period_end).flatten().map(|s| s * 1000);
            out.push((kind, per_event(kind), Facts { plan: Some(label(Some(to))), from_plan: Some(label(from.as_deref())), until, ..Default::default() }));
        }
        Applied::Changed { from, to: None } => {
            let ended = p.paid_tier.or(from.as_deref());
            let why = (p.status == "unpaid").then(|| "unpaid".to_string());
            out.push((Kind::PlanEnded, per_event(Kind::PlanEnded), Facts { plan: Some(label(ended)), next_plan: Some(label(None)), why, ..Default::default() }));
        }
        // Paying starts for a plan the user already had (an admin gave it): still a start.
        Applied::Unchanged if !p.paid_before && p.pays_after => {
            let until = p.period_end.map(|s| s * 1000);
            out.push((Kind::PlanStarted, per_event(Kind::PlanStarted), Facts { plan: Some(label(p.tier)), until, ..Default::default() }));
        }
        Applied::Superseded | Applied::Unchanged => {}
    }
    // Only for the subscription that sets the plan: one replaced or not paid for yet changes nothing.
    let sets_plan = !matches!(p.applied, Applied::Superseded) && p.tier.is_some();
    if sets_plan && p.status == "past_due" && p.status_before != Some("past_due") {
        out.push((Kind::PaymentFailed, per_event(Kind::PaymentFailed), Facts { plan: Some(label(p.tier)), ..Default::default() }));
    }
    if let Some(at) = p.cancel_at.filter(|_| sets_plan && !p.ending) {
        // Once per subscription and end date, whichever of Stripe's events says it first.
        let key = format!("stripe:{}:plan_ending:{at}", p.subscription);
        out.push((Kind::PlanEnding, key, Facts { plan: Some(label(p.tier)), next_plan: Some(label(p.next)), until: Some(at * 1000), ..Default::default() }));
    }
    out
}

/// The emails a subscription event asks for, given what applying it changed. Pure.
pub fn for_subscription(ev: &SubEvent, c: &Change, tiers: &Tiers) -> Vec<NewEmail> {
    let p = PlanEvent {
        event_id: ev.event_id,
        applied: c.applied,
        subscription: &ev.row.subscription_id,
        tier: ev.row.tier.as_deref(),
        status: &ev.row.status,
        period_end: ev.row.period_end,
        cancel_at: ev.cancel_at,
        ending: ev.ending,
        paid_before: c.paying_before.is_some(),
        paid_tier: c.paying_before.and_then(|s| s.tier.as_deref()),
        pays_after: c.paying_after.is_some_and(|s| s.subscription_id == ev.row.subscription_id),
        status_before: c.before.map(|b| b.status.as_str()),
        next: c.other_paying.and_then(|s| s.tier.as_deref()),
    };
    let event_id = Some(ev.event_id.to_string());
    plan_emails(&p, tiers).into_iter().map(|(kind, key, facts)| NewEmail { key, user_id: ev.row.user_id.clone(), kind, facts, event_id: event_id.clone() }).collect()
}

/// A team's subscription event (ADR 0093), as the emails need it.
pub struct TeamSubEvent<'a> {
    pub event_id: &'a str,
    pub row: &'a crate::db::TeamSubscription,
    pub ending: bool,
    /// The team's name, and who's told: its owners and admins.
    pub team: &'a str,
    pub to: &'a [String],
}

/// The emails a team subscription event asks for: the same as a person's, to each of
/// the team's owners and admins, keyed per person. Pure.
pub fn for_team_subscription(ev: &TeamSubEvent, c: &crate::db::TeamChange, tiers: &Tiers) -> Vec<NewEmail> {
    let p = PlanEvent {
        event_id: ev.event_id,
        applied: c.applied,
        subscription: &ev.row.subscription_id,
        tier: ev.row.tier.as_deref(),
        status: &ev.row.status,
        period_end: ev.row.period_end,
        cancel_at: ev.row.cancel_at,
        ending: ev.ending,
        paid_before: c.paying_before.is_some(),
        paid_tier: c.paying_before.and_then(|s| s.tier.as_deref()),
        pays_after: c.paying_after.is_some_and(|s| s.subscription_id == ev.row.subscription_id),
        status_before: c.before.map(|b| b.status.as_str()),
        next: c.other_paying.and_then(|s| s.tier.as_deref()),
    };
    let mut out = Vec::new();
    for (kind, key, facts) in plan_emails(&p, tiers) {
        let facts = Facts { team: Some(ev.team.to_string()), ..facts };
        for user in ev.to {
            out.push(NewEmail { key: format!("{key}:{user}"), user_id: user.clone(), kind, facts: facts.clone(), event_id: Some(ev.event_id.to_string()) });
        }
    }
    out
}

/// One way to send an email. SMTP (ADR 0061) on a real server; a fake in tests.
pub trait Mailer: Send + Sync {
    fn deliver<'a>(&'a self, mail: &'a smtp::Mail) -> BoxFuture<'a, Result<(), String>>;
}

impl Mailer for smtp::Smtp {
    fn deliver<'a>(&'a self, mail: &'a smtp::Mail) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let password = crate::secrets::global().get(smtp::PASSWORD).ok().flatten();
            let mut results = self.send(password.as_ref().map(|p| p.expose()), std::slice::from_ref(mail)).await?;
            results.pop().unwrap_or_else(|| Err("the mail server didn't answer".into()))
        })
    }
}

pub struct BillingMail {
    mailer: Arc<dyn Mailer>,
    /// `{PUBLIC_URL}/app/plan`. None: emails go without links.
    plan_link: Option<String>,
    /// `{PUBLIC_URL}/app/team`, for a team's plan emails.
    team_link: Option<String>,
    wake: tokio::sync::Notify,
    /// One pass at a time, so no email is sent by two.
    busy: tokio::sync::Mutex<()>,
}

impl BillingMail {
    pub fn new(mailer: Arc<dyn Mailer>, public_url: Option<&str>) -> BillingMail {
        let link = |path: &str| public_url.map(|b| format!("{}{path}", b.trim_end_matches('/')));
        BillingMail {
            mailer,
            plan_link: link(crate::billing::RETURN_PATH),
            team_link: link(crate::team_billing::RETURN_PATH),
            wake: tokio::sync::Notify::new(),
            busy: tokio::sync::Mutex::new(()),
        }
    }
}

/// The start-up line while on. Built apart from the mailer, so nothing from the SMTP
/// settings (which hold the sign-in name) can reach the log.
fn said_on(links: bool) -> String {
    let links = if links { "" } else { "; without links (set PUBLIC_URL)" };
    format!("on, through the notification mail server (SMTP_HOST){links}")
}

/// `BILLING_EMAILS` with billing and SMTP as configured. None: off, with why.
pub fn configured(var: &dyn Fn(&str) -> String, billing: bool, smtp: Option<&smtp::Smtp>, public_url: Option<&str>) -> Result<(Option<BillingMail>, String), String> {
    let raw = var(ENV);
    let wanted = match raw.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => return Err(format!("{ENV} must be on or off, not \"{raw}\"")),
    };
    if wanted == Some(false) {
        return Ok((None, format!("off ({ENV}=off)")));
    }
    if !billing {
        return Ok((None, "off: billing is off".into()));
    }
    let Some(s) = smtp else {
        if wanted == Some(true) {
            return Err(format!("{ENV}=on needs SMTP_HOST and SMTP_FROM, the mail server to send through"));
        }
        return Ok((None, "off (set SMTP_HOST and SMTP_FROM to send them)".into()));
    };
    Ok((Some(BillingMail::new(Arc::new(s.clone()), public_url)), said_on(public_url.is_some())))
}

fn system(user: &str) -> Who {
    Who { actor: Actor::system("billing").on_behalf_of(user), source: Default::default() }
}

/// Queues an email while billing emails are on, and wakes the sender. False when off,
/// or when one with its key was queued before.
pub fn queue(app: &App, e: NewEmail) -> bool {
    let Some(m) = app.billing_mail.get() else { return false };
    let queued = app.db.queue_billing_email(&e);
    if queued {
        m.wake.notify_one();
    }
    queued
}

/// Wakes the sender, for emails queued another way (a Stripe event's transaction).
pub fn wake(app: &App) {
    if let Some(m) = app.billing_mail.get() {
        m.wake.notify_one();
    }
}

/// The emails a Stripe event asks for, when billing emails are on.
pub fn subscription_emails(app: &App, ev: &SubEvent, c: &Change) -> Vec<NewEmail> {
    if app.billing_mail.get().is_none() {
        return Vec::new();
    }
    for_subscription(ev, c, app.tiers())
}

/// The emails a team subscription event asks for, when billing emails are on.
pub fn team_subscription_emails(app: &App, ev: &TeamSubEvent, c: &crate::db::TeamChange) -> Vec<NewEmail> {
    if app.billing_mail.get().is_none() {
        return Vec::new();
    }
    for_team_subscription(ev, c, app.tiers())
}

/// A key part per tier and billing period, so each limit says so once a period.
fn usage_key(user: &str, tier: &Tier, period: &str, kind: Kind) -> String {
    format!("usage:{user}:{}:{period}:{}", tier.name, kind.as_str())
}

/// A run left the owner with `after` of the tier's `monthlyTokens` used this period:
/// says so once they're past `TOKENS_WARN_PERCENT`, and once they reach it. From the
/// saved total, not this run's share, so runs that finish together can't skip one.
pub fn tokens(app: &App, user: &str, tier: &Tier, period: &crate::usage::Period, after: u64) {
    let Some(limit) = tier.limits.monthly_tokens.filter(|l| *l > 0) else { return };
    let warn = u64::try_from(u128::from(limit) * u128::from(TOKENS_WARN_PERCENT) / 100).unwrap_or(limit);
    let kind = if after >= limit {
        Kind::TokensUsedUp
    } else if after >= warn {
        Kind::TokensLow
    } else {
        return;
    };
    let facts = Facts { plan: Some(tier.label.clone()), used: Some(after), limit: Some(limit), until: Some(period.end), ..Default::default() };
    queue(app, NewEmail { key: usage_key(user, tier, &period.key, kind), user_id: user.into(), kind, facts, event_id: None });
}

/// The owner's storage is past the warning or full (ADR 0082): said once a billing period.
pub fn storage(app: &App, user: &str, tier: &Tier, used: u64, limit: u64, full: bool) {
    let kind = if full { Kind::StorageFull } else { Kind::StorageLow };
    let period = app.billing_period(user, crate::db::now());
    let facts = Facts { plan: Some(tier.label.clone()), used: Some(used), limit: Some(limit), ..Default::default() };
    queue(app, NewEmail { key: usage_key(user, tier, &period.key, kind), user_id: user.into(), kind, facts, event_id: None });
}

/// A resize a Stripe plan change asked for waits on the user, or failed (ADR 0085):
/// said once per request and outcome.
pub fn resize(app: &App, m: &crate::db::Machine, kind: Kind, message: Option<&str>) {
    if m.resize_cause.as_deref() != Some("stripe") {
        return;
    }
    let key = format!("resize:{}:{}:{}", m.id, m.resize_requested_at.unwrap_or(0), kind.as_str());
    let facts = Facts { plan: Some(app.tier_of(&m.user_id).label.clone()), message: message.map(String::from), ..Default::default() };
    queue(app, NewEmail { key, user_id: m.user_id.clone(), kind, facts, event_id: m.resize_event.clone() });
}

/// What the person's computer is doing about the plan change an email is for, now: only
/// for the resize that change asked for.
fn computer(app: &App, q: &Queued, kind: Kind) -> Option<String> {
    let plan = match kind {
        Kind::PlanStarted | Kind::PlanChanged => q.facts.plan.as_deref()?,
        Kind::PlanEnded => q.facts.next_plan.as_deref()?,
        _ => return None,
    };
    app.control_plane.get().filter(|cp| cp.enabled())?;
    let m = app.db.user_machine(&q.user_id)?;
    if q.event_id.is_none() || m.resize_event != q.event_id {
        return None;
    }
    let own = crate::machines::resize::own_view(&m);
    Some(match m.resize_state.as_deref()? {
        "pending" => format!("Your computer is moving to the {plan} plan's size. It may restart once while it does; nothing on it is lost."),
        "waiting" => match own["message"].as_str() {
            Some(why) => format!("Your computer moves to the {plan} plan's size once that's safe. {why}"),
            None => format!("Your computer moves to the {plan} plan's size once that's safe."),
        },
        "done" => format!("Your computer is now the {plan} plan's size."),
        "failed" => "Your computer couldn't be moved to the new plan's size yet. An admin has been told.".into(),
        _ => return None,
    })
}

/// After a failed try: in a minute, then 4, 16 and 64.
fn backoff_ms(attempts: i64) -> i64 {
    60_000 * 4i64.pow(attempts.clamp(1, 4) as u32 - 1)
}

/// Sends what's due, oldest first. Returns how many went.
pub async fn send_due(app: &App) -> usize {
    let Some(m) = app.billing_mail.get() else { return 0 };
    let _one = m.busy.lock().await;
    let mut sent = 0;
    for q in app.db.due_billing_emails(crate::db::now(), BATCH) {
        match send_one(app, m, &q).await {
            Ok(went) => sent += usize::from(went),
            // Without saving outcomes, sending more could send them again.
            Err(e) => {
                eprintln!("billing: stopped sending billing emails: couldn't save one's outcome: {e}");
                break;
            }
        }
    }
    sent
}

/// Sends one email, or skips it. Ok(true) when it went; Err when its outcome couldn't
/// be saved. Its try is counted, with the next try's time, before it's sent, so an
/// outcome lost after that waits its backoff rather than sending again at once.
async fn send_one(app: &App, m: &BillingMail, q: &Queued) -> Result<bool, String> {
    let by = system(&q.user_id);
    let mut d = json!({ "kind": q.kind, "key": q.key, "eventId": q.event_id });
    let skip = |reason: &str, mut d: Value| -> Result<bool, String> {
        app.db.billing_email_result(q.id, "skipped", Some(reason))?;
        d["reason"] = json!(reason);
        app.db.record(&by.event("billing.email_skipped").target("user", &q.user_id).details(d));
        Ok(false)
    };
    let Some(kind) = Kind::parse(&q.kind) else { return skip("unknown_kind", d) };
    let Some(u) = app.db.user(&q.user_id) else { return skip("no_user", d) };
    let Some(to) = u.email.clone().filter(|e| smtp::address_ok(e)) else { return skip("no_address", d) };
    if !kind.essential() && !app.db.usage_emails(&u.id) {
        return skip("opted_out", d);
    }
    if !kind.essential() && !u.active() {
        return skip("inactive", d);
    }
    // Tries are counted when claimed, so one whose outcome was never saved (botd stopped
    // mid-send) still counts towards the limit.
    if q.attempts >= MAX_ATTEMPTS {
        app.db.billing_email_result(q.id, "failed", Some("out_of_tries"))?;
        d["error"] = json!("out_of_tries");
        d["retrying"] = json!(false);
        d["attempts"] = json!(q.attempts);
        app.db.record(&by.event("billing.email_failed").target("user", &q.user_id).outcome(Outcome::Failure).details(d));
        return Ok(false);
    }
    let attempts = q.attempts + 1;
    if !app.db.claim_billing_email(q.id, crate::db::now() + backoff_ms(attempts))? {
        return Ok(false);
    }
    let r = match q.facts.team {
        Some(_) => render(kind, &q.facts, m.team_link.as_deref(), None),
        None => render(kind, &q.facts, m.plan_link.as_deref(), computer(app, q, kind).as_deref()),
    };
    let mail = smtp::Mail { to: to.clone(), subject: r.subject, body: r.body };
    d["to"] = json!(to);
    d["attempts"] = json!(attempts);
    match m.mailer.deliver(&mail).await {
        Ok(()) => {
            let saved = app.db.billing_email_result(q.id, "sent", None);
            app.db.record(&by.event("billing.email_sent").target("user", &q.user_id).details(d));
            saved.map(|()| true)
        }
        Err(e) => {
            let e = crate::secrets::redact::text(&e).into_owned();
            let retry = attempts < MAX_ATTEMPTS;
            let saved = app.db.billing_email_result(q.id, if retry { "pending" } else { "failed" }, Some(&e));
            // SMTP errors can name the recipient: the details go to the audit event only.
            eprintln!("billing: a billing email failed; see billing.email_failed in the audit log");
            d["error"] = json!(e);
            d["retrying"] = json!(retry);
            app.db.record(&by.event("billing.email_failed").target("user", &q.user_id).outcome(Outcome::Failure).details(d));
            saved.map(|()| false)
        }
    }
}

/// Sends billing emails as they're queued, and retries, while they're on.
pub fn start(app: Arc<App>) {
    let Some(m) = app.billing_mail.get().cloned() else { return };
    tokio::spawn(async move {
        loop {
            send_due(&app).await;
            tokio::select! {
                _ = m.wake.notified() => {}
                _ = tokio::time::sleep(EVERY) => {}
            }
        }
    });
}

fn person(c: &Caller) -> Res<&crate::db::User> {
    if c.principal == crate::rbac::Principal::Bot {
        return Err(ApiError(StatusCode::FORBIDDEN, "Bots don't get billing emails".into()));
    }
    c.user.as_ref().ok_or_else(|| ApiError(StatusCode::CONFLICT, "Email settings are a signed-in person's. Sign in with a sign-in code or SSO.".into()))
}

/// What `GET /api/billing` and `/api/me/emails` say of a person's billing emails.
pub fn view(app: &App, user_id: &str) -> Value {
    json!({ "on": app.billing_mail.get().is_some(), "usage": app.db.usage_emails(user_id) })
}

/// `GET /api/me/emails`: whether this server sends billing emails, and whether you get
/// usage emails. Emails about your plan and payments always go while they're on.
pub async fn get_mine(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    let u = person(&c)?;
    Ok(Json(mine(&app, &c, &u.id)))
}

/// `view`, and whether the caller may change it (read-only people can't).
fn mine(app: &App, c: &Caller, user_id: &str) -> Value {
    let mut v = view(app, user_id);
    v["canChange"] = json!(crate::rbac::allows(c.principal, crate::rbac::Perm::Write));
    v
}

/// `PUT /api/me/emails {usage: bool}`: turns your usage emails on or off.
pub async fn put_mine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    let u = person(&c)?;
    let Some(on) = v.get("usage").and_then(Value::as_bool) else {
        return Err(bad("Send {\"usage\": true} or {\"usage\": false}"));
    };
    let before = app.db.usage_emails(&u.id);
    if before != on {
        app.db.set_usage_emails(&u.id, on).map_err(|e| {
            eprintln!("botd: couldn't save someone's email settings: {e}");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't save your email settings; see the server log.".into())
        })?;
        app.db.record(&by.event("billing.email_settings_updated").target("user", &u.id).details(json!({ "usage": { "from": before, "to": on } })));
    }
    Ok(Json(mine(&app, &c, &u.id)))
}

#[cfg(test)]
pub mod fake {
    //! A mailer that keeps what it's given, and fails while told to.
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct Mailer {
        pub sent: Mutex<Vec<smtp::Mail>>,
        pub fail: Mutex<Option<String>>,
    }

    impl Mailer {
        pub fn sent(&self) -> Vec<smtp::Mail> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl super::Mailer for Mailer {
        fn deliver<'a>(&'a self, mail: &'a smtp::Mail) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                if let Some(e) = self.fail.lock().unwrap().clone() {
                    return Err(e);
                }
                self.sent.lock().unwrap().push(mail.clone());
                Ok(())
            })
        }
    }

    /// Turns billing emails on for `app` through a fake mailer, linking to `public`.
    pub fn install(app: &App, public: Option<&str>) -> Arc<Mailer> {
        let f = Arc::new(Mailer::default());
        let _ = app.billing_mail.set(Arc::new(BillingMail::new(f.clone(), public)));
        f
    }
}

#[cfg(test)]
mod tests;
