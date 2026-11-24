//! SQLite storage: Bots, messages, routines, harness policy, approvals, and the
//! append-only audit log. One connection behind a mutex; every call is short.

use crate::acl::{Grant, Visibility};
use crate::audit;
use crate::machines::State as MachineState;
use crate::policy::{Action, Mode, Override, Policy, Rule};
use crate::rbac::Role;
use crate::secrets::{redact, sealed};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

mod chats;
pub use chats::{ChatMove, ChatStore, Held, drop_from_copy, held_in_copy};
#[cfg(test)]
pub(crate) use chats::Scratch;

#[derive(Clone, Serialize)]
pub struct Bot {
    pub id: String,
    pub name: String,
    pub color: String,
    pub shape: String,
    pub harness: String,
    pub model: Option<String>,
    pub effort: Option<String>,
    #[serde(skip)]
    pub session_id: Option<String>,
    pub primary: bool,
    pub hidden: bool,
    pub unread: bool,
    pub created_at: i64,
    /// The user who owns it (ADR 0017). Bots from before ACLs belong to `operator`.
    pub owner_id: String,
    pub visibility: Visibility,
    /// Suggested prompts in its details. None: the client's defaults; empty: none.
    pub prompts: Option<Vec<String>>,
    /// The owner's service account that made it and keeps it (ADR 0222), if any.
    #[serde(skip)]
    pub service_account_id: Option<String>,
}

/// Why a service account's new Bot wasn't made (ADR 0222).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptBotRefusal {
    /// Its owner's plan has no Bot left.
    PlanLimit,
    /// It keeps as many Bots as a service account may.
    AccountLimit,
    /// It was deleted, or given another owner, meanwhile.
    Account,
}

/// Why an existing Bot wasn't handed to a service account to keep (ADR 0229).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepRefusal {
    /// The Bot is gone, or no longer the owner's.
    Bot,
    /// The account was deleted, or isn't a service account of the Bot's owner.
    Account,
    /// The account keeps as many Bots as one may.
    Limit,
}

/// What handing a Bot to a service account changed (ADR 0229).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handed {
    /// The account that kept it before, which may be the same one.
    pub from: Option<String>,
    /// The account's grant on the Bot, taken away: keeping it gives more.
    pub grant: Option<Grant>,
}

/// One user's grant on one Bot (ADR 0017).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotGrant {
    pub bot_id: String,
    pub user_id: String,
    pub level: Grant,
    pub created_at: i64,
    pub created_by: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Message {
    pub id: i64,
    #[serde(rename = "botId")]
    pub bot_id: String,
    /// "user", "bot", or "routine"
    pub role: String,
    pub text: String,
    /// { title, options, picked? }
    pub question: Option<Value>,
    pub error: bool,
    /// "queued" | "running" | "done" for user and routine messages
    #[serde(skip)]
    pub status: Option<String>,
    /// For "peer" and "reply" messages: the other Bot's id.
    #[serde(rename = "fromBot")]
    pub from_bot: Option<String>,
    #[serde(rename = "at")]
    pub created_at: i64,
    /// Who asked for the run this message starts, for the audit log (ADR 0019).
    #[serde(skip)]
    pub requested_by: Option<audit::Who>,
}

/// A Bot whose chat is kept out of retention (ADR 0098).
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionHold {
    pub bot_id: String,
    pub reason: String,
    /// The admin's user id.
    pub held_by: Option<String>,
    pub held_at: i64,
}

/// What erasing a user removed or changed (ADR 0102), counted for its audit event.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Erased {
    pub sessions: usize,
    pub login_codes: usize,
    pub identities: usize,
    pub mfa: bool,
    pub recovery_codes: usize,
    pub scim: bool,
    pub grants: usize,
    pub team_invites: usize,
    pub signups: usize,
    pub billing_emails: usize,
    /// Routines they wrote in others' Bots.
    pub routines: usize,
    /// Messages they, or their Bots, wrote in others' chats.
    pub messages: usize,
    /// Approvals they decided, now by the pseudonym and without their note.
    pub approvals: usize,
    /// Their destroyed machines' last reports of what their homes held (ADR 0105).
    pub disk_reports: usize,
    pub audit_events: usize,
}

#[derive(Debug, PartialEq)]
pub enum EraseError {
    /// No such user, or already erased.
    Gone,
    /// These Bots' chats are held (ADR 0098).
    Held(Vec<String>),
    Db(String),
}

/// What an erased person's messages and approvals say instead.
pub const ERASED_TEXT: &str = "[erased]";
/// An erased user's name on their tombstone.
pub const ERASED_NAME: &str = "Erased user";

/// Whether the message in `m` was sent by user `?1`, or by a run for them or carrying
/// their data (ADR 0139). The same people as `SENT_BY_ANY`, so a hold keeps what an
/// erasure would rewrite.
const SENT_BY: &str = "(CASE WHEN json_valid(m.requested_by) THEN json_extract(m.requested_by, '$.actor.id') = ?1 OR json_extract(m.requested_by, '$.actor.asker') = ?1 OR EXISTS (SELECT 1 FROM json_each(m.requested_by, '$.actor.carries') WHERE value = ?1) END)";
const SENT_BY_ANY: &str = "(CASE WHEN json_valid(requested_by) THEN json_extract(requested_by, '$.actor.id') = ?1 OR json_extract(requested_by, '$.actor.asker') = ?1 OR EXISTS (SELECT 1 FROM json_each(requested_by, '$.actor.carries') WHERE value = ?1) END)";

/// How an erasure rewrites a string about the erased person: their id becomes the
/// pseudonym wherever it appears, as does an email of theirs (any case); a string that is
/// exactly one of their names or subjects (any case) becomes the pseudonym.
pub(crate) struct Scrub {
    id: String,
    pseudonym: String,
    /// Lowercase.
    emails: Vec<String>,
    /// Lowercase.
    exact: Vec<String>,
}

impl Scrub {
    pub(crate) fn new(id: &str, pseudonym: &str, emails: Vec<String>, exact: Vec<String>) -> Scrub {
        let clean = |v: Vec<String>, min: usize| {
            let mut v: Vec<String> = v.into_iter().map(|s| s.trim().to_lowercase()).filter(|s| s.chars().count() >= min).collect();
            v.sort();
            v.dedup();
            v
        };
        Scrub { id: id.into(), pseudonym: pseudonym.into(), emails: clean(emails, 3), exact: clean(exact, 2) }
    }

    pub(crate) fn text(&self, t: &str) -> Option<String> {
        let lower = t.trim().to_lowercase();
        if self.exact.contains(&lower) || self.emails.contains(&lower) {
            return Some(self.pseudonym.clone());
        }
        let mut out = t.replace(&self.id, &self.pseudonym);
        for e in &self.emails {
            out = replace_ci(&out, e, &self.pseudonym);
        }
        (out != t).then_some(out)
    }

    /// Whether anything in `v` changed.
    pub(crate) fn value(&self, v: &mut Value) -> bool {
        match v {
            Value::String(s) => match self.text(s) {
                Some(n) => {
                    *s = n;
                    true
                }
                None => false,
            },
            Value::Array(a) => a.iter_mut().fold(false, |c, x| self.value(x) | c),
            Value::Object(o) => o.values_mut().fold(false, |c, x| self.value(x) | c),
            _ => false,
        }
    }
}

/// An employee number in a change to the erased person's record, whatever its length:
/// `Scrub` skips values too short to match safely, and one character is a valid number.
fn pseudonymise_employee_number(d: &mut Value, pseudonym: &str) -> bool {
    let Some(c) = d.pointer_mut("/changes/employeeNumber").and_then(Value::as_object_mut) else { return false };
    let mut changed = false;
    for v in c.values_mut().filter(|v| v.as_str().is_some_and(|v| v != pseudonym)) {
        *v = Value::String(pseudonym.into());
        changed = true;
    }
    changed
}

/// `hay` with each `needle` (lowercase) replaced, in any case. Outside ASCII, where case
/// changes lengths, a string that contains it is replaced whole.
fn replace_ci(hay: &str, needle: &str, with: &str) -> String {
    if !(hay.is_ascii() && needle.is_ascii()) {
        return if hay.to_lowercase().contains(needle) { with.into() } else { hay.into() };
    }
    let low = hay.to_ascii_lowercase();
    let (mut out, mut i) = (String::new(), 0);
    while let Some(j) = low[i..].find(needle) {
        out.push_str(&hay[i..i + j]);
        out.push_str(with);
        i += j + needle.len();
    }
    out.push_str(&hay[i..]);
    out
}

fn retention_hold_row(r: &rusqlite::Row) -> rusqlite::Result<RetentionHold> {
    Ok(RetentionHold { bot_id: r.get("bot_id")?, reason: r.get("reason")?, held_by: r.get("held_by")?, held_at: r.get("held_at")? })
}

#[derive(Clone, Serialize)]
pub struct Routine {
    pub id: String,
    pub bot_id: String,
    pub name: String,
    pub cron: String,
    pub instruction: String,
    pub enabled: bool,
    pub last_run_at: Option<i64>,
    pub created_at: i64,
    /// Who last wrote its instruction (ADR 0046); its runs are for them. None: from
    /// before, so its Bot's owner.
    pub author_id: Option<String>,
    /// Set when botd turned it off because someone it runs for was disabled (ADR 0047):
    /// `owner_disabled` or `author_disabled`. Cleared when it's resumed or turned on by hand.
    pub paused_reason: Option<String>,
    /// The disabled user it was paused for; resuming for them turns it back on.
    pub paused_for: Option<String>,
    pub paused_at: Option<i64>,
}

#[derive(Default)]
pub struct BotPatch {
    pub name: Option<String>,
    pub color: Option<String>,
    pub shape: Option<String>,
    pub harness: Option<String>,
    pub model: Option<Option<String>>,
    pub effort: Option<Option<String>>,
    pub session_id: Option<Option<String>>,
    pub hidden: Option<bool>,
    pub unread: Option<bool>,
    pub prompts: Option<Option<Vec<String>>>,
}

/// How many active users may hold a seat now (ADR 0038). None: no limit.
pub type SeatCap = Box<dyn Fn() -> Option<u32> + Send + Sync>;

/// The connection, and the seat limit every way of adding or re-enabling a user checks
/// under the same lock. Unset (as in most tests): no limit.
/// `.2`: TEAMS=on (ADR 0087), so people in no team share Bots with nobody.
/// `.5`: the regions' chat stores attached at startup (ADR 0215).
pub struct Db(Mutex<Connection>, std::sync::OnceLock<SeatCap>, std::sync::atomic::AtomicBool, crate::obs::Metrics, crate::obs::trace::Tracer, std::sync::OnceLock<chats::ChatStores>);

pub fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn bot_row(r: &Row) -> rusqlite::Result<Bot> {
    Ok(Bot {
        id: r.get("id")?,
        name: r.get("name")?,
        color: r.get("color")?,
        shape: r.get("shape")?,
        harness: r.get("harness")?,
        model: r.get("model")?,
        effort: r.get("effort")?,
        session_id: r.get("session_id")?,
        primary: r.get("primary_bot")?,
        hidden: r.get("hidden")?,
        unread: r.get("unread")?,
        created_at: r.get("created_at")?,
        owner_id: r.get("owner_id")?,
        // The column's CHECK allows only the two; anything else would fail closed.
        visibility: Visibility::parse(&r.get::<_, String>("visibility")?).unwrap_or(Visibility::Private),
        prompts: r.get::<_, Option<String>>("prompts")?.and_then(|j| serde_json::from_str(&j).ok()),
        service_account_id: r.get("service_account_id")?,
    })
}

fn grant_row(r: &Row) -> rusqlite::Result<BotGrant> {
    Ok(BotGrant {
        bot_id: r.get("bot_id")?,
        user_id: r.get("user_id")?,
        level: Grant::parse(&r.get::<_, String>("level")?).unwrap_or(Grant::Viewer),
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
    })
}

fn message_row(r: &Row) -> rusqlite::Result<Message> {
    let q: Option<String> = r.get("question")?;
    Ok(Message {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        role: r.get("role")?,
        text: r.get("text")?,
        question: q.and_then(|s| serde_json::from_str(&s).ok()),
        error: r.get("error")?,
        status: r.get("status")?,
        from_bot: r.get("from_bot")?,
        created_at: r.get("created_at")?,
        requested_by: r.get::<_, Option<String>>("requested_by")?.and_then(|s| serde_json::from_str(&s).ok()),
    })
}

/// One model's tokens for one run, to record (ADR 0050). `reported` false: the harness
/// didn't say, so the counts are 0 and unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenRow {
    pub user_id: String,
    pub bot_id: String,
    pub run_id: String,
    pub message_id: Option<i64>,
    pub harness: String,
    pub model: Option<String>,
    pub reported: bool,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub at: i64,
    /// Queue it for Stripe's meter, for this customer: whoever pays for the owner's plan
    /// when the run ends (their team's, ADR 0093, or their own).
    pub meter: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenTotals {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub runs: u64,
    /// Runs whose harness didn't report tokens.
    pub unreported_runs: u64,
}

impl TokenTotals {
    pub fn total(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenSummary {
    pub all: TokenTotals,
    pub by_model: Vec<(Option<String>, TokenTotals)>,
    pub by_bot: Vec<(String, TokenTotals)>,
}

/// A token row waiting for Stripe's meter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeterRow {
    pub id: i64,
    pub user_id: String,
    pub run_id: String,
    pub tokens: u64,
    pub at: i64,
    pub attempts: i64,
    /// Who it's billed to; None for rows from before ADR 0093, sent to the user's own.
    pub customer: Option<String>,
}

/// A subscription at a payment provider (ADR 0040). Every one a user has had is kept,
/// ended ones too, so a late event for one is judged against its own history.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub user_id: String,
    pub provider: String,
    pub customer_id: Option<String>,
    pub subscription_id: String,
    pub status: String,
    pub price_id: Option<String>,
    /// The tier it pays for; None when it pays for none (ended, or an unknown price).
    pub tier: Option<String>,
    /// Start of the paid period, Unix seconds (ADR 0050). None: from before it was kept.
    pub period_start: Option<i64>,
    /// End of the paid period, Unix seconds.
    pub period_end: Option<i64>,
    /// When the provider created the subscription, Unix seconds. Of a user's paying
    /// subscriptions, the one started last sets their tier.
    pub started: i64,
    /// When the provider made the last event applied, Unix seconds.
    pub event_created: i64,
    #[serde(skip)]
    pub updated_at: i64,
}

fn subscription_row(r: &Row) -> rusqlite::Result<Subscription> {
    Ok(Subscription {
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        customer_id: r.get("customer_id")?,
        subscription_id: r.get("subscription_id")?,
        status: r.get("status")?,
        price_id: r.get("price_id")?,
        tier: r.get("tier")?,
        period_start: r.get("period_start")?,
        period_end: r.get("period_end")?,
        started: r.get("started")?,
        event_created: r.get("event_created")?,
        updated_at: r.get("updated_at")?,
    })
}

/// The user's paying subscription started last: the one that sets their tier.
fn paying_subscription(c: &Connection, user_id: &str) -> rusqlite::Result<Option<Subscription>> {
    c.query_row(
        "SELECT * FROM subscriptions WHERE user_id = ? AND tier IS NOT NULL ORDER BY started DESC, subscription_id DESC LIMIT 1",
        [user_id],
        subscription_row,
    )
    .optional()
}

/// What a payment-provider event did (`Db::apply_subscription`).
#[derive(Debug, PartialEq)]
pub enum Applied {
    Duplicate,
    Stale,
    /// Recorded, but another subscription of the user's sets their tier.
    Superseded,
    /// The subscription belongs to another user.
    OtherUser,
    /// Its customer is linked to another user (ADR 0042).
    CustomerOfAnotherUser,
    Unchanged,
    Changed { from: Option<String>, to: Option<String> },
}

/// What an event applied by `Db::apply_subscription` changed, for the billing emails it
/// queues in the same transaction (ADR 0091).
pub struct Change<'a> {
    pub applied: &'a Applied,
    /// This subscription as it was before the event. None: botd hadn't seen it.
    pub before: Option<&'a Subscription>,
    /// The user's paying subscription before the event, when the event was applied.
    pub paying_before: Option<&'a Subscription>,
    /// And after it.
    pub paying_after: Option<&'a Subscription>,
    /// The user's newest other subscription that sets a plan: what pays once this one ends.
    pub other_paying: Option<&'a Subscription>,
}

/// Whom a deleted payment-provider customer was linked to.
#[derive(Debug, Default, PartialEq)]
pub struct Unlinked {
    pub user: Option<String>,
    pub team: Option<String>,
}

/// A team's subscription (ADR 0093), kept like a user's: its latest state, the seats
/// the provider bills (`quantity`) and where bringing them in line with the team stands.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamSubscription {
    pub team_id: String,
    pub provider: String,
    pub customer_id: Option<String>,
    pub subscription_id: String,
    pub status: String,
    pub price_id: Option<String>,
    /// The tier it pays for while it pays; None otherwise.
    pub tier: Option<String>,
    /// The subscription item whose quantity is the seats.
    pub item_id: Option<String>,
    pub quantity: Option<i64>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    /// When the provider will end it, Unix seconds.
    pub cancel_at: Option<i64>,
    pub started: i64,
    pub event_created: i64,
    pub updated_at: i64,
    /// Who opened the checkout that made it, from its metadata.
    pub paid_by: Option<String>,
    /// Seat updates sent to the provider, ever: part of each one's idempotency key.
    pub seat_tries: i64,
    /// Seat updates that failed in a row, for the backoff.
    pub seat_failures: i64,
    pub seat_next_at: i64,
    pub seat_error: Option<String>,
}

fn team_subscription_row(r: &Row) -> rusqlite::Result<TeamSubscription> {
    Ok(TeamSubscription {
        team_id: r.get("team_id")?,
        provider: r.get("provider")?,
        customer_id: r.get("customer_id")?,
        subscription_id: r.get("subscription_id")?,
        status: r.get("status")?,
        price_id: r.get("price_id")?,
        tier: r.get("tier")?,
        item_id: r.get("item_id")?,
        quantity: r.get("quantity")?,
        period_start: r.get("period_start")?,
        period_end: r.get("period_end")?,
        cancel_at: r.get("cancel_at")?,
        started: r.get("started")?,
        event_created: r.get("event_created")?,
        updated_at: r.get("updated_at")?,
        paid_by: r.get("paid_by")?,
        seat_tries: r.get("seat_tries")?,
        seat_failures: r.get("seat_failures")?,
        seat_next_at: r.get("seat_next_at")?,
        seat_error: r.get("seat_error")?,
    })
}

/// The team's paying subscription started last: the one that sets its plan.
fn team_paying_in(c: &Connection, team_id: &str) -> rusqlite::Result<Option<TeamSubscription>> {
    c.query_row(
        "SELECT * FROM team_subscriptions WHERE team_id = ? AND tier IS NOT NULL ORDER BY started DESC, subscription_id DESC LIMIT 1",
        [team_id],
        team_subscription_row,
    )
    .optional()
}

/// What a team subscription event changed (`Db::apply_team_subscription`), for the
/// billing emails it queues in the same transaction.
pub struct TeamChange<'a> {
    pub applied: &'a Applied,
    pub before: Option<&'a TeamSubscription>,
    pub paying_before: Option<&'a TeamSubscription>,
    pub paying_after: Option<&'a TeamSubscription>,
    pub other_paying: Option<&'a TeamSubscription>,
}

/// What linking a payment-provider customer to a user did (ADR 0042). A user has at most
/// one customer and a customer pays for one user; the first link stands.
#[derive(Debug, PartialEq)]
pub enum Linked {
    New,
    Already,
    /// The user is linked to this other customer already.
    UserHasAnother(String),
    /// The customer is linked to this other user already.
    OfAnotherUser(String),
    /// The provider deleted this customer: a late event can't bring it back.
    Deleted,
}

fn link_in(c: &Connection, user_id: &str, provider: &str, customer_id: &str, via: &str) -> rusqlite::Result<Linked> {
    let deleted: bool = c.query_row("SELECT COUNT(*) FROM billing_deleted_customers WHERE customer_id = ?", [customer_id], |r| r.get(0))?;
    if deleted {
        return Ok(Linked::Deleted);
    }
    let by_customer: Option<String> = c.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional()?;
    if let Some(u) = by_customer {
        return Ok(if u == user_id { Linked::Already } else { Linked::OfAnotherUser(u) });
    }
    // A team's customer (ADR 0093) pays for the team, never for one person.
    if let Some(t) = customer_team_in(c, customer_id)? {
        return Ok(Linked::OfAnotherUser(format!("team:{t}")));
    }
    let by_user: Option<String> = c.query_row("SELECT customer_id FROM billing_customers WHERE user_id = ?", [user_id], |r| r.get(0)).optional()?;
    if let Some(other) = by_user {
        return Ok(Linked::UserHasAnother(other));
    }
    c.execute(
        "INSERT INTO billing_customers (user_id, provider, customer_id, linked_at, linked_via) VALUES (?, ?, ?, ?, ?)",
        params![user_id, provider, customer_id, now(), via],
    )?;
    Ok(Linked::New)
}

fn customer_team_in(c: &Connection, customer_id: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT team_id FROM team_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional()
}

/// Links a payment-provider customer to a team (ADR 0093), as `link_in` does to a user:
/// one customer per team, one team per customer, never a user's, and the first link stands.
fn link_team_in(c: &Connection, team_id: &str, provider: &str, customer_id: &str, via: &str) -> rusqlite::Result<Linked> {
    let deleted: bool = c.query_row("SELECT COUNT(*) FROM billing_deleted_customers WHERE customer_id = ?", [customer_id], |r| r.get(0))?;
    if deleted {
        return Ok(Linked::Deleted);
    }
    if let Some(t) = customer_team_in(c, customer_id)? {
        return Ok(if t == team_id { Linked::Already } else { Linked::OfAnotherUser(format!("team:{t}")) });
    }
    let user: Option<String> = c.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional()?;
    if let Some(u) = user {
        return Ok(Linked::OfAnotherUser(u));
    }
    let by_team: Option<String> = c.query_row("SELECT customer_id FROM team_customers WHERE team_id = ?", [team_id], |r| r.get(0)).optional()?;
    if let Some(other) = by_team {
        return Ok(Linked::UserHasAnother(other));
    }
    c.execute(
        "INSERT INTO team_customers (team_id, provider, customer_id, linked_at, linked_via) VALUES (?, ?, ?, ?, ?)",
        params![team_id, provider, customer_id, now(), via],
    )?;
    Ok(Linked::New)
}

/// Queues a billing email, due at `due`, unless one with its key was queued before.
fn queue_email(c: &Connection, e: &crate::billing_mail::NewEmail, due: i64) -> rusqlite::Result<bool> {
    let facts = serde_json::to_string(&e.facts).unwrap_or_else(|_| "{}".into());
    Ok(c.execute(
        "INSERT OR IGNORE INTO billing_emails (key, user_id, kind, facts, event_id, next_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![e.key, e.user_id, e.kind.as_str(), facts, e.event_id, due, now()],
    )? == 1)
}

fn queued_email_row(r: &Row) -> rusqlite::Result<crate::billing_mail::Queued> {
    let facts: String = r.get("facts")?;
    Ok(crate::billing_mail::Queued {
        id: r.get("id")?,
        key: r.get("key")?,
        user_id: r.get("user_id")?,
        kind: r.get("kind")?,
        facts: serde_json::from_str(&facts).unwrap_or_default(),
        event_id: r.get("event_id")?,
        state: r.get("state")?,
        attempts: r.get("attempts")?,
        next_at: r.get("next_at")?,
        created_at: r.get("created_at")?,
        done_at: r.get("done_at")?,
        reason: r.get("reason")?,
    })
}

/// Records a payment-provider event id. False when it was already applied.
fn first_delivery(c: &Connection, event_id: &str, event_type: &str) -> rusqlite::Result<bool> {
    Ok(c.execute("INSERT OR IGNORE INTO billing_events (event_id, type, received_at) VALUES (?, ?, ?)", params![event_id, event_type, now()])? == 1)
}

fn routine_row(r: &Row) -> rusqlite::Result<Routine> {
    Ok(Routine {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        name: r.get("name")?,
        cron: r.get("cron")?,
        instruction: r.get("instruction")?,
        enabled: r.get("enabled")?,
        last_run_at: r.get("last_run_at")?,
        created_at: r.get("created_at")?,
        author_id: r.get("author_id")?,
        paused_reason: r.get("paused_reason")?,
        paused_for: r.get("paused_for")?,
        paused_at: r.get("paused_at")?,
    })
}

/// A rule to save together with a decision.
pub struct NewRule<'a> {
    pub bot_id: Option<&'a str>,
    pub action: Action,
    pub tool: &'a str,
    pub pattern: &'a str,
    pub note: &'a str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub bot_id: String,
    pub harness: String,
    pub tool: String,
    /// "shell", "file", "web", "mcp", or "other"
    pub kind: String,
    /// The command, path, or arguments the user approves.
    pub subject: String,
    pub input: Value,
    pub class: String,
    pub reason: String,
    /// "pending" | "approved" | "denied" | "expired" | "cancelled"
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    /// "user" or "system"
    pub decided_by: Option<String>,
    pub note: Option<String>,
    /// The rule a "remember" decision created.
    pub rule_id: Option<String>,
    /// The run the call came from (`runId` in the audit log), when the hook named the
    /// Bot's live run (ADR 0051).
    pub run_id: Option<String>,
    /// What approving it for the rest of that run would cover: `{covers: [what], exact}`.
    /// None when it can only be approved once.
    pub run_scope: Option<Value>,
    /// How it was approved: "once" or "run". None until approved.
    pub scope: Option<String>,
}

/// One group of [`Db::audit_counts`].
#[derive(Clone, Debug, PartialEq)]
pub struct AuditCount {
    pub action: String,
    pub outcome: String,
    pub method: Option<String>,
    pub code: Option<String>,
    pub n: u64,
    /// Failures these events say weren't logged (`unloggedSinceLast`), of any reason.
    pub skipped: u64,
}

/// One row of the audit log. See `audit.rs` and ADR 0009.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    /// Unix ms, UTC.
    pub at: i64,
    /// `at` as RFC 3339 UTC, e.g. `2026-11-19T13:46:00.123Z`.
    pub time: String,
    /// "user", "bot", or "system"
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    /// The IdP subject (`issuer|subject`) when the person signed in with SSO.
    pub actor_subject: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub bot_id: Option<String>,
    /// "success", "failure", or "denied"
    pub outcome: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: Value,
    // Per-user actors (ADR 0019). Null on rows written before it.
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    /// "password" (break-glass), "code", "sso", "none" (ALLOW_NO_AUTH), or "bot_token".
    pub auth_method: Option<String>,
    /// The SSO provider's type ("entra", "google", "oidc", "github", "apple", "saml"), and its configured id.
    pub idp: Option<String>,
    pub idp_provider: Option<String>,
    pub session_id: Option<String>,
    /// The user a Bot or the scheduler acted for.
    pub on_behalf_of: Option<String>,
    /// The hash chain (ADR 0122): the row before's hash, and this row's.
    pub chain_prev: Option<String>,
    pub chain_hash: Option<String>,
    /// The salted digest of the fields an erasure may rewrite, and its salt (None once
    /// erased). Only the export sends them (ADR 0199).
    #[serde(skip)]
    pub chain_digest: Option<String>,
    #[serde(skip)]
    pub chain_salt: Option<String>,
}

/// A person who can sign in. `operator` is the owner and break-glass account.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub email: Option<String>,
    pub name: String,
    pub role: Role,
    /// "active" or "disabled"
    pub status: String,
    /// The IdP that vouches for this user, once OIDC lands (ADR 0012).
    pub idp_issuer: Option<String>,
    pub idp_subject: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// When a session last started for this user, how ("password", "code", "sso"),
    /// and through which SSO provider id (ADR 0021).
    pub last_login_at: Option<i64>,
    pub last_login_method: Option<String>,
    pub last_login_idp_provider: Option<String>,
    /// The tier an admin (later, billing) gave them. None: the default tier (ADR 0033).
    pub tier: Option<String>,
    /// Where an admin said their machine and its backups live (ADR 0117). None: their
    /// team's, else the server's default.
    pub region: Option<String>,
    /// When they were erased (ADR 0102): the row is a tombstone with no personal data.
    pub erased_at: Option<i64>,
    /// The pseudonym the audit log names them by since.
    pub erased_as: Option<String>,
    /// Their custom role across the server (ADR 0123). `role` is then that role's base.
    /// None once its end has passed, before the sweep takes it away (ADR 0197).
    pub role_id: Option<String>,
    /// When `role_id` ends (ADR 0197). None: it doesn't.
    pub role_expires_at: Option<i64>,
    /// A service account (ADR 0143), not a person: it never signs in, and only its tokens
    /// act as it. People lists and lookups by id or email leave these out.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub service: bool,
}

impl User {
    pub fn active(&self) -> bool {
        self.status == "active"
    }
}

/// A role an admin made (ADR 0123): a base built-in role (member or read-only) and the
/// delegable permissions it adds. `permissions` is as saved; `perms` drops any name the
/// server doesn't know, so it grants nothing.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub base: Role,
    pub permissions: Vec<String>,
    /// Time-bound (ADR 0197): given only by hand, for at most this many days. None: no limit.
    pub max_days: Option<i64>,
    /// People may ask for it (ADR 0209). Only ever set on a time-bound role.
    pub requestable: bool,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
}

impl CustomRole {
    pub fn perms(&self) -> crate::rbac::Perms {
        crate::rbac::Perms::from_names(self.permissions.iter().map(String::as_str))
    }
}

/// A person's request for a requestable role (ADR 0209), for `hours` from when an admin
/// approves it. `team_id` None: across the server; else within that team, theirs when
/// they asked. `expires_at`: when it lapses if nobody decides.
#[derive(Clone, Debug)]
pub struct RoleRequest {
    pub id: String,
    pub user_id: String,
    pub role_id: String,
    pub team_id: Option<String>,
    pub hours: i64,
    pub reason: String,
    /// `pending`, `approved`, `denied`, `cancelled` or `lapsed`.
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub note: Option<String>,
    /// When the role it gave ends. Only once approved.
    pub granted_until: Option<i64>,
}

#[derive(Debug, PartialEq)]
pub enum RoleRequestError {
    /// They have a pending request for this role in this scope already.
    Duplicate,
    /// They have this many pending requests, the most there may be.
    TooMany(usize),
    /// They made this many requests in the last day, the most there may be.
    TooOften(usize),
    /// It was decided, withdrawn or lapsed already: its status.
    NotPending(String),
    /// What, read in the same transaction, makes it one that can't be given (`role_requests::why`).
    Refused(&'static str),
    /// Longer than the role's limit allows now, in hours.
    OverLimit(i64),
    NotFound,
    Db(String),
}

/// What an approval is checked against, all read in its transaction (ADR 0209).
pub struct RequestState<'a> {
    pub request: &'a RoleRequest,
    pub role: &'a CustomRole,
    pub user: &'a User,
    /// Their team membership, when the request is for a team.
    pub member: Option<&'a TeamMember>,
}

/// An approved request, with the role they held in its scope just before (and its end),
/// and the SCIM or SAML claim on it that giving it by hand ended.
#[derive(Debug)]
pub struct ApprovedRequest {
    pub request: RoleRequest,
    pub before: (Option<String>, Option<i64>),
    pub taken: Option<String>,
    pub taken_saml: Option<String>,
}

fn role_request_row(r: &Row) -> rusqlite::Result<RoleRequest> {
    Ok(RoleRequest {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        role_id: r.get("role_id")?,
        team_id: r.get("team_id")?,
        hours: r.get("hours")?,
        reason: r.get("reason")?,
        status: r.get("status")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        decided_at: r.get("decided_at")?,
        decided_by: r.get("decided_by")?,
        note: r.get("note")?,
        granted_until: r.get("granted_until")?,
    })
}

/// A role given by hand whose end passed, as the sweep took it away (ADR 0197). `team_id`
/// None: across the server.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpiredRole {
    pub user_id: String,
    pub team_id: Option<String>,
    pub role_id: String,
    pub expires_at: i64,
}

/// A role held only until its end: still held while `expires_at` is ahead.
fn held_until(role_id: Option<String>, expires_at: Option<i64>) -> (Option<String>, Option<i64>) {
    match (role_id, expires_at) {
        (_, Some(t)) if t <= now() => (None, None),
        (Some(id), t) => (Some(id), t),
        (None, _) => (None, None),
    }
}

/// Each user's team: its members, and its live service accounts (ADR 0143).
const TEAM_OF: &str = "SELECT user_id, team_id FROM team_members UNION ALL SELECT user_id, team_id FROM service_accounts WHERE team_id IS NOT NULL AND deleted_at IS NULL";

/// A service account (ADR 0143): its `users` row (kind `service`: role, custom role across
/// the server, status), and what only it has. `owner_id` is the person whose permissions
/// cap it; `team_id` the team it acts in, with the custom role `team_role_id` there.
#[derive(Clone, Debug)]
pub struct ServiceAccount {
    pub user: User,
    pub description: String,
    pub owner_id: String,
    pub team_id: Option<String>,
    pub team_role_id: Option<String>,
    pub created_by: Option<String>,
    pub deleted_at: Option<i64>,
}

#[derive(Default)]
pub struct ServiceAccountPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<&'static str>,
    pub role: Option<(Role, Option<String>)>,
    pub team: Option<Option<(String, Option<String>)>>,
    pub owner: Option<String>,
}

/// A service account's API token. Only its hash is kept; `hint` is its last four
/// characters, so people can tell tokens apart. `scopes` None: all the account holds.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceToken {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub hint: String,
    pub scopes: Option<Vec<String>>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
    pub revoked_reason: Option<String>,
    pub rotated_to: Option<String>,
}

/// How often one service account was refused for one reason (ADR 0170), and when last.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceRefusal {
    pub account: String,
    pub reason: String,
    pub n: u64,
    pub last_at: i64,
}

pub struct NewServiceToken<'a> {
    pub account_id: &'a str,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub hint: &'a str,
    pub scopes: Option<&'a [&'a str]>,
    pub expires_at: i64,
    pub created_by: Option<&'a str>,
}

#[derive(Debug, PartialEq)]
pub enum RoleError {
    NameTaken,
    NotFound,
    /// Still given to this many people, across the server or in a team.
    InUse(usize),
    /// This many SCIM (ADR 0138) and SAML (ADR 0160) groups map to it.
    Mapped(usize),
    /// A SCIM or SAML group (`via`) maps to it in `scope`, where these permissions would reach admins.
    Reaches { via: &'static str, mapping: String, scope: String, perms: Vec<&'static str> },
    /// It can't be made time-bound (ADR 0197): this many hold it with no end or a later one
    /// than it would allow, and this many SCIM or SAML groups are mapped to it.
    Standing { held: usize, mapped: usize },
    /// People may request it (ADR 0209), so it must stay time-bound.
    Requestable,
    Db(String),
}

/// A custom role's permissions, read in `c`'s transaction. None: no such role.
fn role_perms_in(c: &Connection, role_id: &str) -> rusqlite::Result<Option<crate::rbac::Perms>> {
    let json: Option<String> = c.query_row("SELECT permissions FROM roles WHERE id = ?", [role_id], |r| r.get(0)).optional()?;
    Ok(json.map(|j| {
        let names: Vec<String> = serde_json::from_str(&j).unwrap_or_default();
        crate::rbac::Perms::from_names(names.iter().map(String::as_str))
    }))
}

/// The role `?1` exists and, if time-bound (ADR 0197), the end `?4` is given and no later
/// than its limit from `?2`, now (`?5` is a day). Checked as it's written, against an edit.
const GIVABLE: &str = "EXISTS (SELECT 1 FROM roles WHERE id = ?1 AND (max_days IS NULL OR (?4 IS NOT NULL AND ?4 <= ?2 + max_days * ?5)))";

/// What a service account write returns when a role it would give became time-bound
/// (ADR 0197) after it was checked: service accounts hold roles with no end.
pub const SA_TIME_BOUND: &str = "time-bound";

/// Whether a custom role is time-bound (ADR 0197), read in `c`'s transaction. A group
/// holds what it maps while people are in it, so it is never given one.
fn role_time_bound_in(c: &Connection, role_id: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row("SELECT max_days IS NOT NULL FROM roles WHERE id = ?", [role_id], |r| r.get(0)).optional()?.unwrap_or(false))
}

/// A request for access from the public sign-up form (ADR 0022).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signup {
    pub id: String,
    pub name: String,
    pub email: String,
    pub company: String,
    pub team_size: String,
    pub use_case: String,
    /// `microsoft`, `google`, `github`, `apple`, or `other`.
    pub sign_in: String,
    /// "pending", "approved", or "rejected"
    pub status: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
    /// The user an approval made, and their role.
    pub user_id: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum AddSignup {
    /// This email has a pending request already.
    Duplicate,
    /// The pending cap is reached.
    Full,
}

#[derive(Debug, PartialEq)]
pub enum SignupError {
    NotFound,
    /// Approved or rejected already: the status it has.
    Closed(String),
    EmailTaken,
    /// Every seat is taken (ADR 0038); the request stays pending.
    NoSeat,
    Db(String),
}

pub struct NewSignup<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub company: &'a str,
    pub team_size: &'a str,
    pub use_case: &'a str,
    pub sign_in: &'a str,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

fn signup_row(r: &Row) -> rusqlite::Result<Signup> {
    Ok(Signup {
        id: r.get("id")?,
        name: r.get("name")?,
        email: r.get("email")?,
        company: r.get("company")?,
        team_size: r.get("team_size")?,
        use_case: r.get("use_case")?,
        sign_in: r.get("sign_in")?,
        status: r.get("status")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        created_at: r.get("created_at")?,
        decided_at: r.get("decided_at")?,
        decided_by: r.get("decided_by")?,
        reason: r.get("reason")?,
        user_id: r.get("user_id")?,
        role: r.get("role")?,
    })
}

/// One user's machine (ADR 0025). Destroyed rows stay, as history; a user has at
/// most one that isn't.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    /// The provider's id for it, once created.
    pub provider_id: Option<String>,
    /// Unique at the provider: `<prefix>-<id>`. Creating twice can't make two.
    pub label: String,
    /// The provider tag it is created with and found by: the label prefix when it was
    /// saved, so changing MACHINE_LABEL_PREFIX later can't lose it.
    pub tag: String,
    pub tier: String,
    pub plan: String,
    pub region: String,
    pub state: MachineState,
    /// The provider's last word on it (`running`, `offline`, ...), from reconciliation.
    pub provider_status: Option<String>,
    pub ipv4: Option<String>,
    pub backups: bool,
    pub last_error: Option<String>,
    /// When a create was last sent. One that went unanswered may still make a machine.
    pub create_sent_at: Option<i64>,
    /// The host a create was sent to (ADR 0081), until it is answered: its room stays
    /// taken meanwhile.
    pub placed_on: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
    pub destroyed_at: Option<i64>,
    /// Its agent's certificates (ADR 0031): `none` yet, `enrolled` (one is active),
    /// `held` (while suspended), or `revoked`.
    pub enrollment: String,
    pub enrolled_at: Option<i64>,
    /// The last heartbeat its agent answered, and what it said or why it didn't.
    pub agent_seen_at: Option<i64>,
    pub agent_version: Option<String>,
    pub agent_error: Option<String>,
    /// The provider firewall it was created behind or put behind (ADR 0035).
    pub firewall_id: Option<String>,
    /// When its current enrollment token was issued, plus the enrollment timeout.
    pub enroll_by: Option<i64>,
    /// When the reconciler found it hadn't enrolled by then. Cleared when it enrolls
    /// or gets a new token.
    pub enroll_overdue_at: Option<i64>,
    /// When an admin assigned it to its user, so their Bots run on it (ADR 0036).
    pub assigned_at: Option<i64>,
    pub assigned_by: Option<String>,
    /// What its agent last said of its build, harness CLIs and upgrades (ADR 0039).
    pub agent_upkeep: Option<Value>,
    /// When botd last sent it the harness plan, and the plan's id.
    pub harnesses_sent_at: Option<i64>,
    pub harnesses_sent_plan: Option<String>,
    /// An admin holding its agent at its build: nothing upgrades it.
    pub upgrade_hold_at: Option<i64>,
    pub upgrade_hold_by: Option<String>,
    /// The upgrade on its way: its id, the build, when it was sent, and `auto` or the
    /// admin who asked.
    pub upgrade_id: Option<String>,
    pub upgrade_build: Option<String>,
    pub upgrade_sent_at: Option<i64>,
    pub upgrade_by: Option<String>,
    /// A build that failed to upgrade it, so it isn't tried again by itself.
    pub upgrade_failed_build: Option<String>,
    /// Its latest rebuild with today's agent (ADR 0056): `queued`, `retrying`,
    /// `rebuilding`, `done`, `failed` or `cancelled`. None: never asked.
    pub rebuild_state: Option<String>,
    pub rebuild_id: Option<String>,
    /// `auto` or the admin who asked.
    pub rebuild_by: Option<String>,
    /// The admin accepted that files only on the machine are lost.
    pub rebuild_discard: bool,
    /// Rebuilds sent and checks that failed, for the backoff and the limit.
    pub rebuild_attempts: i64,
    /// Not tried again before this.
    pub rebuild_next_at: Option<i64>,
    pub rebuild_requested_at: Option<i64>,
    /// When it entered its state, and when the last rebuild was sent.
    pub rebuild_at: Option<i64>,
    pub rebuild_sent_at: Option<i64>,
    pub rebuild_error: Option<String>,
    /// Its agent's version when the rebuild was asked for.
    pub rebuild_from: Option<String>,
    /// Its latest resize to follow its user's tier (ADR 0085): `pending`, `waiting`,
    /// `done`, `failed` or `cancelled`. None: never asked.
    #[serde(skip)]
    pub resize_state: Option<String>,
    /// The size it is to have, and the one it had when asked.
    #[serde(skip)]
    pub resize_tier: Option<String>,
    #[serde(skip)]
    pub resize_plan: Option<String>,
    #[serde(skip)]
    pub resize_from_tier: Option<String>,
    #[serde(skip)]
    pub resize_from_plan: Option<String>,
    /// What changed the tier (`stripe` or `admin`), and the Stripe event, if one.
    #[serde(skip)]
    pub resize_cause: Option<String>,
    #[serde(skip)]
    pub resize_event: Option<String>,
    /// Why it waits, failed or was cancelled: a short code and the words people see.
    #[serde(skip)]
    pub resize_reason: Option<String>,
    #[serde(skip)]
    pub resize_error: Option<String>,
    #[serde(skip)]
    pub resize_attempts: i64,
    /// Not tried again before this.
    #[serde(skip)]
    pub resize_next_at: Option<i64>,
    #[serde(skip)]
    pub resize_requested_at: Option<i64>,
    /// When it entered its state.
    #[serde(skip)]
    pub resize_at: Option<i64>,
    /// The size last sent to the provider whose outcome botd hasn't seen: it may hold
    /// that size already, whatever `plan` says. Cleared once the provider is checked.
    #[serde(skip)]
    pub resize_sent_tier: Option<String>,
    #[serde(skip)]
    pub resize_sent_plan: Option<String>,
    /// What its agent last said of its disk, in bytes (ADR 0085), and when.
    pub disk_used: Option<i64>,
    pub disk_total: Option<i64>,
    pub disk_seen_at: Option<i64>,
    /// What its agent last said the Bots' and teammates' homes hold, in bytes, whether
    /// that was a lower bound, and when botd heard it (ADR 0105). None: never said.
    #[serde(skip)]
    pub disk_files: Option<i64>,
    #[serde(skip)]
    pub disk_files_partial: bool,
    #[serde(skip)]
    pub disk_files_at: Option<i64>,
    /// When it was last suspended, while it is. None for one suspended before this was
    /// kept.
    #[serde(skip)]
    pub suspended_at: Option<i64>,
    /// When the provider's own backups of it last succeeded, as the provider last said
    /// (Linode Backups, ADR 0110).
    pub provider_backup_at: Option<i64>,
}

/// A certificate the control plane issued a machine (ADR 0031). Looked up by
/// fingerprint; the machine and user are botd's record, whatever the certificate says.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineCert {
    pub fingerprint: String,
    pub serial: String,
    pub machine_id: String,
    pub user_id: String,
    /// `active`, `held` (the machine is suspended), or `revoked`.
    pub status: String,
    /// `enrolled` or `rotated`.
    pub issued_for: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub not_after: i64,
    /// First used: after a rotation, the certificates before it are revoked then.
    pub first_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
}

impl MachineCert {
    pub fn usable(&self, at: i64) -> bool {
        self.status == "active" && self.not_before <= at && at < self.not_after
    }
}

/// A one-time enrollment token, by its hash.
#[derive(Clone, Debug)]
pub struct MachineToken {
    pub id: i64,
    pub machine_id: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

fn machine_cert_row(r: &Row) -> rusqlite::Result<MachineCert> {
    Ok(MachineCert {
        fingerprint: r.get("fingerprint")?,
        serial: r.get("serial")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        status: r.get("status")?,
        issued_for: r.get("issued_for")?,
        issued_at: r.get("issued_at")?,
        not_before: r.get("not_before")?,
        not_after: r.get("not_after")?,
        first_seen_at: r.get("first_seen_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_reason: r.get("revoked_reason")?,
    })
}

/// Sets a machine's `enrollment` from its certificates.
fn refresh_enrollment(c: &Connection, machine_id: &str) -> rusqlite::Result<usize> {
    c.execute(
        "UPDATE machines SET enrollment = COALESCE((
           SELECT CASE WHEN SUM(status = 'active') > 0 THEN 'enrolled' WHEN SUM(status = 'held') > 0 THEN 'held' ELSE 'revoked' END
           FROM machine_certs WHERE machine_id = ?1 HAVING COUNT(*) > 0), 'none')
         WHERE id = ?1",
        [machine_id],
    )
}

/// Revokes `machine_id`'s certificates that aren't yet and match `filter` (SQL over
/// `machine_certs`, never user input), and returns their fingerprints.
fn revoke_where(
    c: &Connection,
    machine_id: &str,
    filter: &str,
    reason: &str,
) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare(&format!(
        "UPDATE machine_certs SET status = 'revoked', revoked_at = ?2, revoked_reason = ?3
         WHERE machine_id = ?1 AND status <> 'revoked' AND ({filter}) RETURNING fingerprint"
    ))?;
    let out = s
        .query_map(params![machine_id, now(), reason], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(out)
}

pub struct NewMachine<'a> {
    pub user_id: &'a str,
    pub provider: &'a str,
    pub label_prefix: &'a str,
    pub tier: &'a str,
    pub plan: &'a str,
    pub region: &'a str,
    pub created_by: Option<&'a str>,
}

#[derive(Debug)]
pub enum AddMachine {
    /// The user's live machine.
    Exists(Box<Machine>),
    Db(String),
}

fn machine_row(r: &Row) -> rusqlite::Result<Machine> {
    Ok(Machine {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        provider_id: r.get("provider_id")?,
        label: r.get("label")?,
        tag: r.get("tag")?,
        tier: r.get("tier")?,
        plan: r.get("plan")?,
        region: r.get("region")?,
        // The column's CHECK allows only known states.
        state: MachineState::parse(&r.get::<_, String>("state")?).unwrap_or(MachineState::Error),
        provider_status: r.get("provider_status")?,
        ipv4: r.get("ipv4")?,
        backups: r.get("backups")?,
        last_error: r.get("last_error")?,
        create_sent_at: r.get("create_sent_at")?,
        placed_on: r.get("placed_on")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
        destroyed_at: r.get("destroyed_at")?,
        enrollment: r.get("enrollment")?,
        enrolled_at: r.get("enrolled_at")?,
        agent_seen_at: r.get("agent_seen_at")?,
        agent_version: r.get("agent_version")?,
        agent_error: r.get("agent_error")?,
        firewall_id: r.get("firewall_id")?,
        enroll_by: r.get("enroll_by")?,
        enroll_overdue_at: r.get("enroll_overdue_at")?,
        assigned_at: r.get("assigned_at")?,
        assigned_by: r.get("assigned_by")?,
        agent_upkeep: r.get::<_, Option<String>>("agent_upkeep")?.and_then(|j| serde_json::from_str(&j).ok()),
        harnesses_sent_at: r.get("harnesses_sent_at")?,
        harnesses_sent_plan: r.get("harnesses_sent_plan")?,
        upgrade_hold_at: r.get("upgrade_hold_at")?,
        upgrade_hold_by: r.get("upgrade_hold_by")?,
        upgrade_id: r.get("upgrade_id")?,
        upgrade_build: r.get("upgrade_build")?,
        upgrade_sent_at: r.get("upgrade_sent_at")?,
        upgrade_by: r.get("upgrade_by")?,
        upgrade_failed_build: r.get("upgrade_failed_build")?,
        rebuild_state: r.get("rebuild_state")?,
        rebuild_id: r.get("rebuild_id")?,
        rebuild_by: r.get("rebuild_by")?,
        rebuild_discard: r.get("rebuild_discard")?,
        rebuild_attempts: r.get("rebuild_attempts")?,
        rebuild_next_at: r.get("rebuild_next_at")?,
        rebuild_requested_at: r.get("rebuild_requested_at")?,
        rebuild_at: r.get("rebuild_at")?,
        rebuild_sent_at: r.get("rebuild_sent_at")?,
        rebuild_error: r.get("rebuild_error")?,
        rebuild_from: r.get("rebuild_from")?,
        resize_state: r.get("resize_state")?,
        resize_tier: r.get("resize_tier")?,
        resize_plan: r.get("resize_plan")?,
        resize_from_tier: r.get("resize_from_tier")?,
        resize_from_plan: r.get("resize_from_plan")?,
        resize_cause: r.get("resize_cause")?,
        resize_event: r.get("resize_event")?,
        resize_reason: r.get("resize_reason")?,
        resize_error: r.get("resize_error")?,
        resize_attempts: r.get("resize_attempts")?,
        resize_next_at: r.get("resize_next_at")?,
        resize_requested_at: r.get("resize_requested_at")?,
        resize_at: r.get("resize_at")?,
        resize_sent_tier: r.get("resize_sent_tier")?,
        resize_sent_plan: r.get("resize_sent_plan")?,
        disk_used: r.get("disk_used")?,
        disk_total: r.get("disk_total")?,
        disk_seen_at: r.get("disk_seen_at")?,
        disk_files: r.get("disk_files")?,
        disk_files_partial: r.get("disk_files_partial")?,
        disk_files_at: r.get("disk_files_at")?,
        suspended_at: r.get("suspended_at")?,
        provider_backup_at: r.get("provider_backup_at")?,
    })
}

#[derive(Default)]
pub struct UserPatch {
    pub email: Option<Option<String>>,
    pub name: Option<String>,
    /// A built-in role. It replaces any custom role they had (ADR 0123).
    pub role: Option<Role>,
    pub status: Option<&'static str>,
    /// Some(None): back to the default tier.
    pub tier: Option<Option<String>>,
}

/// A sign-in. The token itself is never stored, only its SHA-256.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub user_id: String,
    /// "cookie" (web app) or "token" (bearer: the client, botctl)
    pub kind: String,
    /// How the person proved who they are: "password" (break-glass), "code", or "sso".
    pub method: String,
    /// `issuer|subject` of the SSO identity that signed in, for the audit log.
    pub idp_subject: Option<String>,
    /// The SSO provider id it signed in with (from SSO_PROVIDERS).
    pub idp_provider: Option<String>,
    pub label: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
    /// The second factor the sign-in passed (ADR 0094), if any.
    pub mfa: Option<String>,
}

/// What a native SAML sign-in's assertion said about the person and the IdP's session
/// (ADR 0137): our LogoutRequest names them, and the IdP's names them back.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SamlLogin {
    /// The NameID as the IdP sent it (identities keep it lowercased).
    pub name_id: String,
    pub format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub session_index: Option<String>,
}

/// A phone that gets push notifications (ADR 0080), registered by one session and
/// removed with it. `token` is the provider's address for the device, sealed at rest
/// and never shown: anyone holding it can send to the phone.
#[derive(Clone)]
pub struct PushDevice {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub token: String,
    pub platform: String,
    pub approvals: bool,
    pub routines: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl std::fmt::Debug for PushDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushDevice").field("id", &self.id).field("user_id", &self.user_id).field("platform", &self.platform).finish_non_exhaustive()
    }
}

/// What a push is about, and so which of a device's switches it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushKind {
    Approvals,
    Routines,
}

/// How `put_push_device` changed things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushPut {
    /// A new device for this session (or a new token for it).
    Added,
    /// The token was another session's: it moved here, and that session lost it.
    Moved,
    /// Same token, switches changed.
    Updated,
    Unchanged,
}

/// Each person keeps at most this many devices; registering more drops the oldest.
pub const MAX_PUSH_DEVICES: usize = 20;
pub(crate) const PUSH_TOKEN_CONTEXT: &str = "push_devices.token";

pub struct NewSession<'a> {
    pub user_id: &'a str,
    pub token_hash: &'a str,
    pub kind: &'a str,
    pub method: &'a str,
    pub idp_subject: Option<&'a str>,
    pub idp_provider: Option<&'a str>,
    pub label: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub expires_at: i64,
    /// The second factor the sign-in passed (ADR 0094): "totp" or "recovery_code".
    pub mfa: Option<&'a str>,
}

/// A user's second factor (ADR 0094). `secret` is sealed (`sb1:`); unconfirmed until
/// a first code proves the authenticator app has it.
pub struct MfaRow {
    pub secret: String,
    pub confirmed_at: Option<i64>,
    /// The last TOTP time step used, so no code works twice.
    pub last_step: i64,
}

/// An SSO identity linked to a user (ADR 0014). `(issuer, subject)` is the key; the
/// email is only what the IdP last said, never used to find anyone.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    /// The provider id from SSO_PROVIDERS, e.g. "entra".
    pub provider: String,
    pub issuer: String,
    /// Entra: the object id (`oid`); others: `sub`.
    pub subject: String,
    /// Entra: the tenant id (`tid`), which `issuer` also names.
    pub tenant: Option<String>,
    pub email: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub last_login_at: Option<i64>,
}

pub struct NewIdentity<'a> {
    pub provider: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub tenant: Option<&'a str>,
    pub email: Option<&'a str>,
    pub created_by: Option<&'a str>,
}

fn identity_row(r: &Row) -> rusqlite::Result<Identity> {
    Ok(Identity {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        issuer: r.get("issuer")?,
        subject: r.get("subject")?,
        tenant: r.get("tenant")?,
        email: r.get("email")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        last_login_at: r.get("last_login_at")?,
    })
}

/// A SCIM bearer token (ADR 0023). Only its SHA-256 is stored. Every token belongs to
/// a tenant: one IdP connection, whose users only its tokens can see.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimToken {
    pub id: String,
    pub tenant: String,
    pub label: Option<String>,
    /// The SSO provider whose subjects this tenant's `externalId`s are (from SSO_PROVIDERS).
    pub sso_provider: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
    /// When it stops working (ADR 0196). None only for tokens made before tokens expired.
    pub expires_at: Option<i64>,
    /// The token that replaced it: a rotated token works until its `expires_at`, at most
    /// the overlap the rotation gave.
    pub rotated_to: Option<String>,
    /// The last expiry notice audited for it: `expiring`, then `expired`.
    #[serde(skip)]
    pub expiry_notice: Option<String>,
    /// What it may do (ADR 0224). All four for tokens made before scopes.
    pub scopes: crate::scim::scopes::Scopes,
}

fn scim_token_row(r: &Row) -> rusqlite::Result<ScimToken> {
    let scopes: Option<String> = r.get("scopes")?;
    Ok(ScimToken {
        id: r.get("id")?,
        tenant: r.get("tenant")?,
        label: r.get("label")?,
        sso_provider: r.get("sso_provider")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        last_used_at: r.get("last_used_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
        expires_at: r.get("expires_at")?,
        rotated_to: r.get("rotated_to")?,
        expiry_notice: r.get("expiry_notice")?,
        scopes: crate::scim::scopes::Scopes::from_stored(scopes.as_deref()),
    })
}

/// Claims `notice` for a token, on `c` (inside the transaction that audits it): only
/// while it's still unrevoked, unrotated, and its last notice is `from`.
pub(crate) fn claim_scim_token_notice(c: &Connection, id: &str, from: Option<&str>, notice: &str) -> rusqlite::Result<bool> {
    let n = c.execute(
        "UPDATE scim_tokens SET expiry_notice = ?1 WHERE id = ?2 AND revoked_at IS NULL AND rotated_to IS NULL AND coalesce(expiry_notice, '') = coalesce(?3, '')",
        params![notice, id, from],
    )?;
    Ok(n == 1)
}

/// A tenant's tokens, read on `c`.
pub(crate) fn scim_tenant_tokens(c: &Connection, tenant: &str) -> rusqlite::Result<Vec<ScimToken>> {
    let mut s = c.prepare("SELECT * FROM scim_tokens WHERE tenant = ? ORDER BY created_at, id")?;
    s.query_map([tenant], scim_token_row)?.collect()
}

/// A user as a SCIM tenant provisioned it: the SCIM attributes botd has no column for
/// on `users`, and whether the IdP deleted it (users themselves are never deleted).
#[derive(Clone, Debug)]
pub struct ScimUser {
    pub user: User,
    pub tenant: String,
    pub external_id: Option<String>,
    pub user_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    /// `displayName` and `name.formatted` as the IdP sent them; `users.display_name` is
    /// what SuperBot shows, built from these.
    pub display_name: Option<String>,
    pub formatted: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
    pub enterprise: Enterprise,
    /// The shown name of `enterprise.manager`.
    pub manager_name: Option<String>,
}

/// The columns of a `users` row joined with its `scim_users` row, the SCIM ones prefixed.
const SCIM_USER_SELECT: &str = "SELECT u.*, l.tenant AS scim_tenant, l.external_id AS scim_external_id, l.user_name AS scim_user_name,
  l.given_name AS scim_given_name, l.family_name AS scim_family_name, l.display_name AS scim_display_name,
  l.formatted AS scim_formatted, l.created_at AS scim_created_at,
  l.updated_at AS scim_updated_at, l.deleted_at AS scim_deleted_at,
  l.employee_number AS scim_employee_number, l.cost_center AS scim_cost_center, l.organization AS scim_organization,
  l.division AS scim_division, l.department AS scim_department,
  m.user_id AS scim_manager, mu.display_name AS scim_manager_name
  FROM scim_users l JOIN users u ON u.id = l.user_id
  LEFT JOIN scim_users m ON m.user_id = l.manager_id AND m.tenant = l.tenant AND m.deleted_at IS NULL AND m.user_id <> l.user_id
  LEFT JOIN users mu ON mu.id = m.user_id";

fn scim_user_row(r: &Row) -> rusqlite::Result<ScimUser> {
    Ok(ScimUser {
        user: user_row(r)?,
        tenant: r.get("scim_tenant")?,
        external_id: r.get("scim_external_id")?,
        user_name: r.get("scim_user_name")?,
        given_name: r.get("scim_given_name")?,
        family_name: r.get("scim_family_name")?,
        display_name: r.get("scim_display_name")?,
        formatted: r.get("scim_formatted")?,
        created_at: r.get("scim_created_at")?,
        updated_at: r.get("scim_updated_at")?,
        deleted_at: r.get("scim_deleted_at")?,
        enterprise: Enterprise {
            employee_number: r.get("scim_employee_number")?,
            cost_center: r.get("scim_cost_center")?,
            organization: r.get("scim_organization")?,
            division: r.get("scim_division")?,
            department: r.get("scim_department")?,
            manager: r.get("scim_manager")?,
        },
        manager_name: r.get("scim_manager_name")?,
    })
}

/// The Enterprise User extension (RFC 7643 section 4.3) as a tenant set it. `manager` is
/// the user id of someone this tenant provisioned and hasn't deleted; read back, a
/// manager who has since been deleted (or moved tenant) is None.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Enterprise {
    pub employee_number: Option<String>,
    pub cost_center: Option<String>,
    pub organization: Option<String>,
    pub division: Option<String>,
    pub department: Option<String>,
    pub manager: Option<String>,
}

impl Enterprise {
    pub fn is_empty(&self) -> bool {
        *self == Enterprise::default()
    }
}

/// How a SCIM tenant looks users up: `userName` (any case) or `externalId` (exactly).
#[derive(Clone, Debug, PartialEq)]
pub enum ScimKey {
    UserName(String),
    ExternalId(String),
}

/// What SCIM sets on a user. Never the role.
pub struct ScimFields<'a> {
    pub user_name: &'a str,
    pub external_id: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    /// What the IdP sent, if anything.
    pub scim_display_name: Option<&'a str>,
    pub formatted: Option<&'a str>,
    /// The name SuperBot shows.
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    /// None leaves the status as it is now, so an update that doesn't change `active`
    /// can't undo an admin's disable that landed after it read the user.
    pub active: Option<bool>,
    pub enterprise: &'a Enterprise,
}

/// Why a SCIM write was refused: something unique is someone else's already.
#[derive(Debug, PartialEq)]
pub enum ScimConflict {
    Email,
    UserName,
    ExternalId,
    Identity,
    /// The user belongs to another SCIM tenant, deleted there or not.
    OtherTenant,
    /// Deleted (or never this tenant's) by the time the write ran.
    Gone,
    /// Making the user active needs a seat, and none is free (ADR 0038).
    NoSeat,
    Db(String),
}

fn scim_conflict(e: rusqlite::Error) -> ScimConflict {
    let msg = e.to_string();
    match () {
        _ if !constraint(&e) => ScimConflict::Db(msg),
        _ if msg.contains("users.email") => ScimConflict::Email,
        _ if msg.contains("external_id") => ScimConflict::ExternalId,
        _ if msg.contains("user_name") => ScimConflict::UserName,
        _ if msg.contains("user_identities") => ScimConflict::Identity,
        _ => ScimConflict::Db(msg),
    }
}

/// A SCIM tenant's group: the team it is (ADR 0095). Its SCIM `id` is the team's id.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub team_id: String,
    pub tenant: String,
    pub external_id: Option<String>,
    /// As the IdP (or the admin who linked it) named it. The team's name follows it.
    pub display_name: String,
    /// `scim`: a SCIM `POST` made the team. `admin`: an admin linked a team that existed.
    pub origin: String,
    /// When the IdP created or took on the group. None: an admin's link it hasn't yet.
    pub provisioned_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
}

fn scim_group_row(r: &Row) -> rusqlite::Result<ScimGroup> {
    Ok(ScimGroup {
        team_id: r.get("team_id")?,
        tenant: r.get("tenant")?,
        external_id: r.get("external_id")?,
        display_name: r.get("display_name")?,
        origin: r.get("origin")?,
        provisioned_at: r.get("provisioned_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
    })
}

/// Why a group link wasn't written: something unique in the tenant is another group's,
/// or the team is a group already.
#[derive(Debug, PartialEq)]
pub enum ScimGroupConflict {
    DisplayName,
    ExternalId,
    Team,
    Gone,
    Db(String),
}

fn scim_group_conflict(e: rusqlite::Error) -> ScimGroupConflict {
    let msg = e.to_string();
    match () {
        _ if !constraint(&e) => ScimGroupConflict::Db(msg),
        _ if msg.contains("FOREIGN KEY") => ScimGroupConflict::Gone,
        _ if msg.contains("external_id") => ScimGroupConflict::ExternalId,
        _ if msg.contains("display_name") => ScimGroupConflict::DisplayName,
        _ if msg.contains("team_id") => ScimGroupConflict::Team,
        _ => ScimGroupConflict::Db(msg),
    }
}

#[derive(Debug, PartialEq)]
pub enum JitError {
    /// Another user has this email. Never merged by email: ask an admin to link instead.
    EmailTaken,
    /// Another sign-in linked this identity first.
    IdentityTaken,
    /// Every seat is taken (ADR 0038).
    NoSeat,
    Database,
}

/// Why a user wasn't added or changed.
#[derive(Debug, PartialEq)]
pub enum UserError {
    EmailTaken,
    /// Every seat the license allows is taken, or there is no license (ADR 0038, ADR 0068).
    NoSeat,
    Db(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UserError::EmailTaken => f.write_str("A user with that email already exists"),
            UserError::NoSeat => f.write_str("No seats left"),
            UserError::Db(e) => f.write_str(e),
        }
    }
}

fn constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

fn user_row(r: &Row) -> rusqlite::Result<User> {
    let role: String = r.get("role")?;
    let (role_id, role_expires_at) = held_until(r.get("role_id")?, r.get("role_expires_at")?);
    Ok(User {
        id: r.get("id")?,
        email: r.get("email")?,
        name: r.get("display_name")?,
        role: Role::parse(&role).unwrap_or(Role::Readonly),
        status: r.get("status")?,
        idp_issuer: r.get("idp_issuer")?,
        idp_subject: r.get("idp_subject")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        last_login_at: r.get("last_login_at")?,
        last_login_method: r.get("last_login_method")?,
        last_login_idp_provider: r.get("last_login_idp_provider")?,
        tier: r.get("tier")?,
        region: r.get("region")?,
        erased_at: r.get("erased_at")?,
        erased_as: r.get("erased_as")?,
        role_id,
        role_expires_at,
        service: r.get::<_, String>("kind")? == "service",
    })
}

fn service_account_row(r: &Row) -> rusqlite::Result<ServiceAccount> {
    Ok(ServiceAccount {
        user: user_row(r)?,
        description: r.get("sa_description")?,
        owner_id: r.get("sa_owner")?,
        team_id: r.get("sa_team")?,
        team_role_id: r.get("sa_team_role")?,
        created_by: r.get("sa_created_by")?,
        deleted_at: r.get("sa_deleted_at")?,
    })
}

fn service_token_row(r: &Row) -> rusqlite::Result<ServiceToken> {
    let scopes: Option<String> = r.get("scopes")?;
    Ok(ServiceToken {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        name: r.get("name")?,
        hint: r.get("hint")?,
        scopes: scopes.map(|s| serde_json::from_str(&s).unwrap_or_default()),
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        expires_at: r.get("expires_at")?,
        last_used_at: r.get("last_used_at")?,
        last_used_ip: r.get("last_used_ip")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
        revoked_reason: r.get("revoked_reason")?,
        rotated_to: r.get("rotated_to")?,
    })
}

fn custom_role_row(r: &Row) -> rusqlite::Result<CustomRole> {
    let base: String = r.get("base")?;
    let permissions: String = r.get("permissions")?;
    Ok(CustomRole {
        id: r.get("id")?,
        name: r.get("name")?,
        description: r.get("description")?,
        // The CHECK allows only these two; anything else reads as the lesser.
        base: if base == "member" { Role::Member } else { Role::Readonly },
        permissions: serde_json::from_str(&permissions).unwrap_or_default(),
        max_days: r.get("max_days")?,
        requestable: r.get::<_, Option<bool>>("requestable")?.unwrap_or(false),
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
    })
}

/// A SCIM group mapped to a custom role (ADR 0138): the group's members get the role
/// across the server (`org`) or within the group's team (`team`) while they're in it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleMapping {
    pub id: String,
    pub tenant: String,
    pub team_id: String,
    pub role_id: String,
    /// "org" or "team".
    pub scope: String,
    pub created_at: i64,
    pub created_by: Option<String>,
}

fn scim_role_mapping_row(r: &Row) -> rusqlite::Result<ScimRoleMapping> {
    Ok(ScimRoleMapping {
        id: r.get("id")?,
        tenant: r.get("tenant")?,
        team_id: r.get("team_id")?,
        role_id: r.get("role_id")?,
        scope: r.get("scope")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
    })
}

/// A role a mapping gave someone, so taking it away touches only what SCIM gave.
/// `prior_role` is their built-in role before an `org` grant, given back after.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleGrant {
    pub mapping_id: String,
    pub user_id: String,
    pub scope: String,
    pub prior_role: Option<Role>,
    pub granted_at: i64,
}

fn scim_role_grant_row(r: &Row) -> rusqlite::Result<ScimRoleGrant> {
    let prior: Option<String> = r.get("prior_role")?;
    Ok(ScimRoleGrant {
        mapping_id: r.get("mapping_id")?,
        user_id: r.get("user_id")?,
        scope: r.get("scope")?,
        prior_role: prior.as_deref().and_then(Role::parse).filter(|r| *r != Role::Admin),
        granted_at: r.get("granted_at")?,
    })
}

#[derive(Debug, PartialEq)]
pub enum ScimRoleMapError {
    /// The group has a mapping for this scope already.
    Taken,
    /// The group's link, or the role, went meanwhile.
    Gone,
    /// The role holds these permissions, which reach admins in the scope.
    Reaches(Vec<&'static str>),
    /// The role is time-bound (ADR 0197): only given by hand, with an end.
    TimeBound,
    Db(String),
}

/// A SCIM role group (ADR 0180): a tenant's group an admin declared to give one custom
/// role, across the server or (ADR 0206) within the team each member is on, and nothing
/// else. It is not a team, so people can be in any number of them. Its SCIM `id` is
/// `id`. Until the IdP pushes a group with its `externalId` (or, with none declared, its
/// `displayName`), it waits, unseen by the IdP.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleGroup {
    pub id: String,
    pub tenant: String,
    /// `org` (across the server) or `team` (within the member's team, ADR 0206). Fixed
    /// when declared.
    pub scope: String,
    pub display_name: String,
    /// What the admin declared, given back when the IdP deletes the group.
    pub declared_display_name: String,
    /// The IdP's, once it pushed the group; until then the declared one, if any.
    pub external_id: Option<String>,
    /// What the admin declared: the IdP's group must carry it to be taken on.
    pub declared_external_id: Option<String>,
    pub role_id: String,
    /// When the IdP took it on. None: waiting.
    pub provisioned_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
}

fn scim_role_group_row(r: &Row) -> rusqlite::Result<ScimRoleGroup> {
    Ok(ScimRoleGroup {
        id: r.get("id")?,
        tenant: r.get("tenant")?,
        scope: r.get("scope")?,
        display_name: r.get("display_name")?,
        declared_display_name: r.get("declared_display_name")?,
        external_id: r.get("external_id")?,
        declared_external_id: r.get("declared_external_id")?,
        role_id: r.get("role_id")?,
        provisioned_at: r.get("provisioned_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
    })
}

/// The role a role group gave someone, one per person, so taking it away touches only
/// what the group gave. `role_id` is the role it gave, which stays the one taken away
/// even after the group names another. `prior_role` is their built-in role before, given
/// back after.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleGroupGrant {
    pub group_id: String,
    pub user_id: String,
    pub role_id: String,
    pub prior_role: Option<Role>,
    pub granted_at: i64,
    /// The team it was given in, for a team role group (ADR 0206); None across the server.
    pub team_id: Option<String>,
}

fn scim_role_group_grant_row(r: &Row) -> rusqlite::Result<ScimRoleGroupGrant> {
    let prior: Option<String> = r.get("prior_role")?;
    Ok(ScimRoleGroupGrant {
        group_id: r.get("group_id")?,
        user_id: r.get("user_id")?,
        role_id: r.get("role_id")?,
        prior_role: prior.as_deref().and_then(Role::parse).filter(|r| *r != Role::Admin),
        granted_at: r.get("granted_at")?,
        team_id: r.get("team_id")?,
    })
}

/// Role groups' grants of both scopes, in one shape: a group has one scope, so only one
/// of the two tables has rows for it.
const SCIM_ROLE_GROUP_GRANTS: &str = "SELECT group_id, user_id, role_id, prior_role, granted_at, NULL AS team_id FROM scim_role_group_grants
     UNION ALL SELECT group_id, user_id, role_id, NULL AS prior_role, granted_at, team_id FROM scim_role_group_team_grants";

/// Why a role group wasn't written.
#[derive(Debug, PartialEq)]
pub enum ScimRoleGroupError {
    DisplayName,
    ExternalId,
    /// The group, or the role, went meanwhile.
    Gone,
    /// The role holds these permissions, which reach admins in the group's scope.
    Reaches(Vec<&'static str>),
    /// The role is time-bound (ADR 0197): only given by hand, with an end.
    TimeBound,
    Db(String),
}

/// What reaches admins in a role group's scope: across the server, or within a team.
fn scim_role_group_reach(perms: crate::rbac::Perms, scope: &str) -> Vec<&'static str> {
    perms.reaching_admins(scope == "team")
}

fn scim_role_group_error(e: rusqlite::Error) -> ScimRoleGroupError {
    let msg = e.to_string();
    match () {
        _ if !constraint(&e) => ScimRoleGroupError::Db(msg),
        _ if msg.contains("FOREIGN KEY") => ScimRoleGroupError::Gone,
        _ if msg.contains("external_id") => ScimRoleGroupError::ExternalId,
        _ if msg.contains("display_name") => ScimRoleGroupError::DisplayName,
        _ => ScimRoleGroupError::Db(msg),
    }
}

/// A native SAML provider's group mapped to a custom role across the server (ADR 0160):
/// people the IdP's signed assertion puts in `group` get the role when they sign in, and
/// lose it when a later sign-in no longer does.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlRoleMapping {
    pub id: String,
    pub provider: String,
    pub group: String,
    pub role_id: String,
    pub created_at: i64,
    pub created_by: Option<String>,
}

fn saml_role_mapping_row(r: &Row) -> rusqlite::Result<SamlRoleMapping> {
    Ok(SamlRoleMapping { id: r.get("id")?, provider: r.get("provider")?, group: r.get("group_name")?, role_id: r.get("role_id")?, created_at: r.get("created_at")?, created_by: r.get("created_by")? })
}

/// A role a SAML mapping gave someone, at most one per person (a person holds one custom
/// role across the server). `prior_role` is their built-in role before, given back after.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlRoleGrant {
    pub mapping_id: String,
    pub user_id: String,
    pub prior_role: Option<Role>,
    pub granted_at: i64,
}

fn saml_role_grant_row(r: &Row) -> rusqlite::Result<SamlRoleGrant> {
    let prior: Option<String> = r.get("prior_role")?;
    Ok(SamlRoleGrant {
        mapping_id: r.get("mapping_id")?,
        user_id: r.get("user_id")?,
        prior_role: prior.as_deref().and_then(Role::parse).filter(|r| *r != Role::Admin),
        granted_at: r.get("granted_at")?,
    })
}

/// What taking a SCIM (or SAML) grant away did: whether the role was still theirs to clear,
/// and, across the server, their built-in role before and after.
#[derive(Debug, PartialEq)]
pub struct ScimRevoked {
    pub cleared: bool,
    pub role_before: Option<Role>,
    pub role_after: Option<Role>,
}

/// A role given or taken away by hand: what they held just before, read in the same
/// transaction as the write, and the SCIM (or, across the server, SAML) mapping whose claim
/// on it ended, if one had.
#[derive(Debug, PartialEq)]
pub struct ByHand<T> {
    pub before: T,
    pub taken: Option<String>,
    pub taken_saml: Option<String>,
}

fn session_row(r: &Row) -> rusqlite::Result<Session> {
    Ok(Session {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        kind: r.get("kind")?,
        method: r.get("method")?,
        idp_subject: r.get("idp_subject")?,
        idp_provider: r.get("idp_provider")?,
        label: r.get("label")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        created_at: r.get("created_at")?,
        last_seen_at: r.get("last_seen_at")?,
        expires_at: r.get("expires_at")?,
        revoked_at: r.get("revoked_at")?,
        revoked_by: r.get("revoked_by")?,
        revoke_reason: r.get("revoke_reason")?,
        mfa: r.get("mfa")?,
    })
}

/// None when the sealed token doesn't open (another master key): such a device can't be reached.
fn push_device_row(r: &Row) -> rusqlite::Result<Option<PushDevice>> {
    let Some(token) = sealed::open_field(PUSH_TOKEN_CONTEXT, &r.get::<_, String>("token")?) else { return Ok(None) };
    Ok(Some(PushDevice {
        id: r.get("id")?,
        user_id: r.get("user_id")?,
        provider: r.get("provider")?,
        token,
        platform: r.get("platform")?,
        approvals: r.get("approvals")?,
        routines: r.get("routines")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
    }))
}

/// SQL for "this session still works": not revoked, before its absolute expiry
/// (the stored one and `created_at + max`, so lowering the setting applies to
/// existing sessions), and used within the idle window. Binds `?1` now, `?2` idle ms, `?3` max ms.
const SESSION_LIVE: &str = "s.revoked_at IS NULL AND ?1 < s.expires_at AND ?1 < s.created_at + ?3 AND ?1 < s.last_seen_at + ?2";

fn approval_row(r: &Row) -> rusqlite::Result<Approval> {
    let input: String = r.get("input")?;
    Ok(Approval {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        harness: r.get("harness")?,
        tool: r.get("tool")?,
        kind: r.get("kind")?,
        subject: r.get("subject")?,
        input: match sealed::open_field(&sealed::approval_context(&r.get::<_, String>("id")?), &input) {
            Some(input) => serde_json::from_str(&input).unwrap_or(Value::Null),
            None => serde_json::json!({ "sealed": "unreadable" }),
        },
        class: r.get("class")?,
        reason: r.get("reason")?,
        status: r.get("status")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        decided_at: r.get("decided_at")?,
        decided_by: r.get("decided_by")?,
        note: r.get("note")?,
        rule_id: r.get("rule_id")?,
        run_id: r.get("run_id")?,
        run_scope: r.get::<_, Option<String>>("run_scope")?.and_then(|s| serde_json::from_str(&s).ok()),
        scope: r.get("scope")?,
    })
}

fn rule_row(r: &Row) -> rusqlite::Result<Rule> {
    let action: String = r.get("action")?;
    Ok(Rule {
        id: r.get("id")?,
        bot_id: r.get("bot_id")?,
        action: if action == "allow" { Action::Allow } else { Action::Deny },
        tool: r.get("tool")?,
        pattern: r.get("pattern")?,
        note: r.get("note")?,
        created_at: r.get("created_at")?,
    })
}

fn audit_row(r: &Row) -> rusqlite::Result<AuditEvent> {
    let details: String = r.get("details")?;
    let at: i64 = r.get("at")?;
    Ok(AuditEvent {
        id: r.get("id")?,
        at,
        time: chrono::DateTime::from_timestamp_millis(at)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_default(),
        actor_kind: r.get("actor_kind")?,
        actor_id: r.get("actor_id")?,
        actor_name: r.get("actor_name")?,
        actor_subject: r.get("actor_subject")?,
        action: r.get("action")?,
        target_type: r.get("target_type")?,
        target_id: r.get("target_id")?,
        bot_id: r.get("bot_id")?,
        outcome: r.get("outcome")?,
        ip: r.get("ip")?,
        user_agent: r.get("user_agent")?,
        details: redact::value(serde_json::from_str(&details).unwrap_or(Value::Null)),
        actor_email: r.get("actor_email")?,
        actor_role: r.get("actor_role")?,
        auth_method: r.get("auth_method")?,
        idp: r.get("idp")?,
        idp_provider: r.get("idp_provider")?,
        session_id: r.get("session_id")?,
        on_behalf_of: r.get("on_behalf_of")?,
        chain_prev: r.get("chain_prev")?,
        chain_hash: r.get("chain_hash")?,
        chain_digest: r.get("chain_digest")?,
        chain_salt: r.get("chain_salt")?,
    })
}

/// Schema changes after the first release, in order. `PRAGMA user_version` is how many ran.
/// Each gets `fresh`: true when this database was just created.
const MIGRATIONS: [fn(&Connection, bool) -> rusqlite::Result<()>; 69] = [
    migrate_approvals,
    migrate_audit_events,
    migrate_users,
    migrate_identities,
    migrate_bot_acls,
    migrate_audit_actors,
    migrate_signups,
    migrate_last_login,
    migrate_scim,
    migrate_machines,
    migrate_tiers,
    migrate_machine_enrollment,
    migrate_machine_lockdown,
    migrate_machine_placement,
    migrate_machine_upkeep,
    migrate_billing,
    migrate_billing_customers,
    migrate_routine_authors,
    migrate_routine_pauses,
    migrate_token_usage,
    migrate_approval_runs,
    migrate_teammate_cleanups,
    migrate_bot_prompts,
    migrate_sandbox,
    migrate_machine_rebuild,
    migrate_account_removals,
    migrate_machine_backups,
    migrate_machine_recovery,
    migrate_machine_hosts,
    migrate_push_devices,
    migrate_machine_host_drain,
    migrate_teams,
    migrate_machine_tier_resize,
    migrate_machine_resize_sent,
    migrate_machine_suspended_at,
    migrate_status_incidents,
    migrate_billing_emails,
    migrate_team_billing,
    migrate_mfa,
    migrate_scim_groups,
    migrate_chat_retention,
    migrate_machine_home_use,
    migrate_user_erasure,
    migrate_machine_provider_backups,
    migrate_server_backups,
    migrate_file_retention,
    migrate_data_regions,
    migrate_disable_holds,
    migrate_custom_roles,
    migrate_residency_pins,
    migrate_saml_sessions,
    migrate_audit_chain,
    migrate_scim_group_roles,
    migrate_service_accounts,
    migrate_user_last_seen,
    migrate_audit_checkpoints,
    migrate_health_scores,
    migrate_saml_group_roles,
    migrate_machine_host_dedication,
    migrate_residency_kept_from,
    migrate_scim_enterprise,
    migrate_scim_role_groups,
    migrate_scim_token_expiry,
    migrate_saml_cert_notices,
    migrate_time_bound_roles,
    migrate_scim_team_role_groups,
    migrate_role_requests,
    migrate_service_account_bots,
    migrate_scim_token_scopes,
];

/// SCIM token scopes (ADR 0224): a JSON list of scope names. Tokens made before keep a
/// null, which is every scope, so upgrading changes nothing an IdP can do.
fn migrate_scim_token_scopes(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('scim_tokens') WHERE name = 'scopes'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch("ALTER TABLE scim_tokens ADD COLUMN scopes TEXT;")
}

/// Service accounts' own Bots (ADR 0222): a Bot a service account made names it. The Bot
/// is still its owner's (machine, plan, keys, memory); the account keeps it only while it's
/// live and owned by that same person. Triggers hold that whatever writes: a link is only
/// written to such an account, and goes when the Bot changes owner, or the account changes
/// owner or is deleted.
fn migrate_service_account_bots(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('bots') WHERE name = 'service_account_id'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE bots ADD COLUMN service_account_id TEXT REFERENCES users(id) ON DELETE SET NULL;")?;
    }
    c.execute_batch(
        "CREATE INDEX IF NOT EXISTS bots_service_account ON bots(service_account_id) WHERE service_account_id IS NOT NULL;
        CREATE TRIGGER IF NOT EXISTS bots_service_account_insert BEFORE INSERT ON bots
        WHEN NEW.service_account_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM service_accounts WHERE user_id = NEW.service_account_id AND owner_id = NEW.owner_id AND deleted_at IS NULL)
        BEGIN
          SELECT RAISE(ABORT, 'a Bot can only be kept by a live service account of its owner');
        END;
        CREATE TRIGGER IF NOT EXISTS bots_service_account_update BEFORE UPDATE OF service_account_id ON bots
        WHEN NEW.service_account_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM service_accounts WHERE user_id = NEW.service_account_id AND owner_id = NEW.owner_id AND deleted_at IS NULL)
        BEGIN
          SELECT RAISE(ABORT, 'a Bot can only be kept by a live service account of its owner');
        END;
        CREATE TRIGGER IF NOT EXISTS bots_service_account_owner AFTER UPDATE OF owner_id ON bots
        WHEN NEW.service_account_id IS NOT NULL AND NEW.owner_id IS NOT OLD.owner_id
        BEGIN
          UPDATE bots SET service_account_id = NULL WHERE id = NEW.id;
        END;
        CREATE TRIGGER IF NOT EXISTS service_accounts_release_bots AFTER UPDATE OF owner_id, deleted_at ON service_accounts
        WHEN NEW.deleted_at IS NOT NULL OR NEW.owner_id IS NOT OLD.owner_id
        BEGIN
          UPDATE bots SET service_account_id = NULL WHERE service_account_id = NEW.user_id AND (NEW.deleted_at IS NOT NULL OR owner_id IS NOT NEW.owner_id);
        END;",
    )
}

fn kept_in(c: &Connection, account: &str) -> rusqlite::Result<Vec<String>> {
    let mut s = c.prepare("SELECT id FROM bots WHERE service_account_id = ? ORDER BY created_at, id")?;
    s.query_map([account], |r| r.get(0))?.collect()
}

/// Requests for a role (ADR 0209): a person asks for a requestable, time-bound role for
/// some hours, across the server or in their team, and an admin approves or denies it.
/// One pending request per person, role and scope. A request goes with its role, team
/// or person; the audit log keeps its story.
fn migrate_role_requests(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('roles') WHERE name = 'requestable'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE roles ADD COLUMN requestable INTEGER NOT NULL DEFAULT 0;")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS role_requests (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
          team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
          hours INTEGER NOT NULL CHECK (hours > 0),
          reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'lapsed')),
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          decided_at INTEGER,
          decided_by TEXT,
          note TEXT,
          granted_until INTEGER,
          lapse TEXT
        );
        -- A pending request lapses the moment its role stops being requestable or its person
        -- stops being active, even if that's undone before the sweep audits it.
        CREATE TRIGGER IF NOT EXISTS role_requests_lapse_role AFTER UPDATE OF requestable, max_days ON roles
        WHEN NEW.requestable = 0 OR NEW.max_days IS NULL
        BEGIN
          UPDATE role_requests SET lapse = COALESCE(lapse, 'not_requestable') WHERE role_id = NEW.id AND status = 'pending';
        END;
        CREATE TRIGGER IF NOT EXISTS role_requests_lapse_user AFTER UPDATE OF status ON users
        WHEN NEW.status != 'active'
        BEGIN
          UPDATE role_requests SET lapse = COALESCE(lapse, 'disabled') WHERE user_id = NEW.id AND status = 'pending';
        END;
        CREATE UNIQUE INDEX IF NOT EXISTS role_requests_one_pending ON role_requests(user_id, role_id, COALESCE(team_id, '')) WHERE status = 'pending';
        CREATE INDEX IF NOT EXISTS role_requests_status ON role_requests(status, created_at);
        CREATE INDEX IF NOT EXISTS role_requests_user ON role_requests(user_id, created_at);",
    )
}

/// Time-bound custom roles (ADR 0197): when a role given by hand ends, across the server
/// and within a team, and the most days a role may be given for. An end belongs to the
/// role it was given with: anything that changes `role_id` without setting it (SCIM, SAML,
/// a built-in role, erasure) clears it, so it never ends a role given another way.
fn migrate_time_bound_roles(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for (table, column) in [("roles", "max_days"), ("users", "role_expires_at"), ("team_members", "role_expires_at")] {
        let has: bool = c.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"), [], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} INTEGER;"))?;
        }
    }
    c.execute_batch(
        "CREATE INDEX IF NOT EXISTS users_role_expiry ON users(role_expires_at) WHERE role_expires_at IS NOT NULL;
        CREATE INDEX IF NOT EXISTS team_members_role_expiry ON team_members(role_expires_at) WHERE role_expires_at IS NOT NULL;
        CREATE TRIGGER IF NOT EXISTS users_role_end_follows AFTER UPDATE OF role_id ON users
          WHEN NEW.role_id IS NOT OLD.role_id AND NEW.role_expires_at IS NOT NULL
          BEGIN UPDATE users SET role_expires_at = NULL WHERE id = NEW.id; END;
        CREATE TRIGGER IF NOT EXISTS team_members_role_end_follows AFTER UPDATE OF role_id ON team_members
          WHEN NEW.role_id IS NOT OLD.role_id AND NEW.role_expires_at IS NOT NULL
          BEGIN UPDATE team_members SET role_expires_at = NULL WHERE user_id = NEW.user_id; END;",
    )
}

/// Team role groups (ADR 0206): a role group's scope, `org` for every one made before,
/// and the team role each team role group gave, one per person, since a person is on one
/// team and holds one custom role in it. A grant's team is the one it was given in, so it
/// goes with that team.
fn migrate_scim_team_role_groups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('scim_role_groups') WHERE name = 'scope'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE scim_role_groups ADD COLUMN scope TEXT NOT NULL DEFAULT 'org' CHECK (scope IN ('org', 'team'));")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_role_group_team_grants (
          group_id TEXT NOT NULL REFERENCES scim_role_groups(id) ON DELETE CASCADE,
          user_id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          role_id TEXT NOT NULL,
          granted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS scim_role_group_team_grants_group ON scim_role_group_team_grants(group_id);
        CREATE INDEX IF NOT EXISTS scim_role_group_team_grants_team ON scim_role_group_team_grants(team_id);
        CREATE TABLE IF NOT EXISTS scim_pending_joins (
          user_id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          at INTEGER NOT NULL
        );",
    )
}

/// Which expiry notice was audited for each certificate a native SAML provider uses
/// (ADR 0198): `expiring`, then `expired`, once each.
fn migrate_saml_cert_notices(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS saml_cert_notices (
          provider TEXT NOT NULL,
          role TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          notice TEXT NOT NULL,
          at INTEGER NOT NULL,
          PRIMARY KEY (provider, role, sha256)
        );",
    )
}

/// Claims `notice` (`expiring` or `expired`) for one of a SAML provider's certificates, on
/// `c` (inside the transaction that audits it): `expiring` only if it had no notice, `expired`
/// only if it hadn't had that one. False when it was already given.
pub(crate) fn claim_saml_cert_notice(c: &Connection, provider: &str, role: &str, sha256: &str, notice: &str, at: i64) -> rusqlite::Result<bool> {
    let sql = if notice == "expired" {
        "INSERT INTO saml_cert_notices (provider, role, sha256, notice, at) VALUES (?1, ?2, ?3, 'expired', ?4)
         ON CONFLICT (provider, role, sha256) DO UPDATE SET notice = 'expired', at = excluded.at WHERE notice <> 'expired'"
    } else {
        "INSERT INTO saml_cert_notices (provider, role, sha256, notice, at) VALUES (?1, ?2, ?3, 'expiring', ?4)
         ON CONFLICT (provider, role, sha256) DO NOTHING"
    };
    Ok(c.execute(sql, params![provider, role, sha256, at])? == 1)
}

/// SCIM tokens expire and rotate (ADR 0196). Tokens made before this keep a null
/// `expires_at` and work as before: expiring them on upgrade would stop deprovisioning.
fn migrate_scim_token_expiry(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('scim_tokens') WHERE name = 'expires_at'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE scim_tokens ADD COLUMN expires_at INTEGER;
        ALTER TABLE scim_tokens ADD COLUMN rotated_to TEXT;
        ALTER TABLE scim_tokens ADD COLUMN expiry_notice TEXT;",
    )
}

/// SCIM role groups (ADR 0180): groups an admin declared to give a custom role across
/// the server, not teams; who the IdP put in each (any number of groups a person); and
/// the role each gave, one per person, since a person holds one custom role across the
/// server. `displayName` and `externalId` are unique per tenant here; that they don't
/// clash with a team group's is checked under the SCIM group write lock.
fn migrate_scim_role_groups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_role_groups (
          id TEXT PRIMARY KEY,
          tenant TEXT NOT NULL,
          display_name TEXT NOT NULL COLLATE NOCASE,
          declared_display_name TEXT NOT NULL,
          external_id TEXT,
          declared_external_id TEXT,
          role_id TEXT NOT NULL REFERENCES roles(id),
          provisioned_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS scim_role_groups_external_id ON scim_role_groups(tenant, external_id) WHERE external_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS scim_role_groups_display_name ON scim_role_groups(tenant, display_name);
        CREATE INDEX IF NOT EXISTS scim_role_groups_role ON scim_role_groups(role_id);
        CREATE TABLE IF NOT EXISTS scim_role_group_members (
          group_id TEXT NOT NULL REFERENCES scim_role_groups(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL,
          added_at INTEGER NOT NULL,
          PRIMARY KEY (group_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS scim_role_group_members_user ON scim_role_group_members(user_id);
        CREATE TABLE IF NOT EXISTS scim_role_group_grants (
          group_id TEXT NOT NULL REFERENCES scim_role_groups(id) ON DELETE CASCADE,
          user_id TEXT PRIMARY KEY,
          role_id TEXT NOT NULL,
          prior_role TEXT,
          granted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS scim_role_group_grants_group ON scim_role_group_grants(group_id);",
    )
}

/// The SCIM Enterprise User extension on provisioned users (ADR 0176). `manager_id` is
/// another user of the same tenant; it isn't a foreign key, since a manager's SCIM
/// DELETE keeps their row, and reads show a manager only while they're live there.
fn migrate_scim_enterprise(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('scim_users') WHERE name = 'department'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE scim_users ADD COLUMN employee_number TEXT;
        ALTER TABLE scim_users ADD COLUMN cost_center TEXT;
        ALTER TABLE scim_users ADD COLUMN organization TEXT;
        ALTER TABLE scim_users ADD COLUMN division TEXT;
        ALTER TABLE scim_users ADD COLUMN department TEXT;
        ALTER TABLE scim_users ADD COLUMN manager_id TEXT;
        CREATE INDEX IF NOT EXISTS scim_users_manager ON scim_users(manager_id) WHERE manager_id IS NOT NULL;",
    )
}

/// Native SAML groups mapped to custom roles across the server (ADR 0160): one role per
/// provider and group, and the grants they made, one per person. A grant whose role was
/// then changed by hand is kept as released (`released_at`), so the group doesn't give it
/// back until a sign-in no longer lists the group. A mapped role can't be deleted. Grants
/// are taken away before their mapping is deleted.
fn migrate_saml_group_roles(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS saml_role_mappings (
          id TEXT PRIMARY KEY,
          provider TEXT NOT NULL,
          group_name TEXT NOT NULL,
          role_id TEXT NOT NULL REFERENCES roles(id),
          created_at INTEGER NOT NULL,
          created_by TEXT,
          UNIQUE (provider, group_name)
        );
        CREATE INDEX IF NOT EXISTS saml_role_mappings_role ON saml_role_mappings(role_id);
        CREATE TABLE IF NOT EXISTS saml_role_grants (
          mapping_id TEXT NOT NULL REFERENCES saml_role_mappings(id) ON DELETE CASCADE,
          user_id TEXT PRIMARY KEY,
          prior_role TEXT,
          granted_at INTEGER NOT NULL,
          released_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS saml_role_grants_mapping ON saml_role_grants(mapping_id);",
    )
}

/// A host an admin dedicated to one team (ADR 0166): only that team's machines go
/// there, and the team's machines go nowhere else. No foreign key: a host dedicated to
/// a team that is then deleted stays closed to everyone until an admin shares it.
fn migrate_machine_host_dedication(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_hosts') WHERE name = 'dedicated_team'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machine_hosts ADD COLUMN dedicated_team TEXT;
        ALTER TABLE machine_hosts ADD COLUMN dedicated_at INTEGER;
        ALTER TABLE machine_hosts ADD COLUMN dedicated_by TEXT;
        ALTER TABLE machine_hosts ADD COLUMN dedication_reason TEXT;",
    )
}

/// Signed checkpoints of the audit chain's head, and their RFC 3161 tokens (ADR 0149). A
/// row is keyed by the `audit.checkpoint` event that carries it. What was signed never
/// changes, and a token once stored stays; pruning deletes a row with its event, or its
/// timestamp event when that came later.
fn migrate_audit_checkpoints(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_checkpoints (
          event_id INTEGER PRIMARY KEY,
          at INTEGER NOT NULL,
          seq INTEGER NOT NULL,
          hash TEXT NOT NULL,
          key_id TEXT NOT NULL,
          public_key TEXT NOT NULL,
          signature TEXT NOT NULL,
          tsa_status TEXT NOT NULL,
          tsa TEXT,
          tsa_token TEXT,
          tsa_time INTEGER,
          tsa_nonce TEXT,
          tsa_tries INTEGER NOT NULL DEFAULT 0,
          tsa_error TEXT,
          tsa_event_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS audit_checkpoints_pending ON audit_checkpoints(tsa_status, event_id);
        CREATE TRIGGER IF NOT EXISTS audit_checkpoints_signed BEFORE UPDATE ON audit_checkpoints
          WHEN NEW.event_id IS NOT OLD.event_id OR NEW.at IS NOT OLD.at OR NEW.seq IS NOT OLD.seq OR NEW.hash IS NOT OLD.hash
            OR NEW.key_id IS NOT OLD.key_id OR NEW.public_key IS NOT OLD.public_key OR NEW.signature IS NOT OLD.signature
            OR (OLD.tsa_token IS NOT NULL AND (NEW.tsa_token IS NOT OLD.tsa_token OR NEW.tsa_time IS NOT OLD.tsa_time
              OR NEW.tsa_nonce IS NOT OLD.tsa_nonce OR NEW.tsa_event_id IS NOT OLD.tsa_event_id OR NEW.tsa_status IS NOT OLD.tsa_status))
          BEGIN SELECT RAISE(ABORT, 'audit checkpoints are signed: only a missing timestamp can be added'); END;",
    )
}
/// The customer health score once a day (ADR 0157): counts' verdicts only, no one named.
fn migrate_health_scores(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS health_scores (
          day TEXT PRIMARY KEY,
          at INTEGER NOT NULL,
          window_days INTEGER NOT NULL,
          score INTEGER,
          band TEXT NOT NULL,
          signals TEXT NOT NULL
        );",
    )
}

/// Native SAML sign-ins' NameID and SessionIndex (ADR 0137), for single logout. Gone with
/// their session, however that goes (pruned, or its user erased).
fn migrate_saml_sessions(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS saml_sessions (
          session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
          name_id TEXT NOT NULL,
          name_id_format TEXT,
          name_qualifier TEXT,
          sp_name_qualifier TEXT,
          session_index TEXT
        );",
    )
}

/// SCIM groups mapped to custom roles (ADR 0138): one mapping per group and scope, and
/// the grants each made, one per person and scope (a person is in one group at most).
/// A mapping goes with its team; its people have left the team by then, which took the
/// grants away. A mapped role can't be deleted.
fn migrate_scim_group_roles(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_role_mappings (
          id TEXT PRIMARY KEY,
          tenant TEXT NOT NULL,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          role_id TEXT NOT NULL REFERENCES roles(id),
          scope TEXT NOT NULL CHECK (scope IN ('org', 'team')),
          created_at INTEGER NOT NULL,
          created_by TEXT,
          UNIQUE (team_id, scope)
        );
        CREATE INDEX IF NOT EXISTS scim_role_mappings_role ON scim_role_mappings(role_id);
        CREATE TABLE IF NOT EXISTS scim_role_grants (
          mapping_id TEXT NOT NULL REFERENCES scim_role_mappings(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL,
          scope TEXT NOT NULL CHECK (scope IN ('org', 'team')),
          prior_role TEXT,
          granted_at INTEGER NOT NULL,
          PRIMARY KEY (user_id, scope)
        );
        CREATE INDEX IF NOT EXISTS scim_role_grants_mapping ON scim_role_grants(mapping_id);",
    )
}

/// Service accounts (ADR 0143): `users` rows of kind `service`, which hold a built-in or
/// custom role like anyone (never admin: the triggers refuse it), with no email, sign-in
/// or session; what only they have; and their API tokens, kept as hashes. A token is
/// never deleted, so the audit log's token ids keep meaning something.
fn migrate_service_accounts(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'kind'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'service'));")?;
    }
    c.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS service_accounts_never_admin_insert BEFORE INSERT ON users
           WHEN NEW.kind = 'service' AND (NEW.role = 'admin' OR NEW.email IS NOT NULL)
           BEGIN SELECT RAISE(ABORT, 'a service account is never an admin and has no email'); END;
         CREATE TRIGGER IF NOT EXISTS service_accounts_never_admin_update BEFORE UPDATE ON users
           WHEN NEW.kind != OLD.kind OR (NEW.kind = 'service' AND (NEW.role = 'admin' OR NEW.email IS NOT NULL))
           BEGIN SELECT RAISE(ABORT, 'a service account is never an admin and has no email, and no one changes kind'); END;
         CREATE TABLE IF NOT EXISTS service_accounts (
           user_id TEXT PRIMARY KEY REFERENCES users(id),
           description TEXT NOT NULL DEFAULT '',
           owner_id TEXT NOT NULL REFERENCES users(id),
           team_id TEXT,
           team_role_id TEXT REFERENCES roles(id),
           created_by TEXT,
           created_at INTEGER NOT NULL,
           deleted_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS service_accounts_owner ON service_accounts(owner_id);
         CREATE TABLE IF NOT EXISTS service_tokens (
           id TEXT PRIMARY KEY,
           account_id TEXT NOT NULL REFERENCES users(id),
           name TEXT NOT NULL,
           token_hash TEXT NOT NULL UNIQUE,
           hint TEXT NOT NULL,
           scopes TEXT,
           created_at INTEGER NOT NULL,
           created_by TEXT,
           expires_at INTEGER NOT NULL,
           last_used_at INTEGER,
           last_used_ip TEXT,
           revoked_at INTEGER,
           revoked_by TEXT,
           revoked_reason TEXT,
           rotated_to TEXT
         );
         CREATE INDEX IF NOT EXISTS service_tokens_account ON service_tokens(account_id, created_at);",
    )
}

/// When each user last used a session or API token (ADR 0144), kept on the user so it
/// outlives the session row, which is pruned 30 days after it stops working.
fn migrate_user_last_seen(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'last_seen_at'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE users ADD COLUMN last_seen_at INTEGER;
             UPDATE users SET last_seen_at = (SELECT max(s.last_seen_at) FROM sessions s WHERE s.user_id = users.id);",
        )?;
    }
    Ok(())
}

/// Contractual residency pins (ADR 0129): one per user or team at most.
fn migrate_residency_pins(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS residency_pins (
          subject_type TEXT NOT NULL,
          subject_id TEXT NOT NULL,
          region TEXT NOT NULL,
          reference TEXT NOT NULL,
          pinned_by TEXT,
          pinned_at INTEGER NOT NULL,
          PRIMARY KEY (subject_type, subject_id)
        );",
    )
}

/// A user's pin kept from their team's when they left it (ADR 0171): the team it came from.
fn migrate_residency_kept_from(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('residency_pins') WHERE name = 'kept_from'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE residency_pins ADD COLUMN kept_from TEXT;")?;
    }
    Ok(())
}

/// Machines suspended because their user was disabled (ADR 0124), so enabling them
/// resumes those and no other.
fn migrate_disable_holds(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_disable_holds (
          machine_id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          via TEXT NOT NULL,
          held_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS machine_disable_holds_user ON machine_disable_holds(user_id);",
    )
}

/// Tamper evidence (ADR 0122): every audit row sealed onto a hash chain. Rows already
/// there are sealed now, in order, so the chain covers the whole log from here on; an
/// upgrade records where that happened, as rows before it were sealed at the upgrade,
/// not when written. A trigger refuses rows without a seal, and the erasure exception
/// to the update trigger must keep the seal and drop the salt.
fn migrate_audit_chain(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    for col in crate::audit_chain::COLUMNS {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE audit_events ADD COLUMN {col} TEXT;"))?;
        }
    }
    c.execute_batch("DROP TRIGGER IF EXISTS audit_events_no_update; DROP TRIGGER IF EXISTS audit_events_sealed;")?;
    let (sealed, through) = crate::audit_chain::seal_existing(c)?;
    c.execute_batch(&format!(
        "{}
        CREATE TRIGGER audit_events_sealed BEFORE INSERT ON audit_events
          WHEN NEW.chain_prev IS NULL OR NEW.chain_hash IS NULL OR NEW.chain_digest IS NULL
          BEGIN SELECT RAISE(ABORT, 'audit_events rows must be sealed onto the hash chain'); END;",
        audit_update_trigger(true)
    ))?;
    if !fresh && sealed > 0 {
        let details = serde_json::json!({
            "added": crate::audit_chain::COLUMNS,
            "sealed": sealed,
            "through": through,
            "reason": "tamper evidence: a hash chain over every event; events up to this one were sealed at this upgrade",
        });
        crate::audit_chain::insert_system(c, "migration", "audit.schema_upgraded", ("audit", "chain"), &details)?;
    }
    Ok(())
}

/// Custom roles (ADR 0123): a base built-in role and a fixed set of admin permissions on
/// top. `users.role_id` is a person's role across the server, and `users.role` stays its
/// base, so every check that reads the built-in role keeps working. `team_members.role_id`
/// is a role given within their team, and goes when they leave it. A role still given to
/// someone can't be deleted (the foreign keys refuse it as well).
fn migrate_custom_roles(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS roles (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL COLLATE NOCASE UNIQUE,
          description TEXT NOT NULL DEFAULT '',
          base TEXT NOT NULL CHECK (base IN ('member', 'readonly')),
          permissions TEXT NOT NULL DEFAULT '[]',
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL
        );",
    )?;
    for table in ["users", "team_members"] {
        let has: bool = c.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'role_id'"), [], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN role_id TEXT REFERENCES roles(id);
                 CREATE INDEX IF NOT EXISTS {table}_role ON {table}(role_id) WHERE role_id IS NOT NULL;"
            ))?;
        }
    }
    Ok(())
}

/// Data regions (ADR 0117): the region an admin set for a user or a team, and the
/// region whose store each machine backup went to (NULL: the default store).
fn migrate_data_regions(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for (table, column) in [("users", "region"), ("teams", "region"), ("machine_backups", "store_region")] {
        let has: bool = c.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"), [], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT;"))?;
        }
    }
    Ok(())
}

/// Retention for teammates' archived work (ADR 0112): when the retention pass deleted a
/// removal's archive, or found it gone.
fn migrate_file_retention(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for table in ["teammate_cleanups", "account_removals"] {
        let has: bool = c.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'archive_pruned_at'"), [], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN archive_pruned_at INTEGER;"))?;
        }
    }
    Ok(())
}

/// Off-host copies of the server's own backup archives (ADR 0109): `running`, then `done`
/// or `failed`, and `deleted` once past their retention. One runs at a time. An archive
/// that failed is tried again, so it can have several rows. `destination` is the store
/// and folder it went to: a copy elsewhere doesn't count once the store changes.
fn migrate_server_backups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS server_backups (
          id TEXT PRIMARY KEY,
          archive TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed', 'deleted')),
          destination TEXT NOT NULL,
          object_key TEXT NOT NULL,
          encrypted INTEGER NOT NULL DEFAULT 0,
          encrypted_by TEXT,
          size INTEGER,
          sha256 TEXT,
          error TEXT,
          created_at INTEGER NOT NULL,
          started_at INTEGER NOT NULL,
          finished_at INTEGER,
          expires_at INTEGER,
          deleted_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS server_backups_archive ON server_backups(destination, archive, started_at);
        CREATE INDEX IF NOT EXISTS server_backups_created ON server_backups(destination, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS server_backups_running ON server_backups(state) WHERE state = 'running';",
    )
}

/// The settings key an erasure sets, to its pseudonym, for its own transaction only:
/// while it is there, `audit_events_no_update` lets an update replace a person's fields.
const AUDIT_ERASING: &str = "audit_erasing";
/// Settings key prefix for the Bots an unfinished erasure took on, by user id.
const ERASING_BOTS: &str = "erasing_bots:";

/// Erasing a user (ADR 0102): the user row stays as a tombstone, with when, by whom and
/// as which pseudonym. The audit log stays append-only except that, inside an erasure's
/// transaction (the `audit_erasing` setting names its pseudonym), an update may replace
/// the erased person's id with that pseudonym and clear their name, email, subject,
/// address, user agent and session, and rewrite details; nothing else about an event changes.
fn migrate_user_erasure(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for (col, ty) in [("erased_at", "INTEGER"), ("erased_by", "TEXT"), ("erased_as", "TEXT")] {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE users ADD COLUMN {col} {ty};"))?;
        }
    }
    c.execute_batch(&format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_erased_as ON users(erased_as) WHERE erased_as IS NOT NULL;
        DROP TRIGGER IF EXISTS audit_events_no_update;
        {}",
        audit_update_trigger(false)
    ))
}

/// `audit_events_no_update`: refuses every update but an erasure's (ADR 0102). With the
/// hash chain (ADR 0122) an erasure also keeps the row's seal and clears its salt.
fn audit_update_trigger(chain: bool) -> String {
    let p = format!("(SELECT value FROM settings WHERE key = '{AUDIT_ERASING}')");
    let chain = if chain {
        "AND NEW.chain_prev IS OLD.chain_prev AND NEW.chain_hash IS OLD.chain_hash AND NEW.chain_digest IS OLD.chain_digest AND NEW.chain_salt IS NULL"
    } else {
        ""
    };
    format!(
        "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
          WHEN NOT (
            {p} IS NOT NULL {chain}
            AND NEW.id = OLD.id AND NEW.at = OLD.at AND NEW.actor_kind = OLD.actor_kind AND NEW.action = OLD.action
            AND NEW.outcome = OLD.outcome AND NEW.target_type IS OLD.target_type AND NEW.bot_id IS OLD.bot_id
            AND NEW.actor_role IS OLD.actor_role AND NEW.auth_method IS OLD.auth_method
            AND NEW.idp IS OLD.idp AND NEW.idp_provider IS OLD.idp_provider
            AND (NEW.actor_id IS OLD.actor_id OR NEW.actor_id = {p})
            AND (NEW.target_id IS OLD.target_id OR NEW.target_id = {p})
            AND (NEW.on_behalf_of IS OLD.on_behalf_of OR NEW.on_behalf_of = {p})
            AND (NEW.actor_name IS OLD.actor_name OR NEW.actor_name IS NULL)
            AND (NEW.actor_email IS OLD.actor_email OR NEW.actor_email IS NULL)
            AND (NEW.actor_subject IS OLD.actor_subject OR NEW.actor_subject IS NULL)
            AND (NEW.ip IS OLD.ip OR NEW.ip IS NULL)
            AND (NEW.user_agent IS OLD.user_agent OR NEW.user_agent IS NULL)
            AND (NEW.session_id IS OLD.session_id OR NEW.session_id IS NULL)
          )
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;"
    )
}

/// Whether Bot `?1` is held or has messages from a held Bot in its chat.
const HELD_CHAT: &str = "(EXISTS (SELECT 1 FROM retention_holds WHERE bot_id = ?1)
    OR EXISTS (SELECT 1 FROM messages WHERE bot_id = ?1 AND from_bot IN (SELECT bot_id FROM retention_holds)))";

/// Chat retention (ADR 0098): Bots whose chat an admin holds out of retention, for a legal
/// hold or any other reason, and an index so the deletion job finds old messages by age.
/// A held Bot can't be deleted, so the hold goes only when an admin releases it.
fn migrate_chat_retention(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS retention_holds (
          bot_id TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
          reason TEXT NOT NULL,
          held_by TEXT,
          held_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS messages_created ON messages(created_at);",
    )
}

/// SCIM groups as teams (ADR 0095): which team each of a tenant's groups is. A team is
/// one tenant's group at most. `origin` says who made the link: a SCIM `POST` that made
/// the team (`scim`), or an admin linking a team that already existed (`admin`).
/// `provisioned_at` is when the IdP created or took on the group; an admin's link, and a
/// `POST` that stopped partway, wait for that. `displayName` is unique in a tenant in any case, as Entra ID needs.
fn migrate_scim_groups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_groups (
          team_id TEXT PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
          tenant TEXT NOT NULL,
          external_id TEXT,
          display_name TEXT NOT NULL COLLATE NOCASE,
          origin TEXT NOT NULL CHECK (origin IN ('scim', 'admin')),
          provisioned_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS scim_groups_external_id ON scim_groups(tenant, external_id) WHERE external_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS scim_groups_display_name ON scim_groups(tenant, display_name);",
    )
}

/// Team billing (ADR 0093): a team's own Stripe customer, its subscriptions (kept like
/// a user's, with the seats Stripe bills and where syncing them stands), and its open
/// checkout page. Subscriptions outlive a deleted team, so a late event for one is still
/// placed, and ignored. Token rows also keep the customer they're metered to.
fn migrate_team_billing(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS team_customers (
          team_id TEXT PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          customer_id TEXT NOT NULL UNIQUE,
          linked_at INTEGER NOT NULL,
          linked_via TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS team_subscriptions (
          subscription_id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL,
          provider TEXT NOT NULL,
          customer_id TEXT,
          status TEXT NOT NULL,
          price_id TEXT,
          tier TEXT,
          item_id TEXT,
          quantity INTEGER,
          period_start INTEGER,
          period_end INTEGER,
          cancel_at INTEGER,
          started INTEGER NOT NULL,
          event_created INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          paid_by TEXT,
          seat_tries INTEGER NOT NULL DEFAULT 0,
          seat_failures INTEGER NOT NULL DEFAULT 0,
          seat_next_at INTEGER NOT NULL DEFAULT 0,
          seat_error TEXT
        );
        CREATE INDEX IF NOT EXISTS team_subscriptions_team ON team_subscriptions(team_id, started);
        CREATE TABLE IF NOT EXISTS team_checkouts (
          team_id TEXT PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
          session_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          subscription_id TEXT
        );",
    )?;
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('token_usage') WHERE name = 'meter_customer'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch("ALTER TABLE token_usage ADD COLUMN meter_customer TEXT;")
}

/// A second factor for local sign-ins (ADR 0094): each user's TOTP secret, sealed under
/// the master key, its one-time recovery codes as keyed hashes, and which factor each
/// session's sign-in passed.
fn migrate_mfa(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_mfa (
            user_id TEXT PRIMARY KEY,
            secret TEXT NOT NULL,
            confirmed_at INTEGER,
            last_step INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used_at INTEGER,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, code_hash)
        );",
    )?;
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'mfa'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE sessions ADD COLUMN mfa TEXT;")?;
    }
    Ok(())
}

/// Incident notes for the public status page (ADR 0090), written by admins. Each has a
/// timeline of updates; the newest one's state is the incident's.
fn migrate_status_incidents(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS status_incidents (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          impact TEXT NOT NULL,
          components TEXT NOT NULL DEFAULT '[]',
          state TEXT NOT NULL,
          created_by TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          resolved_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS status_incidents_recent ON status_incidents(resolved_at, created_at);
        CREATE TABLE IF NOT EXISTS status_incident_updates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id TEXT NOT NULL REFERENCES status_incidents(id) ON DELETE CASCADE,
          state TEXT NOT NULL,
          body TEXT NOT NULL,
          created_by TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS status_incident_updates_of ON status_incident_updates(incident_id, id);",
    )
}

/// Billing emails (ADR 0091): one row per email, its `key` unique so a Stripe event,
/// a billing period's limit or a resize asks for it once, kept after it's sent so a
/// redelivery finds it. `email_prefs` holds each person's choice for usage emails.
fn migrate_billing_emails(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS billing_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            facts TEXT NOT NULL,
            event_id TEXT,
            state TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            done_at INTEGER,
            reason TEXT
        );
        CREATE INDEX IF NOT EXISTS billing_emails_due ON billing_emails (state, next_at);
        CREATE INDEX IF NOT EXISTS billing_emails_user ON billing_emails (user_id, id);
        CREATE TABLE IF NOT EXISTS email_prefs (
            user_id TEXT PRIMARY KEY,
            usage_emails INTEGER NOT NULL DEFAULT 1,
            updated_at INTEGER NOT NULL
        );",
    )
}

/// What the homes on a machine hold (ADR 0105), as its agent last said, and when botd
/// heard it: the owner's storage counts it while their Bots work there.
fn migrate_machine_home_use(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'disk_files'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN disk_files INTEGER;
         ALTER TABLE machines ADD COLUMN disk_files_partial INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE machines ADD COLUMN disk_files_at INTEGER;",
    )
}

/// When the provider's own backups of a machine last succeeded (ADR 0110), so Linode
/// machines are held to an RPO by them.
fn migrate_machine_provider_backups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'provider_backup_at'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch("ALTER TABLE machines ADD COLUMN provider_backup_at INTEGER;")
}

/// When a machine was suspended (ADR 0085): what its agent said of its disk before then
/// still holds while it's off, and what it said long before doesn't.
fn migrate_machine_suspended_at(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'suspended_at'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch("ALTER TABLE machines ADD COLUMN suspended_at INTEGER;")
}

/// Team accounts (ADR 0087): a team is a group of this server's users, each in one team
/// at most, with a role in it. Invites wait for the person with that email to accept.
/// `team_machines` are the machines a team gave its members, so leaving can give them back.
fn migrate_teams(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS teams (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          machines INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS team_members (
          user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
          joined_at INTEGER NOT NULL,
          added_by TEXT
        );
        CREATE INDEX IF NOT EXISTS team_members_team ON team_members(team_id, joined_at);
        CREATE TABLE IF NOT EXISTS team_invites (
          id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          email TEXT NOT NULL COLLATE NOCASE,
          role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
          created_at INTEGER NOT NULL,
          created_by TEXT,
          expires_at INTEGER NOT NULL,
          UNIQUE (team_id, email)
        );
        CREATE TABLE IF NOT EXISTS team_machines (
          machine_id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          released_at INTEGER,
          release_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS team_machines_user ON team_machines(user_id);",
    )
}

/// The size last sent to the provider for a resize whose outcome is unknown (ADR 0085).
fn migrate_machine_resize_sent(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'resize_sent_plan'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN resize_sent_tier TEXT;
        ALTER TABLE machines ADD COLUMN resize_sent_plan TEXT;",
    )
}

/// Resizing a machine when its user's tier changes (ADR 0085): the latest resize, kept
/// on the machine as rebuilds are, and what its agent says of its disk.
fn migrate_machine_tier_resize(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'resize_state'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN resize_state TEXT;
        ALTER TABLE machines ADD COLUMN resize_tier TEXT;
        ALTER TABLE machines ADD COLUMN resize_plan TEXT;
        ALTER TABLE machines ADD COLUMN resize_from_tier TEXT;
        ALTER TABLE machines ADD COLUMN resize_from_plan TEXT;
        ALTER TABLE machines ADD COLUMN resize_cause TEXT;
        ALTER TABLE machines ADD COLUMN resize_event TEXT;
        ALTER TABLE machines ADD COLUMN resize_reason TEXT;
        ALTER TABLE machines ADD COLUMN resize_error TEXT;
        ALTER TABLE machines ADD COLUMN resize_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE machines ADD COLUMN resize_next_at INTEGER;
        ALTER TABLE machines ADD COLUMN resize_requested_at INTEGER;
        ALTER TABLE machines ADD COLUMN resize_at INTEGER;
        ALTER TABLE machines ADD COLUMN disk_used INTEGER;
        ALTER TABLE machines ADD COLUMN disk_total INTEGER;
        ALTER TABLE machines ADD COLUMN disk_seen_at INTEGER;",
    )
}

/// Phones that get push notifications (ADR 0080): one per session at most, and a token
/// belongs to one session only, so a phone that changes hands stops reaching the last
/// person. Ending the session removes it; so does deleting the session or the user.
fn migrate_push_devices(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS push_devices (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          token TEXT NOT NULL,
          platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
          approvals INTEGER NOT NULL DEFAULT 1,
          routines INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS push_devices_user ON push_devices(user_id, updated_at);",
    )
}

/// A host an admin drained (ADR 0081): nothing new is placed there, and machines on
/// it stay until moved.
fn migrate_machine_host_drain(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_hosts') WHERE name = 'drained_at'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machine_hosts ADD COLUMN drained_at INTEGER;
            ALTER TABLE machine_hosts ADD COLUMN drained_by TEXT;
            ALTER TABLE machine_hosts ADD COLUMN drain_reason TEXT;",
        )?;
    }
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'placed_on'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE machines ADD COLUMN placed_on TEXT;")?;
    }
    Ok(())
}

/// The hosts machines are on (ADR 0076): the certificate each was first seen with, so
/// one can't be swapped for another under the same name, and what botd last found.
/// Restores say which host they moved a machine from and to, and why.
fn migrate_machine_hosts(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_hosts (
          name TEXT PRIMARY KEY,
          url TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'up' CHECK (state IN ('up', 'down', 'lost')),
          failing_since INTEGER,
          checked_at INTEGER,
          last_error TEXT,
          down_at INTEGER,
          lost_at INTEGER,
          lost_by TEXT,
          created_at INTEGER NOT NULL
        );",
    )?;
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_restores') WHERE name = 'to_host'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machine_restores ADD COLUMN from_host TEXT;
            ALTER TABLE machine_restores ADD COLUMN to_host TEXT;
            ALTER TABLE machine_restores ADD COLUMN reason TEXT;",
        )?;
    }
    Ok(())
}

/// An incident note on the status page (ADR 0090).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusIncident {
    pub id: String,
    pub title: String,
    pub impact: String,
    pub components: Vec<String>,
    pub state: String,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub resolved_at: Option<i64>,
    /// Newest first.
    pub updates: Vec<StatusUpdate>,
}

pub struct NewStatusIncident<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub impact: &'a str,
    pub components: &'a [String],
    pub state: &'a str,
    pub body: &'a str,
    pub by: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusUpdate {
    pub id: i64,
    pub state: String,
    pub body: String,
    pub created_by: Option<String>,
    pub created_at: i64,
}

fn status_incident_row(r: &Row) -> rusqlite::Result<StatusIncident> {
    Ok(StatusIncident {
        id: r.get("id")?,
        title: r.get("title")?,
        impact: r.get("impact")?,
        components: serde_json::from_str(&r.get::<_, String>("components")?).unwrap_or_default(),
        state: r.get("state")?,
        created_by: r.get("created_by")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
        resolved_at: r.get("resolved_at")?,
        updates: Vec::new(),
    })
}

/// An Incus host machines are on (ADR 0076). `state`: `up`, `down` (it hasn't answered
/// since `failing_since`, for longer than the host-down time), or `lost` (an admin
/// said so; never called again).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineHost {
    pub name: String,
    pub url: String,
    pub fingerprint: String,
    pub state: String,
    pub failing_since: Option<i64>,
    pub checked_at: Option<i64>,
    pub last_error: Option<String>,
    pub down_at: Option<i64>,
    pub lost_at: Option<i64>,
    pub lost_by: Option<String>,
    pub drained_at: Option<i64>,
    pub drained_by: Option<String>,
    pub drain_reason: Option<String>,
    /// The team it is dedicated to (ADR 0166). None: shared.
    pub dedicated_team: Option<String>,
    pub dedicated_at: Option<i64>,
    pub dedicated_by: Option<String>,
    pub dedication_reason: Option<String>,
    pub created_at: i64,
}

fn machine_host_row(r: &Row) -> rusqlite::Result<MachineHost> {
    Ok(MachineHost {
        name: r.get("name")?,
        url: r.get("url")?,
        fingerprint: r.get("fingerprint")?,
        state: r.get("state")?,
        failing_since: r.get("failing_since")?,
        checked_at: r.get("checked_at")?,
        last_error: r.get("last_error")?,
        down_at: r.get("down_at")?,
        lost_at: r.get("lost_at")?,
        lost_by: r.get("lost_by")?,
        drained_at: r.get("drained_at")?,
        drained_by: r.get("drained_by")?,
        drain_reason: r.get("drain_reason")?,
        dedicated_team: r.get("dedicated_team")?,
        dedicated_at: r.get("dedicated_at")?,
        dedicated_by: r.get("dedicated_by")?,
        dedication_reason: r.get("dedication_reason")?,
        created_at: r.get("created_at")?,
    })
}

/// Off-host backups of machines and restores from them (ADR 0071). At most one backup
/// running and one restore underway per machine.
fn migrate_machine_backups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_backups (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tier TEXT NOT NULL,
          plan TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed', 'deleted')),
          object_key TEXT NOT NULL,
          encrypted INTEGER NOT NULL DEFAULT 0,
          size INTEGER,
          sha256 TEXT,
          created_by TEXT,
          error TEXT,
          created_at INTEGER NOT NULL,
          finished_at INTEGER,
          expires_at INTEGER,
          deleted_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS machine_backups_machine ON machine_backups(machine_id, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS machine_backups_running ON machine_backups(machine_id) WHERE state = 'running';
        CREATE TABLE IF NOT EXISTS machine_restores (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          backup_id TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('importing', 'replacing', 'enrolling', 'done', 'failed')),
          created_by TEXT,
          error TEXT,
          created_at INTEGER NOT NULL,
          replaced_at INTEGER,
          finished_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS machine_restores_underway ON machine_restores(machine_id)
          WHERE state IN ('importing', 'replacing', 'enrolling');",
    )
}

/// Recovery objectives (ADR 0074): each restore's tier, RTO and how long it took, and
/// each time a machine went past its RPO.
fn migrate_machine_recovery(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machine_restores') WHERE name = 'rto_ms'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machine_restores ADD COLUMN tier TEXT;
            ALTER TABLE machine_restores ADD COLUMN rto_ms INTEGER;
            ALTER TABLE machine_restores ADD COLUMN duration_ms INTEGER;
            ALTER TABLE machine_restores ADD COLUMN rto_exceeded_at INTEGER;",
        )?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_rpo_breaches (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tier TEXT NOT NULL,
          rpo_ms INTEGER NOT NULL,
          covered_since INTEGER NOT NULL,
          breached_at INTEGER NOT NULL,
          detected_at INTEGER NOT NULL,
          ended_at INTEGER,
          end_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS machine_rpo_breaches_at ON machine_rpo_breaches(breached_at);
        CREATE UNIQUE INDEX IF NOT EXISTS machine_rpo_breaches_open ON machine_rpo_breaches(machine_id) WHERE ended_at IS NULL;",
    )
}

/// A time a machine had no off-host backup newer than its RPO (ADR 0074). `breached_at`
/// is when that began (`covered_since` + `rpo_ms`), `detected_at` when botd saw it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRpoBreach {
    pub id: String,
    pub machine_id: String,
    pub user_id: String,
    pub tier: String,
    pub rpo_ms: i64,
    pub covered_since: i64,
    pub breached_at: i64,
    pub detected_at: i64,
    pub ended_at: Option<i64>,
    /// `backed_up`, `objective_changed`, or why the machine stopped counting
    /// (`suspended`, `destroyed`, `restoring`, ...).
    pub end_reason: Option<String>,
}

fn machine_rpo_breach_row(r: &Row) -> rusqlite::Result<MachineRpoBreach> {
    Ok(MachineRpoBreach {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        tier: r.get("tier")?,
        rpo_ms: r.get("rpo_ms")?,
        covered_since: r.get("covered_since")?,
        breached_at: r.get("breached_at")?,
        detected_at: r.get("detected_at")?,
        ended_at: r.get("ended_at")?,
        end_reason: r.get("end_reason")?,
    })
}

/// One off-host backup of a machine (ADR 0071).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineBackup {
    pub id: String,
    pub machine_id: String,
    pub user_id: String,
    pub tier: String,
    pub plan: String,
    /// `running`, `done`, `failed`, or `deleted` (past its retention, or on request).
    pub state: String,
    pub object_key: String,
    /// The data region whose store holds it (ADR 0117). None: the default store.
    pub store_region: Option<String>,
    pub encrypted: bool,
    pub size: Option<i64>,
    pub sha256: Option<String>,
    /// `schedule`, or the admin who asked.
    pub created_by: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub deleted_at: Option<i64>,
}

fn machine_backup_row(r: &Row) -> rusqlite::Result<MachineBackup> {
    Ok(MachineBackup {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        user_id: r.get("user_id")?,
        tier: r.get("tier")?,
        plan: r.get("plan")?,
        state: r.get("state")?,
        object_key: r.get("object_key")?,
        store_region: r.get("store_region")?,
        encrypted: r.get("encrypted")?,
        size: r.get("size")?,
        sha256: r.get("sha256")?,
        created_by: r.get("created_by")?,
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        finished_at: r.get("finished_at")?,
        expires_at: r.get("expires_at")?,
        deleted_at: r.get("deleted_at")?,
    })
}

/// One off-host copy of a server backup archive (ADR 0109).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerBackup {
    pub id: String,
    /// The archive's file name in BACKUP_DIR, e.g. `superbot-20261122-031500.tar.gz.age`.
    pub archive: String,
    /// `running`, `done`, `failed`, or `deleted` (past its retention).
    pub state: String,
    /// `<endpoint>/<bucket>/<folder>` it was copied to.
    pub destination: String,
    pub object_key: String,
    pub encrypted: bool,
    /// `archive` (superbot-backup encrypted it) or `botd` (on its way to the store).
    pub encrypted_by: Option<String>,
    pub size: Option<i64>,
    pub sha256: Option<String>,
    pub error: Option<String>,
    /// When the archive was made: what the RPO counts from.
    pub created_at: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub deleted_at: Option<i64>,
}

fn server_backup_row(r: &Row) -> rusqlite::Result<ServerBackup> {
    Ok(ServerBackup {
        id: r.get("id")?,
        archive: r.get("archive")?,
        state: r.get("state")?,
        destination: r.get("destination")?,
        object_key: r.get("object_key")?,
        encrypted: r.get("encrypted")?,
        encrypted_by: r.get("encrypted_by")?,
        size: r.get("size")?,
        sha256: r.get("sha256")?,
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        started_at: r.get("started_at")?,
        finished_at: r.get("finished_at")?,
        expires_at: r.get("expires_at")?,
        deleted_at: r.get("deleted_at")?,
    })
}

/// A copy of an archive about to start.
pub struct NewServerBackup<'a> {
    pub id: &'a str,
    pub archive: &'a str,
    pub destination: &'a str,
    pub object_key: &'a str,
    pub created_at: i64,
    pub encrypted_by: Option<&'a str>,
}

/// One restore of a machine from a backup (ADR 0071).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRestore {
    pub id: String,
    pub machine_id: String,
    pub backup_id: String,
    /// `importing`, `replacing`, `enrolling`, `done`, or `failed`.
    pub state: String,
    pub created_by: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    /// When the restored disk took the old one's place.
    pub replaced_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// The machine's tier and its RTO when the restore was asked for (ADR 0074).
    pub tier: Option<String>,
    pub rto_ms: Option<i64>,
    /// From the request to the machine enrolling again, once done.
    pub duration_ms: Option<i64>,
    /// When it was seen to take longer than `rto_ms`.
    pub rto_exceeded_at: Option<i64>,
    /// The hosts it was restored from and onto, where the provider has several (ADR 0076).
    pub from_host: Option<String>,
    pub to_host: Option<String>,
    /// `host_lost` when its host was declared lost; None when an admin asked.
    pub reason: Option<String>,
}

fn machine_restore_row(r: &Row) -> rusqlite::Result<MachineRestore> {
    Ok(MachineRestore {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        backup_id: r.get("backup_id")?,
        state: r.get("state")?,
        created_by: r.get("created_by")?,
        error: r.get("error")?,
        created_at: r.get("created_at")?,
        replaced_at: r.get("replaced_at")?,
        finished_at: r.get("finished_at")?,
        tier: r.get("tier")?,
        rto_ms: r.get("rto_ms")?,
        duration_ms: r.get("duration_ms")?,
        rto_exceeded_at: r.get("rto_exceeded_at")?,
        from_host: r.get("from_host")?,
        to_host: r.get("to_host")?,
        reason: r.get("reason")?,
    })
}

/// A backup to start: `machine_backup_start`.
pub struct NewMachineBackup<'a> {
    pub id: &'a str,
    pub machine: &'a Machine,
    pub object_key: &'a str,
    pub store_region: Option<&'a str>,
    pub encrypted: bool,
    pub created_by: Option<&'a str>,
}

/// A restore to start: `machine_restore_start`.
pub struct NewMachineRestore<'a> {
    pub id: &'a str,
    pub machine: &'a Machine,
    pub backup_id: &'a str,
    pub by: Option<&'a str>,
    pub rto_ms: Option<i64>,
    pub from_host: Option<&'a str>,
    pub to_host: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// Rebuilding machines enrolled before ADR 0039 with today's agent (ADR 0056).
fn migrate_machine_rebuild(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'rebuild_state'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN rebuild_state TEXT
           CHECK (rebuild_state IN ('queued', 'retrying', 'rebuilding', 'done', 'failed', 'cancelled'));
        ALTER TABLE machines ADD COLUMN rebuild_id TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_by TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_discard INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE machines ADD COLUMN rebuild_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE machines ADD COLUMN rebuild_next_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_requested_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN rebuild_error TEXT;
        ALTER TABLE machines ADD COLUMN rebuild_from TEXT;",
    )
}

/// Harness sandboxes (ADR 0055). New installs have them on (`Policy::new`); an install
/// upgrading keeps running without, as before, until an admin turns them on. Bots'
/// own overrides have no `sandbox`, so they follow the global setting.
fn migrate_sandbox(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    if fresh {
        return Ok(());
    }
    let saved: Option<String> = c.query_row("SELECT value FROM settings WHERE key = 'policy'", [], |r| r.get(0)).optional()?;
    let Some(mut policy) = saved.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()).filter(serde_json::Value::is_object) else {
        return Ok(());
    };
    policy["sandbox"] = false.into();
    c.execute("UPDATE settings SET value = ? WHERE key = 'policy'", [policy.to_string()])?;
    let details = serde_json::json!({ "sandbox": false, "reason": "existing install keeps harness sandboxes off" });
    c.execute(
        "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, target_id, outcome, details) VALUES (?, 'system', 'migration', 'policy.sandbox_initialized', 'policy', 'global', 'success', ?)",
        params![now(), details.to_string()],
    )?;
    Ok(())
}

/// Suggested prompts per Bot (ADR 0054), as a JSON array. NULL: the client's defaults.
fn migrate_bot_prompts(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('bots') WHERE name = 'prompts'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE bots ADD COLUMN prompts TEXT;")?;
    }
    Ok(())
}

/// Approve once per run (ADR 0051): the run each approval was asked in, what approving
/// it for that run would cover, and which of the two it got. The grants themselves are
/// never stored: they live with the run and end with it.
fn migrate_approval_runs(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for col in ["run_id", "run_scope", "scope"] {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('approvals') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE approvals ADD COLUMN {col} TEXT;"))?;
        }
    }
    Ok(())
}

/// Removing teammates' users from machines when they leave (ADR 0052): one row per
/// removal, `pending` until the agent has done it, then `done`, or `held` while their
/// work waits to be purged; `cancelled` if they came back or the machine went first.
/// At most one pending per machine and teammate, so queueing again changes nothing.
fn migrate_teammate_cleanups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS teammate_cleanups (
          id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          os_user TEXT NOT NULL,
          reason TEXT NOT NULL,
          files TEXT NOT NULL CHECK (files IN ('archive', 'delete')),
          grace_days INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL CHECK (state IN ('pending', 'held', 'done', 'cancelled')),
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          tried_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          removed_at INTEGER,
          archived_to TEXT,
          purge_at INTEGER,
          done_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS teammate_cleanups_pending ON teammate_cleanups(machine_id, user_id) WHERE state = 'pending';
        CREATE INDEX IF NOT EXISTS teammate_cleanups_state ON teammate_cleanups(state, machine_id);",
    )
}

/// One teammate's removal from one machine (ADR 0052).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeammateCleanup {
    pub id: String,
    pub machine_id: String,
    /// The machine's user, whose shared Bots the teammate ran.
    pub owner_id: String,
    /// The teammate.
    pub user_id: String,
    pub os_user: String,
    /// `disabled`, `deprovisioned`, `deleted`, `access_lost` or `admin`.
    pub reason: String,
    /// `archive` or `delete`: what becomes of their work folder.
    pub files: String,
    pub grace_days: i64,
    pub state: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub tried_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub removed_at: Option<i64>,
    pub archived_to: Option<String>,
    pub purge_at: Option<i64>,
    pub done_at: Option<i64>,
}

fn teammate_cleanup_row(r: &Row) -> rusqlite::Result<TeammateCleanup> {
    Ok(TeammateCleanup {
        id: r.get("id")?,
        machine_id: r.get("machine_id")?,
        owner_id: r.get("owner_id")?,
        user_id: r.get("user_id")?,
        os_user: r.get("os_user")?,
        reason: r.get("reason")?,
        files: r.get("files")?,
        grace_days: r.get("grace_days")?,
        state: r.get("state")?,
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
        tried_at: r.get("tried_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        removed_at: r.get("removed_at")?,
        archived_to: r.get("archived_to")?,
        purge_at: r.get("purge_at")?,
        done_at: r.get("done_at")?,
    })
}

/// A removal to queue: `teammate_cleanup_queue`.
pub struct NewTeammateCleanup<'a> {
    pub machine_id: &'a str,
    pub owner_id: &'a str,
    pub user_id: &'a str,
    pub os_user: &'a str,
    pub reason: &'a str,
    pub files: &'a str,
    pub grace_days: i64,
    pub created_by: Option<&'a str>,
}

/// Removing leaving teammates' accounts on one server (ADR 0066): one row per removal of
/// a teammate's account for one owner's Bots (`sb-t-`, ADR 0064), `pending` until the
/// root helper has done it, then `done`, or `held` while their work waits to be purged;
/// `cancelled` if they came back before it was tried. At most one pending per owner and
/// teammate, so queueing again changes nothing.
fn migrate_account_removals(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_removals (
          id TEXT PRIMARY KEY,
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          account TEXT NOT NULL,
          reason TEXT NOT NULL,
          files TEXT NOT NULL CHECK (files IN ('archive', 'delete')),
          grace_days INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL CHECK (state IN ('pending', 'held', 'done', 'cancelled')),
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          tried_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          removed_at INTEGER,
          archived_to TEXT,
          purge_at INTEGER,
          done_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS account_removals_pending ON account_removals(owner_id, user_id) WHERE state = 'pending';
        CREATE INDEX IF NOT EXISTS account_removals_state ON account_removals(state);
        CREATE TABLE IF NOT EXISTS teammate_spaces (
          owner_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          made_at INTEGER NOT NULL,
          PRIMARY KEY (owner_id, user_id)
        );",
    )?;
    // Pairs made before this table, whose accounts a recreated container may have lost
    // while keeping their folders: the audit log is the only record of them. Once only,
    // so a pair removed since is never found again.
    c.execute(
        "INSERT OR IGNORE INTO teammate_spaces (owner_id, user_id, made_at)
         SELECT target_id, json_extract(details, '$.forUser'), MIN(at) FROM audit_events
         WHERE action = 'isolation.account_created' AND target_type = 'user' AND outcome = 'success'
           AND target_id IS NOT NULL AND json_extract(details, '$.forUser') IS NOT NULL
         GROUP BY 1, 2",
        [],
    )?;
    Ok(())
}

/// One teammate's account for one owner's Bots on this server, being removed (ADR 0066).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRemoval {
    pub id: String,
    /// Whose shared Bots the teammate ran.
    pub owner_id: String,
    /// The teammate.
    pub user_id: String,
    /// `sb-t-<hash>`.
    pub account: String,
    /// `disabled`, `deprovisioned`, `deleted`, `access_lost` or `admin`.
    pub reason: String,
    /// `archive` or `delete`: what becomes of their workspace.
    pub files: String,
    pub grace_days: i64,
    pub state: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub tried_at: Option<i64>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub removed_at: Option<i64>,
    pub archived_to: Option<String>,
    pub purge_at: Option<i64>,
    pub done_at: Option<i64>,
}

fn account_removal_row(r: &Row) -> rusqlite::Result<AccountRemoval> {
    Ok(AccountRemoval {
        id: r.get("id")?,
        owner_id: r.get("owner_id")?,
        user_id: r.get("user_id")?,
        account: r.get("account")?,
        reason: r.get("reason")?,
        files: r.get("files")?,
        grace_days: r.get("grace_days")?,
        state: r.get("state")?,
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
        tried_at: r.get("tried_at")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        removed_at: r.get("removed_at")?,
        archived_to: r.get("archived_to")?,
        purge_at: r.get("purge_at")?,
        done_at: r.get("done_at")?,
    })
}

/// A removal to queue: `account_removal_queue`.
pub struct NewAccountRemoval<'a> {
    pub owner_id: &'a str,
    pub user_id: &'a str,
    pub account: &'a str,
    pub reason: &'a str,
    pub files: &'a str,
    pub grace_days: i64,
    pub created_by: Option<&'a str>,
}

/// Token metering (ADR 0050): the model tokens each run used, one row per model, or one
/// row with `reported = 0` when the harness didn't say. Charged to the Bot's owner, like
/// the run; `user_id` and `bot_id` have no foreign key, as `bots.owner_id` doesn't, so a
/// deleted Bot's usage stays billed. `meter_status` is for reporting to Stripe, when
/// that's on. Subscriptions keep their period's start, for billing-period usage.
fn migrate_token_usage(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('subscriptions') WHERE name = 'period_start'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE subscriptions ADD COLUMN period_start INTEGER;")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS token_usage (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL,
          bot_id TEXT NOT NULL,
          run_id TEXT NOT NULL,
          message_id INTEGER,
          harness TEXT NOT NULL,
          model TEXT,
          reported INTEGER NOT NULL CHECK (reported IN (0, 1)),
          input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
          output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
          cache_read_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
          cache_write_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
          at INTEGER NOT NULL,
          meter_status TEXT CHECK (meter_status IN ('pending', 'sent', 'failed')),
          meter_attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS token_usage_user_at ON token_usage(user_id, at);
        CREATE INDEX IF NOT EXISTS token_usage_run ON token_usage(run_id);
        CREATE INDEX IF NOT EXISTS token_usage_meter ON token_usage(id) WHERE meter_status = 'pending';",
    )
}

/// Why botd paused a routine, and for whom (ADR 0047), so it can be resumed.
fn migrate_routine_pauses(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    for (col, ty) in [("paused_reason", "TEXT"), ("paused_for", "TEXT"), ("paused_at", "INTEGER")] {
        let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('routines') WHERE name = ?", [col], |r| r.get(0))?;
        if !has {
            c.execute_batch(&format!("ALTER TABLE routines ADD COLUMN {col} {ty};"))?;
        }
    }
    Ok(())
}

/// Who wrote each routine's instruction, so its runs are for them (ADR 0046). Routines
/// from before have none, and run for their Bot's owner as they did.
fn migrate_routine_authors(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('routines') WHERE name = 'author_id'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE routines ADD COLUMN author_id TEXT;")?;
    }
    Ok(())
}

/// Users linked to their payment-provider customer (ADR 0042), at most one each way;
/// customers the provider deleted, which are never linked again; and each user's open
/// checkout, closed before another is opened so only one can be paid. Subscribers from
/// before keep their portal: a user whose subscriptions name one customer, which no other
/// user's do, is linked to it.
fn migrate_billing_customers(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS billing_customers (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          provider TEXT NOT NULL,
          customer_id TEXT NOT NULL UNIQUE,
          linked_at INTEGER NOT NULL,
          linked_via TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS billing_deleted_customers (
          customer_id TEXT PRIMARY KEY,
          deleted_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS billing_checkouts (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          session_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );",
    )?;
    c.execute(
        "INSERT OR IGNORE INTO billing_customers (user_id, provider, customer_id, linked_at, linked_via)
         SELECT user_id, MIN(provider), MIN(customer_id), ?, 'migration' FROM subscriptions
         WHERE customer_id IS NOT NULL AND customer_id != ''
         GROUP BY user_id
         HAVING COUNT(DISTINCT customer_id) = 1
           AND MIN(customer_id) NOT IN (
             SELECT customer_id FROM subscriptions WHERE customer_id IS NOT NULL
             GROUP BY customer_id HAVING COUNT(DISTINCT user_id) > 1)",
        [now()],
    )?;
    Ok(())
}
/// Harness CLIs and agent upgrades on machines (ADR 0039): what each agent last said,
/// the plan sent to it, and an upgrade on its way, held, or failed.
fn migrate_machine_upkeep(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'agent_upkeep'", [], |r| r.get(0))?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN agent_upkeep TEXT;
        ALTER TABLE machines ADD COLUMN harnesses_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN harnesses_sent_plan TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_hold_at INTEGER;
        ALTER TABLE machines ADD COLUMN upgrade_hold_by TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_id TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_build TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_sent_at INTEGER;
        ALTER TABLE machines ADD COLUMN upgrade_by TEXT;
        ALTER TABLE machines ADD COLUMN upgrade_failed_build TEXT;",
    )
}

/// Billing v0 (ADR 0040): routine runs counted per user and UTC day, every Stripe
/// subscription with its user, and the Stripe event ids already applied, so a
/// redelivered event changes nothing.
fn migrate_billing(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS usage_daily (
          user_id TEXT NOT NULL REFERENCES users(id),
          day TEXT NOT NULL,
          routine_runs INTEGER NOT NULL DEFAULT 0,
          routine_refused INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (user_id, day)
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
          subscription_id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id),
          provider TEXT NOT NULL,
          customer_id TEXT,
          status TEXT NOT NULL,
          price_id TEXT,
          tier TEXT,
          period_end INTEGER,
          started INTEGER NOT NULL,
          event_created INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS subscriptions_user ON subscriptions (user_id);
        CREATE TABLE IF NOT EXISTS billing_events (
          event_id TEXT PRIMARY KEY,
          type TEXT NOT NULL,
          received_at INTEGER NOT NULL
        );",
    )
}
/// Machines come up firewalled and enrolled (ADR 0035): the provider firewall each is
/// behind, and when it must have enrolled by (and when it was found it hadn't).
fn migrate_machine_lockdown(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'firewall_id'",
        [],
        |r| r.get(0),
    )?;
    if has {
        return Ok(());
    }
    c.execute_batch(
        "ALTER TABLE machines ADD COLUMN firewall_id TEXT;
        ALTER TABLE machines ADD COLUMN enroll_by INTEGER;
        ALTER TABLE machines ADD COLUMN enroll_overdue_at INTEGER;",
    )
}
/// Placement (ADR 0036): an admin assigns a user's machine to them, and then that
/// user's Bots run there. Kept on the machine row, so a user can only be placed on
/// their own machine, and destroying it ends the placement.
fn migrate_machine_placement(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'assigned_at'", [], |r| r.get(0))?;
    if !has {
        c.execute_batch("ALTER TABLE machines ADD COLUMN assigned_at INTEGER; ALTER TABLE machines ADD COLUMN assigned_by TEXT;")?;
    }
    Ok(())
}
/// Machine enrollment (ADR 0031). Tokens are kept as SHA-256 hashes, bound to one
/// machine, and used once. Certificates are kept by fingerprint, never with their keys
/// (botd never sees a machine's key); `id` orders them, so the ones before a rotated
/// certificate can be revoked once it's in use.
fn migrate_machine_enrollment(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has: bool = c.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'enrollment'",
        [],
        |r| r.get(0),
    )?;
    if !has {
        c.execute_batch(
            "ALTER TABLE machines ADD COLUMN enrollment TEXT NOT NULL DEFAULT 'none' CHECK (enrollment IN ('none', 'enrolled', 'held', 'revoked'));
            ALTER TABLE machines ADD COLUMN enrolled_at INTEGER;
            ALTER TABLE machines ADD COLUMN agent_seen_at INTEGER;
            ALTER TABLE machines ADD COLUMN agent_version TEXT;
            ALTER TABLE machines ADD COLUMN agent_error TEXT;",
        )?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machine_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          machine_id TEXT NOT NULL REFERENCES machines(id),
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS machine_tokens_machine ON machine_tokens(machine_id);
        CREATE TABLE IF NOT EXISTS machine_certs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          fingerprint TEXT NOT NULL UNIQUE,
          serial TEXT NOT NULL UNIQUE,
          machine_id TEXT NOT NULL REFERENCES machines(id),
          user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL CHECK (status IN ('active', 'held', 'revoked')),
          issued_for TEXT NOT NULL CHECK (issued_for IN ('enrolled', 'rotated')),
          issued_at INTEGER NOT NULL,
          not_before INTEGER NOT NULL,
          not_after INTEGER NOT NULL,
          first_seen_at INTEGER,
          revoked_at INTEGER,
          revoked_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS machine_certs_machine ON machine_certs(machine_id, status);",
    )
}

/// Tiers (ADR 0033): each user's assigned tier (NULL: the configured default) and runs
/// counted per user and UTC month, for the tier's monthly limit. Keyed by user, so
/// every query names one.
fn migrate_tiers(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    let has_tier = c.prepare("SELECT 1 FROM pragma_table_info('users') WHERE name = 'tier'")?.exists([])?;
    if !has_tier {
        c.execute_batch("ALTER TABLE users ADD COLUMN tier TEXT;")?;
    }
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS usage_monthly (
          user_id TEXT NOT NULL REFERENCES users(id),
          period TEXT NOT NULL,
          runs INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (user_id, period)
        );",
    )
}

/// SCIM provisioning (ADR 0023): bearer tokens (hashes only), each in a tenant, and the
/// users a tenant provisioned. One row per user: a user belongs to at most one tenant.
/// `deleted_at` is a SCIM DELETE: the tenant can't see the user any more, but the user,
/// disabled, and its audit history stay. Its `externalId` stays reserved, so the same
/// person provisioned again gets the same user back. No ON DELETE: users are never deleted.
fn migrate_scim(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS scim_tokens (
          id TEXT PRIMARY KEY,
          tenant TEXT NOT NULL,
          label TEXT,
          sso_provider TEXT,
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          last_used_at INTEGER,
          revoked_at INTEGER,
          revoked_by TEXT
        );
        CREATE INDEX IF NOT EXISTS scim_tokens_tenant ON scim_tokens(tenant, created_at);
        CREATE TABLE IF NOT EXISTS scim_users (
          user_id TEXT PRIMARY KEY REFERENCES users(id),
          tenant TEXT NOT NULL,
          external_id TEXT,
          user_name TEXT NOT NULL COLLATE NOCASE,
          given_name TEXT,
          family_name TEXT,
          display_name TEXT,
          formatted TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          deleted_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS scim_users_external_id ON scim_users(tenant, external_id) WHERE external_id IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS scim_users_user_name ON scim_users(tenant, user_name) WHERE deleted_at IS NULL;",
    )
}

/// Per-user machines from the control plane (ADR 0025). Every query names the user or
/// the machine. The partial unique index is "one machine per user": a second request
/// can't insert another while one is live. Destroyed rows are kept as history.
fn migrate_machines(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS machines (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id),
          provider TEXT NOT NULL,
          provider_id TEXT,
          label TEXT NOT NULL UNIQUE,
          tag TEXT NOT NULL,
          tier TEXT NOT NULL,
          plan TEXT NOT NULL,
          region TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'running', 'suspended', 'destroying', 'destroyed', 'error')),
          provider_status TEXT,
          ipv4 TEXT,
          backups INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          create_sent_at INTEGER,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          updated_at INTEGER NOT NULL,
          destroyed_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS machines_one_per_user ON machines(user_id) WHERE state <> 'destroyed';
        CREATE INDEX IF NOT EXISTS machines_state ON machines(state, created_at);",
    )
}

/// Requests for access from the public sign-up form (ADR 0022). Consent is a column,
/// not a flag in a blob: no row exists without it. `user_id` has no foreign key, like
/// `bots.owner_id`: users are never deleted.
fn migrate_signups(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS signups (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT NOT NULL COLLATE NOCASE,
          company TEXT NOT NULL,
          team_size TEXT NOT NULL,
          use_case TEXT NOT NULL,
          sign_in TEXT NOT NULL CHECK (sign_in IN ('microsoft', 'google', 'github', 'apple', 'other')),
          consent_at INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
          ip TEXT,
          user_agent TEXT,
          created_at INTEGER NOT NULL,
          decided_at INTEGER,
          decided_by TEXT,
          reason TEXT,
          user_id TEXT,
          role TEXT
        );
        CREATE INDEX IF NOT EXISTS signups_status ON signups(status, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS signups_one_pending ON signups(email) WHERE status = 'pending';",
    )
}

/// The actor columns the audit log gained with per-user actors (ADR 0019).
pub const AUDIT_ACTOR_COLUMNS: [&str; 7] = ["actor_email", "actor_role", "auth_method", "idp", "idp_provider", "session_id", "on_behalf_of"];

/// Per-user audit actors (ADR 0019): each event says who acted as of then (email,
/// role), how they signed in (method, SSO provider and type, session), and whom a Bot
/// acted for. Only adds nullable columns, so old rows stay as written: the log is
/// append-only, and guessing at who did something before it was recorded would be
/// rewriting history. Sessions remember their SSO provider, and queued messages who
/// asked for them, so the runs they start can be attributed.
fn migrate_audit_actors(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    for col in AUDIT_ACTOR_COLUMNS {
        c.execute_batch(&format!("ALTER TABLE audit_events ADD COLUMN {col} TEXT;"))?;
    }
    c.execute_batch(
        "CREATE INDEX audit_events_on_behalf_of ON audit_events(on_behalf_of, id) WHERE on_behalf_of IS NOT NULL;
        CREATE INDEX audit_events_session ON audit_events(session_id, id) WHERE session_id IS NOT NULL;
        ALTER TABLE sessions ADD COLUMN idp_provider TEXT;
        ALTER TABLE messages ADD COLUMN requested_by TEXT;",
    )?;
    if !fresh {
        let details = serde_json::json!({ "added": AUDIT_ACTOR_COLUMNS, "reason": "per-user actors and IdP; earlier events leave these empty" });
        c.execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, target_id, outcome, details) VALUES (?, 'system', 'migration', 'audit.schema_upgraded', 'audit', 'actors', 'success', ?)",
            params![now(), details.to_string()],
        )?;
    }
    Ok(())
}

/// The admin portal (ADR 0021): when and how each user last signed in. Sessions are
/// pruned 30 days after they end, so this lives on the user; it starts from the
/// newest session still kept.
fn migrate_last_login(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "ALTER TABLE users ADD COLUMN last_login_at INTEGER;
        ALTER TABLE users ADD COLUMN last_login_method TEXT;
        ALTER TABLE users ADD COLUMN last_login_idp_provider TEXT;
        UPDATE users SET (last_login_at, last_login_method, last_login_idp_provider) =
          (SELECT created_at, method, idp_provider FROM sessions WHERE sessions.user_id = users.id ORDER BY created_at DESC, id LIMIT 1);",
    )
}

/// Bot ACLs (ADR 0017): an owner and a visibility per Bot, and per-user grants.
/// Bots from before belong to the owner account (`operator`, break-glass) and stay
/// shared, so everyone keeps the Bots they had. No foreign key on `owner_id`: the
/// owner account is made after migrations run, and users are never deleted.
fn migrate_bot_acls(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "ALTER TABLE bots ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'operator';
        ALTER TABLE bots ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared' CHECK (visibility IN ('private', 'shared'));
        CREATE INDEX bots_owner ON bots(owner_id);
        CREATE TABLE bot_grants (
          bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          level TEXT NOT NULL CHECK (level IN ('viewer', 'operator')),
          created_at INTEGER NOT NULL,
          created_by TEXT,
          PRIMARY KEY (bot_id, user_id)
        );
        CREATE INDEX bot_grants_user ON bot_grants(user_id);",
    )?;
    let n: i64 = c.query_row("SELECT count(*) FROM bots", [], |r| r.get(0))?;
    if n > 0 {
        let details = serde_json::json!({ "bots": n, "owner": "operator", "visibility": "shared", "reason": "Bots from before ACLs" });
        c.execute(
            "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, outcome, details) VALUES (?, 'system', 'migration', 'bot.acl_initialized', 'bot', 'success', ?)",
            params![now(), details.to_string()],
        )?;
    }
    Ok(())
}

/// SSO identities (ADR 0014): any number per user, each `(issuer, subject)` at most
/// once. `users.idp_issuer`/`idp_subject` become the user's first identity and are
/// kept in step with this table. Sessions remember which identity signed them in.
fn migrate_identities(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE user_identities (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          issuer TEXT NOT NULL,
          subject TEXT NOT NULL,
          tenant TEXT,
          email TEXT,
          created_at INTEGER NOT NULL,
          created_by TEXT,
          last_login_at INTEGER,
          UNIQUE (issuer, subject)
        );
        CREATE INDEX user_identities_user ON user_identities(user_id, created_at);
        INSERT INTO user_identities (id, user_id, provider, issuer, subject, created_at)
          SELECT 'i' || lower(hex(randomblob(4))), id, 'oidc', idp_issuer, idp_subject, created_at FROM users WHERE idp_issuer IS NOT NULL;
        ALTER TABLE sessions ADD COLUMN idp_subject TEXT;",
    )
}

/// Users, sessions, and one-time sign-in codes (ADR 0012). Tables start empty; botd
/// creates the owner (`operator`, the break-glass account) on start, so an upgrade
/// keeps the shared password working.
fn migrate_users(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE users (
          id TEXT PRIMARY KEY,
          email TEXT COLLATE NOCASE UNIQUE,
          display_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'readonly')),
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
          idp_issuer TEXT,
          idp_subject TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          CHECK ((idp_issuer IS NULL) = (idp_subject IS NULL))
        );
        CREATE UNIQUE INDEX users_idp ON users(idp_issuer, idp_subject) WHERE idp_issuer IS NOT NULL;
        CREATE TABLE sessions (
          id TEXT PRIMARY KEY,
          token_hash TEXT NOT NULL UNIQUE,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          kind TEXT NOT NULL CHECK (kind IN ('cookie', 'token')),
          method TEXT NOT NULL,
          label TEXT,
          ip TEXT,
          user_agent TEXT,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked_at INTEGER,
          revoked_by TEXT,
          revoke_reason TEXT
        );
        CREATE INDEX sessions_user ON sessions(user_id, created_at);
        CREATE TABLE login_codes (
          code_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_by TEXT,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER
        );",
    )
}

/// Structured audit events (ADR 0009): actor kind and id, target type and id,
/// outcome, and request source. Copies the rows from the first audit table.
/// DELETE is refused except for rows older than `audit_retention_days`.
fn migrate_audit_events(c: &Connection, _fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "DROP TRIGGER audit_events_no_update;
        DROP TRIGGER audit_events_no_delete;
        ALTER TABLE audit_events RENAME TO audit_events_v1;
        CREATE TABLE audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'bot', 'system')),
          actor_id TEXT,
          actor_name TEXT,
          actor_subject TEXT,
          action TEXT NOT NULL,
          target_type TEXT,
          target_id TEXT,
          bot_id TEXT,
          outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
          ip TEXT,
          user_agent TEXT,
          details TEXT NOT NULL DEFAULT '{}'
        );
        INSERT INTO audit_events (id, at, actor_kind, actor_id, action, target_type, target_id, bot_id, outcome, details)
        SELECT id, at,
          CASE actor WHEN 'user' THEN 'user' WHEN 'bot' THEN 'bot' ELSE 'system' END,
          CASE actor WHEN 'user' THEN 'operator' WHEN 'bot' THEN bot_id ELSE NULL END,
          action,
          CASE
            WHEN target IS NULL THEN NULL
            WHEN action LIKE 'approval.%' THEN 'approval'
            WHEN action LIKE 'rule.%' OR action IN ('policy.allowed', 'policy.denied') THEN 'rule'
            ELSE 'policy'
          END,
          target, bot_id,
          CASE WHEN action = 'policy.denied' THEN 'denied' ELSE 'success' END,
          detail
        FROM audit_events_v1 ORDER BY id;
        DROP TABLE audit_events_v1;
        CREATE INDEX audit_events_at ON audit_events(at);
        CREATE INDEX audit_events_action ON audit_events(action, id);
        CREATE INDEX audit_events_actor ON audit_events(actor_kind, actor_id, id);
        CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;",
    )?;
    c.execute_batch(&audit_delete_trigger())
}

fn audit_delete_trigger() -> String {
    format!(
        "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
          WHEN coalesce(OLD.at >= {AUDIT_CUTOFF}, 1)
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;"
    )
}

/// Unix ms before which audit events may be deleted, or NULL while retention is off.
/// Pruning and the delete trigger share it: SQLite's 'now' is fixed for one statement,
/// so both see the same cutoff.
const AUDIT_CUTOFF: &str = "(SELECT (CAST(strftime('%s', 'now') AS INTEGER) - CAST(value AS INTEGER) * 86400) * 1000
  FROM settings WHERE key = 'audit_retention_days' AND CAST(value AS INTEGER) > 0)";

/// Approvals and harness policy. Fresh installs ask before risky tools; existing
/// installs keep running in bypass, as before, until the operator opts in.
fn migrate_approvals(c: &Connection, fresh: bool) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE bot_policies (
          bot_id TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
          policy TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE policy_rules (
          id TEXT PRIMARY KEY,
          bot_id TEXT REFERENCES bots(id) ON DELETE CASCADE,
          action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
          tool TEXT NOT NULL DEFAULT '*',
          pattern TEXT NOT NULL,
          note TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE approvals (
          id TEXT PRIMARY KEY,
          bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
          harness TEXT NOT NULL,
          tool TEXT NOT NULL,
          kind TEXT NOT NULL,
          subject TEXT NOT NULL,
          input TEXT NOT NULL,
          class TEXT NOT NULL,
          reason TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          decided_at INTEGER,
          decided_by TEXT,
          note TEXT,
          rule_id TEXT
        );
        CREATE INDEX approvals_status ON approvals(status, created_at);
        CREATE TABLE audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at INTEGER NOT NULL,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          bot_id TEXT,
          target TEXT,
          detail TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
        CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
          BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;",
    )?;
    let policy = Policy::new(if fresh { Mode::Ask } else { Mode::Bypass });
    c.execute("INSERT INTO settings (key, value) VALUES ('policy', ?)", [serde_json::to_string(&policy).unwrap()])?;
    let detail = serde_json::json!({ "mode": policy.mode, "reason": if fresh { "fresh install" } else { "existing install keeps bypass" } });
    c.execute(
        "INSERT INTO audit_events (at, actor, action, target, detail) VALUES (?, 'system', 'policy.initialized', 'global', ?)",
        params![now(), detail.to_string()],
    )?;
    Ok(())
}

impl Db {
    pub fn open(path: &std::path::Path) -> rusqlite::Result<Db> {
        Db::on(crate::database_encryption::open(path)?)
    }

    /// The database on an open connection: schema and migrations brought up to date.
    pub fn on(c: Connection) -> rusqlite::Result<Db> {
        let fresh: bool = c.query_row("SELECT NOT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'bots')", [], |r| r.get(0))?;
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS bots (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              color TEXT NOT NULL,
              shape TEXT NOT NULL,
              harness TEXT NOT NULL,
              model TEXT,
              session_id TEXT,
              primary_bot INTEGER NOT NULL DEFAULT 0,
              hidden INTEGER NOT NULL DEFAULT 0,
              unread INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
              role TEXT NOT NULL,
              text TEXT NOT NULL,
              question TEXT,
              error INTEGER NOT NULL DEFAULT 0,
              status TEXT,
              created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS messages_bot ON messages(bot_id, id);
            CREATE TABLE IF NOT EXISTS routines (
              id TEXT PRIMARY KEY,
              bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              cron TEXT NOT NULL,
              instruction TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              last_run_at INTEGER,
              created_at INTEGER NOT NULL
            );",
        )?;
        // Added after the first release; fails harmlessly if it already exists.
        let _ = c.execute("ALTER TABLE messages ADD COLUMN from_bot TEXT", []);
        let _ = c.execute("ALTER TABLE bots ADD COLUMN effort TEXT", []);
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, migrate) in MIGRATIONS.iter().enumerate().skip(version.max(0) as usize) {
            let tx = c.unchecked_transaction()?;
            migrate(&tx, fresh)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)?;
            tx.commit()?;
        }
        Ok(Db(Mutex::new(c), std::sync::OnceLock::new(), std::sync::atomic::AtomicBool::new(false), crate::obs::Metrics::default(), crate::obs::trace::Tracer::default(), std::sync::OnceLock::new()))
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The connection, for a module that keeps its own table (audit checkpoints, ADR 0149).
    /// `f` must not call back into `Db`: the connection is held until it returns.
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        f(&self.c())
    }

    /// Set once, by the app, from its license (ADR 0038).
    pub fn set_seat_cap(&self, cap: SeatCap) {
        let _ = self.1.set(cap);
    }

    fn seat_cap(&self) -> Option<u32> {
        self.1.get().and_then(|f| f())
    }

    /// This server's counters for `/metrics` (ADR 0089).
    pub fn metrics(&self) -> &crate::obs::Metrics {
        &self.3
    }

    /// This server's tracer (ADR 0118): off unless started with an endpoint.
    pub fn tracer(&self) -> &crate::obs::trace::Tracer {
        &self.4
    }

    // Generic settings, for small values that need no table of their own.

    pub fn setting(&self, key: &str) -> Option<String> {
        self.c().query_row("SELECT value FROM settings WHERE key = ?", [key], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        self.c().execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [key, value]).unwrap();
    }

    /// Sets (Some) or removes (None) several settings in one transaction: all of them or none.
    pub fn write_settings(&self, writes: &[(&str, Option<&str>)]) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        for (key, value) in writes {
            let done = match value {
                Some(v) => tx.execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [key, v]),
                None => tx.execute("DELETE FROM settings WHERE key = ?", [key]),
            };
            if done.is_err() {
                return false;
            }
        }
        tx.commit().is_ok()
    }

    // Bots

    pub fn bots(&self) -> Vec<Bot> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bots ORDER BY primary_bot DESC, created_at").unwrap();
        s.query_map([], bot_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn bot(&self, id: &str) -> Option<Bot> {
        self.c().query_row("SELECT * FROM bots WHERE id = ?", [id], bot_row).optional().ok().flatten()
    }

    /// Owned by the owner account and shared, like every Bot from before ACLs.
    pub fn create_bot(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool) -> Bot {
        self.create_bot_owned(name, color, shape, harness, model, primary, crate::users::OPERATOR, Visibility::Shared)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_bot_owned(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool, owner: &str, visibility: Visibility) -> Bot {
        self.create_bot_capped(name, color, shape, harness, model, primary, owner, visibility, None).unwrap()
    }

    /// None when the owner already has `max_bots`. Counting and inserting are one
    /// statement, so two creates racing for the last slot can't both get it.
    #[allow(clippy::too_many_arguments)]
    pub fn create_bot_capped(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, primary: bool, owner: &str, visibility: Visibility, max_bots: Option<u32>) -> Option<Bot> {
        let id = crate::short_id();
        let n = self
            .c()
            .execute(
                "INSERT INTO bots (id, name, color, shape, harness, model, primary_bot, created_at, owner_id, visibility)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                 WHERE ?11 IS NULL OR (SELECT COUNT(*) FROM bots WHERE owner_id = ?9) < ?11",
                params![id, name, color, shape, harness, model, primary, now(), owner, visibility.as_str(), max_bots],
            )
            .unwrap();
        if n == 0 { None } else { self.bot(&id) }
    }

    /// A private Bot of `owner` that their service account `account` made and keeps (ADR
    /// 0222). Counted against the owner's `max_bots` and the account's `max_kept`, and only
    /// while the account is live and still `owner`'s, all in one statement.
    #[allow(clippy::too_many_arguments)]
    pub fn create_service_account_bot(&self, name: &str, color: &str, shape: &str, harness: &str, model: Option<&str>, owner: &str, account: &str, max_bots: Option<u32>, max_kept: u32) -> Result<Bot, KeptBotRefusal> {
        let id = crate::short_id();
        let n = self
            .c()
            .execute(
                "INSERT INTO bots (id, name, color, shape, harness, model, primary_bot, created_at, owner_id, visibility, service_account_id)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, 'private', ?9
                 WHERE EXISTS (SELECT 1 FROM service_accounts WHERE user_id = ?9 AND owner_id = ?8 AND deleted_at IS NULL)
                   AND (SELECT COUNT(*) FROM bots WHERE service_account_id = ?9) < ?11
                   AND (?10 IS NULL OR (SELECT COUNT(*) FROM bots WHERE owner_id = ?8) < ?10)",
                params![id, name, color, shape, harness, model, now(), owner, account, max_bots, max_kept],
            )
            .unwrap();
        if n > 0 {
            return self.bot(&id).ok_or(KeptBotRefusal::Account);
        }
        if self.service_account(account).is_none_or(|s| s.deleted_at.is_some() || s.owner_id != owner) {
            Err(KeptBotRefusal::Account)
        } else if self.kept_bots(account).len() >= max_kept as usize {
            Err(KeptBotRefusal::AccountLimit)
        } else {
            Err(KeptBotRefusal::PlanLimit)
        }
    }

    /// The ids of the Bots service account `account` keeps (ADR 0222), oldest first.
    pub fn kept_bots(&self, account: &str) -> Vec<String> {
        kept_in(&self.c(), account).unwrap_or_default()
    }

    /// Hands `bot`, while `owner` owns it, to their live service account `account` to keep
    /// (ADR 0229), and takes away the account's grant on it, in one transaction. The owner,
    /// the account and its `max_kept` are checked in the same statement as the change, so a
    /// request racing another, a new owner or a deleted account can't overshoot or link a
    /// stranger's account.
    pub fn keep_bot(&self, bot: &str, owner: &str, account: &str, max_kept: u32) -> Result<Handed, KeepRefusal> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|_| KeepRefusal::Bot)?;
        let res = (|| {
            let Some(from) = tx.query_row("SELECT service_account_id FROM bots WHERE id = ?1 AND owner_id = ?2", [bot, owner], |r| r.get::<_, Option<String>>(0)).optional()? else {
                return Ok(Err(KeepRefusal::Bot));
            };
            if from.as_deref() == Some(account) {
                return Ok(Ok(Handed { from, grant: None }));
            }
            let n = tx.execute(
                "UPDATE bots SET service_account_id = ?3 WHERE id = ?1 AND owner_id = ?2
                   AND EXISTS (SELECT 1 FROM service_accounts WHERE user_id = ?3 AND owner_id = ?2 AND deleted_at IS NULL)
                   AND (SELECT COUNT(*) FROM bots WHERE service_account_id = ?3 AND id <> ?1) < ?4",
                params![bot, owner, account, max_kept],
            )?;
            if n == 0 {
                let live: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM service_accounts WHERE user_id = ?1 AND owner_id = ?2 AND deleted_at IS NULL)", [account, owner], |r| r.get(0))?;
                return Ok(Err(if live { KeepRefusal::Limit } else { KeepRefusal::Account }));
            }
            let grant = tx
                .query_row("SELECT * FROM bot_grants WHERE bot_id = ?1 AND user_id = ?2", [bot, account], grant_row)
                .optional()?
                .map(|g| g.level);
            tx.execute("DELETE FROM bot_grants WHERE bot_id = ?1 AND user_id = ?2", [bot, account])?;
            Ok::<_, rusqlite::Error>(Ok(Handed { from, grant }))
        })();
        match res {
            Ok(Ok(h)) => tx.commit().map(|_| h).map_err(|_| KeepRefusal::Bot),
            Ok(Err(why)) => Err(why),
            Err(_) => Err(KeepRefusal::Bot),
        }
    }

    /// Stops `account` keeping `bot` (ADR 0229); the Bot stays its owner's. False when it
    /// didn't keep it (any more).
    pub fn release_kept_bot(&self, bot: &str, account: &str) -> bool {
        self.c().execute("UPDATE bots SET service_account_id = NULL WHERE id = ?1 AND service_account_id = ?2", [bot, account]).unwrap() > 0
    }

    // Bot ACLs (ADR 0017)

    /// False when the new owner already has `max_bots`; checked in the same statement.
    pub fn set_bot_owner_capped(&self, id: &str, owner: &str, max_bots: Option<u32>) -> bool {
        self.c()
            .execute(
                "UPDATE bots SET owner_id = ?1 WHERE id = ?2 AND (?3 IS NULL OR (SELECT COUNT(*) FROM bots WHERE owner_id = ?1) < ?3)",
                params![owner, id, max_bots],
            )
            .unwrap()
            > 0
    }

    pub fn set_bot_visibility(&self, id: &str, v: Visibility) {
        self.c().execute("UPDATE bots SET visibility = ? WHERE id = ?", params![v.as_str(), id]).unwrap();
    }

    pub fn grant(&self, bot_id: &str, user_id: &str) -> Option<Grant> {
        self.c()
            .query_row("SELECT * FROM bot_grants WHERE bot_id = ? AND user_id = ?", [bot_id, user_id], grant_row)
            .optional()
            .ok()
            .flatten()
            .map(|g| g.level)
    }

    /// A user's grants, by Bot id.
    pub fn user_grants(&self, user_id: &str) -> std::collections::HashMap<String, Grant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bot_grants WHERE user_id = ?").unwrap();
        s.query_map([user_id], grant_row).unwrap().filter_map(Result::ok).map(|g| (g.bot_id, g.level)).collect()
    }

    pub fn grants(&self, bot_id: &str) -> Vec<BotGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM bot_grants WHERE bot_id = ? ORDER BY created_at, user_id").unwrap();
        s.query_map([bot_id], grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Adds or changes a grant. Returns the level it had before.
    pub fn set_grant(&self, bot_id: &str, user_id: &str, level: Grant, by: &str) -> Option<Grant> {
        let before = self.grant(bot_id, user_id);
        self.c()
            .execute(
                "INSERT INTO bot_grants (bot_id, user_id, level, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(bot_id, user_id) DO UPDATE SET level = ?3, created_at = ?4, created_by = ?5",
                params![bot_id, user_id, level.as_str(), now(), by],
            )
            .unwrap();
        before
    }

    /// Removes a grant. Returns its level, or None if there was none.
    pub fn remove_grant(&self, bot_id: &str, user_id: &str) -> Option<Grant> {
        let before = self.grant(bot_id, user_id)?;
        self.c().execute("DELETE FROM bot_grants WHERE bot_id = ? AND user_id = ?", [bot_id, user_id]).unwrap();
        Some(before)
    }

    pub fn update_bot(&self, id: &str, p: BotPatch) {
        let c = self.c();
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            c.execute(&format!("UPDATE bots SET {col} = ? WHERE id = ?"), params![v, id]).unwrap();
        };
        if let Some(v) = p.name { set("name", &v) }
        if let Some(v) = p.color { set("color", &v) }
        if let Some(v) = p.shape { set("shape", &v) }
        if let Some(v) = p.harness { set("harness", &v) }
        if let Some(v) = p.model { set("model", &v) }
        if let Some(v) = p.effort { set("effort", &v) }
        if let Some(v) = p.session_id { set("session_id", &v) }
        if let Some(v) = p.hidden { set("hidden", &v) }
        if let Some(v) = p.unread { set("unread", &v) }
        if let Some(v) = p.prompts { set("prompts", &v.map(|l| serde_json::to_string(&l).unwrap())) }
    }

    #[cfg(test)]
    pub fn delete_bot(&self, id: &str) {
        self.c().execute("DELETE FROM bots WHERE id = ?", [id]).unwrap();
    }

    // Messages

    pub fn messages(&self, bot_id: &str, limit: i64) -> Vec<Message> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM (SELECT * FROM messages WHERE bot_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id")
            .unwrap();
        s.query_map(params![bot_id, limit], message_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn last_message(&self, bot_id: &str) -> Option<Message> {
        self.c()
            .query_row(
                "SELECT * FROM messages WHERE bot_id = ? AND role != 'routine' ORDER BY id DESC LIMIT 1",
                [bot_id],
                message_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The Bot's latest unanswered handoff card, unless the user wrote after it.
    pub fn open_handoff(&self, bot_id: &str) -> Option<i64> {
        self.c()
            .query_row(
                "SELECT id FROM messages WHERE bot_id = ?1 AND role = 'bot'
                   AND json_extract(question, '$.handoff') = 1 AND json_extract(question, '$.picked') IS NULL
                   AND id > COALESCE((SELECT MAX(id) FROM messages WHERE bot_id = ?1 AND role = 'user'), 0)
                 ORDER BY id DESC LIMIT 1",
                [bot_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn message(&self, id: i64) -> Option<Message> {
        self.c().query_row("SELECT * FROM messages WHERE id = ?", [id], message_row).optional().ok().flatten()
    }

    pub fn add_message(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>) -> Message {
        self.add_message_from(bot_id, role, text, question, error, status, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_message_from(&self, bot_id: &str, role: &str, text: &str, question: Option<&Value>, error: bool, status: Option<&str>, from_bot: Option<&str>) -> Message {
        let owners: Vec<String> = [Some(bot_id), from_bot].into_iter().flatten().filter_map(|b| self.bot_owner(b)).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        let question = question.map(|q| redact::value_for(&owners, q.clone()).to_string());
        let c = self.c();
        let id = self
            .insert_chat_message(
                &c,
                bot_id,
                &["bot_id", "role", "text", "question", "error", "status", "from_bot", "created_at"],
                params![bot_id, role, redact::text_for(&owners, text), question, error, status, from_bot, now()],
            )
            .unwrap();
        drop(c);
        self.message(id).unwrap()
    }

    pub fn last_id(&self) -> i64 {
        self.top_message_id(&self.c())
    }

    /// The Bot's chat bubbles written after message `after`.
    pub fn replies_after(&self, bot_id: &str, after: i64) -> Vec<Message> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM messages WHERE bot_id = ? AND id > ? AND role = 'bot' ORDER BY id").unwrap();
        s.query_map(params![bot_id, after], message_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn set_status(&self, id: i64, status: &str) {
        self.on_places(&self.c(), "UPDATE {messages} SET status = ? WHERE id = ?", params![status, id]).unwrap();
    }

    /// Free text (name, email, user agent) is masked as `record` masks it.
    pub fn set_requested_by(&self, id: i64, who: &audit::Who) {
        let mut who = who.clone();
        for v in [&mut who.actor.name, &mut who.actor.email, &mut who.source.user_agent].into_iter().flatten() {
            *v = audit::redact_text(v);
        }
        let who = serde_json::to_value(&who).map(|v| redact::value(v).to_string()).unwrap_or_default();
        self.on_places(&self.c(), "UPDATE {messages} SET requested_by = ? WHERE id = ?", params![who, id]).unwrap();
    }

    pub fn set_question(&self, id: i64, q: &Value) {
        let owner = self.message(id).and_then(|m| self.bot_owner(&m.bot_id));
        let q = redact::value_for(owner.as_deref().as_slice(), q.clone()).to_string();
        self.on_places(&self.c(), "UPDATE {messages} SET question = ? WHERE id = ?", params![q, id]).unwrap();
    }

    /// Who owns a Bot: whose own secrets are redacted from what it writes (ADR 0029).
    pub fn bot_owner(&self, bot_id: &str) -> Option<String> {
        self.c().query_row("SELECT owner_id FROM bots WHERE id = ?", [bot_id], |r| r.get(0)).ok()
    }

    pub fn pending(&self) -> Vec<Message> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM messages WHERE status IN ('queued', 'running') ORDER BY id").unwrap();
        s.query_map([], message_row).unwrap().filter_map(Result::ok).collect()
    }

    // Chat retention (ADR 0098)

    /// Days of chat history to keep, as last saved. None = forever.
    pub fn chat_retention(&self) -> Option<u32> {
        self.setting("chat_retention_days").and_then(|s| s.parse().ok()).filter(|d| *d > 0)
    }

    pub fn set_chat_retention(&self, days: Option<u32>) {
        match days {
            Some(d) => self.set_setting("chat_retention_days", &d.to_string()),
            None => {
                self.c().execute("DELETE FROM settings WHERE key = 'chat_retention_days'", []).unwrap();
            }
        }
    }

    /// A retention setting in days, as last saved under `key`. None = forever.
    pub fn retention_days(&self, key: &str) -> Option<u32> {
        self.setting(key).and_then(|s| s.parse().ok()).filter(|d| *d > 0)
    }

    pub fn set_retention_days(&self, key: &str, days: Option<u32>) {
        match days {
            Some(d) => self.set_setting(key, &d.to_string()),
            None => {
                self.c().execute("DELETE FROM settings WHERE key = ?", [key]).unwrap();
            }
        }
    }

    /// Teammates' work archived to their owner's `from-teammates/` folder before `cutoff`
    /// (unix ms) and not deleted yet (ADR 0112): `(table, id, owner, machine (None: this
    /// server), archived to)`, oldest first.
    pub fn archives_before(&self, cutoff: i64) -> Vec<(&'static str, String, String, Option<String>, String)> {
        let c = self.c();
        let mut out = Vec::new();
        for (table, machine) in [("teammate_cleanups", "machine_id"), ("account_removals", "NULL")] {
            let mut s = c
                .prepare(&format!(
                    "SELECT id, owner_id, {machine}, archived_to FROM {table}
                     WHERE files = 'archive' AND archived_to IS NOT NULL AND removed_at < ? AND archive_pruned_at IS NULL
                     ORDER BY removed_at, id"
                ))
                .unwrap();
            let rows = s.query_map([cutoff], |r| Ok((table, r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
            out.extend(rows.filter_map(Result::ok));
        }
        out
    }

    /// The retention pass deleted the archive, or found it gone.
    pub fn archive_pruned(&self, table: &str, id: &str) {
        if matches!(table, "teammate_cleanups" | "account_removals") {
            let _ = self.c().execute(&format!("UPDATE {table} SET archive_pruned_at = ? WHERE id = ?"), params![now(), id]);
        }
    }

    /// Sets when a removal was done, as if long ago.
    #[cfg(test)]
    pub fn set_removed_at(&self, table: &str, id: &str, at: i64) {
        self.c().execute(&format!("UPDATE {table} SET removed_at = ? WHERE id = ?"), params![at, id]).unwrap();
    }

    /// Clears the Bot's session if it is still `session_id`, whose files are gone.
    pub fn forget_session_if(&self, bot_id: &str, session_id: &str) -> bool {
        self.c().execute("UPDATE bots SET session_id = NULL WHERE id = ? AND session_id = ?", [bot_id, session_id]).unwrap_or(0) == 1
    }

    /// Deletes up to `limit` of the oldest messages written before `cutoff` (unix ms) and
    /// after `after` (the `(created_at, id)` a pass's previous batch ended on), and returns how
    /// many went and where this batch ended. Never a message whose run is queued or running,
    /// nor one in or from a held Bot's chat; the cursor means each batch starts past the rows
    /// earlier batches already looked at, so a large held chat is walked once per pass.
    pub fn prune_chat_batch(&self, cutoff: i64, after: Option<(i64, i64)>, limit: u32) -> rusqlite::Result<(usize, Option<(i64, i64)>)> {
        let (at, id) = after.unwrap_or((i64::MIN, i64::MIN));
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        let ids: Vec<(i64, i64)> = {
            let mut s = tx.prepare(
                "SELECT created_at, id FROM messages
                  WHERE created_at < ?1 AND (created_at, id) > (?2, ?3)
                    AND (status IS NULL OR status NOT IN ('queued', 'running'))
                    AND bot_id NOT IN (SELECT bot_id FROM retention_holds)
                    AND (from_bot IS NULL OR from_bot NOT IN (SELECT bot_id FROM retention_holds))
                  ORDER BY created_at, id LIMIT ?4",
            )?;
            s.query_map(params![cutoff, at, id, limit], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        let mut deleted = 0;
        for (_, id) in &ids {
            deleted += self.on_places(&tx, "DELETE FROM {messages} WHERE id = ?", &[id])?;
        }
        tx.commit()?;
        Ok((deleted, ids.last().copied()))
    }

    /// How many Bots are held, for a pass's record.
    pub fn retention_hold_count(&self) -> rusqlite::Result<usize> {
        self.c().query_row("SELECT COUNT(*) FROM retention_holds", [], |r| r.get::<_, i64>(0)).map(|n| n as usize)
    }

    pub fn try_set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.c().execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [key, value]).map(|_| ())
    }

    pub fn retention_holds(&self) -> Vec<RetentionHold> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM retention_holds ORDER BY held_at, bot_id").unwrap();
        s.query_map([], retention_hold_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn retention_hold(&self, bot_id: &str) -> Option<RetentionHold> {
        self.c().query_row("SELECT * FROM retention_holds WHERE bot_id = ?", [bot_id], retention_hold_row).optional().ok().flatten()
    }

    /// Holds the Bot's chat, or changes the reason of its hold. Keeps who held it first and when.
    /// None when the Bot is gone, even if it was deleted a moment ago.
    pub fn put_retention_hold(&self, bot_id: &str, reason: &str, by: Option<&str>) -> Option<RetentionHold> {
        let n = self
            .c()
            .execute(
                "INSERT INTO retention_holds (bot_id, reason, held_by, held_at)
                 SELECT id, ?2, ?3, ?4 FROM bots WHERE id = ?1
                 ON CONFLICT(bot_id) DO UPDATE SET reason = ?2",
                params![bot_id, reason, by, now()],
            )
            .ok()?;
        if n == 0 {
            return None;
        }
        self.retention_hold(bot_id)
    }

    /// Whether deleting the Bot would delete held chat: it is held, or a held Bot wrote into
    /// its chat (deleting a Bot deletes every message in its chat).
    pub fn bot_chat_held(&self, id: &str) -> bool {
        self.c().query_row(&format!("SELECT {HELD_CHAT}"), [id], |r| r.get(0)).unwrap()
    }

    /// Deletes the Bot unless its chat is held (`bot_chat_held`), in one statement, so a hold
    /// placed at any moment before wins. Whether it was deleted.
    pub fn delete_bot_unless_held(&self, id: &str) -> bool {
        let c = self.c();
        let gone = c.execute(&format!("DELETE FROM bots WHERE id = ?1 AND NOT {HELD_CHAT}"), [id]).unwrap() > 0;
        if gone {
            for table in ["{messages}", "{routines}", "{approvals}"] {
                self.on_places(&c, &format!("DELETE FROM {table} WHERE bot_id = ?1"), &[&id]).unwrap();
            }
        }
        gone
    }

    /// Whether there was a hold to release.
    pub fn delete_retention_hold(&self, bot_id: &str) -> bool {
        self.c().execute("DELETE FROM retention_holds WHERE bot_id = ?", [bot_id]).unwrap() > 0
    }

    /// `n` plain messages in the Bot's chat, written at `at`, in one transaction.
    #[cfg(test)]
    pub fn add_messages_at(&self, bot_id: &str, n: usize, at: i64, from_bot: Option<&str>) {
        let mut c = self.c();
        let tx = c.transaction().unwrap();
        for i in 0..n {
            self.insert_chat_message(&tx, bot_id, &["bot_id", "role", "text", "from_bot", "created_at"], params![bot_id, "user", format!("old {i}"), from_bot, at]).unwrap();
        }
        tx.commit().unwrap();
    }

    #[cfg(test)]
    pub fn set_message_time(&self, id: i64, at: i64) {
        self.on_places(&self.c(), "UPDATE {messages} SET created_at = ?1 WHERE id = ?2", params![at, id]).unwrap();
    }

    #[cfg(test)]
    pub fn message_count(&self, bot_id: &str) -> i64 {
        self.c().query_row("SELECT COUNT(*) FROM messages WHERE bot_id = ?", [bot_id], |r| r.get(0)).unwrap()
    }

    // Routines

    pub fn routines(&self, bot_id: Option<&str>) -> Vec<Routine> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM routines WHERE ?1 IS NULL OR bot_id = ?1 ORDER BY created_at")
            .unwrap();
        s.query_map([bot_id], routine_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn routine(&self, id: &str) -> Option<Routine> {
        self.c().query_row("SELECT * FROM routines WHERE id = ?", [id], routine_row).optional().ok().flatten()
    }

    #[cfg(test)]
    pub fn add_routine(&self, bot_id: &str, name: &str, cron: &str, instruction: &str) -> Routine {
        self.add_routine_by(bot_id, name, cron, instruction, true, None)
    }

    /// A routine whose runs are for `author` (ADR 0046), written whole so the scheduler
    /// never sees it without its author.
    pub fn add_routine_by(&self, bot_id: &str, name: &str, cron: &str, instruction: &str, enabled: bool, author: Option<&str>) -> Routine {
        let c = self.c();
        let id = self.unused_id(&c, "routines").unwrap();
        let cols = ["id", "bot_id", "name", "cron", "instruction", "enabled", "author_id", "created_at"];
        self.insert_kept(&c, "routines", bot_id, &cols, params![id, bot_id, name, cron, instruction, enabled, author, now()]).unwrap();
        drop(c);
        self.routine(&id).unwrap()
    }

    /// `author`: whom its runs are for once `instruction` changes it (ADR 0046). Both
    /// change under one lock, so the scheduler never reads one without the other.
    pub fn update_routine(&self, id: &str, name: Option<&str>, cron: Option<&str>, instruction: Option<&str>, enabled: Option<bool>, author: Option<&str>) {
        let c = self.c();
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            self.on_places(&c, &format!("UPDATE {{routines}} SET {col} = ? WHERE id = ?"), params![v, id]).unwrap();
        };
        if let Some(v) = name { set("name", &v) }
        if let Some(v) = cron { set("cron", &v) }
        if let Some(v) = instruction {
            if let Some(a) = author {
                self.on_places(&c, "UPDATE {routines} SET author_id = ? WHERE id = ? AND instruction != ?", params![a, id, v]).unwrap();
            }
            set("instruction", &v)
        }
        if let Some(v) = enabled {
            self.on_places(&c, "UPDATE {routines} SET enabled = ?, paused_reason = NULL, paused_for = NULL, paused_at = NULL WHERE id = ?", params![v, id]).unwrap();
        }
    }

    /// Turns a routine off for a disabled user (ADR 0047). False when it was already off.
    pub fn pause_routine(&self, id: &str, reason: &str, for_user: &str, at: i64) -> bool {
        self.on_places(
            &self.c(),
            "UPDATE {routines} SET enabled = 0, paused_reason = ?, paused_for = ?, paused_at = ? WHERE id = ? AND enabled = 1",
            params![reason, for_user, at, id],
        )
        .unwrap()
            > 0
    }

    /// Routines botd paused for `user_id`.
    pub fn routines_paused_for(&self, user_id: &str) -> Vec<Routine> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM routines WHERE paused_for = ? AND enabled = 0 ORDER BY created_at").unwrap();
        s.query_map([user_id], routine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Turns a paused routine back on. False when it isn't paused any more.
    pub fn resume_routine(&self, id: &str) -> bool {
        self.on_places(
            &self.c(),
            "UPDATE {routines} SET enabled = 1, paused_reason = NULL, paused_for = NULL, paused_at = NULL WHERE id = ? AND enabled = 0 AND paused_reason IS NOT NULL",
            &[&id],
        )
        .unwrap()
            > 0
    }

    /// Keeps a paused routine off, now for someone else who is still disabled.
    pub fn repause_routine(&self, id: &str, reason: &str, for_user: &str) {
        self.on_places(&self.c(), "UPDATE {routines} SET paused_reason = ?, paused_for = ? WHERE id = ? AND enabled = 0 AND paused_reason IS NOT NULL", params![reason, for_user, id])
            .unwrap();
    }

    /// Moves what a routine holds for `from` (its authorship, its pause) to `to`.
    pub fn hand_over_routine(&self, id: &str, from: &str, to: &str) {
        self.on_places(
            &self.c(),
            "UPDATE {routines} SET author_id = CASE WHEN author_id = ?1 THEN ?2 ELSE author_id END,
               paused_for = CASE WHEN paused_for = ?1 THEN ?2 ELSE paused_for END WHERE id = ?3",
            params![from, to, id],
        )
        .unwrap();
    }

    pub fn routine_ran(&self, id: &str, at: i64) {
        self.on_places(&self.c(), "UPDATE {routines} SET last_run_at = ? WHERE id = ?", params![at, id]).unwrap();
    }

    pub fn delete_routine(&self, id: &str) {
        self.on_places(&self.c(), "DELETE FROM {routines} WHERE id = ?", &[&id]).unwrap();
    }

    // Harness policy

    pub fn global_policy(&self) -> Policy {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'policy'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| Policy::new(Mode::Ask))
    }

    pub fn set_global_policy(&self, p: &Policy) {
        self.c()
            .execute("INSERT INTO settings (key, value) VALUES ('policy', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [serde_json::to_string(p).unwrap()])
            .unwrap();
    }

    /// The onboarding wizard's progress (ADR 0034).
    pub fn setup_progress(&self) -> crate::setup::Progress {
        Self::read_setup(&self.c())
    }

    fn read_setup(c: &Connection) -> crate::setup::Progress {
        let v: Option<String> = c.query_row("SELECT value FROM settings WHERE key = 'setup'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    /// Changes the progress under one lock, so concurrent saves of different fields don't
    /// undo each other. Returns it before and after; nothing is written when `f` fails.
    pub fn update_setup_progress<E>(&self, f: impl FnOnce(&mut crate::setup::Progress) -> Result<(), E>) -> Result<(crate::setup::Progress, crate::setup::Progress), E> {
        let c = self.c();
        let before = Self::read_setup(&c);
        let mut after = before.clone();
        f(&mut after)?;
        if after != before {
            c.execute("INSERT INTO settings (key, value) VALUES ('setup', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [serde_json::to_string(&after).unwrap()])
                .unwrap();
        }
        Ok((before, after))
    }

    pub fn bot_override(&self, bot_id: &str) -> Option<Override> {
        let v: Option<String> = self.c().query_row("SELECT policy FROM bot_policies WHERE bot_id = ?", [bot_id], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| serde_json::from_str(&s).ok())
    }

    /// None: the Bot follows the global policy again.
    pub fn set_bot_override(&self, bot_id: &str, o: Option<&Override>) {
        let c = self.c();
        match o {
            Some(o) => c.execute(
                "INSERT INTO bot_policies (bot_id, policy, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(bot_id) DO UPDATE SET policy = ?2, updated_at = ?3",
                params![bot_id, serde_json::to_string(o).unwrap(), now()],
            ),
            None => c.execute("DELETE FROM bot_policies WHERE bot_id = ?", [bot_id]),
        }
        .unwrap();
    }

    pub fn effective_policy(&self, bot_id: &str) -> Policy {
        let global = self.global_policy();
        self.bot_override(bot_id).map(|o| o.apply(&global)).unwrap_or(global)
    }

    /// Rules for one Bot plus the global ones (`Some`), only global ones (`None`).
    pub fn rules(&self, bot_id: Option<&str>) -> Vec<Rule> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM policy_rules WHERE bot_id IS NULL OR bot_id = ?1 ORDER BY created_at").unwrap();
        s.query_map([bot_id], rule_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn rule(&self, id: &str) -> Option<Rule> {
        self.c().query_row("SELECT * FROM policy_rules WHERE id = ?", [id], rule_row).optional().ok().flatten()
    }

    pub fn add_rule(&self, bot_id: Option<&str>, action: Action, tool: &str, pattern: &str, note: Option<&str>) -> Rule {
        let id = crate::short_id();
        let action = if action == Action::Allow { "allow" } else { "deny" };
        self.c()
            .execute(
                "INSERT INTO policy_rules (id, bot_id, action, tool, pattern, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![id, bot_id, action, tool, pattern, note, now()],
            )
            .unwrap();
        self.rule(&id).unwrap()
    }

    pub fn delete_rule(&self, id: &str) {
        self.c().execute("DELETE FROM policy_rules WHERE id = ?", [id]).unwrap();
    }

    // Approvals

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_approval(&self, bot_id: &str, harness: &str, tool: &str, kind: &str, subject: &str, input: &Value, class: &str, reason: &str, expires_at: i64) -> Approval {
        self.add_approval_in_run(bot_id, harness, tool, kind, subject, input, class, reason, expires_at, None)
    }

    /// `add_approval` for a call from a live run: `run` is its id, and what approving the
    /// call for the rest of that run would cover (None: it can only be approved once).
    #[allow(clippy::too_many_arguments)]
    pub fn add_approval_in_run(
        &self,
        bot_id: &str,
        harness: &str,
        tool: &str,
        kind: &str,
        subject: &str,
        input: &Value,
        class: &str,
        reason: &str,
        expires_at: i64,
        run: Option<(&str, Option<&crate::policy::RunScope>)>,
    ) -> Approval {
        // Keep the row small: a huge file write is summarized by its subject anyway.
        let owner = self.bot_owner(bot_id);
        let owners: Vec<&str> = owner.as_deref().into_iter().collect();
        let owners = owners.as_slice();
        let mut input = redact::value_for(owners, input.clone()).to_string();
        if input.len() > 20_000 {
            input = serde_json::json!({ "truncated": input.chars().take(20_000).collect::<String>() }).to_string();
        }
        let run_id = run.map(|(r, _)| r);
        let run_scope = run.and_then(|(_, s)| s).map(|s| {
            let covers: Vec<String> = s.covers_text().iter().map(|w| redact::text_for(owners, w).into_owned()).collect();
            serde_json::json!({ "covers": covers, "exact": s.exact.is_some() }).to_string()
        });
        let subject = redact::text_for(owners, subject);
        let c = self.c();
        let id = self.unused_id(&c, "approvals").unwrap();
        // Tool input can hold anything a Bot wrote (file contents, commands), so it is sealed at rest.
        let input = sealed::seal_field(&sealed::approval_context(&id), &input);
        let cols = ["id", "bot_id", "harness", "tool", "kind", "subject", "input", "class", "reason", "status", "created_at", "expires_at", "run_id", "run_scope"];
        let at = now();
        self.insert_kept(&c, "approvals", bot_id, &cols, params![id, bot_id, harness, tool, kind, subject, input, class, reason, "pending", at, expires_at, run_id, run_scope])
            .unwrap();
        drop(c);
        self.approval(&id).unwrap()
    }

    pub fn approval(&self, id: &str) -> Option<Approval> {
        self.c().query_row("SELECT * FROM approvals WHERE id = ?", [id], approval_row).optional().ok().flatten()
    }

    /// Newest first. `status` filters, e.g. "pending".
    pub fn approvals(&self, status: Option<&str>, bot_id: Option<&str>, limit: i64) -> Vec<Approval> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM approvals WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR bot_id = ?2) ORDER BY created_at DESC, rowid DESC LIMIT ?3")
            .unwrap();
        s.query_map(params![status, bot_id, limit], approval_row).unwrap().filter_map(Result::ok).collect()
    }

    /// How many approvals are pending, and when the oldest was asked for.
    pub fn approvals_pending(&self) -> (i64, Option<i64>) {
        self.c()
            .query_row("SELECT COUNT(*), MIN(created_at) FROM approvals WHERE status = 'pending'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or((0, None))
    }

    /// Like `approvals`, but only for these Bots, so `limit` counts only their rows.
    pub fn approvals_among(&self, status: Option<&str>, bot_ids: &[String], limit: i64) -> Vec<Approval> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM approvals WHERE (?1 IS NULL OR status = ?1) AND bot_id IN (SELECT value FROM json_each(?2)) ORDER BY created_at DESC, rowid DESC LIMIT ?3")
            .unwrap();
        let ids = serde_json::to_string(bot_ids).unwrap();
        s.query_map(params![status, ids, limit], approval_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Closes a pending approval. False if it was already closed (first decision wins).
    pub fn finish_approval(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule_id: Option<&str>) -> bool {
        self.finish_approval_scoped(id, status, by, note, rule_id, (status == "approved").then_some("once"))
    }

    /// Approves a pending approval for the rest of its run (ADR 0051). False if it was
    /// already closed.
    pub fn finish_approval_for_run(&self, id: &str, by: &str, note: Option<&str>) -> bool {
        self.finish_approval_scoped(id, "approved", by, note, None, Some("run"))
    }

    fn finish_approval_scoped(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule_id: Option<&str>, scope: Option<&str>) -> bool {
        self.on_places(
            &self.c(),
            "UPDATE {approvals} SET status = ?, decided_by = ?, note = ?, rule_id = ?, scope = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
            params![status, by, note, rule_id, scope, now(), id],
        )
        .unwrap()
            > 0
    }

    /// Closes a pending approval and saves its remembered rule in one transaction,
    /// so a decision that loses the race (to a timeout, a stop, or someone else) saves
    /// no rule. None if the approval was no longer pending.
    pub fn finish_approval_with_rule(&self, id: &str, status: &str, by: &str, note: Option<&str>, rule: &NewRule) -> Option<Rule> {
        let rule_id = crate::short_id();
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let scope = (status == "approved").then_some("once");
        let closed = self
            .on_places(
                &tx,
                "UPDATE {approvals} SET status = ?, decided_by = ?, note = ?, rule_id = ?, scope = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                params![status, by, note, rule_id, scope, now(), id],
            )
            .ok()?;
        if closed == 0 {
            return None;
        }
        let action = if rule.action == Action::Allow { "allow" } else { "deny" };
        tx.execute(
            "INSERT INTO policy_rules (id, bot_id, action, tool, pattern, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![rule_id, rule.bot_id, action, rule.tool, rule.pattern, rule.note, now()],
        )
        .ok()?;
        tx.commit().ok()?;
        drop(c);
        self.rule(&rule_id)
    }

    // Users

    /// Everyone who can sign in: never a service account (ADR 0143), which has its own list.
    pub fn users(&self) -> Vec<User> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM users WHERE kind = 'person' ORDER BY created_at, id").unwrap();
        s.query_map([], user_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn user(&self, id: &str) -> Option<User> {
        self.c().query_row("SELECT * FROM users WHERE id = ?", [id], user_row).optional().ok().flatten()
    }

    /// By id, or by email (case-insensitive) when `key` has an `@`. Never an erased user's
    /// tombstone (ADR 0102); `find_user_any` finds those too.
    pub fn find_user(&self, key: &str) -> Option<User> {
        self.find_user_any(key).filter(|u| u.erased_at.is_none())
    }

    /// `find_user`, erased tombstones included. Never a service account (ADR 0143), so no
    /// route about people (`/api/users`, teams, roles, Bot grants) reaches one.
    pub fn find_user_any(&self, key: &str) -> Option<User> {
        let u = if key.contains('@') {
            self.c().query_row("SELECT * FROM users WHERE email = ?", [key], user_row).optional().ok().flatten()
        } else {
            self.user(key)
        };
        u.filter(|u| !u.service)
    }

    /// Err when the email or id is taken, or no seat is free. The owner account never
    /// needs a seat: it is how an operator gets back in.
    pub fn create_user(&self, id: Option<&str>, email: Option<&str>, name: &str, role: Role) -> Result<User, UserError> {
        let id = id.map(String::from).unwrap_or_else(|| format!("u{}", crate::short_id()));
        let cap = if id == crate::users::OPERATOR { None } else { self.seat_cap() };
        {
            let c = self.c();
            if !Self::seat_free(&c, cap) {
                return Err(UserError::NoSeat);
            }
            Self::insert_user(&c, &id, email, name, role).map_err(|e| if constraint(&e) { UserError::EmailTaken } else { UserError::Db(e.to_string()) })?;
        }
        self.user(&id).ok_or_else(|| UserError::Db("user not saved".into()))
    }

    /// Active users holding a seat (ADR 0038): everyone but the owner account. Service
    /// accounts aren't people and take none (ADR 0143).
    pub fn active_seats(&self) -> u32 {
        Self::seats_used(&self.c())
    }

    fn seats_used(c: &Connection) -> u32 {
        c.query_row("SELECT COUNT(*) FROM users WHERE status = 'active' AND kind = 'person' AND id != ?", [crate::users::OPERATOR], |r| r.get(0)).unwrap_or(0)
    }

    /// Whether one more active user fits under `cap`. Callers hold the one connection
    /// for the count and the write after it, so nothing can take the seat in between.
    fn seat_free(c: &Connection, cap: Option<u32>) -> bool {
        cap.is_none_or(|cap| Self::seats_used(c) < cap)
    }

    /// Whether making this existing user active takes a seat: they're disabled now.
    fn enabling(c: &Connection, user_id: &str) -> bool {
        c.query_row("SELECT status != 'active' AND kind = 'person' AND id != ?2 FROM users WHERE id = ?1", [user_id, crate::users::OPERATOR], |r| r.get(0)).unwrap_or(false)
    }

    fn insert_user(c: &Connection, id: &str, email: Option<&str>, name: &str, role: Role) -> rusqlite::Result<usize> {
        let at = now();
        c.execute(
            "INSERT INTO users (id, email, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![id, email, name, role.as_str(), at, at],
        )
    }

    /// Re-enabling a disabled user needs a free seat, checked in the same transaction.
    pub fn update_user(&self, id: &str, p: UserPatch) -> Result<(), UserError> {
        let cap = self.seat_cap();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| UserError::Db(e.to_string()))?;
        if p.status == Some("active") && Self::enabling(&tx, id) && !Self::seat_free(&tx, cap) {
            return Err(UserError::NoSeat);
        }
        let set = |col: &str, v: &dyn rusqlite::ToSql| {
            tx.execute(&format!("UPDATE users SET {col} = ?, updated_at = ? WHERE id = ?"), params![v, now(), id]).map(|_| ())
        };
        let res = (|| {
            if let Some(v) = &p.email { set("email", v)? }
            if let Some(v) = &p.name { set("display_name", v)? }
            if let Some(v) = p.role {
                set("role", &v.as_str())?;
                set("role_id", &None::<String>)?;
                Self::drop_scim_grant_in(&tx, id, "org")?;
                Self::drop_saml_grant_in(&tx, id)?;
            }
            if let Some(v) = p.status { set("status", &v)? }
            if let Some(v) = &p.tier { set("tier", v)? }
            Ok::<_, rusqlite::Error>(())
        })();
        match res {
            Ok(()) => tx.commit().map_err(|e| UserError::Db(e.to_string())),
            Err(e) if constraint(&e) => Err(UserError::EmailTaken),
            Err(e) => Err(UserError::Db(e.to_string())),
        }
    }

    /// Sets or clears the user's data region (ADR 0117).
    pub fn set_user_region(&self, id: &str, region: Option<&str>) -> bool {
        self.c().execute("UPDATE users SET region = ?1, updated_at = ?2 WHERE id = ?3", params![region, now(), id]).unwrap_or(0) > 0
    }

    // Custom roles (ADR 0123).

    pub fn custom_roles(&self) -> Vec<CustomRole> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM roles ORDER BY name, id").unwrap();
        s.query_map([], custom_role_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn custom_role(&self, id: &str) -> Option<CustomRole> {
        self.c().query_row("SELECT * FROM roles WHERE id = ?", [id], custom_role_row).optional().ok().flatten()
    }

    /// By id, or by name (case-insensitive).
    pub fn find_custom_role(&self, key: &str) -> Option<CustomRole> {
        self.c().query_row("SELECT * FROM roles WHERE id = ?1 OR name = ?1 ORDER BY id = ?1 DESC LIMIT 1", [key], custom_role_row).optional().ok().flatten()
    }

    /// `max_days` is saved with the role, so it is never held without its limit (ADR 0197).
    pub fn create_custom_role(&self, name: &str, description: &str, base: Role, permissions: &[&str], max_days: Option<i64>, by: Option<&str>) -> Result<CustomRole, RoleError> {
        let id = format!("r{}", crate::random_hex(5));
        let at = now();
        let perms = serde_json::to_string(permissions).unwrap_or_else(|_| "[]".into());
        self.c()
            .execute(
                "INSERT INTO roles (id, name, description, base, permissions, max_days, created_at, created_by, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?7)",
                params![id, name, description, base.as_str(), perms, max_days, at, by],
            )
            .map_err(|e| if constraint(&e) { RoleError::NameTaken } else { RoleError::Db(e.to_string()) })?;
        self.custom_role(&id).ok_or(RoleError::NotFound)
    }

    /// Saves the fields given. A new base applies to everyone who holds the role across the
    /// server, in the same transaction; returns those whose built-in role changed.
    /// `max_days` Some(Some(n)) makes it time-bound (ADR 0197), refused while anyone holds it
    /// longer than that or a group is mapped to it; Some(None) lifts the limit. A
    /// requestable role (ADR 0209) must keep one, checked once both are written.
    pub fn update_custom_role(&self, id: &str, name: Option<&str>, description: Option<&str>, base: Option<Role>, permissions: Option<&[&str]>, max_days: Option<Option<i64>>, requestable: Option<bool>) -> Result<Vec<String>, RoleError> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| RoleError::Db(e.to_string()))?;
        let at = now();
        if let Some(Some(days)) = max_days {
            // Service accounts and groups hold what they're given for as long as they are.
            let held: i64 = tx
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM users WHERE role_id = ?1 AND (role_expires_at IS NULL OR role_expires_at > ?2))
                      + (SELECT COUNT(*) FROM team_members WHERE role_id = ?1 AND (role_expires_at IS NULL OR role_expires_at > ?2))
                      + (SELECT COUNT(*) FROM service_accounts WHERE team_role_id = ?1 AND deleted_at IS NULL)",
                    params![id, at + days * crate::roles::DAY],
                    |r| r.get(0),
                )
                .map_err(|e| RoleError::Db(e.to_string()))?;
            let mapped: i64 = tx
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM scim_role_mappings WHERE role_id = ?1) + (SELECT COUNT(*) FROM saml_role_mappings WHERE role_id = ?1)
                      + (SELECT COUNT(*) FROM scim_role_groups WHERE role_id = ?1)",
                    [id],
                    |r| r.get(0),
                )
                .map_err(|e| RoleError::Db(e.to_string()))?;
            if held + mapped > 0 {
                return Err(RoleError::Standing { held: held as usize, mapped: mapped as usize });
            }
        }
        // In the same transaction as the write, so a mapping made meanwhile is seen (ADR 0138).
        if let Some(v) = permissions {
            let new = crate::rbac::Perms::from_names(v.iter().copied());
            let mut st = tx.prepare("SELECT id, scope FROM scim_role_mappings WHERE role_id = ? ORDER BY created_at, id").map_err(|e| RoleError::Db(e.to_string()))?;
            let maps = st.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>).map_err(|e| RoleError::Db(e.to_string()))?;
            drop(st);
            if let Some((mapping, scope, perms)) = maps.into_iter().map(|(m, sc)| { let p = new.reaching_admins(sc == "team"); (m, sc, p) }).find(|(_, _, p)| !p.is_empty()) {
                return Err(RoleError::Reaches { via: "scim", mapping, scope, perms });
            }
            // Role groups give the role across the server (ADR 0180) or within a team (ADR 0206).
            let mut st = tx.prepare("SELECT id, scope FROM scim_role_groups WHERE role_id = ? ORDER BY created_at, id").map_err(|e| RoleError::Db(e.to_string()))?;
            let groups = st.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>).map_err(|e| RoleError::Db(e.to_string()))?;
            drop(st);
            if let Some((mapping, scope, perms)) = groups.into_iter().map(|(g, sc)| { let p = scim_role_group_reach(new, &sc); (g, sc, p) }).find(|(_, _, p)| !p.is_empty()) {
                return Err(RoleError::Reaches { via: "scim", mapping, scope, perms });
            }
            // SAML mappings give the role across the server (ADR 0160).
            let saml: Option<String> = tx.query_row("SELECT id FROM saml_role_mappings WHERE role_id = ? ORDER BY created_at, id LIMIT 1", [id], |r| r.get(0)).optional().map_err(|e| RoleError::Db(e.to_string()))?;
            let perms = new.reaching_admins(false);
            if let Some(mapping) = saml.filter(|_| !perms.is_empty()) {
                return Err(RoleError::Reaches { via: "saml", mapping, scope: "org".into(), perms });
            }
        }
        let res = (|| {
            if tx.execute("UPDATE roles SET updated_at = ?1 WHERE id = ?2", params![at, id])? == 0 {
                return Ok(Err(RoleError::NotFound));
            }
            let set = |col: &str, v: &dyn rusqlite::ToSql| tx.execute(&format!("UPDATE roles SET {col} = ?1 WHERE id = ?2"), params![v, id]);
            if let Some(v) = name { set("name", &v)?; }
            if let Some(v) = description { set("description", &v)?; }
            if let Some(v) = permissions { set("permissions", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()))?; }
            if let Some(v) = max_days { set("max_days", &v)?; }
            if let Some(v) = requestable { set("requestable", &v)?; }
            if tx.query_row("SELECT requestable = 1 AND max_days IS NULL FROM roles WHERE id = ?", [id], |r| r.get::<_, bool>(0))? {
                return Ok(Err(RoleError::Requestable));
            }
            let mut moved = Vec::new();
            if let Some(b) = base {
                set("base", &b.as_str())?;
                // Not those whose time with it is up: they hold it no longer, so keep their role.
                let held = "role_id = ?1 AND role != ?2 AND (role_expires_at IS NULL OR role_expires_at > ?3)";
                let mut s = tx.prepare(&format!("SELECT id FROM users WHERE {held} ORDER BY id"))?;
                moved = s.query_map(params![id, b.as_str(), at], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                tx.execute(&format!("UPDATE users SET role = ?2, updated_at = ?3 WHERE {held}"), params![id, b.as_str(), at])?;
            }
            Ok(Ok(moved))
        })();
        match res {
            Ok(Ok(moved)) => tx.commit().map(|_| moved).map_err(|e| RoleError::Db(e.to_string())),
            Ok(Err(e)) => Err(e),
            Err(e) if constraint(&e) => Err(RoleError::NameTaken),
            Err(e) => Err(RoleError::Db(e.to_string())),
        }
    }

    /// Deletes a role nobody holds. The count and the delete are one transaction.
    pub fn delete_custom_role(&self, id: &str) -> Result<(), RoleError> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| RoleError::Db(e.to_string()))?;
        let held: i64 = tx
            .query_row(
                "SELECT (SELECT COUNT(*) FROM users WHERE role_id = ?1) + (SELECT COUNT(*) FROM team_members WHERE role_id = ?1)
                  + (SELECT COUNT(*) FROM service_accounts WHERE team_role_id = ?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(|e| RoleError::Db(e.to_string()))?;
        if held > 0 {
            return Err(RoleError::InUse(held as usize));
        }
        let mapped: i64 = tx
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scim_role_mappings WHERE role_id = ?1) + (SELECT COUNT(*) FROM saml_role_mappings WHERE role_id = ?1)
                  + (SELECT COUNT(*) FROM scim_role_groups WHERE role_id = ?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(|e| RoleError::Db(e.to_string()))?;
        if mapped > 0 {
            return Err(RoleError::Mapped(mapped as usize));
        }
        match tx.execute("DELETE FROM roles WHERE id = ?", [id]) {
            Ok(0) => Err(RoleError::NotFound),
            Ok(_) => tx.commit().map_err(|e| RoleError::Db(e.to_string())),
            Err(e) => Err(RoleError::Db(e.to_string())),
        }
    }

    /// Who holds the role: users across the server, and (team, user) pairs within a team.
    /// Not those whose time with it is up (ADR 0197).
    pub fn custom_role_holders(&self, id: &str) -> (Vec<String>, Vec<(String, String)>) {
        let c = self.c();
        let users = c
            .prepare("SELECT id FROM users WHERE role_id = ?1 AND (role_expires_at IS NULL OR role_expires_at > ?2) ORDER BY created_at, id")
            .and_then(|mut s| s.query_map(params![id, now()], |r| r.get(0))?.collect())
            .unwrap_or_default();
        let teams = c
            .prepare("SELECT team_id, user_id FROM team_members WHERE role_id = ?1 AND (role_expires_at IS NULL OR role_expires_at > ?2) ORDER BY team_id, joined_at, user_id")
            .and_then(|mut s| s.query_map(params![id, now()], |r| Ok((r.get(0)?, r.get(1)?)))?.collect())
            .unwrap_or_default();
        (users, teams)
    }

    /// Runs `write`, and when it changed a row, ends a SCIM group's claim on `user_id`'s
    /// role in `scope` (ADR 0138), and across the server a SAML group's (ADR 0160), in one
    /// transaction: a role given or taken away by hand is never one a group takes away
    /// later. `held` reads, in the same transaction, what they held before. None if
    /// nothing changed.
    fn by_hand<T>(&self, user_id: &str, scope: &str, held: impl FnOnce(&Connection) -> rusqlite::Result<T>, write: impl FnOnce(&Connection) -> rusqlite::Result<usize>) -> Option<ByHand<T>> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let before = held(&tx).ok()?;
        if write(&tx).unwrap_or(0) == 0 {
            return None;
        }
        let taken = Self::drop_scim_grant_in(&tx, user_id, scope).ok()?;
        let taken_saml = if scope == "org" { Self::drop_saml_grant_in(&tx, user_id).ok()? } else { None };
        tx.commit().ok().map(|_| ByHand { before, taken, taken_saml })
    }

    /// `give_user_custom_role_until` with no end.
    #[cfg(test)]
    pub fn give_user_custom_role(&self, user_id: &str, role_id: &str) -> Option<ByHand<(Option<String>, Option<Role>)>> {
        self.give_user_custom_role_until(user_id, role_id, None).map(|g| ByHand { before: (g.before.0, g.before.1), taken: g.taken, taken_saml: g.taken_saml })
    }

    /// Gives `user_id` the role across the server, its base becoming their built-in role, in
    /// one transaction, so a role deleted meanwhile can't be half given. Written even when
    /// they hold it already, so it is theirs by hand whatever SCIM took away meanwhile, and
    /// ends at `until`, or not at all (ADR 0197). None if either is gone, or the role is
    /// time-bound and `until` is missing or later than it allows, as it is now; else the
    /// custom and built-in roles they held just before, with its end (none once it passed).
    pub fn give_user_custom_role_until(&self, user_id: &str, role_id: &str, until: Option<i64>) -> Option<ByHand<(Option<String>, Option<Role>, Option<i64>)>> {
        let held = |c: &Connection| {
            c.query_row("SELECT role_id, role, role_expires_at FROM users WHERE id = ?", [user_id], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?)))
                .optional()
                .map(|h| h.map_or((None, None, None), |(id, role, ends)| {
                    let (id, ends) = held_until(id, ends);
                    (id, Role::parse(&role), ends)
                }))
        };
        self.by_hand(user_id, "org", held, |c| {
            let n = c.execute(
                &format!("UPDATE users SET role_id = ?1, role = (SELECT base FROM roles WHERE id = ?1), updated_at = ?2 WHERE id = ?3 AND {GIVABLE}"),
                params![role_id, now(), user_id, until, crate::roles::DAY],
            )?;
            if n > 0 {
                c.execute("UPDATE users SET role_expires_at = ?1 WHERE id = ?2", params![until, user_id])?;
            }
            Ok(n)
        })
    }

    /// Takes the role away across the server. They keep its base as their built-in role.
    pub fn clear_user_custom_role(&self, user_id: &str, role_id: &str) -> bool {
        self.by_hand(user_id, "org", |_| Ok(()), |c| c.execute("UPDATE users SET role_id = NULL, updated_at = ?1 WHERE id = ?2 AND role_id = ?3", params![now(), user_id, role_id])).is_some()
    }

    /// Gives (Some) or takes away (None) a role within the team `user_id` is on. False if
    /// they aren't on that team, or the role is gone.
    pub fn set_team_custom_role(&self, team_id: &str, user_id: &str, role_id: Option<&str>) -> bool {
        self.give_team_custom_role(team_id, user_id, role_id).is_some()
    }

    /// `set_team_custom_role`, and the custom role they held in the team just before.
    pub fn give_team_custom_role(&self, team_id: &str, user_id: &str, role_id: Option<&str>) -> Option<ByHand<Option<String>>> {
        let res = match role_id {
            Some(r) => self.give_team_custom_role_until(team_id, user_id, r, None),
            None => {
                let held = |c: &Connection| Self::team_role_held(c, team_id, user_id);
                self.by_hand(user_id, "team", held, |c| c.execute("UPDATE team_members SET role_id = NULL WHERE team_id = ?1 AND user_id = ?2", params![team_id, user_id]))
            }
        };
        res.map(|g| ByHand { before: g.before.0, taken: g.taken, taken_saml: g.taken_saml })
    }

    /// The custom role `user_id` holds in `team_id`, with its end (ADR 0197).
    fn team_role_held(c: &Connection, team_id: &str, user_id: &str) -> rusqlite::Result<(Option<String>, Option<i64>)> {
        let row = c.query_row("SELECT role_id, role_expires_at FROM team_members WHERE team_id = ? AND user_id = ?", [team_id, user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        Ok(row.map_or((None, None), |(id, ends)| held_until(id, ends)))
    }

    /// Gives a role within the team `user_id` is on, ending at `until` (ADR 0197) or not at
    /// all. None as `give_user_custom_role_until` is, or when they aren't on that team.
    pub fn give_team_custom_role_until(&self, team_id: &str, user_id: &str, role_id: &str, until: Option<i64>) -> Option<ByHand<(Option<String>, Option<i64>)>> {
        let held = |c: &Connection| Self::team_role_held(c, team_id, user_id);
        self.by_hand(user_id, "team", held, |c| {
            let n = c.execute(
                &format!("UPDATE team_members SET role_id = ?1 WHERE team_id = ?6 AND user_id = ?3 AND {GIVABLE}"),
                params![role_id, now(), user_id, until, crate::roles::DAY, team_id],
            )?;
            if n > 0 {
                c.execute("UPDATE team_members SET role_expires_at = ?1 WHERE user_id = ?2", params![until, user_id])?;
            }
            Ok(n)
        })
    }

    /// Takes away, from everyone, the roles given by hand whose end has passed (ADR 0197),
    /// in one transaction. They keep its base as their built-in role, as when it's taken
    /// away by hand.
    pub fn expire_custom_roles(&self, at: i64) -> Vec<ExpiredRole> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return Vec::new() };
        let res = (|| {
            let mut out = Vec::new();
            for (table, key, team) in [("users", "id", "NULL"), ("team_members", "user_id", "team_id")] {
                let mut s = tx.prepare(&format!("SELECT {key}, {team}, role_id, role_expires_at FROM {table} WHERE role_expires_at <= ?1 AND role_id IS NOT NULL ORDER BY role_expires_at, {key}"))?;
                let rows = s.query_map([at], |r| Ok(ExpiredRole { user_id: r.get(0)?, team_id: r.get(1)?, role_id: r.get(2)?, expires_at: r.get(3)? }))?.collect::<rusqlite::Result<Vec<_>>>()?;
                drop(s);
                let touch = if table == "users" { ", updated_at = ?2" } else { "" };
                for e in &rows {
                    tx.execute(&format!("UPDATE {table} SET role_id = NULL{touch} WHERE {key} = ?1 AND role_expires_at <= ?2"), params![e.user_id, at])?;
                }
                out.extend(rows);
            }
            Ok::<_, rusqlite::Error>(out)
        })();
        match res {
            Ok(out) if tx.commit().is_ok() => out,
            _ => Vec::new(),
        }
    }

    /// When each holder's time with the role ends (ADR 0197): (user, None) across the
    /// server, (user, Some(team)) within a team. Only those whose end is ahead.
    pub fn custom_role_ends(&self, id: &str) -> HashMap<(String, Option<String>), i64> {
        let c = self.c();
        let at = now();
        let q = "SELECT id, NULL, role_expires_at FROM users WHERE role_id = ?1 AND role_expires_at > ?2
                 UNION ALL SELECT user_id, team_id, role_expires_at FROM team_members WHERE role_id = ?1 AND role_expires_at > ?2";
        c.prepare(q)
            .and_then(|mut s| s.query_map(params![id, at], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))?.collect())
            .unwrap_or_default()
    }

    // Requests for roles (ADR 0209).

    /// Makes a role requestable, or not. Only a time-bound role can be: false when the
    /// role is gone or (asked to be requestable) has no limit, both read as it's written.
    pub fn set_role_requestable(&self, id: &str, on: bool) -> bool {
        self.c()
            .execute("UPDATE roles SET requestable = ?1, updated_at = ?2 WHERE id = ?3 AND (?1 = 0 OR max_days IS NOT NULL)", params![on, now(), id])
            .unwrap_or(0)
            > 0
    }

    /// Files a pending request, lapsing at `expires_at`. Refused, in the same transaction,
    /// when the role isn't requestable or allows fewer hours, when they have a pending
    /// request for it in this scope, `max_pending` pending requests of any kind, or made
    /// `max_daily` requests in the last day, withdrawn ones too.
    #[allow(clippy::too_many_arguments)]
    pub fn create_role_request(&self, user_id: &str, role_id: &str, team_id: Option<&str>, hours: i64, reason: &str, expires_at: i64, max_pending: usize, max_daily: usize) -> Result<RoleRequest, RoleRequestError> {
        let err = |e: rusqlite::Error| RoleRequestError::Db(e.to_string());
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(err)?;
        let limit: Option<Option<i64>> = tx.query_row("SELECT max_days FROM roles WHERE id = ?1 AND requestable = 1", [role_id], |r| r.get(0)).optional().map_err(err)?;
        match limit {
            None | Some(None) => return Err(RoleRequestError::Refused("not_requestable")),
            Some(Some(days)) if hours > days * 24 => return Err(RoleRequestError::OverLimit(days * 24)),
            _ => {}
        }
        let pending: i64 = tx.query_row("SELECT COUNT(*) FROM role_requests WHERE user_id = ? AND status = 'pending'", [user_id], |r| r.get(0)).map_err(err)?;
        if pending as usize >= max_pending {
            return Err(RoleRequestError::TooMany(pending as usize));
        }
        let today: i64 = tx.query_row("SELECT COUNT(*) FROM role_requests WHERE user_id = ?1 AND created_at > ?2", params![user_id, now() - 86_400_000], |r| r.get(0)).map_err(err)?;
        if today as usize >= max_daily {
            return Err(RoleRequestError::TooOften(today as usize));
        }
        let id = format!("rq{}", crate::random_hex(5));
        let res = tx.execute(
            "INSERT INTO role_requests (id, user_id, role_id, team_id, hours, reason, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, user_id, role_id, team_id, hours, reason, now(), expires_at],
        );
        match res {
            Ok(_) => {}
            Err(e) if constraint(&e) => return Err(RoleRequestError::Duplicate),
            Err(e) => return Err(err(e)),
        }
        let r = tx.query_row("SELECT * FROM role_requests WHERE id = ?", [&id], role_request_row).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(r)
    }

    pub fn role_request(&self, id: &str) -> Option<RoleRequest> {
        self.c().query_row("SELECT * FROM role_requests WHERE id = ?", [id], role_request_row).optional().ok().flatten()
    }

    /// Newest first: one person's (`user`), or everyone's; with `status`, only those.
    pub fn role_requests(&self, user: Option<&str>, status: Option<&str>, limit: usize) -> Vec<RoleRequest> {
        let c = self.c();
        c.prepare("SELECT * FROM role_requests WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR status = ?2) ORDER BY created_at DESC, id DESC LIMIT ?3")
            .and_then(|mut s| s.query_map(params![user, status, limit as i64], role_request_row)?.collect())
            .unwrap_or_default()
    }

    /// Denies or withdraws (`status`) a pending request; with `user`, only theirs. None
    /// when there's no such pending request.
    pub fn close_role_request(&self, id: &str, status: &str, by: Option<&str>, note: Option<&str>, user: Option<&str>) -> Option<RoleRequest> {
        self.c()
            .query_row(
                "UPDATE role_requests SET status = ?2, decided_at = ?3, decided_by = ?4, note = ?5
                 WHERE id = ?1 AND status = 'pending' AND (?6 IS NULL OR user_id = ?6) RETURNING *",
                params![id, status, now(), by, note, user],
                role_request_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Lapses the pending requests nobody can approve any more, in one transaction: those
    /// past their time (`expired`), for a role no longer requestable (`not_requestable`),
    /// or from someone disabled (`disabled`).
    pub fn lapse_role_requests(&self, at: i64) -> Vec<(RoleRequest, &'static str)> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return Vec::new() };
        let res = (|| {
            let mut s = tx.prepare(
                "SELECT q.*, CASE WHEN q.lapse IS NOT NULL THEN q.lapse WHEN q.expires_at <= ?1 THEN 'expired' WHEN r.requestable = 0 OR r.max_days IS NULL THEN 'not_requestable' ELSE 'disabled' END AS why
                 FROM role_requests q JOIN roles r ON r.id = q.role_id JOIN users u ON u.id = q.user_id
                 WHERE q.status = 'pending' AND (q.lapse IS NOT NULL OR q.expires_at <= ?1 OR r.requestable = 0 OR r.max_days IS NULL OR u.status != 'active')
                 ORDER BY q.created_at, q.id",
            )?;
            let rows = s.query_map([at], |r| Ok((role_request_row(r)?, r.get::<_, String>("why")?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(s);
            let mut out = Vec::new();
            for (mut q, why) in rows {
                tx.execute("UPDATE role_requests SET status = 'lapsed', decided_at = ?2 WHERE id = ?1 AND status = 'pending'", params![q.id, at])?;
                q.status = "lapsed".into();
                q.decided_at = Some(at);
                out.push((q, match why.as_str() { "expired" => "expired", "not_requestable" => "not_requestable", _ => "disabled" }));
            }
            Ok::<_, rusqlite::Error>(out)
        })();
        match res {
            Ok(out) if tx.commit().is_ok() => out,
            _ => Vec::new(),
        }
    }

    /// Approves a pending request and gives its role for `hours` (the hours asked for when
    /// None) from now, in one transaction: the request, the role, the person and their team
    /// are read in it and handed to `check`, so nothing that changed since the request was
    /// made can slip through. Across the server their built-in role becomes the role's base,
    /// which `check` keeps equal to theirs. Given by hand, it ends any SCIM or SAML claim on
    /// the role in its scope, as `give_user_custom_role_until` does.
    pub fn approve_role_request(&self, id: &str, hours: Option<i64>, by: Option<&str>, note: Option<&str>, check: impl FnOnce(&RequestState) -> Result<(), &'static str>) -> Result<ApprovedRequest, RoleRequestError> {
        let err = |e: rusqlite::Error| RoleRequestError::Db(e.to_string());
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(err)?;
        let at = now();
        let mut q = tx.query_row("SELECT * FROM role_requests WHERE id = ?", [id], role_request_row).optional().map_err(err)?.ok_or(RoleRequestError::NotFound)?;
        if q.status != "pending" {
            return Err(RoleRequestError::NotPending(q.status));
        }
        let lapse: Option<String> = tx.query_row("SELECT lapse FROM role_requests WHERE id = ?", [id], |r| r.get(0)).map_err(err)?;
        if q.expires_at <= at || lapse.is_some() {
            return Err(RoleRequestError::NotPending("lapsed".into()));
        }
        let role = tx.query_row("SELECT * FROM roles WHERE id = ?", [&q.role_id], custom_role_row).optional().map_err(err)?.ok_or(RoleRequestError::NotFound)?;
        let user = tx.query_row("SELECT * FROM users WHERE id = ?", [&q.user_id], user_row).optional().map_err(err)?.ok_or(RoleRequestError::NotFound)?;
        let member = match &q.team_id {
            Some(t) => tx.query_row("SELECT * FROM team_members WHERE user_id = ?1 AND team_id = ?2", [&q.user_id, t], team_member_row).optional().map_err(err)?,
            None => None,
        };
        check(&RequestState { request: &q, role: &role, user: &user, member: member.as_ref() }).map_err(RoleRequestError::Refused)?;
        let hours = hours.unwrap_or(q.hours);
        let limit = role.max_days.map(|d| d * 24).ok_or(RoleRequestError::Refused("not_requestable"))?;
        if hours > limit {
            return Err(RoleRequestError::OverLimit(limit));
        }
        let until = at + hours * 60 * 60_000;
        let scope = if q.team_id.is_some() { "team" } else { "org" };
        let before = match (&q.team_id, &member) {
            (Some(_), Some(m)) => (m.role_id.clone(), m.role_expires_at),
            _ => (user.role_id.clone(), user.role_expires_at),
        };
        // Two writes, as the role's end is cleared by a trigger whenever `role_id` changes.
        match &q.team_id {
            None => {
                tx.execute("UPDATE users SET role_id = ?1, role = (SELECT base FROM roles WHERE id = ?1), updated_at = ?2 WHERE id = ?3", params![role.id, at, user.id]).map_err(err)?;
                tx.execute("UPDATE users SET role_expires_at = ?1 WHERE id = ?2", params![until, user.id]).map_err(err)?;
            }
            Some(t) => {
                tx.execute("UPDATE team_members SET role_id = ?1 WHERE team_id = ?2 AND user_id = ?3", params![role.id, t, user.id]).map_err(err)?;
                tx.execute("UPDATE team_members SET role_expires_at = ?1 WHERE user_id = ?2", params![until, user.id]).map_err(err)?;
            }
        }
        let taken = Self::drop_scim_grant_in(&tx, &user.id, scope).map_err(err)?;
        let taken_saml = if scope == "org" { Self::drop_saml_grant_in(&tx, &user.id).map_err(err)? } else { None };
        tx.execute(
            "UPDATE role_requests SET status = 'approved', decided_at = ?2, decided_by = ?3, note = ?4, granted_until = ?5 WHERE id = ?1",
            params![q.id, at, by, note, until],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        q.status = "approved".into();
        (q.decided_at, q.decided_by, q.note, q.granted_until) = (Some(at), by.map(str::to_string), note.map(str::to_string), Some(until));
        Ok(ApprovedRequest { request: q, before, taken, taken_saml })
    }

    // SCIM groups mapped to custom roles (ADR 0138).

    /// Ends a SCIM claim on `user_id`'s role in `scope`: a mapping's, or a role group's
    /// (ADR 0180, and within a team ADR 0206). The mapping or role group whose claim it was.
    fn drop_scim_grant_in(c: &Connection, user_id: &str, scope: &str) -> rusqlite::Result<Option<String>> {
        let mapping: Option<String> = c.query_row("DELETE FROM scim_role_grants WHERE user_id = ?1 AND scope = ?2 RETURNING mapping_id", [user_id, scope], |r| r.get(0)).optional()?;
        let table = if scope == "org" { "scim_role_group_grants" } else { "scim_role_group_team_grants" };
        let group: Option<String> = c.query_row(&format!("DELETE FROM {table} WHERE user_id = ? RETURNING group_id"), [user_id], |r| r.get(0)).optional()?;
        Ok(mapping.or(group))
    }

    pub fn scim_role_mappings(&self) -> Vec<ScimRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_mappings ORDER BY tenant, created_at, id").unwrap();
        s.query_map([], scim_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_mapping(&self, id: &str) -> Option<ScimRoleMapping> {
        self.c().query_row("SELECT * FROM scim_role_mappings WHERE id = ?", [id], scim_role_mapping_row).optional().ok().flatten()
    }

    /// The mappings of the group `team_id` is, in `tenant`.
    pub fn scim_role_mappings_of(&self, tenant: &str, team_id: &str) -> Vec<ScimRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_mappings WHERE tenant = ? AND team_id = ? ORDER BY scope").unwrap();
        s.query_map([tenant, team_id], scim_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every mapping of `team_id`, whichever tenant's.
    pub fn scim_role_mappings_of_team(&self, team_id: &str) -> Vec<ScimRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_mappings WHERE team_id = ? ORDER BY scope").unwrap();
        s.query_map([team_id], scim_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_mappings_of_role(&self, role_id: &str) -> Vec<ScimRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_mappings WHERE role_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([role_id], scim_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Maps the group `team_id` is in `tenant` to a role, while both still exist and the
    /// role's permissions, as they are now, don't reach admins in `scope`.
    pub fn create_scim_role_mapping(&self, tenant: &str, team_id: &str, role_id: &str, scope: &str, by: Option<&str>) -> Result<ScimRoleMapping, ScimRoleMapError> {
        let id = format!("sm{}", crate::random_hex(5));
        let c = self.c();
        let perms = role_perms_in(&c, role_id).map_err(|e| ScimRoleMapError::Db(e.to_string()))?.ok_or(ScimRoleMapError::Gone)?;
        let reach = perms.reaching_admins(scope == "team");
        if !reach.is_empty() {
            return Err(ScimRoleMapError::Reaches(reach));
        }
        if role_time_bound_in(&c, role_id).map_err(|e| ScimRoleMapError::Db(e.to_string()))? {
            return Err(ScimRoleMapError::TimeBound);
        }
        let n = c
            .execute(
                "INSERT INTO scim_role_mappings (id, tenant, team_id, role_id, scope, created_at, created_by)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
                 WHERE EXISTS (SELECT 1 FROM scim_groups WHERE tenant = ?2 AND team_id = ?3) AND EXISTS (SELECT 1 FROM roles WHERE id = ?4)",
                params![id, tenant, team_id, role_id, scope, now(), by],
            )
            .map_err(|e| if constraint(&e) { ScimRoleMapError::Taken } else { ScimRoleMapError::Db(e.to_string()) })?;
        drop(c);
        if n == 0 {
            return Err(ScimRoleMapError::Gone);
        }
        self.scim_role_mapping(&id).ok_or(ScimRoleMapError::Gone)
    }

    /// Deletes a mapping. Its grants must have been taken away first.
    pub fn delete_scim_role_mapping(&self, id: &str) -> bool {
        self.c().execute("DELETE FROM scim_role_mappings WHERE id = ?", [id]).unwrap_or(0) > 0
    }

    pub fn scim_role_grants(&self, mapping_id: &str) -> Vec<ScimRoleGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_grants WHERE mapping_id = ? ORDER BY granted_at, user_id").unwrap();
        s.query_map([mapping_id], scim_role_grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The grants a mapping made to `user_id`, in either scope.
    pub fn scim_role_grants_of_user(&self, user_id: &str) -> Vec<ScimRoleGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_grants WHERE user_id = ? ORDER BY scope").unwrap();
        s.query_map([user_id], scim_role_grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Gives `user_id` the mapping's role and records that SCIM gave it, in one
    /// transaction, only while they're on its team, hold no custom role in its scope, and
    /// (across the server) aren't an admin or the owner account. Across the server, the
    /// role's base becomes their built-in role, and the one they had is kept to give back.
    pub fn grant_scim_role(&self, m: &ScimRoleMapping, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let on_team = "EXISTS (SELECT 1 FROM team_members WHERE team_id = ?3 AND user_id = ?2) AND EXISTS (SELECT 1 FROM roles WHERE id = ?1)";
        let res = (|| {
            if role_perms_in(&tx, &m.role_id)?.is_none_or(|p| !p.reaching_admins(m.scope == "team").is_empty()) {
                return Ok(false);
            }
            let prior: Option<String> = tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get(0)).optional()?;
            let n = if m.scope == "org" {
                tx.execute(
                    &format!(
                        "UPDATE users SET role_id = ?1, role = (SELECT base FROM roles WHERE id = ?1), updated_at = ?4
                         WHERE id = ?2 AND role_id IS NULL AND role != 'admin' AND id != ?5 AND {on_team}"
                    ),
                    params![m.role_id, user_id, m.team_id, at, crate::users::OPERATOR],
                )?
            } else {
                tx.execute(&format!("UPDATE team_members SET role_id = ?1 WHERE team_id = ?3 AND user_id = ?2 AND role_id IS NULL AND {on_team}"), params![m.role_id, user_id, m.team_id])?
            };
            if n == 0 {
                return Ok(false);
            }
            let prior = if m.scope == "org" { prior } else { None };
            tx.execute(
                "INSERT OR REPLACE INTO scim_role_grants (mapping_id, user_id, scope, prior_role, granted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![m.id, user_id, m.scope, prior, at],
            )?;
            Ok::<_, rusqlite::Error>(true)
        })();
        matches!(res, Ok(true)) && tx.commit().is_ok()
    }

    /// Takes away what the mapping gave `user_id`, and forgets the grant, in one
    /// transaction. Only a role they still hold from it is cleared; across the server their
    /// built-in role goes back to the one they had before. None if it gave them nothing.
    /// `left`: they left the group, so nothing is taken if they're on its team again (a
    /// join that raced the leave holds the grant now).
    pub fn revoke_scim_role(&self, m: &ScimRoleMapping, user_id: &str, left: bool) -> Option<ScimRevoked> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let res = (|| {
            if left && tx.query_row("SELECT EXISTS (SELECT 1 FROM team_members WHERE team_id = ?1 AND user_id = ?2)", [&m.team_id, user_id], |r| r.get::<_, bool>(0))? {
                return Ok(None);
            }
            let prior: Option<Option<String>> =
                tx.query_row("DELETE FROM scim_role_grants WHERE mapping_id = ?1 AND user_id = ?2 RETURNING prior_role", [&m.id, user_id], |r| r.get(0)).optional()?;
            let Some(prior) = prior else { return Ok(None) };
            if m.scope == "team" {
                let n = tx.execute("UPDATE team_members SET role_id = NULL WHERE team_id = ?1 AND user_id = ?2 AND role_id = ?3", params![m.team_id, user_id, m.role_id])?;
                return Ok(Some(ScimRevoked { cleared: n > 0, role_before: None, role_after: None }));
            }
            let role = |tx: &Connection| tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get::<_, String>(0)).optional();
            let before = role(&tx)?;
            // Never back to admin: a grant is never made to one, so a prior admin is a hand edit.
            let prior = prior.filter(|p| Role::parse(p).is_some_and(|r| r != Role::Admin));
            let n = tx.execute(
                "UPDATE users SET role_id = NULL, role = coalesce(?1, role), updated_at = ?2 WHERE id = ?3 AND role_id = ?4",
                params![prior, now(), user_id, m.role_id],
            )?;
            let after = role(&tx)?;
            let parse = |r: Option<String>| r.as_deref().and_then(Role::parse);
            Ok::<_, rusqlite::Error>(Some(ScimRevoked { cleared: n > 0, role_before: parse(before), role_after: parse(after) }))
        })();
        match res {
            Ok(Some(r)) => tx.commit().ok().map(|_| r),
            _ => None,
        }
    }

    // SCIM role groups (ADR 0180). Every query a SCIM request makes names its tenant.

    /// A tenant's role groups, waiting ones too, oldest first.
    pub fn scim_role_groups(&self, tenant: &str) -> Vec<ScimRoleGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_groups WHERE tenant = ? ORDER BY created_at, id").unwrap();
        s.query_map([tenant], scim_role_group_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every tenant's role groups, for admins.
    pub fn all_scim_role_groups(&self) -> Vec<ScimRoleGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_groups ORDER BY tenant, created_at, id").unwrap();
        s.query_map([], scim_role_group_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_group(&self, id: &str) -> Option<ScimRoleGroup> {
        self.c().query_row("SELECT * FROM scim_role_groups WHERE id = ?", [id], scim_role_group_row).optional().ok().flatten()
    }

    pub fn scim_role_groups_of_role(&self, role_id: &str) -> Vec<ScimRoleGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_role_groups WHERE role_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([role_id], scim_role_group_row).unwrap().filter_map(Result::ok).collect()
    }

    /// By `externalId` (exactly) or `displayName` (any case).
    pub fn scim_role_group_find(&self, tenant: &str, external_id: Option<&str>, display_name: Option<&str>) -> Option<ScimRoleGroup> {
        let (col, v) = match (external_id, display_name) {
            (Some(x), _) => ("external_id", x),
            (None, Some(n)) => ("display_name", n),
            (None, None) => return None,
        };
        self.c().query_row(&format!("SELECT * FROM scim_role_groups WHERE tenant = ? AND {col} = ?"), [tenant, v], scim_role_group_row).optional().ok().flatten()
    }

    /// An admin declares a role group, waiting for the IdP, while the role exists and its
    /// permissions, as they are now, don't reach admins in `scope` (`org` or `team`).
    pub fn declare_scim_role_group(&self, tenant: &str, scope: &str, display_name: &str, external_id: Option<&str>, role_id: &str, by: Option<&str>) -> Result<ScimRoleGroup, ScimRoleGroupError> {
        let id = format!("g{}", crate::random_hex(5));
        let at = now();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_role_group_error)?;
        let perms = role_perms_in(&tx, role_id).map_err(scim_role_group_error)?.ok_or(ScimRoleGroupError::Gone)?;
        let reach = scim_role_group_reach(perms, scope);
        if !reach.is_empty() {
            return Err(ScimRoleGroupError::Reaches(reach));
        }
        if role_time_bound_in(&tx, role_id).map_err(scim_role_group_error)? {
            return Err(ScimRoleGroupError::TimeBound);
        }
        tx.execute(
            "INSERT INTO scim_role_groups (id, tenant, scope, display_name, declared_display_name, external_id, declared_external_id, role_id, created_at, created_by, updated_at) VALUES (?1, ?2, ?8, ?3, ?3, ?4, ?4, ?5, ?6, ?7, ?6)",
            params![id, tenant, display_name, external_id, role_id, at, by, scope],
        )
        .map_err(scim_role_group_error)?;
        let g = tx.query_row("SELECT * FROM scim_role_groups WHERE id = ?", [&id], scim_role_group_row).map_err(scim_role_group_error)?;
        tx.commit().map_err(scim_role_group_error)?;
        Ok(g)
    }

    /// Sets a role group's `displayName` and `externalId`. `provision` marks it taken on.
    pub fn save_scim_role_group(&self, id: &str, external_id: Option<&str>, display_name: &str, provision: bool) -> Result<ScimRoleGroup, ScimRoleGroupError> {
        let c = self.c();
        let n = c
            .execute(
                "UPDATE scim_role_groups SET external_id = ?1, display_name = ?2, updated_at = ?3, provisioned_at = CASE WHEN ?4 THEN coalesce(provisioned_at, ?3) ELSE provisioned_at END WHERE id = ?5",
                params![external_id, display_name, now(), provision, id],
            )
            .map_err(scim_role_group_error)?;
        if n != 1 {
            return Err(ScimRoleGroupError::Gone);
        }
        c.query_row("SELECT * FROM scim_role_groups WHERE id = ?", [id], scim_role_group_row).map_err(scim_role_group_error)
    }

    /// The IdP deleted it: it waits again, with what was declared and nobody in it. What
    /// it gave must have been taken away first. Its declared name comes back unless another
    /// role group or a team group of the tenant has taken it since the IdP renamed this one;
    /// likewise its declared externalId.
    pub fn reset_scim_role_group(&self, id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let ok = tx.execute("DELETE FROM scim_role_group_members WHERE group_id = ?", [id]).is_ok()
            && tx
                .execute(
                    "UPDATE scim_role_groups SET provisioned_at = NULL, updated_at = ?1,
                       external_id = CASE WHEN EXISTS (SELECT 1 FROM scim_groups t WHERE t.tenant = scim_role_groups.tenant AND t.external_id = scim_role_groups.declared_external_id)
                           OR EXISTS (SELECT 1 FROM scim_role_groups o WHERE o.tenant = scim_role_groups.tenant AND o.id != scim_role_groups.id AND o.external_id = scim_role_groups.declared_external_id)
                         THEN external_id ELSE declared_external_id END,
                       display_name = CASE WHEN EXISTS (SELECT 1 FROM scim_role_groups o WHERE o.tenant = scim_role_groups.tenant AND o.id != scim_role_groups.id AND o.display_name = scim_role_groups.declared_display_name)
                           OR EXISTS (SELECT 1 FROM scim_groups t WHERE t.tenant = scim_role_groups.tenant AND t.display_name = scim_role_groups.declared_display_name)
                         THEN display_name ELSE declared_display_name END
                     WHERE id = ?2",
                    params![now(), id],
                )
                .unwrap_or(0)
                == 1;
        ok && tx.commit().is_ok()
    }

    /// Gives a role group another role, while that role exists and doesn't reach admins
    /// in the group's scope. What the old one gave must have been taken away first.
    pub fn set_scim_role_group_role(&self, id: &str, role_id: &str) -> Result<ScimRoleGroup, ScimRoleGroupError> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_role_group_error)?;
        let scope: String = tx.query_row("SELECT scope FROM scim_role_groups WHERE id = ?", [id], |r| r.get(0)).optional().map_err(scim_role_group_error)?.ok_or(ScimRoleGroupError::Gone)?;
        let perms = role_perms_in(&tx, role_id).map_err(scim_role_group_error)?.ok_or(ScimRoleGroupError::Gone)?;
        let reach = scim_role_group_reach(perms, &scope);
        if !reach.is_empty() {
            return Err(ScimRoleGroupError::Reaches(reach));
        }
        if role_time_bound_in(&tx, role_id).map_err(scim_role_group_error)? {
            return Err(ScimRoleGroupError::TimeBound);
        }
        if tx.execute("UPDATE scim_role_groups SET role_id = ?1, updated_at = ?2 WHERE id = ?3", params![role_id, now(), id]).map_err(scim_role_group_error)? != 1 {
            return Err(ScimRoleGroupError::Gone);
        }
        let g = tx.query_row("SELECT * FROM scim_role_groups WHERE id = ?", [id], scim_role_group_row).map_err(scim_role_group_error)?;
        tx.commit().map_err(scim_role_group_error)?;
        Ok(g)
    }

    /// Deletes a role group with its members. What it gave must have been taken away first.
    pub fn delete_scim_role_group(&self, id: &str) -> bool {
        self.c().execute("DELETE FROM scim_role_groups WHERE id = ?", [id]).unwrap_or(0) > 0
    }

    /// Everyone in the group, as stored, in the order they were added.
    pub fn scim_role_group_member_ids(&self, group_id: &str) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT user_id FROM scim_role_group_members WHERE group_id = ? ORDER BY added_at, user_id").unwrap();
        s.query_map([group_id], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    /// The group's members `tenant` provisioned and hasn't deleted, as SCIM shows them.
    pub fn scim_role_group_members(&self, tenant: &str, group_id: &str) -> Vec<User> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT u.* FROM scim_role_group_members m JOIN scim_users l ON l.user_id = m.user_id JOIN users u ON u.id = m.user_id
                 WHERE m.group_id = ?1 AND l.tenant = ?2 AND l.deleted_at IS NULL ORDER BY m.added_at, m.user_id",
            )
            .unwrap();
        s.query_map(params![group_id, tenant], user_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_group_has(&self, group_id: &str, user_id: &str) -> bool {
        self.c().query_row("SELECT EXISTS (SELECT 1 FROM scim_role_group_members WHERE group_id = ? AND user_id = ?)", [group_id, user_id], |r| r.get(0)).unwrap_or(false)
    }

    /// Whether they were added: false if they were in it already.
    pub fn add_scim_role_group_member(&self, group_id: &str, user_id: &str) -> bool {
        self.c().execute("INSERT OR IGNORE INTO scim_role_group_members (group_id, user_id, added_at) VALUES (?1, ?2, ?3)", params![group_id, user_id, now()]).unwrap_or(0) > 0
    }

    pub fn remove_scim_role_group_member(&self, group_id: &str, user_id: &str) -> bool {
        self.c().execute("DELETE FROM scim_role_group_members WHERE group_id = ? AND user_id = ?", [group_id, user_id]).unwrap_or(0) > 0
    }

    /// Notes that SCIM is putting `user_id` on `team_id` and hasn't yet offered the roles
    /// the join gives (ADR 0206): saved before the join, cleared once they're offered.
    pub fn begin_scim_join(&self, team_id: &str, user_id: &str) -> bool {
        self.c().execute("INSERT OR REPLACE INTO scim_pending_joins (user_id, team_id, at) VALUES (?1, ?2, ?3)", params![user_id, team_id, now()]).is_ok()
    }

    /// Clears `user_id`'s pending join to `team_id`, and only that team's: a leave from an
    /// old team must not clear a join to a new one that started meanwhile.
    pub fn end_scim_join(&self, team_id: &str, user_id: &str) {
        let _ = self.c().execute("DELETE FROM scim_pending_joins WHERE user_id = ? AND team_id = ?", [user_id, team_id]);
    }

    /// Who SCIM put on `team_id` without finishing the join's role offers: a restart cut it short.
    pub fn scim_pending_joins(&self, team_id: &str) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT user_id FROM scim_pending_joins WHERE team_id = ? ORDER BY at, user_id").unwrap();
        s.query_map([team_id], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    /// The role groups `user_id` is in, oldest declared first: the order roles are offered.
    pub fn scim_role_groups_of_user(&self, user_id: &str) -> Vec<ScimRoleGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT g.* FROM scim_role_groups g JOIN scim_role_group_members m ON m.group_id = g.id WHERE m.user_id = ? ORDER BY g.created_at, g.id").unwrap();
        s.query_map([user_id], scim_role_group_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_group_grants(&self, group_id: &str) -> Vec<ScimRoleGroupGrant> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT * FROM ({SCIM_ROLE_GROUP_GRANTS}) WHERE group_id = ? ORDER BY granted_at, user_id")).unwrap();
        s.query_map([group_id], scim_role_group_grant_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_role_group_grant_of_user(&self, user_id: &str) -> Option<ScimRoleGroupGrant> {
        self.c().query_row("SELECT *, NULL AS team_id FROM scim_role_group_grants WHERE user_id = ?", [user_id], scim_role_group_grant_row).optional().ok().flatten()
    }

    /// The team roles team role groups gave in `team_id` (ADR 0206).
    pub fn scim_team_role_group_grants_in(&self, team_id: &str) -> Vec<ScimRoleGroupGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT *, NULL AS prior_role FROM scim_role_group_team_grants WHERE team_id = ? ORDER BY granted_at, user_id").unwrap();
        s.query_map([team_id], scim_role_group_grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The team role a team role group gave `user_id` (ADR 0206), if one did.
    pub fn scim_team_role_group_grant_of_user(&self, user_id: &str) -> Option<ScimRoleGroupGrant> {
        self.c().query_row("SELECT *, NULL AS prior_role FROM scim_role_group_team_grants WHERE user_id = ?", [user_id], scim_role_group_grant_row).optional().ok().flatten()
    }

    /// Gives `user_id` the group's role across the server and records that the group gave
    /// it, in one transaction, only while they're in the group, the IdP has it, its role is
    /// still this one and reaches no admin, and they hold no custom role, aren't an admin
    /// and aren't the owner account. The role's base becomes their built-in role, and the
    /// one they had is kept to give back.
    pub fn grant_scim_role_group(&self, g: &ScimRoleGroup, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let res = (|| {
            if role_perms_in(&tx, &g.role_id)?.is_none_or(|p| !p.reaching_admins(false).is_empty()) {
                return Ok(false);
            }
            let prior: Option<String> = tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get(0)).optional()?;
            let n = tx.execute(
                "UPDATE users SET role_id = ?1, role = (SELECT base FROM roles WHERE id = ?1), updated_at = ?4
                 WHERE id = ?2 AND role_id IS NULL AND role != 'admin' AND id != ?5
                   AND EXISTS (SELECT 1 FROM scim_role_group_members WHERE group_id = ?3 AND user_id = ?2)
                   AND EXISTS (SELECT 1 FROM scim_role_groups WHERE id = ?3 AND role_id = ?1 AND provisioned_at IS NOT NULL)",
                params![g.role_id, user_id, g.id, at, crate::users::OPERATOR],
            )?;
            if n == 0 {
                return Ok(false);
            }
            tx.execute(
                "INSERT OR REPLACE INTO scim_role_group_grants (group_id, user_id, role_id, prior_role, granted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![g.id, user_id, g.role_id, prior, at],
            )?;
            Ok::<_, rusqlite::Error>(true)
        })();
        matches!(res, Ok(true)) && tx.commit().is_ok()
    }

    /// Takes away what the group gave `user_id`, and forgets the grant, in one transaction.
    /// Only the role they still hold from it is cleared, and their built-in role goes back
    /// to the one they had before. The role taken is the one the grant gave, which may
    /// not be the group's role any more. None if it gave them nothing. `left`: they left
    /// the group, so nothing is taken if they're in it again (an add that raced the removal).
    pub fn revoke_scim_role_group(&self, g: &ScimRoleGroup, user_id: &str, left: bool) -> Option<(String, ScimRevoked)> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let res = (|| {
            if left && tx.query_row("SELECT EXISTS (SELECT 1 FROM scim_role_group_members WHERE group_id = ?1 AND user_id = ?2)", [&g.id, user_id], |r| r.get::<_, bool>(0))? {
                return Ok(None);
            }
            let grant: Option<(String, Option<String>)> = tx
                .query_row("DELETE FROM scim_role_group_grants WHERE group_id = ?1 AND user_id = ?2 RETURNING role_id, prior_role", [&g.id, user_id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let Some((given, prior)) = grant else { return Ok(None) };
            let role = |tx: &Connection| tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get::<_, String>(0)).optional();
            let before = role(&tx)?;
            // Never back to admin: a grant is never made to one, so a prior admin is a hand edit.
            let prior = prior.filter(|p| Role::parse(p).is_some_and(|r| r != Role::Admin));
            let n = tx.execute("UPDATE users SET role_id = NULL, role = coalesce(?1, role), updated_at = ?2 WHERE id = ?3 AND role_id = ?4", params![prior, now(), user_id, given])?;
            let after = role(&tx)?;
            let parse = |r: Option<String>| r.as_deref().and_then(Role::parse);
            Ok::<_, rusqlite::Error>(Some((given, ScimRevoked { cleared: n > 0, role_before: parse(before), role_after: parse(after) })))
        })();
        match res {
            Ok(Some(r)) => tx.commit().ok().map(|_| r),
            _ => None,
        }
    }

    /// Gives `user_id` a team role group's role within their team (ADR 0206) and records
    /// that the group gave it, in one transaction, only while: their team is one of the
    /// group's tenant's team groups, they're in the group, the IdP has it, it is a team role
    /// group whose role is still this one and reaches no admin in a team, they aren't
    /// read-only, and they hold no team role. The team it was given in, or None.
    pub fn grant_scim_team_role_group(&self, g: &ScimRoleGroup, user_id: &str) -> Option<String> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let res = (|| {
            if role_perms_in(&tx, &g.role_id)?.is_none_or(|p| !p.reaching_admins(true).is_empty()) {
                return Ok(None);
            }
            let team: Option<String> = tx
                .query_row("SELECT m.team_id FROM team_members m JOIN scim_groups s ON s.team_id = m.team_id AND s.tenant = ?2 WHERE m.user_id = ?1", [user_id, &g.tenant], |r| r.get(0))
                .optional()?;
            let Some(team) = team else { return Ok(None) };
            let n = tx.execute(
                "UPDATE team_members SET role_id = ?1 WHERE team_id = ?3 AND user_id = ?2 AND role_id IS NULL
                   AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND role != 'readonly')
                   AND EXISTS (SELECT 1 FROM scim_role_group_members WHERE group_id = ?4 AND user_id = ?2)
                   AND EXISTS (SELECT 1 FROM scim_role_groups WHERE id = ?4 AND role_id = ?1 AND scope = 'team' AND provisioned_at IS NOT NULL)",
                params![g.role_id, user_id, team, g.id],
            )?;
            if n == 0 {
                return Ok(None);
            }
            tx.execute(
                "INSERT OR REPLACE INTO scim_role_group_team_grants (group_id, user_id, team_id, role_id, granted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![g.id, user_id, team, g.role_id, now()],
            )?;
            Ok::<_, rusqlite::Error>(Some(team))
        })();
        match res {
            Ok(Some(team)) => tx.commit().ok().map(|_| team),
            _ => None,
        }
    }

    /// Takes away the team role a team role group gave `user_id`, and forgets the grant, in
    /// one transaction; only a role they still hold from it, in the team it was given in,
    /// is cleared. The role and team, or None if it gave them nothing. `left_group`: they
    /// left the group, so nothing is taken if they're in it again. `left_team`: they left
    /// this team, so only a grant in it goes, and nothing if they're on it again (a join
    /// that raced the leave).
    pub fn revoke_scim_team_role_group(&self, g: &ScimRoleGroup, user_id: &str, left_group: bool, left_team: Option<&str>) -> Option<(String, String, bool)> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let res = (|| {
            if left_group && tx.query_row("SELECT EXISTS (SELECT 1 FROM scim_role_group_members WHERE group_id = ?1 AND user_id = ?2)", [&g.id, user_id], |r| r.get::<_, bool>(0))? {
                return Ok(None);
            }
            if let Some(t) = left_team
                && tx.query_row("SELECT EXISTS (SELECT 1 FROM team_members WHERE team_id = ?1 AND user_id = ?2)", [t, user_id], |r| r.get::<_, bool>(0))?
            {
                return Ok(None);
            }
            let grant: Option<(String, String)> = tx
                .query_row(
                    "DELETE FROM scim_role_group_team_grants WHERE group_id = ?1 AND user_id = ?2 AND (?3 IS NULL OR team_id = ?3) RETURNING role_id, team_id",
                    params![g.id, user_id, left_team],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((given, team)) = grant else { return Ok(None) };
            let n = tx.execute("UPDATE team_members SET role_id = NULL WHERE team_id = ?1 AND user_id = ?2 AND role_id = ?3", params![team, user_id, given])?;
            Ok::<_, rusqlite::Error>(Some((given, team, n > 0)))
        })();
        match res {
            Ok(Some(r)) => tx.commit().ok().map(|_| r),
            _ => None,
        }
    }

    // Native SAML groups mapped to custom roles (ADR 0160).

    /// A hand change of `user_id`'s role across the server: the SAML grant they held (its
    /// mapping) is released, not forgotten, so the group doesn't give the role back while
    /// it still lists them.
    fn drop_saml_grant_in(c: &Connection, user_id: &str) -> rusqlite::Result<Option<String>> {
        c.query_row("UPDATE saml_role_grants SET released_at = ?2 WHERE user_id = ?1 AND released_at IS NULL RETURNING mapping_id", params![user_id, now()], |r| r.get(0)).optional()
    }

    /// The mapping whose grant to `user_id` an admin's hand change released, if any.
    pub fn saml_role_released(&self, user_id: &str) -> Option<String> {
        self.c().query_row("SELECT mapping_id FROM saml_role_grants WHERE user_id = ? AND released_at IS NOT NULL", [user_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// Forgets a released grant: the person left the group, so it may give the role again.
    pub fn end_saml_role_release(&self, user_id: &str, mapping_id: &str) -> bool {
        self.c().execute("DELETE FROM saml_role_grants WHERE user_id = ?1 AND mapping_id = ?2 AND released_at IS NOT NULL", [user_id, mapping_id]).unwrap_or(0) > 0
    }

    pub fn saml_role_mappings(&self) -> Vec<SamlRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM saml_role_mappings ORDER BY provider, created_at, id").unwrap();
        s.query_map([], saml_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    /// A provider's mappings, oldest first: the order in which a sign-in tries them.
    pub fn saml_role_mappings_of(&self, provider: &str) -> Vec<SamlRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM saml_role_mappings WHERE provider = ? ORDER BY created_at, id").unwrap();
        s.query_map([provider], saml_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn saml_role_mappings_of_role(&self, role_id: &str) -> Vec<SamlRoleMapping> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM saml_role_mappings WHERE role_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([role_id], saml_role_mapping_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn saml_role_mapping(&self, id: &str) -> Option<SamlRoleMapping> {
        self.c().query_row("SELECT * FROM saml_role_mappings WHERE id = ?", [id], saml_role_mapping_row).optional().ok().flatten()
    }

    /// Maps `provider`'s `group` to a role, while it exists and its permissions, as they are
    /// now, don't reach admins across the server.
    pub fn create_saml_role_mapping(&self, provider: &str, group: &str, role_id: &str, by: Option<&str>) -> Result<SamlRoleMapping, ScimRoleMapError> {
        let id = format!("gm{}", crate::random_hex(5));
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| ScimRoleMapError::Db(e.to_string()))?;
        let perms = role_perms_in(&tx, role_id).map_err(|e| ScimRoleMapError::Db(e.to_string()))?.ok_or(ScimRoleMapError::Gone)?;
        let reach = perms.reaching_admins(false);
        if !reach.is_empty() {
            return Err(ScimRoleMapError::Reaches(reach));
        }
        if role_time_bound_in(&tx, role_id).map_err(|e| ScimRoleMapError::Db(e.to_string()))? {
            return Err(ScimRoleMapError::TimeBound);
        }
        tx.execute("INSERT INTO saml_role_mappings (id, provider, group_name, role_id, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![id, provider, group, role_id, now(), by])
            .map_err(|e| if constraint(&e) { ScimRoleMapError::Taken } else { ScimRoleMapError::Db(e.to_string()) })?;
        tx.commit().map_err(|e| ScimRoleMapError::Db(e.to_string()))?;
        drop(c);
        self.saml_role_mapping(&id).ok_or(ScimRoleMapError::Gone)
    }

    /// Deletes a mapping, with any grant rows left (its grants are taken away first).
    pub fn delete_saml_role_mapping(&self, id: &str) -> bool {
        self.c().execute("DELETE FROM saml_role_mappings WHERE id = ?", [id]).unwrap_or(0) > 0
    }

    pub fn saml_role_grants(&self, mapping_id: &str) -> Vec<SamlRoleGrant> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM saml_role_grants WHERE mapping_id = ? AND released_at IS NULL ORDER BY granted_at, user_id").unwrap();
        s.query_map([mapping_id], saml_role_grant_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The grant a SAML mapping made to `user_id` and still holds, if one did.
    pub fn saml_role_grant_of_user(&self, user_id: &str) -> Option<SamlRoleGrant> {
        self.c().query_row("SELECT * FROM saml_role_grants WHERE user_id = ? AND released_at IS NULL", [user_id], saml_role_grant_row).optional().ok().flatten()
    }

    /// Gives `user_id` the mapping's role across the server and records that the SAML
    /// group gave it, in one transaction, only while the mapping and role exist, the role
    /// doesn't reach admins, and the person is active, holds no custom role, and isn't an
    /// admin or the owner account. The role's base becomes their built-in role; the one
    /// they had is kept to give back.
    pub fn grant_saml_role(&self, m: &SamlRoleMapping, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let res = (|| {
            if role_perms_in(&tx, &m.role_id)?.is_none_or(|p| !p.reaching_admins(false).is_empty()) {
                return Ok(false);
            }
            let prior: Option<String> = tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get(0)).optional()?;
            let n = tx.execute(
                "UPDATE users SET role_id = ?1, role = (SELECT base FROM roles WHERE id = ?1), updated_at = ?3
                 WHERE id = ?2 AND role_id IS NULL AND role != 'admin' AND id != ?4 AND status = 'active'
                   AND EXISTS (SELECT 1 FROM roles WHERE id = ?1) AND EXISTS (SELECT 1 FROM saml_role_mappings WHERE id = ?5 AND role_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM saml_role_grants WHERE user_id = ?2 AND released_at IS NOT NULL)",
                params![m.role_id, user_id, at, crate::users::OPERATOR, m.id],
            )?;
            if n == 0 {
                return Ok(false);
            }
            tx.execute("INSERT OR REPLACE INTO saml_role_grants (mapping_id, user_id, prior_role, granted_at, released_at) VALUES (?1, ?2, ?3, ?4, NULL)", params![m.id, user_id, prior, at])?;
            Ok::<_, rusqlite::Error>(true)
        })();
        matches!(res, Ok(true)) && tx.commit().is_ok()
    }

    /// Takes away what the mapping gave `user_id`, and forgets the grant, in one
    /// transaction. Only a role they still hold from it is cleared, and their built-in role
    /// goes back to the one they had before (never admin). None if it gave them nothing.
    pub fn revoke_saml_role(&self, m: &SamlRoleMapping, user_id: &str) -> Option<ScimRevoked> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let res = (|| {
            let prior: Option<Option<String>> =
                tx.query_row("DELETE FROM saml_role_grants WHERE mapping_id = ?1 AND user_id = ?2 AND released_at IS NULL RETURNING prior_role", [&m.id, user_id], |r| r.get(0)).optional()?;
            let Some(prior) = prior else { return Ok(None) };
            let role = |tx: &Connection| tx.query_row("SELECT role FROM users WHERE id = ?", [user_id], |r| r.get::<_, String>(0)).optional();
            let before = role(&tx)?;
            let prior = prior.filter(|p| Role::parse(p).is_some_and(|r| r != Role::Admin));
            let n = tx.execute(
                "UPDATE users SET role_id = NULL, role = coalesce(?1, role), updated_at = ?2 WHERE id = ?3 AND role_id = ?4",
                params![prior, now(), user_id, m.role_id],
            )?;
            let after = role(&tx)?;
            let parse = |r: Option<String>| r.as_deref().and_then(Role::parse);
            Ok::<_, rusqlite::Error>(Some(ScimRevoked { cleared: n > 0, role_before: parse(before), role_after: parse(after) }))
        })();
        match res {
            Ok(Some(r)) => tx.commit().ok().map(|_| r),
            _ => None,
        }
    }

    /// What a person's custom role across the server adds. Nothing without one.
    pub fn user_perms(&self, u: &User) -> crate::rbac::Perms {
        u.role_id.as_deref().and_then(|id| self.custom_role(id)).map_or(crate::rbac::Perms::NONE, |r| r.perms())
    }

    // Service accounts (ADR 0143).

    /// Makes a service account: a `users` row of kind `service`, with `role` (member or
    /// read-only) and, across the server, the custom role `role_id` (whose base `role` is),
    /// and its own row. `team` is the team it acts in, with the custom role it has there.
    #[allow(clippy::too_many_arguments)]
    pub fn create_service_account(&self, name: &str, description: &str, role: Role, role_id: Option<&str>, team: Option<(&str, Option<&str>)>, owner: &str, by: Option<&str>) -> Result<ServiceAccount, String> {
        let id = format!("sa{}", crate::random_hex(5));
        let at = now();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
            for r in [role_id, team.and_then(|t| t.1)].into_iter().flatten() {
                if role_time_bound_in(&tx, r).map_err(|e| e.to_string())? {
                    return Err(SA_TIME_BOUND.into());
                }
            }
            tx.execute(
                "INSERT INTO users (id, email, display_name, role, role_id, kind, created_at, updated_at) VALUES (?1, NULL, ?2, ?3, ?4, 'service', ?5, ?5)",
                params![id, name, role.as_str(), role_id, at],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO service_accounts (user_id, description, owner_id, team_id, team_role_id, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, description, owner, team.map(|t| t.0), team.and_then(|t| t.1), by, at],
            )
            .map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        self.service_account(&id).ok_or_else(|| "service account not saved".into())
    }

    const SERVICE_ACCOUNT: &str = "SELECT u.*, s.description AS sa_description, s.owner_id AS sa_owner, s.team_id AS sa_team, s.team_role_id AS sa_team_role,
        s.created_by AS sa_created_by, s.deleted_at AS sa_deleted_at FROM users u JOIN service_accounts s ON s.user_id = u.id";

    pub fn service_account(&self, id: &str) -> Option<ServiceAccount> {
        self.c().query_row(&format!("{} WHERE u.id = ?", Self::SERVICE_ACCOUNT), [id], service_account_row).optional().ok().flatten()
    }

    /// Every service account, deleted ones too, oldest first.
    pub fn service_accounts(&self) -> Vec<ServiceAccount> {
        let c = self.c();
        let mut s = c.prepare(&format!("{} ORDER BY u.created_at, u.id", Self::SERVICE_ACCOUNT)).unwrap();
        s.query_map([], service_account_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Saves the fields given, in one transaction. `role` is the built-in role and the
    /// custom role across the server (None: none); `team` the team and the custom role there.
    /// Returns the Bots it no longer keeps (ADR 0222), read in the same transaction.
    pub fn update_service_account(&self, id: &str, p: &ServiceAccountPatch) -> Result<Vec<String>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        let at = now();
        let mut released = Vec::new();
        let res = (|| {
            if tx.execute("UPDATE service_accounts SET user_id = user_id WHERE user_id = ?1 AND deleted_at IS NULL", [id])? == 0 {
                return Ok(Some(false));
            }
            let kept = kept_in(&tx, id)?;
            let roles = [p.role.as_ref().and_then(|r| r.1.as_deref()), p.team.as_ref().and_then(|t| t.as_ref()).and_then(|t| t.1.as_deref())];
            for r in roles.into_iter().flatten() {
                if role_time_bound_in(&tx, r)? {
                    return Ok(None);
                }
            }
            let set = |col: &str, v: &dyn rusqlite::ToSql| tx.execute(&format!("UPDATE users SET {col} = ?1, updated_at = ?2 WHERE id = ?3"), params![v, at, id]);
            if let Some(v) = &p.name { set("display_name", v)?; }
            if let Some(v) = p.status { set("status", &v)?; }
            if let Some((role, role_id)) = &p.role {
                set("role", &role.as_str())?;
                set("role_id", role_id)?;
            }
            let own = |col: &str, v: &dyn rusqlite::ToSql| tx.execute(&format!("UPDATE service_accounts SET {col} = ?1 WHERE user_id = ?2"), params![v, id]);
            if let Some(v) = &p.description { own("description", v)?; }
            if let Some(v) = &p.owner { own("owner_id", v)?; }
            if let Some(team) = &p.team {
                own("team_id", &team.as_ref().map(|t| t.0.clone()))?;
                own("team_role_id", &team.as_ref().and_then(|t| t.1.clone()))?;
            }
            let still = kept_in(&tx, id)?;
            released = kept.into_iter().filter(|b| !still.contains(b)).collect();
            Ok::<_, rusqlite::Error>(Some(true))
        })();
        match res {
            Ok(Some(true)) => tx.commit().map(|_| released).map_err(|e| e.to_string()),
            Ok(Some(false)) => Err("not found".into()),
            Ok(None) => Err(SA_TIME_BOUND.into()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Deletes a service account for good: every live token revoked, the account disabled
    /// and its roles taken away, in one transaction. The row stays, so the audit log keeps
    /// naming it. Returns how many tokens were revoked and the Bots it kept, which stay
    /// their owner's (ADR 0222), or None if it was gone already.
    pub fn delete_service_account(&self, id: &str, by: Option<&str>) -> Option<(usize, Vec<String>)> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let at = now();
        let res = (|| {
            let kept = kept_in(&tx, id)?;
            if tx.execute("UPDATE service_accounts SET deleted_at = ?1, team_id = NULL, team_role_id = NULL WHERE user_id = ?2 AND deleted_at IS NULL", params![at, id])? == 0 {
                return Ok(None);
            }
            tx.execute("UPDATE users SET status = 'disabled', role_id = NULL, updated_at = ?1 WHERE id = ?2", params![at, id])?;
            let n = tx.execute(
                "UPDATE service_tokens SET revoked_at = ?1, revoked_by = ?2, revoked_reason = 'account_deleted' WHERE account_id = ?3 AND revoked_at IS NULL AND expires_at > ?1",
                params![at, by, id],
            )?;
            Ok::<_, rusqlite::Error>(Some((n, kept)))
        })();
        match res {
            Ok(Some(n)) => tx.commit().ok().map(|_| n),
            _ => None,
        }
    }

    pub fn create_service_token(&self, t: &NewServiceToken) -> Option<ServiceToken> {
        let id = format!("st{}", crate::random_hex(5));
        Self::insert_service_token(&self.c(), &id, t).ok()?;
        self.service_token(&id)
    }

    fn insert_service_token(c: &Connection, id: &str, t: &NewServiceToken) -> rusqlite::Result<usize> {
        let scopes = t.scopes.map(|s| serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
        c.execute(
            "INSERT INTO service_tokens (id, account_id, name, token_hash, hint, scopes, created_at, created_by, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![id, t.account_id, t.name, t.token_hash, t.hint, scopes, now(), t.created_by, t.expires_at],
        )
    }

    pub fn service_token(&self, id: &str) -> Option<ServiceToken> {
        self.c().query_row("SELECT * FROM service_tokens WHERE id = ?", [id], service_token_row).optional().ok().flatten()
    }

    pub fn service_token_by_hash(&self, token_hash: &str) -> Option<ServiceToken> {
        self.c().query_row("SELECT * FROM service_tokens WHERE token_hash = ?", [token_hash], service_token_row).optional().ok().flatten()
    }

    /// An account's tokens, newest first, revoked and expired ones too.
    pub fn service_tokens(&self, account_id: &str) -> Vec<ServiceToken> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM service_tokens WHERE account_id = ? ORDER BY created_at DESC, id DESC").unwrap();
        s.query_map([account_id], service_token_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Revokes a token that isn't already. False if it was, or is gone.
    pub fn revoke_service_token(&self, id: &str, by: Option<&str>, reason: &str) -> bool {
        self.c()
            .execute(
                "UPDATE service_tokens SET revoked_at = ?1, revoked_by = ?2, revoked_reason = ?3 WHERE id = ?4 AND revoked_at IS NULL",
                params![now(), by, reason, id],
            )
            .unwrap_or(0)
            > 0
    }

    /// Replaces a live token with `new`, in one transaction: the old one is revoked now, or
    /// with `keep_until`, expires then (whichever is sooner) so callers can switch over.
    /// None if the old one was revoked or expired meanwhile.
    pub fn rotate_service_token(&self, old: &str, new: &NewServiceToken, keep_until: Option<i64>, by: Option<&str>) -> Option<ServiceToken> {
        let id = format!("st{}", crate::random_hex(5));
        let at = now();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().ok()?;
            let changed = match keep_until {
                Some(until) => tx.execute(
                    "UPDATE service_tokens SET expires_at = MIN(expires_at, ?1), rotated_to = ?2 WHERE id = ?3 AND revoked_at IS NULL AND rotated_to IS NULL AND expires_at > ?4",
                    params![until, id, old, at],
                ),
                None => tx.execute(
                    "UPDATE service_tokens SET revoked_at = ?1, revoked_by = ?2, revoked_reason = 'rotated', rotated_to = ?3 WHERE id = ?4 AND revoked_at IS NULL AND rotated_to IS NULL AND expires_at > ?1",
                    params![at, by, id, old],
                ),
            }
            .ok()?;
            if changed == 0 {
                return None;
            }
            Self::insert_service_token(&tx, &id, new).ok()?;
            tx.commit().ok()?;
        }
        self.service_token(&id)
    }

    #[cfg(test)]
    pub fn set_service_token_expiry(&self, id: &str, expires_at: i64) {
        self.c().execute("UPDATE service_tokens SET expires_at = ?1 WHERE id = ?2", params![expires_at, id]).unwrap();
    }

    #[cfg(test)]
    pub fn set_service_token_created(&self, id: &str, created_at: i64) {
        self.c().execute("UPDATE service_tokens SET created_at = ?1 WHERE id = ?2", params![created_at, id]).unwrap();
    }

    /// Notes a token's use, at most once a minute, so a busy integration doesn't write on
    /// every request.
    pub fn touch_service_token(&self, id: &str, at: i64, ip: Option<&str>) {
        let _ = self.c().execute(
            "UPDATE service_tokens SET last_used_at = ?1, last_used_ip = ?2 WHERE id = ?3 AND (last_used_at IS NULL OR last_used_at < ?1 - 60000)",
            params![at, ip, id],
        );
    }

    /// Service accounts' refusals from `from` (unix ms), by account and reason (ADR 0170):
    /// requests refused once its token was taken (`access.denied` with the account as the
    /// actor), and its tokens refused at authentication (`auth.login_failed` naming it),
    /// with the refusals a throttled one folded in counted under its reason. Just `account`'s
    /// when it's given.
    pub fn service_refusals(&self, from: i64, account: Option<&str>) -> Vec<ServiceRefusal> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT account, reason, SUM(n), MAX(at) FROM (
                   SELECT actor_id AS account, CASE WHEN json_valid(details) THEN CAST(json_extract(details, '$.reason') AS TEXT) END AS reason, 1 AS n, at
                     FROM audit_events WHERE at >= ?1 AND action = 'access.denied' AND actor_kind = 'user' AND auth_method = 'service_token'
                   UNION ALL
                   SELECT target_id, CASE WHEN json_valid(details) THEN CAST(json_extract(details, '$.reason') AS TEXT) END,
                     1 + CASE WHEN json_valid(details) THEN max(0, CAST(COALESCE(json_extract(details, '$.unloggedSinceLast'), 0) AS INTEGER)) ELSE 0 END, at
                     FROM audit_events WHERE at >= ?1 AND action = 'auth.login_failed' AND target_type = 'service_account'
                 ) WHERE account IS NOT NULL AND (?2 IS NULL OR account = ?2)
                 GROUP BY account, reason ORDER BY account, reason",
            )
            .unwrap();
        s.query_map(params![from, account], |r| {
            Ok(ServiceRefusal { account: r.get(0)?, reason: r.get::<_, Option<String>>(1)?.unwrap_or_else(|| "unknown".into()), n: r.get::<_, i64>(2)?.max(0) as u64, last_at: r.get(3)? })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    /// The live service accounts that act in `team_id` (ADR 0143).
    pub fn team_service_accounts(&self, team_id: &str) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT user_id FROM service_accounts WHERE team_id = ? AND deleted_at IS NULL ORDER BY user_id").unwrap();
        s.query_map([team_id], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    // Erasure (ADR 0102).

    /// The held Bots that keep `user_id` from being erased: a Bot they own whose chat is
    /// held (ADR 0098), and a held Bot whose chat has messages they sent or one of their
    /// Bots wrote. Their Bots are named by id in `bots`, so it still works once they're gone.
    pub fn erasure_holds(&self, user_id: &str, bots: &[String]) -> Vec<String> {
        Self::holds_in(&self.c(), user_id, bots)
    }

    fn holds_in(c: &Connection, user_id: &str, bots: &[String]) -> Vec<String> {
        let bots = serde_json::to_string(bots).unwrap_or_else(|_| "[]".into());
        let sql = format!(
            "SELECT b.id FROM bots b WHERE b.id IN (SELECT value FROM json_each(?2))
               AND (EXISTS (SELECT 1 FROM retention_holds h WHERE h.bot_id = b.id)
                 OR EXISTS (SELECT 1 FROM messages m WHERE m.bot_id = b.id AND m.from_bot IN (SELECT bot_id FROM retention_holds)))
             UNION
             SELECT h.bot_id FROM retention_holds h WHERE EXISTS (
               SELECT 1 FROM messages m WHERE m.bot_id = h.bot_id AND ({SENT_BY} OR m.from_bot IN (SELECT value FROM json_each(?2))))
             ORDER BY 1"
        );
        let Ok(mut s) = c.prepare(&sql) else {
            return Vec::new();
        };
        s.query_map(params![user_id, bots], |r| r.get(0)).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// The subscription paying for the user's own plan now, if one does.
    pub fn user_paying(&self, user_id: &str) -> Option<Subscription> {
        paying_subscription(&self.c(), user_id).ok().flatten()
    }

    /// The Bots an erasure of `user_id` that didn't finish had taken on (ADR 0102).
    pub fn erasing_bots(&self, user_id: &str) -> Vec<String> {
        self.setting(&format!("{ERASING_BOTS}{user_id}")).and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default()
    }

    pub fn set_erasing_bots(&self, user_id: &str, bots: &[String]) {
        let _ = self.c().execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", params![format!("{ERASING_BOTS}{user_id}"), serde_json::to_string(bots).unwrap_or_default()]);
    }

    /// Erases `user_id`'s personal data in one transaction (ADR 0102). Their Bots must be
    /// gone already; `bots` names them, so what they wrote in others' chats is erased too.
    /// The user row stays as a tombstone named `pseudonym`, and every audit event about
    /// them names them by it, without their name, email, subject, address or user agent.
    pub fn erase_user(&self, user_id: &str, pseudonym: &str, by: Option<&str>, bots: &[String]) -> Result<Erased, EraseError> {
        let db_err = |e: rusqlite::Error| EraseError::Db(e.to_string());
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(db_err)?;
        let u = tx.query_row("SELECT * FROM users WHERE id = ?", [user_id], user_row).optional().map_err(db_err)?.ok_or(EraseError::Gone)?;
        if u.erased_at.is_some() {
            return Err(EraseError::Gone);
        }
        let held = Self::holds_in(&tx, user_id, bots);
        if !held.is_empty() {
            return Err(EraseError::Held(held));
        }
        let (mut emails, mut exact, mut subjects) = (Vec::new(), vec![u.name.clone()], Vec::new());
        emails.extend(u.email.clone());
        if let (Some(i), Some(s)) = (&u.idp_issuer, &u.idp_subject) {
            subjects.extend([s.clone(), format!("{i}|{s}")]);
        }
        let strings = |sql: &str, emails: &mut Vec<String>, exact: &mut Vec<String>, subjects: &mut Vec<String>| -> rusqlite::Result<()> {
            let mut s = tx.prepare(sql)?;
            let rows = s.query_map(params![user_id, u.email], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?;
            for row in rows {
                let (kind, v) = row?;
                let Some(v) = v.filter(|v| !v.trim().is_empty()) else {
                    continue;
                };
                match kind.as_str() {
                    "email" => emails.push(v),
                    "subject" => subjects.push(v),
                    _ => exact.push(v),
                }
            }
            Ok(())
        };
        strings(
            "SELECT 'subject', subject FROM user_identities WHERE user_id = ?1
             UNION ALL SELECT 'subject', issuer || '|' || subject FROM user_identities WHERE user_id = ?1
             UNION ALL SELECT 'email', email FROM user_identities WHERE user_id = ?1
             UNION ALL SELECT 'subject', external_id FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'email', user_name FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'name', given_name FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'name', family_name FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'name', display_name FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'name', formatted FROM scim_users WHERE user_id = ?1
             UNION ALL SELECT 'name', name FROM signups WHERE user_id = ?1 OR (?2 IS NOT NULL AND email = ?2)
             UNION ALL SELECT 'email', email FROM signups WHERE user_id = ?1 OR (?2 IS NOT NULL AND email = ?2)",
            &mut emails,
            &mut exact,
            &mut subjects,
        )
        .map_err(db_err)?;
        // A SCIM userName is often an email, but not always.
        let scrub_of = |emails: Vec<String>, mut exact: Vec<String>, subjects: &[String]| {
            let (names, mails): (Vec<String>, Vec<String>) = emails.into_iter().partition(|e| !e.contains('@'));
            exact.extend(names);
            exact.extend(subjects.iter().cloned());
            Scrub::new(user_id, pseudonym, mails, exact)
        };
        let scrub = scrub_of(emails.clone(), exact.clone(), &subjects);
        // Values they had before may be someone else's now, so they're scrubbed only from
        // events that name them by id.
        Self::past_identifiers(&tx, user_id, &mut emails, &mut exact, &mut subjects).map_err(db_err)?;
        let theirs = scrub_of(emails, exact, &subjects);

        let bots_json = serde_json::to_string(bots).unwrap_or_else(|_| "[]".into());
        let run = |sql: &str, p: &[&dyn rusqlite::ToSql]| tx.execute(sql, p).map_err(db_err);
        let mut out = Erased::default();
        run("DELETE FROM settings WHERE key = ?", &[&format!("{ERASING_BOTS}{user_id}")])?;
        run("DELETE FROM push_devices WHERE user_id = ?", &[&user_id])?;
        out.sessions = run("DELETE FROM sessions WHERE user_id = ?", &[&user_id])?;
        out.login_codes = run("DELETE FROM login_codes WHERE user_id = ?", &[&user_id])?;
        out.identities = run("DELETE FROM user_identities WHERE user_id = ?", &[&user_id])?;
        out.mfa = run("DELETE FROM user_mfa WHERE user_id = ?", &[&user_id])? > 0;
        out.recovery_codes = run("DELETE FROM mfa_recovery_codes WHERE user_id = ?", &[&user_id])?;
        out.scim = run("DELETE FROM scim_users WHERE user_id = ?", &[&user_id])? > 0;
        run("UPDATE scim_users SET manager_id = NULL WHERE manager_id = ?", &[&user_id])?;
        out.grants = run("DELETE FROM bot_grants WHERE user_id = ?", &[&user_id])?;
        out.team_invites = match &u.email {
            Some(e) => run("DELETE FROM team_invites WHERE email = ?", &[e])?,
            None => 0,
        };
        out.signups = run("DELETE FROM signups WHERE user_id = ?1 OR (?2 IS NOT NULL AND email = ?2)", &[&user_id, &u.email])?;
        out.billing_emails = run("DELETE FROM billing_emails WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM email_prefs WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM billing_checkouts WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM team_members WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM role_requests WHERE user_id = ?", &[&user_id])?;
        run("UPDATE role_requests SET decided_by = ?2 WHERE decided_by = ?1", &[&user_id, &pseudonym])?;
        run("DELETE FROM settings WHERE key = ?", &[&format!("machine_egress_policy:user:{user_id}")])?;
        run("DELETE FROM residency_pins WHERE subject_type = 'user' AND subject_id = ?", &[&user_id])?;
        run("DELETE FROM settings WHERE key = ?", &[&format!("{}{user_id}", crate::machines::egress_policy::USER_KEY)])?;
        run("UPDATE residency_pins SET pinned_by = ?2 WHERE pinned_by = ?1", &[&user_id, &pseudonym])?;
        let refs: Vec<(String, String, String)> = {
            let mut st = tx.prepare("SELECT subject_type, subject_id, reference FROM residency_pins").map_err(db_err)?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(db_err)?.filter_map(Result::ok).collect()
        };
        for (kind, id, reference) in refs {
            if let Some(r) = scrub.text(&reference) {
                run("UPDATE residency_pins SET reference = ?3 WHERE subject_type = ?1 AND subject_id = ?2", &[&kind, &id, &r])?;
            }
        }
        out.routines = self.on_places(&tx, "DELETE FROM {routines} WHERE author_id = ?", &[&user_id]).map_err(db_err)?;
        out.messages = self
            .on_places(
                &tx,
                &format!(
                    "UPDATE {{messages}} SET text = '{ERASED_TEXT}', question = NULL, requested_by = NULL
                     WHERE role IN ('user', 'routine') AND {SENT_BY_ANY}
                        OR from_bot IN (SELECT value FROM json_each(?2))"
                ),
                &[&user_id, &bots_json],
            )
            .map_err(db_err)?;
        self.on_places(&tx, &format!("UPDATE {{messages}} SET requested_by = NULL WHERE {SENT_BY_ANY}"), &[&user_id]).map_err(db_err)?;
        out.approvals = self.on_places(&tx, "UPDATE {approvals} SET decided_by = ?2, note = NULL WHERE decided_by = ?1", &[&user_id, &pseudonym]).map_err(db_err)?;
        out.disk_reports = run(
            "UPDATE machines SET disk_files = NULL, disk_files_partial = 0, disk_files_at = NULL WHERE user_id = ? AND (disk_files IS NOT NULL OR disk_files_at IS NOT NULL)",
            &[&user_id],
        )?;
        let at = now();
        run(
            "UPDATE users SET email = NULL, display_name = ?2, role = 'readonly', status = 'disabled', idp_issuer = NULL, idp_subject = NULL,
               last_login_at = NULL, last_login_method = NULL, last_login_idp_provider = NULL, last_seen_at = NULL, tier = NULL, role_id = NULL,
               erased_at = ?3, erased_by = ?4, erased_as = ?5, updated_at = ?3
             WHERE id = ?1",
            &[&user_id, &ERASED_NAME, &at, &by, &pseudonym],
        )?;
        run("DELETE FROM scim_role_grants WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM scim_role_group_grants WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM scim_role_group_team_grants WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM scim_role_group_members WHERE user_id = ?", &[&user_id])?;
        run("DELETE FROM saml_role_grants WHERE user_id = ?", &[&user_id])?;
        out.audit_events = Self::pseudonymise_audit(&tx, &scrub, &theirs).map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(out)
    }

    /// Names, emails and sign-in subjects the user had before: what `user.created`,
    /// `user.updated` and identity events about them recorded, so erasing scrubs old values
    /// a change left in the log.
    fn past_identifiers(c: &Connection, user_id: &str, emails: &mut Vec<String>, exact: &mut Vec<String>, subjects: &mut Vec<String>) -> rusqlite::Result<()> {
        const KEYS: [&str; 10] = ["name", "email", "userName", "externalId", "subject", "givenName", "familyName", "displayName", "formatted", "employeeNumber"];
        let mut st = c.prepare("SELECT details FROM audit_events WHERE target_type = 'user' AND target_id = ? AND action IN ('user.created', 'user.updated', 'user.identity_linked', 'user.identity_unlinked')")?;
        let rows = st.query_map([user_id], |r| r.get::<_, String>(0))?;
        for d in rows {
            let Ok(d) = serde_json::from_str::<Value>(&d?) else { continue };
            if let (Some(i), Some(sub)) = (d["issuer"].as_str(), d["subject"].as_str()) {
                subjects.push(format!("{i}|{sub}"));
            }
            let mut found = |key: &str, v: &Value| {
                let Some(v) = v.as_str().filter(|v| !v.trim().is_empty()) else { return };
                match key {
                    "externalId" | "subject" => subjects.push(v.into()),
                    "email" | "userName" => emails.push(v.into()),
                    _ => exact.push(v.into()),
                }
            };
            for key in KEYS {
                found(key, &d[key]);
                found(key, &d["changes"][key]["from"]);
                found(key, &d["changes"][key]["to"]);
            }
        }
        Ok(())
    }

    /// Rewrites every audit event about `s`'s user as `Scrub` says, inside the caller's
    /// transaction; events that name them by id as `named` says. Returns how many changed.
    fn pseudonymise_audit(c: &Connection, s: &Scrub, named: &Scrub) -> rusqlite::Result<usize> {
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", params![AUDIT_ERASING, s.pseudonym])?;
        let mut sql = String::from(
            "SELECT id, actor_id, actor_name, actor_email, actor_subject, target_id, on_behalf_of, ip, user_agent, session_id, details, action FROM audit_events
             WHERE action != ?2 AND (actor_id = ?1 OR target_id = ?1 OR on_behalf_of = ?1 OR instr(details, ?1) > 0",
        );
        let mut args: Vec<String> = vec![s.id.clone(), crate::audit_chain::ERASED.into()];
        for e in &s.emails {
            args.push(e.clone());
            sql.push_str(&format!(" OR actor_email = ?{n} COLLATE NOCASE OR instr(lower(details), ?{n}) > 0", n = args.len()));
        }
        for x in s.exact.iter().filter(|x| x.chars().count() >= 8) {
            args.push(x.clone());
            sql.push_str(&format!(" OR actor_subject = ?{n} OR instr(details, ?{n}) > 0", n = args.len()));
        }
        sql.push(')');
        type Row = (i64, [Option<String>; 9], String, String);
        let rows: Vec<Row> = {
            let mut st = c.prepare(&sql)?;
            let rows = st.query_map(rusqlite::params_from_iter(&args), |r| Ok((r.get(0)?, [r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?], r.get(10)?, r.get(11)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut cleared = Vec::new();
        for (id, [actor_id, name, email, subject, target, behalf, ip, agent, session], details, action) in rows {
            let is = |v: &Option<String>| v.as_deref() == Some(s.id.as_str());
            // A visitor without an account (a signup) is known only by the email they gave.
            let visitor = actor_id.is_none() && email.as_deref().is_some_and(|e| s.emails.contains(&e.to_lowercase()));
            let theirs = is(&actor_id) || visitor;
            let s = if theirs || is(&target) || is(&behalf) { named } else { s };
            let swap = |v: Option<String>| {
                if v.as_deref() == Some(s.id.as_str()) { Some(s.pseudonym.clone()) } else { v }
            };
            let mine = |v: Option<String>, matches: bool| if theirs || matches { None } else { v };
            let email_match = email.as_deref().is_some_and(|e| s.emails.contains(&e.to_lowercase()));
            let subject_match = subject.as_deref().is_some_and(|x| s.exact.contains(&x.to_lowercase()));
            let mut d: Value = serde_json::from_str(&details).unwrap_or(Value::Null);
            // A checkpoint's details are signed hashes and numbers, and its timestamp's are
            // the TSA's (ADR 0149): a match in them is a coincidence, and rewriting them
            // would break what a check holds them to.
            let signed = [crate::audit_checkpoint::CHECKPOINT, crate::audit_checkpoint::TIMESTAMPED].contains(&action.as_str());
            let changed = !signed && (s.value(&mut d) | (is(&target) && pseudonymise_employee_number(&mut d, &s.pseudonym)));
            let next = (
                swap(actor_id.clone()),
                mine(name.clone(), false),
                mine(email.clone(), email_match),
                mine(subject.clone(), subject_match),
                swap(target.clone()),
                swap(behalf.clone()),
                mine(ip.clone(), false),
                mine(agent.clone(), false),
                mine(session.clone(), false),
            );
            if !changed && next == (actor_id, name, email, subject, target, behalf, ip, agent, session) {
                continue;
            }
            c.execute(
                "UPDATE audit_events SET actor_id = ?2, actor_name = ?3, actor_email = ?4, actor_subject = ?5, target_id = ?6, on_behalf_of = ?7,
                   ip = ?8, user_agent = ?9, session_id = ?10, details = ?11, chain_salt = NULL WHERE id = ?1",
                params![id, next.0, next.1, next.2, next.3, next.4, next.5, next.6, next.7, next.8, if changed { d.to_string() } else { details }],
            )?;
            cleared.push(id);
        }
        // On the chain, in the same transaction: the rows whose salt this erasure cleared.
        // An erased row no such event names is reported as tampered with (ADR 0122).
        if !cleared.is_empty() {
            crate::audit_chain::insert_erased(c, &s.pseudonym, &cleared)?;
        }
        c.execute("DELETE FROM settings WHERE key = ?", [AUDIT_ERASING])?;
        Ok(cleared.len())
    }

    /// Every row of every table, as `(table, the row's columns as text)`.
    #[cfg(test)]
    pub fn all_rows(&self) -> Vec<(String, String)> {
        let c = self.c();
        let tables: Vec<String> = {
            let mut s = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
        };
        let mut out = Vec::new();
        for t in tables {
            let mut s = c.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
            let n = s.column_count();
            let rows = s
                .query_map([], |r| {
                    Ok((0..n)
                        .map(|i| match r.get_ref(i) {
                            Ok(rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b)) => String::from_utf8_lossy(b).into_owned(),
                            Ok(rusqlite::types::ValueRef::Integer(i)) => i.to_string(),
                            _ => String::new(),
                        })
                        .collect::<Vec<_>>()
                        .join("\u{1f}"))
                })
                .unwrap();
            out.extend(rows.filter_map(Result::ok).map(|row| (t.clone(), row)));
        }
        out
    }

    #[cfg(test)]
    pub fn execute_raw(&self, sql: &str) -> rusqlite::Result<usize> {
        self.c().execute(sql, [])
    }

    // Tiers and usage (ADR 0033). Every query names the user.

    /// Tiers assigned to users, each once.
    pub fn assigned_tiers(&self) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT DISTINCT tier FROM users WHERE tier IS NOT NULL ORDER BY tier").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    pub fn owned_bot_count(&self, owner_id: &str) -> u32 {
        self.c().query_row("SELECT COUNT(*) FROM bots WHERE owner_id = ?", [owner_id], |r| r.get(0)).unwrap_or(0)
    }

    /// The ids of the Bots a user owns.
    pub fn owned_bot_ids(&self, owner_id: &str) -> Vec<String> {
        let c = self.c();
        let Ok(mut st) = c.prepare("SELECT id FROM bots WHERE owner_id = ? ORDER BY id") else { return Vec::new() };
        st.query_map([owner_id], |r| r.get(0)).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// Runs counted for this user in `period` (`YYYY-MM`).
    pub fn runs_used(&self, user_id: &str, period: &str) -> u32 {
        self.c()
            .query_row("SELECT runs FROM usage_monthly WHERE user_id = ? AND period = ?", [user_id, period], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Counts one run for the user, unless that would pass `limit`. One statement, so
    /// runs racing for the last one can't both get it. Ok: runs used now; Err: the limit.
    pub fn take_run(&self, user_id: &str, period: &str, limit: Option<u32>) -> Result<u32, u32> {
        let c = self.c();
        let cap = limit.map_or(i64::MAX, i64::from);
        let taken = c
            .query_row(
                "INSERT INTO usage_monthly (user_id, period, runs) SELECT ?1, ?2, 1 WHERE ?3 >= 1
                 ON CONFLICT (user_id, period) DO UPDATE SET runs = runs + 1 WHERE runs < ?3
                 RETURNING runs",
                params![user_id, period, cap],
                |r| r.get::<_, u32>(0),
            )
            .optional()
            .ok()
            .flatten();
        taken.ok_or(limit.unwrap_or(0))
    }

    /// Gives back a run that was counted but didn't happen (it was refused).
    pub fn give_back_run(&self, user_id: &str, period: &str) {
        let _ = self.c().execute("UPDATE usage_monthly SET runs = runs - 1 WHERE user_id = ? AND period = ? AND runs > 0", [user_id, period]);
    }

    /// Routine runs counted for this user on `day` (`YYYY-MM-DD`).
    pub fn routine_runs_used(&self, user_id: &str, day: &str) -> u32 {
        self.c()
            .query_row("SELECT routine_runs FROM usage_daily WHERE user_id = ? AND day = ?", [user_id, day], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Counts one routine run for the user, unless that would pass `limit`, in one
    /// statement like `take_run`. Ok: routine runs used now; Err: the limit.
    pub fn take_routine_run(&self, user_id: &str, day: &str, limit: Option<u32>) -> Result<u32, u32> {
        let cap = limit.map_or(i64::MAX, i64::from);
        let taken = self
            .c()
            .query_row(
                "INSERT INTO usage_daily (user_id, day, routine_runs) SELECT ?1, ?2, 1 WHERE ?3 >= 1
                 ON CONFLICT (user_id, day) DO UPDATE SET routine_runs = routine_runs + 1 WHERE routine_runs < ?3
                 RETURNING routine_runs",
                params![user_id, day, cap],
                |r| r.get::<_, u32>(0),
            )
            .optional()
            .ok()
            .flatten();
        taken.ok_or(limit.unwrap_or(0))
    }

    /// Gives back a routine run that was counted but didn't happen.
    pub fn give_back_routine_run(&self, user_id: &str, day: &str) {
        let _ = self.c().execute("UPDATE usage_daily SET routine_runs = routine_runs - 1 WHERE user_id = ? AND day = ? AND routine_runs > 0", [user_id, day]);
    }

    /// Notes a refused routine run. True for the user's first refusal that day, so the
    /// Bot says so once a day instead of at every firing.
    /// Records one run's model tokens (ADR 0050), all rows or none.
    pub fn record_tokens(&self, rows: &[TokenRow]) -> rusqlite::Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        for r in rows {
            let n = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
            tx.execute(
                "INSERT INTO token_usage (user_id, bot_id, run_id, message_id, harness, model, reported,
                   input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, at, meter_status, meter_customer)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    r.user_id,
                    r.bot_id,
                    r.run_id,
                    r.message_id,
                    r.harness,
                    r.model,
                    r.reported,
                    n(r.input),
                    n(r.output),
                    n(r.cache_read),
                    n(r.cache_write),
                    r.at,
                    r.meter.as_ref().map(|_| "pending"),
                    r.meter
                ],
            )?;
        }
        tx.commit()
    }

    /// Every model token a user's runs used in `[start, end)`, Unix ms.
    pub fn tokens_used(&self, user_id: &str, start: i64, end: i64) -> u64 {
        self.c()
            .query_row(
                "SELECT COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens), 0)
                 FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3",
                params![user_id, start, end],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| u64::try_from(n).unwrap_or(0))
    }

    /// A user's tokens in `[start, end)`, Unix ms: in all, per model, and per Bot.
    pub fn token_summary(&self, user_id: &str, start: i64, end: i64) -> TokenSummary {
        let c = self.c();
        let sums = "COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cache_read_tokens), 0),
                    COALESCE(SUM(cache_write_tokens), 0), COUNT(DISTINCT run_id), COUNT(DISTINCT CASE WHEN reported = 0 THEN run_id END)";
        let totals = |r: &rusqlite::Row, at: usize| -> rusqlite::Result<TokenTotals> {
            let n = |i: usize| r.get::<_, i64>(at + i).map(|v| u64::try_from(v).unwrap_or(0));
            Ok(TokenTotals { input: n(0)?, output: n(1)?, cache_read: n(2)?, cache_write: n(3)?, runs: n(4)?, unreported_runs: n(5)? })
        };
        let all = c
            .query_row(&format!("SELECT {sums} FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3"), params![user_id, start, end], |r| totals(r, 0))
            .unwrap_or_default();
        let grouped = |by: &str| -> Vec<(Option<String>, TokenTotals)> {
            let sql = format!("SELECT {by}, {sums} FROM token_usage WHERE user_id = ?1 AND at >= ?2 AND at < ?3 GROUP BY {by} ORDER BY {by}");
            let Ok(mut st) = c.prepare(&sql) else { return Vec::new() };
            st.query_map(params![user_id, start, end], |r| Ok((r.get::<_, Option<String>>(0)?, totals(r, 1)?)))
                .map(|rows| rows.filter_map(Result::ok).collect())
                .unwrap_or_default()
        };
        let by_model = grouped("model");
        let by_bot = grouped("bot_id").into_iter().filter_map(|(id, t)| Some((id?, t))).collect();
        TokenSummary { all, by_model, by_bot }
    }

    /// The oldest token rows waiting to go to Stripe.
    pub fn pending_meter(&self, limit: u32) -> Vec<MeterRow> {
        let c = self.c();
        let Ok(mut st) = c.prepare(
            "SELECT id, user_id, run_id, input_tokens + output_tokens + cache_read_tokens + cache_write_tokens, at, meter_attempts, meter_customer
             FROM token_usage WHERE meter_status = 'pending' ORDER BY id LIMIT ?1",
        ) else {
            return Vec::new();
        };
        st.query_map([limit], |r| {
            Ok(MeterRow { id: r.get(0)?, user_id: r.get(1)?, run_id: r.get(2)?, tokens: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0), at: r.get(4)?, attempts: r.get(5)?, customer: r.get(6)? })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// Marks a token row `sent` or `failed` at Stripe, or counts one more try when None.
    pub fn meter_result(&self, id: i64, status: Option<&str>) {
        let _ = self.c().execute(
            "UPDATE token_usage SET meter_status = COALESCE(?2, meter_status), meter_attempts = meter_attempts + 1 WHERE id = ?1",
            params![id, status],
        );
    }

    /// Whether `action` was audited about this target at or after `since` (ms).
    pub fn audited_since(&self, action: &str, target_type: &str, target_id: &str, since: i64) -> bool {
        self.c()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM audit_events WHERE action = ?1 AND target_type = ?2 AND target_id = ?3 AND at >= ?4)",
                params![action, target_type, target_id, since],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
    }

    pub fn routine_refused(&self, user_id: &str, day: &str) -> bool {
        self.c()
            .query_row(
                "INSERT INTO usage_daily (user_id, day, routine_refused) VALUES (?1, ?2, 1)
                 ON CONFLICT (user_id, day) DO UPDATE SET routine_refused = routine_refused + 1
                 RETURNING routine_refused",
                [user_id, day],
                |r| r.get::<_, i64>(0),
            )
            .is_ok_and(|n| n == 1)
    }

    // Billing (ADR 0040)

    /// The subscription that sets the user's tier (`paying_subscription`), else the one
    /// with the latest event, to show how it ended.
    pub fn subscription(&self, user_id: &str) -> Option<Subscription> {
        let c = self.c();
        paying_subscription(&c, user_id)
            .ok()
            .flatten()
            .or_else(|| c.query_row("SELECT * FROM subscriptions WHERE user_id = ? ORDER BY event_created DESC, started DESC LIMIT 1", [user_id], subscription_row).optional().ok().flatten())
    }

    pub fn subscription_by_id(&self, subscription_id: &str) -> Option<Subscription> {
        self.c().query_row("SELECT * FROM subscriptions WHERE subscription_id = ?", [subscription_id], subscription_row).optional().ok().flatten()
    }

    /// Applies one payment-provider event, in one transaction: records the event id (a
    /// redelivery is `Duplicate`), skips events older than the last one applied to the
    /// same subscription, or that would revive one cancelled for good (`Stale`; Stripe
    /// times events to the second, so an update can tie with the cancellation after
    /// it), and keeps the subscription's latest state. The
    /// user's tier is then that of their paying subscription started last (None, the
    /// default tier, when nothing pays); `users.tier` is set to it when this event
    /// changed which one that is, or is for that one. An event for any other
    /// subscription is `Superseded`. So the outcome doesn't depend on the order events
    /// arrive in: a late event for a replaced plan can't bring it back, and a new plan
    /// applies whenever the old one's cancellation arrives. `set_tier` false (a
    /// subscription not paid for yet) records it without changing any tier.
    ///
    /// The subscription's customer (ADR 0042) must not be another user's
    /// (`CustomerOfAnotherUser`); a user with no customer yet is linked to it, and the
    /// second value says how.
    ///
    /// `mail` gives the billing emails the event asks for (ADR 0091), queued in the same
    /// transaction, so an event is recorded exactly when its emails are: a redelivery
    /// (`Duplicate`) neither loses nor repeats them.
    pub fn apply_subscription(
        &self,
        event_id: &str,
        event_type: &str,
        sub: &Subscription,
        set_tier: bool,
        mail: &dyn Fn(&Change) -> Vec<crate::billing_mail::NewEmail>,
    ) -> Result<(Applied, Option<Linked>, usize), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok((Applied::Duplicate, None, 0));
        }
        let by_id = tx.query_row("SELECT * FROM subscriptions WHERE subscription_id = ?", [&sub.subscription_id], subscription_row).optional().map_err(|e| e.to_string())?;
        let mut paying_before: Option<Subscription> = None;
        let mut paying_after: Option<Subscription> = None;
        let mut other_paying: Option<Subscription> = None;
        let customer_user = |cus: &str| tx.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [cus], |r| r.get::<_, String>(0)).optional();
        let others_customer = match (&by_id, &sub.customer_id) {
            (Some(s), _) if s.user_id != sub.user_id => false,
            (_, Some(cus)) => {
                customer_user(cus).map_err(|e| e.to_string())?.is_some_and(|u| u != sub.user_id) || customer_team_in(&tx, cus).map_err(|e| e.to_string())?.is_some()
            }
            (_, None) => false,
        };
        let teams: bool = tx.query_row("SELECT COUNT(*) FROM team_subscriptions WHERE subscription_id = ?", [&sub.subscription_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        let outcome = if teams || by_id.as_ref().is_some_and(|s| s.user_id != sub.user_id) {
            Applied::OtherUser
        } else if others_customer {
            Applied::CustomerOfAnotherUser
        } else if by_id.as_ref().is_some_and(|s| {
            // Stripe never revives a subscription it cancelled for good. Its `created` is
            // in seconds, so two events can tie; an ended state wins the tie.
            let fin = |status: &str| crate::billing::FINAL.contains(&status);
            let ended = |status: &str| crate::billing::ENDED.contains(&status);
            sub.event_created < s.event_created
                || (fin(&s.status) && !fin(&sub.status))
                || (sub.event_created == s.event_created && ended(&s.status) && !ended(&sub.status))
        }) {
            Applied::Stale
        } else {
            let paying_id = |s: &Option<Subscription>| s.as_ref().map(|s| s.subscription_id.clone());
            let before = paying_subscription(&tx, &sub.user_id).map_err(|e| e.to_string())?;
            let tier = if set_tier { sub.tier.clone() } else { by_id.as_ref().and_then(|s| s.tier.clone()) };
            tx.execute(
                "INSERT INTO subscriptions (subscription_id, user_id, provider, customer_id, status, price_id, tier, period_end, started, event_created, updated_at, period_start)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT (subscription_id) DO UPDATE SET provider = ?3, customer_id = ?4, status = ?5, price_id = ?6,
                   tier = ?7, period_end = ?8, event_created = ?10, updated_at = ?11, period_start = ?12",
                params![sub.subscription_id, sub.user_id, sub.provider, sub.customer_id, sub.status, sub.price_id, tier, sub.period_end, sub.started, sub.event_created, now(), sub.period_start],
            )
            .map_err(|e| e.to_string())?;
            let after = paying_subscription(&tx, &sub.user_id).map_err(|e| e.to_string())?;
            let moved = paying_id(&before) != paying_id(&after);
            let to = after.as_ref().and_then(|s| s.tier.clone());
            paying_before = before;
            paying_after = after.clone();
            other_paying = tx
                .query_row(
                    "SELECT * FROM subscriptions WHERE user_id = ? AND tier IS NOT NULL AND subscription_id != ? ORDER BY started DESC, subscription_id DESC LIMIT 1",
                    [&sub.user_id, &sub.subscription_id],
                    subscription_row,
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if after.as_ref().is_some_and(|s| s.subscription_id != sub.subscription_id) && !moved {
                Applied::Superseded
            } else if !set_tier && !moved {
                Applied::Unchanged
            } else {
                let from: Option<String> = tx.query_row("SELECT tier FROM users WHERE id = ?", [&sub.user_id], |r| r.get(0)).map_err(|e| e.to_string())?;
                if from != to {
                    tx.execute("UPDATE users SET tier = ?, updated_at = ? WHERE id = ?", params![to, now(), sub.user_id]).map_err(|e| e.to_string())?;
                    Applied::Changed { from, to }
                } else {
                    Applied::Unchanged
                }
            }
        };
        let linked = match (&outcome, &sub.customer_id) {
            (Applied::OtherUser | Applied::CustomerOfAnotherUser, _) | (_, None) => None,
            (_, Some(cus)) => Some(link_in(&tx, &sub.user_id, &sub.provider, cus, "subscription").map_err(|e| e.to_string())?),
        };
        let emails = mail(&Change { applied: &outcome, before: by_id.as_ref(), paying_before: paying_before.as_ref(), paying_after: paying_after.as_ref(), other_paying: other_paying.as_ref() });
        // Held until the caller has followed the event (`release_billing_emails`), so a
        // plan email can say what the computer is doing; due anyway after the hold.
        let due = now() + crate::billing_mail::HOLD_MS;
        let mut queued = 0;
        for e in &emails {
            queued += usize::from(queue_email(&tx, e, due).map_err(|e| e.to_string())?);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok((outcome, linked, queued))
    }

    /// Queues a billing email (ADR 0091) unless one with its key was queued before.
    /// True when this queued it.
    pub fn queue_billing_email(&self, e: &crate::billing_mail::NewEmail) -> bool {
        queue_email(&self.c(), e, now()).unwrap_or_else(|err| {
            crate::obs::log::log_warn!("botd: couldn't queue a billing email: {err}");
            false
        })
    }

    /// Billing emails due now, oldest first.
    pub fn due_billing_emails(&self, now: i64, limit: u32) -> Vec<crate::billing_mail::Queued> {
        let c = self.c();
        let Ok(mut q) = c.prepare("SELECT * FROM billing_emails WHERE state = 'pending' AND next_at <= ? ORDER BY id LIMIT ?") else { return Vec::new() };
        q.query_map(params![now, limit], queued_email_row).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// A user's billing emails, newest first.
    #[cfg(test)]
    pub fn billing_emails_of(&self, user_id: &str, limit: u32) -> Vec<crate::billing_mail::Queued> {
        let c = self.c();
        let Ok(mut q) = c.prepare("SELECT * FROM billing_emails WHERE user_id = ? ORDER BY id DESC LIMIT ?") else { return Vec::new() };
        q.query_map(params![user_id, limit], queued_email_row).map(|rows| rows.flatten().collect()).unwrap_or_default()
    }

    /// Makes a Stripe event's held emails due now.
    pub fn release_billing_emails(&self, event_id: &str) {
        let at = now();
        if let Err(e) = self.c().execute(
            "UPDATE billing_emails SET next_at = ? WHERE event_id = ? AND state = 'pending' AND attempts = 0 AND next_at > ?",
            params![at, event_id, at],
        ) {
            crate::obs::log::log_warn!("botd: couldn't release billing emails for {event_id}: {e}");
        }
    }

    /// Counts a try of a pending billing email before it's sent, and puts its next try
    /// at `next_at`. False when it's no longer pending.
    pub fn claim_billing_email(&self, id: i64, next_at: i64) -> Result<bool, String> {
        self.c()
            .execute("UPDATE billing_emails SET attempts = attempts + 1, next_at = ? WHERE id = ? AND state = 'pending'", params![next_at, id])
            .map(|n| n == 1)
            .map_err(|e| e.to_string())
    }

    /// Settles a pending billing email: `sent`, `skipped` or `failed`, or `pending` with
    /// why its last try failed.
    pub fn billing_email_result(&self, id: i64, state: &str, reason: Option<&str>) -> Result<(), String> {
        let done = (state != "pending").then(now);
        self.c()
            .execute("UPDATE billing_emails SET state = ?, reason = ?, done_at = ? WHERE id = ? AND state = 'pending'", params![state, reason, done, id])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Makes every pending billing email due now, as if its backoff had passed.
    #[cfg(test)]
    pub fn billing_emails_due_now(&self) {
        self.c().execute("UPDATE billing_emails SET next_at = 0 WHERE state = 'pending'", []).unwrap();
    }

    /// Whether the person wants usage emails (ADR 0091). On unless they turned them off.
    pub fn usage_emails(&self, user_id: &str) -> bool {
        self.c().query_row("SELECT usage_emails FROM email_prefs WHERE user_id = ?", [user_id], |r| r.get(0)).optional().ok().flatten().unwrap_or(true)
    }

    pub fn set_usage_emails(&self, user_id: &str, on: bool) -> Result<(), String> {
        self.c()
            .execute(
                "INSERT INTO email_prefs (user_id, usage_emails, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (user_id) DO UPDATE SET usage_emails = ?2, updated_at = ?3",
                params![user_id, on, now()],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The user's payment-provider customer (ADR 0042).
    pub fn customer_of(&self, user_id: &str) -> Option<String> {
        self.c().query_row("SELECT customer_id FROM billing_customers WHERE user_id = ?", [user_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// The user a customer is linked to.
    pub fn customer_user(&self, customer_id: &str) -> Option<String> {
        self.c().query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [customer_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// Links a customer to a user for one provider event, in one transaction with
    /// recording the event. None: the event was applied already.
    pub fn link_customer(&self, event_id: &str, event_type: &str, user_id: &str, provider: &str, customer_id: &str, via: &str) -> Result<Option<Linked>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        let linked = link_in(&tx, user_id, provider, customer_id, via).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(linked))
    }

    /// Drops a customer the provider deleted, for one provider event. `Ok(None)`: the
    /// event was applied already; else the user or team (ADR 0093) that had it, if any.
    pub fn unlink_customer(&self, event_id: &str, event_type: &str, customer_id: &str) -> Result<Option<Unlinked>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        let user: Option<String> =
            tx.query_row("DELETE FROM billing_customers WHERE customer_id = ? RETURNING user_id", [customer_id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        let team: Option<String> =
            tx.query_row("DELETE FROM team_customers WHERE customer_id = ? RETURNING team_id", [customer_id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO billing_deleted_customers (customer_id, deleted_at) VALUES (?, ?)", params![customer_id, now()]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(Unlinked { user, team }))
    }

    /// The user's checkout session that may still be open (`expires_at` in seconds, as Stripe has it).
    pub fn open_checkout(&self, user_id: &str) -> Option<String> {
        let at = now() / 1000;
        self.c().query_row("SELECT session_id FROM billing_checkouts WHERE user_id = ? AND expires_at > ?", params![user_id, at], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_open_checkout(&self, user_id: &str, session_id: &str, expires_at: i64) {
        let _ = self.c().execute(
            "INSERT INTO billing_checkouts (user_id, session_id, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET session_id = excluded.session_id, expires_at = excluded.expires_at",
            params![user_id, session_id, expires_at],
        );
    }

    /// Forgets the user's open checkout if it is `session_id` (closed, or paid).
    pub fn close_checkout(&self, user_id: &str, session_id: &str) {
        let _ = self.c().execute("DELETE FROM billing_checkouts WHERE user_id = ? AND session_id = ?", params![user_id, session_id]);
    }

    // Team billing (ADR 0093)

    /// The team's last checkout while it may still be paid, or is paid and its
    /// subscription isn't recorded yet (kept for Stripe's 3 days of webhook retries).
    pub fn team_open_checkout(&self, team_id: &str) -> Option<String> {
        let at = now() / 1000;
        self.c()
            .query_row(
                "SELECT session_id FROM team_checkouts WHERE team_id = ?1 AND (expires_at > ?2 OR (subscription_id IS NOT NULL AND expires_at > ?2 - 3 * 86400))",
                params![team_id, at],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// A team's checkout went through: keep it until its subscription is recorded, so
    /// no second checkout opens meanwhile. Forgotten at once if it already is.
    pub fn team_checkout_paid(&self, team_id: &str, session_id: &str, subscription_id: Option<&str>) {
        match subscription_id {
            Some(sub) if self.team_subscription_by_id(sub).is_none() => {
                let _ = self.c().execute("UPDATE team_checkouts SET subscription_id = ? WHERE team_id = ? AND session_id = ?", params![sub, team_id, session_id]);
            }
            _ => self.close_team_checkout(team_id, session_id),
        }
    }

    /// The team's paid checkout for `subscription_id` is done with: its subscription is recorded.
    pub fn close_team_checkout_for(&self, team_id: &str, subscription_id: &str) {
        let _ = self.c().execute("DELETE FROM team_checkouts WHERE team_id = ? AND subscription_id = ?", params![team_id, subscription_id]);
    }

    pub fn set_team_open_checkout(&self, team_id: &str, session_id: &str, expires_at: i64) {
        let _ = self.c().execute(
            "INSERT INTO team_checkouts (team_id, session_id, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(team_id) DO UPDATE SET session_id = excluded.session_id, expires_at = excluded.expires_at, subscription_id = NULL",
            params![team_id, session_id, expires_at],
        );
    }

    pub fn close_team_checkout(&self, team_id: &str, session_id: &str) {
        let _ = self.c().execute("DELETE FROM team_checkouts WHERE team_id = ? AND session_id = ?", params![team_id, session_id]);
    }

    /// The team's payment-provider customer.
    pub fn team_customer(&self, team_id: &str) -> Option<String> {
        self.c().query_row("SELECT customer_id FROM team_customers WHERE team_id = ?", [team_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// The team a customer is linked to.
    pub fn customer_team(&self, customer_id: &str) -> Option<String> {
        customer_team_in(&self.c(), customer_id).ok().flatten()
    }

    /// Links a customer to a team for one provider event (a completed checkout). None:
    /// the event was applied already.
    pub fn link_team_customer(&self, event_id: &str, event_type: &str, team_id: &str, provider: &str, customer_id: &str) -> Result<Option<Linked>, String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok(None);
        }
        let linked = link_team_in(&tx, team_id, provider, customer_id, "checkout").map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(linked))
    }

    /// The subscription that sets the team's plan, else the one with the latest event.
    pub fn team_subscription(&self, team_id: &str) -> Option<TeamSubscription> {
        let c = self.c();
        team_paying_in(&c, team_id).ok().flatten().or_else(|| {
            c.query_row("SELECT * FROM team_subscriptions WHERE team_id = ? ORDER BY event_created DESC, started DESC LIMIT 1", [team_id], team_subscription_row)
                .optional()
                .ok()
                .flatten()
        })
    }

    /// The subscription paying for the team's plan now, if one does.
    pub fn team_paying(&self, team_id: &str) -> Option<TeamSubscription> {
        team_paying_in(&self.c(), team_id).ok().flatten()
    }

    pub fn team_subscription_by_id(&self, subscription_id: &str) -> Option<TeamSubscription> {
        self.c().query_row("SELECT * FROM team_subscriptions WHERE subscription_id = ?", [subscription_id], team_subscription_row).optional().ok().flatten()
    }

    /// The subscription paying for the plan of `user_id`'s team, if they're on one that
    /// pays: then its plan is theirs (ADR 0093). One query, as every run asks.
    pub fn team_plan_of(&self, user_id: &str) -> Option<TeamSubscription> {
        self.c()
            .query_row(
                "SELECT s.* FROM team_members m JOIN team_subscriptions s ON s.team_id = m.team_id
                 WHERE m.user_id = ? AND s.tier IS NOT NULL ORDER BY s.started DESC, s.subscription_id DESC LIMIT 1",
                [user_id],
                team_subscription_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Every team's paying subscription, for syncing seats.
    pub fn teams_paying(&self) -> Vec<TeamSubscription> {
        let c = self.c();
        let Ok(mut s) = c.prepare(
            "SELECT * FROM team_subscriptions s WHERE tier IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM team_subscriptions o WHERE o.team_id = s.team_id AND o.tier IS NOT NULL
               AND (o.started > s.started OR (o.started = s.started AND o.subscription_id > s.subscription_id)))
             ORDER BY team_id",
        ) else {
            return Vec::new();
        };
        s.query_map([], team_subscription_row).map(|rows| rows.filter_map(Result::ok).collect()).unwrap_or_default()
    }

    pub fn team_member_count(&self, team_id: &str) -> i64 {
        self.c().query_row("SELECT COUNT(*) FROM team_members WHERE team_id = ?", [team_id], |r| r.get(0)).unwrap_or(0)
    }

    /// Counts a seat update about to be sent, and returns how many have been, this one included.
    pub fn team_seat_try(&self, subscription_id: &str) -> Result<i64, String> {
        self.c()
            .query_row("UPDATE team_subscriptions SET seat_tries = seat_tries + 1 WHERE subscription_id = ? RETURNING seat_tries", [subscription_id], |r| r.get(0))
            .map_err(|e| e.to_string())
    }

    /// The provider now bills `quantity` seats.
    pub fn team_seats_synced(&self, subscription_id: &str, quantity: i64) {
        let _ = self.c().execute(
            "UPDATE team_subscriptions SET quantity = ?, seat_failures = 0, seat_next_at = 0, seat_error = NULL, updated_at = ? WHERE subscription_id = ?",
            params![quantity, now(), subscription_id],
        );
    }

    /// A seat update failed: tried again at `next_at`.
    pub fn team_seats_failed(&self, subscription_id: &str, error: &str, next_at: i64) -> i64 {
        self.c()
            .query_row(
                "UPDATE team_subscriptions SET seat_failures = seat_failures + 1, seat_next_at = ?, seat_error = ? WHERE subscription_id = ? RETURNING seat_failures",
                params![next_at, error, subscription_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Seats match the team again with no update of ours (the provider's own event said so).
    pub fn team_seats_clear(&self, subscription_id: &str) {
        let _ = self.c().execute("UPDATE team_subscriptions SET seat_failures = 0, seat_next_at = 0, seat_error = NULL WHERE subscription_id = ?", [subscription_id]);
    }

    /// Applies one team subscription event (ADR 0093) as `apply_subscription` does a
    /// user's: once (`Duplicate`), in order (`Stale`), only to its own team (`OtherUser`:
    /// another team's subscription), never through a customer someone else has
    /// (`CustomerOfAnotherUser`: a user's or another team's), and the team's plan is its
    /// paying subscription started last, so the order events arrive in doesn't matter.
    /// `Changed` holds the team's plan before and after. The team is linked to the
    /// subscription's customer if it has none, and `mail` queues the event's emails in
    /// the same transaction.
    pub fn apply_team_subscription(
        &self,
        event_id: &str,
        event_type: &str,
        sub: &TeamSubscription,
        set_tier: bool,
        mail: &dyn Fn(&TeamChange) -> Vec<crate::billing_mail::NewEmail>,
    ) -> Result<(Applied, Option<Linked>, usize), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        if !first_delivery(&tx, event_id, event_type).map_err(|e| e.to_string())? {
            return Ok((Applied::Duplicate, None, 0));
        }
        let e = |e: rusqlite::Error| e.to_string();
        let by_id = tx.query_row("SELECT * FROM team_subscriptions WHERE subscription_id = ?", [&sub.subscription_id], team_subscription_row).optional().map_err(e)?;
        let personal: bool = tx.query_row("SELECT COUNT(*) FROM subscriptions WHERE subscription_id = ?", [&sub.subscription_id], |r| r.get(0)).map_err(e)?;
        let others_customer = match &sub.customer_id {
            Some(cus) => {
                let user: Option<String> = tx.query_row("SELECT user_id FROM billing_customers WHERE customer_id = ?", [cus], |r| r.get(0)).optional().map_err(e)?;
                user.is_some() || customer_team_in(&tx, cus).map_err(e)?.is_some_and(|t| t != sub.team_id)
            }
            None => false,
        };
        let (mut paying_before, mut paying_after, mut other_paying) = (None, None, None);
        let outcome = if personal || by_id.as_ref().is_some_and(|s| s.team_id != sub.team_id) {
            Applied::OtherUser
        } else if others_customer {
            Applied::CustomerOfAnotherUser
        } else if by_id.as_ref().is_some_and(|s| {
            let fin = |status: &str| crate::billing::FINAL.contains(&status);
            let ended = |status: &str| crate::billing::ENDED.contains(&status);
            sub.event_created < s.event_created
                || (fin(&s.status) && !fin(&sub.status))
                || (sub.event_created == s.event_created && ended(&s.status) && !ended(&sub.status))
        }) {
            Applied::Stale
        } else {
            let before = team_paying_in(&tx, &sub.team_id).map_err(e)?;
            let tier = if set_tier { sub.tier.clone() } else { by_id.as_ref().and_then(|s| s.tier.clone()) };
            tx.execute(
                "INSERT INTO team_subscriptions (subscription_id, team_id, provider, customer_id, status, price_id, tier, item_id, quantity,
                   period_start, period_end, cancel_at, started, event_created, updated_at, paid_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT (subscription_id) DO UPDATE SET provider = ?3, customer_id = ?4, status = ?5, price_id = ?6, tier = ?7,
                   item_id = COALESCE(?8, item_id), quantity = COALESCE(?9, quantity), period_start = ?10, period_end = ?11, cancel_at = ?12,
                   event_created = ?14, updated_at = ?15, paid_by = COALESCE(paid_by, ?16)",
                params![
                    sub.subscription_id,
                    sub.team_id,
                    sub.provider,
                    sub.customer_id,
                    sub.status,
                    sub.price_id,
                    tier,
                    sub.item_id,
                    sub.quantity,
                    sub.period_start,
                    sub.period_end,
                    sub.cancel_at,
                    sub.started,
                    sub.event_created,
                    now(),
                    sub.paid_by
                ],
            )
            .map_err(e)?;
            let after = team_paying_in(&tx, &sub.team_id).map_err(e)?;
            other_paying = tx
                .query_row(
                    "SELECT * FROM team_subscriptions WHERE team_id = ? AND tier IS NOT NULL AND subscription_id != ? ORDER BY started DESC, subscription_id DESC LIMIT 1",
                    [&sub.team_id, &sub.subscription_id],
                    team_subscription_row,
                )
                .optional()
                .map_err(e)?;
            let id = |s: &Option<TeamSubscription>| s.as_ref().map(|s| s.subscription_id.clone());
            let moved = id(&before) != id(&after);
            let (from, to) = (before.as_ref().and_then(|s| s.tier.clone()), after.as_ref().and_then(|s| s.tier.clone()));
            let outcome = if after.as_ref().is_some_and(|s| s.subscription_id != sub.subscription_id) && !moved {
                Applied::Superseded
            } else if from != to {
                Applied::Changed { from, to }
            } else {
                Applied::Unchanged
            };
            paying_before = before;
            paying_after = after;
            outcome
        };
        let linked = match (&outcome, &sub.customer_id) {
            (Applied::OtherUser | Applied::CustomerOfAnotherUser, _) | (_, None) => None,
            (_, Some(cus)) => Some(link_team_in(&tx, &sub.team_id, &sub.provider, cus, "subscription").map_err(e)?),
        };
        let emails = mail(&TeamChange {
            applied: &outcome,
            before: by_id.as_ref(),
            paying_before: paying_before.as_ref(),
            paying_after: paying_after.as_ref(),
            other_paying: other_paying.as_ref(),
        });
        let due = now() + crate::billing_mail::HOLD_MS;
        let mut queued = 0;
        for m in &emails {
            queued += usize::from(queue_email(&tx, m, due).map_err(e)?);
        }
        tx.commit().map_err(e)?;
        Ok((outcome, linked, queued))
    }

    // SSO identities (ADR 0014)

    /// The identity with this key and its user, whatever the user's status.
    pub fn identity(&self, issuer: &str, subject: &str) -> Option<(Identity, User)> {
        let c = self.c();
        let i = c
            .query_row("SELECT * FROM user_identities WHERE issuer = ? AND subject = ?", [issuer, subject], identity_row)
            .optional()
            .ok()
            .flatten()?;
        let u = c.query_row("SELECT * FROM users WHERE id = ?", [&i.user_id], user_row).optional().ok().flatten()?;
        Some((i, u))
    }

    pub fn identities(&self, user_id: &str) -> Vec<Identity> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM user_identities WHERE user_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([user_id], identity_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every user's identities, keyed by user id, for the admin list.
    pub fn all_identities(&self) -> HashMap<String, Vec<Identity>> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM user_identities ORDER BY created_at, id").unwrap();
        let mut out: HashMap<String, Vec<Identity>> = HashMap::new();
        for i in s.query_map([], identity_row).unwrap().filter_map(Result::ok) {
            out.entry(i.user_id.clone()).or_default().push(i);
        }
        out
    }

    fn insert_identity(tx: &Connection, user_id: &str, i: &NewIdentity) -> rusqlite::Result<String> {
        let id = format!("i{}", crate::short_id());
        tx.execute(
            "INSERT INTO user_identities (id, user_id, provider, issuer, subject, tenant, email, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![id, user_id, i.provider, i.issuer, i.subject, i.tenant, i.email, now(), i.created_by],
        )?;
        // The first identity is also the user's own (users.idp_*).
        tx.execute(
            "UPDATE users SET idp_issuer = ?, idp_subject = ?, updated_at = ? WHERE id = ? AND idp_issuer IS NULL",
            params![i.issuer, i.subject, now(), user_id],
        )?;
        Ok(id)
    }

    fn identity_by_id(&self, id: &str) -> Option<Identity> {
        self.c().query_row("SELECT * FROM user_identities WHERE id = ?", [id], identity_row).optional().ok().flatten()
    }

    /// Err when the identity is linked already, to this user or another.
    pub fn link_identity(&self, user_id: &str, i: &NewIdentity) -> Result<Identity, String> {
        let id = {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
            let id = Self::insert_identity(&tx, user_id, i).map_err(|e| if constraint(&e) { "This identity is already linked to a user".to_string() } else { e.to_string() })?;
            tx.commit().map_err(|e| e.to_string())?;
            id
        };
        self.identity_by_id(&id).ok_or_else(|| "identity not saved".into())
    }

    /// Just-in-time sign-up: a new user and their first identity, together or not at all.
    pub fn create_sso_user(&self, email: Option<&str>, name: &str, role: Role, i: &NewIdentity) -> Result<User, JitError> {
        let id = format!("u{}", crate::short_id());
        let cap = self.seat_cap();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|_| JitError::Database)?;
            if !Self::seat_free(&tx, cap) {
                return Err(JitError::NoSeat);
            }
            let at = now();
            tx.execute(
                "INSERT INTO users (id, email, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                params![id, email, name, role.as_str(), at, at],
            )
            .map_err(|e| if constraint(&e) { JitError::EmailTaken } else { JitError::Database })?;
            Self::insert_identity(&tx, &id, i).map_err(|e| if constraint(&e) { JitError::IdentityTaken } else { JitError::Database })?;
            tx.commit().map_err(|_| JitError::Database)?;
        }
        self.user(&id).ok_or(JitError::Database)
    }

    /// Removes one of a user's identities. If it was the user's own, their next oldest takes its place.
    pub fn unlink_identity(&self, user_id: &str, id: &str) -> Option<Identity> {
        let gone = self.identity_by_id(id).filter(|i| i.user_id == user_id)?;
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        tx.execute("DELETE FROM user_identities WHERE id = ?", [id]).ok()?;
        tx.execute(
            "UPDATE users SET
               idp_issuer = (SELECT issuer FROM user_identities WHERE user_id = ?1 ORDER BY created_at, id LIMIT 1),
               idp_subject = (SELECT subject FROM user_identities WHERE user_id = ?1 ORDER BY created_at, id LIMIT 1),
               updated_at = ?4
             WHERE id = ?1 AND idp_issuer = ?2 AND idp_subject = ?3",
            params![user_id, gone.issuer, gone.subject, now()],
        )
        .ok()?;
        tx.commit().ok()?;
        Some(gone)
    }

    /// A sign-in with this identity: when, and the email the IdP sent this time.
    pub fn touch_identity(&self, id: &str, email: Option<&str>, at: i64) {
        let _ = self.c().execute("UPDATE user_identities SET last_login_at = ?, email = coalesce(?, email) WHERE id = ?", params![at, email, id]);
    }

    // Sessions and sign-in codes. Callers hash tokens; nothing here sees one.

    pub fn create_session(&self, s: &NewSession) -> Session {
        let id = format!("s{}", crate::random_hex(8));
        let at = now();
        {
            let c = self.c();
            c.execute(
                "INSERT INTO sessions (id, token_hash, user_id, kind, method, idp_subject, idp_provider, label, ip, user_agent, created_at, last_seen_at, expires_at, mfa)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, s.token_hash, s.user_id, s.kind, s.method, s.idp_subject, s.idp_provider, s.label, s.ip, s.user_agent, at, at, s.expires_at, s.mfa],
            )
            .unwrap();
            let _ = c.execute(
                "UPDATE users SET last_login_at = ?, last_login_method = ?, last_login_idp_provider = ? WHERE id = ?",
                params![at, s.method, s.idp_provider, s.user_id],
            );
        }
        self.session(&id).unwrap()
    }

    pub fn session(&self, id: &str) -> Option<Session> {
        self.c().query_row("SELECT * FROM sessions WHERE id = ?", [id], session_row).optional().ok().flatten()
    }

    /// The distinct IPs this user's kept sessions came from, newest first, at most `limit`.
    pub fn session_ips(&self, user_id: &str, limit: u32) -> Vec<String> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT ip FROM sessions WHERE user_id = ? AND ip IS NOT NULL GROUP BY ip ORDER BY max(created_at) DESC LIMIT ?")
            .unwrap();
        s.query_map(params![user_id, limit], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    /// The live session with this token hash and its active user. None when it is
    /// unknown, revoked, expired (absolute or idle), or the user is disabled.
    pub fn live_session(&self, token_hash: &str, at: i64, idle_ms: i64, max_ms: i64) -> Option<(Session, User)> {
        let c = self.c();
        let s = c
            .query_row(
                &format!("SELECT s.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?4 AND u.status = 'active' AND {SESSION_LIVE}"),
                params![at, idle_ms, max_ms, token_hash],
                session_row,
            )
            .optional()
            .ok()
            .flatten()?;
        let u = c.query_row("SELECT * FROM users WHERE id = ?", [&s.user_id], user_row).optional().ok().flatten()?;
        Some((s, u))
    }

    pub fn session_is_live(&self, id: &str, at: i64, idle_ms: i64, max_ms: i64) -> bool {
        self.c()
            .query_row(
                &format!("SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?4 AND u.status = 'active' AND {SESSION_LIVE}"),
                params![at, idle_ms, max_ms, id],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// Records use, at most once a minute per session to keep writes down. The idle
    /// window is therefore up to a minute shorter than configured. The user's own
    /// `last_seen_at` follows, for the health score's adoption (ADR 0144).
    pub fn touch_session(&self, id: &str, at: i64) {
        let c = self.c();
        if c.execute("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2 AND last_seen_at <= ?1 - 60000", params![at, id]).unwrap_or(0) > 0 {
            let _ = c.execute(
                "UPDATE users SET last_seen_at = ?1 WHERE id = (SELECT user_id FROM sessions WHERE id = ?2) AND coalesce(last_seen_at, 0) < ?1",
                params![at, id],
            );
        }
    }

    /// Every live session of one user, newest first, with no cap.
    pub fn user_live_sessions(&self, user_id: &str, at: i64, idle_ms: i64, max_ms: i64) -> Vec<Session> {
        let c = self.c();
        let sql = format!("SELECT s.* FROM sessions s WHERE s.user_id = ?4 AND {SESSION_LIVE} ORDER BY s.created_at DESC, s.id");
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(params![at, idle_ms, max_ms, user_id], session_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Live sessions, newest first, optionally for one user.
    pub fn live_sessions(&self, user_id: Option<&str>, at: i64, idle_ms: i64, max_ms: i64) -> Vec<Session> {
        let c = self.c();
        let sql = format!("SELECT s.* FROM sessions s WHERE (?4 IS NULL OR s.user_id = ?4) AND {SESSION_LIVE} ORDER BY s.created_at DESC, s.id LIMIT 1000");
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(params![at, idle_ms, max_ms, user_id], session_row).unwrap().filter_map(Result::ok).collect()
    }

    /// False if it was already revoked or doesn't exist.
    /// Its push device goes with it (ADR 0080), whatever ended it.
    pub fn revoke_session(&self, id: &str, by: &str, reason: &str) -> bool {
        let c = self.c();
        let _ = c.execute("DELETE FROM push_devices WHERE session_id = ?", [id]);
        c.execute("UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL", params![now(), by, reason, id])
            .unwrap_or(0)
            == 1
    }

    pub fn add_saml_session(&self, session_id: &str, l: &SamlLogin) {
        let _ = self.c().execute(
            "INSERT OR REPLACE INTO saml_sessions (session_id, name_id, name_id_format, name_qualifier, sp_name_qualifier, session_index) VALUES (?, ?, ?, ?, ?, ?)",
            params![session_id, l.name_id, l.format, l.name_qualifier, l.sp_name_qualifier, l.session_index],
        );
    }

    pub fn saml_session(&self, session_id: &str) -> Option<SamlLogin> {
        self.c()
            .query_row("SELECT name_id, name_id_format, name_qualifier, sp_name_qualifier, session_index FROM saml_sessions WHERE session_id = ?", [session_id], |r| {
                Ok(SamlLogin { name_id: r.get(0)?, format: r.get(1)?, name_qualifier: r.get(2)?, sp_name_qualifier: r.get(3)?, session_index: r.get(4)? })
            })
            .optional()
            .ok()
            .flatten()
    }

    /// Revokes the live sessions provider `provider` signed in as `idp_subject` (`issuer|subject`),
    /// for the IdP's LogoutRequest (ADR 0137). With `indexes`, only sessions of those IdP
    /// sessions, and those whose IdP session isn't known (signed in before botd kept it). Only
    /// sessions created by `before` (ms).
    pub fn revoke_saml_sessions(&self, provider: &str, idp_subject: &str, indexes: &[String], before: i64, reason: &str) -> Vec<Session> {
        let found: Vec<(Session, Option<String>)> = {
            let c = self.c();
            let mut s = c
                .prepare(
                    "SELECT s.*, m.session_index AS saml_session_index FROM sessions s LEFT JOIN saml_sessions m ON m.session_id = s.id
                     WHERE s.idp_provider = ? AND s.idp_subject = ? AND s.revoked_at IS NULL AND s.created_at <= ? ORDER BY s.created_at, s.id",
                )
                .unwrap();
            s.query_map(params![provider, idp_subject, before], |r| Ok((session_row(r)?, r.get("saml_session_index")?))).unwrap().filter_map(Result::ok).collect()
        };
        found
            .into_iter()
            .filter(|(_, index)| indexes.is_empty() || index.as_ref().is_none_or(|i| indexes.contains(i)))
            .filter_map(|(s, _)| self.revoke_session(&s.id, "sso", reason).then_some(s))
            .collect()
    }

    /// Revokes every session of a user and drops their unused sign-in codes and push
    /// devices. Returns how many sessions.
    pub fn revoke_user_sessions(&self, user_id: &str, by: &str, reason: &str) -> usize {
        let c = self.c();
        let _ = c.execute("DELETE FROM push_devices WHERE user_id = ?", [user_id]);
        let n = c
            .execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL",
                params![now(), by, reason, user_id],
            )
            .unwrap_or(0);
        let _ = c.execute("DELETE FROM login_codes WHERE user_id = ? AND used_at IS NULL", [user_id]);
        n
    }

    pub fn add_login_code(&self, code_hash: &str, user_id: &str, created_by: &str, expires_at: i64) {
        self.c()
            .execute(
                "INSERT INTO login_codes (code_hash, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                params![code_hash, user_id, created_by, now(), expires_at],
            )
            .unwrap();
    }

    /// Adds a sign-in code in place of the user's unused ones, in one transaction so two
    /// admins replacing at once leave one working code. Returns how many it replaced.
    pub fn replace_login_codes(&self, code_hash: &str, user_id: &str, created_by: &str, expires_at: i64) -> usize {
        let mut c = self.c();
        let tx = c.transaction().unwrap();
        let n = tx.execute("DELETE FROM login_codes WHERE user_id = ? AND used_at IS NULL", [user_id]).unwrap();
        tx.execute(
            "INSERT INTO login_codes (code_hash, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![code_hash, user_id, created_by, now(), expires_at],
        )
        .unwrap();
        tx.commit().unwrap();
        n
    }

    /// Unused, unexpired codes per user: how many, and when the last of them expires.
    pub fn pending_codes(&self, at: i64) -> HashMap<String, (i64, i64)> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT user_id, count(*), max(expires_at) FROM login_codes WHERE used_at IS NULL AND ? < expires_at GROUP BY user_id")
            .unwrap();
        s.query_map([at], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?)))).unwrap().filter_map(Result::ok).collect()
    }

    // Sign-ups (ADR 0022)

    /// Saves a request for access, unless `max_pending` are pending already (one
    /// statement, so concurrent requests can't pass the cap together).
    pub fn add_signup(&self, s: &NewSignup, max_pending: i64) -> Result<Signup, AddSignup> {
        let id = format!("su{}", crate::short_id());
        let at = now();
        let res = self.c().execute(
            "INSERT INTO signups (id, name, email, company, team_size, use_case, sign_in, consent_at, ip, user_agent, created_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?8
             WHERE (SELECT count(*) FROM signups WHERE status = 'pending') < ?11",
            params![id, s.name, s.email, s.company, s.team_size, s.use_case, s.sign_in, at, s.ip, s.user_agent, max_pending],
        );
        match res {
            Ok(0) => Err(AddSignup::Full),
            Ok(_) => self.signup(&id).ok_or(AddSignup::Full),
            Err(e) if constraint(&e) => Err(AddSignup::Duplicate),
            Err(e) => panic!("save signup: {e}"),
        }
    }

    pub fn signup(&self, id: &str) -> Option<Signup> {
        self.c().query_row("SELECT * FROM signups WHERE id = ?", [id], signup_row).optional().ok().flatten()
    }

    /// Newest first. `status` None: all of them.
    pub fn signups(&self, status: Option<&str>, limit: u32) -> Vec<Signup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM signups WHERE ?1 IS NULL OR status = ?1 ORDER BY created_at DESC, id LIMIT ?2").unwrap();
        s.query_map(params![status, limit], signup_row).unwrap().filter_map(Result::ok).collect()
    }

    #[cfg(test)]
    pub fn pending_signups(&self) -> i64 {
        self.c().query_row("SELECT count(*) FROM signups WHERE status = 'pending'", [], |r| r.get(0)).unwrap_or(0)
    }

    /// Approves a pending request: its user is made in the same transaction, so a
    /// request is never approved without one, nor a user made for a closed request.
    pub fn approve_signup(&self, id: &str, role: Role, by: &str) -> Result<(Signup, User), SignupError> {
        let cap = self.seat_cap();
        let user_id = {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(|e| SignupError::Db(e.to_string()))?;
            let s = tx.query_row("SELECT * FROM signups WHERE id = ?", [id], signup_row).optional().map_err(|e| SignupError::Db(e.to_string()))?;
            let s = s.ok_or(SignupError::NotFound)?;
            if s.status != "pending" {
                return Err(SignupError::Closed(s.status));
            }
            if !Self::seat_free(&tx, cap) {
                return Err(SignupError::NoSeat);
            }
            let user_id = format!("u{}", crate::short_id());
            Self::insert_user(&tx, &user_id, Some(&s.email), &s.name, role).map_err(|e| if constraint(&e) { SignupError::EmailTaken } else { SignupError::Db(e.to_string()) })?;
            tx.execute(
                "UPDATE signups SET status = 'approved', decided_at = ?, decided_by = ?, user_id = ?, role = ? WHERE id = ? AND status = 'pending'",
                params![now(), by, user_id, role.as_str(), id],
            )
            .map_err(|e| SignupError::Db(e.to_string()))?;
            tx.commit().map_err(|e| SignupError::Db(e.to_string()))?;
            user_id
        };
        Ok((self.signup(id).ok_or(SignupError::NotFound)?, self.user(&user_id).ok_or(SignupError::NotFound)?))
    }

    pub fn reject_signup(&self, id: &str, by: &str, reason: Option<&str>) -> Result<Signup, SignupError> {
        let s = self.signup(id).ok_or(SignupError::NotFound)?;
        let n = self
            .c()
            .execute(
                "UPDATE signups SET status = 'rejected', decided_at = ?, decided_by = ?, reason = ? WHERE id = ? AND status = 'pending'",
                params![now(), by, reason, id],
            )
            .map_err(|e| SignupError::Db(e.to_string()))?;
        if n != 1 {
            return Err(SignupError::Closed(s.status));
        }
        self.signup(id).ok_or(SignupError::NotFound)
    }

    // SCIM (ADR 0023). Callers hash tokens; nothing here sees one.

    /// A tenant's first token sets its SSO provider for good: a token naming another gets
    /// `Err` with the tenant's provider. Checked and written in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn create_scim_token(
        &self,
        tenant: &str,
        label: Option<&str>,
        sso_provider: Option<&str>,
        token_hash: &str,
        by: Option<&str>,
        expires_at: i64,
        scopes: crate::scim::scopes::Scopes,
    ) -> Result<ScimToken, Option<String>> {
        let id = format!("st{}", crate::random_hex(4));
        let c = self.c();
        let tx = c.unchecked_transaction().unwrap();
        let first: Option<Option<String>> =
            tx.query_row("SELECT sso_provider FROM scim_tokens WHERE tenant = ? ORDER BY created_at, id LIMIT 1", [tenant], |r| r.get(0)).optional().unwrap();
        if let Some(first) = first
            && first.as_deref() != sso_provider
        {
            return Err(first);
        }
        tx.execute(
            "INSERT INTO scim_tokens (id, tenant, label, sso_provider, token_hash, created_at, created_by, expires_at, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![id, tenant, label, sso_provider, token_hash, now(), by, expires_at, scopes.to_stored()],
        )
        .unwrap();
        let t = tx.query_row("SELECT * FROM scim_tokens WHERE id = ?", [&id], scim_token_row).unwrap();
        tx.commit().unwrap();
        Ok(t)
    }

    pub fn scim_token(&self, id: &str) -> Option<ScimToken> {
        self.c().query_row("SELECT * FROM scim_tokens WHERE id = ?", [id], scim_token_row).optional().ok().flatten()
    }

    /// Newest first, revoked ones too.
    pub fn scim_tokens(&self) -> Vec<ScimToken> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_tokens ORDER BY created_at DESC, id").unwrap();
        s.query_map([], scim_token_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The unrevoked, unexpired token with this hash. Records use, at most once a minute.
    pub fn live_scim_token(&self, token_hash: &str, at: i64) -> Option<ScimToken> {
        let t = self
            .c()
            .query_row(
                "SELECT * FROM scim_tokens WHERE token_hash = ?1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?2)",
                params![token_hash, at],
                scim_token_row,
            )
            .optional()
            .ok()
            .flatten()?;
        let _ = self.c().execute("UPDATE scim_tokens SET last_used_at = ?1 WHERE id = ?2 AND coalesce(last_used_at, 0) <= ?1 - 60000", params![at, t.id]);
        Some(t)
    }

    /// The token with this hash, revoked or not: a revoked token still in use is worth an alert.
    pub fn scim_token_by_hash(&self, token_hash: &str) -> Option<ScimToken> {
        self.c().query_row("SELECT * FROM scim_tokens WHERE token_hash = ?", [token_hash], scim_token_row).optional().ok().flatten()
    }

    /// Replaces a live, unrotated token with a new one of the same tenant, label and SSO
    /// link, with `scopes`, in one transaction (ADR 0196). The old one is revoked now, or
    /// with `keep_until`, expires then unless it would sooner. None if the old one was
    /// revoked, expired or rotated meanwhile.
    pub fn rotate_scim_token(&self, old: &str, token_hash: &str, expires_at: i64, keep_until: Option<i64>, by: Option<&str>, scopes: crate::scim::scopes::Scopes) -> Option<ScimToken> {
        let id = format!("st{}", crate::random_hex(4));
        let at = now();
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let changed = match keep_until {
            Some(until) => tx.execute(
                "UPDATE scim_tokens SET expires_at = CASE WHEN expires_at IS NULL OR expires_at > ?1 THEN ?1 ELSE expires_at END, rotated_to = ?2
                 WHERE id = ?3 AND revoked_at IS NULL AND rotated_to IS NULL AND (expires_at IS NULL OR expires_at > ?4)",
                params![until, id, old, at],
            ),
            None => tx.execute(
                "UPDATE scim_tokens SET revoked_at = ?1, revoked_by = ?2, rotated_to = ?3
                 WHERE id = ?4 AND revoked_at IS NULL AND rotated_to IS NULL AND (expires_at IS NULL OR expires_at > ?1)",
                params![at, by, id, old],
            ),
        }
        .ok()?;
        if changed == 0 {
            return None;
        }
        tx.execute(
            "INSERT INTO scim_tokens (id, tenant, label, sso_provider, token_hash, created_at, created_by, expires_at, scopes)
             SELECT ?1, tenant, label, sso_provider, ?2, ?3, ?4, ?5, ?7 FROM scim_tokens WHERE id = ?6",
            params![id, token_hash, at, by, expires_at, old, scopes.to_stored()],
        )
        .ok()?;
        let t = tx.query_row("SELECT * FROM scim_tokens WHERE id = ?", [&id], scim_token_row).ok()?;
        tx.commit().ok()?;
        Some(t)
    }

    /// Unrevoked, unrotated tokens owed an expiry notice at `at`: `expiring` once within
    /// `warn_ms` of their end, then `expired` once they've ended.
    pub fn scim_tokens_due_notice(&self, at: i64, warn_ms: i64) -> Vec<(ScimToken, &'static str)> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT * FROM scim_tokens WHERE revoked_at IS NULL AND rotated_to IS NULL AND expires_at IS NOT NULL
                 AND ((expires_at <= ?1 AND coalesce(expiry_notice, '') <> 'expired') OR (expires_at > ?1 AND expires_at <= ?1 + ?2 AND expiry_notice IS NULL))
                 ORDER BY expires_at, id",
            )
            .unwrap();
        s.query_map(params![at, warn_ms], scim_token_row)
            .unwrap()
            .filter_map(Result::ok)
            .map(|t| {
                let notice = if t.expires_at.is_some_and(|e| e <= at) { "expired" } else { "expiring" };
                (t, notice)
            })
            .collect()
    }

    #[cfg(test)]
    pub fn conn_for_tests(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.c()
    }

    #[cfg(test)]
    pub fn set_scim_token_notice(&self, id: &str, notice: Option<&str>) {
        self.c().execute("UPDATE scim_tokens SET expiry_notice = ?1 WHERE id = ?2", params![notice, id]).unwrap();
    }

    #[cfg(test)]
    pub fn set_scim_token_scopes(&self, id: &str, scopes: Option<&str>) {
        self.c().execute("UPDATE scim_tokens SET scopes = ?1 WHERE id = ?2", params![scopes, id]).unwrap();
    }

    #[cfg(test)]
    pub fn set_scim_token_expiry(&self, id: &str, expires_at: Option<i64>) {
        self.c().execute("UPDATE scim_tokens SET expires_at = ?1 WHERE id = ?2", params![expires_at, id]).unwrap();
    }

    /// False if it was already revoked or doesn't exist.
    pub fn revoke_scim_token(&self, id: &str, by: &str) -> bool {
        self.c().execute("UPDATE scim_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL", params![now(), by, id]).unwrap_or(0) == 1
    }

    /// Which tenant manages a user, if any, deleted or not.
    pub fn scim_user_of(&self, user_id: &str) -> Option<ScimUser> {
        self.c().query_row(&format!("{SCIM_USER_SELECT} WHERE l.user_id = ?"), [user_id], scim_user_row).optional().ok().flatten()
    }

    /// A user the tenant manages and hasn't deleted.
    pub fn scim_user(&self, tenant: &str, user_id: &str) -> Option<ScimUser> {
        self.c()
            .query_row(&format!("{SCIM_USER_SELECT} WHERE l.tenant = ? AND l.user_id = ? AND l.deleted_at IS NULL"), [tenant, user_id], scim_user_row)
            .optional()
            .ok()
            .flatten()
    }

    /// By `externalId`, deleted users included (re-provisioning finds them); by `userName`, live ones only.
    pub fn scim_find(&self, tenant: &str, key: &ScimKey) -> Option<ScimUser> {
        let (clause, v) = match key {
            ScimKey::ExternalId(v) => ("l.external_id = ?2", v),
            ScimKey::UserName(v) => ("l.user_name = ?2 AND l.deleted_at IS NULL", v),
        };
        self.c().query_row(&format!("{SCIM_USER_SELECT} WHERE l.tenant = ?1 AND {clause}"), params![tenant, v], scim_user_row).optional().ok().flatten()
    }

    /// A page of the tenant's live users, oldest first, and how many match in all.
    pub fn scim_list(&self, tenant: &str, key: Option<&ScimKey>, offset: i64, limit: i64) -> (i64, Vec<ScimUser>) {
        let (col, v) = match key {
            None => ("l.user_name", None),
            Some(ScimKey::UserName(v)) => ("l.user_name", Some(v)),
            Some(ScimKey::ExternalId(v)) => ("l.external_id", Some(v)),
        };
        let c = self.c();
        let filter = format!("WHERE l.tenant = ?1 AND l.deleted_at IS NULL AND (?2 IS NULL OR {col} = ?2)");
        let total: i64 = c.query_row(&format!("SELECT count(*) FROM scim_users l {filter}"), params![tenant, v], |r| r.get(0)).unwrap_or(0);
        let mut s = c.prepare(&format!("{SCIM_USER_SELECT} {filter} ORDER BY l.created_at, l.user_id LIMIT ?3 OFFSET ?4")).unwrap();
        let list = s.query_map(params![tenant, v, limit, offset], scim_user_row).unwrap().filter_map(Result::ok).collect();
        (total, list)
    }

    /// Turning a disabled user back on takes a seat under `cap`, checked here, in the write's transaction.
    fn write_scim_user(tx: &Connection, tenant: &str, user_id: &str, f: &ScimFields, at: i64, cap: Option<u32>) -> Result<(), ScimConflict> {
        if f.active == Some(true) && Self::enabling(tx, user_id) && !Self::seat_free(tx, cap) {
            return Err(ScimConflict::NoSeat);
        }
        Self::write_scim_rows(tx, tenant, user_id, f, at).map_err(scim_conflict)
    }

    fn write_scim_rows(tx: &Connection, tenant: &str, user_id: &str, f: &ScimFields, at: i64) -> rusqlite::Result<()> {
        tx.execute(
            "UPDATE users SET email = ?, display_name = ?, status = coalesce(?, status), updated_at = ? WHERE id = ?",
            params![f.email, f.display_name, f.active.map(|on| if on { "active" } else { "disabled" }), at, user_id],
        )?;
        tx.execute(
            "INSERT INTO scim_users (user_id, tenant, external_id, user_name, given_name, family_name, display_name, formatted, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT (user_id) DO UPDATE SET external_id = ?3, user_name = ?4, given_name = ?5, family_name = ?6, display_name = ?7, formatted = ?8,
               updated_at = ?9, deleted_at = NULL",
            params![user_id, tenant, f.external_id, f.user_name, f.given_name, f.family_name, f.scim_display_name, f.formatted, at],
        )?;
        let e = f.enterprise;
        // A manager must be someone else this tenant has, checked in the write's transaction.
        tx.execute(
            "UPDATE scim_users SET employee_number = ?2, cost_center = ?3, organization = ?4, division = ?5, department = ?6,
               manager_id = (SELECT m.user_id FROM scim_users m WHERE m.user_id = ?7 AND m.tenant = ?8 AND m.deleted_at IS NULL AND m.user_id <> ?1)
             WHERE user_id = ?1",
            params![user_id, e.employee_number, e.cost_center, e.organization, e.division, e.department, e.manager, tenant],
        )?;
        Ok(())
    }

    /// A new user made by a SCIM tenant, with its SSO identity when the tenant links one.
    /// All of it or none.
    pub fn create_scim_user(&self, tenant: &str, f: &ScimFields, role: Role, identity: Option<&NewIdentity>) -> Result<User, ScimConflict> {
        let id = format!("u{}", crate::short_id());
        let cap = self.seat_cap();
        {
            let c = self.c();
            let tx = c.unchecked_transaction().map_err(scim_conflict)?;
            // A user provisioned inactive takes no seat until they're turned on.
            if f.active != Some(false) && !Self::seat_free(&tx, cap) {
                return Err(ScimConflict::NoSeat);
            }
            Self::insert_user(&tx, &id, f.email, f.display_name, role).map_err(scim_conflict)?;
            Self::write_scim_user(&tx, tenant, &id, f, now(), None)?;
            if let Some(i) = identity {
                Self::insert_identity(&tx, &id, i).map_err(scim_conflict)?;
            }
            tx.commit().map_err(scim_conflict)?;
        }
        self.user(&id).ok_or_else(|| ScimConflict::Db("user not saved".into()))
    }

    /// Sets what SCIM manages on an existing user. An update (`restore` false) needs the
    /// tenant's live user; `restore` also takes a user the tenant deleted, or one no tenant
    /// manages. Never another tenant's: checked in the same transaction as the write.
    pub fn save_scim_user(&self, tenant: &str, user_id: &str, f: &ScimFields, restore: bool) -> Result<(), ScimConflict> {
        let cap = self.seat_cap();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_conflict)?;
        let row: Option<(String, Option<i64>)> =
            tx.query_row("SELECT tenant, deleted_at FROM scim_users WHERE user_id = ?", [user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(scim_conflict)?;
        match row {
            Some((t, _)) if t != tenant => return Err(ScimConflict::OtherTenant),
            Some((_, None)) => {}
            _ if !restore => return Err(ScimConflict::Gone),
            _ => {}
        }
        Self::write_scim_user(&tx, tenant, user_id, f, now(), cap)?;
        tx.commit().map_err(scim_conflict)
    }

    /// A SCIM DELETE: the user is disabled and hidden from the tenant, never removed.
    pub fn delete_scim_user(&self, tenant: &str, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let n = tx.execute("UPDATE scim_users SET deleted_at = ?, updated_at = ? WHERE tenant = ? AND user_id = ? AND deleted_at IS NULL", params![at, at, tenant, user_id]).unwrap_or(0);
        let ok = n == 1 && tx.execute("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?", params![at, user_id]).is_ok();
        ok && tx.commit().is_ok()
    }

    // SCIM groups as teams (ADR 0095). Every query a SCIM request makes names its tenant.

    /// A tenant's groups, oldest first.
    pub fn scim_groups(&self, tenant: &str) -> Vec<ScimGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_groups WHERE tenant = ? ORDER BY created_at, team_id").unwrap();
        s.query_map([tenant], scim_group_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every tenant's groups, for admins.
    pub fn all_scim_groups(&self) -> Vec<ScimGroup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM scim_groups ORDER BY tenant, created_at, team_id").unwrap();
        s.query_map([], scim_group_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn scim_group(&self, tenant: &str, team_id: &str) -> Option<ScimGroup> {
        self.c().query_row("SELECT * FROM scim_groups WHERE tenant = ? AND team_id = ?", [tenant, team_id], scim_group_row).optional().ok().flatten()
    }

    /// The group a team is, whichever tenant's.
    pub fn scim_group_of_team(&self, team_id: &str) -> Option<ScimGroup> {
        self.c().query_row("SELECT * FROM scim_groups WHERE team_id = ?", [team_id], scim_group_row).optional().ok().flatten()
    }

    /// By `externalId` (exactly) or `displayName` (any case).
    pub fn scim_group_find(&self, tenant: &str, external_id: Option<&str>, display_name: Option<&str>) -> Option<ScimGroup> {
        let (col, v) = match (external_id, display_name) {
            (Some(x), _) => ("external_id", x),
            (None, Some(n)) => ("display_name", n),
            (None, None) => return None,
        };
        self.c().query_row(&format!("SELECT * FROM scim_groups WHERE tenant = ? AND {col} = ?"), [tenant, v], scim_group_row).optional().ok().flatten()
    }

    /// A new team for a group a SCIM tenant created, linked to it: both or neither. A
    /// team SCIM makes gives no machines until an admin turns that on.
    pub fn create_scim_group(&self, tenant: &str, external_id: Option<&str>, display_name: &str, team_name: &str, by: Option<&str>) -> Result<ScimGroup, ScimGroupConflict> {
        let id = format!("t{}", crate::random_hex(5));
        let at = now();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_group_conflict)?;
        tx.execute("INSERT INTO teams (id, name, machines, created_at, created_by, updated_at) VALUES (?1, ?2, 0, ?3, ?4, ?3)", params![id, team_name, at, by])
            .map_err(scim_group_conflict)?;
        tx.execute(
            "INSERT INTO scim_groups (team_id, tenant, external_id, display_name, origin, provisioned_at, created_at, created_by, updated_at) VALUES (?1, ?2, ?3, ?4, 'scim', ?5, ?5, ?6, ?5)",
            params![id, tenant, external_id, display_name, at, by],
        )
        .map_err(scim_group_conflict)?;
        let g = tx.query_row("SELECT * FROM scim_groups WHERE team_id = ?", [&id], scim_group_row).map_err(scim_group_conflict)?;
        tx.commit().map_err(scim_group_conflict)?;
        Ok(g)
    }

    /// An admin links a team that exists to a tenant's group, for the IdP to take on.
    pub fn link_scim_group(&self, tenant: &str, team_id: &str, external_id: Option<&str>, display_name: &str, by: Option<&str>) -> Result<ScimGroup, ScimGroupConflict> {
        let at = now();
        let c = self.c();
        c.execute(
            "INSERT INTO scim_groups (team_id, tenant, external_id, display_name, origin, created_at, created_by, updated_at) VALUES (?1, ?2, ?3, ?4, 'admin', ?5, ?6, ?5)",
            params![team_id, tenant, external_id, display_name, at, by],
        )
        .map_err(scim_group_conflict)?;
        c.query_row("SELECT * FROM scim_groups WHERE team_id = ?", [team_id], scim_group_row).map_err(scim_group_conflict)
    }

    /// Sets a group's `displayName` and `externalId` and renames its team, while the
    /// tenant still has it. `provision` marks an admin's link as taken on by the IdP.
    pub fn save_scim_group(&self, tenant: &str, team_id: &str, external_id: Option<&str>, display_name: &str, team_name: &str, provision: bool) -> Result<ScimGroup, ScimGroupConflict> {
        let at = now();
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(scim_group_conflict)?;
        let n = tx
            .execute(
                "UPDATE scim_groups SET external_id = ?1, display_name = ?2, updated_at = ?3, provisioned_at = CASE WHEN ?4 THEN coalesce(provisioned_at, ?3) ELSE provisioned_at END
                 WHERE tenant = ?5 AND team_id = ?6",
                params![external_id, display_name, at, provision, tenant, team_id],
            )
            .map_err(scim_group_conflict)?;
        if n != 1 {
            return Err(ScimGroupConflict::Gone);
        }
        tx.execute("UPDATE teams SET name = ?1, updated_at = ?2 WHERE id = ?3 AND name != ?1", params![team_name, at, team_id]).map_err(scim_group_conflict)?;
        let g = tx.query_row("SELECT * FROM scim_groups WHERE team_id = ?", [team_id], scim_group_row).map_err(scim_group_conflict)?;
        tx.commit().map_err(scim_group_conflict)?;
        Ok(g)
    }

    /// A `POST` that made or took on the group stopped partway: it waits to be taken on
    /// again, so the IdP's retry of that `POST` finishes it.
    pub fn reopen_scim_group(&self, tenant: &str, team_id: &str) {
        let _ = self.c().execute("UPDATE scim_groups SET provisioned_at = NULL, updated_at = ?1 WHERE tenant = ?2 AND team_id = ?3", params![now(), tenant, team_id]);
    }

    /// Ends a team's link to its group, and returns what it was. The team stays.
    pub fn unlink_scim_group(&self, team_id: &str) -> Option<ScimGroup> {
        self.c().query_row("DELETE FROM scim_groups WHERE team_id = ? RETURNING *", [team_id], scim_group_row).optional().ok().flatten()
    }

    /// The team's members `tenant` provisioned and hasn't deleted, oldest member first.
    /// With `deleted`, the ones it deleted too: its group still owns their place there.
    pub fn scim_group_members(&self, tenant: &str, team_id: &str, deleted: bool) -> Vec<User> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT u.* FROM team_members m JOIN scim_users l ON l.user_id = m.user_id JOIN users u ON u.id = m.user_id
                 WHERE m.team_id = ?1 AND l.tenant = ?2 AND (?3 OR l.deleted_at IS NULL) ORDER BY m.joined_at, m.user_id",
            )
            .unwrap();
        s.query_map(params![team_id, tenant, deleted], user_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Spends a sign-in code: once, before it expires, for an active user. Returns the user.
    pub fn use_login_code(&self, code_hash: &str, at: i64) -> Option<User> {
        let c = self.c();
        let user_id: String = c
            .query_row(
                "UPDATE login_codes SET used_at = ?1 WHERE code_hash = ?2 AND used_at IS NULL AND ?1 < expires_at
                   AND user_id IN (SELECT id FROM users WHERE status = 'active')
                 RETURNING user_id",
                params![at, code_hash],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        c.query_row("SELECT * FROM users WHERE id = ?", [user_id], user_row).optional().ok().flatten()
    }

    // Second factor (ADR 0094). Secrets are sealed under the user's id; recovery codes
    // are kept as keyed hashes only.

    pub fn mfa(&self, user_id: &str) -> Option<MfaRow> {
        self.c()
            .query_row("SELECT secret, confirmed_at, last_step FROM user_mfa WHERE user_id = ?", [user_id], |r| {
                Ok(MfaRow { secret: r.get(0)?, confirmed_at: r.get(1)?, last_step: r.get(2)? })
            })
            .optional()
            .ok()
            .flatten()
    }

    /// Users with a confirmed second factor, and since when.
    pub fn mfa_enabled(&self) -> HashMap<String, i64> {
        let c = self.c();
        let mut s = c.prepare("SELECT user_id, confirmed_at FROM user_mfa WHERE confirmed_at IS NOT NULL").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    /// Starts (or restarts) enrolment with a new sealed secret. False when the user
    /// already has a confirmed one: that must be turned off first.
    pub fn mfa_begin(&self, user_id: &str, sealed: &str) -> bool {
        let at = now();
        self.c()
            .execute(
                "INSERT INTO user_mfa (user_id, secret, confirmed_at, last_step, created_at, updated_at) VALUES (?1, ?2, NULL, 0, ?3, ?3)
                 ON CONFLICT(user_id) DO UPDATE SET secret = ?2, last_step = 0, created_at = ?3, updated_at = ?3 WHERE confirmed_at IS NULL",
                params![user_id, sealed, at],
            )
            .unwrap_or(0)
            == 1
    }

    /// Confirms the pending secret `sealed` with the step its first code was for, and
    /// sets its recovery codes. False when there is no such pending secret (it was
    /// replaced, removed, or already confirmed).
    pub fn mfa_confirm(&self, user_id: &str, sealed: &str, step: i64, recovery: &[String]) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let n = tx
            .execute(
                "UPDATE user_mfa SET confirmed_at = ?1, last_step = ?2, updated_at = ?1 WHERE user_id = ?3 AND secret = ?4 AND confirmed_at IS NULL",
                params![at, step, user_id, sealed],
            )
            .unwrap_or(0);
        n == 1 && Self::write_recovery(&tx, user_id, recovery, at).is_ok() && tx.commit().is_ok()
    }

    /// Enrols in one go, from a sign-in that had to enrol. False when the user already
    /// has a confirmed second factor.
    pub fn mfa_enable(&self, user_id: &str, sealed: &str, step: i64, recovery: &[String]) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let at = now();
        let n = tx
            .execute(
                "INSERT INTO user_mfa (user_id, secret, confirmed_at, last_step, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?3, ?3)
                 ON CONFLICT(user_id) DO UPDATE SET secret = ?2, confirmed_at = ?3, last_step = ?4, created_at = ?3, updated_at = ?3 WHERE confirmed_at IS NULL",
                params![user_id, sealed, at, step],
            )
            .unwrap_or(0);
        n == 1 && Self::write_recovery(&tx, user_id, recovery, at).is_ok() && tx.commit().is_ok()
    }

    fn write_recovery(tx: &rusqlite::Transaction, user_id: &str, recovery: &[String], at: i64) -> rusqlite::Result<()> {
        tx.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", [user_id])?;
        for h in recovery {
            tx.execute("INSERT INTO mfa_recovery_codes (user_id, code_hash, used_at, created_at) VALUES (?, ?, NULL, ?)", params![user_id, h, at])?;
        }
        Ok(())
    }

    /// Replaces a confirmed user's recovery codes. False when they have no second factor.
    pub fn mfa_replace_recovery(&self, user_id: &str, recovery: &[String]) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let on: bool = tx.query_row("SELECT COUNT(*) FROM user_mfa WHERE user_id = ? AND confirmed_at IS NOT NULL", [user_id], |r| r.get(0)).unwrap_or(false);
        on && Self::write_recovery(&tx, user_id, recovery, now()).is_ok() && tx.commit().is_ok()
    }

    /// Spends a TOTP step: only a step later than the last one used, so a code works once.
    pub fn mfa_use_step(&self, user_id: &str, step: i64) -> bool {
        self.c()
            .execute(
                "UPDATE user_mfa SET last_step = ?1, updated_at = ?2 WHERE user_id = ?3 AND confirmed_at IS NOT NULL AND last_step < ?1",
                params![step, now(), user_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Spends a recovery code, once, for a user whose second factor is on.
    pub fn mfa_use_recovery(&self, user_id: &str, code_hash: &str) -> bool {
        self.c()
            .execute(
                "UPDATE mfa_recovery_codes SET used_at = ?1 WHERE user_id = ?2 AND code_hash = ?3 AND used_at IS NULL
                   AND user_id IN (SELECT user_id FROM user_mfa WHERE confirmed_at IS NOT NULL)",
                params![now(), user_id, code_hash],
            )
            .unwrap_or(0)
            == 1
    }

    pub fn mfa_recovery_left(&self, user_id: &str) -> i64 {
        self.c().query_row("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL", [user_id], |r| r.get(0)).unwrap_or(0)
    }

    /// Removes the user's second factor and recovery codes. True if they had a confirmed one.
    pub fn mfa_delete(&self, user_id: &str) -> bool {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else { return false };
        let confirmed = tx.execute("DELETE FROM user_mfa WHERE user_id = ? AND confirmed_at IS NOT NULL", [user_id]).unwrap_or(0) == 1;
        let _ = tx.execute("DELETE FROM user_mfa WHERE user_id = ?", [user_id]);
        let _ = tx.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", [user_id]);
        tx.commit().is_ok() && confirmed
    }

    // Push devices (ADR 0080). Tokens are sealed; the hash keeps each on one session.

    /// Registers `token` for this session, in place of any it had. A token another
    /// session held moves here, so that session (and its person) stops getting it.
    #[allow(clippy::too_many_arguments)]
    pub fn put_push_device(&self, user_id: &str, session_id: &str, provider: &str, token: &str, platform: &str, approvals: bool, routines: bool) -> (PushDevice, PushPut) {
        let token_hash = crate::users::hash(token);
        let at = now();
        let mut c = self.c();
        let tx = c.transaction().unwrap();
        let mine = tx.query_row("SELECT * FROM push_devices WHERE session_id = ?", [session_id], push_device_row).optional().unwrap().flatten();
        let theirs: Option<String> =
            tx.query_row("SELECT session_id FROM push_devices WHERE token_hash = ? AND session_id <> ?", params![token_hash, session_id], |r| r.get(0)).optional().unwrap();
        let change = match &mine {
            Some(d) if d.token == token && d.provider == provider && d.platform == platform => {
                if (d.approvals, d.routines) == (approvals, routines) { PushPut::Unchanged } else { PushPut::Updated }
            }
            _ if theirs.is_some() => PushPut::Moved,
            _ => PushPut::Added,
        };
        tx.execute("DELETE FROM push_devices WHERE token_hash = ? AND session_id <> ?", params![token_hash, session_id]).unwrap();
        // Read raw, so a row whose token no longer opens still keeps its id (ON CONFLICT does).
        let stored: Option<(String, i64)> =
            tx.query_row("SELECT id, created_at FROM push_devices WHERE session_id = ?", [session_id], |r| Ok((r.get(0)?, r.get(1)?))).optional().unwrap();
        let (id, created) = stored.unwrap_or_else(|| (format!("pd{}", crate::random_hex(8)), at));
        tx.execute(
            "INSERT INTO push_devices (id, user_id, session_id, provider, token_hash, token, platform, approvals, routines, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session_id) DO UPDATE SET provider = ?4, token_hash = ?5, token = ?6, platform = ?7, approvals = ?8, routines = ?9, updated_at = ?11",
            params![id, user_id, session_id, provider, token_hash, sealed::seal_field(PUSH_TOKEN_CONTEXT, token), platform, approvals, routines, created, at],
        )
        .unwrap();
        tx.execute(
            "DELETE FROM push_devices WHERE user_id = ?1 AND id NOT IN (SELECT id FROM push_devices WHERE user_id = ?1 ORDER BY updated_at DESC, id LIMIT ?2)",
            params![user_id, MAX_PUSH_DEVICES as i64],
        )
        .unwrap();
        let d = tx.query_row("SELECT * FROM push_devices WHERE id = ?", [&id], push_device_row).unwrap().expect("just sealed");
        tx.commit().unwrap();
        (d, change)
    }

    pub fn session_push_device(&self, session_id: &str) -> Option<PushDevice> {
        self.c().query_row("SELECT * FROM push_devices WHERE session_id = ?", [session_id], push_device_row).optional().ok().flatten().flatten()
    }

    /// The device this session registered, removed. None: it had none.
    pub fn delete_session_push_device(&self, session_id: &str) -> Option<PushDevice> {
        let d = self.session_push_device(session_id)?;
        (self.c().execute("DELETE FROM push_devices WHERE id = ?", [&d.id]).unwrap_or(0) == 1).then_some(d)
    }

    /// Removes a device the provider says is gone, if it still has the token it said
    /// that about. Returns whether it did.
    pub fn delete_push_device_with(&self, id: &str, token_hash: &str) -> bool {
        self.c().execute("DELETE FROM push_devices WHERE id = ? AND token_hash = ?", params![id, token_hash]).unwrap_or(0) == 1
    }

    /// `user_id`'s devices that want `kind`, while the session that registered each is
    /// still live and theirs, and they are active. Binds the session lifetimes as
    /// `live_session` does, so an idle or expired session's phone gets nothing.
    pub fn live_push_devices(&self, user_id: &str, kind: PushKind, at: i64, idle_ms: i64, max_ms: i64) -> Vec<PushDevice> {
        let want = match kind {
            PushKind::Approvals => "d.approvals = 1",
            PushKind::Routines => "d.routines = 1",
        };
        let sql = format!(
            "SELECT d.* FROM push_devices d JOIN sessions s ON s.id = d.session_id JOIN users u ON u.id = d.user_id
             WHERE d.user_id = ?4 AND s.user_id = d.user_id AND u.status = 'active' AND {want} AND {SESSION_LIVE} ORDER BY d.created_at, d.id"
        );
        let c = self.c();
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(params![at, idle_ms, max_ms, user_id], push_device_row).unwrap().filter_map(|r| r.ok().flatten()).collect()
    }

    /// Deletes sessions and codes that stopped working before `before` (unix ms).
    pub fn prune_sessions(&self, before: i64, idle_ms: i64, max_ms: i64) -> usize {
        let c = self.c();
        let n = c
            .execute(
                "DELETE FROM sessions WHERE coalesce(revoked_at, min(expires_at, created_at + ?2, last_seen_at + ?3)) < ?1",
                params![before, max_ms, idle_ms],
            )
            .unwrap_or(0);
        let _ = c.execute("DELETE FROM login_codes WHERE coalesce(used_at, expires_at) < ?", [before]);
        n
    }

    // Audit: append-only. There is no update or delete here; triggers refuse both,
    // except retention pruning of rows older than `audit_retention_days`.

    /// Writes one event. `details` is scrubbed of secrets; free text (names, the user
    /// agent) is masked the same way; everything is clipped.
    pub fn record(&self, e: &audit::Event) {
        if let Err(err) = self.try_record(e) {
            crate::obs::log::log_warn!("audit: could not record {}: {err}", e.action);
        }
    }

    /// [`Db::record`] for when saving the event is the operation itself: returns the
    /// new event's id, or the error.
    pub fn try_record(&self, e: &audit::Event) -> rusqlite::Result<i64> {
        self.record_at(e, now())
    }

    /// [`Db::try_record`] as of `at` (unix ms), for tests of what happens to old events.
    pub(crate) fn record_at(&self, e: &audit::Event, at: i64) -> rusqlite::Result<i64> {
        self.record_sealed(e, at, |_, _, _| Ok(None))
    }

    /// Records `e` with details `details` makes inside the audit log's write lock, from the
    /// new event's id and the head it seals onto, in the same transaction as anything
    /// it writes: a checkpoint signs that head (ADR 0149). Its details are stored as
    /// they come, so they must hold nothing personal or secret.
    pub(crate) fn record_with(
        &self,
        e: &audit::Event,
        details: impl FnOnce(&Connection, i64, Option<&crate::audit_chain::Link>) -> rusqlite::Result<serde_json::Value>,
    ) -> rusqlite::Result<i64> {
        self.record_sealed(e, now(), |c, id, head| details(c, id, head).map(Some))
    }

    fn record_sealed(
        &self,
        e: &audit::Event,
        at: i64,
        hook: impl FnOnce(&Connection, i64, Option<&crate::audit_chain::Link>) -> rusqlite::Result<Option<serde_json::Value>>,
    ) -> rusqlite::Result<i64> {
        let o = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(s, max));
        let a = &e.actor;
        let bot_actor = matches!(a.kind, audit::ActorKind::Bot).then_some(a.id.as_deref()).flatten();
        let owners: Vec<String> = [e.bot_id.as_deref(), bot_actor].into_iter().flatten().filter_map(|b| self.bot_owner(b)).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        let text = |v: &Option<String>, max: usize| v.as_deref().map(|s| audit::clip(&redact::text_for(&owners, &audit::redact_text(s)), max));
        let mut details = redact::value_for(&owners, audit::scrub(e.details.clone()));
        // Recorded during a traced request or run (ADR 0118): the trace that shows it.
        if let Some(t) = crate::obs::trace::current_sampled() {
            if details.is_null() {
                details = serde_json::json!({});
            }
            if let Some(d) = details.as_object_mut() {
                d.insert("traceId".into(), serde_json::json!(t.trace_id()));
                d.insert("spanId".into(), serde_json::json!(t.span_id()));
            }
        }
        use rusqlite::types::Value as V;
        let v = |s: Option<String>| s.map_or(V::Null, V::Text);
        let cols = [
            ("at", V::Integer(at)),
            ("actor_kind", V::Text(a.kind.as_str().into())),
            ("actor_id", v(o(&a.id, 128))),
            ("actor_name", v(text(&a.name, 128))),
            ("actor_subject", v(o(&a.subject, 256))),
            ("action", V::Text(audit::clip(&e.action, 64))),
            ("target_type", v(o(&e.target_type, 32))),
            ("target_id", v(o(&e.target_id, 128))),
            ("bot_id", v(o(&e.bot_id, 128))),
            ("outcome", V::Text(e.outcome.as_str().into())),
            ("ip", v(o(&e.source.ip, 64))),
            ("user_agent", v(text(&e.source.user_agent, 256))),
            ("details", V::Text(details.to_string())),
            ("actor_email", v(text(&a.email, 254))),
            ("actor_role", v(o(&a.role, 16))),
            ("auth_method", v(o(&a.method, 32))),
            ("idp", v(o(&a.idp, 32))),
            ("idp_provider", v(o(&a.idp_provider, 64))),
            ("session_id", v(o(&a.session, 64))),
            ("on_behalf_of", v(o(&a.on_behalf_of, 128))),
        ];
        let res = crate::audit_chain::insert_with(&self.c(), &cols, hook);
        let reason = e.details.get("reason").and_then(|r| r.as_str());
        self.metrics().audited(&e.action, e.outcome.as_str(), reason);
        crate::obs::trace::audited(&e.action, e.outcome.as_str(), reason);
        res
    }

    /// Newest first (or oldest first with `oldest_first`), filtered, at most `limit`.
    /// Rows that can't be read are left out; see `try_audit_events`.
    pub fn audit_events(&self, f: &audit::Filter, limit: i64, oldest_first: bool) -> Vec<AuditEvent> {
        self.select_audit_events(f, limit, oldest_first, false).unwrap()
    }

    /// Like `audit_events`, but a row that can't be read is an error, not a gap.
    pub fn try_audit_events(&self, f: &audit::Filter, limit: i64, oldest_first: bool) -> rusqlite::Result<Vec<AuditEvent>> {
        self.select_audit_events(f, limit, oldest_first, true)
    }

    fn select_audit_events(&self, f: &audit::Filter, limit: i64, oldest_first: bool, strict: bool) -> rusqlite::Result<Vec<AuditEvent>> {
        use rusqlite::types::Value as V;
        let mut sql = String::from("SELECT * FROM audit_events WHERE 1 = 1");
        let mut args: Vec<V> = Vec::new();
        let mut and = |clause: &str, v: Vec<V>| {
            sql.push_str(" AND ");
            sql.push_str(clause);
            args.extend(v);
        };
        if let Some(t) = f.from {
            and("at >= ?", vec![V::Integer(t)]);
        }
        if let Some(t) = f.to {
            and("at < ?", vec![V::Integer(t)]);
        }
        if !f.actions.is_empty() {
            let mut parts = Vec::new();
            let mut vals = Vec::new();
            for a in &f.actions {
                match a.strip_suffix('*') {
                    Some(prefix) => {
                        parts.push("substr(action, 1, ?) = ?");
                        vals.extend([V::Integer(prefix.len() as i64), V::Text(prefix.into())]);
                    }
                    None => {
                        parts.push("action = ?");
                        vals.push(V::Text(a.clone()));
                    }
                }
            }
            and(&format!("({})", parts.join(" OR ")), vals);
        }
        let exact = [
            ("actor_kind", &f.actor_kind),
            ("actor_id", &f.actor_id),
            ("idp", &f.idp),
            ("idp_provider", &f.idp_provider),
            ("actor_subject", &f.subject),
            ("session_id", &f.session_id),
            ("on_behalf_of", &f.on_behalf_of),
            ("outcome", &f.outcome),
            ("bot_id", &f.bot_id),
            ("target_type", &f.target_type),
            ("target_id", &f.target_id),
        ];
        for (col, v) in exact {
            if let Some(v) = v {
                and(&format!("{col} = ?"), vec![V::Text(v.clone())]);
            }
        }
        if let Some(e) = &f.actor_email {
            and("actor_email = ? COLLATE NOCASE", vec![V::Text(e.clone())]);
        }
        if !f.methods.is_empty() {
            let marks = vec!["?"; f.methods.len()].join(", ");
            and(&format!("auth_method IN ({marks})"), f.methods.iter().map(|m| V::Text(m.clone())).collect());
        }
        if let Some(id) = f.before {
            and("id < ?", vec![V::Integer(id)]);
        }
        if let Some(id) = f.after {
            and("id > ?", vec![V::Integer(id)]);
        }
        sql.push_str(if oldest_first { " ORDER BY id ASC LIMIT ?" } else { " ORDER BY id DESC LIMIT ?" });
        args.push(V::Integer(limit));
        let c = self.c();
        let mut s = c.prepare(&sql)?;
        let rows = s.query_map(rusqlite::params_from_iter(args), audit_row)?;
        if strict { rows.collect() } else { Ok(rows.filter_map(Result::ok).collect()) }
    }

    /// Audit events from `from` (unix ms) whose action is one of `actions` (a trailing `*`
    /// matches a prefix), counted by action, outcome, sign-in method and code: a run's
    /// `details.result`, else `details.reason`. Counts only, never who (ADR 0144). A
    /// throttled failure's `unloggedSinceLast` is summed apart as `skipped`: the failures
    /// it stands for were of any reason, not necessarily its own.
    pub fn audit_counts(&self, from: i64, actions: &[&str]) -> Vec<AuditCount> {
        use rusqlite::types::Value as V;
        let mut args = vec![V::Integer(from)];
        let mut parts = Vec::new();
        for a in actions {
            match a.strip_suffix('*') {
                Some(prefix) => {
                    parts.push("substr(action, 1, ?) = ?");
                    args.extend([V::Integer(prefix.len() as i64), V::Text(prefix.into())]);
                }
                None => {
                    parts.push("action = ?");
                    args.push(V::Text(a.to_string()));
                }
            }
        }
        if parts.is_empty() {
            return Vec::new();
        }
        let sql = format!(
            "SELECT action, outcome, auth_method,
               CASE WHEN json_valid(details) THEN CAST(COALESCE(json_extract(details, '$.result'), json_extract(details, '$.reason')) AS TEXT) END AS code,
               COUNT(*),
               SUM(CASE WHEN json_valid(details) THEN max(0, CAST(COALESCE(json_extract(details, '$.unloggedSinceLast'), 0) AS INTEGER)) ELSE 0 END)
             FROM audit_events WHERE at >= ? AND ({})
             GROUP BY action, outcome, auth_method, code ORDER BY action, outcome, code",
            parts.join(" OR ")
        );
        let c = self.c();
        let mut s = c.prepare(&sql).unwrap();
        s.query_map(rusqlite::params_from_iter(args), |r| {
            Ok(AuditCount { action: r.get(0)?, outcome: r.get(1)?, method: r.get(2)?, code: r.get(3)?, n: r.get::<_, i64>(4)?.max(0) as u64, skipped: r.get::<_, i64>(5)?.max(0) as u64 })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    /// Active people, the owner aside as seats count them, and how many of them signed in
    /// or used a session from `since` (unix ms).
    pub fn people_active_since(&self, since: i64) -> (u64, u64) {
        self.c()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(u.last_login_at >= ?1 OR u.last_seen_at >= ?1 OR EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.id AND s.last_seen_at >= ?1)), 0)
                 FROM users u WHERE u.status = 'active' AND u.kind = 'person' AND u.id != ?2",
                params![since, crate::users::OPERATOR],
                |r| Ok((r.get::<_, i64>(0)?.max(0) as u64, r.get::<_, i64>(1)?.max(0) as u64)),
            )
            .unwrap_or((0, 0))
    }

    /// Whether per-user accounts were on, with their copies in order, when last saved (ADR 0037).
    pub fn isolation_was_on(&self) -> bool {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'isolation'", [], |r| r.get(0)).optional().ok().flatten();
        v.as_deref() == Some("users")
    }

    pub fn save_isolation(&self, on: bool) {
        let now = if on { "users" } else { "off" };
        self.c().execute("INSERT INTO settings (key, value) VALUES ('isolation', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1", [now]).unwrap();
    }

    /// Days of audit history to keep. None = forever.
    pub fn audit_retention(&self) -> Option<u32> {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = 'audit_retention_days'", [], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|s| s.parse().ok()).filter(|d| *d > 0)
    }

    pub fn set_audit_retention(&self, days: Option<u32>) {
        let c = self.c();
        match days {
            Some(d) => c.execute(
                "INSERT INTO settings (key, value) VALUES ('audit_retention_days', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
                [d.to_string()],
            ),
            None => c.execute("DELETE FROM settings WHERE key = 'audit_retention_days'", []),
        }
        .unwrap();
    }

    /// Deletes events older than the saved retention window (the trigger refuses any row
    /// inside it), as one run from the start of the log, so the hash chain stays whole:
    /// an old row after a younger one waits for it. None after `delivered`, the SIEM
    /// export's cursor, so nothing goes before it's off the host (ADR 0122). Saves the
    /// last deleted row as the chain's anchor, and returns how many went and the anchor.
    pub fn prune_audit(&self, delivered: Option<i64>) -> rusqlite::Result<(usize, Option<crate::audit_chain::Link>)> {
        let c = self.c();
        let tx = rusqlite::Transaction::new_unchecked(&c, rusqlite::TransactionBehavior::Immediate)?;
        // An earlier statement's 'now' than the delete's, so its cutoff is never later than the trigger's.
        let end: Option<i64> = tx.query_row(
            &format!("SELECT coalesce((SELECT MIN(id) FROM audit_events WHERE at >= {AUDIT_CUTOFF}), (SELECT MAX(id) + 1 FROM audit_events)) WHERE {AUDIT_CUTOFF} IS NOT NULL"),
            [],
            |r| r.get(0),
        ).optional()?.flatten();
        let Some(end) = end.map(|e: i64| delivered.map_or(e, |d| e.min(d + 1))) else { return Ok((0, None)) };
        let last: Option<(i64, Option<String>)> =
            tx.query_row("SELECT id, chain_hash FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT 1", [end], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let Some((last, hash)) = last else { return Ok((0, None)) };
        let n = tx.execute("DELETE FROM audit_events WHERE id <= ?", [last])?;
        // A record outlives its checkpoint while its timestamp event is still in the log, so that
        // event's export and check still have the token.
        tx.execute("DELETE FROM audit_checkpoints WHERE event_id <= ?1 AND (tsa_event_id IS NULL OR tsa_event_id <= ?1)", [last])?;
        let anchor = hash.map(|hash| crate::audit_chain::Link { id: last, hash });
        if let Some(a) = &anchor {
            crate::audit_chain::set_anchor(&tx, a)?;
        }
        tx.commit()?;
        Ok((n, anchor))
    }

    /// The last pruned audit row, which the first one left links to (ADR 0122).
    pub fn audit_chain_anchor(&self) -> Option<crate::audit_chain::Link> {
        crate::audit_chain::anchor(&self.c()).ok().flatten()
    }

    /// Up to `limit` audit rows after id `after`, oldest first, as the hash chain sees them.
    /// A row that can't be read is an error, never skipped: skipping would hide it.
    pub fn audit_chain_rows(&self, after: i64, limit: i64) -> rusqlite::Result<Vec<crate::audit_chain::Row>> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT {} FROM audit_events WHERE id > ? ORDER BY id LIMIT ?", crate::audit_chain::select_list()))?;
        s.query_map(params![after, limit], crate::audit_chain::read_row)?.collect()
    }

    /// The newest audit event's id, 0 when there is none.
    pub fn audit_head(&self) -> i64 {
        self.c().query_row("SELECT coalesce(MAX(id), 0) FROM audit_events", [], |r| r.get(0)).unwrap_or(0)
    }

    /// Where the SIEM export to `sink` got to: the last event it delivered (ADR 0122).
    pub fn audit_export_cursor(&self, sink: &str) -> Option<i64> {
        let v: Option<String> = self.c().query_row("SELECT value FROM settings WHERE key = ?", [format!("audit_export:{sink}")], |r| r.get(0)).optional().ok().flatten();
        v.and_then(|v| v.parse().ok())
    }

    /// The furthest any sink ever got, configured now or not: the last event delivered or
    /// cut into a batch. Keys other than `except` that don't hold an id are skipped.
    pub fn audit_export_furthest(&self, except: &str) -> rusqlite::Result<i64> {
        let c = self.c();
        let mut q = c.prepare("SELECT value FROM settings WHERE key LIKE 'audit\\_export:%' ESCAPE '\\' AND key != ?")?;
        let values = q.query_map([format!("audit_export:{except}")], |r| r.get::<_, String>(0))?;
        let mut furthest = 0;
        for v in values {
            furthest = furthest.max(v?.parse().unwrap_or(0));
        }
        Ok(furthest)
    }

    pub fn set_audit_export_cursor(&self, sink: &str, delivered: i64) -> rusqlite::Result<()> {
        self.c().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![format!("audit_export:{sink}"), delivered.to_string()],
        )?;
        Ok(())
    }

    // Machines (ADR 0025)

    /// A new `pending` machine for the user, unless they have a live one already.
    pub fn add_machine(&self, n: &NewMachine) -> Result<Machine, AddMachine> {
        let id = format!("m{}", crate::short_id());
        let at = now();
        let res = self.c().execute(
            "INSERT INTO machines (id, user_id, provider, label, tag, tier, plan, region, state, created_at, created_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?9)",
            params![id, n.user_id, n.provider, format!("{}-{id}", n.label_prefix), n.label_prefix, n.tier, n.plan, n.region, at, n.created_by],
        );
        match res {
            Ok(_) => self.machine(&id).ok_or_else(|| AddMachine::Db("the new machine wasn't saved".into())),
            Err(e) if constraint(&e) => self.user_machine(n.user_id).map_or_else(|| Err(AddMachine::Db(e.to_string())), |m| Err(AddMachine::Exists(Box::new(m)))),
            Err(e) => Err(AddMachine::Db(e.to_string())),
        }
    }

    pub fn machine(&self, id: &str) -> Option<Machine> {
        self.c().query_row("SELECT * FROM machines WHERE id = ?", [id], machine_row).optional().ok().flatten()
    }

    /// The user's machine that isn't destroyed, if any.
    pub fn user_machine(&self, user_id: &str) -> Option<Machine> {
        self.c().query_row("SELECT * FROM machines WHERE user_id = ? AND state <> 'destroyed'", [user_id], machine_row).optional().ok().flatten()
    }

    /// Newest first. `state` None: every one, destroyed too.
    pub fn machines(&self, state: Option<MachineState>) -> Vec<Machine> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machines WHERE ?1 IS NULL OR state = ?1 ORDER BY created_at DESC, id").unwrap();
        s.query_map([state.map(MachineState::as_str)], machine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Writes `m` back if the stored machine is still in state `from`, so two changes
    /// can't both win. The user and label never change. Returns whether it was saved.
    pub fn save_machine(&self, m: &Machine, from: MachineState) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET provider_id = ?, tier = ?, plan = ?, region = ?, state = ?, provider_status = ?, ipv4 = ?, backups = ?,
                 last_error = ?, create_sent_at = ?, placed_on = ?, updated_at = ?, destroyed_at = ?, firewall_id = ?,
                 suspended_at = CASE WHEN ?5 != 'suspended' THEN NULL WHEN state = 'suspended' THEN suspended_at ELSE ?12 END,
                 provider_backup_at = ?15
                 WHERE id = ?16 AND state = ?17",
                params![
                    m.provider_id,
                    m.tier,
                    m.plan,
                    m.region,
                    m.state.as_str(),
                    m.provider_status,
                    m.ipv4,
                    m.backups,
                    m.last_error,
                    m.create_sent_at,
                    m.placed_on,
                    now(),
                    m.destroyed_at,
                    m.firewall_id,
                    m.provider_backup_at,
                    m.id,
                    from.as_str()
                ],
            )
            .unwrap()
            == 1
    }

    // Machine enrollment (ADR 0031)

    /// Saves a token's hash. The machine must enroll by `enroll_by` (ADR 0035); a new
    /// token starts that clock again and clears an earlier overdue mark.
    pub fn add_machine_token(
        &self,
        machine_id: &str,
        token_hash: &str,
        expires_at: i64,
        created_by: Option<&str>,
        enroll_by: i64,
    ) -> rusqlite::Result<()> {
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO machine_tokens (machine_id, token_hash, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![machine_id, token_hash, now(), created_by, expires_at],
        )?;
        tx.execute(
            "UPDATE machines SET enroll_by = ?, enroll_overdue_at = NULL WHERE id = ?",
            params![enroll_by, machine_id],
        )?;
        tx.commit()
    }

    /// Puts back the enrollment deadline and overdue mark a token replaced, when the
    /// machine it was for never got it (a restore that failed before the swap).
    pub fn restore_enroll_by(&self, machine_id: &str, enroll_by: Option<i64>, overdue_at: Option<i64>) {
        let _ = self.c().execute(
            "UPDATE machines SET enroll_by = ?, enroll_overdue_at = ? WHERE id = ?",
            params![enroll_by, overdue_at, machine_id],
        );
    }

    /// Marks the machine overdue if it had to enroll by now and hasn't (ADR 0035).
    /// Returns whether this call marked it, so it is reported once.
    pub fn mark_enroll_overdue(&self, machine_id: &str) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE machines SET enroll_overdue_at = ?1 WHERE id = ?2 AND enroll_overdue_at IS NULL
                 AND enroll_by IS NOT NULL AND enroll_by <= ?1 AND enrollment IN ('none', 'revoked')",
                params![at, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records that the machine is behind firewall `firewall_id` at the provider.
    pub fn set_machine_firewall(&self, machine_id: &str, firewall_id: &str) {
        let _ = self.c().execute("UPDATE machines SET firewall_id = ? WHERE id = ?", params![firewall_id, machine_id]);
    }

    /// How many machines other than `except` that aren't destroyed use the firewall.
    pub fn machines_on_firewall(&self, firewall_id: &str, except: &str) -> usize {
        self.c()
            .query_row(
                "SELECT COUNT(*) FROM machines WHERE firewall_id = ? AND id <> ? AND state <> 'destroyed'",
                params![firewall_id, except],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| n as usize)
    }

    /// A token by its hash, used or not.
    pub fn machine_token(&self, token_hash: &str) -> Option<MachineToken> {
        self.c()
            .query_row("SELECT id, machine_id, expires_at, used_at, revoked_at FROM machine_tokens WHERE token_hash = ?", [token_hash], |r| {
                Ok(MachineToken { id: r.get(0)?, machine_id: r.get(1)?, expires_at: r.get(2)?, used_at: r.get(3)?, revoked_at: r.get(4)? })
            })
            .optional()
            .ok()
            .flatten()
    }

    /// Unused tokens for the machine can't be used any more. Returns how many.
    pub fn revoke_machine_tokens(&self, machine_id: &str) -> usize {
        self.c()
            .execute("UPDATE machine_tokens SET revoked_at = ? WHERE machine_id = ? AND used_at IS NULL AND revoked_at IS NULL", params![now(), machine_id])
            .unwrap_or(0)
    }

    /// Uses token `token_id` for `machine_id` and records `cert` as the machine's one
    /// active certificate, all at once. The token must be unused, unrevoked, and
    /// unexpired at this moment, so two enrollments with it can't both win. Every other
    /// unused token for the machine is revoked, and its earlier certificates too
    /// (`replaced`). Returns those certificates' fingerprints, or None if the token
    /// couldn't be used.
    pub fn enroll_machine(
        &self,
        token_id: i64,
        machine_id: &str,
        user_id: &str,
        cert: &crate::machines::pki::Issued,
    ) -> Option<Vec<String>> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let at = now();
        let used = tx
            .execute(
                "UPDATE machine_tokens SET used_at = ?1 WHERE id = ?2 AND machine_id = ?3 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
                params![at, token_id, machine_id],
            )
            .ok()?;
        if used != 1 {
            return None;
        }
        tx.execute("UPDATE machine_tokens SET revoked_at = ?1 WHERE machine_id = ?2 AND used_at IS NULL AND revoked_at IS NULL", params![at, machine_id]).ok()?;
        let replaced = revoke_where(&tx, machine_id, "1", "replaced").ok()?;
        tx.execute(
            "INSERT INTO machine_certs (fingerprint, serial, machine_id, user_id, status, issued_for, issued_at, not_before, not_after)
             VALUES (?, ?, ?, ?, 'active', 'enrolled', ?, ?, ?)",
            params![cert.fingerprint, cert.serial, machine_id, user_id, at, cert.not_before, cert.not_after],
        )
        .ok()?;
        tx.execute(
            "UPDATE machines SET enrolled_at = ?, enroll_by = NULL, enroll_overdue_at = NULL WHERE id = ?",
            params![at, machine_id],
        )
        .ok()?;
        refresh_enrollment(&tx, machine_id).ok()?;
        tx.commit().ok()?;
        Some(replaced)
    }

    pub fn machine_cert(&self, fingerprint: &str) -> Option<MachineCert> {
        self.c()
            .query_row(
                "SELECT * FROM machine_certs WHERE fingerprint = ?",
                [fingerprint],
                machine_cert_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Every certificate the machine was issued, newest first.
    pub fn machine_certs(&self, machine_id: &str) -> Vec<MachineCert> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM machine_certs WHERE machine_id = ? ORDER BY id DESC")
            .unwrap();
        s.query_map([machine_id], machine_cert_row)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    }

    /// Fingerprints of the machine's usable certificates: the only ones botd accepts
    /// from it when calling it.
    pub fn machine_pins(&self, machine_id: &str) -> Vec<String> {
        let at = now();
        self.machine_certs(machine_id)
            .into_iter()
            .filter(|c| c.usable(at))
            .map(|c| c.fingerprint)
            .collect()
    }

    /// Records `new`, issued to replace `old`. `old` stays usable until `new` is first
    /// used, so a machine that never got the answer isn't locked out. A replacement
    /// issued earlier that was never used is revoked (`superseded`); returns those.
    /// None if `old` was held or revoked, or its machine stopped, after the caller
    /// checked it: a rotation can't undo that. The check and the insert share one
    /// transaction on the one connection, so a revocation lands wholly before or after.
    pub fn add_rotated_cert(
        &self,
        old: &MachineCert,
        new: &crate::machines::pki::Issued,
    ) -> Option<Vec<String>> {
        let c = self.c();
        let tx = c.unchecked_transaction().ok()?;
        let old_id: i64 = tx
            .query_row(
                "SELECT mc.id FROM machine_certs mc JOIN machines m ON m.id = mc.machine_id AND m.user_id = mc.user_id
                 WHERE mc.fingerprint = ?1 AND mc.machine_id = ?2 AND mc.status = 'active'
                   AND m.state IN ('provisioning', 'running')",
                params![old.fingerprint, old.machine_id],
                |r| r.get(0),
            )
            .ok()?;
        let filter = format!(
            "issued_for = 'rotated' AND first_seen_at IS NULL AND status = 'active' AND id > {old_id}"
        );
        let superseded = revoke_where(&tx, &old.machine_id, &filter, "superseded").ok()?;
        tx.execute(
            "INSERT INTO machine_certs (fingerprint, serial, machine_id, user_id, status, issued_for, issued_at, not_before, not_after)
             VALUES (?, ?, ?, ?, 'active', 'rotated', ?, ?, ?)",
            params![new.fingerprint, new.serial, old.machine_id, old.user_id, now(), new.not_before, new.not_after],
        )
        .ok()?;
        refresh_enrollment(&tx, &old.machine_id).ok()?;
        tx.commit().ok()?;
        Some(superseded)
    }

    /// Marks the certificate used. The first time, the machine's certificates issued
    /// before it are revoked (`rotated`); returns those.
    pub fn machine_cert_seen(&self, fingerprint: &str) -> Vec<String> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else {
            return Vec::new();
        };
        let Ok(Some((id, machine_id))) = tx
            .query_row(
                "UPDATE machine_certs SET first_seen_at = ? WHERE fingerprint = ? AND first_seen_at IS NULL AND status = 'active' RETURNING id, machine_id",
                params![now(), fingerprint],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
        else {
            return Vec::new();
        };
        let revoked =
            revoke_where(&tx, &machine_id, &format!("id < {id}"), "rotated").unwrap_or_default();
        if refresh_enrollment(&tx, &machine_id).is_err() || tx.commit().is_err() {
            return Vec::new();
        }
        revoked
    }

    /// Moves the machine's certificates from `from` to `to` (`held`, `active`, or
    /// `revoked` with `reason`). Returns the fingerprints that changed.
    pub fn set_machine_certs(
        &self,
        machine_id: &str,
        from: &[&str],
        to: &str,
        reason: Option<&str>,
    ) -> Vec<String> {
        let c = self.c();
        let Ok(tx) = c.unchecked_transaction() else {
            return Vec::new();
        };
        let list = from
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let changed: rusqlite::Result<Vec<String>> = if to == "revoked" {
            revoke_where(
                &tx,
                machine_id,
                &format!("status IN ({list})"),
                reason.unwrap_or("revoked"),
            )
        } else {
            tx.prepare(&format!("UPDATE machine_certs SET status = ?2 WHERE machine_id = ?1 AND status IN ({list}) RETURNING fingerprint"))
                .and_then(|mut s| s.query_map(params![machine_id, to], |r| r.get(0))?.collect())
        };
        match changed {
            Ok(fps) if refresh_enrollment(&tx, machine_id).is_ok() && tx.commit().is_ok() => fps,
            _ => Vec::new(),
        }
    }

    /// Places the machine's user on it: their Bots run there (ADR 0036). Only a live
    /// machine. Returns whether it changed.
    pub fn assign_machine(&self, machine_id: &str, by: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET assigned_at = ?, assigned_by = ? WHERE id = ? AND assigned_at IS NULL AND state NOT IN ('destroying', 'destroyed')",
                params![now(), by, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Their Bots run where routing puts unassigned users again. Returns whether it changed.
    pub fn unassign_machine(&self, machine_id: &str) -> bool {
        self.c().execute("UPDATE machines SET assigned_at = NULL, assigned_by = NULL WHERE id = ? AND assigned_at IS NOT NULL", [machine_id]).unwrap_or(0) == 1
    }

    /// Forgets the harness sessions of the user's Bots: a session lives on the host
    /// that ran it, so after a move the next run starts a new one. Returns how many.
    pub fn forget_sessions_of(&self, owner_id: &str) -> usize {
        self.c().execute("UPDATE bots SET session_id = NULL WHERE owner_id = ? AND session_id IS NOT NULL", [owner_id]).unwrap_or(0)
    }

    /// When the owner's machine was assigned (None: it isn't). A run reads this as it
    /// starts and passes it to `keep_session`.
    pub fn placed_at(&self, owner_id: &str) -> Option<i64> {
        self.user_machine(owner_id).and_then(|m| m.assigned_at)
    }

    /// Saves a run's session unless the owner was assigned or unassigned since the run
    /// began (`placed_at` then), so a run on the old host can't undo `forget_sessions_of`.
    pub fn keep_session(&self, bot_id: &str, session_id: &str, placed_at: Option<i64>) -> bool {
        self.c()
            .execute(
                "UPDATE bots SET session_id = ?1 WHERE id = ?2 AND session_id IS NOT ?1
                 AND (SELECT assigned_at FROM machines WHERE user_id = bots.owner_id AND state <> 'destroyed') IS ?3",
                params![session_id, bot_id, placed_at],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records a heartbeat: `Ok(version)` when the agent answered, `Err(why)` when not.
    pub fn machine_agent_seen(&self, machine_id: &str, result: Result<&str, &str>) {
        let _ = match result {
            Ok(version) => self.c().execute(
                "UPDATE machines SET agent_seen_at = ?, agent_version = ?, agent_error = NULL WHERE id = ?",
                params![now(), version, machine_id],
            ),
            Err(why) => self.c().execute("UPDATE machines SET agent_error = ? WHERE id = ?", params![why, machine_id]),
        };
    }

    /// What the agent said of its build, harnesses and upgrades (ADR 0039), if it was
    /// still `old`. Returns whether it was, so each change is seen once.
    pub fn machine_upkeep_swap(&self, machine_id: &str, old: Option<&Value>, new: &Value) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET agent_upkeep = ? WHERE id = ? AND agent_upkeep IS ?",
                params![new.to_string(), machine_id, old.map(Value::to_string)],
            )
            .unwrap_or(0)
            == 1
    }

    /// Queues a teammate's removal from a machine, unless one is pending: returns that
    /// one then, and whether this call made it.
    pub fn teammate_cleanup_queue(&self, n: &NewTeammateCleanup) -> Option<(TeammateCleanup, bool)> {
        let c = self.c();
        let made = c
            .execute(
                "INSERT OR IGNORE INTO teammate_cleanups (id, machine_id, owner_id, user_id, os_user, reason, files, grace_days, state, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![crate::random_hex(8), n.machine_id, n.owner_id, n.user_id, n.os_user, n.reason, n.files, n.grace_days, now(), n.created_by],
            )
            .unwrap_or(0)
            == 1;
        c.query_row(
            "SELECT * FROM teammate_cleanups WHERE machine_id = ? AND user_id = ? AND state = 'pending'",
            [n.machine_id, n.user_id],
            teammate_cleanup_row,
        )
        .optional()
        .ok()
        .flatten()
        .map(|r| (r, made))
    }

    pub fn teammate_cleanup(&self, id: &str) -> Option<TeammateCleanup> {
        self.c().query_row("SELECT * FROM teammate_cleanups WHERE id = ?", [id], teammate_cleanup_row).optional().ok().flatten()
    }

    /// Newest first, in `state` (any if None), on `machine_id` (any if None).
    pub fn teammate_cleanups(&self, state: Option<&str>, machine_id: Option<&str>) -> Vec<TeammateCleanup> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT * FROM teammate_cleanups WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR machine_id = ?2)
                 ORDER BY created_at DESC, id",
            )
            .unwrap();
        s.query_map(params![state, machine_id], teammate_cleanup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// An attempt at a pending (or held, for a purge) removal failed, or is waiting on
    /// the machine (`attempt` false). Returns whether it was still in `state`.
    pub fn teammate_cleanup_failed(&self, id: &str, state: &str, error: &str, attempt: bool) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET last_error = ?, attempts = attempts + ?, tried_at = CASE WHEN ? THEN ? ELSE tried_at END
                 WHERE id = ? AND state = ?",
                params![error, attempt as i64, attempt, now(), id, state],
            )
            .unwrap_or(0)
            == 1
    }

    /// The agent removed the teammate: `held` while their work waits for `purge_at`,
    /// else done. Returns whether it was still pending, so it's recorded once.
    pub fn teammate_cleanup_removed(&self, id: &str, archived_to: Option<&str>, purge_at: Option<i64>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = CASE WHEN ?1 IS NULL THEN 'done' ELSE 'held' END, purge_at = ?1, archived_to = ?2,
                 removed_at = ?3, done_at = CASE WHEN ?1 IS NULL THEN ?3 ELSE NULL END, attempts = attempts + 1, tried_at = ?3, last_error = NULL
                 WHERE id = ?4 AND state = 'pending'",
                params![purge_at, archived_to, at, id],
            )
            .unwrap_or(0)
            == 1
    }

    #[cfg(test)]
    pub fn teammate_cleanup_due_now(&self, id: &str) {
        self.c().execute("UPDATE teammate_cleanups SET purge_at = ? WHERE id = ?", params![now() - 1, id]).unwrap();
    }

    /// Ends a removal in `from` as `to` (`done` or `cancelled`), with `note` as its
    /// last word. Returns whether it was still in `from`.
    pub fn teammate_cleanup_end(&self, id: &str, from: &str, to: &str, note: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = ?, done_at = ?, last_error = ? WHERE id = ? AND state = ?",
                params![to, now(), note, id, from],
            )
            .unwrap_or(0)
            == 1
    }

    /// An admin asked for this pending removal: it's theirs now, so it's never cancelled
    /// because the teammate is wanted again. Returns whether it changed.
    pub fn teammate_cleanup_force(&self, id: &str) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET reason = 'admin' WHERE id = ? AND state = 'pending' AND reason <> 'admin'",
                [id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Cancels a pending removal with `note`, but only if no admin asked for it and the
    /// agent was never asked. Returns whether it did.
    pub fn teammate_cleanup_cancel_unasked(&self, id: &str, note: &str) -> bool {
        self.c()
            .execute(
                "UPDATE teammate_cleanups SET state = 'cancelled', done_at = ?, last_error = ?
                 WHERE id = ? AND state = 'pending' AND reason <> 'admin' AND attempts = 0",
                params![now(), note, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// A teammate's account and folders for an owner's Bots are on this server (ADR 0066).
    /// Kept with botd's data, so a recreated container, whose password database starts
    /// afresh while the folders stay, still knows whose folders they are.
    pub fn teammate_space_made(&self, owner_id: &str, user_id: &str) {
        let _ = self.c().execute("INSERT OR IGNORE INTO teammate_spaces (owner_id, user_id, made_at) VALUES (?, ?, ?)", params![owner_id, user_id, now()]);
    }

    /// Every `(owner, teammate)` whose account and folders may be on this server.
    pub fn teammate_spaces(&self) -> Vec<(String, String)> {
        let c = self.c();
        let mut s = c.prepare("SELECT owner_id, user_id FROM teammate_spaces ORDER BY owner_id, user_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    pub fn teammate_space_gone(&self, owner_id: &str, user_id: &str) {
        let _ = self.c().execute("DELETE FROM teammate_spaces WHERE owner_id = ? AND user_id = ?", [owner_id, user_id]);
    }

    /// Queues the removal of a teammate's account for an owner's Bots, unless one is
    /// pending: returns that one then, and whether this call made it.
    pub fn account_removal_queue(&self, n: &NewAccountRemoval) -> Option<(AccountRemoval, bool)> {
        let c = self.c();
        let made = c
            .execute(
                "INSERT OR IGNORE INTO account_removals (id, owner_id, user_id, account, reason, files, grace_days, state, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                params![crate::random_hex(8), n.owner_id, n.user_id, n.account, n.reason, n.files, n.grace_days, now(), n.created_by],
            )
            .unwrap_or(0)
            == 1;
        c.query_row(
            "SELECT * FROM account_removals WHERE owner_id = ? AND user_id = ? AND state = 'pending'",
            [n.owner_id, n.user_id],
            account_removal_row,
        )
        .optional()
        .ok()
        .flatten()
        .map(|r| (r, made))
    }

    pub fn account_removal(&self, id: &str) -> Option<AccountRemoval> {
        self.c().query_row("SELECT * FROM account_removals WHERE id = ?", [id], account_removal_row).optional().ok().flatten()
    }

    /// Newest first, in `state` (any if None), where `user_id` (anyone if None) is the
    /// owner or the teammate.
    pub fn account_removals(&self, state: Option<&str>, user_id: Option<&str>) -> Vec<AccountRemoval> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT * FROM account_removals WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR owner_id = ?2 OR user_id = ?2)
                 ORDER BY created_at DESC, id",
            )
            .unwrap();
        s.query_map(params![state, user_id], account_removal_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The helper is about to run for a pending (or held, for a purge) removal: counted
    /// before it starts, so one that stopped halfway is never taken for untried. Returns
    /// whether it was still in `state`.
    pub fn account_removal_tried(&self, id: &str, state: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET attempts = attempts + 1, tried_at = ? WHERE id = ? AND state = ?", params![now(), id, state])
            .unwrap_or(0)
            == 1
    }

    /// A try at a pending (or held, for a purge) removal failed. Returns whether it was
    /// still in `state`.
    pub fn account_removal_failed(&self, id: &str, state: &str, error: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET last_error = ?, tried_at = ? WHERE id = ? AND state = ?", params![error, now(), id, state])
            .unwrap_or(0)
            == 1
    }

    /// The helper removed the account: `held` while their work waits for `purge_at`,
    /// else done. Returns whether it was still pending, so it's recorded once.
    pub fn account_removal_removed(&self, id: &str, archived_to: Option<&str>, purge_at: Option<i64>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE account_removals SET state = CASE WHEN ?1 IS NULL THEN 'done' ELSE 'held' END, purge_at = ?1, archived_to = ?2,
                 removed_at = ?3, done_at = CASE WHEN ?1 IS NULL THEN ?3 ELSE NULL END, tried_at = ?3, last_error = NULL
                 WHERE id = ?4 AND state = 'pending'",
                params![purge_at, archived_to, at, id],
            )
            .unwrap_or(0)
            == 1
    }

    #[cfg(test)]
    pub fn account_removal_due_now(&self, id: &str) {
        self.c().execute("UPDATE account_removals SET purge_at = ? WHERE id = ?", params![now() - 1, id]).unwrap();
    }

    /// Ends a removal in `from` as `to` (`done` or `cancelled`), with `note` as its last
    /// word. Returns whether it was still in `from`.
    pub fn account_removal_end(&self, id: &str, from: &str, to: &str, note: Option<&str>) -> bool {
        self.c()
            .execute("UPDATE account_removals SET state = ?, done_at = ?, last_error = ? WHERE id = ? AND state = ?", params![to, now(), note, id, from])
            .unwrap_or(0)
            == 1
    }

    /// An admin asked for this pending removal: it's theirs now, so it's never cancelled
    /// because the teammate is wanted again. Returns whether it changed.
    pub fn account_removal_force(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE account_removals SET reason = 'admin' WHERE id = ? AND state = 'pending' AND reason <> 'admin'", [id])
            .unwrap_or(0)
            == 1
    }

    /// Cancels a pending removal with `note`, but only if no admin asked for it and the
    /// helper was never started for it. Returns whether it did.
    pub fn account_removal_cancel_unasked(&self, id: &str, note: &str) -> bool {
        self.c()
            .execute(
                "UPDATE account_removals SET state = 'cancelled', done_at = ?, last_error = ?
                 WHERE id = ? AND state = 'pending' AND reason <> 'admin' AND attempts = 0",
                params![now(), note, id],
            )
            .unwrap_or(0)
            == 1
    }

    pub fn machine_harnesses_sent(&self, machine_id: &str, plan: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET harnesses_sent_at = ?, harnesses_sent_plan = ? WHERE id = ?",
            params![now(), plan, machine_id],
        );
    }

    /// Records an upgrade as on its way, unless the machine is held or another is (one
    /// sent before `stale_before` no longer counts). Returns whether this one is.
    pub fn machine_upgrade_claim(&self, machine_id: &str, id: &str, build: &str, by: &str, stale_before: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_id = ?, upgrade_build = ?, upgrade_sent_at = ?, upgrade_by = ?
                 WHERE id = ? AND upgrade_hold_at IS NULL AND (upgrade_id IS NULL OR upgrade_sent_at < ?)",
                params![id, build, now(), by, machine_id, stale_before],
            )
            .unwrap_or(0)
            == 1
    }

    /// Ends upgrade `id`. `failed`: the build that failed, kept so it isn't tried again
    /// by itself; None clears it. Returns whether `id` was the one on its way.
    pub fn machine_upgrade_end(&self, machine_id: &str, id: &str, failed: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_id = NULL, upgrade_build = NULL, upgrade_sent_at = NULL, upgrade_by = NULL,
                 upgrade_failed_build = ? WHERE id = ? AND upgrade_id = ?",
                params![failed, machine_id, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Lets a build that failed be tried again.
    pub fn machine_upgrade_forget_failure(&self, machine_id: &str) {
        let _ = self.c().execute("UPDATE machines SET upgrade_failed_build = NULL WHERE id = ?", [machine_id]);
    }

    /// Holds the agent at its build, unless it is held already or an upgrade is on its
    /// way (one sent before `stale_before` no longer counts): a hold that is taken means
    /// no upgrade starts until it is released. Returns whether it was taken.
    pub fn machine_upgrade_hold(&self, machine_id: &str, by: Option<&str>, stale_before: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_hold_at = ?, upgrade_hold_by = ?
                 WHERE id = ? AND upgrade_hold_at IS NULL AND (upgrade_id IS NULL OR upgrade_sent_at < ?)",
                params![now(), by, machine_id, stale_before],
            )
            .unwrap_or(0)
            == 1
    }

    /// Lets a held agent go. Returns whether it was held.
    pub fn machine_upgrade_release(&self, machine_id: &str) -> bool {
        self.c()
            .execute(
                "UPDATE machines SET upgrade_hold_at = NULL, upgrade_hold_by = NULL WHERE id = ? AND upgrade_hold_at IS NOT NULL",
                [machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    // Rebuilds (ADR 0056). Each step names the rebuild and the states it may come
    // from, so a stale step, or one racing an admin's cancel, changes nothing.

    /// Queues rebuild `id`, unless the machine isn't running, its agent is held, or a
    /// rebuild is underway. Returns whether this one is queued.
    pub fn machine_rebuild_queue(&self, machine_id: &str, id: &str, by: &str, discard: bool, from: Option<&str>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE machines SET rebuild_state = 'queued', rebuild_id = ?1, rebuild_by = ?2, rebuild_discard = ?3, rebuild_attempts = 0,
                 rebuild_next_at = ?4, rebuild_requested_at = ?4, rebuild_at = ?4, rebuild_sent_at = NULL, rebuild_error = NULL, rebuild_from = ?5
                 WHERE id = ?6 AND state = 'running' AND upgrade_hold_at IS NULL
                 AND (rebuild_state IS NULL OR rebuild_state IN ('done', 'failed', 'cancelled'))",
                params![id, by, discard, at, from, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Moves rebuild `id` from one of `from` to `to`. `attempt` counts one more try;
    /// `next_at` is when to try next. Returns whether it was in `from`.
    #[allow(clippy::too_many_arguments)]
    pub fn machine_rebuild_move(
        &self,
        machine_id: &str,
        id: &str,
        from: &[&str],
        to: &str,
        attempt: bool,
        next_at: Option<i64>,
        error: Option<&str>,
    ) -> bool {
        let states = from.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(", ");
        self.c()
            .execute(
                &format!(
                    "UPDATE machines SET rebuild_state = ?1, rebuild_attempts = rebuild_attempts + ?2, rebuild_next_at = ?3, rebuild_error = ?4,
                     rebuild_at = CASE WHEN rebuild_state = ?1 THEN rebuild_at ELSE ?5 END
                     WHERE id = ?6 AND rebuild_id = ?7 AND rebuild_state IN ({states})"
                ),
                params![to, attempt as i64, next_at, error, now(), machine_id, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records rebuild `id` as sent now, from one of `from`. Returns whether it was there.
    pub fn machine_rebuild_sending(&self, machine_id: &str, id: &str, from: &[&str]) -> bool {
        let at = now();
        if !self.machine_rebuild_move(machine_id, id, from, "rebuilding", true, None, None) {
            return false;
        }
        let _ = self.c().execute("UPDATE machines SET rebuild_sent_at = ?, rebuild_at = ? WHERE id = ?", params![at, at, machine_id]);
        true
    }

    /// Forgets what the old agent said and was sent: a rebuilt machine starts afresh.
    pub fn machine_rebuilt_reset(&self, machine_id: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET agent_upkeep = NULL, harnesses_sent_at = NULL, harnesses_sent_plan = NULL, upgrade_id = NULL,
             upgrade_build = NULL, upgrade_sent_at = NULL, upgrade_by = NULL, upgrade_failed_build = NULL,
             disk_files = NULL, disk_files_partial = 0, disk_files_at = NULL WHERE id = ?",
            [machine_id],
        );
    }

    // Resizes that follow a user's tier (ADR 0085). Each step names the target and the
    // states it may come from, so a stale step, or one racing a newer tier, changes nothing.

    /// Asks for `machine_id` to become `(tier, plan)`, replacing any resize not yet done.
    /// Returns whether it was saved: not when the same one is open already.
    pub fn machine_resize_queue(&self, machine_id: &str, tier: &str, plan: &str, from: (&str, &str), cause: &str, event: Option<&str>) -> bool {
        let at = now();
        self.c()
            .execute(
                "UPDATE machines SET resize_state = 'pending', resize_tier = ?1, resize_plan = ?2, resize_from_tier = ?3, resize_from_plan = ?4,
                 resize_cause = ?5, resize_event = ?6, resize_reason = NULL, resize_error = NULL, resize_attempts = 0, resize_next_at = ?7,
                 resize_requested_at = ?7, resize_at = ?7
                 WHERE id = ?8 AND state NOT IN ('destroying', 'destroyed')
                 AND NOT (resize_state IN ('pending', 'waiting') AND resize_tier IS ?1 AND resize_plan IS ?2)",
                params![tier, plan, from.0, from.1, cause, event, at, machine_id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Moves the resize to `plan` from one of `from` to `to`, with why. `attempt` counts
    /// one more try; `next_at` is when to look again. Returns whether it was in `from`.
    #[allow(clippy::too_many_arguments)]
    pub fn machine_resize_move(
        &self,
        machine_id: &str,
        plan: &str,
        from: &[&str],
        to: &str,
        reason: Option<&str>,
        error: Option<&str>,
        attempt: bool,
        next_at: Option<i64>,
    ) -> bool {
        let states = from.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(", ");
        self.c()
            .execute(
                &format!(
                    "UPDATE machines SET resize_state = ?1, resize_reason = ?2, resize_error = ?3, resize_attempts = resize_attempts + ?4, resize_next_at = ?5,
                     resize_at = CASE WHEN resize_state = ?1 THEN resize_at ELSE ?6 END
                     WHERE id = ?7 AND resize_plan IS ?8 AND resize_state IN ({states})"
                ),
                params![to, reason, error, attempt as i64, next_at, now(), machine_id, plan],
            )
            .unwrap_or(0)
            == 1
    }

    /// Records that the machine is about to be sent to `plan` (for `tier`), before the
    /// provider is asked, so a lost answer is checked rather than forgotten.
    pub fn machine_resize_sent(&self, machine_id: &str, tier: &str, plan: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET resize_sent_tier = ?, resize_sent_plan = ? WHERE id = ?",
            params![tier, plan, machine_id],
        );
    }

    /// The provider's answer for a resize sent to `plan` (None: any) is known: forgets
    /// it, unless another was sent since.
    pub fn machine_resize_unsent(&self, machine_id: &str, plan: Option<&str>) {
        let _ = self.c().execute(
            "UPDATE machines SET resize_sent_tier = NULL, resize_sent_plan = NULL WHERE id = ?1 AND (?2 IS NULL OR resize_sent_plan IS ?2)",
            params![machine_id, plan],
        );
    }

    /// Machines with a resize not yet done, or one sent whose outcome is unknown.
    pub fn machines_resizing(&self) -> Vec<Machine> {
        let c = self.c();
        let mut s = c
            .prepare("SELECT * FROM machines WHERE resize_state IN ('pending', 'waiting') OR resize_sent_plan IS NOT NULL ORDER BY resize_requested_at, id")
            .unwrap();
        s.query_map([], machine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// What the machine's agent said of its disk, in bytes.
    pub fn machine_disk_seen(&self, machine_id: &str, used: u64, total: u64) {
        let b = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        let _ = self.c().execute(
            "UPDATE machines SET disk_used = ?, disk_total = ?, disk_seen_at = ? WHERE id = ?",
            params![b(used), b(total), now(), machine_id],
        );
    }

    /// What the machine's agent said its homes hold, in bytes (ADR 0105). A heartbeat
    /// without it (an agent that hasn't measured yet) leaves the last one as it was.
    pub fn machine_files_seen(&self, machine_id: &str, bytes: u64, partial: bool) {
        self.machine_files_seen_at(machine_id, bytes, partial, now());
    }

    /// The same, heard at `at` (tests set it long ago).
    pub fn machine_files_seen_at(&self, machine_id: &str, bytes: u64, partial: bool, at: i64) {
        let _ = self.c().execute(
            "UPDATE machines SET disk_files = ?, disk_files_partial = ?, disk_files_at = ? WHERE id = ?",
            params![i64::try_from(bytes).unwrap_or(i64::MAX), partial, at, machine_id],
        );
    }

    /// What the machine's agent said of its disk at `at`, as if long ago.
    #[cfg(test)]
    pub fn machine_disk_seen_at(&self, machine_id: &str, used: u64, total: u64, at: i64) {
        self.machine_disk_seen(machine_id, used, total);
        let _ = self.c().execute("UPDATE machines SET disk_seen_at = ? WHERE id = ?", params![at, machine_id]);
    }

    /// Forgets a machine's resize, as if none was ever asked for.
    #[cfg(test)]
    pub fn machine_resize_forget(&self, machine_id: &str) {
        let _ = self.c().execute(
            "UPDATE machines SET resize_state = NULL, resize_tier = NULL, resize_plan = NULL WHERE id = ?",
            params![machine_id],
        );
    }

    // Off-host machine backups (ADR 0071)

    /// Records a backup as running, unless one of the machine's is running already.
    pub fn machine_backup_start(&self, n: &NewMachineBackup) -> Option<MachineBackup> {
        let m = n.machine;
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_backups (id, machine_id, user_id, tier, plan, state, object_key, store_region, encrypted, created_by, created_at)
                 VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)",
                params![n.id, m.id, m.user_id, m.tier, m.plan, n.object_key, n.store_region, n.encrypted, n.created_by, now()],
            )
            .unwrap_or(0)
            == 1;
        if made { self.machine_backup(n.id) } else { None }
    }

    pub fn machine_backup(&self, id: &str) -> Option<MachineBackup> {
        self.c().query_row("SELECT * FROM machine_backups WHERE id = ?", [id], machine_backup_row).optional().ok().flatten()
    }

    /// The machine's backups, newest first, deleted ones too.
    pub fn machine_backups(&self, machine_id: &str) -> Vec<MachineBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_backups WHERE machine_id = ? ORDER BY created_at DESC, id DESC").unwrap();
        s.query_map([machine_id], machine_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every backup in `state`, oldest first.
    pub fn machine_backups_in(&self, state: &str) -> Vec<MachineBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_backups WHERE state = ? ORDER BY created_at, id").unwrap();
        s.query_map([state], machine_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The machine's newest backup that finished.
    pub fn machine_last_backup(&self, machine_id: &str) -> Option<MachineBackup> {
        self.c()
            .query_row(
                "SELECT * FROM machine_backups WHERE machine_id = ? AND state = 'done' ORDER BY created_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_backup_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Ends a running backup as `done` (with its size, hash and expiry) or `failed`.
    pub fn machine_backup_end(&self, id: &str, done: Option<(i64, &str, i64)>, error: Option<&str>) -> bool {
        let (state, size, sha, expires) = match done {
            Some((size, sha, expires)) => ("done", Some(size), Some(sha), Some(expires)),
            None => ("failed", None, None, None),
        };
        self.c()
            .execute(
                "UPDATE machine_backups SET state = ?, size = ?, sha256 = ?, expires_at = ?, error = ?, finished_at = ? WHERE id = ? AND state = 'running'",
                params![state, size, sha, expires, error.map(|e| crate::audit::clip(e, 500)), now(), id],
            )
            .unwrap_or(0)
            == 1
    }

    /// A finished backup whose objects are gone from the store.
    pub fn machine_backup_deleted(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE machine_backups SET state = 'deleted', deleted_at = ? WHERE id = ? AND state IN ('done', 'failed')", params![now(), id])
            .unwrap_or(0)
            == 1
    }

    // Off-host copies of server backups (ADR 0109)

    /// Records a copy as running, unless one is running already.
    pub fn server_backup_start(&self, n: &NewServerBackup) -> Option<ServerBackup> {
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO server_backups (id, archive, state, destination, object_key, encrypted, encrypted_by, created_at, started_at)
                 VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?)",
                params![n.id, n.archive, n.destination, n.object_key, n.encrypted_by.is_some(), n.encrypted_by, n.created_at, now()],
            )
            .unwrap_or(0)
            == 1;
        if made { self.server_backup(n.id) } else { None }
    }

    pub fn server_backup(&self, id: &str) -> Option<ServerBackup> {
        self.c().query_row("SELECT * FROM server_backups WHERE id = ?", [id], server_backup_row).optional().ok().flatten()
    }

    /// The newest `limit` copies, by when their archive was made, deleted and failed ones too.
    pub fn server_backups(&self, limit: i64) -> Vec<ServerBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM server_backups ORDER BY created_at DESC, started_at DESC, id DESC LIMIT ?").unwrap();
        s.query_map([limit], server_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every copy of `archive` to `destination`, newest attempt first.
    pub fn server_backups_of(&self, destination: &str, archive: &str) -> Vec<ServerBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM server_backups WHERE destination = ? AND archive = ? ORDER BY started_at DESC, id DESC").unwrap();
        s.query_map([destination, archive], server_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Finished copies not to `destination` (None: to anywhere) and not deleted: made to
    /// a store botd no longer copies to (ADR 0184).
    pub fn server_backups_done_elsewhere(&self, destination: Option<&str>) -> i64 {
        self.c()
            .query_row("SELECT COUNT(*) FROM server_backups WHERE state = 'done' AND destination IS NOT ?", [destination], |r| r.get(0))
            .unwrap_or(0)
    }

    /// Every copy in `state`, oldest archive first.
    pub fn server_backups_in(&self, state: &str) -> Vec<ServerBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM server_backups WHERE state = ? ORDER BY created_at, id").unwrap();
        s.query_map([state], server_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The newest archive whose copy to `destination` finished. Of archives made in the same
    /// second, the one copied last: only the newest is ever copied.
    pub fn server_last_backup(&self, destination: &str) -> Option<ServerBackup> {
        self.c()
            .query_row(
                "SELECT * FROM server_backups WHERE destination = ? AND state = 'done' ORDER BY created_at DESC, finished_at DESC, id DESC LIMIT 1",
                [destination],
                server_backup_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Ends a running copy as `done` (with its size, hash and expiry, if it has one) or `failed`.
    pub fn server_backup_end(&self, id: &str, done: Option<(i64, &str, Option<i64>)>, error: Option<&str>) -> bool {
        let (state, size, sha, expires) = match done {
            Some((size, sha, expires)) => ("done", Some(size), Some(sha), expires),
            None => ("failed", None, None, None),
        };
        self.c()
            .execute(
                "UPDATE server_backups SET state = ?, size = ?, sha256 = ?, expires_at = ?, error = ?, finished_at = ? WHERE id = ? AND state = 'running'",
                params![state, size, sha, expires, error.map(|e| crate::audit::clip(e, 500)), now(), id],
            )
            .unwrap_or(0)
            == 1
    }

    /// A finished copy whose objects are gone from the store.
    pub fn server_backup_deleted(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE server_backups SET state = 'deleted', deleted_at = ? WHERE id = ? AND state = 'done'", params![now(), id])
            .unwrap_or(0)
            == 1
    }

    /// Moves a copy `ms` into the past, for tests.
    #[cfg(test)]
    pub fn server_backup_backdate(&self, id: &str, ms: i64) {
        self.c()
            .execute(
                "UPDATE server_backups SET created_at = created_at - ?1, started_at = started_at - ?1, finished_at = finished_at - ?1, expires_at = expires_at - ?1 WHERE id = ?2",
                params![ms, id],
            )
            .unwrap();
    }

    /// Clears a generic setting.
    pub fn clear_setting(&self, key: &str) {
        let _ = self.c().execute("DELETE FROM settings WHERE key = ?", [key]);
    }

    /// Backups of any of the user's machines, destroyed ones too, not yet deleted.
    /// Every data region's store a kept backup is in (ADR 0117).
    pub fn machine_backup_stores(&self) -> Vec<String> {
        let c = self.c();
        let mut s = c.prepare("SELECT DISTINCT store_region FROM machine_backups WHERE store_region IS NOT NULL AND state <> 'deleted' ORDER BY store_region").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().filter_map(Result::ok).collect()
    }

    pub fn user_machine_backups_kept(&self, user_id: &str) -> Vec<MachineBackup> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_backups WHERE user_id = ? AND state <> 'deleted' ORDER BY created_at, id").unwrap();
        s.query_map([user_id], machine_backup_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every restore of the machine, oldest first.
    pub fn machine_restores(&self, machine_id: &str) -> Vec<MachineRestore> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_restores WHERE machine_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([machine_id], machine_restore_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Starts a restore of the machine, unless one is underway.
    pub fn machine_restore_start(&self, n: &NewMachineRestore) -> Option<MachineRestore> {
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_restores (id, machine_id, backup_id, state, created_by, created_at, tier, rto_ms, from_host, to_host, reason)
                 VALUES (?, ?, ?, 'importing', ?, ?, ?, ?, ?, ?, ?)",
                params![n.id, n.machine.id, n.backup_id, n.by, now(), n.machine.tier, n.rto_ms, n.from_host, n.to_host, n.reason],
            )
            .unwrap_or(0)
            == 1;
        if made { self.machine_restore(n.id) } else { None }
    }

    // The status page (ADR 0090)

    /// How long a trivial query takes, holding the connection as every other query must.
    pub fn ping(&self) -> rusqlite::Result<std::time::Duration> {
        let started = std::time::Instant::now();
        self.c().query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
        Ok(started.elapsed())
    }

    /// Live machines by state: destroyed ones aren't counted.
    pub fn machine_state_counts(&self) -> HashMap<String, i64> {
        let c = self.c();
        let mut s = c.prepare("SELECT state, COUNT(*) FROM machines WHERE state != 'destroyed' GROUP BY state").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    pub fn status_incident_create(&self, n: &NewStatusIncident) -> rusqlite::Result<StatusIncident> {
        let at = now();
        let resolved = (n.state == "resolved").then_some(at);
        let comps = serde_json::to_string(n.components).unwrap_or_else(|_| "[]".into());
        {
            let c = self.c();
            let tx = c.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO status_incidents (id, title, impact, components, state, created_by, created_at, updated_at, resolved_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)",
                params![n.id, n.title, n.impact, comps, n.state, n.by, at, resolved],
            )?;
            tx.execute(
                "INSERT INTO status_incident_updates (incident_id, state, body, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                params![n.id, n.state, n.body, n.by, at],
            )?;
            tx.commit()?;
        }
        self.status_incident(n.id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn status_incident(&self, id: &str) -> rusqlite::Result<Option<StatusIncident>> {
        let Some(mut i) = self.c().query_row("SELECT * FROM status_incidents WHERE id = ?", [id], status_incident_row).optional()? else {
            return Ok(None);
        };
        i.updates = self.status_updates(&i.id, i64::MAX)?;
        Ok(Some(i))
    }

    fn status_updates(&self, id: &str, limit: i64) -> rusqlite::Result<Vec<StatusUpdate>> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM status_incident_updates WHERE incident_id = ? ORDER BY id DESC LIMIT ?")?;
        let rows = s.query_map(params![id, limit], |r| {
            Ok(StatusUpdate { id: r.get("id")?, state: r.get("state")?, body: r.get("body")?, created_by: r.get("created_by")?, created_at: r.get("created_at")? })
        })?;
        rows.collect()
    }

    /// Open incidents, and those resolved at or after `resolved_since`, newest first, with
    /// up to `updates` of each one's newest updates.
    pub fn status_incidents(&self, resolved_since: i64, limit: i64, updates: i64) -> rusqlite::Result<Vec<StatusIncident>> {
        let list: Vec<StatusIncident> = {
            let c = self.c();
            let mut s = c.prepare("SELECT * FROM status_incidents WHERE resolved_at IS NULL OR resolved_at >= ? ORDER BY resolved_at IS NOT NULL, created_at DESC LIMIT ?")?;
            let rows = s.query_map(params![resolved_since, limit], status_incident_row)?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        list.into_iter()
            .map(|mut i| {
                i.updates = self.status_updates(&i.id, updates)?;
                Ok(i)
            })
            .collect()
    }

    /// Every open incident's impact and components, however many there are.
    pub fn status_incidents_open(&self) -> rusqlite::Result<Vec<(String, Vec<String>)>> {
        let c = self.c();
        let mut s = c.prepare("SELECT impact, components FROM status_incidents WHERE resolved_at IS NULL")?;
        let rows = s.query_map([], |r| Ok((r.get::<_, String>(0)?, serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or_default())))?;
        rows.collect()
    }

    pub fn status_incident_edit(&self, id: &str, title: Option<&str>, impact: Option<&str>, components: Option<&[String]>) -> rusqlite::Result<bool> {
        let comps = components.map(|c| serde_json::to_string(c).unwrap_or_else(|_| "[]".into()));
        Ok(self.c().execute(
            "UPDATE status_incidents SET title = COALESCE(?1, title), impact = COALESCE(?2, impact), components = COALESCE(?3, components), updated_at = ?4 WHERE id = ?5",
            params![title, impact, comps, now(), id],
        )? == 1)
    }

    /// Adds an update; its state becomes the incident's. Resolving stamps `resolved_at`,
    /// and any other state reopens it.
    pub fn status_incident_add_update(&self, id: &str, state: &str, body: &str, by: Option<&str>) -> rusqlite::Result<bool> {
        let at = now();
        let c = self.c();
        let tx = c.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE status_incidents SET state = ?1, updated_at = ?2,
               resolved_at = CASE WHEN ?1 = 'resolved' THEN COALESCE(resolved_at, ?2) ELSE NULL END
             WHERE id = ?3",
            params![state, at, id],
        )? == 1;
        if changed {
            tx.execute(
                "INSERT INTO status_incident_updates (incident_id, state, body, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                params![id, state, body, by, at],
            )?;
        }
        tx.commit()?;
        Ok(changed)
    }

    pub fn status_incident_delete(&self, id: &str) -> rusqlite::Result<bool> {
        Ok(self.c().execute("DELETE FROM status_incidents WHERE id = ?", [id])? == 1)
    }

    // Hosts (ADR 0076)

    pub fn machine_hosts(&self) -> Vec<MachineHost> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_hosts ORDER BY created_at, name").unwrap();
        s.query_map([], machine_host_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn machine_host(&self, name: &str) -> Option<MachineHost> {
        self.c().query_row("SELECT * FROM machine_hosts WHERE name = ?", [name], machine_host_row).optional().ok().flatten()
    }

    /// Records a host the first time it is configured; its address may change later,
    /// its certificate may not.
    pub fn machine_host_add(&self, name: &str, url: &str, fingerprint: &str) -> MachineHost {
        let c = self.c();
        c.execute(
            "INSERT INTO machine_hosts (name, url, fingerprint, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET url = ?2",
            params![name, url, fingerprint, now()],
        )
        .unwrap();
        c.query_row("SELECT * FROM machine_hosts WHERE name = ?", [name], machine_host_row).unwrap()
    }

    /// It answered: up again, if it was down. Returns whether it was down.
    pub fn machine_host_answered(&self, name: &str) -> bool {
        let c = self.c();
        let was_down = c
            .query_row("SELECT state = 'down' FROM machine_hosts WHERE name = ?", [name], |r| r.get::<_, bool>(0))
            .unwrap_or(false);
        c.execute(
            "UPDATE machine_hosts SET state = 'up', failing_since = NULL, last_error = NULL, down_at = NULL, checked_at = ?1
             WHERE name = ?2 AND state != 'lost'",
            params![now(), name],
        )
        .unwrap();
        was_down
    }

    /// It didn't answer: since when it hasn't.
    pub fn machine_host_failed(&self, name: &str, error: &str) -> Option<i64> {
        let c = self.c();
        c.execute(
            "UPDATE machine_hosts SET failing_since = COALESCE(failing_since, ?1), last_error = ?2, checked_at = ?1
             WHERE name = ?3 AND state != 'lost'",
            params![now(), crate::audit::clip(error, 300), name],
        )
        .unwrap();
        c.query_row("SELECT failing_since FROM machine_hosts WHERE name = ?", [name], |r| r.get(0)).ok().flatten()
    }

    /// Up to down, once. Returns whether this call did it.
    pub fn machine_host_down(&self, name: &str) -> bool {
        self.c()
            .execute("UPDATE machine_hosts SET state = 'down', down_at = ? WHERE name = ? AND state = 'up' AND failing_since IS NOT NULL", params![now(), name])
            .unwrap_or(0)
            == 1
    }

    /// Declared lost, once. Returns whether this call did it.
    pub fn machine_host_lost(&self, name: &str, by: Option<&str>) -> bool {
        self.c()
            .execute("UPDATE machine_hosts SET state = 'lost', lost_at = ?, lost_by = ? WHERE name = ? AND state != 'lost'", params![now(), by, name])
            .unwrap_or(0)
            == 1
    }

    /// Drained, once (ADR 0081). Returns whether this call did it.
    pub fn machine_host_drain(&self, name: &str, by: Option<&str>, reason: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machine_hosts SET drained_at = ?, drained_by = ?, drain_reason = ? WHERE name = ? AND drained_at IS NULL",
                params![now(), by, reason, name],
            )
            .unwrap_or(0)
            == 1
    }

    /// Open to new machines again. Returns whether it was drained.
    pub fn machine_host_undrain(&self, name: &str) -> bool {
        self.c()
            .execute("UPDATE machine_hosts SET drained_at = NULL, drained_by = NULL, drain_reason = NULL WHERE name = ? AND drained_at IS NOT NULL", [name])
            .unwrap_or(0)
            == 1
    }

    /// Dedicated to `team`, if it is shared now (ADR 0166). Returns whether this call did it.
    pub fn machine_host_dedicate(&self, name: &str, team: &str, by: Option<&str>, reason: Option<&str>) -> bool {
        self.c()
            .execute(
                "UPDATE machine_hosts SET dedicated_team = ?, dedicated_at = ?, dedicated_by = ?, dedication_reason = ? WHERE name = ? AND dedicated_team IS NULL",
                params![team, now(), by, reason, name],
            )
            .unwrap_or(0)
            == 1
    }

    /// Shared again. Returns whether it was dedicated.
    pub fn machine_host_share(&self, name: &str) -> bool {
        self.c()
            .execute(
                "UPDATE machine_hosts SET dedicated_team = NULL, dedicated_at = NULL, dedicated_by = NULL, dedication_reason = NULL WHERE name = ? AND dedicated_team IS NOT NULL",
                [name],
            )
            .unwrap_or(0)
            == 1
    }

    /// Gives a machine its new provider id, as after a move to another host.
    pub fn set_machine_provider_id(&self, machine_id: &str, provider_id: &str) {
        self.c().execute("UPDATE machines SET provider_id = ?, updated_at = ? WHERE id = ?", params![provider_id, now(), machine_id]).unwrap();
    }

    /// The firewall a machine is behind now, as after a move to a host that has only today's.
    pub fn set_machine_firewall_id(&self, machine_id: &str, firewall_id: Option<&str>) {
        self.c().execute("UPDATE machines SET firewall_id = ?, updated_at = ? WHERE id = ?", params![firewall_id, now(), machine_id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_host_failing_backdate(&self, name: &str, ms: i64) {
        self.c().execute("UPDATE machine_hosts SET failing_since = failing_since - ?1 WHERE name = ?2", params![ms, name]).unwrap();
    }

    pub fn machine_restore(&self, id: &str) -> Option<MachineRestore> {
        self.c().query_row("SELECT * FROM machine_restores WHERE id = ?", [id], machine_restore_row).optional().ok().flatten()
    }

    /// The machine's restore underway, if any.
    pub fn machine_restoring(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? AND state IN ('importing', 'replacing', 'enrolling')",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The machine's newest restore.
    pub fn machine_last_restore(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The machine's newest restore that finished.
    pub fn machine_last_restore_done(&self, machine_id: &str) -> Option<MachineRestore> {
        self.c()
            .query_row(
                "SELECT * FROM machine_restores WHERE machine_id = ? AND state = 'done' ORDER BY finished_at DESC, id DESC LIMIT 1",
                [machine_id],
                machine_restore_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The newest restores of every machine, newest first.
    pub fn machine_restores_recent(&self, limit: u32) -> Vec<MachineRestore> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_restores ORDER BY created_at DESC, id DESC LIMIT ?").unwrap();
        s.query_map([limit], machine_restore_row).unwrap().filter_map(Result::ok).collect()
    }

    /// How long a finished restore took (ADR 0074).
    /// Moves an enrolling restore to done with how long it took, in one write so a restart
    /// can't leave it done without its timing. Returns whether it moved.
    pub fn machine_restore_done(&self, id: &str, duration_ms: i64) -> bool {
        self.c()
            .execute(
                "UPDATE machine_restores SET state = 'done', finished_at = ?1, duration_ms = ?2 WHERE id = ?3 AND state = 'enrolling'",
                params![now(), duration_ms, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Marks a restore as past its RTO, once. Returns whether this call did.
    pub fn machine_restore_rto_exceeded(&self, id: &str) -> bool {
        self.c()
            .execute("UPDATE machine_restores SET rto_exceeded_at = ? WHERE id = ? AND rto_exceeded_at IS NULL", params![now(), id])
            .unwrap_or(0)
            == 1
    }

    // RPO breaches (ADR 0074)

    /// Opens a breach for the machine, unless one is open. Returns it if this call did.
    pub fn machine_rpo_breach_start(&self, id: &str, m: &Machine, rpo_ms: i64, covered_since: i64) -> Option<MachineRpoBreach> {
        let made = self
            .c()
            .execute(
                "INSERT OR IGNORE INTO machine_rpo_breaches (id, machine_id, user_id, tier, rpo_ms, covered_since, breached_at, detected_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![id, m.id, m.user_id, m.tier, rpo_ms, covered_since, covered_since + rpo_ms, now()],
            )
            .unwrap_or(0)
            == 1;
        if made { self.c().query_row("SELECT * FROM machine_rpo_breaches WHERE id = ?", [id], machine_rpo_breach_row).ok() } else { None }
    }

    /// Ends an open breach. Returns whether this call did.
    pub fn machine_rpo_breach_end(&self, id: &str, reason: &str) -> bool {
        self.c()
            .execute("UPDATE machine_rpo_breaches SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL", params![now(), reason, id])
            .unwrap_or(0)
            == 1
    }

    /// Every open breach.
    pub fn machine_rpo_breaches_open(&self) -> Vec<MachineRpoBreach> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_rpo_breaches WHERE ended_at IS NULL ORDER BY breached_at, id").unwrap();
        s.query_map([], machine_rpo_breach_row).unwrap().filter_map(Result::ok).collect()
    }

    /// The machine's open breach, if any.
    pub fn machine_rpo_breach_open(&self, machine_id: &str) -> Option<MachineRpoBreach> {
        self.c()
            .query_row("SELECT * FROM machine_rpo_breaches WHERE machine_id = ? AND ended_at IS NULL", [machine_id], machine_rpo_breach_row)
            .ok()
    }

    /// The newest breaches, open or not, newest first.
    pub fn machine_rpo_breaches(&self, limit: u32) -> Vec<MachineRpoBreach> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_rpo_breaches ORDER BY breached_at DESC, id DESC LIMIT ?").unwrap();
        s.query_map([limit], machine_rpo_breach_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Every restore in `state`.
    pub fn machine_restores_in(&self, state: &str) -> Vec<MachineRestore> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM machine_restores WHERE state = ? ORDER BY created_at, id").unwrap();
        s.query_map([state], machine_restore_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Moves a restore from one of `from` to `to`. Returns whether it moved.
    pub fn machine_restore_move(&self, id: &str, from: &[&str], to: &str, error: Option<&str>) -> bool {
        let at = now();
        let states = from.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ");
        self.c()
            .execute(
                &format!(
                    "UPDATE machine_restores SET state = ?1, error = COALESCE(?2, error),
                     replaced_at = CASE WHEN ?1 = 'enrolling' THEN ?3 ELSE replaced_at END,
                     finished_at = CASE WHEN ?1 IN ('done', 'failed') THEN ?3 ELSE finished_at END
                     WHERE id = ?4 AND state IN ({states})"
                ),
                params![to, error.map(|e| crate::audit::clip(e, 500)), at, id],
            )
            .unwrap_or(0)
            == 1
    }

    /// Whether files that exist only on the machine may be lost if it is wiped: it is
    /// assigned, or ever was, or a Bot ever ran there (from the audit log).
    pub fn machine_may_hold_work(&self, machine_id: &str) -> bool {
        self.c()
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM machines WHERE id = ?1 AND assigned_at IS NOT NULL)
                 OR EXISTS (SELECT 1 FROM audit_events WHERE action = 'placement.assigned' AND target_type = 'machine' AND target_id = ?1)
                 OR EXISTS (SELECT 1 FROM audit_events WHERE action = 'bot.run_routed' AND json_extract(details, '$.machine') = ?1)",
                [machine_id],
                |r| r.get(0),
            )
            .unwrap_or(true)
    }

    #[cfg(test)]
    pub fn machine_tokens_unused(&self, machine_id: &str) -> i64 {
        self.c()
            .query_row("SELECT COUNT(*) FROM machine_tokens WHERE machine_id = ? AND used_at IS NULL AND revoked_at IS NULL", [machine_id], |r| r.get(0))
            .unwrap()
    }

    #[cfg(test)]
    pub fn machine_rebuild_due_now(&self, machine_id: &str) {
        self.c().execute("UPDATE machines SET rebuild_next_at = ? WHERE id = ?", params![now() - 1, machine_id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_rebuild_backdate(&self, machine_id: &str, ms: i64) {
        self.c()
            .execute(
                "UPDATE machines SET rebuild_sent_at = rebuild_sent_at - ?1, rebuild_at = rebuild_at - ?1, enroll_by = enroll_by - ?1,
                 enrolled_at = enrolled_at - ?1 WHERE id = ?2",
                params![ms, machine_id],
            )
            .unwrap();
    }

    #[cfg(test)]
    pub fn machine_backup_backdate(&self, id: &str, ms: i64) {
        self.c()
            .execute("UPDATE machine_backups SET created_at = created_at - ?1, expires_at = expires_at - ?1 WHERE id = ?2", params![ms, id])
            .unwrap();
    }

    #[cfg(test)]
    pub fn machine_restore_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machine_restores SET created_at = created_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_restore_replaced_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machine_restores SET replaced_at = replaced_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_enrolled_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machines SET enrolled_at = enrolled_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_backdate(&self, id: &str, ms: i64) {
        self.c().execute("UPDATE machines SET created_at = created_at - ?1 WHERE id = ?2", params![ms, id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_upgrade_backdate(&self, machine_id: &str, ms: i64) {
        self.c()
            .execute("UPDATE machines SET upgrade_sent_at = upgrade_sent_at - ? WHERE id = ?", params![ms, machine_id])
            .unwrap();
    }
}

/// A team account (ADR 0087).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub name: String,
    /// Each member gets a machine of their own when they join, if the control plane is on.
    pub machines: bool,
    /// Where its members' machines and their backups live (ADR 0117). None: the
    /// server's default.
    pub region: Option<String>,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub user_id: String,
    pub team_id: String,
    /// "owner", "admin" or "member".
    pub role: String,
    pub joined_at: i64,
    pub added_by: Option<String>,
    /// A custom role given to them within the team (ADR 0123). None once its end has
    /// passed, before the sweep takes it away (ADR 0197).
    #[serde(skip)]
    pub role_id: Option<String>,
    /// When `role_id` ends (ADR 0197). None: it doesn't.
    #[serde(skip)]
    pub role_expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamInvite {
    pub id: String,
    pub team_id: String,
    pub email: String,
    pub role: String,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub expires_at: i64,
}

/// A machine a team gave one of its members. `released_at`: they left, so it was
/// suspended; it's destroyed at `release_at` unless they join a team again first.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMachine {
    pub machine_id: String,
    pub team_id: String,
    pub user_id: String,
    pub created_at: i64,
    pub released_at: Option<i64>,
    pub release_at: Option<i64>,
}

/// What a residency pin is on (ADR 0129).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PinOn {
    User,
    Team,
}

impl PinOn {
    pub fn as_str(self) -> &'static str {
        match self {
            PinOn::User => "user",
            PinOn::Team => "team",
        }
    }
}

/// A contractual residency pin (ADR 0129): the user's or team's data stays in `region`,
/// under the agreement `reference` names, until an admin unpins it with a reason.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResidencyPin {
    pub subject_type: PinOn,
    pub subject_id: String,
    pub region: String,
    pub reference: String,
    pub pinned_by: Option<String>,
    pub pinned_at: i64,
    /// A user's pin kept from their team's when they left it (ADR 0171): that team's id.
    pub kept_from: Option<String>,
}

fn residency_pin_row(r: &Row) -> rusqlite::Result<ResidencyPin> {
    let kind: String = r.get("subject_type")?;
    Ok(ResidencyPin {
        subject_type: if kind == "team" { PinOn::Team } else { PinOn::User },
        subject_id: r.get("subject_id")?,
        region: r.get("region")?,
        reference: r.get("reference")?,
        pinned_by: r.get("pinned_by")?,
        pinned_at: r.get("pinned_at")?,
        kept_from: r.get("kept_from")?,
    })
}

fn team_row(r: &Row) -> rusqlite::Result<Team> {
    Ok(Team {
        id: r.get("id")?,
        name: r.get("name")?,
        machines: r.get("machines")?,
        region: r.get("region")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        updated_at: r.get("updated_at")?,
    })
}

fn team_member_row(r: &Row) -> rusqlite::Result<TeamMember> {
    let (role_id, role_expires_at) = held_until(r.get("role_id")?, r.get("role_expires_at")?);
    Ok(TeamMember {
        user_id: r.get("user_id")?,
        team_id: r.get("team_id")?,
        role: r.get("role")?,
        joined_at: r.get("joined_at")?,
        added_by: r.get("added_by")?,
        role_id,
        role_expires_at,
    })
}

fn team_invite_row(r: &Row) -> rusqlite::Result<TeamInvite> {
    Ok(TeamInvite {
        id: r.get("id")?,
        team_id: r.get("team_id")?,
        email: r.get("email")?,
        role: r.get("role")?,
        created_at: r.get("created_at")?,
        created_by: r.get("created_by")?,
        expires_at: r.get("expires_at")?,
    })
}

fn team_machine_row(r: &Row) -> rusqlite::Result<TeamMachine> {
    Ok(TeamMachine {
        machine_id: r.get("machine_id")?,
        team_id: r.get("team_id")?,
        user_id: r.get("user_id")?,
        created_at: r.get("created_at")?,
        released_at: r.get("released_at")?,
        release_at: r.get("release_at")?,
    })
}

impl Db {
    /// TEAMS=on (ADR 0087): people in no team are a team of one for sharing.
    pub fn set_teams_strict(&self, on: bool) {
        self.2.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn teams_strict(&self) -> bool {
        self.2.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether a Bot `owner` shares, or grants, can reach `user` (ADR 0087): people in
    /// the same team, or two people in no team unless TEAMS=on. The owner always.
    pub fn same_team(&self, owner: &str, user: &str) -> bool {
        owner == user || crate::acl::reaches(self.teams_strict(), self.team_id_of(owner).as_deref(), self.team_id_of(user).as_deref())
    }

    pub fn create_team(&self, name: &str, by: Option<&str>) -> Team {
        let id = format!("t{}", crate::random_hex(5));
        let at = now();
        self.c()
            .execute(
                "INSERT INTO teams (id, name, machines, created_at, created_by, updated_at) VALUES (?1, ?2, 1, ?3, ?4, ?3)",
                params![id, name, at, by],
            )
            .unwrap();
        self.team(&id).unwrap()
    }

    pub fn team(&self, id: &str) -> Option<Team> {
        self.c().query_row("SELECT * FROM teams WHERE id = ?", [id], team_row).optional().ok().flatten()
    }

    pub fn teams(&self) -> Vec<Team> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM teams ORDER BY created_at, id").unwrap();
        s.query_map([], team_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn update_team(&self, id: &str, name: Option<&str>, machines: Option<bool>) {
        let c = self.c();
        if let Some(n) = name {
            c.execute("UPDATE teams SET name = ?1, updated_at = ?2 WHERE id = ?3", params![n, now(), id]).unwrap();
        }
        if let Some(m) = machines {
            c.execute("UPDATE teams SET machines = ?1, updated_at = ?2 WHERE id = ?3", params![m, now(), id]).unwrap();
        }
    }

    /// Sets or clears the team's data region (ADR 0117).
    pub fn set_team_region(&self, id: &str, region: Option<&str>) -> bool {
        self.c().execute("UPDATE teams SET region = ?1, updated_at = ?2 WHERE id = ?3", params![region, now(), id]).unwrap_or(0) > 0
    }

    /// The residency pin on a user or a team (ADR 0129), if there is one.
    pub fn residency_pin(&self, kind: PinOn, id: &str) -> Option<ResidencyPin> {
        let c = self.c();
        c.query_row("SELECT * FROM residency_pins WHERE subject_type = ?1 AND subject_id = ?2", params![kind.as_str(), id], residency_pin_row)
            .optional()
            .unwrap_or(None)
    }

    /// Every residency pin, oldest first.
    pub fn residency_pins(&self) -> Vec<ResidencyPin> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM residency_pins ORDER BY pinned_at, subject_type, subject_id").unwrap();
        s.query_map([], residency_pin_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Audit events from `from` (inclusive) to `to` (exclusive), unix ms, that bear on
    /// residency pins (ADR 0155): those whose action is one of `actions`, and
    /// `harness.invoked` only for runs held to a region. Oldest first, at most `limit`.
    pub fn residency_audit(&self, from: i64, to: i64, actions: &[&str], limit: i64) -> rusqlite::Result<Vec<AuditEvent>> {
        use rusqlite::types::Value as V;
        let marks = vec!["?"; actions.len().max(1)].join(", ");
        let sql = format!(
            "SELECT * FROM audit_events WHERE at >= ? AND at < ? AND (action IN ({marks})
               OR (action = 'harness.invoked' AND json_valid(details) AND json_extract(details, '$.residency') IS NOT NULL))
             ORDER BY id ASC LIMIT ?"
        );
        let mut args = vec![V::Integer(from), V::Integer(to)];
        args.extend(actions.iter().map(|a| V::Text(a.to_string())));
        if actions.is_empty() {
            args.push(V::Null);
        }
        args.push(V::Integer(limit));
        let c = self.c();
        let mut s = c.prepare(&sql)?;
        let rows = s.query_map(rusqlite::params_from_iter(args), audit_row)?;
        rows.collect()
    }

    /// Sets the user's or team's own data region to `region` and pins them there (or
    /// replaces the pin's reference), both or neither. Err: they're gone, or the write failed.
    pub fn pin_residency(&self, kind: PinOn, id: &str, region: &str, reference: &str, by: Option<&str>) -> Result<(), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        let table = match kind {
            PinOn::User => "users",
            PinOn::Team => "teams",
        };
        let at = now();
        let n = tx
            .execute(&format!("UPDATE {table} SET region = ?1, updated_at = CASE WHEN region IS ?1 THEN updated_at ELSE ?2 END WHERE id = ?3"), params![region, at, id])
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err(format!("no {} {id}", kind.as_str()));
        }
        tx.execute(
            "INSERT INTO residency_pins (subject_type, subject_id, region, reference, pinned_by, pinned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (subject_type, subject_id) DO UPDATE SET region = excluded.region, reference = excluded.reference, pinned_by = excluded.pinned_by, pinned_at = excluded.pinned_at, kept_from = NULL",
            params![kind.as_str(), id, region, reference, by, at],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Ends a pin. Ok(false): there was none.
    pub fn unpin_residency(&self, kind: PinOn, id: &str) -> Result<bool, String> {
        self.c()
            .execute("DELETE FROM residency_pins WHERE subject_type = ?1 AND subject_id = ?2", params![kind.as_str(), id])
            .map(|n| n > 0)
            .map_err(|e| e.to_string())
    }

    /// Ends `user_id`'s pin if it is still one kept from a team (ADR 0171) and they have
    /// no machine that isn't destroyed and no machine backup not yet deleted, all in one
    /// statement (ADR 0205). Ok(Some): the pin that ended.
    pub fn end_kept_pin(&self, user_id: &str) -> Result<Option<ResidencyPin>, String> {
        self.c()
            .query_row(
                "DELETE FROM residency_pins WHERE subject_type = 'user' AND subject_id = ?1 AND kept_from IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM machines WHERE user_id = ?1 AND state <> 'destroyed')
                   AND NOT EXISTS (SELECT 1 FROM machine_backups WHERE user_id = ?1 AND state <> 'deleted')
                 RETURNING *",
                [user_id],
                residency_pin_row,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Teams this server deleted and that aren't here now, with when each was (ADR 0236).
    /// Read from its own audit log, so only as far back as AUDIT_RETENTION_DAYS keeps it.
    pub fn deleted_teams(&self) -> Vec<(String, i64)> {
        let c = self.c();
        let mut s = c
            .prepare(
                "SELECT target_id, MAX(at) FROM audit_events
                 WHERE action = 'team.deleted' AND target_type = 'team' AND outcome = 'success' AND target_id IS NOT NULL
                   AND target_id NOT IN (SELECT id FROM teams)
                 GROUP BY target_id ORDER BY target_id",
            )
            .unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    /// Deletes the team, its invites and its residency pin (ADR 0129). Its members must
    /// have left first.
    pub fn delete_team(&self, id: &str) -> bool {
        let c = self.c();
        let gone = c.execute("DELETE FROM teams WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM team_members WHERE team_id = ?1)", [id]).unwrap() > 0;
        if gone {
            let _ = c.execute("DELETE FROM residency_pins WHERE subject_type = 'team' AND subject_id = ?1", [id]);
        }
        gone
    }

    pub fn team_member(&self, user_id: &str) -> Option<TeamMember> {
        self.c().query_row("SELECT * FROM team_members WHERE user_id = ?", [user_id], team_member_row).optional().ok().flatten()
    }

    /// The user's team: as a member, or as the team's service account (ADR 0143), which
    /// shares and is shared with as one of the team, though it isn't on its list.
    pub fn team_id_of(&self, user_id: &str) -> Option<String> {
        self.c().query_row(&format!("SELECT team_id FROM ({TEAM_OF}) WHERE user_id = ?"), [user_id], |r| r.get(0)).optional().ok().flatten()
    }

    /// Every member's team, by user id, with teams' service accounts.
    pub fn team_ids(&self) -> HashMap<String, String> {
        let c = self.c();
        let mut s = c.prepare(TEAM_OF).unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(Result::ok).collect()
    }

    pub fn team_members(&self, team_id: &str) -> Vec<TeamMember> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM team_members WHERE team_id = ? ORDER BY joined_at, user_id").unwrap();
        s.query_map([team_id], team_member_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Adds `user_id` to the team. False if they're in a team already, this one included.
    pub fn add_team_member(&self, team_id: &str, user_id: &str, role: &str, by: Option<&str>) -> bool {
        self.c()
            .execute(
                "INSERT OR IGNORE INTO team_members (user_id, team_id, role, joined_at, added_by) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![user_id, team_id, role, now(), by],
            )
            .unwrap()
            > 0
    }

    /// Changes a member's role, unless it would leave the team without an owner. One
    /// statement, so two owners demoting themselves at once can't both succeed.
    pub fn set_team_role(&self, team_id: &str, user_id: &str, role: &str) -> bool {
        self.c()
            .execute(
                "UPDATE team_members SET role = ?1 WHERE team_id = ?2 AND user_id = ?3
                 AND (?1 = 'owner' OR role != 'owner' OR (SELECT COUNT(*) FROM team_members WHERE team_id = ?2 AND role = 'owner') > 1)",
                params![role, team_id, user_id],
            )
            .unwrap()
            > 0
    }

    /// Takes a member off a team, keeping no pin.
    #[cfg(test)]
    pub fn remove_team_member(&self, team_id: &str, user_id: &str, keep_owner: bool) -> bool {
        self.remove_team_member_keeping_pin(team_id, user_id, keep_owner, false).unwrap().0
    }

    /// Makes every new residency pin fail to save, or stops that.
    #[cfg(test)]
    pub fn fail_pin_saves(&self, on: bool) {
        let sql = if on { "CREATE TRIGGER pins_full BEFORE INSERT ON residency_pins BEGIN SELECT RAISE(ABORT, 'disk full'); END;" } else { "DROP TRIGGER pins_full;" };
        self.c().execute_batch(sql).unwrap();
    }

    /// Takes a member off a team. With `keep_owner`, not its last owner while others
    /// remain, in the same statement. With `keep_pin`, in the same transaction, the
    /// team's residency pin is copied to the leaver as their own (ADR 0171), with their
    /// own data region set to it, unless they have a pin of their own already. Ok:
    /// whether they were taken off, and the pin kept. Err: nothing changed.
    pub fn remove_team_member_keeping_pin(&self, team_id: &str, user_id: &str, keep_owner: bool, keep_pin: bool) -> Result<(bool, Option<ResidencyPin>), String> {
        let c = self.c();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        let gone = tx
            .execute(
                "DELETE FROM team_members WHERE team_id = ?1 AND user_id = ?2
                 AND (NOT ?3 OR role != 'owner'
                      OR (SELECT COUNT(*) FROM team_members WHERE team_id = ?1 AND role = 'owner') > 1
                      OR (SELECT COUNT(*) FROM team_members WHERE team_id = ?1) = 1)",
                params![team_id, user_id, keep_owner],
            )
            .map_err(|e| e.to_string())?
            > 0;
        if !gone {
            return Ok((false, None));
        }
        let pin = |kind: &str, id: &str| {
            tx.query_row("SELECT * FROM residency_pins WHERE subject_type = ?1 AND subject_id = ?2", params![kind, id], residency_pin_row).optional().map_err(|e| e.to_string())
        };
        let kept = match (keep_pin, pin("team", team_id)?, pin("user", user_id)?) {
            (true, Some(team), None) => {
                let at = now();
                tx.execute("UPDATE users SET region = ?1, updated_at = CASE WHEN region IS ?1 THEN updated_at ELSE ?2 END WHERE id = ?3", params![team.region, at, user_id])
                    .map_err(|e| e.to_string())?;
                tx.execute(
                    "INSERT INTO residency_pins (subject_type, subject_id, region, reference, pinned_by, pinned_at, kept_from) VALUES ('user', ?1, ?2, ?3, ?4, ?5, ?6)",
                    params![user_id, team.region, team.reference, team.pinned_by, at, team_id],
                )
                .map_err(|e| e.to_string())?;
                pin("user", user_id)?
            }
            _ => None,
        };
        tx.commit().map_err(|e| e.to_string())?;
        Ok((true, kept))
    }

    /// Invites `email`, or renews a pending invite with the new role and expiry.
    pub fn put_team_invite(&self, team_id: &str, email: &str, role: &str, by: Option<&str>, expires_at: i64) -> TeamInvite {
        let id = format!("ti{}", crate::random_hex(8));
        let c = self.c();
        c.execute(
            "INSERT INTO team_invites (id, team_id, email, role, created_at, created_by, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(team_id, email) DO UPDATE SET role = ?4, created_at = ?5, created_by = ?6, expires_at = ?7",
            params![id, team_id, email, role, now(), by, expires_at],
        )
        .unwrap();
        c.query_row("SELECT * FROM team_invites WHERE team_id = ? AND email = ?", [team_id, email], team_invite_row).unwrap()
    }

    pub fn team_invite(&self, id: &str) -> Option<TeamInvite> {
        self.c().query_row("SELECT * FROM team_invites WHERE id = ?", [id], team_invite_row).optional().ok().flatten()
    }

    pub fn team_invites(&self, team_id: &str) -> Vec<TeamInvite> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM team_invites WHERE team_id = ? ORDER BY created_at, id").unwrap();
        s.query_map([team_id], team_invite_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn invites_for_email(&self, email: &str) -> Vec<TeamInvite> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM team_invites WHERE email = ? ORDER BY created_at, id").unwrap();
        s.query_map([email], team_invite_row).unwrap().filter_map(Result::ok).collect()
    }

    pub fn delete_team_invite(&self, id: &str) -> bool {
        self.c().execute("DELETE FROM team_invites WHERE id = ?", [id]).unwrap() > 0
    }

    pub fn delete_team_invites_for(&self, team_id: &str, email: &str) {
        self.c().execute("DELETE FROM team_invites WHERE team_id = ? AND email = ?", [team_id, email]).unwrap();
    }

    /// Notes that `team_id` gave `user_id` the machine, or gives it back to a team after
    /// they left one: it's no longer released.
    pub fn team_machine_mark(&self, machine_id: &str, team_id: &str, user_id: &str) {
        self.c()
            .execute(
                "INSERT INTO team_machines (machine_id, team_id, user_id, created_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(machine_id) DO UPDATE SET team_id = ?2, user_id = ?3, released_at = NULL, release_at = NULL",
                params![machine_id, team_id, user_id, now()],
            )
            .unwrap();
    }

    pub fn team_machine(&self, machine_id: &str) -> Option<TeamMachine> {
        self.c().query_row("SELECT * FROM team_machines WHERE machine_id = ?", [machine_id], team_machine_row).optional().ok().flatten()
    }

    pub fn team_machines(&self) -> Vec<TeamMachine> {
        let c = self.c();
        let mut s = c.prepare("SELECT * FROM team_machines ORDER BY created_at, machine_id").unwrap();
        s.query_map([], team_machine_row).unwrap().filter_map(Result::ok).collect()
    }

    /// Releases `machine_id` if `team_id` still holds it: another team may have taken it.
    pub fn team_machine_release(&self, machine_id: &str, team_id: &str, release_at: i64) -> bool {
        self.c()
            .execute(
                "UPDATE team_machines SET released_at = ?1, release_at = ?2 WHERE machine_id = ?3 AND team_id = ?4 AND released_at IS NULL",
                params![now(), release_at, machine_id, team_id],
            )
            .unwrap()
            > 0
    }

    pub fn team_machine_forget(&self, machine_id: &str) {
        self.c().execute("DELETE FROM team_machines WHERE machine_id = ?", [machine_id]).unwrap();
    }

    /// Marks `machine_id` as off because `user_id` was disabled (ADR 0124). The first
    /// hold stays: a second disable doesn't move when or how it began.
    pub fn hold_for_disable(&self, machine_id: &str, user_id: &str, via: &str) {
        self.c()
            .execute(
                "INSERT OR IGNORE INTO machine_disable_holds (machine_id, user_id, via, held_at) VALUES (?1, ?2, ?3, ?4)",
                params![machine_id, user_id, via, now()],
            )
            .unwrap();
    }

    /// Every disable hold: (machine id, user id, via).
    pub fn disable_holds(&self) -> Vec<(String, String, String)> {
        let c = self.c();
        let mut s = c.prepare("SELECT machine_id, user_id, via FROM machine_disable_holds ORDER BY held_at, machine_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(Result::ok).collect()
    }

    pub fn disable_hold(&self, machine_id: &str) -> bool {
        self.c().query_row("SELECT 1 FROM machine_disable_holds WHERE machine_id = ?", [machine_id], |_| Ok(())).optional().ok().flatten().is_some()
    }

    /// Ends the hold on `machine_id`. Whether there was one.
    pub fn drop_disable_hold(&self, machine_id: &str) -> bool {
        self.c().execute("DELETE FROM machine_disable_holds WHERE machine_id = ?", [machine_id]).unwrap() > 0
    }

    #[cfg(test)]
    pub fn team_machine_backdate(&self, machine_id: &str, ms: i64) {
        self.c().execute("UPDATE team_machines SET release_at = release_at - ?1 WHERE machine_id = ?2", params![ms, machine_id]).unwrap();
    }

    #[cfg(test)]
    pub fn machine_set_enrolled(&self, machine_id: &str) {
        self.c().execute("UPDATE machines SET enrollment = 'enrolled' WHERE id = ?", [machine_id]).unwrap();
    }
}

/// One day's customer health score (ADR 0157).
#[derive(Clone, Debug, PartialEq)]
pub struct HealthScoreDay {
    /// The UTC date, `YYYY-MM-DD`.
    pub day: String,
    pub at: i64,
    pub window_days: i64,
    pub score: Option<u32>,
    pub band: String,
    /// Each signal's status by id, as JSON.
    pub signals: String,
}

impl Db {
    /// Records a day's score. False if that day already has one: the first of the day stays.
    pub fn health_score_record(&self, d: &HealthScoreDay) -> rusqlite::Result<bool> {
        self.c()
            .execute(
                "INSERT OR IGNORE INTO health_scores (day, at, window_days, score, band, signals) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![d.day, d.at, d.window_days, d.score, d.band, d.signals],
            )
            .map(|n| n > 0)
    }

    /// The days from `from` (`YYYY-MM-DD`), oldest first.
    pub fn health_scores_since(&self, from: &str) -> rusqlite::Result<Vec<HealthScoreDay>> {
        let c = self.c();
        let mut s = c.prepare("SELECT day, at, window_days, score, band, signals FROM health_scores WHERE day >= ? ORDER BY day")?;
        s.query_map([from], |r| Ok(HealthScoreDay { day: r.get(0)?, at: r.get(1)?, window_days: r.get(2)?, score: r.get(3)?, band: r.get(4)?, signals: r.get(5)? }))?.collect()
    }

    /// Deletes the days before `before` (`YYYY-MM-DD`); how many went.
    pub fn health_scores_prune(&self, before: &str) -> rusqlite::Result<usize> {
        self.c().execute("DELETE FROM health_scores WHERE day < ?", [before])
    }
}

/// How many schema changes this botd knows. A database whose `PRAGMA user_version` is past
/// it was made by a newer botd.
pub fn schema_version() -> i64 {
    MIGRATIONS.len() as i64
}

#[cfg(test)]
impl Db {
    /// A database encrypted under `key` (ADR 0116), without setting the process's key.
    pub fn open_keyed(path: &std::path::Path, key: &crate::database_encryption::DbKey) -> Db {
        Db::on(crate::database_encryption::open_with(path, Some(key)).unwrap()).unwrap()
    }

    /// Moves when a pending request for a role lapses to `at`, as the clock passing it would (ADR 0209).
    pub fn move_role_request_lapse(&self, id: &str, at: i64) {
        self.c().execute("UPDATE role_requests SET expires_at = ?1 WHERE id = ?2", params![at, id]).unwrap();
    }

    /// Moves the end of `user_id`'s custom role, across the server and in their team, to
    /// `at`, as the clock passing it would (ADR 0197).
    pub fn move_role_end(&self, user_id: &str, at: i64) {
        let c = self.c();
        c.execute("UPDATE users SET role_expires_at = ?1 WHERE id = ?2 AND role_expires_at IS NOT NULL", params![at, user_id]).unwrap();
        c.execute("UPDATE team_members SET role_expires_at = ?1 WHERE user_id = ?2 AND role_expires_at IS NOT NULL", params![at, user_id]).unwrap();
    }

    /// The end stored for `user_id`'s custom role across the server and in their team, ended or not.
    pub fn stored_role_ends(&self, user_id: &str) -> (Option<i64>, Option<i64>) {
        let c = self.c();
        let org = c.query_row("SELECT role_expires_at FROM users WHERE id = ?", [user_id], |r| r.get(0)).unwrap();
        let team = c.query_row("SELECT role_expires_at FROM team_members WHERE user_id = ?", [user_id], |r| r.get(0)).optional().unwrap().flatten();
        (org, team)
    }
}

#[cfg(test)]
pub fn temp_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("superbot-test-{tag}-{}", crate::short_id()));
    crate::paths::root(&dir.to_string_lossy()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn all_events(db: &Db) -> Vec<AuditEvent> {
        db.audit_events(&audit::Filter::default(), 1000, false)
    }

    #[test]
    fn saml_role_grants_only_ever_take_back_what_they_gave() {
        let db = Db::open(&temp_path("saml-roles").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Readonly).unwrap();
        let b = db.create_user(None, Some("b@example.com"), "B", Role::Member).unwrap();
        let boss = db.create_user(None, Some("boss@example.com"), "Boss", Role::Admin).unwrap();
        let r = db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
        let hand = db.create_custom_role("Hand", "", Role::Member, &["users.manage"], None, None).unwrap();
        let ops = db.create_custom_role("Ops", "", Role::Member, &["bots.manage"], None, None).unwrap();
        assert!(matches!(db.create_saml_role_mapping("corp", "Ops", &ops.id, None), Err(ScimRoleMapError::Reaches(p)) if p == ["bots.manage"]), "never a role that reaches admins");
        assert!(matches!(db.create_saml_role_mapping("corp", "Ghosts", "rnone", None), Err(ScimRoleMapError::Gone)));
        let m = db.create_saml_role_mapping("corp", "Auditors", &r.id, Some("admin")).unwrap();
        assert!(matches!(db.create_saml_role_mapping("corp", "Auditors", &hand.id, None), Err(ScimRoleMapError::Taken)), "one role per group");
        let okta = db.create_saml_role_mapping("okta", "Auditors", &r.id, None).unwrap();
        assert!(matches!(db.delete_custom_role(&r.id), Err(RoleError::Mapped(2))));
        assert!(matches!(db.update_custom_role(&r.id, None, None, None, Some(&["audit.view", "machines.manage"]), None, None), Err(RoleError::Reaches { via: "saml", .. })), "checked as it's saved");

        assert!(db.grant_saml_role(&m, &a.id));
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Member, Some(r.id.clone())));
        assert!(!db.grant_saml_role(&m, &a.id), "once");
        assert!(!db.grant_saml_role(&m, &boss.id), "never an admin");
        assert!(!db.grant_saml_role(&m, crate::users::OPERATOR), "never the owner account");
        assert!(db.give_user_custom_role(&b.id, &hand.id).is_some());
        assert!(!db.grant_saml_role(&m, &b.id), "never over a role given by hand");
        assert_eq!(db.saml_role_grants(&m.id).len(), 1);
        let back = db.revoke_saml_role(&m, &a.id).unwrap();
        assert_eq!((back.cleared, back.role_before, back.role_after), (true, Some(Role::Member), Some(Role::Readonly)));
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Readonly, None));
        assert!(db.revoke_saml_role(&m, &a.id).is_none(), "nothing left to take");

        // Changed by hand: released, not taken back, and held until the group is left.
        assert!(db.grant_saml_role(&m, &a.id));
        let g = db.give_user_custom_role(&a.id, &hand.id).unwrap();
        assert_eq!((g.taken, g.taken_saml.as_deref()), (None, Some(m.id.as_str())));
        assert!(db.revoke_saml_role(&m, &a.id).is_none());
        assert_eq!(db.user(&a.id).unwrap().role_id, Some(hand.id.clone()));
        assert_eq!((db.saml_role_grant_of_user(&a.id).is_none(), db.saml_role_released(&a.id)), (true, Some(m.id.clone())));
        assert!(db.end_saml_role_release(&a.id, &m.id) && db.saml_role_released(&a.id).is_none());
        assert!(db.clear_user_custom_role(&a.id, &hand.id));
        // A built-in role set by hand releases it too.
        assert!(db.grant_saml_role(&m, &a.id));
        db.update_user(&a.id, UserPatch { role: Some(Role::Readonly), ..Default::default() }).unwrap();
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Readonly, None));
        assert_eq!(db.saml_role_released(&a.id), Some(m.id.clone()));
        // While it's held no mapping gives anything, another provider's included.
        assert!(!db.grant_saml_role(&okta, &a.id), "another provider's mapping");
        assert!(!db.grant_saml_role(&m, &a.id));
        assert_eq!((db.saml_role_released(&a.id), db.user(&a.id).unwrap().role_id), (Some(m.id.clone()), None));
        // Once it ends, mappings give again; disabled people get nothing.
        assert!(db.end_saml_role_release(&a.id, &m.id));
        assert!(db.grant_saml_role(&m, &a.id) && db.saml_role_released(&a.id).is_none());
        assert!(db.revoke_saml_role(&m, &a.id).is_some());
        db.update_user(&a.id, UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
        assert!(!db.grant_saml_role(&m, &a.id), "only active people");

        // The mapping removed between the read and the grant: nothing given.
        db.update_user(&a.id, UserPatch { status: Some("active"), ..Default::default() }).unwrap();
        assert!(db.delete_saml_role_mapping(&m.id));
        assert!(!db.grant_saml_role(&m, &a.id));
        assert_eq!(db.user(&a.id).unwrap().role_id, None);
    }

    #[test]
    fn a_role_ends_when_its_time_is_up_and_an_end_follows_its_role() {
        let db = Db::open(&temp_path("role-ends").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Admin).unwrap();
        let b = db.create_user(None, Some("b@example.com"), "B", Role::Member).unwrap();
        let team = db.create_team("Eng", None);
        assert!(db.add_team_member(&team.id, &b.id, "member", None));
        let r = db.create_custom_role("Auditor", "", Role::Readonly, &["audit.view"], None, None).unwrap();
        let other = db.create_custom_role("Ops", "", Role::Member, &["users.manage"], None, None).unwrap();
        let at = now();
        let soon = at + 3_600_000;

        let g = db.give_user_custom_role_until(&a.id, &r.id, Some(soon)).unwrap();
        assert_eq!(g.before, (None, Some(Role::Admin), None));
        let u = db.user(&a.id).unwrap();
        assert_eq!((u.role, u.role_id.as_deref(), u.role_expires_at), (Role::Readonly, Some(r.id.as_str()), Some(soon)));
        // Given again, it moves the end; the end before is what they held.
        let g = db.give_user_custom_role_until(&a.id, &r.id, None).unwrap();
        assert_eq!(g.before, (Some(r.id.clone()), Some(Role::Readonly), Some(soon)));
        assert_eq!(db.user(&a.id).unwrap().role_expires_at, None);
        db.give_user_custom_role_until(&a.id, &r.id, Some(soon)).unwrap();

        // Once the end passes it grants nothing, before any sweep, and its base stays.
        db.move_role_end(&a.id, at - 1);
        let u = db.user(&a.id).unwrap();
        assert_eq!((u.role, u.role_id.clone(), u.role_expires_at), (Role::Readonly, None, None));
        assert_eq!(db.user_perms(&u), crate::rbac::Perms::NONE);
        assert_eq!(db.custom_role_holders(&r.id), (vec![], vec![]));
        assert_eq!(db.give_user_custom_role_until(&a.id, &other.id, None).unwrap().before, (None, Some(Role::Readonly), None), "an ended role isn't what they held");
        db.give_user_custom_role_until(&a.id, &r.id, Some(soon)).unwrap();
        db.move_role_end(&a.id, at - 1);

        let g = db.give_team_custom_role_until(&team.id, &b.id, &r.id, Some(soon)).unwrap();
        assert_eq!(g.before, (None, None));
        assert_eq!(db.team_member(&b.id).unwrap().role_expires_at, Some(soon));
        assert!(db.give_team_custom_role_until(&team.id, &a.id, &r.id, Some(soon)).is_none(), "not on the team");
        db.move_role_end(&b.id, at - 1);
        assert_eq!(db.team_member(&b.id).unwrap().role_id, None);

        let gone = db.expire_custom_roles(now());
        assert_eq!(gone, vec![
            ExpiredRole { user_id: a.id.clone(), team_id: None, role_id: r.id.clone(), expires_at: at - 1 },
            ExpiredRole { user_id: b.id.clone(), team_id: Some(team.id.clone()), role_id: r.id.clone(), expires_at: at - 1 },
        ]);
        assert_eq!((db.stored_role_ends(&a.id), db.stored_role_ends(&b.id)), ((None, None), (None, None)), "the end goes with the role");
        assert_eq!(db.user(&a.id).unwrap().role, Role::Readonly, "never back to admin");
        assert!(db.expire_custom_roles(now()).is_empty(), "once");
        assert!(db.delete_custom_role(&r.id).is_ok(), "nobody holds it");

        // Anything else that changes the role clears its end, so it never ends a role given another way.
        db.give_user_custom_role_until(&b.id, &other.id, Some(soon)).unwrap();
        db.update_user(&b.id, UserPatch { role: Some(Role::Member), ..Default::default() }).unwrap();
        assert_eq!(db.stored_role_ends(&b.id).0, None, "a built-in role");
        db.give_user_custom_role_until(&b.id, &other.id, Some(soon)).unwrap();
        assert!(db.clear_user_custom_role(&b.id, &other.id));
        assert_eq!(db.stored_role_ends(&b.id).0, None, "taken away by hand");
        db.give_team_custom_role_until(&team.id, &b.id, &other.id, Some(soon)).unwrap();
        assert!(db.set_team_custom_role(&team.id, &b.id, None));
        assert_eq!(db.stored_role_ends(&b.id).1, None, "taken away in the team");
    }

    #[test]
    fn a_role_made_time_bound_after_its_check_is_never_saved_on_a_service_account() {
        let db = Db::open(&temp_path("time-bound-sa").join("app.sqlite")).unwrap();
        let owner = db.create_user(None, Some("o@example.com"), "O", Role::Admin).unwrap();
        let team = db.create_team("Eng", None);
        let r = db.create_custom_role("Break glass", "", Role::Member, &["users.manage"], None, None).unwrap();
        let sa = db.create_service_account("CI", "", Role::Member, None, None, &owner.id, None).unwrap();
        // The handler checked `r` while it had no limit; one is set before the write.
        db.update_custom_role(&r.id, None, None, None, None, Some(Some(7)), None).unwrap();
        assert_eq!(db.create_service_account("X", "", Role::Member, Some(&r.id), None, &owner.id, None).err().as_deref(), Some(SA_TIME_BOUND));
        assert_eq!(db.create_service_account("X", "", Role::Member, None, Some((&team.id, Some(&r.id))), &owner.id, None).err().as_deref(), Some(SA_TIME_BOUND));
        let org = ServiceAccountPatch { role: Some((Role::Member, Some(r.id.clone()))), ..Default::default() };
        assert_eq!(db.update_service_account(&sa.user.id, &org).err().as_deref(), Some(SA_TIME_BOUND));
        let in_team = ServiceAccountPatch { team: Some(Some((team.id.clone(), Some(r.id.clone())))), ..Default::default() };
        assert_eq!(db.update_service_account(&sa.user.id, &in_team).err().as_deref(), Some(SA_TIME_BOUND));
        let sa = db.service_account(&sa.user.id).unwrap();
        assert_eq!((sa.user.role_id, sa.team_id), (None, None), "nothing saved");
        assert_eq!(db.service_accounts().len(), 1);
        assert_eq!(db.update_service_account(&sa.user.id, &ServiceAccountPatch { name: Some("CI 2".into()), ..Default::default() }), Ok(vec![]));
    }

    #[test]
    fn a_role_is_created_with_its_limit_in_one_write() {
        let db = Db::open(&temp_path("time-bound-create").join("app.sqlite")).unwrap();
        let r = db.create_custom_role("Break glass", "", Role::Member, &["users.manage"], Some(7), None).unwrap();
        assert_eq!(r.max_days, Some(7));
        assert_eq!(db.custom_role(&r.id).unwrap().max_days, Some(7));
    }

    #[test]
    fn time_bound_roles_are_never_standing() {
        let db = Db::open(&temp_path("time-bound").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Member).unwrap();
        let team = db.create_team("Eng", None);
        assert!(db.add_team_member(&team.id, &a.id, "member", None));
        db.link_scim_group("okta", &team.id, None, "Eng", None).unwrap();
        let r = db.create_custom_role("Break glass", "", Role::Member, &["users.manage"], None, None).unwrap();
        let week = Some(Some(7));

        // Held with no end, it can't be made time-bound.
        db.give_user_custom_role_until(&a.id, &r.id, None).unwrap();
        assert_eq!(db.update_custom_role(&r.id, None, None, None, None, week, None), Err(RoleError::Standing { held: 1, mapped: 0 }));
        db.give_user_custom_role_until(&a.id, &r.id, Some(now() + 8 * crate::roles::DAY)).unwrap();
        assert_eq!(db.update_custom_role(&r.id, None, None, None, None, week, None), Err(RoleError::Standing { held: 1, mapped: 0 }), "nor held longer than it allows");
        db.give_user_custom_role_until(&a.id, &r.id, Some(now() + 6 * crate::roles::DAY)).unwrap();
        assert!(db.update_custom_role(&r.id, None, None, None, None, week, None).is_ok());
        assert_eq!(db.custom_role(&r.id).unwrap().max_days, Some(7));

        // Once it is, it's given only with an end within its limit, checked as it's written.
        assert!(db.give_user_custom_role_until(&a.id, &r.id, None).is_none());
        assert!(db.give_user_custom_role_until(&a.id, &r.id, Some(now() + 8 * crate::roles::DAY)).is_none());
        assert!(db.give_team_custom_role_until(&team.id, &a.id, &r.id, None).is_none());
        assert!(db.give_team_custom_role_until(&team.id, &a.id, &r.id, Some(now() + crate::roles::DAY)).is_some());
        // And no group is given it: a group holds its role while people are in it.
        assert!(matches!(db.create_scim_role_mapping("okta", &team.id, &r.id, "org", None), Err(ScimRoleMapError::TimeBound)));
        assert!(matches!(db.create_saml_role_mapping("corp", "Admins", &r.id, None), Err(ScimRoleMapError::TimeBound)));
        assert!(matches!(db.declare_scim_role_group("okta", "org", "Helpdesk", None, &r.id, None), Err(ScimRoleGroupError::TimeBound)));
        let plain = db.create_custom_role("Plain", "", Role::Member, &["users.manage"], None, None).unwrap();
        let g = db.declare_scim_role_group("okta", "org", "Helpdesk", None, &plain.id, None).unwrap();
        assert!(matches!(db.set_scim_role_group_role(&g.id, &r.id), Err(ScimRoleGroupError::TimeBound)));
        assert_eq!(db.update_custom_role(&plain.id, None, None, None, None, week, None), Err(RoleError::Standing { held: 0, mapped: 1 }));
        // The limit lifted, it's a role like any other.
        assert!(db.update_custom_role(&r.id, None, None, None, None, Some(None), None).is_ok());
        assert!(db.give_user_custom_role_until(&a.id, &r.id, None).is_some());
        assert!(db.create_saml_role_mapping("corp", "Admins", &r.id, None).is_ok());
    }

    #[test]
    fn scim_role_grants_only_ever_take_back_what_they_gave() {
        let db = Db::open(&temp_path("scim-roles").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Readonly).unwrap();
        let b = db.create_user(None, Some("b@example.com"), "B", Role::Member).unwrap();
        let team = db.create_team("Eng", None);
        let other = db.create_team("Ops", None);
        for u in [&a, &b] {
            assert!(db.add_team_member(&team.id, &u.id, "member", None));
        }
        db.link_scim_group("okta", &team.id, None, "Eng", None).unwrap();
        let r = db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
        let hand = db.create_custom_role("Hand", "", Role::Member, &["users.manage"], None, None).unwrap();
        assert!(matches!(db.create_scim_role_mapping("okta", &other.id, &r.id, "org", None), Err(ScimRoleMapError::Gone)), "not a group");
        assert!(matches!(db.create_scim_role_mapping("entra", &team.id, &r.id, "org", None), Err(ScimRoleMapError::Gone)), "another tenant's");
        let org = db.create_scim_role_mapping("okta", &team.id, &r.id, "org", None).unwrap();
        assert!(matches!(db.create_scim_role_mapping("okta", &team.id, &hand.id, "org", None), Err(ScimRoleMapError::Taken)));

        assert!(db.grant_scim_role(&org, &a.id));
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Member, Some(r.id.clone())));
        assert!(!db.grant_scim_role(&org, &a.id), "once");
        assert!(db.give_user_custom_role(&b.id, &hand.id).is_some());
        assert!(!db.grant_scim_role(&org, &b.id), "never over a role given by hand");
        assert!(matches!(db.update_custom_role(&r.id, None, None, None, Some(&["audit.view", "bots.manage"]), None, None), Err(RoleError::Reaches { .. })), "checked as it's saved");
        assert!(db.update_custom_role(&r.id, None, None, None, Some(&["audit.view"]), None, None).is_ok());
        assert!(db.revoke_scim_role(&org, &a.id, true).is_none(), "a leave that a rejoin overtook keeps the server-wide grant");
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Member, Some(r.id.clone())));
        assert_eq!(db.scim_role_grants(&org.id).len(), 1);
        let back = db.revoke_scim_role(&org, &a.id, false).unwrap();
        assert_eq!((back.cleared, back.role_before, back.role_after), (true, Some(Role::Member), Some(Role::Readonly)));
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Readonly, None));
        assert!(db.revoke_scim_role(&org, &a.id, false).is_none());

        // An admin confirms it just as SCIM takes it away: written back, from what was there then.
        assert!(db.grant_scim_role(&org, &a.id));
        assert!(db.revoke_scim_role(&org, &a.id, false).is_some());
        assert_eq!(db.give_user_custom_role(&a.id, &r.id), Some(ByHand { before: (None, Some(Role::Readonly)), taken: None, taken_saml: None }));
        assert_eq!((db.user(&a.id).unwrap().role, db.user(&a.id).unwrap().role_id), (Role::Member, Some(r.id.clone())));
        assert!(db.clear_user_custom_role(&a.id, &r.id));

        // Given by hand after SCIM gave one: SCIM's claim ends and nothing is taken back.
        assert!(db.grant_scim_role(&org, &a.id));
        assert!(db.give_user_custom_role(&a.id, &hand.id).is_some());
        assert!(db.revoke_scim_role(&org, &a.id, false).is_none());
        assert_eq!(db.user(&a.id).unwrap().role_id, Some(hand.id.clone()));

        let in_team = db.create_scim_role_mapping("okta", &team.id, &r.id, "team", None).unwrap();
        assert!(db.grant_scim_role(&in_team, &b.id));
        assert_eq!(db.team_member(&b.id).unwrap().role_id, Some(r.id.clone()));
        assert!(db.revoke_scim_role(&in_team, &b.id, true).is_none(), "a leave that a rejoin overtook takes nothing");
        assert_eq!(db.team_member(&b.id).unwrap().role_id, Some(r.id.clone()));
        assert_eq!(db.give_team_custom_role(&team.id, &b.id, Some(&r.id)), Some(ByHand { before: Some(r.id.clone()), taken: Some(in_team.id.clone()), taken_saml: None }), "the same role, now by hand");
        assert!(db.revoke_scim_role(&in_team, &b.id, false).is_none());
        assert_eq!(db.team_member(&b.id).unwrap().role_id, Some(r.id.clone()), "kept by hand");
        // An admin confirms the role SCIM gave just as SCIM takes it away: it is still theirs.
        assert!(db.set_team_custom_role(&team.id, &b.id, None));
        assert!(db.grant_scim_role(&in_team, &b.id));
        assert!(db.revoke_scim_role(&in_team, &b.id, false).is_some());
        assert_eq!(db.give_team_custom_role(&team.id, &b.id, Some(&r.id)), Some(ByHand { before: None, taken: None, taken_saml: None }), "it says what was there as it wrote");
        assert_eq!(db.team_member(&b.id).unwrap().role_id, Some(r.id.clone()));
        assert!(db.remove_team_member(&team.id, &b.id, false));
        assert!(!db.grant_scim_role(&in_team, &b.id), "only on the team");

        let wide = db.create_custom_role("Wide", "", Role::Member, &["bots.manage"], None, None).unwrap();
        let ops = db.create_team("Ops2", None);
        db.link_scim_group("okta", &ops.id, None, "Ops2", None).unwrap();
        assert_eq!(db.create_scim_role_mapping("okta", &ops.id, &wide.id, "org", None).err(), Some(ScimRoleMapError::Reaches(vec!["bots.manage"])));
        assert!(db.create_scim_role_mapping("okta", &ops.id, &wide.id, "team", None).is_ok(), "bots.manage means nothing in a team");
        assert_eq!(db.delete_custom_role(&r.id), Err(RoleError::Mapped(2)));
        assert!(db.delete_scim_role_mapping(&org.id));
        assert!(db.scim_role_grants(&org.id).is_empty());
    }

    #[test]
    fn teammate_accounts_made_before_their_table_are_remembered_from_the_audit_log() {
        let db = Db::open(&temp_path("spaces").join("app.sqlite")).unwrap();
        let made = |owner: &str, d: Value| audit::Who::system("isolation").event("isolation.account_created").target("user", owner).details(d);
        db.record(&made("u1", json!({ "account": "sb-t-1", "forUser": "u2" })));
        db.record(&made("u1", json!({ "account": "sb-t-1", "forUser": "u2" })));
        db.record(&made("u1", json!({ "account": "sb-u-u1" })));
        db.record(&made("u3", json!({ "account": "sb-t-2", "forUser": "u4" })).outcome(audit::Outcome::Failure));
        db.c().execute("DELETE FROM teammate_spaces", []).unwrap();
        migrate_account_removals(&db.c(), false).unwrap();
        assert_eq!(db.teammate_spaces(), [("u1".to_string(), "u2".to_string())]);
    }

    #[test]
    fn service_accounts_are_never_admins_people_or_seats() {
        let db = Db::open(&temp_path("service-accounts").join("app.sqlite")).unwrap();
        let owner = db.create_user(None, Some("own@example.com"), "Own", Role::Admin).unwrap();
        let seats = db.active_seats();
        let sa = db.create_service_account("CI", "", Role::Member, None, None, &owner.id, Some(&owner.id)).unwrap();
        assert!(sa.user.service && sa.user.email.is_none() && sa.deleted_at.is_none());
        assert_eq!(db.active_seats(), seats, "takes no seat");
        assert!(db.users().iter().all(|u| u.id != sa.user.id), "not on the people list");
        assert!(db.find_user(&sa.user.id).is_none() && db.find_user_any(&sa.user.id).is_none());
        assert!(db.user(&sa.user.id).is_some(), "but found by id for auth and audit names");
        // The triggers refuse an admin service account, an email, and a change of kind, whatever writes it.
        assert!(db.create_service_account("Root", "", Role::Admin, None, None, &owner.id, None).is_err());
        assert!(db.update_user(&sa.user.id, UserPatch { role: Some(Role::Admin), ..Default::default() }).is_err());
        assert!(db.update_service_account(&sa.user.id, &ServiceAccountPatch { role: Some((Role::Admin, None)), ..Default::default() }).is_err());
        assert!(db.update_user(&sa.user.id, UserPatch { email: Some(Some("sa@example.com".into())), ..Default::default() }).is_err());
        assert!(db.c().execute("UPDATE users SET kind = 'person' WHERE id = ?", [&sa.user.id]).is_err());
        assert!(db.c().execute("UPDATE users SET kind = 'service' WHERE id = ?", [&owner.id]).is_err());
        assert!(db.c().execute("INSERT INTO users (id, display_name, role, kind, created_at, updated_at) VALUES ('x', 'X', 'admin', 'service', 0, 0)", []).is_err());
        assert!(db.c().execute("INSERT INTO users (id, display_name, role, kind, created_at, updated_at) VALUES ('x', 'X', 'member', 'robot', 0, 0)", []).is_err());
        assert_eq!(db.user(&sa.user.id).unwrap().role, Role::Member);

        let t = NewServiceToken { account_id: &sa.user.id, name: "deploy", token_hash: "h1", hint: "abcd", scopes: Some(&["read"][..]), expires_at: now() + 60_000, created_by: None };
        let tok = db.create_service_token(&t).unwrap();
        assert_eq!((tok.scopes.clone(), db.service_token_by_hash("h1").map(|t| t.id)), (Some(vec!["read".to_string()]), Some(tok.id.clone())));
        let next = NewServiceToken { token_hash: "h2", ..t };
        let rotated = db.rotate_service_token(&tok.id, &next, None, None).unwrap();
        assert!(db.rotate_service_token(&tok.id, &NewServiceToken { token_hash: "h3", ..next }, None, None).is_none(), "only once");
        assert_eq!(db.service_token(&tok.id).unwrap().rotated_to.as_deref(), Some(rotated.id.as_str()));
        assert_eq!(db.delete_service_account(&sa.user.id, None), Some((1, vec![])));
        assert_eq!(db.delete_service_account(&sa.user.id, None), None);
        assert!(db.service_token(&rotated.id).unwrap().revoked_at.is_some());
        assert!(!db.user(&sa.user.id).unwrap().active());
    }

    #[test]
    fn an_existing_bot_is_handed_only_to_a_live_service_account_of_its_owner_within_its_limit() {
        let db = Db::open(&temp_path("keep-bot").join("app.sqlite")).unwrap();
        let ana = db.create_user(None, Some("ana@example.com"), "Ana", Role::Member).unwrap();
        let bea = db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let ci = db.create_service_account("CI", "", Role::Member, None, None, &ana.id, None).unwrap().user.id;
        let nightly = db.create_service_account("Nightly", "", Role::Member, None, None, &ana.id, None).unwrap().user.id;
        let beas = db.create_service_account("Bea's CI", "", Role::Member, None, None, &bea.id, None).unwrap().user.id;
        let bot = |name: &str, owner: &str| db.create_bot_owned(name, "#fff", "waddle", "claude", None, false, owner, Visibility::Shared).id;
        let (ledger, notes, other) = (bot("Ledger", &ana.id), bot("Notes", &ana.id), bot("Bea's", &bea.id));

        // Its grant goes in the same transaction: keeping it gives more.
        db.set_grant(&ledger, &ci, Grant::Operator, &ana.id);
        assert_eq!(db.keep_bot(&ledger, &ana.id, &ci, 1), Ok(Handed { from: None, grant: Some(Grant::Operator) }));
        assert_eq!((db.bot(&ledger).unwrap().service_account_id.as_deref(), db.grant(&ledger, &ci)), (Some(ci.as_str()), None));
        assert_eq!(db.keep_bot(&ledger, &ana.id, &ci, 1), Ok(Handed { from: Some(ci.clone()), grant: None }), "again changes nothing");

        // Counted with the ones it keeps, the Bot itself aside.
        assert_eq!(db.keep_bot(&notes, &ana.id, &ci, 1), Err(KeepRefusal::Limit));
        assert_eq!(db.bot(&notes).unwrap().service_account_id, None);
        // Only the owner's own accounts, and only while the owner still owns it.
        assert_eq!(db.keep_bot(&notes, &ana.id, &beas, 9), Err(KeepRefusal::Account));
        assert_eq!(db.keep_bot(&other, &ana.id, &ci, 9), Err(KeepRefusal::Bot), "not Ana's Bot");
        assert_eq!(db.keep_bot(&other, &bea.id, &ci, 9), Err(KeepRefusal::Account), "not Bea's account");
        assert_eq!(db.keep_bot("gone", &ana.id, &ci, 9), Err(KeepRefusal::Bot));

        // Another of Ana's accounts takes it over; letting go only works for the one keeping it.
        assert_eq!(db.keep_bot(&ledger, &ana.id, &nightly, 9), Ok(Handed { from: Some(ci.clone()), grant: None }));
        assert!(!db.release_kept_bot(&ledger, &ci));
        assert!(db.release_kept_bot(&ledger, &nightly));
        assert!(!db.release_kept_bot(&ledger, &nightly), "once");
        assert_eq!(db.bot(&ledger).unwrap().owner_id, ana.id, "it stays Ana's");

        // A deleted account keeps nothing, and takes nothing.
        assert!(db.delete_service_account(&nightly, None).is_some());
        assert_eq!(db.keep_bot(&ledger, &ana.id, &nightly, 9), Err(KeepRefusal::Account));
    }

    #[test]
    fn a_bot_is_kept_only_by_a_live_service_account_of_its_owner() {
        let db = Db::open(&temp_path("kept-bots").join("app.sqlite")).unwrap();
        let ana = db.create_user(None, Some("ana@example.com"), "Ana", Role::Member).unwrap();
        let bea = db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let sa = db.create_service_account("CI", "", Role::Member, None, None, &ana.id, None).unwrap().user.id;
        let beas = db.create_service_account("Bea's CI", "", Role::Member, None, None, &bea.id, None).unwrap().user.id;
        let make = |owner: &str, max_bots: Option<u32>, max_kept: u32| db.create_service_account_bot("CI", "#fff", "waddle", "claude", None, owner, &sa, max_bots, max_kept);

        // Private, its owner's, and counted against both limits in the same statement.
        let one = make(&ana.id, None, 2).unwrap();
        assert_eq!((one.owner_id.as_str(), one.service_account_id.as_deref(), one.visibility, one.primary), (ana.id.as_str(), Some(sa.as_str()), Visibility::Private, false));
        assert_eq!(make(&ana.id, Some(1), 2).err(), Some(KeptBotRefusal::PlanLimit));
        let two = make(&ana.id, Some(2), 2).unwrap();
        assert_eq!(make(&ana.id, None, 2).err(), Some(KeptBotRefusal::AccountLimit));
        assert_eq!(make(&bea.id, None, 9).err(), Some(KeptBotRefusal::Account), "only for its own owner");
        assert_eq!(db.kept_bots(&sa), [one.id.clone(), two.id.clone()]);

        // Nothing writes a link to another owner's account, whatever writes it.
        assert!(db.c().execute("UPDATE bots SET service_account_id = ?1 WHERE id = ?2", [&beas, &one.id]).is_err());
        let other = db.create_bot_owned("Ana's", "#fff", "waddle", "claude", None, false, &ana.id, Visibility::Private);
        assert!(db.c().execute("UPDATE bots SET service_account_id = ?1 WHERE id = ?2", [&beas, &other.id]).is_err());
        assert!(db.c().execute("UPDATE bots SET service_account_id = ?1 WHERE id = ?2", [&sa, &other.id]).is_ok(), "its owner's Bot");

        // A Bot that changes owner leaves it; so do all of them when it changes owner or is deleted.
        assert!(db.set_bot_owner_capped(&one.id, &bea.id, None));
        assert_eq!(db.bot(&one.id).unwrap().service_account_id, None);
        let mut released = db.update_service_account(&sa, &ServiceAccountPatch { owner: Some(bea.id.clone()), ..Default::default() }).unwrap();
        let mut both = vec![two.id.clone(), other.id.clone()];
        released.sort();
        both.sort();
        assert_eq!(released, both, "read in the same transaction as the change");
        assert!(db.kept_bots(&sa).is_empty());
        assert_eq!(db.bot(&two.id).unwrap().owner_id, ana.id, "they stay Ana's");
        assert_eq!(make(&ana.id, None, 9).err(), Some(KeptBotRefusal::Account), "nor makes more for Ana");
        let three = make(&bea.id, None, 9).unwrap();
        assert_eq!(db.delete_service_account(&sa, None), Some((0, vec![three.id.clone()])));
        assert!(db.kept_bots(&sa).is_empty() && db.bot(&three.id).is_some());
        assert!(db.c().execute("UPDATE bots SET service_account_id = ?1 WHERE id = ?2", [&sa, &three.id]).is_err(), "a deleted account keeps nothing");
    }

    #[test]
    fn a_residency_pin_and_its_region_are_saved_together_or_not_at_all() {
        let db = Db::open(&temp_path("pin-atomic").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("pin@example.com"), "P", Role::Member).unwrap();
        let t = db.create_team("Acme", None);
        db.c().execute_batch("CREATE TRIGGER pins_full BEFORE INSERT ON residency_pins BEGIN SELECT RAISE(ABORT, 'disk full'); END;").unwrap();
        for (kind, id) in [(PinOn::User, &u.id), (PinOn::Team, &t.id)] {
            assert!(db.pin_residency(kind, id, "gb-lon", "DPA-1", None).unwrap_err().contains("disk full"));
            assert!(db.residency_pin(kind, id).is_none());
        }
        assert_eq!((db.user(&u.id).unwrap().region, db.team(&t.id).unwrap().region), (None, None), "the region rolled back with the pin");
        assert!(db.pin_residency(PinOn::User, "nobody", "gb-lon", "DPA-1", None).is_err());

        db.c().execute_batch("DROP TRIGGER pins_full; CREATE TRIGGER pins_kept BEFORE DELETE ON residency_pins BEGIN SELECT RAISE(ABORT, 'disk full'); END;").unwrap();
        db.pin_residency(PinOn::User, &u.id, "gb-lon", "DPA-1", None).unwrap();
        assert_eq!(db.user(&u.id).unwrap().region.as_deref(), Some("gb-lon"));
        assert!(db.unpin_residency(PinOn::User, &u.id).is_err());
        assert!(db.residency_pin(PinOn::User, &u.id).is_some());
        db.c().execute_batch("DROP TRIGGER pins_kept;").unwrap();
        assert_eq!((db.unpin_residency(PinOn::User, &u.id), db.unpin_residency(PinOn::User, &u.id)), (Ok(true), Ok(false)));
    }

    #[test]
    fn a_leaver_keeps_the_teams_pin_with_the_leave_or_neither_happens() {
        let db = Db::open(&temp_path("pin-kept").join("app.sqlite")).unwrap();
        let t = db.create_team("Acme", None);
        let [ada, bea, cy, dee] = ["ada", "bea", "cy", "dee"].map(|n| db.create_user(None, Some(&format!("{n}@example.com")), n, Role::Member).unwrap());
        assert!(db.add_team_member(&t.id, &ada.id, "owner", None));
        for u in [&bea, &cy, &dee] {
            assert!(db.add_team_member(&t.id, &u.id, "member", None));
        }
        db.pin_residency(PinOn::Team, &t.id, "gb-lon", "MSA-7", Some(&ada.id)).unwrap();

        // Kept: the team's region and reference, who pinned it, and where it came from.
        let (gone, kept) = db.remove_team_member_keeping_pin(&t.id, &bea.id, true, true).unwrap();
        let kept = kept.unwrap();
        assert!(gone && db.team_member(&bea.id).is_none());
        assert_eq!((kept.subject_type, kept.region.as_str(), kept.reference.as_str()), (PinOn::User, "gb-lon", "MSA-7"));
        assert_eq!((kept.pinned_by.as_deref(), kept.kept_from.as_deref()), (Some(ada.id.as_str()), Some(t.id.as_str())));
        assert_eq!(db.user(&bea.id).unwrap().region.as_deref(), Some("gb-lon"), "their own region holds it");
        // An admin renewing it makes it their own pin, no longer kept from the team.
        db.pin_residency(PinOn::User, &bea.id, "gb-lon", "DPA-bea", None).unwrap();
        assert_eq!(db.residency_pin(PinOn::User, &bea.id).unwrap().kept_from, None);

        // Their own pin already holds them: left as it is.
        db.pin_residency(PinOn::User, &cy.id, "gb-lon", "DPA-cy", None).unwrap();
        assert!(matches!(db.remove_team_member_keeping_pin(&t.id, &cy.id, true, true), Ok((true, None))));
        assert_eq!(db.residency_pin(PinOn::User, &cy.id).unwrap().reference, "DPA-cy");

        // The pin can't be kept: they stay on the team, and nothing is pinned.
        db.c().execute_batch("CREATE TRIGGER pins_full BEFORE INSERT ON residency_pins BEGIN SELECT RAISE(ABORT, 'disk full'); END;").unwrap();
        assert!(db.remove_team_member_keeping_pin(&t.id, &dee.id, true, true).unwrap_err().contains("disk full"));
        assert!(db.team_member(&dee.id).is_some() && db.residency_pin(PinOn::User, &dee.id).is_none());
        assert_eq!(db.user(&dee.id).unwrap().region, None, "the region rolled back with it");
        db.c().execute_batch("DROP TRIGGER pins_full;").unwrap();

        // Not kept when asked not to (an erasure), nor for the last owner who may not go.
        assert!(!db.remove_team_member_keeping_pin(&t.id, &ada.id, true, true).unwrap().0, "the last owner, with others on the team");
        assert!(db.residency_pin(PinOn::User, &ada.id).is_none());
        assert!(matches!(db.remove_team_member_keeping_pin(&t.id, &dee.id, true, false), Ok((true, None))));
        assert!(db.residency_pin(PinOn::User, &dee.id).is_none());
        // No team pin: nothing to keep.
        db.unpin_residency(PinOn::Team, &t.id).unwrap();
        assert!(matches!(db.remove_team_member_keeping_pin(&t.id, &ada.id, true, true), Ok((true, None))));
    }

    #[test]
    fn a_kept_pin_ends_only_once_no_machine_or_backup_of_theirs_is_left() {
        let db = Db::open(&temp_path("pin-kept-end").join("app.sqlite")).unwrap();
        let t = db.create_team("Acme", None);
        let [ada, bea, cy] = ["ada", "bea", "cy"].map(|n| db.create_user(None, Some(&format!("{n}@example.com")), n, Role::Member).unwrap());
        for u in [&ada, &bea, &cy] {
            assert!(db.add_team_member(&t.id, &u.id, "member", None));
        }
        db.pin_residency(PinOn::Team, &t.id, "gb-lon", "MSA-7", None).unwrap();
        let new = NewMachine { user_id: &bea.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let mut m = db.add_machine(&new).unwrap();
        for u in [&ada, &bea, &cy] {
            assert!(db.remove_team_member_keeping_pin(&t.id, &u.id, false, true).unwrap().1.is_some());
        }

        // A machine that isn't destroyed holds it, in any state.
        assert!(matches!(db.end_kept_pin(&bea.id), Ok(None)));
        let from = m.state;
        m.state = MachineState::Destroying;
        assert!(db.save_machine(&m, from));
        assert!(matches!(db.end_kept_pin(&bea.id), Ok(None)));
        // So does a backup not yet deleted, a failed one too.
        let b = NewMachineBackup { id: "b1", machine: &m, object_key: "t/b1.incus", store_region: None, encrypted: false, created_by: None };
        db.machine_backup_start(&b).unwrap();
        assert!(db.machine_backup_end("b1", None, Some("botd stopped")));
        m.state = MachineState::Destroyed;
        assert!(db.save_machine(&m, MachineState::Destroying));
        assert!(matches!(db.end_kept_pin(&bea.id), Ok(None)));
        assert!(db.residency_pin(PinOn::User, &bea.id).is_some());
        // Once it's deleted, the kept pin ends, and the region it set stays.
        assert!(db.machine_backup_deleted("b1"));
        let ended = db.end_kept_pin(&bea.id).unwrap().unwrap();
        assert_eq!((ended.region.as_str(), ended.reference.as_str(), ended.kept_from.as_deref()), ("gb-lon", "MSA-7", Some(t.id.as_str())));
        assert!(db.residency_pin(PinOn::User, &bea.id).is_none());
        assert_eq!(db.user(&bea.id).unwrap().region.as_deref(), Some("gb-lon"));
        assert!(matches!(db.end_kept_pin(&bea.id), Ok(None)), "once");

        // A renewed pin isn't kept any more, and stays; so does a team's.
        db.pin_residency(PinOn::User, &ada.id, "gb-lon", "DPA-ada", None).unwrap();
        assert!(matches!(db.end_kept_pin(&ada.id), Ok(None)));
        assert_eq!(db.residency_pin(PinOn::User, &ada.id).unwrap().reference, "DPA-ada");
        db.pin_residency(PinOn::Team, &t.id, "gb-lon", "MSA-7", None).unwrap();
        assert!(matches!(db.end_kept_pin(&t.id), Ok(None)));
        assert!(db.residency_pin(PinOn::Team, &t.id).is_some());
        // Someone who never had data ends at once.
        assert!(db.end_kept_pin(&cy.id).unwrap().is_some());
    }

    #[test]
    fn a_message_carrying_someones_data_is_held_and_erased_with_theirs() {
        let db = Db::open(&temp_path("carried-erasure").join("app.sqlite")).unwrap();
        let ada = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let bea = db.create_user(None, Some("bea@example.com"), "Bea", Role::Member).unwrap();
        let bot = db.create_bot_owned("Bea's", "#fff", "waddle", "hermes", None, false, &bea.id, Visibility::Shared);
        let mut actor = audit::Actor::for_bot(&bot);
        actor.carries = vec![bea.id.clone(), ada.id.clone()];
        let m = db.add_message(&bot.id, "user", "Ada's numbers", None, false, Some("done"));
        db.set_requested_by(m.id, &audit::Who { actor, source: Default::default() });

        db.put_retention_hold(&bot.id, "litigation", None).unwrap();
        assert_eq!(db.erasure_holds(&ada.id, &[]), vec![bot.id.clone()]);
        assert!(matches!(db.erase_user(&ada.id, "erased-1", None, &[]), Err(EraseError::Held(_))));
        assert_eq!(db.message(m.id).unwrap().text, "Ada's numbers", "a held message isn't erased");

        assert!(db.delete_retention_hold(&bot.id));
        db.erase_user(&ada.id, "erased-1", None, &[]).unwrap();
        let m = db.message(m.id).unwrap();
        assert!((m.text.as_str(), m.requested_by.is_none()) == (ERASED_TEXT, true), "{} {:?}", m.text, m.requested_by);
    }

    #[test]
    fn push_tokens_are_sealed_one_per_session_and_capped_per_person() {
        let db = Db::open(&temp_path("push").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("push@example.com"), "P", Role::Member).unwrap();
        let other = db.create_user(None, Some("push2@example.com"), "Q", Role::Member).unwrap();
        let session = |user: &str| {
            let hash = crate::random_hex(16);
            let s = NewSession { user_id: user, token_hash: &hash, kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: now() + 60_000, mfa: None };
            db.create_session(&s).id
        };
        let s1 = session(&u.id);
        let (d, change) = db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-1]", "ios", true, true);
        assert_eq!((change, d.token.as_str()), (PushPut::Added, "ExponentPushToken[t-1]"));
        let raw: String = db.c().query_row("SELECT token FROM push_devices", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("t-1"), "sealed at rest: {raw}");
        let (d2, change) = db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", true, true);
        assert_eq!((change, d2.id == d.id), (PushPut::Added, true), "a new token for the session replaces the old one");
        assert_eq!(db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", true, true).1, PushPut::Unchanged);
        assert_eq!(db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", false, true).1, PushPut::Updated);
        // A token sealed under a lost key doesn't open; registering again still works and keeps the row.
        let lost = crate::secrets::sealed::Cipher::new(&crate::secrets::key::MasterKey::generate()).seal(PUSH_TOKEN_CONTEXT, b"ExponentPushToken[t-2]");
        db.c().execute("UPDATE push_devices SET token = ? WHERE session_id = ?", params![lost, s1]).unwrap();
        assert!(db.session_push_device(&s1).is_none());
        let (d3, change) = db.put_push_device(&u.id, &s1, "expo", "ExponentPushToken[t-2]", "ios", true, true);
        assert_eq!((change, d3.id == d.id, d3.token.as_str()), (PushPut::Added, true, "ExponentPushToken[t-2]"));
        let s2 = session(&other.id);
        assert_eq!(db.put_push_device(&other.id, &s2, "expo", "ExponentPushToken[t-2]", "android", true, true).1, PushPut::Moved);
        assert!(db.session_push_device(&s1).is_none(), "a token lives on one session only");
        for i in 0..MAX_PUSH_DEVICES + 3 {
            let s = session(&u.id);
            db.put_push_device(&u.id, &s, "expo", &format!("ExponentPushToken[c-{i}]"), "ios", true, true);
        }
        let n: i64 = db.c().query_row("SELECT COUNT(*) FROM push_devices WHERE user_id = ?", [&u.id], |r| r.get(0)).unwrap();
        assert_eq!(n as usize, MAX_PUSH_DEVICES, "the oldest go");
        db.c().execute("DELETE FROM sessions WHERE id = ?", [&s2]).unwrap();
        assert!(db.session_push_device(&s2).is_none(), "a pruned session takes its device");
    }

    #[test]
    fn activity_outlives_the_session_it_was_seen_on() {
        let db = Db::open(&temp_path("last-seen").join("app.sqlite")).unwrap();
        let day = 86_400_000;
        let seen = db.create_user(None, Some("seen@example.com"), "Seen", Role::Member).unwrap();
        db.create_user(None, Some("idle@example.com"), "Idle", Role::Member).unwrap();
        let token = NewSession { user_id: &seen.id, token_hash: "h1", kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: now() + day, mfa: None };
        let s = db.create_session(&token);
        db.c().execute("UPDATE sessions SET created_at = ?1, last_seen_at = ?1", [now() - 120 * day]).unwrap();
        db.c().execute("UPDATE users SET last_login_at = ?1 WHERE last_login_at IS NOT NULL", [now() - 120 * day]).unwrap();
        db.touch_session(&s.id, now() - 50 * day);
        db.prune_sessions(now() + 2 * day, day, 365 * day);
        let left: i64 = db.c().query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0, "the token's session is gone");
        assert_eq!(db.people_active_since(now() - 90 * day), (2, 1), "the token was used 50 days ago");
        assert_eq!(db.people_active_since(now() - 30 * day), (2, 0));
        db.create_service_account("ci", "", Role::Member, None, None, &seen.id, None).unwrap();
        assert_eq!(db.people_active_since(now() - 30 * day), (2, 0), "a service account isn't a person");
    }

    #[test]
    fn the_bot_cap_holds_under_concurrent_requests() {
        let db = std::sync::Arc::new(Db::open(&temp_path("bot-cap").join("app.sqlite")).unwrap());
        let u = db.create_user(None, Some("cap@example.com"), "Cap", Role::Member).unwrap();
        let other = db.create_user(None, Some("other@example.com"), "Other", Role::Member).unwrap();
        let theirs: Vec<String> = (0..8).map(|_| db.create_bot_owned("T", "#fff", "waddle", "claude", None, false, &other.id, Visibility::Private).id).collect();
        // Creates and transfers race for the same 3 slots.
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let (db, owner, bot) = (db.clone(), u.id.clone(), theirs[i % 8].clone());
                std::thread::spawn(move || {
                    if i < 8 {
                        db.create_bot_capped("B", "#fff", "waddle", "claude", None, false, &owner, Visibility::Private, Some(3)).is_some()
                    } else {
                        db.set_bot_owner_capped(&bot, &owner, Some(3))
                    }
                })
            })
            .collect();
        let won = threads.into_iter().map(|t| t.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!((won, db.owned_bot_count(&u.id)), (3, 3));
        assert!(db.create_bot_capped("B", "#fff", "waddle", "claude", None, false, &other.id, Visibility::Private, None).is_some());
    }

    #[test]
    fn subscription_events_end_in_the_same_tier_whatever_order_they_arrive_in() {
        fn orders(n: usize) -> Vec<Vec<usize>> {
            if n == 0 {
                return vec![vec![]];
            }
            orders(n - 1)
                .into_iter()
                .flat_map(|o| {
                    (0..n).map(move |i| {
                        let mut o = o.clone();
                        o.insert(i, n - 1);
                        o
                    })
                })
                .collect()
        }
        let db = Db::open(&temp_path("sub-order").join("app.sqlite")).unwrap();
        // Plan A (pro) started at 10, was updated at 25 and cancelled at 30. Plan B
        // (starter) started at 20, replacing it, and was cancelled at 40. Then ties:
        // A cancelled in the same second it started, an update to A in the same second
        // as its cancellation, and A paused and resumed in the same second.
        let events = [
            ("a", "active", Some("pro"), 10, 10),
            ("b", "active", Some("starter"), 20, 20),
            ("a", "active", Some("pro"), 10, 25),
            ("a", "canceled", None, 10, 30),
            ("b", "canceled", None, 20, 40),
            ("a", "canceled", None, 10, 10),
            ("a", "active", Some("pro"), 10, 30),
            ("a", "paused", None, 10, 50),
            ("a", "active", Some("pro"), 10, 50),
        ];
        let cases = [
            (&[0, 1, 2, 3][..], Some("starter")),
            (&[0, 1, 2, 3, 4][..], None),
            (&[0, 1, 2, 4][..], Some("pro")),
            (&[0, 5][..], None),
            (&[0, 3, 6][..], None),
            (&[0, 7, 8][..], None),
        ];
        for (picked, want) in cases {
            for order in orders(picked.len()) {
                let u = db.create_user(None, None, "Payer", Role::Member).unwrap();
                for (n, &i) in order.iter().enumerate() {
                    let (plan, status, tier, started, at) = events[picked[i]];
                    let s = Subscription {
                        user_id: u.id.clone(),
                        provider: "stripe".into(),
                        customer_id: None,
                        subscription_id: format!("{}-{plan}", u.id),
                        status: status.into(),
                        price_id: None,
                        tier: tier.map(String::from),
                        period_start: None,
                        period_end: None,
                        started,
                        event_created: at,
                        updated_at: 0,
                    };
                    db.apply_subscription(&format!("{}-{n}", u.id), "customer.subscription.updated", &s, true, &|_| Vec::new()).unwrap();
                }
                assert_eq!(db.user(&u.id).unwrap().tier.as_deref(), want, "events {picked:?} in order {order:?}");
            }
        }
    }

    #[test]
    fn a_stripe_events_emails_are_queued_with_it_once_and_held_until_released() {
        use crate::billing_mail::{Facts, HOLD_MS, Kind, NewEmail};
        let db = Db::open(&temp_path("billing-emails-held").join("app.sqlite")).unwrap();
        let u = db.create_user(None, None, "Payer", Role::Member).unwrap();
        let s = Subscription {
            user_id: u.id.clone(),
            provider: "stripe".into(),
            customer_id: None,
            subscription_id: "sub_1".into(),
            status: "active".into(),
            price_id: None,
            tier: Some("pro".into()),
            period_start: None,
            period_end: None,
            started: 10,
            event_created: 10,
            updated_at: 0,
        };
        let mail = |_: &Change| vec![NewEmail { key: "stripe:evt_1:plan_started".into(), user_id: u.id.clone(), kind: Kind::PlanStarted, facts: Facts::default(), event_id: Some("evt_1".into()) }];
        let (applied, _, queued) = db.apply_subscription("evt_1", "customer.subscription.updated", &s, true, &mail).unwrap();
        assert_eq!((applied, queued), (Applied::Changed { from: None, to: Some("pro".into()) }, 1));
        let (applied, _, queued) = db.apply_subscription("evt_1", "customer.subscription.updated", &s, true, &mail).unwrap();
        assert_eq!((applied, queued), (Applied::Duplicate, 0));
        // Held, but due after the hold even if never released.
        let at = now();
        assert!(db.due_billing_emails(at, 10).is_empty());
        assert_eq!(db.due_billing_emails(at + HOLD_MS + 1_000, 10).len(), 1);
        db.release_billing_emails("evt_1");
        let due = db.due_billing_emails(now(), 10);
        assert_eq!(due.len(), 1);
        // A claimed try counts and waits for its next time; a settled email can't be claimed.
        assert!(db.claim_billing_email(due[0].id, now() + 60_000).unwrap());
        assert!(db.due_billing_emails(now(), 10).is_empty());
        db.billing_email_result(due[0].id, "sent", None).unwrap();
        assert!(!db.claim_billing_email(due[0].id, 0).unwrap());
        let row = &db.billing_emails_of(&u.id, 1)[0];
        assert_eq!((row.state.as_str(), row.attempts), ("sent", 1));
        // Releasing again doesn't bring a sent email back.
        db.release_billing_emails("evt_1");
        assert!(db.due_billing_emails(now() + HOLD_MS * 2, 10).is_empty());
    }

    #[test]
    fn subscribers_from_before_customers_were_linked_keep_their_portal() {
        let db = Db::open(&temp_path("billing-backfill").join("app.sqlite")).unwrap();
        let ids: Vec<String> = (0..4).map(|_| db.create_user(None, None, "Payer", Role::Member).unwrap().id).collect();
        // One customer; two of their own; one shared with another user (ADR 0040 kept the
        // other user's subscription out, but its id may still be on record).
        let rows = [(&ids[0], "sub_a", "cus_a"), (&ids[0], "sub_a2", "cus_a"), (&ids[1], "sub_b", "cus_b"), (&ids[1], "sub_b2", "cus_b2"), (&ids[2], "sub_c", "cus_shared"), (&ids[3], "sub_d", "cus_shared")];
        {
            let c = db.c();
            c.execute("DELETE FROM billing_customers", []).unwrap();
            for (u, sub, cus) in rows {
                c.execute(
                    "INSERT INTO subscriptions (subscription_id, user_id, provider, customer_id, status, started, event_created, updated_at) VALUES (?, ?, 'stripe', ?, 'active', 1, 1, 1)",
                    params![sub, u, cus],
                )
                .unwrap();
            }
            migrate_billing_customers(&c, false).unwrap();
            migrate_billing_customers(&c, false).unwrap();
        }
        let linked: Vec<Option<String>> = ids.iter().map(|u| db.customer_of(u)).collect();
        assert_eq!(linked, [Some("cus_a".to_string()), None, None, None]);
    }

    #[test]
    fn the_pending_cap_holds_under_concurrent_requests() {
        let db = std::sync::Arc::new(Db::open(&temp_path("signup-cap").join("app.sqlite")).unwrap());
        let results: Vec<_> = (0..16)
            .map(|i| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let email = format!("p{i}@example.com");
                    let s = NewSignup { name: "P", email: &email, company: "C", team_size: "1", use_case: "U", sign_in: "other", ip: None, user_agent: None };
                    db.add_signup(&s, 3).map(|_| ())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(results.iter().all(|r| r.is_ok() || *r == Err(AddSignup::Full)));
        assert_eq!(db.pending_signups(), 3);
        let taken = db.signups(Some("pending"), 1)[0].email.to_uppercase();
        let s = NewSignup { name: "P", email: &taken, company: "C", team_size: "1", use_case: "U", sign_in: "other", ip: None, user_agent: None };
        assert_eq!(db.add_signup(&s, 10).map(|_| ()), Err(AddSignup::Duplicate), "emails match without case");
    }

    #[test]
    fn fresh_install_asks() {
        let db = Db::open(&temp_path("fresh").join("app.sqlite")).unwrap();
        assert_eq!(db.global_policy().mode, Mode::Ask);
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let e = &all_events(&db)[0];
        assert_eq!((e.action.as_str(), e.actor_kind.as_str(), e.target_type.as_deref(), e.outcome.as_str()), ("policy.initialized", "system", Some("policy"), "success"));
        assert!(e.time.ends_with('Z'), "{}", e.time);
    }

    #[test]
    fn a_held_machine_claims_no_upgrade() {
        let db = Db::open(&temp_path("upgrade-hold").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(db.machine_upgrade_hold(&m.id, Some("admin"), 0));
        assert!(!db.machine_upgrade_hold(&m.id, Some("admin"), 0), "held already");
        assert!(!db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0), "held");
        assert!(db.machine_upgrade_release(&m.id));
        assert!(!db.machine_upgrade_release(&m.id), "released already");
        assert!(db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0));
        assert!(!db.machine_upgrade_claim(&m.id, "u2", "b", "admin", 0), "one on its way");
    }

    #[test]
    fn a_rebuild_steps_only_from_the_state_it_expects() {
        let path = temp_path("rebuild-steps").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(!db.machine_rebuild_queue(&m.id, "r1", "auto", false, None), "only a running machine");
        db.c().execute("UPDATE machines SET state = 'running' WHERE id = ?", [&m.id]).unwrap();
        assert!(!db.machine_may_hold_work(&m.id));
        assert!(db.machine_rebuild_queue(&m.id, "r1", "auto", false, Some("0.3.0")));
        assert!(!db.machine_rebuild_queue(&m.id, "r2", "auto", false, None), "one at a time");
        assert!(!db.machine_rebuild_move(&m.id, "r0", &["queued"], "cancelled", false, None, None), "a stale rebuild changes nothing");
        assert!(!db.machine_rebuild_sending(&m.id, "r1", &["retrying"]), "not from another state");
        assert!(db.machine_rebuild_sending(&m.id, "r1", &["queued"]));
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_state.as_deref(), r.rebuild_attempts, r.rebuild_from.as_deref()), (Some("rebuilding"), 1, Some("0.3.0")));
        assert!(r.rebuild_sent_at.is_some());
        assert!(db.machine_rebuild_move(&m.id, "r1", &["rebuilding"], "failed", false, None, Some("no")));
        assert!(db.machine_upgrade_hold(&m.id, None, 0));
        assert!(!db.machine_rebuild_queue(&m.id, "r3", "admin", true, None), "held");
        db.machine_upgrade_release(&m.id);
        assert!(db.machine_rebuild_queue(&m.id, "r3", "admin", true, None), "again after a failure");
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_attempts, r.rebuild_error.as_deref(), r.rebuild_discard), (0, None, true));
        assert!(db.assign_machine(&m.id, None));
        assert!(db.machine_may_hold_work(&m.id), "assigned");
        assert!(db.unassign_machine(&m.id));
        let routed = audit::Event::new(audit::Actor::system("t"), "bot.run_routed").details(json!({ "machine": m.id }));
        db.record(&routed);
        assert!(db.machine_may_hold_work(&m.id), "a Bot ran there");

        // An install from before ADR 0056 gets the columns, empty.
        db.c()
            .execute_batch(
                "ALTER TABLE machines DROP COLUMN rebuild_state; ALTER TABLE machines DROP COLUMN rebuild_id;
                 ALTER TABLE machines DROP COLUMN rebuild_by; ALTER TABLE machines DROP COLUMN rebuild_discard;
                 ALTER TABLE machines DROP COLUMN rebuild_attempts; ALTER TABLE machines DROP COLUMN rebuild_next_at;
                 ALTER TABLE machines DROP COLUMN rebuild_requested_at; ALTER TABLE machines DROP COLUMN rebuild_at;
                 ALTER TABLE machines DROP COLUMN rebuild_sent_at; ALTER TABLE machines DROP COLUMN rebuild_error;
                 ALTER TABLE machines DROP COLUMN rebuild_from;",
            )
            .unwrap();
        let rebuild = MIGRATIONS.iter().position(|m| std::ptr::fn_addr_eq(*m, migrate_machine_rebuild as fn(&Connection, bool) -> rusqlite::Result<()>)).unwrap();
        db.c().execute_batch(&format!("PRAGMA user_version = {rebuild};")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let r = db.machine(&m.id).unwrap();
        assert_eq!((r.rebuild_state, r.rebuild_attempts, r.rebuild_discard), (None, 0, false));
    }

    #[test]
    fn role_groups_from_before_team_scope_stay_across_the_server() {
        let path = temp_path("team-role-groups").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let r = db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
        let g = db.declare_scim_role_group("okta", "org", "Auditors", None, &r.id, None).unwrap();
        db.c()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 CREATE TABLE old AS SELECT id, tenant, display_name, declared_display_name, external_id, declared_external_id, role_id, provisioned_at, created_at, created_by, updated_at FROM scim_role_groups;
                 DROP TABLE scim_role_groups; ALTER TABLE old RENAME TO scim_role_groups; DROP TABLE scim_role_group_team_grants;
                 PRAGMA foreign_keys = ON;",
            )
            .unwrap();
        let at = MIGRATIONS.iter().position(|m| std::ptr::fn_addr_eq(*m, migrate_scim_team_role_groups as fn(&Connection, bool) -> rusqlite::Result<()>)).unwrap();
        db.c().execute_batch(&format!("PRAGMA user_version = {at};")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.scim_role_group(&g.id).unwrap().scope, "org");
        assert!(db.scim_team_role_group_grants_in("t1").is_empty());
        assert!(db.scim_role_group_grants(&g.id).is_empty());
    }

    #[test]
    fn an_upgrade_on_its_way_takes_no_hold() {
        let db = Db::open(&temp_path("upgrade-claimed").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None };
        let m = db.add_machine(&new).unwrap();
        assert!(db.machine_upgrade_claim(&m.id, "u1", "b", "admin", 0));
        assert!(!db.machine_upgrade_hold(&m.id, Some("admin"), 0), "an upgrade is on its way");
        assert!(db.machine(&m.id).unwrap().upgrade_hold_at.is_none());
        db.machine_upgrade_backdate(&m.id, 60_000);
        assert!(db.machine_upgrade_hold(&m.id, Some("admin"), now() - 1000), "a stale one doesn't count");
        assert!(db.machine_upgrade_end(&m.id, "u1", None));
        assert!(!db.machine_upgrade_claim(&m.id, "u2", "b", "admin", 0), "held");
    }

    #[test]
    fn one_live_machine_per_user() {
        let path = temp_path("machines").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let new = NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: Some("operator") };
        let m = db.add_machine(&new).unwrap();
        assert_eq!((m.state, m.label.clone(), m.provider_id.as_deref()), (MachineState::Pending, format!("superbot-{}", m.id), None));
        match db.add_machine(&new) {
            Err(AddMachine::Exists(e)) => assert_eq!(e.id, m.id),
            other => panic!("{other:?}"),
        }
        let missing = NewMachine { user_id: "u-nobody", ..new };
        assert!(matches!(db.add_machine(&missing), Err(AddMachine::Db(_))), "only for real users");

        let mut next = m.clone();
        next.state = MachineState::Provisioning;
        next.provider_id = Some("42".into());
        assert!(db.save_machine(&next, MachineState::Pending));
        assert!(!db.save_machine(&next, MachineState::Pending), "a stale change loses");
        next.state = MachineState::Destroyed;
        assert!(db.save_machine(&next, MachineState::Provisioning));
        assert!(db.user_machine(&u.id).is_none());
        let again = db.add_machine(&new).unwrap();
        assert_ne!(again.id, m.id);
        assert_eq!(db.machines(None).len(), 2);
        assert_eq!(db.machines(Some(MachineState::Destroyed))[0].provider_id.as_deref(), Some("42"));
        assert!(db.c().execute("UPDATE machines SET state = 'lost'", []).is_err(), "only known states");

        // An install from before machines (user_version 9) gets the table on upgrade.
        db.c().execute_batch(&format!("DROP TABLE machines; {REWIND_AUDIT_CHAIN} PRAGMA user_version = 9;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(db.machines(None).is_empty());
        assert!(db.add_machine(&new).is_ok());

        // An install with tiers but no enrollment (user_version 11) gets enrollment on upgrade.
        db.c().execute_batch(&format!("DROP TABLE machine_certs; DROP TABLE machine_tokens; {REWIND_AUDIT_CHAIN} PRAGMA user_version = 11;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let tables: i64 = db.c().query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('machine_certs', 'machine_tokens', 'usage_monthly')", [], |r| r.get(0)).unwrap();
        assert_eq!(tables, 3);

        // An install at main's enrollment version (12) gets the lockdown columns, and
        // its machines keep working.
        let live = db.machines(None).into_iter().find(|m| m.state != MachineState::Destroyed).unwrap();
        db.c()
            .execute_batch(
                "ALTER TABLE machines DROP COLUMN firewall_id; ALTER TABLE machines DROP COLUMN enroll_by;
                 ALTER TABLE machines DROP COLUMN enroll_overdue_at; DROP TRIGGER IF EXISTS audit_events_sealed; PRAGMA user_version = 12;",
            )
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let m = db.machine(&live.id).unwrap();
        assert_eq!((m.firewall_id, m.enroll_by, m.enroll_overdue_at), (None, None, None));
        db.set_machine_firewall(&live.id, "501");
        assert_eq!(db.machines_on_firewall("501", "nobody"), 1);
        assert_eq!(db.machines_on_firewall("501", &live.id), 0, "not counting the one asked about");
    }

    #[test]
    fn existing_install_keeps_bypass() {
        let path = temp_path("existing").join("app.sqlite");
        // A database from before approvals: tables exist, user_version is 0.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE bots (id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL, shape TEXT NOT NULL,
               harness TEXT NOT NULL, model TEXT, session_id TEXT, primary_bot INTEGER NOT NULL DEFAULT 0,
               hidden INTEGER NOT NULL DEFAULT 0, unread INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
             INSERT INTO bots (id, name, color, shape, harness, created_at) VALUES ('b1', 'Old', '#fff', 'waddle', 'claude', 0);",
        )
        .unwrap();
        drop(c);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.global_policy().mode, Mode::Bypass);
        assert!(!db.global_policy().sandbox, "an upgrade keeps harness sandboxes off");
        assert_eq!(db.bots().len(), 1);
        // Reopening doesn't re-run the migrations.
        drop(db);
        let db = Db::open(&path).unwrap();
        let actions: Vec<String> = all_events(&db).into_iter().map(|e| e.action).collect();
        assert_eq!(actions, ["audit.schema_upgraded", "policy.sandbox_initialized", "audit.schema_upgraded", "bot.acl_initialized", "policy.initialized"]);
    }

    #[test]
    fn an_install_from_before_sandboxes_keeps_them_off() {
        let path = temp_path("sandbox-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        assert!(db.global_policy().sandbox, "a fresh install has them on");
        let bot = db.create_bot("Ada", "#fff", "waddle", "codex", None, false);
        db.set_bot_override(&bot.id, Some(&Override { timeout_minutes: Some(3), ..Default::default() }));
        // As saved before ADR 0055: no `sandbox` in the policy.
        let mut p = serde_json::to_value(db.global_policy()).unwrap();
        p.as_object_mut().unwrap().remove("sandbox");
        db.c().execute("UPDATE settings SET value = ? WHERE key = 'policy'", [p.to_string()]).unwrap();
        let sandbox = MIGRATIONS.iter().position(|m| std::ptr::fn_addr_eq(*m, migrate_sandbox as fn(&Connection, bool) -> rusqlite::Result<()>)).unwrap();
        db.c().execute_batch(&format!("{REWIND_AUDIT_CHAIN} PRAGMA user_version = {sandbox};")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(!db.global_policy().sandbox);
        assert_eq!((db.effective_policy(&bot.id).sandbox, db.effective_policy(&bot.id).timeout_minutes), (false, 3), "its Bots follow it");
        let e = all_events(&db).into_iter().find(|e| e.action == "policy.sandbox_initialized").unwrap();
        assert_eq!((e.actor_kind.as_str(), e.target_id.as_deref(), e.details["sandbox"].as_bool()), ("system", Some("global"), Some(false)));
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(all_events(&db).iter().filter(|e| e.action == "policy.sandbox_initialized").count(), 1, "once");
    }

    /// Before a test rewinds `user_version` past the hash chain (ADR 0122): earlier
    /// migrations write audit rows raw, as they did then, and the chain's seals them.
    const REWIND_AUDIT_CHAIN: &str = "DROP TRIGGER IF EXISTS audit_events_sealed;";

    macro_rules! undo_audit_actors {
        () => {
            "DROP TRIGGER audit_events_no_update; DROP TRIGGER IF EXISTS audit_events_sealed;
            CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
            DROP INDEX audit_events_on_behalf_of; DROP INDEX audit_events_session;
            ALTER TABLE audit_events DROP COLUMN actor_email; ALTER TABLE audit_events DROP COLUMN actor_role;
            ALTER TABLE audit_events DROP COLUMN auth_method; ALTER TABLE audit_events DROP COLUMN idp;
            ALTER TABLE audit_events DROP COLUMN idp_provider; ALTER TABLE audit_events DROP COLUMN session_id;
            ALTER TABLE audit_events DROP COLUMN on_behalf_of; ALTER TABLE sessions DROP COLUMN idp_provider;
            ALTER TABLE messages DROP COLUMN requested_by;"
        };
    }

    macro_rules! undo_last_login {
        () => {
            "ALTER TABLE users DROP COLUMN last_login_at; ALTER TABLE users DROP COLUMN last_login_method;
            ALTER TABLE users DROP COLUMN last_login_idp_provider; "
        };
    }

    /// Rewinds a database to before last sign-ins (user_version 7).
    const UNDO_LAST_LOGIN: &str = undo_last_login!();

    /// Rewinds a database to before per-user audit actors (user_version 5).
    const UNDO_AUDIT_ACTORS: &str = concat!(undo_last_login!(), undo_audit_actors!());

    /// Rewinds a database to before bot ACLs, so a test can set `user_version` lower.
    const UNDO_BOT_ACLS: &str =
        concat!(undo_last_login!(), undo_audit_actors!(), " DROP TRIGGER bots_service_account_insert; DROP TRIGGER bots_service_account_update;
        DROP TRIGGER bots_service_account_owner; DROP TRIGGER service_accounts_release_bots; DROP INDEX bots_service_account; ALTER TABLE bots DROP COLUMN service_account_id;
        DROP TABLE bot_grants; DROP INDEX bots_owner; ALTER TABLE bots DROP COLUMN visibility; ALTER TABLE bots DROP COLUMN owner_id;");

    #[test]
    fn upgrade_keeps_old_audit_rows_and_records_new_actors() {
        let path = temp_path("actors-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let bot = db.create_bot("Kept", "#fff", "waddle", "claude", None, true);
        let queued = db.add_message(&bot.id, "user", "hi", None, false, Some("queued"));
        db.c().execute_batch(&format!("{UNDO_AUDIT_ACTORS} PRAGMA user_version = 5;")).unwrap();
        // A row as version 5 wrote it.
        db.c()
            .execute(
                "INSERT INTO audit_events (at, actor_kind, actor_id, actor_name, action, outcome, details) VALUES (1, 'user', 'operator', 'Owner', 'bot.created', 'success', '{}')",
                [],
            )
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let rows = all_events(&db);
        let upgraded = rows.iter().find(|e| e.action == "audit.schema_upgraded" && e.target_id.as_deref() == Some("actors")).unwrap();
        let old = rows.iter().find(|e| e.action == "bot.created").unwrap();
        assert_eq!((upgraded.action.as_str(), upgraded.actor_id.as_deref()), ("audit.schema_upgraded", Some("migration")));
        assert_eq!(upgraded.details["added"].as_array().map(Vec::len), Some(AUDIT_ACTOR_COLUMNS.len()));
        assert_eq!((old.actor_id.as_deref(), old.actor_name.as_deref()), (Some("operator"), Some("Owner")), "old rows stay as written");
        assert_eq!((&old.actor_email, &old.auth_method, &old.idp, &old.session_id, &old.on_behalf_of), (&None, &None, &None, &None, &None));
        let m = db.message(queued.id).unwrap();
        assert!(m.requested_by.is_none(), "messages queued before the upgrade have no requester");

        let who = audit::Who {
            actor: audit::Actor {
                email: Some("ada@example.com".into()),
                role: Some("admin".into()),
                method: Some("sso".into()),
                idp: Some("entra".into()),
                idp_provider: Some("work".into()),
                session: Some("s1".into()),
                ..audit::Actor::operator()
            },
            source: audit::Source::default(),
        };
        db.set_requested_by(m.id, &who);
        assert_eq!(db.message(m.id).unwrap().requested_by.map(|w| w.actor), Some(who.actor.clone()));
        db.record(&who.event("bot.updated"));
        let e = &all_events(&db)[0];
        assert_eq!(
            (e.actor_email.as_deref(), e.actor_role.as_deref(), e.auth_method.as_deref(), e.idp.as_deref(), e.idp_provider.as_deref(), e.session_id.as_deref()),
            (Some("ada@example.com"), Some("admin"), Some("sso"), Some("entra"), Some("work"), Some("s1"))
        );
        assert!(db.c().execute("UPDATE audit_events SET actor_email = 'x'", []).is_err(), "still append-only");
    }

    #[test]
    fn actor_text_is_scrubbed_and_clipped() {
        let db = Db::open(&temp_path("actor-scrub").join("app.sqlite")).unwrap();
        let actor = audit::Actor { name: Some("Ada password=hunter2".into()), email: Some(format!("{}@example.com", "a".repeat(300))), ..audit::Actor::operator() };
        let source = audit::Source { ip: None, user_agent: Some("curl --token sbs_0123456789abcdef0123456789".into()) };
        db.record(&audit::Who { actor, source }.event("x.y"));
        let e = &all_events(&db)[0];
        assert_eq!(e.actor_name.as_deref(), Some("Ada password=[redacted]"));
        assert!(!e.user_agent.as_deref().unwrap().contains("sbs_0123"), "{:?}", e.user_agent);
        assert_eq!(e.actor_email.as_deref().unwrap().chars().count(), 255, "254 and an ellipsis");
    }

    #[test]
    fn upgrade_takes_last_sign_ins_from_kept_sessions() {
        let path = temp_path("last-login-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let seen = db.create_user(None, None, "Seen", Role::Member).unwrap();
        let never = db.create_user(None, None, "Never", Role::Member).unwrap();
        let s = db.create_session(&NewSession { user_id: &seen.id, token_hash: "h", kind: "token", method: "sso", idp_subject: None, idp_provider: Some("work"), label: None, ip: None, user_agent: None, expires_at: now() + 1000, mfa: None });
        assert_eq!(db.user(&seen.id).unwrap().last_login_at, Some(s.created_at), "a new session stamps it");
        db.c().execute_batch(&format!("{UNDO_LAST_LOGIN} {REWIND_AUDIT_CHAIN} PRAGMA user_version = 7;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let u = db.user(&seen.id).unwrap();
        assert_eq!((u.last_login_at, u.last_login_method.as_deref(), u.last_login_idp_provider.as_deref()), (Some(s.created_at), Some("sso"), Some("work")));
        assert_eq!(db.user(&never.id).unwrap().last_login_at, None);
    }

    #[test]
    fn upgrade_gives_existing_bots_to_the_owner_shared() {
        let path = temp_path("acl-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let old = db.create_bot("Old", "#fff", "waddle", "claude", None, true);
        db.c().execute_batch(&format!("{UNDO_BOT_ACLS} PRAGMA user_version = 4;")).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let b = db.bot(&old.id).unwrap();
        assert_eq!((b.owner_id.as_str(), b.visibility), ("operator", Visibility::Shared));
        let e = all_events(&db).into_iter().find(|e| e.action == "bot.acl_initialized").unwrap();
        assert_eq!((e.action.as_str(), e.actor_id.as_deref(), e.details["bots"].as_i64()), ("bot.acl_initialized", Some("migration"), Some(1)));

        // Grants: one per user and Bot, gone with the Bot, and the schema refuses unknown words.
        let u = db.create_user(None, Some("g@example.com"), "G", Role::Member).unwrap();
        let mine = db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, &u.id, Visibility::Private);
        assert_eq!((mine.owner_id.as_str(), mine.visibility), (u.id.as_str(), Visibility::Private));
        assert_eq!(db.set_grant(&old.id, &u.id, Grant::Viewer, "operator"), None);
        assert_eq!(db.set_grant(&old.id, &u.id, Grant::Operator, "operator"), Some(Grant::Viewer));
        assert_eq!(db.grants(&old.id).len(), 1);
        assert_eq!(db.user_grants(&u.id).get(&old.id), Some(&Grant::Operator));
        let c = db.c();
        assert!(c.execute("UPDATE bots SET visibility = 'public' WHERE id = ?", [&old.id]).is_err());
        assert!(c.execute("UPDATE bot_grants SET level = 'owner'", []).is_err());
        drop(c);
        db.set_bot_visibility(&old.id, Visibility::Private);
        assert!(db.set_bot_owner_capped(&old.id, &u.id, None));
        assert_eq!(db.bot(&old.id).map(|b| (b.owner_id, b.visibility)), Some((u.id.clone(), Visibility::Private)));
        assert_eq!(db.remove_grant(&old.id, &u.id), Some(Grant::Operator));
        assert_eq!(db.remove_grant(&old.id, &u.id), None);
        let other = db.create_user(None, Some("o@example.com"), "O", Role::Member).unwrap();
        db.set_grant(&mine.id, &other.id, Grant::Viewer, &u.id);
        assert_eq!(db.grants(&mine.id).len(), 1);
        db.delete_bot(&mine.id);
        assert!(db.grants(&mine.id).is_empty() && db.grant(&mine.id, &other.id).is_none());
    }

    #[test]
    fn audit_is_append_only() {
        let db = Db::open(&temp_path("audit").join("app.sqlite")).unwrap();
        db.record(&audit::Event::new(audit::Actor::operator(), "policy.updated").target("policy", "global").details(json!({ "mode": "ask" })));
        assert!(db.c().execute("UPDATE audit_events SET actor_id = 'x'", []).is_err());
        assert!(db.c().execute("UPDATE audit_events SET details = '{}' WHERE action = 'policy.updated'", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert!(db.c().execute("DELETE FROM audit_events WHERE action = 'policy.updated'", []).is_err());
        // No retention set: nothing can be deleted, however old.
        assert!(db.c().execute("DELETE FROM audit_events WHERE at < ?", [now() + 60_000]).is_err());
        assert_eq!(db.prune_audit(None).unwrap(), (0, None));
        assert_eq!(all_events(&db).len(), 2);
        let e = &all_events(&db)[0];
        assert_eq!((e.actor_kind.as_str(), e.actor_id.as_deref(), e.target_id.as_deref()), ("user", Some("operator"), Some("global")));
        // Sealed on the hash chain (ADR 0122): a row without a seal can't get in, and no
        // seal can change, even during an erasure.
        assert!(e.chain_hash.as_ref().is_some_and(|h| h.len() == 64) && e.chain_prev == all_events(&db)[1].chain_hash);
        let raw = "INSERT INTO audit_events (at, actor_kind, action, outcome, details) VALUES (1, 'system', 'forged', 'success', '{}')";
        assert!(db.c().execute(raw, []).unwrap_err().to_string().contains("sealed"));
        db.c().execute("INSERT INTO settings (key, value) VALUES (?, 'p')", [AUDIT_ERASING]).unwrap();
        assert!(db.c().execute("UPDATE audit_events SET chain_hash = chain_prev", []).is_err());
        assert!(db.c().execute("UPDATE audit_events SET chain_digest = 'x', chain_salt = NULL", []).is_err());
        assert_eq!(db.c().execute("UPDATE audit_events SET chain_salt = NULL", []).unwrap(), 2, "an erasure clears the salt");
        db.c().execute("DELETE FROM settings WHERE key = ?", [AUDIT_ERASING]).unwrap();
        // Cleared by hand, with no erasure event naming the rows: their contents can't be vouched for.
        let r = crate::audit_chain::verify(&db, vec![]);
        assert_eq!((r.ok, r.checked, r.erased, r.broken), (false, 2, 2, 2), "{r:?}");
        let ids: Vec<i64> = all_events(&db).iter().map(|e| e.id).collect();
        crate::audit_chain::insert_erased(&db.c(), "erased-test", &ids).unwrap();
        let r = crate::audit_chain::verify(&db, vec![]);
        assert_eq!((r.ok, r.checked, r.erased), (true, 3, 2), "{r:?}");
    }

    /// Retention deletes a run from the start of the log (ADR 0122), never past the
    /// SIEM export's cursor, and leaves an anchor the chain carries on from.
    #[test]
    fn audit_pruning_keeps_the_chain_whole() {
        let db = Db::open(&temp_path("audit-prune").join("app.sqlite")).unwrap();
        db.c().execute_batch(&format!("DROP TRIGGER audit_events_no_delete; DELETE FROM audit_events; {}", audit_delete_trigger())).unwrap();
        let old = now() - 40 * 86_400_000;
        let at = |action: &str, t: i64| db.record_at(&audit::Event::new(audit::Actor::system("test"), action), t).unwrap();
        let [o1, o2, o3] = [at("old", old), at("old", old), at("old", old)];
        let young = at("young", now());
        let late = at("old", old);
        assert_eq!(db.prune_audit(Some(o1)).unwrap(), (0, None), "no retention set");
        db.set_audit_retention(Some(30));
        let (n, anchor) = db.prune_audit(Some(o1)).unwrap();
        assert_eq!((n, anchor.as_ref().map(|a| a.id)), (1, Some(o1)), "held at what the SIEM has");
        assert!(crate::audit_chain::verify(&db, vec![]).ok);
        let (n, anchor) = db.prune_audit(None).unwrap();
        assert_eq!((n, anchor.map(|a| a.id)), (2, Some(o3)));
        assert_eq!(db.audit_chain_anchor().map(|a| a.id), Some(o3));
        assert_eq!(db.prune_audit(None).unwrap(), (0, None), "the old row after a young one waits");
        let r = crate::audit_chain::verify(&db, vec![]);
        assert_eq!((r.ok, r.first, r.anchor.as_ref().map(|a| a.id), r.checked), (true, Some(young), Some(o3), 2), "{r:?}");
        assert!(o2 < o3 && late > young);
        // New rows chain on.
        at("next", now());
        assert!(crate::audit_chain::verify(&db, vec![]).ok);
    }

    #[test]
    fn chat_pruning_takes_the_oldest_first_and_holds_go_with_their_bot() {
        let db = Db::open(&temp_path("chat-retention").join("app.sqlite")).unwrap();
        let day = 86_400_000;
        let bot = db.create_bot("Ada", "#fff", "waddle", "claude", None, false);
        db.add_messages_at(&bot.id, 3, now() - 50 * day, None);
        db.add_messages_at(&bot.id, 2, now() - 40 * day, None);
        let cutoff = now() - 30 * day;
        let (n, end) = db.prune_chat_batch(cutoff, None, 4).unwrap();
        assert_eq!(n, 4, "a batch never goes past its limit");
        let left = db.messages(&bot.id, 10);
        assert_eq!((left.len(), left[0].created_at < now() - 39 * day), (1, true), "the oldest went first");
        assert_eq!(db.prune_chat_batch(cutoff, end, 4).unwrap().0, 1);
        assert_eq!(db.prune_chat_batch(cutoff, None, 4).unwrap(), (0, None));

        // A held Bot's old rows are looked at once a pass: a batch starts past the last one's end.
        let held = db.create_bot("Held", "#fff", "waddle", "claude", None, false);
        assert!(db.put_retention_hold(&held.id, "hold", None).is_some());
        db.add_messages_at(&held.id, 3, now() - 60 * day, None);
        db.add_messages_at(&bot.id, 2, now() - 50 * day, None);
        let (n, end) = db.prune_chat_batch(cutoff, None, 1).unwrap();
        let (n2, end2) = db.prune_chat_batch(cutoff, end, 1).unwrap();
        assert_eq!((n, n2, db.prune_chat_batch(cutoff, end2, 1).unwrap().0), (1, 1, 0));
        assert!(end.is_some() && end < end2, "the cursor moves forward");
        assert!(!db.delete_bot_unless_held(&held.id), "a held Bot isn't deleted");
        assert_eq!(db.message_count(&held.id), 3);
        let to = db.create_bot("To", "#fff", "waddle", "claude", None, false);
        db.add_messages_at(&to.id, 1, now(), Some(&held.id));
        assert!(db.bot_chat_held(&to.id) && !db.delete_bot_unless_held(&to.id), "nor one a held Bot wrote to");
        assert!(!db.bot_chat_held(&bot.id));
        db.delete_retention_hold(&held.id);
        assert!(db.delete_bot_unless_held(&to.id));
        assert!(db.delete_bot_unless_held(&held.id));
        assert!(db.put_retention_hold(&held.id, "too late", None).is_none(), "no hold on a Bot that's gone");

        db.set_chat_retention(Some(90));
        assert_eq!(db.chat_retention(), Some(90));
        db.set_chat_retention(None);
        assert_eq!(db.chat_retention(), None);

        db.put_retention_hold(&bot.id, "hold", Some("u1")).unwrap();
        assert_eq!(db.retention_holds().len(), 1);
        db.delete_bot(&bot.id);
        assert!(db.retention_holds().is_empty(), "a Bot deleted under the database's feet takes its hold");
    }

    #[test]
    fn a_held_chat_with_a_message_carrying_someones_data_holds_their_erasure() {
        let db = Db::open(&temp_path("carries-hold").join("app.sqlite")).unwrap();
        let from = db.create_bot("Bea's", "#fff", "waddle", "claude", None, false);
        let held = db.create_bot("Cy's", "#fff", "waddle", "claude", None, false);
        let m = db.add_message(&held.id, "user", "status?", None, false, None);
        let mut actor = audit::Actor::for_bot(&from);
        actor.carries = vec!["ada".into()];
        db.set_requested_by(m.id, &audit::Who { actor, source: Default::default() });
        assert!(db.erasure_holds("ada", &[]).is_empty(), "no hold yet");
        assert!(db.put_retention_hold(&held.id, "hold", None).is_some());
        assert_eq!(db.erasure_holds("ada", &[]), vec![held.id.clone()]);
        assert!(db.erasure_holds("cy", &[]).is_empty());
    }

    #[test]
    fn retention_deletes_only_rows_past_the_window() {
        let db = Db::open(&temp_path("retention").join("app.sqlite")).unwrap();
        let day = 86_400_000;
        // A log that starts with old rows, since pruning takes a run from the start.
        db.c().execute_batch(&format!("DROP TRIGGER audit_events_no_delete; DELETE FROM audit_events; {}", audit_delete_trigger())).unwrap();
        let event = |action: &str, at: i64| db.record_at(&audit::Event::new(audit::Actor::system("test"), action), at).unwrap();
        event("old.event", now() - 40 * day);
        assert_eq!(db.prune_audit(None).unwrap(), (0, None), "no retention saved yet");
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        db.set_audit_retention(Some(30));
        assert_eq!(db.audit_retention(), Some(30));
        // Rows on both sides of the cutoff, to the millisecond: pruning never trips the trigger.
        let start = now();
        let edge = start - 30 * day;
        for ms in (-2_000..=2_000).step_by(50) {
            event("edge.event", edge + ms);
        }
        // A cutoff inside the window would delete young rows, so the whole statement fails.
        assert!(db.c().execute("DELETE FROM audit_events WHERE at < ?", [now()]).is_err());
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        assert!(db.prune_audit(None).unwrap().0 >= 21, "the 40-day-old row and the edge rows older than a second");
        // The cutoff moves with the clock, so a slow runner ages more edge rows out.
        let late = (now() - start).max(1_000);
        let left: Vec<i64> = all_events(&db).iter().filter(|e| e.action == "edge.event").map(|e| e.at).collect();
        assert!(left.iter().all(|&at| at > edge - 1_000), "rows past the window are gone");
        let young = (-2_000..=2_000).step_by(50).filter(|&ms| ms >= late).count();
        assert_eq!(left.iter().filter(|&&at| at >= edge + late).count(), young, "rows inside the window stay");
        assert!(all_events(&db).iter().all(|e| e.action != "old.event"));
        db.set_audit_retention(None);
        assert_eq!(db.audit_retention(), None);
    }

    #[test]
    fn secrets_never_reach_the_audit_table() {
        let db = Db::open(&temp_path("scrub").join("app.sqlite")).unwrap();
        let subject = r#"mcp__chat__send {"message":"hi there","token":"hunter3"}"#;
        let e = audit::Event::new(audit::Actor::operator(), "x.y").details(json!({ "token": "abc", "cmd": "curl -u admin:hunter2 https://x", "subject": subject }));
        db.record(&e);
        let raw: String = db.c().query_row("SELECT details FROM audit_events WHERE action = 'x.y'", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("abc") && !raw.contains("hunter2") && !raw.contains("hunter3"), "{raw}");
        assert!(raw.contains("hi there"), "{raw}");
    }

    #[test]
    fn upgrades_first_audit_table() {
        let path = temp_path("upgrade").join("app.sqlite");
        // A database at schema version 1 (approvals), with audit rows in the first format.
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE bots (id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL, shape TEXT NOT NULL,
               harness TEXT NOT NULL, model TEXT, session_id TEXT, primary_bot INTEGER NOT NULL DEFAULT 0,
               hidden INTEGER NOT NULL DEFAULT 0, unread INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);",
        )
        .unwrap();
        migrate_approvals(&c, true).unwrap();
        c.execute_batch(
            "INSERT INTO audit_events (at, actor, action, bot_id, target, detail) VALUES
               (1, 'user', 'policy.updated', NULL, 'global', '{\"after\":1}'),
               (2, 'bot', 'approval.requested', 'b1', 'a1', '{}'),
               (3, 'system', 'policy.denied', 'b1', NULL, '{}'),
               (4, 'user', 'rule.added', 'b1', 'r1', '{}');
             PRAGMA user_version = 1;",
        )
        .unwrap();
        drop(c);
        let db = Db::open(&path).unwrap();
        let rows = db.audit_events(&audit::Filter::default(), 10, true);
        let view: Vec<_> = rows
            .iter()
            .map(|e| (e.action.as_str(), e.actor_kind.as_str(), e.actor_id.as_deref(), e.target_type.as_deref(), e.target_id.as_deref(), e.outcome.as_str()))
            .collect();
        assert_eq!(
            view,
            [
                ("policy.initialized", "system", None, Some("policy"), Some("global"), "success"),
                ("policy.updated", "user", Some("operator"), Some("policy"), Some("global"), "success"),
                ("approval.requested", "bot", Some("b1"), Some("approval"), Some("a1"), "success"),
                ("policy.denied", "system", None, None, None, "denied"),
                ("rule.added", "user", Some("operator"), Some("rule"), Some("r1"), "success"),
                ("audit.schema_upgraded", "system", Some("migration"), Some("audit"), Some("actors"), "success"),
                ("policy.sandbox_initialized", "system", Some("migration"), Some("policy"), Some("global"), "success"),
                // Every row above, sealed onto the hash chain (ADR 0122).
                ("audit.schema_upgraded", "system", Some("migration"), Some("audit"), Some("chain"), "success"),
            ]
        );
        assert_eq!(rows[1].details, json!({ "after": 1 }));
        // Still append-only, and ids keep counting up.
        assert!(db.c().execute("DELETE FROM audit_events", []).is_err());
        db.record(&audit::Event::new(audit::Actor::system("server"), "server.started"));
        assert!(all_events(&db)[0].id > rows.last().unwrap().id);
        let r = crate::audit_chain::verify(&db, vec![]);
        assert_eq!((r.ok, r.first, r.checked), (true, Some(rows[0].id), rows.len() as u64 + 1), "{r:?}");
        assert_eq!(rows.last().unwrap().details["sealed"].as_i64(), Some(rows.len() as i64 - 1));
    }

    #[test]
    fn upgrade_adds_users_and_keeps_data() {
        let path = temp_path("users-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let bot = db.create_bot("Kept", "#fff", "waddle", "claude", None, true);
        // As a database from before users: no user tables, user_version 2.
        db.c()
            .execute_batch(&format!("{UNDO_BOT_ACLS} DROP TABLE push_devices; DROP TABLE user_identities; DROP TABLE login_codes; DROP TABLE sessions; DROP TABLE users; PRAGMA user_version = 2;"))
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.bot(&bot.id).map(|b| b.name), Some("Kept".into()));
        assert!(db.users().is_empty(), "the owner is made by botd at start, not by the migration");
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        // The schema refuses what the code never writes.
        let c = db.c();
        assert!(c.execute("INSERT INTO users (id, display_name, role, created_at, updated_at) VALUES ('x', 'X', 'root', 0, 0)", []).is_err());
        assert!(c.execute("INSERT INTO users (id, display_name, role, idp_issuer, created_at, updated_at) VALUES ('x', 'X', 'member', 'iss', 0, 0)", []).is_err());
    }

    #[test]
    fn upgrade_moves_a_users_idp_columns_into_identities() {
        let path = temp_path("identities-upgrade").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let u = db.create_user(None, None, "Linked", Role::Member).unwrap();
        db.c()
            .execute_batch(&format!(
                "{UNDO_BOT_ACLS} DROP TABLE user_identities; ALTER TABLE sessions DROP COLUMN idp_subject;
                 UPDATE users SET idp_issuer = 'https://idp.example', idp_subject = 's1' WHERE id = '{}'; PRAGMA user_version = 3;",
                u.id
            ))
            .unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        let (i, found) = db.identity("https://idp.example", "s1").unwrap();
        assert_eq!((found.id.as_str(), i.provider.as_str()), (u.id.as_str(), "oidc"));
    }

    #[test]
    fn identities_link_once_and_keep_the_users_own_in_step() {
        let db = Db::open(&temp_path("identities").join("app.sqlite")).unwrap();
        let a = db.create_user(None, Some("a@example.com"), "A", Role::Member).unwrap();
        let b = db.create_user(None, None, "B", Role::Member).unwrap();
        let new = |subject: &'static str| NewIdentity { provider: "entra", issuer: "https://login.example/t1/v2.0", subject, tenant: Some("t1"), email: None, created_by: Some("operator") };
        let first = db.link_identity(&a.id, &new("oid-1")).unwrap();
        let second = db.link_identity(&a.id, &new("oid-2")).unwrap();
        assert!(db.link_identity(&b.id, &new("oid-1")).is_err(), "one user per identity");
        assert!(db.link_identity(&a.id, &new("oid-1")).is_err(), "and once");
        assert_eq!(db.user(&a.id).unwrap().idp_subject.as_deref(), Some("oid-1"), "the first is the user's own");
        assert_eq!(db.identity("https://login.example/t1/v2.0", "oid-2").map(|(i, u)| (i.id, u.id)), Some((second.id.clone(), a.id.clone())));
        assert!(db.identity("https://login.example/t2/v2.0", "oid-2").is_none(), "the issuer is part of the key");
        db.touch_identity(&first.id, Some("new@example.com"), 42);
        db.touch_identity(&first.id, None, 43);
        let touched = db.identities(&a.id).into_iter().find(|i| i.id == first.id).unwrap();
        assert_eq!((touched.email.as_deref(), touched.last_login_at), (Some("new@example.com"), Some(43)));

        assert!(db.unlink_identity(&b.id, &first.id).is_none(), "only the owner's");
        assert_eq!(db.unlink_identity(&a.id, &first.id).map(|i| i.subject), Some("oid-1".into()));
        assert_eq!(db.user(&a.id).unwrap().idp_subject.as_deref(), Some("oid-2"), "the next one takes over");
        db.unlink_identity(&a.id, &second.id).unwrap();
        let u = db.user(&a.id).unwrap();
        assert_eq!((u.idp_issuer, u.idp_subject), (None, None));

        // Just in time: a user and their identity together, never merged by email.
        let jit = |email: Option<&'static str>, subject: &'static str| db.create_sso_user(email, "J", Role::Readonly, &new(subject));
        assert_eq!(jit(Some("A@example.com"), "oid-3").unwrap_err(), JitError::EmailTaken);
        assert!(db.identity("https://login.example/t1/v2.0", "oid-3").is_none(), "nothing half made");
        let j = jit(Some("j@example.com"), "oid-3").unwrap();
        assert_eq!((j.role, j.idp_subject.as_deref()), (Role::Readonly, Some("oid-3")));
        assert_eq!(jit(None, "oid-3").unwrap_err(), JitError::IdentityTaken);
    }

    #[test]
    fn audit_filters() {
        let db = Db::open(&temp_path("filters").join("app.sqlite")).unwrap();
        let ev = |actor: audit::Actor, action: &str| audit::Event::new(actor, action);
        db.record(&ev(audit::Actor::operator(), "bot.created").bot("b1"));
        db.record(&ev(audit::Actor::bot(Some("b1"), Some("A")), "routine.created").bot("b1"));
        db.record(&ev(audit::Actor::bot(Some("b2"), None), "routine.deleted").bot("b2"));
        db.record(&ev(audit::Actor::operator(), "auth.login_failed").outcome(audit::Outcome::Failure));
        let q = |f: audit::Filter| db.audit_events(&f, 100, false).into_iter().map(|e| e.action).collect::<Vec<_>>();
        let f = |k: &str, v: &str| audit::Filter::from_query(&[(k.to_string(), v.to_string())].into()).unwrap();
        assert_eq!(q(f("action", "routine.*")), ["routine.deleted", "routine.created"]);
        assert_eq!(q(f("action", "bot.created,auth.login_failed")), ["auth.login_failed", "bot.created"]);
        assert_eq!(q(f("actor", "bot:b1")), ["routine.created"]);
        assert_eq!(q(f("actor", "bot")).len(), 2);
        assert_eq!(q(f("outcome", "failure")), ["auth.login_failed"]);
        assert_eq!(q(f("bot", "b1")), ["routine.created", "bot.created"]);
        assert_eq!(q(f("to", "2000-01-01")).len(), 0);
        assert_eq!(q(f("from", "2000-01-01")).len(), 5);
        let newest = all_events(&db)[0].id;
        assert_eq!(q(audit::Filter { before: Some(newest), ..Default::default() }).len(), 4);
        let oldest_first = db.audit_events(&audit::Filter { after: Some(newest - 2), ..Default::default() }, 100, true);
        assert_eq!(oldest_first.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["routine.deleted", "auth.login_failed"]);
    }

    #[test]
    fn audit_filters_by_person_and_sign_in() {
        let db = Db::open(&temp_path("actor-filters").join("app.sqlite")).unwrap();
        let ada = db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        let person = |method: &str, idp: Option<&str>, session: &str| audit::Actor {
            id: Some(ada.id.clone()),
            email: Some("Ada@Example.com".into()),
            method: Some(method.into()),
            idp: idp.map(|_| "entra".into()),
            idp_provider: idp.map(String::from),
            subject: idp.map(|_| "https://login.example/t1/v2.0|oid-1".into()),
            session: Some(session.into()),
            ..audit::Actor::operator()
        };
        let mut gone = person("code", None, "s3");
        gone.id = Some("u-deleted".into());
        let ev = |actor: audit::Actor, action: &str| audit::Event::new(actor, action);
        db.record(&ev(person("sso", Some("work"), "s1"), "bot.created"));
        db.record(&ev(person("password", None, "s2"), "policy.updated"));
        db.record(&ev(audit::Actor::bot(Some("b1"), Some("A")).method("bot_token").on_behalf_of(&ada.id), "approval.requested"));
        db.record(&ev(audit::Actor::system("scheduler").on_behalf_of(&ada.id), "routine.fired"));
        db.record(&ev(gone, "auth.login"));
        let q = |f: audit::Filter| db.audit_events(&f, 100, false).into_iter().map(|e| e.action).collect::<Vec<_>>();
        let f = |k: &str, v: &str| {
            let mut f = audit::Filter::from_query(&[(k.to_string(), v.to_string())].into()).unwrap();
            f.resolve_users(|key| db.find_user(key).map(|u| u.id));
            f
        };
        assert_eq!(q(f("actor", &format!("user:{}", ada.id))), ["policy.updated", "bot.created"]);
        assert_eq!(q(f("actor", "user:ada@example.com")), ["policy.updated", "bot.created"], "an email finds the user");
        assert_eq!(q(f("actor", "user:ADA@example.com")), ["policy.updated", "bot.created"], "any case");
        let mut old_email = audit::Filter::from_query(&[("actor".into(), "user:ada@example.com".into())].into()).unwrap();
        old_email.resolve_users(|_| None);
        assert_eq!(q(old_email), ["auth.login", "policy.updated", "bot.created"], "no such user now: matches the recorded email");
        assert_eq!(q(f("method", "sso")), ["bot.created"]);
        assert_eq!(q(f("method", "password,bot_token")), ["approval.requested", "policy.updated"]);
        assert_eq!(q(f("idpProvider", "work")), ["bot.created"]);
        assert_eq!(q(f("idp", "entra")), ["bot.created"]);
        assert_eq!(q(f("subject", "https://login.example/t1/v2.0|oid-1")), ["bot.created"]);
        assert_eq!(q(f("session", "s2")), ["policy.updated"]);
        assert_eq!(q(f("onBehalfOf", &ada.id)), ["routine.fired", "approval.requested"]);
        assert_eq!(q(f("onBehalfOf", "ada@example.com")), ["routine.fired", "approval.requested"]);
    }

    #[test]
    fn bot_policy_inherits_and_overrides() {
        let db = Db::open(&temp_path("policy").join("app.sqlite")).unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let o = Override { mode: Some(Mode::Bypass), ..Default::default() };
        db.set_bot_override(&bot.id, Some(&o));
        assert_eq!(db.effective_policy(&bot.id).mode, Mode::Bypass);
        let mut g = db.global_policy();
        g.timeout_minutes = 5;
        db.set_global_policy(&g);
        assert_eq!(db.effective_policy(&bot.id).timeout_minutes, 5);
        db.set_bot_override(&bot.id, None);
        assert_eq!(db.effective_policy(&bot.id).mode, Mode::Ask);

        let global = db.add_rule(None, Action::Deny, "*", "*evil*", None);
        let mine = db.add_rule(Some(&bot.id), Action::Allow, "shell", "git push", Some("note"));
        assert_eq!(db.rules(Some(&bot.id)).len(), 2);
        assert_eq!(db.rules(None).len(), 1);
        db.delete_rule(&mine.id);
        assert_eq!(db.rules(Some(&bot.id)).iter().map(|r| r.id.clone()).collect::<Vec<_>>(), [global.id]);
    }

    #[test]
    fn first_decision_wins() {
        let db = Db::open(&temp_path("approval").join("app.sqlite")).unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let a = db.add_approval(&bot.id, "claude", "Bash", "shell", "git push", &json!({ "command": "git push" }), "git_push", "Pushes", now() + 1000);
        assert_eq!(db.approvals(Some("pending"), None, 10).len(), 1);
        assert!(db.finish_approval(&a.id, "approved", "user", None, None));
        assert!(!db.finish_approval(&a.id, "denied", "user", None, None));
        assert_eq!(db.approval(&a.id).unwrap().status, "approved");
        assert!(db.approvals(Some("pending"), None, 10).is_empty());
    }

    #[test]
    fn a_scim_manager_is_someone_else_live_in_the_same_tenant() {
        fn fields<'a>(user_name: &'a str, enterprise: &'a Enterprise) -> ScimFields<'a> {
            ScimFields {
                user_name,
                external_id: None,
                given_name: None,
                family_name: None,
                scim_display_name: None,
                formatted: None,
                display_name: user_name,
                email: None,
                active: Some(true),
                enterprise,
            }
        }
        fn with(manager: &str) -> Enterprise {
            Enterprise { department: Some("Eng".into()), employee_number: Some("E-1".into()), manager: Some(manager.into()), ..Default::default() }
        }
        let db = Db::open(&temp_path("scim-manager").join("app.sqlite")).unwrap();
        let none = Enterprise::default();
        let boss = db.create_scim_user("entra", &fields("boss", &none), Role::Member, None).unwrap();
        let other = db.create_scim_user("okta", &fields("other", &none), Role::Member, None).unwrap();
        let ada = db.create_scim_user("entra", &fields("ada", &none), Role::Member, None).unwrap();
        let manager_of = |db: &Db| db.scim_user("entra", &ada.id).map(|u| (u.enterprise.manager, u.manager_name));

        for not_one in [other.id.as_str(), ada.id.as_str(), "nobody"] {
            db.save_scim_user("entra", &ada.id, &fields("ada", &with(not_one)), false).unwrap();
            assert_eq!(manager_of(&db), Some((None, None)), "{not_one}");
            assert_eq!(db.scim_user("entra", &ada.id).unwrap().enterprise.department.as_deref(), Some("Eng"), "the rest is kept");
        }
        db.save_scim_user("entra", &ada.id, &fields("ada", &with(&boss.id)), false).unwrap();
        assert_eq!(manager_of(&db), Some((Some(boss.id.clone()), Some("boss".into()))));
        assert!(db.delete_scim_user("entra", &boss.id));
        assert_eq!(manager_of(&db), Some((None, None)), "a deleted manager isn't shown");
        db.save_scim_user("entra", &boss.id, &fields("boss", &none), true).unwrap();
        assert_eq!(manager_of(&db), Some((Some(boss.id.clone()), Some("boss".into()))), "taken back, shown again");

        let changed = json!({ "changes": { "employeeNumber": { "from": null, "to": "7" } } });
        db.record(&audit::Event::new(audit::Actor::system("scim"), "user.updated").target("user", &boss.id).details(changed));
        db.erase_user(&boss.id, "erased-1", None, &[]).unwrap();
        assert_eq!(manager_of(&db), Some((None, None)));
        let d: String = db.c().query_row("SELECT details FROM audit_events WHERE action = 'user.updated'", [], |r| r.get(0)).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&d).unwrap()["changes"]["employeeNumber"], json!({ "from": null, "to": "erased-1" }), "even one character is scrubbed");
        let stale: Option<String> = db.c().query_row("SELECT manager_id FROM scim_users WHERE user_id = ?", [&ada.id], |r| r.get(0)).unwrap();
        assert_eq!(stale, None, "erasing someone clears them as a manager");
    }

    #[test]
    fn scim_groups_are_unique_per_tenant_and_go_with_their_team() {
        let db = Db::open(&temp_path("scim-groups").join("app.sqlite")).unwrap();
        let eng = db.create_scim_group("okta", Some("00g1"), "Eng", "Eng", Some("scim:st1")).unwrap();
        assert_eq!((eng.origin.as_str(), eng.provisioned_at.is_some(), db.team(&eng.team_id).unwrap().machines), ("scim", true, false));
        // Another tenant may use the same name and externalId; this one may not, in any case.
        assert!(db.create_scim_group("entra", Some("00g1"), "Eng", "Eng", None).is_ok());
        assert_eq!(db.create_scim_group("okta", None, "ENG", "ENG", None).err(), Some(ScimGroupConflict::DisplayName));
        // ASCII case only: the filter compares the same way.
        assert!(db.create_scim_group("entra", None, "Équipe", "Équipe", None).is_ok());
        assert!(db.create_scim_group("entra", None, "éQUIPE", "éQUIPE", None).is_ok());
        assert!(db.scim_group_find("entra", None, Some("ÉQUIPE")).is_some_and(|g| g.display_name == "Équipe"));
        assert_eq!(db.create_scim_group("okta", Some("00g1"), "Other", "Other", None).err(), Some(ScimGroupConflict::ExternalId));
        assert_eq!(db.teams().len(), 4, "a refused group leaves no team behind");
        assert_eq!(db.scim_group_find("okta", None, Some("eng")).map(|g| g.team_id), Some(eng.team_id.clone()));
        assert!(db.scim_group_find("okta", Some("00G1"), None).is_none(), "externalId is exact");

        // A team made by hand, linked once, to one tenant.
        let ops = db.create_team("Ops", None);
        let l = db.link_scim_group("okta", &ops.id, None, "Ops", Some("u1")).unwrap();
        assert_eq!((l.origin.as_str(), l.provisioned_at), ("admin", None));
        assert_eq!(db.link_scim_group("entra", &ops.id, None, "Ops", None).err(), Some(ScimGroupConflict::Team));
        assert_eq!(db.link_scim_group("okta", "t-none", None, "Gone", None).err(), Some(ScimGroupConflict::Gone));
        let saved = db.save_scim_group("okta", &ops.id, Some("00g2"), "Operations", "Operations", true).unwrap();
        assert!(saved.provisioned_at.is_some());
        assert_eq!(db.team(&ops.id).unwrap().name, "Operations");
        assert_eq!(db.save_scim_group("entra", &ops.id, None, "x", "x", true).err(), Some(ScimGroupConflict::Gone), "another tenant's");

        // Unlinked, a stale write finds nothing; a deleted team takes its link with it.
        assert_eq!(db.unlink_scim_group(&ops.id).map(|g| g.origin), Some("admin".into()));
        assert_eq!(db.save_scim_group("okta", &ops.id, None, "x", "x", true).err(), Some(ScimGroupConflict::Gone));
        assert!(db.team(&ops.id).is_some());
        assert!(db.delete_team(&eng.team_id));
        assert!(db.scim_group("okta", &eng.team_id).is_none() && db.scim_groups("okta").is_empty());
    }
}
