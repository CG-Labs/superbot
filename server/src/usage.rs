//! Billing-period usage (ADR 0048): the model tokens and runs a user's Bots used in their
//! billing period. The period is their paid Stripe subscription's month when they have
//! one, else the calendar month (UTC). Runs and tokens count against the same period;
//! routine runs stay per UTC day.

use crate::db::{TokenSummary, TokenTotals};
use crate::rbac::{Principal, Role};
use crate::runner::App;
use crate::users::{need_user_key, Caller};
use crate::{need_user, AppState, Res};
use axum::extract::{Extension, Path, State};
use axum::Json;
use chrono::{DateTime, Datelike, Months, TimeZone, Utc};
use serde_json::{json, Value};

/// A subscription period longer than this (a yearly plan) is split into months.
const LONGEST_MONTH_MS: i64 = 32 * 24 * 3600 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Period {
    /// Names the period in `usage_monthly`: `YYYY-MM` for a calendar month, else the
    /// period's start, like `2026-11-14T08:00:00Z`.
    pub key: String,
    /// `[start, end)`, Unix ms.
    pub start: i64,
    pub end: i64,
    pub source: Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Subscription,
    Calendar,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Subscription => "subscription",
            Source::Calendar => "calendar",
        }
    }
}

impl Period {
    pub fn view(&self) -> Value {
        json!({ "key": self.key, "start": self.start, "end": self.end, "source": self.source.as_str() })
    }

    /// When the period ends, for people: `1 Dec 2026` (UTC).
    pub fn end_day(&self) -> String {
        DateTime::from_timestamp_millis(self.end).unwrap_or_default().format("%-d %b %Y").to_string()
    }
}

/// The billing period `at` (Unix ms) falls in, given a paid subscription's period
/// (`start`, `end`, Unix seconds, as Stripe sends them). A monthly subscription's own
/// period, while `at` is in it. Otherwise months counted from its end once `at` is past
/// it (the months after a period whose renewal hasn't arrived yet, which Stripe starts
/// at that end), else from its start (a yearly plan's months). No subscription: the
/// calendar month.
pub fn period_at(sub: Option<(Option<i64>, Option<i64>)>, at: i64) -> Period {
    let ms = |s: i64| s.saturating_mul(1000);
    let (start, end) = sub.unwrap_or_default();
    if let (Some(s), Some(e)) = (start, end)
        && ms(s) <= at
        && at < ms(e)
        && ms(e) - ms(s) <= LONGEST_MONTH_MS
    {
        return subscription(ms(s), ms(e));
    }
    let past_end = end.is_some_and(|e| at >= ms(e));
    let anchor = if past_end { end } else { start.or(end) };
    if let Some(anchor) = anchor.and_then(|s| DateTime::from_timestamp(s, 0)) {
        let now = DateTime::from_timestamp_millis(at).unwrap_or_default();
        let shift = |n: i64| -> Option<DateTime<Utc>> {
            let m = Months::new(u32::try_from(n.unsigned_abs()).ok()?);
            if n >= 0 { anchor.checked_add_months(m) } else { anchor.checked_sub_months(m) }
        };
        let mut n = i64::from(now.year() - anchor.year()) * 12 + i64::from(now.month()) - i64::from(anchor.month());
        // At most one step either way: the estimate is off only by the day of the month.
        for _ in 0..3 {
            match (shift(n), shift(n + 1)) {
                (Some(a), _) if now < a => n -= 1,
                (_, Some(b)) if now >= b => n += 1,
                (Some(a), Some(b)) => return subscription(a.timestamp_millis(), b.timestamp_millis()),
                _ => break,
            }
        }
    }
    calendar(at)
}

fn subscription(start: i64, end: i64) -> Period {
    let key = DateTime::from_timestamp_millis(start).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    Period { key, start, end, source: Source::Subscription }
}

fn calendar(at: i64) -> Period {
    let now = DateTime::from_timestamp_millis(at).unwrap_or_default();
    let first = |y: i32, m: u32| Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).single().map_or(0, |d| d.timestamp_millis());
    let (y, m) = (now.year(), now.month());
    let next = if m == 12 { first(y + 1, 1) } else { first(y, m + 1) };
    Period { key: crate::tiers::period(at), start: first(y, m), end: next, source: Source::Calendar }
}

/// `5000000` -> `5,000,000`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn totals(t: &TokenTotals) -> Value {
    json!({
        "input": t.input, "output": t.output, "cacheRead": t.cache_read, "cacheWrite": t.cache_write,
        "total": t.total(), "runs": t.runs, "unreportedRuns": t.unreported_runs,
    })
}

/// A user's usage this billing period. `admin`: include the per-model breakdown, which
/// a managed tier hides from its members (ADR 0033), and the name of every Bot the
/// usage was on. Otherwise only Bots the user still owns are named: a Bot given to
/// someone else keeps its usage here, but not its new name.
pub fn view(app: &App, user_id: &str, models: bool, admin: bool) -> Value {
    let p = app.billing_period(user_id, crate::db::now());
    let tier = app.tier_of(user_id);
    let TokenSummary { all, by_model, by_bot } = app.db.token_summary(user_id, p.start, p.end);
    let mut tokens = totals(&all);
    tokens["limit"] = json!(tier.limits.monthly_tokens);
    let bots: Vec<Value> = by_bot
        .iter()
        .map(|(id, t)| {
            let mut v = totals(t);
            v["bot"] = json!(id);
            v["name"] = json!(app.db.bot(id).filter(|b| admin || b.owner_id == user_id).map(|b| b.name));
            v
        })
        .collect();
    let mut v = json!({
        "user": user_id,
        "tier": tier.view(),
        "period": p.view(),
        "tokens": tokens,
        "runs": { "used": app.db.runs_used(user_id, &p.key), "limit": tier.limits.monthly_runs },
        "byBot": bots,
    });
    if models {
        v["byModel"] = by_model
            .iter()
            .map(|(m, t)| {
                let mut v = totals(t);
                v["model"] = json!(m);
                v
            })
            .collect();
    }
    v
}

/// `GET /api/me/usage`: your own usage this billing period, nobody else's. People only;
/// the operator sees their own (break-glass) account's.
pub async fn mine(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    need_user(c.principal)?;
    let id = c.user.as_ref().map_or(crate::users::OPERATOR, |u| u.id.as_str());
    let admin = c.principal == Principal::User(Role::Admin);
    Ok(Json(view(&app, id, admin || !app.tier_of(id).managed(), admin)))
}

/// `GET /api/users/{key}/usage` (admins): one user's usage this billing period.
pub async fn of_user(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    Ok(Json(view(&app, &u.id, true, true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(s: &str) -> i64 {
        DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()
    }
    fn secs(s: &str) -> i64 {
        ms(s) / 1000
    }

    #[test]
    fn big_numbers_get_commas() {
        assert_eq!([0, 999, 1000, 5_000_000, 12_345_678].map(thousands), ["0", "999", "1,000", "5,000,000", "12,345,678"]);
    }

    #[test]
    fn no_subscription_means_the_calendar_month() {
        let p = period_at(None, ms("2026-11-20T10:00:00Z"));
        assert_eq!((p.key.as_str(), p.source), ("2026-11", Source::Calendar));
        assert_eq!((p.start, p.end), (ms("2026-11-01T00:00:00Z"), ms("2026-12-01T00:00:00Z")));
        let dec = period_at(None, ms("2026-12-31T23:59:59Z"));
        assert_eq!((dec.key.as_str(), dec.end), ("2026-12", ms("2027-01-01T00:00:00Z")));
        assert_eq!(dec.end_day(), "1 Jan 2027");
        // A subscription with no period known yet: the calendar too.
        assert_eq!(period_at(Some((None, None)), ms("2026-11-20T10:00:00Z")).source, Source::Calendar);
    }

    #[test]
    fn a_monthly_subscription_uses_its_own_period() {
        let (s, e) = (secs("2026-11-14T08:00:00Z"), secs("2026-12-14T08:00:00Z"));
        let p = period_at(Some((Some(s), Some(e))), ms("2026-11-20T10:00:00Z"));
        assert_eq!(p, Period { key: "2026-11-14T08:00:00Z".into(), start: s * 1000, end: e * 1000, source: Source::Subscription });
        // Its end belongs to the next period, which goes on monthly until renewal arrives.
        let next = period_at(Some((Some(s), Some(e))), e * 1000);
        assert_eq!((next.start, next.end), (e * 1000, ms("2027-01-14T08:00:00Z")));
        let later = period_at(Some((Some(s), Some(e))), ms("2027-02-01T00:00:00Z"));
        assert_eq!((later.key.as_str(), later.end), ("2027-01-14T08:00:00Z", ms("2027-02-14T08:00:00Z")));
        // A month-end period whose renewal is late: months from its end, where Stripe's
        // next period starts, not from its start.
        let (fs, fe) = (secs("2026-02-28T12:00:00Z"), secs("2026-03-31T12:00:00Z"));
        let late = period_at(Some((Some(fs), Some(fe))), ms("2026-04-01T00:00:00Z"));
        assert_eq!((late.key.as_str(), late.end), ("2026-03-31T12:00:00Z", ms("2026-04-30T12:00:00Z")));
        // Known only by its end (from before starts were kept): months back from the end.
        let old = period_at(Some((None, Some(e))), ms("2026-11-20T10:00:00Z"));
        assert_eq!((old.start, old.end), (s * 1000, e * 1000));
    }

    #[test]
    fn a_yearly_subscription_counts_by_month() {
        let (s, e) = (secs("2026-01-31T12:00:00Z"), secs("2027-01-31T12:00:00Z"));
        let feb = period_at(Some((Some(s), Some(e))), ms("2026-03-01T00:00:00Z"));
        // From the original anchor: 31 Jan, 28 Feb, 31 Mar.
        assert_eq!((feb.start, feb.end), (ms("2026-02-28T12:00:00Z"), ms("2026-03-31T12:00:00Z")));
        let jan = period_at(Some((Some(s), Some(e))), ms("2026-02-10T00:00:00Z"));
        assert_eq!((jan.start, jan.end, jan.source), (s * 1000, ms("2026-02-28T12:00:00Z"), Source::Subscription));
        // Before the start (a clock skew): the month before it.
        let before = period_at(Some((Some(s), Some(e))), ms("2026-01-20T00:00:00Z"));
        assert_eq!((before.start, before.end), (ms("2025-12-31T12:00:00Z"), s * 1000));
    }
}
