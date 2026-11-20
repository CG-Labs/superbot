//! Routines scheduler. Standard 5-field cron: minute hour day-of-month month day-of-week.
//! Supports *, numbers, lists (1,2), ranges (1-5), and steps (*/15, 1-10/2).
//! Uses the server's local time (set TZ).

use crate::audit::{Actor, Outcome, Who};
use crate::db::Routine;
use crate::runner::App;
use crate::tiers;
use chrono::{Datelike, Local, Timelike};
use serde_json::json;
use std::sync::Arc;

const RANGES: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

pub fn parse(expr: &str) -> Result<[Vec<bool>; 5], String> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err("Cron needs 5 fields: minute hour day month weekday".into());
    }
    let mut out: [Vec<bool>; 5] = Default::default();
    for (i, f) in fields.iter().enumerate() {
        let (lo, hi) = RANGES[i];
        let mut set = vec![false; hi as usize + 1];
        for part in f.split(',') {
            let bad = || format!("Bad cron field \"{f}\"");
            let (range, step) = match part.split_once('/') {
                Some((r, s)) => (r, s.parse::<u32>().map_err(|_| bad())?),
                None => (part, 1),
            };
            let (start, end) = if range == "*" {
                (lo, hi)
            } else if let Some((a, b)) = range.split_once('-') {
                (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?)
            } else {
                let v: u32 = range.parse().map_err(|_| bad())?;
                (v, if part.contains('/') { hi } else { v })
            };
            if start < lo || end > hi || start > end || step == 0 {
                return Err(format!("Cron value out of range in \"{f}\""));
            }
            for v in (start..=end).step_by(step as usize) {
                set[if i == 4 && v == 7 { 0 } else { v as usize }] = true;
            }
        }
        out[i] = set;
    }
    Ok(out)
}

pub fn matches(expr: &str, t: &chrono::DateTime<Local>) -> bool {
    let Ok([min, hour, dom, mon, dow]) = parse(expr) else { return false };
    let f: Vec<&str> = expr.split_whitespace().collect();
    let (d, w) = (dom[t.day() as usize], dow[t.weekday().num_days_from_sunday() as usize]);
    // Classic cron: if both day fields are restricted, either one may match.
    let day_ok = if f[2] == "*" || f[4] == "*" { d && w } else { d || w };
    min[t.minute() as usize] && hour[t.hour() as usize] && mon[t.month() as usize] && day_ok
}

/// Checks every 15 seconds; each routine fires at most once per matching minute.
pub fn start(app: Arc<App>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tick.tick().await;
            let now = Local::now();
            let minute = now.timestamp() / 60;
            for r in app.db.routines(None) {
                if !r.enabled || r.last_run_at.is_some_and(|t| t / 60_000 == minute) || !matches(&r.cron, &now) {
                    continue;
                }
                fire(&app, &r, now.timestamp_millis());
            }
        }
    });
}

/// Runs a routine now: queues its instruction for its Bot, unless the owner's tier has
/// no routine runs left today.
pub(crate) fn fire(app: &Arc<App>, r: &Routine, at_ms: i64) {
    app.db.routine_ran(&r.id, at_ms);
    let mut scheduler = Actor::system("scheduler");
    scheduler.on_behalf_of = app.db.bot(&r.bot_id).map(|b| b.owner_id);
    scheduler.asker = r.author_id.clone();
    let by = Who { actor: scheduler, source: Default::default() };
    if let Some(owner) = by.actor.on_behalf_of.as_deref()
        && !take_routine_run(app, r, owner, &by, at_ms)
    {
        return;
    }
    app.db.record(&by.event("routine.fired").target("routine", &r.id).bot(&r.bot_id).details(json!({ "name": r.name, "cron": r.cron })));
    let text = format!("{}: {}", r.name, r.instruction);
    let mut msg = app.db.add_message(&r.bot_id, "routine", &text, None, false, Some("queued"));
    app.db.set_requested_by(msg.id, &by);
    msg.requested_by = Some(by);
    app.push_message(&msg);
    app.enqueue(msg);
}

/// Counts a firing against the owner's daily routine runs (ADR 0040). False: the
/// tier's are used up today, so it doesn't run; that is audited every time, and the
/// Bot says so at the first refusal of the day only.
fn take_routine_run(app: &App, r: &Routine, owner: &str, by: &Who, at_ms: i64) -> bool {
    let day = tiers::day(at_ms);
    let tier = app.tier_of(owner);
    let Err(limit) = app.db.take_routine_run(owner, &day, tier.limits.daily_routine_runs) else { return true };
    let details = json!({ "reason": "tier_routine_limit", "name": r.name, "owner": owner, "tier": tier.name, "limit": limit, "day": day });
    app.db.record(&by.event("routine.run_refused").target("routine", &r.id).bot(&r.bot_id).outcome(Outcome::Denied).details(details));
    if app.db.routine_refused(owner, &day) {
        let text = format!(
            "The {} plan allows {limit} routine runs a day, and today's are used up, so I skipped \"{}\". Routines run again after midnight (UTC).",
            tier.label, r.name
        );
        app.say(&r.bot_id, &text, true);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn cron() {
        let t = Local.with_ymd_and_hms(2026, 11, 16, 7, 30, 0).unwrap(); // a Monday
        assert!(matches("30 7 * * *", &t));
        assert!(matches("*/15 * * * *", &t));
        assert!(matches("30 7 * * 1-5", &t));
        assert!(!matches("30 7 * * 0,6", &t));
        assert!(matches("30 7 1 * 1", &t)); // day-of-month OR weekday
        assert!(!matches("0 8 * * *", &t));
        assert!(parse("61 * * * *").is_err());
        assert!(parse("* * *").is_err());
    }
}
