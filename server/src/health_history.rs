//! Customer health score history (ADR 0157): botd records the 30-day health score
//! (ADR 0144) once a UTC day, keeps `HEALTH_SCORE_HISTORY_DAYS` of them (400 by default,
//! 0 to stop), and shows the trend: `GET /api/support/health-score/history` (admins),
//! `botctl health-score history`, the console's Support tab, and
//! `health-score-history.json` in the support bundle.
//!
//! Each day keeps only the score, its band and each signal's status, never the counts or
//! reason codes behind them, so a review deck can quote it as it is.

use crate::db::{HealthScoreDay, now};
use crate::health_score::{self, Status};
use crate::runner::App;
use crate::{AppState, Res, bad};
use axum::Json;
use axum::extract::{Query, State};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};

pub const DEFAULT_KEEP_DAYS: u32 = 400;
pub const MAX_KEEP_DAYS: u32 = 3650;
/// Days shown when none are asked for, and the most that can be.
pub const DEFAULT_DAYS: i64 = 90;
pub const MAX_DAYS: i64 = MAX_KEEP_DAYS as i64;
const DAY_MS: i64 = 86_400_000;

/// `HEALTH_SCORE_HISTORY_DAYS`: days of scores kept; None when botd doesn't record them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Settings {
    pub keep_days: Option<u32>,
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let keep_days = match get("HEALTH_SCORE_HISTORY_DAYS").trim() {
            "" => Some(DEFAULT_KEEP_DAYS),
            "0" => None,
            d => Some(
                d.parse::<u32>()
                    .ok()
                    .filter(|d| (1..=MAX_KEEP_DAYS).contains(d))
                    .ok_or_else(|| format!("HEALTH_SCORE_HISTORY_DAYS must be days from 1 to {MAX_KEEP_DAYS}, or 0 to record none, not {d}"))?,
            ),
        };
        Ok(Settings { keep_days })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings { keep_days: Some(DEFAULT_KEEP_DAYS) }
    }
}

/// Set once at startup, for the history's own report of how long it keeps scores.
static SETTINGS: OnceLock<Settings> = OnceLock::new();

fn settings() -> Settings {
    SETTINGS.get().copied().unwrap_or_default()
}

pub fn date_of(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

/// The day's row for a health score report.
pub fn day_of(report: &Value, at: i64) -> HealthScoreDay {
    let signals: BTreeMap<String, String> = report["signals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s["id"].as_str()?.to_string(), s["status"].as_str()?.to_string())))
        .collect();
    HealthScoreDay {
        day: date_of(at),
        at,
        window_days: report["windowDays"].as_i64().unwrap_or(health_score::DEFAULT_DAYS),
        score: report["score"].as_u64().and_then(|s| u32::try_from(s).ok()),
        band: report["band"].as_str().unwrap_or("unknown").to_string(),
        signals: serde_json::to_string(&signals).unwrap_or_else(|_| "{}".into()),
    }
}

/// Records today's score unless today has one. True if it recorded one.
pub fn record(app: &App, now_ms: i64) -> bool {
    if app.db.health_scores_since(&date_of(now_ms)).iter().any(|d| d.day == date_of(now_ms)) {
        return false;
    }
    let report = health_score::build(app, now_ms, health_score::DEFAULT_DAYS);
    app.db.health_score_record(&day_of(&report, now_ms))
}

/// One pass: today's score, then the days past `keep_days` go.
pub fn tick(app: &App, s: Settings, now_ms: i64) -> (bool, usize) {
    let Some(keep) = s.keep_days else { return (false, 0) };
    let recorded = record(app, now_ms);
    let pruned = app.db.health_scores_prune(&date_of(now_ms - i64::from(keep) * DAY_MS));
    (recorded, pruned)
}

/// Checks hourly that today's score is recorded, unless `HEALTH_SCORE_HISTORY_DAYS=0`.
pub fn start(app: Arc<App>, s: Settings) {
    let _ = SETTINGS.set(s);
    let Some(keep) = s.keep_days else {
        crate::obs::log::log_info!("Health score history: off (HEALTH_SCORE_HISTORY_DAYS=0).");
        return;
    };
    crate::obs::log::log_info!("Health score history: recorded daily, kept {keep} days (ADR 0157).");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        loop {
            let app = app.clone();
            let _ = tokio::task::spawn_blocking(move || tick(&app, s, now())).await;
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}

fn status(s: &str) -> Status {
    match s {
        "ok" => Status::Ok,
        "watch" => Status::Watch,
        "risk" => Status::Risk,
        _ => Status::NotApplicable,
    }
}

fn statuses(d: &HealthScoreDay) -> BTreeMap<String, String> {
    serde_json::from_str(&d.signals).unwrap_or_default()
}

/// How the newest day compares with the oldest: the score's change, and the signals that
/// got worse or better (a signal with nothing to judge on either day is neither).
pub fn trend(days: &[HealthScoreDay]) -> Value {
    let (Some(first), Some(last)) = (days.first(), days.last()) else { return Value::Null };
    if days.len() < 2 {
        return Value::Null;
    }
    let (was, now) = (statuses(first), statuses(last));
    let (mut worse, mut better) = (Vec::new(), Vec::new());
    for s in &health_score::SIGNALS {
        let (a, b) = (was.get(s.id).map_or(Status::NotApplicable, |v| status(v)), now.get(s.id).map_or(Status::NotApplicable, |v| status(v)));
        if a == Status::NotApplicable || b == Status::NotApplicable {
            continue;
        }
        if b > a {
            worse.push(s.id);
        } else if b < a {
            better.push(s.id);
        }
    }
    let change = match (first.score, last.score) {
        (Some(a), Some(b)) => Some(i64::from(b) - i64::from(a)),
        _ => None,
    };
    json!({
        "from": first.day, "to": last.day,
        "fromScore": first.score, "toScore": last.score, "change": change,
        "fromBand": first.band, "toBand": last.band,
        "worse": worse, "better": better,
    })
}

/// The last `days` of recorded scores, oldest first, with the trend across them.
pub fn history(app: &App, now_ms: i64, days: i64) -> Value {
    let rows = app.db.health_scores_since(&date_of(now_ms - (days - 1) * DAY_MS));
    let s = settings();
    json!({
        "recording": s.keep_days.is_some(),
        "keepDays": s.keep_days,
        "windowDays": health_score::DEFAULT_DAYS,
        "days": days,
        "points": rows.iter().map(|d| json!({
            "date": d.day, "score": d.score, "band": d.band, "windowDays": d.window_days, "signals": statuses(d),
        })).collect::<Vec<_>>(),
        "trend": trend(&rows),
    })
}

/// `days` from 1 to `MAX_DAYS`, `DEFAULT_DAYS` if not given.
pub fn days(q: &HashMap<String, String>) -> Result<i64, String> {
    match q.get("days") {
        None => Ok(DEFAULT_DAYS),
        Some(d) => match d.parse::<i64>() {
            Ok(n) if (1..=MAX_DAYS).contains(&n) => Ok(n),
            _ => Err(format!("days must be a whole number from 1 to {MAX_DAYS}")),
        },
    }
}

/// `GET /api/support/health-score/history[?days=90]` (admins).
pub async fn get(State(app): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Res {
    let days = days(&q).map_err(bad)?;
    let v = tokio::task::spawn_blocking(move || history(&app, now(), days))
        .await
        .map_err(|e| crate::ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't read the health score history: {e}")))?;
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY0: i64 = 1_800_000_000_000;

    fn day(n: i64, score: Option<u32>, band: &str, signals: &[(&str, &str)]) -> HealthScoreDay {
        let map: BTreeMap<&str, &str> = signals.iter().copied().collect();
        HealthScoreDay { day: date_of(DAY0 + n * DAY_MS), at: DAY0 + n * DAY_MS, window_days: 30, score, band: band.into(), signals: serde_json::to_string(&map).unwrap() }
    }

    #[test]
    fn settings_default_to_400_days_and_0_turns_it_off() {
        let from = |v: &str| Settings::from_env(&|k| if k == "HEALTH_SCORE_HISTORY_DAYS" { v.into() } else { String::new() });
        assert_eq!(from(""), Ok(Settings { keep_days: Some(400) }));
        assert_eq!(from("0"), Ok(Settings { keep_days: None }));
        assert_eq!(from(" 30 "), Ok(Settings { keep_days: Some(30) }));
        for bad in ["-1", "3651", "a year"] {
            assert!(from(bad).unwrap_err().contains("HEALTH_SCORE_HISTORY_DAYS must be"), "{bad}");
        }
    }

    #[test]
    fn a_day_keeps_the_score_band_and_statuses_only() {
        let report = health_score::report(&health_score::Inputs { days: 30, ..Default::default() }, DAY0);
        let d = day_of(&report, DAY0);
        assert_eq!((d.day.as_str(), d.score, d.band.as_str(), d.window_days), ("2027-01-15", Some(50), "watch", 30));
        let s: BTreeMap<String, String> = serde_json::from_str(&d.signals).unwrap();
        assert_eq!(s.keys().map(String::as_str).collect::<Vec<_>>(), ["adoption", "approvals", "backups", "identity", "license", "runs"]);
        assert_eq!(s["backups"], "watch");
        assert!(!d.signals.contains("summary") && !d.signals.contains("facts"), "{}", d.signals);
    }

    #[test]
    fn the_trend_compares_the_newest_day_with_the_oldest() {
        let days = [
            day(0, Some(90), "healthy", &[("adoption", "ok"), ("runs", "watch"), ("backups", "ok"), ("license", "n/a")]),
            day(1, Some(70), "watch", &[("adoption", "ok"), ("runs", "ok"), ("backups", "ok"), ("license", "ok")]),
            day(2, Some(62), "watch", &[("adoption", "watch"), ("runs", "ok"), ("backups", "risk"), ("license", "ok")]),
        ];
        let t = trend(&days);
        assert_eq!((t["fromScore"].as_u64(), t["toScore"].as_u64(), t["change"].as_i64()), (Some(90), Some(62), Some(-28)), "{t:#}");
        assert_eq!(t["worse"], json!(["adoption", "backups"]), "in the playbook's order");
        assert_eq!(t["better"], json!(["runs"]));
        assert_eq!((t["fromBand"].as_str(), t["toBand"].as_str()), (Some("healthy"), Some("watch")));
        assert_eq!(trend(&days[..1]), Value::Null, "one day is no trend");
        assert_eq!(trend(&[]), Value::Null);
        let unknown = [day(0, None, "unknown", &[]), day(1, Some(80), "healthy", &[])];
        assert_eq!(trend(&unknown)["change"], Value::Null);
    }

    #[test]
    fn one_score_a_day_and_old_days_go() {
        let app = crate::runner::test_app();
        assert!(record(&app, DAY0));
        assert!(!record(&app, DAY0 + 3_600_000), "the first of the day stays");
        assert_eq!(app.db.health_scores_since("2000-01-01").len(), 1);
        for n in 1..=5 {
            assert_eq!(tick(&app, Settings { keep_days: Some(3) }, DAY0 + n * DAY_MS).0, true);
        }
        let kept: Vec<String> = app.db.health_scores_since("2000-01-01").into_iter().map(|d| d.day).collect();
        assert_eq!(kept, [date_of(DAY0 + 2 * DAY_MS), date_of(DAY0 + 3 * DAY_MS), date_of(DAY0 + 4 * DAY_MS), date_of(DAY0 + 5 * DAY_MS)], "today and the 3 days before");
        assert_eq!(tick(&app, Settings { keep_days: None }, DAY0 + 9 * DAY_MS), (false, 0), "off records and deletes nothing");
        assert_eq!(app.db.health_scores_since("2000-01-01").len(), 4);
    }

    #[test]
    fn the_window_is_checked() {
        let q = |d: &str| HashMap::from([("days".to_string(), d.to_string())]);
        assert_eq!(days(&HashMap::new()), Ok(90));
        assert_eq!((days(&q("1")), days(&q("3650"))), (Ok(1), Ok(3650)));
        for d in ["0", "3651", "x", "-3"] {
            assert!(days(&q(d)).is_err(), "{d}");
        }
    }
}
