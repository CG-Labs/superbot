//! Health score alerts (ADR 0307): when botd records the day's health score (ADR 0157),
//! it compares it with the day recorded before and, when it got worse in a way the
//! playbook acts on, records `support.health_score_fell` and sends one notice to the
//! admins' alert channels (the global email list and webhook, ADR 0061): the band fell, a
//! signal went at risk, or the score fell `FALL_POINTS` or more below the last monthly
//! health check's (ADR 0252). Each change is told once, on the day it shows.
//!
//! `/metrics` shows the newest recorded day too, for
//! `deploy/prometheus/superbot-health-score.rules.yml`. Codes, counts and dates only, as
//! in the score itself: no names, emails or reasons.

use crate::audit::{Actor, Event, Filter};
use crate::db::HealthScoreDay;
use crate::health_score::SIGNALS;
use crate::notify::Alert;
use crate::obs::metrics;
use crate::runner::App;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const FELL: &str = "support.health_score_fell";
/// A fall this big since the last health check is worth a line in the customer's record
/// (docs/support/health-score.md#history).
pub const FALL_POINTS: u32 = 10;
/// Bands from best to worst; `unknown` is none of them.
pub const BANDS: [&str; 3] = ["healthy", "watch", "at_risk"];
const ACTOR: &str = "health-score";
/// The console tab a notice links to.
pub const PAGE: &str = "support";
const PLAYBOOK: &str = "docs/support/health-score.md";

/// What got worse from one recorded day to the next.
#[derive(Clone, Debug, PartialEq)]
pub struct Fall {
    pub from_day: String,
    pub day: String,
    pub from_score: Option<u32>,
    pub score: Option<u32>,
    pub from_band: String,
    pub band: String,
    pub band_fell: bool,
    /// Signals at risk that weren't the day before, in the playbook's order, with what
    /// botd saw.
    pub at_risk: Vec<(&'static str, &'static str, String)>,
    /// The last health check's score, when the score is now `FALL_POINTS` below it and
    /// wasn't on a day recorded since the check.
    pub below_check: Option<u32>,
}

fn rank(band: &str) -> Option<usize> {
    BANDS.iter().position(|b| *b == band)
}

fn band_words(band: &str) -> &str {
    match band {
        "at_risk" => "at risk",
        b => b,
    }
}

fn statuses(d: &HealthScoreDay) -> BTreeMap<String, String> {
    serde_json::from_str(&d.signals).unwrap_or_default()
}

/// How `today` (a health score report, recorded on `day`) compares with `before`, the day
/// recorded before it, and with the last health check's score and time. None when nothing
/// got worse in a way the playbook acts on.
pub fn fall(before: &HealthScoreDay, today: &Value, day: &str, last_check: Option<(u32, i64)>) -> Option<Fall> {
    let score = today["score"].as_u64().and_then(|s| u32::try_from(s).ok());
    let band = today["band"].as_str().unwrap_or("unknown").to_string();
    let band_fell = matches!((rank(&before.band), rank(&band)), (Some(a), Some(b)) if b > a);
    let was = statuses(before);
    let signal = |id: &str| today["signals"].as_array().into_iter().flatten().find(|s| s["id"] == id).cloned().unwrap_or(Value::Null);
    let at_risk = SIGNALS
        .iter()
        .filter_map(|s| {
            let now = signal(s.id);
            (now["status"] == "risk" && was.get(s.id).map(String::as_str) != Some("risk")).then(|| (s.id, s.label, now["summary"].as_str().unwrap_or_default().to_string()))
        })
        .collect::<Vec<_>>();
    let below = |s: Option<u32>, c: u32| s.is_some_and(|s| s + FALL_POINTS <= c);
    // A day recorded before the check can't have told of a fall measured from it.
    let below_check = last_check.filter(|&(c, at)| below(score, c) && !(before.at >= at && below(before.score, c))).map(|(c, _)| c);
    (band_fell || !at_risk.is_empty() || below_check.is_some()).then(|| Fall {
        from_day: before.day.clone(),
        day: day.to_string(),
        from_score: before.score,
        score,
        from_band: before.band.clone(),
        band,
        band_fell,
        at_risk,
        below_check,
    })
}

fn score_words(score: Option<u32>, band: &str) -> String {
    match score {
        Some(s) => format!("{s} ({})", band_words(band)),
        None => "unknown".into(),
    }
}

impl Fall {
    /// What `support.health_score_fell` records: codes, scores and dates.
    pub fn audit_details(&self) -> Value {
        json!({
            "from": self.from_day, "to": self.day,
            "fromScore": self.from_score, "score": self.score,
            "fromBand": self.from_band, "band": self.band,
            "bandFell": self.band_fell,
            "atRisk": self.at_risk.iter().map(|(id, _, _)| id).collect::<Vec<_>>(),
            "belowCheck": self.below_check,
        })
    }

    /// The notice: what fell, from what, and where each signal's playbook is.
    pub fn alert(&self) -> Alert {
        let title = format!("The customer health score fell to {}", score_words(self.score, &self.band));
        let mut lines = vec![format!("{}: {}. {}: {}.", self.day, score_words(self.score, &self.band), self.from_day, score_words(self.from_score, &self.from_band))];
        if self.band_fell {
            lines.push(format!("The band fell from {} to {}.", band_words(&self.from_band), band_words(&self.band)));
        }
        for (id, label, summary) in &self.at_risk {
            let summary = if summary.is_empty() { String::new() } else { format!(" {summary}") };
            lines.push(format!("Now at risk: {label}.{summary} What to do: {PLAYBOOK}#{id}"));
        }
        if let Some(c) = self.below_check {
            lines.push(format!("{FALL_POINTS} points or more below the last health check's {c}."));
        }
        lines.push(format!("botctl health-score shows each signal; {PLAYBOOK}#reading-the-score says what each band asks for."));
        Alert { event: FELL.into(), title, lines, target_type: "support".into(), target_id: "health_score".into(), link: None, ..Default::default() }
    }
}

/// The score the last monthly health check recorded, and when, if any.
pub fn last_check(app: &App) -> Option<(u32, i64)> {
    let f = Filter { actions: vec![crate::health_check::CHECKED.into()], ..Default::default() };
    let e = app.db.audit_events(&f, 1, false).into_iter().next()?;
    Some((u32::try_from(e.details["score"].as_u64()?).ok()?, e.at))
}

/// Called once today's score is recorded: records what fell since `before`, the day
/// recorded before today, and returns the notice for it.
pub fn watch(app: &App, before: Option<&HealthScoreDay>, today: &Value, day: &str) -> Option<Alert> {
    let f = fall(before?, today, day, last_check(app))?;
    app.db.record(&Event::new(Actor::system(ACTOR), FELL).target("support", "health_score").details(f.audit_details()));
    Some(f.alert())
}

/// The gauges `/metrics` shows from the newest recorded day, while botd records them. With
/// no day it can read, the timestamp is 0, so a history that never records is alerted on.
pub fn render(app: &App, out: &mut String) {
    if !crate::health_history::recording() {
        return;
    }
    let newest = app.db.health_scores_newest(1).ok().and_then(|v| v.into_iter().next());
    metrics::family(out, "superbot_health_score_recorded_timestamp_seconds", "gauge", "When botd recorded the newest day's health score (ADR 0157); 0 when it has none it can read.");
    metrics::sample(out, "superbot_health_score_recorded_timestamp_seconds", &[], newest.as_ref().map_or(0.0, |d| d.at as f64 / 1000.0));
    let Some(d) = newest else { return };
    if let Some(s) = d.score {
        metrics::family(out, "superbot_health_score", "gauge", "The newest recorded 30-day customer health score, 0 to 100 (ADR 0144).");
        metrics::sample(out, "superbot_health_score", &[], f64::from(s));
    }
    metrics::family(out, "superbot_health_score_band", "gauge", "1 for the newest recorded day's band, 0 for the others; all 0 when unknown.");
    for b in BANDS {
        metrics::sample(out, "superbot_health_score_band", &[("band", b)], f64::from(u8::from(d.band == b)));
    }
    let s = statuses(&d);
    metrics::family(out, "superbot_health_signal_at_risk", "gauge", "1 when a health score signal was at risk on the newest recorded day, by signal.");
    for sig in &SIGNALS {
        metrics::sample(out, "superbot_health_signal_at_risk", &[("signal", sig.id)], f64::from(u8::from(s.get(sig.id).map(String::as_str) == Some("risk"))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(score: Option<u32>, band: &str, signals: &[(&str, &str)]) -> HealthScoreDay {
        let map: BTreeMap<&str, &str> = signals.iter().copied().collect();
        HealthScoreDay { day: "2026-11-25".into(), at: 0, window_days: 30, score, band: band.into(), signals: serde_json::to_string(&map).unwrap() }
    }

    fn report(score: Option<u32>, band: &str, signals: &[(&str, &str, &str)]) -> Value {
        json!({
            "score": score, "band": band,
            "signals": signals.iter().map(|(id, status, summary)| json!({ "id": id, "status": status, "summary": summary })).collect::<Vec<_>>(),
        })
    }

    const OK: [(&str, &str); 3] = [("adoption", "ok"), ("backups", "ok"), ("license", "n/a")];

    #[test]
    fn nothing_worse_is_no_fall() {
        let before = day(Some(85), "healthy", &OK);
        assert_eq!(fall(&before, &report(Some(85), "healthy", &[("adoption", "ok", ""), ("backups", "ok", "")]), "2026-11-26", None), None);
        assert_eq!(fall(&before, &report(Some(81), "healthy", &[("adoption", "watch", "")]), "2026-11-26", Some((85, 0))), None, "4 points, still healthy");
        let risky = day(Some(60), "watch", &[("backups", "risk")]);
        assert_eq!(fall(&risky, &report(Some(55), "watch", &[("backups", "risk", "")]), "2026-11-26", None), None, "at risk yesterday too: told then");
        assert_eq!(fall(&day(Some(40), "at_risk", &OK), &report(Some(70), "watch", &[]), "2026-11-26", None), None, "better");
        assert_eq!(fall(&day(None, "unknown", &[]), &report(Some(60), "watch", &[]), "2026-11-26", None), None, "no band to fall from");
    }

    #[test]
    fn a_band_that_falls_is_told() {
        let f = fall(&day(Some(85), "healthy", &OK), &report(Some(72), "watch", &[("adoption", "watch", "")]), "2026-11-26", None).unwrap();
        assert_eq!((f.band_fell, f.at_risk.len(), f.below_check), (true, 0, None));
        assert_eq!((f.from_score, f.score, f.from_day.as_str(), f.day.as_str()), (Some(85), Some(72), "2026-11-25", "2026-11-26"));
        let a = f.alert();
        assert_eq!(a.title, "The customer health score fell to 72 (watch)");
        assert_eq!(a.lines[0], "2026-11-26: 72 (watch). 2026-11-25: 85 (healthy).");
        assert_eq!(a.lines[1], "The band fell from healthy to watch.");
        assert_eq!((a.event.as_str(), a.target_type.as_str(), a.target_id.as_str()), (FELL, "support", "health_score"));
        let f = fall(&day(Some(60), "watch", &OK), &report(Some(45), "at_risk", &[]), "2026-11-26", None).unwrap();
        assert_eq!(f.alert().lines[1], "The band fell from watch to at risk.");
    }

    #[test]
    fn signals_newly_at_risk_are_told_in_the_playbooks_order_with_what_botd_saw() {
        let before = day(Some(90), "healthy", &[("adoption", "ok"), ("backups", "watch"), ("license", "n/a")]);
        let today = report(
            Some(80),
            "watch",
            &[("license", "risk", "The license has ended."), ("adoption", "ok", ""), ("backups", "risk", "Server backups are past their RPO.")],
        );
        let f = fall(&before, &today, "2026-11-26", None).unwrap();
        assert_eq!(f.at_risk.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(), ["backups", "license"], "from watch and from n/a");
        let a = f.alert();
        assert!(a.lines.contains(&"Now at risk: Backups. Server backups are past their RPO. What to do: docs/support/health-score.md#backups".to_string()), "{a:?}");
        assert!(a.lines.contains(&"Now at risk: License. The license has ended. What to do: docs/support/health-score.md#license".to_string()), "{a:?}");
        assert_eq!(f.audit_details()["atRisk"], json!(["backups", "license"]));
        let healthy_band = fall(&day(Some(95), "healthy", &[("license", "ok")]), &report(Some(95), "watch", &[("license", "risk", "")]), "2026-11-26", None).unwrap();
        assert_eq!(healthy_band.alert().lines[2], "Now at risk: License. What to do: docs/support/health-score.md#license", "no summary, no gap");
    }

    #[test]
    fn a_fall_below_the_last_check_is_told_on_the_day_it_crosses() {
        let today = report(Some(72), "watch", &[]);
        let f = fall(&day(Some(78), "watch", &[]), &today, "2026-11-26", Some((82, 0))).unwrap();
        assert_eq!((f.below_check, f.band_fell), (Some(82), false));
        assert!(f.alert().lines.contains(&"10 points or more below the last health check's 82.".to_string()));
        assert_eq!(fall(&day(Some(71), "watch", &[]), &today, "2026-11-26", Some((82, 0))), None, "already 10 below yesterday, after the check");
        assert_eq!(fall(&day(Some(78), "watch", &[]), &today, "2026-11-26", Some((81, 0))), None, "9 below");
        assert_eq!(fall(&day(Some(78), "watch", &[]), &today, "2026-11-26", None), None, "no check yet");
        assert_eq!(fall(&day(None, "unknown", &[]), &today, "2026-11-26", Some((90, 0))).unwrap().below_check, Some(90), "from unknown");
        assert_eq!(fall(&day(Some(78), "watch", &[]), &report(None, "unknown", &[]), "2026-11-26", Some((90, 0))), None, "unknown isn't a fall");
        let recovered = fall(&day(Some(68), "watch", &[]), &report(Some(68), "watch", &[]), "2026-11-26", Some((100, 1))).unwrap();
        assert_eq!(recovered.below_check, Some(100), "yesterday was recorded before a check that saw it recover, so it told nothing");
    }

    #[test]
    fn the_audit_details_hold_codes_scores_and_dates_only() {
        let f = fall(&day(Some(85), "healthy", &OK), &report(Some(40), "at_risk", &[("backups", "risk", "Server backups are past their RPO.")]), "2026-11-26", Some((88, 0))).unwrap();
        assert_eq!(
            f.audit_details(),
            json!({
                "from": "2026-11-25", "to": "2026-11-26", "fromScore": 85, "score": 40, "fromBand": "healthy", "band": "at_risk",
                "bandFell": true, "atRisk": ["backups"], "belowCheck": 88,
            })
        );
        assert_eq!(fall(&day(Some(85), "healthy", &OK), &report(None, "unknown", &[("runs", "risk", "")]), "2026-11-26", None).unwrap().alert().title, "The customer health score fell to unknown");
    }

    #[test]
    fn it_tells_the_day_after_the_first_record_and_the_metrics_show_the_newest_day() {
        let app = crate::runner::test_app();
        let mut out = String::new();
        render(&app, &mut out);
        assert_eq!(out.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>(), ["superbot_health_score_recorded_timestamp_seconds 0"], "nothing recorded yet");
        app.db.execute_raw("ALTER TABLE health_scores RENAME TO health_scores_gone").unwrap();
        out.clear();
        render(&app, &mut out);
        assert!(out.contains("superbot_health_score_recorded_timestamp_seconds 0\n"), "unreadable: {out}");
        app.db.execute_raw("ALTER TABLE health_scores_gone RENAME TO health_scores").unwrap();
        out.clear();
        let today = report(Some(70), "watch", &[("backups", "risk", "")]);
        assert!(watch(&app, None, &today, "2026-11-26").is_none(), "nothing to compare with");
        let before = day(Some(90), "healthy", &[("backups", "ok")]);
        let a = watch(&app, Some(&before), &today, "2026-11-26").unwrap();
        assert_eq!(a.event, FELL);
        let ev = app.db.audit_events(&Filter { actions: vec![FELL.into()], ..Default::default() }, 10, false);
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].actor_kind.as_str(), ev[0].details["bandFell"].as_bool()), ("system", Some(true)));

        app.db.health_score_record(&before).unwrap();
        app.db.health_score_record(&HealthScoreDay { day: "2026-11-26".into(), at: 1_795_000_000_000, ..day(Some(70), "watch", &[("backups", "risk"), ("adoption", "ok")]) }).unwrap();
        render(&app, &mut out);
        for want in [
            "superbot_health_score 70\n",
            "superbot_health_score_recorded_timestamp_seconds 1795000000\n",
            "superbot_health_score_band{band=\"healthy\"} 0\n",
            "superbot_health_score_band{band=\"watch\"} 1\n",
            "superbot_health_signal_at_risk{signal=\"backups\"} 1\n",
            "superbot_health_signal_at_risk{signal=\"adoption\"} 0\n",
            "superbot_health_signal_at_risk{signal=\"license\"} 0\n",
        ] {
            assert!(out.contains(want), "{want}: {out}");
        }
    }
}
