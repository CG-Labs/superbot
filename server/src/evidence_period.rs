//! The period an evidence bundle covers: whole UTC days, `from` included and `to` not.
//! Shared by botd's evidence bundles (ADR 0142) and `superbot-evidence`'s
//! change-management bundles (ADR 0148), which includes it with `#[path]`, so it needs
//! nothing but chrono.

use chrono::{Datelike, NaiveDate};

/// The longest period one bundle covers: a year's observation period and some.
pub const MAX_DAYS: i64 = 400;

/// A run of whole UTC days, `from` included, `to` not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

impl Period {
    /// The calendar month before `today`.
    pub fn month_before(today: NaiveDate) -> Period {
        let to = today.with_day(1).unwrap_or(today);
        let from = to.pred_opt().and_then(|d| d.with_day(1)).unwrap_or(to);
        Period { from, to }
    }

    /// `from` and `to` as `YYYY-MM-DD`, both or neither (the month before `today`).
    pub fn parse(from: Option<&str>, to: Option<&str>, today: NaiveDate) -> Result<Period, String> {
        let day = |s: &str| NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|_| format!("{s} isn't a date: use YYYY-MM-DD (UTC)"));
        let p = match (from, to) {
            (None, None) => return Ok(Period::month_before(today)),
            (Some(f), Some(t)) => Period { from: day(f)?, to: day(t)? },
            _ => return Err("Give both from and to (YYYY-MM-DD, UTC; to is not included), or neither for last month.".into()),
        };
        if p.to <= p.from {
            return Err("to must be after from.".into());
        }
        if p.days() > MAX_DAYS {
            return Err(format!("A bundle covers at most {MAX_DAYS} days; make one per month or quarter."));
        }
        if p.to > today.succ_opt().unwrap_or(today) {
            return Err("to can be tomorrow at the latest: the period can't end in the future.".into());
        }
        Ok(p)
    }

    pub fn days(&self) -> i64 {
        (self.to - self.from).num_days()
    }

    fn ms(d: NaiveDate) -> i64 {
        d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp_millis()).unwrap_or_default()
    }

    pub fn start_ms(&self) -> i64 {
        Period::ms(self.from)
    }

    pub fn end_ms(&self) -> i64 {
        Period::ms(self.to)
    }

    pub fn label(&self) -> String {
        format!("{}_{}", self.from, self.to)
    }
}
