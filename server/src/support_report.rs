//! The Provider's monthly support report (ADR 0167, #60): from a ticket system's CSV
//! export, each month's tickets by severity, how many had a first human answer within
//! their plan's response target (docs/support/severity.md), which missed it, and what was
//! still open at the end. Business hours, holidays and an agreement's targets are options.
//!
//! It reads only a ticket's id, severity, plan, opened, first-response and resolved times,
//! and (to pick one customer's tickets) its organisation. Subjects, requesters and every
//! other column are never read into the report, and a skipped row is named by its line,
//! not its contents. Runs offline: no botd, no ticket system API.

use chrono::{DateTime, Datelike, FixedOffset, Months, NaiveDate, NaiveDateTime, SecondsFormat, TimeDelta, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const USAGE: &str = "Usage: botctl support-report <tickets.csv | -> [--plan <plan>] [--customer <name>]
    [--from <YYYY-MM> --to <YYYY-MM>] [--hours <HH:MM-HH:MM>] [--weekdays <mon-fri>]
    [--utc-offset <+HH:MM>] [--holidays <YYYY-MM-DD,...>] [--target <severity>=<30m|1h|4bh|1bd>]...
    [--column <field>=<header>]... [--as-of <time>] [--markdown | --json]";

/// The plans of docs/support/severity.md's response targets table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Plan {
    SelfHost,
    Starter,
    Pro,
    Max,
    Enterprise,
}

impl Plan {
    pub const ALL: [Plan; 5] = [Plan::SelfHost, Plan::Starter, Plan::Pro, Plan::Max, Plan::Enterprise];

    pub fn parse(s: &str) -> Option<Plan> {
        let s: String = s.to_ascii_lowercase().chars().filter(char::is_ascii_alphanumeric).collect();
        Some(match s.as_str() {
            "selfhost" | "selfhostlicensed" | "licensed" => Plan::SelfHost,
            "starter" => Plan::Starter,
            "pro" => Plan::Pro,
            "max" => Plan::Max,
            "enterprise" => Plan::Enterprise,
            _ => return None,
        })
    }

    pub fn id(self) -> &'static str {
        match self {
            Plan::SelfHost => "self-host",
            Plan::Starter => "starter",
            Plan::Pro => "pro",
            Plan::Max => "max",
            Plan::Enterprise => "enterprise",
        }
    }
}

/// A response target: clock time, or time inside business hours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Clock(i64),
    Business(i64),
    BusinessDays(i64),
}

impl Target {
    /// `30m` or `1h` on the clock, `4bh` business hours, `1bd` business days.
    pub fn parse(s: &str) -> Option<Target> {
        let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
        let n: i64 = digits.parse().ok().filter(|n| *n > 0 && *n <= 10_000)?;
        Some(match &s[digits.len()..] {
            "m" | "min" => Target::Clock(n),
            "h" => Target::Clock(n * 60),
            "bh" => Target::Business(n * 60),
            "bd" => Target::BusinessDays(n),
            _ => return None,
        })
    }

    /// Plan defaults, as in severity.md (Enterprise: its "by agreement" defaults).
    pub fn default_for(plan: Plan, severity: u8) -> Target {
        use Target::*;
        const H: i64 = 60;
        match (plan, severity) {
            (Plan::SelfHost, 1) => BusinessDays(1),
            (Plan::SelfHost, 2) => BusinessDays(2),
            (Plan::SelfHost, 3) => BusinessDays(3),
            (Plan::SelfHost, _) => BusinessDays(5),
            (Plan::Starter, 1) => Business(4 * H),
            (Plan::Starter, 2) => BusinessDays(1),
            (Plan::Starter, 3) => BusinessDays(2),
            (Plan::Starter, _) => BusinessDays(5),
            (Plan::Pro, 1) => Clock(H),
            (Plan::Pro, 2) => Business(4 * H),
            (Plan::Pro, 3) => BusinessDays(1),
            (Plan::Pro, _) => BusinessDays(3),
            (Plan::Max, 1) => Clock(H),
            (Plan::Max, 2) => Business(2 * H),
            (Plan::Max, 3) => BusinessDays(1),
            (Plan::Max, _) => BusinessDays(2),
            (Plan::Enterprise, 1) => Clock(30),
            (Plan::Enterprise, 2) => Clock(2 * H),
            (Plan::Enterprise, 3) => Business(4 * H),
            (Plan::Enterprise, _) => BusinessDays(1),
        }
    }

    pub fn describe(self) -> String {
        match self {
            Target::Clock(m) => format!("{}, 24×7", minutes(m)),
            Target::Business(m) => format!("{} business h", hours_text(m)),
            Target::BusinessDays(1) => "1 business day".into(),
            Target::BusinessDays(n) => format!("{n} business days"),
        }
    }

    fn limit_secs(self, cal: &Calendar) -> i64 {
        match self {
            Target::Clock(m) | Target::Business(m) => m * 60,
            Target::BusinessDays(n) => n * cal.day_secs(),
        }
    }

    fn elapsed_secs(self, cal: &Calendar, from: DateTime<Utc>, to: DateTime<Utc>) -> i64 {
        match self {
            Target::Clock(_) => (to - from).num_seconds().max(0),
            Target::Business(_) | Target::BusinessDays(_) => cal.business_secs(from, to),
        }
    }
}

fn hours_text(m: i64) -> String {
    if m % 60 == 0 { (m / 60).to_string() } else { format!("{:.1}", m as f64 / 60.0) }
}

/// "45 min", "5 h 10 min", "3 h".
fn minutes(m: i64) -> String {
    match (m / 60, m % 60) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

const WEEKDAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// The support hours that business-time targets count: one span a day on some weekdays,
/// at a fixed UTC offset, except holidays.
#[derive(Clone, Debug)]
pub struct Calendar {
    pub open: i64,
    pub close: i64,
    pub weekdays: [bool; 7],
    pub offset: FixedOffset,
    pub holidays: HashSet<NaiveDate>,
}

impl Default for Calendar {
    fn default() -> Self {
        Calendar { open: 9 * 60, close: 17 * 60 + 30, weekdays: [true, true, true, true, true, false, false], offset: FixedOffset::east_opt(0).unwrap(), holidays: HashSet::new() }
    }
}

impl Calendar {
    fn day_secs(&self) -> i64 {
        (self.close - self.open) * 60
    }

    fn is_business_day(&self, d: NaiveDate) -> bool {
        self.weekdays[d.weekday().num_days_from_monday() as usize] && !self.holidays.contains(&d)
    }

    /// Seconds between two instants that fall inside business hours.
    pub fn business_secs(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> i64 {
        if to <= from {
            return 0;
        }
        let a = from.with_timezone(&self.offset).naive_local();
        let b = to.with_timezone(&self.offset).naive_local();
        let mut total = 0;
        let mut day = a.date();
        while day <= b.date() {
            if self.is_business_day(day) {
                let midnight = day.and_hms_opt(0, 0, 0).unwrap();
                let start = (midnight + TimeDelta::minutes(self.open)).max(a);
                let end = (midnight + TimeDelta::minutes(self.close)).min(b);
                total += (end - start).num_seconds().max(0);
            }
            let Some(next) = day.succ_opt() else { break };
            day = next;
        }
        total
    }

    fn hours(&self) -> String {
        let hm = |m: i64| format!("{:02}:{:02}", m / 60, m % 60);
        format!("{}-{}", hm(self.open), hm(self.close))
    }

    fn weekday_names(&self) -> Vec<&'static str> {
        WEEKDAYS.iter().zip(self.weekdays).filter(|(_, on)| *on).map(|(d, _)| *d).collect()
    }
}

fn parse_hours(s: &str) -> Option<(i64, i64)> {
    let hm = |t: &str| -> Option<i64> {
        let (h, m) = t.split_once(':')?;
        let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
        (h <= 24 && m < 60 && h * 60 + m <= 24 * 60).then_some(h * 60 + m)
    };
    let (a, b) = s.split_once('-')?;
    let (a, b) = (hm(a)?, hm(b)?);
    (a < b).then_some((a, b))
}

fn parse_weekdays(s: &str) -> Option<[bool; 7]> {
    let day = |d: &str| WEEKDAYS.iter().position(|w| d.to_ascii_lowercase().starts_with(w));
    let mut on = [false; 7];
    if s == "all" {
        return Some([true; 7]);
    }
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (day(a)?, day(b)?);
                if a > b {
                    return None;
                }
                on[a..=b].iter_mut().for_each(|d| *d = true);
            }
            None => on[day(part)?] = true,
        }
    }
    on.contains(&true).then_some(on)
}

fn parse_offset(s: &str) -> Option<FixedOffset> {
    if s.eq_ignore_ascii_case("utc") || s == "Z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
    let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
    (h <= 14 && m < 60).then(|| FixedOffset::east_opt(sign * (h * 3600 + m * 60))).flatten()
}

/// RFC 3339, or a date and time as ticket systems export them; with no offset, at `offset`.
pub fn parse_time(s: &str, offset: FixedOffset) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    for f in ["%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M %z", "%Y-%m-%dT%H:%M:%S%z"] {
        if let Ok(t) = DateTime::parse_from_str(s, f) {
            return Some(t.with_timezone(&Utc));
        }
    }
    for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, f) {
            return Some((t - TimeDelta::seconds(offset.local_minus_utc() as i64)).and_utc());
        }
    }
    None
}

/// Severity 1 to 4 from "1", "Sev 2", "S3", "P1", "Severity 1: Critical", or the names
/// ticket systems use for priorities.
pub fn parse_severity(s: &str) -> Option<u8> {
    let lower = s.trim().to_ascii_lowercase();
    if let Some(at) = lower.find(|c: char| c.is_ascii_digit()) {
        let n: String = lower[at..].chars().take_while(char::is_ascii_digit).collect();
        return n.parse::<u8>().ok().filter(|d| (1..=4).contains(d));
    }
    Some(match lower.as_str() {
        "critical" | "urgent" | "emergency" | "highest" | "blocker" => 1,
        "high" | "major" => 2,
        "normal" | "medium" | "moderate" => 3,
        "low" | "lowest" | "minor" | "trivial" => 4,
        _ => return None,
    })
}

/// The columns the report reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Id,
    Severity,
    Opened,
    Responded,
    Resolved,
    Plan,
    Customer,
}

impl Field {
    const ALL: [Field; 7] = [Field::Id, Field::Severity, Field::Opened, Field::Responded, Field::Resolved, Field::Plan, Field::Customer];

    fn parse(s: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == s)
    }

    fn name(self) -> &'static str {
        match self {
            Field::Id => "id",
            Field::Severity => "severity",
            Field::Opened => "opened",
            Field::Responded => "first-response",
            Field::Resolved => "resolved",
            Field::Plan => "plan",
            Field::Customer => "customer",
        }
    }

    /// Header names that mean this field, lowercased with punctuation as spaces.
    fn aliases(self) -> &'static [&'static str] {
        match self {
            Field::Id => &["id", "ticket id", "ticket", "ticket number", "ticket no", "number", "key", "issue key", "case number", "case id"],
            Field::Severity => &["severity", "sev", "priority", "ticket priority"],
            Field::Opened => &["opened", "opened at", "created", "created at", "date created", "created date", "requested", "submitted", "submitted at"],
            Field::Responded => &["first response", "first response at", "first responded at", "first response time", "first reply", "first reply at", "first replied at", "responded at"],
            Field::Resolved => &["resolved", "resolved at", "solved", "solved at", "closed", "closed at", "date closed", "resolution date"],
            Field::Plan => &["plan", "tier", "support plan", "support tier"],
            Field::Customer => &["customer", "organization", "organisation", "org", "account", "company"],
        }
    }
}

fn normalize(h: &str) -> String {
    let s: String = h.trim().trim_start_matches('\u{feff}').to_lowercase().chars().map(|c| if c.is_alphanumeric() { c } else { ' ' }).collect();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// RFC 4180 records, each with the line it starts on: quoted fields with commas, quotes
/// and line breaks. The delimiter is the header line's commonest of comma, semicolon and tab.
pub fn parse_csv(text: &str) -> Result<Vec<(usize, Vec<String>)>, String> {
    let text = text.trim_start_matches('\u{feff}');
    let header = text.lines().next().unwrap_or("");
    let delim = [',', ';', '\t'].into_iter().max_by_key(|d| header.matches(*d).count()).unwrap_or(',');
    let (mut rows, mut row, mut field) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, text.chars().peekable());
    let (mut line, mut start) = (1, 1);
    while let Some(c) = chars.next() {
        if c == '\n' {
            line += 1;
        }
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => quoted = true,
            (false, c) if c == delim => row.push(std::mem::take(&mut field)),
            (false, '\r') if chars.peek() == Some(&'\n') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push((start, std::mem::take(&mut row)));
                start = line;
            }
            (false, c) => field.push(c),
        }
    }
    if quoted {
        return Err("the CSV ends inside a quoted field".into());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push((start, row));
    }
    rows.retain(|(_, r)| r.iter().any(|f| !f.trim().is_empty()));
    Ok(rows)
}

#[derive(Clone, Debug)]
pub struct Options {
    pub plan: Option<Plan>,
    pub customer: Option<String>,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub calendar: Calendar,
    pub targets: BTreeMap<u8, Target>,
    pub columns: Vec<(Field, String)>,
    pub as_of: DateTime<Utc>,
}

impl Options {
    /// The last three full months before `as_of`, the plans' targets, and default hours.
    pub fn new(as_of: DateTime<Utc>) -> Options {
        let this = as_of.date_naive().with_day(1).unwrap();
        Options {
            plan: None,
            customer: None,
            from: this - Months::new(3),
            to: this - Months::new(1),
            calendar: Calendar::default(),
            targets: BTreeMap::new(),
            columns: Vec::new(),
            as_of,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Markdown,
    Json,
}

fn month(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(&format!("{s}-01"), "%Y-%m-%d").map_err(|_| format!("{s} isn't a month (YYYY-MM)"))
}

/// `botctl support-report ...`: the file (`-` for stdin), the options and the format.
pub fn parse_args(rest: &[&str], now: DateTime<Utc>) -> Result<(String, Options, Format), String> {
    let mut o = Options::new(now);
    let (mut file, mut format, mut period, mut as_of) = (None, Format::Text, (None, None), None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().copied().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{a} needs a value.\n{USAGE}"));
        match *a {
            "--markdown" => format = Format::Markdown,
            "--json" | "json" => format = Format::Json,
            "--plan" => {
                let v = value()?;
                let plans: Vec<&str> = Plan::ALL.iter().map(|p| p.id()).collect();
                o.plan = Some(Plan::parse(v).ok_or_else(|| format!("--plan: {v} isn't one of {}", plans.join(", ")))?);
            }
            "--customer" => o.customer = Some(value()?.to_string()),
            "--from" => period.0 = Some(month(value()?)?),
            "--to" => period.1 = Some(month(value()?)?),
            "--hours" => {
                let v = value()?;
                (o.calendar.open, o.calendar.close) = parse_hours(v).ok_or_else(|| format!("--hours: {v} isn't HH:MM-HH:MM with the start first"))?;
            }
            "--weekdays" => {
                let v = value()?;
                o.calendar.weekdays = parse_weekdays(v).ok_or_else(|| format!("--weekdays: {v} isn't days like mon-fri or mon,wed,fri"))?;
            }
            "--utc-offset" => {
                let v = value()?;
                o.calendar.offset = parse_offset(v).ok_or_else(|| format!("--utc-offset: {v} isn't an offset like +01:00 or -05:00"))?;
            }
            "--holidays" => {
                for d in value()?.split(',').filter(|d| !d.is_empty()) {
                    o.calendar.holidays.insert(NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| format!("--holidays: {d} isn't a date (YYYY-MM-DD)"))?);
                }
            }
            "--target" => {
                let v = value()?;
                let bad = || format!("--target: {v} isn't <severity>=<time>, such as 1=30m, 2=2h, 3=4bh or 4=1bd");
                let (sev, t) = v.split_once('=').ok_or_else(bad)?;
                let sev = sev.parse::<u8>().ok().filter(|s| (1..=4).contains(s)).ok_or_else(bad)?;
                o.targets.insert(sev, Target::parse(t).ok_or_else(bad)?);
            }
            "--column" => {
                let v = value()?;
                let (f, header) = v.split_once('=').filter(|(_, h)| !h.trim().is_empty()).ok_or_else(|| format!("--column: {v} isn't <field>=<header>"))?;
                let names: Vec<&str> = Field::ALL.iter().map(|f| f.name()).collect();
                let field = Field::parse(f).ok_or_else(|| format!("--column: {f} isn't one of {}", names.join(", ")))?;
                o.columns.push((field, header.to_string()));
            }
            "--as-of" => as_of = Some(value()?),
            v if file.is_none() && (v == "-" || !v.starts_with('-')) => file = Some(v.to_string()),
            _ => return Err(USAGE.into()),
        }
    }
    if let Some(t) = as_of {
        o.as_of = parse_time(t, o.calendar.offset).ok_or_else(|| format!("--as-of: {t} isn't a time"))?;
        let fresh = Options::new(o.as_of);
        (o.from, o.to) = (fresh.from, fresh.to);
    }
    match period {
        (None, None) => {}
        (Some(f), Some(t)) if f <= t && t < f + Months::new(36) => (o.from, o.to) = (f, t),
        (Some(_), Some(_)) => return Err("--from must be on or before --to, and at most 36 months before it".into()),
        _ => return Err("Give both --from and --to, or neither for the last three full months".into()),
    }
    Ok((file.ok_or(USAGE)?, o, format))
}

#[derive(Clone, Debug, Default)]
struct Counts {
    opened: u32,
    met: u32,
    missed: u32,
    waiting: u32,
    closed: u32,
    firsts: Vec<i64>,
}

impl Counts {
    fn median_minutes(&self) -> Option<i64> {
        let mut v = self.firsts.clone();
        v.sort_unstable();
        let n = v.len();
        (n > 0).then(|| (if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2 }) / 60)
    }

    fn add(&mut self, o: &Counts) {
        self.opened += o.opened;
        self.met += o.met;
        self.missed += o.missed;
        self.waiting += o.waiting;
        self.closed += o.closed;
        self.firsts.extend(&o.firsts);
    }

    fn json(&self) -> Value {
        json!({ "opened": self.opened, "met": self.met, "missed": self.missed, "waiting": self.waiting, "closed": self.closed, "medianFirstResponseMinutes": self.median_minutes() })
    }
}

#[derive(Clone, Debug)]
struct Miss {
    id: String,
    severity: u8,
    plan: Plan,
    opened: DateTime<Utc>,
    answered: bool,
    took: i64,
    target: Target,
}

#[derive(Debug)]
pub struct Report {
    o: Options,
    months: Vec<(NaiveDate, [Counts; 4])>,
    missed: Vec<Miss>,
    open_at_end: Option<[u32; 4]>,
    plans: BTreeSet<Plan>,
    skipped: Vec<(usize, &'static str)>,
}

/// The report on `csv`'s tickets, as `o` says.
pub fn report(csv: &str, o: &Options) -> Result<Report, String> {
    let rows = parse_csv(csv)?;
    let ((_, header), body) = rows.split_first().ok_or("the CSV is empty")?;
    let headers: Vec<String> = header.iter().map(|h| normalize(h)).collect();
    let mut col = BTreeMap::new();
    for f in Field::ALL {
        let named = o.columns.iter().find(|(c, _)| *c == f).map(|(_, h)| normalize(h));
        let at = match &named {
            Some(h) => Some(headers.iter().position(|x| x == h).ok_or_else(|| format!("--column {}: the CSV has no column \"{h}\"", f.name()))?),
            None => f.aliases().iter().find_map(|a| headers.iter().position(|x| x == a)),
        };
        if let Some(i) = at {
            col.insert(f.name(), i);
        }
    }
    for f in [Field::Id, Field::Severity, Field::Opened, Field::Responded] {
        if !col.contains_key(f.name()) {
            return Err(format!("the CSV has no {} column; name it with --column {}=<header>", f.name(), f.name()));
        }
    }
    if o.plan.is_none() && !col.contains_key("plan") {
        return Err("say which plan the tickets are on with --plan, or name a plan column with --column plan=<header>".into());
    }
    if o.customer.is_some() && !col.contains_key("customer") {
        return Err("--customer needs a customer column; name it with --column customer=<header>".into());
    }

    let end = o.to + Months::new(1);
    let month_of = |t: DateTime<Utc>| t.date_naive().with_day(1).unwrap();
    let in_period = |t: DateTime<Utc>| (o.from..end).contains(&t.date_naive());
    let mut months: BTreeMap<NaiveDate, [Counts; 4]> = BTreeMap::new();
    let mut m = o.from;
    while m < end {
        months.insert(m, Default::default());
        m = m + Months::new(1);
    }
    let (mut missed, mut plans, mut skipped) = (Vec::new(), BTreeSet::new(), Vec::new());
    let mut open_at_end = col.contains_key("resolved").then_some([0u32; 4]);
    let wanted = o.customer.as_deref().map(normalize);
    if wanted.as_deref() == Some("") {
        return Err("--customer needs a name with letters or digits in it".into());
    }
    let offset = o.calendar.offset;

    for (line, r) in body {
        let line = *line;
        let cell = |f: Field| col.get(f.name()).and_then(|&c| r.get(c)).map(|s| s.trim()).filter(|s| !s.is_empty());
        if let Some(w) = &wanted {
            if cell(Field::Customer).map(normalize).as_ref() != Some(w) {
                continue;
            }
        }
        let time = |f: Field| cell(f).map(|s| parse_time(s, offset).ok_or("a time that can't be read"));
        let ticket = (|| -> Result<_, &'static str> {
            let id = cell(Field::Id).ok_or("no id")?;
            let severity = parse_severity(cell(Field::Severity).ok_or("no severity")?).ok_or("a severity that isn't 1 to 4")?;
            let plan = match cell(Field::Plan) {
                Some(p) => Plan::parse(p).ok_or("a plan that isn't one of SuperBot's")?,
                None => o.plan.ok_or("no plan (give --plan)")?,
            };
            let opened = time(Field::Opened).ok_or("no opened time")??;
            let responded = time(Field::Responded).transpose()?;
            let resolved = time(Field::Resolved).transpose()?;
            if responded.is_some_and(|t| t < opened) || resolved.is_some_and(|t| t < opened) {
                return Err("a time before it was opened");
            }
            Ok((id, severity, plan, opened, responded, resolved))
        })();
        let (id, severity, plan, opened, responded, resolved) = match ticket {
            Ok(t) => t,
            Err(why) => {
                skipped.push((line, why));
                continue;
            }
        };
        let s = severity as usize - 1;
        if let Some(open) = &mut open_at_end {
            if opened.date_naive() < end && resolved.is_none_or(|t| t.date_naive() >= end) {
                open[s] += 1;
            }
        }
        if let Some(t) = resolved.filter(|t| in_period(*t)) {
            months.get_mut(&month_of(t)).unwrap()[s].closed += 1;
        }
        if !in_period(opened) {
            continue;
        }
        plans.insert(plan);
        let target = o.targets.get(&severity).copied().unwrap_or_else(|| Target::default_for(plan, severity));
        let limit = target.limit_secs(&o.calendar);
        let c = &mut months.get_mut(&month_of(opened)).unwrap()[s];
        c.opened += 1;
        let (took, answered) = match responded {
            Some(t) => {
                c.firsts.push((t - opened).num_seconds());
                (target.elapsed_secs(&o.calendar, opened, t), true)
            }
            None => (target.elapsed_secs(&o.calendar, opened, o.as_of), false),
        };
        if answered && took <= limit {
            c.met += 1;
        } else if !answered && took <= limit {
            c.waiting += 1;
        } else {
            c.missed += 1;
            missed.push(Miss { id: id.to_string(), severity, plan, opened, answered, took, target });
        }
    }
    missed.sort_by(|a, b| a.opened.cmp(&b.opened).then(a.id.cmp(&b.id)));
    Ok(Report { o: o.clone(), months: months.into_iter().collect(), missed, open_at_end, plans, skipped })
}

fn percent(met: u32, missed: u32) -> Option<u32> {
    let judged = met + missed;
    (judged > 0).then(|| ((met as f64 / judged as f64) * 100.0).floor() as u32)
}

impl Report {
    fn totals(&self) -> [Counts; 4] {
        let mut t: [Counts; 4] = Default::default();
        for (_, m) in &self.months {
            for (a, b) in t.iter_mut().zip(m) {
                a.add(b);
            }
        }
        t
    }

    fn month_name(d: NaiveDate) -> String {
        d.format("%Y-%m").to_string()
    }

    fn targets(&self) -> Vec<(Plan, u8, Target)> {
        let plans: Vec<Plan> = if self.plans.is_empty() { self.o.plan.into_iter().collect() } else { self.plans.iter().copied().collect() };
        plans.into_iter().flat_map(|p| (1..=4).map(move |s| (p, s))).map(|(p, s)| (p, s, self.o.targets.get(&s).copied().unwrap_or_else(|| Target::default_for(p, s)))).collect()
    }

    fn miss_json(m: &Miss) -> Value {
        json!({
            "id": m.id, "severity": m.severity, "plan": m.plan.id(), "opened": m.opened.to_rfc3339_opts(SecondsFormat::Secs, true),
            "answered": m.answered, "tookMinutes": m.took / 60, "target": m.target.describe(),
        })
    }

    pub fn json(&self) -> Value {
        let cal = &self.o.calendar;
        let totals = self.totals();
        let (met, missed) = totals.iter().fold((0, 0), |(a, b), c| (a + c.met, b + c.missed));
        json!({
            "format": 1,
            "from": Self::month_name(self.o.from),
            "to": Self::month_name(self.o.to),
            "asOf": self.o.as_of.to_rfc3339_opts(SecondsFormat::Secs, true),
            "customer": self.o.customer,
            "businessHours": { "hours": cal.hours(), "weekdays": cal.weekday_names(), "utcOffset": cal.offset.to_string(), "holidays": cal.holidays.len() },
            "targets": self.targets().iter().map(|(p, s, t)| json!({ "plan": p.id(), "severity": s, "target": t.describe(), "agreed": self.o.targets.contains_key(s) })).collect::<Vec<_>>(),
            "months": self.months.iter().map(|(m, c)| json!({ "month": Self::month_name(*m), "severities": c.iter().enumerate().map(|(i, c)| { let mut v = c.json(); v["severity"] = json!(i + 1); v }).collect::<Vec<_>>() })).collect::<Vec<_>>(),
            "totals": { "severities": totals.iter().enumerate().map(|(i, c)| { let mut v = c.json(); v["severity"] = json!(i + 1); v }).collect::<Vec<_>>(), "met": met, "missed": missed, "metPercent": percent(met, missed) },
            "missed": self.missed.iter().map(Self::miss_json).collect::<Vec<_>>(),
            "openAtEnd": self.open_at_end.map(|o| o.iter().enumerate().map(|(i, n)| json!({ "severity": i + 1, "open": n })).collect::<Vec<_>>()),
            "skipped": self.skipped.iter().map(|(line, why)| json!({ "line": line, "reason": why })).collect::<Vec<_>>(),
        })
    }

    fn heading(&self) -> String {
        let cal = &self.o.calendar;
        let who = self.o.customer.as_deref().map_or(String::new(), |c| format!(" for {c}"));
        let holidays = match cal.holidays.len() {
            0 => String::new(),
            1 => ", 1 holiday".into(),
            n => format!(", {n} holidays"),
        };
        format!(
            "Support report{who}: {} to {}, as of {}\nBusiness hours {} {} at UTC{}{holidays}",
            Self::month_name(self.o.from),
            Self::month_name(self.o.to),
            self.o.as_of.format("%Y-%m-%d %H:%M UTC"),
            cal.hours(),
            cal.weekday_names().join(","),
            cal.offset,
        )
    }

    fn summary(&self) -> String {
        let t = self.totals();
        let (met, missed, waiting) = t.iter().fold((0, 0, 0), |(a, b, c), x| (a + x.met, b + x.missed, c + x.waiting));
        let mut s = match percent(met, missed) {
            Some(p) => format!("{met} of {} answered within target ({p}%).", met + missed),
            None => "No tickets to judge in the period.".into(),
        };
        if waiting > 0 {
            s.push_str(&format!(" {waiting} still waiting for a first answer, within target."));
        }
        s
    }

    fn missed_line(m: &Miss) -> (String, String, String, String) {
        let took = if m.answered { format!("answered after {}", minutes(m.took / 60)) } else { format!("no answer yet after {}", minutes(m.took / 60)) };
        let unit = match m.target {
            Target::Clock(_) => "",
            _ => " of business time",
        };
        (m.id.clone(), format!("{} ({})", m.severity, m.plan.id()), m.opened.format("%Y-%m-%d %H:%M UTC").to_string(), format!("{took}{unit}; target {}", m.target.describe()))
    }

    fn open_line(&self) -> Option<String> {
        self.open_at_end.map(|o| o.iter().enumerate().map(|(i, n)| format!("Sev {}: {n}", i + 1)).collect::<Vec<_>>().join(", "))
    }

    fn skipped_line(&self) -> Option<String> {
        (!self.skipped.is_empty()).then(|| {
            let shown: Vec<String> = self.skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
            let more = if self.skipped.len() > 20 { format!(", and {} more", self.skipped.len() - 20) } else { String::new() };
            format!("Skipped {} rows: {}{more}.", self.skipped.len(), shown.join(", "))
        })
    }

    fn month_rows(&self) -> Vec<[String; 7]> {
        let median = |c: &Counts| c.median_minutes().map_or("-".into(), minutes);
        let mut rows = Vec::new();
        for (m, counts) in &self.months {
            let busy: Vec<(usize, &Counts)> = counts.iter().enumerate().filter(|(_, c)| c.opened + c.closed > 0).collect();
            if busy.is_empty() {
                rows.push([Self::month_name(*m), "-".into(), "0".into(), "0".into(), "0".into(), "0".into(), "-".into()]);
            }
            for (i, c) in busy {
                rows.push([Self::month_name(*m), (i + 1).to_string(), c.opened.to_string(), c.met.to_string(), c.missed.to_string(), c.closed.to_string(), median(c)]);
            }
        }
        rows
    }

    pub fn text(&self) -> String {
        let mut out = format!("{}\n\n", self.heading());
        out.push_str(&format!("{:<8} {:>3} {:>6} {:>5} {:>6} {:>6}  {}\n", "Month", "Sev", "Opened", "Met", "Missed", "Closed", "Median first answer"));
        for r in self.month_rows() {
            out.push_str(&format!("{:<8} {:>3} {:>6} {:>5} {:>6} {:>6}  {}\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6]));
        }
        out.push_str(&format!("\n{}\n", self.summary()));
        if !self.missed.is_empty() {
            out.push_str("Missed:\n");
            for m in &self.missed {
                let (id, sev, opened, what) = Self::missed_line(m);
                out.push_str(&format!("  {id}  Sev {sev}  opened {opened}  {what}\n"));
            }
        }
        if let Some(o) = self.open_line() {
            out.push_str(&format!("Open at the end of the period: {o}.\n"));
        }
        if let Some(s) = self.skipped_line() {
            out.push_str(&format!("{s}\n"));
        }
        out.push_str("Targets: docs/support/severity.md. Met and missed count first human answers only.\n");
        out
    }

    pub fn markdown(&self) -> String {
        let mut out = String::new();
        let mut head = self.heading().lines().map(String::from).collect::<Vec<_>>();
        out.push_str(&format!("## {}\n\n{}.\n\n", head.remove(0), head.join(" ")));
        out.push_str("| Month | Severity | Opened | Met | Missed | Closed | Median first answer |\n|---|---|---|---|---|---|---|\n");
        for r in self.month_rows() {
            out.push_str(&format!("| {} |\n", r.join(" | ")));
        }
        out.push_str(&format!("\n{}\n", self.summary()));
        if !self.missed.is_empty() {
            out.push_str("\n### Missed response targets\n\n| Ticket | Severity | Opened | What happened |\n|---|---|---|---|\n");
            for m in &self.missed {
                let (id, sev, opened, what) = Self::missed_line(m);
                out.push_str(&format!("| {} | {sev} | {opened} | {what} |\n", id.replace('|', "\\|")));
            }
        }
        if let Some(o) = self.open_line() {
            out.push_str(&format!("\nOpen at the end of the period: {o}.\n"));
        }
        if let Some(s) = self.skipped_line() {
            out.push_str(&format!("\n{s}\n"));
        }
        out.push_str("\nTargets per plan and severity: ");
        out.push_str(&self.targets().iter().map(|(p, s, t)| format!("{} Sev {s} {}", p.id(), t.describe())).collect::<Vec<_>>().join("; "));
        out.push_str(".\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s, FixedOffset::east_opt(0).unwrap()).unwrap()
    }

    fn opts(as_of: &str) -> Options {
        Options::new(t(as_of))
    }

    #[test]
    fn plan_defaults_match_the_severity_playbook() {
        let md = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/severity.md")).unwrap();
        let section = md.split("## Response targets").nth(1).unwrap().split("\n## ").next().unwrap();
        let header: Vec<&str> = section.lines().find(|l| l.starts_with("| Severity |")).unwrap().trim_matches('|').split('|').map(str::trim).collect();
        let plan_of = |h: &str| Plan::parse(h).unwrap_or_else(|| panic!("severity.md's column {h} isn't a plan"));
        let cols: Vec<Plan> = header[1..].iter().map(|h| plan_of(h)).collect();
        assert_eq!(cols, Plan::ALL, "a column per plan, in order");
        let mut seen = 0;
        for line in section.lines() {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let Ok(sev) = cells[0].parse::<u8>() else { continue };
            for (plan, cell) in cols.iter().zip(&cells[1..]) {
                let cell = cell.strip_prefix("By agreement (default ").and_then(|c| c.strip_suffix(')')).unwrap_or(cell);
                let want = Target::default_for(*plan, sev).describe();
                assert_eq!(cell, want, "severity {sev} on {plan:?}");
                seen += 1;
            }
        }
        assert_eq!(seen, 20, "4 severities by 5 plans");
    }

    #[test]
    fn targets_and_options_parse() {
        assert_eq!(Target::parse("30m"), Some(Target::Clock(30)));
        assert_eq!(Target::parse("2h"), Some(Target::Clock(120)));
        assert_eq!(Target::parse("4bh"), Some(Target::Business(240)));
        assert_eq!(Target::parse("1bd"), Some(Target::BusinessDays(1)));
        for bad in ["", "0h", "h", "3x", "-1h", "99999h"] {
            assert_eq!(Target::parse(bad), None, "{bad}");
        }
        assert_eq!(parse_hours("09:00-17:30"), Some((540, 1050)));
        assert_eq!(parse_hours("00:00-24:00"), Some((0, 1440)));
        assert_eq!(parse_hours("17:00-09:00"), None);
        assert_eq!(parse_hours("25:00-26:00"), None);
        assert_eq!(parse_weekdays("mon-fri"), Some([true, true, true, true, true, false, false]));
        assert_eq!(parse_weekdays("sun,sat"), Some([false, false, false, false, false, true, true]));
        assert_eq!(parse_weekdays("fri-mon"), None);
        assert_eq!(parse_offset("+01:00").map(|o| o.local_minus_utc()), Some(3600));
        assert_eq!(parse_offset("-05:30").map(|o| o.local_minus_utc()), Some(-19800));
        assert_eq!(parse_offset("1"), None);
        for (s, want) in [("1", 1), ("Sev 2", 2), ("S3", 3), ("P4", 4), ("Severity 1: Critical", 1), ("Urgent", 1), ("high", 2), ("Normal", 3), ("low", 4)] {
            assert_eq!(parse_severity(s), Some(want), "{s}");
        }
        assert_eq!(parse_severity("5"), None);
        assert_eq!(parse_severity("10"), None);
        assert_eq!(parse_severity("Sev 24"), None);
        assert_eq!(parse_severity("whenever"), None);
        assert_eq!(Plan::parse("Self-host (licensed)"), Some(Plan::SelfHost));
        assert_eq!(Plan::parse("Max"), Some(Plan::Max));
    }

    #[test]
    fn times_read_as_ticket_systems_export_them() {
        let plus1 = FixedOffset::east_opt(3600).unwrap();
        assert_eq!(parse_time("2026-09-01T10:00:00Z", plus1), Some(t("2026-09-01T10:00:00Z")));
        assert_eq!(parse_time("2026-09-01T11:00:00+01:00", plus1), Some(t("2026-09-01T10:00:00Z")));
        assert_eq!(parse_time("2026-09-01 11:00", plus1), Some(t("2026-09-01T10:00:00Z")));
        assert_eq!(parse_time("2026-09-01 11:00:00 +0100", FixedOffset::east_opt(0).unwrap()), Some(t("2026-09-01T10:00:00Z")));
        assert_eq!(parse_time("1 Sept", plus1), None);
    }

    #[test]
    fn business_time_counts_only_support_hours() {
        let cal = Calendar::default();
        // Friday 16:30 to Monday 10:00: an hour on Friday and one on Monday.
        assert_eq!(cal.business_secs(t("2026-09-04T16:30:00Z"), t("2026-09-07T10:00:00Z")), 2 * 3600);
        // Overnight on a weekday.
        assert_eq!(cal.business_secs(t("2026-09-01T17:00:00Z"), t("2026-09-02T09:30:00Z")), 3600);
        assert_eq!(cal.business_secs(t("2026-09-05T10:00:00Z"), t("2026-09-06T10:00:00Z")), 0, "a weekend");
        let mut holiday = Calendar::default();
        holiday.holidays.insert(NaiveDate::from_ymd_opt(2026, 9, 7).unwrap());
        assert_eq!(holiday.business_secs(t("2026-09-04T16:30:00Z"), t("2026-09-08T10:00:00Z")), 2 * 3600, "Monday is a holiday");
        let mut east = Calendar::default();
        east.offset = FixedOffset::east_opt(2 * 3600).unwrap();
        assert_eq!(east.business_secs(t("2026-09-01T06:00:00Z"), t("2026-09-01T08:00:00Z")), 3600, "09:00 local is 07:00 UTC");
        assert_eq!(cal.business_secs(t("2026-09-02T10:00:00Z"), t("2026-09-01T10:00:00Z")), 0);
    }

    #[test]
    fn csv_handles_quotes_line_breaks_and_semicolons() {
        let rows = parse_csv("\u{feff}id,subject\r\n1,\"Hello, \"\"world\"\"\nagain\"\r\n\r\n2,x").unwrap();
        assert_eq!(rows, vec![(1, vec!["id".to_string(), "subject".into()]), (2, vec!["1".into(), "Hello, \"world\"\nagain".into()]), (5, vec!["2".into(), "x".into()])], "each record with the line it starts on");
        assert_eq!(parse_csv("a;b\n1;2,5\n").unwrap(), vec![(1, vec!["a".to_string(), "b".into()]), (2, vec!["1".into(), "2,5".into()])]);
        assert!(parse_csv("a\n\"open").is_err());
    }

    const TICKETS: &str = "Ticket ID,Subject,Requester,Organization,Priority,Created at,First reply at,Solved at,Plan
T-1,Can't sign in,ana@example.com,Acme,Urgent,2026-09-01 10:00,2026-09-01 10:20,2026-09-01 12:00,enterprise
T-2,Hermes down,bo@example.com,Acme,High,2026-09-02 10:00,2026-09-02 13:00,2026-09-03 09:00,enterprise
T-3,How to SCIM,cy@example.com,Acme,Low,2026-09-04 16:00,2026-09-07 15:00,,enterprise
T-4,Slow,di@example.com,Globex,Normal,2026-09-04 16:00,2026-09-07 09:30,2026-09-09 09:00,pro
T-5,Typo,ed@example.com,Acme,low,2026-10-30 16:00,,,enterprise
T-6,Old,fi@example.com,Acme,Normal,2026-08-30 10:00,2026-08-30 10:05,2026-09-02 10:00,enterprise
T-7,Bad,gu@example.com,Acme,Someday,2026-09-01 10:00,,,enterprise
T-8,Bad time,hu@example.com,Acme,Low,yesterday,,,enterprise
";

    #[test]
    fn a_report_counts_met_missed_waiting_and_open() {
        let mut o = opts("2026-11-02T09:00:00Z");
        (o.from, o.to) = (NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 10, 1).unwrap());
        let r = report(TICKETS, &o).unwrap();
        let v = r.json();
        assert_eq!(v["from"], "2026-09");
        assert_eq!(v["to"], "2026-10");
        let sep = &v["months"][0]["severities"];
        // T-1: Enterprise Sev 1 in 20 min against 30 min.
        assert_eq!(sep[0]["met"], 1);
        assert_eq!(sep[0]["medianFirstResponseMinutes"], 20);
        // T-2: 3 h against 2 h on the clock.
        assert_eq!(sep[1]["missed"], 1);
        // T-4 (Pro, Sev 3): Fri 16:00 to Mon 09:30 is 2 business h, within a business day.
        assert_eq!(sep[2]["met"], 1);
        // T-6 opened in August but closed in September.
        assert_eq!(sep[2]["opened"], 1);
        assert_eq!(sep[2]["closed"], 2);
        // T-3: Enterprise Sev 4, Fri 16:00 to Mon 15:00 is 7.5 business h, within 1 business day (8.5 h).
        assert_eq!(sep[3]["met"], 1);
        // T-5: opened Fri 30 Oct 16:00, unanswered at Mon 09:00: 1.5 business h, still waiting.
        assert_eq!(v["months"][1]["severities"][3]["waiting"], 1);
        assert_eq!(v["totals"]["met"], 3);
        assert_eq!(v["totals"]["missed"], 1);
        assert_eq!(v["totals"]["metPercent"], 75);
        assert_eq!(v["missed"].as_array().unwrap().len(), 1);
        assert_eq!(v["missed"][0]["id"], "T-2");
        assert_eq!(v["missed"][0]["tookMinutes"], 180);
        assert_eq!(v["missed"][0]["target"], "2 h, 24×7");
        // Open at the end of October: T-3 (no solved time) and T-5.
        assert_eq!(v["openAtEnd"][3]["open"], 2);
        let skipped: Vec<u64> = v["skipped"].as_array().unwrap().iter().map(|s| s["line"].as_u64().unwrap()).collect();
        assert_eq!(skipped, vec![8, 9]);
        assert_eq!(v["skipped"][0]["reason"], "a severity that isn't 1 to 4");
        let all = format!("{}{}{}", v, r.text(), r.markdown());
        for never in ["example.com", "Can't sign in", "Hermes down", "Someday", "yesterday"] {
            assert!(!all.contains(never), "the report leaks {never}");
        }
    }

    #[test]
    fn an_unanswered_ticket_past_its_target_is_missed() {
        let csv = "id,severity,opened,first response\nA,1,2026-09-01T10:00:00Z,\n";
        let mut o = opts("2026-09-01T11:01:00Z");
        (o.from, o.to) = (NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 9, 1).unwrap());
        o.plan = Some(Plan::Max);
        let v = report(csv, &o).unwrap().json();
        assert_eq!(v["missed"][0]["answered"], false);
        assert_eq!(v["missed"][0]["tookMinutes"], 61);
        assert_eq!(v["openAtEnd"], Value::Null, "no resolved column, so no backlog");
        o.as_of = t("2026-09-01T10:59:00Z");
        assert_eq!(report(csv, &o).unwrap().json()["totals"]["severities"][0]["waiting"], 1);
    }

    #[test]
    fn customers_with_non_ascii_names_stay_apart() {
        let csv = "id,severity,opened,first response,organisation\nA,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z,北京\nB,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z,上海\nC,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z,Zürich AG\n";
        let mut o = opts("2026-11-02T09:00:00Z");
        o.plan = Some(Plan::Pro);
        for (name, want) in [("北京", 1), ("上海", 1), ("zürich ag", 1), ("Zurich AG", 0)] {
            o.customer = Some(name.into());
            assert_eq!(report(csv, &o).unwrap().json()["totals"]["met"], want, "{name}");
        }
        o.customer = Some("—".into());
        assert!(report(csv, &o).is_err(), "a name with nothing to match");
    }

    #[test]
    fn skipped_rows_are_named_by_the_line_they_start_on() {
        let csv = "id,subject,severity,opened,first response\nA,\"two\nlines\",1,2026-09-01T10:00:00Z,\n\nB,x,10,2026-09-01T10:00:00Z,\nC,x,1,soon,\n";
        let mut o = opts("2026-11-02T09:00:00Z");
        o.plan = Some(Plan::Pro);
        let v = report(csv, &o).unwrap().json();
        let lines: Vec<(u64, &str)> = v["skipped"].as_array().unwrap().iter().map(|s| (s["line"].as_u64().unwrap(), s["reason"].as_str().unwrap())).collect();
        assert_eq!(lines, vec![(5, "a severity that isn't 1 to 4"), (6, "a time that can't be read")]);
    }

    #[test]
    fn a_customer_and_agreed_targets() {
        let mut o = opts("2026-11-02T09:00:00Z");
        (o.from, o.to) = (NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 9, 1).unwrap());
        o.customer = Some("globex".into());
        let v = report(TICKETS, &o).unwrap().json();
        assert_eq!(v["totals"]["met"], 1, "only Globex's T-4");
        assert_eq!(v["targets"][0]["plan"], "pro");
        o.targets.insert(3, Target::Business(60));
        let r = report(TICKETS, &o).unwrap();
        let v = r.json();
        assert_eq!(v["totals"]["missed"], 1, "T-4 took 2 business h against an agreed 1");
        assert_eq!(v["targets"][2]["agreed"], true);
        assert!(r.markdown().contains("| T-4 | 3 (pro) | 2026-09-04 16:00 UTC | answered after 2 h of business time; target 1 business h |"), "{}", r.markdown());
        assert!(r.text().starts_with("Support report for globex: 2026-09 to 2026-09"));
    }

    #[test]
    fn columns_are_found_or_named() {
        let o = opts("2026-11-02T09:00:00Z");
        let csv = "Case,Sev,Raised,Answered\nA,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z\n";
        let e = report(csv, &Options { plan: Some(Plan::Pro), ..o.clone() }).unwrap_err();
        assert!(e.contains("no id column"), "{e}");
        let named = Options {
            plan: Some(Plan::Pro),
            columns: vec![(Field::Id, "Case".into()), (Field::Opened, "Raised".into()), (Field::Responded, "Answered".into())],
            from: NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
            ..o.clone()
        };
        assert_eq!(report(csv, &named).unwrap().json()["totals"]["met"], 1);
        let e = report("id,severity,opened,first response\n", &o).unwrap_err();
        assert!(e.contains("--plan"), "{e}");
        let e = report("id,severity,opened,first response\n", &Options { plan: Some(Plan::Pro), customer: Some("x".into()), ..o.clone() }).unwrap_err();
        assert!(e.contains("customer column"), "{e}");
        assert!(report("", &o).is_err());
    }

    #[test]
    fn arguments() {
        let now = t("2026-11-23T02:00:00Z");
        let (file, o, f) = parse_args(&["tickets.csv"], now).unwrap();
        assert_eq!((file.as_str(), f), ("tickets.csv", Format::Text));
        assert_eq!((o.from, o.to), (NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()), "the last three full months");
        let (_, o, f) = parse_args(
            &["-", "--plan", "enterprise", "--from", "2026-01", "--to", "2026-03", "--hours", "08:00-18:00", "--weekdays", "mon-sat", "--utc-offset", "+01:00", "--holidays", "2026-01-01,2026-04-03", "--target", "1=15m", "--column", "id=Case #", "--markdown"],
            now,
        )
        .unwrap();
        assert_eq!(f, Format::Markdown);
        assert_eq!(o.plan, Some(Plan::Enterprise));
        assert_eq!((o.calendar.open, o.calendar.close), (480, 1080));
        assert!(o.calendar.weekdays[5] && !o.calendar.weekdays[6]);
        assert_eq!(o.calendar.holidays.len(), 2);
        assert_eq!(o.targets.get(&1), Some(&Target::Clock(15)));
        assert_eq!(o.columns, vec![(Field::Id, "Case #".to_string())]);
        let (_, o, _) = parse_args(&["x.csv", "--as-of", "2026-04-10T00:00:00Z", "--json"], now).unwrap();
        assert_eq!(o.from, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), "--as-of moves the default period");
        for bad in [
            &["x.csv", "--from", "2026-01"][..],
            &["x.csv", "--from", "2026-03", "--to", "2026-01"],
            &["x.csv", "--from", "2023-01", "--to", "2026-01"],
            &["x.csv", "--plan", "gold"],
            &["x.csv", "--target", "5=1h"],
            &["x.csv", "--column", "subject=Subject"],
            &["x.csv", "--hours"],
            &[],
            &["a.csv", "b.csv"],
        ] {
            assert!(parse_args(bad, now).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_empty_period_still_has_its_months() {
        let mut o = opts("2026-11-02T09:00:00Z");
        o.plan = Some(Plan::Starter);
        let r = report("id,severity,opened,first response\n", &o).unwrap();
        assert_eq!(r.json()["months"].as_array().unwrap().len(), 3);
        assert_eq!(r.json()["totals"]["metPercent"], Value::Null);
        assert!(r.text().contains("No tickets to judge"));
    }
}
