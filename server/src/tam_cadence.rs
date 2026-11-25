//! The TAM cadence across the Provider's accounts (ADR 0295, #60): from the CRM's export of
//! the accounts that have a TAM, each promise of docs/support/tam.md's cadence that is
//! overdue or due soon: the kickoff within 5 business days of signing, check-ins weekly
//! until go-live and in the week after it, the monthly health check, the quarterly business
//! review, the restore drill twice a year, the walk-through of a Severity 1's review within
//! 5 business days, and the renewal.
//!
//! It reads only an account's customer name, its TAM's name and the dates of those steps;
//! contacts, emails, revenue and every other column are left alone. It says what's due and
//! tells nobody: no botd, no CRM API, no calendar.

use crate::support_escalations::{md_cell, one_line};
use crate::support_report::{normalize, parse_csv, parse_offset, parse_time, parse_weekdays, Calendar, Format};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, TimeDelta, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const USAGE: &str = "Usage: botctl tam-cadence <accounts.csv | -> [--tam <name>] [--customer <name>]
    [--weekdays <mon-fri>] [--utc-offset <+HH:MM>] [--holidays <YYYY-MM-DD,...>] [--warn-days <days>]
    [--renewal-days <days>] [--column <field>=<header>]... [--as-of <time>] [--markdown | --json]";

/// tam.md's cadence: the kickoff within 5 business days of signing, a check-in each week
/// until go-live and in the week after it, a health check each month, a business review
/// each quarter, a restore drill twice a year, and a Severity 1's review walked through
/// within 5 business days.
pub const KICKOFF_BUSINESS_DAYS: i64 = 5;
pub const CHECK_IN_DAYS: i64 = 7;
pub const HEALTH_CHECK_DAYS: i64 = 31;
pub const RESTORE_DRILL_DAYS: i64 = 183;
pub const INCIDENT_REVIEW_BUSINESS_DAYS: i64 = 5;
/// The week-1 check-in is judged in the first month after go-live; after that the monthly
/// health check is the cadence.
pub const WEEK_ONE_JUDGED_DAYS: i64 = 31;
pub const DEFAULT_WARN_DAYS: i64 = 7;
/// As the health check's license item: a renewal within 90 days is with the account owner.
pub const DEFAULT_RENEWAL_DAYS: i64 = 90;

/// The columns the check reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    Customer,
    Tam,
    Signed,
    Kickoff,
    GoLive,
    CheckIn,
    HealthCheck,
    BusinessReview,
    RestoreDrill,
    Severity1,
    IncidentReview,
    Renewal,
}

impl Field {
    pub const ALL: [Field; 12] = [
        Field::Customer,
        Field::Tam,
        Field::Signed,
        Field::Kickoff,
        Field::GoLive,
        Field::CheckIn,
        Field::HealthCheck,
        Field::BusinessReview,
        Field::RestoreDrill,
        Field::Severity1,
        Field::IncidentReview,
        Field::Renewal,
    ];

    fn parse(s: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == s)
    }

    pub fn name(self) -> &'static str {
        match self {
            Field::Customer => "customer",
            Field::Tam => "tam",
            Field::Signed => "signed",
            Field::Kickoff => "kickoff",
            Field::GoLive => "go-live",
            Field::CheckIn => "check-in",
            Field::HealthCheck => "health-check",
            Field::BusinessReview => "business-review",
            Field::RestoreDrill => "restore-drill",
            Field::Severity1 => "severity-1",
            Field::IncidentReview => "incident-review",
            Field::Renewal => "renewal",
        }
    }

    /// Header names that mean this field, lowercased with punctuation as spaces.
    fn aliases(self) -> &'static [&'static str] {
        match self {
            Field::Customer => &["customer", "customer name", "organization", "organisation", "org", "account", "account name", "company"],
            Field::Tam => &["tam", "tam name", "technical account manager", "named tam"],
            Field::Signed => &["signed", "signed on", "signed date", "contract signed", "signature date", "close date", "closed won date"],
            Field::Kickoff => &["kickoff", "kick off", "kickoff date", "kick off date", "kicked off"],
            Field::GoLive => &["go live", "go live date", "went live", "live date", "live since"],
            Field::CheckIn => &["check in", "last check in", "check in date", "last check in date"],
            Field::HealthCheck => &["health check", "last health check", "health check date", "last health check date"],
            Field::BusinessReview => &["business review", "last business review", "qbr", "last qbr", "qbr date", "last qbr date"],
            Field::RestoreDrill => &["restore drill", "last restore drill", "restore drill date", "last drill"],
            Field::Severity1 => &["severity 1", "last severity 1", "sev 1", "last sev 1", "sev1", "last sev1", "last major incident"],
            Field::IncidentReview => &["incident review", "last incident review", "incident review shared", "review shared", "review walked through"],
            Field::Renewal => &["renewal", "renewal date", "renews", "renews on", "contract end", "contract end date"],
        }
    }
}

/// A promise of the cadence, most urgent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    IncidentReview,
    Kickoff,
    CheckIn,
    HealthCheck,
    BusinessReview,
    RestoreDrill,
    Renewal,
}

impl Item {
    pub const ALL: [Item; 7] = [Item::IncidentReview, Item::Kickoff, Item::CheckIn, Item::HealthCheck, Item::BusinessReview, Item::RestoreDrill, Item::Renewal];

    pub fn code(self) -> &'static str {
        match self {
            Item::IncidentReview => "incident_review",
            Item::Kickoff => "kickoff",
            Item::CheckIn => "check_in",
            Item::HealthCheck => "health_check",
            Item::BusinessReview => "business_review",
            Item::RestoreDrill => "restore_drill",
            Item::Renewal => "renewal",
        }
    }

    /// The columns it's judged from; without them it isn't judged.
    fn needs(self) -> &'static [Field] {
        match self {
            Item::IncidentReview => &[Field::Severity1, Field::IncidentReview],
            Item::Kickoff => &[Field::Signed, Field::Kickoff],
            Item::CheckIn => &[Field::CheckIn],
            Item::HealthCheck => &[Field::HealthCheck],
            Item::BusinessReview => &[Field::BusinessReview],
            Item::RestoreDrill => &[Field::RestoreDrill],
            Item::Renewal => &[Field::Renewal],
        }
    }

    fn action(self, status: Status) -> &'static str {
        match (self, status) {
            (Item::IncidentReview, _) => "Walk the customer's owner and sponsor through the Severity 1's review (botctl incident review drafts it)",
            (Item::Kickoff, _) => "Hold the kickoff with the customer's owner, IdP admin and security contact, and put the onboarding dates in calendars",
            (Item::CheckIn, _) => "Hold the check-in with the customer's owner (botctl onboarding on their server shows what's open)",
            (Item::HealthCheck, _) => "Run the monthly health check (botctl health-check on their server), and call the owner if anything is watch or at risk",
            (Item::BusinessReview, _) => "Book the quarterly business review with the sponsor and owner (botctl business-review drafts it)",
            (Item::RestoreDrill, _) => "Book the restore drill with the on-call engineer and the customer's owner, and record its times against the RTO",
            (Item::Renewal, Status::Overdue) => "Renew with the account owner, or correct the renewal date in the record",
            (Item::Renewal, Status::DueSoon) => "Raise the renewal with the account owner, and put it on the next business review's agenda",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Overdue,
    DueSoon,
}

impl Status {
    fn code(self) -> &'static str {
        match self {
            Status::Overdue => "overdue",
            Status::DueSoon => "due_soon",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Signed,
    Onboarding,
    Live,
}

impl Stage {
    fn code(self) -> &'static str {
        match self {
            Stage::Signed => "signed",
            Stage::Onboarding => "onboarding",
            Stage::Live => "live",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub tam: Option<String>,
    pub customer: Option<String>,
    pub calendar: Calendar,
    pub warn_days: i64,
    pub renewal_days: i64,
    pub columns: Vec<(Field, String)>,
    pub as_of: DateTime<Utc>,
}

impl Options {
    pub fn new(as_of: DateTime<Utc>) -> Options {
        Options { tam: None, customer: None, calendar: Calendar::default(), warn_days: DEFAULT_WARN_DAYS, renewal_days: DEFAULT_RENEWAL_DAYS, columns: Vec::new(), as_of }
    }

    fn today(&self) -> NaiveDate {
        self.as_of.with_timezone(&self.calendar.offset).date_naive()
    }
}

fn date(flag: &str, s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| format!("{flag}: {s} isn't a date (YYYY-MM-DD)"))
}

/// `botctl tam-cadence ...`: the accounts file (`-` for stdin), the options and the format.
pub fn parse_args(rest: &[&str], now: DateTime<Utc>) -> Result<(String, Options, Format), String> {
    let mut o = Options::new(now);
    let (mut file, mut format, mut as_of) = (None, Format::Text, None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().copied().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{a} needs a value.\n{USAGE}"));
        match *a {
            "--markdown" => format = Format::Markdown,
            "--json" => format = Format::Json,
            "--tam" => o.tam = Some(value()?.to_string()),
            "--customer" => o.customer = Some(value()?.to_string()),
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
                    o.calendar.holidays.insert(date("--holidays", d)?);
                }
            }
            "--warn-days" => {
                let v = value()?;
                o.warn_days = v.parse().ok().filter(|n| (0..=60).contains(n)).ok_or_else(|| format!("--warn-days: {v} isn't days from 0 to 60"))?;
            }
            "--renewal-days" => {
                let v = value()?;
                o.renewal_days = v.parse().ok().filter(|n| (1..=366).contains(n)).ok_or_else(|| format!("--renewal-days: {v} isn't days from 1 to 366"))?;
            }
            "--column" => {
                let v = value()?;
                let (f, header) = v.split_once('=').filter(|(_, h)| !h.trim().is_empty()).ok_or_else(|| format!("--column: {v} isn't <field>=<header>"))?;
                let names: Vec<&str> = Field::ALL.iter().map(|f| f.name()).collect();
                let field = Field::parse(f).ok_or_else(|| format!("--column: {f} isn't one of {}", names.join(", ")))?;
                o.columns.push((field, header.to_string()));
            }
            "--as-of" => as_of = Some(value()?),
            f if file.is_none() && (f == "-" || !f.starts_with('-')) => file = Some(f.to_string()),
            _ => return Err(USAGE.into()),
        }
    }
    let file = file.ok_or_else(|| USAGE.to_string())?;
    if let Some(t) = as_of {
        o.as_of = match NaiveDate::parse_from_str(t, "%Y-%m-%d") {
            Ok(d) => (d.and_hms_opt(12, 0, 0).unwrap() - TimeDelta::seconds(o.calendar.offset.local_minus_utc() as i64)).and_utc(),
            Err(_) => parse_time(t, o.calendar.offset).ok_or_else(|| format!("--as-of: {t} isn't a time or a date"))?,
        };
    }
    Ok((file, o, format))
}

/// A date as CRMs export them: `YYYY-MM-DD`, `YYYY/MM/DD`, or a time, taken on its day in
/// the support timezone.
fn parse_day(s: &str, o: &Options) -> Option<NaiveDate> {
    let s = s.trim();
    for f in ["%Y-%m-%d", "%Y/%m/%d"] {
        if let Ok(d) = NaiveDate::parse_from_str(s, f) {
            return Some(d);
        }
    }
    parse_time(s, o.calendar.offset).map(|t| t.with_timezone(&o.calendar.offset).date_naive())
}

/// The day `n` business days after `d`.
fn add_business_days(cal: &Calendar, d: NaiveDate, n: i64) -> NaiveDate {
    let (mut day, mut left) = (d, n);
    while left > 0 {
        let Some(next) = day.succ_opt() else { break };
        day = next;
        if cal.is_business_day(day) {
            left -= 1;
        }
    }
    day
}

/// The last day of the calendar quarter after `d`'s: a review held any time in a quarter
/// is followed by one by the end of the next.
fn end_of_next_quarter(d: NaiveDate) -> NaiveDate {
    let months = d.year() * 12 + (d.month0() / 3 * 3) as i32 + 6;
    let first = NaiveDate::from_ymd_opt(months.div_euclid(12), months.rem_euclid(12) as u32 + 1, 1).unwrap_or(NaiveDate::MAX);
    first.pred_opt().unwrap_or(first)
}

#[derive(Clone, Debug)]
struct Finding {
    item: Item,
    status: Status,
    due: Option<NaiveDate>,
    last: Option<NaiveDate>,
    detail: String,
}

#[derive(Clone, Debug)]
struct Account {
    customer: String,
    tam: Option<String>,
    stage: Stage,
    since: Option<NaiveDate>,
    findings: Vec<Finding>,
}

#[derive(Debug)]
pub struct Cadence {
    o: Options,
    today: NaiveDate,
    accounts: usize,
    listed: Vec<Account>,
    tams: Vec<(Option<String>, usize, usize, usize)>,
    not_judged: Vec<Item>,
    notes: Vec<String>,
    skipped: Vec<(usize, String)>,
}

fn columns(header: &[String], o: &Options) -> Result<HashMap<Field, usize>, String> {
    let headers: Vec<String> = header.iter().map(|h| normalize(h)).collect();
    let mut col = HashMap::new();
    for f in Field::ALL {
        let named = o.columns.iter().find(|(c, _)| *c == f).map(|(_, h)| normalize(h));
        let at = match &named {
            Some(h) => Some(headers.iter().position(|x| x == h).ok_or_else(|| format!("--column {}: the export has no column \"{h}\"", f.name()))?),
            None => f.aliases().iter().find_map(|a| headers.iter().position(|x| x == a)),
        };
        if let Some(i) = at {
            col.insert(f, i);
        }
    }
    if !col.contains_key(&Field::Customer) {
        return Err("the accounts export has no customer column; name it with --column customer=<header>".into());
    }
    Ok(col)
}

fn days(n: i64) -> String {
    if n == 1 { "1 day".into() } else { format!("{n} days") }
}

/// The cadence due at `o.as_of` across `csv`'s accounts.
pub fn check(csv: &str, o: &Options) -> Result<Cadence, String> {
    let rows = parse_csv(csv)?;
    let ((_, header), body) = rows.split_first().ok_or("the accounts export is empty")?;
    let col = columns(header, o)?;
    let today = o.today();
    let has = |f: Field| col.contains_key(&f);
    let not_judged: Vec<Item> = Item::ALL.into_iter().filter(|i| !i.needs().iter().all(|f| has(*f))).collect();
    let judged = |i: Item| !not_judged.contains(&i);

    let (mut seen, mut skipped, mut listed, mut accounts) = (HashSet::new(), Vec::new(), Vec::new(), 0);
    let mut tams: BTreeMap<String, (Option<String>, usize, usize, usize)> = BTreeMap::new();
    'rows: for (line, r) in body {
        let cell = |f: Field| col.get(&f).and_then(|&c| r.get(c)).map(|s| s.trim()).filter(|s| !normalize(s).is_empty());
        let Some(customer) = cell(Field::Customer) else {
            skipped.push((*line, "no customer".to_string()));
            continue;
        };
        let tam = cell(Field::Tam);
        if o.customer.as_deref().is_some_and(|c| normalize(c) != normalize(customer)) || o.tam.as_deref().is_some_and(|t| tam.is_none_or(|x| normalize(x) != normalize(t))) {
            continue;
        }
        if !seen.insert(normalize(customer)) {
            skipped.push((*line, "a customer already listed".to_string()));
            continue;
        }
        let mut dates: HashMap<Field, NaiveDate> = HashMap::new();
        for f in Field::ALL.into_iter().skip(2) {
            if let Some(v) = cell(f) {
                match parse_day(v, o) {
                    Some(d) => {
                        dates.insert(f, d);
                    }
                    None => {
                        skipped.push((*line, format!("a {} date that can't be read", f.name())));
                        continue 'rows;
                    }
                }
            }
        }
        accounts += 1;
        // Steps dated after today haven't happened yet: a kickoff or review booked ahead.
        let done = |f: Field| dates.get(&f).copied().filter(|d| *d <= today);
        let stage = if !has(Field::GoLive) || done(Field::GoLive).is_some() {
            Stage::Live
        } else if done(Field::Kickoff).is_some() {
            Stage::Onboarding
        } else {
            Stage::Signed
        };
        let since = match stage {
            Stage::Live => done(Field::GoLive),
            Stage::Onboarding => done(Field::Kickoff),
            Stage::Signed => dates.get(&Field::Signed).copied(),
        };
        let mut findings = Vec::new();
        let mut judge = |item: Item, due: Option<NaiveDate>, last: Option<NaiveDate>, detail: String, window: i64| {
            let status = match due {
                None => Some(Status::Overdue),
                Some(d) if today > d => Some(Status::Overdue),
                Some(d) if (d - today).num_days() <= window => Some(Status::DueSoon),
                Some(_) => None,
            };
            if let Some(status) = status {
                findings.push(Finding { item, status, due, last, detail });
            }
        };
        let warn = o.warn_days;
        let golive = done(Field::GoLive);
        let latest = |a: Option<NaiveDate>, b: Option<NaiveDate>| a.max(b);

        if judged(Item::IncidentReview) {
            if let Some(s) = done(Field::Severity1) {
                let review = done(Field::IncidentReview);
                if review.is_none_or(|r| r < s) {
                    let due = add_business_days(&o.calendar, s, INCIDENT_REVIEW_BUSINESS_DAYS);
                    let before = review.map_or(String::new(), |r| format!("; the last review walked through was {r}"));
                    judge(Item::IncidentReview, Some(due), review, format!("Severity 1 on {s}, its review walked through within {INCIDENT_REVIEW_BUSINESS_DAYS} business days{before}"), warn);
                }
            }
        }
        match stage {
            Stage::Signed if judged(Item::Kickoff) => match dates.get(&Field::Signed).copied() {
                Some(s) => judge(Item::Kickoff, Some(add_business_days(&o.calendar, s, KICKOFF_BUSINESS_DAYS)), None, format!("signed {s}, kickoff within {KICKOFF_BUSINESS_DAYS} business days"), warn),
                None => judge(Item::Kickoff, None, None, "no kickoff, go-live or signing date recorded".into(), warn),
            },
            Stage::Onboarding if judged(Item::CheckIn) => {
                let last = latest(done(Field::CheckIn), done(Field::Kickoff));
                let detail = match done(Field::CheckIn).filter(|c| Some(*c) == last) {
                    Some(c) => format!("weekly until go-live; last check-in {c}"),
                    None => format!("weekly until go-live; none since the kickoff on {}", last.map_or_else(String::new, |d| d.to_string())),
                };
                judge(Item::CheckIn, last.map(|d| d + TimeDelta::days(CHECK_IN_DAYS)), done(Field::CheckIn), detail, warn);
            }
            Stage::Live => {
                if let (true, Some(g)) = (judged(Item::CheckIn), golive) {
                    if (today - g).num_days() <= WEEK_ONE_JUDGED_DAYS && done(Field::CheckIn).is_none_or(|c| c < g) {
                        judge(Item::CheckIn, Some(g + TimeDelta::days(CHECK_IN_DAYS)), done(Field::CheckIn), format!("the check-in in the week after go-live on {g}"), warn);
                    }
                }
                let mut periodic = |item: Item, field: Field, every: &str, due: &dyn Fn(NaiveDate) -> NaiveDate| {
                    if !judged(item) {
                        return;
                    }
                    let last = done(field);
                    let base = latest(last, golive);
                    let detail = match (last, golive) {
                        (Some(l), _) if Some(l) == base => format!("{every}; last {l}"),
                        (_, Some(g)) => format!("{every}; none since go-live on {g}"),
                        _ => format!("{every}; none recorded"),
                    };
                    judge(item, base.map(due), last, detail, warn);
                };
                periodic(Item::HealthCheck, Field::HealthCheck, "monthly", &|d| d + TimeDelta::days(HEALTH_CHECK_DAYS));
                periodic(Item::BusinessReview, Field::BusinessReview, "each quarter", &end_of_next_quarter);
                periodic(Item::RestoreDrill, Field::RestoreDrill, "twice a year", &|d| d + TimeDelta::days(RESTORE_DRILL_DAYS));
            }
            _ => {}
        }
        if let Some(r) = dates.get(&Field::Renewal).copied().filter(|_| judged(Item::Renewal)) {
            let detail = if today > r { "the renewal date in the record has passed".to_string() } else { format!("renewals go to the account owner from {} before", days(o.renewal_days)) };
            judge(Item::Renewal, Some(r), None, detail, o.renewal_days);
        }

        findings.sort_by(|a, b| a.status.cmp(&b.status).then(a.due.cmp(&b.due)).then(a.item.cmp(&b.item)));
        let key = tam.map_or(String::new(), normalize);
        let e = tams.entry(key).or_insert_with(|| (tam.map(str::to_string), 0, 0, 0));
        e.1 += 1;
        e.2 += findings.iter().filter(|f| f.status == Status::Overdue).count();
        e.3 += findings.iter().filter(|f| f.status == Status::DueSoon).count();
        if !findings.is_empty() {
            listed.push(Account { customer: customer.to_string(), tam: tam.map(str::to_string), stage, since, findings });
        }
    }
    let first = |a: &Account| (a.findings[0].status, a.findings[0].due);
    listed.sort_by(|a, b| first(a).cmp(&first(b)).then(normalize(&a.customer).cmp(&normalize(&b.customer))));
    let mut tams: Vec<_> = tams.into_values().collect();
    tams.sort_by(|a, b| b.2.cmp(&a.2).then(b.3.cmp(&a.3)).then(a.0.is_none().cmp(&b.0.is_none())).then(a.0.cmp(&b.0)));

    let mut notes = Vec::new();
    if !has(Field::GoLive) {
        notes.push("The export has no go-live column, so every account is taken as live.".to_string());
    }
    if !not_judged.is_empty() {
        let why: Vec<String> = not_judged.iter().map(|i| format!("{} (needs {})", i.code(), i.needs().iter().map(|f| f.name()).collect::<Vec<_>>().join(" and "))).collect();
        notes.push(format!("Not judged, since the export has no column for it: {}.", why.join(", ")));
    }
    if tams.iter().any(|t| t.0.is_none()) {
        notes.push("Some accounts have no TAM in the export: botctl support-readiness --tams checks the TAM list.".to_string());
    }
    Ok(Cadence { o: o.clone(), today, accounts, listed, tams, not_judged, notes, skipped })
}

impl Cadence {
    /// Whether any promise is overdue: then botctl exits 1.
    pub fn overdue(&self) -> bool {
        self.count(Status::Overdue) > 0
    }

    fn count(&self, s: Status) -> usize {
        self.listed.iter().flat_map(|a| &a.findings).filter(|f| f.status == s).count()
    }

    fn when(&self, f: &Finding) -> String {
        match (f.status, f.due) {
            (_, None) => "due now".to_string(),
            (Status::Overdue, Some(d)) => format!("{} overdue (due {d})", days((self.today - d).num_days())),
            (Status::DueSoon, Some(d)) if d == self.today => format!("due today ({d})"),
            (Status::DueSoon, Some(d)) => format!("due {d}, in {}", days((d - self.today).num_days())),
        }
    }

    fn stage_text(a: &Account) -> String {
        match (a.stage, a.since) {
            (Stage::Live, Some(d)) => format!("live since {d}"),
            (Stage::Live, None) => "live".into(),
            (Stage::Onboarding, Some(d)) => format!("onboarding since {d}"),
            (Stage::Onboarding, None) => "onboarding".into(),
            (Stage::Signed, Some(d)) => format!("signed {d}, not kicked off"),
            (Stage::Signed, None) => "not kicked off".into(),
        }
    }

    fn heading(&self, name: fn(&str) -> String) -> (String, String) {
        let mut scope = String::new();
        if let Some(t) = &self.o.tam {
            scope.push_str(&format!(" for TAM {}", name(t)));
        }
        if let Some(c) = &self.o.customer {
            scope.push_str(&format!(" for {}", name(c)));
        }
        let cal = &self.o.calendar;
        let holidays = match cal.holidays.len() {
            0 => String::new(),
            1 => ", 1 holiday".into(),
            n => format!(", {n} holidays"),
        };
        (
            format!("TAM cadence{scope} as of {} (UTC{})", self.today, cal.offset),
            format!("Business days {}{holidays}; due soon within {}, renewals within {}", cal.weekday_names().join(","), days(self.o.warn_days), days(self.o.renewal_days)),
        )
    }

    fn summary(&self) -> String {
        let accounts = if self.accounts == 1 { "1 account".to_string() } else { format!("{} accounts", self.accounts) };
        let (over, soon) = (self.count(Status::Overdue), self.count(Status::DueSoon));
        let verdict = match (over, soon) {
            (0, 0) => "nothing due.".to_string(),
            _ => format!("{over} overdue, {soon} due soon, across {} of them.", self.listed.len()),
        };
        format!("{accounts}: {verdict}")
    }

    fn tam_name(t: &Option<String>) -> String {
        t.as_deref().map_or("(no TAM)".to_string(), one_line)
    }

    fn skipped_line(&self) -> Option<String> {
        (!self.skipped.is_empty()).then(|| {
            let shown: Vec<String> = self.skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
            let more = if self.skipped.len() > 20 { format!(", and {} more", self.skipped.len() - 20) } else { String::new() };
            format!("Skipped {} rows: {}{more}.", self.skipped.len(), shown.join(", "))
        })
    }

    const FOOTER: &'static str = "Cadence: docs/support/tam.md#cadence. This lists what's due; it tells nobody.";

    pub fn text(&self) -> String {
        let (title, hours) = self.heading(one_line);
        let mut out = format!("{title}\n{hours}\n\n{}\n", self.summary());
        for a in &self.listed {
            out.push_str(&format!("\n{}  TAM {}  {}\n", one_line(&a.customer), Self::tam_name(&a.tam), Self::stage_text(a)));
            for f in &a.findings {
                let label = if f.status == Status::Overdue { "OVERDUE" } else { "DUE" };
                out.push_str(&format!("  {label:<7}  {}: {}; {}. {}\n", f.item.code(), self.when(f), f.detail, f.item.action(f.status)));
            }
        }
        if !self.tams.is_empty() {
            let width = self.tams.iter().map(|t| Self::tam_name(&t.0).chars().count()).chain([3]).max().unwrap_or(3);
            out.push_str(&format!("\n{:<width$}  Accounts  Overdue  Due soon\n", "TAM"));
            for (t, n, over, soon) in &self.tams {
                out.push_str(&format!("{:<width$}  {n:>8}  {over:>7}  {soon:>8}\n", Self::tam_name(t)));
            }
        }
        out.push('\n');
        for n in self.notes.iter().cloned().chain(self.skipped_line()) {
            out.push_str(&format!("{n}\n"));
        }
        out.push_str(&format!("{}\n", Self::FOOTER));
        out
    }

    pub fn markdown(&self) -> String {
        let (title, hours) = self.heading(md_cell);
        let mut out = format!("## {title}\n\n{hours}.\n\n{}\n", self.summary());
        if !self.listed.is_empty() {
            out.push_str("\n| Customer | TAM | Stage | Item | Status | When | Why | What to do |\n|---|---|---|---|---|---|---|---|\n");
            for a in &self.listed {
                for f in &a.findings {
                    let status = if f.status == Status::Overdue { "**Overdue**" } else { "Due soon" };
                    out.push_str(&format!(
                        "| {} | {} | {} | `{}` | {status} | {} | {} | {} |\n",
                        md_cell(&a.customer),
                        a.tam.as_deref().map_or("(no TAM)".to_string(), md_cell),
                        Self::stage_text(a),
                        f.item.code(),
                        self.when(f),
                        f.detail,
                        f.item.action(f.status)
                    ));
                }
            }
        }
        if !self.tams.is_empty() {
            out.push_str("\n| TAM | Accounts | Overdue | Due soon |\n|---|---|---|---|\n");
            for (t, n, over, soon) in &self.tams {
                out.push_str(&format!("| {} | {n} | {over} | {soon} |\n", t.as_deref().map_or("(no TAM)".to_string(), md_cell)));
            }
        }
        for n in self.notes.iter().cloned().chain(self.skipped_line()) {
            out.push_str(&format!("\n{n}\n"));
        }
        out.push_str(&format!("\n{}\n", Self::FOOTER));
        out
    }

    pub fn json(&self) -> Value {
        let cal = &self.o.calendar;
        let mut counts = serde_json::Map::new();
        for i in Item::ALL {
            let n = |s: Status| self.listed.iter().flat_map(|a| &a.findings).filter(|f| f.item == i && f.status == s).count();
            counts.insert(i.code().into(), json!({ "overdue": n(Status::Overdue), "dueSoon": n(Status::DueSoon) }));
        }
        let day = |d: Option<NaiveDate>| d.map(|d| d.to_string());
        json!({
            "format": 1,
            "asOf": self.o.as_of.to_rfc3339_opts(SecondsFormat::Secs, true),
            "today": self.today.to_string(),
            "tam": self.o.tam,
            "customer": self.o.customer,
            "businessDays": { "weekdays": cal.weekday_names(), "utcOffset": cal.offset.to_string(), "holidays": cal.holidays.len() },
            "warnDays": self.o.warn_days,
            "renewalDays": self.o.renewal_days,
            "accounts": self.accounts,
            "overdue": self.count(Status::Overdue),
            "dueSoon": self.count(Status::DueSoon),
            "due": self.overdue(),
            "counts": counts,
            "notJudged": self.not_judged.iter().map(|i| i.code()).collect::<Vec<_>>(),
            "listed": self.listed.iter().map(|a| json!({
                "customer": a.customer, "tam": a.tam, "stage": a.stage.code(), "since": day(a.since),
                "items": a.findings.iter().map(|f| json!({
                    "item": f.item.code(), "status": f.status.code(), "due": day(f.due), "last": day(f.last),
                    "detail": f.detail, "action": f.item.action(f.status),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "tams": self.tams.iter().map(|(t, n, over, soon)| json!({ "tam": t, "accounts": n, "overdue": over, "dueSoon": soon })).collect::<Vec<_>>(),
            "notes": self.notes,
            "skipped": self.skipped.iter().map(|(line, why)| json!({ "line": line, "reason": why })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s, FixedOffset::east_opt(0).unwrap()).unwrap()
    }

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    /// Wednesday 25 November 2026, at noon UTC.
    fn opts(extra: &[&str]) -> Options {
        let args = [&["a.csv", "--as-of", "2026-11-25"][..], extra].concat();
        parse_args(&args, t("2026-01-01T00:00:00Z")).unwrap().1
    }

    fn items(v: &Value, customer: &str) -> Vec<(String, String, Option<String>)> {
        let a = v["listed"].as_array().unwrap().iter().find(|a| a["customer"] == customer);
        a.map_or(Vec::new(), |a| {
            a["items"].as_array().unwrap().iter().map(|i| (i["item"].as_str().unwrap().to_string(), i["status"].as_str().unwrap().to_string(), i["due"].as_str().map(str::to_string))).collect()
        })
    }

    fn one(item: &str, status: &str, due: Option<&str>) -> (String, String, Option<String>) {
        (item.to_string(), status.to_string(), due.map(str::to_string))
    }

    #[test]
    fn the_cadence_matches_the_tam_playbook() {
        let tam = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/tam.md")).unwrap();
        let cadence = tam.split("## Cadence").nth(1).unwrap().split("\n## ").next().unwrap();
        let whens: Vec<&str> = cadence.lines().filter(|l| l.starts_with("| ") && !l.starts_with("| When")).map(|l| l.trim_matches('|').split('|').next().unwrap().trim()).collect();
        for when in [
            format!("Within {KICKOFF_BUSINESS_DAYS} business days of signing"),
            "Weekly until go-live".to_string(),
            "Week 1 after go-live".to_string(),
            "Monthly".to_string(),
            "Quarterly".to_string(),
            "Twice a year".to_string(),
            format!("Within {INCIDENT_REVIEW_BUSINESS_DAYS} business days of a Severity 1"),
        ] {
            assert!(whens.contains(&when.as_str()), "tam.md's cadence has no \"{when}\": {whens:?}");
        }
        assert_eq!((CHECK_IN_DAYS, HEALTH_CHECK_DAYS, RESTORE_DRILL_DAYS), (7, 31, 183), "a week, a month as the TAM handover counts it, half a year");
        let check = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/health-check.md")).unwrap();
        assert!(check.contains(&format!("a renewal within {DEFAULT_RENEWAL_DAYS} days is with the account owner")), "health-check.md's license item");
    }

    #[test]
    fn business_days_and_quarters() {
        let cal = opts(&["--holidays", "2026-12-25,2026-12-28"]).calendar;
        assert_eq!(add_business_days(&cal, d("2026-11-16"), 5), d("2026-11-23"), "Monday plus 5 is the next Monday");
        assert_eq!(add_business_days(&cal, d("2026-11-21"), 1), d("2026-11-23"), "a Saturday's next business day is Monday");
        assert_eq!(add_business_days(&cal, d("2026-12-23"), 3), d("2026-12-30"), "Christmas and the 28th are holidays");
        let six = opts(&["--weekdays", "mon-sat"]).calendar;
        assert_eq!(add_business_days(&six, d("2026-11-16"), 5), d("2026-11-21"));
        for (last, due) in [("2026-08-20", "2026-12-31"), ("2026-07-01", "2026-12-31"), ("2026-11-10", "2027-03-31"), ("2026-03-31", "2026-06-30"), ("2026-12-31", "2027-03-31")] {
            assert_eq!(end_of_next_quarter(d(last)), d(due), "{last}");
        }
    }

    #[test]
    fn the_options_parse() {
        let now = t("2026-11-25T20:00:00Z");
        let (f, o, fmt) = parse_args(&["-"], now).unwrap();
        assert_eq!((f.as_str(), o.as_of, o.warn_days, o.renewal_days, fmt), ("-", now, 7, 90, Format::Text));
        let (_, o, fmt) = parse_args(
            &["accounts.csv", "--tam", "Ana", "--customer", "Acme", "--weekdays", "mon-sat", "--utc-offset", "+10:00", "--holidays", "2026-12-25", "--warn-days", "0", "--renewal-days", "120", "--column", "go-live=Launched", "--as-of", "2026-11-25", "--json"],
            now,
        )
        .unwrap();
        assert_eq!(fmt, Format::Json);
        assert_eq!((o.tam.as_deref(), o.customer.as_deref(), o.warn_days, o.renewal_days), (Some("Ana"), Some("Acme"), 0, 120));
        assert_eq!(o.columns, vec![(Field::GoLive, "Launched".to_string())]);
        assert_eq!((o.as_of, o.today()), (t("2026-11-25T02:00:00Z"), d("2026-11-25")), "a date is noon there");
        let (_, o, _) = parse_args(&["a.csv", "--utc-offset", "-05:00", "--as-of", "2026-11-26T03:00:00Z"], now).unwrap();
        assert_eq!(o.today(), d("2026-11-25"), "today is the support timezone's");
        for bad in [
            &[][..],
            &["--json"],
            &["a.csv", "b.csv"],
            &["a.csv", "--warn-days", "61"],
            &["a.csv", "--renewal-days", "0"],
            &["a.csv", "--column", "email=Email"],
            &["a.csv", "--column", "tam="],
            &["a.csv", "--as-of", "soon"],
            &["a.csv", "--holidays", "25/12/2026"],
            &["a.csv", "--tam"],
            &["a.csv", "--plan", "pro"],
        ] {
            assert!(parse_args(bad, now).is_err(), "{bad:?}");
        }
    }

    const ACCOUNTS: &str = "Account Name,TAM,TAM email,Signed,Kickoff,Go-live,Last check-in,Last health check,Last QBR,Last restore drill,Last Sev 1,Review shared,Renewal date,ARR,Owner email
Acme,Ana Lima,ana@example.com,2026-01-05,2026-01-07,2026-02-02,2026-02-06,2026-10-01,2026-08-20,2026-03-10,2026-11-16,2026-06-01,2027-01-31,120000,owner@acme.example
Globex,Ana Lima,ana@example.com,2026-11-16,,,,,,,,,2027-11-16,50000,
Soylent,ana lima,,2026-11-23,,,,,,,,,,,
Initech,Bo Chen,,2026-10-01,2026-10-06,,2026-11-10,,,,,,2027-10-01,,
Umbrella,Bo Chen,,2026-11-02,2026-11-04,,,,,,,,,,
Hooli,Bo Chen,,2025-06-01,2025-06-04,2025-07-01,2025-07-03,2026-11-20,2026-10-15,2026-09-01,2026-09-01,2026-09-04,2027-06-30,,
Vandelay,,,2026-09-01,2026-09-02,2026-11-02,2026-10-30,,,,,,2026-11-01,,
Wonka,Cy Diaz,,2026-11-01,2026-12-01,,,,,,,,,,
Stark,Cy Diaz,,,,,,,,,,,,,
acme,Bo Chen,,,,,,,,,,,,,
,Bo Chen,,,,,,,,,,,,,
Tyrell,Cy Diaz,,2026-13-01,,,,,,,,,,,
";

    #[test]
    fn a_book_of_accounts_is_judged_against_the_cadence() {
        let c = check(ACCOUNTS, &opts(&[])).unwrap();
        let v = c.json();
        assert_eq!((v["accounts"].clone(), v["today"].clone()), (json!(9), json!("2026-11-25")));
        // Live since February: the restore drill 77 days late, the health check 24, and a
        // Severity 1 on Monday 16th whose review (an older one was in June) was due by the 23rd.
        assert_eq!(
            items(&v, "Acme"),
            vec![one("restore_drill", "overdue", Some("2026-09-09")), one("health_check", "overdue", Some("2026-11-01")), one("incident_review", "overdue", Some("2026-11-23")), one("renewal", "due_soon", Some("2027-01-31"))]
        );
        // Signed on Monday 16th: kickoff due 5 business days later, the 23rd.
        assert_eq!(items(&v, "Globex"), vec![one("kickoff", "overdue", Some("2026-11-23"))]);
        assert_eq!(items(&v, "Soylent"), vec![one("kickoff", "due_soon", Some("2026-11-30"))]);
        // Onboarding: weekly check-ins, from the last one or from the kickoff.
        assert_eq!(items(&v, "Initech"), vec![one("check_in", "overdue", Some("2026-11-17"))]);
        assert_eq!(items(&v, "Umbrella"), vec![one("check_in", "overdue", Some("2026-11-11"))]);
        // Everything in hand: the review after its Severity 1 was walked through in time.
        assert_eq!(items(&v, "Hooli"), vec![]);
        // Live since 2 November with no check-in since: the week-1 check-in, and the renewal
        // date has passed; the first health check isn't due until a month after go-live.
        assert_eq!(items(&v, "Vandelay"), vec![one("renewal", "overdue", Some("2026-11-01")), one("check_in", "overdue", Some("2026-11-09"))]);
        // A kickoff booked for December hasn't happened: it's due from the signing.
        assert_eq!(items(&v, "Wonka"), vec![one("kickoff", "overdue", Some("2026-11-06"))]);
        assert_eq!(items(&v, "Stark"), vec![one("kickoff", "overdue", None)], "no dates at all is a record to fix");
        let stark = v["listed"].as_array().unwrap().iter().find(|a| a["customer"] == "Stark").unwrap();
        assert_eq!(stark["items"][0]["detail"], "no kickoff, go-live or signing date recorded");

        let skipped: Vec<(u64, &str)> = v["skipped"].as_array().unwrap().iter().map(|s| (s["line"].as_u64().unwrap(), s["reason"].as_str().unwrap())).collect();
        assert_eq!(skipped, vec![(11, "a customer already listed"), (12, "no customer"), (13, "a signed date that can't be read")]);
        assert_eq!((v["overdue"].clone(), v["dueSoon"].clone(), v["due"].clone()), (json!(10), json!(2), json!(true)));
        assert_eq!(v["counts"]["kickoff"], json!({ "overdue": 3, "dueSoon": 1 }));
        assert_eq!(v["notJudged"], json!([]));
        // The most urgent first: a promise with no date at all, then the oldest due.
        let order: Vec<&str> = v["listed"].as_array().unwrap().iter().map(|a| a["customer"].as_str().unwrap()).collect();
        assert_eq!(order, vec!["Stark", "Acme", "Vandelay", "Wonka", "Umbrella", "Initech", "Globex", "Soylent"]);
        assert_eq!(
            v["tams"],
            json!([
                { "tam": "Ana Lima", "accounts": 3, "overdue": 4, "dueSoon": 2 },
                { "tam": "Bo Chen", "accounts": 3, "overdue": 2, "dueSoon": 0 },
                { "tam": "Cy Diaz", "accounts": 2, "overdue": 2, "dueSoon": 0 },
                { "tam": null, "accounts": 1, "overdue": 2, "dueSoon": 0 },
            ])
        );
        assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("support-readiness --tams")));

        let all = format!("{v}{}{}", c.text(), c.markdown());
        for never in ["example", "120000", "50000"] {
            assert!(!all.contains(never), "the check leaks {never}");
        }
        let text = c.text();
        assert!(text.starts_with("TAM cadence as of 2026-11-25 (UTC+00:00)\nBusiness days mon,tue,wed,thu,fri; due soon within 7 days, renewals within 90 days\n\n9 accounts: 10 overdue, 2 due soon, across 8 of them.\n"), "{text}");
        assert!(text.contains("\nAcme  TAM Ana Lima  live since 2026-02-02\n  OVERDUE  restore_drill: 77 days overdue (due 2026-09-09); twice a year; last 2026-03-10. Book the restore drill"), "{text}");
        assert!(text.contains("  DUE      kickoff: due 2026-11-30, in 5 days; signed 2026-11-23, kickoff within 5 business days."), "{text}");
        assert!(text.contains("incident_review: 2 days overdue (due 2026-11-23); Severity 1 on 2026-11-16, its review walked through within 5 business days; the last review walked through was 2026-06-01."), "{text}");
        assert!(text.contains("\nTAM       Accounts  Overdue  Due soon\nAna Lima         3        4         2\n"), "{text}");
        assert!(text.contains("\n(no TAM)         1        2         0\n"), "{text}");
        assert!(text.ends_with("Cadence: docs/support/tam.md#cadence. This lists what's due; it tells nobody.\n"));
        let md = c.markdown();
        assert!(md.starts_with("## TAM cadence as of 2026-11-25 (UTC+00:00)\n"), "{md}");
        assert!(md.contains("| `Globex` | `Ana Lima` | signed 2026-11-16, not kicked off | `kickoff` | **Overdue** | 2 days overdue (due 2026-11-23) |"), "{md}");
        assert!(md.contains("| (no TAM) | 1 | 2 | 0 |"), "{md}");
    }

    #[test]
    fn the_week_one_check_in_gives_way_to_the_health_check_and_a_review_answers_its_severity_1() {
        let csv = "customer,go-live,check-in,health check,severity 1,incident review\nA,2026-09-01,2026-08-25,2026-11-10,2026-11-24,2026-11-24\nB,2026-11-20,2026-11-19,,,\nC,2026-11-20,2026-11-20,,2026-11-20,2026-11-19\n";
        let v = check(csv, &opts(&[])).unwrap().json();
        assert_eq!(v["notJudged"], json!(["kickoff", "business_review", "restore_drill", "renewal"]));
        assert_eq!(items(&v, "A"), vec![], "past a month after go-live the week-1 check-in isn't judged; the review was walked through the day of the Severity 1");
        assert_eq!(items(&v, "B"), vec![one("check_in", "due_soon", Some("2026-11-27"))], "a check-in before go-live isn't the one after it");
        assert_eq!(items(&v, "C"), vec![one("incident_review", "due_soon", Some("2026-11-27"))], "a review older than the Severity 1 doesn't answer it");
        let notes = v["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect::<Vec<_>>().join("\n");
        assert!(notes.contains("restore_drill (needs restore-drill)") && notes.contains("kickoff (needs signed and kickoff)"), "{notes}");
    }

    #[test]
    fn without_a_go_live_column_every_account_is_live() {
        let csv = "Company,Health check,QBR,Drill\nA,,,\nB,2026-11-20,2026-10-01,2026-11-01\n";
        let mut o = opts(&["--column", "restore-drill=Drill"]);
        let v = check(csv, &o).unwrap().json();
        assert_eq!(items(&v, "A"), vec![one("health_check", "overdue", None), one("business_review", "overdue", None), one("restore_drill", "overdue", None)]);
        assert_eq!(items(&v, "B"), vec![]);
        assert!(v["notes"][0].as_str().unwrap().contains("no go-live column, so every account is taken as live"), "{v}");
        let a = v["listed"][0]["items"].as_array().unwrap().iter().map(|i| i["detail"].as_str().unwrap()).collect::<Vec<_>>();
        assert_eq!(a, vec!["monthly; none recorded", "each quarter; none recorded", "twice a year; none recorded"]);
        o.columns = vec![(Field::RestoreDrill, "Nothing".into())];
        assert!(check(csv, &o).unwrap_err().contains("no column \"nothing\""));
        assert!(check("Name,TAM\nA,B\n", &opts(&[])).unwrap_err().contains("no customer column"));
        assert!(check("", &o).is_err());
    }

    #[test]
    fn warning_windows_and_filters() {
        let o = opts(&["--warn-days", "0", "--renewal-days", "30"]);
        let v = check(ACCOUNTS, &o).unwrap().json();
        assert_eq!(items(&v, "Soylent"), vec![], "a kickoff due in 5 days isn't due soon with --warn-days 0");
        assert_eq!(items(&v, "Acme").last().unwrap().0, "incident_review", "nor is a renewal 67 days off within 30");
        let v = check(ACCOUNTS, &opts(&["--tam", "ANA LIMA"])).unwrap().json();
        assert_eq!((v["accounts"].clone(), v["tams"].as_array().unwrap().len()), (json!(3), 1), "the same TAM by name, in any case");
        let c = check(ACCOUNTS, &opts(&["--customer", "hooli"])).unwrap();
        assert!(!c.overdue());
        assert!(c.text().contains("TAM cadence for hooli as of") && c.text().contains("1 account: nothing due."), "{}", c.text());
    }

    #[test]
    fn names_from_the_export_cant_break_a_line_or_the_markdown() {
        let csv = "customer,tam,signed,kickoff,go-live\n\"Evil|Co [x](https://example.net)\",\"`Ma`\nlory\",2026-11-01,,\nhttps://example.net,*Bo*,2026-11-01,,\n";
        let c = check(csv, &opts(&["--tam", "`Ma`\nlory"])).unwrap();
        let md = c.markdown();
        assert!(md.contains("## TAM cadence for TAM `` `Ma` lory `` as of"), "{md}");
        assert!(md.contains("| `Evil\\|Co [x](https://example.net)` | `` `Ma` lory `` |"), "{md}");
        let text = c.text();
        assert!(text.contains("\nEvil|Co [x](https://example.net)  TAM `Ma` lory  signed 2026-11-01"), "{text}");
        let md = check(csv, &opts(&["--customer", "https://example.net"])).unwrap().markdown();
        assert!(md.contains("| `https://example.net` | `*Bo*` |"), "{md}");
    }

    #[test]
    fn dates_read_as_crms_export_them() {
        let o = opts(&["--utc-offset", "+10:00"]);
        assert_eq!(parse_day("2026-11-02", &o), Some(d("2026-11-02")));
        assert_eq!(parse_day("2026/11/02", &o), Some(d("2026-11-02")));
        assert_eq!(parse_day("2026-11-01T20:00:00Z", &o), Some(d("2026-11-02")), "a time is on its day in the support timezone");
        assert_eq!(parse_day("2026-11-02 09:30", &o), Some(d("2026-11-02")));
        assert_eq!(parse_day("02/11/2026", &o), None, "day and month order is ambiguous");
    }
}
