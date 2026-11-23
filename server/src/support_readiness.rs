//! Is the Provider ready to keep its support promises (ADR 0211, #60)? Three offline
//! checks, each optional: the contact placeholders left in its copy of the playbooks
//! (docs/support), its on-call rota against the hours its plans sell Severity 1 response
//! in (docs/support/tiers.md), and its TAM list against the TAM programme
//! (docs/support/tam.md): every Enterprise customer with a TAM and a different backup,
//! and no TAM over their number of accounts.
//!
//! The rota and TAM list are CSV exports from the Provider's paging tool and CRM. Only a
//! shift's person, start, end and role, and a customer's name, TAM and backup, are read;
//! emails, phone numbers and every other column are left alone. Runs offline: no botd,
//! no paging tool or CRM API.

use crate::support_report::{minutes, normalize, parse_csv, parse_hours, parse_offset, parse_time, parse_weekdays, Calendar, Plan};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, TimeDelta, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

pub const USAGE: &str = "Usage: botctl support-readiness [--docs <dir>] [--rota <rota.csv | ->] [--tams <tams.csv | ->]
    [--plan <plan>]... [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [--hours <HH:MM-HH:MM>] [--weekdays <mon-fri>]
    [--utc-offset <+HH:MM>] [--holidays <YYYY-MM-DD,...>] [--max-stretch <hours>] [--max-accounts <n>]
    [--column <field>=<header>]... [--as-of <time>] [--markdown | --json]";

/// The playbooks' placeholders for the Provider's own contacts, hours and limits: one
/// value each, filled in once.
pub const PROVIDER_PLACEHOLDERS: [&str; 17] = [
    "<support-email>",
    "<support-portal-url>",
    "<security-email>",
    "<status-page-url>",
    "<support-hours>",
    "<support-timezone>",
    "<support-languages>",
    "<self-host-contacts>",
    "<supported-releases>",
    "<on-call-pager>",
    "<on-call-line>",
    "<incident-channel>",
    "<engineering-escalation>",
    "<support-manager>",
    "<engineering-manager>",
    "<escalation-email>",
    "<tam-accounts-per-person>",
];

/// Placeholders that differ per customer: they stay in the playbooks, and the TAM list
/// is checked instead.
pub const PER_CUSTOMER_PLACEHOLDERS: [&str; 3] = ["<tam-name>", "<tam-email>", "<backup-tam-name>"];

/// Whether a plan sells Severity 1 response outside business hours (tiers.md).
pub fn sev1_outside_hours(plan: Plan) -> bool {
    matches!(plan, Plan::Pro | Plan::Max | Plan::Enterprise)
}

/// The columns the checks read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Person,
    Start,
    End,
    Role,
    Customer,
    Tam,
    Backup,
}

impl Field {
    pub const ALL: [Field; 7] = [Field::Person, Field::Start, Field::End, Field::Role, Field::Customer, Field::Tam, Field::Backup];

    fn parse(s: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == s)
    }

    pub fn name(self) -> &'static str {
        match self {
            Field::Person => "person",
            Field::Start => "start",
            Field::End => "end",
            Field::Role => "role",
            Field::Customer => "customer",
            Field::Tam => "tam",
            Field::Backup => "backup",
        }
    }

    /// Header names that mean this field, lowercased with punctuation as spaces.
    fn aliases(self) -> &'static [&'static str] {
        match self {
            Field::Person => &["person", "name", "user", "user name", "engineer", "responder", "on call", "on call user", "member"],
            Field::Start => &["start", "starts", "start time", "start at", "starts at", "start date", "from", "shift start", "on call start"],
            Field::End => &["end", "ends", "end time", "end at", "ends at", "end date", "until", "to", "shift end", "on call end"],
            Field::Role => &["role", "level", "escalation level", "layer", "position", "rota role"],
            Field::Customer => &["customer", "organization", "organisation", "org", "account", "company"],
            Field::Tam => &["tam", "tam name", "technical account manager", "account manager", "named tam"],
            Field::Backup => &["backup", "backup tam", "backup tam name", "deputy", "cover", "secondary tam"],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub docs: Option<String>,
    pub rota: Option<String>,
    pub tams: Option<String>,
    pub plans: Vec<Plan>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub calendar: Calendar,
    pub max_stretch_hours: i64,
    pub max_accounts: Option<usize>,
    pub columns: Vec<(Field, String)>,
    pub as_of: DateTime<Utc>,
}

impl Options {
    /// The four weeks from `as_of`, every plan, default business hours, a week's stretch.
    pub fn new(as_of: DateTime<Utc>) -> Options {
        Options {
            docs: None,
            rota: None,
            tams: None,
            plans: Vec::new(),
            from: as_of,
            to: as_of + TimeDelta::days(28),
            calendar: Calendar::default(),
            max_stretch_hours: 168,
            max_accounts: None,
            columns: Vec::new(),
            as_of,
        }
    }

    fn plans(&self) -> Vec<Plan> {
        if self.plans.is_empty() { Plan::ALL.to_vec() } else { self.plans.clone() }
    }

    fn local_midnight(&self, d: NaiveDate) -> DateTime<Utc> {
        (d.and_hms_opt(0, 0, 0).unwrap() - TimeDelta::seconds(self.calendar.offset.local_minus_utc() as i64)).and_utc()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Markdown,
    Json,
}

fn date(flag: &str, s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| format!("{flag}: {s} isn't a date (YYYY-MM-DD)"))
}

/// `botctl support-readiness ...`: the options and the format.
pub fn parse_args(rest: &[&str], now: DateTime<Utc>) -> Result<(Options, Format), String> {
    let mut o = Options::new(now);
    let (mut format, mut period, mut as_of) = (Format::Text, (None, None), None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().copied().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{a} needs a value.\n{USAGE}"));
        match *a {
            "--markdown" => format = Format::Markdown,
            "--json" | "json" => format = Format::Json,
            "--docs" => o.docs = Some(value()?.to_string()),
            "--rota" => o.rota = Some(value()?.to_string()),
            "--tams" => o.tams = Some(value()?.to_string()),
            "--plan" => {
                let v = value()?;
                let plans: Vec<&str> = Plan::ALL.iter().map(|p| p.id()).collect();
                let p = Plan::parse(v).ok_or_else(|| format!("--plan: {v} isn't one of {}", plans.join(", ")))?;
                if !o.plans.contains(&p) {
                    o.plans.push(p);
                }
            }
            "--from" => period.0 = Some(date("--from", value()?)?),
            "--to" => period.1 = Some(date("--to", value()?)?),
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
                    o.calendar.holidays.insert(date("--holidays", d)?);
                }
            }
            "--max-stretch" => {
                let v = value()?;
                o.max_stretch_hours = v.parse().ok().filter(|h| (1..=8784).contains(h)).ok_or_else(|| format!("--max-stretch: {v} isn't hours from 1 to 8784"))?;
            }
            "--max-accounts" => {
                let v = value()?;
                o.max_accounts = Some(v.parse().ok().filter(|n| (1..=1000).contains(n)).ok_or_else(|| format!("--max-accounts: {v} isn't a number from 1 to 1000"))?);
            }
            "--column" => {
                let v = value()?;
                let (f, header) = v.split_once('=').filter(|(_, h)| !h.trim().is_empty()).ok_or_else(|| format!("--column: {v} isn't <field>=<header>"))?;
                let names: Vec<&str> = Field::ALL.iter().map(|f| f.name()).collect();
                let field = Field::parse(f).ok_or_else(|| format!("--column: {f} isn't one of {}", names.join(", ")))?;
                o.columns.push((field, header.to_string()));
            }
            "--as-of" => as_of = Some(value()?),
            _ => return Err(USAGE.into()),
        }
    }
    if o.docs.is_none() && o.rota.is_none() && o.tams.is_none() {
        return Err(format!("Give at least one of --docs, --rota and --tams.\n{USAGE}"));
    }
    if o.rota.as_deref() == Some("-") && o.tams.as_deref() == Some("-") {
        return Err("Only one of --rota and --tams can read stdin".into());
    }
    if let Some(t) = as_of {
        o.as_of = parse_time(t, o.calendar.offset).ok_or_else(|| format!("--as-of: {t} isn't a time"))?;
        (o.from, o.to) = (o.as_of, o.as_of + TimeDelta::days(28));
    }
    match period {
        (None, None) => {}
        (Some(f), Some(t)) if f <= t && t < f + TimeDelta::days(366) => (o.from, o.to) = (o.local_midnight(f), o.local_midnight(t + TimeDelta::days(1))),
        (Some(_), Some(_)) => return Err("--from must be on or before --to, and less than 366 days before it".into()),
        _ => return Err("Give both --from and --to, or neither for the four weeks from now".into()),
    }
    Ok((o, format))
}

/// Every Markdown file under `dir`, by its path from there, in order.
pub fn read_docs(dir: &str) -> Result<Vec<(String, String)>, String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
        let entries = std::fs::read_dir(at).map_err(|e| format!("{}: {e}", at.display()))?;
        for e in entries {
            let path = e.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                walk(root, &path, out)?;
            } else if path.extension().is_some_and(|x| x == "md") {
                let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                let rel = path.strip_prefix(root).unwrap_or(&path).components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
                out.push((rel, text));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(Path::new(dir), Path::new(dir), &mut out)?;
    out.sort();
    if out.is_empty() {
        return Err(format!("{dir} has no Markdown files"));
    }
    Ok(out)
}

/// The inputs: the playbooks' pages, the rota's CSV and the TAM list's CSV.
#[derive(Default)]
pub struct Inputs {
    pub docs: Option<Vec<(String, String)>>,
    pub rota: Option<String>,
    pub tams: Option<String>,
}

#[derive(Debug)]
struct Contacts {
    dir: String,
    pages: usize,
    left: Vec<(&'static str, Vec<String>)>,
}

fn contacts(dir: &str, pages: &[(String, String)]) -> Contacts {
    let mut left = Vec::new();
    for p in PROVIDER_PLACEHOLDERS {
        let at: Vec<String> = pages.iter().flat_map(|(name, text)| text.lines().enumerate().filter(|(_, l)| l.contains(p)).map(move |(i, _)| format!("{name}:{}", i + 1))).collect();
        if !at.is_empty() {
            left.push((p, at));
        }
    }
    Contacts { dir: dir.to_string(), pages: pages.len(), left }
}

/// Columns by field, found by header or named with `--column`.
fn columns(header: &[String], wanted: &[Field], o: &Options, what: &str) -> Result<HashMap<&'static str, usize>, String> {
    let headers: Vec<String> = header.iter().map(|h| normalize(h)).collect();
    let mut col = HashMap::new();
    for &f in wanted {
        let named = o.columns.iter().find(|(c, _)| *c == f).map(|(_, h)| normalize(h));
        let at = match &named {
            Some(h) => Some(headers.iter().position(|x| x == h).ok_or_else(|| format!("--column {}: the {what} has no column \"{h}\"", f.name()))?),
            None => f.aliases().iter().find_map(|a| headers.iter().position(|x| x == a)),
        };
        if let Some(i) = at {
            col.insert(f.name(), i);
        }
    }
    Ok(col)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Primary,
    Secondary,
    Other,
}

/// Primary from "primary", "1", "Level 1" or "L1"; secondary from "secondary", "backup",
/// "2"; further escalation levels are read but don't count as cover.
fn parse_role(s: &str) -> Option<Role> {
    let lower = s.trim().to_ascii_lowercase();
    if let Some(at) = lower.find(|c: char| c.is_ascii_digit()) {
        let n: String = lower[at..].chars().take_while(char::is_ascii_digit).collect();
        return match n.parse::<u32>().ok()? {
            0 => None,
            1 => Some(Role::Primary),
            2 => Some(Role::Secondary),
            _ => Some(Role::Other),
        };
    }
    Some(match lower.as_str() {
        "primary" | "first" | "main" => Role::Primary,
        "secondary" | "second" | "backup" => Role::Secondary,
        "tertiary" | "third" | "manager" | "escalation" => Role::Other,
        _ => return None,
    })
}

#[derive(Debug)]
struct Shift {
    person: usize,
    role: Role,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

type Span = (DateTime<Utc>, DateTime<Utc>);

#[derive(Debug, Default, Clone)]
struct Load {
    primary: i64,
    secondary: i64,
    outside: i64,
}

#[derive(Debug)]
struct Rota {
    all_hours: bool,
    plans: Vec<Plan>,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    shifts: usize,
    other_levels: usize,
    gaps: Vec<Span>,
    no_backup: Vec<(DateTime<Utc>, DateTime<Utc>, &'static str)>,
    stretches: Vec<(String, DateTime<Utc>, DateTime<Utc>)>,
    load: Vec<(String, Load)>,
    skipped: Vec<(usize, &'static str)>,
}

/// The business hours between `from` and `to`, each day's span in UTC.
fn business_spans(o: &Options) -> Vec<Span> {
    let cal = &o.calendar;
    let first = o.from.with_timezone(&cal.offset).date_naive() - TimeDelta::days(1);
    let last = o.to.with_timezone(&cal.offset).date_naive() + TimeDelta::days(1);
    let mut spans = Vec::new();
    let mut day = first;
    while day <= last {
        if cal.weekdays[day.weekday().num_days_from_monday() as usize] && !cal.holidays.contains(&day) {
            let midnight = o.local_midnight(day);
            let (a, b) = ((midnight + TimeDelta::minutes(cal.open)).max(o.from), (midnight + TimeDelta::minutes(cal.close)).min(o.to));
            if a < b {
                spans.push((a, b));
            }
        }
        let Some(next) = day.succ_opt() else { break };
        day = next;
    }
    spans
}

fn push_span<T: PartialEq + Copy>(list: &mut Vec<(DateTime<Utc>, DateTime<Utc>, T)>, a: DateTime<Utc>, b: DateTime<Utc>, tag: T) {
    match list.last_mut() {
        Some(last) if last.1 == a && last.2 == tag => last.1 = b,
        _ => list.push((a, b, tag)),
    }
}

fn rota(csv: &str, o: &Options) -> Result<Rota, String> {
    let rows = parse_csv(csv)?;
    let ((_, header), body) = rows.split_first().ok_or("the rota is empty")?;
    let col = columns(header, &[Field::Person, Field::Start, Field::End, Field::Role], o, "rota")?;
    for f in [Field::Person, Field::Start, Field::End] {
        if !col.contains_key(f.name()) {
            return Err(format!("the rota has no {} column; name it with --column {}=<header>", f.name(), f.name()));
        }
    }
    let (mut people, mut keys): (Vec<String>, HashMap<String, usize>) = (Vec::new(), HashMap::new());
    let (mut shifts, mut skipped, mut other_levels) = (Vec::new(), Vec::new(), 0);
    for (line, r) in body {
        let cell = |f: Field| col.get(f.name()).and_then(|&c| r.get(c)).map(|s| s.trim()).filter(|s| !s.is_empty());
        let shift = (|| -> Result<_, &'static str> {
            let person = cell(Field::Person).filter(|p| !normalize(p).is_empty()).ok_or("no person")?;
            let time = |f: Field, none: &'static str| cell(f).ok_or(none).and_then(|s| parse_time(s, o.calendar.offset).ok_or("a time that can't be read"));
            let start = time(Field::Start, "no start")?;
            let end = time(Field::End, "no end")?;
            if end <= start {
                return Err("an end that isn't after its start");
            }
            let role = match cell(Field::Role) {
                Some(r) => parse_role(r).ok_or("a role that isn't primary, secondary or a level")?,
                None if col.contains_key(Field::Role.name()) => return Err("no role"),
                None => Role::Primary,
            };
            Ok((person, role, start, end))
        })();
        let (person, role, start, end) = match shift {
            Ok(s) => s,
            Err(why) => {
                skipped.push((*line, why));
                continue;
            }
        };
        if role == Role::Other {
            other_levels += 1;
            continue;
        }
        let key = normalize(person);
        let id = *keys.entry(key).or_insert_with(|| {
            people.push(person.to_string());
            people.len() - 1
        });
        shifts.push(Shift { person: id, role, start, end });
    }

    let business = business_spans(o);
    let plans = o.plans();
    let all_hours = plans.iter().any(|p| sev1_outside_hours(*p));
    let mut points: Vec<DateTime<Utc>> = vec![o.from, o.to];
    for s in &shifts {
        points.extend([s.start.clamp(o.from, o.to), s.end.clamp(o.from, o.to)]);
    }
    for (a, b) in &business {
        points.extend([*a, *b]);
    }
    points.sort();
    points.dedup();

    let mut load = vec![Load::default(); people.len()];
    let (mut gaps, mut no_backup) = (Vec::new(), Vec::new());
    for w in points.windows(2) {
        let (a, b) = (w[0], w[1]);
        let secs = (b - a).num_seconds();
        let in_hours = business.iter().any(|(s, e)| *s <= a && b <= *e);
        let on = |role: Role| -> BTreeSet<usize> { shifts.iter().filter(|s| s.role == role && s.start <= a && b <= s.end).map(|s| s.person).collect() };
        let (primaries, secondaries) = (on(Role::Primary), on(Role::Secondary));
        for p in &primaries {
            load[*p].primary += secs;
        }
        for p in &secondaries {
            load[*p].secondary += secs;
        }
        if !in_hours {
            for p in primaries.union(&secondaries) {
                load[*p].outside += secs;
            }
        }
        if !(all_hours || in_hours) {
            continue;
        }
        if primaries.is_empty() {
            push_span(&mut gaps, a, b, ());
        } else if secondaries.difference(&primaries).next().is_none() {
            let why = if secondaries.is_empty() { "no secondary" } else { "the secondary is also the primary" };
            push_span(&mut no_backup, a, b, why);
        }
    }

    let mut stretches = Vec::new();
    for (id, name) in people.iter().enumerate() {
        let mut mine: Vec<Span> = shifts.iter().filter(|s| s.person == id && s.role == Role::Primary).map(|s| (s.start, s.end)).collect();
        mine.sort();
        let mut merged: Vec<Span> = Vec::new();
        for (s, e) in mine {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        for (s, e) in merged {
            if e > o.from && s < o.to && e - s > TimeDelta::hours(o.max_stretch_hours) {
                stretches.push((name.clone(), s, e));
            }
        }
    }
    stretches.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut load: Vec<(String, Load)> = people.into_iter().zip(load).filter(|(_, l)| l.primary + l.secondary > 0).collect();
    load.sort_by(|a, b| (b.1.primary + b.1.secondary).cmp(&(a.1.primary + a.1.secondary)).then(a.0.cmp(&b.0)));
    Ok(Rota {
        all_hours,
        plans,
        from: o.from,
        to: o.to,
        shifts: shifts.len(),
        other_levels,
        gaps: gaps.into_iter().map(|(a, b, ())| (a, b)).collect(),
        no_backup,
        stretches,
        load,
        skipped,
    })
}

#[derive(Debug)]
struct Tams {
    customers: usize,
    no_tam: Vec<String>,
    no_backup: Vec<(String, &'static str)>,
    duplicates: Vec<String>,
    over: Vec<(String, usize)>,
    load: Vec<(String, usize, usize)>,
    skipped: Vec<(usize, &'static str)>,
}

fn tams(csv: &str, o: &Options) -> Result<Tams, String> {
    let rows = parse_csv(csv)?;
    let ((_, header), body) = rows.split_first().ok_or("the TAM list is empty")?;
    let col = columns(header, &[Field::Customer, Field::Tam, Field::Backup], o, "TAM list")?;
    for f in [Field::Customer, Field::Tam, Field::Backup] {
        if !col.contains_key(f.name()) {
            return Err(format!("the TAM list has no {} column; name it with --column {}=<header>", f.name(), f.name()));
        }
    }
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut people: BTreeMap<String, (String, usize, usize)> = BTreeMap::new();
    let mut counted: BTreeSet<(String, String, bool)> = BTreeSet::new();
    let (mut no_tam, mut no_backup, mut duplicates, mut skipped, mut customers) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), 0);
    for (line, r) in body {
        let cell = |f: Field| col.get(f.name()).and_then(|&c| r.get(c)).map(|s| s.trim()).filter(|s| !normalize(s).is_empty());
        let Some(customer) = cell(Field::Customer) else {
            skipped.push((*line, "no customer"));
            continue;
        };
        customers += 1;
        let n = seen.entry(normalize(customer)).or_insert(0);
        *n += 1;
        if *n == 2 {
            duplicates.push(customer.to_string());
        }
        let (tam, backup) = (cell(Field::Tam), cell(Field::Backup));
        let mut count = |name: &str, backup: bool| {
            if !counted.insert((normalize(name), normalize(customer), backup)) {
                return;
            }
            let e = people.entry(normalize(name)).or_insert_with(|| (name.to_string(), 0, 0));
            if backup { e.2 += 1 } else { e.1 += 1 }
        };
        if let Some(t) = tam {
            count(t, false);
        }
        if let Some(b) = backup {
            count(b, true);
        }
        match (tam, backup) {
            (None, _) => no_tam.push(customer.to_string()),
            (Some(_), None) => no_backup.push((customer.to_string(), "no backup TAM")),
            (Some(t), Some(b)) if normalize(t) == normalize(b) => no_backup.push((customer.to_string(), "the backup TAM is the TAM")),
            _ => {}
        }
    }
    let mut load: Vec<(String, usize, usize)> = people.into_values().collect();
    load.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    let over = o.max_accounts.map_or(Vec::new(), |max| load.iter().filter(|(_, n, _)| *n > max).map(|(t, n, _)| (t.clone(), *n)).collect());
    Ok(Tams { customers, no_tam, no_backup, duplicates, over, load, skipped })
}

#[derive(Debug)]
pub struct Readiness {
    o: Options,
    contacts: Option<Contacts>,
    rota: Option<Rota>,
    tams: Option<Tams>,
}

/// The checks `o` asks for, on `inputs`.
pub fn check(inputs: &Inputs, o: &Options) -> Result<Readiness, String> {
    let contacts = inputs.docs.as_ref().map(|pages| contacts(o.docs.as_deref().unwrap_or("docs"), pages));
    let rota = inputs.rota.as_deref().map(|csv| rota(csv, o)).transpose().map_err(|e| format!("--rota: {e}"))?;
    let tams = inputs.tams.as_deref().map(|csv| tams(csv, o)).transpose().map_err(|e| format!("--tams: {e}"))?;
    Ok(Readiness { o: o.clone(), contacts, rota, tams })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Fail,
    Warn,
}

fn at(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M UTC").to_string()
}

fn rfc(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn span_text(a: DateTime<Utc>, b: DateTime<Utc>) -> String {
    format!("{} to {} ({})", at(a), at(b), minutes((b - a).num_minutes()))
}

fn hours(secs: i64) -> f64 {
    (secs as f64 / 360.0).round() / 10.0
}

fn hours_text(secs: i64) -> String {
    format!("{} h", hours(secs))
}

fn plan_list(plans: &[Plan]) -> String {
    let ids: Vec<&str> = plans.iter().map(|p| p.id()).collect();
    match ids.as_slice() {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// At most 3 places, and how many more.
fn places(at: &[String]) -> String {
    let shown = at.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if at.len() > 3 { format!("{shown} and {} more", at.len() - 3) } else { shown }
}

fn skipped_line(skipped: &[(usize, &str)]) -> Option<String> {
    (!skipped.is_empty()).then(|| {
        let shown: Vec<String> = skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
        let more = if skipped.len() > 20 { format!(", and {} more", skipped.len() - 20) } else { String::new() };
        format!("Skipped {} rows: {}{more}", skipped.len(), shown.join(", "))
    })
}

struct Section {
    title: String,
    notes: Vec<String>,
    findings: Vec<(Status, String)>,
    table: Option<(Vec<&'static str>, Vec<Vec<String>>)>,
}

impl Readiness {
    fn sections(&self) -> Vec<Section> {
        let mut out = Vec::new();
        if let Some(c) = &self.contacts {
            let findings = c.left.iter().map(|(p, at)| (Status::Fail, format!("{p} is still a placeholder: {}", places(at)))).collect();
            let notes = vec![format!("Per customer, so checked in the TAM list instead: {}.", PER_CUSTOMER_PLACEHOLDERS.join(", "))];
            out.push(Section { title: format!("Contacts: {}, {} pages", c.dir, c.pages), notes, findings, table: None });
        }
        if let Some(r) = &self.rota {
            let need = if r.all_hours {
                let selling: Vec<Plan> = r.plans.iter().copied().filter(|p| sev1_outside_hours(*p)).collect();
                format!("Needs a primary on call 24×7: {} sell{} Severity 1 response outside business hours.", plan_list(&selling), if selling.len() == 1 { "s" } else { "" })
            } else {
                format!("Needs a primary on call in business hours only: {} sell{} no Severity 1 response outside them.", plan_list(&r.plans), if r.plans.len() == 1 { "s" } else { "" })
            };
            let mut notes = vec![need];
            if r.other_levels > 0 {
                notes.push(format!("{} shifts at later escalation levels aren't counted as cover.", r.other_levels));
            }
            let mut findings: Vec<(Status, String)> = r.gaps.iter().map(|(a, b)| (Status::Fail, format!("No primary on call {}", span_text(*a, *b)))).collect();
            findings.extend(r.no_backup.iter().map(|(a, b, why)| (Status::Warn, format!("No backup ({why}) {}", span_text(*a, *b)))));
            findings.extend(r.stretches.iter().map(|(p, a, b)| (Status::Warn, format!("{p} primary for {} without a break, {} to {}", hours_text((*b - *a).num_seconds()), at(*a), at(*b)))));
            findings.extend(skipped_line(&r.skipped).map(|s| (Status::Warn, s)));
            let rows = r.load.iter().map(|(p, l)| vec![p.clone(), hours_text(l.primary), hours_text(l.secondary), hours_text(l.outside)]).collect();
            out.push(Section {
                title: format!("On-call rota: {} to {}, {} shifts", at(r.from), at(r.to), r.shifts),
                notes,
                findings,
                table: Some((vec!["Person", "Primary", "Secondary", "Outside business hours"], rows)),
            });
        }
        if let Some(t) = &self.tams {
            let mut findings: Vec<(Status, String)> = t.no_tam.iter().map(|c| (Status::Fail, format!("{c} has no TAM"))).collect();
            findings.extend(t.no_backup.iter().map(|(c, why)| (Status::Fail, format!("{c}: {why}"))));
            let max = self.o.max_accounts.unwrap_or(0);
            findings.extend(t.over.iter().map(|(p, n)| (Status::Fail, format!("{p} is TAM for {n} customers, over the {max} a TAM covers"))));
            findings.extend(t.duplicates.iter().map(|c| (Status::Warn, format!("{c} is listed more than once"))));
            findings.extend(skipped_line(&t.skipped).map(|s| (Status::Warn, s)));
            let notes = if self.o.max_accounts.is_none() { vec!["Accounts per TAM aren't judged: give --max-accounts, the number tam.md promises.".to_string()] } else { Vec::new() };
            let rows = t.load.iter().map(|(p, n, b)| vec![p.clone(), n.to_string(), b.to_string()]).collect();
            out.push(Section { title: format!("TAMs: {} customers", t.customers), notes, findings, table: Some((vec!["Person", "TAM for", "Backup for"], rows)) });
        }
        out
    }

    fn counts(&self) -> (usize, usize) {
        let all: Vec<Status> = self.sections().into_iter().flat_map(|s| s.findings.into_iter().map(|(st, _)| st)).collect();
        (all.iter().filter(|s| **s == Status::Fail).count(), all.iter().filter(|s| **s == Status::Warn).count())
    }

    pub fn ready(&self) -> bool {
        self.counts().0 == 0
    }

    fn headline(&self) -> String {
        let (f, w) = self.counts();
        let n = |n: usize, one: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") };
        let verdict = match (f, w) {
            (0, 0) => "ready".to_string(),
            (0, w) => format!("ready, with {}", n(w, "warning")),
            (f, w) => format!("not ready: {} and {}", n(f, "failure"), n(w, "warning")),
        };
        format!("Support readiness as of {}: {verdict}", at(self.o.as_of))
    }

    pub fn text(&self) -> String {
        let mut out = format!("{}\n", self.headline());
        for s in self.sections() {
            out.push_str(&format!("\n{}\n", s.title));
            for n in &s.notes {
                out.push_str(&format!("  {n}\n"));
            }
            for (st, f) in s.findings.iter().take(50) {
                out.push_str(&format!("  {}  {f}\n", if *st == Status::Fail { "FAIL" } else { "WARN" }));
            }
            if s.findings.len() > 50 {
                out.push_str(&format!("  and {} more (--json lists them all)\n", s.findings.len() - 50));
            }
            if let Some((head, rows)) = s.table.filter(|(_, r)| !r.is_empty()) {
                let width = rows.iter().map(|r| r[0].chars().count()).chain([head[0].len()]).max().unwrap_or(0);
                out.push_str(&format!("  {:<width$}  {}\n", head[0], head[1..].join("  ")));
                for r in rows {
                    let cells: Vec<String> = r[1..].iter().zip(&head[1..]).map(|(c, h)| format!("{c:>w$}", w = h.len())).collect();
                    out.push_str(&format!("  {:<width$}  {}\n", r[0], cells.join("  ")));
                }
            }
        }
        out.push_str("\nPromises: docs/support/tiers.md, severity.md and tam.md.\n");
        out
    }

    pub fn markdown(&self) -> String {
        let cell = |s: &str| s.replace('|', "\\|");
        let mut out = format!("## {}\n", self.headline());
        for s in self.sections() {
            out.push_str(&format!("\n### {}\n\n", s.title));
            for n in &s.notes {
                out.push_str(&format!("{n}\n\n"));
            }
            for (st, f) in &s.findings {
                out.push_str(&format!("- **{}**: {f}\n", if *st == Status::Fail { "Fail" } else { "Warning" }));
            }
            if s.findings.is_empty() {
                out.push_str("Nothing to fix.\n");
            }
            if let Some((head, rows)) = s.table.filter(|(_, r)| !r.is_empty()) {
                out.push_str(&format!("\n| {} |\n|{}\n", head.join(" | "), "---|".repeat(head.len())));
                for r in rows {
                    out.push_str(&format!("| {} |\n", r.iter().map(|c| cell(c)).collect::<Vec<_>>().join(" | ")));
                }
            }
        }
        out
    }

    pub fn json(&self) -> Value {
        let (failures, warnings) = self.counts();
        let span = |a: &DateTime<Utc>, b: &DateTime<Utc>| json!({ "start": rfc(*a), "end": rfc(*b), "minutes": (*b - *a).num_minutes() });
        let skipped = |s: &[(usize, &str)]| s.iter().map(|(line, why)| json!({ "line": line, "reason": why })).collect::<Vec<_>>();
        json!({
            "format": 1,
            "asOf": rfc(self.o.as_of),
            "ready": failures == 0,
            "failures": failures,
            "warnings": warnings,
            "contacts": self.contacts.as_ref().map(|c| json!({
                "pages": c.pages,
                "left": c.left.iter().map(|(p, at)| json!({ "placeholder": p, "count": at.len(), "at": at })).collect::<Vec<_>>(),
                "perCustomer": PER_CUSTOMER_PLACEHOLDERS,
            })),
            "rota": self.rota.as_ref().map(|r| json!({
                "from": rfc(r.from),
                "to": rfc(r.to),
                "coverage": if r.all_hours { "24x7" } else { "business hours" },
                "plans": r.plans.iter().map(|p| p.id()).collect::<Vec<_>>(),
                "shifts": r.shifts,
                "otherLevels": r.other_levels,
                "maxStretchHours": self.o.max_stretch_hours,
                "gaps": r.gaps.iter().map(|(a, b)| span(a, b)).collect::<Vec<_>>(),
                "noBackup": r.no_backup.iter().map(|(a, b, why)| { let mut v = span(a, b); v["reason"] = json!(why); v }).collect::<Vec<_>>(),
                "longStretches": r.stretches.iter().map(|(p, a, b)| json!({ "person": p, "start": rfc(*a), "end": rfc(*b), "hours": hours((*b - *a).num_seconds()) })).collect::<Vec<_>>(),
                "load": r.load.iter().map(|(p, l)| json!({ "person": p, "primaryHours": hours(l.primary), "secondaryHours": hours(l.secondary), "outsideBusinessHours": hours(l.outside) })).collect::<Vec<_>>(),
                "skipped": skipped(&r.skipped),
            })),
            "tams": self.tams.as_ref().map(|t| json!({
                "customers": t.customers,
                "maxAccounts": self.o.max_accounts,
                "noTam": t.no_tam,
                "noBackup": t.no_backup.iter().map(|(c, why)| json!({ "customer": c, "reason": why })).collect::<Vec<_>>(),
                "overCapacity": t.over.iter().map(|(p, n)| json!({ "person": p, "accounts": n })).collect::<Vec<_>>(),
                "duplicates": t.duplicates,
                "load": t.load.iter().map(|(p, n, b)| json!({ "person": p, "tamFor": n, "backupFor": b })).collect::<Vec<_>>(),
                "skipped": skipped(&t.skipped),
            })),
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

    /// Monday 2 to Monday 9 November 2026, every plan.
    fn week() -> Options {
        let (o, _) = parse_args(&["--rota", "r.csv", "--from", "2026-11-02", "--to", "2026-11-08", "--as-of", "2026-11-01T12:00:00Z"], t("2026-11-23T00:00:00Z")).unwrap();
        o
    }

    fn rota_of(csv: &str, o: &Options) -> Readiness {
        check(&Inputs { rota: Some(csv.into()), ..Default::default() }, o).unwrap()
    }

    #[test]
    fn severity_1_outside_hours_matches_the_tiers_playbook() {
        let md = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/tiers.md")).unwrap();
        let header: Vec<&str> = md.lines().find(|l| l.starts_with("| Plan |")).unwrap().trim_matches('|').split('|').map(str::trim).collect();
        let col = header.iter().position(|h| *h == "Severity 1 outside hours").expect("tiers.md's Severity 1 outside hours column");
        let mut seen = 0;
        for line in md.lines().filter(|l| l.starts_with('|')) {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let Some(plan) = cells.first().and_then(|c| Plan::parse(c)) else { continue };
            assert_eq!(cells[col].starts_with("Yes"), sev1_outside_hours(plan), "{plan:?}");
            seen += 1;
        }
        assert_eq!(seen, Plan::ALL.len(), "a row per plan");
    }

    #[test]
    fn the_period_and_options_parse() {
        let now = t("2026-11-23T20:00:00Z");
        let (o, f) = parse_args(&["--docs", "docs/support"], now).unwrap();
        assert_eq!((o.from, o.to, f), (now, t("2026-12-21T20:00:00Z"), Format::Text), "the four weeks from now");
        let (o, f) = parse_args(
            &["--rota", "-", "--tams", "t.csv", "--plan", "starter", "--plan", "self-host", "--plan", "starter", "--from", "2026-12-01", "--to", "2026-12-31", "--utc-offset", "+01:00", "--hours", "08:00-18:00", "--weekdays", "mon-sat", "--holidays", "2026-12-25,2026-12-26", "--max-stretch", "24", "--max-accounts", "8", "--column", "person=Engineer", "--markdown"],
            now,
        )
        .unwrap();
        assert_eq!(f, Format::Markdown);
        assert_eq!((o.rota.as_deref(), o.tams.as_deref()), (Some("-"), Some("t.csv")));
        assert_eq!(o.plans, vec![Plan::Starter, Plan::SelfHost]);
        assert_eq!((o.from, o.to), (t("2026-11-30T23:00:00Z"), t("2026-12-31T23:00:00Z")), "local midnights, the last day included");
        assert_eq!((o.calendar.open, o.calendar.close, o.calendar.holidays.len()), (480, 1080, 2));
        assert_eq!((o.max_stretch_hours, o.max_accounts), (24, Some(8)));
        assert_eq!(o.columns, vec![(Field::Person, "Engineer".to_string())]);
        let (o, _) = parse_args(&["--tams", "t.csv", "--as-of", "2026-01-01T00:00:00Z", "--json"], now).unwrap();
        assert_eq!(o.to, t("2026-01-29T00:00:00Z"), "--as-of moves the default period");
        for bad in [
            &[][..],
            &["--json"],
            &["--rota", "-", "--tams", "-"],
            &["--rota", "r.csv", "--from", "2026-12-01"],
            &["--rota", "r.csv", "--from", "2026-12-01", "--to", "2026-11-01"],
            &["--rota", "r.csv", "--from", "2026-01-01", "--to", "2027-06-01"],
            &["--rota", "r.csv", "--plan", "gold"],
            &["--rota", "r.csv", "--max-stretch", "0"],
            &["--tams", "t.csv", "--max-accounts", "x"],
            &["--rota", "r.csv", "--column", "email=Email"],
            &["--rota"],
            &["r.csv"],
        ] {
            assert!(parse_args(bad, now).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn roles_read_as_paging_tools_export_them() {
        for (s, want) in [("primary", Some(Role::Primary)), ("Level 1", Some(Role::Primary)), ("L1", Some(Role::Primary)), ("1", Some(Role::Primary)), ("Backup", Some(Role::Secondary)), ("secondary", Some(Role::Secondary)), ("Escalation level 2", Some(Role::Secondary)), ("3", Some(Role::Other)), ("manager", Some(Role::Other)), ("0", None), ("shadow", None)] {
            assert_eq!(parse_role(s), want, "{s}");
        }
    }

    const ROTA: &str = "Engineer,Email,Phone,Start,End,Escalation level
Ana Lima,ana@example.com,+44 7700 900123,2026-11-02T00:00:00Z,2026-11-05T00:00:00Z,1
Bo Chen,bo@example.com,+44 7700 900456,2026-11-02T00:00:00Z,2026-11-05T00:00:00Z,2
Bo Chen,bo@example.com,+44 7700 900456,2026-11-05T00:00:00Z,2026-11-07T08:00:00Z,1
Bo Chen,bo@example.com,+44 7700 900456,2026-11-05T00:00:00Z,2026-11-07T00:00:00Z,2
Cy Diaz,cy@example.com,,2026-11-07T12:00:00Z,2026-11-09T00:00:00Z,Primary
Ana Lima,,,2026-11-07T12:00:00Z,2026-11-09T00:00:00Z,secondary
Di Evans,,,2026-11-02T00:00:00Z,2026-11-09T00:00:00Z,3
,,,2026-11-02T00:00:00Z,2026-11-03T00:00:00Z,1
Ed Fox,,,2026-11-03T00:00:00Z,2026-11-02T00:00:00Z,1
Fi Gray,,,soon,2026-11-02T00:00:00Z,1
Gu Hall,,,2026-11-02T00:00:00Z,2026-11-03T00:00:00Z,shadow
Hu Ito,,,2026-11-07T08:00:00Z,2026-11-07T12:00:00Z,
";

    #[test]
    fn a_rota_has_gaps_missing_backups_long_stretches_and_load() {
        let r = rota_of(ROTA, &week());
        let v = r.json();
        let rota = &v["rota"];
        assert_eq!(rota["coverage"], "24x7");
        assert_eq!(rota["shifts"], 6);
        assert_eq!(rota["otherLevels"], 1, "level 3 is read but isn't cover");
        // Saturday 08:00 to 12:00: nobody primary.
        assert_eq!(rota["gaps"], json!([{ "start": "2026-11-07T08:00:00Z", "end": "2026-11-07T12:00:00Z", "minutes": 240 }]));
        // Thursday to Saturday 00:00 Bo is primary and secondary; then 00:00 to 08:00 no secondary at all.
        assert_eq!(
            rota["noBackup"],
            json!([
                { "start": "2026-11-05T00:00:00Z", "end": "2026-11-07T00:00:00Z", "minutes": 2880, "reason": "the secondary is also the primary" },
                { "start": "2026-11-07T00:00:00Z", "end": "2026-11-07T08:00:00Z", "minutes": 480, "reason": "no secondary" },
            ])
        );
        // Bo is on call from Monday to Saturday 08:00, but primary for only 56 h of it.
        assert_eq!(rota["longStretches"], json!([]));
        let load = rota["load"].as_array().unwrap();
        assert_eq!(load[0]["person"], "Bo Chen");
        assert_eq!((load[0]["primaryHours"].as_f64(), load[0]["secondaryHours"].as_f64()), (Some(56.0), Some(120.0)));
        let ana = load.iter().find(|l| l["person"] == "Ana Lima").unwrap();
        assert_eq!((ana["primaryHours"].as_f64(), ana["secondaryHours"].as_f64()), (Some(72.0), Some(36.0)), "the same person by name, once");
        // Ana's Monday to Thursday is 72 h, 25.5 of it business hours (3 × 8.5).
        assert_eq!(ana["outsideBusinessHours"].as_f64(), Some(72.0 - 25.5 + 36.0));
        let skipped: Vec<(u64, &str)> = rota["skipped"].as_array().unwrap().iter().map(|s| (s["line"].as_u64().unwrap(), s["reason"].as_str().unwrap())).collect();
        assert_eq!(skipped, vec![(9, "no person"), (10, "an end that isn't after its start"), (11, "a time that can't be read"), (12, "a role that isn't primary, secondary or a level"), (13, "no role")]);
        assert_eq!((v["ready"].clone(), v["failures"].clone(), v["warnings"].clone()), (json!(false), json!(1), json!(3)));
        let all = format!("{v}{}{}", r.text(), r.markdown());
        for never in ["example.com", "7700", "Di Evans"] {
            assert!(!all.contains(never), "the check leaks {never}");
        }
        assert!(r.text().contains("  FAIL  No primary on call 2026-11-07 08:00 UTC to 2026-11-07 12:00 UTC (4 h)"), "{}", r.text());
        assert!(r.text().contains("pro, max and enterprise sell Severity 1 response outside business hours"), "{}", r.text());
        assert!(r.markdown().contains("| Person | Primary | Secondary | Outside business hours |\n|---|---|---|---|\n| Bo Chen | 56 h | 120 h |"), "{}", r.markdown());
    }

    #[test]
    fn plans_without_round_the_clock_severity_1_need_business_hours_only() {
        let csv = "person,start,end\nAna,2026-11-02T09:00:00Z,2026-11-02T17:30:00Z\nBo,2026-11-03T09:00:00Z,2026-11-06T17:30:00Z\n";
        let mut o = week();
        o.plans = vec![Plan::Starter, Plan::SelfHost];
        let v = rota_of(csv, &o).json();
        assert_eq!(v["rota"]["coverage"], "business hours");
        assert_eq!(v["rota"]["gaps"], json!([]), "Monday to Friday 09:00 to 17:30 is covered; nights and the weekend aren't needed");
        assert_eq!(v["rota"]["noBackup"].as_array().unwrap().len(), 5, "no role column: everyone is primary, with no secondary each business day");
        o.calendar.holidays.insert(NaiveDate::from_ymd_opt(2026, 11, 9).unwrap());
        o.calendar.weekdays = [true; 7];
        let v = rota_of(csv, &o).json();
        assert_eq!(v["rota"]["gaps"], json!([{ "start": "2026-11-07T09:00:00Z", "end": "2026-11-07T17:30:00Z", "minutes": 510 }, { "start": "2026-11-08T09:00:00Z", "end": "2026-11-08T17:30:00Z", "minutes": 510 }]));
        o.plans = vec![Plan::Max];
        let v = rota_of(csv, &o).json();
        assert_eq!(v["rota"]["gaps"][0], json!({ "start": "2026-11-02T00:00:00Z", "end": "2026-11-02T09:00:00Z", "minutes": 540 }), "Max sells Severity 1 at night");
    }

    #[test]
    fn business_hours_follow_the_offset() {
        let mut o = week();
        o.calendar.offset = FixedOffset::east_opt(-5 * 3600).unwrap();
        (o.from, o.to) = (o.local_midnight(NaiveDate::from_ymd_opt(2026, 11, 2).unwrap()), o.local_midnight(NaiveDate::from_ymd_opt(2026, 11, 3).unwrap()));
        o.plans = vec![Plan::Starter];
        let v = rota_of("person,start,end\nAna,2026-11-02T14:00:00Z,2026-11-02T22:30:00Z\n", &o).json();
        assert_eq!(v["rota"]["from"], "2026-11-02T05:00:00Z");
        assert_eq!(v["rota"]["gaps"], json!([]), "09:00 to 17:30 at -05:00 is 14:00 to 22:30 UTC");
        assert_eq!(v["rota"]["load"][0]["outsideBusinessHours"].as_f64(), Some(0.0));
    }

    #[test]
    fn a_long_stretch_is_flagged_once_and_an_empty_rota_is_one_gap() {
        let csv = "person,start,end,role\nAna,2026-10-30T00:00:00Z,2026-11-04T00:00:00Z,primary\nana,2026-11-04T00:00:00Z,2026-11-09T00:00:00Z,primary\n";
        let v = rota_of(csv, &week()).json();
        assert_eq!(v["rota"]["longStretches"], json!([{ "person": "Ana", "start": "2026-10-30T00:00:00Z", "end": "2026-11-09T00:00:00Z", "hours": 240.0 }]));
        assert_eq!(v["rota"]["load"][0]["primaryHours"].as_f64(), Some(168.0), "load counts only the period");
        let just_over = "person,start,end\nAna,2026-11-02T00:00:00Z,2026-11-09T00:30:00Z\n";
        assert_eq!(rota_of(just_over, &week()).json()["rota"]["longStretches"][0]["hours"].as_f64(), Some(168.5), "half an hour over a week is over");
        let mut o = week();
        o.max_stretch_hours = 300;
        assert_eq!(rota_of(csv, &o).json()["rota"]["longStretches"], json!([]));
        let handed_on = "person,start,end,role\nAna,2026-10-30T00:00:00Z,2026-11-04T00:00:00Z,primary\nAna,2026-11-04T00:00:00Z,2026-11-09T00:00:00Z,secondary\n";
        assert_eq!(rota_of(handed_on, &week()).json()["rota"]["longStretches"], json!([]), "a week as primary, then as secondary, isn't a stretch");
        let v = rota_of("person,start,end\n", &week()).json();
        assert_eq!(v["rota"]["gaps"], json!([{ "start": "2026-11-02T00:00:00Z", "end": "2026-11-09T00:00:00Z", "minutes": 10080 }]));
    }

    #[test]
    fn rota_columns_are_found_or_named() {
        let o = week();
        let e = check(&Inputs { rota: Some("Who,From,Until\n".into()), ..Default::default() }, &o).unwrap_err();
        assert!(e.starts_with("--rota: the rota has no person column"), "{e}");
        let named = Options { columns: vec![(Field::Person, "Who".into())], ..o.clone() };
        assert!(check(&Inputs { rota: Some("Who,From,Until\n".into()), ..Default::default() }, &named).is_ok());
        let bad = Options { columns: vec![(Field::Person, "Nobody".into())], ..o };
        assert!(check(&Inputs { rota: Some("Who,From,Until\n".into()), ..Default::default() }, &bad).unwrap_err().contains("no column \"nobody\""));
        assert!(check(&Inputs { rota: Some(String::new()), ..Default::default() }, &week()).is_err());
    }

    const TAMS: &str = "Organisation,TAM,TAM email,Backup TAM
Acme,Ana Lima,ana@example.com,Bo Chen
Globex,Ana Lima,ana@example.com,
Initech,ana lima,,Ana Lima
Umbrella,,,Bo Chen
acme,Bo Chen,,Ana Lima
,Bo Chen,,Ana Lima
Hooli,Bo Chen,,Cy Diaz
";

    #[test]
    fn every_customer_has_a_tam_and_a_different_backup() {
        let mut o = week();
        o.max_accounts = Some(2);
        let r = check(&Inputs { tams: Some(TAMS.into()), ..Default::default() }, &o).unwrap();
        let v = r.json();
        let t = &v["tams"];
        assert_eq!(t["customers"], 6);
        assert_eq!(t["noTam"], json!(["Umbrella"]));
        assert_eq!(t["noBackup"], json!([{ "customer": "Globex", "reason": "no backup TAM" }, { "customer": "Initech", "reason": "the backup TAM is the TAM" }]));
        assert_eq!(t["duplicates"], json!(["acme"]));
        assert_eq!(t["overCapacity"], json!([{ "person": "Ana Lima", "accounts": 3 }]));
        assert_eq!(t["load"][0], json!({ "person": "Ana Lima", "tamFor": 3, "backupFor": 2 }));
        assert_eq!(t["skipped"], json!([{ "line": 7, "reason": "no customer" }]));
        assert_eq!((v["failures"].clone(), v["warnings"].clone()), (json!(4), json!(2)));
        assert!(!format!("{v}{}{}", r.text(), r.markdown()).contains("example.com"));
        assert!(r.text().contains("  FAIL  Ana Lima is TAM for 3 customers, over the 2 a TAM covers"), "{}", r.text());
        o.max_accounts = None;
        let r = check(&Inputs { tams: Some(TAMS.into()), ..Default::default() }, &o).unwrap();
        assert_eq!(r.json()["tams"]["overCapacity"], json!([]));
        assert!(r.text().contains("give --max-accounts"));
        o.max_accounts = Some(1);
        let twice = "customer,tam,backup\nAcme,Ana,Bo\nACME,ana,Bo\n";
        let v = check(&Inputs { tams: Some(twice.into()), ..Default::default() }, &o).unwrap().json();
        assert_eq!((v["tams"]["overCapacity"].clone(), v["tams"]["duplicates"].clone()), (json!([]), json!(["ACME"])), "a customer listed twice is one account");
        assert_eq!(v["tams"]["load"][0], json!({ "person": "Ana", "tamFor": 1, "backupFor": 0 }));
        let e = check(&Inputs { tams: Some("customer,tam\nAcme,Ana\n".into()), ..Default::default() }, &o).unwrap_err();
        assert!(e.contains("no backup column"), "{e}");
    }

    #[test]
    fn contacts_left_as_placeholders_fail_and_per_customer_ones_dont() {
        let pages = vec![
            ("README.md".to_string(), "Write to `<support-email>`.\nOr <support-email> again, and `<status-page-url>`.\n".to_string()),
            ("tam.md".to_string(), "Your TAM is `<tam-name>` (`<tam-email>`).\n".to_string()),
        ];
        let mut o = week();
        o.docs = Some("support".into());
        let r = check(&Inputs { docs: Some(pages), ..Default::default() }, &o).unwrap();
        let v = r.json();
        assert_eq!(v["contacts"]["left"], json!([{ "placeholder": "<support-email>", "count": 2, "at": ["README.md:1", "README.md:2"] }, { "placeholder": "<status-page-url>", "count": 1, "at": ["README.md:2"] }]));
        assert_eq!(v["failures"], 2);
        assert!(r.text().contains("Contacts: support, 2 pages"));
        let filled = vec![("README.md".to_string(), "Write to help at the Provider. Your TAM is `<tam-name>`.\n".to_string())];
        let r = check(&Inputs { docs: Some(filled), ..Default::default() }, &o).unwrap();
        assert!(r.ready());
        assert!(r.text().starts_with("Support readiness as of 2026-11-01 12:00 UTC: ready\n"), "{}", r.text());
        assert!(r.markdown().contains("Nothing to fix."));
    }

    #[test]
    fn the_shipped_playbooks_are_all_placeholders() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support");
        let pages = read_docs(dir).unwrap();
        assert!(pages.iter().any(|(n, _)| n == "README.md"));
        let c = contacts(dir, &pages);
        let left: Vec<&str> = c.left.iter().map(|(p, _)| *p).collect();
        assert_eq!(left, PROVIDER_PLACEHOLDERS, "every Provider placeholder is used in the playbooks");
        assert!(read_docs("/nonexistent-support-dir").is_err());
    }
}
