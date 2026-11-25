//! Escalations due now (ADR 0289, #60): from the ticket system's export of tickets (and,
//! with `--updates`, of replies), each open ticket that docs/support/escalation.md's timed
//! escalation says must go to someone now: a response target missed or about to be, a
//! Severity 1 for the on-call engineer and, after 2 hours, management, a Severity 2 still
//! in the runbook 2 hours after its first answer, and an update overdue or about to be.
//!
//! It reads what the support report reads (ids, severities, plans and times, the customer
//! only to pick one) and, from the replies, what its update targets read. It says who to
//! tell and tells nobody: no botd, no ticket system, no pager.

use crate::support_report::{self, minutes, Format, Options, Plan, Target, Ticket};
use crate::support_updates::{self, UpdateOptions};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};

pub const USAGE: &str = "Usage: botctl support-escalations <tickets.csv | -> [--plan <plan>] [--customer <name>]
    [--hours <HH:MM-HH:MM>] [--weekdays <mon-fri>] [--utc-offset <+HH:MM>] [--holidays <YYYY-MM-DD,...>]
    [--target <severity>=<30m|1h|4bh|1bd>]... [--column <field>=<header>]... [--warn <percent>]
    [--as-of <time>] [--markdown | --json]
    [--updates <updates.csv | -> [--update-target <severity>=<1h|4bh|3bd>]... [--update-column <field>=<header>]...]";

/// escalation.md's timed escalation: management for a Severity 1 open this long without a
/// workaround, and the on-call engineer for a Severity 2 this long in the runbook.
pub const SEV1_MANAGEMENT_MINUTES: i64 = 120;
pub const SEV2_ON_CALL_MINUTES: i64 = 120;
/// How much of a target may go before it's "about to be missed".
pub const DEFAULT_WARN_PERCENT: i64 = 75;

/// What an open ticket needs, most urgent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    ResponseMissed,
    Sev1Management,
    Sev1OnCall,
    UpdateOverdue,
    Sev2OnCall,
    ResponseAtRisk,
    UpdateDueSoon,
}

impl Kind {
    pub const ALL: [Kind; 7] = [Kind::ResponseMissed, Kind::Sev1Management, Kind::Sev1OnCall, Kind::UpdateOverdue, Kind::Sev2OnCall, Kind::ResponseAtRisk, Kind::UpdateDueSoon];

    pub fn code(self) -> &'static str {
        match self {
            Kind::ResponseMissed => "response.missed",
            Kind::Sev1Management => "sev1.management",
            Kind::Sev1OnCall => "sev1.on_call",
            Kind::UpdateOverdue => "update.overdue",
            Kind::Sev2OnCall => "sev2.on_call",
            Kind::ResponseAtRisk => "response.at_risk",
            Kind::UpdateDueSoon => "update.due_soon",
        }
    }

    /// Who it goes to, by escalation.md's roles.
    pub fn who(self, plan: Plan) -> &'static str {
        match self {
            Kind::ResponseMissed | Kind::ResponseAtRisk => "support manager",
            Kind::Sev1Management => "management",
            Kind::Sev1OnCall if plan == Plan::Enterprise => "on-call engineer, incident commander and TAM",
            Kind::Sev1OnCall => "on-call engineer and incident commander",
            Kind::Sev2OnCall => "on-call engineer",
            Kind::UpdateOverdue | Kind::UpdateDueSoon => "support engineer",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Kind::ResponseMissed => "Answer it now and tell the support manager: the response target is missed",
            Kind::Sev1Management => "Tell management, unless there's a workaround",
            Kind::Sev1OnCall => "Page the on-call engineer and name an incident commander, if not done",
            Kind::UpdateOverdue => "Update the customer now: the update target is missed",
            Kind::Sev2OnCall => "Hand it to the on-call engineer, unless the runbook is getting somewhere",
            Kind::ResponseAtRisk => "Answer it before the target, or tell the support manager now that it will be missed",
            Kind::UpdateDueSoon => "Update the customer before the next update is due",
        }
    }
}

#[derive(Clone, Debug)]
struct Finding {
    kind: Kind,
    detail: String,
}

#[derive(Clone, Debug)]
struct Open {
    ticket: Ticket,
    findings: Vec<Finding>,
}

#[derive(Debug)]
pub struct Escalations {
    o: Options,
    warn: i64,
    updates_checked: bool,
    open: [u32; 4],
    waiting: u32,
    tickets: Vec<Open>,
    notes: Vec<String>,
    skipped: Vec<(usize, &'static str)>,
}

fn unit(t: Target) -> &'static str {
    match t {
        Target::Clock(_) => "",
        _ => " of business time",
    }
}

/// `minutes` long, counted as `like` counts time: on the clock, or in business hours.
fn counted_as(like: Target, minutes: i64) -> Target {
    match like {
        Target::Clock(_) => Target::Clock(minutes),
        _ => Target::Business(minutes),
    }
}

fn took(secs: i64) -> String {
    minutes(secs / 60)
}

/// `botctl support-escalations ...`: the tickets file (`-` for stdin), the report's options
/// it shares, the updates export's, the warning percentage and the format.
pub fn parse_args(rest: &[&str], now: DateTime<Utc>) -> Result<(String, Options, UpdateOptions, i64, Format), String> {
    let fix = |e: String| e.replace(support_report::USAGE, USAGE);
    let (mut left, mut warn) = (Vec::new(), DEFAULT_WARN_PERCENT);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--warn" => {
                let v = it.next().copied().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("--warn needs a value.\n{USAGE}"))?;
                warn = v.strip_suffix('%').unwrap_or(v).parse::<i64>().ok().filter(|n| (1..=99).contains(n)).ok_or_else(|| format!("--warn: {v} isn't a percentage from 1 to 99"))?;
            }
            "--from" | "--to" => return Err(format!("{a}: escalations are judged as of now (or --as-of), not over months; the support report takes {a}")),
            other => left.push(other),
        }
    }
    let (left, updates) = support_updates::split_args(&left).map_err(fix)?;
    let (file, o, format) = support_report::parse_args(&left, now).map_err(fix)?;
    Ok((file, o, updates, warn, format))
}

/// The escalations due at `o.as_of` among `tickets`' open tickets, with update targets
/// judged from `replies` when given.
pub fn check(tickets: &str, replies: Option<&str>, o: &Options, u: &UpdateOptions, warn: i64) -> Result<Escalations, String> {
    let read = support_report::read_tickets(tickets, o)?;
    let (cal, now) = (&o.calendar, o.as_of);
    let mut notes = Vec::new();
    if !read.has_resolved {
        notes.push("The export has no resolved column, so every ticket in it is taken as open.".to_string());
    }
    let open: Vec<Ticket> = read
        .tickets
        .into_iter()
        .filter(|t| t.opened <= now && t.resolved.is_none_or(|r| r > now))
        .map(|t| Ticket { responded: t.responded.filter(|r| *r <= now), ..t })
        .collect();

    let near = |elapsed: i64, limit: i64| elapsed * 100 >= limit * warn;
    let (mut counts, mut waiting) = ([0u32; 4], 0);
    let mut found: Vec<Open> = Vec::new();
    for t in &open {
        counts[t.severity as usize - 1] += 1;
        let target = o.targets.get(&t.severity).copied().unwrap_or_else(|| Target::default_for(t.plan, t.severity));
        let mut findings = Vec::new();
        match t.responded {
            None => {
                waiting += 1;
                let (elapsed, limit) = (target.elapsed_secs(cal, t.opened, now), target.limit_secs(cal));
                if elapsed > limit {
                    findings.push(Finding { kind: Kind::ResponseMissed, detail: format!("no first answer after {}{}; target {}", took(elapsed), unit(target), target.describe()) });
                } else if near(elapsed, limit) {
                    findings.push(Finding { kind: Kind::ResponseAtRisk, detail: format!("{}{} left; target {}", took(limit - elapsed), unit(target), target.describe()) });
                }
            }
            Some(first) if t.severity == 2 => {
                let clock = counted_as(target, SEV2_ON_CALL_MINUTES);
                let elapsed = clock.elapsed_secs(cal, first, now);
                if elapsed >= clock.limit_secs(cal) {
                    findings.push(Finding { kind: Kind::Sev2OnCall, detail: format!("{}{} since its first answer, past {}", took(elapsed), unit(target), minutes(SEV2_ON_CALL_MINUTES)) });
                }
            }
            Some(_) => {}
        }
        if t.severity == 1 {
            let clock = counted_as(target, SEV1_MANAGEMENT_MINUTES);
            let elapsed = clock.elapsed_secs(cal, t.opened, now);
            findings.push(Finding { kind: Kind::Sev1OnCall, detail: format!("open {}", took((now - t.opened).num_seconds())) });
            if elapsed >= clock.limit_secs(cal) {
                findings.push(Finding { kind: Kind::Sev1Management, detail: format!("open {}{}, past {}", took(elapsed), unit(target), minutes(SEV1_MANAGEMENT_MINUTES)) });
            }
        }
        found.push(Open { ticket: t.clone(), findings });
    }

    let mut skipped: Vec<(usize, &'static str)> = read.skipped;
    if let Some(csv) = replies {
        let target_for = |s: u8| u.targets.get(&s).copied().or_else(|| support_updates::default_target(s));
        let answered: Vec<Ticket> = open.iter().filter(|t| t.responded.is_some() && target_for(t.severity).is_some()).cloned().collect();
        let r = support_updates::read_replies(&answered, csv, o, u).map_err(|e| format!("--updates: {e}"))?;
        let mut without_rows = 0;
        for f in found.iter_mut() {
            let t = &f.ticket;
            let (Some(first), Some(target)) = (t.responded, target_for(t.severity)) else { continue };
            let k = support_updates::key(&t.id);
            if !r.seen.contains(&k) {
                without_rows += 1;
            }
            let last = r.times.get(&k).into_iter().flatten().copied().filter(|x| *x <= now).fold(first, |a, b| a.max(b));
            let (elapsed, limit) = (target.elapsed_secs(cal, last, now), target.limit_secs(cal));
            if elapsed > limit {
                f.findings.push(Finding { kind: Kind::UpdateOverdue, detail: format!("last update {}{} ago; target {}", took(elapsed), unit(target), target.describe()) });
            } else if near(elapsed, limit) {
                f.findings.push(Finding { kind: Kind::UpdateDueSoon, detail: format!("{}{} left; target {}", took(limit - elapsed), unit(target), target.describe()) });
            }
        }
        let plural = |n: u32, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
        if without_rows > 0 {
            notes.push(format!("{} had no rows in the updates export, so they're judged from their first answer: check that it covers every open ticket.", plural(without_rows, "open answered ticket", "open answered tickets")));
        }
        if r.unmatched > 0 {
            notes.push(format!("Update rows for tickets that aren't open and answered weren't read: {}.", r.unmatched));
        }
        if !r.skipped.is_empty() {
            let shown: Vec<String> = r.skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
            let more = if r.skipped.len() > 20 { format!(", and {} more", r.skipped.len() - 20) } else { String::new() };
            notes.push(format!("Skipped {} update rows: {}{more}.", r.skipped.len(), shown.join(", ")));
        }
    } else {
        notes.push("Update targets aren't checked without --updates.".to_string());
    }

    found.retain(|f| !f.findings.is_empty());
    for f in found.iter_mut() {
        f.findings.sort_by_key(|x| x.kind);
    }
    found.sort_by(|a, b| a.findings[0].kind.cmp(&b.findings[0].kind).then(a.ticket.severity.cmp(&b.ticket.severity)).then(a.ticket.opened.cmp(&b.ticket.opened)).then(a.ticket.id.cmp(&b.ticket.id)));
    skipped.sort_unstable();
    Ok(Escalations { o: o.clone(), warn, updates_checked: replies.is_some(), open: counts, waiting, tickets: found, notes, skipped })
}

/// A ticket id from the export, on one line.
fn one_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// A ticket id for a Markdown table: a code span on one line, so nothing in it becomes a
/// link (bare URLs included), a tag or emphasis. Its fence is longer than any run of
/// backticks in it, and `|` stays escaped, since GitHub splits cells even inside code.
fn md_cell(s: &str) -> String {
    let id = one_line(s).replace('|', "\\|");
    let run = id.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(run + 1);
    let pad = if id.starts_with('`') || id.ends_with('`') { " " } else { "" };
    format!("{fence}{pad}{id}{pad}{fence}")
}

impl Escalations {
    /// Whether anything needs escalating now: then botctl exits 1.
    pub fn due(&self) -> bool {
        !self.tickets.is_empty()
    }

    fn heading(&self) -> (String, String) {
        let cal = &self.o.calendar;
        let who = self.o.customer.as_deref().map_or(String::new(), |c| format!(" for {}", one_line(c)));
        let holidays = match cal.holidays.len() {
            0 => String::new(),
            1 => ", 1 holiday".into(),
            n => format!(", {n} holidays"),
        };
        (
            format!("Escalations{who} as of {}", self.o.as_of.format("%Y-%m-%d %H:%M UTC")),
            format!("Business hours {} {} at UTC{}{holidays}; about to be missed at {}% of a target", cal.hours(), cal.weekday_names().join(","), cal.offset, self.warn),
        )
    }

    fn summary(&self) -> String {
        let open: Vec<String> = self.open.iter().enumerate().map(|(i, n)| format!("Sev {}: {n}", i + 1)).collect();
        let waiting = match self.waiting {
            0 => String::new(),
            1 => ", 1 waiting for a first answer".into(),
            n => format!(", {n} waiting for a first answer"),
        };
        let due = match self.tickets.len() {
            0 => "Nothing to escalate.".to_string(),
            1 => "1 ticket needs escalating now.".to_string(),
            n => format!("{n} tickets need escalating now."),
        };
        format!("Open: {}{waiting}.\n{due}", open.join(", "))
    }

    fn ticket_line(t: &Ticket) -> (String, String) {
        (format!("{} ({})", t.severity, t.plan.id()), t.opened.format("%Y-%m-%d %H:%M UTC").to_string())
    }

    fn skipped_line(&self) -> Option<String> {
        (!self.skipped.is_empty()).then(|| {
            let shown: Vec<String> = self.skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
            let more = if self.skipped.len() > 20 { format!(", and {} more", self.skipped.len() - 20) } else { String::new() };
            format!("Skipped {} rows: {}{more}.", self.skipped.len(), shown.join(", "))
        })
    }

    const FOOTER: &'static str = "Rules: docs/support/escalation.md#timed-escalation. This lists who to tell; it tells nobody.";

    pub fn text(&self) -> String {
        let (title, hours) = self.heading();
        let mut out = format!("{title}\n{hours}\n\n{}\n", self.summary());
        for o in &self.tickets {
            let (sev, opened) = Self::ticket_line(&o.ticket);
            out.push_str(&format!("\n{}  Sev {sev}  opened {opened}\n", one_line(&o.ticket.id)));
            for f in &o.findings {
                out.push_str(&format!("  {}: {} ({}) [{}]\n", f.kind.who(o.ticket.plan), f.kind.action(), f.detail, f.kind.code()));
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
        let (title, hours) = self.heading();
        let mut out = format!("## {title}\n\n{hours}.\n\n{}\n", self.summary().replace('\n', " "));
        if !self.tickets.is_empty() {
            out.push_str("\n| Ticket | Severity | Opened | Tell | What to do | Why |\n|---|---|---|---|---|---|\n");
            for o in &self.tickets {
                let (sev, opened) = Self::ticket_line(&o.ticket);
                for f in &o.findings {
                    out.push_str(&format!("| {} | {sev} | {opened} | {} | {} | {} (`{}`) |\n", md_cell(&o.ticket.id), f.kind.who(o.ticket.plan), f.kind.action(), f.detail, f.kind.code()));
                }
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
        for k in Kind::ALL {
            counts.insert(k.code().into(), json!(self.tickets.iter().flat_map(|o| &o.findings).filter(|f| f.kind == k).count()));
        }
        json!({
            "format": 1,
            "asOf": self.o.as_of.to_rfc3339_opts(SecondsFormat::Secs, true),
            "customer": self.o.customer,
            "businessHours": { "hours": cal.hours(), "weekdays": cal.weekday_names(), "utcOffset": cal.offset.to_string(), "holidays": cal.holidays.len() },
            "warnPercent": self.warn,
            "updatesChecked": self.updates_checked,
            "open": self.open.iter().enumerate().map(|(i, n)| json!({ "severity": i + 1, "open": n })).collect::<Vec<_>>(),
            "waiting": self.waiting,
            "due": self.due(),
            "counts": counts,
            "tickets": self.tickets.iter().map(|o| json!({
                "id": o.ticket.id, "severity": o.ticket.severity, "plan": o.ticket.plan.id(),
                "opened": o.ticket.opened.to_rfc3339_opts(SecondsFormat::Secs, true), "answered": o.ticket.responded.is_some(),
                "escalations": o.findings.iter().map(|f| json!({ "code": f.kind.code(), "tell": f.kind.who(o.ticket.plan), "action": f.kind.action(), "detail": f.detail })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "notes": self.notes,
            "skipped": self.skipped.iter().map(|(line, why)| json!({ "line": line, "reason": why })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support_report::parse_time;
    use chrono::FixedOffset;

    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s, FixedOffset::east_opt(0).unwrap()).unwrap()
    }

    fn at(s: &str) -> Options {
        Options::new(t(s))
    }

    #[test]
    fn thresholds_match_the_escalation_playbook() {
        let md = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/escalation.md")).unwrap();
        let timed = md.split("### Timed escalation").nth(1).unwrap().split("\n### ").next().unwrap();
        assert!(timed.contains(&format!("management at {} hours without a workaround", SEV1_MANAGEMENT_MINUTES / 60)), "{timed}");
        assert!(timed.contains(&format!("on-call engineer after {} hours in the runbook", SEV2_ON_CALL_MINUTES / 60)), "{timed}");
        assert!(timed.contains("about to be missed"), "{timed}");
        let roles = md.split("## Inside the Provider").nth(1).unwrap().split("\n## ").next().unwrap().to_lowercase();
        for k in Kind::ALL {
            for plan in Plan::ALL {
                for role in k.who(plan).to_lowercase().split(',').flat_map(|r| r.split(" and ")).map(str::trim).filter(|r| !r.is_empty()) {
                    assert!(roles.contains(role) || role == "tam", "{}'s {role} isn't a role in escalation.md", k.code());
                }
            }
        }
    }

    const TICKETS: &str = "Ticket ID,Subject,Requester,Organization,Priority,Created at,First reply at,Solved at,Plan
E-1,Everything down,ana@example.com,Acme,Urgent,2026-09-01 09:30,2026-09-01 09:50,,enterprise
E-2,Can't sign in,bo@example.com,Acme,Urgent,2026-09-01 11:35,,,enterprise
P-3,Hermes failing,cy@example.com,Globex,High,2026-08-31 13:00,2026-08-31 13:30,,pro
P-4,SSO broken,di@example.com,Globex,High,2026-09-01 09:00,,,pro
S-5,Machine slow,ed@example.com,Initech,Normal,2026-08-27 10:00,,,starter
M-6,Typo,fi@example.com,Hooli,Low,2026-09-01 11:00,2026-09-01 11:05,,max
X-7,Was down,gu@example.com,Acme,Urgent,2026-09-01 08:00,2026-09-01 08:10,2026-09-01 09:00,enterprise
F-8,Later,hu@example.com,Globex,Normal,2026-09-01 13:00,,,pro
B-9,Bad,iv@example.com,Acme,Someday,2026-09-01 10:00,,,enterprise
E-10,Slow runs,jo@example.com,Acme,High,2026-09-01 10:30,2026-09-01 10:45,,enterprise
";

    #[test]
    fn open_tickets_are_escalated_as_the_playbook_says() {
        let o = at("2026-09-01T12:00:00Z");
        let e = check(TICKETS, None, &o, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap();
        let v = e.json();
        assert!(e.due());
        assert_eq!(v["open"], json!([{ "severity": 1, "open": 2 }, { "severity": 2, "open": 3 }, { "severity": 3, "open": 1 }, { "severity": 4, "open": 1 }]), "X-7 is resolved, F-8 opened after --as-of");
        assert_eq!(v["waiting"], 3);
        let ids: Vec<&str> = v["tickets"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["S-5", "E-1", "E-2", "P-3", "P-4"], "most urgent first; M-6 and E-10 need nothing");
        let codes = |i: usize| -> Vec<&str> { v["tickets"][i]["escalations"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap()).collect() };
        // S-5: Starter Sev 3, 2 business days; Thu 10:00 to Tue 12:00 is 27.5 business h.
        assert_eq!(codes(0), vec!["response.missed"]);
        assert_eq!(v["tickets"][0]["escalations"][0]["detail"], "no first answer after 27 h 30 min of business time; target 2 business days");
        assert_eq!(v["tickets"][0]["escalations"][0]["tell"], "support manager");
        // E-1: Enterprise Sev 1 open 2 h 30 min on the clock: management, and the TAM with on-call.
        assert_eq!(codes(1), vec!["sev1.management", "sev1.on_call"]);
        assert_eq!(v["tickets"][1]["escalations"][0]["detail"], "open 2 h 30 min, past 2 h");
        assert_eq!(v["tickets"][1]["escalations"][1]["tell"], "on-call engineer, incident commander and TAM");
        // E-2: 25 of its 30 minutes gone.
        assert_eq!(codes(2), vec!["sev1.on_call", "response.at_risk"]);
        assert_eq!(v["tickets"][2]["escalations"][1]["detail"], "5 min left; target 30 min, 24×7");
        // P-3: Pro Sev 2, counted in business hours: Mon 13:30 to 17:30 and Tue 09:00 to 12:00.
        assert_eq!(codes(3), vec!["sev2.on_call"]);
        assert_eq!(v["tickets"][3]["escalations"][0]["detail"], "7 h of business time since its first answer, past 2 h");
        // P-4: 3 of its 4 business hours gone, exactly the warning.
        assert_eq!(codes(4), vec!["response.at_risk"]);
        assert_eq!(v["tickets"][4]["escalations"][0]["detail"], "1 h of business time left; target 4 business h");
        assert_eq!(v["counts"]["sev1.on_call"], 2);
        assert_eq!(v["counts"]["update.overdue"], 0);
        assert_eq!(v["skipped"], json!([{ "line": 10, "reason": "a severity that isn't 1 to 4" }]));
        assert_eq!(v["updatesChecked"], false);
        assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("without --updates")));

        let text = e.text();
        assert!(text.starts_with("Escalations as of 2026-09-01 12:00 UTC\nBusiness hours 09:00-17:30 mon,tue,wed,thu,fri at UTC+00:00; about to be missed at 75% of a target\n\nOpen: Sev 1: 2, Sev 2: 3, Sev 3: 1, Sev 4: 1, 3 waiting for a first answer.\n5 tickets need escalating now.\n"), "{text}");
        assert!(text.contains("\nE-1  Sev 1 (enterprise)  opened 2026-09-01 09:30 UTC\n  management: Tell management, unless there's a workaround (open 2 h 30 min, past 2 h) [sev1.management]\n"), "{text}");
        let md = e.markdown();
        assert!(md.contains("| `P-3` | 2 (pro) | 2026-08-31 13:00 UTC | on-call engineer | Hand it to the on-call engineer, unless the runbook is getting somewhere | 7 h of business time since its first answer, past 2 h (`sev2.on_call`) |"), "{md}");
        let all = format!("{v}{text}{md}");
        for never in ["example.com", "Acme", "Globex", "Initech", "Everything down", "Can't sign in", "Someday", "X-7", "F-8"] {
            assert!(!all.contains(never), "the escalations leak {never}");
        }
    }

    const UPDATES: &str = "Comment ID,Ticket ID,Author,Author role,Public,Created at,Body
c1,E-1,Ana,agent,true,2026-09-01 10:40,Looking
c2,E-1,Ana,agent,true,2026-09-01 10:55,Still looking
c3,E-1,Ana,agent,false,2026-09-01 11:30,internal note
c4,E-1,Bo,end-user,true,2026-09-01 11:45,any news?
c5,P-3,Cy,agent,true,2026-08-31 17:00,Update
c6,P-3,Cy,end-user,true,2026-09-01 11:00,hello?
c7,X-7,Gu,agent,true,2026-09-01 08:50,closed one
c8,E-10,Jo,agent,true,2026-09-01 11:00,Update
c9,E-1,Ana,agent,true,soon,odd
c10,E-10,Jo,agent,true,2026-09-01 12:30,after --as-of
";

    #[test]
    fn updates_overdue_or_about_to_be() {
        let o = at("2026-09-01T12:00:00Z");
        let u = UpdateOptions { file: Some("replies.csv".into()), ..Default::default() };
        let e = check(TICKETS, Some(UPDATES), &o, &u, DEFAULT_WARN_PERCENT).unwrap();
        let v = e.json();
        let find = |id: &str| v["tickets"].as_array().unwrap().iter().find(|t| t["id"] == id).cloned();
        // E-1: support's last public reply was 10:55; the note and the customer's don't count.
        let e1 = find("E-1").unwrap();
        assert_eq!(e1["escalations"][2], json!({ "code": "update.overdue", "tell": "support engineer", "action": "Update the customer now: the update target is missed", "detail": "last update 1 h 5 min ago; target 1 h, 24×7" }));
        // P-3: Mon 17:00, then 30 min that day and 3 h on Tuesday of its 4 business h.
        let p3 = find("P-3").unwrap();
        assert_eq!(p3["escalations"][1]["code"], "update.due_soon");
        assert_eq!(p3["escalations"][1]["detail"], "30 min of business time left; target 4 business h");
        // E-10: an hour of its 4 business h since 11:00; the reply after --as-of isn't read as made.
        assert!(find("E-10").is_none());
        assert_eq!(v["updatesChecked"], true);
        let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
        assert!(notes.contains(&"Update rows for tickets that aren't open and answered weren't read: 1."), "{notes:?}");
        assert!(notes.contains(&"Skipped 1 update rows: line 10 (a time that can't be read)."), "{notes:?}");
        assert!(!notes.iter().any(|n| n.contains("no rows")), "every open answered ticket has rows");
        let all = format!("{v}{}{}", e.text(), e.markdown());
        for never in ["Ana", "Looking", "internal note", "any news", "closed one", "c1"] {
            assert!(!all.contains(never), "the escalations leak {never}");
        }

        // An agreed 24×7 update target, and a ticket with no rows judged from its first answer.
        let agreed = UpdateOptions { targets: [(2, Target::Clock(60))].into(), ..u.clone() };
        let v = check(TICKETS, Some("ticket,time\nE-1,2026-09-01T11:10:00Z\n"), &o, &agreed, DEFAULT_WARN_PERCENT).unwrap().json();
        let e10 = v["tickets"].as_array().unwrap().iter().find(|t| t["id"] == "E-10").unwrap().clone();
        assert_eq!(e10["escalations"][0]["detail"], "last update 1 h 15 min ago; target 1 h, 24×7");
        let e1 = v["tickets"].as_array().unwrap().iter().find(|t| t["id"] == "E-1").unwrap().clone();
        assert_eq!(e1["escalations"][2]["detail"], "10 min left; target 1 h, 24×7", "50 of its 60 minutes");
        assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("2 open answered tickets had no rows")), "P-3 and E-10: {v}");
    }

    #[test]
    fn as_of_an_earlier_time_and_an_export_of_open_tickets() {
        // At 09:40 E-1 hadn't been answered yet: 10 of its 30 minutes, under the warning.
        let o = at("2026-09-01T09:40:00Z");
        let v = check(TICKETS, None, &o, &UpdateOptions::default(), 30).unwrap().json();
        let e1 = v["tickets"].as_array().unwrap().iter().find(|t| t["id"] == "E-1").unwrap().clone();
        assert_eq!(e1["answered"], false);
        assert_eq!(e1["escalations"][1], json!({ "code": "response.at_risk", "tell": "support manager", "action": "Answer it before the target, or tell the support manager now that it will be missed", "detail": "20 min left; target 30 min, 24×7" }));
        assert!(!v["tickets"].as_array().unwrap().iter().any(|t| t["id"] == "X-7" || t["id"] == "E-2"), "X-7 was resolved at 09:00, E-2 not yet opened");
        let csv = "id,severity,opened,first response\nA,3,2026-09-01T10:00:00Z,2026-09-01T10:30:00Z\n";
        let e = check(csv, None, &Options { plan: Some(Plan::Pro), ..at("2026-09-01T12:00:00Z") }, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap();
        assert!(!e.due());
        assert!(e.text().contains("Open: Sev 1: 0, Sev 2: 0, Sev 3: 1, Sev 4: 0.\nNothing to escalate.\n"), "{}", e.text());
        assert!(e.json()["notes"][0].as_str().unwrap().contains("no resolved column"));
    }

    #[test]
    fn agreed_targets_and_business_hours_move_the_escalations() {
        let csv = "id,severity,opened,first response,resolved\nA,2,2026-09-04T16:00:00Z,2026-09-04T16:30:00Z,\nB,1,2026-09-05T08:30:00Z,,\n";
        // Saturday 11:00. A Pro Sev 2 answered Friday 16:30 has had an hour of business time;
        // a Pro Sev 1 opened at 08:30 on Saturday is late and for management, on the clock.
        let mut o = Options { plan: Some(Plan::Pro), ..at("2026-09-05T11:00:00Z") };
        let v = check(csv, None, &o, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap().json();
        assert_eq!(v["tickets"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["tickets"][0]["id"], "B");
        assert_eq!(v["tickets"][0]["escalations"][0]["code"], "response.missed", "Pro Sev 1 is 1 h, 24×7");
        assert_eq!(v["tickets"][0]["escalations"][1]["code"], "sev1.management", "and counted on the clock");
        // Agreed 24×7 for Severity 2: Friday 16:30 to Saturday 11:00 is over 2 h on the clock.
        o.targets.insert(2, Target::Clock(240));
        o.targets.insert(1, Target::BusinessDays(1));
        let v = check(csv, None, &o, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap().json();
        let codes: Vec<&str> = v["tickets"].as_array().unwrap().iter().flat_map(|t| t["escalations"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap())).collect();
        assert_eq!(codes, vec!["sev1.on_call", "sev2.on_call"], "Sev 1 counted in business hours now has had none");
        assert_eq!(v["tickets"][1]["escalations"][0]["detail"], "18 h 30 min since its first answer, past 2 h");
    }

    #[test]
    fn ids_from_the_export_cant_break_a_line_or_a_table() {
        let csv = "id,severity,opened,first response\n\"[x](https://evil.example)|\nNew line\",1,2026-09-01T10:00:00Z,\n";
        let e = check(csv, None, &Options { plan: Some(Plan::Max), ..at("2026-09-01T12:00:00Z") }, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap();
        let md = e.markdown();
        assert!(md.contains("| `[x](https://evil.example)\\| New line` | 1 (max) |"), "{md}");
        assert!(e.text().contains("\n[x](https://evil.example)| New line  Sev 1 (max)"), "{}", e.text());
        let csv = "id,severity,opened,first response\nhttps://evil.example,1,2026-09-01T10:00:00Z,\n`a``b`,1,2026-09-01T10:00:00Z,\n";
        let md = check(csv, None, &Options { plan: Some(Plan::Max), ..at("2026-09-01T12:00:00Z") }, &UpdateOptions::default(), DEFAULT_WARN_PERCENT).unwrap().markdown();
        assert!(md.contains("| `https://evil.example` | 1 (max) |"), "a bare URL is code, not a link: {md}");
        assert!(md.contains("| ``` `a``b` ``` | 1 (max) |"), "backticks can't close the span: {md}");
        assert_eq!(md.matches("https://evil.example").count(), md.matches("| `https://evil.example` |").count(), "only ever inside its code span: {md}");
    }

    #[test]
    fn arguments() {
        let now = t("2026-09-01T12:00:00Z");
        let (file, o, u, warn, f) = parse_args(&["-", "--plan", "pro", "--warn", "50%", "--updates", "r.csv", "--update-target", "2=4h", "--hours", "08:00-18:00", "--markdown"], now).unwrap();
        assert_eq!((file.as_str(), warn, f, o.plan), ("-", 50, Format::Markdown, Some(Plan::Pro)));
        assert_eq!((u.file.as_deref(), u.targets.get(&2)), (Some("r.csv"), Some(&Target::Clock(240))));
        assert_eq!((o.calendar.open, o.as_of), (480, now));
        let (_, _, _, warn, _) = parse_args(&["t.csv"], now).unwrap();
        assert_eq!(warn, DEFAULT_WARN_PERCENT);
        for (bad, says) in [
            (&["t.csv", "--warn"][..], "--warn needs a value"),
            (&["t.csv", "--warn", "100"], "1 to 99"),
            (&["t.csv", "--warn", "0"], "1 to 99"),
            (&["t.csv", "--from", "2026-08"], "the support report takes --from"),
            (&["t.csv", "--to", "2026-08"], "not over months"),
            (&["t.csv", "--update-target", "1=1h"], "need --updates"),
            (&["t.csv", "--plan", "gold"], "--plan: gold"),
            (&[], "Usage: botctl support-escalations"),
            (&["t.csv", "--hours"], "Usage: botctl support-escalations"),
        ] {
            let e = parse_args(bad, now).unwrap_err();
            assert!(e.contains(says), "{bad:?}: {e}");
            assert!(!e.contains("botctl support-report"), "{bad:?}: {e}");
        }
    }
}
