//! Update targets in the support report (ADR 0286, #60): from a second export of the
//! ticket system, one row per reply or comment on a ticket, whether each Severity 1 to 3
//! ticket the report counts was updated as often as docs/support/severity.md promises,
//! from its first answer until it was resolved (or until now, while it's open).
//!
//! It reads only a row's ticket id and time, and whether the row was public and from the
//! Provider's side. Bodies, authors, emails and every other column are never read, and a
//! skipped row is named by its line, not its contents. Runs offline, like the report.

use crate::support_report::{minutes, normalize, parse_csv, parse_time, Options, Plan, Target, Ticket};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The update targets of severity.md's "Updates until it's fixed": hourly around the
/// clock, every 4 hours of the plan's support hours, at least every 3 business days, and
/// none for Severity 4 ("when there's news").
pub fn default_target(severity: u8) -> Option<Target> {
    match severity {
        1 => Some(Target::Clock(60)),
        2 => Some(Target::Business(4 * 60)),
        3 => Some(Target::BusinessDays(3)),
        _ => None,
    }
}

/// The columns of the updates export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Ticket,
    Time,
    Public,
    Private,
    Author,
}

impl Field {
    const ALL: [Field; 5] = [Field::Ticket, Field::Time, Field::Public, Field::Private, Field::Author];

    fn parse(s: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == s)
    }

    fn name(self) -> &'static str {
        match self {
            Field::Ticket => "ticket",
            Field::Time => "time",
            Field::Public => "public",
            Field::Private => "private",
            Field::Author => "author",
        }
    }

    /// Header names that mean this field, lowercased with punctuation as spaces. A bare
    /// "id" isn't one: in a comments export it is usually the comment's own id.
    fn aliases(self) -> &'static [&'static str] {
        match self {
            Field::Ticket => &["ticket id", "ticket", "ticket number", "ticket no", "ticket key", "issue key", "issue id", "case number", "case id", "case"],
            Field::Time => &["created at", "created", "time", "timestamp", "date", "posted at", "posted", "sent at", "sent", "comment created", "comment created at", "comment date", "replied at", "reply time"],
            Field::Public => &["public", "is public", "visibility", "visible to customer", "public reply"],
            Field::Private => &["private", "is private", "internal", "is internal", "internal note"],
            Field::Author => &["author role", "author type", "sender type", "user type", "role", "direction"],
        }
    }
}

/// `true` for yes-like and public-like words, `false` for no-like and internal-like ones.
fn public_word(s: &str) -> Option<bool> {
    match normalize(s).as_str() {
        "true" | "yes" | "y" | "1" | "public" | "external" | "customer" | "visible" | "reply" | "public reply" => Some(true),
        "false" | "no" | "n" | "0" | "internal" | "private" | "note" | "internal note" | "hidden" => Some(false),
        _ => None,
    }
}

/// Whether a row's author is the Provider's support (an update) or not (the customer, or
/// an automation, whose messages aren't updates).
fn from_support(s: &str) -> Option<bool> {
    match normalize(s).as_str() {
        "agent" | "light agent" | "staff" | "support" | "admin" | "administrator" | "provider" | "engineer" | "team" | "outgoing" | "outbound" => Some(true),
        "end user" | "enduser" | "customer" | "requester" | "user" | "contact" | "client" | "reporter" | "incoming" | "inbound" | "system" | "automation" | "bot" | "trigger" => Some(false),
        _ => None,
    }
}

fn key(id: &str) -> String {
    id.trim().trim_start_matches('#').to_lowercase()
}

#[derive(Clone, Debug, Default)]
pub struct UpdateOptions {
    /// The updates export, `-` for stdin; without it there's no update section.
    pub file: Option<String>,
    pub targets: BTreeMap<u8, Target>,
    pub columns: Vec<(Field, String)>,
}

/// Takes `--updates`, `--update-target` and `--update-column` out of `botctl
/// support-report`'s arguments, leaving the rest for the report's own.
pub fn split_args<'a>(rest: &[&'a str]) -> Result<(Vec<&'a str>, UpdateOptions), String> {
    let (mut left, mut u) = (Vec::new(), UpdateOptions::default());
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().copied().filter(|v| *v == "-" || !v.starts_with("--")).ok_or_else(|| format!("{a} needs a value"));
        match *a {
            "--updates" => {
                if u.file.is_some() {
                    return Err("--updates is given twice".into());
                }
                u.file = Some(value()?.to_string());
            }
            "--update-target" => {
                let v = value()?;
                let bad = || format!("--update-target: {v} isn't <severity>=<time>, such as 1=30m, 2=4h, 2=4bh or 3=1bd");
                let (sev, t) = v.split_once('=').ok_or_else(bad)?;
                let sev = sev.parse::<u8>().ok().filter(|s| (1..=4).contains(s)).ok_or_else(bad)?;
                u.targets.insert(sev, Target::parse(t).ok_or_else(bad)?);
            }
            "--update-column" => {
                let v = value()?;
                let (f, header) = v.split_once('=').filter(|(_, h)| !h.trim().is_empty()).ok_or_else(|| format!("--update-column: {v} isn't <field>=<header>"))?;
                let names: Vec<&str> = Field::ALL.iter().map(|f| f.name()).collect();
                let field = Field::parse(f).ok_or_else(|| format!("--update-column: {f} isn't one of {}", names.join(", ")))?;
                u.columns.push((field, header.to_string()));
            }
            other => left.push(other),
        }
    }
    if u.file.is_none() && (!u.targets.is_empty() || !u.columns.is_empty()) {
        return Err("--update-target and --update-column need --updates <updates.csv | ->".into());
    }
    Ok((left, u))
}

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    judged: u32,
    kept: u32,
    late: u32,
}

#[derive(Clone, Debug)]
struct Late {
    id: String,
    severity: u8,
    plan: Plan,
    opened: DateTime<Utc>,
    gaps: u32,
    longest: i64,
    target: Target,
    open: bool,
    overdue_now: bool,
}

#[derive(Debug)]
pub struct Updates {
    targets: Vec<(u8, Target, bool)>,
    severities: [Counts; 4],
    late: Vec<Late>,
    not_answered: u32,
    without_rows: u32,
    unmatched: u32,
    skipped: Vec<(usize, &'static str)>,
}

/// Judges the update targets of `tickets` (the report's) from the updates export `csv`.
pub fn judge(tickets: &[Ticket], csv: &str, o: &Options, u: &UpdateOptions) -> Result<Updates, String> {
    let rows = parse_csv(csv)?;
    let ((_, header), body) = rows.split_first().ok_or("the updates CSV is empty")?;
    let headers: Vec<String> = header.iter().map(|h| normalize(h)).collect();
    let mut col: HashMap<&'static str, usize> = HashMap::new();
    for f in Field::ALL {
        let named = u.columns.iter().find(|(c, _)| *c == f).map(|(_, h)| normalize(h));
        let at = match &named {
            Some(h) => Some(headers.iter().position(|x| x == h).ok_or_else(|| format!("--update-column {}: the updates CSV has no column \"{h}\"", f.name()))?),
            None => f.aliases().iter().find_map(|a| headers.iter().position(|x| x == a)),
        };
        if let Some(i) = at {
            col.insert(f.name(), i);
        }
    }
    for f in [Field::Ticket, Field::Time] {
        if !col.contains_key(f.name()) {
            return Err(format!("the updates CSV has no {} column; name it with --update-column {}=<header>", f.name(), f.name()));
        }
    }

    let wanted: HashSet<String> = tickets.iter().map(|t| key(&t.id)).collect();
    let (mut times, mut skipped, mut unmatched): (HashMap<String, Vec<DateTime<Utc>>>, _, _) = (HashMap::new(), Vec::new(), 0);
    let mut seen: HashSet<String> = HashSet::new();
    for (line, r) in body {
        let cell = |f: Field| col.get(f.name()).and_then(|&c| r.get(c)).map(|s| s.trim()).filter(|s| !s.is_empty());
        let Some(ticket) = cell(Field::Ticket).map(key) else {
            skipped.push((*line, "no ticket id"));
            continue;
        };
        if !wanted.contains(&ticket) {
            unmatched += 1;
            continue;
        }
        seen.insert(ticket.clone());
        let row = (|| -> Result<_, &'static str> {
            let time = parse_time(cell(Field::Time).ok_or("no time")?, o.calendar.offset).ok_or("a time that can't be read")?;
            let flag = |f: Field, why: &'static str| -> Result<Option<bool>, &'static str> {
                if !col.contains_key(f.name()) {
                    return Ok(None);
                }
                cell(f).map(public_word).ok_or(why)?.ok_or(why).map(Some)
            };
            let public = flag(Field::Public, "a visibility it doesn't know")?.unwrap_or(true);
            let private = flag(Field::Private, "a visibility it doesn't know")?.unwrap_or(false);
            let support = match col.contains_key(Field::Author.name()) {
                true => cell(Field::Author).map(from_support).ok_or("an author it doesn't know")?.ok_or("an author it doesn't know")?,
                false => true,
            };
            Ok((time, public && !private && support))
        })();
        match row {
            Err(why) => skipped.push((*line, why)),
            Ok((time, true)) => times.entry(ticket).or_default().push(time),
            Ok((_, false)) => {}
        }
    }

    let target_for = |s: u8| u.targets.get(&s).copied().or_else(|| default_target(s));
    let (mut severities, mut late, mut not_answered, mut without_rows) = ([Counts::default(); 4], Vec::new(), 0, 0);
    let cal = &o.calendar;
    for t in tickets {
        let Some(target) = target_for(t.severity) else { continue };
        let Some(first) = t.responded else {
            not_answered += 1;
            continue;
        };
        let open = t.resolved.is_none_or(|r| r > o.as_of);
        let end = t.resolved.unwrap_or(o.as_of).min(o.as_of).max(first);
        let k = key(&t.id);
        if !seen.contains(&k) {
            without_rows += 1;
        }
        let mut points: Vec<DateTime<Utc>> = times.get(&k).into_iter().flatten().copied().filter(|x| *x > first && *x <= end).collect();
        points.sort_unstable();
        points.insert(0, first);
        points.push(end);
        let limit = target.limit_secs(cal);
        let (mut gaps, mut longest, mut overdue_now) = (0, 0, false);
        for (i, w) in points.windows(2).enumerate() {
            let took = target.elapsed_secs(cal, w[0], w[1]);
            longest = longest.max(took);
            if took > limit {
                gaps += 1;
                overdue_now |= open && i == points.len() - 2;
            }
        }
        let c = &mut severities[t.severity as usize - 1];
        c.judged += 1;
        if gaps == 0 {
            c.kept += 1;
        } else {
            c.late += 1;
            late.push(Late { id: t.id.clone(), severity: t.severity, plan: t.plan, opened: t.opened, gaps, longest, target, open, overdue_now });
        }
    }
    late.sort_by(|a, b| a.opened.cmp(&b.opened).then(a.id.cmp(&b.id)));
    let targets = (1..=4).filter_map(|s| target_for(s).map(|t| (s, t, u.targets.contains_key(&s)))).collect();
    Ok(Updates { targets, severities, late, not_answered, without_rows, unmatched, skipped })
}

fn percent(kept: u32, judged: u32) -> Option<u32> {
    (judged > 0).then(|| ((kept as f64 / judged as f64) * 100.0).floor() as u32)
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

impl Updates {
    fn totals(&self) -> Counts {
        self.severities.iter().fold(Counts::default(), |a, c| Counts { judged: a.judged + c.judged, kept: a.kept + c.kept, late: a.late + c.late })
    }

    /// Each severity with an update target, and its counts.
    fn rows(&self) -> impl Iterator<Item = (u8, Counts)> + '_ {
        self.targets.iter().map(|(s, _, _)| (*s, self.severities[*s as usize - 1]))
    }

    fn target_text(&self, severity: u8) -> String {
        match self.targets.iter().find(|(s, _, _)| *s == severity) {
            Some((_, t, true)) => format!("{} (agreed)", t.describe()),
            Some((_, t, false)) => t.describe(),
            None => "none".into(),
        }
    }

    fn summary(&self) -> String {
        let t = self.totals();
        match percent(t.kept, t.judged) {
            Some(p) => format!("{} of {} tickets kept every update target ({p}%).", t.kept, t.judged),
            None => "No answered Severity 1 to 3 tickets to judge in the period.".into(),
        }
    }

    fn late_line(l: &Late) -> (String, String, String, String) {
        let unit = match l.target {
            Target::Clock(_) => "",
            _ => " of business time",
        };
        let gaps = if l.gaps == 1 { "1 gap".to_string() } else { format!("{} gaps", l.gaps) };
        let now = match (l.open, l.overdue_now) {
            (true, true) => ", still open with the next update overdue",
            (true, false) => ", still open",
            _ => "",
        };
        (
            l.id.clone(),
            format!("{} ({})", l.severity, l.plan.id()),
            l.opened.format("%Y-%m-%d %H:%M UTC").to_string(),
            format!("{gaps} over target, the longest {}{unit}{now}; target {}", minutes(l.longest / 60), l.target.describe()),
        )
    }

    fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        let plural = |n: u32, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
        if self.not_answered > 0 {
            notes.push(format!("Not judged: {} with no first answer yet (the response target covers it).", plural(self.not_answered, "ticket", "tickets")));
        }
        if self.without_rows > 0 {
            notes.push(format!("{} had no rows in the updates export: check that it covers every ticket in the tickets export.", plural(self.without_rows, "judged ticket", "judged tickets")));
        }
        if self.unmatched > 0 {
            notes.push(format!("{} were for tickets outside the report and weren't read.", plural(self.unmatched, "update row", "update rows")));
        }
        if !self.skipped.is_empty() {
            let shown: Vec<String> = self.skipped.iter().take(20).map(|(l, why)| format!("line {l} ({why})")).collect();
            let more = if self.skipped.len() > 20 { format!(", and {} more", self.skipped.len() - 20) } else { String::new() };
            notes.push(format!("Skipped {} update rows: {}{more}.", self.skipped.len(), shown.join(", ")));
        }
        notes
    }

    const FOOTER: &'static str = "Update targets: docs/support/severity.md. Updates are support's public replies after the first answer, until resolved; Severity 4 has none.";

    pub fn text(&self) -> String {
        let mut out = format!("Update targets\n{:<3} {:<22} {:>6} {:>5} {:>5}\n", "Sev", "Target", "Judged", "Kept", "Late");
        for (s, c) in self.rows() {
            out.push_str(&format!("{:<3} {:<22} {:>6} {:>5} {:>5}\n", s, self.target_text(s), c.judged, c.kept, c.late));
        }
        out.push_str(&format!("\n{}\n", self.summary()));
        if !self.late.is_empty() {
            out.push_str("Late updates:\n");
            for l in &self.late {
                let (id, sev, opened, what) = Self::late_line(l);
                out.push_str(&format!("  {id}  Sev {sev}  opened {opened}  {what}\n"));
            }
        }
        for n in self.notes() {
            out.push_str(&format!("{n}\n"));
        }
        out.push_str(Self::FOOTER);
        out.push('\n');
        out
    }

    pub fn markdown(&self) -> String {
        let mut out = String::from("### Update targets\n\n| Severity | Target | Judged | Kept | Late |\n|---|---|---|---|---|\n");
        for (s, c) in self.rows() {
            out.push_str(&format!("| {s} | {} | {} | {} | {} |\n", self.target_text(s), c.judged, c.kept, c.late));
        }
        out.push_str(&format!("\n{}\n", self.summary()));
        if !self.late.is_empty() {
            out.push_str("\n#### Late updates\n\n| Ticket | Severity | Opened | What happened |\n|---|---|---|---|\n");
            for l in &self.late {
                let (id, sev, opened, what) = Self::late_line(l);
                out.push_str(&format!("| {} | {sev} | {opened} | {what} |\n", md_cell(&id)));
            }
        }
        for n in self.notes() {
            out.push_str(&format!("\n{n}\n"));
        }
        out.push_str(&format!("\n{}\n", Self::FOOTER));
        out
    }

    pub fn json(&self) -> Value {
        let t = self.totals();
        json!({
            "targets": self.targets.iter().map(|(s, t, agreed)| json!({ "severity": s, "target": t.describe(), "agreed": agreed })).collect::<Vec<_>>(),
            "severities": self.rows().map(|(s, c)| json!({ "severity": s, "judged": c.judged, "kept": c.kept, "late": c.late })).collect::<Vec<_>>(),
            "judged": t.judged,
            "kept": t.kept,
            "lateCount": t.late,
            "keptPercent": percent(t.kept, t.judged),
            "late": self.late.iter().map(|l| json!({
                "id": l.id, "severity": l.severity, "plan": l.plan.id(), "opened": l.opened.to_rfc3339_opts(SecondsFormat::Secs, true),
                "gaps": l.gaps, "longestGapMinutes": l.longest / 60, "target": l.target.describe(), "open": l.open, "overdueNow": l.overdue_now,
            })).collect::<Vec<_>>(),
            "notAnswered": self.not_answered,
            "withoutRows": self.without_rows,
            "unmatchedRows": self.unmatched,
            "skipped": self.skipped.iter().map(|(line, why)| json!({ "line": line, "reason": why })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support_report::report;
    use chrono::{FixedOffset, NaiveDate};

    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s, FixedOffset::east_opt(0).unwrap()).unwrap()
    }

    fn september(as_of: &str) -> Options {
        let mut o = Options::new(t(as_of));
        (o.from, o.to) = (NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 9, 1).unwrap());
        o
    }

    fn with_file() -> UpdateOptions {
        UpdateOptions { file: Some("updates.csv".into()), ..Default::default() }
    }

    #[test]
    fn defaults_match_the_severity_playbook() {
        let md = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/support/severity.md")).unwrap();
        let section = md.split("## Updates until it's fixed").nth(1).unwrap().split("\n## ").next().unwrap();
        let mut seen = 0;
        for line in section.lines() {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let Ok(sev) = cells[0].parse::<u8>() else { continue };
            let want = match default_target(sev) {
                Some(Target::Clock(60)) => "At least hourly, around the clock",
                Some(Target::Business(240)) => "Every 4 hours during the plan's support hours",
                Some(Target::BusinessDays(3)) => "at least every 3 business days",
                None => "When there's news",
                other => panic!("severity {sev}'s default {other:?} isn't written in severity.md"),
            };
            assert!(cells[1].contains(want), "severity {sev}: severity.md says {:?}, the code {want:?}", cells[1]);
            seen += 1;
        }
        assert_eq!(seen, 4);
    }

    const TICKETS: &str = "Ticket ID,Subject,Priority,Created at,First reply at,Solved at,Plan
T-1,Down,Urgent,2026-09-01 10:00,2026-09-01 10:20,2026-09-01 14:00,enterprise
T-2,SSO,High,2026-09-02 10:00,2026-09-02 10:30,2026-09-03 12:00,enterprise
T-3,Machine,Normal,2026-09-04 16:00,2026-09-07 09:30,,pro
T-4,Typo,Low,2026-09-04 16:00,2026-09-07 09:30,,pro
T-5,Waiting,Urgent,2026-09-30 23:50,,,pro
T-6,Quiet,High,2026-09-10 10:00,2026-09-10 10:05,2026-09-10 11:00,pro
";

    const UPDATES: &str = "Comment ID,Ticket ID,Author,Author role,Public,Created at,Body
c1,T-1,Ana,agent,true,2026-09-01 11:15,Looking
c2,T-1,Ana,agent,false,2026-09-01 12:00,internal note
c3,T-1,Bo,end-user,true,2026-09-01 12:10,any news?
c4,T-1,Ana,agent,true,2026-09-01 13:20,Fixed soon
c5,#t-2,Ana,agent,true,2026-09-02 17:00,Update
c6,T-3,Cy,agent,true,2026-09-09 10:00,Update
c7,T-99,Di,agent,true,2026-09-09 10:00,another customer
c8,T-3,Cy,agent,yes please,2026-09-09 11:00,odd
c9,T-3,Cy,agent,true,last week,odd
";

    #[test]
    fn gaps_between_updates_are_judged_against_each_severity() {
        let o = september("2026-10-01T09:00:00Z");
        let r = report(TICKETS, &o).unwrap();
        let u = judge(r.tickets(), UPDATES, &o, &with_file()).unwrap();
        let v = u.json();
        // T-1, Sev 1: 10:20, 11:15, 13:20, resolved 14:00. The internal note and the
        // customer's message don't count, so 11:15 to 13:20 is over an hour.
        assert_eq!(v["severities"][0], json!({ "severity": 1, "judged": 1, "kept": 0, "late": 1 }));
        assert_eq!(v["late"][0]["id"], "T-1");
        assert_eq!(v["late"][0]["gaps"], 1);
        assert_eq!(v["late"][0]["longestGapMinutes"], 125);
        assert_eq!(v["late"][0]["open"], false);
        // T-2, Sev 2 (4 business h): 10:30 to 17:00 is 6.5 h; "#t-2" matches "T-2". Then
        // 17:00 to resolved 12:00 the next day is 3 business h. T-6: resolved within the hour.
        assert_eq!(v["severities"][1], json!({ "severity": 2, "judged": 2, "kept": 1, "late": 1 }));
        assert_eq!(v["late"][1]["id"], "T-2");
        assert_eq!(v["late"][1]["longestGapMinutes"], 390);
        // T-3, Sev 3 (3 business days): Mon 09:30, Wed 10:00, then open until Thu 1 Oct 09:00:
        // 3 weeks of silence, so the next update is overdue now.
        assert_eq!(v["severities"][2]["late"], 1);
        let t3 = &v["late"][2];
        assert_eq!((t3["id"].as_str(), t3["open"].as_bool(), t3["overdueNow"].as_bool()), (Some("T-3"), Some(true), Some(true)));
        // T-4 is Severity 4, with no update target; T-5 has no first answer yet.
        assert_eq!(v["judged"], 4);
        assert_eq!(v["notAnswered"], 1);
        assert_eq!(v["withoutRows"], 1, "T-6 has no rows");
        assert_eq!(v["unmatchedRows"], 1, "T-99 isn't in the report");
        let skipped: Vec<(u64, &str)> = v["skipped"].as_array().unwrap().iter().map(|s| (s["line"].as_u64().unwrap(), s["reason"].as_str().unwrap())).collect();
        assert_eq!(skipped, vec![(9, "a visibility it doesn't know"), (10, "a time that can't be read")]);
        assert_eq!(v["keptPercent"], 25);
        let all = format!("{v}{}{}", u.text(), u.markdown());
        for never in ["Ana", "Bo,", "Looking", "internal note", "any news", "another customer", "c1", "yes please"] {
            assert!(!all.contains(never), "the update targets leak {never}");
        }
        assert!(u.markdown().contains("| T-1 | 1 (enterprise) | 2026-09-01 10:00 UTC | 1 gap over target, the longest 2 h 5 min; target 1 h, 24×7 |"), "{}", u.markdown());
        assert!(u.text().contains("T-3  Sev 3 (pro)  opened 2026-09-04 16:00 UTC  1 gap over target, the longest"), "{}", u.text());
        assert!(u.text().contains("of business time, still open with the next update overdue; target 3 business days"), "{}", u.text());
    }

    #[test]
    fn an_agreed_target_and_named_columns() {
        let o = september("2026-10-01T09:00:00Z");
        let r = report(TICKETS, &o).unwrap();
        let csv = "Issue,When,Visible\nT-2,2026-09-02T12:00:00Z,yes\nT-2,2026-09-02T14:00:00Z,yes\nT-2,2026-09-02T16:00:00Z,yes\nT-2,2026-09-02T17:00:00Z,yes\n";
        let mut u = with_file();
        u.columns = vec![(Field::Ticket, "Issue".into()), (Field::Time, "When".into()), (Field::Public, "Visible".into())];
        let v = judge(r.tickets(), csv, &o, &u).unwrap().json();
        // 10:30, 12:00, 14:00, 16:00, 17:00, then 3.5 business h to 12:00 the next day.
        assert_eq!(v["severities"][1]["kept"], 2);
        // A 24×7 agreement of 2 h: 17:00 to the next day's 12:00 is 19 h on the clock.
        u.targets.insert(2, Target::Clock(120));
        let w = judge(r.tickets(), csv, &o, &u).unwrap();
        let v = w.json();
        let t2 = v["late"].as_array().unwrap().iter().find(|l| l["id"] == "T-2").unwrap();
        assert_eq!(t2["longestGapMinutes"], 19 * 60);
        assert_eq!(t2["gaps"], 1, "12:00 to 14:00 is 2 h, not over");
        assert_eq!(v["targets"][1], json!({ "severity": 2, "target": "2 h, 24×7", "agreed": true }));
        assert!(w.markdown().contains("| 2 | 2 h, 24×7 (agreed) | 2 | 1 | 1 |"), "{}", w.markdown());
        assert!(!w.markdown().contains("| 4 |"), "Severity 4 has no target unless agreed");
        u.targets.insert(4, Target::BusinessDays(5));
        let v = judge(r.tickets(), csv, &o, &u).unwrap().json();
        assert_eq!(v["severities"][3], json!({ "severity": 4, "judged": 1, "kept": 0, "late": 1 }), "T-4, silent since 7 September");
        assert_eq!(v["severities"][2]["judged"], 1, "and not counted as Severity 3");
    }

    #[test]
    fn a_private_column_and_authors_who_arent_support() {
        let o = september("2026-10-01T09:00:00Z");
        let csv = "id,severity,opened,first response,resolved\nA,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z,2026-09-01T12:00:00Z\n";
        let r = report(csv, &Options { plan: Some(Plan::Max), ..o.clone() }).unwrap();
        let updates = "Ticket,Created,Private,Direction\nA,2026-09-01T11:00:00Z,false,outgoing\nA,2026-09-01T11:30:00Z,true,outgoing\nA,2026-09-01T11:40:00Z,false,incoming\n";
        let v = judge(r.tickets(), updates, &o, &with_file()).unwrap().json();
        // 10:10, 11:00, then nothing public from support until resolved at 12:00: 60 min, kept.
        assert_eq!(v["kept"], 1);
        let v = judge(r.tickets(), "Ticket,Created,Direction\nA,2026-09-01T11:00:00Z,sideways\n", &o, &with_file()).unwrap().json();
        assert_eq!(v["skipped"][0]["reason"], "an author it doesn't know");
        assert_eq!(v["late"][0]["longestGapMinutes"], 110, "with its only update skipped");
    }

    #[test]
    fn a_reply_at_the_cutoff_isnt_overdue_and_other_tickets_rows_arent_read() {
        let o = september("2026-09-01T14:00:00Z");
        let csv = "id,severity,opened,first response\nA,1,2026-09-01T10:00:00Z,2026-09-01T10:10:00Z\n";
        let r = report(csv, &Options { plan: Some(Plan::Pro), ..o.clone() }).unwrap();
        let updates = "ticket,time,public\nA,2026-09-01T14:00:00Z,true\nB,never,maybe\nA,soon,true\n";
        let v = judge(r.tickets(), updates, &o, &with_file()).unwrap().json();
        assert_eq!(v["late"][0]["longestGapMinutes"], 230, "10:10 to 14:00 is still late");
        assert_eq!(v["late"][0]["overdueNow"], false, "but answered at --as-of, so nothing's overdue now");
        assert_eq!(v["unmatchedRows"], 1, "B's unreadable row isn't the report's business");
        assert_eq!(v["skipped"], json!([{ "line": 4, "reason": "a time that can't be read" }]));
        assert_eq!(v["withoutRows"], 0);
        let v = judge(r.tickets(), "ticket,time\nA,soon\n", &o, &with_file()).unwrap().json();
        assert_eq!((v["withoutRows"].as_u64(), v["skipped"].as_array().unwrap().len()), (Some(0), 1), "rows it can't read aren't no rows");
    }

    #[test]
    fn a_ticket_resolved_with_its_first_answer_has_no_gaps() {
        let o = september("2026-10-01T09:00:00Z");
        let csv = "id,severity,opened,first response,resolved\nA,1,2026-09-01T10:00:00Z,2026-09-01T12:00:00Z,2026-09-01T11:00:00Z\n";
        let r = report(csv, &Options { plan: Some(Plan::Pro), ..o.clone() }).unwrap();
        let v = judge(r.tickets(), "ticket,time\nA,2026-09-01T12:00:00Z\n", &o, &with_file()).unwrap().json();
        assert_eq!((v["judged"].as_u64(), v["kept"].as_u64()), (Some(1), Some(1)));
    }

    #[test]
    fn columns_it_needs_and_an_empty_period() {
        let o = september("2026-10-01T09:00:00Z");
        let r = report(TICKETS, &o).unwrap();
        let e = judge(r.tickets(), "id,created at\n1,2026-09-01T10:00:00Z\n", &o, &with_file()).unwrap_err();
        assert!(e.contains("no ticket column") && e.contains("--update-column ticket="), "{e}");
        let e = judge(r.tickets(), "ticket\nT-1\n", &o, &UpdateOptions { columns: vec![(Field::Time, "When".into())], ..with_file() }).unwrap_err();
        assert!(e.contains("no column \"when\""), "{e}");
        assert!(judge(r.tickets(), "", &o, &with_file()).is_err());
        let empty = judge(&[], "ticket,time\n", &o, &with_file()).unwrap();
        assert_eq!(empty.json()["keptPercent"], Value::Null);
        assert!(empty.text().contains("No answered Severity 1 to 3 tickets to judge"));
    }

    #[test]
    fn arguments_are_split_from_the_reports() {
        let (left, u) = split_args(&["t.csv", "--plan", "pro", "--updates", "-", "--update-target", "2=4h", "--update-column", "ticket=Issue key", "--json"]).unwrap();
        assert_eq!(left, vec!["t.csv", "--plan", "pro", "--json"]);
        assert_eq!(u.file.as_deref(), Some("-"));
        assert_eq!(u.targets.get(&2), Some(&Target::Clock(240)));
        assert_eq!(u.columns, vec![(Field::Ticket, "Issue key".to_string())]);
        let (left, u) = split_args(&["t.csv"]).unwrap();
        assert_eq!((left, u.file), (vec!["t.csv"], None));
        for bad in [
            &["t.csv", "--updates"][..],
            &["t.csv", "--updates", "--json"],
            &["t.csv", "--updates", "a", "--updates", "b"],
            &["t.csv", "--update-target", "1=1h"],
            &["t.csv", "--updates", "u.csv", "--update-target", "5=1h"],
            &["t.csv", "--updates", "u.csv", "--update-target", "1=soon"],
            &["t.csv", "--updates", "u.csv", "--update-column", "body=Body"],
            &["t.csv", "--updates", "u.csv", "--update-column", "ticket="],
        ] {
            assert!(split_args(bad).is_err(), "{bad:?}");
        }
    }
}
