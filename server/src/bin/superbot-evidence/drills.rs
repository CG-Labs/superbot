//! Restore drill evidence (ADR 0177): for a period, every run of the restore drills CI
//! performs on the branch (the installer's backup and restore onto a fresh host, the
//! Compose restore, an Incus container restored from its off-host backup, and a lost
//! host's container restored onto another), each drill step's result and how long it
//! took, and the drill artifacts each run kept; plus the records of drills the operator
//! ran on their own servers (`deploy/backup-drill.sh`, `deploy/machine-restore-drill.sh`),
//! each timed against its objective. A dated bundle in the shape of the change-management
//! bundle (ADR 0148).
//!
//! Never in it: the token, logs, artifacts' contents, or the operator's drill output
//! beyond its record line: only that line's known fields, and the saved output's SHA-256.

use crate::changes::{all, enc, json_file, ms, rfc3339, sha256, valid_branch};
use crate::github::{Api, Failure};
use crate::period::Period;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-drills-";
/// GitHub stops a date-filtered listing of workflow runs at 1,000.
const SEARCH_CAP: u64 = 1_000;
/// The largest drill output read for its record: the drills print a few hundred lines.
pub const MAX_RECORD_BYTES: u64 = 16 << 20;

/// One file of the bundle and the criteria and checklist rows it is evidence for. The
/// evidence plan's drill table must match. The manifest maps a file to them only when it
/// holds a drill, so a month without drills shows as a gap in the coverage report.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

pub const SECTIONS: [Section; 2] = [
    Section { file: "ci-drills.json", criteria: &["A1.2", "A1.3"], rows: &["A1.3-1"] },
    Section { file: "operator-drills.json", criteria: &["A1.3", "CC9.1"], rows: &["A1.3-1", "CC9.1-2"] },
];

/// A restore drill CI runs: the workflow, the job (by name prefix, so each matrix job
/// counts), the step that is the drill, and the artifacts that keep its timing. A job that
/// skipped `attempted` didn't attempt the drill: the Incus versions botd refuses pass the
/// drill's step by checking the refusal, and restore nothing.
pub struct Drill {
    pub id: &'static str,
    pub title: &'static str,
    pub workflow: &'static str,
    pub job: &'static str,
    pub step: &'static str,
    pub attempted: Option<&'static str>,
    pub artifacts: &'static [&'static str],
    pub objective: &'static str,
}

pub const DRILLS: [Drill; 4] = [
    Drill {
        id: "server-restore",
        title: "Server backup restored onto a fresh host (installer)",
        workflow: "server.yml",
        job: "backup-drill",
        step: "Backup and restore drill",
        attempted: None,
        artifacts: &[],
        objective: "deploy/backup-drill.sh fails the step unless the restore takes at most SUPERBOT_DRILL_RTO_SECONDS (300) and the next backup is due within the RPO (ADR 0030)",
    },
    Drill {
        id: "compose-restore",
        title: "Every Compose volume deleted and restored",
        workflow: "docker.yml",
        job: "compose-smoke",
        step: "Smoke test",
        attempted: None,
        artifacts: &[],
        objective: "deploy/docker/smoke-test.sh fails the step unless the restore takes at most SMOKE_RTO_SECONDS (ADR 0030)",
    },
    Drill {
        id: "machine-restore",
        title: "An Incus container restored from its off-host backup",
        workflow: "incus-e2e.yml",
        job: "Containers on Incus",
        step: "Containers enroll",
        attempted: Some("The restore drill's timing"),
        artifacts: &["restore-drill-"],
        objective: "the test fails the step unless botd records the restore within its tier's RTO (ADR 0074)",
    },
    Drill {
        id: "host-loss",
        title: "A lost Incus host's container restored onto another host",
        workflow: "incus-e2e.yml",
        job: "Containers on Incus",
        step: "A lost host's container",
        attempted: Some("The restore drill's timing"),
        artifacts: &["host-drill-"],
        objective: "the test fails the step unless the container is restored onto another host and enrolls anew within its tier's RTO (ADR 0076)",
    },
];

/// The drills an operator runs on their own servers, by the `drill` their scripts record.
pub const OPERATOR_DRILLS: [(&str, &str); 2] =
    [("server-restore", "deploy/backup-drill.sh: the server restored onto a fresh host"), ("machine-restore", "deploy/machine-restore-drill.sh: a drill user's machine restored from its backup")];

const README: &str = "SuperBot restore drill evidence bundle
======================================

Made by superbot-evidence, for a SOC 2 Type II evidence store
(docs/security/soc2-evidence-plan.md, ADR 0177). It covers the period in manifest.json:
from its first day (00:00 UTC) up to, not including, its last.

  ci-drills.json        every run in the period of the restore drills CI performs on the
                        branch, read from the GitHub API with a read-only token: each
                        drill step's result, when it started and how long it took, and
                        the artifacts the run kept (name, size, GitHub's digest, expiry);
                        counted by drill, with the exceptions
  operator-drills.json  the drills the operator ran on their own servers in the period,
                        from the record line deploy/backup-drill.sh and
                        deploy/machine-restore-drill.sh print, each timed against its
                        objective, with the SHA-256 of the saved output it came from
  manifest.json         what is in this bundle, the period, and each file's SHA-256
  SHA256SUMS            the same digests, for `sha256sum -c SHA256SUMS`

Never in it: the token, logs, artifacts' contents, or any of a drill's output but its
record line's known fields. Artifacts expire on GitHub: download the ones kept as
evidence from each run's url, and check them against the digest here. Keep each
operator drill's saved output beside this bundle; its SHA-256 is in operator-drills.json.
";

// Reading GitHub

pub struct Options {
    pub repo: String,
    pub branch: Option<String>,
    pub period: Period,
}

/// One workflow's runs in the period, or what GitHub said when they couldn't be read.
pub struct Workflow {
    pub file: &'static str,
    pub runs: Result<Vec<Value>, (u16, String)>,
    pub truncated: bool,
    pub in_progress: usize,
    pub not_attempted: usize,
}

pub struct Collected {
    pub repo: Value,
    pub branch: String,
    pub workflows: Vec<Workflow>,
    pub executions: Vec<Value>,
}

fn workflows() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = DRILLS.iter().map(|d| d.workflow).collect();
    out.dedup();
    out
}

/// A matrix job's variant, from its name's last parentheses (`Containers on Incus (zabbly)`),
/// or the job's whole name.
pub fn variant(job: &str) -> &str {
    job.strip_suffix(')').and_then(|j| j.rsplit_once(" (")).map_or(job, |(_, v)| v)
}

fn find_step<'a>(job: &'a Value, prefix: &str) -> Option<&'a Value> {
    job["steps"].as_array().into_iter().flatten().find(|s| s["name"].as_str().is_some_and(|n| n.starts_with(prefix)))
}

/// Whether the job attempted the drill at all (see `Drill::attempted`).
pub fn attempted(d: &Drill, job: &Value) -> bool {
    d.attempted.and_then(|p| find_step(job, p)).is_none_or(|s| s["conclusion"] != "skipped")
}

/// A drill's step in one job of one run: its result, timing and the job's own artifacts
/// (named for its matrix variant, as `restore-drill-zabbly`).
pub fn execution(d: &Drill, run: &Value, job: &Value, artifacts: &[Value], now_ms: i64) -> Value {
    let step = find_step(job, d.step);
    let job_name = job["name"].as_str().unwrap_or_default();
    let own = |n: &str| d.artifacts.iter().any(|p| if job_name.ends_with(')') { n.strip_prefix(p) == Some(variant(job_name)) } else { n.starts_with(p) });
    let (started, completed) = match step {
        Some(s) => (ms(&s["started_at"]), ms(&s["completed_at"])),
        None => (ms(&job["started_at"]), ms(&job["completed_at"])),
    };
    let conclusion = step.map_or(Value::Null, |s| s["conclusion"].clone());
    let outcome = match (step, conclusion.as_str()) {
        (None, _) => "step not found",
        (_, Some("success")) => "passed",
        (_, Some("failure" | "timed_out")) => "failed",
        (_, Some("cancelled")) => "cancelled",
        (_, Some("skipped")) => "not reached",
        _ => "unfinished",
    };
    let kept: Vec<Value> = artifacts
        .iter()
        .filter(|a| a["name"].as_str().is_some_and(own))
        .map(|a| {
            json!({
                "id": a["id"], "name": a["name"], "bytes": a["size_in_bytes"], "digest": a["digest"],
                "createdAt": a["created_at"], "expiresAt": a["expires_at"],
                "expired": a["expired"] == true || ms(&a["expires_at"]).is_some_and(|t| t <= now_ms),
            })
        })
        .collect();
    let run_id = run["id"].as_u64().unwrap_or_default();
    let job_id = job["id"].as_u64().unwrap_or_default();
    json!({
        "id": format!("{}#{run_id}/{job_id}", d.id),
        "drill": d.id,
        "outcome": outcome,
        "stepConclusion": conclusion,
        "jobConclusion": job["conclusion"],
        "job": job["name"],
        "variant": variant(job_name),
        "startedAt": started.map(rfc3339),
        "completedAt": completed.map(rfc3339),
        "seconds": started.zip(completed).map(|(s, c)| ((c - s).max(0) + 500) / 1000),
        "run": {
            "id": run_id, "workflow": run["path"], "event": run["event"], "headSha": run["head_sha"], "attempt": run["run_attempt"],
            "createdAt": run["created_at"], "url": run["html_url"],
        },
        "jobUrl": job["html_url"],
        "artifactsExpected": !d.artifacts.is_empty(),
        "artifacts": kept,
    })
}

/// The runs and whether the listing was truncated, or the status and message GitHub
/// refused the listing with.
type Runs = Result<(Vec<Value>, bool), (u16, String)>;

/// Runs of `file` on `branch` created in the period, oldest first.
fn runs(api: &mut dyn Api, repo: &str, file: &str, branch: &str, p: &Period) -> Result<Runs, Failure> {
    let last = p.to.pred_opt().unwrap_or(p.to);
    let created = format!("{}T00:00:00Z..{last}T23:59:59Z", p.from);
    let first = format!("/repos/{repo}/actions/workflows/{file}/runs?branch={}&created={}&exclude_pull_requests=true&per_page=100", enc(branch), enc(&created));
    let head = match api.get(&first) {
        Ok(r) => r,
        Err(f) if matches!(f.status, 401 | 403 | 404) => return Ok(Err((f.status, f.message.chars().take(200).collect()))),
        Err(f) => return Err(f),
    };
    let truncated = head.body["total_count"].as_u64().is_some_and(|n| n > SEARCH_CAP);
    let mut out = head.body["workflow_runs"].as_array().cloned().unwrap_or_default();
    if let Some(next) = head.next {
        out.extend(all(api, &next, Some("workflow_runs"))?);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| ms(&r["created_at"]).is_some_and(|t| t >= p.start_ms() && t < p.end_ms()) && seen.insert(r["id"].as_u64()));
    out.sort_by_key(|r| (ms(&r["created_at"]), r["id"].as_u64()));
    Ok(Ok((out, truncated)))
}

/// Everything for `ci-drills.json`, read from GitHub. `now_ms` decides which artifacts
/// have expired.
pub fn collect(api: &mut dyn Api, o: &Options, now_ms: i64) -> Result<Collected, Failure> {
    let repo = &o.repo;
    let info = api.get(&format!("/repos/{repo}"))?.body;
    let branch = o.branch.clone().or_else(|| info["default_branch"].as_str().map(String::from)).unwrap_or_else(|| "main".into());
    if !valid_branch(&branch) {
        return Err(Failure::new(0, format!("{branch} isn't a branch name this tool reads")));
    }
    let (mut wfs, mut executions) = (Vec::new(), Vec::new());
    for file in workflows() {
        let drills: Vec<&Drill> = DRILLS.iter().filter(|d| d.workflow == file).collect();
        let (list, truncated) = match runs(api, repo, file, &branch, &o.period)? {
            Ok(v) => v,
            Err(e) => {
                wfs.push(Workflow { file, runs: Err(e), truncated: false, in_progress: 0, not_attempted: 0 });
                continue;
            }
        };
        let (mut in_progress, mut not_attempted) = (0, 0);
        for run in &list {
            if run["status"] != "completed" {
                in_progress += 1;
                continue;
            }
            let id = run["id"].as_u64().unwrap_or_default();
            let jobs = all(api, &format!("/repos/{repo}/actions/runs/{id}/jobs?filter=latest&per_page=100"), Some("jobs"))?;
            let all_matching: Vec<(&Drill, &Value)> = drills.iter().flat_map(|d| jobs.iter().filter(|j| j["name"].as_str().is_some_and(|n| n.starts_with(d.job))).map(move |j| (*d, j))).collect();
            let matching: Vec<(&Drill, &Value)> = all_matching.iter().copied().filter(|(d, j)| attempted(d, j)).collect();
            not_attempted += all_matching.len() - matching.len();
            if matching.is_empty() {
                continue;
            }
            let artifacts = if matching.iter().any(|(d, _)| !d.artifacts.is_empty()) { all(api, &format!("/repos/{repo}/actions/runs/{id}/artifacts?per_page=100"), Some("artifacts"))? } else { Vec::new() };
            executions.extend(matching.iter().map(|(d, j)| execution(d, run, j, &artifacts, now_ms)));
        }
        wfs.push(Workflow { file, runs: Ok(list), truncated, in_progress, not_attempted });
    }
    executions.sort_by_key(|e| (ms(&e["run"]["createdAt"]), e["id"].as_str().map(String::from)));
    let repo_view = json!({ "fullName": info["full_name"], "private": info["private"], "defaultBranch": info["default_branch"], "url": info["html_url"] });
    Ok(Collected { repo: repo_view, branch, workflows: wfs, executions })
}

// Operator records

fn plain(v: &Value, max: usize) -> Option<String> {
    let s = v.as_str()?;
    (!s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-/".contains(&c))).then(|| s.to_string())
}

/// The record line a drill script prints: the last line of its output that is a JSON
/// object with `superbotDrill`. Only its known fields are kept, with the output's SHA-256,
/// and only a record that finished in the period is taken.
pub fn record(file: &str, output: &[u8], p: &Period) -> Result<Value, String> {
    let text = String::from_utf8_lossy(output);
    let line = text
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .find(|v| v.get("superbotDrill").is_some())
        .ok_or(format!("{file} has no drill record: save the whole output of deploy/backup-drill.sh or deploy/machine-restore-drill.sh"))?;
    if line["superbotDrill"] != 1 {
        return Err(format!("{file}: its drill record is version {}, which this tool doesn't know; use a newer superbot-evidence", line["superbotDrill"]));
    }
    let drill = line["drill"].as_str().filter(|d| OPERATOR_DRILLS.iter().any(|(id, _)| id == d)).ok_or(format!("{file}: its drill record names no drill this tool knows"))?;
    let finished = ms(&line["finishedAt"]).ok_or(format!("{file}: its drill record doesn't say when it finished"))?;
    if finished < p.start_ms() || finished >= p.end_ms() {
        return Err(format!("{file}: the drill finished at {}, outside the period {} to {}", rfc3339(finished), p.from, p.to));
    }
    let passed = line["passed"].as_bool().ok_or(format!("{file}: its drill record doesn't say whether it passed"))?;
    let num = |k: &str| line[k].as_u64();
    let (took, objective) = (num("durationMs"), num("rtoMs"));
    if passed && (took.is_none() || objective.is_none()) {
        return Err(format!("{file}: a passed drill's record needs durationMs and rtoMs"));
    }
    Ok(json!({
        "drill": drill,
        "finishedAt": rfc3339(finished),
        "passed": passed,
        "durationMs": took,
        "rtoMs": objective,
        "withinObjective": took.zip(objective).map(|(t, o)| t <= o),
        "nextBackupInSeconds": num("nextBackupInSeconds"),
        "rpoBudgetSeconds": num("rpoBudgetSeconds"),
        "tier": plain(&line["tier"], 64),
        "restoreId": plain(&line["restoreId"], 128),
        "backupId": plain(&line["backupId"], 128),
        "file": std::path::Path::new(file).file_name().map(|n| n.to_string_lossy().into_owned()),
        "fileBytes": output.len(),
        "fileSha256": sha256(output),
    }))
}

// The bundle

fn median(mut xs: Vec<u64>) -> Option<u64> {
    xs.sort_unstable();
    let n = xs.len();
    (n > 0).then(|| if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]).div_ceil(2) })
}

/// Counts by drill, and the runs an auditor would ask about. `collected` is false when CI
/// wasn't read (`--no-ci`).
pub fn tally(executions: &[Value], collected: bool) -> (Value, Value) {
    let mut by = serde_json::Map::new();
    let mut not_run = Vec::new();
    let mut no_pass = Vec::new();
    let mut failing_at_end = Vec::new();
    for d in &DRILLS {
        let of: Vec<&Value> = executions.iter().filter(|e| e["drill"] == d.id).collect();
        let count = |o: &str| of.iter().filter(|e| e["outcome"] == o).count();
        let passed: Vec<u64> = of.iter().filter(|e| e["outcome"] == "passed").filter_map(|e| e["seconds"].as_u64()).collect();
        let finished: Vec<&&Value> = of.iter().filter(|e| matches!(e["outcome"].as_str(), Some("passed" | "failed"))).collect();
        // Each matrix variant's latest result: one passing doesn't hide another still failing.
        let mut latest: BTreeMap<&str, &str> = BTreeMap::new();
        for e in &finished {
            latest.insert(e["variant"].as_str().unwrap_or_default(), e["outcome"].as_str().unwrap_or_default());
        }
        let failing: Vec<&str> = latest.iter().filter(|(_, o)| **o == "failed").map(|(v, _)| *v).collect();
        let last = if failing.is_empty() { finished.last().map(|e| e["outcome"].clone()) } else { Some(json!("failed")) };
        by.insert(
            d.id.into(),
            json!({
                "title": d.title, "workflow": format!(".github/workflows/{}", d.workflow), "job": d.job, "step": d.step, "objective": d.objective,
                "runs": of.len(), "passed": count("passed"), "failed": count("failed"), "notReached": count("not reached"), "cancelled": count("cancelled"),
                "lastPassedAt": of.iter().rev().find(|e| e["outcome"] == "passed").map(|e| e["completedAt"].clone()),
                "lastOutcome": last, "failingVariants": failing,
                "medianSeconds": median(passed.clone()), "longestSeconds": passed.iter().max(),
            }),
        );
        if collected && of.is_empty() {
            not_run.push(json!(d.id));
        } else if collected && count("passed") == 0 {
            no_pass.push(json!(d.id));
        }
        if !failing.is_empty() {
            failing_at_end.push(json!(d.id));
        }
    }
    let ids = |keep: &dyn Fn(&Value) -> bool| -> Vec<Value> { executions.iter().filter(|e| keep(e)).map(|e| e["id"].clone()).collect() };
    let expired: Vec<Value> = executions.iter().flat_map(|e| e["artifacts"].as_array().into_iter().flatten().filter(|a| a["expired"] == true).map(move |a| json!(format!("{} {}", e["id"].as_str().unwrap_or_default(), a["name"].as_str().unwrap_or_default())))).collect();
    let exceptions = json!({
        "notRunInPeriod": not_run,
        "noPassInPeriod": no_pass,
        "failingAtEnd": failing_at_end,
        "failed": ids(&|e| e["outcome"] == "failed"),
        "stepNotFound": ids(&|e| e["outcome"] == "step not found"),
        "artifactMissing": ids(&|e| e["outcome"] == "passed" && e["artifactsExpected"] == true && e["artifacts"].as_array().is_none_or(Vec::is_empty)),
        "artifactExpired": expired,
    });
    (Value::Object(by), exceptions)
}

fn ci_file(c: Option<&Collected>) -> Value {
    let Some(c) = c else {
        let (by, exceptions) = tally(&[], false);
        return json!({ "collected": false, "why": "made with --no-ci: CI's drills weren't read", "summary": { "runs": 0, "byDrill": by }, "exceptions": exceptions, "executions": [] });
    };
    let (by, exceptions) = tally(&c.executions, true);
    let sources: Vec<Value> = c
        .workflows
        .iter()
        .map(|w| match &w.runs {
            Ok(r) => json!({ "workflow": format!(".github/workflows/{}", w.file), "available": true, "runs": r.len(), "inProgress": w.in_progress, "jobsNotAttempting": w.not_attempted, "truncated": w.truncated }),
            Err((status, message)) => json!({ "workflow": format!(".github/workflows/{}", w.file), "available": false, "status": status, "message": message, "why": "reading workflow runs needs actions read access" }),
        })
        .collect();
    json!({
        "collected": true,
        "repository": c.repo["fullName"],
        "branch": c.branch,
        "basis": "a drill's run counts when its workflow ran on the branch in the period and the job attempted the drill (jobs that skip the drill's timing step, such as Incus versions botd refuses, don't, and are counted per workflow); it passed when its drill step succeeded, which each drill allows only within its objective; seconds is the step's duration, which includes setting up, so it is at most the restore time the drill checks",
        "workflows": sources,
        "summary": { "runs": c.executions.len(), "byDrill": by },
        "exceptions": exceptions,
        "executions": c.executions,
    })
}

fn operator_file(records: &[Value]) -> Value {
    let mut by: BTreeMap<&str, Value> = BTreeMap::new();
    for (id, what) in OPERATOR_DRILLS {
        let of: Vec<&Value> = records.iter().filter(|r| r["drill"] == id).collect();
        by.insert(
            id,
            json!({
                "what": what, "records": of.len(), "passed": of.iter().filter(|r| r["passed"] == true).count(),
                "lastPassedAt": of.iter().rev().find(|r| r["passed"] == true).map(|r| r["finishedAt"].clone()),
                "longestMs": of.iter().filter(|r| r["passed"] == true).filter_map(|r| r["durationMs"].as_u64()).max(),
            }),
        );
    }
    let ids = |keep: &dyn Fn(&Value) -> bool| -> Vec<Value> { records.iter().filter(|r| keep(r)).map(|r| json!(format!("{} {}", r["drill"].as_str().unwrap_or_default(), r["finishedAt"].as_str().unwrap_or_default()))).collect() };
    json!({
        "basis": "each record is the line the drill script printed when it finished, from the saved output whose SHA-256 is given; it is within its objective when durationMs is at most rtoMs (botd's recorded restore time and the tier's RTO, or the server drill's timed restore and its budget)",
        "summary": { "records": records.len(), "byDrill": by },
        "exceptions": { "failed": ids(&|r| r["passed"] == false), "overObjective": ids(&|r| r["withinObjective"] == false) },
        "records": records,
    })
}

/// A bundle's name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

pub fn build(c: Option<&Collected>, records: &[Value], p: &Period, src: &crate::changes::Source, now_ms: i64) -> crate::changes::Bundle {
    let name = name(p, now_ms);
    let created = rfc3339(now_ms);
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let mut ci = ci_file(c);
    ci["periodCovered"] = period.clone();
    let mut operator = operator_file(records);
    operator["periodCovered"] = period.clone();
    let held = [("ci-drills.json", c.map_or(0, |c| c.executions.len())), ("operator-drills.json", records.len())];
    let mut files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec()), ("ci-drills.json", json_file(&ci)), ("operator-drills.json", json_file(&operator))];
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let s = SECTIONS.iter().find(|s| s.file == *n).filter(|_| held.iter().any(|(f, k)| f == n && *k > 0));
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": s.map(|s| s.criteria).unwrap_or_default(), "checklist": s.map(|s| s.rows).unwrap_or_default() })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "recovery-drills",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": created,
        "period": period,
        "source": {
            "ci": c.is_some(),
            "api": (c.is_some()).then(|| src.api_host.clone()),
            "repository": c.map(|c| c.repo["fullName"].clone()),
            "private": c.map(|c| c.repo["private"].clone()),
            "branch": c.map(|c| c.branch.clone()),
            "requests": src.requests,
            "tokenScopes": src.scopes,
            "tokenCanWrite": src.scopes.as_deref().map(crate::changes::can_write),
        },
        "ciDrillRuns": c.map_or(0, |c| c.executions.len()),
        "operatorRecords": records.len(),
        "files": listed,
        "notIncluded": "the token, logs, artifacts' contents, and drill output beyond its record line's known fields",
    });
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    crate::changes::Bundle { sha256: sha256(&tar), manifest_sha256, name, tar }
}

/// The lines printed after saving.
pub fn summary(c: Option<&Collected>, records: &[Value]) -> String {
    let mut out = String::new();
    match c {
        None => out += "CI's drills weren't read (--no-ci).",
        Some(c) => {
            let (by, ex) = tally(&c.executions, true);
            out += &format!("{} drill runs in CI on {}:", c.executions.len(), c.branch);
            for d in &DRILLS {
                let b = &by[d.id];
                out += &format!("\n  {}: {} runs, {} passed, {} failed", d.id, b["runs"], b["passed"], b["failed"]);
            }
            for (k, label) in [
                ("notRunInPeriod", "Not run in the period"),
                ("noPassInPeriod", "Run but never passed"),
                ("failingAtEnd", "Failing at the period's end"),
                ("stepNotFound", "Drill step not found (renamed?)"),
                ("artifactMissing", "Passed without its drill artifact"),
                ("artifactExpired", "Artifacts already expired on GitHub"),
            ] {
                if let Some(v) = ex[k].as_array().filter(|v| !v.is_empty()) {
                    out += &format!("\n  {label}: {}", v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
                }
            }
            for w in &c.workflows {
                if let Err((status, _)) = &w.runs {
                    out += &format!("\n  {}'s runs weren't readable (GitHub answered {status}): the bundle says so.", w.file);
                }
            }
        }
    }
    out += &format!("\n{} operator drill records", records.len());
    let f = operator_file(records);
    for (k, label) in [("failed", "failed"), ("overObjective", "over their objective")] {
        if let Some(v) = f["exceptions"][k].as_array().filter(|v| !v.is_empty()) {
            out += &format!("; {label}: {}", v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
        }
    }
    out += ".";
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Reply;
    use std::collections::HashMap;

    fn period() -> Period {
        let d = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        Period { from: d("2026-10-01"), to: d("2026-11-01") }
    }

    fn run(id: u64, created: &str) -> Value {
        json!({ "id": id, "status": "completed", "path": ".github/workflows/incus-e2e.yml", "event": "schedule", "head_sha": "abc", "run_attempt": 1, "created_at": created, "html_url": format!("https://github.com/o/r/actions/runs/{id}") })
    }

    fn step(name: &str, conclusion: &str, from: &str, to: &str) -> Value {
        json!({ "name": name, "conclusion": conclusion, "started_at": from, "completed_at": to })
    }

    fn job(id: u64, name: &str, steps: Vec<Value>) -> Value {
        json!({ "id": id, "name": name, "conclusion": "success", "started_at": "2026-10-06T05:41:00Z", "completed_at": "2026-10-06T06:10:00Z", "html_url": format!("https://github.com/o/r/actions/runs/1/job/{id}"), "steps": steps })
    }

    fn incus_job(id: u64, restore: &str, host: &str) -> Value {
        job(
            id,
            "Containers on Incus (stable)",
            vec![
                step("Make the runner an Incus host", "success", "2026-10-06T05:42:00Z", "2026-10-06T05:44:00Z"),
                step("Containers enroll, stay apart, follow the lifecycle, and are backed up and restored", restore, "2026-10-06T05:44:00Z", "2026-10-06T05:52:30Z"),
                step("A lost host's container is restored onto another host and enrolls anew", host, "2026-10-06T05:52:30Z", "2026-10-06T05:55:00Z"),
            ],
        )
    }

    fn artifact(name: &str, expires: &str) -> Value {
        json!({ "id": 7, "name": name, "size_in_bytes": 210, "digest": "sha256:feed", "created_at": "2026-10-06T06:00:00Z", "expires_at": expires, "expired": false })
    }

    #[test]
    fn a_drill_step_is_timed_and_judged_with_its_artifacts() {
        let now = period().end_ms();
        let arts = [artifact("restore-drill-stable", "2027-01-04T00:00:00Z"), artifact("host-drill-stable", "2026-10-20T00:00:00Z"), artifact("image-scan-amd64", "2027-01-01T00:00:00Z")];
        let j = incus_job(11, "success", "failure");
        let m = execution(&DRILLS[2], &run(1, "2026-10-06T05:41:00Z"), &j, &arts, now);
        assert_eq!((m["outcome"].as_str(), m["seconds"].as_u64(), m["startedAt"].as_str()), (Some("passed"), Some(510), Some("2026-10-06T05:44:00Z")));
        assert_eq!(m["artifacts"].as_array().unwrap().iter().map(|a| a["name"].as_str().unwrap()).collect::<Vec<_>>(), ["restore-drill-stable"], "only the drill's own artifacts");
        assert_eq!((m["artifacts"][0]["digest"].as_str(), m["artifacts"][0]["expired"].as_bool()), (Some("sha256:feed"), Some(false)));
        let h = execution(&DRILLS[3], &run(1, "2026-10-06T05:41:00Z"), &j, &arts, now);
        assert_eq!((h["outcome"].as_str(), h["id"].as_str(), h["artifacts"][0]["expired"].as_bool()), (Some("failed"), Some("host-loss#1/11"), Some(true)), "expired by the time of the export");
        let mut too_old = incus_job(14, "success", "skipped");
        too_old["steps"].as_array_mut().unwrap().push(step("The restore drill's timing (ADR 0074)", "skipped", "2026-10-06T05:55:00Z", "2026-10-06T05:55:00Z"));
        assert!(!attempted(&DRILLS[2], &too_old) && !attempted(&DRILLS[3], &too_old), "a version botd refuses restores nothing");
        assert!(attempted(&DRILLS[2], &j) && attempted(&DRILLS[0], &too_old));
        let other = execution(&DRILLS[2], &run(1, "2026-10-06T05:41:00Z"), &job(15, "Containers on Incus (lts)", j["steps"].as_array().unwrap().clone()), &arts, now);
        assert_eq!((other["artifacts"].as_array().map(Vec::len), other["variant"].as_str()), (Some(0), Some("lts")), "another variant's artifact isn't this job's");
        let skipped = execution(&DRILLS[3], &run(1, "2026-10-06T05:41:00Z"), &incus_job(12, "failure", "skipped"), &[], now);
        assert_eq!(skipped["outcome"], "not reached");
        let renamed = execution(&DRILLS[0], &run(2, "2026-10-07T00:00:00Z"), &job(13, "backup-drill", vec![step("Something else", "success", "2026-10-07T00:00:00Z", "2026-10-07T00:01:00Z")]), &[], now);
        assert_eq!((renamed["outcome"].as_str(), renamed["seconds"].as_u64()), (Some("step not found"), Some(1740)), "the job's time, and said so");
    }

    #[test]
    fn tallies_and_exceptions() {
        let now = period().end_ms();
        let e = |d: usize, id: u64, j: &Value, arts: &[Value]| execution(&DRILLS[d], &run(id, "2026-10-06T05:41:00Z"), j, arts, now);
        let pass = incus_job(1, "success", "success");
        let fail = incus_job(2, "success", "failure");
        let execs = vec![
            e(2, 1, &pass, &[artifact("restore-drill-stable", "2027-01-01T00:00:00Z")]),
            e(3, 1, &pass, &[artifact("host-drill-stable", "2027-01-01T00:00:00Z")]),
            e(2, 2, &fail, &[]),
            e(3, 2, &fail, &[]),
        ];
        let (by, ex) = tally(&execs, true);
        assert_eq!((by["machine-restore"]["runs"].as_u64(), by["machine-restore"]["passed"].as_u64(), by["machine-restore"]["medianSeconds"].as_u64()), (Some(2), Some(2), Some(510)));
        assert_eq!((by["host-loss"]["failed"].as_u64(), by["host-loss"]["lastOutcome"].as_str()), (Some(1), Some("failed")));
        assert_eq!(ex["notRunInPeriod"], json!(["server-restore", "compose-restore"]));
        assert_eq!(ex["noPassInPeriod"], json!([]));
        assert_eq!(ex["failingAtEnd"], json!(["host-loss"]));
        assert_eq!(ex["failed"], json!(["host-loss#2/2"]));
        assert_eq!(ex["artifactMissing"], json!(["machine-restore#2/2"]), "a pass without its timing record");
        let (_, none) = tally(&[], false);
        assert_eq!(none["notRunInPeriod"], json!([]), "not judged when CI wasn't read");
        let only_fail = vec![e(3, 2, &fail, &[])];
        assert_eq!(tally(&only_fail, true).1["noPassInPeriod"], json!(["host-loss"]));
        let mut lts = incus_job(3, "failure", "skipped");
        lts["name"] = json!("Containers on Incus (lts)");
        let siblings = vec![e(2, 3, &lts, &[]), e(2, 3, &pass, &[])];
        let (by, ex) = tally(&siblings, true);
        assert_eq!((by["machine-restore"]["lastOutcome"].as_str(), by["machine-restore"]["failingVariants"].clone()), (Some("failed"), json!(["lts"])), "a passing sibling doesn't hide a failing variant");
        assert_eq!(ex["failingAtEnd"], json!(["machine-restore"]));
    }

    fn out(lines: &[&str]) -> Vec<u8> {
        lines.join("\n").into_bytes()
    }

    #[test]
    fn operator_records_are_read_from_the_drills_output() {
        let machine = out(&[
            "==> drill: objectives",
            r#"{"tier":"pro","rpoHours":26}"#,
            "==> drill: restore r1 took 412 s of an RTO of 60 minutes",
            r#"{"superbotDrill":1,"drill":"machine-restore","finishedAt":"2026-10-14T09:12:00Z","passed":true,"restoreId":"r1","backupId":"b9","tier":"pro","durationMs":412000,"rtoMs":3600000,"user":"drill@example.com"}"#,
            "==> drill: passed",
        ]);
        let r = record("/home/ops/drills/2026-10-machine.log", &machine, &period()).unwrap();
        assert_eq!((r["drill"].as_str(), r["passed"].as_bool(), r["withinObjective"].as_bool(), r["tier"].as_str()), (Some("machine-restore"), Some(true), Some(true), Some("pro")));
        assert_eq!((r["file"].as_str(), r["fileSha256"].as_str()), (Some("2026-10-machine.log"), Some(sha256(&machine).as_str())), "the file's name, never its folder, and its digest");
        assert!(!r.to_string().contains("example.com") && !r.to_string().contains("/home/ops"), "only known fields: {r}");

        let failed = out(&[r#"{"superbotDrill":1,"drill":"server-restore","finishedAt":"2026-10-03T00:00:00Z","passed":false}"#]);
        let f = record("f.log", &failed, &period()).unwrap();
        assert_eq!((f["passed"].as_bool(), f["withinObjective"].clone()), (Some(false), Value::Null));

        let slow = out(&[r#"{"superbotDrill":1,"drill":"server-restore","finishedAt":"2026-10-03T00:00:00Z","passed":true,"durationMs":400000,"rtoMs":300000}"#]);
        assert_eq!(record("s.log", &slow, &period()).unwrap()["withinObjective"], false);

        let odd_tier = out(&[r#"{"superbotDrill":1,"drill":"machine-restore","finishedAt":"2026-10-03T00:00:00Z","passed":true,"durationMs":1,"rtoMs":2,"tier":"a b; rm"}"#]);
        assert_eq!(record("t.log", &odd_tier, &period()).unwrap()["tier"], Value::Null, "a value that isn't plain is left out");

        for (bad, want) in [
            (out(&["==> drill: passed"]), "no drill record"),
            (out(&[r#"{"superbotDrill":2,"drill":"server-restore"}"#]), "version 2"),
            (out(&[r#"{"superbotDrill":1,"drill":"tabletop","finishedAt":"2026-10-03T00:00:00Z","passed":true}"#]), "no drill this tool knows"),
            (out(&[r#"{"superbotDrill":1,"drill":"server-restore","finishedAt":"2026-11-01T00:00:00Z","passed":true,"durationMs":1,"rtoMs":2}"#]), "outside the period"),
            (out(&[r#"{"superbotDrill":1,"drill":"server-restore","finishedAt":"2026-10-03T00:00:00Z","passed":true}"#]), "needs durationMs and rtoMs"),
            (out(&[r#"{"superbotDrill":1,"drill":"server-restore","passed":true}"#]), "when it finished"),
        ] {
            let e = record("x.log", &bad, &period()).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn a_month_without_drills_maps_no_controls() {
        let src = crate::changes::Source { api_host: "api.github.com".into(), requests: 3, scopes: None };
        let now = period().end_ms() + 60_000;
        let manifest = |b: &crate::changes::Bundle| -> Value {
            let entries = crate::coverage::untar(&b.tar).unwrap();
            serde_json::from_slice(&entries.iter().find(|(n, _)| n.ends_with("/manifest.json")).unwrap().1).unwrap()
        };
        let empty = Collected { repo: json!({ "fullName": "o/r" }), branch: "main".into(), workflows: vec![], executions: vec![] };
        let m = manifest(&build(Some(&empty), &[], &period(), &src, now));
        assert!(m["files"].as_array().unwrap().iter().all(|f| f["checklist"] == json!([]) && f["criteria"] == json!([])), "{m}");
        let rec = record("m.log", &out(&[r#"{"superbotDrill":1,"drill":"machine-restore","finishedAt":"2026-10-03T00:00:00Z","passed":true,"durationMs":1,"rtoMs":2}"#]), &period()).unwrap();
        let m = manifest(&build(None, &[rec], &period(), &src, now));
        let files = m["files"].as_array().unwrap();
        assert_eq!((files[1]["checklist"].clone(), files[2]["checklist"].clone()), (json!([]), json!(["A1.3-1", "CC9.1-2"])));
        assert_eq!((m["source"]["ci"].as_bool(), m["source"]["api"].clone(), m["kind"].as_str()), (Some(false), Value::Null, Some("recovery-drills")));
    }

    struct Fake(HashMap<String, Result<(Value, Option<String>), u16>>);

    impl Api for Fake {
        fn get(&mut self, path: &str) -> Result<Reply, Failure> {
            match self.0.get(path).cloned() {
                Some(Ok((body, next))) => Ok(Reply { body, next }),
                Some(Err(s)) => Err(Failure::new(s, format!("GitHub answered {s} for {path}"))),
                None => Err(Failure::new(500, format!("no fixture for {path}"))),
            }
        }
    }

    #[test]
    fn reads_each_workflow_once_and_records_one_it_cant_read() {
        let mut f = Fake(HashMap::new());
        f.0.insert("/repos/o/r".into(), Ok((json!({ "full_name": "o/r", "default_branch": "main" }), None)));
        let list = |file: &str| format!("/repos/o/r/actions/workflows/{file}/runs?branch=main&created={}&exclude_pull_requests=true&per_page=100", enc("2026-10-01T00:00:00Z..2026-10-31T23:59:59Z"));
        f.0.insert(list("server.yml"), Ok((json!({ "total_count": 2, "workflow_runs": [run(5, "2026-10-02T00:00:00Z"), run(6, "2026-09-30T23:00:00Z")] }), Some("p2".into()))));
        f.0.insert("p2".into(), Ok((json!({ "workflow_runs": [json!({ "id": 8, "status": "in_progress", "created_at": "2026-10-30T00:00:00Z" })] }), None)));
        f.0.insert("/repos/o/r/actions/runs/5/jobs?filter=latest&per_page=100".into(), Ok((json!({ "jobs": [job(50, "backup-drill", vec![step("Backup and restore drill (installer units)", "success", "2026-10-02T00:01:00Z", "2026-10-02T00:03:10Z")]), job(51, "rust", vec![])] }), None)));
        f.0.insert(list("docker.yml"), Err(403));
        f.0.insert(list("incus-e2e.yml"), Ok((json!({ "total_count": 1, "workflow_runs": [run(9, "2026-10-06T05:41:00Z")] }), None)));
        f.0.insert("/repos/o/r/actions/runs/9/jobs?filter=latest&per_page=100".into(), Ok((json!({ "jobs": [incus_job(90, "success", "success"), incus_job(91, "success", "success"), job(92, "Containers on Incus (ubuntu)", vec![step("Containers enroll", "success", "2026-10-06T05:44:00Z", "2026-10-06T05:45:00Z"), step("The restore drill's timing", "skipped", "2026-10-06T05:45:00Z", "2026-10-06T05:45:00Z")])] }), None)));
        f.0.insert("/repos/o/r/actions/runs/9/artifacts?per_page=100".into(), Ok((json!({ "artifacts": [artifact("restore-drill-stable", "2027-01-01T00:00:00Z")] }), None)));
        let o = Options { repo: "o/r".into(), branch: None, period: period() };
        let c = collect(&mut f, &o, period().end_ms()).unwrap();
        assert_eq!(c.executions.iter().map(|e| e["id"].as_str().unwrap()).collect::<Vec<_>>(), ["server-restore#5/50", "host-loss#9/90", "host-loss#9/91", "machine-restore#9/90", "machine-restore#9/91"], "each matrix job counts; run 6 is before the period");
        assert_eq!(c.executions[0]["seconds"], 130);
        assert_eq!((c.workflows[0].in_progress, c.workflows[1].runs.as_ref().err().map(|e| e.0), c.workflows[2].not_attempted), (1, Some(403), 2));
        let s = summary(Some(&c), &[]);
        assert!(s.contains("5 drill runs in CI on main") && s.contains("docker.yml's runs weren't readable (GitHub answered 403)") && s.contains("Not run in the period: compose-restore") && s.contains("Passed without its drill artifact: host-loss#9/90, host-loss#9/91"), "{s}");
        let ci = ci_file(Some(&c));
        assert_eq!((ci["workflows"][1]["available"].as_bool(), ci["summary"]["byDrill"]["server-restore"]["passed"].as_u64()), (Some(false), Some(1)));
        let mut broken = Fake(HashMap::new());
        broken.0.insert("/repos/o/r".into(), Ok((json!({ "default_branch": "main" }), None)));
        assert_eq!(collect(&mut broken, &o, 0).err().map(|f| f.status), Some(500), "a server error is a failure, not a gap");
    }

    /// Each drill's job and step names are in its workflow, so a rename is caught here
    /// rather than as `step not found` months later; and the artifacts it keeps.
    #[test]
    fn every_drill_is_in_its_workflow() {
        for d in &DRILLS {
            let wf = match d.workflow {
                "server.yml" => include_str!("../../../../.github/workflows/server.yml"),
                "docker.yml" => include_str!("../../../../.github/workflows/docker.yml"),
                "incus-e2e.yml" => include_str!("../../../../.github/workflows/incus-e2e.yml"),
                other => panic!("{other} isn't read by this test"),
            };
            let job_line = wf.lines().any(|l| l.trim() == format!("{}:", d.job) || l.trim().strip_prefix("name: ").is_some_and(|n| n.starts_with(d.job)));
            assert!(job_line, "{}: no job named {} in {}", d.id, d.job, d.workflow);
            assert!(wf.lines().any(|l| l.trim().strip_prefix("- name: ").is_some_and(|n| n.starts_with(d.step))), "{}: no step named {}… in {}", d.id, d.step, d.workflow);
            if let Some(a) = d.attempted {
                assert!(wf.lines().any(|l| l.trim().strip_prefix("- name: ").is_some_and(|n| n.starts_with(a))), "{}: no step named {a}… in {}", d.id, d.workflow);
            }
            for a in d.artifacts {
                assert!(wf.contains(&format!("name: {a}")), "{}: {} keeps no {a} artifact", d.id, d.workflow);
            }
        }
        for (script, drill) in [(include_str!("../../../../deploy/backup-drill.sh"), "server-restore"), (include_str!("../../../../deploy/machine-restore-drill.sh"), "machine-restore")] {
            assert!(script.contains("superbotDrill") && script.contains(drill), "{drill}'s script prints its record");
        }
    }

    #[test]
    fn names_never_collide_with_the_other_bundles() {
        let n = name(&period(), 1_795_000_000_000);
        assert!(n.starts_with("superbot-drills-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/operator-drills.json".len() <= 100, "fits a ustar name");
        assert!(![crate::changes::PREFIX, crate::vulns::PREFIX, "superbot-evidence-"].iter().any(|p| n.starts_with(p)));
    }

    /// Every file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, each under one of its criteria, and the evidence plan's drill table
    /// lists each file with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## The drill bundle").nth(1).and_then(|s| s.split("\n## ").next()).expect("the evidence plan has a drill bundle section");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = section.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's drill table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
        for d in &DRILLS {
            assert!(section.contains(&format!("`{}`", d.id)), "the evidence plan's drill section doesn't name {}", d.id);
        }
    }
}
