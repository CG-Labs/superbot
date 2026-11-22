//! Change-management evidence (ADR 0148): for a period, every pull request merged into the
//! branch with its reviews, approvers, checks and merge commit; commits that reached the
//! branch without one; the branch's protection as it stands; and every CI workflow run on
//! the branch. Written as a dated bundle in the shape of botd's evidence bundles
//! (ADR 0142): JSON files, a manifest with each file's SHA-256 and the controls it serves,
//! and `SHA256SUMS`.
//!
//! Never in it: the token, pull request and review bodies, comments, commit messages,
//! emails, logs or artifacts. People are named by their GitHub logins, which an auditor
//! needs to see that the approver isn't the author.

use crate::github::{Api, Failure};
use crate::period::Period;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-changes-";
/// GitHub stops a date-filtered listing of workflow runs at 1,000.
const SEARCH_CAP: u64 = 1_000;
/// Pages followed for any one listing, at 100 a page.
const MAX_PAGES: usize = 200;
/// Commits not merged by a pull request in the period that are looked up one by one.
const MAX_COMMIT_LOOKUPS: usize = 300;
/// A check that ended like this passes a required check (GitHub's own rule).
const PASSING: [&str; 3] = ["success", "neutral", "skipped"];
/// A check that ended like this failed.
const FAILING: [&str; 6] = ["failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"];

/// One file of the bundle and the Trust Services criteria and readiness checklist rows it
/// is evidence for. The evidence plan's change-management table must match.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

pub const SECTIONS: [Section; 3] = [
    Section { file: "pull-requests.json", criteria: &["CC3.4", "CC8.1"], rows: &["CC3.4-1", "CC8.1-1", "CC8.1-2"] },
    Section { file: "branch-protection.json", criteria: &["CC8.1"], rows: &["CC8.1-1"] },
    Section { file: "workflow-runs.json", criteria: &["CC4.1", "CC5.2", "CC7.1", "CC8.1"], rows: &["CC5.2-2", "CC7.1-1", "CC7.1-3"] },
];

const README: &str = "SuperBot change-management evidence bundle
==========================================

Made by superbot-evidence from the GitHub API with a read-only token, for a SOC 2 Type II
evidence store (docs/security/soc2-evidence-plan.md, ADR 0148). It covers the period in
manifest.json: from its first day (00:00 UTC) up to, not including, its last. Branch
protection is as of createdAt, which may be after the period.

  pull-requests.json      every pull request merged into the branch in the period: author,
                          reviews and approvers, checks on its last commit, which were
                          required and their result at the merge, merge commit and who
                          merged it, the CI runs on its merge
                          commit; every update of the branch (merges, pushes, force
                          pushes); and every commit that reached the branch without one
  branch-protection.json  the branch's protection now: rulesets and classic protection,
                          required checks and approvals, force pushes and deletions
  workflow-runs.json      every GitHub Actions run on the branch in the period, counted by
                          workflow and conclusion, by day, and listed
  manifest.json           what is in this bundle, the period, and each file's SHA-256
  SHA256SUMS              the same digests, for `sha256sum -c SHA256SUMS`

Never in it: the token, pull request and review bodies, comments, commit messages, emails,
logs or artifacts. People are named by their GitHub logins. Run logs and artifacts expire
on GitHub: download the ones kept as evidence from each run's url.
";

// Time

fn ms(v: &Value) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(v.as_str()?).ok().map(|t| t.timestamp_millis())
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

fn in_period(p: &Period, v: &Value) -> bool {
    ms(v).is_some_and(|t| t >= p.start_ms() && t < p.end_ms())
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn login(v: &Value) -> Value {
    v["login"].as_str().map_or(Value::Null, |s| json!(s))
}

// Reading GitHub

/// Every item of a listing, page by page: the body itself, or its `key` array.
fn all(api: &mut dyn Api, first: &str, key: Option<&str>) -> Result<Vec<Value>, Failure> {
    let (mut out, mut url) = (Vec::new(), first.to_string());
    for _ in 0..MAX_PAGES {
        let r = api.get(&url)?;
        let items = match key {
            Some(k) => r.body[k].as_array().cloned(),
            None => r.body.as_array().cloned(),
        };
        out.extend(items.unwrap_or_default());
        match r.next {
            Some(n) => url = n,
            None => return Ok(out),
        }
    }
    Err(Failure::new(0, format!("{first} has more than {MAX_PAGES} pages")))
}

/// A reply, or None when GitHub refuses or hides it (401, 403, 404): what a read-only token
/// can't see is recorded as unavailable, not a failure.
fn optional<T>(r: Result<T, Failure>) -> Result<Result<T, u16>, Failure> {
    match r {
        Ok(v) => Ok(Ok(v)),
        Err(f) if matches!(f.status, 401 | 403 | 404) => Ok(Err(f.status)),
        Err(f) => Err(f),
    }
}

/// Pull requests merged into `branch` in the period, oldest merge first. Read newest
/// update first, so the listing stops at the first one last updated before the period:
/// a merge in the period is an update in it.
fn merged(api: &mut dyn Api, repo: &str, branch: &str, p: &Period) -> Result<Vec<Value>, Failure> {
    let mut url = format!("/repos/{repo}/pulls?state=closed&base={}&sort=updated&direction=desc&per_page=100", enc(branch));
    let mut out = Vec::new();
    let mut pages = 0;
    'pages: loop {
        pages += 1;
        if pages > MAX_PAGES {
            return Err(Failure::new(0, format!("the merged pull requests run past {MAX_PAGES} pages; export a shorter period")));
        }
        let r = api.get(&url)?;
        for pr in r.body.as_array().into_iter().flatten() {
            if ms(&pr["updated_at"]).is_some_and(|t| t < p.start_ms()) {
                break 'pages;
            }
            if in_period(p, &pr["merged_at"]) {
                out.push(pr.clone());
            }
        }
        match r.next {
            Some(n) => url = n,
            None => break,
        }
    }
    out.sort_by_key(|pr| (ms(&pr["merged_at"]), pr["number"].as_u64()));
    Ok(out)
}

/// Every update of `branch` in the period (pull request merges, pushes, force pushes), from
/// GitHub's record of the branch, newest first: the commit list goes by commit date, so a
/// commit made before the period and pushed in it is only here. Err with GitHub's status
/// when the token can't read it.
fn branch_updates(api: &mut dyn Api, repo: &str, branch: &str, p: &Period) -> Result<Result<Vec<Value>, u16>, Failure> {
    let mut url = format!("/repos/{repo}/activity?ref={}&direction=desc&per_page=100", enc(&format!("refs/heads/{branch}")));
    let mut out = Vec::new();
    for _ in 0..MAX_PAGES {
        let r = match optional(api.get(&url))? {
            Ok(r) => r,
            Err(status) => return Ok(Err(status)),
        };
        for a in r.body.as_array().into_iter().flatten() {
            if ms(&a["timestamp"]).is_some_and(|t| t < p.start_ms()) {
                return Ok(Ok(out));
            }
            if in_period(p, &a["timestamp"]) {
                out.push(json!({ "id": a["id"], "at": a["timestamp"], "type": a["activity_type"], "actor": login(&a["actor"]), "before": a["before"], "after": a["after"] }));
            }
        }
        match r.next {
            Some(n) => url = n,
            None => return Ok(Ok(out)),
        }
    }
    Err(Failure::new(0, format!("{branch}'s updates run past {MAX_PAGES} pages; export a shorter period")))
}

/// A branch update that isn't a pull request merging.
fn pushed(u: &Value) -> bool {
    !matches!(u["type"].as_str(), Some("pr_merge" | "merge_queue_merge"))
}

/// Workflow runs on `branch` created from `from` up to `to`. A date-filtered listing stops
/// at 1,000 runs, so a range with more is split in two, down to single days; a day with more
/// still is listed as far as GitHub goes and marked truncated.
fn runs_between(api: &mut dyn Api, repo: &str, branch: &str, from: chrono::NaiveDate, to: chrono::NaiveDate, out: &mut Vec<Value>) -> Result<bool, Failure> {
    let last = to.pred_opt().unwrap_or(to);
    let created = format!("{from}T00:00:00Z..{last}T23:59:59Z");
    let first = format!("/repos/{repo}/actions/runs?branch={}&created={}&exclude_pull_requests=true&per_page=100", enc(branch), enc(&created));
    let r = api.get(&first)?;
    let total = r.body["total_count"].as_u64().unwrap_or_default();
    let days = (to - from).num_days();
    if total > SEARCH_CAP && days > 1 {
        let mid = from + chrono::Days::new((days / 2) as u64);
        let a = runs_between(api, repo, branch, from, mid, out)?;
        let b = runs_between(api, repo, branch, mid, to, out)?;
        return Ok(a || b);
    }
    out.extend(r.body["workflow_runs"].as_array().cloned().unwrap_or_default());
    if let Some(next) = r.next {
        out.extend(all(api, &next, Some("workflow_runs"))?);
    }
    Ok(total > SEARCH_CAP)
}

// What each file says

/// What the branch's protection requires of a merge, from its rulesets and classic
/// protection, as far as the token can see.
#[derive(Debug, Default, PartialEq)]
pub struct Required {
    /// Each required check's name, and the app it must come from when one is set.
    pub checks: BTreeMap<String, Option<u64>>,
    pub approvals: Option<u64>,
}

impl Required {
    fn require(&mut self, name: &str, app: Option<u64>) {
        let pinned = self.checks.entry(name.to_string()).or_default();
        if app.is_some() {
            *pinned = app;
        }
    }

    fn names(&self) -> Vec<&str> {
        self.checks.keys().map(String::as_str).collect()
    }

    fn apps(&self) -> BTreeMap<&str, u64> {
        self.checks.iter().filter_map(|(n, a)| Some((n.as_str(), (*a)?))).collect()
    }
}

fn enabled(v: &Value, key: &str) -> Option<bool> {
    v.get(key)?.get("enabled")?.as_bool()
}

/// `branch-protection.json`, and what it requires. `rules` and `classic` are Err with the
/// status GitHub refused them with.
pub fn protection(branch: &str, info: &Value, rules: &Result<Vec<Value>, u16>, classic: &Result<Value, u16>) -> (Value, Required) {
    let mut req = Required::default();
    let none = Vec::new();
    let rule_list = rules.as_ref().unwrap_or(&none);
    let has = |t: &str| rule_list.iter().any(|r| r["type"] == t);
    for r in rule_list {
        match r["type"].as_str() {
            Some("required_status_checks") => {
                for c in r["parameters"]["required_status_checks"].as_array().into_iter().flatten() {
                    if let Some(name) = c["context"].as_str() {
                        req.require(name, c["integration_id"].as_u64());
                    }
                }
            }
            Some("pull_request") => {
                let n = r["parameters"]["required_approving_review_count"].as_u64().unwrap_or_default();
                req.approvals = Some(req.approvals.unwrap_or_default().max(n));
            }
            _ => {}
        }
    }
    let c = classic.as_ref().ok();
    if let Some(c) = c {
        let rsc = &c["required_status_checks"];
        for name in rsc["contexts"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            req.require(name, None);
        }
        for x in rsc["checks"].as_array().into_iter().flatten() {
            if let Some(name) = x["context"].as_str() {
                req.require(name, x["app_id"].as_u64());
            }
        }
        if let Some(n) = c["required_pull_request_reviews"]["required_approving_review_count"].as_u64() {
            req.approvals = Some(req.approvals.unwrap_or_default().max(n));
        } else if c["required_pull_request_reviews"].is_object() {
            req.approvals = Some(req.approvals.unwrap_or_default());
        }
    }
    let shown = &info["protection"]["required_status_checks"];
    if shown["enforcement_level"].as_str().is_some_and(|l| l != "off") {
        for name in shown["contexts"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            req.require(name, None);
        }
        for x in shown["checks"].as_array().into_iter().flatten() {
            if let Some(name) = x["context"].as_str() {
                req.require(name, x["app_id"].as_u64());
            }
        }
    }
    let protected = info["protected"].as_bool().unwrap_or(false);
    let known = rules.is_ok() && (c.is_some() || !protected);
    // Blocked by a rule, by classic protection, or unknown when the token can't see either.
    let blocked = |rule: &str, classic_key: &str| -> Value {
        if has(rule) {
            json!(true)
        } else if let Some(allowed) = c.and_then(|c| enabled(c, classic_key)) {
            json!(!allowed)
        } else if known {
            json!(false)
        } else {
            Value::Null
        }
    };
    let pr_required = if has("pull_request") || c.is_some_and(|c| c["required_pull_request_reviews"].is_object()) {
        json!(true)
    } else if known {
        json!(false)
    } else {
        Value::Null
    };
    let classic_view = match classic {
        Ok(c) => json!({
            "available": true,
            "requiredStatusChecks": c["required_status_checks"].is_object().then(|| json!({
                "strict": c["required_status_checks"]["strict"],
                "contexts": c["required_status_checks"]["contexts"],
            })),
            "requiredPullRequestReviews": c["required_pull_request_reviews"].is_object().then(|| {
                let r = &c["required_pull_request_reviews"];
                json!({
                    "requiredApprovingReviewCount": r["required_approving_review_count"],
                    "dismissStaleReviews": r["dismiss_stale_reviews"],
                    "requireCodeOwnerReviews": r["require_code_owner_reviews"],
                    "requireLastPushApproval": r["require_last_push_approval"],
                })
            }),
            "enforceAdmins": enabled(c, "enforce_admins"),
            "requiredLinearHistory": enabled(c, "required_linear_history"),
            "allowForcePushes": enabled(c, "allow_force_pushes"),
            "allowDeletions": enabled(c, "allow_deletions"),
            "requiredSignatures": enabled(c, "required_signatures"),
            "requiredConversationResolution": enabled(c, "required_conversation_resolution"),
            "pushRestricted": c["restrictions"].is_object(),
        }),
        Err(status) => json!({ "available": false, "status": status, "why": "GitHub shows classic protection only to tokens with administration read access" }),
    };
    let rules_view = match rules {
        Ok(rs) => json!({
            "available": true,
            "rules": rs.iter().map(|r| json!({
                "type": r["type"], "parameters": r["parameters"], "rulesetId": r["ruleset_id"],
                "rulesetSourceType": r["ruleset_source_type"], "rulesetSource": r["ruleset_source"],
            })).collect::<Vec<_>>(),
        }),
        Err(status) => json!({ "available": false, "status": status }),
    };
    let view = json!({
        "branch": branch,
        "protected": protected,
        "summary": {
            "pullRequestRequired": pr_required,
            "requiredApprovals": req.approvals,
            "requiredChecks": req.names(),
            "requiredCheckApps": req.apps(),
            "forcePushesBlocked": blocked("non_fast_forward", "allow_force_pushes"),
            "deletionsBlocked": blocked("deletion", "allow_deletions"),
            "adminsIncluded": c.and_then(|c| enabled(c, "enforce_admins")),
        },
        "rulesets": rules_view,
        "classic": classic_view,
        "shownOnTheBranch": {
            "enabled": info["protection"]["enabled"],
            "requiredStatusChecks": { "enforcementLevel": shown["enforcement_level"], "contexts": shown["contexts"] },
        },
    });
    (view, req)
}

/// The latest of `items` by `at`, then id: re-runs and the same check from another event
/// (push and pull_request) leave several.
fn latest<'a>(items: impl Iterator<Item = &'a Value>, at: impl Fn(&Value) -> Option<i64>) -> Option<&'a Value> {
    items.filter(|v| at(v).is_some()).max_by_key(|v| (at(v), v["id"].as_u64()))
}

fn finished(r: &Value) -> Option<i64> {
    ms(&r["completed_at"])
}

fn created(s: &Value) -> Option<i64> {
    ms(&s["created_at"]).or_else(|| ms(&s["updated_at"]))
}

/// What a required check said at the merge, from the latest run completed by then (from
/// its app, when one is required) or else the latest status set by then, and what it says
/// now. A check still running at the merge didn't pass, whatever it did later.
fn required_check(name: &str, app: Option<u64>, runs: &[Value], statuses: &[Value], merged: i64) -> Value {
    let named = || runs.iter().filter(move |r| r["name"] == name);
    let from_app = || named().filter(move |r| app.is_none_or(|a| r["app"]["id"].as_u64() == Some(a)));
    let ctx = || statuses.iter().filter(move |s| app.is_none() && s["context"] == name);
    let by_merge = |t: Option<i64>| t.filter(|t| *t <= merged);
    // GitHub wants every result under a required name to pass: a check run and a status
    // with the same name both count.
    let judge = |run: Option<&Value>, st: Option<&Value>| {
        let run_ok = run.is_none_or(|r| r["conclusion"].as_str().is_some_and(|c| PASSING.contains(&c)));
        let st_ok = st.is_none_or(|s| s["state"] == "success");
        (run.map_or(Value::Null, |r| r["conclusion"].clone()), st.map_or(Value::Null, |s| s["state"].clone()), (run.is_some() || st.is_some()) && run_ok && st_ok)
    };
    let (run, status, passed) = judge(latest(from_app(), |r| by_merge(finished(r))), latest(ctx(), |s| by_merge(created(s))));
    let (run_now, status_now, passed_now) = judge(latest(from_app(), finished), latest(ctx(), created));
    json!({
        "name": name,
        "app": app,
        "found": from_app().next().is_some() || ctx().next().is_some(),
        "checkRun": run,
        "status": status,
        "passed": passed,
        "checkRunNow": run_now,
        "statusNow": status_now,
        "passedNow": passed_now,
        "fromOtherApps": named().count() - from_app().count(),
    })
}

/// Checks whose latest result by the merge failed: each run by name and app, each status
/// by context.
fn failing_at_merge(runs: &[Value], statuses: &[Value], merged: i64) -> Vec<String> {
    let mut last: BTreeMap<(&str, Option<u64>), &Value> = BTreeMap::new();
    for r in runs.iter().filter(|r| finished(r).is_some_and(|t| t <= merged)) {
        let Some(name) = r["name"].as_str() else { continue };
        let k = (name, r["app"]["id"].as_u64());
        if last.get(&k).is_none_or(|old| (finished(r), r["id"].as_u64()) >= (finished(old), old["id"].as_u64())) {
            last.insert(k, r);
        }
    }
    let mut out: BTreeSet<String> = last.iter().filter(|(_, r)| r["conclusion"].as_str().is_some_and(|c| FAILING.contains(&c))).map(|((n, _), _)| n.to_string()).collect();
    let mut by_ctx: BTreeMap<&str, &Value> = BTreeMap::new();
    for st in statuses.iter().filter(|st| created(st).is_some_and(|t| t <= merged)) {
        let Some(c) = st["context"].as_str() else { continue };
        if by_ctx.get(c).is_none_or(|old| (created(st), st["id"].as_u64()) >= (created(old), old["id"].as_u64())) {
            by_ctx.insert(c, st);
        }
    }
    out.extend(by_ctx.iter().filter(|(_, st)| matches!(st["state"].as_str(), Some("failure" | "error"))).map(|(c, _)| c.to_string()));
    out.into_iter().collect()
}

/// One merged pull request: who wrote, reviewed, approved and merged it, and the checks
/// on its last commit. Reviews after the merge are listed but approve nothing; reviews by
/// bots are listed but are never an approval (the change management policy).
pub fn pull_view(pr: &Value, reviews: &[Value], check_runs: &[Value], statuses: &[Value], required: &Required, titles: bool) -> Value {
    let author = pr["user"]["login"].as_str().unwrap_or_default();
    let head = pr["head"]["sha"].as_str().unwrap_or_default();
    let merged = ms(&pr["merged_at"]).unwrap_or(i64::MAX);
    let mut listed = Vec::new();
    let mut decisive: BTreeMap<&str, &Value> = BTreeMap::new();
    let mut automated = BTreeSet::new();
    for r in reviews.iter().filter(|r| r["state"] != "PENDING") {
        let who = r["user"]["login"].as_str().unwrap_or_default();
        let bot = r["user"]["type"] == "Bot";
        let before = ms(&r["submitted_at"]).is_some_and(|t| t <= merged);
        listed.push(json!({
            "reviewer": who, "reviewerType": r["user"]["type"], "association": r["author_association"], "state": r["state"],
            "submittedAt": r["submitted_at"], "commitId": r["commit_id"], "onFinalCommit": r["commit_id"] == head, "beforeMerge": before,
        }));
        if bot {
            automated.insert(who);
        } else if before && who != author && matches!(r["state"].as_str(), Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")) {
            decisive.insert(who, r);
        }
    }
    let approvers: Vec<&str> = decisive.iter().filter(|(_, r)| r["state"] == "APPROVED").map(|(w, _)| *w).collect();
    let on_final = decisive.values().any(|r| r["state"] == "APPROVED" && r["commit_id"] == head);
    let changes_requested: Vec<&str> = decisive.iter().filter(|(_, r)| r["state"] == "CHANGES_REQUESTED").map(|(w, _)| *w).collect();

    let failing = failing_at_merge(check_runs, statuses, merged);
    let req: Vec<Value> = required.checks.iter().map(|(name, app)| required_check(name, *app, check_runs, statuses, merged)).collect();
    let all_passed = (!req.is_empty()).then(|| req.iter().all(|r| r["passed"] == true));
    let all_passed_now = (!req.is_empty()).then(|| req.iter().all(|r| r["passedNow"] == true));
    json!({
        "number": pr["number"],
        "title": if titles { pr["title"].clone() } else { Value::Null },
        "url": pr["html_url"],
        "author": author,
        "authorType": pr["user"]["type"],
        "createdAt": pr["created_at"],
        "mergedAt": pr["merged_at"],
        "mergedBy": login(&pr["merged_by"]),
        "base": pr["base"]["ref"],
        "headSha": head,
        "mergeCommit": pr["merge_commit_sha"],
        "reviews": listed,
        "approvers": approvers,
        "approvedByOther": !approvers.is_empty(),
        "approvedFinalCommit": on_final,
        "changesRequestedAtMerge": changes_requested,
        "automatedReviewers": automated,
        "checks": {
            "required": req,
            "allRequiredPassed": all_passed,
            "allRequiredPassedNow": all_passed_now,
            "failing": failing,
            "runs": check_runs.iter().map(|r| json!({
                "name": r["name"], "app": r["app"]["slug"], "appId": r["app"]["id"], "status": r["status"], "conclusion": r["conclusion"],
                "completedAt": r["completed_at"], "beforeMerge": finished(r).is_some_and(|t| t <= merged), "url": r["html_url"],
            })).collect::<Vec<_>>(),
            "statuses": statuses.iter().map(|s| json!({ "context": s["context"], "state": s["state"], "createdAt": s["created_at"], "beforeMerge": created(s).is_some_and(|t| t <= merged) })).collect::<Vec<_>>(),
        },
    })
}

pub fn run_view(r: &Value) -> Value {
    json!({
        "id": r["id"], "workflow": r["name"], "path": r["path"], "event": r["event"], "status": r["status"], "conclusion": r["conclusion"],
        "headSha": r["head_sha"], "runNumber": r["run_number"], "attempt": r["run_attempt"], "createdAt": r["created_at"],
        "startedAt": r["run_started_at"], "updatedAt": r["updated_at"], "actor": login(&r["actor"]), "triggeringActor": login(&r["triggering_actor"]),
        "url": r["html_url"],
    })
}

fn commit_view(c: &Value, pr: Option<u64>) -> Value {
    json!({
        "sha": c["sha"], "committedAt": c["commit"]["committer"]["date"], "author": login(&c["author"]), "committer": login(&c["committer"]),
        "parents": c["parents"].as_array().map_or(0, Vec::len), "verified": c["commit"]["verification"]["verified"], "pullRequest": pr,
    })
}

// Collecting

pub struct Options {
    pub repo: String,
    pub branch: Option<String>,
    pub period: Period,
    pub titles: bool,
}

pub struct Collected {
    pub repo: Value,
    pub branch: String,
    pub protection: Value,
    pub required: Required,
    pub pulls: Vec<Value>,
    pub commits: Value,
    pub updates: Result<Vec<Value>, u16>,
    pub runs: Vec<Value>,
    pub runs_truncated: bool,
}

/// `owner/name`, as GitHub allows them.
pub fn valid_repo(s: &str) -> bool {
    let part = |p: &str| !p.is_empty() && p.len() <= 100 && p != "." && p != ".." && p.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c));
    s.split_once('/').is_some_and(|(o, n)| part(o) && part(n))
}

pub fn valid_branch(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.starts_with('/') && !s.contains("..") && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._/-".contains(&c))
}

/// Everything for the bundle, read from GitHub.
pub fn collect(api: &mut dyn Api, o: &Options) -> Result<Collected, Failure> {
    let repo = &o.repo;
    let info = api.get(&format!("/repos/{repo}"))?.body;
    let branch = o.branch.clone().or_else(|| info["default_branch"].as_str().map(String::from)).unwrap_or_else(|| "main".into());
    if !valid_branch(&branch) {
        return Err(Failure::new(0, format!("{branch} isn't a branch name this tool reads")));
    }
    let p = &o.period;

    let branch_info = api.get(&format!("/repos/{repo}/branches/{branch}"))?.body;
    let rules = optional(all(api, &format!("/repos/{repo}/rules/branches/{branch}?per_page=100"), None))?;
    let classic = optional(api.get(&format!("/repos/{repo}/branches/{branch}/protection")).map(|r| r.body))?;
    let (protection, required) = protection(&branch, &branch_info, &rules, &classic);

    let mut pulls = Vec::new();
    for listed in merged(api, repo, &branch, p)? {
        let n = listed["number"].as_u64().unwrap_or_default();
        // The list leaves out who merged it.
        let pr = api.get(&format!("/repos/{repo}/pulls/{n}"))?.body;
        let head = pr["head"]["sha"].as_str().unwrap_or_default().to_string();
        let reviews = all(api, &format!("/repos/{repo}/pulls/{n}/reviews?per_page=100"), None)?;
        // Every run and status, not just the latest, so the result at the merge can be told
        // from one that came later.
        let (checks, statuses) = if head.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (
                all(api, &format!("/repos/{repo}/commits/{head}/check-runs?filter=all&per_page=100"), Some("check_runs"))?,
                all(api, &format!("/repos/{repo}/commits/{head}/statuses?per_page=100"), None)?,
            )
        };
        pulls.push(pull_view(&pr, &reviews, &checks, &statuses, &required, o.titles));
    }
    pulls.sort_by_key(|pr| pr["number"].as_u64());

    let mut raw_runs = Vec::new();
    let runs_truncated = runs_between(api, repo, &branch, p.from, p.to, &mut raw_runs)?;
    let mut seen = HashSet::new();
    raw_runs.retain(|r| in_period(p, &r["created_at"]) && seen.insert(r["id"].as_u64()));
    raw_runs.sort_by_key(|r| (ms(&r["created_at"]), r["id"].as_u64()));
    let runs: Vec<Value> = raw_runs.iter().map(run_view).collect();
    for pr in &mut pulls {
        pr["postMergeRuns"] = match pr["mergeCommit"].as_str() {
            Some(sha) => json!(merge_runs(api, repo, &branch, sha)?),
            None => json!([]),
        };
    }

    let commits = commits_on_branch(api, repo, &branch, p, &pulls)?;
    let repo_view = json!({ "fullName": info["full_name"], "private": info["private"], "defaultBranch": info["default_branch"], "url": info["html_url"] });
    let updates = branch_updates(api, repo, &branch, p)?;
    Ok(Collected { repo: repo_view, branch, protection, required, pulls, commits, updates, runs, runs_truncated })
}

/// The CI runs on a merge commit, read by commit so a run that started after the period
/// still counts for a pull request merged just before its end.
fn merge_runs(api: &mut dyn Api, repo: &str, branch: &str, sha: &str) -> Result<Vec<Value>, Failure> {
    let mut runs = all(api, &format!("/repos/{repo}/actions/runs?head_sha={}&exclude_pull_requests=true&per_page=100", enc(sha)), Some("workflow_runs"))?;
    runs.retain(|r| r["head_branch"] == branch);
    runs.sort_by_key(|r| (ms(&r["created_at"]), r["id"].as_u64()));
    Ok(runs.iter().map(|r| json!({ "id": r["id"], "workflow": r["name"], "conclusion": r["conclusion"], "createdAt": r["created_at"], "url": r["html_url"] })).collect())
}

/// Every commit on the branch dated in the period, with the merged pull request it came from.
fn commits_on_branch(api: &mut dyn Api, repo: &str, branch: &str, p: &Period, pulls: &[Value]) -> Result<Value, Failure> {
    let since = format!("{}T00:00:00Z", p.from);
    let until = format!("{}T00:00:00Z", p.to);
    let listed = all(api, &format!("/repos/{repo}/commits?sha={}&since={}&until={}&per_page=100", enc(branch), enc(&since), enc(&until)), None)?;
    let by_merge: HashMap<&str, u64> = pulls.iter().filter_map(|pr| Some((pr["mergeCommit"].as_str()?, pr["number"].as_u64()?))).collect();
    let (mut commits, mut direct, mut unchecked, mut refused, mut lookups) = (Vec::new(), Vec::new(), 0, 0, 0);
    for c in listed.iter().filter(|c| in_period(p, &c["commit"]["committer"]["date"])) {
        let sha = c["sha"].as_str().unwrap_or_default();
        let pr = match by_merge.get(sha) {
            Some(n) => Some(*n),
            None if lookups < MAX_COMMIT_LOOKUPS => {
                lookups += 1;
                // A refused lookup proves nothing about the commit, so it's unchecked, not direct.
                let Ok(prs) = optional(all(api, &format!("/repos/{repo}/commits/{sha}/pulls?per_page=100"), None))? else {
                    (unchecked, refused) = (unchecked + 1, refused + 1);
                    commits.push(commit_view(c, None));
                    continue;
                };
                prs.iter().find(|x| x["merged_at"].is_string() && x["base"]["ref"] == branch).and_then(|x| x["number"].as_u64())
            }
            None => {
                unchecked += 1;
                commits.push(commit_view(c, None));
                continue;
            }
        };
        let v = commit_view(c, pr);
        if pr.is_none() {
            direct.push(v.clone());
        }
        commits.push(v);
    }
    Ok(json!({
        "basis": "commit date: a commit made before the period and pushed to the branch in it is in branchUpdates, not here",
        "total": commits.len(),
        "viaPullRequest": commits.iter().filter(|c| c["pullRequest"].is_u64()).count(),
        "direct": direct,
        "unchecked": unchecked,
        "uncheckedBecauseRefused": refused,
        "commits": commits,
    }))
}

// The bundle

fn numbers(pulls: &[Value], keep: impl Fn(&Value) -> bool) -> Vec<Value> {
    pulls.iter().filter(|p| keep(p)).map(|p| p["number"].clone()).collect()
}

fn pull_requests(c: &Collected, snapshot: &str) -> Value {
    let pulls = &c.pulls;
    let required = !c.required.checks.is_empty();
    let direct: Vec<Value> = c.commits["direct"].as_array().into_iter().flatten().map(|d| d["sha"].clone()).collect();
    let pushes: Option<Vec<Value>> = c.updates.as_ref().ok().map(|u| u.iter().filter(|u| pushed(u)).map(|u| u["after"].clone()).collect());
    let updates = match &c.updates {
        Ok(u) => {
            let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
            for x in u {
                *by_type.entry(x["type"].as_str().unwrap_or("unknown").to_string()).or_default() += 1;
            }
            json!({ "available": true, "total": u.len(), "byType": by_type, "updates": u })
        }
        Err(status) => json!({ "available": false, "status": status, "why": "GitHub didn't show this token the branch's activity; direct pushes are known only from commit dates" }),
    };
    json!({
        "repository": c.repo["fullName"],
        "branch": c.branch,
        "rulesAsOf": snapshot,
        "requiredChecks": c.required.names(),
        "requiredCheckApps": c.required.apps(),
        "requiredApprovals": c.required.approvals,
        "summary": {
            "merged": pulls.len(),
            "approvedByOther": pulls.iter().filter(|p| p["approvedByOther"] == true).count(),
            "approvedFinalCommit": pulls.iter().filter(|p| p["approvedFinalCommit"] == true).count(),
            "requiredChecksPassed": required.then(|| pulls.iter().filter(|p| p["checks"]["allRequiredPassed"] == true).count()),
            "withFailingChecks": pulls.iter().filter(|p| p["checks"]["failing"].as_array().is_some_and(|f| !f.is_empty())).count(),
            "commitsOnBranch": c.commits["total"],
            "directCommits": direct.len(),
            "branchUpdates": c.updates.as_ref().ok().map(Vec::len),
            "directPushes": pushes.as_ref().map(Vec::len),
        },
        "exceptions": {
            "noIndependentApproval": numbers(pulls, |p| p["approvedByOther"] != true),
            "approvalNotOnFinalCommit": numbers(pulls, |p| p["approvedByOther"] == true && p["approvedFinalCommit"] != true),
            "changesRequestedAtMerge": numbers(pulls, |p| p["changesRequestedAtMerge"].as_array().is_some_and(|a| !a.is_empty())),
            "requiredChecksNotPassed": if required { json!(numbers(pulls, |p| p["checks"]["allRequiredPassed"] != true)) } else { Value::Null },
            "requiredChecksPassedOnlyAfterMerge": if required { json!(numbers(pulls, |p| p["checks"]["allRequiredPassed"] != true && p["checks"]["allRequiredPassedNow"] == true)) } else { Value::Null },
            "failingChecksAtMerge": numbers(pulls, |p| p["checks"]["failing"].as_array().is_some_and(|f| !f.is_empty())),
            "directCommits": direct,
            "directPushes": pushes,
        },
        "pullRequests": pulls,
        "branchUpdates": updates,
        "commitsOnBranch": c.commits,
    })
}

fn workflow_runs(c: &Collected) -> Value {
    let mut by: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut daily: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let ended = |r: &Value| r["conclusion"].as_str().unwrap_or(r["status"].as_str().unwrap_or("unknown")).to_string();
    for r in &c.runs {
        let wf = r["path"].as_str().or(r["workflow"].as_str()).unwrap_or("unknown").to_string();
        *by.entry(wf.clone()).or_default().entry(ended(r)).or_default() += 1;
        let day = r["createdAt"].as_str().and_then(|s| s.get(..10)).unwrap_or_default().to_string();
        *daily.entry(day).or_default().entry(format!("{wf} {}", ended(r))).or_default() += 1;
    }
    let failed: Vec<Value> = c
        .runs
        .iter()
        .filter(|r| r["conclusion"].as_str().is_some_and(|x| FAILING.contains(&x)))
        .map(|r| json!({ "id": r["id"], "workflow": r["path"], "conclusion": r["conclusion"], "createdAt": r["createdAt"], "url": r["url"] }))
        .collect();
    json!({
        "repository": c.repo["fullName"],
        "branch": c.branch,
        "total": c.runs.len(),
        "truncated": c.runs_truncated,
        "byWorkflow": by,
        "daily": daily,
        "failed": failed,
        "runs": c.runs,
    })
}

fn json_file(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s.into_bytes()
}

pub fn sha256(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
}

/// A bundle's name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

/// Where the bundle's facts came from, for the manifest.
pub struct Source {
    pub api_host: String,
    pub requests: u64,
    pub scopes: Option<String>,
}

/// Classic token scopes that can write; a fine-grained token's are not shown.
const WRITE_SCOPES: [&str; 6] = ["repo", "public_repo", "workflow", "delete_repo", "write:", "admin:"];

pub fn can_write(scopes: &str) -> bool {
    scopes.split(',').map(str::trim).any(|s| WRITE_SCOPES.iter().any(|w| if w.ends_with(':') { s.starts_with(w) } else { s == *w }))
}

pub struct Bundle {
    pub name: String,
    pub tar: Vec<u8>,
    pub sha256: String,
    pub manifest_sha256: String,
}

pub fn build(c: &Collected, p: &Period, src: &Source, now_ms: i64) -> Bundle {
    let name = name(p, now_ms);
    let created = rfc3339(now_ms);
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let with_period = |mut v: Value| {
        v["periodCovered"] = period.clone();
        v
    };
    let mut protection = c.protection.clone();
    protection["snapshotAt"] = json!(created);
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("pull-requests.json", json_file(&with_period(pull_requests(c, &created)))),
        ("branch-protection.json", json_file(&protection)),
        ("workflow-runs.json", json_file(&with_period(workflow_runs(c)))),
    ];
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let s = SECTIONS.iter().find(|s| s.file == *n);
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": s.map(|s| s.criteria).unwrap_or_default(), "checklist": s.map(|s| s.rows).unwrap_or_default() })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "change-management",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": created,
        "period": period,
        "source": {
            "api": src.api_host, "repository": c.repo["fullName"], "private": c.repo["private"], "branch": c.branch,
            "requests": src.requests,
            "tokenScopes": src.scopes,
            "tokenCanWrite": src.scopes.as_deref().map(can_write),
        },
        "pullRequests": c.pulls.len(),
        "workflowRuns": c.runs.len(),
        "files": listed,
        "notIncluded": "the token, pull request and review bodies, comments, commit messages, emails, logs and artifacts",
    });
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    Bundle { sha256: sha256(&tar), manifest_sha256, name, tar }
}

/// The lines printed after saving: what the period holds and what an auditor would ask about.
pub fn summary(c: &Collected) -> String {
    let pr = pull_requests(c, "");
    let list = |k: &str| -> Option<String> {
        let v = pr["exceptions"][k].as_array()?;
        (!v.is_empty()).then(|| v.iter().map(|x| x.as_u64().map_or_else(|| x.as_str().unwrap_or_default().chars().take(12).collect(), |n| format!("#{n}"))).collect::<Vec<_>>().join(", "))
    };
    let mut out = format!("{} pull requests merged into {}, {} workflow runs on it.", c.pulls.len(), c.branch, c.runs.len());
    for (k, label) in [
        ("noIndependentApproval", "Merged without an approval by someone else"),
        ("approvalNotOnFinalCommit", "Approved, but not on the last commit"),
        ("changesRequestedAtMerge", "Merged with changes requested"),
        ("requiredChecksNotPassed", "Merged without every required check passing"),
        ("requiredChecksPassedOnlyAfterMerge", "Required checks that passed only after the merge"),
        ("failingChecksAtMerge", "Merged with a failing check"),
        ("directCommits", "Commits without a merged pull request"),
        ("directPushes", "Pushes, not pull request merges, to the branch"),
    ] {
        if let Some(l) = list(k) {
            out += &format!("\n  {label}: {l}");
        }
    }
    if c.required.checks.is_empty() {
        out += &format!("\n  {} requires no status checks that this token can see.", c.branch);
    }
    if let Err(status) = c.updates {
        out += &format!("\n  GitHub answered {status} for {}'s activity: direct pushes are known only from commit dates.", c.branch);
    }
    if let Some(n) = c.commits["unchecked"].as_u64().filter(|n| *n > 0) {
        out += &format!("\n  {n} commits on the branch weren't checked for a pull request.");
    }
    if c.runs_truncated {
        out += "\n  More than 1,000 runs on one day: that day's list is incomplete.";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Reply;

    fn d(s: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn period() -> Period {
        Period { from: d("2026-10-01"), to: d("2026-11-01") }
    }

    fn review(who: &str, kind: &str, state: &str, at: &str, commit: &str) -> Value {
        json!({ "user": { "login": who, "type": kind }, "state": state, "submitted_at": at, "commit_id": commit, "author_association": "MEMBER", "body": "LGTM, body text never kept" })
    }

    fn pr() -> Value {
        json!({ "number": 7, "title": "Add a thing", "user": { "login": "author-a", "type": "User" }, "head": { "sha": "head1" }, "base": { "ref": "main" },
                "merged_at": "2026-10-10T12:00:00Z", "merge_commit_sha": "merge1", "merged_by": { "login": "author-a" }, "html_url": "https://github.com/o/r/pull/7", "body": "never kept" })
    }

    #[test]
    fn approvals_are_by_someone_else_before_the_merge_and_never_a_bot() {
        let req = Required::default();
        let cases: Vec<(Vec<Value>, Vec<&str>, bool)> = vec![
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-10T11:00:00Z", "head1")], vec!["reviewer-b"], true),
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-09T11:00:00Z", "old")], vec!["reviewer-b"], false),
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-09T11:00:00Z", "old"), review("reviewer-b", "User", "APPROVED", "2026-10-10T11:00:00Z", "head1")], vec!["reviewer-b"], true),
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-11T11:00:00Z", "head1")], vec![], false),
            (vec![review("author-a", "User", "APPROVED", "2026-10-10T11:00:00Z", "head1")], vec![], false),
            (vec![review("review-bot[bot]", "Bot", "APPROVED", "2026-10-10T11:00:00Z", "head1")], vec![], false),
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-09T11:00:00Z", "head1"), review("reviewer-b", "User", "DISMISSED", "2026-10-09T12:00:00Z", "head1")], vec![], false),
            (vec![review("reviewer-b", "User", "APPROVED", "2026-10-09T11:00:00Z", "head1"), review("reviewer-b", "User", "COMMENTED", "2026-10-09T12:00:00Z", "head1")], vec!["reviewer-b"], true),
        ];
        for (i, (reviews, approvers, on_final)) in cases.into_iter().enumerate() {
            let v = pull_view(&pr(), &reviews, &[], &[], &req, true);
            assert_eq!(v["approvers"], json!(approvers), "case {i}");
            assert_eq!(v["approvedByOther"], !approvers.is_empty(), "case {i}");
            assert_eq!(v["approvedFinalCommit"], on_final, "case {i}");
        }
        let v = pull_view(&pr(), &[review("reviewer-c", "User", "CHANGES_REQUESTED", "2026-10-09T11:00:00Z", "head1"), review("review-bot[bot]", "Bot", "COMMENTED", "2026-10-09T11:00:00Z", "head1")], &[], &[], &req, false);
        assert_eq!((v["changesRequestedAtMerge"].clone(), v["automatedReviewers"].clone()), (json!(["reviewer-c"]), json!(["review-bot[bot]"])));
        assert_eq!(v["title"], Value::Null, "--no-titles");
        let text = v.to_string();
        assert!(!text.contains("never kept") && !text.contains("LGTM"), "no bodies: {text}");
    }

    #[test]
    fn required_checks_pass_on_the_latest_result_by_the_merge_from_the_right_app() {
        let req = Required { checks: BTreeMap::from([("rust".into(), None), ("docs".into(), Some(15368)), ("legacy".into(), None), ("missing".into(), None), ("late".into(), None), ("both".into(), None)]), approvals: Some(1) };
        let run = |id: u64, name: &str, conclusion: &str, at: &str, app: u64| json!({ "id": id, "name": name, "conclusion": conclusion, "completed_at": at, "app": { "id": app, "slug": format!("app-{app}") } });
        let runs = vec![
            run(1, "docs", "failure", "2026-10-09T10:00:00Z", 15368),
            run(2, "docs", "success", "2026-10-09T11:00:00Z", 15368),
            run(3, "docs", "failure", "2026-10-09T11:30:00Z", 999),
            run(4, "rust", "skipped", "2026-10-09T11:00:00Z", 15368),
            run(5, "lint", "timed_out", "2026-10-09T11:00:00Z", 15368),
            run(6, "late", "failure", "2026-10-10T11:00:00Z", 15368),
            run(7, "late", "success", "2026-10-11T11:00:00Z", 15368),
            json!({ "id": 8, "name": "rust", "status": "in_progress", "conclusion": null, "completed_at": null, "app": { "id": 15368 } }),
            run(9, "both", "success", "2026-10-09T11:00:00Z", 15368),
        ];
        let statuses = vec![
            json!({ "id": 2, "context": "legacy", "state": "success", "created_at": "2026-10-09T11:00:00Z" }),
            json!({ "id": 1, "context": "legacy", "state": "pending", "created_at": "2026-10-09T10:00:00Z" }),
            json!({ "id": 3, "context": "other", "state": "error", "created_at": "2026-10-09T11:00:00Z" }),
            json!({ "id": 4, "context": "other", "state": "success", "created_at": "2026-10-12T11:00:00Z" }),
            json!({ "id": 5, "context": "both", "state": "pending", "created_at": "2026-10-09T11:00:00Z" }),
        ];
        let v = pull_view(&pr(), &[], &runs, &statuses, &req, true);
        let got = |key: &str| -> BTreeMap<String, bool> { v["checks"]["required"].as_array().unwrap().iter().map(|r| (r["name"].as_str().unwrap().to_string(), r[key].as_bool().unwrap())).collect() };
        assert_eq!(got("passed"), BTreeMap::from([("both".into(), false), ("docs".into(), true), ("late".into(), false), ("legacy".into(), true), ("missing".into(), false), ("rust".into(), true)]), "at the merge; docs' failure from another app doesn't count; a passing run doesn't hide a pending status of the same name");
        assert!(got("passedNow")["late"], "passed after the merge");
        let docs = v["checks"]["required"].as_array().unwrap().iter().find(|r| r["name"] == "docs").unwrap();
        assert_eq!((docs["app"].as_u64(), docs["fromOtherApps"].as_u64()), (Some(15368), Some(1)));
        assert_eq!((v["checks"]["allRequiredPassed"].clone(), v["checks"]["allRequiredPassedNow"].clone()), (json!(false), json!(false)), "missing never passes");
        assert_eq!(v["checks"]["failing"], json!(["docs", "late", "lint", "other"]), "failing by the merge, by name and app; later results don't hide them");
        assert_eq!(v["checks"]["runs"].as_array().unwrap().len(), 9, "every run is listed");
        assert_eq!((v["checks"]["runs"][5]["beforeMerge"].clone(), v["checks"]["runs"][6]["beforeMerge"].clone()), (json!(true), json!(false)));

        let pinned = Required { checks: BTreeMap::from([("docs".into(), Some(15368))]), approvals: None };
        let other_app_only = vec![run(9, "docs", "success", "2026-10-09T11:00:00Z", 999)];
        let v = pull_view(&pr(), &[], &other_app_only, &[json!({ "id": 5, "context": "docs", "state": "success", "created_at": "2026-10-09T11:00:00Z" })], &pinned, true);
        assert_eq!((v["checks"]["required"][0]["passed"].clone(), v["checks"]["required"][0]["found"].clone()), (json!(false), json!(false)), "another app's run or a status never stands in for a pinned app");
        assert_eq!(pull_view(&pr(), &[], &runs, &statuses, &Required::default(), true)["checks"]["allRequiredPassed"], Value::Null, "nothing required");
    }

    #[test]
    fn protection_reads_rulesets_and_classic_and_says_what_it_cant_see() {
        let unprotected = json!({ "protected": false, "protection": { "enabled": false, "required_status_checks": { "enforcement_level": "off", "contexts": [] } } });
        let (v, req) = protection("main", &unprotected, &Ok(vec![]), &Err(404));
        assert_eq!(req, Required::default());
        assert_eq!(v["summary"], json!({ "pullRequestRequired": false, "requiredApprovals": null, "requiredChecks": [], "requiredCheckApps": {}, "forcePushesBlocked": false, "deletionsBlocked": false, "adminsIncluded": null }));
        assert_eq!(v["classic"]["available"], false);

        let rules = vec![
            json!({ "type": "pull_request", "parameters": { "required_approving_review_count": 1 }, "ruleset_id": 9 }),
            json!({ "type": "required_status_checks", "parameters": { "required_status_checks": [{ "context": "rust", "integration_id": 15368 }] } }),
            json!({ "type": "deletion" }),
        ];
        let shown = json!({ "protected": true, "protection": { "enabled": true, "required_status_checks": { "enforcement_level": "non_admins", "contexts": ["docs"] } } });
        let (v, req) = protection("main", &shown, &Ok(rules.clone()), &Err(403));
        assert_eq!(req.checks, BTreeMap::from([("docs".to_string(), None), ("rust".to_string(), Some(15368))]), "the app a ruleset pins is kept");
        assert_eq!(v["summary"]["requiredCheckApps"], json!({ "rust": 15368 }));
        assert_eq!(req.approvals, Some(1));
        assert_eq!((v["summary"]["deletionsBlocked"].clone(), v["summary"]["forcePushesBlocked"].clone()), (json!(true), Value::Null), "classic hidden: unknown, not false");

        let classic = json!({
            "required_status_checks": { "strict": true, "contexts": ["server"], "checks": [{ "context": "server", "app_id": 77 }] },
            "required_pull_request_reviews": { "required_approving_review_count": 2, "dismiss_stale_reviews": true, "dismissal_restrictions": { "users": [{ "login": "x" }] } },
            "enforce_admins": { "enabled": true }, "allow_force_pushes": { "enabled": false }, "allow_deletions": { "enabled": true },
            "restrictions": { "users": [{ "login": "someone" }] },
        });
        let (v, req) = protection("main", &shown, &Ok(rules), &Ok(classic));
        assert_eq!(req.approvals, Some(2));
        assert_eq!(req.checks.get("server"), Some(&Some(77)), "classic protection's app is kept");
        assert_eq!(v["summary"]["forcePushesBlocked"], true);
        assert_eq!(v["summary"]["deletionsBlocked"], true, "a ruleset blocks it even where classic allows it");
        assert_eq!(v["summary"]["adminsIncluded"], true);
        assert!(!v.to_string().contains("someone"), "who may push isn't listed");
    }

    struct Fake(HashMap<String, (Value, Option<String>)>, Vec<String>);

    impl Api for Fake {
        fn get(&mut self, path: &str) -> Result<Reply, Failure> {
            self.1.push(path.to_string());
            let (body, next) = self.0.get(path).cloned().ok_or_else(|| Failure::new(404, format!("no fixture for {path}")))?;
            Ok(Reply { body, next })
        }
    }

    #[test]
    fn merged_pull_requests_stop_at_the_first_updated_before_the_period() {
        let first = "/repos/o/r/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100".to_string();
        let page = |n: u64, updated: &str, merged: Option<&str>| json!({ "number": n, "updated_at": updated, "merged_at": merged });
        let mut fake = Fake(HashMap::new(), Vec::new());
        fake.0.insert(first.clone(), (json!([page(5, "2026-11-03T00:00:00Z", Some("2026-11-02T00:00:00Z")), page(4, "2026-10-20T00:00:00Z", Some("2026-10-20T00:00:00Z"))]), Some("next-1".into())));
        fake.0.insert("next-1".into(), (json!([page(3, "2026-10-04T00:00:00Z", None), page(2, "2026-10-03T00:00:00Z", Some("2026-09-30T23:59:59Z")), page(1, "2026-09-30T00:00:00Z", Some("2026-09-30T00:00:00Z"))]), Some("never".into())));
        let got: Vec<u64> = merged(&mut fake, "o/r", "main", &period()).unwrap().iter().map(|p| p["number"].as_u64().unwrap()).collect();
        assert_eq!(got, vec![4]);
        assert_eq!(fake.1, vec![first.clone(), "next-1".to_string()], "the page past the first old update isn't read");

        let mut endless = Fake(HashMap::new(), Vec::new());
        endless.0.insert(first.clone(), (json!([page(9, "2026-10-20T00:00:00Z", Some("2026-10-20T00:00:00Z"))]), Some(first)));
        let err = merged(&mut endless, "o/r", "main", &period()).unwrap_err();
        assert!(err.message.contains("pages"), "a list cut short is an error, never a short list: {}", err.message);
        assert_eq!(endless.1.len(), MAX_PAGES);
    }

    #[test]
    fn commit_lookups_read_every_page_and_a_refused_one_is_unchecked_not_direct() {
        let commit = |sha: &str| json!({ "sha": sha, "commit": { "committer": { "date": "2026-10-10T00:00:00Z" } } });
        let mut fake = Fake(HashMap::new(), Vec::new());
        let list = format!("/repos/o/r/commits?sha=main&since={}&until={}&per_page=100", enc("2026-10-01T00:00:00Z"), enc("2026-11-01T00:00:00Z"));
        fake.0.insert(list, (json!([commit("m1"), commit("d1"), commit("x1"), commit("p1")]), None));
        fake.0.insert("/repos/o/r/commits/d1/pulls?per_page=100".into(), (json!([]), None));
        let other = json!({ "number": 3, "merged_at": "2026-10-09T00:00:00Z", "base": { "ref": "release" } });
        fake.0.insert("/repos/o/r/commits/p1/pulls?per_page=100".into(), (json!([other]), Some("p1-page-2".into())));
        fake.0.insert("p1-page-2".into(), (json!([{ "number": 8, "merged_at": "2026-10-10T00:00:00Z", "base": { "ref": "main" } }]), None));
        let pulls = [json!({ "number": 7, "mergeCommit": "m1" })];
        let v = commits_on_branch(&mut fake, "o/r", "main", &period(), &pulls).unwrap();
        assert_eq!(v["direct"].as_array().unwrap().iter().map(|c| c["sha"].as_str().unwrap()).collect::<Vec<_>>(), ["d1"], "p1's pull request into main is on the second page");
        assert_eq!(v["commits"][3]["pullRequest"], 8);
        assert_eq!((v["unchecked"].as_u64(), v["uncheckedBecauseRefused"].as_u64(), v["total"].as_u64(), v["viaPullRequest"].as_u64()), (Some(1), Some(1), Some(4), Some(2)));
        assert!(!fake.1.iter().any(|u| u.contains("/m1/")), "a merge commit isn't looked up");
    }

    #[test]
    fn branch_updates_are_read_back_to_the_period_and_pushes_are_told_from_merges() {
        let first = format!("/repos/o/r/activity?ref={}&direction=desc&per_page=100", enc("refs/heads/main"));
        let up = |id: u64, at: &str, kind: &str| json!({ "id": id, "timestamp": at, "activity_type": kind, "actor": { "login": "someone" }, "before": "b", "after": format!("sha{id}") });
        let mut fake = Fake(HashMap::new(), Vec::new());
        fake.0.insert(first.clone(), (json!([up(5, "2026-11-02T00:00:00Z", "pr_merge"), up(4, "2026-10-20T00:00:00Z", "pr_merge")]), Some("next-1".into())));
        fake.0.insert("next-1".into(), (json!([up(3, "2026-10-15T00:00:00Z", "push"), up(2, "2026-10-14T00:00:00Z", "force_push"), up(1, "2026-09-30T23:59:59Z", "push")]), Some("never".into())));
        let got = branch_updates(&mut fake, "o/r", "main", &period()).unwrap().unwrap();
        assert_eq!(got.iter().map(|u| u["id"].as_u64().unwrap()).collect::<Vec<_>>(), vec![4, 3, 2]);
        assert_eq!(got.iter().filter(|u| pushed(u)).map(|u| u["after"].as_str().unwrap()).collect::<Vec<_>>(), vec!["sha3", "sha2"]);
        assert_eq!(fake.1, vec![first, "next-1".to_string()], "stops at the first update before the period");
        let mut hidden = Fake(HashMap::new(), Vec::new());
        assert_eq!(branch_updates(&mut hidden, "o/r", "main", &period()).unwrap(), Err(404), "what the token can't see is unavailable, not a failure");
    }

    #[test]
    fn a_range_with_over_1000_runs_is_split() {
        let mut fake = Fake(HashMap::new(), Vec::new());
        let url = |a: &str, b: &str| format!("/repos/o/r/actions/runs?branch=main&created={}&exclude_pull_requests=true&per_page=100", enc(&format!("{a}T00:00:00Z..{b}T23:59:59Z")));
        let run = |id: u64| json!({ "id": id, "created_at": "2026-10-02T00:00:00Z" });
        fake.0.insert(url("2026-10-01", "2026-10-31"), (json!({ "total_count": 1500, "workflow_runs": [run(1)] }), None));
        fake.0.insert(url("2026-10-01", "2026-10-15"), (json!({ "total_count": 2, "workflow_runs": [run(2)] }), Some("p2".into())));
        fake.0.insert("p2".into(), (json!({ "total_count": 2, "workflow_runs": [run(3)] }), None));
        fake.0.insert(url("2026-10-16", "2026-10-31"), (json!({ "total_count": 1, "workflow_runs": [run(4)] }), None));
        let mut out = Vec::new();
        assert!(!runs_between(&mut fake, "o/r", "main", d("2026-10-01"), d("2026-11-01"), &mut out).unwrap());
        assert_eq!(out.iter().map(|r| r["id"].as_u64().unwrap()).collect::<Vec<_>>(), vec![2, 3, 4], "the capped page is dropped");
        let mut fake = Fake(HashMap::new(), Vec::new());
        fake.0.insert(url("2026-10-01", "2026-10-01"), (json!({ "total_count": 1200, "workflow_runs": [run(1)] }), None));
        assert!(runs_between(&mut fake, "o/r", "main", d("2026-10-01"), d("2026-10-02"), &mut Vec::new()).unwrap(), "one day over the cap is truncated");
    }

    #[test]
    fn names_tokens_and_repos() {
        let n = name(&period(), 1_795_000_000_000);
        assert!(n.starts_with("superbot-changes-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/branch-protection.json".len() <= 100, "fits a ustar name");
        assert!(!n.starts_with("superbot-evidence-"), "never mistaken for botd's monthly bundle in EVIDENCE_DIR");
        assert!(can_write("repo, read:org") && can_write("public_repo") && can_write("write:packages") && can_write("admin:repo_hook"));
        assert!(!can_write("read:org, read:packages") && !can_write("") && !can_write("repository"));
        assert!(valid_repo("CG-Labs/superbot") && valid_repo("a.b/c_d-e"));
        for bad in ["superbot", "a/b/c", "a/..", "a/b?x=1", "/b", "a/"] {
            assert!(!valid_repo(bad), "{bad}");
        }
        assert!(valid_branch("main") && valid_branch("release/1.2"));
        for bad in ["", "/main", "a..b", "main?x", "a b"] {
            assert!(!valid_branch(bad), "{bad}");
        }
    }

    /// Every file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, each under one of its criteria, and the evidence plan's
    /// change-management table lists each file with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = plan.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's change-management table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
    }
}
