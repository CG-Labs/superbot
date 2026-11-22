//! ADR 0148: `superbot-evidence github` against a stand-in for the GitHub API that answers
//! with recorded responses (`tests/fixtures/github/`): pages followed by their `Link`
//! headers and no further than the period needs, a rate limit waited out, the token sent
//! on every request and never written, and a bundle any `tar` and `sha256sum -c` accept,
//! holding each merged pull request's approvals and checks, the exceptions an auditor
//! samples, the branch's protection and the CI runs on it. Also checks the workflow that
//! runs it monthly asks for read access only.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const REPO: &str = "/repos/example-org/example-repo";
const TOKEN: &str = "test-token-3f9c1e7a5b2d4c6e8f0a";
const HEAD102: &str = "a102a102a102a102a102a102a102a102a102a102";
const HEAD101: &str = "a101a101a101a101a101a101a101a101a101a101";
const DIRECT: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn fixture(name: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github").join(name)).unwrap_or_else(|_| panic!("fixture {name}"))
}

struct Mock {
    base: Mutex<String>,
    requests: Mutex<Vec<(String, Option<String>)>>,
    limited: AtomicBool,
}

fn reply(status: u16, body: String, link: Option<String>) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap(), body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    h.insert("x-oauth-scopes", "repo, read:org".parse().unwrap());
    if let Some(l) = link {
        h.insert(header::LINK, l.parse().unwrap());
    }
    r
}

async fn github(State(m): State<Arc<Mock>>, uri: Uri, headers: HeaderMap) -> Response {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
    m.requests.lock().unwrap().push((uri.to_string(), auth));
    let q: HashMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    let base = m.base.lock().unwrap().clone();
    let path = uri.path();
    if path == REPO && !m.limited.swap(true, Ordering::SeqCst) {
        let reset = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 1;
        let mut r = reply(403, r#"{"message":"API rate limit exceeded"}"#.into(), None);
        r.headers_mut().insert("x-ratelimit-remaining", "0".parse().unwrap());
        r.headers_mut().insert("x-ratelimit-reset", reset.to_string().parse().unwrap());
        return r;
    }
    let ok = |name: &str| reply(200, fixture(name), None);
    let Some(rest) = path.strip_prefix(REPO) else { return reply(404, r#"{"message":"Not Found"}"#.into(), None) };
    let pulls = format!("{base}{REPO}/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=");
    match rest {
        "" => ok("repo.json"),
        "/branches/main" => ok("branch-main.json"),
        "/branches/main/protection" => reply(403, fixture("protection-main.json"), None),
        "/rules/branches/main" => ok("rules-main.json"),
        "/pulls" => {
            assert_eq!((q["state"].as_str(), q["base"].as_str(), q["sort"].as_str(), q["direction"].as_str()), ("closed", "main", "updated", "desc"));
            match q.get("page").map(String::as_str) {
                None => reply(200, fixture("pulls-page1.json"), Some(format!("<{pulls}2>; rel=\"next\", <{pulls}3>; rel=\"last\""))),
                Some("2") => reply(200, fixture("pulls-page2.json"), Some(format!("<{pulls}3>; rel=\"next\""))),
                _ => reply(500, r#"{"message":"page 3 is past the period and must not be read"}"#.into(), None),
            }
        }
        "/pulls/102/reviews" => ok("reviews-102.json"),
        "/pulls/101/reviews" => ok("reviews-101.json"),
        "/actions/runs" => {
            assert_eq!((q["branch"].as_str(), q["created"].as_str()), ("main", "2026-10-01T00:00:00Z..2026-10-31T23:59:59Z"));
            ok("runs.json")
        }
        "/commits" => {
            assert_eq!((q["sha"].as_str(), q["since"].as_str(), q["until"].as_str()), ("main", "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"));
            ok("commits.json")
        }
        r if r == format!("/commits/{HEAD102}/check-runs") => ok("check-runs-102.json"),
        r if r == format!("/commits/{HEAD101}/check-runs") => ok("check-runs-101.json"),
        r if r == format!("/commits/{HEAD102}/status") => ok("status-102.json"),
        r if r == format!("/commits/{HEAD101}/status") => ok("status-101.json"),
        r if r == format!("/commits/{DIRECT}/pulls") => ok("commit-pulls-direct.json"),
        _ => reply(404, r#"{"message":"Not Found"}"#.into(), None),
    }
}

fn serve() -> Arc<Mock> {
    let m = Arc::new(Mock { base: Mutex::new(String::new()), requests: Mutex::new(Vec::new()), limited: AtomicBool::new(false) });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    *m.base.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(github).with_state(m.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(l, app).await.unwrap();
        });
    });
    m
}

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-change-evidence-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn export(dir: &Path, api: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_superbot-evidence"));
    cmd.current_dir(dir).env_remove("GITHUB_TOKEN").env_remove("GH_TOKEN").env("GITHUB_API_URL", api);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(["github", "--repo", "example-org/example-repo", "--from", "2026-10-01", "--to", "2026-11-01"]).args(args).output().unwrap()
}

fn text(o: &Output) -> (String, String) {
    (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn json(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

#[test]
fn exports_merged_pull_requests_checks_protection_and_runs_as_a_checkable_bundle() {
    let m = serve();
    let api = m.base.lock().unwrap().clone();
    let dir = temp();
    let o = export(&dir, &api, &[("GITHUB_TOKEN", TOKEN)], &[]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "superbot-evidence failed:\n{out}\n{err}");
    assert!(err.contains("rate limit"), "the rate limit is waited out and said so: {err}");
    assert!(err.contains("this token can write"), "a classic token with repo scope is warned about: {err}");
    assert!(out.contains("2 pull requests merged into main, 3 workflow runs on it."), "{out}");
    assert!(out.contains("Merged without an approval by someone else: #101"), "{out}");
    assert!(out.contains("Merged without every required check passing: #101"), "{out}");
    assert!(out.contains("Commits without a merged pull request: d0d0d0d0d0d0"), "{out}");

    let requests = m.requests.lock().unwrap().clone();
    assert!(requests.iter().all(|(_, auth)| auth.as_deref() == Some(&format!("Bearer {TOKEN}"))), "every request carries the token as a bearer");
    assert!(requests.iter().all(|(u, _)| !u.contains(TOKEN)), "never in a URL");
    assert!(!requests.iter().any(|(u, _)| u.contains("page=3")), "the page past the period isn't read");

    let tars: Vec<PathBuf> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "tar")).collect();
    assert_eq!(tars.len(), 1);
    let tar = &tars[0];
    let name = tar.file_stem().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("superbot-changes-2026-10-01_2026-11-01-"), "{name}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(tar).unwrap().permissions().mode() & 0o777, 0o600, "private to its owner");
    }
    let raw = fs::read(tar).unwrap();
    assert!(!raw.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()), "the token is never written");
    for never in ["Secret body", "Please rename", "Looks good", "Automated summary", "Commit message never kept", "Direct push message", "author@example.com", "log text never kept", "Author Name"] {
        assert!(!raw.windows(never.len()).any(|w| w == never.as_bytes()), "{never:?} is in the bundle");
    }
    assert!(Command::new("tar").arg("-xf").arg(tar).current_dir(&dir).status().unwrap().success(), "any tar reads it");
    let folder = dir.join(&name);
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));

    let manifest = json(&folder, "manifest.json");
    let digest = |b: &[u8]| -> String {
        let o = Command::new("sha256sum").arg(folder.join(String::from_utf8_lossy(b).as_ref())).output().unwrap();
        String::from_utf8_lossy(&o.stdout).split_whitespace().next().unwrap().to_string()
    };
    assert!(out.contains(&format!("Manifest SHA-256: {}", digest(b"manifest.json"))), "the printed digest is the manifest's");
    assert_eq!((manifest["kind"].as_str(), manifest["format"].as_u64()), (Some("change-management"), Some(1)));
    assert_eq!(manifest["period"], serde_json::json!({ "from": "2026-10-01", "to": "2026-11-01", "days": 31 }));
    assert_eq!(manifest["source"]["repository"], "example-org/example-repo");
    assert_eq!((manifest["source"]["tokenScopes"].as_str(), manifest["source"]["tokenCanWrite"].as_bool()), (Some("repo, read:org"), Some(true)));
    assert_eq!(manifest["source"]["requests"].as_u64(), Some(requests.len() as u64), "every request is counted");
    let files: Vec<&str> = manifest["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert_eq!(files, ["README.txt", "pull-requests.json", "branch-protection.json", "workflow-runs.json"]);
    for f in manifest["files"].as_array().unwrap() {
        assert_eq!(f["sha256"].as_str().unwrap(), digest(f["name"].as_str().unwrap().as_bytes()), "{}", f["name"]);
    }
    assert_eq!(manifest["files"][1]["checklist"], serde_json::json!(["CC3.4-1", "CC8.1-1", "CC8.1-2"]));

    let prs = json(&folder, "pull-requests.json");
    let list = prs["pullRequests"].as_array().unwrap();
    assert_eq!(list.iter().map(|p| p["number"].as_u64().unwrap()).collect::<Vec<_>>(), [101, 102], "merged in the period, oldest first; not 99, 100 or 103");
    let (p101, p102) = (&list[0], &list[1]);
    assert_eq!(p102["title"], "Add the widget");
    assert_eq!((p102["author"].as_str(), p102["mergedBy"].as_str(), p102["mergeCommit"].as_str()), (Some("author-a"), Some("maintainer-m"), Some("b102b102b102b102b102b102b102b102b102b102")));
    assert_eq!((p102["approvers"].clone(), p102["approvedFinalCommit"].as_bool()), (serde_json::json!(["reviewer-b"]), Some(true)));
    assert_eq!(p102["automatedReviewers"], serde_json::json!(["review-bot[bot]"]));
    assert_eq!(p102["checks"]["allRequiredPassed"], true, "docs passed on its re-run");
    assert_eq!(p102["postMergeRuns"][0]["id"], 9001);
    assert_eq!(p101["approvers"], serde_json::json!([]), "approved only after the merge");
    assert_eq!(p101["reviews"][1]["beforeMerge"], false);
    assert_eq!(p101["checks"]["failing"], serde_json::json!(["docs"]));
    assert_eq!(p101["checks"]["statuses"][0]["context"], "ci/legacy");
    assert_eq!(prs["exceptions"]["noIndependentApproval"], serde_json::json!([101]));
    assert_eq!(prs["exceptions"]["requiredChecksNotPassed"], serde_json::json!([101]));
    assert_eq!(prs["exceptions"]["directCommits"], serde_json::json!([DIRECT]));
    assert_eq!((prs["summary"]["merged"].as_u64(), prs["summary"]["commitsOnBranch"].as_u64()), (Some(2), Some(3)));
    assert_eq!(prs["periodCovered"]["days"], 31);

    let bp = json(&folder, "branch-protection.json");
    assert_eq!(bp["summary"]["requiredChecks"], serde_json::json!(["docs", "rust"]));
    assert_eq!((bp["summary"]["requiredApprovals"].as_u64(), bp["summary"]["forcePushesBlocked"].as_bool(), bp["summary"]["deletionsBlocked"].as_bool()), (Some(1), Some(true), Some(true)));
    assert_eq!((bp["classic"]["available"].as_bool(), bp["classic"]["status"].as_u64()), (Some(false), Some(403)), "a read-only token can't see classic protection; said so");
    assert!(bp["snapshotAt"].is_string());

    let runs = json(&folder, "workflow-runs.json");
    assert_eq!(runs["total"], 3);
    assert_eq!(runs["byWorkflow"][".github/workflows/docs.yml"]["failure"], 1);
    assert_eq!(runs["failed"].as_array().unwrap().iter().map(|r| r["id"].as_u64().unwrap()).collect::<Vec<_>>(), [9002]);
    assert_eq!(runs["runs"][0]["id"], 9002, "oldest first");

    let o = export(&dir, &api, &[("GH_TOKEN", TOKEN)], &["--no-titles", "-o", "october.tar"]);
    assert!(o.status.success(), "{:?}", text(&o));
    let raw = fs::read(dir.join("october.tar")).unwrap();
    assert!(!raw.windows("Add the widget".len()).any(|w| w == b"Add the widget"), "--no-titles leaves titles out");
    let o = export(&dir, &api, &[("GITHUB_TOKEN", TOKEN)], &["-o", "october.tar"]);
    assert!(!o.status.success() && text(&o).1.contains("october.tar"), "never over an existing file");
    assert_eq!(fs::read(dir.join("october.tar")).unwrap(), raw);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn refuses_without_a_token_off_https_and_with_a_token_on_the_command_line() {
    let dir = temp();
    let o = export(&dir, "", &[], &[]);
    assert!(!o.status.success() && text(&o).1.contains("GITHUB_TOKEN"), "{:?}", text(&o));
    let o = export(&dir, "http://api.example.com", &[("GITHUB_TOKEN", TOKEN)], &[]);
    assert!(!o.status.success() && text(&o).1.contains("https"), "{:?}", text(&o));
    let o = export(&dir, "", &[], &["--token", TOKEN]);
    let (_, err) = text(&o);
    assert!(!o.status.success() && err.contains("never on the command line") && !err.contains(TOKEN), "{err}");
    let o = export(&dir, "", &[("GITHUB_TOKEN", TOKEN)], &["--to", "2026-12-31"]);
    assert!(!o.status.success(), "{:?}", text(&o));
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "nothing written");
    let _ = fs::remove_dir_all(&dir);
}

/// The workflow that runs it monthly: read access only, the export pinned to this
/// repository's own code, dispatch inputs through the environment, never into the script.
#[test]
fn the_monthly_workflow_reads_only() {
    let wf = fs::read_to_string(repo().join(".github/workflows/change-evidence.yml")).expect(".github/workflows/change-evidence.yml exists");
    let perms: Vec<&str> = wf.lines().skip_while(|l| *l != "permissions:").skip(1).take_while(|l| l.starts_with("  ")).map(str::trim).collect();
    assert!(!perms.is_empty(), "a top-level permissions block");
    for want in ["contents: read", "pull-requests: read", "actions: read", "checks: read", "statuses: read"] {
        assert!(perms.contains(&want), "permissions need {want}: {perms:?}");
    }
    assert!(perms.iter().all(|p| p.ends_with(": read")), "read access only: {perms:?}");
    assert!(!wf.contains("write"), "nothing in it may write");
    assert!(wf.contains("cron:") && wf.contains("workflow_dispatch:"), "monthly, and on demand");
    assert!(wf.contains("--bin superbot-evidence"), "builds the exporter from this commit");
    assert!(wf.contains("GITHUB_TOKEN: ${{ github.token }}"), "uses the workflow's own token");
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut block: Option<usize> = None;
    let mut scripts = 0;
    for l in wf.lines() {
        if let Some(at) = block {
            if l.trim().is_empty() || indent(l) > at {
                assert!(!l.contains("${{"), "expressions go through env, never into a script: {l}");
                continue;
            }
            block = None;
        }
        let t = l.trim_start().trim_start_matches("- ");
        if let Some(rest) = t.strip_prefix("run:") {
            scripts += 1;
            assert!(!rest.contains("${{"), "expressions go through env, never into a script: {l}");
            if matches!(rest.trim(), "|" | ">") {
                block = Some(indent(l));
            }
        }
    }
    assert!(scripts > 0, "found no run steps");
    assert!(wf.contains("actions/upload-artifact@"), "keeps the bundle as an artifact");
}
