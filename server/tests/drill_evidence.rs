//! ADR 0177: `superbot-evidence drills` against a stand-in for the GitHub API: each drill
//! workflow's runs in the period, every matrix job's drill step timed and judged, the drill
//! artifacts with GitHub's digests, a workflow the token can't read recorded rather than
//! fatal, and the token sent on every request and never written. The operator's records
//! come from the real drill scripts' output (`deploy/machine-restore-drill.sh` against a
//! stand-in `botctl`, and `deploy/backup-drill.sh`'s record function), keep none of the
//! rest of it, and must have finished in the period. The bundle checks with `tar`,
//! `sha256sum -c` and `superbot-evidence coverage`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const REPO: &str = "/repos/example-org/example-repo";
const TOKEN: &str = "test-token-drills-5e8a2c";

struct Mock {
    requests: Mutex<Vec<(String, Option<String>)>>,
}

fn reply(status: u16, body: Value) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap(), body.to_string()).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

fn run(id: u64, created: &str, path: &str) -> Value {
    json!({ "id": id, "status": "completed", "conclusion": "success", "path": path, "event": "push", "head_sha": format!("{id:040}"), "run_attempt": 1, "created_at": created, "html_url": format!("https://github.com/example-org/example-repo/actions/runs/{id}") })
}

fn step(name: &str, conclusion: &str, from: &str, to: &str) -> Value {
    json!({ "name": name, "conclusion": conclusion, "number": 3, "started_at": from, "completed_at": to })
}

fn job(id: u64, name: &str, steps: Vec<Value>) -> Value {
    json!({ "id": id, "name": name, "conclusion": "success", "started_at": "2026-10-01T00:00:00Z", "completed_at": "2026-10-01T00:30:00Z", "html_url": format!("https://github.com/example-org/example-repo/actions/runs/1/job/{id}"), "steps": steps })
}

async fn github(State(m): State<Arc<Mock>>, uri: Uri, headers: HeaderMap) -> Response {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
    m.requests.lock().unwrap().push((uri.to_string(), auth));
    let q: HashMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    let Some(rest) = uri.path().strip_prefix(REPO) else { return reply(404, json!({ "message": "Not Found" })) };
    let runs_of = |file: &str| {
        assert_eq!((q["branch"].as_str(), q["created"].as_str(), q["exclude_pull_requests"].as_str()), ("main", "2026-10-01T00:00:00Z..2026-10-31T23:59:59Z", "true"), "{file}: the branch's runs in the period");
    };
    match rest {
        "" => reply(200, json!({ "full_name": "example-org/example-repo", "private": false, "default_branch": "main", "html_url": "https://github.com/example-org/example-repo" })),
        "/actions/workflows/server.yml/runs" => {
            runs_of("server.yml");
            reply(200, json!({ "total_count": 2, "workflow_runs": [run(101, "2026-10-02T10:00:00Z", ".github/workflows/server.yml"), run(102, "2026-10-20T10:00:00Z", ".github/workflows/server.yml")] }))
        }
        "/actions/workflows/docker.yml/runs" => {
            runs_of("docker.yml");
            reply(403, json!({ "message": "Resource not accessible by integration" }))
        }
        "/actions/workflows/incus-e2e.yml/runs" => {
            runs_of("incus-e2e.yml");
            reply(200, json!({ "total_count": 1, "workflow_runs": [run(301, "2026-10-06T05:41:00Z", ".github/workflows/incus-e2e.yml")] }))
        }
        "/actions/runs/101/jobs" | "/actions/runs/102/jobs" => {
            assert_eq!(q["filter"].as_str(), "latest", "the latest attempt's jobs");
            let ok = if rest.contains("101") { "success" } else { "failure" };
            reply(200, json!({ "total_count": 2, "jobs": [
                job(if ok == "success" { 1011 } else { 1021 }, "backup-drill", vec![
                    step("Install age and sqlite3", "success", "2026-10-02T10:01:00Z", "2026-10-02T10:01:20Z"),
                    step("Backup and restore drill (installer units, encrypted archive, fresh host, RTO and RPO budgets)", ok, "2026-10-02T10:01:20Z", "2026-10-02T10:04:05Z"),
                ]),
                job(1099, "rust", vec![step("cargo test", "success", "2026-10-02T10:00:00Z", "2026-10-02T10:20:00Z")]),
            ] }))
        }
        "/actions/runs/301/jobs" => {
            let incus = |id: u64, v: &str| {
                job(id, &format!("Containers on Incus ({v})"), vec![
                    step("Containers enroll, stay apart, follow the lifecycle, and are backed up and restored", "success", "2026-10-06T05:44:00Z", "2026-10-06T05:52:30Z"),
                    step("A lost host's container is restored onto another host and enrolls anew", "success", "2026-10-06T05:52:30Z", "2026-10-06T05:55:00Z"),
                ])
            };
            reply(200, json!({ "jobs": [incus(3011, "stable"), incus(3012, "7.0")] }))
        }
        "/actions/runs/301/artifacts" => reply(200, json!({ "artifacts": [
            { "id": 1, "name": "restore-drill-stable", "size_in_bytes": 180, "digest": "sha256:aaaa", "created_at": "2026-10-06T06:00:00Z", "expires_at": "2027-01-04T06:00:00Z", "expired": false },
            { "id": 2, "name": "restore-drill-7.0", "size_in_bytes": 181, "digest": "sha256:bbbb", "created_at": "2026-10-06T06:00:00Z", "expires_at": "2027-01-04T06:00:00Z", "expired": false },
            { "id": 3, "name": "host-drill-stable", "size_in_bytes": 190, "digest": "sha256:cccc", "created_at": "2026-10-06T06:00:00Z", "expires_at": "2026-10-20T06:00:00Z", "expired": true },
        ] })),
        _ => reply(404, json!({ "message": "Not Found" })),
    }
}

fn serve() -> (Arc<Mock>, String) {
    let m = Arc::new(Mock { requests: Mutex::new(Vec::new()) });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(github).with_state(m.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move { axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap() });
    });
    (m, base)
}

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-drill-evidence-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn evidence(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_superbot-evidence"));
    cmd.current_dir(dir).env_remove("GITHUB_TOKEN").env_remove("GH_TOKEN");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn json_in(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

fn unpack(dir: &Path, tar: &Path) -> PathBuf {
    assert!(Command::new("tar").arg("-xf").arg(tar).current_dir(dir).status().unwrap().success(), "any tar reads it");
    let folder = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with("superbot-drills-")).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

#[test]
fn exports_cis_restore_drills_and_the_operators_records_as_a_checkable_bundle() {
    let (m, api) = serve();
    let dir = temp();
    let machine = "==> drill: objectives\n{\"tier\":\"pro\"}\n==> drill: restoring drill@example.com's machine from b9\n{\"superbotDrill\":1,\"drill\":\"machine-restore\",\"finishedAt\":\"2026-10-14T09:12:00Z\",\"passed\":true,\"restoreId\":\"r1\",\"backupId\":\"b9\",\"tier\":\"pro\",\"durationMs\":412000,\"rtoMs\":3600000}\n==> drill: passed\n";
    let server = "==> drill: passed: restore took 410s (budget 300s)\n{\"superbotDrill\":1,\"drill\":\"server-restore\",\"finishedAt\":\"2026-10-21T08:00:00Z\",\"passed\":true,\"durationMs\":410000,\"rtoMs\":300000,\"nextBackupInSeconds\":3600,\"rpoBudgetSeconds\":87300}\n";
    fs::write(dir.join("machine.log"), machine).unwrap();
    fs::write(dir.join("server.log"), server).unwrap();
    let env = [("GITHUB_TOKEN", TOKEN), ("GITHUB_API_URL", api.as_str())];
    let period = ["--from", "2026-10-01", "--to", "2026-11-01"];

    let o = evidence(&dir, &env, &[&["drills", "--repo", "example-org/example-repo", "--record", "machine.log", "--record", "server.log", "-o", "drills.tar"][..], &period].concat());
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    for want in [
        "6 drill runs in CI on main",
        "server-restore: 2 runs, 1 passed, 1 failed",
        "machine-restore: 2 runs, 2 passed, 0 failed",
        "Not run in the period: compose-restore",
        "Failing at the period's end: server-restore",
        "Artifacts already expired on GitHub: host-loss#301/3011 host-drill-stable, host-loss#301/3012 host-drill-stable",
        "docker.yml's runs weren't readable (GitHub answered 403)",
        "2 operator drill records; over their objective: server-restore 2026-10-21T08:00:00Z.",
    ] {
        assert!(out.contains(want), "{want}\n{out}");
    }
    assert!(!out.contains("Passed without its drill artifact"), "artifacts belong to the run, so each matrix job has them: {out}");
    let requests = m.requests.lock().unwrap().clone();
    assert!(requests.iter().all(|(_, a)| a.as_deref() == Some(&format!("Bearer {TOKEN}"))), "every request carries the token");
    assert!(!requests.iter().any(|(u, _)| u.contains("/runs/101/artifacts")), "no artifacts are listed for a drill that keeps none");

    let tar = dir.join("drills.tar");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&tar).unwrap().permissions().mode() & 0o777, 0o600, "private to its owner");
    }
    let raw = fs::read(&tar).unwrap();
    for never in [TOKEN, "drill@example.com", "==> drill"] {
        assert!(!raw.windows(never.len()).any(|w| w == never.as_bytes()), "{never:?} is in the bundle");
    }
    let folder = unpack(&dir, &tar);
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["format"].as_u64(), manifest["ciDrillRuns"].as_u64(), manifest["operatorRecords"].as_u64()), (Some("recovery-drills"), Some(1), Some(6), Some(2)));
    assert_eq!(manifest["source"]["requests"].as_u64(), Some(requests.len() as u64));
    let files: Vec<&str> = manifest["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert_eq!(files, ["README.txt", "ci-drills.json", "operator-drills.json"]);
    assert_eq!((manifest["files"][1]["checklist"].clone(), manifest["files"][2]["checklist"].clone()), (json!(["A1.3-1"]), json!(["A1.3-1", "CC9.1-2"])));

    let ci = json_in(&folder, "ci-drills.json");
    let ids: Vec<&str> = ci["executions"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["server-restore#101/1011", "host-loss#301/3011", "host-loss#301/3012", "machine-restore#301/3011", "machine-restore#301/3012", "server-restore#102/1021"]);
    let first = &ci["executions"][0];
    assert_eq!((first["outcome"].as_str(), first["seconds"].as_u64(), first["run"]["event"].as_str()), (Some("passed"), Some(165), Some("push")));
    let restore = &ci["executions"][3];
    assert_eq!((restore["artifacts"][0]["name"].as_str(), restore["artifacts"][0]["digest"].as_str()), (Some("restore-drill-stable"), Some("sha256:aaaa")), "the drill's own artifact, with GitHub's digest");
    assert_eq!(ci["summary"]["byDrill"]["server-restore"]["lastOutcome"], "failed");
    assert_eq!(ci["exceptions"]["failed"], json!(["server-restore#102/1021"]));
    assert_eq!((ci["workflows"][1]["available"].as_bool(), ci["workflows"][1]["status"].as_u64()), (Some(false), Some(403)));

    let op = json_in(&folder, "operator-drills.json");
    let recs = op["records"].as_array().unwrap();
    assert_eq!(recs.iter().map(|r| r["drill"].as_str().unwrap()).collect::<Vec<_>>(), ["machine-restore", "server-restore"], "oldest first");
    assert_eq!((recs[0]["withinObjective"].as_bool(), recs[0]["file"].as_str(), recs[0]["fileBytes"].as_u64()), (Some(true), Some("machine.log"), Some(machine.len() as u64)));
    let digest = String::from_utf8_lossy(&Command::new("sha256sum").arg(dir.join("machine.log")).output().unwrap().stdout).split_whitespace().next().unwrap().to_string();
    assert_eq!(recs[0]["fileSha256"].as_str(), Some(digest.as_str()), "matches the output kept beside the bundle");
    assert_eq!(op["exceptions"]["overObjective"], json!(["server-restore 2026-10-21T08:00:00Z"]));

    // The coverage report reads it as a fourth kind of bundle.
    let store = dir.join("store");
    fs::create_dir_all(store.join("A1.3/2026-10")).unwrap();
    fs::copy(&tar, store.join("A1.3/2026-10/drills.tar")).unwrap();
    let o = evidence(&dir, &[], &[&["coverage", store.to_str().unwrap(), "--json"][..], &period].concat());
    assert_eq!(o.status.code(), Some(2), "the other kinds are missing: {}", text(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    let kind = r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == "recovery-drills").unwrap();
    assert_eq!((kind["complete"].as_bool(), r["bundles"][0]["verified"].as_bool()), (Some(true), Some(true)), "{r:#}");
    let row = r["rows"].as_array().unwrap().iter().find(|x| x["row"] == "CC9.1-2").unwrap();
    assert_eq!(row["complete"], true);
    assert_eq!(r["bundles"][0]["exceptions"]["ci-drills.json"]["failed"], 1);

    // A record from another period, or the same output twice, writes nothing.
    fs::write(dir.join("old.log"), machine.replace("2026-10-14", "2026-09-14")).unwrap();
    for (records, want) in [(["--record", "old.log"], "outside the period"), (["--record", "machine.log"], "same output")] {
        let mut args = vec!["drills", "--repo", "example-org/example-repo", "--record", "machine.log", "-o", "again.tar"];
        args.extend(records);
        args.extend(period);
        let o = evidence(&dir, &env, &args);
        assert!(!o.status.success() && text(&o).contains(want), "{want}: {}", text(&o));
        assert!(!dir.join("again.tar").exists());
    }
    let o = evidence(&dir, &env, &[&["drills", "--repo", "example-org/example-repo", "-o", "drills.tar"][..], &period].concat());
    assert!(!o.status.success() && text(&o).contains("drills.tar"), "never over an existing file");
    let _ = fs::remove_dir_all(&dir);
}

/// The record lines the real scripts print are the ones the tool reads: the machine drill
/// run end to end against a stand-in botctl, and the server drill's record function.
#[test]
fn the_drill_scripts_records_are_read_without_github() {
    let dir = temp();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let botctl = dir.join("botctl");
    fs::write(
        &botctl,
        r#"#!/usr/bin/env bash
case "$*" in
  "machine recovery") echo '{"objectives":[{"tier":"pro","rtoMs":3600000}]}' ;;
  "machine backups drill@example.com") echo '{"backups":[{"id":"b9","state":"done"}]}' ;;
  "machine restore drill@example.com b9 --yes") echo '{"restore":{"id":"r1"}}' ;;
  "machine restore drill@example.com status") echo '{"restore":{"id":"r1","state":"done","backupId":"b9","tier":"pro","createdAt":1,"rtoMs":3600000,"durationMs":412000}}' ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&botctl, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let o = Command::new("bash").arg(root.join("deploy/machine-restore-drill.sh")).args(["drill@example.com", "--yes"]).env("BOTCTL", &botctl).env("SUPERBOT_DRILL_POLL_SECONDS", "0").output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    fs::write(dir.join("machine.log"), &o.stdout).unwrap();

    let script = fs::read_to_string(root.join("deploy/backup-drill.sh")).unwrap();
    let record_fn = script.lines().find(|l| l.starts_with("record() {")).expect("backup-drill.sh has a record function");
    let o = Command::new("bash").arg("-c").arg(format!("{record_fn}\nRTO=97 RTO_BUDGET=300 next_in=3500 RPO_BUDGET=87300\nrecord \"\\\"passed\\\":true,\\\"durationMs\\\":$((RTO * 1000)),\\\"rtoMs\\\":$((RTO_BUDGET * 1000)),\\\"nextBackupInSeconds\\\":$next_in,\\\"rpoBudgetSeconds\\\":$RPO_BUDGET\"")).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let call = script.lines().find(|l| l.starts_with("record \"\\\"passed\\\":true")).expect("backup-drill.sh records a pass");
    assert!(call.contains("$((RTO * 1000))") && call.contains("$((RTO_BUDGET * 1000))"), "{call}");
    fs::write(dir.join("server.log"), &o.stdout).unwrap();

    let today = chrono::Utc::now().date_naive();
    let (from, to) = (today.to_string(), today.succ_opt().unwrap().to_string());
    let env = [("GITHUB_API_URL", "https://unreachable.invalid")];
    let o = evidence(&dir, &env, &["drills", "--no-ci", "--record", "machine.log", "--record", "server.log", "--from", &from, "--to", &to, "-o", "drills.tar"]);
    let out = text(&o);
    assert!(o.status.success() && out.contains("in 0 requests") && out.contains("CI's drills weren't read (--no-ci)") && out.contains("2 operator drill records."), "{out}");
    let folder = unpack(&dir, &dir.join("drills.tar"));
    let op = json_in(&folder, "operator-drills.json");
    let recs = op["records"].as_array().unwrap();
    let machine = recs.iter().find(|r| r["drill"] == "machine-restore").unwrap();
    assert_eq!((machine["durationMs"].as_u64(), machine["rtoMs"].as_u64(), machine["withinObjective"].as_bool(), machine["restoreId"].as_str()), (Some(412_000), Some(3_600_000), Some(true), Some("r1")));
    let server = recs.iter().find(|r| r["drill"] == "server-restore").unwrap();
    assert_eq!((server["durationMs"].as_u64(), server["nextBackupInSeconds"].as_u64(), server["withinObjective"].as_bool()), (Some(97_000), Some(3500), Some(true)));
    let ci = json_in(&folder, "ci-drills.json");
    assert_eq!((ci["collected"].as_bool(), ci["exceptions"]["notRunInPeriod"].clone()), (Some(false), json!([])));
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["source"]["ci"].as_bool(), manifest["files"][1]["checklist"].clone()), (Some(false), json!([])), "no CI runs read, so ci-drills.json maps no rows");

    let o = evidence(&dir, &[], &["drills", "--no-ci", "--repo", "example-org/example-repo", "--record", "machine.log"]);
    assert!(!o.status.success() && text(&o).contains("--no-ci reads only the drill records"), "{}", text(&o));
    let _ = fs::remove_dir_all(&dir);
}
