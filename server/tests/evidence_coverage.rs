//! ADR 0166: `superbot-evidence coverage` over an evidence store holding the real botd's
//! evidence bundles, one kept as its tar and one unpacked, in the evidence plan's
//! per-criterion, per-month folders. Both check against the digests botd recorded; the
//! kinds of bundle that aren't there are reported day by day; a file changed after the
//! bundle was made fails it and opens a gap; the store is never written to, a report is
//! saved private and never over a file, and the exit code says whether it is complete.

use chrono::{Datelike, NaiveDate};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

struct Botd {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(dir: &Path) -> Botd {
    let port = free_port();
    for d in ["data", "workspace", "home"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let child = Command::new(env!("CARGO_BIN_EXE_botd"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .stdin(Stdio::null())
        .spawn()
        .expect("start botd");
    let b = Botd { child, port, dir: dir.to_path_buf() };
    let t = Instant::now();
    while get(b.port, "/healthz").0 != 200 {
        assert!(t.elapsed() < Duration::from_secs(30), "botd didn't start");
        std::thread::sleep(Duration::from_millis(50));
    }
    b
}

/// One GET as the break-glass operator: status, headers and the body's bytes.
fn get(port: u16, path: &str) -> (u16, String, Vec<u8>) {
    use base64::Engine;
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return (0, String::new(), Vec::new()) };
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("e2e:{PASSWORD}"));
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {auth}\r\n\r\n").as_bytes()).unwrap();
    let mut res = Vec::new();
    let _ = s.read_to_end(&mut res);
    let split = res.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(res.len());
    let head = String::from_utf8_lossy(&res[..split]).to_string();
    let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, head, res.get(split + 4..).unwrap_or_default().to_vec())
}

fn header(head: &str, name: &str) -> String {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())).unwrap_or_default()
}

fn coverage(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superbot-evidence")).arg("coverage").args(args).output().unwrap()
}

fn report(args: &[&str]) -> (Option<i32>, Value) {
    let out = coverage(args);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
    (out.status.code(), v)
}

fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        if e.path().is_dir() {
            out.extend(listing(&e.path()));
        } else {
            out.push((e.path().display().to_string(), std::fs::read(e.path()).unwrap()));
        }
    }
    out.sort();
    out
}

fn first_of_month(d: NaiveDate) -> NaiveDate {
    d.with_day(1).unwrap()
}

#[test]
fn coverage_checks_botds_bundles_and_finds_each_missing_day() {
    let root = std::env::temp_dir().join(format!("evidence-coverage-{}-{}", std::process::id(), free_port()));
    let b = start(&root.join("botd"));
    let m0 = first_of_month(chrono::Utc::now().date_naive());
    let m1 = first_of_month(m0.pred_opt().unwrap());
    let m2 = first_of_month(m1.pred_opt().unwrap());
    let store = root.join("store");

    // Two months of botd's bundles: the first kept as its tar, the second unpacked.
    let mut manifests = Vec::new();
    for (i, (from, to)) in [(m2, m1), (m1, m0)].into_iter().enumerate() {
        let (code, head, tar) = get(b.port, &format!("/api/evidence/bundle?from={from}&to={to}"));
        assert_eq!(code, 200, "{head}");
        manifests.push(header(&head, "x-evidence-manifest-sha256"));
        let name = String::from_utf8_lossy(&tar[..100]).trim_end_matches('\0').split('/').next().unwrap().to_string();
        let folder = store.join("CC6.3").join(from.format("%Y-%m").to_string());
        std::fs::create_dir_all(&folder).unwrap();
        let file = folder.join(format!("{name}.tar"));
        std::fs::write(&file, &tar).unwrap();
        if i == 1 {
            assert!(Command::new("tar").arg("-xf").arg(&file).current_dir(&folder).status().unwrap().success());
            std::fs::remove_file(&file).unwrap();
        }
    }
    std::fs::write(store.join("notes.txt"), "kept by hand").unwrap();
    std::fs::write(store.join(".superbot-evidence-partial.tar"), "half written").unwrap();
    let before = listing(&store);

    let checklist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/security/soc2-readiness-checklist.md");
    let (s, checklist) = (store.to_str().unwrap(), checklist.to_str().unwrap());
    let (from, to) = (m2.to_string(), m0.to_string());
    let (code, r) = report(&[s, "--from", &from, "--to", &to, "--json", "--checklist", checklist]);
    assert_eq!(code, Some(2), "{r:#}");
    assert_eq!((r["summary"]["bundles"].as_u64(), r["summary"]["verified"].as_u64(), r["summary"]["failed"].as_u64()), (Some(2), Some(2), Some(0)), "{r:#}");
    let got: Vec<&str> = r["bundles"].as_array().unwrap().iter().filter_map(|b| b["manifestSha256"].as_str()).collect();
    assert_eq!(got, manifests.iter().map(String::as_str).collect::<Vec<_>>(), "each manifest's digest is the one botd recorded");
    assert!(r["bundles"][0]["path"].as_str().unwrap().ends_with(".tar"));
    assert!(r["bundles"][1]["path"].as_str().unwrap().starts_with(&format!("CC6.3/{}/superbot-evidence-", m1.format("%Y-%m"))), "{r:#}");
    let kind = |r: &Value, id: &str| r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == id).unwrap().clone();
    assert_eq!(kind(&r, "evidence")["complete"], true, "{r:#}");
    let days = (m0 - m2).num_days();
    for id in ["change-management", "vulnerability-management"] {
        assert_eq!(kind(&r, id)["coveredDays"], 0);
        assert!(r["problems"].as_array().unwrap().iter().any(|p| p.as_str().unwrap().contains(&format!("covers {m2} to {m0} ({days} days)"))), "{r:#}");
    }
    assert_eq!(r["problems"].as_array().unwrap().len(), 2, "{r:#}");
    let row = |r: &Value, id: &str| r["rows"].as_array().unwrap().iter().find(|x| x["row"] == id).unwrap().clone();
    assert_eq!(row(&r, "CC6.3-1")["complete"], true);
    assert_eq!(row(&r, "CC8.1-1")["coveredDays"], 0);
    assert!(r["checklist"]["noAutomatedEvidence"].as_array().unwrap().iter().any(|x| x["row"] == "CC1.1-1"));
    assert_eq!(listing(&store), before, "the store isn't written to");

    // A file changed after the bundle was made fails it and opens a gap.
    let unpacked = std::fs::read_dir(store.join("CC6.3").join(m1.format("%Y-%m").to_string())).unwrap().next().unwrap().unwrap().path();
    let mut f = std::fs::OpenOptions::new().append(true).open(unpacked.join("access-review.json")).unwrap();
    f.write_all(b" ").unwrap();
    let (code, r) = report(&[s, "--from", &from, "--to", &to, "--json"]);
    assert_eq!(code, Some(2));
    assert_eq!(r["summary"]["failed"], 1);
    assert!(r["problems"].as_array().unwrap().iter().any(|p| p.as_str().unwrap().contains("access-review.json doesn't match its SHA-256 in SHA256SUMS")), "{r:#}");
    assert_eq!(kind(&r, "evidence")["gaps"], serde_json::json!([{ "from": m1.to_string(), "to": m0.to_string(), "days": (m0 - m1).num_days() }]));

    // With neither date, the period runs from the first bundle that checks to the last.
    let (_, r) = report(&[s, "--json"]);
    assert_eq!((r["period"]["from"].as_str(), r["period"]["to"].as_str()), (Some(from.as_str()), Some(m1.to_string().as_str())));

    // Markdown, saved private, never over a file.
    let out = root.join("coverage.md");
    let o = coverage(&[s, "--from", &from, "--to", &to, "-o", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    let said = String::from_utf8_lossy(&o.stdout);
    assert!(said.contains("SHA-256: ") && said.contains("problems"), "{said}");
    let md = std::fs::read_to_string(&out).unwrap();
    assert!(md.starts_with(&format!("# SOC 2 evidence coverage, {m2} to {m0}")) && md.contains("**Not complete:**") && md.contains("| Row | Bundles | Days covered | Gaps |"), "{md}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let again = coverage(&[s, "-o", out.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), md);

    let missing = coverage(&[root.join("nowhere").to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("isn't a folder"));
    drop(b);
    let _ = std::fs::remove_dir_all(&root);
}
