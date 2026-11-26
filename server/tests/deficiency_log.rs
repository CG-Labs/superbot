//! ADR 0326: `superbot-evidence deficiencies` on an evidence store of two months' register
//! bundles made by `superbot-evidence register`, the second made after an incident's
//! review was recorded: the log checks with `tar` and `sha256sum -c`, says the overdue
//! review is no longer listed and what still is, keeps a condition that runs on (an
//! unfilled role) as one finding from month to month, names each finding's owners from
//! the readiness checklist, takes control-testing deviations from a results bundle, says
//! with `--since` what changed since the last log, exits 2 while anything is still
//! listed, copies no names or notes, and refuses, writing nothing, a bundle of the wrong
//! kind.

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const PERIOD: [&str; 4] = ["--from", "2026-08-01", "--to", "2026-10-01"];

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-deficiency-log-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn evidence(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superbot-evidence")).current_dir(dir).env_remove("GITHUB_TOKEN").env_remove("GH_TOKEN").args(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn unpack(dir: &Path, tar: &str, prefix: &str) -> PathBuf {
    let out = dir.join(format!("unpacked-{tar}"));
    fs::create_dir_all(&out).unwrap();
    assert!(Command::new("tar").arg("-xf").arg(dir.join(tar)).current_dir(&out).status().unwrap().success(), "any tar reads it");
    let folder = fs::read_dir(&out).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with(prefix)).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

fn json_in(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

fn checklist() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/security/soc2-readiness-checklist.md").to_string_lossy().into_owned()
}

/// The register, with INC-1's review recorded or not.
fn register(reviewed: Option<&str>) -> Value {
    let mut incident = json!({ "id": "INC-1", "detected": "2026-08-05", "triaged": "2026-08-05", "commander": "p-b", "severity": "SEV-2", "closed": "2026-08-06", "notes": "Frank's laptop" });
    if let Some(r) = reviewed {
        incident["reviewed"] = json!(r);
        incident["reviewSha256"] = json!("c".repeat(64));
    }
    json!({
        "superbotRegister": 1,
        "people": [
            { "id": "p-a", "name": "Alice Example", "joined": "2026-01-01" },
            { "id": "p-b", "name": "Bob Example", "joined": "2026-01-01" },
            { "id": "p-c", "name": "Carol Example", "joined": "2026-01-01" },
        ],
        "roles": [
            { "role": "Management", "holder": "p-a", "deputy": "p-b", "from": "2026-01-01" },
            { "role": "Security owner", "holder": "p-b", "deputy": "p-a", "from": "2026-01-01" },
            { "role": "Operator", "holder": "p-c", "deputy": "p-b", "from": "2026-01-01" },
        ],
        "systems": [{ "id": "hosting", "kind": "hosting", "since": "2026-01-01" }],
        "access": [{ "person": "p-c", "system": "hosting", "level": "user", "requested": "2026-08-02", "approved": "2026-08-03", "approvedBy": ["p-b"], "granted": "2026-08-03", "notes": "login carol-gh" }],
        "accessReviews": [{ "system": "hosting", "at": "2026-08-10", "by": "p-b", "listSha256": "a".repeat(64), "mfa": true }],
        "incidents": [incident],
        "changes": [{ "id": "CHG-1", "system": "hosting", "recorded": "2026-08-04", "recordSha256": "b".repeat(64), "approved": "2026-08-04", "approvedBy": "p-a", "made": "2026-08-04", "madeBy": "p-c", "notes": "Ivan's upgrade" }],
    })
}

/// A store with August's register bundle, made before INC-1's review was recorded, and
/// September's, made after.
fn store() -> PathBuf {
    let dir = temp();
    let store = dir.join("store");
    fs::create_dir_all(&store).unwrap();
    for (from, to, reviewed) in [("2026-08-01", "2026-09-01", None), ("2026-09-01", "2026-10-01", Some("2026-09-03"))] {
        fs::write(dir.join("register.json"), serde_json::to_vec_pretty(&register(reviewed)).unwrap()).unwrap();
        let o = evidence(&store, &["register", "../register.json", "--from", from, "--to", to]);
        assert!(o.status.success(), "{}", text(&o));
    }
    dir
}

fn finding<'a>(l: &'a Value, file: &str, exception: &str, item: &str) -> &'a Value {
    l["findings"].as_array().unwrap().iter().find(|f| f["file"] == file && f["exception"] == exception && f["item"] == item).unwrap_or_else(|| panic!("{file} {exception} {item}: {:#}", l["findings"]))
}

#[test]
fn the_log_says_what_is_still_listed_and_what_was_put_right() {
    let dir = store();
    let cl = checklist();
    let o = evidence(&dir, &[&["deficiencies", "store"][..], &PERIOD, &["--checklist", &cl, "-o", "log.tar"]].concat());
    assert_eq!(o.status.code(), Some(2), "findings still listed: {}", text(&o));
    assert!(text(&o).contains("from 2 bundles that check") && text(&o).contains("Still listed by owner:"), "{}", text(&o));
    let folder = unpack(&dir, "log.tar", "superbot-deficiencies-2026-08-01_2026-10-01-");
    let l = json_in(&folder, "deficiencies.json");

    let overdue = finding(&l, "incidents.json", "reviewOverdue", "INC-1");
    assert_eq!((overdue["stillListed"].as_bool(), overdue["lastListed"]["to"].as_str()), (Some(false), Some("2026-09-01")), "the review was recorded: {overdue:#}");
    let late = finding(&l, "incidents.json", "reviewLate", "INC-1");
    assert_eq!(late["stillListed"], true, "it was late, and September's bundle says so");
    assert!(late["owners"].as_array().unwrap().contains(&json!("Security owner")), "{late:#}");

    let unfilled = finding(&l, "roles.json", "roleUnfilled", "Engineering lead");
    assert_eq!((unfilled["stillListed"].as_bool(), unfilled["listedIn"].as_u64()), (Some(true), Some(2)), "one finding from month to month: {unfilled:#}");
    assert_eq!((unfilled["firstListed"]["from"].as_str(), unfilled["lastListed"]["to"].as_str()), (Some("2026-08-01"), Some("2026-10-01")));
    assert_eq!(unfilled["rows"], json!(["CC1.3-1"]));
    assert_eq!(unfilled["owners"], json!(["Management"]));
    assert_eq!(finding(&l, "policies.json", "notApproved", "information-security")["stillListed"], true, "the policies are drafts");

    let s = &l["summary"];
    assert_eq!(s["noLongerListed"], 1, "only the overdue review: {s:#}");
    assert_eq!(s["stillListed"].as_u64(), Some(s["findings"].as_u64().unwrap() - 1));
    assert_eq!(s["storeComplete"], false, "the store has only register bundles");
    let open = l["checklist"]["open"].as_array().unwrap();
    assert!(open.iter().any(|r| r["row"] == "CC4.2-1") && !open.iter().any(|r| r["status"] == "Done"));

    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["product"].as_str()), (Some("deficiency-log"), Some("SuperBot")));
    let md = fs::read_to_string(folder.join("deficiencies.md")).unwrap();
    assert!(md.contains("## Still listed, by owner") && md.contains("### Management") && md.contains("not a SOC 2 opinion"), "{md}");
    let tar = fs::read(dir.join("log.tar")).unwrap();
    for leak in ["Alice Example", "Carol Example", "Frank's laptop", "carol-gh", "Ivan's upgrade"] {
        assert!(!tar.windows(leak.len()).any(|w| w == leak.as_bytes()), "{leak} is in the log");
    }

    let again = evidence(&dir, &[&["deficiencies", "store"][..], &PERIOD, &["--checklist", &cl, "--since", "log.tar", "-o", "again.tar"]].concat());
    assert_eq!(again.status.code(), Some(2), "{}", text(&again));
    let a = json_in(&unpack(&dir, "again.tar", "superbot-deficiencies-"), "deficiencies.json");
    assert_eq!(a["findings"], l["findings"], "the same store, the same findings, with the same ids");
    assert_eq!((a["since"]["new"].as_array().map(Vec::len), a["since"]["noLongerListed"].as_array().map(Vec::len)), (Some(0), Some(0)), "{:#}", a["since"]);
    assert_eq!(a["since"]["stillListed"].as_array().map(Vec::len), s["stillListed"].as_u64().map(|n| n as usize));
}

#[test]
fn control_testing_deviations_are_findings_of_their_rows() {
    let dir = store();
    let o = evidence(&dir, &[&["sample", "store"][..], &PERIOD, &["-o", "samples.tar"]].concat());
    assert!(o.status.success(), "{}", text(&o));
    let s = json_in(&unpack(&dir, "samples.tar", "superbot-samples-"), "samples.json");
    let tested = chrono::Utc::now().date_naive().to_string();
    let mut sheet = String::from("test,item,result,tester,tested_on,reference,notes\n");
    for t in s["tests"].as_array().unwrap() {
        for i in t["sample"].as_array().unwrap() {
            let fail = t["id"] == "production-changes";
            sheet.push_str(&format!("{},{},{},p-b,{tested},{},\"Erin's note\"\n", t["id"].as_str().unwrap(), i["item"].as_str().unwrap(), if fail { "fail" } else { "pass" }, if fail { "TICKET-12" } else { "" }));
        }
    }
    fs::write(dir.join("worksheet.csv"), sheet).unwrap();
    let r = evidence(&dir, &["results", "samples.tar", "worksheet.csv", "-o", "results.tar"]);
    assert_eq!(r.status.code(), Some(2), "{}", text(&r));

    let cl = checklist();
    let o = evidence(&dir, &[&["deficiencies", "store"][..], &PERIOD, &["--checklist", &cl, "--results", "results.tar", "-o", "log.tar"]].concat());
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let l = json_in(&unpack(&dir, "log.tar", "superbot-deficiencies-"), "deficiencies.json");
    let dev = l["findings"].as_array().unwrap().iter().find(|f| f["source"] == "audit-results" && f["exception"] == "deviations").unwrap_or_else(|| panic!("{:#}", l["findings"]));
    let drawn = json_in(&unpack(&dir, "results.tar", "superbot-results-"), "manifest.json")["samples"]["manifestSha256"].as_str().unwrap().to_string();
    let scope = format!("2026-08-01_2026-10-01, samples {}", &drawn[..16]);
    assert_eq!((dev["item"].as_str(), dev["stillListed"].as_bool(), dev["scope"].as_str()), (Some("production-changes CHG-1"), Some(true), Some(scope.as_str())), "{dev:#}");
    assert_eq!((&dev["rows"], &dev["criteria"], &dev["owners"]), (&json!(["CC8.1-2"]), &json!(["CC8.1"]), &json!(["Engineering lead"])), "{dev:#}");
    assert_eq!(l["summary"]["testingDeviations"], 1);
    assert_eq!(l["testing"].as_array().map(Vec::len), Some(1));
    assert!(!fs::read(dir.join("log.tar")).unwrap().windows(5).any(|w| w == b"Erin'"), "the tester's notes stay in the worksheet");

    let before = fs::read_dir(&dir).unwrap().count();
    for bad in [&["--results", "samples.tar"][..], &["--since", "results.tar"], &["--results", "results.tar", "--results", "results.tar"], &["--checklist", "worksheet.csv"]] {
        let o = evidence(&dir, &[&["deficiencies", "store"][..], &PERIOD, bad].concat());
        assert_eq!(o.status.code(), Some(1), "{bad:?}: {}", text(&o));
    }
    assert_eq!(fs::read_dir(&dir).unwrap().count(), before, "nothing written");
}
