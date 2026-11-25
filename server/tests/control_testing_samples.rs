//! ADR 0296: `superbot-evidence sample` on an evidence store of two months' register
//! bundles made by `superbot-evidence register`: the samples bundle checks with `tar` and
//! `sha256sum -c`, draws the same items each time from the same store, re-performably by
//! SHA-256, says which populations the store can't make complete, and copies no names or
//! notes. `superbot-evidence results` checks a filled-in worksheet against it, writes the
//! deviations without the tester's notes, exits 2 while anything deviated or a population
//! was incomplete, and refuses, writing nothing, a worksheet with items it didn't draw or
//! a samples bundle changed since it was made.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const PERIOD: [&str; 4] = ["--from", "2026-08-01", "--to", "2026-10-01"];

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-control-testing-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
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

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn unpack(dir: &Path, tar: &Path, prefix: &str) -> PathBuf {
    let out = dir.join(format!("unpacked-{}", tar.file_stem().unwrap().to_string_lossy()));
    fs::create_dir_all(&out).unwrap();
    assert!(Command::new("tar").arg("-xf").arg(tar).current_dir(&out).status().unwrap().success(), "any tar reads it");
    let folder = fs::read_dir(&out).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with(prefix)).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

fn json_in(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

fn test<'a>(samples: &'a Value, id: &str) -> &'a Value {
    samples["tests"].as_array().unwrap().iter().find(|t| t["id"] == id).unwrap_or_else(|| panic!("{id}"))
}

fn register() -> Value {
    let changes: Vec<Value> = (1..=14)
        .map(|n| {
            let day = format!("2026-{:02}-{:02}", if n <= 7 { 8 } else { 9 }, (n - 1) % 7 * 4 + 2);
            json!({ "id": format!("CHG-{n}"), "system": "hosting", "recorded": day, "recordSha256": hex(format!("change {n}").as_bytes()), "approved": day, "approvedBy": "p-a", "made": day, "madeBy": "p-c", "notes": "Ivan's upgrade" })
        })
        .collect();
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
        "accessReviews": [{ "system": "hosting", "at": "2026-08-10", "by": "p-b", "listSha256": hex(b"hosting users"), "mfa": true }],
        "incidents": [{ "id": "INC-1", "detected": "2026-09-05", "triaged": "2026-09-05", "commander": "p-b", "severity": "SEV-4", "closed": "2026-09-06", "notes": "Frank's laptop flagged" }],
        "changes": changes,
    })
}

/// A store of August's and September's register bundles, beside the register.
fn store() -> PathBuf {
    let dir = temp();
    fs::write(dir.join("register.json"), serde_json::to_vec_pretty(&register()).unwrap()).unwrap();
    let store = dir.join("store");
    fs::create_dir_all(&store).unwrap();
    for (from, to) in [("2026-08-01", "2026-09-01"), ("2026-09-01", "2026-10-01")] {
        let o = evidence(&store, &["register", "../register.json", "--from", from, "--to", to]);
        assert!(o.status.success(), "{}", text(&o));
    }
    dir
}

fn tested_today() -> String {
    chrono::Utc::now().date_naive().to_string()
}

#[test]
fn samples_drawn_from_the_store_the_same_way_each_time() {
    let dir = store();
    let one = evidence(&dir, &[&["sample", "store"][..], &PERIOD, &["-o", "one.tar"]].concat());
    assert!(one.status.success(), "{}", text(&one));
    assert!(text(&one).contains("production-changes: 5 of 14") && text(&one).contains("merged-pull-requests: 0 of 0 (incomplete"), "{}", text(&one));
    let two = evidence(&dir, &[&["sample", "store"][..], &PERIOD, &["-o", "two.tar"]].concat());
    assert!(two.status.success(), "{}", text(&two));
    let (a, b) = (unpack(&dir, &dir.join("one.tar"), "superbot-samples-2026-08-01_2026-10-01-"), unpack(&dir, &dir.join("two.tar"), "superbot-samples-2026-08-01_2026-10-01-"));
    assert_eq!(fs::read(a.join("samples.json")).unwrap(), fs::read(b.join("samples.json")).unwrap(), "the same store, the same samples");
    assert_eq!(fs::read(a.join("worksheet.csv")).unwrap(), fs::read(b.join("worksheet.csv")).unwrap());

    let s = json_in(&a, "samples.json");
    assert_eq!(s["seedFrom"], "store");
    let changes = test(&s, "production-changes");
    assert_eq!((changes["population"]["size"].as_u64(), changes["population"]["complete"].as_bool(), changes["population"]["bundles"].as_array().map(Vec::len)), (Some(14), Some(true), Some(2)));
    let seed = s["seed"].as_str().unwrap();
    let mut ranked: Vec<(String, String)> = (1..=14).map(|n| (hex(format!("{seed}\nproduction-changes\nCHG-{n}\n").as_bytes()), format!("CHG-{n}"))).collect();
    ranked.sort();
    let drawn: Vec<&str> = changes["sample"].as_array().unwrap().iter().map(|i| i["item"].as_str().unwrap()).collect();
    assert_eq!(drawn, ranked[..5].iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(), "re-performed from the seed alone");
    assert_eq!(test(&s, "security-events")["sample"][0]["item"], "INC-1");
    assert_eq!(test(&s, "access-grants")["sample"][0]["item"], "p-c/hosting/user/2026-08-03");
    let incomplete = s["summary"]["populationsIncomplete"].as_array().unwrap();
    assert!(incomplete.contains(&json!("merged-pull-requests")) && incomplete.contains(&json!("backup-days")) && !incomplete.contains(&json!("production-changes")));

    let manifest = json_in(&a, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["product"].as_str()), (Some("audit-samples"), Some("SuperBot")));
    let tar = fs::read(dir.join("one.tar")).unwrap();
    for leak in ["Alice Example", "Carol Example", "Ivan's upgrade", "carol-gh", "Frank's laptop"] {
        assert!(!tar.windows(leak.len()).any(|w| w == leak.as_bytes()), "{leak} is in the samples bundle");
    }

    let given = evidence(&dir, &[&["sample", "store"][..], &PERIOD, &["--seed", "auditor-2026", "--size", "production-changes=14", "-o", "given.tar"]].concat());
    assert!(given.status.success(), "{}", text(&given));
    let g = json_in(&unpack(&dir, &dir.join("given.tar"), "superbot-samples-"), "samples.json");
    assert_eq!((g["seed"].as_str(), g["seedFrom"].as_str(), test(&g, "production-changes")["sampleSize"].as_u64()), (Some("auditor-2026"), Some("given"), Some(14)));
    for bad in [&["sample", "store", "--size", "nonsense=3"][..], &["sample", "store", "--seed", "two words"], &["sample"]] {
        let o = evidence(&dir, bad);
        assert_eq!(o.status.code(), Some(1), "{bad:?}: {}", text(&o));
    }
}

#[test]
fn results_from_the_filled_in_worksheet() {
    let dir = store();
    let o = evidence(&dir, &[&["sample", "store"][..], &PERIOD, &["-o", "samples.tar"]].concat());
    assert!(o.status.success(), "{}", text(&o));
    let s = json_in(&unpack(&dir, &dir.join("samples.tar"), "superbot-samples-"), "samples.json");
    let items: Vec<(String, String)> = s["tests"].as_array().unwrap().iter().flat_map(|t| t["sample"].as_array().unwrap().iter().map(move |i| (t["id"].as_str().unwrap().to_string(), i["item"].as_str().unwrap().to_string()))).collect();
    assert_eq!(items.len(), 8, "5 changes, a grant, a review and an event");
    let today = tested_today();
    let mut sheet = String::from("test,item,result,tester,tested_on,reference,notes\n");
    for (n, (t, i)) in items.iter().enumerate() {
        let (result, reference) = if n == 0 { ("fail", "TICKET-12") } else { ("pass", "") };
        sheet.push_str(&format!("{t},{i},{result},p-b,{today},{reference},\"Erin's note, private\"\n"));
    }
    fs::write(dir.join("worksheet.csv"), &sheet).unwrap();
    let r = evidence(&dir, &["results", "samples.tar", "worksheet.csv", "-o", "results.tar"]);
    assert_eq!(r.status.code(), Some(2), "a deviation and incomplete populations: {}", text(&r));
    assert!(text(&r).contains("8 of 8 items tested by 1 testers, 1 deviations, 0 not tested"), "{}", text(&r));
    let folder = unpack(&dir, &dir.join("results.tar"), "superbot-results-2026-08-01_2026-10-01-");
    let res = json_in(&folder, "results.json");
    assert_eq!(res["exceptions"]["deviations"], json!([format!("{} {}", items[0].0, items[0].1)]));
    assert!(res["exceptions"]["deviationsWithoutReference"].as_array().unwrap().is_empty());
    assert!(res["exceptions"]["populationsIncomplete"].as_array().unwrap().contains(&json!("merged-pull-requests")));
    assert_eq!(json_in(&folder, "manifest.json")["kind"], "audit-results");
    let tar = fs::read(dir.join("results.tar")).unwrap();
    assert!(!tar.windows(5).any(|w| w == b"Erin'"), "the tester's notes stay in the worksheet");
    assert!(String::from_utf8_lossy(&tar).contains(&hex(sheet.as_bytes())), "the worksheet is recorded by SHA-256");

    let before = fs::read_dir(&dir).unwrap().count();
    fs::write(dir.join("wrong.csv"), format!("test,item,result,tester,tested_on\nproduction-changes,CHG-99,pass,p-b,{today}\n")).unwrap();
    let wrong = evidence(&dir, &["results", "samples.tar", "wrong.csv"]);
    assert_eq!(wrong.status.code(), Some(1), "{}", text(&wrong));
    assert!(text(&wrong).contains("wasn't drawn"), "{}", text(&wrong));

    let changed = unpack(&dir, &dir.join("samples.tar"), "superbot-samples-");
    let mut v = json_in(&changed, "samples.json");
    v["seed"] = json!("chosen");
    fs::write(changed.join("samples.json"), serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let tampered = evidence(&dir, &["results", changed.to_str().unwrap(), "worksheet.csv"]);
    assert_eq!(tampered.status.code(), Some(1), "{}", text(&tampered));
    assert!(text(&tampered).contains("doesn't check"), "{}", text(&tampered));
    assert_eq!(fs::read_dir(&dir).unwrap().count(), before + 1, "only wrong.csv was added: nothing written");
}
