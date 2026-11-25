//! ADR 0204: `superbot-evidence register` on a register kept for a month, against the real
//! policy files: the bundle checks with `tar`, `sha256sum -c` and `superbot-evidence
//! coverage`, names nobody, flags a policy text changed since its approval and a server
//! excepting a setting no exception approved, and is refused, writing nothing, for a
//! register that doesn't hold together, a baseline from outside the period, or a period
//! longer than a month. ADR 0214: the code of conduct is acknowledged like the other
//! policies, and conduct concerns are checked in `conduct.json`, by id only. ADR 0223:
//! security incidents, breach notices, reviews, actions and tabletops in `incidents.json`.
//! ADR 0231: production access in `access.json`, with a managed server's review matched to
//! the sign-off in its evidence bundle's `access-review.json`. ADR 0241: vulnerabilities
//! found outside the scans and penetration tests in `vulnerabilities.json`. ADR 0270:
//! production and emergency changes in `production-changes.json`.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const PERIOD: [&str; 4] = ["--from", "2026-10-01", "--to", "2026-11-01"];

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-register-evidence-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
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

fn policies() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/security/policies")
}

fn register() -> Value {
    let mut approvals = Vec::new();
    for e in fs::read_dir(policies()).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if name != "README" && path.extension().is_some_and(|x| x == "md") {
            approvals.push(json!({ "policy": name, "sha256": hex(&fs::read(&path).unwrap()), "commit": "abc1234", "approvedBy": "p-a", "approvedAt": "2026-09-01" }));
        }
    }
    let role = |r: &str, h: &str, d: &str| json!({ "role": r, "holder": h, "deputy": d, "from": "2025-12-01" });
    let mut acks = Vec::new();
    let mut training = Vec::new();
    for p in ["p-a", "p-b", "p-c"] {
        for policy in ["information-security", "acceptable-use", "code-of-conduct"] {
            acks.push(json!({ "person": p, "policy": policy, "at": "2026-09-05" }));
        }
        training.push(json!({ "person": p, "course": "security-awareness", "at": "2026-09-05" }));
    }
    json!({
        "superbotRegister": 1,
        "notes": "Kept by the security owner",
        "riskAppetite": 9,
        "people": [
            { "id": "p-a", "name": "Alice Example", "joined": "2025-12-01" },
            { "id": "p-b", "name": "Bob Example", "joined": "2025-12-01" },
            { "id": "p-c", "name": "Carol Example", "joined": "2025-12-01" },
            { "id": "p-d", "name": "Dan Example", "joined": "2025-12-01", "left": "2026-10-15" },
        ],
        "roles": [role("Management", "p-a", "p-b"), role("Security owner", "p-b", "p-a"), role("Engineering lead", "p-c", "p-b"), role("Operator", "p-c", "p-b"), role("People lead", "p-a", "p-b"), role("Privacy lead", "p-b", "p-a")],
        "policyApprovals": approvals,
        "acknowledgements": acks,
        "training": training,
        "risks": [
            { "id": "R-1", "title": "Cross-user data leak", "owner": "Engineering lead", "likelihood": 2, "impact": 5, "treatment": "reduce", "controls": ["CC6.1-1"], "identified": "2026-01-01", "reviewed": ["2026-09-10"] },
            { "id": "R-2", "title": "Signup abuse", "owner": "Management", "likelihood": 3, "impact": 3, "treatment": "accept", "fraud": true, "identified": "2026-01-01", "reviewed": ["2026-09-10"], "acceptedBy": "p-a", "acceptedAt": "2026-09-10", "acceptedUntil": "2027-03-10", "notes": "a private reason" },
        ],
        "riskReviews": [{ "at": "2026-09-10", "by": "p-b" }],
        "managementReviews": [{ "at": "2026-09-15", "attendees": ["p-a", "p-b"], "minutesSha256": hex(b"minutes") }],
        "vendors": [
            { "id": "hosting", "tier": "critical", "hosting": true, "since": "2026-01-01", "assessed": "2025-12-15", "approvedBy": "p-b", "reviewed": ["2026-06-01"] },
            { "id": "code-host", "tier": "high", "since": "2026-01-01", "assessed": "2025-12-15", "approvedBy": "p-b", "reviewed": ["2026-06-01"] },
        ],
        "exceptions": [
            { "id": "EX-1", "policy": "information-security", "setting": "TEAMS", "approvedBy": "p-b", "approvedAt": "2026-09-01", "ends": "2027-03-01", "reviewed": ["2026-10-01"], "notes": "a private reason" },
        ],
        "conductConcerns": [
            { "id": "CC-1", "received": "2026-10-02", "triaged": "2026-10-05", "handledBy": "p-a", "closed": "2026-10-20", "outcome": "substantiated", "notes": "Dave said Erin took a gift" },
            { "id": "CC-2", "received": "2026-10-10" },
        ],
        "breachNoticeHours": 48,
        "incidents": [
            { "id": "INC-1", "detected": "2026-10-05", "triaged": "2026-10-05", "commander": "p-b", "severity": "SEV-4", "closed": "2026-10-06", "notes": "Frank's laptop flagged" },
            {
                "id": "INC-2", "detected": "2026-10-12", "triaged": "2026-10-12", "commander": "p-c", "severity": "SEV-2", "breach": true,
                "awareAt": "2026-10-12T09:30:00Z", "customersNotifiedAt": "2026-10-13T12:00:00Z", "closed": "2026-10-14",
                "notes": "Globex's files were readable",
            },
        ],
        "tabletops": [{ "at": "2026-09-20", "attendees": ["p-a", "p-b", "p-c"], "recordSha256": hex(b"tabletop record"), "actions": [{ "id": "T-1", "owner": "Operator", "due": "2026-12-01" }] }],
        "systems": [
            { "id": "botd-1", "kind": "superbot", "since": "2026-01-01" },
            { "id": "hosting", "kind": "hosting", "since": "2026-01-01" },
            { "id": "code-host", "since": "2026-01-01", "notes": "Initech's GitHub organisation" },
        ],
        "access": [
            { "person": "p-b", "system": "botd-1", "level": "admin", "granted": "2026-01-01" },
            { "person": "p-c", "system": "hosting", "level": "admin", "granted": "2026-01-01" },
            { "person": "p-d", "system": "code-host", "level": "user", "granted": "2026-01-01" },
            { "person": "p-c", "system": "code-host", "level": "user", "requested": "2026-10-02", "approved": "2026-10-03", "approvedBy": ["p-b"], "granted": "2026-10-03", "notes": "login carol-gh" },
        ],
        "accessReviews": [
            { "system": "botd-1", "at": "2026-10-12", "by": "p-b", "listSha256": REPORT, "mfa": true },
            { "system": "hosting", "at": "2026-10-10", "by": "p-b", "listSha256": hex(b"hosting users"), "mfa": true },
            { "system": "code-host", "at": "2026-09-20", "by": "p-b", "listSha256": hex(b"code host users"), "mfa": true },
        ],
        "penTests": [{ "id": "PT-1", "reported": "2026-08-01", "reportSha256": hex(b"pentest report"), "retested": "2026-09-10", "retestSha256": hex(b"retest letter"), "notes": "Hooli's testers" }],
        "vulnerabilities": [
            { "id": "V-1", "source": "report", "received": "2026-10-02", "acknowledged": "2026-10-08", "assessed": "2026-10-06", "severity": "high", "owner": "Engineering lead", "fixed": "2026-10-20", "notes": "Grace found it" },
            { "id": "V-2", "source": "pentest", "penTest": "PT-1", "received": "2026-08-01", "assessed": "2026-08-03", "severity": "critical", "owner": "Engineering lead", "fixed": "2026-08-20" },
            { "id": "V-3", "source": "vendor", "received": "2026-09-15", "assessed": "2026-09-16", "severity": "medium", "owner": "Operator" },
        ],
        "changes": [
            { "id": "CHG-1", "system": "botd-1", "recorded": "2026-10-06", "recordSha256": hex(b"change record"), "approved": "2026-10-06", "approvedBy": "p-a", "made": "2026-10-07", "madeBy": "p-b", "notes": "Ivan's upgrade" },
            {
                "id": "CHG-2", "system": "hosting", "kind": "emergency", "incident": "INC-2", "recorded": "2026-10-13", "recordSha256": hex(b"incident change"),
                "approved": "2026-10-12", "approvedBy": "p-c", "made": "2026-10-12", "madeBy": "p-c", "verified": "2026-10-12", "reviewed": "2026-10-13", "reviewedBy": "p-b",
            },
        ],
    })
}

const REPORT: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// A managed server's evidence bundle `access-review.json`, with one sign-off of `REPORT`.
fn access_review(signed_at: &str) -> Value {
    json!({
        "snapshotAt": "2026-11-01T00:00:00Z", "reportDigest": REPORT, "mfaPolicy": "admins", "summary": {}, "people": [{ "email": "carol@initech.test" }], "serviceAccounts": [], "reviewsSignedOffInPeriod": 1,
        "period": { "counts": {}, "daily": [], "eventsTotal": 1, "eventsListed": 1, "events": [{ "id": 7, "time": signed_at, "action": "access_review.completed", "outcome": "ok", "actor": "u-2", "target": "access-review", "botId": null, "details": { "digest": REPORT } }] },
        "periodCovered": { "from": "2026-10-01", "to": "2026-11-01", "days": 31 },
    })
}

fn baseline(at: &str, excepted: &[&str]) -> Value {
    json!({ "format": 1, "checkedAt": at, "ok": true, "digest": hex(at.as_bytes()), "counts": {}, "settings": [], "exceptions": { "deviations": [], "excepted": excepted, "unknownExceptions": [] } })
}

fn write(dir: &Path, name: &str, v: &Value) {
    fs::write(dir.join(name), serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn unpack(dir: &Path, tar: &Path) -> PathBuf {
    assert!(Command::new("tar").arg("-xf").arg(tar).current_dir(dir).status().unwrap().success(), "any tar reads it");
    let folder = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with("superbot-register-")).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

fn json_in(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

#[test]
fn a_months_register_checks_against_the_real_policies_and_the_coverage_report() {
    let dir = temp();
    write(&dir, "register.json", &register());
    write(&dir, "baseline-a.json", &baseline("2026-10-05T10:00:00Z", &["TEAMS"]));
    write(&dir, "baseline-b.json", &baseline("2026-11-01T00:00:05Z", &["AUTH_MFA"]));
    write(&dir, "access-review.json", &access_review("2026-10-12T15:00:00Z"));
    let pol = policies();
    let o = evidence(&dir, &[&["register", "register.json", "--policies", pol.to_str().unwrap(), "--baseline", "baseline-a.json", "--baseline", "baseline-b.json", "--access-review", "botd-1=access-review.json", "-o", "register.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    for want in [
        "against the policy files given",
        "roles.json: no exceptions; evidence for CC1.3-1",
        "policies.json: no exceptions; evidence for CC3.1-1, CC5.3-1",
        "people.json: no exceptions; evidence for CC1.4-1, CC2.2-1",
        "risks.json: no exceptions; evidence for CC3.2-1, CC3.3-1",
        "management-reviews.json: no exceptions; evidence for CC1.2-1",
        "vendors.json: no exceptions; evidence for CC6.4-1, CC9.2-1",
        "policy-exceptions.json: baselineExceptionNotApproved 1; evidence for CC5.1-1",
        "conduct.json: triagedLate 1; evidence for CC1.1-1",
        "incidents.json: reviewOverdue 1; evidence for CC7.3-1, CC7.4-1, CC7.4-2, CC7.5-1",
        "access.json: leaverNotRemoved 1; evidence for CC6.1-2, CC6.2-2, CC6.3-2",
        "vulnerabilities.json: acknowledgedLate 1; evidence for CC2.3-1, CC3.2-2, CC4.2-1",
        "production-changes.json: notChecked 1; evidence for CC8.1-2",
    ] {
        assert!(out.contains(want), "{want}\n{out}");
    }

    let tar = dir.join("register.tar");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&tar).unwrap().permissions().mode() & 0o777, 0o600, "private to its owner");
    }
    let raw = fs::read(&tar).unwrap();
    for never in ["Alice", "Bob Example", "Cross-user data leak", "Signup abuse", "a private reason", "Kept by the security owner", "Dave", "took a gift", "Frank", "Globex", "Initech", "carol-gh", "initech.test", "Hooli", "Grace", "Ivan"] {
        assert!(!raw.windows(never.len()).any(|w| w == never.as_bytes()), "{never:?} is in the bundle");
    }
    let folder = unpack(&dir, &tar);
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["format"].as_u64(), manifest["source"]["policyTextsChecked"].as_bool(), manifest["source"]["baselineChecks"].as_u64()), (Some("policy-register"), Some(6), Some(true), Some(2)));
    assert_eq!(manifest["source"]["accessReviewFiles"], 1);
    assert_eq!(manifest["source"]["registerSha256"].as_str(), Some(hex(&fs::read(dir.join("register.json")).unwrap()).as_str()), "identifies the register kept beside it");
    let files: Vec<&str> = manifest["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert_eq!(files, ["README.txt", "roles.json", "policies.json", "people.json", "risks.json", "management-reviews.json", "vendors.json", "policy-exceptions.json", "conduct.json", "incidents.json", "access.json", "vulnerabilities.json", "production-changes.json"]);
    let changes = json_in(&folder, "production-changes.json");
    assert_eq!(changes["exceptions"]["notChecked"], json!(["CHG-1 standard on botd-1 (made 2026-10-07, not checked, due 2026-10-08)"]), "{changes:#}");
    assert_eq!((changes["changes"][0]["heldRole"].as_str(), changes["changes"][1]["heldRole"].as_str(), changes["changes"][1]["makerHadAccess"].as_bool()), (Some("Management"), Some("Incident commander"), Some(true)), "{changes:#}");
    assert_eq!(changes["summary"]["madeInPeriodByKind"], json!({ "emergency": 1, "standard": 1 }), "{changes:#}");
    let vulns = json_in(&folder, "vulnerabilities.json");
    assert_eq!(vulns["exceptions"]["acknowledgedLate"], json!(["V-1 (received 2026-10-02, acknowledged 2026-10-08, due 2026-10-05)"]), "{vulns:#}");
    assert_eq!(vulns["vulnerabilities"].as_array().unwrap().iter().map(|v| v["id"].as_str().unwrap()).collect::<Vec<_>>(), ["V-1", "V-3"], "V-2 was finished before the period: {vulns:#}");
    assert_eq!((vulns["penTests"][0]["retestCoversFixes"].as_bool(), vulns["summary"]["openAtEnd"].as_u64(), vulns["informationSecurityPolicy"]["penTestDue"].as_str()), (Some(true), Some(1), Some("2027-09-01")), "{vulns:#}");
    let access = json_in(&folder, "access.json");
    assert_eq!(access["exceptions"]["leaverNotRemoved"], json!(["p-d on code-host (user): left 2026-10-15, not removed"]), "{access:#}");
    let botd = access["reviews"].as_array().unwrap().iter().find(|r| r["system"] == "botd-1").unwrap();
    assert_eq!((botd["signOffChecked"].as_bool(), botd["signedOffAt"].as_str()), (Some(true), Some("2026-10-12T15:00:00Z")), "{access:#}");
    assert_eq!(access["signOffFiles"][0]["system"], "botd-1");
    assert_eq!((access["signOffFiles"][0]["sha256"].as_str(), access["summary"]["grantedInPeriod"].as_u64()), (Some(hex(&fs::read(dir.join("access-review.json")).unwrap()).as_str()), Some(1)), "{access:#}");
    let incidents = json_in(&folder, "incidents.json");
    assert_eq!(incidents["exceptions"]["reviewOverdue"], json!(["INC-2 (closed 2026-10-14, not reviewed, due 2026-10-28)"]), "a possible breach needs a written review: {incidents:#}");
    assert_eq!(incidents["incidents"][1]["noticeDue"], "2026-10-14T09:30:00Z", "{incidents:#}");
    assert_eq!((incidents["summary"]["detectedInPeriodBySeverity"]["SEV-2"].as_u64(), incidents["incidentResponsePlan"]["lastTabletop"].as_str()), (Some(1), Some("2026-09-20")), "{incidents:#}");
    let ex = json_in(&folder, "policy-exceptions.json");
    assert_eq!(ex["exceptions"]["baselineExceptionNotApproved"].as_array().map(Vec::len), Some(1), "{ex:#}");
    assert!(ex["exceptions"]["baselineExceptionNotApproved"][0].as_str().unwrap().contains("AUTH_MFA"), "{ex:#}");
    let conduct = json_in(&folder, "conduct.json");
    assert_eq!(conduct["exceptions"]["triagedLate"], json!(["CC-2 (received 2026-10-10, not triaged, due 2026-10-17)"]), "{conduct:#}");
    assert_eq!((conduct["codeOfConduct"]["acknowledgedWithinAYear"].as_u64(), conduct["summary"]["closedInPeriodByOutcome"]["substantiated"].as_u64()), (Some(3), Some(1)), "{conduct:#}");
    let pols = json_in(&folder, "policies.json");
    assert!(pols["policies"].as_array().unwrap().iter().all(|p| p["textApproved"] == true), "{pols:#}");

    // The coverage report reads it as a fifth kind of bundle.
    let store = dir.join("store");
    fs::create_dir_all(store.join("register/2026-10")).unwrap();
    fs::copy(&tar, store.join("register/2026-10/register.tar")).unwrap();
    let o = evidence(&dir, &[&["coverage", store.to_str().unwrap(), "--json"][..], &PERIOD].concat());
    assert_eq!(o.status.code(), Some(2), "the other kinds are missing: {}", text(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    let kind = r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == "policy-register").unwrap();
    assert_eq!((kind["complete"].as_bool(), r["bundles"][0]["verified"].as_bool()), (Some(true), Some(true)), "{r:#}");
    for row in ["CC1.1-1", "CC1.2-1", "CC1.3-1", "CC3.3-1", "CC6.4-1", "CC9.2-1", "CC7.3-1", "CC7.4-1", "CC7.4-2", "CC7.5-1", "CC6.1-2", "CC6.2-2", "CC6.3-2", "CC2.3-1", "CC3.2-2", "CC4.2-1", "CC8.1-2"] {
        let x = r["rows"].as_array().unwrap().iter().find(|x| x["row"] == row).unwrap_or_else(|| panic!("{row}: {r:#}"));
        assert_eq!(x["complete"], true, "{row}");
    }
    assert_eq!(r["bundles"][0]["exceptions"]["policy-exceptions.json"]["baselineExceptionNotApproved"], 1);
    assert_eq!(r["bundles"][0]["exceptions"]["conduct.json"]["triagedLate"], 1);
    assert_eq!(r["bundles"][0]["exceptions"]["incidents.json"]["reviewOverdue"], 1);
    assert_eq!(r["bundles"][0]["exceptions"]["access.json"]["leaverNotRemoved"], 1);
    assert_eq!(r["bundles"][0]["exceptions"]["vulnerabilities.json"]["acknowledgedLate"], 1);
    assert_eq!(r["bundles"][0]["exceptions"]["production-changes.json"]["notChecked"], 1);

    // A managed server's review with no sign-off that day in botd is flagged.
    write(&dir, "other-day.json", &access_review("2026-10-13T09:00:00Z"));
    let o = evidence(&dir, &[&["register", "register.json", "--access-review", "botd-1=other-day.json", "-o", "other-day.tar"][..], &PERIOD].concat());
    assert!(o.status.success() && text(&o).contains("access.json: leaverNotRemoved 1, signOffNotFound 1"), "{}", text(&o));

    // A policy changed since its approval is flagged; the same command never writes over a file.
    let changed = dir.join("policies");
    fs::create_dir_all(&changed).unwrap();
    for e in fs::read_dir(&pol).unwrap() {
        let p = e.unwrap().path();
        fs::copy(&p, changed.join(p.file_name().unwrap())).unwrap();
    }
    let ac = changed.join("access-control.md");
    fs::write(&ac, fs::read_to_string(&ac).unwrap() + "\nA change after approval.\n").unwrap();
    let o = evidence(&dir, &[&["register", "register.json", "--policies", changed.to_str().unwrap(), "-o", "changed.tar"][..], &PERIOD].concat());
    assert!(o.status.success() && text(&o).contains("policies.json: changedSinceApproval 1"), "{}", text(&o));
    let o = evidence(&dir, &[&["register", "register.json", "-o", "register.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("register.tar"), "never over an existing file: {}", text(&o));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_register_that_doesnt_hold_together_or_a_baseline_from_another_month_writes_nothing() {
    let dir = temp();
    let mut bad = register();
    bad["roles"][0]["holder"] = json!("p-nobody");
    bad["people"][2]["id"] = json!("carol@example.com");
    write(&dir, "bad.json", &bad);
    let o = evidence(&dir, &[&["register", "bad.json", "-o", "out.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(out.contains("names p-nobody, who isn't in people") && out.contains("carol@example.com isn't plain"), "every problem is listed: {out}");
    assert!(!dir.join("out.tar").exists());

    write(&dir, "register.json", &register());
    write(&dir, "old.json", &baseline("2026-11-08T00:00:00Z", &[]));
    let o = evidence(&dir, &[&["register", "register.json", "--baseline", "old.json", "-o", "out.tar"][..], &PERIOD].concat());
    assert!(o.status.code() == Some(1) && text(&o).contains("outside the period"), "{}", text(&o));
    assert!(!dir.join("out.tar").exists());

    write(&dir, "not-access-review.json", &json!({ "format": 1 }));
    let o = evidence(&dir, &[&["register", "register.json", "--access-review", "botd-1=not-access-review.json", "-o", "out.tar"][..], &PERIOD].concat());
    assert!(o.status.code() == Some(1) && text(&o).contains("has no snapshotAt or reportDigest"), "{}", text(&o));
    assert!(!dir.join("out.tar").exists());
    write(&dir, "access-review.json", &access_review("2026-10-12T15:00:00Z"));
    let o = evidence(&dir, &[&["register", "register.json", "--access-review", "botd-1=access-review.json", "--access-review", "botd-1=access-review.json", "-o", "out.tar"][..], &PERIOD].concat());
    assert!(o.status.code() == Some(1) && text(&o).contains("same file as another --access-review"), "{}", text(&o));
    assert!(!dir.join("out.tar").exists());
    for (given, want) in [("access-review.json", "give --access-review <system>=<file>"), ("hosting=access-review.json", "hosting isn't a system of kind superbot"), ("botd-9=access-review.json", "botd-9 isn't a system of kind superbot")] {
        let o = evidence(&dir, &[&["register", "register.json", "--access-review", given, "-o", "out.tar"][..], &PERIOD].concat());
        assert!(o.status.code() == Some(1) && text(&o).contains(want), "{given}: {}", text(&o));
        assert!(!dir.join("out.tar").exists());
    }

    let o = evidence(&dir, &["register", "register.json", "--from", "2026-05-01", "--to", "2026-11-01", "-o", "out.tar"]);
    assert!(o.status.code() == Some(1) && text(&o).contains("one month at most"), "a late record can't cover earlier months: {}", text(&o));
    assert!(!dir.join("out.tar").exists());

    let o = evidence(&dir, &[&["register", "register.json", "-o", "out.tar"][..], &PERIOD].concat());
    assert!(o.status.success() && text(&o).contains("without the policy files"), "{}", text(&o));
    let _ = fs::remove_dir_all(&dir);
}
