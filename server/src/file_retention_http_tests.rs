//! Retention for harness session files and teammates' archived work (ADR 0112) on the real
//! router: off unless set; deletes old Claude Code, Codex and Pi sessions but never a
//! running Bot's, nor anything in a HOME a held Bot uses; forgets a saved session whose
//! files went; deletes old archived work unless the owner's Bot is held; audits each pass
//! with its counts and shows it to admins.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::parse;
use crate::*;
use std::path::Path;

const DAY: i64 = 86_400_000;
const A: &str = "0b9d2f6e-3c1a-4e8b-9f00-1a2b3c4d5e6f";
const B: &str = "1c8e3a7f-4d2b-4f9c-8e11-2b3c4d5e6f70";
const C: &str = "2d7f4b80-5e3c-4a0d-9f22-3c4d5e6f7081";
const D: &str = "3e8a5c91-6f4d-4b1e-8a33-4d5e6f708192";

async fn audit(port: u16, admin: &str, action: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", &format!("/api/audit?action={action}"), admin, "").await.1)
}

/// Writes `path` and sets its last change `days` ago.
fn file(path: &Path, days: i64) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "{}\n").unwrap();
    age(path, days);
}

/// Sets `path`'s last change `days` ago: a folder's changes when a file is added to it.
fn age(path: &Path, days: i64) {
    let at = std::time::SystemTime::now() - Duration::from_millis((days * DAY) as u64);
    std::fs::File::open(path).unwrap().set_modified(at).unwrap();
}

#[tokio::test]
async fn off_by_default_keeps_every_file() {
    let (port, app, admin, _) = serve_app().await;
    let home = app.cfg.home.clone().unwrap();
    file(&home.join(format!(".claude/projects/-w/{A}.jsonl")), 400);
    retention::start(app.clone(), retention::Settings::default());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(home.join(format!(".claude/projects/-w/{A}.jsonl")).exists());
    let (code, body) = call(port, "GET", "/api/retention", &admin, "").await;
    let v = parse(&body);
    assert_eq!(code, 200, "{body}");
    for k in ["harnessSessions", "teammateFiles"] {
        assert_eq!((v[k]["retentionDays"].clone(), v[k]["lastPass"].clone()), (Value::Null, Value::Null), "{v}");
    }
    assert!(audit(port, &admin, "harness_sessions.*").await.is_empty() && audit(port, &admin, "teammate_files.*").await.is_empty());
}

#[tokio::test]
async fn turning_them_on_prunes_now_and_records_each_change() {
    let (port, app, admin, _) = serve_app().await;
    let home = app.cfg.home.clone().unwrap();
    let old = home.join(format!(".codex/sessions/2026/01/02/rollout-2026-01-02T03-04-05-{A}.jsonl"));
    file(&old, 40);
    retention::start(app.clone(), retention::Settings { sessions: Some(30), teammate_files: Some(90), ..Default::default() });
    for _ in 0..100 {
        if !old.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!old.exists(), "pruned at start");
    for (action, after) in [("harness_sessions.retention_changed", 30), ("teammate_files.retention_changed", 90)] {
        let changed = audit(port, &admin, action).await;
        assert_eq!((changed.len(), changed[0]["details"]["before"].clone(), changed[0]["details"]["after"].as_u64()), (1, Value::Null, Some(after)), "{changed:?}");
    }
    let pruned = audit(port, &admin, "harness_sessions.pruned").await;
    assert_eq!((pruned[0]["details"]["sessions"].as_u64(), pruned[0]["details"]["files"].as_u64()), (Some(1), Some(1)), "{pruned:?}");
    let (_, body) = call(port, "GET", "/api/retention", &admin, "").await;
    let v = parse(&body);
    assert_eq!((v["harnessSessions"]["retentionDays"].as_u64(), v["teammateFiles"]["retentionDays"].as_u64()), (Some(30), Some(90)), "{v}");
    assert_eq!(v["harnessSessions"]["lastPass"]["sessions"].as_u64(), Some(1), "{v}");
    assert_eq!(v["teammateFiles"]["lastPass"]["deleted"].as_u64(), Some(0), "{v}");

    // The same again is no change; off is.
    retention::start(app.clone(), retention::Settings { sessions: Some(30), teammate_files: Some(90), ..Default::default() });
    retention::start(app.clone(), retention::Settings::default());
    assert_eq!(audit(port, &admin, "harness_sessions.retention_changed").await.len(), 2);
    assert_eq!(audit(port, &admin, "teammate_files.retention_changed").await.len(), 2);
    assert_eq!(app.db.retention_days(file_retention::SESSIONS_KEY), None);
}

#[tokio::test]
async fn a_pass_spares_running_and_held_bots_and_forgets_sessions_that_went() {
    let (port, app, admin, _) = serve_app().await;
    let now = db::now();
    let home = app.cfg.home.clone().unwrap();
    let ada = app.db.create_bot("Ada", "#fff", "waddle", "claude", None, false);
    let run = app.db.create_bot("Runner", "#fff", "waddle", "claude", None, false);
    let pi = app.db.create_bot("Pia", "#fff", "waddle", "pi", None, false);
    app.db.keep_session(&ada.id, A, None);
    app.db.keep_session(&run.id, B, None);
    let proj = home.join(".claude/projects/-work");
    // Ada's saved session, old; Runner's, old but running; one nobody saved, old; one recent.
    file(&proj.join(format!("{A}.jsonl")), 40);
    file(&proj.join(format!("{A}/subagents/agent-1.jsonl")), 40);
    file(&proj.join(format!("{B}.jsonl")), 40);
    file(&proj.join(format!("{C}.jsonl")), 40);
    file(&proj.join(format!("{D}.jsonl")), 2);
    file(&proj.join("memory/MEMORY.md"), 400);
    file(&home.join(format!(".claude/file-history/{A}/v1")), 40);
    for dir in [proj.join(format!("{A}/subagents")), proj.join(A), home.join(format!(".claude/file-history/{A}"))] {
        age(&dir, 40);
    }
    let pi_dir = app.bot_dir(&pi.id).unwrap().join("pi-sessions");
    file(&pi_dir.join(format!("2026-01-02T03-04-05_s-{C}.jsonl")), 40);

    let running = app.using_session_files(&run.id).await;
    let pass = file_retention::prune_sessions(&app, 30, now).await;
    drop(running);
    assert_eq!((pass["sessions"].as_u64(), pass["files"].as_u64(), pass["busyBots"].as_u64(), pass["sessionsForgotten"].as_u64()), (Some(4), Some(5), Some(1), Some(1)), "{pass}");
    assert!(pass["errors"].as_array().unwrap().is_empty(), "{pass}");
    for gone in [format!("{A}.jsonl"), A.to_string(), format!("{C}.jsonl")] {
        assert!(!proj.join(&gone).exists(), "{gone}");
    }
    assert!(!home.join(format!(".claude/file-history/{A}")).exists() && !pi_dir.join(format!("2026-01-02T03-04-05_s-{C}.jsonl")).exists());
    for kept in [format!("{B}.jsonl"), format!("{D}.jsonl"), "memory/MEMORY.md".into()] {
        assert!(proj.join(&kept).exists(), "{kept}");
    }
    assert_eq!(app.db.bot(&ada.id).unwrap().session_id, None, "its next run starts fresh");
    assert_eq!(app.db.bot(&run.id).unwrap().session_id.as_deref(), Some(B));
    let pruned = audit(port, &admin, "harness_sessions.pruned").await;
    assert_eq!((pruned.len(), pruned[0]["actorId"].as_str(), pruned[0]["outcome"].as_str()), (1, Some("retention"), Some("success")), "{pruned:?}");

    // A held Bot runs in this HOME: nothing in it goes, nor in the held Bot's own folder.
    file(&proj.join(format!("{C}.jsonl")), 40);
    file(&pi_dir.join(format!("2026-01-02T03-04-05_s-{C}.jsonl")), 40);
    let (code, body) = call(port, "PUT", &format!("/api/retention/holds/{}", pi.id), &admin, &json!({ "reason": "Legal hold" }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    let pass = file_retention::prune_sessions(&app, 30, now).await;
    assert_eq!((pass["sessions"].as_u64(), pass["heldHomes"].as_u64(), pass["heldBots"].as_u64()), (Some(0), Some(1), Some(1)), "{pass}");
    assert!(proj.join(format!("{C}.jsonl")).exists() && pi_dir.join(format!("2026-01-02T03-04-05_s-{C}.jsonl")).exists());
    // Nor does the harness delete its own: a run there keeps them forever.
    assert_eq!(file_retention::keep_sessions_days(&app, &ada, false, false), Some(retention::MAX_DAYS));
    assert_eq!(audit(port, &admin, "harness_sessions.pruned").await.len(), 1, "a pass that deletes nothing isn't audited");

    // Released, they go, with Runner's now it isn't running.
    assert_eq!(call(port, "DELETE", &format!("/api/retention/holds/{}", pi.id), &admin, "").await.0, 200);
    let pass = file_retention::prune_sessions(&app, 30, now).await;
    assert_eq!((pass["sessions"].as_u64(), pass["sessionsForgotten"].as_u64()), (Some(3), Some(1)), "{pass}");
    assert_eq!(app.db.bot(&run.id).unwrap().session_id, None);
    assert_eq!(file_retention::keep_sessions_days(&app, &ada, false, false), None, "retention is off: the harness's own default");
    app.db.set_retention_days(file_retention::SESSIONS_KEY, Some(30));
    assert_eq!(file_retention::keep_sessions_days(&app, &ada, false, false), Some(30));
}

#[tokio::test]
async fn archived_work_goes_once_old_unless_its_owner_is_held() {
    use crate::acl::Visibility;
    use crate::db::{NewAccountRemoval, NewTeammateCleanup};
    let (port, app, admin, _) = serve_app().await;
    let now = db::now();
    let owner = app.db.create_user(None, Some("own@example.com"), "Own", rbac::Role::Member).unwrap();
    let bot = app.db.create_bot_owned("Shared", "#fff", "waddle", "claude", None, false, &owner.id, Visibility::Shared);
    // Archived on a machine that's gone since: the archive went with it.
    let n = NewTeammateCleanup { machine_id: "m-gone", owner_id: &owner.id, user_id: "u-lee", os_user: "sb-lee", reason: "disabled", files: "archive", grace_days: 0, created_by: None };
    let (machine_row, _) = app.db.teammate_cleanup_queue(&n).unwrap();
    app.db.teammate_cleanup_removed(&machine_row.id, Some("/home/superbot/work/from-teammates/lee-2026-01-02"), None);
    app.db.set_removed_at("teammate_cleanups", &machine_row.id, now - 100 * DAY);
    // Archived on this server, whose per-user accounts are off now: nothing of it is left.
    let removal = |user: &'static str, name: &str, at: i64| {
        let n = NewAccountRemoval { owner_id: &owner.id, user_id: user, account: "sb-t-x", reason: "disabled", files: "archive", grace_days: 0, created_by: None };
        let (r, _) = app.db.account_removal_queue(&n).unwrap();
        app.db.account_removal_removed(&r.id, Some(&format!("/srv/superbot/users/own/workspace/from-teammates/{name}")), None);
        app.db.set_removed_at("account_removals", &r.id, at);
        r.id
    };
    removal("u-max", "max-2026-01-02", now - 100 * DAY);
    let recent = removal("u-neo", "neo-2026-01-02", now - DAY);

    assert_eq!(call(port, "PUT", &format!("/api/retention/holds/{}", bot.id), &admin, &json!({ "reason": "Hold" }).to_string()).await.0, 200);
    let pass = file_retention::prune_teammate_files(&app, 30, now).await;
    assert_eq!((pass["held"].as_u64(), pass["missing"].as_u64(), pass["deleted"].as_u64()), (Some(2), Some(0), Some(0)), "{pass}");
    assert!(audit(port, &admin, "teammate_files.pruned").await.is_empty());

    assert_eq!(call(port, "DELETE", &format!("/api/retention/holds/{}", bot.id), &admin, "").await.0, 200);
    let pass = file_retention::prune_teammate_files(&app, 30, now).await;
    assert_eq!((pass["held"].as_u64(), pass["missing"].as_u64(), pass["errors"].as_array().map(Vec::len)), (Some(0), Some(2), Some(0)), "{pass}");
    let pruned = audit(port, &admin, "teammate_files.pruned").await;
    assert_eq!(pruned[0]["details"]["missing"].as_u64(), Some(2), "{pruned:?}");
    // Each is done once; the recent one waits.
    let left: Vec<String> = app.db.archives_before(now).into_iter().map(|a| a.1).collect();
    assert_eq!(left, [recent], "{left:?}");
    let again = file_retention::prune_teammate_files(&app, 30, now).await;
    assert_eq!(again["missing"].as_u64(), Some(0), "{again}");
}
