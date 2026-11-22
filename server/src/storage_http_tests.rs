//! Storage limits per tier (ADR 0082) on the real router: each user's files are measured
//! on their own, shown against their plan's cap to them and to admins, warned about once a
//! day from 90%, and at the cap new messages and runs are refused in plain words and
//! audited. A tier without a cap never refuses. Nobody else's files count, or show.

use crate::acl::Visibility;
use crate::billing_http_tests::audit;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::tests::{call, serve_app, serve_app_with};
use crate::tiers::Tiers;
use crate::tiers_http_tests::fake_claude;
use crate::users_http_tests::user_with;
use crate::*;

/// Small: 1 MB of storage. Open: no cap.
const TIERS: &str = r#"{
  "default": "small",
  "tiers": [
    { "name": "small", "label": "Small", "routes": [{ "harness": "claude", "model": "claude-haiku-4-5" }], "limits": { "maxStorageMb": 1 } },
    { "name": "open", "label": "Open", "routes": "any" }
  ]
}"#;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
}

async fn world() -> World {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, admin, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    fake_claude(&app);
    World { port, app, admin, a_id, a, b_id, b }
}

async fn set_tier(w: &World, user: &str, tier: Value) {
    let (code, body) = call(w.port, "PATCH", &format!("/api/users/{user}"), &w.admin, &json!({ "tier": tier }).to_string()).await;
    assert_eq!(code, 200, "{body}");
}

/// Puts `bytes` of files in the user's working folder, as their Bots would.
fn fill(app: &App, user: &str, name: &str, bytes: usize) {
    let dir = app.workspace_for(user).unwrap();
    std::fs::write(dir.join(name), vec![b'x'; bytes]).unwrap();
    app.storage.forget(user);
}

async fn get(w: &World, path: &str, who: &str) -> (u16, Value) {
    let (code, body) = call(w.port, "GET", path, who, "").await;
    (code, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// Sends "go" and waits until the run is over and audited, or refused.
async fn go(w: &World, who: &str, bot: &str) {
    let before = audit(w.port, &w.admin, &format!("bot={bot}")).await.len();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    wait_run(w, bot, before).await;
}

async fn wait_run(w: &World, bot: &str, before: usize) {
    for _ in 0..300 {
        let now = audit(w.port, &w.admin, &format!("bot={bot}")).await;
        let done = now.len() > before && now.iter().take(now.len() - before).any(|e| matches!(e["action"].as_str(), Some("bot.run_finished" | "bot.run_refused")));
        if done && !w.app.is_running(bot) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{bot} didn't finish");
}

#[tokio::test]
async fn storage_is_measured_per_user_and_shown_against_the_plan() {
    let w = world().await;
    let app = &w.app;
    fill(app, &w.a_id, "notes.bin", 400_000);
    let data = crate::isolation::user_dir(&app.cfg.data_dir, &w.a_id).unwrap();
    std::fs::write(data.join("extra.bin"), vec![0u8; 100_000]).unwrap();

    // Ada's plan screen: her files and botd's for her, against Small's 1 MB.
    let (code, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!(code, 200, "{plan}");
    let s = &plan["usage"]["storage"];
    let used = s["used"].as_u64().unwrap();
    assert!((500_000..510_000).contains(&used), "{s}");
    assert_eq!((s["files"].as_u64(), s["limit"].as_u64(), s["limitMb"].as_u64()), (Some(400_000), Some(1_000_000), Some(1)), "{s}");
    assert_eq!((s["percent"].as_u64(), s["state"].as_str(), s["warnAt"].as_u64(), s["partial"].as_bool()), (Some(50), Some("ok"), Some(90), Some(false)), "{s}");
    assert_eq!(plan["limits"]["maxStorageMb"], 1);
    let (_, mine) = get(&w, "/api/me/usage", &w.a).await;
    assert_eq!(mine["storage"]["used"].as_u64(), Some(used), "{mine}");
    // No folder names reach anyone.
    assert!(!plan.to_string().contains(&app.cfg.workspace.display().to_string()));

    // Bea's are her own: none of Ada's count, or show, by any route.
    let (_, hers) = get(&w, "/api/me/tier", &w.b).await;
    assert!(hers["usage"]["storage"]["used"].as_u64().unwrap() < 10_000, "{hers}");
    let (_, hers) = get(&w, "/api/me/usage", &w.b).await;
    assert!(hers["storage"]["used"].as_u64().unwrap() < 10_000 && !hers.to_string().contains(&w.a_id), "{hers}");
    for path in [format!("/api/users/{}/usage", w.a_id), "/api/usage".to_string(), format!("/api/users/{}", w.a_id)] {
        assert_eq!(get(&w, &path, &w.b).await.0, 403, "{path}");
    }
    // Only the user's own folders are walked, never another's.
    let f = storage::folders(app, &w.a_id, false);
    let all: Vec<String> = f.files.iter().chain(&f.data).map(|p| p.display().to_string()).collect();
    assert!(all.iter().all(|p| p.contains(&w.a_id)) && !all.iter().any(|p| p.contains(&w.b_id)), "{all:?}");

    // Admins see everyone's, on the usage list and each user.
    let (_, all) = get(&w, "/api/usage", &w.admin).await;
    let row = |id: &str| all["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == id).unwrap().clone();
    assert_eq!(row(&w.a_id)["plan"]["usage"]["storage"]["used"].as_u64(), Some(used));
    assert_eq!(row(&w.a_id)["over"], json!([]));
    let (_, one) = get(&w, &format!("/api/users/{}/usage", w.a_id), &w.admin).await;
    assert_eq!(one["storage"]["used"].as_u64(), Some(used));
    let (_, detail) = get(&w, &format!("/api/users/{}", w.a_id), &w.admin).await;
    assert_eq!(detail["plan"]["usage"]["storage"]["used"].as_u64(), Some(used), "{detail}");
    let (_, list) = get(&w, "/api/users", &w.admin).await;
    let listed = list.as_array().unwrap().iter().find(|u| u["id"] == w.a_id.as_str()).unwrap();
    assert_eq!(listed["plan"]["usage"]["storage"]["used"].as_u64(), Some(used), "{listed}");
}

#[tokio::test]
async fn nearly_full_storage_warns_once_a_day_and_still_runs() {
    let w = world().await;
    let app = &w.app;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    fill(app, &w.a_id, "big.bin", 950_000);
    go(&w, &w.a, &bot.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 1);
    let warned = audit(w.port, &w.admin, "action=usage.storage_warning").await;
    assert_eq!(warned.len(), 1, "{warned:?}");
    let d = &warned[0]["details"];
    assert_eq!((warned[0]["actorId"].as_str(), warned[0]["onBehalfOf"].as_str(), d["limit"].as_u64(), d["warnAt"].as_u64()), (Some("billing"), Some(w.a_id.as_str()), Some(1_000_000), Some(90)), "{d}");
    // The Bot says it in plain words, not as an error, and names no model.
    let notes: Vec<_> = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.text.starts_with("Storage is")).collect();
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].error && notes[0].text.starts_with("Storage is 9") && notes[0].text.contains("of the Small plan's 1 MB"), "{}", notes[0].text);
    assert!(!notes[0].text.contains("claude"));

    // Not again today.
    go(&w, &w.a, &bot.id).await;
    assert_eq!(audit(w.port, &w.admin, "action=usage.storage_warning").await.len(), 1);
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 2);
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!(plan["usage"]["storage"]["state"], "warning");
    // A restarted botd remembers from the audit log: still not again today.
    let fresh = storage::Cache::default();
    assert!(!fresh.first_warning(&app.db, &w.a_id, db::now()));
    assert!(fresh.first_warning(&app.db, &w.b_id, db::now()));
}

#[tokio::test]
async fn a_run_that_waited_is_checked_again_when_its_turn_comes() {
    let w = world().await;
    let app = &w.app;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    crate::slots_http_tests::gated_claude(app, &dir);
    let [x, y] = ["X", "Y"].map(|n| app.db.create_bot_owned(n, "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private).id);
    let before = audit(w.port, &w.admin, &format!("bot={y}")).await.len();
    for b in [&x, &y] {
        let (code, body) = call(w.port, "POST", &format!("/api/bots/{b}/messages"), &w.a, r#"{"text":"go"}"#).await;
        assert_eq!(code, 202, "{body}");
    }
    for _ in 0..400 {
        if app.slots.waiting(&y).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(app.slots.waiting(&y).is_some(), "Y didn't queue");
    // X fills Ada's storage while Y waits, as a run would: nothing tells the cache.
    std::fs::write(app.workspace_for(&w.a_id).unwrap().join("big.bin"), vec![b'x'; 1_200_000]).unwrap();
    std::fs::write(dir.join(format!("go-{x}")), "").unwrap();
    wait_run(&w, &y, before).await;
    let refused = audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={y}")).await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["details"]["reason"], "storage_limit", "{refused:?}");
    assert!(std::fs::read_to_string(dir.join("order")).unwrap().lines().all(|l| l == x), "Y ran");
    // Y's run is given back: only X's counts.
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!(plan["usage"]["runs"], 1, "{plan}");
}

#[tokio::test]
async fn full_storage_refuses_messages_and_runs_in_plain_words() {
    let w = world().await;
    let app = &w.app;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    fill(app, &w.a_id, "big.bin", 1_200_000);

    // A new message is refused before it's taken in, and audited.
    let before = app.db.messages(&bot.id, 50).len();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", bot.id), &w.a, r#"{"text":"go"}"#).await;
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("Storage is full: 1.2 MB used of the Small plan's 1 MB. Delete files from the workspace"), "{body}");
    assert!(!body.contains("claude") && !body.contains(&app.cfg.workspace.display().to_string()), "{body}");
    assert_eq!(app.db.messages(&bot.id, 50).len(), before);
    let refused = audit(w.port, &w.admin, "action=bot.message_refused").await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["owner"].as_str(), d["limit"].as_u64(), d["tier"].as_str()), (Some("storage_limit"), Some(w.a_id.as_str()), Some(1_000_000), Some("small")), "{d}");
    assert!(d["used"].as_u64().unwrap() >= 1_200_000);
    assert_eq!((refused[0]["outcome"].as_str(), refused[0]["actorId"].as_str()), (Some("denied"), Some(w.a_id.as_str())));

    // A refused answer to a choice card leaves the card open, to answer later.
    let card = app.db.add_message(&bot.id, "bot", "Which?", Some(&json!({ "options": ["A", "B"] })), false, None);
    let answer = json!({ "text": "A", "answer": { "messageId": card.id, "option": 0 } }).to_string();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", bot.id), &w.a, &answer).await;
    assert_eq!(code, 403, "{body}");
    assert!(app.db.message(card.id).unwrap().question.unwrap()["picked"].is_null());

    // A routine firing is refused at the run, audited, and the Bot says why.
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "Sum up my email");
    let before = audit(w.port, &w.admin, &format!("bot={}", bot.id)).await.len();
    cron::fire(app, &r, db::now());
    wait_run(&w, &bot.id, before).await;
    let runs = audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    let d = &runs[0]["details"];
    assert_eq!((d["reason"].as_str(), d["limit"].as_u64()), (Some("storage_limit"), Some(1_000_000)), "{d}");
    assert!(d.get("periodEnd").is_none(), "{d}");
    let said: Vec<String> = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.error).map(|m| m.text).collect();
    assert_eq!(said, ["Storage is full: 1.2 MB used of the Small plan's 1 MB, so I didn't run. Delete files from the workspace, or move to a bigger plan, then ask again."]);
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 0);
    // The refused firing doesn't use a routine run.
    assert_eq!(app.db.routine_runs_used(&w.a_id, &tiers::day(db::now())), 0);

    // Admins see Ada over it.
    let (_, all) = get(&w, "/api/usage", &w.admin).await;
    let over = |id: &str| all["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == id).unwrap()["over"].clone();
    assert_eq!(over(&w.a_id), json!(["maxStorageMb"]));
    assert_eq!(over(&w.b_id), json!([]));

    // Bea's storage is her own: her Bot on the same plan still runs.
    let hers = app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    go(&w, &w.b, &hers.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", hers.id)).await.len(), 1);

    // Deleting files frees it again.
    std::fs::remove_file(app.workspace_for(&w.a_id).unwrap().join("big.bin")).unwrap();
    app.storage.forget(&w.a_id);
    go(&w, &w.a, &bot.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 1);
}

#[tokio::test]
async fn a_tier_without_a_cap_never_refuses() {
    let w = world().await;
    let app = &w.app;
    set_tier(&w, &w.a_id, json!("open")).await;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    fill(app, &w.a_id, "big.bin", 1_200_000);
    go(&w, &w.a, &bot.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 1);
    assert!(audit(w.port, &w.admin, "action=usage.storage_warning").await.is_empty());
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    let s = &plan["usage"]["storage"];
    assert!(s["used"].as_u64().unwrap() >= 1_200_000, "{s}");
    assert_eq!((s["limit"].clone(), s["percent"].clone(), s["state"].as_str()), (Value::Null, Value::Null, Some("ok")), "{s}");

    // No tiers file at all: the open self-host tier, as before.
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let dir = app.workspace_for(&a_id).unwrap();
    std::fs::write(dir.join("big.bin"), vec![0u8; 2_000_000]).unwrap();
    let (code, made) = call(port, "POST", "/api/bots", &a, r#"{"name":"Free","harness":"claude"}"#).await;
    assert_eq!(code, 201, "{made}");
    let id = serde_json::from_str::<Value>(&made).unwrap()["id"].as_str().unwrap().to_string();
    assert!(crate::tiers_http_tests::run(port, &app, &a, &id).await.starts_with("model="));
    let (_, plan) = call(port, "GET", "/api/me/tier", &a, "").await;
    let plan: Value = serde_json::from_str(&plan).unwrap();
    assert_eq!((plan["usage"]["storage"]["limit"].clone(), plan["usage"]["storage"]["state"].as_str()), (Value::Null, Some("ok")));
}

/// `world`, with machine routing on for assigned users (ADR 0036), and Ada assigned to a
/// machine of her own. Nothing answers for it: what its agent said is set by hand.
async fn world_on_machine() -> (World, crate::db::Machine) {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let mut cp = ControlPlane::for_tests(p);
    cp.routing = crate::machines::route::Routing::Assigned;
    let cp = Arc::new(cp);
    let (port, app, admin, _) = serve_app_with(move |a| a.machines = cp).await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    fake_claude(&app);
    let new = crate::db::NewMachine { user_id: &a_id, provider: "fake", label_prefix: "superbot", tier: "small", plan: "g6-standard-1", region: "gb-lon", created_by: None };
    let m = app.db.add_machine(&new).unwrap();
    (World { port, app, admin, a_id, a, b_id, b }, m)
}

#[tokio::test]
async fn a_machines_homes_count_instead_of_the_workspace_while_bots_work_there() {
    let (w, m) = world_on_machine().await;
    let app = &w.app;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    // 900 KB in her workspace here, from before she had a machine.
    fill(app, &w.a_id, "old.bin", 900_000);
    let storage = |plan: Value| plan["usage"]["storage"].clone();
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    let s = storage(plan);
    assert!(s["used"].as_u64().unwrap() >= 900_000 && s["onMachine"] == false && s["machine"].is_null(), "{s}");

    // Assigned: her Bots work on the machine, which hasn't said yet what its homes hold.
    // The copy here isn't counted, and the total is only a lower bound.
    assert!(app.db.assign_machine(&m.id, None));
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    let s = storage(plan);
    assert!(s["used"].as_u64().unwrap() < 100_000, "{s}");
    assert_eq!((s["onMachine"].as_bool(), s["files"].clone(), s["partial"].as_bool()), (Some(true), Value::Null, Some(true)), "{s}");
    assert_eq!((s["machine"]["report"].as_str(), s["machine"]["used"].clone(), s["machine"]["measuredAt"].clone()), (Some("missing"), Value::Null, Value::Null), "{s}");

    // Its agent says 400 KB: that counts, fresh.
    app.db.machine_files_seen(&m.id, 400_000, false);
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    let s = storage(plan);
    let used = s["used"].as_u64().unwrap();
    assert!((400_000..500_000).contains(&used), "{s}");
    assert_eq!((s["machine"]["report"].as_str(), s["machine"]["used"].as_u64(), s["partial"].as_bool(), s["state"].as_str()), (Some("fresh"), Some(400_000), Some(false), Some("ok")), "{s}");
    // Bea's machine-less numbers are her own, and Ada's machine shows nowhere of hers.
    let (_, hers) = get(&w, "/api/me/usage", &w.b).await;
    assert!(hers["storage"]["onMachine"] == false && hers["storage"]["machine"].is_null(), "{hers}");

    // 1.2 MB on the machine: full. A message is refused, saying where to delete files.
    app.db.machine_files_seen(&m.id, 1_200_000, false);
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", bot.id), &w.a, r#"{"text":"go"}"#).await;
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("Storage is full: 1.2 MB used of the Small plan's 1 MB. Delete files on the computer this Bot works on"), "{body}");
    let refused = audit(w.port, &w.admin, "action=bot.message_refused").await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["machine"]["report"].as_str(), d["machine"]["used"].as_u64(), d["partial"].as_bool()), (Some("storage_limit"), Some("fresh"), Some(1_200_000), Some(false)), "{d}");

    // A report from long ago (the machine's agent stopped answering) still counts: Bots
    // write there only in runs, and every run starts by reaching it.
    app.db.machine_files_seen_at(&m.id, 1_200_000, false, db::now() - 20 * 60_000);
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "Sum up my email");
    let before = audit(w.port, &w.admin, &format!("bot={}", bot.id)).await.len();
    cron::fire(app, &r, db::now());
    wait_run(&w, &bot.id, before).await;
    let runs = audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    let d = &runs[0]["details"];
    assert_eq!((d["reason"].as_str(), d["machine"]["report"].as_str(), d["used"].as_u64().map(|u| u >= 1_200_000)), (Some("storage_limit"), Some("stale"), Some(true)), "{d}");
    let said: Vec<String> = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.error).map(|m| m.text).collect();
    assert!(said[0].ends_with("Delete files on the computer I work on, or move to a bigger plan, then ask again."), "{said:?}");
    let (_, all) = get(&w, "/api/usage", &w.admin).await;
    let row = all["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == w.a_id.as_str()).unwrap().clone();
    assert_eq!((row["over"].clone(), row["plan"]["usage"]["storage"]["machine"]["report"].as_str()), (json!(["maxStorageMb"]), Some("stale")), "{row}");

    // Operators see how recent the reports storage relies on are.
    let metrics = crate::obs::render(app);
    assert!(metrics.contains(r#"superbot_machine_storage_reports{report="stale"} 1"#), "{metrics}");
    assert!(metrics.contains(r#"superbot_machine_storage_reports{report="missing"} 0"#), "{metrics}");

    // Files deleted on the machine: under the cap, and the message is taken again.
    app.db.machine_files_seen(&m.id, 100_000, false);
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", bot.id), &w.a, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!(storage(plan)["state"], "ok");

    // Unassigned: the Bots work here again, and the workspace here counts again.
    assert!(app.db.unassign_machine(&m.id));
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    let s = storage(plan);
    assert!(s["used"].as_u64().unwrap() >= 900_000 && s["onMachine"] == false && s["files"].as_u64().unwrap() >= 900_000, "{s}");
}

#[tokio::test]
async fn nearly_full_on_a_machine_warns_with_what_the_machine_said() {
    let (w, m) = world_on_machine().await;
    let app = &w.app;
    assert!(app.db.assign_machine(&m.id, None));
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    // A walk on the machine that couldn't read everything: at least 950 KB.
    app.db.machine_files_seen(&m.id, 950_000, true);
    let before = audit(w.port, &w.admin, &format!("bot={}", bot.id)).await.len();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{}/messages", bot.id), &w.a, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    wait_run(&w, &bot.id, before).await;
    let warned = audit(w.port, &w.admin, "action=usage.storage_warning").await;
    assert_eq!(warned.len(), 1, "{warned:?}");
    let d = &warned[0]["details"];
    assert_eq!((d["machine"]["used"].as_u64(), d["machine"]["partial"].as_bool(), d["partial"].as_bool(), d["warnAt"].as_u64()), (Some(950_000), Some(true), Some(true), Some(90)), "{d}");
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!((plan["usage"]["storage"]["state"].as_str(), plan["usage"]["storage"]["partial"].as_bool()), (Some("warning"), Some(true)), "{plan}");
}

/// A stand-in Claude that leaves 2.5 MB in the machine's workspace.
const FILLS_THE_DISK: &str = r#"#!/bin/sh
head -c 2500000 /dev/zero > "$HOME/work/big.bin"
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}'
"#;

/// Heartbeats until the machine's agent has said its homes hold at least `bytes`.
async fn reported(env: &crate::machines_mtls_tests::Env, mid: &str, bytes: u64) {
    for _ in 0..400 {
        let (code, r) = call(env.port, "POST", "/api/machines/reconcile", &env.admin, "").await;
        assert_eq!(code, 200, "{r}");
        if env.app.db.machine(mid).and_then(|m| m.disk_files).is_some_and(|b| b as u64 >= bytes) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the agent never said its homes hold {bytes} bytes");
}

#[tokio::test]
async fn what_a_run_leaves_on_the_machine_counts_before_the_next_one() {
    use crate::machines_mtls_tests::{agent_with, events, json_call, machine_for, serve_with, wait_for_event};
    let mut env = serve_with(|e| e).await;
    // Small: 2 MB.
    let tiers = r#"{ "default": "small", "tiers": [{ "name": "small", "label": "Small", "routes": "any", "limits": { "maxStorageMb": 2 } }] }"#;
    env.app.tiers.set(Arc::new(Tiers::parse(tiers, None).unwrap())).unwrap();
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let m = agent_with(&mut env, &mid, &token, FILLS_THE_DISK).await;
    let bot = env.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &uid, Visibility::Shared);
    // The agent measures its homes off the request path and says so in its heartbeat.
    reported(&env, &mid, 0).await;
    let (_, u) = json_call(&env, "GET", &format!("/api/users/{uid}/usage"), "").await;
    assert_eq!((u["storage"]["onMachine"].as_bool(), u["storage"]["machine"]["report"].as_str(), u["storage"]["state"].as_str()), (Some(true), Some("fresh"), Some("ok")), "{u}");

    // The run leaves 2.5 MB there; its end has the agent measure again, so the next
    // heartbeat says it, and the next message is refused before anything runs.
    crate::machines_mtls_tests::send(&env, &bot.id, "fill it").await;
    wait_for_event(&env, "bot.run_finished").await;
    assert!(m.home.join("work/big.bin").exists());
    reported(&env, &mid, 2_500_000).await;
    let (code, body) = call(env.port, "POST", &format!("/api/bots/{}/messages", bot.id), &env.admin, r#"{"text":"again"}"#).await;
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("Storage is full") && body.contains("Delete files on the computer this Bot works on"), "{body}");
    assert!(!body.contains(&m.home.display().to_string()), "no paths: {body}");
    let refused = events(&env, "bot.message_refused").await;
    assert_eq!(refused[0]["details"]["machine"]["report"], "fresh", "{refused:?}");
    assert_eq!(events(&env, "harness.invoked").await.len(), 1, "nothing more ran");
    let (_, u) = json_call(&env, "GET", &format!("/api/users/{uid}/usage"), "").await;
    assert!(u["storage"]["machine"]["used"].as_u64().unwrap() >= 2_500_000 && u["storage"]["state"] == "over", "{u}");
    m.server.abort();
}
