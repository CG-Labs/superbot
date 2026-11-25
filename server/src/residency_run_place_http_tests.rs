//! Runs held to a pin's region by where they run (ADR 0267), on the real router: a
//! pinned person's run on botd's own server runs only when the operator states botd is in
//! their region, and a run on its owner's machine only when that machine is in the region
//! of everyone it carries. Otherwise it is refused, audited and not counted, and admins,
//! the residency report and the app say so. No model provider is called.

use crate::acl::Visibility;
use crate::db::PinOn;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::residency::{self, RunsOn};
use crate::machines::route::recording::{self, Recording};
use crate::machines::route::{MachineLink, Routing};
use crate::machines::server_data::ServerData;
use crate::tests::{audit_list, call, serve_app_with};
use crate::tiers::Tiers;
use crate::users_http_tests::user_with;
use crate::*;

const KEY: &str = "RUN_PLACE_E2E_EU_KEY";

/// Claude Code's only route goes to an endpoint in both regions, so the model route never
/// decides here: only where the run takes place does.
fn tiers() -> Tiers {
    let raw = json!({
        "providers": { "eu-claude": { "protocol": "anthropic-messages", "baseUrl": "https://eu.claude.example", "keySecret": KEY, "regions": ["gb-lon", "de-fra-2"] } },
        "tiers": [{ "name": "pro", "label": "Pro", "routes": [{ "harness": "claude", "provider": "eu-claude", "model": "claude-sonnet-5-5" }] }],
    });
    Tiers::parse(&raw.to_string(), None).unwrap()
}

fn stand_in_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let script = r#"#!/bin/sh
[ "$1" = --version ] && { echo "2.1.329 (Claude Code)"; exit 0; }
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"ran here"}]}}\n'
"#;
    let path = app.cfg.bin_dir.join("claude");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn audit(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// Sends "go" to `bot` as `who`. The id of the last message before it.
async fn send(port: u16, app: &App, who: &str, bot: &str) -> i64 {
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    before
}

async fn reply_after(app: &App, bot: &str, before: i64) -> String {
    for _ in 0..300 {
        if let Some(m) = app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

async fn run(port: u16, app: &App, who: &str, bot: &str) -> String {
    let before = send(port, app, who, bot).await;
    reply_after(app, bot, before).await
}

fn fake() -> Arc<dyn MachineProvider> {
    Arc::new(Fake::default())
}

#[tokio::test]
async fn a_pinned_persons_runs_stay_off_botds_server_unless_it_is_in_their_region() {
    let (port, app, owner, _) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(fake());
        cp.server_data = ServerData { region: Some("gb-lon".into()), ..ServerData::default() };
        a.machines = Arc::new(cp);
    })
    .await;
    let cp = app.control_plane.get().unwrap().clone();
    assert_eq!(cp.routing, Routing::Off, "every Bot runs on botd's own server");
    app.tiers.set(Arc::new(tiers())).unwrap();
    crate::secrets::global().put(KEY, "sk-eu-not-real").unwrap();
    stand_in_claude(&app);
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    let runs = || async { serde_json::from_str::<Value>(&call(port, "GET", "/api/me/tier", &ada, "").await.1).unwrap()["usage"]["runs"].as_u64() };

    // Unpinned, and pinned to botd's own region: it runs here, as before.
    assert_eq!(run(port, &app, &ada, &bot.id).await, "ran here");
    app.db.pin_residency(PinOn::User, &ada_id, "gb-lon", "DPA-7", None).unwrap();
    assert_eq!(run(port, &app, &ada, &bot.id).await, "ran here");
    assert!(residency::warnings(&app, &cp).iter().all(|w| !w.contains("ADR 0267")), "nothing to warn about while botd is in the region");

    // Pinned to Frankfurt: botd's server is in London, so nothing runs; audited, not counted.
    app.db.pin_residency(PinOn::User, &ada_id, "de-fra-2", "DPA-8", None).unwrap();
    let before = runs().await;
    let said = run(port, &app, &ada, &bot.id).await;
    assert!(said.contains("pinned to de-fra-2") && said.contains("I run on this server, which isn't in de-fra-2") && said.contains("give you a computer in de-fra-2"), "{said}");
    assert!(!said.contains("DPA-8") && !said.contains("gb-lon"), "no reference or botd's region in the chat: {said}");
    assert_eq!(runs().await, before, "a refused run isn't counted");
    let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), refused[0]["outcome"].as_str(), d["action"].as_str()), (Some("residency_pinned"), Some("denied"), Some("run on botd's server")), "{d}");
    assert_eq!((d["runsOn"].as_str(), d["serverDataRegion"].as_str(), d["machine"].clone()), (Some("server"), Some("gb-lon"), Value::Null), "{d}");
    assert_eq!((d["pinnedRegions"].clone(), d["pins"][0]["reference"].as_str(), d["people"].clone()), (json!(["de-fra-2"]), Some("DPA-8"), json!([ada_id])), "{d}");
    assert_eq!(d["error"].as_str(), Some("de-fra-2: botd's own server is in gb-lon"), "{d}");
    assert_eq!(audit(port, &admin, &format!("action=harness.invoked&bot={}", bot.id)).await.len(), 2, "it didn't start");

    // Admins are warned; the report and the app say where the Bots run and that it's refused.
    let warnings = residency::warnings(&app, &cp);
    let w = warnings.iter().find(|w| w.contains("ADR 0267")).unwrap_or_else(|| panic!("{warnings:?}"));
    assert!(w.contains("pinned to de-fra-2 (DPA-8)") && w.contains("Bots run on botd's own server, and botd's own server is in gb-lon") && w.contains("MACHINE_ROUTING"), "{w}");
    let pin = app.db.residency_pin(PinOn::User, &ada_id).unwrap();
    let r = crate::machines::residency_report::build(&app, &cp, &pin, 0, db::now() + 1, db::now(), false).unwrap();
    assert_eq!(r["people"][0]["runs"], json!({ "on": "server", "inRegion": false }), "{r}");
    assert!(r["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("Bots run on botd's own server") && w.as_str().unwrap().contains("ADR 0267")), "{r}");
    let kinds: Vec<&str> = r["activity"]["refusals"].as_array().unwrap().iter().filter_map(|e| e["kind"].as_str()).collect();
    assert!(kinds.contains(&"run on botd's server"), "{r}");
    assert!(crate::machines::residency_report::markdown(&r).contains("| botd's server, outside (refused) |"));
    let (code, me) = call(port, "GET", "/api/me/residency", &ada, "").await;
    assert_eq!(code, 200, "{me}");
    assert_eq!(serde_json::from_str::<Value>(&me).unwrap()["runs"], json!({ "on": "server", "inRegion": false }), "{me}");

    // Unpinned again: as before, and nothing to warn about.
    assert!(app.db.unpin_residency(PinOn::User, &ada_id).unwrap());
    assert_eq!(run(port, &app, &ada, &bot.id).await, "ran here");
    assert!(residency::warnings(&app, &cp).iter().all(|w| !w.contains("ADR 0267")));
}

#[test]
fn botds_server_is_in_a_region_only_as_the_operator_states_it() {
    let app = crate::runner::test_app();
    let mut cp = ControlPlane::for_tests(fake());
    let why = residency::run_outside(&app, &cp, RunsOn::Server, "gb-lon").unwrap();
    assert!(why.contains("isn't stated to be in any data region (SERVER_DATA_REGION)"), "{why}");
    cp.server_data.region = Some("gb-lon".into());
    assert_eq!(residency::run_outside(&app, &cp, RunsOn::Server, "gb-lon"), None);
    assert_eq!(residency::run_outside(&app, &cp, RunsOn::Machine("gone"), "gb-lon").as_deref(), Some("the machine is gone"));

    // Without the control plane nothing is checked: there are no machines, and no pins can be made.
    let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", crate::rbac::Role::Member).unwrap().id;
    app.db.pin_residency(PinOn::User, &ada, "de-fra-2", "DPA-1", None).unwrap();
    let people = vec![ada];
    assert_eq!(residency::run_place_gaps(&app, &cp, &people, RunsOn::Server).len(), 1);
    assert!(residency::run_place_gaps(&app, &ControlPlane::default(), &people, RunsOn::Server).is_empty());
}

#[tokio::test]
async fn a_pinned_teammates_run_stays_off_an_owners_machine_outside_their_region() {
    let link = Arc::new(Recording::default());
    let l: Arc<dyn MachineLink> = link.clone();
    let (port, app, owner, _) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(fake());
        (cp.routing, cp.link) = (Routing::On, l);
        a.machines = Arc::new(cp);
    })
    .await;
    let cp = app.control_plane.get().unwrap().clone();
    app.tiers.set(Arc::new(tiers())).unwrap();
    crate::secrets::global().put(KEY, "sk-eu-not-real").unwrap();
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea_id, bea) = user_with(port, &admin, "bea@example.com", "member").await;
    assert_eq!(call(port, "POST", &format!("/api/users/{ada_id}/machine"), &admin, "{}").await.0, 202);
    assert_eq!(call(port, "POST", "/api/machines/reconcile", &admin, "").await.0, 200);
    let machine = app.db.user_machine(&ada_id).unwrap();
    assert_eq!(machine.region, "gb-lon");
    recording::enroll(&app.db, &machine);
    assert_eq!(call(port, "PUT", &format!("/api/users/{ada_id}/placement"), &admin, "").await.0, 200);
    let bot = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Shared);
    let sent = || link.sent.lock().unwrap().len();
    let until_sent = |n: usize| async move {
        for _ in 0..300 {
            if sent() >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the run never reached the machine");
    };

    // Ada pinned to London, her machine's region: her run and Bea's go to it.
    app.db.pin_residency(PinOn::User, &ada_id, "gb-lon", "DPA-7", None).unwrap();
    send(port, &app, &ada, &bot.id).await;
    until_sent(1).await;
    app.db.pin_residency(PinOn::User, &bea_id, "gb-lon", "DPA-9", None).unwrap();
    send(port, &app, &bea, &bot.id).await;
    until_sent(2).await;

    // Bea pinned to Frankfurt: her run of Ada's Bot would carry her data to London. Refused.
    app.db.pin_residency(PinOn::User, &bea_id, "de-fra-2", "DPA-10", None).unwrap();
    let said = run(port, &app, &bea, &bot.id).await;
    let name = app.db.user(&ada_id).unwrap().name;
    assert!(said.contains("pinned to de-fra-2") && said.contains(&format!("I run on {name}'s computer, which isn't in de-fra-2")), "{said}");
    assert_eq!(sent(), 2, "nothing more reached the machine");
    let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["action"].as_str(), d["runsOn"].as_str()), (Some("residency_pinned"), Some("run on a machine outside the region"), Some("machine")), "{d}");
    assert_eq!((d["machine"].as_str(), d["forUser"].as_str(), d["owner"].as_str()), (Some(machine.id.as_str()), Some(bea_id.as_str()), Some(ada_id.as_str())), "{d}");
    assert_eq!(d["error"].as_str(), Some("de-fra-2: the machine is in gb-lon"), "{d}");

    // Ada's own run still goes to her machine, and her report says her Bots run there, in London.
    send(port, &app, &ada, &bot.id).await;
    until_sent(3).await;
    let pin = app.db.residency_pin(PinOn::User, &ada_id).unwrap();
    let r = crate::machines::residency_report::build(&app, &cp, &pin, 0, db::now() + 1, db::now(), false).unwrap();
    assert_eq!(r["people"][0]["runs"], json!({ "on": "machine", "inRegion": true }), "{r}");
    assert!(crate::machines::residency_report::markdown(&r).contains("| their machine, in region |"));
    let bea_pin = app.db.residency_pin(PinOn::User, &bea_id).unwrap();
    let r = crate::machines::residency_report::build(&app, &cp, &bea_pin, 0, db::now() + 1, db::now(), false).unwrap();
    assert_eq!(r["people"][0]["runs"], json!({ "on": "nowhere", "inRegion": null }), "Bea has no machine of her own: {r}");
    let kinds: Vec<&str> = r["activity"]["refusals"].as_array().unwrap().iter().filter_map(|e| e["kind"].as_str()).collect();
    assert!(kinds.contains(&"run on a machine outside the region"), "Bea's report lists the refusal: {r}");
}
