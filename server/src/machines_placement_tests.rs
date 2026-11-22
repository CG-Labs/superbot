//! Placing machines on Incus hosts by load (ADR 0081), end to end on loopback: Incus
//! stand-ins as hosts with capacities, the S3 stand-in, botd's machine port and the
//! real agent. New machines go to the least loaded host with room, never past a
//! host's capacity, a drained host or one that didn't answer; with no room the request
//! is refused, audited and alerted; restores and a lost host's machines are placed the
//! same way.

use crate::db::NewMachine;
use crate::machines::State;
use crate::machines::provider::CreateSpec;
use crate::machines::incus::fleet::{Fleet, Member, capacity};
use crate::machines_hosts_tests::{
    DOWN_MS, Env, alerts_to, back_up, events, json_call, machine_on, mail_with, reconcile, serve_with, settled, until,
};
use crate::tests::call;
use crate::users_http_tests::user_with;
use crate::*;

fn sized(m: Member, cap: &str) -> Member {
    Member { capacity: Some(capacity(cap).unwrap()), ..m }
}

async fn ask(env: &Env, uid: &str) -> (u16, Value) {
    json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await
}

async fn hosts(env: &Env) -> Value {
    let (code, h) = json_call(env, "GET", "/api/machines/hosts", "").await;
    assert_eq!(code, 200, "{h}");
    h
}

fn on<'a>(h: &'a Value, name: &str) -> &'a Value {
    h["hosts"].as_array().unwrap().iter().find(|x| x["name"] == name).unwrap()
}

#[tokio::test]
async fn new_machines_go_to_the_least_loaded_open_host_and_never_past_its_room() {
    // Room for two starters (c1-m2-d20) on each.
    let env = serve_with(|a, b, _| Fleet::new(vec![sized(a, "c2-m4-d40"), sized(b, "c2-m4-d40")], DOWN_MS)).await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&env, &mail);
    let h = hosts(&env).await;
    assert_eq!((h["policy"].as_str(), h["placement"].as_str(), h["placementFor"]["plan"].as_str()), (Some("spread"), Some("a"), Some("c1-m2-d20")), "{h}");
    assert_eq!(on(&h, "a")["load"]["free"], json!({ "cpus": 2, "memoryGiB": 4, "diskGiB": 40 }), "{h}");

    // Spread: each to the host with the most room left, ties in the order configured.
    machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    let (bea, _) = machine_on(&env, &env.b, "b", "bea@example.com", false).await;
    machine_on(&env, &env.a, "a", "cy@example.com", false).await;

    // A host that didn't answer its last check gets nothing, though it isn't down yet;
    // and a full one gets nothing: refused, audited and alerted.
    env.b.w().down = true;
    reconcile(&env).await;
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let (ed, _) = user_with(env.port, &env.admin, "ed@example.com", "member").await;
    let (code, e) = ask(&env, &dee).await;
    assert_eq!(code, 409, "{e}");
    let why = e["error"].as_str().unwrap();
    assert!(why.contains("No Incus host has room for a c1-m2-d20 machine"), "{why}");
    assert!(why.contains("a has 0 of 2 CPUs free, 1 needed") && why.contains("b didn't answer its last check"), "{why}");
    assert!(env.app.db.user_machine(&dee).is_none(), "nothing recorded for a refused request");
    let failed = events(&env, "machine.placement_failed").await;
    assert_eq!((failed.len(), failed[0]["targetType"].as_str(), failed[0]["targetId"].as_str()), (1, Some("user"), Some(dee.as_str())), "{failed:?}");
    let alert = mail_with(&mail, "No Incus host has room for a machine").await;
    assert!(alert.body.contains("botctl machine hosts"), "{}", alert.body);
    env.b.w().down = false;
    reconcile(&env).await;
    let (code, d) = ask(&env, &dee).await;
    assert_eq!(code, 202, "{d}");
    assert!(d["providerId"].as_str().unwrap().starts_with("b/"), "{d}");

    // Both full: refused, and the view says so.
    let (code, e) = ask(&env, &ed).await;
    assert_eq!(code, 409, "{e}");
    let h = hosts(&env).await;
    assert!(h["placement"].is_null() && h["placementRefused"].as_str().unwrap().contains("room"), "{h}");
    let b = &on(&h, "b")["load"];
    assert_eq!((b["machines"].as_u64(), b["allocated"]["cpus"].as_u64(), b["free"]["diskGiB"].as_u64()), (Some(2), Some(2), Some(0)), "{h}");

    // Drained: nothing new goes there, though it has room again.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{bea}/machine"), "").await;
    assert_eq!(code, 200);
    until("bea's machine gone", || env.app.db.user_machine(&bea).is_none_or(|m| m.state == State::Destroyed)).await;
    let (_, member) = user_with(env.port, &env.admin, "fay@example.com", "member").await;
    let (code, _) = call(env.port, "PUT", "/api/machines/hosts/b/drain", &member, "{}").await;
    assert_eq!(code, 403, "admins only");
    let (code, _) = json_call(&env, "PUT", "/api/machines/hosts/nope/drain", "{}").await;
    assert_eq!(code, 404);
    let (code, _) = json_call(&env, "PUT", "/api/machines/hosts/b/drain", &json!({ "reason": "disk\nswap" }).to_string()).await;
    assert_eq!(code, 400);
    let (code, _) = json_call(&env, "PUT", "/api/machines/hosts/b/drain", &json!({ "force": true }).to_string()).await;
    assert!((400..500).contains(&code), "unknown fields are refused: {code}");
    for _ in 0..2 {
        let (code, v) = json_call(&env, "PUT", "/api/machines/hosts/b/drain", &json!({ "reason": "disk swap" }).to_string()).await;
        assert_eq!(code, 200, "{v}");
        assert_eq!((v["drainReason"].as_str(), v["load"]["open"].as_bool(), v["load"]["closed"].as_str()), (Some("disk swap"), Some(false), Some("b is drained")), "{v}");
        assert!(v["drainedAt"].is_i64() && v["drainedBy"].is_string(), "{v}");
    }
    let drained = events(&env, "machine.host_drained").await;
    assert_eq!((drained.len(), drained[0]["targetId"].as_str(), drained[0]["details"]["reason"].as_str()), (1, Some("b"), Some("disk swap")), "once: {drained:?}");
    let (code, e) = ask(&env, &ed).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("b is drained"), "{e}");

    // One the reconciler sends (a retried create) waits with the reason, said once.
    let (gus, _) = user_with(env.port, &env.admin, "gus@example.com", "member").await;
    let new = NewMachine { user_id: &gus, provider: "incus", label_prefix: "superbot", tier: "starter", plan: "c1-m2-d20", region: "local", created_by: None };
    let g = env.app.db.add_machine(&new).ok().unwrap();
    reconcile(&env).await;
    reconcile(&env).await;
    let gm = env.app.db.machine(&g.id).unwrap();
    assert_eq!((gm.state, gm.provider_id.as_deref()), (State::Pending, None));
    assert!(gm.last_error.as_deref().unwrap().contains("No Incus host has room"), "{:?}", gm.last_error);
    let failed: Vec<Value> = events(&env, "machine.placement_failed").await.into_iter().filter(|e| e["targetId"] == g.id.as_str()).collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    let m = crate::obs::render(&env.app);
    assert_eq!(value(&m, "superbot_incus_machines_waiting_for_room"), Some(1.0), "{m}");
    assert!(value(&m, r#"superbot_events_total{event="machine.placement_failed",outcome="failure"}"#).is_some_and(|n| n >= 1.0), "{m}");
    // Its reason changes as hosts do (a stops answering), and it isn't announced again.
    env.a.w().down = true;
    reconcile(&env).await;
    let gm = env.app.db.machine(&g.id).unwrap();
    assert!(gm.last_error.as_deref().unwrap().contains("a didn't answer its last check"), "{:?}", gm.last_error);
    let failed: Vec<Value> = events(&env, "machine.placement_failed").await.into_iter().filter(|e| e["targetId"] == g.id.as_str()).collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    env.a.w().down = false;
    reconcile(&env).await;

    // Undrained: open again, and the waiting machine is made there.
    let (code, v) = json_call(&env, "DELETE", "/api/machines/hosts/b/drain", "").await;
    assert_eq!((code, v["drainedAt"].is_null(), v["load"]["open"].as_bool()), (200, true, Some(true)), "{v}");
    let undrained = events(&env, "machine.host_undrained").await;
    assert_eq!((undrained.len(), undrained[0]["details"]["reason"].as_str()), (1, Some("disk swap")), "{undrained:?}");
    reconcile(&env).await;
    let gm = env.app.db.machine(&g.id).unwrap();
    assert_eq!((gm.provider_id.as_deref(), gm.last_error.as_deref()), (Some(format!("b/{}", gm.label).as_str()), None), "{gm:?}");
    assert_eq!(value(&crate::obs::render(&env.app), "superbot_incus_machines_waiting_for_room"), Some(0.0));
}

#[tokio::test]
async fn restores_and_a_lost_hosts_machines_are_placed_by_load() {
    // a: four starters, b: two, c: one.
    let env = serve_with(|a, b, c| Fleet::new(vec![sized(a, "c4-m8-d80"), sized(b, "c2-m4-d40"), sized(c, "c1-m2-d20")], DOWN_MS)).await;
    for h in ["b", "c"] {
        let (code, _) = json_call(&env, "PUT", &format!("/api/machines/hosts/{h}/drain"), "{}").await;
        assert_eq!(code, 200);
    }
    let mut on_a = Vec::new();
    for email in ["ada@example.com", "bea@example.com", "cy@example.com"] {
        let (uid, m) = machine_on(&env, &env.a, "a", email, true).await;
        on_a.push((uid.clone(), m.clone(), back_up(&env, &uid).await));
    }
    let (code, _) = json_call(&env, "DELETE", "/api/machines/hosts/b/drain", "").await;
    assert_eq!(code, 200);
    let (dee, _) = machine_on(&env, &env.b, "b", "dee@example.com", false).await;

    // A move onto a drained host, or one without room, is refused before anything changes.
    let (ada, m, b) = &on_a[0];
    let path = format!("/api/users/{ada}/machine/restore");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id, "host": "c" }).to_string()).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("c is drained"), "{e}");
    let (code, _) = json_call(&env, "DELETE", "/api/machines/hosts/c/drain", "").await;
    assert_eq!(code, 200);
    let (code, _) = json_call(&env, "PUT", "/api/machines/hosts/b/drain", "{}").await;
    assert_eq!(code, 200);
    let (code, e) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("answers"), "{e}");
    assert_eq!(env.app.db.machine(&m.id).unwrap().provider_id, m.provider_id, "nothing moved");
    let (code, _) = json_call(&env, "DELETE", "/api/machines/hosts/b/drain", "").await;
    assert_eq!(code, 200);

    // a is lost: each machine goes where there is most room, counting the ones placed
    // before it; the one with nowhere to go is left for later.
    env.a.w().down = true;
    reconcile(&env).await;
    env.app.db.machine_host_failing_backdate("a", DOWN_MS);
    reconcile(&env).await;
    for (_, m, _) in &on_a {
        for s in [&env.b, &env.c] {
            s.w().addresses.insert(format!("{}-restore", m.label), "127.0.0.1".into());
        }
    }
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert_eq!(code, 202, "{out}");
    assert_eq!((out["to"].is_null(), &out["toHosts"], out["placement"].as_str()), (true, &json!(["c", "b"]), Some("spread")), "{out}");
    let restoring = out["restoring"].as_array().unwrap();
    assert_eq!(restoring.iter().map(|r| r["toHost"].as_str().unwrap()).collect::<Vec<_>>(), ["c", "b"], "{out}");
    let skipped = out["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1, "{out}");
    let left = skipped[0]["machineId"].as_str().unwrap().to_string();
    assert!(on_a.iter().any(|(_, m, _)| m.id == left), "{out}");
    assert!(skipped[0]["reason"].as_str().unwrap().contains("No Incus host has room"), "{out}");
    for (r, s) in restoring.iter().zip([&env.c, &env.b]) {
        let id = r["restore"]["id"].as_str().unwrap();
        let done = settled(&env, id).await;
        assert_eq!((done.state.as_str(), done.to_host.as_deref()), ("enrolling", r["toHost"].as_str()), "{:?}", done.error);
        let mm = env.app.db.machine(r["machineId"].as_str().unwrap()).unwrap();
        assert!(s.instance(&mm.label).is_some(), "on {}", done.to_host.unwrap());
    }
    let h = hosts(&env).await;
    assert_eq!((on(&h, "b")["load"]["machines"].as_u64(), on(&h, "c")["load"]["machines"].as_u64()), (Some(2), Some(1)), "{h}");

    // Room freed on b: recovering again places the one left.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{dee}/machine"), "").await;
    assert_eq!(code, 200);
    until("dee's machine gone", || env.app.db.user_machine(&dee).is_none_or(|m| m.state == State::Destroyed)).await;
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert_eq!(code, 202, "{out}");
    assert_eq!((out["declaredLost"].as_bool(), &out["toHosts"], out["skipped"].as_array().map(Vec::len)), (Some(false), &json!(["b"]), Some(0)), "{out}");
    let r = settled(&env, out["restoring"][0]["restore"]["id"].as_str().unwrap()).await;
    assert_eq!((r.state.as_str(), r.machine_id.as_str()), ("enrolling", left.as_str()), "{:?}", r.error);
}

#[tokio::test]
async fn a_create_whose_answer_was_lost_is_adopted_where_it_landed_not_made_again() {
    let env = serve_with(|a, b, _| Fleet::new(vec![a, b], DOWN_MS)).await;
    machine_on(&env, &env.a, "a", "bea@example.com", false).await;
    let (uid, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let new = NewMachine { user_id: &uid, provider: "incus", label_prefix: "superbot", tier: "starter", plan: "c1-m2-d20", region: "local", created_by: None };
    let mut m = env.app.db.add_machine(&new).ok().unwrap();
    // It reached a, but botd never heard; spread alone would now pick b.
    let spec = CreateSpec {
        label: m.label.clone(),
        plan: m.plan.clone(),
        region: m.region.clone(),
        image: crate::machines::incus::DEFAULT_IMAGE.into(),
        tags: vec![m.tag.clone(), format!("{}-user-{}", m.tag, m.user_id)],
        authorized_keys: vec![],
        user_data: None,
        firewall_id: Some("superbot-fw".into()),
    };
    env.cp.hosts().unwrap().create_on("a", &spec).await.unwrap();
    m.create_sent_at = Some(crate::db::now());
    assert!(env.app.db.save_machine(&m, State::Pending));
    assert_eq!(hosts(&env).await["placement"].as_str(), Some("b"));
    reconcile(&env).await;
    let mm = env.app.db.machine(&m.id).unwrap();
    assert_eq!(mm.provider_id.as_deref(), Some(format!("a/{}", m.label).as_str()), "{mm:?}");
    assert!(env.b.instance(&m.label).is_none(), "no second copy on b");
    let created = events(&env, "machine.created").await;
    let mine = created.iter().find(|e| e["targetId"] == m.id.as_str()).unwrap();
    assert_eq!(mine["details"]["adopted"].as_bool(), Some(true), "{created:?}");
}

#[tokio::test]
async fn a_create_sent_but_not_answered_keeps_its_room_until_it_is() {
    let env = serve_with(|a, _, _| Fleet::new(vec![Member { max_machines: Some(1), ..a }], DOWN_MS)).await;
    let (uid, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let new = NewMachine { user_id: &uid, provider: "incus", label_prefix: "superbot", tier: "starter", plan: "c1-m2-d20", region: "local", created_by: None };
    let mut m = env.app.db.add_machine(&new).ok().unwrap();
    // Sent to a; Incus hasn't answered yet.
    m.create_sent_at = Some(crate::db::now());
    m.placed_on = Some("a".into());
    assert!(env.app.db.save_machine(&m, State::Pending));
    let h = hosts(&env).await;
    assert_eq!(on(&h, "a")["load"]["machines"].as_u64(), Some(1), "{h}");
    let (bea, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (code, e) = ask(&env, &bea).await;
    assert_eq!(code, 409, "its room is taken: {e}");

    // Nothing landed after all: the room is freed, and the retry takes it.
    reconcile(&env).await;
    let mm = env.app.db.machine(&m.id).unwrap();
    assert_eq!((mm.provider_id.as_deref(), mm.placed_on.as_deref()), (Some(format!("a/{}", m.label).as_str()), None), "{mm:?}");
    let (code, e) = ask(&env, &bea).await;
    assert_eq!(code, 409, "{e}");
}

#[tokio::test]
async fn a_host_that_didnt_answer_doesnt_hold_up_creates_on_the_others() {
    let env = serve_with(|a, b, _| Fleet::new(vec![a, b], DOWN_MS)).await;
    machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    env.b.w().down = true;
    reconcile(&env).await;
    let (bea, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (code, d) = ask(&env, &bea).await;
    assert_eq!(code, 202, "{d}");
    assert!(d["providerId"].as_str().is_some_and(|p| p.starts_with("a/")), "made on a, not left pending: {d}");
}

#[tokio::test]
async fn a_refused_create_frees_its_room_for_its_retry() {
    let env = serve_with(|a, _, _| Fleet::new(vec![Member { max_machines: Some(1), ..a }], DOWN_MS)).await;
    let (uid, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    // Not found (no such cluster member), a refusal like any other.
    env.a.w().fail_create = Some((404, "Cluster member not found".into()));
    let (code, d) = ask(&env, &uid).await;
    assert!(code >= 400 && d["machine"]["lastError"].is_string(), "{code} {d}");
    let m = env.app.db.user_machine(&uid).unwrap();
    assert_eq!((m.state, m.placed_on.as_deref()), (State::Error, None), "{m:?}");
    let h = hosts(&env).await;
    assert_eq!(on(&h, "a")["load"]["machines"].as_u64(), Some(0), "{h}");
    // The image is back: the retry isn't refused for want of the room it held.
    let (code, d) = ask(&env, &uid).await;
    assert_eq!(code, 202, "{d}");
    assert!(d["providerId"].as_str().is_some_and(|p| p.starts_with("a/")), "{d}");
}

/// A sample's value on `/metrics`, if the series is there.
fn value(metrics: &str, series: &str) -> Option<f64> {
    metrics.lines().find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

/// Every `superbot_*` metric name in `text`.
fn metric_names(text: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find("superbot_") {
        let name: String = rest[at..].chars().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').collect();
        rest = &rest[at + name.len()..];
        out.insert(name);
    }
    out
}

#[tokio::test]
async fn metrics_show_each_hosts_allocation_against_its_capacity_and_what_it_uses() {
    let env = serve_with(|a, b, _| Fleet::new(vec![Member { max_machines: Some(3), ..sized(a, "c4-m8-d80") }, sized(b, "c2-m4-d40")], DOWN_MS)).await;
    let gib = (1u64 << 30) as f64;

    // With /metrics off, botd never asks hosts what they use; placement's view and
    // botd's own host are there all the same.
    reconcile(&env).await;
    assert!(env.a.calls("GET", "/1.0/resources").is_empty(), "no extra calls with metrics off");
    let m = crate::obs::render(&env.app);
    assert_eq!(value(&m, r#"superbot_incus_host_up{host="a"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_open{host="b"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_capacity_cpus{host="a"}"#), Some(4.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_capacity_memory_bytes{host="b"}"#), Some(4.0 * gib), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_max_machines{host="a"}"#), Some(3.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_max_machines{host="b"}"#), None, "b has no maximum: {m}");
    assert!(value(&m, r#"superbot_host_cpus{host="botd",kind="server"}"#).is_some_and(|n| n > 0.0), "{m}");
    assert!(!m.contains(r#"kind="incus""#), "{m}");

    // With it on, each host check reads what each host has and uses.
    env.app.db.metrics().want_host_use();
    let (_, ada) = machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    let m = crate::obs::render(&env.app);
    assert_eq!(value(&m, r#"superbot_incus_host_machines{host="a"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_machines{host="b"}"#), Some(0.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_allocated_cpus{host="a"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_allocated_memory_bytes{host="a"}"#), Some(2.0 * gib), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_allocated_disk_bytes{host="a"}"#), Some(20.0 * gib), "{m}");
    assert_eq!(value(&m, r#"superbot_host_cpus{host="a",kind="incus"}"#), Some(16.0), "{m}");
    assert_eq!(value(&m, r#"superbot_host_load1{host="b",kind="incus"}"#), Some(1.5), "{m}");
    assert_eq!(value(&m, r#"superbot_host_memory_used_bytes{host="a",kind="incus"}"#), Some(8.0 * gib), "{m}");
    assert_eq!(value(&m, r#"superbot_host_disk_bytes{host="a",kind="incus",disk="pool"}"#), Some(1000.0 * gib), "{m}");
    assert!(value(&m, r#"superbot_host_disk_bytes{host="botd",kind="server",disk="data"}"#).is_some_and(|n| n > 0.0), "{m}");
    let read_b = value(&m, r#"superbot_host_reading_timestamp_seconds{host="b",kind="incus"}"#).unwrap();
    assert!(read_b > 0.0, "{m}");

    // A host that stops answering is neither up nor open, and keeps its last reading;
    // a drained one is up but not open; a pool that stops saying drops its disk.
    env.b.w().down = true;
    env.a.w().pool_resources = Value::Null;
    env.a.w().resources["memory"]["used"] = json!(60u64 << 30);
    reconcile(&env).await;
    let (code, d) = json_call(&env, "PUT", "/api/machines/hosts/a/drain", "{}").await;
    assert_eq!(code, 200, "{d}");
    let m = crate::obs::render(&env.app);
    assert_eq!(value(&m, r#"superbot_incus_host_up{host="b"}"#), Some(0.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_open{host="b"}"#), Some(0.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_up{host="a"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_open{host="a"}"#), Some(0.0), "{m}");
    assert_eq!(value(&m, r#"superbot_host_reading_timestamp_seconds{host="b",kind="incus"}"#), Some(read_b), "{m}");
    assert_eq!(value(&m, r#"superbot_host_memory_used_bytes{host="a",kind="incus"}"#), Some(60.0 * gib), "{m}");
    assert_eq!(value(&m, r#"superbot_host_disk_bytes{host="a",kind="incus",disk="pool"}"#), None, "{m}");

    // Hosts are the only new label values: no people, machines or addresses.
    let capacity: Vec<&str> = m.lines().filter(|l| l.starts_with("superbot_incus_host_") || l.starts_with("superbot_host_")).collect();
    for bad in ["@example.com", ada.label.as_str(), ada.id.as_str(), "127.0.0.1"] {
        assert!(!capacity.iter().any(|l| l.contains(bad)), "{bad} leaked into: {capacity:?}");
    }

    // The dashboard and the alert rules use only metrics botd writes.
    let types: std::collections::BTreeSet<String> = m.lines().filter_map(|l| Some(l.strip_prefix("# TYPE ")?.split(' ').next()?.to_string())).collect();
    for (file, text) in [
        ("deploy/grafana/superbot-capacity.json", include_str!("../../deploy/grafana/superbot-capacity.json")),
        ("deploy/prometheus/superbot-capacity.rules.yml", include_str!("../../deploy/prometheus/superbot-capacity.rules.yml")),
    ] {
        let used = metric_names(text);
        assert!(!used.is_empty(), "{file}");
        let missing: Vec<_> = used.difference(&types).collect();
        assert!(missing.is_empty(), "{file} uses metrics botd doesn't write: {missing:?}");
    }
    let dashboard: Value = serde_json::from_str(include_str!("../../deploy/grafana/superbot-capacity.json")).unwrap();
    assert!(dashboard["panels"].as_array().is_some_and(|p| !p.is_empty()), "a Grafana dashboard with panels");
}
