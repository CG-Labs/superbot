//! Placing machines on Incus hosts by load (ADR 0081), end to end on loopback: Incus
//! stand-ins as hosts with capacities, the S3 stand-in, botd's machine port and the
//! real agent. New machines go to the least loaded host with room, never past a
//! host's capacity, a drained host or one that didn't answer; with no room the request
//! is refused, audited and alerted; restores and a lost host's machines are placed the
//! same way.

use crate::db::NewMachine;
use crate::machines::State;
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

    // Undrained: open again, and the waiting machine is made there.
    let (code, v) = json_call(&env, "DELETE", "/api/machines/hosts/b/drain", "").await;
    assert_eq!((code, v["drainedAt"].is_null(), v["load"]["open"].as_bool()), (200, true, Some(true)), "{v}");
    let undrained = events(&env, "machine.host_undrained").await;
    assert_eq!((undrained.len(), undrained[0]["details"]["reason"].as_str()), (1, Some("disk swap")), "{undrained:?}");
    reconcile(&env).await;
    let gm = env.app.db.machine(&g.id).unwrap();
    assert_eq!((gm.provider_id.as_deref(), gm.last_error.as_deref()), (Some(format!("b/{}", gm.label).as_str()), None), "{gm:?}");
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
