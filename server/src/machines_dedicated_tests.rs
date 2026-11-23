//! Incus hosts dedicated to one team (ADR 0166), end to end on loopback: Incus stand-ins
//! as hosts, the S3 stand-in, botd's machine port and the real agent. A dedicated host
//! takes only its team's machines, and the team's machines go only on its hosts: new
//! ones, retries, restores onto another host and a lost host's recovery. Dedicating is
//! refused while anyone else's machine is there; sharing again needs a reason; a machine
//! left on the wrong host by a team change is reported until it is moved.

use crate::db::NewMachine;
use crate::machines::State;
use crate::machines::incus::fleet::{Fleet, Member, capacity};
use crate::machines::provider::Policy;
use crate::machines_hosts_tests::{DOWN_MS, Env, back_up, events, json_call, machine_for, reconcile, serve_with, settled};
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

/// A team owned by `owner` (an email), giving no machines on joining.
async fn team(env: &Env, name: &str, owner: &str) -> String {
    let (code, t) = json_call(env, "POST", "/api/teams", &json!({ "name": name, "owner": owner, "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    t["id"].as_str().unwrap().to_string()
}

async fn join(env: &Env, team: &str, uid: &str) {
    let (code, v) = json_call(env, "PUT", &format!("/api/teams/{team}/members/{uid}"), r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");
}

async fn dedicate(env: &Env, host: &str, team: &str, reason: Option<&str>) -> (u16, Value) {
    json_call(env, "PUT", &format!("/api/machines/hosts/{host}/dedication"), &json!({ "team": team, "reason": reason }).to_string()).await
}

async fn share(env: &Env, host: &str, reason: &str) -> (u16, Value) {
    json_call(env, "DELETE", &format!("/api/machines/hosts/{host}/dedication"), &json!({ "reason": reason }).to_string()).await
}

/// The host `uid`'s machine was placed on.
fn host_of(env: &Env, uid: &str) -> String {
    let m = env.app.db.user_machine(uid).unwrap();
    m.provider_id.unwrap().split('/').next().unwrap().to_string()
}

fn value(metrics: &str, series: &str) -> Option<f64> {
    metrics.lines().find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[tokio::test]
async fn a_dedicated_host_takes_only_its_teams_machines_and_the_team_goes_nowhere_else() {
    // Room for two starters (c1-m2-d20) on each; spread.
    let env = serve_with(|a, b, c| Fleet::new(vec![sized(a, "c2-m4-d40"), sized(b, "c2-m4-d40"), sized(c, "c2-m4-d40")], DOWN_MS)).await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (an, _) = user_with(env.port, &env.admin, "an@example.com", "member").await;
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    let globex = team(&env, "Globex", "dee@example.com").await;
    join(&env, &acme, &al).await;
    join(&env, &acme, &an).await;

    // Server admins only; a host and a team that exist; one line of reason.
    let (_, member) = user_with(env.port, &env.admin, "mo@example.com", "member").await;
    let body = json!({ "team": acme }).to_string();
    assert_eq!(call(env.port, "PUT", "/api/machines/hosts/b/dedication", &member, &body).await.0, 403, "admins only");
    assert_eq!(call(env.port, "DELETE", "/api/machines/hosts/b/dedication", &member, r#"{"reason":"x"}"#).await.0, 403);
    assert_eq!(dedicate(&env, "nope", &acme, None).await.0, 404);
    assert_eq!(dedicate(&env, "b", "no-such-team", None).await.0, 404);
    assert_eq!(dedicate(&env, "b", &acme, Some("MSA\n7")).await.0, 400);
    let (code, _) = json_call(&env, "PUT", "/api/machines/hosts/b/dedication", &json!({ "team": acme, "force": true }).to_string()).await;
    assert!((400..500).contains(&code), "unknown fields are refused: {code}");

    // Dedicated once, audited once.
    for _ in 0..2 {
        let (code, v) = dedicate(&env, "b", &acme, Some("MSA-7")).await;
        assert_eq!(code, 200, "{v}");
        assert_eq!((v["dedicatedTeam"].as_str(), v["dedicationReason"].as_str(), v["load"]["dedicatedTo"].as_str()), (Some(acme.as_str()), Some("MSA-7"), Some(acme.as_str())), "{v}");
        assert!(v["dedicatedAt"].is_i64() && v["dedicatedBy"].is_string(), "{v}");
    }
    let done = events(&env, "machine.host_dedicated").await;
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!((done[0]["targetId"].as_str(), done[0]["details"]["team"].as_str(), done[0]["details"]["teamName"].as_str()), (Some("b"), Some(acme.as_str()), Some("Acme")));
    let (code, e) = dedicate(&env, "b", &globex, None).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("dedicated to another team"), "{e}");

    // Someone in no team, and a team without hosts of its own, skip the empty b.
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    assert_eq!(ask(&env, &cy).await.0, 202);
    assert_eq!(host_of(&env, &cy), "a");
    assert_eq!(ask(&env, &dee).await.0, 202);
    assert_eq!(host_of(&env, &dee), "c", "b is emptier and first, but Globex's machines don't go there");

    // Acme's go on b, though a ties with it and comes first.
    assert_eq!(ask(&env, &ada).await.0, 202);
    assert_eq!(ask(&env, &al).await.0, 202);
    assert_eq!((host_of(&env, &ada), host_of(&env, &al)), ("b".into(), "b".into()));

    // b is full: Acme's next machine is refused, never put on a shared host with room.
    let (code, e) = ask(&env, &an).await;
    assert_eq!(code, 409, "{e}");
    let why = e["error"].as_str().unwrap();
    assert!(why.contains("a is shared, and this team's machines go only on its own hosts") && why.contains("b has 0 of 2 CPUs free"), "{why}");
    assert!(env.app.db.user_machine(&an).is_none());
    let failed = events(&env, "machine.placement_failed").await;
    assert_eq!((failed.len(), failed[0]["targetId"].as_str()), (1, Some(an.as_str())), "{failed:?}");

    // A retried create waits the same way, said once.
    let new = NewMachine { user_id: &an, provider: "incus", label_prefix: "superbot", tier: "starter", plan: "c1-m2-d20", region: "local", created_by: None };
    let waiting = env.app.db.add_machine(&new).ok().unwrap();
    reconcile(&env).await;
    reconcile(&env).await;
    let w = env.app.db.machine(&waiting.id).unwrap();
    assert_eq!((w.state, w.provider_id.as_deref()), (State::Pending, None));
    assert!(w.last_error.as_deref().unwrap().contains("this team's machines go only on its own hosts"), "{:?}", w.last_error);
    assert!(env.a.instance(&w.label).is_none() && env.c.instance(&w.label).is_none(), "not on a shared host");

    // Strangers fill a and c, then are refused rather than put on b.
    for email in ["ed@example.com", "fay@example.com"] {
        let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
        assert_eq!(ask(&env, &uid).await.0, 202);
        assert_ne!(host_of(&env, &uid), "b");
    }
    let (gus, _) = user_with(env.port, &env.admin, "gus@example.com", "member").await;
    let (code, e) = ask(&env, &gus).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("b is dedicated to another team"), "{e}");

    // The view: b's dedication, where each team's next machine goes, nothing misplaced.
    let h = hosts(&env).await;
    assert_eq!((on(&h, "b")["dedicatedTeam"].as_str(), on(&h, "a")["dedicatedTeam"].as_str()), (Some(acme.as_str()), None), "{h}");
    let d = &h["dedicated"][0];
    assert_eq!((d["team"].as_str(), d["name"].as_str(), &d["hosts"]), (Some(acme.as_str()), Some("Acme"), &json!(["b"])), "{h}");
    assert!(d["placement"].is_null() && d["placementRefused"].as_str().unwrap().contains("b has 0 of 2"), "{h}");
    assert_eq!((&h["misplaced"], &h["dedicationWarnings"]), (&json!([]), &json!([])), "{h}");
    let m = crate::obs::render(&env.app);
    assert_eq!(value(&m, r#"superbot_incus_host_dedicated{host="b"}"#), Some(1.0), "{m}");
    assert_eq!(value(&m, r#"superbot_incus_host_dedicated{host="a"}"#), Some(0.0), "{m}");
    assert_eq!(value(&m, "superbot_incus_machines_misplaced"), Some(0.0), "{m}");
    assert!(!m.lines().filter(|l| l.starts_with("superbot_incus_host_dedicated")).any(|l| l.contains(&acme)), "no team ids in labels: {m}");
}

#[tokio::test]
async fn dedicating_is_refused_while_anyone_elses_machine_is_there_and_sharing_needs_a_reason() {
    let env = serve_with(|a, b, _| Fleet::new(vec![a, b], DOWN_MS).with_policy(Policy::Fill)).await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    assert_eq!(ask(&env, &cy).await.0, 202);
    assert_eq!(host_of(&env, &cy), "a");
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;

    // cy's machine is on a: refused, naming it, audited as denied; nothing changes.
    let cym = env.app.db.user_machine(&cy).unwrap();
    let (code, e) = dedicate(&env, "a", &acme, None).await;
    assert_eq!(code, 409, "{e}");
    assert!(e["error"].as_str().unwrap().contains(&cym.id) && e["error"].as_str().unwrap().contains("not on team Acme"), "{e}");
    let refused = events(&env, "machine.host_dedication_refused").await;
    assert_eq!((refused.len(), refused[0]["outcome"].as_str(), refused[0]["details"]["machines"].as_u64()), (1, Some("denied"), Some(1)), "{refused:?}");
    assert!(env.app.db.machine_host("a").unwrap().dedicated_team.is_none());

    // A create sent to b but not yet answered counts as being there too.
    let (bo, _) = user_with(env.port, &env.admin, "bo@example.com", "member").await;
    let new = NewMachine { user_id: &bo, provider: "incus", label_prefix: "superbot", tier: "starter", plan: "c1-m2-d20", region: "local", created_by: None };
    let mut sent = env.app.db.add_machine(&new).ok().unwrap();
    sent.create_sent_at = Some(crate::db::now());
    sent.placed_on = Some("b".into());
    assert!(env.app.db.save_machine(&sent, State::Pending));
    let (code, e) = dedicate(&env, "b", &acme, None).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains(&sent.id), "{e}");
    sent.placed_on = None;
    sent.create_sent_at = None;
    assert!(env.app.db.save_machine(&sent, State::Pending));
    let (code, v) = dedicate(&env, "b", &acme, None).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(ask(&env, &ada).await.0, 202);
    assert_eq!(host_of(&env, &ada), "b", "fill would pick a, but Acme's go on b");

    // Sharing needs a reason, and is audited with what it ends.
    for body in ["", "{}", r#"{"reason":"  "}"#, r#"{"reason":"a\nb"}"#] {
        let (code, _) = json_call(&env, "DELETE", "/api/machines/hosts/b/dedication", body).await;
        assert_eq!(code, 400, "{body}");
    }
    let (code, v) = share(&env, "b", "contract ended").await;
    assert_eq!((code, v["dedicatedTeam"].is_null()), (200, true), "{v}");
    let shared = events(&env, "machine.host_shared").await;
    assert_eq!(shared.len(), 1, "{shared:?}");
    let sd = &shared[0]["details"];
    assert_eq!((sd["team"].as_str(), sd["reason"].as_str(), sd["machines"].as_u64()), (Some(acme.as_str()), Some("contract ended"), Some(1)), "{sd}");
    assert_eq!(share(&env, "b", "again").await.0, 200);
    assert_eq!(events(&env, "machine.host_shared").await.len(), 1, "once");

    // A host dedicated to a team that is then gone takes nobody, and says so.
    let (dee, _) = user_with(env.port, &env.admin, "dee@example.com", "member").await;
    let globex = team(&env, "Globex", "dee@example.com").await;
    assert_eq!(dedicate(&env, "b", &globex, None).await.0, 409, "ada's machine is on b");
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{ada}/machine"), "").await;
    assert_eq!(code, 200);
    crate::machines_hosts_tests::until("ada's machine gone", || env.app.db.user_machine(&ada).is_none_or(|m| m.state == State::Destroyed)).await;
    assert_eq!(dedicate(&env, "b", &globex, None).await.0, 200);
    let (code, _) = json_call(&env, "DELETE", &format!("/api/teams/{globex}/members/{dee}"), "").await;
    assert_eq!(code, 200);
    assert!(env.app.db.team(&globex).is_none(), "its last member left");
    let h = hosts(&env).await;
    let warnings = h["dedicationWarnings"].as_array().unwrap();
    assert!(warnings.len() == 1 && warnings[0].as_str().unwrap().contains("b is dedicated to a team that no longer exists"), "{h}");
    assert_eq!(json_call(&env, "PUT", "/api/machines/hosts/a/drain", "{}").await.0, 200);
    let (ed, _) = user_with(env.port, &env.admin, "ed@example.com", "member").await;
    let (code, e) = ask(&env, &ed).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("b is dedicated to another team"), "{e}");
    assert_eq!(share(&env, "b", "Globex is gone").await.0, 200);
    assert_eq!(ask(&env, &ed).await.0, 202);
    assert_eq!(host_of(&env, &ed), "b");
}

#[tokio::test]
async fn red_team_no_restore_or_recovery_puts_a_machine_on_the_wrong_teams_host() {
    // a: shared with room for many; b and c: Acme's, c with room for one starter.
    let env = serve_with(|a, b, c| Fleet::new(vec![sized(a, "c8-m16-d160"), sized(b, "c2-m4-d40"), sized(c, "c1-m2-d20")], DOWN_MS).with_policy(Policy::Fill)).await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    for h in ["b", "c"] {
        assert_eq!(dedicate(&env, h, &acme, Some("MSA-7")).await.0, 200);
    }
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let cym = machine_for(&env, &env.a, "a", &cy, true).await;
    let cyb = back_up(&env, &cy).await;
    let mut acmes = Vec::new();
    for uid in [&ada, &al] {
        let m = machine_for(&env, &env.b, "b", uid, true).await;
        acmes.push((uid.clone(), m, back_up(&env, uid).await));
    }

    // Moves by hand onto the wrong team's host are refused before anything changes.
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{cy}/machine/restore"), &json!({ "backupId": cyb.id, "host": "b" }).to_string()).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("Host b is dedicated to another team (ADR 0166)"), "{e}");
    let (uid, m, b) = &acmes[0];
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/restore"), &json!({ "backupId": b.id, "host": "a" }).to_string()).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("Host a is shared, and this team's machines go only on its own hosts"), "{e}");
    assert_eq!(env.app.db.machine(&m.id).unwrap().provider_id, m.provider_id, "nothing moved");
    assert_eq!(env.app.db.machine(&cym.id).unwrap().provider_id, cym.provider_id, "nothing moved");

    // b is lost. Recovering onto the shared a skips both of Acme's machines.
    env.b.w().down = true;
    reconcile(&env).await;
    env.app.db.machine_host_failing_backdate("b", DOWN_MS);
    reconcile(&env).await;
    for (_, m, _) in &acmes {
        for s in [&env.a, &env.c] {
            s.w().addresses.insert(format!("{}-restore", m.label), "127.0.0.1".into());
        }
    }
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/b/recover", r#"{"to":"a"}"#).await;
    assert_eq!(code, 202, "{out}");
    assert_eq!((out["declaredLost"].as_bool(), out["restoring"].as_array().map(Vec::len)), (Some(true), Some(0)), "{out}");
    let skipped = out["skipped"].as_array().unwrap();
    assert!(skipped.len() == 2 && skipped.iter().all(|s| s["reason"].as_str().unwrap().contains("Host a is shared")), "{out}");

    // By placement: one fits on c; the other waits rather than go on a with its room.
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/b/recover", "{}").await;
    assert_eq!(code, 202, "{out}");
    assert_eq!(&out["toHosts"], &json!(["c"]), "{out}");
    let skipped = out["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1, "{out}");
    let why = skipped[0]["reason"].as_str().unwrap();
    assert!(why.contains("a is shared, and this team's machines go only on its own hosts") && why.contains("c has 0 of 1 CPUs free"), "{why}");
    let r = settled(&env, out["restoring"][0]["restore"]["id"].as_str().unwrap()).await;
    assert_eq!((r.state.as_str(), r.to_host.as_deref()), ("enrolling", Some("c")), "{:?}", r.error);
    for (_, m, _) in &acmes {
        assert!(env.a.instance(&m.label).is_none(), "nothing of Acme's on the shared host");
    }
    assert!(env.c.instance(&cym.label).is_none() && env.b.instance(&cym.label).is_none(), "cy's machine stayed on a");
}

#[tokio::test]
async fn a_machine_left_on_the_wrong_host_by_a_team_change_is_reported_until_it_is_moved() {
    let env = serve_with(|a, b, _| Fleet::new(vec![a, b], DOWN_MS).with_policy(Policy::Fill)).await;
    let (ada, _) = user_with(env.port, &env.admin, "ada@example.com", "member").await;
    let (al, _) = user_with(env.port, &env.admin, "al@example.com", "member").await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let acme = team(&env, "Acme", "ada@example.com").await;
    join(&env, &acme, &al).await;
    assert_eq!(dedicate(&env, "b", &acme, None).await.0, 200);
    let alm = machine_for(&env, &env.b, "b", &al, true).await;
    let alb = back_up(&env, &al).await;
    let cym = machine_for(&env, &env.a, "a", &cy, false).await;

    // Al leaves Acme with his own machine; cy joins it with hers.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/teams/{acme}/members/{al}"), "").await;
    assert_eq!(code, 200);
    join(&env, &acme, &cy).await;
    let h = hosts(&env).await;
    let misplaced = h["misplaced"].as_array().unwrap();
    assert_eq!(misplaced.len(), 2, "{h}");
    let of = |id: &str| misplaced.iter().find(|x| x["machineId"] == id).unwrap()["reason"].as_str().unwrap().to_string();
    assert_eq!(of(&alm.id), "b is dedicated to a team its owner isn't on");
    assert_eq!(of(&cym.id), "a is shared, and its owner's team has hosts of its own");
    let w = h["dedicationWarnings"].as_array().unwrap();
    assert!(w.len() == 1 && w[0].as_str().unwrap().starts_with("2 machines are on hosts"), "{h}");
    assert_eq!(value(&crate::obs::render(&env.app), "superbot_incus_machines_misplaced"), Some(2.0));

    // Moved by a restore onto a host they may use: no longer reported.
    env.a.w().addresses.insert(format!("{}-restore", alm.label), "127.0.0.1".into());
    let (code, r) = json_call(&env, "POST", &format!("/api/users/{al}/machine/restore"), &json!({ "backupId": alb.id, "host": "a" }).to_string()).await;
    assert_eq!(code, 202, "{r}");
    let done = settled(&env, r["restore"]["id"].as_str().unwrap()).await;
    assert_eq!((done.state.as_str(), done.to_host.as_deref()), ("enrolling", Some("a")), "{:?}", done.error);
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{cy}/machine"), "").await;
    assert_eq!(code, 200);
    crate::machines_hosts_tests::until("cy's machine gone", || env.app.db.user_machine(&cy).is_none_or(|m| m.state == State::Destroyed)).await;
    let h = hosts(&env).await;
    assert_eq!((&h["misplaced"], &h["dedicationWarnings"]), (&json!([]), &json!([])), "{h}");
    assert_eq!(value(&crate::obs::render(&env.app), "superbot_incus_machines_misplaced"), Some(0.0));
    let _ = ada;
}
