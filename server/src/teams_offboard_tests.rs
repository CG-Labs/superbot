//! Leaving a team (ADR 0087), end to end on loopback: the real router, botd's machine
//! port and the real agent over mutual TLS. Leaving is losing access, so ADR 0052's
//! offboarding takes the leaver's user off teammates' machines, and someone on another
//! team never gets one.

use crate::machines::{agent, runas};
use crate::machines_mtls_tests::{events, json_call, wait_for_event};
use crate::machines_teammates_tests::{ada_auth, run, shared_pi, world_with};
use crate::tests::call;
use crate::users_http_tests::user_with;
use serde_json::json;

fn stand_in(c: agent::Config) -> agent::Config {
    agent::Config {
        teammate_stand_in: Some(runas::current_user().unwrap()),
        ..c
    }
}

#[tokio::test]
async fn a_teammate_who_leaves_loses_their_user_and_another_team_never_gets_one() {
    let w = world_with(|e| e, |_| {}, stand_in).await;
    let bot = shared_pi(&w);
    let ada = ada_auth(&w).await;
    let (cy_id, cy) = user_with(w.env.port, &w.env.admin, "cy@example.com", "member").await;
    let (code, v) = json_call(&w.env, "POST", "/api/teams", &json!({ "name": "Alpha", "owner": w.ada, "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let alpha = v["id"].as_str().unwrap().to_string();
    assert_eq!(json_call(&w.env, "PUT", &format!("/api/teams/{alpha}/members/{}", w.bea_id), "{}").await.0, 200);
    let (code, v) = json_call(&w.env, "POST", "/api/teams", &json!({ "name": "Beta", "owner": cy_id, "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{v}");

    // Bea, on Ada's team, runs Ada's shared Bot in her own home there and can log in to
    // its harness; Cy, on another team, can't reach the Bot, the machine or a login.
    run(&w, &ada, &bot, "go").await;
    run(&w, &w.bea, &bot, "go").await;
    let bea_home = w.m.agent.teammates.home_of(&w.bea_id);
    assert!(bea_home.join("whoami").is_file());
    let logins = format!("/api/machine/teammate/{}/harness-logins", w.ada);
    assert_ne!(call(w.env.port, "GET", &logins, &w.bea, "").await.0, 404, "Bea finds the machine");
    for (m, p, b) in [
        ("POST", format!("/api/bots/{bot}/messages"), r#"{"text":"go"}"#),
        ("GET", format!("/api/bots/{bot}/screen"), ""),
        ("GET", logins.clone(), ""),
    ] {
        assert_eq!(call(w.env.port, m, &p, &cy, b).await.0, 404, "Cy: {m} {p}");
    }
    assert!(!w.m.agent.teammates.known().contains(&cy_id));

    // Bea leaves: her user and home go, as for anyone who lost access.
    assert_eq!(call(w.env.port, "POST", "/api/team/leave", &w.bea, "").await.0, 200);
    let removed = wait_for_event(&w.env, "machine.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    let d = &removed[0]["details"];
    assert_eq!((d["forUser"].as_str(), d["reason"].as_str()), (Some(w.bea_id.as_str()), Some("left_team")), "{d}");
    assert!(std::fs::symlink_metadata(&bea_home).is_err(), "Bea's home is still there");
    assert!(!w.m.agent.teammates.known().contains(&w.bea_id));
    assert_eq!(std::fs::read_to_string(&w.secret).unwrap(), "ada's login", "Ada's login is untouched");
    assert!(events(&w.env, "machine.teammate_removal_failed").await.is_empty());

    // And she's out: no Bot, no machine, no login.
    for (m, p, b) in [("POST", format!("/api/bots/{bot}/messages"), r#"{"text":"back"}"#), ("GET", logins.clone(), "")] {
        assert_eq!(call(w.env.port, m, &p, &w.bea, b).await.0, 404, "Bea: {m} {p}");
    }
    let left = events(&w.env, "team.member_left").await;
    assert_eq!(left[0]["details"]["reason"], "left", "{left:?}");
}
