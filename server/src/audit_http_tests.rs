//! HTTP tests for per-user audit actors (ADR 0018): who acted, how they signed in,
//! and whom a Bot or a run acted for, on the real router.

use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn events(port: u16, admin: &str, query: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?limit=1000&{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn session_id(port: u16, auth: &str) -> String {
    let (_, me) = call(port, "GET", "/api/auth/me", auth, "").await;
    parse(&me)["session"]["id"].as_str().unwrap().to_string()
}

async fn wait_for(port: u16, admin: &str, query: &str) -> Vec<Value> {
    for _ in 0..500 {
        let found = events(port, admin, query).await;
        if !found.is_empty() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no audit event for {query}");
}

#[tokio::test]
async fn people_are_recorded_with_how_they_signed_in() {
    let (port, _, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let ada_session = session_id(port, &ada_auth).await;
    assert_eq!(call(port, "POST", "/api/bots", &ada_auth, r#"{"name":"Ada's"}"#).await.0, 201);
    assert_eq!(call(port, "POST", "/api/bots", &admin, r#"{"name":"Owner's"}"#).await.0, 201);

    let created = events(port, &admin, "action=bot.created").await;
    let by = |name: &str| created.iter().find(|e| e["details"]["name"] == name).unwrap().clone();
    let (mine, owners) = (by("Ada's"), by("Owner's"));
    assert_eq!(
        (mine["actorKind"].as_str(), mine["actorId"].as_str(), mine["actorEmail"].as_str(), mine["actorRole"].as_str()),
        (Some("user"), Some(ada.as_str()), Some("ada@example.com"), Some("member"))
    );
    assert_eq!((mine["authMethod"].as_str(), mine["sessionId"].as_str(), mine["idp"].as_str()), (Some("code"), Some(ada_session.as_str()), None));
    // AUTH_PASSWORD over Basic: break-glass, as the owner, with no session.
    assert_eq!(
        (owners["actorId"].as_str(), owners["actorRole"].as_str(), owners["authMethod"].as_str(), owners["sessionId"].as_str()),
        (Some("operator"), Some("admin"), Some("password"), None)
    );
    // Her sign-in is on record with its session too.
    let login = &events(port, &admin, &format!("action=auth.login&actor=user:{ada}")).await[0];
    assert_eq!((login["authMethod"].as_str(), login["sessionId"].as_str(), login["targetId"].as_str()), (Some("code"), Some(ada_session.as_str()), Some(ada_session.as_str())));

    // Filters: by email (any case), method, and session.
    let actions = |ev: Vec<Value>| ev.iter().map(|e| e["action"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    let hers = actions(events(port, &admin, "actor=user:ADA@example.com").await);
    assert_eq!(hers, ["bot.created", "auth.login"]);
    assert_eq!(actions(events(port, &admin, &format!("session={ada_session}")).await), hers);
    assert!(events(port, &admin, "method=code").await.iter().all(|e| e["actorId"] == ada.as_str()));
    assert!(events(port, &admin, "method=password").await.iter().any(|e| e["actorId"] == "operator"));
    assert_eq!(call(port, "GET", "/api/audit?method=Password", &admin, "").await.0, 400);
    assert_eq!(call(port, "GET", "/api/audit?session=a%20b", &admin, "").await.0, 400);

    // The CSV export filters the same way and carries the new columns at the end.
    let (code, _, csv) = call_with(port, "GET", "/api/audit/export.csv?actor=user:ada@example.com&action=bot.created", &admin, "", "").await;
    assert_eq!(code, 200);
    let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
    assert_eq!(lines.len(), 2, "{csv}");
    assert!(lines[0].ends_with(",details,actor_email,actor_role,auth_method,idp,idp_provider,session_id,on_behalf_of"));
    assert!(lines[1].ends_with(&format!(",ada@example.com,member,code,,,{ada_session},")), "{}", lines[1]);
    let exported = &events(port, &admin, "action=audit.exported").await[0];
    assert_eq!((exported["details"]["actorId"].as_str(), exported["details"]["actorEmail"].as_str()), (Some(ada.as_str()), None), "the email became her id");

    // Tokens never reach the log.
    let (_, all) = call(port, "GET", "/api/audit?limit=1000", &admin, "").await;
    let token = ada_auth.trim_start_matches("Bearer ");
    assert!(!all.contains(token) && !csv.contains(token));
}

#[tokio::test]
async fn bots_act_for_their_owner() {
    let (port, _, admin, bot_auth) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (_, b) = call(port, "POST", "/api/bots", &ada_auth, r#"{"name":"Scout"}"#).await;
    let bot = parse(&b)["id"].as_str().unwrap().to_string();

    // botctl: the Bot, by BOT_TOKEN, for Ada.
    let botctl = format!("User-Agent: botctl\r\nX-SuperBot-Bot: {bot}\r\n");
    let routine = r#"{"name":"Standup","cron":"0 9 * * 1-5","instruction":"post the plan"}"#;
    assert_eq!(call_with(port, "POST", &format!("/api/bots/{bot}/routines"), &bot_auth, &botctl, routine).await.0, 201);
    let e = &events(port, &admin, "action=routine.created").await[0];
    assert_eq!(
        (e["actorKind"].as_str(), e["actorId"].as_str(), e["actorName"].as_str(), e["authMethod"].as_str(), e["onBehalfOf"].as_str()),
        (Some("bot"), Some(bot.as_str()), Some("Scout"), Some("bot_token"), Some(ada.as_str()))
    );
    assert_eq!((e["actorEmail"].as_str(), e["sessionId"].as_str()), (None, None), "a Bot has no email or session");
    // A Bot that doesn't name itself acts for no one in particular.
    assert_eq!(call(port, "GET", "/api/audit", &bot_auth, "").await.0, 403);
    let denied = &events(port, &admin, "action=access.denied&actor=bot").await[0];
    assert_eq!((denied["actorId"].as_str(), denied["authMethod"].as_str(), denied["onBehalfOf"].as_str()), (None, Some("bot_token"), None));

    // Its approval request is the Bot's, for Ada; her decision is hers, with her session.
    let check = json!({ "from": bot, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push origin main" }, "cwd": "/tmp" } }).to_string();
    let hook = tokio::spawn({
        let bot_auth = bot_auth.clone();
        async move { call(port, "POST", "/api/approvals/check", &bot_auth, &check).await }
    });
    let pending = loop {
        let (_, list) = call(port, "GET", "/api/approvals?status=pending", &ada_auth, "").await;
        if let Some(a) = serde_json::from_str::<Vec<Value>>(&list).unwrap().into_iter().next() {
            break a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let id = pending["id"].as_str().unwrap();
    assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/deny"), &ada_auth, "{}").await.0, 200);
    assert_eq!(hook.await.unwrap().1.lines().next(), Some("deny"));
    let requested = &events(port, &admin, "action=approval.requested").await[0];
    assert_eq!((requested["actorId"].as_str(), requested["onBehalfOf"].as_str()), (Some(bot.as_str()), Some(ada.as_str())));
    let decided = &events(port, &admin, "action=approval.denied").await[0];
    let ada_session = session_id(port, &ada_auth).await;
    assert_eq!(
        (decided["actorId"].as_str(), decided["authMethod"].as_str(), decided["sessionId"].as_str()),
        (Some(ada.as_str()), Some("code"), Some(ada_session.as_str()))
    );

    // Everything done for Ada, by her Bots, by her email.
    let for_ada = events(port, &admin, "onBehalfOf=ada@example.com").await;
    assert!(for_ada.len() >= 2 && for_ada.iter().all(|e| e["onBehalfOf"] == ada.as_str()), "{for_ada:?}");
    assert!(for_ada.iter().any(|e| e["action"] == "routine.created") && for_ada.iter().any(|e| e["action"] == "approval.requested"));
}

/// A stand-in `claude` on the Bots' PATH that replies once and exits.
fn fake_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"On it."}]}}"#;
    std::fs::write(&path, format!("#!/bin/sh\necho '{reply}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn runs_and_harness_calls_are_attributed_to_who_asked() {
    let (port, app, admin, bot_auth) = serve_app().await;
    fake_claude(&app);
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let ada_session = session_id(port, &ada_auth).await;
    let mk = |name: &'static str| {
        let auth = ada_auth.clone();
        async move {
            let (_, b) = call(port, "POST", "/api/bots", &auth, &json!({ "name": name, "harness": "claude" }).to_string()).await;
            parse(&b)["id"].as_str().unwrap().to_string()
        }
    };
    let (scout, helper) = (mk("Scout").await, mk("Helper").await);

    // A person's message: the run is hers, with her session.
    let (code, m) = call(port, "POST", &format!("/api/bots/{scout}/messages"), &ada_auth, r#"{"text":"check the build"}"#).await;
    assert_eq!(code, 202, "{m}");
    let message = parse(&m)["id"].as_i64().unwrap().to_string();
    let finished = &wait_for(port, &admin, &format!("action=bot.run_finished&bot={scout}")).await[0];
    let invoked = &events(port, &admin, &format!("action=harness.invoked&bot={scout}")).await[0];
    for e in [invoked, finished] {
        assert_eq!(
            (e["actorId"].as_str(), e["authMethod"].as_str(), e["sessionId"].as_str(), e["targetId"].as_str()),
            (Some(ada.as_str()), Some("code"), Some(ada_session.as_str()), Some(message.as_str())),
            "{e}"
        );
    }
    assert_eq!((invoked["details"]["harness"].as_str(), invoked["details"]["trigger"].as_str(), invoked["details"]["attempt"].as_i64()), (Some("claude"), Some("user"), Some(1)));
    assert_eq!((finished["outcome"].as_str(), finished["details"]["result"].as_str(), finished["details"]["replies"].as_i64()), (Some("success"), Some("done"), Some(1)));
    assert!(invoked["details"]["policy"].is_string());

    // botctl ask: the asked Bot's run is the asking Bot's, for Ada.
    let ask = json!({ "from": scout, "to": "Helper", "text": "status?" }).to_string();
    let (code, _, reply) = call_with(port, "POST", "/api/ask", &bot_auth, &format!("X-SuperBot-Bot: {scout}\r\n"), &ask).await;
    assert_eq!((code, reply.as_str()), (200, "On it."));
    let asked = &events(port, &admin, "action=bot.asked").await[0];
    assert_eq!((asked["actorId"].as_str(), asked["authMethod"].as_str(), asked["onBehalfOf"].as_str()), (Some(scout.as_str()), Some("bot_token"), Some(ada.as_str())));
    let peer = &wait_for(port, &admin, &format!("action=bot.run_finished&bot={helper}")).await[0];
    assert_eq!((peer["actorKind"].as_str(), peer["actorId"].as_str(), peer["onBehalfOf"].as_str()), (Some("bot"), Some(scout.as_str()), Some(ada.as_str())));
    assert_eq!(peer["details"]["trigger"], "peer");

    // Everything Ada's Bots ran for her, and a routine run with no requester saved.
    let routine = app.db.add_message(&helper, "routine", "Standup: post the plan", None, false, Some("queued"));
    app.enqueue(routine.clone());
    let scheduled = wait_for(port, &admin, &format!("action=harness.invoked&actor=system:scheduler&bot={helper}")).await;
    assert_eq!((scheduled[0]["onBehalfOf"].as_str(), scheduled[0]["details"]["trigger"].as_str()), (Some(ada.as_str()), Some("routine")));
    assert!(events(port, &admin, &format!("onBehalfOf={ada}&action=harness.invoked")).await.len() >= 2);
}
