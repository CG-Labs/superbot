//! HTTP tests for Bot ACLs (ADR 0017), on the real router: who can see, run, and
//! manage which Bot, what they get in lists and the live stream, and the audit trail.

use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Got {
    /// 404 "Bot not found": as if it didn't exist.
    Hidden,
    Forbidden,
    Allowed,
}

async fn got(port: u16, method: &str, path: &str, auth: &str, body: &str) -> Got {
    let (code, res) = call(port, method, path, auth, body).await;
    assert_ne!(code, 401, "{method} {path}");
    match code {
        403 => Got::Forbidden,
        404 if parse(&res)["error"].as_str().is_some_and(|e| {
            e.starts_with("Bot") || e.starts_with("Routine") || e.starts_with("Approval")
        }) =>
        {
            Got::Hidden
        }
        _ => Got::Allowed,
    }
}

fn ids(body: &str) -> Vec<String> {
    parse(body)
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|b| b["id"].as_str().map(String::from))
        .collect()
}

/// One private Bot owned by member A, and everyone's access to it.
#[tokio::test]
async fn the_allow_deny_matrix() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (_, b) = user_with(port, &admin, "b@example.com", "member").await;
    let (c_id, c) = user_with(port, &admin, "c@example.com", "member").await;
    let (d_id, d) = user_with(port, &admin, "d@example.com", "member").await;
    let (r_id, r) = user_with(port, &admin, "r@example.com", "readonly").await;
    let p = app.db.create_bot_owned(
        "Private",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    app.db.set_grant(&p.id, &c_id, acl::Grant::Viewer, &a_id);
    app.db.set_grant(&p.id, &d_id, acl::Grant::Operator, &a_id);
    // Read-only users never get past viewing, whatever their grant.
    app.db.set_grant(&p.id, &r_id, acl::Grant::Operator, &a_id);
    let routine = app.db.add_routine(&p.id, "Daily", "0 9 * * *", "x");
    let pid = p.id.as_str();

    use Access::{Manage as M, Operate as O, View as V};
    let routes: Vec<(&str, String, String, Access)> = vec![
        ("GET", format!("/api/bots/{pid}/messages"), "".into(), V),
        ("GET", format!("/api/bots/{pid}/routines"), "".into(), V),
        ("GET", format!("/api/bots/{pid}/policy"), "".into(), V),
        ("GET", format!("/api/bots/{pid}/access"), "".into(), V),
        ("GET", format!("/api/policy/rules?bot={pid}"), "".into(), V),
        ("GET", format!("/api/approvals?bot={pid}"), "".into(), V),
        ("POST", format!("/api/bots/{pid}/read"), "".into(), O),
        ("POST", format!("/api/bots/{pid}/stop"), "".into(), O),
        ("GET", format!("/api/bots/{pid}/screen"), "".into(), O),
        (
            "POST",
            format!("/api/bots/{pid}/routines"),
            r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#.into(),
            O,
        ),
        (
            "PATCH",
            format!("/api/routines/{}", routine.id),
            r#"{"enabled":true}"#.into(),
            O,
        ),
        (
            "POST",
            "/api/handoff".into(),
            json!({ "from": pid }).to_string(),
            O,
        ),
        (
            "POST",
            "/api/ask".into(),
            json!({ "from": pid, "to": pid }).to_string(),
            O,
        ),
        (
            "PATCH",
            format!("/api/bots/{pid}"),
            r##"{"color":"#3b82f6"}"##.into(),
            M,
        ),
        (
            "PATCH",
            format!("/api/bots/{pid}/access"),
            r#"{"visibility":"private"}"#.into(),
            M,
        ),
        (
            "PUT",
            format!("/api/bots/{pid}/grants/c%40example.com"),
            r#"{"level":"viewer"}"#.into(),
            M,
        ),
    ];
    let people = [
        ("admin", &admin, M),
        ("owner", &a, M),
        ("stranger", &b, Access::None),
        ("viewer", &c, V),
        ("operator", &d, O),
        ("readonly", &r, V),
    ];
    for (who, auth, has) in people {
        for (method, path, body, need) in &routes {
            let want = match (has, who) {
                (Access::None, _) => Got::Hidden,
                // Its role refuses writes before any ACL check.
                (_, "readonly") if *method != "GET" => Got::Forbidden,
                _ if has >= *need => Got::Allowed,
                _ => Got::Forbidden,
            };
            assert_eq!(
                got(port, method, path, auth, body).await,
                want,
                "{who} {method} {path}"
            );
        }
    }

    // Lists keep only what each can see, tagged with their access.
    for (who, auth, has) in people {
        let (_, list) = call(port, "GET", "/api/bots", auth, "").await;
        let (_, state) = call(port, "GET", "/api/state", auth, "").await;
        let mine = |v: Value| {
            v.as_array()
                .unwrap()
                .iter()
                .find(|b| b["id"] == pid)
                .map(|b| b["access"].clone())
        };
        let want = (has != Access::None).then(|| json!(has));
        assert_eq!(mine(parse(&list)), want, "{who} /api/bots");
        assert_eq!(
            mine(parse(&state)["bots"].clone()),
            want,
            "{who} /api/state"
        );
    }
    let (_, access) = call(port, "GET", &format!("/api/bots/{pid}/access"), &c, "").await;
    let access = parse(&access);
    assert_eq!(
        (
            access["owner"]["id"].as_str(),
            access["visibility"].as_str(),
            access["access"].as_str()
        ),
        (Some(a_id.as_str()), Some("private"), Some("view"))
    );
    assert!(
        access["grants"].is_null(),
        "only those who manage it see its grants"
    );
    let (_, access) = call(port, "GET", &format!("/api/bots/{pid}/access"), &a, "").await;
    assert_eq!(parse(&access)["grants"].as_array().map(Vec::len), Some(3));

    // Deleting needs manage too; a hidden Bot stays hidden.
    assert_eq!(
        got(port, "DELETE", &format!("/api/bots/{pid}"), &b, "").await,
        Got::Hidden
    );
    assert_eq!(
        got(port, "DELETE", &format!("/api/bots/{pid}"), &d, "").await,
        Got::Forbidden
    );
    assert_eq!(
        got(
            port,
            "DELETE",
            &format!("/api/routines/{}", routine.id),
            &c,
            ""
        )
        .await,
        Got::Forbidden
    );
    assert_eq!(
        got(
            port,
            "DELETE",
            &format!("/api/routines/{}", routine.id),
            &b,
            ""
        )
        .await,
        Got::Hidden
    );
    assert_eq!(
        got(port, "DELETE", &format!("/api/bots/{pid}"), &a, "").await,
        Got::Allowed
    );
    assert!(app.db.bot(pid).is_none());

    let (_, body) = call(
        port,
        "GET",
        "/api/audit?action=access.denied&limit=1000",
        &admin,
        "",
    )
    .await;
    let denied: Vec<Value> = audit_list(&body)
        .into_iter()
        .filter(|e| e["details"]["reason"] == "bot_acl")
        .collect();
    assert!(
        denied
            .iter()
            .any(|e| e["actorName"] == "b" && e["details"]["has"] == "none" && e["botId"] == pid)
    );
    assert!(denied.iter().any(|e| e["actorName"] == "c"
        && e["details"]["need"] == "operate"
        && e["details"]["has"] == "view"));
    assert!(
        denied
            .iter()
            .any(|e| e["actorName"] == "d" && e["details"]["need"] == "manage")
    );
}

#[tokio::test]
async fn owners_share_and_grant_and_admins_reassign() {
    let (port, _, admin, _) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "b@example.com", "member").await;
    let (_, r) = user_with(port, &admin, "r@example.com", "readonly").await;

    // A person owns what they make, private if they ask.
    let (code, made) = call(
        port,
        "POST",
        "/api/bots",
        &a,
        r#"{"name":"Mine","visibility":"private"}"#,
    )
    .await;
    assert_eq!(code, 201, "{made}");
    let made = parse(&made);
    assert_eq!(
        (
            made["owner"]["id"].as_str(),
            made["visibility"].as_str(),
            made["access"].as_str()
        ),
        (Some(a_id.as_str()), Some("private"), Some("manage"))
    );
    let id = made["id"].as_str().unwrap().to_string();
    assert_eq!(
        call(
            port,
            "POST",
            "/api/bots",
            &a,
            r#"{"name":"X","visibility":"public"}"#
        )
        .await
        .0,
        400
    );
    let (_, shared) = call(port, "POST", "/api/bots", &a, r#"{"name":"Shared"}"#).await;
    assert_eq!(parse(&shared)["visibility"], "shared", "shared by default");
    let shared_id = parse(&shared)["id"].as_str().unwrap().to_string();
    let access = format!("/api/bots/{id}/access");
    assert!(!ids(&call(port, "GET", "/api/bots", &b, "").await.1).contains(&id));

    // Sharing: only the owner or an admin.
    assert_eq!(
        call(
            port,
            "PATCH",
            &format!("/api/bots/{shared_id}/access"),
            &b,
            r#"{"visibility":"private"}"#
        )
        .await
        .0,
        403,
        "operate is not manage"
    );
    assert_eq!(
        call(port, "PATCH", &access, &r, r#"{"visibility":"shared"}"#)
            .await
            .0,
        403
    );
    assert_eq!(
        call(port, "PATCH", &access, &a, r#"{"visibility":"everyone"}"#)
            .await
            .0,
        400
    );
    assert_eq!(call(port, "PATCH", &access, &a, "{}").await.0, 400);
    let (code, res) = call(port, "PATCH", &access, &a, r#"{"visibility":"shared"}"#).await;
    assert_eq!(
        (code, parse(&res)["visibility"].as_str()),
        (200, Some("shared")),
        "{res}"
    );
    let (_, list) = call(port, "GET", "/api/bots", &b, "").await;
    let seen = parse(&list)
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == id.as_str())
        .cloned()
        .unwrap();
    assert_eq!(seen["access"], "operate");
    assert_eq!(
        call(port, "PATCH", &access, &a, r#"{"visibility":"private"}"#)
            .await
            .0,
        200
    );

    // Grants: add, change, refuse nonsense, revoke.
    let grant = format!("/api/bots/{id}/grants/b%40example.com");
    assert_eq!(
        call(port, "PUT", &grant, &b, r#"{"level":"operator"}"#)
            .await
            .0,
        404,
        "B can't see it, so can't grant itself"
    );
    assert_eq!(
        call(port, "PUT", &grant, &a, r#"{"level":"owner"}"#)
            .await
            .0,
        400
    );
    assert_eq!(
        call(
            port,
            "PUT",
            &format!("/api/bots/{id}/grants/nobody%40example.com"),
            &a,
            r#"{"level":"viewer"}"#
        )
        .await
        .0,
        404
    );
    assert_eq!(
        call(
            port,
            "PUT",
            &format!("/api/bots/{id}/grants/{a_id}"),
            &a,
            r#"{"level":"viewer"}"#
        )
        .await
        .0,
        409,
        "the owner"
    );
    let (code, res) = call(port, "PUT", &grant, &a, r#"{"level":"viewer"}"#).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(parse(&res)["grants"][0]["user"]["id"], b_id.as_str());
    assert_eq!(
        call(port, "GET", &format!("/api/bots/{id}/messages"), &b, "")
            .await
            .0,
        200
    );
    assert_eq!(
        call(port, "POST", &format!("/api/bots/{id}/stop"), &b, "")
            .await
            .0,
        403
    );
    assert_eq!(
        call(port, "PUT", &grant, &a, r#"{"level":"operator"}"#)
            .await
            .0,
        200
    );
    assert_eq!(
        call(port, "POST", &format!("/api/bots/{id}/stop"), &b, "")
            .await
            .0,
        200
    );
    assert_eq!(
        call(port, "PATCH", &access, &b, r#"{"visibility":"shared"}"#)
            .await
            .0,
        403,
        "operators don't manage"
    );
    assert_eq!(call(port, "DELETE", &grant, &a, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &grant, &a, "").await.0, 404);
    assert_eq!(
        call(port, "GET", &format!("/api/bots/{id}/messages"), &b, "")
            .await
            .0,
        404
    );

    // Giving a Bot away: admins only, to an active user.
    assert_eq!(
        call(
            port,
            "PATCH",
            &access,
            &a,
            &json!({ "owner": b_id }).to_string()
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            port,
            "PATCH",
            &access,
            &admin,
            r#"{"owner":"ghost@example.com"}"#
        )
        .await
        .0,
        404
    );
    let (code, res) = call(
        port,
        "PATCH",
        &access,
        &admin,
        r#"{"owner":"B@example.com"}"#,
    )
    .await;
    assert_eq!(
        (code, parse(&res)["owner"]["id"].as_str()),
        (200, Some(b_id.as_str())),
        "{res}"
    );
    assert_eq!(
        call(port, "GET", &format!("/api/bots/{id}/messages"), &a, "")
            .await
            .0,
        404,
        "private, and no longer A's"
    );
    assert_eq!(
        call(
            port,
            "PATCH",
            &format!("/api/bots/{id}"),
            &b,
            r#"{"name":"Ours"}"#
        )
        .await
        .0,
        200
    );

    let (_, body) = call(
        port,
        "GET",
        &format!("/api/audit?bot={id}&limit=1000"),
        &admin,
        "",
    )
    .await;
    let ev = audit_list(&body);
    let has = |action: &str, f: &dyn Fn(&Value) -> bool| {
        ev.iter().any(|e| e["action"] == action && f(&e["details"]))
    };
    assert!(has("bot.created", &|d| d["owner"] == a_id.as_str()
        && d["visibility"] == "private"));
    assert!(has("bot.visibility_changed", &|d| d["from"] == "private"
        && d["to"] == "shared"));
    assert!(has("bot.access_granted", &|d| d["user"] == b_id.as_str()
        && d["level"] == "viewer"
        && d["from"].is_null()));
    assert!(has("bot.access_granted", &|d| d["level"] == "operator"
        && d["from"] == "viewer"));
    assert!(has("bot.access_revoked", &|d| d["user"] == b_id.as_str()
        && d["level"] == "operator"));
    assert!(has("bot.owner_changed", &|d| d["from"] == a_id.as_str()
        && d["to"] == b_id.as_str()));
}

#[tokio::test]
async fn approvals_follow_bot_access() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, _) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "b@example.com", "member").await;
    let (_, c) = user_with(port, &admin, "c@example.com", "member").await;
    let p = app.db.create_bot_owned(
        "Private",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    app.db.set_grant(&p.id, &b_id, acl::Grant::Viewer, &a_id);
    let far = db::now() + 600_000;
    let ap = app.db.add_approval(
        &p.id,
        "claude",
        "Bash",
        "shell",
        "ls",
        &json!({}),
        "shell",
        "ask",
        far,
    );
    let ids = |body: &str| {
        parse(body)
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    assert!(ids(&call(port, "GET", "/api/approvals", &c, "").await.1).is_empty());
    assert!(
        parse(&call(port, "GET", "/api/state", &c, "").await.1)["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ids(&call(port, "GET", "/api/approvals", &b, "").await.1),
        [ap.id.as_str()]
    );
    let approve = format!("/api/approvals/{}/approve", ap.id);
    assert_eq!(got(port, "POST", &approve, &c, "{}").await, Got::Hidden);
    assert_eq!(
        got(port, "POST", &approve, &b, "{}").await,
        Got::Forbidden,
        "viewers can't answer"
    );
    app.db.set_grant(&p.id, &b_id, acl::Grant::Operator, &a_id);
    let (code, res) = call(port, "POST", &approve, &b, "{}").await;
    assert_eq!(
        (code, parse(&res)["status"].as_str()),
        (200, Some("approved")),
        "{res}"
    );

    // Others' hidden approvals don't crowd yours out of a page.
    let mine = app.db.create_bot_owned(
        "Mine",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &b_id,
        Visibility::Private,
    );
    let ap_b = app.db.add_approval(
        &mine.id,
        "claude",
        "Bash",
        "shell",
        "ls",
        &json!({}),
        "shell",
        "ask",
        far,
    );
    for _ in 0..200 {
        app.db.add_approval(
            &p.id,
            "claude",
            "Bash",
            "shell",
            "ls",
            &json!({}),
            "shell",
            "ask",
            far,
        );
    }
    app.db.remove_grant(&p.id, &b_id);
    assert_eq!(
        ids(
            &call(port, "GET", "/api/approvals?status=pending&limit=1", &b, "")
                .await
                .1
        ),
        std::slice::from_ref(&ap_b.id)
    );
    let state = parse(&call(port, "GET", "/api/state", &b, "").await.1);
    assert_eq!(
        state["approvals"]
            .as_array()
            .map(|l| l.iter().map(|a| a["id"].clone()).collect::<Vec<_>>()),
        Some(vec![json!(ap_b.id)])
    );
}

/// Answering a handoff card goes only to a Bot the caller can operate.
#[tokio::test]
async fn handoff_answers_stay_with_their_bot() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, _) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "b@example.com", "member").await;
    let p = app.db.create_bot_owned(
        "Private",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    let s = app.db.create_bot_owned(
        "Shared",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Shared,
    );
    app.db.set_grant(&p.id, &b_id, acl::Grant::Viewer, &a_id);
    let waiting = {
        let (app, p) = (app.clone(), p.clone());
        tokio::spawn(async move { app.handoff(&p, "Sign in", Duration::from_secs(5)).await })
    };
    let card = loop {
        if let Some(m) = app
            .db
            .messages(&p.id, 10)
            .into_iter()
            .find(|m| m.question.is_some())
        {
            break m.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    let sneaky =
        json!({ "text": "Done", "answer": { "messageId": card, "option": 0 } }).to_string();
    assert_eq!(
        call(
            port,
            "POST",
            &format!("/api/bots/{}/messages", s.id),
            &b,
            &sneaky
        )
        .await
        .0,
        202
    );
    assert_eq!(
        got(
            port,
            "POST",
            &format!("/api/bots/{}/messages", p.id),
            &b,
            &sneaky
        )
        .await,
        Got::Forbidden
    );
    assert!(
        app.db
            .message(card)
            .and_then(|m| m.question)
            .is_some_and(|q| q["picked"].is_null())
    );
    let tx = app.take_handoff(card).expect("still waiting");
    tx.send("from the owner".into()).unwrap();
    assert_eq!(waiting.await.unwrap().as_deref(), Some("from the owner"));
}

/// Reads the stream until `until` shows up. Returns all it read.
pub(super) async fn read_until(s: &mut tokio::net::TcpStream, until: &str) -> String {
    let mut got = String::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !got.contains(until) {
        let n = tokio::time::timeout_at(deadline, s.read(&mut buf))
            .await
            .expect("timed out")
            .unwrap();
        assert!(n > 0, "stream closed");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    got
}

#[tokio::test]
async fn the_live_stream_carries_only_visible_bots() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, _) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "b@example.com", "member").await;
    let p = app.db.create_bot_owned(
        "Private",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    let s = app.db.create_bot_owned(
        "Shared",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Shared,
    );
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let req =
        format!("GET /api/events HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {b}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    read_until(&mut stream, "\r\n\r\n").await;

    app.push_bot(&p.id);
    app.send(json!({ "type": "status", "botId": p.id, "working": true }));
    app.push_bot(&s.id);
    let got = read_until(&mut stream, &s.id).await;
    assert!(!got.contains(&p.id), "{got}");
    assert!(got.contains(r#""access":"operate""#), "{got}");

    // A grant sends a resync, after which the Bot shows up.
    let (code, _) = call(
        port,
        "PUT",
        &format!("/api/bots/{}/grants/{b_id}", p.id),
        &admin,
        r#"{"level":"viewer"}"#,
    )
    .await;
    assert_eq!(code, 200);
    let got = read_until(&mut stream, r#""access":"view""#).await;
    assert!(got.contains("resync") && got.contains(&p.id), "{got}");
    app.send(json!({ "type": "draft", "botId": p.id, "text": "hello there" }));
    read_until(&mut stream, "hello there").await;

    // A role change re-scopes an open stream, and tells the client to reload.
    let other = app.db.create_bot_owned(
        "Other",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    assert_eq!(
        call(
            port,
            "PATCH",
            &format!("/api/users/{b_id}"),
            &admin,
            r#"{"role":"admin"}"#
        )
        .await
        .0,
        200
    );
    read_until(&mut stream, "resync").await;
    app.send(json!({ "type": "draft", "botId": other.id, "text": "now visible" }));
    read_until(&mut stream, "now visible").await;
}

#[tokio::test]
async fn bots_act_with_their_owners_access() {
    let (port, app, admin, key) = serve_app().await;
    let (a_id, _) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, _) = user_with(port, &admin, "b@example.com", "member").await;
    let p = app.db.create_bot_owned(
        "Secret",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    let helper = app.db.create_bot_owned(
        "Helper",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &b_id,
        Visibility::Private,
    );
    let bot = key.auth(&helper.id);
    let as_helper = "";

    let (_, _, list) = call_with(port, "GET", "/api/bots", &bot, as_helper, "").await;
    let list = ids(&list);
    assert!(
        list.contains(&helper.id) && !list.contains(&p.id),
        "{list:?}"
    );
    let ask = json!({ "from": helper.id, "to": "Secret", "text": "hi" }).to_string();
    let (code, _, res) = call_with(port, "POST", "/api/ask", &bot, as_helper, &ask).await;
    assert_eq!(code, 400, "{res}");
    assert!(res.contains("No Bot named"), "{res}");
    assert_eq!(
        call_with(
            port,
            "GET",
            &format!("/api/bots/{}/messages", p.id),
            &bot,
            as_helper,
            ""
        )
        .await
        .0,
        404
    );

    // A new Bot made by a Bot belongs to that Bot's owner.
    let (code, _, made) = call_with(
        port,
        "POST",
        "/api/bots",
        &bot,
        as_helper,
        r#"{"name":"Child"}"#,
    )
    .await;
    assert_eq!(code, 201, "{made}");
    assert_eq!(parse(&made)["owner"]["id"], b_id.as_str());
    // Its prompt lists only the Bots its owner can see.
    let prompt = app.system_prompt(&helper);
    assert!(prompt.contains("- Child (id"));
    assert!(!prompt.contains("Secret"));
}
