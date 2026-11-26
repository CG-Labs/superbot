//! Team owners and admins deciding requests for roles within their own team (ADR 0263), on
//! the real router: only requests within their team, from people still on it; approved
//! only for its plain members, never their own, never over a role from the identity
//! provider; checked again in the approval's transaction; audited as the team's.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn requestable(port: u16, admin: &str, name: &str, perms: &[&str], days: i64) -> String {
    let body = json!({ "name": name, "permissions": perms, "maxDays": days, "requestable": true });
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn team(port: u16, admin: &str, name: &str, owner: &str, members: &[(&str, &str)]) -> String {
    let (code, t) = json_call(port, "POST", "/api/teams", admin, &json!({ "name": name, "owner": owner }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let id = t["id"].as_str().unwrap().to_string();
    for (u, r) in members {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{id}/members/{u}"), admin, &json!({ "role": r }).to_string()).await.0, 200);
    }
    id
}

/// Files a request that must succeed. Returns its id.
async fn asked(port: u16, who: &str, body: Value) -> String {
    let (code, v) = json_call(port, "POST", "/api/me/role-requests", who, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

fn at(id: &str, verb: &str) -> String {
    format!("/api/team/role-requests/{id}/{verb}")
}

#[tokio::test]
async fn team_owners_and_admins_decide_requests_within_their_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "eve@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (dee, dee_auth) = user_with(port, &admin, "dee@example.com", "member").await;
    let (bea, bea_auth) = user_with(port, &admin, "bea@example.com", "member").await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let alpha = team(port, &admin, "Alpha", &ada, &[(&eve, "admin"), (&cy, "member"), (&dee, "member")]).await;
    team(port, &admin, "Beta", &bea, &[(&bo, "member")]).await;
    let helpdesk = requestable(port, &admin, "Team helpdesk", &["users.manage", "audit.view"], 7).await;
    requestable(port, &admin, "On-call", &["machines.manage"], 1).await;

    let cy_q = asked(port, &cy_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 48, "reason": "Onboarding week" })).await;
    let org_q = asked(port, &dee_auth, json!({ "role": "On-call", "hours": 8, "reason": "Incident 42" })).await;
    let bo_q = asked(port, &bo_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "Beta's invites" })).await;

    // Owners and admins see how many wait, and which: only their team's, never one across the server.
    for who in [&ada_auth, &eve_auth] {
        let (_, mine) = json_call(port, "GET", "/api/team", who, "").await;
        assert_eq!(mine["roleRequests"], 1, "{mine}");
        let (code, v) = json_call(port, "GET", "/api/team/role-requests", who, "").await;
        assert_eq!((code, v["pending"].as_i64(), v["team"]["name"].as_str()), (200, Some(1), Some("Alpha")), "{v}");
        let q = &v["requests"][0];
        assert_eq!((q["id"].as_str(), q["user"]["id"].as_str(), q["reason"].as_str(), q["role"]["applies"].clone()), (Some(cy_q.as_str()), Some(cy.as_str()), Some("Onboarding week"), json!(["users.manage"])), "{v}");
    }
    let (_, v) = json_call(port, "GET", "/api/team/role-requests", &bea_auth, "").await;
    assert_eq!(v["requests"].as_array().unwrap().iter().map(|q| q["id"].as_str().unwrap()).collect::<Vec<_>>(), [bo_q.as_str()], "{v}");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert!(mine.get("roleRequests").is_none(), "members aren't told: {mine}");
    assert_eq!(call(port, "GET", "/api/team/role-requests", &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/team/role-requests?status=nope", &ada_auth, "").await.0, 400);

    // Requests elsewhere read as missing, and plain members decide nothing.
    for (who, id, code, why) in [
        (&bea_auth, &cy_q, 404, "another team's owner"),
        (&ada_auth, &bo_q, 404, "another team's request"),
        (&ada_auth, &org_q, 404, "a request across the server stays with server admins"),
        (&dee_auth, &cy_q, 403, "a plain member"),
        (&cy_auth, &cy_q, 403, "the asker, a plain member"),
    ] {
        let (c, v) = json_call(port, "POST", &at(id, "approve"), who, "{}").await;
        assert_eq!(c, code, "{why}: {v}");
        assert_eq!(call(port, "POST", &at(id, "deny"), who, "{}").await.0, code, "{why}");
    }
    assert_eq!(call(port, "POST", &at(&cy_q, "approve"), &eve_auth, r#"{"hours":49}"#).await.0, 400, "never longer than asked");
    assert_eq!(call(port, "POST", &at(&cy_q, "approve"), &eve_auth, r#"{"until":5}"#).await.0, 400, "unknown field");

    // A team admin approves it for fewer hours; only its team permissions apply, only there.
    let (code, v) = json_call(port, "POST", &at(&cy_q, "approve"), &eve_auth, r#"{"hours":24,"note":"A day is enough"}"#).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["applies"].clone()), (200, Some("approved"), json!(["users.manage"])), "{v}");
    let ends = v["role"]["expiresAt"].as_i64().unwrap();
    assert!((ends - db::now() - 24 * 3_600_000).abs() < 60_000, "{v}");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!((mine["customRole"]["id"].as_str(), mine["permissions"].clone()), (Some(helpdesk.as_str()), json!(["users.manage"])), "{mine}");
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 201);
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 403, "nothing across the server");
    assert_eq!(app.db.user(&cy).unwrap().role_id, None);
    let approved = &events(port, &admin, "role.request_approved").await[0];
    let d = &approved["details"];
    assert_eq!((approved["actorId"].as_str(), d["via"].as_str(), d["hours"].as_i64(), d["requestedHours"].as_i64(), d["note"].as_str()), (Some(eve.as_str()), Some("team"), Some(24), Some(48), Some("A day is enough")), "{approved}");
    let given = &events(port, &admin, "role.assigned").await[0];
    let d = &given["details"];
    assert_eq!((d["via"].as_str(), d["request"].as_str(), d["team"].as_str(), d["reason"].as_str(), d["expiresAt"].as_i64()), (Some("team"), Some(cy_q.as_str()), Some(alpha.as_str()), Some("Onboarding week"), Some(ends)), "{given}");
    assert_eq!(call(port, "POST", &at(&cy_q, "approve"), &ada_auth, "{}").await.0, 409, "decided already");
    let (_, mine) = json_call(port, "GET", "/api/team", &ada_auth, "").await;
    assert_eq!(mine["roleRequests"], 0, "{mine}");

    // Holding users.manage in the team, they still don't decide: only owners and admins do.
    let dee_q = asked(port, &dee_auth, json!({ "role": helpdesk, "scope": "team", "hours": 8, "reason": "Cover for cy" })).await;
    assert_eq!(call(port, "GET", "/api/team/role-requests", &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "POST", &at(&dee_q, "approve"), &cy_auth, "{}").await.0, 403);

    // The owner denies one, with a note the asker sees.
    let (code, v) = json_call(port, "POST", &at(&dee_q, "deny"), &ada_auth, r#"{"note":"cy has it covered"}"#).await;
    assert_eq!((code, v["status"].as_str(), v["note"].as_str()), (200, Some("denied"), Some("cy has it covered")), "{v}");
    assert_eq!(call(port, "POST", &at(&dee_q, "deny"), &ada_auth, "{}").await.0, 409, "denied already");
    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &dee_auth, "").await;
    assert_eq!(mine["requests"][0]["note"].as_str(), Some("cy has it covered"), "{mine}");
    let denied = &events(port, &admin, "role.request_denied").await[0];
    assert_eq!((denied["actorId"].as_str(), denied["details"]["via"].as_str()), (Some(ada.as_str()), Some("team")), "{denied}");
    let (_, v) = json_call(port, "GET", "/api/team/role-requests?status=all", &ada_auth, "").await;
    assert_eq!((v["requests"].as_array().unwrap().len(), v["pending"].as_i64()), (2, Some(0)), "{v}");

    // Server admins still decide team requests, without a via.
    let (code, _) = json_call(port, "POST", &format!("/api/role-requests/{bo_q}/approve"), &admin, "{}").await;
    assert_eq!(code, 200);
    assert!(events(port, &admin, "role.request_approved").await[0]["details"].get("via").is_none());
    assert_eq!(app.db.team_member(&bo).unwrap().role_id.as_deref(), Some(helpdesk.as_str()));
}

#[tokio::test]
async fn not_their_own_nor_a_team_admins_nor_over_the_identity_provider() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "eve@example.com", "member").await;
    let (fay, fay_auth) = user_with(port, &admin, "fay@example.com", "member").await;
    let (gus, gus_auth) = user_with(port, &admin, "gus@example.com", "member").await;
    let alpha = team(port, &admin, "Alpha", &ada, &[(&eve, "admin"), (&fay, "member"), (&gus, "member")]).await;
    let helpdesk = requestable(port, &admin, "Team helpdesk", &["users.manage"], 7).await;
    let billing = requestable(port, &admin, "Team billing", &["billing.manage"], 7).await;

    // A team admin's own request: not by themselves, and not by the team's owner either,
    // since they can do all of it already. A server admin still can.
    let eve_q = asked(port, &eve_auth, json!({ "role": helpdesk, "scope": "team", "hours": 8, "reason": "x" })).await;
    let (code, v) = json_call(port, "POST", &at(&eve_q, "approve"), &eve_auth, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("your own request"), "{v}");
    let (code, v) = json_call(port, "POST", &at(&eve_q, "approve"), &ada_auth, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("owners or admins"), "{v}");
    assert_eq!(app.db.role_request(&eve_q).unwrap().status, "pending", "a refused approval leaves it pending");
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{eve_q}/approve"), &admin, "{}").await.0, 200);

    // A role the identity provider gives them in the team stays with its mapping, even when
    // SCIM gives it after they asked.
    let fay_q = asked(port, &fay_auth, json!({ "role": helpdesk, "scope": "team", "hours": 8, "reason": "x" })).await;
    app.db.link_scim_group("okta", &alpha, None, "Alpha", None).unwrap();
    let standing = {
        let body = json!({ "name": "Team payer", "permissions": ["billing.manage"] });
        json_call(port, "POST", "/api/roles", &admin, &body.to_string()).await.1["id"].as_str().unwrap().to_string()
    };
    let m = app.db.create_scim_role_mapping("okta", &alpha, &standing, "team", None).unwrap();
    assert!(app.db.grant_scim_role(&m, &fay));
    let (code, v) = json_call(port, "POST", &at(&fay_q, "approve"), &ada_auth, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("identity provider"), "{v}");
    assert_eq!(app.db.team_member(&fay).unwrap().role_id.as_deref(), Some(standing.as_str()), "unchanged");
    // Read in the approval's own transaction.
    let saw = std::cell::Cell::new(false);
    let r = app.db.approve_role_request(
        &fay_q,
        None,
        Some(&ada),
        None,
        |s| {
            saw.set(s.from_idp);
            Err("from_idp")
        },
        |_| false,
    );
    assert_eq!((saw.get(), r.unwrap_err()), (true, db::RoleRequestError::Refused("from_idp")));
    // Denying changes no role, so they may.
    assert_eq!(call(port, "POST", &at(&fay_q, "deny"), &ada_auth, "{}").await.0, 200);

    // Someone who left the team: their requests are gone from its view, and can't be decided there.
    let gus_q = asked(port, &gus_auth, json!({ "role": billing, "scope": "team", "hours": 8, "reason": "x" })).await;
    let (_, v) = json_call(port, "GET", "/api/team/role-requests", &ada_auth, "").await;
    assert_eq!(v["pending"], 1, "{v}");
    assert_eq!(call(port, "POST", "/api/team/leave", &gus_auth, "").await.0, 200);
    let (_, v) = json_call(port, "GET", "/api/team/role-requests?status=all", &ada_auth, "").await;
    assert!(v["requests"].as_array().unwrap().iter().all(|q| q["id"] != gus_q.as_str()), "{v}");
    assert_eq!(v["pending"], 0, "{v}");
    assert_eq!(call(port, "POST", &at(&gus_q, "approve"), &ada_auth, "{}").await.0, 404);
    assert_eq!(call(port, "POST", &at(&gus_q, "deny"), &ada_auth, "{}").await.0, 404);
}

pub(crate) async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..500 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// A notifier with a stand-in mail server and push provider, and email on to `ops@example.com`.
pub(crate) async fn notices(app: &App) -> (notify::smtp::fake::Server, notify::push::fake::Recorder) {
    use notify::{push, smtp};
    let mail = smtp::fake::start(Default::default()).await;
    let rec = push::fake::Recorder::default();
    let p = push::Push::new(Box::new(rec.clone()), users::SessionConfig::default());
    let n = notify::Notifier::new(Some(smtp::Smtp::for_test("127.0.0.1", mail.port, smtp::Tls::None, None, None)), Some("https://bots.example.com".into())).with_push(p);
    assert!(app.notifier.set(Arc::new(n)).is_ok());
    let email = notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: true };
    notify::save(&app.db, &notify::Settings { email, ..Default::default() });
    (mail, rec)
}

pub(crate) fn mailed(mail: &notify::smtp::fake::Server) -> Vec<String> {
    let mut to: Vec<String> = mail.got.lock().unwrap().iter().flat_map(|m| m.to.clone()).collect();
    to.sort();
    to
}

pub(crate) fn pushed(rec: &notify::push::fake::Recorder) -> Vec<String> {
    let mut to: Vec<String> = rec.sent.lock().unwrap().iter().map(|m| m.to.clone()).collect();
    to.sort();
    to
}

#[tokio::test]
async fn team_owners_and_admins_hear_of_requests_they_may_decide() {
    let (port, app, admin, _) = serve_app().await;
    let (mail, rec) = notices(&app).await;
    let (ada, ada_auth) = user_with(port, &admin, "notice-ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "notice-eve@example.com", "member").await;
    let (rae, _) = user_with(port, &admin, "notice-rae@example.com", "readonly").await;
    let (dot, dot_auth) = user_with(port, &admin, "notice-dot@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "notice-cy@example.com", "member").await;
    let (dee, dee_auth) = user_with(port, &admin, "notice-dee@example.com", "member").await;
    let (bea, bea_auth) = user_with(port, &admin, "notice-bea@example.com", "member").await;
    team(port, &admin, "Alpha", &ada, &[(&eve, "admin"), (&rae, "admin"), (&dot, "admin"), (&cy, "member"), (&dee, "member")]).await;
    team(port, &admin, "Beta", &bea, &[]).await;
    requestable(port, &admin, "Team helpdesk", &["users.manage", "audit.view"], 7).await;
    requestable(port, &admin, "On-call", &["machines.manage"], 1).await;
    let phone = |who: &str| format!("ExponentPushToken[{who}-phone]");
    for (who, auth) in [("ada", &ada_auth), ("eve", &eve_auth), ("dot", &dot_auth), ("cy", &cy_auth), ("dee", &dee_auth), ("bea", &bea_auth)] {
        let body = json!({ "token": phone(who), "platform": "ios" }).to_string();
        assert_eq!(call(port, "PUT", "/api/me/push", auth, &body).await.0, 200, "{who}");
    }
    // A team admin who's since been disabled hears nothing.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{dot}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);

    // A plain member's request reaches the team's active owners and admins who may decide it,
    // besides the notification list: never a read-only one, the asker, or another team.
    let cy_q = asked(port, &cy_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "Ticket 4242" })).await;
    let want = ["notice-ada@example.com", "notice-eve@example.com", "ops@example.com"];
    assert_eq!(until("three emails", || Some(mailed(&mail)).filter(|m| m.len() >= 3)).await, want);
    assert_eq!(until("two pushes", || Some(pushed(&rec)).filter(|p| p.len() >= 2)).await, [phone("ada"), phone("eve")]);
    let m = mail.got.lock().unwrap()[0].clone();
    assert!(m.headers.contains("Subject: [SuperBot] notice-cy@example.com asks for Team helpdesk for 8 hours"), "{}", m.headers);
    for line in ["Why: Ticket 4242", "In the team Alpha.", "or the team's owners and admins in Team", "Open it in SuperBot (the team's owners and admins): https://bots.example.com/app/team", "Console (admins): https://bots.example.com/console/#roles"] {
        assert!(m.body.contains(line), "{line}: {}", m.body);
    }
    for p in rec.sent.lock().unwrap().iter() {
        assert_eq!((p.title.as_str(), p.body.as_str(), &p.data), ("Request for a team role", "Someone on Alpha is waiting for your decision.", &json!({ "type": "role_request", "url": "/team" })));
    }
    let sent = until("both audit events", || Some(events_now(&app, "notification.sent")).filter(|e| e.len() >= 2)).await;
    let push = sent.iter().find(|e| e.details["channel"] == "push").unwrap();
    assert_eq!((push.details["event"].as_str(), push.target_id.as_deref()), (Some("role.requested"), app.db.role_request(&cy_q).map(|q| q.role_id).as_deref()));
    let mut users: Vec<&str> = push.details["users"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    users.sort();
    let mut both = [ada.as_str(), eve.as_str()];
    both.sort();
    assert_eq!(users, both);
    let email = sent.iter().find(|e| e.details["channel"] == "email").unwrap();
    assert_eq!(email.details["to"].as_array().map(Vec::len), Some(3), "{}", email.details);

    // Requests the team can't decide reach only the notification list: one from a team admin,
    // and one across the server.
    asked(port, &eve_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "Cover" })).await;
    asked(port, &dee_auth, json!({ "role": "On-call", "hours": 8, "reason": "Incident 42" })).await;
    until("two more emails", || Some(mailed(&mail)).filter(|m| m.len() >= 5)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mailed(&mail)[3..], ["ops@example.com", "ops@example.com"]);
    assert_eq!(pushed(&rec).len(), 2, "no phone heard of them");
    let m = mail.got.lock().unwrap()[3].clone();
    assert!(!m.body.contains("/app/team") && !m.body.contains("in Team"), "{}", m.body);

    // With email kept to the list, owners and admins still hear on their phones.
    let email = notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: false };
    notify::save(&app.db, &notify::Settings { email, ..Default::default() });
    asked(port, &dee_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 4, "reason": "Invites" })).await;
    until("two more pushes", || Some(pushed(&rec)).filter(|p| p.len() >= 4)).await;
    until("one more email", || Some(mailed(&mail)).filter(|m| m.len() >= 6)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mailed(&mail).iter().filter(|t| t.as_str() == "ops@example.com").count(), 4, "only the list's address");
    assert_eq!(mailed(&mail).len(), 6);
}

pub(crate) fn events_now(app: &App, action: &str) -> Vec<db::AuditEvent> {
    let f = audit::Filter::from_query(&HashMap::from([("action".to_string(), action.to_string())])).unwrap();
    app.db.audit_events(&f, 50, true)
}

#[tokio::test]
async fn a_first_approval_tells_the_others_who_may_give_the_second() {
    let (port, app, admin, _) = serve_app().await;
    let (mail, rec) = notices(&app).await;
    user_with(port, &admin, "second-ana@example.com", "admin").await;
    let (ada, ada_auth) = user_with(port, &admin, "second-ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "second-eve@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "second-cy@example.com", "member").await;
    team(port, &admin, "Alpha", &ada, &[(&eve, "admin"), (&cy, "member")]).await;
    let body = json!({ "name": "Team helpdesk", "permissions": ["users.manage"], "maxDays": 7, "requestable": true, "approvals": 2 });
    assert_eq!(call(port, "POST", "/api/roles", &admin, &body.to_string()).await.0, 201);
    let phone = |who: &str| format!("ExponentPushToken[{who}-phone]");
    for (who, auth) in [("ada", &ada_auth), ("eve", &eve_auth), ("cy", &cy_auth)] {
        let body = json!({ "token": phone(who), "platform": "ios" }).to_string();
        assert_eq!(call(port, "PUT", "/api/me/push", auth, &body).await.0, 200, "{who}");
    }
    let q = asked(port, &cy_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "Ticket 77" })).await;
    until("the request's three emails", || Some(mailed(&mail)).filter(|m| m.len() >= 3)).await;
    until("the request's two pushes", || Some(pushed(&rec)).filter(|p| p.len() >= 2)).await;

    // The first approver's teammates and the list hear it needs a second; the first approver doesn't.
    assert_eq!(call(port, "POST", &at(&q, "approve"), &eve_auth, r#"{"hours":4}"#).await.0, 200);
    until("two more emails", || Some(mailed(&mail)).filter(|m| m.len() >= 5)).await;
    until("one more push", || Some(pushed(&rec)).filter(|p| p.len() >= 3)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut more: Vec<String> = mail.got.lock().unwrap()[3..].iter().flat_map(|m| m.to.clone()).collect();
    more.sort();
    assert_eq!(more, ["ops@example.com", "second-ada@example.com"]);
    let m = mail.got.lock().unwrap()[3].clone();
    assert!(m.headers.contains("Subject: [SuperBot] second-cy@example.com's request for Team helpdesk needs a second approver"), "{}", m.headers);
    for line in ["second-eve@example.com approved it for 4 hours.", "Why: Ticket 77", "In the team Alpha.", "Someone else approves or denies it in Roles, or the team's owners and admins in Team"] {
        assert!(m.body.contains(line), "{line}: {}", m.body);
    }
    let p = rec.sent.lock().unwrap()[2].clone();
    assert_eq!((p.to.as_str(), p.body.as_str(), &p.data), (phone("ada").as_str(), "A request on Alpha needs a second approver.", &json!({ "type": "role_request", "url": "/team" })));
    let sent = until("the push's audit event", || Some(events_now(&app, "notification.sent")).filter(|e| e.iter().any(|e| e.details["event"] == "role.request_first_approved" && e.details["channel"] == "push"))).await;
    let push = sent.iter().find(|e| e.details["event"] == "role.request_first_approved" && e.details["channel"] == "push").unwrap();
    assert_eq!(push.details["users"], json!([ada]));

    // The second approval gives it, and tells only the asker (ADR 0329).
    assert_eq!(call(port, "POST", &at(&q, "approve"), &ada_auth, "{}").await.0, 200);
    until("the asker's email", || Some(mailed(&mail)).filter(|m| m.len() >= 6)).await;
    until("the asker's push", || Some(pushed(&rec)).filter(|p| p.len() >= 4)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((mailed(&mail).len(), pushed(&rec).len()), (6, 4));
    let m = mail.got.lock().unwrap()[5].clone();
    assert_eq!(m.to, ["second-cy@example.com"]);
    assert!(m.body.contains("Approved by second-eve@example.com and second-ada@example.com."), "{}", m.body);
    assert_eq!(rec.sent.lock().unwrap()[3].to, phone("cy"));
}
