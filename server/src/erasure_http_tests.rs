//! Erasing a user (ADR 0102) on the real router: their personal data leaves the database,
//! the audit log keeps its events under a pseudonym, and a legal hold, the last owner of a
//! team, or a machine still there refuses it. Admins only, and twice is once.

use crate::audit::{Actor, ActorKind, Source, Who};
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::scim_http_tests::{okta_user, scim, session_for, token};
use crate::tests::{audit_list, call, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn erase(port: u16, who: &str, user: &str, body: &str) -> (u16, Value) {
    let body = if body.is_empty() { "{}" } else { body };
    json_call(port, "POST", &format!("/api/users/{user}/erase"), who, body).await
}

async fn audit(port: u16, admin: &str, query: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?limit=1000&{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// A message in `bot`'s chat that `user` sent.
fn sent_by(app: &AppState, bot: &str, user: &str, text: &str) -> i64 {
    let m = app.db.add_message(bot, "user", text, None, false, None);
    let who = Who { actor: Actor { kind: ActorKind::User, id: Some(user.into()), ..Default::default() }, source: Source::default() };
    app.db.set_requested_by(m.id, &who);
    m.id
}

async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn bot_of(port: u16, auth: &str, name: &str) -> String {
    let (code, b) = json_call(port, "POST", "/api/bots", auth, &json!({ "name": name }).to_string()).await;
    assert_eq!(code, 201, "{b}");
    b["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn erasing_leaves_no_personal_data_and_the_audit_log_names_a_pseudonym() {
    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (code, _, made) = scim(port, &t, "POST", "/scim/v2/Users", okta_user("ada@example.com", "ext-ada-0001")).await;
    assert_eq!(code, 201, "{made}");
    let ada = made["id"].as_str().unwrap().to_string();
    let ada_auth = session_for(port, &admin, &ada).await;
    app.db.link_identity(&ada, &db::NewIdentity { provider: "entra", issuer: "https://login.example.com/t1", subject: "subject-ada-0001", tenant: None, email: Some("ada.work@example.com"), created_by: None }).unwrap();
    let old = app
        .db
        .link_identity(&ada, &db::NewIdentity { provider: "entra", issuer: "https://login.example.com/t2", subject: "subject-old-0002", tenant: None, email: None, created_by: None })
        .unwrap();
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada}/identities/{}", old.id), &admin, "").await.0, 200, "unlinked before, still in the log");
    assert!(app.db.mfa_begin(&ada, "sealed-totp-of-ada"));
    secrets::global().user_put(&ada, "OPENAI_API_KEY", "sk-ada-private-key").unwrap();

    // Her own Bot, with chat and a routine; a teammate's shared Bot she wrote in, and a grant on it.
    let mine = bot_of(port, &ada_auth, "Notebook").await;
    app.db.add_message(&mine, "user", "my private diary entry", None, false, None);
    app.db.add_routine(&mine, "daily", "0 9 * * *", "summarise my private inbox");
    let shared = app.db.create_bot("Team", "#fff", "waddle", "claude", None, false).id;
    let wrote = sent_by(&app, &shared, &ada, "Ada's secret plan for Lovelace Ltd");
    let reply = app.db.add_message(&shared, "bot", "Noted.", None, false, None);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{shared}/grants/{ada}"), &admin, r#"{"level":"operator"}"#).await.0, 200);
    let before = audit(port, &admin, "").await;
    assert!(before.iter().any(|e| e.to_string().contains("ada@example.com")), "the log names her before");

    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    let p = v["pseudonym"].as_str().unwrap().to_string();
    assert!(p.starts_with("erased-"), "{v}");
    assert_eq!((v["already"].clone(), v["removed"]["bots"].clone(), v["removed"]["secrets"].clone(), v["removed"]["grants"].clone()), (json!(false), json!(1), json!(1), json!(1)), "{v}");
    assert_eq!((v["removed"]["mfa"].clone(), v["removed"]["identities"].clone(), v["removed"]["scim"].clone(), v["removed"]["messages"].clone()), (json!(true), json!(1), json!(true), json!(1)), "{v}");

    // The tombstone: no name, email or sign-in, and gone for every other admin route.
    let (code, u) = json_call(port, "GET", &format!("/api/users/{ada}"), &admin, "").await;
    assert_eq!(code, 200, "{u}");
    assert_eq!((u["email"].clone(), u["name"].as_str(), u["status"].as_str(), u["erasedAs"].as_str(), u["idpSubject"].clone()), (Value::Null, Some("Erased user"), Some("disabled"), Some(p.as_str()), Value::Null), "{u}");
    assert_eq!(u["identities"], json!([]));
    assert_eq!(call(port, "GET", "/api/auth/me", &ada_auth, "").await.0, 401, "her sessions are gone");
    assert_eq!(call(port, "GET", &format!("/api/users/{ada}/bots"), &admin, "").await.0, 410);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ada}"), &admin, r#"{"status":"active"}"#).await.0, 410, "never enabled again");
    assert_eq!(call(port, "POST", &format!("/api/users/{ada}/login-codes"), &admin, "").await.0, 410);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{shared}/grants/{ada}"), &admin, r#"{"level":"viewer"}"#).await.0, 404);
    assert_eq!(call(port, "GET", "/api/users/ada@example.com", &admin, "").await.0, 404, "her email finds nobody");
    assert_eq!(scim(port, &t, "GET", &format!("/scim/v2/Users/{ada}"), Value::Null).await.0, 404);
    assert!(app.db.bot(&mine).is_none());
    assert_eq!(app.db.message(wrote).unwrap().text, "[erased]");
    assert!(app.db.message(wrote).unwrap().requested_by.is_none());
    assert_eq!(app.db.message(reply.id).unwrap().text, "Noted.", "others' messages stay");
    assert!(secrets::global().user_list(&ada).unwrap().is_empty());

    // Nothing of hers is left in any table, and the audit log doesn't have her id.
    let rows = app.db.all_rows();
    assert!(rows.iter().any(|(t, r)| t == "users" && r.contains("Erased user")) && rows.iter().any(|(t, _)| t == "audit_events"));
    for (table, row) in rows {
        let low = row.to_lowercase();
        for pii in ["ada@example.com", "ada.work@example.com", "lovelace", "ext-ada-0001", "subject-ada-0001", "subject-old-0002", "sealed-totp-of-ada", "diary", "private inbox", "secret plan"] {
            assert!(!low.contains(pii), "{pii} in {table}: {row}");
        }
        if table == "audit_events" {
            assert!(!row.contains(&ada), "her id in the audit log: {row}");
        }
    }

    // Her events stay, under the pseudonym; the erasure names who did it.
    let after = audit(port, &admin, "").await;
    assert_eq!(after.len(), before.len() + after.iter().filter(|e| e["id"].as_i64() > before[0]["id"].as_i64()).count());
    let created = audit(port, &admin, "action=user.created").await;
    assert!(created.iter().any(|e| e["targetId"].as_str() == Some(p.as_str()) && e["details"]["email"].as_str() == Some(p.as_str())), "{created:?}");
    let logins: Vec<Value> = audit(port, &admin, "action=auth.login").await.into_iter().filter(|e| e["actorId"].as_str() == Some(p.as_str())).collect();
    assert!(!logins.is_empty() && logins.iter().all(|e| e["actorEmail"].is_null() && e["actorName"].is_null() && e["sessionId"].is_null()), "{logins:?}");
    let erased = audit(port, &admin, "action=user.erased").await;
    assert_eq!(erased.len(), 1, "{erased:?}");
    assert_eq!((erased[0]["actorId"].as_str(), erased[0]["targetId"].as_str(), erased[0]["details"]["pseudonym"].as_str()), (Some("operator"), Some(p.as_str()), Some(p.as_str())));

    // The log is still append-only outside an erasure.
    assert!(app.db.execute_raw("UPDATE audit_events SET actor_name = NULL").is_err());
    assert!(app.db.execute_raw(&format!("UPDATE audit_events SET actor_id = 'x' WHERE actor_id = '{p}'")).is_err());

    // The IdP provisioning her again makes a new user, with none of the old history.
    let (code, _, again) = scim(port, &t, "POST", "/scim/v2/Users", okta_user("ada@example.com", "ext-ada-0001")).await;
    assert_eq!(code, 201, "{again}");
    assert_ne!(again["id"].as_str(), Some(ada.as_str()));
}

#[tokio::test]
async fn a_user_under_legal_hold_is_not_erased() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let mine = bot_of(port, &ada_auth, "Notebook").await;
    assert_eq!(call(port, "PUT", &format!("/api/retention/holds/{mine}"), &admin, r#"{"reason":"litigation"}"#).await.0, 200);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("legal hold") && v["error"].as_str().unwrap().contains(&mine), "{v}");
    assert_eq!(app.db.user(&ada).unwrap().email.as_deref(), Some("ada@example.com"), "nothing changed");
    assert!(app.db.bot(&mine).is_some());
    let refused = audit(port, &admin, "action=user.erase_refused").await;
    assert_eq!((refused[0]["outcome"].as_str(), refused[0]["details"]["reason"].as_str()), (Some("denied"), Some("legal_hold")), "{refused:?}");
    assert_eq!(call(port, "DELETE", &format!("/api/retention/holds/{mine}"), &admin, "").await.0, 200);

    // Someone else's held Bot with a message she sent holds her too.
    let held = app.db.create_bot("Case", "#fff", "waddle", "claude", None, false).id;
    sent_by(&app, &held, &ada, "evidence");
    assert_eq!(call(port, "PUT", &format!("/api/retention/holds/{held}"), &admin, r#"{"reason":"litigation"}"#).await.0, 200);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(&held), "{v}");
    assert_eq!(call(port, "DELETE", &format!("/api/retention/holds/{held}"), &admin, "").await.0, 200);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
}

#[tokio::test]
async fn only_another_admin_erases_and_never_the_owner_account() {
    let (port, app, owner, key) = serve_app().await;
    let (ada, _) = user_with(port, &owner, "ada@example.com", "member").await;
    let (_, member) = user_with(port, &owner, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &owner, "r@example.com", "readonly").await;
    let (admin_id, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let bot = key.auth(&app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false).id);
    assert_eq!(erase(port, "", &ada, "").await.0, 401);
    for who in [&member, &readonly, &bot] {
        assert_eq!(erase(port, who, &ada, "").await.0, 403);
    }
    assert!(app.db.user(&ada).unwrap().erased_at.is_none());
    assert_eq!(erase(port, &admin, &admin_id, "").await.0, 409, "not yourself");
    assert_eq!(erase(port, &admin, users::OPERATOR, "").await.0, 409, "not the owner account");
    assert_eq!(erase(port, &admin, "nobody@example.com", "").await.0, 404);
    assert_eq!(erase(port, &admin, &ada, r#"{"destroyMachine":"yes"}"#).await.0, 400);
    let (code, v) = erase(port, &admin, "ada@example.com", "").await;
    assert_eq!(code, 200, "by email too: {v}");
    let erased = audit(port, &owner, "action=user.erased").await;
    assert_eq!(erased[0]["actorId"].as_str(), Some(admin_id.as_str()), "{erased:?}");
}

#[tokio::test]
async fn erasing_twice_is_erasing_once() {
    let (port, _, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, first) = erase(port, &admin, &ada, "").await;
    assert_eq!((code, first["already"].clone()), (200, json!(false)), "{first}");
    let (code, again) = erase(port, &admin, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!((code, again["already"].clone(), again["pseudonym"].clone()), (200, json!(true), first["pseudonym"].clone()), "{again}");
    assert_eq!(audit(port, &admin, "action=user.erased").await.len(), 1);
    assert_eq!(erase(port, &admin, "ada@example.com", "").await.0, 404, "her email is gone");
}

#[tokio::test]
async fn the_last_owner_of_a_team_is_not_erased() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": "ada@example.com", "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), &admin, "{}").await.0, 200);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("only owner"), "{v}");
    assert_eq!(audit(port, &admin, "action=user.erase_refused").await[0]["details"]["reason"].as_str(), Some("last_team_owner"));
    assert!(app.db.team_member(&ada).is_some());

    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{bea}"), &admin, r#"{"role":"owner"}"#).await.0, 200);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!((code, v["removed"]["team"].as_str()), (200, Some(team.as_str())), "{v}");
    let (_, t) = json_call(port, "GET", &format!("/api/teams/{team}"), &admin, "").await;
    assert_eq!(t["members"].as_array().map(|m| m.iter().map(|m| m["user"]["id"].as_str().or(m["id"].as_str()).unwrap_or_default().to_string()).collect::<Vec<_>>()), Some(vec![bea.clone()]), "{t}");
    let left = audit(port, &admin, "action=team.member_left").await;
    assert_eq!(left[0]["details"]["reason"].as_str(), Some("erased"), "{left:?}");

    // Their team's last member: the team goes with them.
    let (code, v) = erase(port, &admin, &bea, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(call(port, "GET", &format!("/api/teams/{team}"), &admin, "").await.0, 404);
}

#[tokio::test]
async fn a_machine_is_destroyed_first_or_the_erasure_waits() {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, m) = json_call(port, "POST", &format!("/api/users/{ada}/machine"), &admin, "{}").await;
    assert!([201, 202].contains(&code), "{code} {m}");
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("destroyMachine"), "{v}");
    assert_eq!(audit(port, &admin, "action=user.erase_refused").await[0]["details"]["reason"].as_str(), Some("machine"));
    assert!(app.db.user_machine(&ada).is_some(), "kept");

    // The last member of a paying team is refused before the machine goes.
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Solo", "owner": "ada@example.com", "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    app.db
        .execute_raw(&format!("INSERT INTO team_subscriptions (subscription_id, team_id, provider, status, tier, started, event_created, updated_at) VALUES ('sub_1', '{team}', 'stripe', 'active', 'pro', 0, 0, 0)"))
        .unwrap();
    let (code, v) = erase(port, &admin, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(audit(port, &admin, "action=user.erase_refused").await[0]["details"]["reason"].as_str(), Some("team_pays"));
    assert!(app.db.user_machine(&ada).is_some(), "not destroyed for an erasure that was refused");
    app.db.execute_raw("DELETE FROM team_subscriptions").unwrap();
    // What their homes held, as the agent said (ADR 0105), and botd's measurement of it.
    let mid = app.db.user_machine(&ada).unwrap().id;
    app.db.execute_raw(&format!("UPDATE machines SET disk_files = 4096, disk_files_partial = 1, disk_files_at = 1 WHERE id = '{mid}'")).unwrap();
    crate::storage::current(&app, &ada, std::time::Duration::ZERO).await;
    assert!(app.storage.last(&ada).is_some());

    let (code, v) = erase(port, &admin, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["removed"]["machine"]["destroyed"], json!(true), "{v}");
    assert_eq!(v["removed"]["diskReports"], json!(1), "{v}");
    assert!(app.db.user_machine(&ada).is_none());
    let m = app.db.machine(&mid).unwrap();
    assert_eq!((m.disk_files, m.disk_files_partial, m.disk_files_at), (None, false, None));
    assert!(app.storage.last(&ada).is_none(), "their measurement is forgotten");
    assert_eq!(audit(port, &admin, "action=machine.destroy_requested").await.len(), 1);
}

#[tokio::test]
async fn what_their_signup_recorded_is_erased_too() {
    let (port, app, admin, _) = serve_app().await;
    let form = json!({
        "name": "Grace Brewster Hopper", "email": "grace@example.com", "company": "Eckert-Mauchly", "teamSize": "11-50",
        "useCase": "Compiler notes", "signIn": "microsoft", "consent": true, "website": "",
    });
    let extra = "X-Forwarded-For: 192.0.2.77\r\nUser-Agent: GraceBrowser/1.0\r\n";
    assert_eq!(crate::tests::call_with(port, "POST", "/api/signups", "", extra, &form.to_string()).await.0, 202);
    let (_, list) = json_call(port, "GET", "/api/signups?status=pending", &admin, "").await;
    let id = list[0]["id"].as_str().unwrap().to_string();
    let (code, v) = json_call(port, "POST", &format!("/api/signups/{id}/approve"), &admin, r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");
    let grace = v["user"]["id"].as_str().unwrap().to_string();
    assert!(audit(port, &admin, "action=signup.submitted").await[0]["ip"].as_str() == Some("192.0.2.77"));
    let (code, v) = erase(port, &admin, &grace, "").await;
    assert_eq!(code, 200, "{v}");
    for (table, row) in app.db.all_rows() {
        for pii in ["Grace Brewster Hopper", "grace@example.com", "192.0.2.77", "GraceBrowser"] {
            assert!(!row.contains(pii), "{pii} in {table}: {row}");
        }
    }
    assert_eq!(audit(port, &admin, "action=signup.submitted").await.len(), 1, "the event stays");
}

#[tokio::test]
async fn names_and_emails_they_had_before_are_erased_too() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada.byron@example.com", "member").await;
    for patch in [json!({ "name": "Augusta Ada Byron" }), json!({ "name": "Countess of Lovelace", "email": "ada@example.com" })] {
        assert_eq!(call(port, "PATCH", &format!("/api/users/{ada}"), &admin, &patch.to_string()).await.0, 200);
    }
    // Someone else gets her old address; what's recorded about them stays theirs.
    let (bob, bob_auth) = user_with(port, &admin, "ada.byron@example.com", "member").await;
    bot_of(port, &bob_auth, "Bob's").await;
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    for (table, row) in app.db.all_rows() {
        let low = row.to_lowercase();
        for pii in ["augusta ada byron", "countess of lovelace", "ada@example.com"] {
            assert!(!low.contains(pii), "{pii} in {table}: {row}");
        }
        if table == "audit_events" && low.contains("ada.byron@example.com") {
            assert!(row.contains(&bob), "her old address only in Bob's events: {row}");
        }
    }
    let created = audit(port, &admin, "action=user.created").await;
    assert!(created.iter().any(|e| e["targetId"].as_str() == Some(bob.as_str()) && e["details"]["email"].as_str() == Some("ada.byron@example.com")), "{created:?}");
    let bots = audit(port, &admin, "action=bot.created").await;
    assert!(bots.iter().any(|e| e["actorId"].as_str() == Some(bob.as_str()) && e["actorEmail"].as_str() == Some("ada.byron@example.com")), "{bots:?}");
}

#[tokio::test]
async fn another_visitors_events_stay_theirs() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let visitor = |email: &str| Who {
        actor: Actor { kind: ActorKind::User, name: Some("Ada Visiting".into()), email: Some(email.into()), ..Default::default() },
        source: Source { ip: Some("203.0.113.77".into()), user_agent: Some("AdaBrowser/1.0".into()) },
    };
    app.db.record(&visitor("Ada@Example.com").event("signup.submitted").target("signup", "su_1"));
    app.db.record(&visitor("bob@example.com").event("signup.submitted").target("signup", "su_2"));
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    let events = audit(port, &admin, "action=signup.submitted").await;
    let of = |t: &str| events.iter().find(|e| e["targetId"].as_str() == Some(t)).unwrap().clone();
    let (hers, his) = (of("su_1"), of("su_2"));
    for k in ["actorName", "actorEmail", "ip", "userAgent"] {
        assert!(hers[k].is_null(), "{k}: {hers}");
    }
    assert_eq!(his["actorName"].as_str(), Some("Ada Visiting"), "another visitor's event stays: {his}");
    assert_eq!(his["ip"].as_str(), Some("203.0.113.77"), "{his}");
}

#[tokio::test]
async fn their_answer_to_a_handoff_in_someone_elses_bot_is_erased() {
    let (port, app, admin, _) = serve_app().await;
    let (owner, _) = user_with(port, &admin, "owner@example.com", "member").await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Shared", "#fff", "waddle", "claude", None, false, &owner, acl::Visibility::Private);
    app.db.set_grant(&bot.id, &ada, acl::Grant::Operator, &owner);
    let waiting = {
        let (app, bot) = (app.clone(), bot.clone());
        tokio::spawn(async move { app.handoff(&bot, "Sign in", Duration::from_secs(5)).await })
    };
    let card = loop {
        if let Some(m) = app.db.messages(&bot.id, 10).into_iter().find(|m| m.question.is_some()) {
            break m.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let answer = json!({ "text": "Done, my code was 314159", "answer": { "messageId": card, "option": 0 } }).to_string();
    assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", bot.id), &ada_auth, &answer).await.0, 202);
    assert_eq!(waiting.await.unwrap().as_deref(), Some("Done, my code was 314159"));
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    for (table, row) in app.db.all_rows() {
        assert!(!row.contains("314159"), "in {table}: {row}");
    }
}

#[tokio::test]
async fn a_retried_erasure_still_erases_what_its_deleted_bots_wrote() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let gone = bot_of(port, &ada_auth, "Scribe").await;
    let shared = app.db.create_bot("Team", "#fff", "waddle", "claude", None, false).id;
    let wrote = app.db.add_message_from(&shared, "user", "notes about Ada's health", None, false, None, Some(&gone)).id;
    // As if a first try deleted the Bot and then stopped.
    app.db.set_erasing_bots(&ada, std::slice::from_ref(&gone));
    app.db.delete_bot(&gone);
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(app.db.message(wrote).unwrap().text, "[erased]");
    assert!(app.db.erasing_bots(&ada).is_empty(), "forgotten once erased");
    let kept: Vec<String> = serde_json::from_str(&app.db.setting(&format!("{}{ada}", crate::db::ERASED_BOTS)).unwrap()).unwrap();
    assert_eq!(kept, [gone], "kept for restoring a chat store backup made mid-erasure");
}

#[tokio::test]
async fn an_open_checkout_is_closed_first_and_a_paid_one_refuses() {
    let (w, stripe) = crate::billing_http_tests::shop().await;
    assert_eq!(crate::billing_http_tests::buy(&w, &w.a, "pro").await.0, 200);
    stripe.pay("cs_test_1");
    let (code, v) = erase(w.port, &w.admin, &w.a_id, "").await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(audit(w.port, &w.admin, "action=user.erase_refused").await[0]["details"]["reason"].as_str(), Some("checkout_paid"));
    assert!(w.app.db.user(&w.a_id).unwrap().erased_at.is_none());

    assert_eq!(crate::billing_http_tests::buy(&w, &w.b, "pro").await.0, 200);
    let session = w.app.db.open_checkout(&w.b_id).unwrap();
    let (code, v) = erase(w.port, &w.admin, &w.b_id, "").await;
    assert_eq!(code, 200, "{v}");
    assert!(stripe.seen().iter().any(|s| s.path == format!("/v1/checkout/sessions/{session}/expire")), "her open page was expired at Stripe");
}

#[tokio::test]
async fn a_primary_bot_given_to_them_while_stripe_answers_is_not_deleted() {
    let (w, stripe) = crate::billing_http_tests::shop().await;
    let primary = w.app.db.create_bot("Main", "#fff", "waddle", "claude", None, true).id;
    assert_eq!(crate::billing_http_tests::buy(&w, &w.b, "pro").await.0, 200);
    stripe.slow(600);
    let erasing = {
        let (port, admin, b) = (w.port, w.admin.clone(), w.b_id.clone());
        tokio::spawn(async move { erase(port, &admin, &b, "").await })
    };
    // Past the first primary Bot check, the erasure waits on Stripe to close her checkout.
    until("the erasure to reach Stripe", || stripe.seen().iter().any(|s| s.path.ends_with("/expire"))).await;
    let (code, v) = json_call(w.port, "PATCH", &format!("/api/bots/{primary}/access"), &w.admin, &json!({ "owner": w.b_id }).to_string()).await;
    assert_eq!(code, 200, "{v}");
    let (code, v) = erasing.await.unwrap();
    assert_eq!(code, 409, "{v}");
    assert_eq!(audit(w.port, &w.admin, "action=user.erase_refused").await[0]["details"]["reason"].as_str(), Some("primary_bot"));
    assert_eq!(w.app.db.bot(&primary).map(|b| b.owner_id), Some(w.b_id.clone()), "kept, and still hers");
    assert!(w.app.db.user(&w.b_id).unwrap().active() && !crate::erasure::under_way(&w.b_id));
}

#[tokio::test]
async fn no_bot_becomes_theirs_or_leaves_them_while_they_are_erased() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let beas = app.db.create_bot_owned("Bea's", "#fff", "waddle", "claude", None, false, &bea, acl::Visibility::Private).id;
    let hers = bot_of(port, &ada_auth, "Hers").await;
    {
        let _erasing = crate::erasure::begin(&ada);
        let (code, v) = json_call(port, "POST", "/api/bots", &ada_auth, r#"{"name":"Late"}"#).await;
        assert_eq!(code, 409, "{v}");
        for (bot, to) in [(&beas, &ada), (&hers, &bea)] {
            let (code, v) = json_call(port, "PATCH", &format!("/api/bots/{bot}/access"), &admin, &json!({ "owner": to }).to_string()).await;
            assert_eq!(code, 409, "{v}");
        }
    }
    assert_eq!(app.db.bots().iter().filter(|b| b.owner_id == ada).map(|b| b.id.clone()).collect::<Vec<_>>(), vec![hers.clone()]);
    assert_eq!(app.db.bot(&beas).unwrap().owner_id, bea);

    // Creates racing a real erasure land before it lists her Bots, or not at all.
    let racers: Vec<_> = (0..4)
        .map(|i| {
            let auth = ada_auth.clone();
            tokio::spawn(async move {
                let mut made = Vec::new();
                for n in 0..500 {
                    let (code, b) = json_call(port, "POST", "/api/bots", &auth, &json!({ "name": format!("R{i}-{n}") }).to_string()).await;
                    match code {
                        201 => made.push(b["id"].as_str().unwrap().to_string()),
                        401 | 409 => return (code, made),
                        _ => panic!("{code} {b}"),
                    }
                }
                panic!("never refused")
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    let mut made = Vec::new();
    for r in racers {
        made.extend(r.await.unwrap().1);
    }
    assert!(!made.is_empty(), "some landed before the erasure");
    assert!(made.iter().all(|b| app.db.bot(b).is_none()), "every Bot made for her went with her");
    assert!(app.db.bots().iter().all(|b| b.owner_id != ada));
}

#[tokio::test]
async fn an_open_team_checkout_refuses_before_the_machine_goes() {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, m) = json_call(port, "POST", &format!("/api/users/{ada}/machine"), &admin, "{}").await;
    assert!([201, 202].contains(&code), "{code} {m}");
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Solo", "owner": "ada@example.com", "machines": false }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    // Not paying yet, but a checkout for it is open: the team can't go with her.
    app.db.set_team_open_checkout(&team, "cs_team_1", db::now() / 1000 + 3600);
    let (code, v) = erase(port, &admin, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("checkout"), "{v}");
    let refused = audit(port, &admin, "action=user.erase_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["team"].as_str()), (Some("team_delete_refused"), Some(team.as_str())), "{refused:?}");
    assert_eq!(audit(port, &admin, "action=team.delete_refused").await[0]["details"]["reason"].as_str(), Some("checkout_open"));
    assert!(app.db.user_machine(&ada).is_some(), "not destroyed for an erasure that was refused");
    assert!(audit(port, &admin, "action=machine.destroy_requested").await.is_empty());
    assert!(app.db.team_member(&ada).is_some() && app.db.user(&ada).unwrap().active());
    assert!(!crate::erasure::under_way(&ada), "her work runs as before");

    app.db.close_team_checkout(&team, "cs_team_1");
    let (code, v) = erase(port, &admin, &ada, r#"{"destroyMachine":true}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["removed"]["machine"]["destroyed"].clone(), v["removed"]["team"].as_str()), (json!(true), Some(team.as_str())), "{v}");
    assert_eq!(call(port, "GET", &format!("/api/teams/{team}"), &admin, "").await.0, 404);
}

#[tokio::test]
async fn runs_they_asked_for_in_others_bots_end_and_are_recorded_before_the_log_is_rewritten() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    crate::slots_http_tests::gated_claude(&app, &dir);
    let started = || std::fs::read_to_string(dir.join("order")).unwrap_or_default().lines().map(String::from).collect::<Vec<_>>();
    let (bob, _) = user_with(port, &admin, "bob@example.com", "member").await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let shared = |name: &str| {
        let b = app.db.create_bot_owned(name, "#fff", "waddle", "claude", None, false, &bob, acl::Visibility::Shared);
        app.db.set_grant(&b.id, &ada, acl::Grant::Operator, &bob);
        b.id
    };
    let (live, waiting) = (shared("Live"), shared("Waiting"));
    let say = |bot: String, text: &'static str| {
        let auth = ada_auth.clone();
        async move {
            let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), &auth, &json!({ "text": text }).to_string()).await;
            assert_eq!(code, 202, "{body}");
        }
    };
    // Her run going in Bob's Bot, another of hers queued behind it, and one waiting for a slot.
    say(live.clone(), "first").await;
    until("her run to start", || started() == std::slice::from_ref(&live)).await;
    say(live.clone(), "second").await;
    say(waiting.clone(), "third").await;
    until("the third to wait for a slot", || app.slots.waiting(&waiting).is_some()).await;

    let (code, v) = erase(port, &admin, &ada, "").await;
    assert_eq!(code, 200, "{v}");
    let p = v["pseudonym"].as_str().unwrap().to_string();
    // Its end was recorded before the rewrite, so under the pseudonym; the others never ran.
    let finished = audit(port, &admin, "action=bot.run_finished").await;
    assert!(finished.iter().any(|e| e["botId"] == live.as_str() && e["actorId"] == p.as_str() && e["details"]["result"] == "stopped"), "{finished:?}");
    let dequeued = audit(port, &admin, "action=bot.run_dequeued").await;
    assert!(dequeued.iter().any(|e| e["botId"] == waiting.as_str() && e["actorId"] == p.as_str() && e["details"]["result"] == "stopped"), "{dequeued:?}");
    assert!(!app.serving(&live, None) && !app.serving(&waiting, None));
    for bot in [&live, &waiting] {
        assert!(app.db.messages(bot, 20).iter().filter(|m| m.role == "user").all(|m| m.status.as_deref() == Some("done")), "{bot}");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(started(), std::slice::from_ref(&live), "nothing else of hers started");
    for (table, row) in app.db.all_rows() {
        if table == "audit_events" {
            assert!(!row.contains(&ada), "her id in the audit log: {row}");
        }
    }
}

#[tokio::test]
async fn once_their_runs_are_stopped_nothing_starts_for_them_whatever_their_status() {
    let (port, app, admin, _) = serve_app().await;
    let dir = app.cfg.data_dir.join("gate");
    crate::slots_http_tests::gated_claude(&app, &dir);
    let started = || std::fs::read_to_string(dir.join("order")).unwrap_or_default().lines().count();
    let (bob, _) = user_with(port, &admin, "bob@example.com", "member").await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let bot = app.db.create_bot_owned("Shared", "#fff", "waddle", "claude", None, false, &bob, acl::Visibility::Shared).id;
    app.db.set_grant(&bot, &ada, acl::Grant::Operator, &bob);
    let (path, say) = (format!("/api/bots/{bot}/messages"), |text: &str| json!({ "text": text }).to_string());

    // Marked, before her runs are stopped: her work runs, as a refused erasure would leave it.
    let erasing = crate::erasure::begin(&ada);
    assert_eq!(call(port, "POST", &path, &ada_auth, &say("first")).await.0, 202);
    until("her run to start", || started() == 1).await;
    std::fs::write(dir.join(format!("go-{bot}")), "").unwrap();
    until("it to end", || !app.serving(&bot, None)).await;

    // Her runs stopped: she's still active (as if enabled again), and nothing starts.
    erasing.stop_runs();
    assert!(app.db.user(&ada).unwrap().active());
    assert_eq!(call(port, "POST", &path, &ada_auth, &say("second")).await.0, 202);
    until("the Bot to say why", || app.db.last_message(&bot).is_some_and(|m| m.text.contains("being erased"))).await;
    assert_eq!(started(), 1, "nothing else started");
    drop(erasing);
    assert!(!crate::erasure::runs_stopped(&ada));
}
