//! The self-host license (ADR 0038) end to end: installing, refusing, and the seats it
//! allows on every way a person is added, on the real router. There is no free tier
//! (ADR 0068): without a license nobody is added and Bots don't run, unless the operator
//! turned on testing mode. Test servers start in testing mode, as the dogfood server runs.

use crate::license::test_keys::{KID, claims, mint, stranger};
use crate::license::{Mode, token};
use crate::rbac::Role;
use crate::sso_http_tests::{failures, header, mock_oidc, provider_vars, serve_vars, web_sign_in};
use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(
        port,
        "GET",
        &format!("/api/audit?action={action}"),
        admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn install(port: u16, admin: &str, key: &str) -> (u16, Value) {
    let (code, body) = call(
        port,
        "PUT",
        "/api/license",
        admin,
        &json!({ "key": key }).to_string(),
    )
    .await;
    (code, parse(&body))
}

async fn license(port: u16, admin: &str) -> Value {
    let (code, body) = call(port, "GET", "/api/license", admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

/// Active users until `n` seats are taken.
fn fill(app: &AppState, n: u32) {
    while app.db.active_seats() < n {
        let email = format!("p{}@example.com", random_hex(4));
        app.db
            .create_user(None, Some(&email), "Person", Role::Member)
            .unwrap();
    }
}

async fn add(port: u16, admin: &str, email: &str) -> (u16, Value) {
    let (code, body) = call(
        port,
        "POST",
        "/api/users",
        admin,
        &json!({ "email": email }).to_string(),
    )
    .await;
    (code, parse(&body))
}

#[tokio::test]
async fn admins_install_and_remove_a_license_and_never_see_the_key_again() {
    let (port, app, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    app.license.set_testing(false);
    let fresh = license(port, &admin).await;
    assert_eq!(
        (
            fresh["mode"].as_str(),
            fresh["licensed"].as_bool(),
            fresh["edition"].as_str()
        ),
        (Some("unlicensed"), Some(false), Some("none"))
    );
    assert_eq!(
        (
            fresh["testing"].as_bool(),
            fresh["usable"].as_bool(),
            fresh["ok"].as_bool()
        ),
        (Some(false), Some(false), Some(false))
    );
    assert_eq!(
        (
            fresh["seats"]["limit"].as_u64(),
            fresh["seats"]["used"].as_u64()
        ),
        (Some(0), Some(1))
    );
    assert!(
        fresh["detail"].as_str().unwrap().contains("no free tier"),
        "{fresh}"
    );
    assert!(fresh["seats"].get("community").is_none(), "{fresh}");
    assert_eq!(fresh["billing"]["enabled"], json!(false));
    assert!(
        fresh["billing"]["detail"]
            .as_str()
            .unwrap()
            .contains("off during testing"),
        "{fresh}"
    );
    for (m, body) in [("GET", ""), ("PUT", r#"{"key":"x"}"#), ("DELETE", "")] {
        assert_eq!(
            call(port, m, "/api/license", &member, body).await.0,
            403,
            "{m}"
        );
    }

    let c = claims(Some(25), 200);
    let key = mint(&c);
    let (code, v) = install(port, &admin, &format!("\n{key}  \n")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        (
            v["mode"].as_str(),
            v["edition"].as_str(),
            v["source"].as_str(),
            v["savable"].as_bool()
        ),
        (Some("active"), Some("business"), Some("file"), Some(true))
    );
    assert_eq!(
        (
            v["license"]["licensee"].as_str(),
            v["license"]["seats"].as_u64(),
            v["seats"]["limit"].as_u64()
        ),
        (Some("Acme Ltd"), Some(25), Some(25))
    );
    assert_eq!(v["features"], json!(["sso", "scim"]));
    assert_eq!(v["license"]["expiresAt"].as_i64(), Some(c.exp * 1000));
    // Saved for the next start, readable by botd's user only, and never sent back.
    let path = app.cfg.data_dir.join(crate::license::FILE);
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), key);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let shown = call(port, "GET", "/api/license", &admin, "").await.1;
    assert!(
        !shown.contains(&key) && !shown.contains(key.split('.').nth(2).unwrap()),
        "{shown}"
    );
    let ev = &events(port, &admin, "license.installed").await[0];
    assert_eq!(
        (
            ev["targetId"].as_str(),
            ev["details"]["to"]["mode"].as_str(),
            ev["details"]["to"]["seats"].as_u64()
        ),
        (Some(c.jti.as_str()), Some("active"), Some(25))
    );
    assert!(!ev.to_string().contains(&key));
    // The same key again changes nothing and logs nothing.
    assert_eq!(install(port, &admin, &key).await.0, 200);
    assert_eq!(events(port, &admin, "license.installed").await.len(), 1);
    // A restart reads it back.
    let again = crate::license::Licensing::new(crate::license::trusted(), &app.cfg.data_dir);
    again.load(|_| String::new());
    assert_eq!(again.status().mode, Mode::Active);

    let (code, body) = call(port, "DELETE", "/api/license", &admin, "").await;
    assert_eq!(
        (
            code,
            parse(&body)["mode"].as_str(),
            parse(&body)["usable"].as_bool()
        ),
        (200, Some("unlicensed"), Some(false)),
        "{body}"
    );
    assert!(!path.exists());
    let ev = &events(port, &admin, "license.removed").await[0];
    assert_eq!(
        (
            ev["targetId"].as_str(),
            ev["details"]["from"]["licensee"].as_str()
        ),
        (Some(c.jti.as_str()), Some("Acme Ltd"))
    );
    assert_eq!(
        call(port, "DELETE", "/api/license", &admin, "").await.0,
        404
    );
}

#[tokio::test]
async fn invalid_tampered_foreign_and_expired_keys_are_refused_and_logged() {
    let (port, _, admin, _) = serve_app().await;
    let good = claims(Some(20), 100);
    assert_eq!(install(port, &admin, &mint(&good)).await.0, 200);

    let t = mint(&claims(Some(20), 100));
    let mut parts: Vec<String> = t.split('.').map(String::from).collect();
    let mut more = claims(Some(20), 100);
    more.seats = Some(10_000);
    use base64::Engine;
    parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&more).unwrap());
    let tampered = parts.join(".");
    let foreign = token::sign(&stranger(), KID, &claims(Some(20), 100)).unwrap();
    let unknown = token::sign(&stranger(), "cg-1999", &claims(Some(20), 100)).unwrap();
    let ended = mint(&claims(Some(20), -1));
    for (key, reason, says) in [
        ("hello", "malformed", "isn't a SuperBot license"),
        (tampered.as_str(), "bad_signature", "signature"),
        (foreign.as_str(), "bad_signature", "signature"),
        (unknown.as_str(), "unknown_key", "key"),
        (ended.as_str(), "expired", "ended on"),
    ] {
        let (code, v) = install(port, &admin, key).await;
        assert_eq!(code, 400, "{reason}: {v}");
        assert!(
            v["error"].as_str().unwrap_or_default().contains(says),
            "{reason}: {v}"
        );
        let ev = &events(port, &admin, "license.refused").await[0];
        assert_eq!(
            (ev["details"]["reason"].as_str(), ev["outcome"].as_str()),
            (Some(reason), Some("failure")),
            "{ev}"
        );
        assert!(!ev.to_string().contains(key) || key == "hello", "{ev}");
    }
    assert_eq!(call(port, "PUT", "/api/license", &admin, "{}").await.0, 400);
    // The license in place is untouched.
    let v = license(port, &admin).await;
    assert_eq!(
        (v["mode"].as_str(), v["license"]["id"].as_str()),
        (Some("active"), Some(good.jti.as_str()))
    );
}

#[tokio::test]
async fn the_seat_limit_blocks_new_and_re_enabled_people_with_a_clear_error() {
    let (port, app, admin, _) = serve_app().await;
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(12), 100))).await.0,
        200
    );
    fill(&app, 11);
    let (code, last) = add(port, &admin, "twelve@example.com").await;
    assert_eq!(code, 201, "{last}");
    assert_eq!(app.db.active_seats(), 12, "the owner account takes no seat");

    let (code, v) = add(port, &admin, "thirteen@example.com").await;
    assert_eq!(code, 403, "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("the license for Acme Ltd covers 12 active users, and 12 are active"),
        "{msg}"
    );
    assert!(app.db.find_user("thirteen@example.com").is_none());
    let ev = &events(port, &admin, "license.seat_refused").await[0];
    assert_eq!(
        (
            ev["outcome"].as_str(),
            ev["details"]["via"].as_str(),
            ev["details"]["email"].as_str(),
            ev["details"]["limit"].as_u64()
        ),
        (
            Some("denied"),
            Some("admin"),
            Some("thirteen@example.com"),
            Some(12)
        )
    );
    assert_eq!(
        license(port, &admin).await["seats"]["available"].as_u64(),
        Some(0)
    );

    // Disabling someone frees their seat; turning them back on needs one.
    let id = last["id"].as_str().unwrap();
    let off = call(
        port,
        "PATCH",
        &format!("/api/users/{id}"),
        &admin,
        r#"{"status":"disabled"}"#,
    )
    .await;
    assert_eq!(off.0, 200, "{}", off.1);
    assert_eq!(add(port, &admin, "thirteen@example.com").await.0, 201);
    let (code, body) = call(
        port,
        "PATCH",
        &format!("/api/users/{id}"),
        &admin,
        r#"{"status":"active"}"#,
    )
    .await;
    assert_eq!(code, 403, "{body}");
    assert!(!app.db.user(id).unwrap().active());
    assert_eq!(
        events(port, &admin, "license.seat_refused").await[0]["details"]["via"].as_str(),
        Some("enable")
    );
    // Other changes to people need no seat.
    let renamed = call(
        port,
        "PATCH",
        &format!("/api/users/{id}"),
        &admin,
        r#"{"name":"Still Off"}"#,
    )
    .await;
    assert_eq!(renamed.0, 200, "{}", renamed.1);
    // The owner account always works.
    users::ensure_operator(&app.db, "Owner", Some("owner@example.com"));
    assert_eq!(call(port, "GET", "/api/auth/me", &admin, "").await.0, 200);
}

#[tokio::test]
async fn per_user_accounts_take_no_seat_and_disabled_people_get_none() {
    let (port, app, admin, _) = serve_app().await;
    let root = app
        .cfg
        .data_dir
        .parent()
        .unwrap()
        .join(format!("iso-{}", short_id()));
    std::fs::create_dir_all(&root).unwrap();
    let _ = app
        .isolation
        .set(Arc::new(accounts::for_tests(&root, "/bin/false")));
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(12), 100))).await.0,
        200
    );
    fill(&app, 11);
    let (id, _) = user_with(port, &admin, "a@example.com", "member").await;
    assert_eq!(app.db.active_seats(), 12);

    // An active user's account is tried (the fake helper fails), and seats don't move.
    let (code, res) = call(
        port,
        "POST",
        &format!("/api/users/{id}/isolation"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 502, "{res}");
    assert_eq!(app.db.active_seats(), 12);

    // Disabled: no seat, so no account and no harness login, and nothing tried.
    let off = call(
        port,
        "PATCH",
        &format!("/api/users/{id}"),
        &admin,
        r#"{"status":"disabled"}"#,
    )
    .await;
    assert_eq!(off.0, 200, "{}", off.1);
    assert_eq!(app.db.active_seats(), 11);
    for (path, body) in [
        ("isolation", ""),
        ("harness-login", r#"{"harness":"claude"}"#),
    ] {
        let (code, res) = call(
            port,
            "POST",
            &format!("/api/users/{id}/{path}"),
            &admin,
            body,
        )
        .await;
        assert_eq!(code, 400, "{path}: {res}");
        assert!(
            parse(&res)["error"].as_str().unwrap().contains("disabled"),
            "{res}"
        );
    }
    assert_eq!(
        events(port, &admin, "isolation.account_failed").await.len(),
        1
    );
}

#[tokio::test]
async fn without_a_license_or_testing_mode_nobody_is_added_and_nobody_is_locked_out() {
    let (port, app, admin, _) = serve_app().await;
    let (_, ten) = user_with(port, &admin, "ten@example.com", "member").await;
    app.license.set_testing(false);
    // No free tier: not one seat, and a clear way out.
    let (code, v) = add(port, &admin, "eleven@example.com").await;
    assert_eq!(code, 403, "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("no license, and SuperBot has no free tier") && msg.contains("TESTING_MODE"),
        "{msg}"
    );
    let v = license(port, &admin).await;
    assert_eq!(
        (
            v["seats"]["used"].as_u64(),
            v["seats"]["limit"].as_u64(),
            v["seats"]["available"].as_u64()
        ),
        (Some(1), Some(0), Some(0))
    );
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("no free tier")),
        "{v}"
    );
    // Nobody already here is signed out or disabled, and the owner account still works.
    assert_eq!(
        call(port, "GET", "/api/auth/me", &ten, "").await.0,
        200,
        "still signed in"
    );
    assert_eq!(call(port, "GET", "/api/auth/me", &admin, "").await.0, 200);
    assert_eq!(app.db.active_seats(), 1);
    // The wizard says so.
    let s = parse(&call(port, "GET", "/api/setup", &admin, "").await.1);
    let item = s["checklist"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "license")
        .unwrap()
        .clone();
    assert_eq!(item["done"], false, "{item}");

    // A license sets the seats; testing mode, turned on by the operator, lifts the limit.
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(15), 100))).await.0,
        200
    );
    assert_eq!(add(port, &admin, "eleven@example.com").await.0, 201);
    assert_eq!(
        call(port, "DELETE", "/api/license", &admin, "").await.0,
        200
    );
    assert_eq!(add(port, &admin, "twelve@example.com").await.0, 403);
    app.license.set_testing(true);
    let v = license(port, &admin).await;
    assert_eq!(
        (
            v["mode"].as_str(),
            v["edition"].as_str(),
            v["testing"].as_bool(),
            v["seats"]["limit"].as_u64()
        ),
        (Some("unlicensed"), Some("testing"), Some(true), None)
    );
    assert!(
        v["detail"].as_str().unwrap().contains("billing is off"),
        "{v}"
    );
    assert_eq!(add(port, &admin, "twelve@example.com").await.0, 201);
    let s = parse(&call(port, "GET", "/api/setup", &admin, "").await.1);
    let item = s["checklist"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "license")
        .unwrap()
        .clone();
    assert_eq!(item["done"], true, "{item}");
}

#[tokio::test]
async fn bots_dont_run_without_a_license_or_testing_mode() {
    let w = crate::billing_http_tests::world(false).await;
    let bot = w.app.db.create_bot_owned(
        "Mine",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &w.a_id,
        crate::acl::Visibility::Private,
    );
    // Testing mode: runs, on the user's tier.
    assert!(
        crate::tiers_http_tests::run(w.port, &w.app, &w.a, &bot.id)
            .await
            .starts_with("model=")
    );
    w.app.license.set_testing(false);
    let said = crate::tiers_http_tests::run(w.port, &w.app, &w.a, &bot.id).await;
    assert!(
        said.contains("no SuperBot license") && said.contains("no free tier"),
        "{said}"
    );
    let refused = crate::billing_http_tests::audit(
        w.port,
        &w.admin,
        &format!("action=bot.run_refused&bot={}", bot.id),
    )
    .await;
    assert_eq!(refused[0]["details"]["reason"], "unlicensed", "{refused:?}");
    // A license makes it run again.
    assert_eq!(
        install(w.port, &w.admin, &mint(&claims(None, 100))).await.0,
        200
    );
    assert!(
        crate::tiers_http_tests::run(w.port, &w.app, &w.a, &bot.id)
            .await
            .starts_with("model=")
    );
}

#[tokio::test]
async fn an_ended_license_keeps_its_seats_through_the_grace_period_then_allows_nobody_new() {
    let (port, app, admin, _) = serve_app().await;
    app.license.set_testing(false);
    let c = claims(Some(30), -3);
    let key = mint(&c);
    // Set in the environment, which wins: the API can't change it.
    app.license.load(|k| {
        if k == "LICENSE_KEY" {
            key.clone()
        } else {
            String::new()
        }
    });
    let v = license(port, &admin).await;
    assert_eq!(
        (
            v["mode"].as_str(),
            v["licensed"].as_bool(),
            v["source"].as_str(),
            v["savable"].as_bool(),
            v["ok"].as_bool()
        ),
        (
            Some("grace"),
            Some(true),
            Some("env"),
            Some(false),
            Some(false)
        )
    );
    assert_eq!(v["seats"]["limit"].as_u64(), Some(30));
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("keeps working until"),
        "{v}"
    );
    fill(&app, 20);
    assert_eq!(
        add(port, &admin, "grace@example.com").await.0,
        201,
        "seats still honoured"
    );
    let (code, body) = call(
        port,
        "PUT",
        "/api/license",
        &admin,
        &json!({ "key": mint(&claims(None, 100)) }).to_string(),
    )
    .await;
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("LICENSE_KEY"), "{body}");
    assert_eq!(
        events(port, &admin, "license.refused").await[0]["details"]["reason"].as_str(),
        Some("set_in_env")
    );
    assert_eq!(
        call(port, "DELETE", "/api/license", &admin, "").await.0,
        409
    );

    // Past the grace period: no free fallback. Nobody is locked out; nobody new gets in.
    let gone = app
        .license
        .status_at(c.exp * 1000 + (crate::license::GRACE_DAYS + 1) * 86_400_000);
    assert_eq!(
        (gone.mode, gone.seat_cap(), gone.licensed(), gone.usable()),
        (Mode::Expired, Some(0), false, false)
    );
    let ended = mint(&claims(Some(30), -(crate::license::GRACE_DAYS + 1)));
    app.license.load(|k| {
        if k == "LICENSE_KEY" {
            ended.clone()
        } else {
            String::new()
        }
    });
    let v = license(port, &admin).await;
    assert_eq!(
        (
            v["mode"].as_str(),
            v["edition"].as_str(),
            v["seats"]["limit"].as_u64()
        ),
        (Some("expired"), Some("none"), Some(0))
    );
    assert!(app.db.active_seats() > 10, "nobody was disabled");
    assert_eq!(add(port, &admin, "late@example.com").await.0, 403);
}

#[tokio::test]
async fn changes_nobody_made_through_the_api_are_logged_once() {
    let (port, app, admin, _) = serve_app().await;
    app.license.set_testing(false);
    app.license.observe(&app.db);
    assert!(
        events(port, &admin, "license.status_changed")
            .await
            .is_empty(),
        "a server that never had a license logs nothing"
    );
    let c = claims(Some(30), -3);
    let key = mint(&c);
    app.license.load(|k| {
        if k == "LICENSE_KEY" {
            key.clone()
        } else {
            String::new()
        }
    });
    app.license.observe(&app.db);
    app.license.observe(&app.db);
    let list = events(port, &admin, "license.status_changed").await;
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(
        (
            list[0]["targetId"].as_str(),
            list[0]["details"]["to"]["mode"].as_str(),
            list[0]["outcome"].as_str()
        ),
        (Some(c.jti.as_str()), Some("grace"), Some("success"))
    );
    app.license.load(|k| {
        if k == "LICENSE_KEY" {
            "junk".into()
        } else {
            String::new()
        }
    });
    app.license.observe(&app.db);
    let ev = &events(port, &admin, "license.status_changed").await[0];
    assert_eq!(
        (
            ev["details"]["to"]["mode"].as_str(),
            ev["details"]["to"]["error"].as_str(),
            ev["outcome"].as_str()
        ),
        (Some("invalid"), Some("malformed"), Some("failure"))
    );
}

#[tokio::test]
async fn approving_a_sign_up_needs_a_seat() {
    let (port, app, admin, _) = serve_app().await;
    let form = json!({
        "name": "Ada Lovelace", "email": "ada@example.com", "company": "Analytical Engines", "teamSize": "11-50",
        "useCase": "Daily research briefs", "signIn": "microsoft", "consent": true, "website": "",
    });
    let (code, _, body) = call_with(
        port,
        "POST",
        "/api/signups",
        "",
        "X-Forwarded-For: 198.51.100.7\r\n",
        &form.to_string(),
    )
    .await;
    assert_eq!(code, 202, "{body}");
    let (_, list) = call(port, "GET", "/api/signups?status=pending", &admin, "").await;
    let id = parse(&list)[0]["id"].as_str().unwrap().to_string();
    app.license.set_testing(false);
    let (code, body) = call(
        port,
        "POST",
        &format!("/api/signups/{id}/approve"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 403, "{body}");
    assert!(body.contains("No seats"), "{body}");
    assert_eq!(
        app.db.signup(&id).unwrap().status,
        "pending",
        "still waiting"
    );
    assert!(app.db.find_user("ada@example.com").is_none());
    let ev = &events(port, &admin, "license.seat_refused").await[0];
    assert_eq!(
        (
            ev["details"]["via"].as_str(),
            ev["details"]["email"].as_str()
        ),
        (Some("signup"), Some("ada@example.com"))
    );
    // With a seat, it goes through.
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(11), 100))).await.0,
        200
    );
    let (code, body) = call(
        port,
        "POST",
        &format!("/api/signups/{id}/approve"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{body}");
}

#[tokio::test]
async fn scim_creates_and_re_activations_need_a_seat_but_inactive_people_dont() {
    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let (code, t) = call(
        port,
        "POST",
        "/api/scim/tokens",
        &admin,
        r#"{"tenant":"okta"}"#,
    )
    .await;
    assert_eq!(code, 201, "{t}");
    let bearer = format!("Bearer {}", parse(&t)["token"].as_str().unwrap());
    let person = |n: &str, active: bool| {
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": format!("{n}@example.com"), "externalId": n, "active": active,
                "emails": [{ "primary": true, "value": format!("{n}@example.com") }] })
        .to_string()
    };
    app.license.set_testing(false);
    let (code, body) = call(
        port,
        "POST",
        "/scim/v2/Users",
        &bearer,
        &person("ada", true),
    )
    .await;
    assert_eq!(code, 403, "{body}");
    assert!(
        parse(&body)["detail"]
            .as_str()
            .unwrap()
            .contains("No seats"),
        "{body}"
    );
    assert!(app.db.find_user("ada@example.com").is_none());
    assert_eq!(
        events(port, &admin, "license.seat_refused").await[0]["details"]["via"].as_str(),
        Some("scim")
    );
    // Provisioned inactive: no seat needed, until they're turned on.
    let (code, body) = call(
        port,
        "POST",
        "/scim/v2/Users",
        &bearer,
        &person("grace", false),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let id = parse(&body)["id"].as_str().unwrap().to_string();
    let on =
        json!({ "Operations": [{ "op": "replace", "path": "active", "value": true }] }).to_string();
    let (code, body) = call(port, "PATCH", &format!("/scim/v2/Users/{id}"), &bearer, &on).await;
    assert_eq!(code, 403, "{body}");
    assert!(!app.db.user(&id).unwrap().active());
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(11), 100))).await.0,
        200
    );
    let (code, body) = call(port, "PATCH", &format!("/scim/v2/Users/{id}"), &bearer, &on).await;
    assert_eq!(code, 200, "{body}");
    assert!(app.db.user(&id).unwrap().active());
}

#[tokio::test]
async fn just_in_time_sso_sign_up_needs_a_seat() {
    let idp = mock_oidc("", false, crate::sso_http_tests::google_claims()).await;
    let id = format!("g{}", random_hex(4));
    let vars = provider_vars(
        &id,
        "google",
        &idp.issuer,
        &idp.secret,
        &[("HOSTED_DOMAINS", "example.com"), ("JIT_ROLE", "member")],
    );
    let (port, app, admin) = serve_vars(
        vars.into_iter()
            .chain([("SSO_PROVIDERS".into(), id.clone())])
            .collect(),
    )
    .await;
    app.license.set_testing(false);
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!(
        (code, header(&head, "location").as_deref()),
        (303, Some("/login?error=sso_no_seat"))
    );
    assert!(app.db.find_user("ada@example.com").is_none());
    assert_eq!(
        failures(port, &admin).await[0]["details"]["reason"].as_str(),
        Some("no_seat")
    );
    let ev = &events(port, &admin, "license.seat_refused").await[0];
    assert_eq!(
        (
            ev["details"]["via"].as_str(),
            ev["details"]["email"].as_str(),
            ev["actorKind"].as_str()
        ),
        (Some("sso"), Some("ada@example.com"), Some("system"))
    );
    assert_eq!(
        install(port, &admin, &mint(&claims(Some(11), 100))).await.0,
        200
    );
    assert_eq!(web_sign_in(port, &id).await.0, 200);
    assert!(app.db.find_user("ada@example.com").is_some());
}
