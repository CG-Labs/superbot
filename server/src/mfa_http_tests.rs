//! HTTP tests for two-factor sign-in (ADR 0094), on the real router.

use crate::mfa::{self, Policy};
use crate::tests::{audit_list, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, signed_in, user_with};
use crate::*;

static PW: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| random_hex(16));

async fn serve(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String, crate::tests::BotKey) {
    serve_app_with(|a| {
        a.password = PW.clone();
        tweak(a);
    })
    .await
}

async fn login(port: u16, extra: &str, body: Value) -> (u16, String, Value) {
    let (code, head, body) = call_with(port, "POST", "/api/auth/login", "", extra, &body.to_string()).await;
    (code, head, parse(&body))
}

async fn json_call(port: u16, method: &str, path: &str, auth: &str, body: Value) -> (u16, Value) {
    let body = if body.is_null() { String::new() } else { body.to_string() };
    let (code, res) = call(port, method, path, auth, &body).await;
    (code, parse(&res))
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn unbase32(s: &str) -> Vec<u8> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {s}"),
        };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// The code an authenticator app shows `steps` time steps from now.
fn code(key: &[u8], steps: i64) -> String {
    mfa::code_at(key, db::now() + steps * mfa::STEP_MS)
}

/// Sets up a second factor in settings. Returns the key and the recovery codes.
async fn enrol(port: u16, auth: &str) -> (Vec<u8>, Vec<String>) {
    let (status, setup) = json_call(port, "POST", "/api/auth/mfa/enroll", auth, json!({})).await;
    assert_eq!(status, 200, "{setup}");
    let key = unbase32(setup["secret"].as_str().unwrap());
    let (status, done) = json_call(port, "POST", "/api/auth/mfa/confirm", auth, json!({ "totp": code(&key, 0) })).await;
    assert_eq!(status, 200, "{done}");
    let codes = done["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    (key, codes)
}

async fn set_policy(port: u16, admin: &str, require: &str) -> (u16, Value) {
    json_call(port, "PUT", "/api/auth/mfa/policy", admin, json!({ "require": require })).await
}

#[tokio::test]
async fn the_owner_enrols_at_sign_in_once_admins_need_a_second_factor() {
    let (port, app, basic, _) = serve(|_| {}).await;
    let (_, other_admin) = user_with(port, &basic, "admin2@example.com", "admin").await;

    let (status, res) = set_policy(port, &basic, "admins").await;
    assert_eq!((status, res["policy"].as_str(), res["required"].as_bool()), (200, Some("admins"), Some(true)), "{res}");
    // The password alone no longer gets in over HTTP Basic: not for the API, not for pages.
    let (status, res) = call(port, "GET", "/api/state", &basic, "").await;
    assert_eq!(status, 401, "{res}");
    assert!(parse(&res)["error"].as_str().unwrap().contains("two-factor"), "{res}");
    let (status, head, _) = call_with(port, "GET", "/console/", &basic, "", "").await;
    assert_eq!(status, 303);
    assert!(head.to_ascii_lowercase().contains("location: /login") && !head.to_ascii_lowercase().contains("www-authenticate"), "{head}");
    // Sessions already open keep working.
    assert_eq!(call(port, "GET", "/api/state", &other_admin, "").await.0, 200);

    // Sign-in asks the owner to set up an authenticator app.
    let (status, head, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    assert_eq!((status, res["mfa"].as_str()), (401, Some("enroll")), "{res}");
    assert!(head.to_ascii_lowercase().contains("cache-control: no-store"));
    let challenge = res["challenge"].as_str().unwrap().to_string();
    assert!(challenge.starts_with("sbm_"));
    assert!(res["qrSvg"].as_str().unwrap().starts_with("<svg"));
    assert!(res["otpauthUrl"].as_str().unwrap().starts_with("otpauth://totp/SuperBot:"));
    let secret = res["secret"].as_str().unwrap().to_string();
    let key = unbase32(&secret);
    assert!(app.db.mfa(users::OPERATOR).is_none(), "nothing is saved until a code proves the app");

    let (status, _, res) = login(port, "", json!({ "challenge": challenge, "totp": "000000" })).await;
    assert_eq!((status, res["mfa"].as_str()), (401, Some("enroll")), "{res}");
    let first = code(&key, 0);
    let (status, _, res) = login(port, "", json!({ "challenge": challenge, "totp": first, "label": "Laptop" })).await;
    assert_eq!(status, 200, "{res}");
    assert_eq!((res["session"]["mfa"].as_str(), res["user"]["id"].as_str()), (Some("totp"), Some("operator")));
    let recovery: Vec<String> = res["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(recovery.len(), 10);
    let owner = bearer(res["token"].as_str().unwrap());
    // The challenge is spent.
    assert_eq!(login(port, "", json!({ "challenge": challenge, "totp": code(&key, 1) })).await.0, 401);

    let (_, status_view) = json_call(port, "GET", "/api/auth/mfa", &owner, Value::Null).await;
    assert_eq!((status_view["enabled"].as_bool(), status_view["required"].as_bool(), status_view["recoveryCodesLeft"].as_i64()), (Some(true), Some(true), Some(10)));
    let (_, me) = json_call(port, "GET", "/api/auth/me", &owner, Value::Null).await;
    assert_eq!(me["mfa"], json!({ "enabled": true, "required": true }));
    // The policy keeps it on.
    let (status, _) = json_call(port, "POST", "/api/auth/mfa/disable", &owner, json!({ "recoveryCode": recovery[0] })).await;
    assert_eq!(status, 409);

    // The same code never works twice.
    let (status, _, res) = login(port, "", json!({ "password": PW.as_str(), "totp": first })).await;
    assert_eq!((status, res["mfa"].as_str()), (401, Some("totp")), "{res}");
    // The next one does, sent with the password in one go (botctl login --totp).
    let (status, _, res) = login(port, "", json!({ "password": PW.as_str(), "totp": code(&key, 1) })).await;
    assert_eq!((status, res["session"]["mfa"].as_str()), (200, Some("totp")), "{res}");

    // A recovery code works once, at the second step.
    let (_, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    assert_eq!(res["mfa"].as_str(), Some("totp"));
    assert!(res["secret"].is_null() && res["qrSvg"].is_null(), "the secret is shown only to set it up");
    let challenge = res["challenge"].as_str().unwrap().to_string();
    let (status, _, res) = login(port, "", json!({ "challenge": challenge, "recoveryCode": recovery[1].to_uppercase() })).await;
    assert_eq!((status, res["session"]["mfa"].as_str()), (200, Some("recovery_code")), "{res}");
    let (_, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    let (status, _, _) = login(port, "", json!({ "challenge": res["challenge"], "recoveryCode": recovery[1] })).await;
    assert_eq!(status, 401);

    // Signing someone out everywhere ends their sign-ins still waiting on a code.
    let (_, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    let waiting = res["challenge"].as_str().unwrap().to_string();
    assert_eq!(call(port, "DELETE", "/api/users/operator/sessions", &other_admin, "").await.0, 200);
    let (status, _, res) = login(port, "", json!({ "challenge": waiting, "recoveryCode": recovery[2] })).await;
    assert_eq!((status, res["error"].as_str()), (401, Some("That sign-in expired. Sign in again.")), "{res}");
    assert_eq!(call(port, "GET", "/api/auth/me", &owner, "").await.0, 401);

    // The audit log tells the story without a secret, code, or challenge in it.
    let (_, body) = call(port, "GET", "/api/audit?limit=1000", &other_admin, "").await;
    let ev = audit_list(&body);
    assert!(ev.iter().any(|e| e["action"] == "auth.mfa_policy_updated" && e["details"]["to"] == "admins"));
    assert!(ev.iter().any(|e| e["action"] == "user.mfa_enabled" && e["details"]["via"] == "sign_in"));
    assert!(ev.iter().any(|e| e["action"] == "auth.login" && e["details"]["mfa"] == "recovery_code" && e["details"]["recoveryCodesLeft"] == 9));
    let failed: Vec<_> = ev.iter().filter(|e| e["action"] == "auth.login_failed").collect();
    assert!(failed.iter().any(|e| e["details"]["method"] == "totp" && e["details"]["reason"] == "wrong_code" && e["actorId"] == "operator"));
    assert!(failed.iter().any(|e| e["details"]["reason"] == "replayed"));
    assert!(failed.iter().any(|e| e["details"]["method"] == "password" && e["details"]["reason"] == "mfa_required"));
    for (i, s) in [PW.as_str(), &secret, &first, &challenge, &waiting].into_iter().chain(recovery.iter().map(String::as_str)).enumerate() {
        assert!(!body.contains(s), "audit leaks secret #{i}");
    }
    let stored = app.db.mfa(users::OPERATOR).unwrap().secret;
    assert!(stored.starts_with("sb1:") && !stored.contains(&secret), "the secret is sealed on disk");
}

#[tokio::test]
async fn wrong_codes_are_limited_per_challenge_and_per_user() {
    let (port, _, basic, _) = serve(|_| {}).await;
    let (_, other_admin) = user_with(port, &basic, "admin2@example.com", "admin").await;
    let owner = bearer(&parse(&call(port, "POST", "/api/auth/login", "", &json!({ "password": PW.as_str() }).to_string()).await.1)["token"].as_str().unwrap().to_string());
    let (key, _) = enrol(port, &owner).await;
    // With the owner enrolled, the password alone stops working over HTTP Basic, policy or not.
    assert_eq!(call(port, "GET", "/api/state", &basic, "").await.0, 401);

    let (_, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    let challenge = res["challenge"].as_str().unwrap().to_string();
    for _ in 0..4 {
        let (status, _, res) = login(port, "", json!({ "challenge": challenge, "totp": "123456" })).await;
        assert_eq!((status, res["mfa"].as_str()), (401, Some("totp")), "{res}");
    }
    let (status, _, res) = login(port, "", json!({ "challenge": challenge, "totp": "123456" })).await;
    assert_eq!((status, res["error"].as_str()), (401, Some("Too many wrong codes. Sign in again.")));
    assert!(res["challenge"].is_null());
    // The right code is too late for that challenge, and the user is locked out for a while.
    assert_eq!(login(port, "", json!({ "challenge": challenge, "totp": code(&key, 1) })).await.0, 401);
    let (status, _, _) = login(port, "", json!({ "password": PW.as_str(), "totp": code(&key, 1) })).await;
    assert_eq!(status, 429);
    let (status, _) = json_call(port, "POST", "/api/auth/mfa/recovery-codes", &owner, json!({ "totp": code(&key, 1) })).await;
    assert_eq!(status, 429);
    // Made-up challenges fail like expired ones.
    assert_eq!(login(port, "", json!({ "challenge": "sbm_nope", "totp": "123456" })).await.0, 401);
    // An admin can reset it; the password then works again.
    let (status, res) = json_call(port, "DELETE", "/api/users/operator/mfa", &other_admin, Value::Null).await;
    assert_eq!((status, res["reset"].as_bool()), (200, Some(true)), "{res}");
    assert_eq!(call(port, "GET", "/api/state", &basic, "").await.0, 200);
}

#[tokio::test]
async fn people_manage_their_own_second_factor() {
    let (port, app, basic, bot) = serve(|_| {}).await;
    let (id, member) = user_with(port, &basic, "member@example.com", "member").await;

    let (_, view) = json_call(port, "GET", "/api/auth/mfa", &member, Value::Null).await;
    assert_eq!((view["enabled"].as_bool(), view["required"].as_bool(), view["policy"].as_str()), (Some(false), Some(false), Some("off")));
    let (status, setup) = json_call(port, "POST", "/api/auth/mfa/enroll", &member, json!({})).await;
    assert_eq!(status, 200);
    let key = unbase32(setup["secret"].as_str().unwrap());
    let (_, view) = json_call(port, "GET", "/api/auth/mfa", &member, Value::Null).await;
    assert_eq!((view["enabled"].as_bool(), view["pending"].as_bool()), (Some(false), Some(true)));
    // Until it's confirmed, sign-in doesn't ask.
    assert!(signed_in(port, &basic, &id).await.is_some());
    let (status, _) = json_call(port, "POST", "/api/auth/mfa/confirm", &member, json!({ "totp": "000000" })).await;
    assert_eq!(status, 403);
    let (status, done) = json_call(port, "POST", "/api/auth/mfa/confirm", &member, json!({ "totp": code(&key, 0) })).await;
    assert_eq!((status, done["enabled"].as_bool()), (200, Some(true)), "{done}");
    let old: Vec<String> = done["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(json_call(port, "POST", "/api/auth/mfa/enroll", &member, json!({})).await.0, 409);
    let (_, users) = json_call(port, "GET", &format!("/api/users/{id}"), &basic, Value::Null).await;
    assert_eq!(users["mfa"]["enabled"].as_bool(), Some(true));

    // A sign-in code now needs the second factor too.
    let (_, c) = call(port, "POST", &format!("/api/users/{id}/login-codes"), &basic, "").await;
    let (status, _, res) = login(port, "", json!({ "code": parse(&c)["code"] })).await;
    assert_eq!((status, res["mfa"].as_str()), (401, Some("totp")), "{res}");
    let (status, _, res) = login(port, "", json!({ "challenge": res["challenge"], "totp": code(&key, 1) })).await;
    assert_eq!((status, res["session"]["method"].as_str(), res["session"]["mfa"].as_str()), (200, Some("code"), Some("totp")), "{res}");

    // New recovery codes replace the old ones.
    let (status, res) = json_call(port, "POST", "/api/auth/mfa/recovery-codes", &member, json!({ "recoveryCode": old[0] })).await;
    assert_eq!(status, 200, "{res}");
    let new: Vec<String> = res["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(json_call(port, "POST", "/api/auth/mfa/disable", &member, json!({ "recoveryCode": old[1] })).await.0, 403);
    let (status, res) = json_call(port, "POST", "/api/auth/mfa/disable", &member, json!({ "recoveryCode": new[0] })).await;
    assert_eq!((status, res["enabled"].as_bool()), (200, Some(false)), "{res}");
    assert!(app.db.mfa(&id).is_none());
    assert!(signed_in(port, &basic, &id).await.is_some(), "sign-in stops asking");

    // Bots have no second factor to manage, and members can't change the policy or reset others.
    let (_, b) = call(port, "POST", "/api/bots", &basic, r#"{"name":"Helper"}"#).await;
    let bot_auth = bot.auth(parse(&b)["id"].as_str().unwrap());
    assert_eq!(json_call(port, "GET", "/api/auth/mfa", &bot_auth, Value::Null).await.0, 403);
    assert_eq!(json_call(port, "POST", "/api/auth/mfa/enroll", &bot_auth, json!({})).await.0, 403);
    assert_eq!(set_policy(port, &member, "all").await.0, 403);
    assert_eq!(json_call(port, "DELETE", "/api/users/operator/mfa", &member, Value::Null).await.0, 403);
    // Admins turn off their own in settings, not with the reset.
    assert_eq!(json_call(port, "DELETE", "/api/users/operator/mfa", &basic, Value::Null).await.0, 409);

    let (_, body) = call(port, "GET", "/api/audit?limit=1000", &basic, "").await;
    let ev = audit_list(&body);
    for action in ["user.mfa_enabled", "user.mfa_recovery_codes_created", "user.mfa_disabled", "access.denied"] {
        assert!(ev.iter().any(|e| e["action"] == action), "{action}");
    }
    assert!(!body.contains(setup["secret"].as_str().unwrap()));
    for c in old.iter().chain(&new) {
        assert!(!body.contains(c.as_str()), "audit leaks a recovery code");
    }
}

#[tokio::test]
async fn everyone_enrols_under_all_and_cookie_sign_ins_finish_the_same_way() {
    let (port, _, basic, _) = serve(|_| {}).await;
    let (_, c) = call(port, "POST", "/api/users", &basic, &json!({ "email": "m@example.com", "role": "member" }).to_string()).await;
    let id = parse(&c)["id"].as_str().unwrap().to_string();
    assert_eq!(set_policy(port, &basic, "nope").await.0, 400);
    assert_eq!(set_policy(port, &basic, "all").await.0, 200);
    // The owner is covered too, so HTTP Basic stops here.
    assert_eq!(call(port, "GET", "/api/state", &basic, "").await.0, 401);

    let origin = format!("Origin: http://127.0.0.1:{port}\r\n");
    let (_, _, res) = login(port, &origin, json!({ "password": PW.as_str(), "session": "cookie" })).await;
    assert_eq!(res["mfa"].as_str(), Some("enroll"));
    let key = unbase32(res["secret"].as_str().unwrap());
    let body = json!({ "challenge": res["challenge"], "totp": code(&key, 0), "session": "cookie" });
    assert_eq!(login(port, "Origin: https://evil.example\r\n", body.clone()).await.0, 403);
    let (status, head, res) = login(port, &origin, body).await;
    assert_eq!(status, 200, "{res}");
    assert!(res["token"].is_null() && res["recoveryCodes"].as_array().is_some_and(|c| c.len() == 10));
    let set = head.lines().find(|l| l.to_ascii_lowercase().starts_with("set-cookie:")).unwrap();
    let token = set.split_once('=').unwrap().1.split(';').next().unwrap();
    let owner = format!("Cookie: __Host-superbot_session={token}\r\n");
    // With a session cookie, a stale Basic header in the browser doesn't get in the way.
    let (status, _, _) = call_with(port, "GET", "/api/state", &basic, &owner, "").await;
    assert_eq!(status, 200);

    let (_, _, c) = call_with(port, "POST", &format!("/api/users/{id}/login-codes"), "", &format!("{owner}{origin}"), "").await;
    let (status, _, res) = login(port, "", json!({ "code": parse(&c)["code"] })).await;
    assert_eq!((status, res["mfa"].as_str()), (401, Some("enroll")), "{res}");
}

#[tokio::test]
async fn auth_mfa_pins_the_policy() {
    let (port, _, basic, _) = serve(|a| a.mfa = mfa::Mfa::with_policy(Some(Policy::Off))).await;
    let (status, res) = set_policy(port, &basic, "all").await;
    assert_eq!(status, 409, "{res}");
    let (_, view) = json_call(port, "GET", "/api/auth/mfa", &basic, Value::Null).await;
    assert_eq!((view["policy"].as_str(), view["policyPinned"].as_bool()), (Some("off"), Some(true)));

    let (port, app, basic, _) = serve(|a| a.mfa = mfa::Mfa::with_policy(Some(Policy::Admins))).await;
    app.db.set_setting(mfa::POLICY_KEY, "off");
    assert_eq!(call(port, "GET", "/api/state", &basic, "").await.0, 401, "AUTH_MFA wins over the setting");
    let (_, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    assert_eq!(res["mfa"].as_str(), Some("enroll"));
}
