//! The onboarding wizard (ADR 0034), on the real router: only admins read or change it,
//! it reports what a fresh install has and lacks, saving the progress is audited where it
//! matters, and an SSO secret saved through the secrets API makes its provider ready at once.

use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn get(port: u16, auth: &str, extra: &str) -> Value {
    let (code, _, body) = call_with(port, "GET", "/api/setup", auth, extra, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

async fn patch(port: u16, auth: &str, body: Value) -> (u16, Value) {
    let (code, body) = call(port, "PATCH", "/api/setup", auth, &body.to_string()).await;
    (code, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn check<'a>(s: &'a Value, id: &str) -> &'a Value {
    s["checklist"].as_array().unwrap().iter().find(|i| i["id"] == id).unwrap_or_else(|| panic!("no {id} in {s}"))
}

#[tokio::test]
async fn a_fresh_install_reports_what_it_lacks() {
    let (port, _, admin, _) = serve_app().await;
    let s = get(port, &admin, "").await;
    assert_eq!(s["steps"], json!(["domain", "signin", "tiers", "finish"]));
    assert_eq!((s["progress"]["step"].as_str(), s["progress"]["show"].as_bool()), (Some("domain"), Some(true)));
    // Loopback only, straight to botd: no public address, no HTTPS, and how to get both.
    let d = &s["domain"];
    assert_eq!((d["publicUrl"].clone(), d["scheme"].as_str(), d["ok"].as_bool()), (Value::Null, Some("direct"), Some(false)));
    let commands = d["instructions"].to_string();
    assert!(commands.contains("install.sh --domain <your-domain>") && commands.contains("./init.sh --domain <your-domain>"), "{commands}");
    // No SSO: codes work, so nothing is waiting; templates cover every provider type.
    let si = &s["signIn"];
    assert_eq!((si["providers"].as_array().map(Vec::len), si["ok"].as_bool(), si["breakGlass"].as_bool()), (Some(0), Some(true), Some(true)));
    let types: Vec<&str> = si["templates"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
    assert_eq!(types, ["entra", "google", "github", "apple", "oidc", "saml"]);
    assert!(si["templates"][0]["env"].as_str().unwrap().contains("SSO_PUBLIC_URL=https://<your-domain>"));
    // The built-in open tier, and approvals on, as fresh installs start.
    assert_eq!((s["tiers"]["fileLoaded"].as_bool(), s["tiers"]["default"].as_str()), (Some(false), Some("self-host")));
    assert_eq!((s["approvals"]["mode"].as_str(), s["approvals"]["ok"].as_bool()), (Some("ask"), Some(true)));
    assert_eq!(check(&s, "domain")["done"], false);
    assert_eq!(check(&s, "admin")["done"], false, "break-glass is the only admin");
    assert_eq!(check(&s, "approvals")["done"], true);
    assert_eq!((s["done"].as_u64(), s["total"].as_u64()), (Some(3), Some(5)));
}

#[tokio::test]
async fn only_admins_read_or_change_it() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "mia@example.com", "member").await;
    let (_, viewer) = user_with(port, &admin, "rex@example.com", "readonly").await;
    let bot = key.auth(&app.db.create_bot("Scout", "#fff", "waddle", "claude", None, false).id);
    for (m, body) in [("GET", ""), ("PATCH", r#"{"completed":true}"#), ("PATCH", r#"{"dismissed":true}"#)] {
        assert_eq!(call(port, m, "/api/setup", "", body).await.0, 401, "{m} signed out");
        for (who, auth) in [("member", &member), ("readonly", &viewer), ("bot", &bot)] {
            let (code, res) = call(port, m, "/api/setup", auth, body).await;
            assert_eq!(code, 403, "{who}: {m} {res}");
            assert!(!res.contains("templates"), "{who} saw the report");
        }
    }
    assert_eq!(app.db.setup_progress(), setup::Progress::default(), "refused calls changed nothing");
    let (_, denied) = call(port, "GET", "/api/audit?action=access.denied", &admin, "").await;
    assert!(audit_list(&denied).iter().any(|e| e["details"]["path"] == "/api/setup"));
    // A second admin is an admin like any other.
    let (_, other) = user_with(port, &admin, "ola@example.com", "admin").await;
    assert_eq!(check(&get(port, &other, "").await, "admin")["done"], true);
}

#[tokio::test]
async fn progress_is_saved_and_finishing_is_audited() {
    let (port, app, admin, _) = serve_app().await;
    let (code, s) = patch(port, &admin, json!({ "step": "tiers" })).await;
    assert_eq!((code, s["progress"]["step"].as_str()), (200, Some("tiers")));
    assert_eq!(app.db.setup_progress().step, "tiers", "resumable");
    for bad in [json!({ "step": "billing" }), json!({ "dismissed": "yes" }), json!({ "completed": 1 }), json!({ "domain": "x.example" }), json!(["step"])] {
        assert_eq!(patch(port, &admin, bad.clone()).await.0, 400, "{bad}");
    }
    assert_eq!(app.db.setup_progress().step, "tiers");
    // Hiding it, and bringing it back.
    let (_, s) = patch(port, &admin, json!({ "dismissed": true })).await;
    assert_eq!(s["progress"]["show"], false);
    let (_, s) = patch(port, &admin, json!({ "dismissed": false })).await;
    assert_eq!(s["progress"]["show"], true);
    // Finishing: by whom, once.
    let (_, s) = patch(port, &admin, json!({ "completed": true })).await;
    let p = &s["progress"];
    assert_eq!((p["show"].as_bool(), p["step"].as_str(), p["completedBy"].as_str()), (Some(false), Some("finish"), Some(users::OPERATOR)));
    assert!(p["completedAt"].as_i64().is_some());
    let at = p["completedAt"].clone();
    let (_, s) = patch(port, &admin, json!({ "completed": true })).await;
    assert_eq!(s["progress"]["completedAt"], at, "finishing again keeps the first time");
    let (_, s) = patch(port, &admin, json!({ "completed": false })).await;
    assert_eq!((s["progress"]["show"].as_bool(), s["progress"]["completedAt"].clone()), (Some(true), Value::Null));

    let (_, audit) = call(port, "GET", "/api/audit?action=setup.*", &admin, "").await;
    let ev = audit_list(&audit);
    let actions: Vec<&str> = ev.iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["setup.reopened", "setup.completed", "setup.resumed", "setup.dismissed"], "steps alone aren't audited");
    let done = &ev[1];
    assert_eq!((done["actorId"].as_str(), done["targetType"].as_str()), (Some(users::OPERATOR), Some("setup")));
    assert_eq!(done["details"]["open"], json!(["domain", "admin"]));
}

#[tokio::test]
async fn the_domain_counts_once_https_reaches_botd_through_its_proxy() {
    let (port, _, admin, _) = serve_app_with(|a| a.hosts.push("bots.example.com".into())).await;
    let d = get(port, &admin, "X-Forwarded-Proto: https\r\n").await["domain"].clone();
    assert_eq!((d["publicUrl"].as_str(), d["scheme"].as_str(), d["ok"].as_bool()), (Some("https://bots.example.com"), Some("https"), Some(true)));
    assert!(d["instructions"].to_string().contains("install.sh --domain bots.example.com"));
    let d = get(port, &admin, "X-Forwarded-Proto: http\r\n").await["domain"].clone();
    assert_eq!((d["scheme"].as_str(), d["ok"].as_bool()), (Some("http"), Some(false)));
    assert!(d["detail"].as_str().unwrap().contains("plain HTTP") && d["httpsChecked"] == true, "{d}");
    // botctl and SSH tunnels reach botd on loopback without the proxy: HTTPS can't be checked from there.
    let d = get(port, &admin, "").await["domain"].clone();
    assert_eq!((d["scheme"].as_str(), d["httpsChecked"].as_bool(), d["ok"].as_bool()), (Some("direct"), Some(false), Some(true)));
    assert!(d["detail"].as_str().unwrap().contains("can't be checked from this machine"), "{d}");
}

#[tokio::test]
async fn a_provider_waiting_for_its_secret_is_ready_once_it_is_saved() {
    let id = format!("t{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let vars: HashMap<String, String> = [
        ("SSO_PROVIDERS".to_string(), id.clone()),
        ("SSO_PUBLIC_URL".to_string(), "https://bots.example.com".to_string()),
        (format!("SSO_{up}_TYPE"), "oidc".to_string()),
        (format!("SSO_{up}_ISSUER"), "https://idp.example.com".to_string()),
        (format!("SSO_{up}_CLIENT_ID"), "abc".to_string()),
    ]
    .into();
    let sso = sso::Sso::from_vars(&|k| vars.get(k).cloned()).unwrap();
    let (port, _, admin, _) = serve_app_with(|a| a.sso = sso).await;
    let si = get(port, &admin, "").await["signIn"].clone();
    let p = &si["providers"][0];
    assert_eq!((p["id"].as_str(), p["ready"].as_bool(), si["ok"].as_bool()), (Some(id.as_str()), Some(false), Some(false)));
    let secret = format!("SSO_{up}_CLIENT_SECRET");
    assert_eq!(p["secret"].as_str(), Some(secret.as_str()));
    assert!(p["problem"].as_str().unwrap().contains(&secret));
    assert_eq!(p["callbackUrl"], format!("https://bots.example.com/api/auth/sso/{id}/callback"));
    assert_eq!(si["publicUrl"], "https://bots.example.com");
    // Templates add to the provider that's there, and don't repeat SSO_PUBLIC_URL.
    let entra = si["templates"].as_array().unwrap().iter().find(|t| t["id"] == "entra").unwrap()["env"].as_str().unwrap().to_string();
    assert!(entra.starts_with(&format!("SSO_PROVIDERS={id},entra\n")) && !entra.contains("SSO_PUBLIC_URL"), "{entra}");

    let value = format!("s3cret-{}", random_hex(8));
    let (code, _) = call(port, "PUT", &format!("/api/secrets/{secret}"), &admin, &json!({ "value": value }).to_string()).await;
    assert_eq!(code, 200);
    let s = get(port, &admin, "").await;
    assert_eq!((s["signIn"]["providers"][0]["ready"].as_bool(), check(&s, "signin")["done"].as_bool()), (Some(true), Some(true)));
    assert!(!s.to_string().contains(&value), "the report never holds a secret");
    let _ = secrets::global().delete(&secret);
}

#[tokio::test]
async fn a_tiers_file_and_bypass_show_up() {
    let (port, app, admin, _) = serve_app().await;
    let mut t = tiers::Tiers::parse(tiers::EXAMPLE, None).unwrap();
    t.source = "/srv/tiers.json".into();
    app.tiers.set(Arc::new(t)).unwrap();
    assert_eq!(call(port, "PUT", "/api/policy", &admin, r#"{"mode":"bypass"}"#).await.0, 200);
    let s = get(port, &admin, "").await;
    let t = &s["tiers"];
    assert_eq!((t["fileLoaded"].as_bool(), t["default"].as_str(), t["managed"].as_bool()), (Some(true), Some("starter"), Some(true)));
    assert_eq!(t["tiers"].as_array().map(Vec::len), Some(3));
    assert!(!t.to_string().contains("claude-haiku"), "the wizard names plans, not their models");
    assert_eq!((s["approvals"]["mode"].as_str(), check(&s, "approvals")["done"].as_bool()), (Some("bypass"), Some(false)));
}
