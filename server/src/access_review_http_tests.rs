//! HTTP tests for the access-review report (ADR 0099), on the real router: what it
//! lists for each person, that it shows metadata and never a credential, its CSV
//! export, and the audited sign-off.

use crate::acl::{Grant, Visibility};
use crate::db::{NewMachine, ScimFields};
use crate::rbac::Role;
use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn report(port: u16, auth: &str) -> Value {
    let (code, body) = call(port, "GET", "/api/access-review", auth, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

fn people(r: &Value) -> Vec<Value> {
    r["groups"].as_array().unwrap().iter().flat_map(|g| g["people"].as_array().unwrap().clone()).collect()
}

fn find(r: &Value, id: &str) -> Value {
    people(r).into_iter().find(|p| p["id"] == id).unwrap_or_else(|| panic!("{id} not in {r}"))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

#[tokio::test]
async fn the_report_lists_each_persons_access_and_never_a_credential() {
    let (port, app, admin, key) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "readonly").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    // Ada: on a team, with a second factor, a machine assigned to her, and a grant on a private Bot.
    let team = app.db.create_team("Research", None);
    assert!(app.db.add_team_member(&team.id, &ada, "owner", None));
    assert!(app.db.add_team_member(&team.id, &cy, "member", None));
    assert!(app.db.mfa_begin(&ada, "sealed") && app.db.mfa_confirm(&ada, "sealed", 1, &[]));
    let m = app
        .db
        .add_machine(&NewMachine { user_id: &ada, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None })
        .unwrap();
    assert!(app.db.assign_machine(&m.id, Some("operator")));
    let private = app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &cy, Visibility::Private);
    app.db.set_grant(&private.id, &ada, Grant::Operator, &cy);
    let hidden = app.db.create_bot_owned("Diary", "#fff", "waddle", "claude", None, false, &cy, Visibility::Private);
    // Bo: disabled, so his sessions end.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    // Dee: made by a SCIM tenant.
    let f = ScimFields { user_name: "dee@example.com", external_id: Some("e1"), given_name: None, family_name: None, scim_display_name: None, formatted: None, display_name: "Dee", email: Some("dee@example.com"), active: Some(true) };
    let dee = app.db.create_scim_user("okta", &f, Role::Member, None).unwrap().id;

    let r = report(port, &admin).await;
    let a = find(&r, &ada);
    assert_eq!((a["role"].as_str(), a["status"].as_str(), a["email"].as_str()), (Some("member"), Some("active"), Some("ada@example.com")));
    assert_eq!(a["team"], json!({ "id": team.id, "name": "Research", "role": "owner" }));
    assert_eq!(a["mfa"]["enabled"], true);
    assert_eq!(a["lastLogin"]["method"], "code");
    assert_eq!(a["scim"], Value::Null);
    assert_eq!((a["machine"]["id"].as_str(), a["machine"]["assignedAt"].is_i64()), (Some(m.id.as_str()), true));
    // Her one sign-in is a bearer token: listed with its id and when it ends, never the token.
    let tokens = a["apiTokens"].as_array().unwrap();
    assert_eq!((tokens.len(), a["sessions"].as_array().unwrap().len()), (1, 0));
    assert!(tokens[0]["id"].is_string() && tokens[0]["endsAt"].is_i64());
    let bots = a["botAccess"]["bots"].as_array().unwrap();
    let ledger = bots.iter().find(|b| b["id"] == private.id.as_str()).expect("granted Bot");
    assert_eq!((ledger["access"].as_str(), ledger["grant"].as_str(), ledger["owner"]["name"].as_str(), ledger["own"].as_bool()), (Some("operate"), Some("operator"), Some("cy"), Some(false)));
    assert!(!bots.iter().any(|b| b["id"] == hidden.id.as_str()), "a private Bot without a grant isn't hers");
    // The owner is an admin: every Bot, by role, not listed one by one.
    let owner = find(&r, "operator");
    assert_eq!((owner["breakGlass"].as_bool(), owner["botAccess"]["all"].as_bool(), owner["role"].as_str()), (Some(true), Some(true), Some("admin")));
    let b = find(&r, &bo);
    assert_eq!((b["status"].as_str(), b["apiTokens"].as_array().unwrap().len()), (Some("disabled"), 0));
    assert_eq!(find(&r, &dee)["scim"], json!({ "tenant": "okta", "deleted": false }));
    // Grouped by tenant, then team: people in neither come first, then Okta's, then Research.
    let groups: Vec<(Value, Value)> = r["groups"].as_array().unwrap().iter().map(|g| (g["tenant"].clone(), g["team"]["name"].clone())).collect();
    assert_eq!(groups, [(Value::Null, Value::Null), (Value::Null, json!("Research")), (json!("okta"), Value::Null)]);
    assert_eq!(r["summary"]["people"], 5);
    assert_eq!((r["summary"]["disabled"].as_i64(), r["summary"]["activeWithoutMfa"].as_i64(), r["summary"]["scimManaged"].as_i64()), (Some(1), Some(3), Some(1)));
    assert_eq!(r["digest"].as_str().map(str::len), Some(64));

    // Nothing secret: no token, hash, code, IP or second-factor secret.
    let text = r.to_string();
    let token = ada_auth.strip_prefix("Bearer ").unwrap();
    for bad in [token, &users::hash(token), "tokenHash", "\"ip\"", "sealed", "userAgent"] {
        assert!(!text.contains(bad), "{bad} in {text}");
    }
    // Admins only: not members, read-only people or Bots, and nobody signed out.
    let bot = key.auth(&app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false).id);
    for (who, auth) in [("member", ada_auth.as_str()), ("bot", bot.as_str())] {
        for (m, p) in [("GET", "/api/access-review"), ("GET", "/api/access-review/export.csv"), ("POST", "/api/access-review/complete")] {
            assert_eq!(call(port, m, p, auth, &json!({ "digest": r["digest"] }).to_string()).await.0, 403, "{who}: {m} {p}");
        }
    }
    assert_eq!(call(port, "GET", "/api/access-review", "", "").await.0, 401);
    assert!(events(port, &admin, "access_review.*").await.is_empty(), "refused calls sign nothing off");
}

#[tokio::test]
async fn the_csv_has_a_dated_row_per_person_and_its_export_is_audited() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    // A name a spreadsheet would run as a formula.
    app.db.update_user(&ada, crate::db::UserPatch { name: Some("=HYPERLINK(\"x\")".into()), ..Default::default() }).unwrap();
    let digest = report(port, &admin).await["digest"].as_str().unwrap().to_string();
    let (code, head, body) = call_with(port, "GET", "/api/access-review/export.csv", &admin, "", "").await;
    assert_eq!(code, 200, "{body}");
    let head = head.to_ascii_lowercase();
    assert!(head.contains("content-type: text/csv") && head.contains("filename=\"superbot-access-review-") && head.contains("cache-control: no-store"), "{head}");
    let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines[0], access_review::CSV_HEADER.trim_end());
    assert_eq!(lines.len(), 3, "the owner and Ada: {body}");
    let row = lines.iter().find(|l| l.contains(&ada)).unwrap();
    assert!(row.contains("\"'=HYPERLINK(\"\"x\"\")\""), "formulas are escaped: {row}");
    assert!(row.starts_with("20") && row.ends_with(&digest) && row.contains(",member,active,false,false,false,"), "{row}");
    let owner = lines.iter().find(|l| l.contains(",operator,")).unwrap();
    assert!(owner.contains("all (admin)") && owner.contains(",admin,active,false,true,"), "{owner}");
    let ev = events(port, &admin, "access_review.exported").await;
    assert_eq!((ev.len(), ev[0]["details"]["digest"].as_str(), ev[0]["actorId"].as_str()), (1, Some(digest.as_str()), Some("operator")));

    // Asked for the report on screen: the same one exports, a changed one is refused.
    let url = format!("/api/access-review/export.csv?digest={digest}");
    assert_eq!(call_with(port, "GET", &url, &admin, "", "").await.0, 200);
    let (new, _) = user_with(port, &admin, "new@example.com", "admin").await;
    let (code, _, body) = call_with(port, "GET", &url, &admin, "", "").await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(events(port, &admin, "access_review.exported").await.len(), 2);

    // The web client names the file from Content-Disposition, so a browser on another origin must be let read it.
    let bearer = crate::scim_http_tests::session_for(port, &admin, &new).await;
    let (code, head, _) = call_with(port, "GET", "/api/access-review/export.csv", &bearer, "Origin: http://localhost:8081\r\n", "").await;
    assert_eq!(code, 200);
    assert!(head.to_ascii_lowercase().contains("access-control-expose-headers: content-disposition"), "{head}");
}

#[tokio::test]
async fn a_reviewer_signs_off_on_the_report_they_saw() {
    let (port, _, admin, _) = serve_app().await;
    let (_, second) = user_with(port, &admin, "lee@example.com", "admin").await;
    let r = report(port, &second).await;
    let digest = r["digest"].as_str().unwrap().to_string();
    assert_eq!(r["reviews"], json!([]));
    assert_eq!(report(port, &second).await["digest"], r["digest"], "looking again changes nothing");

    for (body, want) in [
        (json!({}), 400),
        (json!({ "digest": "" }), 400),
        (json!({ "digest": digest, "notes": 7 }), 400),
        (json!({ "digest": digest, "notes": "x".repeat(501) }), 400),
        (json!({ "digest": "0".repeat(64) }), 409),
    ] {
        let (code, res) = call(port, "POST", "/api/access-review/complete", &second, &body.to_string()).await;
        assert_eq!(code, want, "{body}: {res}");
    }
    assert!(events(port, &admin, "access_review.completed").await.is_empty());

    let (code, res) = call(port, "POST", "/api/access-review/complete", &second, &json!({ "digest": digest, "notes": "  Q4: removed nobody  " }).to_string()).await;
    assert_eq!(code, 201, "{res}");
    let review = parse(&res)["review"].clone();
    assert_eq!((review["digest"].as_str(), review["notes"].as_str(), review["reviewer"]["email"].as_str(), review["reviewer"]["role"].as_str()), (Some(digest.as_str()), Some("Q4: removed nobody"), Some("lee@example.com"), Some("admin")));
    assert_eq!(review["summary"]["people"], 2);
    let ev = &events(port, &admin, "access_review.completed").await[0];
    assert_eq!((ev["actorEmail"].as_str(), ev["authMethod"].as_str(), ev["targetType"].as_str()), (Some("lee@example.com"), Some("code"), Some("access_review")));
    assert!(ev["sessionId"].is_string() && ev["time"].is_string());
    assert_eq!(review["eventId"], ev["id"]);
    assert_eq!(report(port, &admin).await["reviews"][0]["eventId"], ev["id"]);

    // Access changes: the old digest no longer signs anything off.
    let _ = user_with(port, &admin, "new@example.com", "member").await;
    let (code, res) = call(port, "POST", "/api/access-review/complete", &second, &json!({ "digest": digest }).to_string()).await;
    assert_eq!(code, 409, "{res}");
    assert_eq!(events(port, &admin, "access_review.completed").await.len(), 1);
}
