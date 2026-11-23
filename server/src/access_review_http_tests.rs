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
    let f = ScimFields { user_name: "dee@example.com", external_id: Some("e1"), given_name: None, family_name: None, scim_display_name: None, formatted: None, display_name: "Dee", email: Some("dee@example.com"), active: Some(true), enterprise: &Default::default() };
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
    assert_eq!(find(&r, &dee)["scim"], json!({ "tenant": "okta", "deleted": false, "department": null, "employeeNumber": null, "manager": null }));
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

fn service<'a>(r: &'a Value, id: &str) -> &'a Value {
    r["serviceAccounts"].as_array().unwrap().iter().find(|s| s["id"] == id).expect("the service account is in the report")
}

#[tokio::test]
async fn service_accounts_are_reviewed_with_their_owner_tokens_and_bots() {
    use crate::service_accounts_http_tests::{account, role, token};
    let (port, app, admin, _) = serve_app().await;
    let before = report(port, &admin).await;
    assert_eq!((before["serviceAccounts"].clone(), before["summary"]["serviceAccounts"].clone()), (json!([]), json!(0)));
    // A deleted service account holds nothing: the report and its digest are as if it never was.
    let temp = account(port, &admin, json!({ "name": "Temp" })).await;
    assert_ne!(report(port, &admin).await["digest"], before["digest"]);
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{temp}"), &admin, "").await.0, 200);
    assert_eq!(report(port, &admin).await["digest"], before["digest"], "reports without service accounts keep their digests");

    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let (code, t) = call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": bo }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = parse(&t)["id"].as_str().unwrap().to_string();
    let shared = app.db.create_bot_owned("Alpha ops", "#fff", "waddle", "claude", None, false, &bo, Visibility::Shared).id;
    let exporter = role(port, &admin, "Exporter", "readonly", &["audit.view"]).await;
    let audit = account(port, &admin, json!({ "name": "Audit export", "role": "Exporter" })).await;
    let (audit_tok, audit_t) = token(port, &admin, &audit, json!({ "name": "SIEM pull", "scopes": ["read", "audit.view"] })).await;
    let ci = account(port, &admin, json!({ "name": "CI", "role": "member", "team": team })).await;
    let (_, ci_t) = token(port, &admin, &ci, json!({})).await;
    let adas = account(port, &admin, json!({ "name": "Ada's report" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{adas}"), &admin, &json!({ "owner": ada }).to_string()).await.0, 200);
    let (_, adas_t) = token(port, &admin, &adas, json!({})).await;

    let r = report(port, &admin).await;
    let names: Vec<&str> = r["serviceAccounts"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Ada's report", "Audit export", "CI"], "live ones, by name");
    let a = service(&r, &audit);
    assert_eq!((a["role"].as_str(), a["status"].as_str(), a["owner"]["id"].as_str(), a["ownerActive"].as_bool()), (Some("readonly"), Some("active"), Some(users::OPERATOR), Some(true)));
    assert_eq!((a["customRole"]["id"].as_str(), a["customRole"]["permissions"].clone()), (Some(exporter.as_str()), json!(["audit.view"])));
    assert_eq!(a["effective"], json!(["account", "read", "review", "audit.view"]));
    let tok = &a["tokens"][0];
    let hint = audit_t["tokenInfo"]["hint"].as_str().unwrap();
    assert_eq!((tok["id"].clone(), tok["name"].as_str(), tok["scopes"].clone()), (audit_t["tokenInfo"]["id"].clone(), Some("SIEM pull"), json!(["read", "audit.view"])));
    assert_eq!((tok["preview"].as_str(), tok["lastUsedAt"].clone(), tok["expiresAt"].is_i64()), (Some(format!("sbsa_…{hint}").as_str()), Value::Null, true));
    assert_eq!(a["flags"], json!([]), "a scoped token, used or not yet old, needs no second look");
    // A team's service account: its team, as a plain member, and the team's shared Bots.
    let c = service(&r, &ci);
    assert_eq!((c["team"]["id"].as_str(), c["team"]["name"].as_str(), c["team"]["role"].as_str()), (Some(team.as_str()), Some("Alpha"), Some("member")));
    let bots = c["botAccess"]["bots"].as_array().unwrap();
    assert!(bots.iter().any(|b| b["id"] == shared.as_str() && b["owner"]["id"] == bo.as_str()), "{bots:?}");
    assert_eq!(c["flags"], json!(["unscoped_token"]), "a token with all the account holds");
    assert_eq!(service(&r, &adas)["owner"]["id"].as_str(), Some(ada.as_str()));
    assert_eq!((r["summary"]["serviceAccounts"].clone(), r["summary"]["serviceApiAccess"].clone(), r["summary"]["serviceAccountsFlagged"].clone()), (json!(3), json!(3), json!(2)));
    assert_eq!(r["summary"]["people"], 3, "service accounts aren't counted as people");
    assert!(people(&r).iter().all(|p| p["id"] != audit.as_str() && p["id"] != ci.as_str()));

    // Using a token changes nothing a reviewer signs off on; only when it was last used.
    assert_eq!(call(port, "GET", "/api/auth/me", &audit_tok, "").await.0, 200);
    let used = report(port, &admin).await;
    assert!(service(&used, &audit)["tokens"][0]["lastUsedAt"].is_i64());
    assert_eq!(used["digest"], r["digest"], "a script calling during the review changes nothing");
    // Metadata only: never a token, its hash, or where it was used from.
    let text = used.to_string();
    let secret = audit_tok.strip_prefix("Bearer ").unwrap();
    for (what, bad) in [("the token", secret), ("its hash", users::hash(secret).as_str()), ("tokenHash", "tokenHash"), ("token_hash", "token_hash"), ("lastUsedIp", "lastUsedIp"), ("an address", "127.0.0.1")] {
        assert!(!text.contains(bad), "{what} is in the report");
    }

    // A token left unused for 90 days is flagged, and stays in the digest unchanged.
    app.db.set_service_token_created(ci_t["tokenInfo"]["id"].as_str().unwrap(), db::now() - 91 * 24 * 60 * 60_000);
    let old = report(port, &admin).await;
    assert_eq!(service(&old, &ci)["flags"], json!(["unscoped_token", "unused_token"]));
    assert_eq!(old["digest"], r["digest"]);

    // An owner who's disabled lends nothing: flagged, nothing usable today, and a new digest.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ada}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    let off = report(port, &admin).await;
    let s = service(&off, &adas);
    assert_eq!((s["ownerActive"].as_bool(), s["effective"].clone(), s["owner"]["status"].as_str()), (Some(false), json!([]), Some("disabled")));
    assert_eq!(s["flags"], json!(["owner_inactive", "unscoped_token"]));
    assert_ne!(off["digest"], r["digest"]);
    // A new token is new access: the old digest no longer signs off.
    let _ = token(port, &admin, &audit, json!({ "scopes": ["read"] })).await;
    let (code, res) = call(port, "POST", "/api/access-review/complete", &admin, &json!({ "digest": off["digest"] }).to_string()).await;
    assert_eq!(code, 409, "{res}");
    // Revoked tokens leave the report, and the sign-off keeps the counts.
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{adas}/tokens/{}", adas_t["tokenInfo"]["id"].as_str().unwrap()), &admin, "").await.0, 200);
    let now = report(port, &admin).await;
    assert_eq!(service(&now, &adas)["tokens"], json!([]));
    let (code, res) = call(port, "POST", "/api/access-review/complete", &admin, &json!({ "digest": now["digest"] }).to_string()).await;
    assert_eq!(code, 201, "{res}");
    assert_eq!((parse(&res)["review"]["summary"]["serviceAccounts"].clone(), parse(&res)["review"]["summary"]["serviceApiAccess"].clone()), (json!(3), json!(3)));
}

#[tokio::test]
async fn a_service_account_whose_owner_is_off_its_team_is_flagged() {
    use crate::service_accounts_http_tests::account;
    let (port, app, admin, _) = serve_app().await;
    let (ana, _) = user_with(port, &admin, "ana@example.com", "member").await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let (code, t) = call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": bo }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let alpha = parse(&t)["id"].as_str().unwrap().to_string();
    let (code, body) = call(port, "PUT", &format!("/api/teams/{alpha}/members/{ana}"), &admin, "{}").await;
    assert!(code == 200 || code == 201, "{body}");
    let anas = account(port, &admin, json!({ "name": "Ana's sync", "role": "member", "team": alpha })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{anas}"), &admin, &json!({ "owner": ana }).to_string()).await.0, 200);
    let admins = account(port, &admin, json!({ "name": "Alpha ops", "role": "member", "team": alpha })).await;
    let loose = account(port, &admin, json!({ "name": "Loose" })).await;

    let on = report(port, &admin).await;
    let s = service(&on, &anas);
    assert_eq!((s["ownerOnTeam"].clone(), s["flags"].clone()), (json!(true), json!([])), "{s}");
    assert_eq!(service(&on, &admins)["ownerOnTeam"], json!(true), "an admin owner is on every team");
    assert_eq!(service(&on, &loose)["ownerOnTeam"], Value::Null, "in no team, there's nothing to be on");

    // Ana leaves Alpha: her account acts in no team, so the reviewer is told and the old digest is stale.
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{alpha}/members/{ana}"), &admin, "").await.0, 200);
    let off = report(port, &admin).await;
    let s = service(&off, &anas);
    assert_eq!((s["ownerOnTeam"].clone(), s["flags"].clone(), s["team"]["id"].as_str()), (json!(false), json!(["owner_off_team"]), Some(alpha.as_str())), "{s}");
    assert_eq!(service(&off, &admins)["flags"], json!([]));
    assert_eq!(off["summary"]["serviceAccountsFlagged"], 1);
    assert_ne!(off["digest"], on["digest"]);
    let (code, res) = call(port, "POST", "/api/access-review/complete", &admin, &json!({ "digest": on["digest"] }).to_string()).await;
    assert_eq!(code, 409, "{res}");
    let (code, _, csv) = call_with(port, "GET", &format!("/api/access-review/export.csv?digest={}", off["digest"].as_str().unwrap()), &admin, "", "").await;
    assert_eq!(code, 200, "{csv}");
    let row = csv.split("\r\n").find(|l| l.contains(&anas)).unwrap();
    assert!(row.ends_with(&format!(",owner_off_team,{}", off["digest"].as_str().unwrap())), "{row}");

    // An inactive owner lends nothing anywhere: that flag says it, not both.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(service(&report(port, &admin).await, &anas)["flags"], json!(["owner_inactive"]));
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"active"}"#).await.0, 200);

    // Back on the team, it acts there again, and the report is as it was.
    assert!(app.db.add_team_member(&alpha, &ana, "member", None));
    let back = report(port, &admin).await;
    assert_eq!((service(&back, &anas)["ownerOnTeam"].clone(), service(&back, &anas)["flags"].clone()), (json!(true), json!([])));
}

#[tokio::test]
async fn the_csv_has_a_row_per_service_account() {
    use crate::service_accounts_http_tests::{account, token};
    let (port, _, admin, _) = serve_app().await;
    let sa = account(port, &admin, json!({ "name": "=Export", "role": "member" })).await;
    let (tok, t) = token(port, &admin, &sa, json!({ "name": "Nightly", "scopes": ["read", "write"] })).await;
    let wide = account(port, &admin, json!({ "name": "Wide" })).await;
    let _ = token(port, &admin, &wide, json!({})).await;
    let digest = report(port, &admin).await["digest"].as_str().unwrap().to_string();
    let (code, _, body) = call_with(port, "GET", &format!("/api/access-review/export.csv?digest={digest}"), &admin, "", "").await;
    assert_eq!(code, 200, "{body}");
    let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines[0], access_review::CSV_HEADER.trim_end());
    assert!(lines[0].ends_with(",kind,owner,effective_permissions,service_tokens,service_flags,report_digest"), "{}", lines[0]);
    assert_eq!(lines.len(), 4, "the owner and the service accounts: {body}");
    let flagged = lines.iter().find(|l| l.contains(&wide)).unwrap();
    assert!(flagged.contains(&format!("scopes:all expires:")) && flagged.ends_with(&format!(",unscoped_token,{digest}")), "flags agree with the report: {flagged}");
    let person = lines.iter().find(|l| l.contains(",operator,")).unwrap();
    assert!(person.contains(&format!(",person,,,,,{digest}")), "{person}");
    let row = lines.iter().find(|l| l.contains(&sa)).unwrap();
    let hint = t["tokenInfo"]["hint"].as_str().unwrap();
    assert!(row.contains(",'=Export,"), "formulas are escaped: {row}");
    assert!(row.contains(",member,active,false,false,,,,,"), "no email, second factor or sign-in: {row}");
    assert!(row.contains(",service_account,Owner (operator),account read review write approve,"), "{row}");
    assert!(row.contains(&format!("Nightly sbsa_…{hint} scopes:read write expires:20")) && row.contains("last_used:never"), "{row}");
    assert!(row.ends_with(&format!(",{digest}")) && row.contains(&format!("last_used:never,,{digest}")), "a scoped, new token has no flags: {row}");
    assert!(row.starts_with("20") && row.ends_with(&digest), "{row}");
    assert!(!body.contains(tok.strip_prefix("Bearer ").unwrap()), "never the token");
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
