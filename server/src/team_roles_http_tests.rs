//! Team owners and admins giving custom roles in their own team (ADR 0254), on the real
//! router: only roles that add something in a team, only to its plain members, never to
//! themselves nor over their identity provider, and audited as the team's.

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

async fn role(port: u16, admin: &str, body: Value) -> String {
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

fn path(user: &str) -> String {
    format!("/api/team/members/{user}/custom-role")
}

#[tokio::test]
async fn team_owners_and_admins_give_roles_in_their_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "eve@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (dee, _) = user_with(port, &admin, "dee@example.com", "member").await;
    let (ro, _) = user_with(port, &admin, "ro@example.com", "readonly").await;
    let (bea, bea_auth) = user_with(port, &admin, "bea@example.com", "member").await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let alpha = team(port, &admin, "Alpha", &ada, &[(&eve, "admin"), (&cy, "member"), (&dee, "member"), (&ro, "member")]).await;
    team(port, &admin, "Beta", &bea, &[(&bo, "member")]).await;
    let people = role(port, &admin, json!({ "name": "Team people", "permissions": ["users.manage", "audit.view"] })).await;
    let ops = role(port, &admin, json!({ "name": "On call", "permissions": ["machines.manage"], "maxDays": 7 })).await;
    let auditor = role(port, &admin, json!({ "name": "Auditor", "base": "readonly", "permissions": ["audit.view"] })).await;

    // Owners and admins are offered the roles that add something in a team, with what they add there.
    for who in [&ada_auth, &eve_auth] {
        let (_, mine) = json_call(port, "GET", "/api/team", who, "").await;
        let choices = mine["roleChoices"].as_array().unwrap();
        assert_eq!(choices.iter().map(|c| c["id"].as_str().unwrap()).collect::<Vec<_>>(), [ops.as_str(), people.as_str()], "{mine}");
        let p = choices.iter().find(|c| c["id"] == people.as_str()).unwrap();
        assert_eq!((p["applies"].clone(), p["maxDays"].clone()), (json!(["users.manage"]), Value::Null), "{p}");
        assert_eq!(choices.iter().find(|c| c["id"] == ops.as_str()).unwrap()["maxDays"], 7);
    }
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert!(mine.get("roleChoices").is_none(), "members aren't offered any: {mine}");

    // A plain member gives nothing.
    assert_eq!(call(port, "PUT", &path(&dee), &cy_auth, &json!({ "role": people }).to_string()).await.0, 403);

    // The owner gives one, by id or name; only its team permissions apply, only there.
    let (code, v) = json_call(port, "PUT", &path(&cy), &ada_auth, &json!({ "role": "team people", "reason": "Helps with invites" }).to_string()).await;
    assert_eq!((code, v["applies"].clone(), v["role"]["id"].as_str()), (200, json!(["users.manage"]), Some(people.as_str())), "{v}");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!((mine["customRole"]["name"].as_str(), mine["permissions"].clone()), (Some("Team people"), json!(["users.manage"])), "{mine}");
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 201);
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 403, "nothing across the server");
    assert_eq!(app.db.user(&cy).unwrap().role_id, None);
    let given = events(port, &admin, "role.assigned").await;
    let e = &given[0];
    assert_eq!((e["actorId"].as_str(), e["targetId"].as_str()), (Some(ada.as_str()), Some(people.as_str())), "{e}");
    let d = &e["details"];
    assert_eq!((d["via"].as_str(), d["scope"].as_str(), d["team"].as_str(), d["user"].as_str(), d["reason"].as_str()), (Some("team"), Some("team"), Some(alpha.as_str()), Some(cy.as_str()), Some("Helps with invites")), "{e}");

    // Holding users.manage in the team, they still don't give roles: only owners and admins do.
    assert_eq!(call(port, "PUT", &path(&dee), &cy_auth, &json!({ "role": people }).to_string()).await.0, 403);
    assert_eq!(call(port, "DELETE", &path(&cy), &cy_auth, "").await.0, 403);

    // A team admin gives a time-bound role, with an end within its limit.
    let day = roles::DAY;
    assert_eq!(call(port, "PUT", &path(&dee), &eve_auth, &json!({ "role": ops }).to_string()).await.0, 400, "a time-bound role needs an end");
    assert_eq!(call(port, "PUT", &path(&dee), &eve_auth, &json!({ "role": ops, "expiresAt": db::now() + 8 * day }).to_string()).await.0, 400, "within its limit");
    let ends = db::now() + 2 * day;
    let (code, v) = json_call(port, "PUT", &path(&dee), &eve_auth, &json!({ "role": ops, "expiresAt": ends }).to_string()).await;
    assert_eq!((code, v["role"]["expiresAt"].as_i64()), (200, Some(ends)), "{v}");
    let (_, owner_view) = json_call(port, "GET", "/api/team", &ada_auth, "").await;
    let dee_row = owner_view["members"].as_array().unwrap().iter().find(|m| m["id"] == dee.as_str()).unwrap().clone();
    assert_eq!(dee_row["customRole"], json!({ "id": ops, "name": "On call", "expiresAt": ends }), "{dee_row}");

    // What can't be given, and to whom.
    for (who, body, code, why) in [
        (&ada_auth, json!({ "role": auditor }), 409, "adds nothing in a team"),
        (&ada_auth, json!({ "role": "nope" }), 404, "no such role"),
        (&ada_auth, json!({}), 400, "names a role"),
        (&ada_auth, json!({ "role": people, "until": db::now() + day }), 400, "unknown field"),
    ] {
        let (c, v) = json_call(port, "PUT", &path(&cy), who, &body.to_string()).await;
        assert_eq!(c, code, "{why}: {v}");
    }
    for (target, who, code, why) in [
        (&ada, &ada_auth, 409, "not yourself"),
        (&eve, &ada_auth, 409, "the team's admins hold it all already"),
        (&ada, &eve_auth, 409, "nor its owners"),
        (&ro, &ada_auth, 409, "read-only people change nothing"),
        (&bo, &ada_auth, 404, "someone on another team"),
        (&cy, &bea_auth, 404, "another team's owner"),
    ] {
        let (c, v) = json_call(port, "PUT", &path(target), who, &json!({ "role": people }).to_string()).await;
        assert_eq!(c, code, "{why}: {v}");
    }
    assert_eq!(call(port, "DELETE", &path(&cy), &bea_auth, "").await.0, 404);

    // Taking it away, whoever gave it.
    let billing = role(port, &admin, json!({ "name": "Billing", "permissions": ["billing.manage"] })).await;
    let (code, v) = json_call(port, "DELETE", &path(&cy), &eve_auth, "").await;
    assert_eq!((code, v["role"].clone()), (200, Value::Null), "{v}");
    assert_eq!(call(port, "DELETE", &path(&cy), &eve_auth, "").await.0, 404, "they hold none now");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!(mine["permissions"], json!([]), "{mine}");
    let taken = events(port, &admin, "role.unassigned").await;
    assert_eq!((taken[0]["actorId"].as_str(), taken[0]["details"]["via"].as_str(), taken[0]["details"]["user"].as_str()), (Some(eve.as_str()), Some("team"), Some(cy.as_str())), "{taken:?}");
    // One a server admin gave, too.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{billing}/teams/{alpha}/users/{cy}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &path(&cy), &ada_auth, "").await.0, 200);
    // The admin's own route doesn't name a via.
    let given = events(port, &admin, "role.assigned").await;
    assert!(given[0]["details"].get("via").is_none(), "{:?}", given[0]);
}

#[tokio::test]
async fn a_role_from_the_identity_provider_stays_with_its_mapping() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (fay, _) = user_with(port, &admin, "fay@example.com", "member").await;
    let alpha = team(port, &admin, "Alpha", &ada, &[(&fay, "member")]).await;
    let billing = role(port, &admin, json!({ "name": "Billing", "permissions": ["billing.manage"] })).await;
    let people = role(port, &admin, json!({ "name": "Team people", "permissions": ["users.manage"] })).await;
    app.db.link_scim_group("okta", &alpha, None, "Alpha", None).unwrap();
    let m = app.db.create_scim_role_mapping("okta", &alpha, &billing, "team", None).unwrap();
    assert!(app.db.grant_scim_role(&m, &fay));

    let (_, mine) = json_call(port, "GET", "/api/team", &ada_auth, "").await;
    let row = mine["members"].as_array().unwrap().iter().find(|r| r["id"] == fay.as_str()).unwrap().clone();
    assert_eq!(row["customRole"], json!({ "id": billing, "name": "Billing", "fromIdp": true }), "{row}");
    let (code, v) = json_call(port, "PUT", &path(&fay), &ada_auth, &json!({ "role": people }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("identity provider"), "{v}");
    assert_eq!(call(port, "DELETE", &path(&fay), &ada_auth, "").await.0, 409);
    assert_eq!(app.db.team_member(&fay).unwrap().role_id.as_deref(), Some(billing.as_str()), "unchanged");

    // Checked again in the write's transaction, so a SCIM grant landing after the route's own
    // check still keeps the team's owners and admins off it.
    assert!(app.db.give_team_custom_role_unless_idp(&alpha, &fay, &people, None).is_none());
    assert!(!app.db.take_team_custom_role_unless_idp(&alpha, &fay));
    let (t, u, r) = (app.db.team(&alpha).unwrap(), app.db.user(&fay).unwrap(), app.db.custom_role(&people).unwrap());
    let by = audit::Who::system("test");
    let giving = roles::parse_giving(&json!({}), &r).unwrap();
    assert_eq!(roles::give_in_team(&app, &by, &r, &t, &u, giving, Some("team")).unwrap_err().0, StatusCode::CONFLICT);
    assert_eq!(roles::take_in_team(&app, &by, &r, &t, &u, Some("team")).unwrap_err().0, StatusCode::CONFLICT);
    assert_eq!(app.db.team_member(&fay).unwrap().role_id.as_deref(), Some(billing.as_str()), "still unchanged");

    // A server admin still overrides it, as before.
    let (code, _) = json_call(port, "PUT", &format!("/api/roles/{people}/teams/{alpha}/users/{fay}"), &admin, "").await;
    assert_eq!(code, 200);
    let given = events(port, &admin, "role.assigned").await;
    assert_eq!(given[0]["details"]["takenFromScim"].as_str(), Some(m.id.as_str()), "{:?}", given[0]);
}
