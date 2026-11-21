//! Team accounts (ADR 0087), on the real router with the in-memory provider: sharing
//! stops at the team, team admins manage teammates' machines and nothing else of
//! theirs, and joining and leaving provision and release machines. Nothing here talks
//! to a cloud.

use crate::acl::Visibility;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::Routing;
use crate::tests::{audit_list, call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
    /// Alpha's owner, and a member of it.
    ada_id: String,
    ada: String,
    al_id: String,
    al: String,
    /// Beta's owner.
    bea_id: String,
    bea: String,
    alpha: String,
    beta: String,
}

async fn serve(routing: Routing, teams: crate::teams::Settings) -> World {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, owner, _) = serve_app_with(move |a| {
        let mut cp = ControlPlane::for_tests(p);
        cp.routing = routing;
        a.machines = Arc::new(cp);
    })
    .await;
    app.teams.set(teams).unwrap();
    app.db.set_teams_strict(teams.strict);
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let (al_id, al) = user_with(port, &admin, "al@example.com", "member").await;
    let (bea_id, bea) = user_with(port, &admin, "bea@example.com", "member").await;
    let alpha = make_team(port, &admin, "Alpha", "ada@example.com").await;
    let beta = make_team(port, &admin, "Beta", "bea@example.com").await;
    let (code, v) = json_call(port, "PUT", &format!("/api/teams/{alpha}/members/{al_id}"), &admin, "{}").await;
    assert_eq!((code, v["role"].as_str(), v["provisioned"].as_str()), (200, Some("member"), Some("requested")), "{v}");
    World { port, app, admin, fake, ada_id, ada, al_id, al, bea_id, bea, alpha, beta }
}

async fn world() -> World {
    serve(Routing::Off, Default::default()).await
}

async fn make_team(port: u16, admin: &str, name: &str, owner: &str) -> String {
    let (code, v) = json_call(port, "POST", "/api/teams", admin, &json!({ "name": name, "owner": owner }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    assert_eq!(v["members"][0]["role"], "owner", "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(w: &World, action: &str) -> Vec<Value> {
    let (code, body) = call(w.port, "GET", &format!("/api/audit?action={action}&limit=200"), &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(w: &World) -> Value {
    let (code, v) = json_call(w.port, "POST", "/api/machines/reconcile", &w.admin, "").await;
    assert_eq!(code, 200, "{v}");
    v
}

fn bot(w: &World, name: &str, owner: &str, v: Visibility) -> String {
    w.app.db.create_bot_owned(name, "#fff", "waddle", "claude", None, false, owner, v).id
}

async fn bot_ids(w: &World, who: &str) -> Vec<String> {
    let (code, v) = json_call(w.port, "GET", "/api/bots", who, "").await;
    assert_eq!(code, 200, "{v}");
    v.as_array().unwrap().iter().filter_map(|b| b["id"].as_str().map(String::from)).collect()
}

#[tokio::test]
async fn sharing_stops_at_the_team() {
    let w = world().await;
    let ops = bot(&w, "Ops", &w.ada_id, Visibility::Shared);
    let ledger = bot(&w, "Ledger", &w.ada_id, Visibility::Private);
    let desk = bot(&w, "Desk", &w.bea_id, Visibility::Shared);

    // Al, on Ada's team, sees and runs her shared Bot; Bea, on another, doesn't see it.
    let al_sees = bot_ids(&w, &w.al).await;
    assert!(al_sees.contains(&ops) && !al_sees.contains(&ledger) && !al_sees.contains(&desk), "{al_sees:?}");
    let bea_sees = bot_ids(&w, &w.bea).await;
    assert!(bea_sees.contains(&desk) && !bea_sees.contains(&ops) && !bea_sees.contains(&ledger), "{bea_sees:?}");

    // Every way into Ada's Bots is plain not found for Bea: its chat, its routines, its
    // screen, sending it work, stopping it, and asking it from her own Bot.
    for (m, p, b) in [
        ("GET", format!("/api/bots/{ops}/messages"), ""),
        ("GET", format!("/api/bots/{ops}/routines"), ""),
        ("GET", format!("/api/bots/{ops}/screen"), ""),
        ("GET", format!("/api/bots/{ops}/access"), ""),
        ("POST", format!("/api/bots/{ops}/messages"), r#"{"text":"leak it"}"#),
        ("POST", format!("/api/bots/{ops}/stop"), ""),
        ("PATCH", format!("/api/bots/{ops}"), r#"{"name":"Mine"}"#),
    ] {
        let (code, res) = call(w.port, m, &p, &w.bea, b).await;
        assert_eq!(code, 404, "Bea: {m} {p}: {res}");
    }
    assert!(w.app.db.messages(&ops, 10).is_empty(), "nothing reached Ops");
    assert_eq!(call(w.port, "GET", &format!("/api/bots/{ops}/messages"), &w.al, "").await.0, 200);

    // Nor can a grant carry a Bot across: Ada can't name Bea; an admin is told why.
    let (code, res) = call(w.port, "PUT", &format!("/api/bots/{ledger}/grants/{}", w.bea_id), &w.ada, r#"{"level":"operator"}"#).await;
    assert_eq!(code, 404, "{res}");
    let (code, res) = call(w.port, "PUT", &format!("/api/bots/{ledger}/grants/{}", w.bea_id), &w.admin, r#"{"level":"operator"}"#).await;
    assert_eq!(code, 409, "{res}");
    assert!(w.app.db.grant(&ledger, &w.bea_id).is_none());
    let refused = events(&w, "bot.access_refused").await;
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert!(refused.iter().all(|e| e["details"]["reason"] == "other_team" && e["outcome"] == "denied"), "{refused:?}");
    // Within the team it works as before.
    let (code, res) = call(w.port, "PUT", &format!("/api/bots/{ledger}/grants/{}", w.al_id), &w.ada, r#"{"level":"operator"}"#).await;
    assert_eq!(code, 200, "{res}");
    assert!(bot_ids(&w, &w.al).await.contains(&ledger));

    // A grant made before teams (or by hand in the database) gives nothing across them.
    w.app.db.set_grant(&ledger, &w.bea_id, crate::acl::Grant::Operator, &w.ada_id);
    assert!(!bot_ids(&w, &w.bea).await.contains(&ledger));
    assert_eq!(call(w.port, "GET", &format!("/api/bots/{ledger}/messages"), &w.bea, "").await.0, 404);

    // Harness logins on Ada's machine are only for people who can run her Bots.
    let (code, res) = call(w.port, "GET", &format!("/api/machine/teammate/{}/harness-logins", w.ada_id), &w.bea, "").await;
    assert_eq!(code, 404, "{res}");
}

#[tokio::test]
async fn a_team_admin_sees_teammates_machines_and_nothing_of_their_data() {
    let w = world().await;
    reconcile(&w).await;
    let al_machine = w.app.db.user_machine(&w.al_id).expect("joining gave Al a machine");
    assert!(w.app.db.team_machine(&al_machine.id).is_some_and(|t| t.team_id == w.alpha));

    // Ada, Alpha's owner, sees Al's machine: its state, size and placement, nothing more.
    let (code, v) = json_call(w.port, "GET", "/api/team", &w.ada, "").await;
    assert_eq!((code, v["role"].as_str(), v["name"].as_str()), (200, Some("owner"), Some("Alpha")), "{v}");
    let al = v["members"].as_array().unwrap().iter().find(|m| m["id"] == w.al_id.as_str()).unwrap().clone();
    let m = &al["machine"];
    assert_eq!((m["state"].as_str(), m["team"].as_bool(), m["assigned"].as_bool()), (Some("running"), Some(true), Some(false)), "{m}");
    let keys: Vec<&str> = m.as_object().unwrap().keys().map(String::as_str).collect();
    for hidden in ["ipv4", "ipv6", "providerId", "id", "error", "rootPassword", "lastError", "certificates"] {
        assert!(!keys.contains(&hidden), "{hidden} in {m}");
    }
    assert!(!v.to_string().contains("192.0.2."), "no address: {v}");
    // Al, a member, sees his team, with no one's machine.
    let (code, v) = json_call(w.port, "GET", "/api/team", &w.al, "").await;
    assert_eq!((code, v["role"].as_str()), (200, Some("member")), "{v}");
    assert!(v["members"].as_array().unwrap().iter().all(|m| m.get("machine").is_none()) && v.get("invites").is_none(), "{v}");

    // She suspends and resumes it.
    let path = format!("/api/team/members/{}/machine", w.al_id);
    let (code, v) = json_call(w.port, "POST", &format!("{path}/suspend"), &w.ada, "").await;
    assert_eq!((code, v["machine"]["state"].as_str()), (200, Some("suspended")), "{v}");
    let (code, v) = json_call(w.port, "POST", &format!("{path}/resume"), &w.ada, "").await;
    assert!(code == 200 || code == 202, "{code} {v}");
    let suspended = events(&w, "machine.suspended").await;
    assert_eq!(suspended[0]["actorId"], w.ada_id.as_str(), "{suspended:?}");
    assert_eq!(suspended[0]["onBehalfOf"], w.al_id.as_str(), "{suspended:?}");

    // Al's data stays out of reach: his Bots, secrets, screens, folder sync and logins
    // are behind the ACL and the server admins' routes, as before.
    let al_bot = bot(&w, "Notes", &w.al_id, Visibility::Private);
    for (m, p, b) in [
        ("GET", format!("/api/bots/{al_bot}/messages"), ""),
        ("GET", format!("/api/bots/{al_bot}/screen"), ""),
        ("POST", format!("/api/bots/{al_bot}/messages"), r#"{"text":"hi"}"#),
    ] {
        assert_eq!(call(w.port, m, &p, &w.ada, b).await.0, 404, "{m} {p}");
    }
    for (m, p) in [
        ("GET", format!("/api/users/{}/secrets", w.al_id)),
        ("GET", format!("/api/users/{}/machine", w.al_id)),
        ("GET", format!("/api/users/{}/machine/screens", w.al_id)),
        ("GET", format!("/api/users/{}/machine/harness-logins", w.al_id)),
        ("GET", format!("/api/users/{}/machine/folder-sync", w.al_id)),
        ("POST", format!("/api/users/{}/machine/rebuild", w.al_id)),
        ("DELETE", format!("/api/users/{}/machine", w.al_id)),
        ("DELETE", path.clone()),
        ("POST", format!("{path}/resize")),
        ("PUT", format!("/api/users/{}/placement", w.al_id)),
        ("GET", "/api/teams".to_string()),
        ("PUT", format!("/api/teams/{}/members/{}", w.alpha, w.bea_id)),
    ] {
        assert_eq!(call(w.port, m, &p, &w.ada, "{}").await.0, 403, "{m} {p}");
    }
    assert_eq!(call(w.port, "GET", &format!("/api/machine/teammate/{}/harness-logins", w.al_id), &w.ada, "").await.0, 404);

    // Bea, Beta's owner, can't touch Alpha's people: they aren't there for her.
    for (m, p) in [
        ("POST", format!("{path}/suspend")),
        ("POST", format!("{path}/resume")),
        ("POST", path.clone()),
        ("PATCH", format!("/api/team/members/{}", w.al_id)),
        ("DELETE", format!("/api/team/members/{}", w.al_id)),
    ] {
        let (code, res) = call(w.port, m, &p, &w.bea, r#"{"role":"admin"}"#).await;
        assert_eq!(code, 404, "{m} {p}: {res}");
    }
    // Nor can Al, a member, manage anyone's machine, his own included.
    assert_eq!(call(w.port, "POST", &format!("/api/team/members/{}/machine/suspend", w.ada_id), &w.al, "").await.0, 403);
    assert_eq!(call(w.port, "POST", &format!("{path}/suspend"), &w.al, "").await.0, 403);
    assert_eq!(w.app.db.user_machine(&w.al_id).unwrap().state, crate::machines::State::Running);

    // A machine someone has of their own is theirs, not the team's.
    let (dee_id, _) = user_with(w.port, &w.admin, "dee@example.com", "member").await;
    assert_eq!(call(w.port, "POST", &format!("/api/users/{dee_id}/machine"), &w.admin, "{}").await.0, 202);
    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{}/members/{dee_id}", w.alpha), &w.admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str(), v["machine"]["team"].as_bool()), (200, Some("own"), Some(false)), "{v}");
    let (code, res) = call(w.port, "POST", &format!("/api/team/members/{dee_id}/machine/suspend"), &w.ada, "").await;
    assert_eq!(code, 403, "{res}");
    assert!(res.contains("isn't the team's"), "{res}");
}

#[tokio::test]
async fn invites_join_people_and_give_them_a_machine_that_is_placed_once_ready() {
    let w = serve(Routing::Assigned, Default::default()).await;
    let (cy_id, cy) = user_with(w.port, &w.admin, "cy@example.com", "member").await;
    let (code, inv) = json_call(w.port, "POST", "/api/team/invites", &w.ada, r#"{"email":"CY@example.com","role":"admin"}"#).await;
    assert_eq!((code, inv["email"].as_str()), (201, Some("cy@example.com")), "{inv}");
    // Members don't invite; Beta's owner doesn't see Alpha's invites.
    assert_eq!(call(w.port, "POST", "/api/team/invites", &w.al, r#"{"email":"x@example.com"}"#).await.0, 403);
    let (_, list) = json_call(w.port, "GET", "/api/me/team-invites", &w.bea, "").await;
    assert_eq!(list, json!([]));
    let id = inv["id"].as_str().unwrap();
    assert_eq!(call(w.port, "POST", &format!("/api/me/team-invites/{id}/accept"), &w.bea, "").await.0, 404);

    let (_, list) = json_call(w.port, "GET", "/api/me/team-invites", &cy, "").await;
    assert_eq!((list[0]["team"]["name"].as_str(), list[0]["role"].as_str()), (Some("Alpha"), Some("admin")), "{list}");
    let (code, v) = json_call(w.port, "POST", &format!("/api/me/team-invites/{id}/accept"), &cy, "").await;
    assert_eq!((code, v["role"].as_str(), v["provisioned"].as_str()), (200, Some("admin"), Some("requested")), "{v}");
    assert!(w.app.db.team_invite(id).is_none());
    let joined = events(&w, "team.member_joined").await;
    assert!(joined.iter().any(|e| e["details"]["user"] == cy_id.as_str() && e["details"]["via"] == "invite"), "{joined:?}");

    // Running and enrolled, the reconciler places Cy's Bots on it with no admin step.
    reconcile(&w).await;
    let m = w.app.db.user_machine(&cy_id).unwrap();
    assert_eq!((m.state, m.assigned_at), (crate::machines::State::Running, None));
    w.app.db.machine_set_enrolled(&m.id);
    let out = reconcile(&w).await;
    assert!(out["teams"]["machinesAssigned"].as_u64().unwrap() >= 1, "{out}");
    assert!(w.app.db.user_machine(&cy_id).unwrap().assigned_at.is_some());
    let assigned = events(&w, "placement.assigned").await;
    assert!(assigned.iter().any(|e| e["details"]["reason"] == "team" && e["details"]["team"] == w.alpha.as_str()), "{assigned:?}");
    // Nothing changes on the next pass.
    assert!(reconcile(&w).await.get("teams").is_none());

    // On another team already, an invite can't move you.
    let (code, inv) = json_call(w.port, "POST", "/api/team/invites", &w.bea, r#"{"email":"cy@example.com"}"#).await;
    assert_eq!(code, 201);
    let (code, res) = call(w.port, "POST", &format!("/api/me/team-invites/{}/accept", inv["id"].as_str().unwrap()), &cy, "").await;
    assert_eq!(code, 409, "{res}");
    assert_eq!(w.app.db.team_id_of(&cy_id).as_deref(), Some(w.alpha.as_str()));
}

#[tokio::test]
async fn leaving_cuts_sharing_suspends_the_machine_and_destroys_it_later() {
    let w = world().await;
    reconcile(&w).await;
    let ops = bot(&w, "Ops", &w.ada_id, Visibility::Shared);
    let notes = bot(&w, "Notes", &w.al_id, Visibility::Private);
    let ledger = bot(&w, "Ledger", &w.ada_id, Visibility::Private);
    assert_eq!(call(w.port, "PUT", &format!("/api/bots/{notes}/grants/{}", w.ada_id), &w.al, r#"{"level":"viewer"}"#).await.0, 200);
    assert_eq!(call(w.port, "PUT", &format!("/api/bots/{ledger}/grants/{}", w.al_id), &w.ada, r#"{"level":"operator"}"#).await.0, 200);
    assert!(bot_ids(&w, &w.al).await.contains(&ops));
    let machine = w.app.db.user_machine(&w.al_id).unwrap();

    // Ada takes Al off the team.
    let (code, res) = call(w.port, "DELETE", &format!("/api/team/members/{}", w.al_id), &w.ada, "").await;
    assert_eq!(code, 200, "{res}");
    assert!(w.app.db.team_member(&w.al_id).is_none());
    let sees = bot_ids(&w, &w.al).await;
    assert!(!sees.contains(&ops) && !sees.contains(&ledger), "{sees:?}");
    assert!(!bot_ids(&w, &w.ada).await.contains(&notes));
    assert!(w.app.db.grant(&notes, &w.ada_id).is_none() && w.app.db.grant(&ledger, &w.al_id).is_none());
    let revoked = events(&w, "bot.access_revoked").await;
    assert_eq!(revoked.len(), 2, "{revoked:?}");
    assert!(revoked.iter().all(|e| e["details"]["reason"] == "left_team"), "{revoked:?}");
    let left = events(&w, "team.member_left").await;
    assert_eq!((left[0]["details"]["user"].as_str(), left[0]["details"]["reason"].as_str()), (Some(w.al_id.as_str()), Some("removed")), "{left:?}");

    // His machine is suspended, released with a date, and outside Ada's reach now.
    let m = w.app.db.machine(&machine.id).unwrap();
    assert_eq!(m.state, crate::machines::State::Suspended);
    let tm = w.app.db.team_machine(&machine.id).unwrap();
    assert!(tm.released_at.is_some() && tm.release_at.unwrap() > crate::db::now() + 6 * 86_400_000, "{:?}", tm.release_at);
    assert_eq!(call(w.port, "POST", &format!("/api/team/members/{}/machine/resume", w.al_id), &w.ada, "").await.0, 404);
    assert!(reconcile(&w).await.get("teams").is_none(), "not due yet");
    let at_provider = w.fake.machines().len();
    assert_eq!(at_provider, 3, "Ada's, Al's and Bea's");

    // Due, the reconciler destroys it at the provider.
    w.app.db.team_machine_backdate(&machine.id, 8 * 86_400_000);
    let out = reconcile(&w).await;
    assert_eq!(out["teams"]["machinesDestroyed"], 1, "{out}");
    reconcile(&w).await;
    assert_eq!(w.fake.machines().len(), at_provider - 1, "{:?}", w.fake.machines());
    let destroyed = events(&w, "team.machine_destroyed").await;
    assert_eq!(destroyed[0]["details"]["user"], w.al_id.as_str(), "{destroyed:?}");
    assert!(w.app.db.team_machine(&machine.id).is_none() || w.app.db.machine(&machine.id).is_some_and(|m| m.state == crate::machines::State::Destroyed));
}

#[tokio::test]
async fn coming_back_before_the_deadline_keeps_the_machine() {
    let w = world().await;
    reconcile(&w).await;
    let machine = w.app.db.user_machine(&w.al_id).unwrap();
    let (code, res) = call(w.port, "POST", "/api/team/leave", &w.al, "").await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(w.app.db.machine(&machine.id).unwrap().state, crate::machines::State::Suspended);

    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{}/members/{}", w.alpha, w.al_id), &w.admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str()), (200, Some("kept")), "{v}");
    assert_eq!(w.fake.calls("create"), 3, "no second machine for Al");
    let tm = w.app.db.team_machine(&machine.id).unwrap();
    assert_eq!((tm.released_at, tm.release_at), (None, None));
    assert!(matches!(w.app.db.machine(&machine.id).unwrap().state, crate::machines::State::Running | crate::machines::State::Provisioning));
    w.app.db.team_machine_backdate(&machine.id, 30 * 86_400_000);
    reconcile(&w).await;
    assert_eq!(w.fake.machines().len(), 3, "kept");
}

#[tokio::test]
async fn owners_stay_and_teams_without_machines_give_none() {
    let w = world().await;
    // Ada is Alpha's only owner: she can't leave while Al is on it, or be demoted.
    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.ada, "").await.0, 409);
    assert_eq!(call(w.port, "PUT", &format!("/api/teams/{}/members/{}", w.alpha, w.ada_id), &w.admin, r#"{"role":"member"}"#).await.0, 409);
    // An admin can't make owners, or remove one.
    w.app.db.set_team_role(&w.alpha, &w.al_id, "admin");
    assert_eq!(call(w.port, "PATCH", &format!("/api/team/members/{}", w.al_id), &w.al, r#"{"role":"owner"}"#).await.0, 403);
    assert_eq!(call(w.port, "DELETE", &format!("/api/team/members/{}", w.ada_id), &w.al, "").await.0, 403);
    // Bea alone on Beta leaves, and the team goes with her.
    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.bea, "").await.0, 200);
    assert!(w.app.db.team(&w.beta).is_none());

    // A team with machines off gives none.
    let (code, _) = json_call(w.port, "PATCH", &format!("/api/teams/{}", w.alpha), &w.admin, r#"{"machines":false}"#).await;
    assert_eq!(code, 200);
    let (dee_id, _) = user_with(w.port, &w.admin, "dee@example.com", "member").await;
    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{}/members/{dee_id}", w.alpha), &w.admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str()), (200, Some("manual")), "{v}");
    assert!(w.app.db.user_machine(&dee_id).is_none());
    // A team admin can still give one by hand.
    let (code, v) = json_call(w.port, "POST", &format!("/api/team/members/{dee_id}/machine"), &w.ada, "").await;
    assert_eq!(code, 202, "{v}");
    assert!(w.app.db.user_machine(&dee_id).is_some_and(|m| w.app.db.team_machine(&m.id).is_some_and(|t| t.team_id == w.alpha)));

    // Deleting a team takes everyone off it.
    assert_eq!(call(w.port, "DELETE", &format!("/api/teams/{}", w.alpha), &w.admin, "").await.0, 200);
    assert!(w.app.db.team(&w.alpha).is_none() && w.app.db.team_member(&w.ada_id).is_none());
}

#[tokio::test]
async fn by_default_people_in_no_team_share_as_before_and_teams_on_stops_that() {
    for strict in [false, true] {
        let w = serve(Routing::Off, crate::teams::Settings { strict, machine_days: 7 }).await;
        let (_, cy) = user_with(w.port, &w.admin, "cy@example.com", "member").await;
        let (dee_id, _) = user_with(w.port, &w.admin, "dee@example.com", "member").await;
        let open = bot(&w, "Open", &dee_id, Visibility::Shared);
        let alpha_bot = bot(&w, "Ops", &w.ada_id, Visibility::Shared);
        let cy_sees = bot_ids(&w, &cy).await;
        assert_eq!(cy_sees.contains(&open), !strict, "strict={strict}: {cy_sees:?}");
        assert!(!cy_sees.contains(&alpha_bot), "never a team's Bot");
        assert!(!bot_ids(&w, &w.ada).await.contains(&open), "nor the other way");
    }
}

#[tokio::test]
async fn bots_and_viewers_cannot_use_team_routes() {
    let (port, app, owner, key) = serve_app_with(|_| {}).await;
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let (_, ro) = user_with(port, &admin, "ro@example.com", "readonly").await;
    make_team(port, &admin, "Gamma", "ro@example.com").await;
    let b = app.db.create_bot("Ops", "#fff", "waddle", "claude", None, false).id;
    let bot = key.auth(&b);
    for (m, p) in [("GET", "/api/team"), ("POST", "/api/team/invites"), ("GET", "/api/me/team-invites")] {
        let code = call(port, m, p, &bot, r#"{"email":"x@example.com"}"#).await.0;
        assert!(code == 403 || code == 401, "Bot: {m} {p}: {code}");
    }
    assert_eq!(call(port, "GET", "/api/team", &ro, "").await.0, 200);
    for (m, p) in [("POST", "/api/team/leave"), ("POST", "/api/team/invites")] {
        assert_eq!(call(port, m, p, &ro, r#"{"email":"x@example.com"}"#).await.0, 403, "readonly: {m} {p}");
    }
}

/// A stand-in `claude` that takes `secs` to answer.
fn slow_claude(app: &App, secs: u32) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let script = format!("#!/bin/sh\nsleep {secs}\nprintf '%s\\n' '{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"done\"}}]}}}}'\n");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn with_open_shared_bots_leaving_stops_the_run_and_what_was_queued() {
    let w = world().await;
    assert_ne!(w.app.shared_bots(), crate::acl::SharedBots::Isolated, "open, as self-hosted without routing");
    slow_claude(&w.app, 30);
    let ops = bot(&w, "Ops", &w.ada_id, Visibility::Shared);
    for text in ["first", "second"] {
        let (code, res) = call(w.port, "POST", &format!("/api/bots/{ops}/messages"), &w.al, &json!({ "text": text }).to_string()).await;
        assert_eq!(code, 202, "{res}");
    }
    for _ in 0..300 {
        if w.app.live_run(&ops).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let b = w.app.db.bot(&ops).unwrap();
    assert!(w.app.live_run(&ops).is_some() && w.app.requested_by(&b) == w.al_id, "Al's run, though it acts as Ada");

    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.al, "").await.0, 200);
    for _ in 0..300 {
        if w.app.live_run(&ops).is_none() && !events(&w, "bot.run_refused").await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(w.app.live_run(&ops).is_none(), "Al's run went on after he left");
    assert!(events(&w, "harness.invoked").await.len() <= 1, "the second message never ran");
}

#[tokio::test]
async fn with_open_shared_bots_work_queued_before_leaving_does_not_run() {
    let w = world().await;
    slow_claude(&w.app, 1);
    let ops = bot(&w, "Ops", &w.ada_id, Visibility::Shared);
    // Ada's own run, with Al's message waiting behind it.
    for (who, text) in [(&w.ada, "mine"), (&w.al, "his")] {
        let (code, res) = call(w.port, "POST", &format!("/api/bots/{ops}/messages"), who, &json!({ "text": text }).to_string()).await;
        assert_eq!(code, 202, "{res}");
    }
    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.al, "").await.0, 200);
    let mut refused = Vec::new();
    for _ in 0..300 {
        refused = events(&w, "bot.run_refused").await;
        if !refused.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(refused.iter().any(|e| e["details"]["reason"] == "asker_lost_access" && e["details"]["forUser"] == w.al_id.as_str()), "{refused:?}");
    assert_eq!(events(&w, "harness.invoked").await.len(), 1, "only Ada's ran");
}

#[tokio::test]
async fn a_machine_still_being_built_is_suspended_once_ready_after_its_owner_leaves() {
    let w = world().await;
    let m = w.app.db.user_machine(&w.al_id).unwrap();
    assert_eq!(m.state, crate::machines::State::Provisioning);
    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.al, "").await.0, 200);
    let released = events(&w, "team.machine_released").await;
    assert_eq!(released[0]["details"]["suspended"], false, "{released:?}");
    reconcile(&w).await;
    reconcile(&w).await;
    assert_eq!(w.app.db.machine(&m.id).unwrap().state, crate::machines::State::Suspended);
    assert!(w.app.db.team_machine(&m.id).unwrap().release_at.is_some(), "still due to go later");
}

#[tokio::test]
async fn a_machine_taken_back_is_never_destroyed_by_an_earlier_decision() {
    let w = world().await;
    reconcile(&w).await;
    let m = w.app.db.user_machine(&w.al_id).unwrap();
    assert_eq!(call(w.port, "POST", "/api/team/leave", &w.al, "").await.0, 200);
    w.app.db.team_machine_backdate(&m.id, 8 * 86_400_000);
    // Al is back before the sweep gets to it.
    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{}/members/{}", w.alpha, w.al_id), &w.admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str()), (200, Some("kept")), "{v}");
    // A destroy decided on the old record refuses, under the machines' lock.
    let cp = w.app.control_plane.get().unwrap().clone();
    let by = crate::audit::Who::system("test");
    let still = |x: &crate::db::Machine| w.app.db.team_machine(&x.id).is_some_and(|t| t.released_at.is_some());
    let res = crate::machines::destroy_as(&w.app, &cp, &by, &w.al_id, &still).await;
    assert_eq!(res.err().map(|e| e.0), Some(StatusCode::CONFLICT));
    reconcile(&w).await;
    assert_ne!(w.app.db.machine(&m.id).unwrap().state, crate::machines::State::Destroying);
    assert_eq!(w.fake.machines().len(), 3);
}

#[tokio::test]
async fn a_team_admin_retries_a_machine_the_provider_failed_to_build() {
    let w = world().await;
    let (dee_id, _) = user_with(w.port, &w.admin, "dee@example.com", "member").await;
    w.fake.fail_next("create", crate::machines::provider::ProviderError::Api { status: 400, message: "region full on host-7".into() });
    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{}/members/{dee_id}", w.alpha), &w.admin, "{}").await;
    assert_eq!((code, v["provisioned"].as_str()), (200, Some("failed")), "{v}");
    let m = w.app.db.user_machine(&dee_id).unwrap();
    assert_eq!(m.state, crate::machines::State::Error);
    let (code, v) = json_call(w.port, "POST", &format!("/api/team/members/{dee_id}/machine"), &w.ada, "").await;
    assert!(code == 200 || code == 202, "{code} {v}");
    assert_ne!(w.app.db.user_machine(&dee_id).unwrap().state, crate::machines::State::Error);
    assert!(!v.to_string().contains("host-7"), "{v}");
}

#[tokio::test]
async fn errors_to_team_admins_keep_the_details_for_server_admins() {
    let w = world().await;
    let path = format!("/api/team/members/{}/machine/suspend", w.al_id);
    let (code, body) = call(w.port, "POST", &path, &w.ada, "").await;
    assert_eq!(code, 409, "suspending a machine still being built: {body}");
    assert!(body.contains("can't do that now") && !body.to_lowercase().contains("provisioning"), "{body}");
    let failed = events(&w, "team.machine_failed").await;
    assert!(failed.iter().any(|e| e["details"]["status"] == 409 && e["details"]["error"].as_str().is_some_and(|s| !s.is_empty())), "{failed:?}");
}

#[tokio::test]
async fn a_server_admin_cannot_remove_a_teams_only_owner() {
    let w = world().await;
    let (code, res) = call(w.port, "DELETE", &format!("/api/teams/{}/members/{}", w.alpha, w.ada_id), &w.admin, "").await;
    assert_eq!(code, 409, "{res}");
    assert_eq!(call(w.port, "DELETE", &format!("/api/teams/{}/members/{}", w.alpha, w.al_id), &w.admin, "").await.0, 200);
    // Now alone, she can be removed, and the empty team goes.
    assert_eq!(call(w.port, "DELETE", &format!("/api/teams/{}/members/{}", w.alpha, w.ada_id), &w.admin, "").await.0, 200);
    assert!(w.app.db.team(&w.alpha).is_none());
}
