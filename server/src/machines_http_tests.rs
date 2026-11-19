//! HTTP tests for the control plane (ADR 0025), on the real router, with the
//! in-memory provider. Nothing here talks to Linode.

use crate::machines::fake::Fake;
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::{ControlPlane, NOT_CONFIGURED, State};
use crate::tests::{audit_list, call, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

/// The real router with the fake provider. Returns the port, the app, an SSO-less admin
/// signed in with a code (so audit events carry a real person), the Bots' token, and
/// the fake.
async fn serve() -> (u16, AppState, String, String, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, owner, key) =
        serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await;
    let bot = key.auth(&app.db.create_bot("Ops", "#fff", "waddle", "claude", None, false).id);
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    (port, app, admin, bot, fake)
}

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(
        port,
        "GET",
        &format!("/api/audit?action={action}&limit=200"),
        admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(port: u16, admin: &str) -> Value {
    let (code, v) = json_call(port, "POST", "/api/machines/reconcile", admin, "").await;
    assert_eq!(code, 200, "{v}");
    v
}

/// Every admin route, for user `u`.
fn admin_routes(u: &str) -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("GET", "/api/machines".into(), ""),
        ("POST", "/api/machines/reconcile".into(), ""),
        ("GET", format!("/api/users/{u}/machine"), ""),
        ("POST", format!("/api/users/{u}/machine"), "{}"),
        ("POST", format!("/api/users/{u}/machine/suspend"), ""),
        ("POST", format!("/api/users/{u}/machine/resume"), ""),
        (
            "POST",
            format!("/api/users/{u}/machine/resize"),
            r#"{"tier":"pro"}"#,
        ),
        ("DELETE", format!("/api/users/{u}/machine"), ""),
    ]
}

#[tokio::test]
async fn off_by_default_with_a_clear_error() {
    let (port, app, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    for (m, p, b) in
        admin_routes("operator")
            .into_iter()
            .chain([("GET", "/api/machine".to_string(), "")])
    {
        let who = if p == "/api/machine" { &member } else { &admin };
        let (code, v) = json_call(port, m, &p, who, b).await;
        assert_eq!(
            (code, v["error"].as_str()),
            (503, Some(NOT_CONFIGURED)),
            "{m} {p}"
        );
        assert_eq!(
            call(port, m, &p, "", b).await.0,
            401,
            "still needs sign-in: {m} {p}"
        );
    }
    assert!(app.db.machines(None).is_empty());
    assert!(events(port, &admin, "machine.*").await.is_empty());
}

#[tokio::test]
async fn only_admins_manage_machines() {
    let (port, app, admin, bot, fake) = serve().await;
    let (member_id, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    assert_eq!(
        json_call(
            port,
            "POST",
            &format!("/api/users/{member_id}/machine"),
            &admin,
            ""
        )
        .await
        .0,
        202
    );
    for who in [member.as_str(), readonly.as_str(), bot.as_str()] {
        for (m, p, b) in admin_routes(&member_id) {
            assert_eq!(call(port, m, &p, who, b).await.0, 403, "{m} {p}");
        }
    }
    for (m, p, b) in admin_routes(&member_id) {
        assert_eq!(call(port, m, &p, "", b).await.0, 401, "{m} {p}");
    }
    assert_eq!(
        (
            fake.calls("create"),
            fake.calls("shutdown"),
            fake.calls("delete"),
            fake.calls("resize")
        ),
        (1, 0, 0, 0),
        "nothing reached the provider"
    );
    assert_eq!(
        app.db.user_machine(&member_id).unwrap().state,
        State::Provisioning
    );
    let denied = events(port, &admin, "access.denied").await;
    assert!(
        denied.iter().any(|e| e["actorEmail"] == "m@example.com"
            && e["details"]["path"] == format!("/api/users/{member_id}/machine/suspend")),
        "refusals are on the record"
    );
}

#[tokio::test]
async fn provisioning_is_idempotent_and_reconciled() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let path = "/api/users/ada@example.com/machine";
    assert_eq!(
        json_call(port, "POST", path, &admin, r#"{"tier":"huge"}"#)
            .await
            .0,
        400
    );
    assert_eq!(
        json_call(port, "POST", path, &admin, r#"{"region":"us-east"}"#)
            .await
            .0,
        400,
        "only allowed regions"
    );
    assert_eq!(
        json_call(port, "POST", path, &admin, r#"{"size":"big"}"#)
            .await
            .0,
        400,
        "unknown fields"
    );
    assert_eq!(
        json_call(
            port,
            "POST",
            "/api/users/nobody@example.com/machine",
            &admin,
            ""
        )
        .await
        .0,
        404
    );
    assert_eq!(
        json_call(port, "GET", path, &admin, "").await.0,
        404,
        "none yet"
    );

    let (code, m) = json_call(
        port,
        "POST",
        path,
        &admin,
        r#"{"tier":"pro","region":"de-fra-2"}"#,
    )
    .await;
    assert_eq!(code, 202, "{m}");
    let id = m["id"].as_str().unwrap().to_string();
    assert_eq!(
        (
            m["state"].as_str(),
            m["tier"].as_str(),
            m["plan"].as_str(),
            m["region"].as_str()
        ),
        (
            Some("provisioning"),
            Some("pro"),
            Some("g6-standard-2"),
            Some("de-fra-2")
        )
    );
    assert_eq!(
        (
            m["userId"].as_str(),
            m["userEmail"].as_str(),
            m["label"].as_str()
        ),
        (
            Some(uid.as_str()),
            Some("ada@example.com"),
            Some(format!("superbot-{id}").as_str())
        )
    );
    let at = fake.machines();
    assert_eq!(at.len(), 1);
    assert_eq!(
        (
            m["providerId"].as_str(),
            at[0].plan.as_str(),
            at[0].region.as_str()
        ),
        (Some(at[0].id.as_str()), "g6-standard-2", "de-fra-2")
    );
    assert_eq!(
        at[0].tags,
        ["superbot".to_string(), format!("superbot-user-{uid}")]
    );

    // Asking again is safe: same machine, nothing new at the provider.
    for body in ["", "{}", r#"{"tier":"pro"}"#] {
        let (code, again) = json_call(port, "POST", path, &admin, body).await;
        assert_eq!(
            (code, again["id"].as_str()),
            (200, Some(id.as_str())),
            "{body}"
        );
    }
    let (code, v) = json_call(port, "POST", path, &admin, r#"{"tier":"starter"}"#).await;
    assert_eq!(code, 409, "a different tier is a resize: {v}");
    assert_eq!((fake.calls("create"), app.db.machines(None).len()), (1, 1));

    assert_eq!(
        reconcile(port, &admin).await,
        json!({ "checked": 1, "changed": 1 })
    );
    let (_, m) = json_call(port, "GET", path, &admin, "").await;
    assert_eq!(
        (
            m["state"].as_str(),
            m["providerStatus"].as_str(),
            m["backups"].as_bool()
        ),
        (Some("running"), Some("running"), Some(true)),
        "{m}"
    );
    assert!(m["ipv4"].as_str().unwrap().starts_with("192.0.2."));
    assert_eq!(
        reconcile(port, &admin).await,
        json!({ "checked": 1, "changed": 0 }),
        "settled"
    );
    assert_eq!(fake.calls("enable_backups"), 1);

    let (_, all) = json_call(port, "GET", "/api/machines", &admin, "").await;
    assert_eq!(all.as_array().unwrap().len(), 1);
    assert_eq!(
        json_call(port, "GET", "/api/machines?state=running", &admin, "")
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json_call(port, "GET", "/api/machines?state=lost", &admin, "")
            .await
            .0,
        400
    );

    // The admin who asked is on the record as themselves; the reconciler acts for the user.
    let ev = events(port, &admin, "machine.*").await;
    let actions: Vec<&str> = ev
        .iter()
        .rev()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        [
            "machine.requested",
            "machine.created",
            "machine.running",
            "machine.backups_enabled"
        ]
    );
    for e in &ev {
        assert_eq!(
            (
                e["targetType"].as_str(),
                e["targetId"].as_str(),
                e["details"]["userId"].as_str()
            ),
            (Some("machine"), Some(id.as_str()), Some(uid.as_str())),
            "{e}"
        );
    }
    let requested = ev
        .iter()
        .find(|e| e["action"] == "machine.requested")
        .unwrap();
    assert_eq!(
        (
            requested["actorEmail"].as_str(),
            requested["actorRole"].as_str(),
            requested["details"]["tier"].as_str()
        ),
        (Some("ops@example.com"), Some("admin"), Some("pro"))
    );
    let running = ev
        .iter()
        .find(|e| e["action"] == "machine.running")
        .unwrap();
    assert_eq!(
        (
            running["actorKind"].as_str(),
            running["actorId"].as_str(),
            running["onBehalfOf"].as_str()
        ),
        (Some("system"), Some("control_plane"), Some(uid.as_str())),
        "{running}"
    );
}

#[tokio::test]
async fn suspend_resume_resize_and_destroy() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");
    let act = |a: &str| format!("{base}/{a}");
    assert_eq!(
        json_call(port, "POST", &act("suspend"), &admin, "").await.0,
        404,
        "no machine yet"
    );
    assert_eq!(json_call(port, "POST", &base, &admin, "").await.0, 202);
    let (code, v) = json_call(port, "POST", &act("suspend"), &admin, "").await;
    assert_eq!(
        (code, v["error"].as_str()),
        (409, Some("Can't suspend a machine that is provisioning."))
    );
    reconcile(port, &admin).await;
    let pid = app.db.user_machine(&uid).unwrap().provider_id.unwrap();
    let status = || {
        fake.machines()
            .into_iter()
            .find(|m| m.id == pid)
            .map(|m| (m.status, m.plan))
    };

    let (code, m) = json_call(port, "POST", &act("suspend"), &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (200, Some("suspended")), "{m}");
    assert_eq!(status().unwrap().0, "offline");
    assert_eq!(
        json_call(port, "POST", &act("suspend"), &admin, "").await.0,
        200,
        "again: nothing to do"
    );
    assert_eq!(fake.calls("shutdown"), 1);
    assert_eq!(
        json_call(port, "POST", &act("resize"), &admin, r#"{"tier":"max"}"#)
            .await
            .1["plan"]
            .as_str(),
        Some("g6-standard-4"),
        "a suspended machine can be resized"
    );
    assert_eq!(status().unwrap().1, "g6-standard-4");

    let (code, m) = json_call(port, "POST", &act("resume"), &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (200, Some("running")));
    assert_eq!(
        json_call(port, "POST", &act("resume"), &admin, "").await.0,
        200
    );
    assert_eq!(fake.calls("boot"), 1);
    reconcile(port, &admin).await;
    assert_eq!(status().unwrap().0, "running");

    assert_eq!(
        json_call(port, "POST", &act("resize"), &admin, "").await.0,
        400
    );
    assert_eq!(
        json_call(port, "POST", &act("resize"), &admin, r#"{"tier":"huge"}"#)
            .await
            .0,
        400
    );
    let (code, m) = json_call(port, "POST", &act("resize"), &admin, r#"{"tier":"pro"}"#).await;
    assert_eq!(
        (
            code,
            m["tier"].as_str(),
            m["plan"].as_str(),
            m["state"].as_str()
        ),
        (200, Some("pro"), Some("g6-standard-2"), Some("running"))
    );
    assert_eq!(
        json_call(port, "POST", &act("resize"), &admin, r#"{"tier":"pro"}"#)
            .await
            .0,
        200
    );
    assert_eq!(fake.calls("resize"), 2);

    let (code, m) = json_call(port, "DELETE", &base, &admin, "").await;
    assert_eq!(
        (code, m["state"].as_str(), m["ipv4"].is_null()),
        (200, Some("destroyed"), true),
        "{m}"
    );
    assert!(m["destroyedAt"].as_i64().is_some());
    assert!(fake.machines().is_empty(), "deleted at the provider");
    assert_eq!(json_call(port, "GET", &base, &admin, "").await.0, 404);
    assert_eq!(json_call(port, "DELETE", &base, &admin, "").await.0, 404);
    assert_eq!(
        json_call(port, "POST", &act("resume"), &admin, "").await.0,
        404
    );

    // Destroyed machines stay as history; the user can have a new one.
    let (code, m) = json_call(port, "POST", &base, &admin, "").await;
    assert_eq!(code, 202);
    assert_ne!(m["id"].as_str(), Some(pid.as_str()));
    assert_eq!(
        json_call(port, "GET", "/api/machines?state=destroyed", &admin, "")
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(app.db.machines(None).len(), 2);

    let ev = events(port, &admin, "machine.*").await;
    let mut actions: Vec<&str> = ev.iter().map(|e| e["action"].as_str().unwrap()).collect();
    actions.dedup();
    for a in [
        "machine.suspended",
        "machine.resumed",
        "machine.resized",
        "machine.destroy_requested",
        "machine.destroyed",
    ] {
        assert!(actions.contains(&a), "{a}: {actions:?}");
    }
    assert_eq!(
        ev.iter()
            .filter(|e| e["action"] == "machine.resized")
            .count(),
        2,
        "a repeat records nothing"
    );
    let resized = ev
        .iter()
        .find(|e| e["action"] == "machine.resized")
        .unwrap();
    assert_eq!(
        (
            resized["details"]["fromTier"].as_str(),
            resized["details"]["toTier"].as_str(),
            resized["actorEmail"].as_str()
        ),
        (Some("max"), Some("pro"), Some("ops@example.com"))
    );
}

#[tokio::test]
async fn users_see_only_their_own_machine() {
    let (port, app, admin, bot, _) = serve().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (_, b) = user_with(port, &admin, "b@example.com", "member").await;
    let (_, r) = user_with(port, &admin, "r@example.com", "readonly").await;
    assert_eq!(
        json_call(
            port,
            "POST",
            &format!("/api/users/{a_id}/machine"),
            &admin,
            ""
        )
        .await
        .0,
        202
    );

    let (code, mine) = json_call(port, "GET", "/api/machine", &a, "").await;
    assert_eq!(
        (code, mine["state"].as_str(), mine["tier"].as_str()),
        (200, Some("provisioning"), Some("starter")),
        "{mine}"
    );
    for hidden in [
        "userId",
        "userEmail",
        "providerId",
        "label",
        "createdBy",
        "lastError",
    ] {
        assert!(mine.get(hidden).is_none(), "{hidden}");
    }
    for who in [&b, &r] {
        let (code, v) = json_call(port, "GET", "/api/machine", who, "").await;
        assert_eq!(
            (code, v["error"].as_str()),
            (404, Some("You don't have a machine yet."))
        );
        assert_eq!(
            json_call(port, "GET", &format!("/api/users/{a_id}/machine"), who, "")
                .await
                .0,
            403
        );
        assert_eq!(
            json_call(port, "GET", "/api/users/a@example.com/machine", who, "")
                .await
                .0,
            403
        );
        assert_eq!(
            json_call(port, "GET", "/api/machines", who, "").await.0,
            403
        );
    }
    assert_eq!(
        json_call(port, "GET", "/api/machine", &bot, "").await.0,
        403,
        "Bots have no machine of their own"
    );
    assert_eq!(
        json_call(port, "GET", "/api/machine", &admin, "").await.0,
        404,
        "admins too see only their own here"
    );
    assert_eq!(
        json_call(port, "GET", "/api/machine?user=a@example.com", &b, "")
            .await
            .0,
        404,
        "no way to name someone else"
    );
    assert_eq!(app.db.machines(None).len(), 1);
}

#[tokio::test]
async fn lost_answers_are_adopted_and_failures_recover() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");

    // A create that reached the provider but whose answer was lost: the next try finds
    // the machine by its label instead of making a second.
    fake.fail_next(
        "create",
        ProviderError::Transport("connection reset".into()),
    );
    let (code, m) = json_call(port, "POST", &base, &admin, "").await;
    assert_eq!(
        (code, m["state"].as_str()),
        (202, Some("pending")),
        "a transient failure is retried: {m}"
    );
    assert!(
        m["lastError"]
            .as_str()
            .unwrap()
            .contains("connection reset")
    );
    let orphan = fake.insert(
        m["label"].as_str().unwrap(),
        "g6-standard-1",
        "gb-lon",
        &["superbot"],
    );
    assert_eq!(reconcile(port, &admin).await["changed"], 1);
    let saved = app.db.user_machine(&uid).unwrap();
    assert_eq!(
        (
            saved.state,
            saved.provider_id.as_deref(),
            saved.last_error.as_deref()
        ),
        (State::Provisioning, Some(orphan.as_str()), None)
    );
    assert_eq!(fake.machines().len(), 1, "adopted, not doubled");
    let created = events(port, &admin, "machine.created").await;
    assert_eq!(
        (
            created[0]["details"]["adopted"].as_bool(),
            created[0]["actorId"].as_str()
        ),
        (Some(true), Some("control_plane"))
    );
    let failed = events(port, &admin, "machine.create_failed").await;
    assert_eq!(
        (
            failed[0]["outcome"].as_str(),
            failed[0]["details"]["retrying"].as_bool()
        ),
        (Some("failure"), Some(true))
    );

    // Gone at the provider: an error for an admin, then a fresh try.
    reconcile(port, &admin).await;
    fake.remove(&orphan);
    reconcile(port, &admin).await;
    let (_, m) = json_call(port, "GET", &base, &admin, "").await;
    assert_eq!(
        (m["state"].as_str(), m["lastError"].as_str()),
        (Some("error"), Some("The machine is gone at the provider."))
    );
    assert_eq!(
        events(port, &admin, "machine.lost").await[0]["outcome"].as_str(),
        Some("failure")
    );
    assert_eq!(
        json_call(port, "POST", &format!("{base}/suspend"), &admin, "")
            .await
            .0,
        409
    );
    assert_eq!(
        reconcile(port, &admin).await["checked"],
        0,
        "errors wait for an admin"
    );

    // A refusal is an error straight away; asking again retries.
    fake.fail_next(
        "create",
        ProviderError::Api {
            status: 400,
            message: "type: not a plan".into(),
        },
    );
    let (code, v) = json_call(port, "POST", &base, &admin, "").await;
    assert_eq!(
        (code, v["machine"]["state"].as_str()),
        (502, Some("error")),
        "{v}"
    );
    assert!(v["error"].as_str().unwrap().contains("not a plan"));
    let (code, m) = json_call(port, "POST", &base, &admin, r#"{"tier":"pro"}"#).await;
    assert_eq!(
        (
            code,
            m["state"].as_str(),
            m["tier"].as_str(),
            m["lastError"].is_null()
        ),
        (202, Some("provisioning"), Some("pro"), true),
        "{m}"
    );
    assert_eq!(events(port, &admin, "machine.retried").await.len(), 2);

    // A delete the provider didn't take stays destroying until it does.
    reconcile(port, &admin).await;
    fake.fail_next("delete", ProviderError::RateLimited);
    let (code, m) = json_call(port, "DELETE", &base, &admin, "").await;
    assert_eq!(
        (code, m["state"].as_str()),
        (202, Some("destroying")),
        "{m}"
    );
    assert_eq!(
        json_call(port, "POST", &base, &admin, "").await.0,
        409,
        "no new machine while one is going"
    );
    assert_eq!(fake.machines().len(), 1);
    reconcile(port, &admin).await;
    assert!(fake.machines().is_empty());
    assert!(app.db.user_machine(&uid).is_none());
    assert_eq!(
        events(port, &admin, "machine.destroy_failed").await.len(),
        1
    );

    // A provider error on an action changes nothing and is on the record.
    assert_eq!(json_call(port, "POST", &base, &admin, "").await.0, 202);
    reconcile(port, &admin).await;
    fake.fail_next(
        "shutdown",
        ProviderError::Api {
            status: 400,
            message: "Linode busy.".into(),
        },
    );
    let (code, v) = json_call(port, "POST", &format!("{base}/suspend"), &admin, "").await;
    assert_eq!(
        (code, v["machine"]["state"].as_str()),
        (502, Some("running"))
    );
    let ev = events(port, &admin, "machine.suspended").await;
    assert_eq!(
        (
            ev[0]["outcome"].as_str(),
            ev[0]["details"]["error"].as_str()
        ),
        (
            Some("failure"),
            Some("the provider refused (400): Linode busy.")
        )
    );
}

#[tokio::test]
async fn disabled_users_get_no_machine() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "gone@example.com", "member").await;
    assert_eq!(
        call(
            port,
            "PATCH",
            &format!("/api/users/{uid}"),
            &admin,
            r#"{"status":"disabled"}"#
        )
        .await
        .0,
        200
    );
    let (code, v) = json_call(
        port,
        "POST",
        &format!("/api/users/{uid}/machine"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 409, "{v}");
    assert_eq!((fake.calls("create"), app.db.machines(None).len()), (0, 0));
}

#[tokio::test]
async fn power_and_size_follow_the_provider() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");
    let act = |a: &str| format!("{base}/{a}");
    assert_eq!(json_call(port, "POST", &base, &admin, "").await.0, 202);
    reconcile(port, &admin).await;
    let pid = app.db.user_machine(&uid).unwrap().provider_id.unwrap();

    // A shutdown the provider took but whose answer was lost: still "running" here.
    fake.set(&pid, |m| m.status = "offline".into());
    let (code, m) = json_call(port, "POST", &act("resume"), &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (200, Some("running")), "{m}");
    assert_eq!(fake.calls("boot"), 1, "booted, not taken as done");

    // And the reverse: off at the provider already, so suspending only records it.
    fake.set(&pid, |m| m.status = "offline".into());
    let (code, m) = json_call(port, "POST", &act("suspend"), &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (200, Some("suspended")));
    assert_eq!(fake.calls("shutdown"), 0);
    let ev = events(port, &admin, "machine.suspended").await;
    assert_eq!(ev[0]["details"]["providerCall"].as_bool(), Some(false));

    // Booted at the provider while suspended here: suspending again powers it off.
    fake.set(&pid, |m| m.status = "running".into());
    let (code, m) = json_call(port, "POST", &act("suspend"), &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (200, Some("suspended")));
    assert_eq!(fake.calls("shutdown"), 1);

    // A tier whose plan changed in MACHINE_TIERS is resized to the new plan.
    let mut saved = app.db.user_machine(&uid).unwrap();
    saved.plan = "g6-standard-old".into();
    assert!(app.db.save_machine(&saved, State::Suspended));
    let (code, m) = json_call(
        port,
        "POST",
        &act("resize"),
        &admin,
        r#"{"tier":"starter"}"#,
    )
    .await;
    assert_eq!(
        (code, m["plan"].as_str()),
        (200, Some("g6-standard-1")),
        "{m}"
    );
    assert_eq!(
        fake.calls("resize"),
        0,
        "the provider had that plan already"
    );
    fake.set(&pid, |m| m.plan = "g6-standard-old".into());
    let mut saved = app.db.user_machine(&uid).unwrap();
    saved.plan = "g6-standard-old".into();
    assert!(app.db.save_machine(&saved, State::Suspended));
    json_call(
        port,
        "POST",
        &act("resize"),
        &admin,
        r#"{"tier":"starter"}"#,
    )
    .await;
    assert_eq!(fake.calls("resize"), 1);
    assert_eq!(
        fake.machines()[0].plan,
        "g6-standard-1",
        "moved to the new plan"
    );
}

#[tokio::test]
async fn outages_retry_and_late_creates_are_deleted() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");

    // A 503 from the provider is an outage, not a refusal: it stays pending.
    fake.fail_next(
        "create",
        ProviderError::Api {
            status: 503,
            message: "Service unavailable".into(),
        },
    );
    let (code, m) = json_call(port, "POST", &base, &admin, "").await;
    assert_eq!((code, m["state"].as_str()), (202, Some("pending")), "{m}");
    // So does an outage while looking for the machine a lost create made.
    let label = m["label"].as_str().unwrap().to_string();
    let orphan = fake.insert(&label, "g6-standard-1", "gb-lon", &["superbot"]);
    fake.fail_next(
        "list",
        ProviderError::Api {
            status: 502,
            message: "Bad gateway".into(),
        },
    );
    reconcile(port, &admin).await;
    assert_eq!(app.db.user_machine(&uid).unwrap().state, State::Pending);
    reconcile(port, &admin).await;
    let saved = app.db.user_machine(&uid).unwrap();
    assert_eq!(
        (saved.state, saved.provider_id.as_deref()),
        (State::Provisioning, Some(orphan.as_str()))
    );
    assert_eq!(json_call(port, "DELETE", &base, &admin, "").await.0, 200);

    // A create left unanswered, then deleted before the machine shows up: it stays
    // destroying, and the late machine is deleted when it does.
    fake.fail_next("create", ProviderError::Transport("timed out".into()));
    let (_, m) = json_call(port, "POST", &base, &admin, "").await;
    let label = m["label"].as_str().unwrap().to_string();
    let (code, m) = json_call(port, "DELETE", &base, &admin, "").await;
    assert_eq!(
        (code, m["state"].as_str()),
        (202, Some("destroying")),
        "{m}"
    );
    assert!(m["lastError"].as_str().unwrap().contains("didn't answer"));
    let late = fake.insert(&label, "g6-standard-1", "gb-lon", &["superbot"]);
    reconcile(port, &admin).await;
    assert!(fake.machines().iter().all(|x| x.id != late), "deleted");
    assert!(app.db.user_machine(&uid).is_none());

    // Once it has had time to show up and hasn't, the row is done.
    fake.fail_next("create", ProviderError::Transport("timed out".into()));
    json_call(port, "POST", &base, &admin, "").await;
    assert_eq!(json_call(port, "DELETE", &base, &admin, "").await.0, 202);
    let mut saved = app.db.user_machine(&uid).unwrap();
    saved.create_sent_at = Some(crate::db::now() - crate::machines::CREATE_SETTLE_MS - 1);
    assert!(app.db.save_machine(&saved, State::Destroying));
    reconcile(port, &admin).await;
    assert!(app.db.user_machine(&uid).is_none());

    // A refusal made nothing, so its row needn't wait.
    fake.fail_next(
        "create",
        ProviderError::Api {
            status: 400,
            message: "region: not here".into(),
        },
    );
    assert_eq!(json_call(port, "POST", &base, &admin, "").await.0, 502);
    assert_eq!(json_call(port, "DELETE", &base, &admin, "").await.0, 200);
}

#[tokio::test]
async fn machines_are_found_by_their_own_tag() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    // Saved under an older MACHINE_LABEL_PREFIX, before a create whose answer was lost.
    let m = app
        .db
        .add_machine(&crate::db::NewMachine {
            user_id: &uid,
            provider: "fake",
            label_prefix: "oldbot",
            tier: "starter",
            plan: "g6-standard-1",
            region: "gb-lon",
            created_by: None,
        })
        .unwrap();
    assert_eq!(m.tag, "oldbot");
    let orphan = fake.insert(&m.label, "g6-standard-1", "gb-lon", &["oldbot"]);
    reconcile(port, &admin).await;
    let saved = app.db.user_machine(&uid).unwrap();
    assert_eq!(
        saved.provider_id.as_deref(),
        Some(orphan.as_str()),
        "adopted"
    );
    assert_eq!(fake.machines().len(), 1);

    // And deleted by it too, when the provider id was never saved.
    let mut saved = saved;
    saved.provider_id = None;
    assert!(app.db.save_machine(&saved, State::Provisioning));
    let (code, v) = json_call(
        port,
        "DELETE",
        &format!("/api/users/{uid}/machine"),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{v}");
    assert!(fake.machines().is_empty(), "not left running and billed");
}

#[tokio::test]
async fn retries_keep_a_machine_that_exists() {
    let (port, app, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");

    // A create that went through with its answer lost, then a refusal (say, a revoked
    // token): an error row with a machine at the provider.
    fake.fail_next("create", ProviderError::Transport("timed out".into()));
    let (_, m) = json_call(port, "POST", &base, &admin, "").await;
    let orphan = fake.insert(
        m["label"].as_str().unwrap(),
        "g6-standard-2",
        "gb-lon",
        &["superbot"],
    );
    fake.fail_next(
        "create",
        ProviderError::Api {
            status: 401,
            message: "Invalid Token".into(),
        },
    );
    reconcile(port, &admin).await;
    assert_eq!(app.db.user_machine(&uid).unwrap().state, State::Error);

    // Can't tell yet: nothing changes.
    fake.fail_next(
        "list",
        ProviderError::Api {
            status: 401,
            message: "Invalid Token".into(),
        },
    );
    let (code, v) = json_call(port, "POST", &base, &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!(
        (code, v["machine"]["state"].as_str()),
        (502, Some("error")),
        "{v}"
    );
    // It's there: a new region or tier is refused rather than reported falsely.
    let (code, v) = json_call(port, "POST", &base, &admin, r#"{"region":"de-fra-2"}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("gb-lon"), "{v}");
    assert_eq!(
        app.db.user_machine(&uid).unwrap().region,
        "gb-lon",
        "unchanged"
    );

    // A plain retry adopts it, recorded as it really is.
    let (code, m) = json_call(port, "POST", &base, &admin, "").await;
    assert_eq!(
        (
            code,
            m["state"].as_str(),
            m["providerId"].as_str(),
            m["tier"].as_str(),
            m["plan"].as_str(),
            m["region"].as_str()
        ),
        (
            202,
            Some("provisioning"),
            Some(orphan.as_str()),
            Some("pro"),
            Some("g6-standard-2"),
            Some("gb-lon")
        ),
        "{m}"
    );
    assert_eq!(fake.machines().len(), 1);
}

#[tokio::test]
async fn a_plain_retry_keeps_the_saved_settings() {
    let (port, _, admin, _, fake) = serve().await;
    let (uid, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let base = format!("/api/users/{uid}/machine");
    fake.fail_next(
        "create",
        ProviderError::Api {
            status: 400,
            message: "region: try later".into(),
        },
    );
    let (code, _) = json_call(
        port,
        "POST",
        &base,
        &admin,
        r#"{"tier":"pro","region":"de-fra-2"}"#,
    )
    .await;
    assert_eq!(code, 502);
    let (code, m) = json_call(port, "POST", &base, &admin, "{}").await;
    assert_eq!(
        (
            code,
            m["tier"].as_str(),
            m["plan"].as_str(),
            m["region"].as_str()
        ),
        (202, Some("pro"), Some("g6-standard-2"), Some("de-fra-2")),
        "not the defaults: {m}"
    );
    assert_eq!(
        (
            fake.machines()[0].plan.as_str(),
            fake.machines()[0].region.as_str()
        ),
        ("g6-standard-2", "de-fra-2")
    );
}
