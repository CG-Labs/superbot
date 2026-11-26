//! A disabled user's routines (SCIM-05, ADR 0047), on the real router: disabling pauses
//! them, nothing fires or runs for a disabled owner or author, they come back only when
//! an admin asks (or ROUTINES_ON_ENABLE=resume), and an admin can hand them over.

use crate::acl::Visibility;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn events(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

fn bot(app: &App, name: &str, owner: &str) -> db::Bot {
    app.db.create_bot_owned(name, "#fff", "waddle", "claude", None, false, owner, Visibility::Shared)
}

/// A routine `who` writes on `bot` through the API.
async fn routine(port: u16, who: &str, bot: &str, name: &str) -> String {
    let body = json!({ "name": name, "cron": "0 9 * * *", "instruction": "report" }).to_string();
    let (code, r) = call(port, "POST", &format!("/api/bots/{bot}/routines"), who, &body).await;
    assert_eq!(code, 201, "{r}");
    parse(&r)["id"].as_str().unwrap().to_string()
}

async fn set_status(port: u16, admin: &str, user: &str, status: &str) {
    let (code, r) = call(port, "PATCH", &format!("/api/users/{user}"), admin, &json!({ "status": status }).to_string()).await;
    assert_eq!(code, 200, "{r}");
}

async fn done(app: &App, id: i64) {
    for _ in 0..300 {
        if app.db.message(id).and_then(|m| m.status).as_deref() == Some("done") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("message {id} never finished");
}

#[tokio::test]
async fn a_disabled_users_routines_are_paused_and_never_fire() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (_, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let bea = app.db.find_user("bea@example.com").unwrap().id;
    let adas = bot(&app, "Ada's", &ada);
    let beas = bot(&app, "Bea's", &bea);
    let own = routine(port, &a, &adas.id, "Own").await;
    let off = routine(port, &a, &adas.id, "Off").await;
    assert_eq!(call(port, "PATCH", &format!("/api/routines/{off}"), &a, r#"{"enabled":false}"#).await.0, 200);
    let written = routine(port, &a, &beas.id, "Written").await;
    let theirs = routine(port, &b, &beas.id, "Theirs").await;

    set_status(port, &admin, &ada, "disabled").await;
    let r = |id: &str| app.db.routine(id).unwrap();
    assert!(!r(&own).enabled && r(&own).paused_reason.as_deref() == Some("owner_disabled") && r(&own).paused_for.as_deref() == Some(ada.as_str()));
    assert!(!r(&written).enabled && r(&written).paused_reason.as_deref() == Some("author_disabled"), "a routine Ada wrote on Bea's Bot runs for Ada");
    assert!(!r(&off).enabled && r(&off).paused_reason.is_none(), "already off by hand: not botd's to resume");
    assert!(r(&theirs).enabled, "Bea's own routine is untouched");
    let paused = events(port, &admin, "action=routine.paused").await;
    assert_eq!(paused.len(), 2, "{paused:?}");
    assert!(paused.iter().all(|e| e["details"]["forUser"] == ada.as_str() && e["actorId"] == "operator"), "{paused:?}");
    assert_eq!(events(port, &admin, "action=user.disabled").await[0]["details"]["routinesPaused"], 2);
    let (_, listed) = call(port, "GET", &format!("/api/users/{ada}/routines"), &admin, "").await;
    assert_eq!(parse(&listed)["routines"].as_array().unwrap().len(), 3, "{listed}");

    // A routine still on (say, from a database edit) is refused when it fires, and paused.
    let sneaky = app.db.add_routine(&adas.id, "Sneaky", "* * * * *", "x");
    let before = app.db.last_id();
    cron::fire(&app, &sneaky, db::now());
    assert_eq!(app.db.last_id(), before, "nothing queued");
    let refused = events(port, &admin, "action=routine.run_refused").await;
    assert!(refused.iter().any(|e| e["targetId"] == sneaky.id.as_str() && e["details"]["reason"] == "owner_disabled" && e["outcome"] == "denied"), "{refused:?}");
    assert_eq!(r(&sneaky.id).paused_reason.as_deref(), Some("owner_disabled"));
    assert!(events(port, &admin, "action=routine.fired").await.is_empty());
    // As is one Ada wrote on Bea's Bot.
    let stale = app.db.add_routine_by(&beas.id, "Stale", "* * * * *", "x", true, Some(&ada));
    cron::fire(&app, &stale, db::now());
    assert_eq!(app.db.last_id(), before);
    assert_eq!(r(&stale.id).paused_reason.as_deref(), Some("author_disabled"));

    // A routine message queued before she was disabled doesn't run either.
    let by = audit::Who { actor: audit::Actor { asker: Some(ada.clone()), ..audit::Actor::system("scheduler").on_behalf_of(&bea) }, source: Default::default() };
    let msg = app.db.add_message(&beas.id, "routine", "Written: report", None, false, Some("queued"));
    app.db.set_requested_by(msg.id, &by);
    app.enqueue(app.db.message(msg.id).unwrap());
    done(&app, msg.id).await;
    let refused = events(port, &admin, "action=bot.run_refused").await;
    assert!(refused.iter().any(|e| e["details"]["reason"] == "author_disabled" && e["details"]["forUser"] == ada.as_str()), "{refused:?}");
    assert!(events(port, &admin, &format!("action=harness.invoked&bot={}", beas.id)).await.is_empty(), "nothing ran");

    // Nobody can turn it back on while she's disabled.
    let (code, res) = call(port, "PATCH", &format!("/api/routines/{own}"), &admin, r#"{"enabled":true}"#).await;
    assert!(code == 409 && res.contains("turned off"), "{code} {res}");
    let (code, _) = call(port, "POST", &format!("/api/bots/{}/routines", adas.id), &admin, r#"{"name":"N","cron":"0 9 * * *","instruction":"x"}"#).await;
    assert_eq!(code, 409);
    let (code, _) = call(port, "POST", &format!("/api/bots/{}/routines", adas.id), &admin, r#"{"name":"N","cron":"0 9 * * *","instruction":"x","enabled":false}"#).await;
    assert_eq!(code, 201, "a paused one is fine");
    assert_eq!(call(port, "POST", &format!("/api/users/{ada}/routines/resume"), &admin, "").await.0, 409, "enable her first");

    // Enabling her leaves them paused, until an admin resumes them.
    set_status(port, &admin, &ada, "active").await;
    assert!(!r(&own).enabled && !r(&written).enabled);
    assert_eq!(events(port, &admin, "action=user.enabled").await[0]["details"]["routinesResumed"], 0);
    let (code, res) = call(port, "POST", &format!("/api/users/{ada}/routines/resume"), &admin, "").await;
    assert_eq!(code, 200, "{res}");
    let listed = parse(&res)["resumed"].as_array().unwrap().clone();
    assert_eq!(listed.len(), 4, "{res}");
    assert!(listed.iter().all(|r| r["enabled"] == true && r["pausedReason"].is_null() && r["pausedFor"].is_null()), "the saved state: {res}");
    assert!(r(&own).enabled && r(&written).enabled && r(&own).paused_reason.is_none());
    assert!(!r(&off).enabled, "the one she'd turned off stays off");
    let resumed = events(port, &admin, "action=routine.resumed").await;
    assert_eq!(resumed.len(), 4);
    assert!(resumed.iter().all(|e| e["details"]["reason"] == "admin" && e["details"]["pausedFor"] == ada.as_str()), "{resumed:?}");
    // Members can't.
    assert_eq!(call(port, "POST", &format!("/api/users/{ada}/routines/resume"), &b, "").await.0, 403);
}

#[tokio::test]
async fn a_routine_stays_paused_while_anyone_it_runs_for_is_disabled() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let beas = bot(&app, "Bea's", &bea);
    let written = routine(port, &a, &beas.id, "Written").await;
    set_status(port, &admin, &ada, "disabled").await;
    set_status(port, &admin, &bea, "disabled").await;
    set_status(port, &admin, &ada, "active").await;
    let (_, res) = call(port, "POST", &format!("/api/users/{ada}/routines/resume"), &admin, "").await;
    assert_eq!(parse(&res)["resumed"], json!([]));
    let r = app.db.routine(&written).unwrap();
    assert_eq!((r.enabled, r.paused_reason.as_deref(), r.paused_for.as_deref()), (false, Some("owner_disabled"), Some(bea.as_str())), "now held for Bea");
}

#[tokio::test]
async fn routines_on_enable_resume_brings_them_back_with_the_user() {
    let (port, app, admin, _) = serve_app().await;
    app.resume_routines_on_enable.set(true).unwrap();
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let adas = bot(&app, "Ada's", &ada);
    let own = routine(port, &a, &adas.id, "Own").await;
    set_status(port, &admin, &ada, "disabled").await;
    assert!(!app.db.routine(&own).unwrap().enabled);
    set_status(port, &admin, &ada, "active").await;
    assert!(app.db.routine(&own).unwrap().enabled);
    assert_eq!(events(port, &admin, "action=user.enabled").await[0]["details"]["routinesResumed"], 1);
    assert_eq!(events(port, &admin, "action=routine.resumed").await[0]["details"]["reason"], "user_enabled");
}

#[tokio::test]
async fn an_admin_hands_a_disabled_users_bots_and_routines_to_someone_else() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let (cal, _) = user_with(port, &admin, "cal@example.com", "member").await;
    let (ro, _) = user_with(port, &admin, "ro@example.com", "readonly").await;
    let adas = bot(&app, "Ada's", &ada);
    let own = routine(port, &a, &adas.id, "Own").await;
    let teams = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &bea, Visibility::Shared);
    let on_team = routine(port, &a, &teams.id, "On team").await;
    let private = app.db.create_bot_owned("Private", "#fff", "waddle", "claude", None, false, &bea, Visibility::Private);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{}/grants/{ada}", private.id), &b, r#"{"level":"operator"}"#).await.0, 200);
    let on_private = routine(port, &a, &private.id, "On private").await;
    let path = format!("/api/users/{ada}/handover");
    let to = |who: &str| json!({ "to": who }).to_string();

    let (code, res) = call(port, "POST", &path, &admin, &to(&cal)).await;
    assert!(code == 409 && res.contains("active"), "only a disabled user's: {res}");
    set_status(port, &admin, &ada, "disabled").await;
    assert_eq!(call(port, "POST", &path, &admin, &to(&ada)).await.0, 400);
    assert_eq!(call(port, "POST", &path, &admin, &to(&ro)).await.0, 400, "read-only users can't run Bots");
    assert_eq!(call(port, "POST", &path, &admin, &to("nobody@example.com")).await.0, 404);
    assert_eq!(call(port, "POST", &path, &b, &to(&cal)).await.0, 403, "admins only");

    let (code, res) = call(port, "POST", &path, &admin, &to(&cal)).await;
    assert_eq!(code, 200, "{res}");
    let res = parse(&res);
    assert_eq!(res["bots"], json!([adas.id]));
    assert_eq!(app.db.bot(&adas.id).unwrap().owner_id, cal);
    let r = |id: &str| app.db.routine(id).unwrap();
    // Her Bot's routine and the one on a shared Bot are Cal's now, still paused.
    for id in [&own, &on_team] {
        assert!(!r(id).enabled && r(id).paused_for.as_deref() == Some(cal.as_str()), "{id}");
    }
    assert_eq!(r(&on_team).author_id.as_deref(), Some(cal.as_str()));
    // Cal can't use Bea's private Bot, so that one stays Ada's, paused.
    assert_eq!(res["skipped"], json!([on_private]));
    assert_eq!((r(&on_private).author_id.as_deref(), r(&on_private).paused_for.as_deref()), (Some(ada.as_str()), Some(ada.as_str())));
    assert_eq!(res["resumed"], json!([]));

    let owner = events(port, &admin, "action=bot.owner_changed").await;
    assert!(owner.iter().any(|e| e["targetId"] == adas.id.as_str() && e["details"]["to"] == cal.as_str()), "{owner:?}");
    assert_eq!(events(port, &admin, "action=routine.handed_over").await.len(), 2);
    let handed = &events(port, &admin, "action=user.handed_over").await[0];
    assert_eq!((handed["targetId"].as_str(), handed["details"]["to"].as_str()), (Some(ada.as_str()), Some(cal.as_str())));

    // Cal's admin resumes them, and they fire for Cal.
    let (code, res) = call(port, "POST", &format!("/api/users/{cal}/routines/resume"), &admin, "").await;
    assert_eq!((code, parse(&res)["resumed"].as_array().unwrap().len()), (200, 2), "{res}");
    cron::fire(&app, &r(&own), db::now());
    let fired = events(port, &admin, "action=routine.fired").await;
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0]["onBehalfOf"], cal.as_str());
}

#[tokio::test]
async fn a_handover_can_resume_routines_at_once() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cal, _) = user_with(port, &admin, "cal@example.com", "member").await;
    let adas = bot(&app, "Ada's", &ada);
    let own = routine(port, &a, &adas.id, "Own").await;
    set_status(port, &admin, &ada, "disabled").await;
    let (code, res) = call(port, "POST", &format!("/api/users/{ada}/handover"), &admin, &json!({ "to": cal, "resumeRoutines": true }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(parse(&res)["resumed"], json!([own]));
    let r = app.db.routine(&own).unwrap();
    assert!(r.enabled && r.paused_reason.is_none());
    assert_eq!(events(port, &admin, "action=routine.resumed").await[0]["details"]["reason"], "handover");
    let (code, _) = call(port, "POST", &format!("/api/users/{ada}/handover"), &admin, r#"{"to":"cal@example.com","resumeRoutines":"yes"}"#).await;
    assert_eq!(code, 400);
}

#[tokio::test]
async fn users_disabled_before_the_upgrade_get_their_routines_paused_at_start() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let adas = bot(&app, "Ada's", &ada);
    let own = routine(port, &a, &adas.id, "Own").await;
    // As an older botd left it: disabled, routines still on.
    app.db.update_user(&ada, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    assert!(app.db.routine(&own).unwrap().enabled);
    let by = audit::Who { actor: audit::Actor::system("bootstrap"), source: Default::default() };
    assert_eq!(handover::pause_already_disabled(&app, &by), 1);
    assert_eq!(handover::pause_already_disabled(&app, &by), 0, "once");
    app.db.update_user(&ada, db::UserPatch { status: Some("active"), ..Default::default() }).unwrap();
    let r = app.db.routine(&own).unwrap();
    assert_eq!((r.enabled, r.paused_reason.as_deref()), (false, Some("owner_disabled")), "an admin resumes it");
    assert_eq!(events(port, &admin, "action=routine.paused").await[0]["actorId"], "bootstrap");
}

/// A role that only hands Bots on: `bots.manage` on top of member.
async fn offboarder(port: u16, admin: &str, email: &str) -> (String, String, String) {
    let offboarding = crate::service_accounts_http_tests::role(port, admin, "Offboarding", "member", &["bots.manage"]).await;
    let (id, auth) = user_with(port, admin, email, "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{offboarding}/users/{id}"), admin, "").await.0, 200);
    (id, auth, offboarding)
}

#[tokio::test]
async fn someone_with_bots_manage_hands_a_disabled_persons_bots_on_without_an_admin() {
    let (port, app, admin, _) = serve_app().await;
    let (dee, d, _) = offboarder(port, &admin, "dee@example.com").await;
    let (ada, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cal, _) = user_with(port, &admin, "cal@example.com", "member").await;
    let (_, plain) = user_with(port, &admin, "plain@example.com", "member").await;
    let adas = bot(&app, "Ada's", &ada);
    let own = routine(port, &a, &adas.id, "Own").await;
    set_status(port, &admin, &ada, "disabled").await;
    let path = format!("/api/users/{ada}/handover");

    assert_eq!(call(port, "POST", &path, &plain, &json!({ "to": cal }).to_string()).await.0, 403, "a plain member can't");
    // Never to themselves: someone else decides who gets a leaver's Bots, chats and memory.
    let (code, res) = call(port, "POST", &path, &d, &json!({ "to": dee }).to_string()).await;
    assert!(code == 403 && res.contains("yourself"), "{code} {res}");
    let denied = events(port, &admin, "action=access.denied").await;
    assert_eq!((denied[0]["details"]["limit"].as_str(), denied[0]["details"]["user"].as_str(), denied[0]["actorId"].as_str()), (Some("self"), Some(ada.as_str()), Some(dee.as_str())), "{denied:?}");
    assert_eq!(app.db.bot(&adas.id).unwrap().owner_id, ada, "nothing moved");
    // The rules every handover keeps still apply.
    let (code, res) = call(port, "POST", &format!("/api/users/{cal}/handover"), &d, &json!({ "to": dee }).to_string()).await;
    assert!(code == 409 && res.contains("active"), "{code} {res}");

    let (code, res) = call(port, "POST", &path, &d, &json!({ "to": "cal@example.com", "resumeRoutines": true }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    let res = parse(&res);
    assert_eq!((res["bots"].clone(), res["resumed"].clone()), (json!([adas.id]), json!([own])));
    assert_eq!(app.db.bot(&adas.id).unwrap().owner_id, cal);
    let r = app.db.routine(&own).unwrap();
    assert!(r.enabled && r.author_id.as_deref() == Some(cal.as_str()), "Cal's now, and running");
    let handed = &events(port, &admin, "action=user.handed_over").await[0];
    assert_eq!((handed["actorId"].as_str(), handed["details"]["via"].as_str(), handed["details"]["to"].as_str()), (Some(dee.as_str()), Some("bots.manage"), Some(cal.as_str())), "{handed}");
    let owner = &events(port, &admin, "action=bot.owner_changed").await[0];
    assert_eq!(owner["actorId"].as_str(), Some(dee.as_str()));
    assert_eq!(events(port, &admin, "action=routine.resumed").await[0]["details"]["reason"], "handover");

    // An admin's handover says nothing of a delegate.
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    bot(&app, "Bea's", &bea);
    set_status(port, &admin, &bea, "disabled").await;
    assert_eq!(call(port, "POST", &format!("/api/users/{bea}/handover"), &admin, &json!({ "to": dee }).to_string()).await.0, 200, "an admin may hand them to Dee");
    let handed = &events(port, &admin, "action=user.handed_over").await[0];
    assert_eq!((handed["targetId"].as_str(), handed["details"].get("via")), (Some(bea.as_str()), None), "{handed}");
}

#[tokio::test]
async fn bots_manage_never_hands_over_an_admins_a_custom_role_holders_or_the_primary_bot() {
    let (port, app, admin, _) = serve_app().await;
    let (dee, d, offboarding) = offboarder(port, &admin, "dee@example.com").await;
    let (cal, _) = user_with(port, &admin, "cal@example.com", "member").await;
    let (boss, _) = user_with(port, &admin, "boss@example.com", "admin").await;
    let (lead, _) = user_with(port, &admin, "lead@example.com", "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{offboarding}/users/{lead}"), &admin, "").await.0, 200);
    let (pam, _) = user_with(port, &admin, "pam@example.com", "member").await;
    let bosses = bot(&app, "Boss's", &boss);
    let leads = bot(&app, "Lead's", &lead);
    let main = app.db.create_bot_owned("Main", "#fff", "waddle", "claude", None, true, &pam, Visibility::Shared);
    bot(&app, "Pam's", &pam);
    for u in [&boss, &lead, &pam] {
        set_status(port, &admin, u, "disabled").await;
    }
    let to_cal = json!({ "to": cal }).to_string();
    let hand = |who: &str| format!("/api/users/{who}/handover");

    for (from, limit, says) in [(&boss, "protected_user", "Only an admin"), (&lead, "protected_user", "Only an admin"), (&pam, "primary_bot", "primary Bot")] {
        let (code, res) = call(port, "POST", &hand(from), &d, &to_cal).await;
        assert!(code == 403 && res.contains(says), "{from}: {code} {res}");
        let denied = &events(port, &admin, "action=access.denied").await[0];
        assert_eq!((denied["details"]["limit"].as_str(), denied["details"]["user"].as_str(), denied["actorId"].as_str()), (Some(limit), Some(from.as_str()), Some(dee.as_str())), "{denied}");
    }
    assert_eq!(app.db.bot(&bosses.id).unwrap().owner_id, boss);
    assert_eq!(app.db.bot(&leads.id).unwrap().owner_id, lead);
    assert_eq!(app.db.bot(&main.id).unwrap().owner_id, pam, "not even the rest of Pam's Bots");
    assert!(events(port, &admin, "action=user.handed_over").await.is_empty());

    // An admin still hands each of them over.
    for from in [&boss, &lead, &pam] {
        assert_eq!(call(port, "POST", &hand(from), &admin, &to_cal).await.0, 200, "{from}");
    }
    assert_eq!(app.db.bot(&main.id).unwrap().owner_id, cal);
}

#[tokio::test]
async fn a_service_account_with_bots_manage_hands_nothing_over() {
    let (port, app, admin, _) = serve_app().await;
    let (dee, _, _) = offboarder(port, &admin, "dee@example.com").await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cal, _) = user_with(port, &admin, "cal@example.com", "member").await;
    let adas = bot(&app, "Ada's", &ada);
    set_status(port, &admin, &ada, "disabled").await;
    let sa = crate::service_accounts_http_tests::account(port, &admin, json!({ "name": "Offboarding job", "role": "Offboarding" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, &json!({ "owner": dee }).to_string()).await.0, 200);
    let (tok, _) = crate::service_accounts_http_tests::token(port, &admin, &sa, json!({})).await;
    let (code, listed) = call(port, "GET", &format!("/api/users/{ada}/routines"), &tok, "").await;
    assert_eq!(code, 200, "it holds bots.manage: {listed}");

    let (code, res) = call(port, "POST", &format!("/api/users/{ada}/handover"), &tok, &json!({ "to": cal }).to_string()).await;
    assert!(code == 403 && res.contains("service account"), "{code} {res}");
    let denied = &events(port, &admin, "action=access.denied").await[0];
    assert_eq!(denied["details"]["limit"].as_str(), Some("service_account"), "{denied}");
    assert_eq!(app.db.bot(&adas.id).unwrap().owner_id, ada);
}
