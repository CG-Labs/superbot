//! Team billing (ADR 0093) on the real router: a team's owners and admins buy one plan
//! for everyone on it through Stripe Checkout, every member gets its tier and their
//! computer follows, seats follow the team's members with prorations, and team and
//! personal billing never cross. Stripe is a fake on loopback and its events are
//! fixtures: nothing here reaches Stripe, and the keys are made up.

use crate::billing::Billing;
use crate::billing_http_tests::{CHECKOUT_DONE, CUSTOMER_DELETED, DELETED, FakeStripe, KEY, PUBLIC, SECRET, UPDATED, World, audit, deliver, event, fake_stripe, world, world_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = crate::tests::call(port, method, path, who, body).await;
    (code, parse(&body))
}

/// The billing world with checkout against a fake Stripe, and Alpha: Ada its owner,
/// Bea a member.
async fn shop() -> (World, FakeStripe, String) {
    let (url, f) = fake_stripe().await;
    let w = world_with(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC))).await;
    let alpha = team(&w, "Alpha").await;
    (w, f, alpha)
}

async fn team(w: &World, name: &str) -> String {
    let (code, v) = json_call(w.port, "POST", "/api/teams", &w.admin, &json!({ "name": name, "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    add(w, &id, &w.b_id, "member").await;
    id
}

async fn add(w: &World, team: &str, user: &str, role: &str) {
    let (code, v) = json_call(w.port, "PUT", &format!("/api/teams/{team}/members/{user}"), &w.admin, &json!({ "role": role }).to_string()).await;
    assert_eq!(code, 200, "{v}");
}

/// A subscription event for `team`'s subscription, priced `price`, with `seats`.
fn team_event(team: &str, id: &str, created: i64, f: impl FnOnce(&mut Value)) -> String {
    event(UPDATED, "", id, created, |v| {
        let o = &mut v["data"]["object"];
        o["id"] = json!("sub_test_alpha");
        o["customer"] = json!("cus_test_alpha");
        o["metadata"] = json!({ "superbot_team_id": team, "superbot_paid_by": "someone" });
        o["items"]["data"][0]["id"] = json!("si_test_alpha");
        o["items"]["data"][0]["quantity"] = json!(2);
        f(v);
    })
}

fn tier(w: &World, user: &str) -> String {
    w.app.tier_of(user).name.clone()
}

fn seat_posts(f: &FakeStripe) -> Vec<crate::billing_http_tests::Seen> {
    f.seen().into_iter().filter(|s| s.path.starts_with("/v1/subscription_items/")).collect()
}

#[tokio::test]
async fn a_team_buys_one_plan_for_everyone_on_it() {
    let (w, stripe, alpha) = shop().await;
    let port = w.port;

    // Before it pays: no plan; its owner sees the plans for sale, its member only the plan.
    let (code, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    assert_eq!(code, 200, "{mine}");
    let b = &mine["billing"];
    assert_eq!((&b["plan"], &b["subscription"], &b["seats"], b["portal"].as_bool(), b["canChange"].as_bool()), (&Value::Null, &Value::Null, &Value::Null, Some(false), Some(true)), "{b}");
    assert_eq!(b["plans"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect::<Vec<_>>(), ["starter", "pro"]);
    assert!(!mine.to_string().contains("price_"), "{mine}");
    let (_, hers) = json_call(port, "GET", "/api/team", &w.b, "").await;
    assert_eq!(hers["billing"], json!({ "plan": null, "canChange": false }), "{hers}");

    // Only owners and admins buy it.
    for p in ["/api/team/billing/checkout", "/api/team/billing/portal"] {
        let (code, v) = json_call(port, "POST", p, &w.b, r#"{"tier":"pro"}"#).await;
        assert_eq!(code, 403, "{p}: {v}");
    }
    let (code, v) = json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"max"}"#).await;
    assert_eq!(code, 400, "{v}");
    let (code, v) = json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"pro"}"#).await;
    assert_eq!(code, 200, "{v}");
    assert!(v["url"].as_str().unwrap().starts_with("https://checkout.stripe.com/"), "{v}");
    let made = stripe.seen().into_iter().find(|s| s.path == "/v1/checkout/sessions").unwrap();
    assert_eq!(
        (made.get("line_items[0][price]"), made.get("line_items[0][quantity]"), made.get("metadata[superbot_team_id]"), made.get("subscription_data[metadata][superbot_team_id]")),
        (Some("price_pro_monthly"), Some("2"), Some(alpha.as_str()), Some(alpha.as_str()))
    );
    assert_eq!((made.get("metadata[superbot_paid_by]"), made.get("customer_email"), made.get("metadata[superbot_user_id]"), made.get("client_reference_id")), (Some(w.a_id.as_str()), Some("ada@example.com"), None, None));
    assert_eq!(made.get("success_url"), Some(format!("{PUBLIC}/app/team?checkout=success").as_str()));
    let ev = audit(port, &w.admin, "action=billing.checkout_created").await;
    assert_eq!((ev[0]["targetType"].as_str(), ev[0]["targetId"].as_str(), ev[0]["details"]["seats"].as_i64()), (Some("team"), Some(alpha.as_str()), Some(2)), "{:?}", ev[0]);

    // The checkout completes: the team gets its own customer.
    let done = event(CHECKOUT_DONE, "", "evt_t1", 1_795_000_000, |v| {
        let o = &mut v["data"]["object"];
        o["customer"] = json!("cus_test_alpha");
        o["client_reference_id"] = Value::Null;
        o["metadata"] = json!({ "superbot_team_id": alpha, "superbot_paid_by": w.a_id });
    });
    assert_eq!(deliver(port, &done, None).await.1["outcome"], "customer_linked");
    assert_eq!(w.app.db.team_customer(&alpha).as_deref(), Some("cus_test_alpha"));
    assert_eq!(w.app.db.customer_of(&w.a_id), None, "the team's customer isn't Ada's");

    // Its subscription pays: everyone on the team is on pro, and only through the team.
    let paid = team_event(&alpha, "evt_t2", 1_795_000_100, |_| {});
    let (code, res) = deliver(port, &paid, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("tier_changed")), "{res}");
    assert_eq!((tier(&w, &w.a_id), tier(&w, &w.b_id)), ("pro".to_string(), "pro".to_string()));
    assert_eq!((w.app.db.user(&w.a_id).unwrap().tier, w.app.db.user(&w.b_id).unwrap().tier), (None, None));
    let t = &audit(port, &w.admin, "action=team.tier_changed").await[0];
    assert_eq!((t["targetId"].as_str(), t["details"]["effectiveTo"].as_str(), t["details"]["source"].as_str()), (Some(alpha.as_str()), Some("pro"), Some("stripe")), "{t}");
    let users = audit(port, &w.admin, "action=user.tier_changed").await;
    let mut moved: Vec<&str> = users.iter().map(|e| e["targetId"].as_str().unwrap()).collect();
    moved.sort();
    let mut want = vec![w.a_id.as_str(), w.b_id.as_str()];
    want.sort();
    assert_eq!(moved, want);
    assert!(users.iter().all(|e| e["details"]["source"] == "team" && e["details"]["team"] == alpha.as_str() && e["details"]["effectiveFrom"] == "starter"), "{users:?}");
    // A member's limits are the team plan's at once.
    let (_, me) = json_call(port, "GET", "/api/me/tier", &w.b, "").await;
    assert_eq!(me["name"], "pro");

    // The team screen shows it; Bea's plan says the team pays.
    let (_, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    let b = &mine["billing"];
    assert_eq!((b["plan"]["name"].as_str(), b["subscription"]["status"].as_str(), b["portal"].as_bool()), (Some("pro"), Some("active"), Some(true)), "{b}");
    assert_eq!(b["seats"], json!({ "members": 2, "billed": 2, "syncing": false, "error": null }));
    assert!(!mine.to_string().contains("sub_test") && !mine.to_string().contains("cus_test"), "{mine}");
    let (_, hers) = json_call(port, "GET", "/api/team", &w.b, "").await;
    assert_eq!(hers["billing"]["plan"]["name"], "pro");
    let (_, info) = json_call(port, "GET", "/api/billing", &w.b, "").await;
    assert_eq!((info["plan"]["name"].as_str(), info["teamPlan"]["name"].as_str(), info["teamPlan"]["tier"].as_str()), (Some("pro"), Some("Alpha"), Some("pro")), "{info}");
    // Nobody on it buys a plan of their own, and the team can't buy a second.
    let (code, v) = json_call(port, "POST", "/api/billing/checkout", &w.b, r#"{"tier":"pro"}"#).await;
    assert_eq!((code, v["teamPays"].as_bool()), (409, Some(true)), "{v}");
    let (code, _) = json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"starter"}"#).await;
    assert_eq!(code, 409);
    assert_eq!(audit(port, &w.admin, "action=billing.checkout_created&outcome=denied").await.len(), 2);

    // Redelivered: nothing more.
    assert_eq!(deliver(port, &paid, None).await.1["outcome"], "duplicate");
    assert_eq!(audit(port, &w.admin, "action=team.tier_changed").await.len(), 1);

    // Its portal is the team's customer's, back to the Team screen.
    let (code, v) = json_call(port, "POST", "/api/team/billing/portal", &w.a, "").await;
    assert_eq!(code, 200, "{v}");
    let portal = stripe.seen().into_iter().find(|s| s.path == "/v1/billing_portal/sessions").unwrap();
    assert_eq!((portal.get("customer"), portal.get("return_url")), (Some("cus_test_alpha"), Some(format!("{PUBLIC}/app/team").as_str())));

    // While it pays, the team can't be deleted or emptied.
    let (code, v) = json_call(port, "DELETE", &format!("/api/teams/{alpha}"), &w.admin, "").await;
    assert_eq!(code, 409, "{v}");
    let refused = audit(port, &w.admin, "action=team.delete_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["outcome"].as_str()), (Some("team_pays"), Some("denied")));
    assert!(w.app.db.team(&alpha).is_some());

    // It ends: everyone goes back to their own plan, and the team can go.
    let ended = event(DELETED, "", "evt_t3", 1_795_100_000, |v| {
        v["data"]["object"]["id"] = json!("sub_test_alpha");
        v["data"]["object"]["customer"] = json!("cus_test_alpha");
        v["data"]["object"]["metadata"] = json!({});
    });
    assert_eq!(deliver(port, &ended, None).await.1["outcome"], "tier_changed");
    assert_eq!((tier(&w, &w.a_id), tier(&w, &w.b_id)), ("starter".to_string(), "starter".to_string()));
    let (_, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    assert_eq!((&mine["billing"]["plan"], mine["billing"]["subscription"]["status"].as_str()), (&Value::Null, Some("canceled")));
    assert_eq!(json_call(port, "DELETE", &format!("/api/teams/{alpha}"), &w.admin, "").await.0, 200);
    // A late event for a team that's gone is ignored.
    let late = team_event(&alpha, "evt_t4", 1_795_200_000, |v| v["data"]["object"]["id"] = json!("sub_test_alpha_2"));
    assert_eq!(deliver(port, &late, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"], "unknown_team");
}

#[tokio::test]
async fn seats_follow_the_team_with_prorations() {
    let (w, stripe, alpha) = shop().await;
    let port = w.port;
    assert_eq!(deliver(port, &team_event(&alpha, "evt_s1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    // Billed for 2, and 2 on it: nothing to send.
    assert_eq!(team_billing::sync_seats(&w.app).await, 0);
    assert!(seat_posts(&stripe).is_empty());

    // Cy joins: on the team's plan at once, and billed a seat with prorations.
    let (cy_id, _) = user_with(port, &w.admin, "cy@example.com", "member").await;
    add(&w, &alpha, &cy_id, "admin").await;
    assert_eq!(tier(&w, &cy_id), "pro");
    let joined = audit(port, &w.admin, &format!("action=user.tier_changed&target=user:{cy_id}")).await;
    assert_eq!((joined[0]["details"]["via"].as_str(), joined[0]["details"]["effectiveTo"].as_str()), (Some("joined"), Some("pro")), "{joined:?}");
    let (_, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    assert_eq!(mine["billing"]["seats"], json!({ "members": 3, "billed": 2, "syncing": true, "error": null }));
    assert_eq!(team_billing::sync_seats(&w.app).await, 1);
    let posts = seat_posts(&stripe);
    assert_eq!(posts.len(), 1, "{posts:?}");
    assert_eq!((posts[0].path.as_str(), posts[0].get("quantity"), posts[0].get("proration_behavior")), ("/v1/subscription_items/si_test_alpha", Some("3"), Some("create_prorations")));
    assert!(posts[0].key.starts_with("superbot-seats-") && posts[0].auth == format!("Bearer {KEY}"), "{:?}", posts[0]);
    assert_eq!(w.app.db.team_paying(&alpha).unwrap().quantity, Some(3));
    let synced = audit(port, &w.admin, "action=team.seats_synced").await;
    assert_eq!((synced[0]["targetId"].as_str(), synced[0]["details"]["from"].as_i64(), synced[0]["details"]["to"].as_i64()), (Some(alpha.as_str()), Some(2), Some(3)));
    assert_eq!(team_billing::sync_seats(&w.app).await, 0, "in line now");

    // Stripe is down: the update is retried later, said on the team screen, and audited.
    add_and_remove_seat_fails(&w, &stripe, &alpha, &cy_id).await;

    // Cy leaves: back on their own plan, and the seat goes.
    let (code, _) = json_call(port, "DELETE", &format!("/api/teams/{alpha}/members/{cy_id}"), &w.admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(tier(&w, &cy_id), "starter");
    let left = audit(port, &w.admin, &format!("action=user.tier_changed&target=user:{cy_id}")).await;
    assert_eq!((left[0]["details"]["via"].as_str(), left[0]["details"]["effectiveTo"].as_str()), (Some("left"), Some("starter")));
    assert_eq!(team_billing::sync_seats(&w.app).await, 1);
    assert_eq!(seat_posts(&stripe).last().unwrap().get("quantity"), Some("2"));
    let (_, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    assert_eq!(mine["billing"]["seats"], json!({ "members": 2, "billed": 2, "syncing": false, "error": null }));
    // Each update has its own key, so going back to a count sent before still sends it.
    let keys: std::collections::HashSet<String> = seat_posts(&stripe).into_iter().map(|s| s.key).collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
}

async fn add_and_remove_seat_fails(w: &World, stripe: &FakeStripe, alpha: &str, cy_id: &str) {
    let (dan_id, _) = user_with(w.port, &w.admin, "dan@example.com", "member").await;
    add(w, alpha, &dan_id, "member").await;
    let busy = json!({ "error": { "type": "api_error" } });
    stripe.reply(500, busy.clone());
    stripe.reply(500, busy);
    let before = seat_posts(stripe).len();
    assert_eq!(team_billing::sync_seats(&w.app).await, 0);
    assert_eq!(seat_posts(stripe).len(), before + 2, "one retry within the call");
    let failed = audit(w.port, &w.admin, "action=team.seats_sync_failed").await;
    let d = &failed[0]["details"];
    assert_eq!((d["to"].as_i64(), d["retrying"].as_bool(), d["error"].as_str(), failed[0]["outcome"].as_str()), (Some(4), Some(true), Some("HTTP 500 api_error"), Some("failure")), "{d}");
    assert!(d["retryAt"].as_i64().unwrap() > db::now());
    let (_, mine) = json_call(w.port, "GET", "/api/team", &w.a, "").await;
    let seats = &mine["billing"]["seats"];
    assert_eq!((seats["members"].as_i64(), seats["billed"].as_i64(), seats["syncing"].as_bool()), (Some(4), Some(3), Some(true)));
    assert!(seats["error"].as_str().unwrap().contains("keeps trying") && !seats.to_string().contains("500"), "{seats}");
    // Not again before its backoff.
    assert_eq!(team_billing::sync_seats(&w.app).await, 0);
    assert_eq!(seat_posts(stripe).len(), before + 2);
    // Dan leaves before it's tried again: what's sent is the count then.
    let (code, _) = json_call(w.port, "DELETE", &format!("/api/teams/{alpha}/members/{dan_id}"), &w.admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(team_billing::sync_seats(&w.app).await, 0, "3 billed and 3 on it");
    let (_, mine) = json_call(w.port, "GET", "/api/team", &w.a, "").await;
    assert_eq!(mine["billing"]["seats"]["error"], Value::Null, "cleared once in line");
    assert_eq!(w.app.db.team_member_count(alpha), 3, "{cy_id} is still on it");
}

#[tokio::test]
async fn team_and_personal_billing_never_cross() {
    let (w, _stripe, alpha) = shop().await;
    let port = w.port;
    let ignored = || async { audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"].as_str().unwrap().to_string() };

    // Ada pays for pro herself.
    assert_eq!(deliver(port, &event(UPDATED, &w.a_id, "evt_p1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w, &w.a_id), "pro");
    // A team subscription through Ada's own customer, or naming her too, is refused.
    let hers = team_event(&alpha, "evt_x1", 1_795_000_100, |v| v["data"]["object"]["customer"] = json!("cus_test_ada"));
    assert_eq!(deliver(port, &hers, None).await.1["outcome"], "ignored");
    assert_eq!(ignored().await, "customer_of_another_payer");
    let both = team_event(&alpha, "evt_x2", 1_795_000_200, |v| v["data"]["object"]["metadata"]["superbot_user_id"] = json!(w.a_id));
    assert_eq!(deliver(port, &both, None).await.1["outcome"], "ignored");
    assert_eq!(ignored().await, "ambiguous_payer");
    assert!(w.app.db.team_paying(&alpha).is_none());

    // The team's plan (starter) is everyone's while it pays, over Ada's own.
    let starter = team_event(&alpha, "evt_x3", 1_795_000_300, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly"));
    assert_eq!(deliver(port, &starter, None).await.1["outcome"], "tier_changed");
    assert_eq!((tier(&w, &w.a_id), w.app.db.user(&w.a_id).unwrap().tier.as_deref()), ("starter".to_string(), Some("pro")));
    // A personal event for the team's subscription, or the team's customer, places nothing.
    let theirs = event(UPDATED, &w.b_id, "evt_x4", 1_795_000_400, |v| v["data"]["object"]["id"] = json!("sub_test_alpha"));
    assert_eq!(deliver(port, &theirs, None).await.1["outcome"], "ignored");
    assert_eq!(ignored().await, "ambiguous_payer");
    let via = event(UPDATED, &w.b_id, "evt_x5", 1_795_000_500, |v| {
        v["data"]["object"]["id"] = json!("sub_test_bea");
        v["data"]["object"]["customer"] = json!("cus_test_alpha");
    });
    assert_eq!(deliver(port, &via, None).await.1["outcome"], "ignored");
    assert_eq!(ignored().await, "customer_of_another_user");
    assert_eq!(w.app.db.user(&w.b_id).unwrap().tier, None);
    // A subscription naming no one, under the team's customer, is the team's.
    let bare = team_event(&alpha, "evt_x6", 1_795_000_600, |v| {
        v["data"]["object"]["id"] = json!("sub_test_alpha_2");
        v["data"]["object"]["created"] = json!(1_795_000_600);
        v["data"]["object"]["metadata"] = json!({});
    });
    assert_eq!(deliver(port, &bare, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w, &w.b_id), "pro");
    assert_eq!(w.app.db.team_paying(&alpha).unwrap().subscription_id, "sub_test_alpha_2");

    // The team's customer deleted at Stripe: unlinked from the team.
    let gone = event(CUSTOMER_DELETED, "", "evt_x7", 1_795_000_700, |v| v["data"]["object"]["id"] = json!("cus_test_alpha"));
    assert_eq!(deliver(port, &gone, None).await.1["outcome"], "customer_unlinked");
    assert_eq!(w.app.db.team_customer(&alpha), None);
    let un = audit(port, &w.admin, "action=billing.customer_unlinked").await;
    assert_eq!((un[0]["targetType"].as_str(), un[0]["targetId"].as_str()), (Some("team"), Some(alpha.as_str())));
    assert_eq!(w.app.db.customer_of(&w.a_id).as_deref(), Some("cus_test_ada"), "Ada's own is untouched");
}

#[tokio::test]
async fn a_team_plans_emails_go_to_its_owners_and_admins() {
    let (w, _stripe, alpha) = shop().await;
    let (cy_id, _) = user_with(w.port, &w.admin, "cy@example.com", "member").await;
    add(&w, &alpha, &cy_id, "admin").await;
    let mailer = billing_mail::fake::install(&w.app, Some(PUBLIC));
    assert_eq!(deliver(w.port, &team_event(&alpha, "evt_m1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    billing_mail::send_due(&w.app).await;
    let mut to: Vec<String> = mailer.sent().iter().map(|m| m.to.clone()).collect();
    to.sort();
    assert_eq!(to, ["ada@example.com", "cy@example.com"], "Bea, a member, isn't told");
    let m = &mailer.sent()[0];
    assert_eq!(m.subject, "[SuperBot] Alpha's Pro plan has started");
    assert!(m.body.contains(&format!("{PUBLIC}/app/team")) && !m.body.contains("sub_test"), "{}", m.body);
    // The members' resizes send nothing of their own: the team's plan isn't theirs to pay.
    assert_eq!(mailer.sent().len(), 2);
}

#[tokio::test]
async fn team_billing_is_off_without_checkout() {
    for stripe in [false, true] {
        let w = world(stripe).await;
        let alpha = team(&w, "Alpha").await;
        let (_, mine) = json_call(w.port, "GET", "/api/team", &w.a, "").await;
        assert!(mine.get("billing").is_none(), "{mine}");
        let (_, list) = json_call(w.port, "GET", "/api/teams", &w.admin, "").await;
        assert!(list["teams"][0].get("billing").is_none(), "{list}");
        for p in ["/api/team/billing/checkout", "/api/team/billing/portal"] {
            let (code, v) = json_call(w.port, "POST", p, &w.a, r#"{"tier":"pro"}"#).await;
            assert_eq!(code, 404, "{p}: {v}");
        }
        assert_eq!(team_billing::sync_seats(&w.app).await, 0);
        // Teams work as before: deleted with nothing to refuse.
        assert_eq!(json_call(w.port, "DELETE", &format!("/api/teams/{alpha}"), &w.admin, "").await.0, 200);
    }
}

/// Small gives g6-standard-1 machines, big g6-standard-2 and is sold as the fixture's price.
const SIZED: &str = r#"{
  "default": "small",
  "tiers": [
    { "name": "small", "label": "Small", "routes": "any", "limits": { "machineType": "g6-standard-1" }, "stripePrices": ["price_small_monthly"] },
    { "name": "big", "label": "Big", "routes": "any", "limits": { "machineType": "g6-standard-2" }, "stripePrices": ["price_pro_monthly"] }
  ]
}"#;

#[tokio::test]
async fn members_computers_follow_the_team_plan() {
    use crate::machines::provider::MachineProvider;
    let (url, _stripe) = fake_stripe().await;
    let b = Billing::with_checkout(SECRET, KEY, &url, PUBLIC);
    let seats = b.seats().unwrap();
    let p: Arc<dyn MachineProvider> = Arc::new(crate::machines::fake::Fake::default());
    let (port, app, admin, _) = crate::tests::serve_app_with(|a| {
        a.machines = Arc::new(crate::machines::ControlPlane::for_tests(p));
        a.payments = b;
    })
    .await;
    app.tiers.set(Arc::new(crate::tiers::Tiers::parse(SIZED, None).unwrap())).unwrap();
    let _ = app.team_seats.set(seats);
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, v) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let alpha = v["id"].as_str().unwrap().to_string();
    // Joining gives each a machine of the plan they're on: small.
    assert_eq!(json_call(port, "PUT", &format!("/api/teams/{alpha}/members/{bea}"), &admin, "{}").await.0, 200);
    assert_eq!(app.db.user_machine(&bea).unwrap().plan, "g6-standard-1");
    // The team pays for big: both machines are asked to grow, for the team.
    assert_eq!(deliver(port, &team_event(&alpha, "evt_r1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    let resized = audit(port, &admin, "action=machine.resize_queued").await;
    assert_eq!(resized.len(), 2, "{resized:?}");
    assert!(resized.iter().all(|e| e["details"]["cause"] == "team" && e["details"]["toPlan"] == "g6-standard-2" && e["details"]["eventId"] == "evt_r1"), "{resized:?}");
    for u in [&ada, &bea] {
        let m = app.db.user_machine(u).unwrap();
        assert_eq!((m.resize_state.as_deref(), m.resize_plan.as_deref(), m.resize_cause.as_deref()), (Some("pending"), Some("g6-standard-2"), Some("team")));
    }
    // A newcomer's machine is the team plan's size from the start.
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    assert_eq!(json_call(port, "PUT", &format!("/api/teams/{alpha}/members/{cy}"), &admin, "{}").await.0, 200);
    assert_eq!(app.db.user_machine(&cy).unwrap().plan, "g6-standard-2");
}

#[tokio::test]
async fn server_admins_see_each_teams_plan_and_seats() {
    let (w, _stripe, alpha) = shop().await;
    assert_eq!(deliver(w.port, &team_event(&alpha, "evt_a1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    let (code, list) = json_call(w.port, "GET", "/api/teams", &w.admin, "").await;
    assert_eq!(code, 200, "{list}");
    let b = &list["teams"][0]["billing"];
    assert_eq!((b["plan"]["name"].as_str(), b["seats"]["billed"].as_i64(), b["subscription"]["status"].as_str()), (Some("pro"), Some(2), Some("active")), "{b}");
    // Admin usage shows each member on the team's plan, over the tier they were given.
    let (_, usage) = json_call(w.port, "GET", "/api/usage", &w.admin, "").await;
    let bea = usage["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == w.b_id.as_str()).unwrap().clone();
    assert_eq!((bea["plan"]["name"].as_str(), &bea["tier"], bea["plan"]["usage"]["periodSource"].as_str()), (Some("pro"), &Value::Null, Some("subscription")), "{bea}");
}

#[tokio::test]
async fn a_paid_checkout_holds_the_team_until_its_subscription_arrives() {
    let (w, stripe, alpha) = shop().await;
    let port = w.port;
    assert_eq!(json_call(port, "DELETE", &format!("/api/teams/{alpha}/members/{}", w.b_id), &w.admin, "").await.0, 200);

    // Ada, alone on Alpha, pays a checkout and tries to leave before Stripe's events: refused.
    assert_eq!(json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"pro"}"#).await.0, 200);
    stripe.pay("cs_test_1");
    let (code, v) = json_call(port, "POST", "/api/team/leave", &w.a, "").await;
    assert_eq!(code, 409, "{v}");
    let refused = audit(port, &w.admin, "action=team.delete_refused").await;
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["via"].as_str()), (Some("checkout_completed"), Some("last_member_left")), "{}", refused[0]);
    assert_eq!(json_call(port, "DELETE", &format!("/api/teams/{alpha}"), &w.admin, "").await.0, 409);
    assert!(w.app.db.team(&alpha).is_some());

    // The checkout completes, its subscription not yet seen: no second checkout opens.
    let done = event(CHECKOUT_DONE, "", "evt_h1", 1_795_000_000, |v| {
        let o = &mut v["data"]["object"];
        o["id"] = json!("cs_test_1");
        o["customer"] = json!("cus_test_alpha");
        o["subscription"] = json!("sub_test_alpha");
        o["client_reference_id"] = Value::Null;
        o["metadata"] = json!({ "superbot_team_id": alpha, "superbot_paid_by": w.a_id });
    });
    assert_eq!(deliver(port, &done, None).await.1["outcome"], "customer_linked");
    let (code, v) = json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"starter"}"#).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(audit(port, &w.admin, "action=billing.checkout_created&outcome=denied").await[0]["details"]["reason"], "checkout_completed");
    assert_eq!(stripe.seen().iter().filter(|s| s.path == "/v1/checkout/sessions").count(), 1);

    // Its subscription arrives but never pays: the checkout is done with, and a new one may open.
    let lapsed = team_event(&alpha, "evt_h2", 1_795_000_100, |v| v["data"]["object"]["status"] = json!("incomplete_expired"));
    deliver(port, &lapsed, None).await;
    assert_eq!(w.app.db.team_open_checkout(&alpha), None);
    assert_eq!(json_call(port, "POST", "/api/team/billing/checkout", &w.a, r#"{"tier":"pro"}"#).await.0, 200);

    // Leaving with an unpaid checkout open expires it first, then the team goes.
    let open = w.app.db.team_open_checkout(&alpha).unwrap();
    let (code, v) = json_call(port, "POST", "/api/team/leave", &w.a, "").await;
    assert_eq!(code, 200, "{v}");
    assert!(stripe.seen().iter().any(|s| s.path == format!("/v1/checkout/sessions/{open}/expire")));
    assert!(w.app.db.team(&alpha).is_none());
}

#[tokio::test]
async fn a_team_members_tokens_are_metered_to_the_team() {
    use crate::usage_http_tests::{fake_claude_tokens, go};
    let (url, _stripe) = fake_stripe().await;
    let w = world_with(Some(Billing::with_metering(SECRET, KEY, &url, PUBLIC, "superbot_tokens"))).await;
    let alpha = team(&w, "Alpha").await;
    // Ada has a customer of her own; Bea none.
    w.app.db.link_customer("evt_c1", "checkout.session.completed", &w.a_id, "stripe", "cus_test_ada", "checkout").unwrap();
    assert_eq!((w.app.meter_customer(&w.a_id).as_deref(), w.app.meter_customer(&w.b_id)), (Some("cus_test_ada"), None));
    assert_eq!(deliver(w.port, &team_event(&alpha, "evt_m1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    assert_eq!((w.app.meter_customer(&w.a_id).as_deref(), w.app.meter_customer(&w.b_id).as_deref()), (Some("cus_test_alpha"), Some("cus_test_alpha")));

    // Each run's tokens are queued for whoever pays when it ends, and stay theirs.
    fake_claude_tokens(&w.app, 1000);
    let hers = w.app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, crate::acl::Visibility::Private);
    go(&w, &w.b, &hers.id).await;
    let pending = w.app.db.pending_meter(100);
    assert_eq!(pending.iter().map(|r| r.customer.as_deref()).collect::<Vec<_>>(), [Some("cus_test_alpha")], "{pending:?}");
    assert_eq!(json_call(w.port, "DELETE", &format!("/api/teams/{alpha}/members/{}", w.b_id), &w.admin, "").await.0, 200);
    assert_eq!(w.app.db.pending_meter(100)[0].customer.as_deref(), Some("cus_test_alpha"));
}
