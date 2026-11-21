//! Billing emails (ADR 0089) on the real router: Stripe's signed subscription events
//! email the person the plan is for, once per event however often Stripe redelivers
//! it; payments that fail, plans set to end and plans that end say so with a link to
//! the Plan screen; a downgrade that waits on the user's files says so; nearing or
//! reaching a plan's tokens or storage says so once a period unless the person turned
//! those off; failed sends are tried again and audited; and with billing emails off
//! nothing is queued. Mail goes to a fake mailer, except one test through the SMTP client.

use crate::acl::Visibility;
use crate::billing::Billing;
use crate::billing_http_tests::{DELETED, PUBLIC, SECRET, UPDATED, audit, deliver, event, set_tier, world};
use crate::billing_mail::{self, fake};
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::State as MachineState;
use crate::notify::smtp;
use crate::tests::{call, serve_app_with};
use crate::tiers::Tiers;
use crate::usage_http_tests::{fake_claude_tokens, go, tokens};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const PLAN: &str = "https://bots.example.com/app/plan";
/// What a provider id or secret looks like: none may reach an email.
const PROVIDER: [&str; 6] = ["sub_", "cus_", "price_", "evt_", "whsec_", "sk_"];

/// An event for Ada's subscription, made at `created`, with its status set and the rest changed by `f`.
fn ada(w: &crate::billing_http_tests::World, id: &str, created: i64, status: &str, f: impl FnOnce(&mut Value)) -> String {
    event(UPDATED, &w.a_id, id, created, |v| {
        v["data"]["object"]["status"] = json!(status);
        f(v)
    })
}

async fn sent(app: &App, mailer: &fake::Mailer) -> Vec<smtp::Mail> {
    billing_mail::send_due(app).await;
    mailer.sent()
}

fn assert_plain(m: &smtp::Mail) {
    for p in PROVIDER {
        assert!(!m.subject.contains(p) && !m.body.contains(p), "{p} in {m:?}");
    }
    assert!(!m.body.contains(SECRET));
}

#[tokio::test]
async fn stripe_events_email_the_plans_person_once_each() {
    let w = world(true).await;
    let app = &w.app;
    let mailer = fake::install(app, Some(PUBLIC));
    let t = 1_795_000_000;

    // Subscribed: one email, however often Stripe delivers the event.
    let start = ada(&w, "evt_start", t, "active", |_| {});
    for _ in 0..3 {
        let (code, res) = deliver(w.port, &start, None).await;
        assert_eq!(code, 200, "{res}");
    }
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let m = &got[0];
    assert_eq!((m.to.as_str(), m.subject.as_str()), ("ada@example.com", "[SuperBot] Your Pro plan has started"));
    assert!(m.body.contains("It renews on 18 December 2026.") && m.body.contains(PLAN), "{}", m.body);
    assert_plain(m);
    assert_eq!(sent(app, &mailer).await.len(), 1, "sent once");
    let audited = audit(w.port, &w.admin, "action=billing.email_sent").await;
    assert_eq!(audited.len(), 1, "{audited:?}");
    let e = &audited[0];
    assert_eq!((e["actorId"].as_str(), e["onBehalfOf"].as_str(), e["targetId"].as_str()), (Some("billing"), Some(w.a_id.as_str()), Some(w.a_id.as_str())), "{e}");
    let d = &e["details"];
    assert_eq!((d["kind"].as_str(), d["eventId"].as_str(), d["to"].as_str(), d["attempts"].as_i64()), (Some("plan_started"), Some("evt_start"), Some("ada@example.com"), Some(1)), "{d}");

    // The card fails: said once, with where to fix it, while she keeps the plan.
    for (id, at) in [("evt_late", t + 100), ("evt_late", t + 100), ("evt_still_late", t + 200)] {
        deliver(w.port, &ada(&w, id, at, "past_due", |_| {}), None).await;
    }
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 2, "{got:?}");
    let m = &got[1];
    assert_eq!(m.subject, "[SuperBot] Your payment for the Pro plan didn't go through");
    assert!(m.body.contains(&format!("Manage billing on your plan:\n  {PLAN}")), "{}", m.body);
    assert_plain(m);
    assert_eq!(app.db.user(&w.a_id).unwrap().tier.as_deref(), Some("pro"));

    // Paid after all, then set to end at the period's end: said once, from either event.
    deliver(w.port, &ada(&w, "evt_paid", t + 300, "active", |_| {}), None).await;
    for (id, at) in [("evt_cancel", t + 400), ("evt_cancel_again", t + 500)] {
        deliver(w.port, &ada(&w, id, at, "active", |v| v["data"]["object"]["cancel_at_period_end"] = json!(true)), None).await;
    }
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[2].subject, "[SuperBot] Your Pro plan ends on 18 December 2026");
    assert!(got[2].body.contains("you move to the Starter plan"), "{}", got[2].body);

    // It ends.
    let end = event(DELETED, &w.a_id, "evt_end", t + 600, |_| {});
    deliver(w.port, &end, None).await;
    deliver(w.port, &end, None).await;
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 4, "{got:?}");
    assert_eq!(got[3].subject, "[SuperBot] Your Pro plan has ended");
    assert!(got[3].body.contains("You're on the Starter plan now"), "{}", got[3].body);
    got.iter().for_each(assert_plain);
    assert!(got.iter().all(|m| m.to == "ada@example.com"), "Bea's plan didn't change");
    let rows = app.db.billing_emails_of(&w.a_id, 20);
    assert_eq!(rows.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(), ["sent"; 4]);
    assert_eq!(audit(w.port, &w.admin, "action=billing.email_sent").await.len(), 4);
}

#[tokio::test]
async fn a_new_plan_changes_it_and_an_unpaid_one_ends_it_saying_why() {
    let w = world(true).await;
    let app = &w.app;
    let mailer = fake::install(app, Some(PUBLIC));
    let t = 1_795_000_000;
    let starter = |v: &mut Value| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly");
    deliver(w.port, &ada(&w, "evt_s", t, "active", starter), None).await;
    // Moved to Pro on the same subscription.
    deliver(w.port, &ada(&w, "evt_p", t + 100, "active", |_| {}), None).await;
    let got = sent(app, &mailer).await;
    assert_eq!(got.iter().map(|m| m.subject.as_str()).collect::<Vec<_>>(), ["[SuperBot] Your Starter plan has started", "[SuperBot] Your plan changed to Pro"]);
    assert!(got[1].body.contains("Your plan changed from Starter to Pro."), "{}", got[1].body);
    // Stripe gives up on the card.
    deliver(w.port, &ada(&w, "evt_u", t + 200, "unpaid", |_| {}), None).await;
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 3);
    assert!(got[2].body.contains("Your Pro plan has ended because its payment didn't go through."), "{}", got[2].body);
    // An admin's tier change isn't billing: no email.
    set_tier(&w, &w.a_id, json!("pro")).await;
    assert_eq!(sent(app, &mailer).await.len(), 3);
}

#[tokio::test]
async fn with_billing_emails_off_nothing_is_queued_or_sent() {
    let w = world(true).await;
    let (code, res) = deliver(w.port, &ada(&w, "evt_1", 1_795_000_000, "active", |_| {}), None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("tier_changed")), "{res}");
    assert!(w.app.db.billing_emails_of(&w.a_id, 10).is_empty());
    assert_eq!(billing_mail::send_due(&w.app).await, 0);
    let (_, me) = call(w.port, "GET", "/api/me/emails", &w.a, "").await;
    assert_eq!(parse(&me), json!({ "on": false, "usage": true }));
}

#[tokio::test]
async fn failed_sends_are_tried_again_then_given_up_and_audited() {
    let w = world(true).await;
    let app = &w.app;
    let mailer = fake::install(app, Some(PUBLIC));
    *mailer.fail.lock().unwrap() = Some("550 mailbox unavailable".into());
    deliver(w.port, &ada(&w, "evt_1", 1_795_000_000, "active", |_| {}), None).await;
    assert_eq!(billing_mail::send_due(app).await, 0);
    let row = &app.db.billing_emails_of(&w.a_id, 1)[0];
    assert_eq!((row.state.as_str(), row.attempts), ("pending", 1));
    assert!(row.next_at > db::now() + 50_000, "backs off: {row:?}");
    // Not tried again before its time.
    billing_mail::send_due(app).await;
    assert_eq!(app.db.billing_emails_of(&w.a_id, 1)[0].attempts, 1);
    for _ in 1..billing_mail::MAX_ATTEMPTS {
        app.db.billing_emails_due_now();
        billing_mail::send_due(app).await;
    }
    let row = &app.db.billing_emails_of(&w.a_id, 1)[0];
    assert_eq!((row.state.as_str(), row.attempts, row.reason.as_deref()), ("failed", billing_mail::MAX_ATTEMPTS, Some("550 mailbox unavailable")));
    let failed = audit(w.port, &w.admin, "action=billing.email_failed").await;
    assert_eq!(failed.len(), billing_mail::MAX_ATTEMPTS as usize);
    assert_eq!((failed[0]["outcome"].as_str(), failed[0]["details"]["retrying"].as_bool()), (Some("failure"), Some(false)), "the last gives up");
    assert_eq!(failed[1]["details"]["retrying"], true);
    // Given up for good: a working mail server later sends nothing more.
    *mailer.fail.lock().unwrap() = None;
    app.db.billing_emails_due_now();
    assert!(sent(app, &mailer).await.is_empty());

    // A send that fails once goes on the next try.
    *mailer.fail.lock().unwrap() = Some("421 try later".into());
    deliver(w.port, &ada(&w, "evt_2", 1_795_000_100, "past_due", |_| {}), None).await;
    billing_mail::send_due(app).await;
    *mailer.fail.lock().unwrap() = None;
    app.db.billing_emails_due_now();
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 1);
    assert_eq!(audit(w.port, &w.admin, "action=billing.email_sent").await[0]["details"]["attempts"], 2);
}

#[tokio::test]
async fn token_emails_go_once_a_period_unless_turned_off() {
    let w = world(true).await;
    let app = &w.app;
    let mailer = fake::install(app, Some(PUBLIC));
    // Pro: 5,000,000 tokens a period. Each run here uses `tokens` + 500.
    set_tier(&w, &w.a_id, json!("pro")).await;
    set_tier(&w, &w.b_id, json!("pro")).await;
    fake_claude_tokens(app, 3_000_000);
    let bot = app.db.create_bot_owned("Busy", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;
    assert!(sent(app, &mailer).await.is_empty(), "60% says nothing");
    tokens(app, 1_000_000);
    go(&w, &w.a, &bot.id).await;
    let got = sent(app, &mailer).await;
    assert_eq!(got.iter().map(|m| m.subject.as_str()).collect::<Vec<_>>(), ["[SuperBot] You've used 80% of this period's model tokens"]);
    assert!(got[0].body.contains("4,001,000 of the Pro plan's 5,000,000") && got[0].body.contains("turn off usage emails on your plan: https://bots.example.com/app/plan"), "{}", got[0].body);
    go(&w, &w.a, &bot.id).await;
    go(&w, &w.a, &bot.id).await;
    let got = sent(app, &mailer).await;
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[1].subject, "[SuperBot] You've used this period's model tokens");
    // Refused runs after that say nothing more.
    go(&w, &w.a, &bot.id).await;
    assert_eq!(sent(app, &mailer).await.len(), 2);

    // Bea turns usage emails off: hers are skipped and audited; her plan's still go.
    let (code, body) = call(w.port, "PUT", "/api/me/emails", &w.b, r#"{"usage":false}"#).await;
    assert_eq!((code, parse(&body)), (200, json!({ "on": true, "usage": false })), "{body}");
    let changed = audit(w.port, &w.admin, "action=billing.email_settings_updated").await;
    assert_eq!((changed.len(), changed[0]["details"]["usage"].clone()), (1, json!({ "from": true, "to": false })));
    call(w.port, "PUT", "/api/me/emails", &w.b, r#"{"usage":false}"#).await;
    assert_eq!(audit(w.port, &w.admin, "action=billing.email_settings_updated").await.len(), 1, "no change, no event");
    let (code, _) = call(w.port, "PUT", "/api/me/emails", &w.b, r#"{"usage":"no"}"#).await;
    assert_eq!(code, 400);
    tokens(app, 6_000_000);
    let hers = app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    go(&w, &w.b, &hers.id).await;
    assert_eq!(sent(app, &mailer).await.len(), 2);
    let skipped = audit(w.port, &w.admin, "action=billing.email_skipped").await;
    assert_eq!((skipped.len(), skipped[0]["details"]["reason"].as_str(), skipped[0]["details"]["kind"].as_str()), (1, Some("opted_out"), Some("tokens_used_up")), "{skipped:?}");
    let bea = event(UPDATED, &w.b_id, "evt_bea", 1_795_000_000, |v| {
        v["data"]["object"]["id"] = json!("sub_test_bea");
        v["data"]["object"]["customer"] = json!("cus_test_bea");
        v["data"]["object"]["status"] = json!("past_due");
    });
    deliver(w.port, &bea, None).await;
    let got = sent(app, &mailer).await;
    assert_eq!((got.len(), got[2].to.as_str(), got[2].subject.as_str()), (3, "bea@example.com", "[SuperBot] Your payment for the Pro plan didn't go through"));
    // The Plan screen's view says so too.
    let (_, me) = call(w.port, "GET", "/api/me/emails", &w.b, "").await;
    assert_eq!(parse(&me)["usage"], false);
}

/// Small: 1 MB of storage and the g6-standard-1 machine; big: g6-standard-2, sold as
/// the fixture's price.
const SIZED: &str = r#"{
  "default": "small",
  "tiers": [
    { "name": "small", "label": "Small", "routes": [{ "harness": "claude", "model": "claude-haiku-4-5" }],
      "limits": { "machineType": "g6-standard-1", "maxStorageMb": 1 }, "stripePrices": ["price_small_monthly"] },
    { "name": "big", "label": "Big", "routes": "any",
      "limits": { "machineType": "g6-standard-2" }, "stripePrices": ["price_pro_monthly"] }
  ]
}"#;

struct Sized {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
    mailer: Arc<fake::Mailer>,
    a_id: String,
    a: String,
}

async fn sized() -> Sized {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(|a| {
        a.machines = Arc::new(ControlPlane::for_tests(p));
        a.payments = Billing::with_secret(SECRET);
    })
    .await;
    app.tiers.set(Arc::new(Tiers::parse(SIZED, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    crate::tiers_http_tests::fake_claude(&app);
    let mailer = fake::install(&app, Some(PUBLIC));
    Sized { port, app, admin, fake, mailer, a_id, a }
}

impl Sized {
    async fn reconcile(&self) {
        let (code, body) = call(self.port, "POST", "/api/machines/reconcile", &self.admin, "").await;
        assert_eq!(code, 200, "{body}");
    }

    async fn machine(&self) -> crate::db::Machine {
        let (code, body) = call(self.port, "POST", &format!("/api/users/{}/machine", self.a_id), &self.admin, "{}").await;
        assert_eq!(code, 202, "{body}");
        for _ in 0..5 {
            self.reconcile().await;
            let m = self.app.db.user_machine(&self.a_id).unwrap();
            if m.state == MachineState::Running {
                return m;
            }
        }
        panic!("Ada's machine never ran");
    }

    fn fill(&self, bytes: usize) {
        let ws = self.app.workspace_for(&self.a_id).unwrap();
        std::fs::write(ws.join("big.bin"), vec![b'x'; bytes]).unwrap();
        self.app.storage.forget(&self.a_id);
    }

    fn moved_to(&self, id: &str, created: i64, price: &str) -> String {
        event(UPDATED, &self.a_id, id, created, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!(price))
    }
}

#[tokio::test]
async fn a_downgrade_that_waits_on_the_users_files_says_so() {
    let w = sized().await;
    let (code, body) = call(w.port, "PATCH", &format!("/api/users/{}", w.a_id), &w.admin, r#"{"tier":"big"}"#).await;
    assert_eq!(code, 200, "{body}");
    w.machine().await;
    w.fill(1_200_000);
    // Stripe moves her to small: the plan email says her computer is moving.
    deliver(w.port, &w.moved_to("evt_down", 1_795_000_000, "price_small_monthly"), None).await;
    let got = sent(&w.app, &w.mailer).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].subject, "[SuperBot] Your Small plan has started");
    assert!(got[0].body.contains("Your computer is moving to the Small plan's size. It may restart once while it does; nothing on it is lost."), "{}", got[0].body);
    // The reconciler finds her files don't fit: she hears what to do, once.
    for _ in 0..2 {
        w.reconcile().await;
    }
    let got = sent(&w.app, &w.mailer).await;
    assert_eq!(got.len(), 2, "{got:?}");
    let m = &got[1];
    assert_eq!(m.subject, "[SuperBot] Your computer is waiting to move to the Small size");
    assert!(m.body.contains("Storage is 1.2 MB used of the Small plan's 1 MB.") && m.body.contains(PLAN), "{}", m.body);
    assert_plain(m);
    assert!(!m.body.contains("g6-standard"), "no provider plans: {}", m.body);
    let rows = w.app.db.billing_emails_of(&w.a_id, 5);
    assert_eq!((rows[0].kind.as_str(), rows[0].event_id.as_deref()), ("resize_waiting", Some("evt_down")));
}

#[tokio::test]
async fn an_upgrade_the_provider_refuses_says_an_admin_was_told() {
    let w = sized().await;
    w.machine().await;
    w.fake.fail_next("resize", ProviderError::Api { status: 400, message: "plan unavailable in region".into() });
    deliver(w.port, &w.moved_to("evt_up", 1_795_000_000, "price_pro_monthly"), None).await;
    w.reconcile().await;
    w.reconcile().await;
    let got = sent(&w.app, &w.mailer).await;
    let subjects: Vec<&str> = got.iter().map(|m| m.subject.as_str()).collect();
    assert_eq!(subjects, ["[SuperBot] Your Big plan has started", "[SuperBot] Your computer couldn't move to the Big size"], "{got:?}");
    assert!(got[1].body.contains("an admin has been told") && !got[1].body.contains("region"), "no provider errors: {}", got[1].body);
    // An admin's resize isn't billing's to email about.
    let (code, body) = call(w.port, "PATCH", &format!("/api/users/{}", w.a_id), &w.admin, r#"{"tier":"small"}"#).await;
    assert_eq!(code, 200, "{body}");
    w.fake.fail_next("resize", ProviderError::Api { status: 400, message: "nope".into() });
    w.reconcile().await;
    assert_eq!(sent(&w.app, &w.mailer).await.len(), 2);
}

#[tokio::test]
async fn storage_emails_go_once_a_period() {
    let w = sized().await;
    let bot = w.app.db.create_bot_owned("Files", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let path = format!("/api/bots/{}/messages", bot.id);
    let ask = || call(w.port, "POST", &path, &w.a, r#"{"text":"go"}"#);
    w.fill(950_000);
    for n in 1..=2 {
        assert_eq!(ask().await.0, 202);
        crate::billing_http_tests::replies(&w.app, &bot.id, 0, n).await;
    }
    let got = sent(&w.app, &w.mailer).await;
    assert_eq!(got.len(), 1, "once, however many runs: {got:?}");
    assert!(got[0].subject.starts_with("[SuperBot] Your storage is 9") && got[0].subject.ends_with("% full"), "{}", got[0].subject);
    w.fill(1_100_000);
    for _ in 0..2 {
        assert_eq!(ask().await.0, 403);
    }
    let got = sent(&w.app, &w.mailer).await;
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[1].subject, "[SuperBot] Your storage is full");
    assert!(got[1].body.contains("1.1 MB of the Small plan's 1 MB"), "{}", got[1].body);
}

#[tokio::test]
async fn bots_have_no_email_settings_and_the_plan_view_shows_them() {
    let w = world(true).await;
    fake::install(&w.app, Some(PUBLIC));
    let bot = w.app.db.create_bot_owned("Helper", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let (code, _) = call(w.port, "PUT", "/api/me/emails", &w.bots.auth(&bot.id), r#"{"usage":false}"#).await;
    assert_eq!(code, 403);
    assert!(w.app.db.usage_emails(&w.a_id));
    let (code, body) = call(w.port, "GET", "/api/me/emails", &w.a, "").await;
    assert_eq!((code, parse(&body)), (200, json!({ "on": true, "usage": true })));
}

#[tokio::test]
async fn smtp_sends_billing_emails_one_per_message() {
    let w = world(true).await;
    let server = smtp::fake::start(smtp::fake::Options::default()).await;
    let mail = smtp::Smtp::for_test("127.0.0.1", server.port, smtp::Tls::None, None, None);
    let _ = w.app.billing_mail.set(Arc::new(billing_mail::BillingMail::new(Arc::new(mail), Some(PUBLIC))));
    deliver(w.port, &ada(&w, "evt_1", 1_795_000_000, "past_due", |_| {}), None).await;
    assert_eq!(billing_mail::send_due(&w.app).await, 2);
    let got = server.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].from.as_str(), got[0].to.clone()), ("bots@example.com", vec!["ada@example.com".to_string()]));
    assert!(got[0].headers.contains("Subject: [SuperBot] Your Pro plan has started"), "{}", got[0].headers);
    assert!(got[1].body.contains(PLAN), "{}", got[1].body);
}
