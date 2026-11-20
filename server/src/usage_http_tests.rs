//! Billing-period usage and token metering (ADR 0048) on the real router: each run's
//! tokens are recorded for its Bot's owner, or recorded as unknown; people see only
//! their own usage and admins everyone's; the token limit refuses runs in plain words
//! and is audited; a paid subscription sets the period; and tokens go to a Stripe meter
//! only when it's configured, here a fake on loopback. Nothing talks to Stripe.

use crate::acl::Visibility;
use crate::billing::{self, Billing};
use crate::billing_http_tests::{audit, deliver, event, fake_stripe, set_tier, world, world_with, World, KEY, PUBLIC, SECRET, UPDATED};
use crate::tests::call;
use crate::*;

/// Claude Code as far as usage goes: names its model, answers, and reports the tokens
/// in `bin/tokens` (input; plus 200 output and 300 cache reads), or none when it's 0.
fn fake_claude_tokens(app: &App, input: u64) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let script = r#"#!/bin/sh
model=default
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model=$2; shift ;;
    --) break ;;
  esac
  shift
done
printf '%s\n' "{\"type\":\"system\",\"subtype\":\"init\",\"model\":\"$model\"}"
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"model=$model\"}]}}"
tokens=$(cat "$(dirname "$0")/tokens")
if [ "$tokens" -gt 0 ]; then
  printf '%s\n' "{\"type\":\"result\",\"is_error\":false,\"result\":\"ok\",\"usage\":{\"input_tokens\":$tokens,\"output_tokens\":200,\"cache_read_input_tokens\":300,\"cache_creation_input_tokens\":0}}"
else
  printf '%s\n' "{\"type\":\"result\",\"is_error\":false,\"result\":\"ok\"}"
fi
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    tokens(app, input);
}

fn tokens(app: &App, input: u64) {
    std::fs::write(app.cfg.bin_dir.join("tokens"), input.to_string()).unwrap();
}

/// Sends "go" to `bot` as `who` and waits until its run is over and audited.
async fn go(w: &World, who: &str, bot: &str) {
    let before = audit(w.port, &w.admin, &format!("bot={bot}")).await.len();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{bot}/messages"), who, r#"{"text":"go"}"#).await;
    assert_eq!(code, 202, "{body}");
    for _ in 0..300 {
        let now = audit(w.port, &w.admin, &format!("bot={bot}")).await;
        let done = now.len() > before && now.iter().take(now.len() - before).any(|e| matches!(e["action"].as_str(), Some("bot.run_finished" | "bot.run_refused")));
        if done && !w.app.is_running(bot) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{bot} didn't finish");
}

async fn get(w: &World, path: &str, who: &str) -> (u16, Value) {
    let (code, body) = call(w.port, "GET", path, who, "").await;
    (code, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn tokens_are_recorded_per_run_and_shown_only_to_their_owner() {
    let w = world(false).await;
    let app = &w.app;
    fake_claude_tokens(app, 1000);
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;

    // The run's tokens, for Ada, this calendar month (she has no subscription).
    let (code, mine) = get(&w, "/api/me/usage", &w.a).await;
    assert_eq!(code, 200, "{mine}");
    let t = &mine["tokens"];
    assert_eq!((t["input"].as_u64(), t["output"].as_u64(), t["cacheRead"].as_u64(), t["total"].as_u64(), t["runs"].as_u64()), (Some(1000), Some(200), Some(300), Some(1500), Some(1)), "{mine}");
    assert_eq!((mine["user"].as_str(), mine["period"]["source"].as_str(), mine["period"]["key"].as_str()), (Some(w.a_id.as_str()), Some("calendar"), Some(tiers::period(db::now()).as_str())));
    assert_eq!((mine["runs"]["used"].as_u64(), mine["runs"]["limit"].as_u64()), (Some(1), Some(3)));
    assert_eq!((mine["byBot"][0]["bot"].as_str(), mine["byBot"][0]["name"].as_str(), mine["byBot"][0]["total"].as_u64()), (Some(bot.id.as_str()), Some("Ada's"), Some(1500)));
    // Starter picks the model, so Ada doesn't see model names (ADR 0033).
    assert!(mine.get("byModel").is_none() && !mine.to_string().contains("claude-haiku"), "{mine}");
    // Her plan shows the tokens too.
    let (_, plan) = get(&w, "/api/me/tier", &w.a).await;
    assert_eq!((plan["usage"]["tokens"].as_u64(), plan["usage"]["periodSource"].as_str()), (Some(1500), Some("calendar")));

    // The run's audit says what it used; one run id ties both events to the rows.
    let finished = audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await;
    let invoked = audit(w.port, &w.admin, &format!("action=harness.invoked&bot={}", bot.id)).await;
    let run_id = finished[0]["details"]["runId"].as_str().unwrap().to_string();
    assert_eq!((finished[0]["details"]["usage"].as_u64(), invoked[0]["details"]["runId"].as_str()), (Some(1500), Some(run_id.as_str())));

    // Bea sees only her own (none), and nobody else's, by any route.
    let (code, hers) = get(&w, "/api/me/usage", &w.b).await;
    assert_eq!((code, hers["user"].as_str(), hers["tokens"]["total"].as_u64(), hers["byBot"].clone()), (200, Some(w.b_id.as_str()), Some(0), json!([])), "{hers}");
    assert!(!hers.to_string().contains(&bot.id) && !hers.to_string().contains(&w.a_id));
    for path in [format!("/api/users/{}/usage", w.a_id), "/api/usage".to_string(), "/api/users/ada@example.com/usage".to_string()] {
        let (code, body) = get(&w, &path, &w.b).await;
        assert_eq!(code, 403, "{path}: {body}");
        assert!(!body.to_string().contains("1500"));
    }
    // A Bot's token isn't a person.
    let bot_key = w.bots.auth(&bot.id);
    assert_eq!(get(&w, "/api/me/usage", &bot_key).await.0, 403);

    // Admins see Ada's, models and all, and everyone's in the usage list.
    let (code, hers) = get(&w, &format!("/api/users/{}/usage", w.a_id), &w.admin).await;
    assert_eq!((code, hers["tokens"]["total"].as_u64()), (200, Some(1500)), "{hers}");
    assert_eq!((hers["byModel"][0]["model"].as_str(), hers["byModel"][0]["total"].as_u64()), (Some("claude-haiku-4-5"), Some(1500)), "{hers}");
    assert_eq!(get(&w, "/api/users/nobody@example.com/usage", &w.admin).await.0, 404);
    let (_, all) = get(&w, "/api/usage", &w.admin).await;
    let row = all["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == w.a_id.as_str()).unwrap();
    assert_eq!(row["plan"]["usage"]["tokens"].as_u64(), Some(1500));

    // A harness that reports no tokens: the run is recorded as unknown, not as free.
    tokens(app, 0);
    go(&w, &w.a, &bot.id).await;
    let (_, mine) = get(&w, "/api/me/usage", &w.a).await;
    assert_eq!((mine["tokens"]["total"].as_u64(), mine["tokens"]["runs"].as_u64(), mine["tokens"]["unreportedRuns"].as_u64()), (Some(1500), Some(2), Some(1)), "{mine}");
    let finished = audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await;
    assert_eq!(finished[0]["details"]["usage"], Value::Null);

    // An admin gives the Bot to Bea, who renames it: Ada keeps its usage, not its new name.
    let (code, body) = call(w.port, "PATCH", &format!("/api/bots/{}/access", bot.id), &w.admin, &json!({ "owner": w.b_id, "visibility": "private" }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    let (code, body) = call(w.port, "PATCH", &format!("/api/bots/{}", bot.id), &w.b, r#"{"name":"Bea's secret project"}"#).await;
    assert_eq!(code, 200, "{body}");
    let (_, mine) = get(&w, "/api/me/usage", &w.a).await;
    assert_eq!((mine["byBot"][0]["bot"].as_str(), mine["byBot"][0]["name"].clone(), mine["tokens"]["total"].as_u64()), (Some(bot.id.as_str()), Value::Null, Some(1500)), "{mine}");
    assert!(!mine.to_string().contains("secret project"));
    let (_, hers) = get(&w, &format!("/api/users/{}/usage", w.a_id), &w.admin).await;
    assert_eq!(hers["byBot"][0]["name"], "Bea's secret project");
}

#[tokio::test]
async fn the_token_limit_refuses_runs_in_plain_words() {
    let w = world(false).await;
    let app = &w.app;
    // Pro: 5,000,000 tokens a period. One big run uses them up, and more.
    set_tier(&w, &w.a_id, json!("pro")).await;
    set_tier(&w, &w.b_id, json!("pro")).await;
    fake_claude_tokens(app, 5_999_500);
    let bot = app.db.create_bot_owned("Busy", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;
    // The run that crossed the limit is audited, for Ada, by billing.
    let reached = audit(w.port, &w.admin, "action=usage.token_limit_reached").await;
    assert_eq!(reached.len(), 1, "{reached:?}");
    let r = &reached[0];
    assert_eq!((r["actorId"].as_str(), r["onBehalfOf"].as_str(), r["details"]["limit"].as_u64(), r["details"]["used"].as_u64()), (Some("billing"), Some(w.a_id.as_str()), Some(5_000_000), Some(6_000_000)), "{r}");

    // The next runs are refused, audited and answered each time, and no run is counted.
    tokens(app, 10);
    let runs_before = app.db.runs_used(&w.a_id, &tiers::period(db::now()));
    for _ in 0..2 {
        go(&w, &w.a, &bot.id).await;
    }
    let refused = audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    assert_eq!(refused.len(), 2, "{refused:?}");
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["limit"].as_u64(), d["used"].as_u64(), d["tier"].as_str()), (Some("tier_token_limit"), Some(5_000_000), Some(6_000_000), Some("pro")), "{d}");
    assert_eq!(refused[0]["outcome"], "denied");
    let errors: Vec<String> = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.error).map(|m| m.text).collect();
    let said = "The Pro plan allows 5,000,000 model tokens a month, and this month's are used up. More start on the 1st (UTC).";
    assert_eq!(errors, [said, said]);
    // A routine that keeps firing into the used-up period: audited each time, and not
    // said again while the last bubble says it.
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "Sum up my email");
    for _ in 0..2 {
        cron::fire(app, &r, db::now());
        for _ in 0..300 {
            if !app.is_running(&bot.id) && app.db.messages(&bot.id, 50).iter().filter(|m| m.role == "routine").all(|m| m.status.as_deref() != Some("queued")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    for _ in 0..300 {
        if audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", bot.id)).await.len() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", bot.id)).await.len(), 4);
    let errors = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.error).count();
    assert_eq!(errors, 2, "the last bubble already says it");
    assert_eq!(app.db.runs_used(&w.a_id, &tiers::period(db::now())), runs_before);
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 1);
    // Admins see Ada over it.
    let (_, all) = get(&w, "/api/usage", &w.admin).await;
    let over = |id: &str| all["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == id).unwrap()["over"].clone();
    assert_eq!(over(&w.a_id), json!(["monthlyTokens"]));

    // Bea's tokens are her own: her Bot still runs.
    let hers = app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    go(&w, &w.b, &hers.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", hers.id)).await.len(), 1);
    assert_eq!(over(&w.b_id), json!([]));

    // Another tier with no token limit: Ada runs again.
    set_tier(&w, &w.a_id, json!("self-host")).await;
    go(&w, &w.a, &bot.id).await;
    assert_eq!(audit(w.port, &w.admin, &format!("action=bot.run_finished&bot={}", bot.id)).await.len(), 2);
}

#[tokio::test]
async fn a_paid_subscription_sets_the_billing_period() {
    let w = world(true).await;
    fake_claude_tokens(&w.app, 1000);
    let body = event(UPDATED, &w.a_id, "evt_1", 1_795_000_000, |_| {});
    assert_eq!(deliver(w.port, &body, None).await.0, 200);
    let sub = w.app.db.subscription(&w.a_id).unwrap();
    assert_eq!((sub.period_start, sub.period_end), (Some(1_794_990_000), Some(1_797_582_000)));
    let (_, mine) = get(&w, "/api/me/usage", &w.a).await;
    let p = &mine["period"];
    let (start, end, now) = (p["start"].as_i64().unwrap(), p["end"].as_i64().unwrap(), db::now());
    assert_eq!(p["source"], "subscription", "{mine}");
    assert!(start <= now && now < end && end - start <= 31 * 86_400_000, "{p}");
    // Runs count in the same period, so a new subscriber's runs start from their period.
    let bot = w.app.db.create_bot_owned("Paid", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;
    let (_, mine) = get(&w, "/api/me/usage", &w.a).await;
    assert_eq!((mine["runs"]["used"].as_u64(), mine["tokens"]["total"].as_u64()), (Some(1), Some(1500)), "{mine}");
    assert_eq!(w.app.db.runs_used(&w.a_id, p["key"].as_str().unwrap()), 1);
    // Bea has no subscription: the calendar month.
    let (_, hers) = get(&w, "/api/me/usage", &w.b).await;
    assert_eq!(hers["period"]["source"], "calendar");
}

#[tokio::test]
async fn tokens_go_to_a_stripe_meter_only_when_one_is_set() {
    // Checkout on, metering off (the default): nothing is queued, nothing is sent.
    let (url, stripe) = fake_stripe().await;
    let w = world_with(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC))).await;
    assert!(w.app.meter.get().is_none());
    fake_claude_tokens(&w.app, 1000);
    w.app.db.link_customer("evt_c1", "checkout.session.completed", &w.a_id, "stripe", "cus_test_ada", "checkout").unwrap();
    let bot = w.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;
    assert!(w.app.db.pending_meter(100).is_empty());
    assert!(stripe.seen().iter().all(|s| s.path != "/v1/billing/meter_events"));

    // STRIPE_METER_EVENT set: each run with tokens, for someone with a customer, is sent once.
    let (url, stripe) = fake_stripe().await;
    let w = world_with(Some(Billing::with_metering(SECRET, KEY, &url, PUBLIC, "superbot_tokens"))).await;
    let meter = w.app.meter.get().cloned().expect("metering on");
    // Pro: no cap on runs, so Ada can run as often as this needs.
    set_tier(&w, &w.a_id, json!("pro")).await;
    fake_claude_tokens(&w.app, 1000);
    w.app.db.link_customer("evt_c1", "checkout.session.completed", &w.a_id, "stripe", "cus_test_ada", "checkout").unwrap();
    let bot = w.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    go(&w, &w.a, &bot.id).await;
    // Bea has no Stripe customer, and an unknown run has nothing to send: neither queued.
    let hers = w.app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    go(&w, &w.b, &hers.id).await;
    tokens(&w.app, 0);
    go(&w, &w.a, &bot.id).await;
    let pending = w.app.db.pending_meter(100);
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(billing::send_meter_events(&w.app, &meter).await, 1);
    let sent: Vec<_> = stripe.seen().into_iter().filter(|s| s.path == "/v1/billing/meter_events").collect();
    assert_eq!(sent.len(), 1);
    let s = &sent[0];
    let row = &pending[0];
    let id = format!("superbot-{}-{}", row.run_id, row.id);
    assert_eq!(
        (s.get("event_name"), s.get("payload[stripe_customer_id]"), s.get("payload[value]"), s.get("identifier"), s.get("timestamp")),
        (Some("superbot_tokens"), Some("cus_test_ada"), Some("1500"), Some(id.as_str()), Some((row.at / 1000).to_string().as_str()))
    );
    assert_eq!((s.auth.as_str(), s.version.as_str()), (format!("Bearer {KEY}").as_str(), crate::stripe::VERSION));
    assert!(!s.key.is_empty(), "an idempotency key");
    // Sent once: the next pass has nothing to do.
    assert_eq!(billing::send_meter_events(&w.app, &meter).await, 0);
    assert!(w.app.db.pending_meter(100).is_empty());

    // Stripe refuses one: it's marked failed and audited, not dropped silently.
    tokens(&w.app, 1000);
    go(&w, &w.a, &bot.id).await;
    stripe.reply(400, json!({ "error": { "type": "invalid_request_error", "code": "timestamp_too_far_in_past" } }));
    assert_eq!(billing::send_meter_events(&w.app, &meter).await, 0);
    assert!(w.app.db.pending_meter(100).is_empty());
    let failed = audit(w.port, &w.admin, "action=billing.meter_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!((failed[0]["onBehalfOf"].as_str(), failed[0]["outcome"].as_str(), failed[0]["details"]["usage"].as_u64()), (Some(w.a_id.as_str()), Some("failure"), Some(1500)));
    assert!(failed[0]["details"]["error"].as_str().unwrap().contains("400"), "{}", failed[0]);

    // Stripe down: kept, and tried again next pass.
    go(&w, &w.a, &bot.id).await;
    for _ in 0..2 {
        stripe.reply(503, json!({ "error": { "type": "api_error" } }));
    }
    assert_eq!(billing::send_meter_events(&w.app, &meter).await, 0);
    assert_eq!(w.app.db.pending_meter(100).len(), 1);
    assert_eq!(billing::send_meter_events(&w.app, &meter).await, 1);
}

#[test]
fn the_meter_is_off_unless_configured_and_needs_a_key() {
    use crate::secrets::env::EnvStore;
    let store = |pairs: &[(&str, &str)]| EnvStore::fixed(pairs);
    let var = |meter: &'static str| move |k: &str| match k {
        "STRIPE_METER_EVENT" => meter.to_string(),
        "PUBLIC_URL" => PUBLIC.to_string(),
        _ => String::new(),
    };
    let both = [("STRIPE_WEBHOOK_SECRET", SECRET), ("STRIPE_SECRET_KEY", KEY)];
    assert!(Billing::from_env(&store(&both), &var("")).unwrap().meter().is_none(), "off by default");
    assert!(Billing::from_env(&store(&both), &var("superbot_tokens")).unwrap().meter().is_some());
    let err = Billing::from_env(&store(&[("STRIPE_WEBHOOK_SECRET", SECRET)]), &var("superbot_tokens")).err().unwrap();
    assert!(err.contains("STRIPE_METER_EVENT needs STRIPE_SECRET_KEY"), "{err}");
    assert!(Billing::from_env(&store(&[]), &var("superbot_tokens")).is_err());
    assert!(Billing::from_env(&store(&both), &var("bad name!")).err().unwrap().contains("STRIPE_METER_EVENT"));
    assert!(billing::describe(true, true, true, &tiers::Tiers::self_host()).contains("Stripe meter"));
    assert!(!billing::describe(true, true, false, &tiers::Tiers::self_host()).contains("meter"));
}
