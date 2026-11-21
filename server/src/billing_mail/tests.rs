use super::*;
use crate::tiers::EXAMPLE;

const LINK: &str = "https://bots.example.com/app/plan";
/// What a provider id looks like: none may reach an email.
const PROVIDER: [&str; 7] = ["sub_", "cus_", "price_", "evt_", "whsec_", "sk_", "billing.stripe.com"];

fn tiers() -> Tiers {
    Tiers::parse(EXAMPLE, None).unwrap()
}

fn sub(status: &str, tier: Option<&str>) -> Subscription {
    Subscription {
        user_id: "u_ada".into(),
        provider: "stripe".into(),
        customer_id: Some("cus_test_ada".into()),
        subscription_id: "sub_test_ada".into(),
        status: status.into(),
        price_id: Some("price_pro_monthly".into()),
        tier: tier.map(String::from),
        period_start: Some(1_794_990_000),
        period_end: Some(1_797_582_000),
        started: 1_794_990_000,
        event_created: 1_795_000_000,
        updated_at: 0,
    }
}

fn emails(row: &Subscription, applied: Applied, before: Option<&Subscription>, paying_before: Option<&Subscription>, cancel_at: Option<i64>, ending: bool) -> Vec<NewEmail> {
    let ev = SubEvent { event_id: "evt_1", row, cancel_at, ending };
    for_subscription(&ev, &Change { applied: &applied, before, paying_before }, &tiers())
}

fn kinds(e: &[NewEmail]) -> Vec<Kind> {
    e.iter().map(|e| e.kind).collect()
}

fn changed(from: Option<&str>, to: Option<&str>) -> Applied {
    Applied::Changed { from: from.map(String::from), to: to.map(String::from) }
}

fn assert_plain(r: &Rendered) {
    assert!(r.subject.starts_with("[SuperBot] ") && !r.subject.contains(['\r', '\n']), "{r:?}");
    for p in PROVIDER {
        assert!(!r.subject.contains(p) && !r.body.contains(p), "{p} in {r:?}");
    }
}

#[test]
fn kinds_round_trip_and_only_usage_emails_can_be_turned_off() {
    for k in KINDS {
        assert_eq!(Kind::parse(k.as_str()), Some(k));
    }
    assert_eq!(Kind::parse("receipt"), None);
    let optional: Vec<Kind> = KINDS.into_iter().filter(|k| !k.essential()).collect();
    assert_eq!(optional, [Kind::TokensLow, Kind::TokensUsedUp, Kind::StorageLow, Kind::StorageFull]);
}

#[test]
fn a_first_paying_subscription_starts_a_plan_and_a_second_changes_it() {
    let pro = sub("active", Some("pro"));
    let e = emails(&pro, changed(None, Some("pro")), None, None, None, false);
    assert_eq!(kinds(&e), [Kind::PlanStarted]);
    assert_eq!(e[0].key, "stripe:evt_1:plan_started");
    assert_eq!(e[0].event_id.as_deref(), Some("evt_1"));
    assert_eq!(e[0].facts, Facts { plan: Some("Pro".into()), from_plan: Some("Starter".into()), until: Some(1_797_582_000_000), ..Default::default() });
    // A plan from an admin before doesn't count as paying: it still starts.
    assert_eq!(kinds(&emails(&pro, changed(Some("starter"), Some("pro")), None, None, None, false)), [Kind::PlanStarted]);
    let old = Subscription { subscription_id: "sub_test_old".into(), tier: Some("starter".into()), ..sub("active", Some("starter")) };
    let e = emails(&pro, changed(Some("starter"), Some("pro")), None, Some(&old), None, false);
    assert_eq!(kinds(&e), [Kind::PlanChanged]);
    assert_eq!((e[0].facts.from_plan.as_deref(), e[0].facts.plan.as_deref()), (Some("Starter"), Some("Pro")));
    // No facts carry a provider id.
    let facts = serde_json::to_string(&e[0].facts).unwrap();
    assert!(PROVIDER.iter().all(|p| !facts.contains(p)), "{facts}");
}

#[test]
fn an_ending_says_which_plan_ended_and_whether_payments_failed() {
    let pro = sub("active", Some("pro"));
    let e = emails(&sub("canceled", None), changed(Some("pro"), None), Some(&pro), Some(&pro), None, true);
    assert_eq!(kinds(&e), [Kind::PlanEnded]);
    assert_eq!(e[0].facts, Facts { plan: Some("Pro".into()), next_plan: Some("Starter".into()), ..Default::default() });
    let e = emails(&sub("unpaid", None), changed(Some("pro"), None), Some(&pro), Some(&pro), None, true);
    assert_eq!(e[0].facts.why.as_deref(), Some("unpaid"));
    // Ended, but another subscription pays: no email.
    assert!(emails(&sub("canceled", None), Applied::Superseded, Some(&pro), Some(&pro), None, true).is_empty());
}

#[test]
fn a_payment_fails_once_per_move_into_past_due() {
    let active = sub("active", Some("pro"));
    let late = sub("past_due", Some("pro"));
    let e = emails(&late, Applied::Unchanged, Some(&active), Some(&active), None, false);
    assert_eq!(kinds(&e), [Kind::PaymentFailed]);
    assert_eq!((e[0].key.as_str(), e[0].facts.plan.as_deref()), ("stripe:evt_1:payment_failed", Some("Pro")));
    // Still past due on a later event: said already.
    assert!(emails(&late, Applied::Unchanged, Some(&late), Some(&late), None, false).is_empty());
    // First seen past due (its earlier events lost): said.
    assert_eq!(kinds(&emails(&late, changed(None, Some("pro")), None, None, None, false)), [Kind::PlanStarted, Kind::PaymentFailed]);
    // A replaced subscription, or one that pays for no plan, says nothing.
    assert!(emails(&late, Applied::Superseded, Some(&active), Some(&active), None, false).is_empty());
    assert!(emails(&sub("past_due", None), Applied::Unchanged, Some(&active), None, None, false).is_empty());
}

#[test]
fn a_scheduled_cancellation_is_said_once_per_subscription_and_date() {
    let pro = sub("active", Some("pro"));
    let e = emails(&pro, Applied::Unchanged, Some(&pro), Some(&pro), Some(1_797_582_000), false);
    assert_eq!(kinds(&e), [Kind::PlanEnding]);
    assert_eq!(e[0].key, "stripe:sub_test_ada:plan_ending:1797582000", "the same key from any event");
    assert_eq!(e[0].facts, Facts { plan: Some("Pro".into()), next_plan: Some("Starter".into()), until: Some(1_797_582_000_000), ..Default::default() });
    // The ending itself, or a subscription that isn't the plan, isn't "ending".
    assert!(emails(&sub("canceled", None), changed(Some("pro"), None), Some(&pro), Some(&pro), Some(1_797_582_000), true).iter().all(|e| e.kind != Kind::PlanEnding));
    assert!(emails(&pro, Applied::Superseded, Some(&pro), Some(&pro), Some(1_797_582_000), false).is_empty());
}

#[test]
fn events_that_did_nothing_send_nothing() {
    let pro = sub("past_due", Some("pro"));
    for a in [Applied::Duplicate, Applied::Stale, Applied::OtherUser, Applied::CustomerOfAnotherUser] {
        assert!(emails(&pro, a, None, None, Some(1_797_582_000), false).is_empty());
    }
    assert!(emails(&sub("active", Some("pro")), Applied::Unchanged, Some(&sub("active", Some("pro"))), None, None, false).is_empty());
}

#[test]
fn every_email_is_plain_text_with_a_link_and_no_provider_details() {
    let f = Facts {
        plan: Some("Pro".into()),
        from_plan: Some("Starter".into()),
        next_plan: Some("Starter".into()),
        until: Some(1_797_582_000_000),
        used: Some(4_000_500),
        limit: Some(5_000_000),
        why: None,
        message: Some("Storage is 1.2 MB used of the Small plan's 1 MB.".into()),
    };
    for k in KINDS {
        let r = render(k, &f, Some(LINK), None);
        assert_plain(&r);
        assert!(r.body.contains(LINK), "{k:?}: {}", r.body);
        assert!(r.body.contains("Pro") || r.subject.contains("Pro") || !matches!(k, Kind::PlanStarted | Kind::PlanChanged), "{r:?}");
        // Usage emails say how to stop them; the rest can't be stopped.
        assert_eq!(r.body.contains("turn off usage emails"), !k.essential(), "{k:?}: {}", r.body);
        // Without a public address, they still say where to look.
        let bare = render(k, &f, None, None);
        assert_plain(&bare);
        assert!(!bare.body.contains("https://") && bare.body.contains("in SuperBot"), "{k:?}: {}", bare.body);
    }
    let r = render(Kind::PlanStarted, &f, Some(LINK), None);
    assert_eq!(r.subject, "[SuperBot] Your Pro plan has started");
    assert!(r.body.contains("It renews on 18 December 2026."), "{}", r.body);
    let r = render(Kind::PaymentFailed, &f, Some(LINK), None);
    assert_eq!(r.subject, "[SuperBot] Your payment for the Pro plan didn't go through");
    assert!(r.body.contains(&format!("choose Manage billing on your plan:\n  {LINK}")), "{}", r.body);
    assert_eq!(render(Kind::PlanEnding, &f, Some(LINK), None).subject, "[SuperBot] Your Pro plan ends on 18 December 2026");
    let ended = render(Kind::PlanEnded, &Facts { why: Some("unpaid".into()), ..f.clone() }, Some(LINK), None);
    assert!(ended.body.contains("because its payment didn't go through") && ended.body.contains("on the Starter plan now"), "{}", ended.body);
    let low = render(Kind::TokensLow, &f, Some(LINK), None);
    assert_eq!(low.subject, "[SuperBot] You've used 80% of this period's model tokens");
    assert!(low.body.contains("4,000,500 of the Pro plan's 5,000,000"), "{}", low.body);
    let storage = render(Kind::StorageLow, &Facts { used: Some(950_000), limit: Some(1_000_000), ..f.clone() }, Some(LINK), None);
    assert!(storage.subject.ends_with("95% full") && storage.body.contains("950 KB of the Pro plan's 1 MB"), "{storage:?}");
    assert!(render(Kind::ResizeWaiting, &f, Some(LINK), None).body.contains("Small plan's 1 MB"));
}

#[test]
fn the_computer_line_goes_in_the_body_and_labels_cant_break_the_subject() {
    let f = Facts { plan: Some("Pro\r\nBcc: someone@example.com".into()), ..Default::default() };
    let r = render(Kind::PlanChanged, &f, Some(LINK), Some("Your computer is now the Pro plan's size."));
    assert_eq!(r.subject, "[SuperBot] Your plan changed to Pro Bcc: someone@example.com");
    assert!(r.body.contains("\nYour computer is now the Pro plan's size.\n"), "{}", r.body);
}

#[test]
fn billing_emails_are_off_unless_billing_and_smtp_are_on() {
    let smtp = smtp::Smtp::for_test("127.0.0.1", 25, smtp::Tls::None, None, None);
    let vars = |v: &'static str| move |k: &str| if k == ENV { v.to_string() } else { String::new() };
    // A self-hosted server: billing off, so off, whatever SMTP is.
    let (m, said) = configured(&vars(""), false, Some(&smtp), None).unwrap();
    assert!(m.is_none() && said.contains("billing is off"), "{said}");
    let (m, said) = configured(&vars(""), true, None, None).unwrap();
    assert!(m.is_none() && said.contains("SMTP_HOST"), "{said}");
    assert!(configured(&vars("on"), true, None, None).err().unwrap().contains("SMTP_HOST"));
    let (m, said) = configured(&vars("off"), true, Some(&smtp), None).unwrap();
    assert!(m.is_none() && said.contains("off"), "{said}");
    let (m, said) = configured(&vars(""), true, Some(&smtp), Some("https://bots.example.com/")).unwrap();
    assert_eq!(m.unwrap().plan_link.as_deref(), Some(LINK));
    assert!(said.starts_with("on, through 127.0.0.1:25") && !said.contains("without links"), "{said}");
    let (_, said) = configured(&vars("on"), true, Some(&smtp), None).unwrap();
    assert!(said.contains("without links"), "{said}");
    assert!(configured(&vars("sometimes"), true, Some(&smtp), None).err().unwrap().contains(ENV));
}

#[test]
fn failed_sends_back_off_then_stop() {
    assert_eq!([1, 2, 3, 4, 5].map(backoff_ms), [60_000, 240_000, 960_000, 3_840_000, 3_840_000]);
}

#[tokio::test]
async fn without_billing_emails_nothing_is_queued() {
    let app = crate::runner::test_app();
    let tier = app.tier_of("u_nobody").clone();
    let e = NewEmail { key: "k".into(), user_id: "u_nobody".into(), kind: Kind::StorageFull, facts: Facts::default(), event_id: None };
    assert!(!queue(&app, e));
    storage(&app, "u_nobody", &tier, 10, 1, true);
    assert_eq!(send_due(&app).await, 0);
    assert!(app.db.billing_emails_of("u_nobody", 10).is_empty());
}
