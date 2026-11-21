use super::*;
use crate::acl::Visibility;
use crate::rbac::Role;
use crate::runner::test_app;

/// Tests that set the global webhook URL, one shared secret, take turns.
pub(crate) static GLOBAL_URL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn user(db: &Db, email: &str, role: Role) -> User {
    db.create_user(None, Some(email), email, role).unwrap()
}

fn approval(db: &Db, bot: &str, subject: &str) -> Approval {
    db.add_approval(
        bot,
        "claude",
        "Bash",
        "shell",
        subject,
        &json!({ "command": subject }),
        "git_push",
        "Pushes commits to a remote",
        crate::db::now() + 600_000,
    )
}

fn events(db: &Db, action: &str) -> Vec<crate::db::AuditEvent> {
    let f = crate::audit::Filter::from_query(&HashMap::from([(
        "action".to_string(),
        action.to_string(),
    )]))
    .unwrap();
    db.audit_events(&f, 500, true)
}

async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..300 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn patches_change_only_what_they_name_and_refuse_bad_values() {
    let s = Settings::default();
    assert!(
        !s.email.enabled && !s.webhook.enabled,
        "off until configured"
    );
    let p = apply_patch(&s, &json!({ "email": { "enabled": true, "to": "a@example.com, B@example.com\nb@example.com" }, "throttleSeconds": 0, "detail": "minimal" })).unwrap();
    assert_eq!(
        p.email.to,
        ["a@example.com", "B@example.com"],
        "split, trimmed, deduped regardless of case"
    );
    assert_eq!(
        (
            p.email.enabled,
            p.email.deciders,
            p.throttle_seconds,
            p.delay_seconds,
            p.detail
        ),
        (true, true, 0, DEFAULT_DELAY_SECONDS, Detail::Minimal)
    );
    let p2 = apply_patch(&p, &json!({ "webhook": { "format": "json" } })).unwrap();
    assert_eq!((p2.webhook.format, p2.email.to.len()), (Format::Json, 2));
    let many: Vec<String> = (0..=MAX_RECIPIENTS)
        .map(|i| format!("u{i}@example.com"))
        .collect();
    for bad in [
        json!([]),
        json!({ "email": { "to": "not an address" } }),
        json!({ "email": { "to": many } }),
        json!({ "email": { "to": ["a@example.com\r\nBcc: x@example.com"] } }),
        json!({ "email": { "enabled": "yes" } }),
        json!({ "webhook": { "format": "xml" } }),
        json!({ "delaySeconds": MAX_DELAY_SECONDS + 1 }),
        json!({ "throttleSeconds": -1 }),
        json!({ "detail": "everything" }),
    ] {
        assert!(apply_patch(&s, &bad).is_err(), "{bad}");
    }
}

#[test]
fn a_bots_fields_go_back_to_the_global_settings_with_null() {
    let o = apply_bot_patch(
        &BotSettings::default(),
        &json!({ "email": false, "webhook": true, "format": "json" }),
    )
    .unwrap();
    assert_eq!(
        (o.email, o.webhook, o.format),
        (Some(false), Some(true), Some(Format::Json))
    );
    let o = apply_bot_patch(&o, &json!({ "webhook": null, "format": null })).unwrap();
    assert_eq!((o.email, o.webhook, o.format), (Some(false), None, None));
    assert!(
        apply_bot_patch(&o, &json!({ "email": null }))
            .unwrap()
            .is_empty()
    );
    for bad in [
        json!({ "email": "off" }),
        json!({ "format": "xml" }),
        json!(null),
    ] {
        assert!(apply_bot_patch(&o, &bad).is_err(), "{bad}");
    }
}

#[test]
fn held_approvals_go_out_before_their_deadline() {
    let mut t = Throttle::default();
    let (w, t0) = (Duration::from_secs(120), Instant::now());
    let far = t0 + Duration::from_secs(86_400);
    assert_eq!(t.offer("b", "a1", w, far, t0), Offer::Now);
    let s = |n| t0 + Duration::from_secs(n);
    assert_eq!(
        t.offer("b", "a2", w, far, s(10)),
        Offer::Held(Some(Duration::from_secs(110)))
    );
    assert_eq!(
        t.offer("b", "a3", w, s(40), s(20)),
        Offer::Held(Some(Duration::from_secs(20))),
        "a sooner deadline moves the flush earlier"
    );
    assert_eq!(
        t.offer("b", "a4", w, s(90), s(25)),
        Offer::Held(None),
        "a later one doesn't"
    );
    assert!(t.take("b", s(30)).is_empty(), "not due yet");
    assert_eq!(t.take("b", s(40)), ["a2", "a3", "a4"]);
    assert!(
        t.take("b", s(120)).is_empty(),
        "the window-end flush finds nothing left"
    );
    assert_eq!(
        t.offer("b", "a5", w, s(50), s(50)),
        Offer::Now,
        "no time left: send now"
    );
}

#[test]
fn the_throttle_sends_each_approval_once_and_folds_the_rest_into_one_digest() {
    let mut t = Throttle::default();
    let (w, t0) = (Duration::from_secs(120), Instant::now());
    let far = t0 + Duration::from_secs(86_400);
    assert_eq!(t.offer("b1", "a1", w, far, t0), Offer::Now);
    assert_eq!(t.offer("b1", "a1", w, far, t0), Offer::Duplicate);
    assert_eq!(
        t.offer("b2", "a2", w, far, t0),
        Offer::Now,
        "each Bot has its own window"
    );
    assert_eq!(
        t.offer("b1", "a3", w, far, t0 + Duration::from_secs(20)),
        Offer::Held(Some(Duration::from_secs(100)))
    );
    assert_eq!(
        t.offer("b1", "a4", w, far, t0 + Duration::from_secs(30)),
        Offer::Held(None),
        "one flush per window"
    );
    assert_eq!(t.take("b1", t0 + w), ["a3", "a4"]);
    assert_eq!(
        t.offer("b1", "a5", w, far, t0 + w + Duration::from_secs(1)),
        Offer::Held(Some(Duration::from_secs(119))),
        "the digest started a new window"
    );
    assert_eq!(t.take("b1", t0 + w * 2), ["a5"]);
    assert!(t.take("b1", t0 + w * 3).is_empty());
    assert_eq!(
        t.offer("b1", "a6", w, far, t0 + w * 4),
        Offer::Now,
        "an empty take doesn't start a window"
    );
    assert_eq!(t.offer("b3", "a7", Duration::ZERO, far, t0), Offer::Now);
    assert_eq!(
        t.offer("b3", "a8", Duration::ZERO, far, t0),
        Offer::Now,
        "no throttle"
    );
}

#[test]
fn notices_show_what_the_approval_card_shows_and_no_more() {
    let app = test_app();
    let secret = format!("sk-live-{}", crate::random_hex(16));
    secrets::redact::register(&secret);
    let bot = app
        .db
        .create_bot("Builder", "#fff", "waddle", "claude", None, false);
    let long = format!(
        "curl -H 'Authorization: {secret}' https://example.com/{}",
        "x".repeat(400)
    );
    let a = approval(&app.db, &bot.id, &long);
    let n = Notifier::new(None, Some("https://bots.example.com".into()));

    let notice = n.notice(&bot, std::slice::from_ref(&a), Detail::Summary);
    let i = &notice.items[0];
    assert_eq!(
        (notice.kind, i.class_label.as_str()),
        (
            NoticeKind::Approval,
            crate::policy::CLASSES
                .iter()
                .find(|(c, _)| *c == "git_push")
                .unwrap()
                .1
        )
    );
    let subject = i.subject.as_deref().unwrap();
    assert!(
        !subject.contains(&secret)
            && subject.chars().count() <= SUBJECT_CHARS
            && subject.ends_with('…'),
        "{subject}"
    );
    assert_eq!(
        i.link.as_deref(),
        Some(format!("https://bots.example.com/app/home?approval={}", a.id).as_str())
    );
    assert_eq!(
        i.console_link.as_deref(),
        Some(
            format!(
                "https://bots.example.com/console/#audit?target=approval:{}",
                a.id
            )
            .as_str()
        )
    );
    assert_eq!(
        notice.email_subject(),
        "[SuperBot] Builder is waiting for approval to run Bash"
    );
    let body = notice.email_body(None);
    assert!(
        body.contains(i.link.as_deref().unwrap())
            && body.contains("Denied at")
            && !body.contains(&secret),
        "{body}"
    );
    assert!(
        !body.contains(&"x".repeat(300)),
        "the full command stays in the app"
    );

    let minimal = n.notice(&bot, std::slice::from_ref(&a), Detail::Minimal);
    assert!(minimal.items[0].subject.is_none() && minimal.items[0].reason.is_none());
    assert!(!minimal.email_body(None).contains("curl"));

    let many: Vec<Approval> = (0..MAX_ITEMS + 3)
        .map(|k| approval(&app.db, &bot.id, &format!("git push {k}")))
        .collect();
    let d = n.notice(&bot, &many, Detail::Summary);
    assert_eq!(
        (d.kind, d.items.len(), d.more),
        (NoticeKind::Digest, MAX_ITEMS, 3)
    );
    assert_eq!(
        d.summary(),
        format!("{} approvals are waiting for Builder", MAX_ITEMS + 3)
    );
    assert!(d.email_body(None).contains("…and 3 more."));

    let unlinked =
        Notifier::new(None, None).notice(&bot, std::slice::from_ref(&a), Detail::Summary);
    assert!(unlinked.items[0].link.is_none() && unlinked.items[0].console_link.is_none());
}

#[test]
fn deciders_are_the_owner_and_operators_who_can_still_approve() {
    let app = test_app();
    let db = &app.db;
    let owner = user(db, "owner@example.com", Role::Member);
    let operator = user(db, "op@example.com", Role::Member);
    let viewer = user(db, "viewer@example.com", Role::Member);
    let readonly = user(db, "ro@example.com", Role::Readonly);
    let gone = user(db, "gone@example.com", Role::Member);
    let bot = db.create_bot_owned(
        "Mine",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &owner.id,
        Visibility::Shared,
    );
    db.set_grant(&bot.id, &operator.id, Grant::Operator, "test");
    db.set_grant(&bot.id, &viewer.id, Grant::Viewer, "test");
    db.set_grant(&bot.id, &readonly.id, Grant::Operator, "test");
    db.set_grant(&bot.id, &gone.id, Grant::Operator, "test");
    db.update_user(
        &gone.id,
        crate::db::UserPatch {
            status: Some("disabled"),
            ..Default::default()
        },
    )
    .unwrap();
    let ids: Vec<String> = deciders(db, &bot).into_iter().map(|u| u.id).collect();
    assert_eq!(
        ids,
        [owner.id.clone(), operator.id.clone()],
        "not every member of a shared Bot, nor read-only or disabled people"
    );
}

#[test]
fn the_plan_follows_the_global_settings_and_each_bots_own() {
    let app = test_app();
    let db = &app.db;
    let owner = user(db, "plan-owner@example.com", Role::Member);
    let bot = db.create_bot_owned(
        "Plan",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &owner.id,
        Visibility::Private,
    );
    let smtp = smtp::Smtp::for_test("127.0.0.1", 1, smtp::Tls::None, None, None);
    let n = Notifier::new(Some(smtp), None);
    let mut s = Settings::default();
    assert!(n.plan(db, Some(&bot), &s).is_empty(), "off by default");

    s.email = EmailSettings {
        enabled: true,
        to: vec!["Plan-Owner@example.com".into(), "ops@example.com".into()],
        deciders: true,
    };
    assert_eq!(
        n.plan(db, Some(&bot), &s).email,
        ["Plan-Owner@example.com", "ops@example.com"],
        "the owner's address only once"
    );
    s.email.deciders = false;
    assert_eq!(n.plan(db, Some(&bot), &s).email.len(), 2);
    s.email.to.clear();
    s.email.deciders = true;
    assert_eq!(n.plan(db, Some(&bot), &s).email, ["plan-owner@example.com"]);
    assert!(n.plan(db, None, &s).email.is_empty(), "no Bot, no deciders");
    s.bots.insert(
        bot.id.clone(),
        BotSettings {
            email: Some(false),
            ..Default::default()
        },
    );
    assert!(n.plan(db, Some(&bot), &s).is_empty());
    assert!(
        Notifier::new(None, None)
            .plan(
                db,
                Some(&bot),
                &Settings {
                    bots: BTreeMap::new(),
                    ..s.clone()
                }
            )
            .email
            .is_empty(),
        "no SMTP server, no email"
    );

    let own = webhook::bot_secret(&bot.id);
    secrets::global()
        .put(&own, "https://hooks.example.com/own")
        .unwrap();
    s.bots.clear();
    s.email.enabled = false;
    assert_eq!(
        n.plan(db, Some(&bot), &s).webhook,
        Some((own.clone(), Format::Slack)),
        "its own URL turns it on"
    );
    s.bots.insert(
        bot.id.clone(),
        BotSettings {
            webhook: Some(false),
            ..Default::default()
        },
    );
    assert!(n.plan(db, Some(&bot), &s).webhook.is_none());
    s.bots.insert(
        bot.id.clone(),
        BotSettings {
            format: Some(Format::Json),
            ..Default::default()
        },
    );
    assert_eq!(
        n.plan(db, Some(&bot), &s).webhook,
        Some((own.clone(), Format::Json))
    );
    secrets::global().delete(&own).unwrap();
}

struct Rig {
    app: Arc<App>,
    notifier: Arc<Notifier>,
    mail: smtp::fake::Server,
    hook: webhook::fake::Receiver,
    bot: Bot,
    owner: User,
}

async fn rig(settings: Settings, refuse: Option<&str>) -> Rig {
    let app = test_app();
    let mail = smtp::fake::start(smtp::fake::Options {
        refuse: refuse.map(String::from),
        ..Default::default()
    })
    .await;
    let hook = webhook::fake::start("/hook").await;
    let owner = user(
        &app.db,
        &format!("owner-{}@example.com", crate::random_hex(3)),
        Role::Member,
    );
    let bot = app.db.create_bot_owned(
        "Rig",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &owner.id,
        Visibility::Private,
    );
    secrets::global()
        .put(&webhook::bot_secret(&bot.id), &hook.url)
        .unwrap();
    let smtp = smtp::Smtp::for_test("127.0.0.1", mail.port, smtp::Tls::None, None, None);
    let notifier = Arc::new(Notifier::new(
        Some(smtp),
        Some("https://bots.example.com".into()),
    ));
    let _ = app.notifier.set(notifier.clone());
    save(&app.db, &settings);
    Rig {
        app,
        notifier,
        mail,
        hook,
        bot,
        owner,
    }
}

fn on(delay: u32, throttle: u32) -> Settings {
    Settings {
        email: EmailSettings {
            enabled: true,
            to: vec!["ops@example.com".into()],
            deciders: true,
        },
        delay_seconds: delay,
        throttle_seconds: throttle,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_pending_approval_reaches_email_and_the_webhook_once_with_audit() {
    let r = rig(on(0, 0), None).await;
    let a = approval(&r.app.db, &r.bot.id, "git push origin main");
    requested(&r.app, &a);
    requested(&r.app, &a);

    let got = until("two emails", || {
        Some(r.mail.got.lock().unwrap().clone()).filter(|g| g.len() >= 2)
    })
    .await;
    let mut to: Vec<String> = got.iter().flat_map(|m| m.to.clone()).collect();
    to.sort();
    let mut want = vec![
        r.owner.email.clone().unwrap(),
        "ops@example.com".to_string(),
    ];
    want.sort();
    assert_eq!(
        to, want,
        "one message each: recipients don't see each other"
    );
    let m = &got[0];
    assert_eq!(m.from, "bots@example.com");
    assert!(
        m.headers
            .contains("Subject: [SuperBot] Rig is waiting for approval to run Bash"),
        "{}",
        m.headers
    );
    assert!(
        m.body.contains(&format!(
            "https://bots.example.com/app/home?approval={}",
            a.id
        )),
        "{}",
        m.body
    );

    let hits = until("a webhook", || {
        Some(r.hook.hits.lock().unwrap().clone()).filter(|h| !h.is_empty())
    })
    .await;
    let text = hits[0].body["text"].as_str().unwrap();
    assert!(
        text.contains("Rig is waiting for approval")
            && text.contains(&format!("approval={}", a.id)),
        "{text}"
    );

    let sent = until("two audit events", || {
        Some(events(&r.app.db, "notification.sent")).filter(|e| e.len() >= 2)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        events(&r.app.db, "notification.sent").len(),
        2,
        "sent once, not twice"
    );
    assert_eq!(r.mail.got.lock().unwrap().len(), 2);
    for e in &sent {
        assert_eq!(
            (
                e.target_type.as_deref(),
                e.target_id.as_deref(),
                e.bot_id.as_deref()
            ),
            (
                Some("approval"),
                Some(a.id.as_str()),
                Some(r.bot.id.as_str())
            )
        );
        assert!(
            !e.details.to_string().contains(&r.hook.url)
                && !e.details.to_string().contains("/hook"),
            "the URL is a secret: {}",
            e.details
        );
    }
    let hook = sent
        .iter()
        .find(|e| e.details["channel"] == "webhook")
        .unwrap();
    assert_eq!(
        (hook.details["host"].as_str(), hook.details["own"].as_bool()),
        (Some("127.0.0.1"), Some(true))
    );
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn short_approvals_are_noticed_before_they_time_out() {
    let r = rig(
        Settings {
            email: EmailSettings {
                enabled: false,
                ..Default::default()
            },
            ..on(30, 120)
        },
        None,
    )
    .await;
    let soon = |subject: &str| {
        r.app.db.add_approval(
            &r.bot.id,
            "claude",
            "Bash",
            "shell",
            subject,
            &json!({ "command": subject }),
            "git_push",
            "Pushes",
            crate::db::now() + 3_000,
        )
    };
    let (a, b) = (soon("git push 1"), soon("git push 2"));
    requested(&r.app, &a);
    requested(&r.app, &b);
    let hits = until("both, inside the 30 s delay and the 120 s window", || {
        Some(r.hook.hits.lock().unwrap().clone()).filter(|h| h.len() >= 2)
    })
    .await;
    let text: String = hits
        .iter()
        .map(|h| h.body["text"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(text.contains(&a.id) && text.contains(&b.id), "{text}");
    assert!(
        r.app.db.approval(&b.id).unwrap().status == "pending",
        "with time left to answer"
    );
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn a_stalled_mail_server_does_not_hold_up_the_webhook() {
    let r = rig(on(0, 0), None).await;
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let keep = held.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = silent.accept().await {
            keep.lock().unwrap().push(s);
        }
    });
    let stalled = Arc::new(Notifier::new(
        Some(smtp::Smtp::for_test(
            "127.0.0.1",
            port,
            smtp::Tls::None,
            None,
            None,
        )),
        Some("https://bots.example.com".into()),
    ));
    let a = approval(&r.app.db, &r.bot.id, "git push");
    let (app, n) = (r.app.clone(), stalled.clone());
    tokio::spawn(async move {
        n.send_pending(&app, &a.bot_id, std::slice::from_ref(&a.id))
            .await
    });
    until("the webhook while email waits", || {
        Some(r.hook.hits.lock().unwrap().len()).filter(|n| *n > 0)
    })
    .await;
    assert!(
        !held.lock().unwrap().is_empty()
            && events(&r.app.db, "notification.*")
                .iter()
                .all(|e| e.details["channel"] != "email"),
        "email is still waiting"
    );
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn approvals_answered_during_the_delay_send_nothing() {
    let r = rig(on(1, 0), None).await;
    let a = approval(&r.app.db, &r.bot.id, "git push");
    requested(&r.app, &a);
    r.app
        .db
        .finish_approval(&a.id, "approved", "user", None, None);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(r.mail.got.lock().unwrap().is_empty() && r.hook.hits.lock().unwrap().is_empty());
    assert!(events(&r.app.db, "notification.*").is_empty());
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn a_burst_becomes_one_notice_then_one_digest() {
    let r = rig(
        Settings {
            email: EmailSettings {
                enabled: false,
                ..Default::default()
            },
            ..on(0, 1)
        },
        None,
    )
    .await;
    let ids: Vec<String> = (0..4)
        .map(|k| approval(&r.app.db, &r.bot.id, &format!("git push {k}")).id)
        .collect();
    for id in &ids {
        requested(&r.app, &r.app.db.approval(id).unwrap());
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    r.app
        .db
        .finish_approval(&ids[3], "denied", "user", None, None);
    let hits = until("the digest", || {
        Some(r.hook.hits.lock().unwrap().clone()).filter(|h| h.len() >= 2)
    })
    .await;
    assert!(
        hits[0].body["text"]
            .as_str()
            .unwrap()
            .contains("waiting for approval")
    );
    let digest = hits[1].body["text"].as_str().unwrap();
    assert!(
        digest.starts_with("*2 approvals are waiting for Rig*"),
        "answered ones drop out: {digest}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(r.hook.hits.lock().unwrap().len(), 2);
    let e = events(&r.app.db, "notification.sent");
    let d = e.iter().find(|e| e.details["kind"] == "digest").unwrap();
    assert_eq!(
        (
            d.target_type.as_deref(),
            d.details["approvals"].as_array().map(Vec::len)
        ),
        (Some("bot"), Some(2))
    );
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn failures_are_audited_without_secrets() {
    let r = rig(on(0, 0), Some("ops@")).await;
    *r.hook.status.lock().unwrap() = 500;
    let a = approval(&r.app.db, &r.bot.id, "git push");
    requested(&r.app, &a);
    let failed = until("two failures", || {
        Some(events(&r.app.db, "notification.failed")).filter(|e| e.len() >= 2)
    })
    .await;
    let mail = failed
        .iter()
        .find(|e| e.details["channel"] == "email")
        .unwrap();
    assert_eq!(
        (
            mail.details["delivered"].as_u64(),
            mail.details["failed"].as_u64()
        ),
        (Some(1), Some(1)),
        "{}",
        mail.details
    );
    assert!(
        mail.details["error"]
            .as_str()
            .unwrap()
            .contains("ops@example.com")
    );
    let hook = failed
        .iter()
        .find(|e| e.details["channel"] == "webhook")
        .unwrap();
    assert!(
        hook.details["error"].as_str().unwrap().contains("500"),
        "{}",
        hook.details
    );
    assert!(!hook.details.to_string().contains(&r.hook.url));
    assert!(failed.iter().all(|e| e.outcome == "failure"));
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
}

#[tokio::test]
async fn a_test_goes_out_now_past_the_delay_and_says_where() {
    let r = rig(on(600, 3600), None).await;
    let results = r.notifier.test(&r.app, Some(&r.bot)).await.unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|x| x["ok"] == true), "{results:?}");
    let got = r.mail.got.lock().unwrap().clone();
    assert!(
        got[0]
            .headers
            .contains("Test notification from SuperBot for Rig")
    );
    assert_eq!(r.hook.hits.lock().unwrap().len(), 1);
    assert!(
        events(&r.app.db, "notification.sent")
            .iter()
            .all(|e| e.details["test"] == true)
    );
    save(&r.app.db, &Settings::default());
    secrets::global()
        .delete(&webhook::bot_secret(&r.bot.id))
        .unwrap();
    assert!(
        r.notifier
            .test(&r.app, Some(&r.bot))
            .await
            .unwrap_err()
            .contains("Nothing would reach anyone")
    );
}

#[test]
fn deleting_a_bot_forgets_its_settings_and_url() {
    let app = test_app();
    let n = Arc::new(Notifier::new(None, None));
    let _ = app.notifier.set(n);
    let bot = app
        .db
        .create_bot("Gone", "#fff", "waddle", "claude", None, false);
    let mut s = Settings::default();
    s.bots.insert(
        bot.id.clone(),
        BotSettings {
            webhook: Some(true),
            ..Default::default()
        },
    );
    save(&app.db, &s);
    secrets::global()
        .put(&webhook::bot_secret(&bot.id), "https://hooks.example.com/x")
        .unwrap();
    forget_bot(&app, &bot.id);
    assert!(load(&app.db).bots.is_empty() && !secret_set(&webhook::bot_secret(&bot.id)));
}
