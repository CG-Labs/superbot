//! Resizing a user's machine when their tier changes (ADR 0085), on the real router:
//! a Stripe subscription event (or an admin) changing the tier asks for the new tier's
//! size, and the reconciler resizes the machine once that's safe. Redelivered events
//! don't resize twice; a downgrade waits while the user's storage or the machine's
//! disk wouldn't fit, saying why; a provider that fails is tried again; an Incus host
//! without room holds it up. Nothing here talks to Stripe, Linode or Incus: Stripe
//! events are fixtures, machines the fake provider or the Incus stand-ins.

use crate::billing::Billing;
use crate::billing_http_tests::{SECRET, UPDATED, deliver, event};
use crate::machines::fake::Fake;
use crate::machines::incus::fleet::{Fleet, Member, capacity};
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::{ControlPlane, State};
use crate::machines_hosts_tests::{DOWN_MS, alerts_to, events, json_call, machine_on, mail_with, reconcile, serve_with, until};
use crate::tests::{audit_list, call, serve_app_with};
use crate::tiers::Tiers;
use crate::users_http_tests::{parse, user_with};
use crate::*;

/// Small: g6-standard-1 (the starter size, a 50 GB disk) and 1 MB of storage; big:
/// g6-standard-2 (the pro size, 80 GB), sold as the fixture's price. Machines are named
/// after their size (MACHINE_TIERS), not the plan.
const TIERS: &str = r#"{
  "default": "small",
  "tiers": [
    { "name": "small", "label": "Small", "routes": "any",
      "limits": { "machineType": "g6-standard-1", "maxStorageMb": 1 }, "stripePrices": ["price_small_monthly"] },
    { "name": "big", "label": "Big", "routes": "any",
      "limits": { "machineType": "g6-standard-2" }, "stripePrices": ["price_pro_monthly"] }
  ]
}"#;

const GB: u64 = 1_000_000_000;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
    a_id: String,
    a: String,
}

async fn world() -> World {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(|a| {
        a.machines = Arc::new(ControlPlane::for_tests(p));
        a.payments = Billing::with_secret(SECRET);
    })
    .await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    World { port, app, admin, fake, a_id, a }
}

impl World {
    async fn reconcile(&self) {
        let (code, body) = call(self.port, "POST", "/api/machines/reconcile", &self.admin, "").await;
        assert_eq!(code, 200, "{body}");
    }

    /// Ada's machine, running, at her tier's size.
    async fn machine(&self) -> crate::db::Machine {
        let (code, body) = call(self.port, "POST", &format!("/api/users/{}/machine", self.a_id), &self.admin, "{}").await;
        assert_eq!(code, 202, "{body}");
        for _ in 0..5 {
            self.reconcile().await;
            let m = self.app.db.user_machine(&self.a_id).unwrap();
            if m.state == State::Running {
                return m;
            }
        }
        panic!("Ada's machine never ran");
    }

    async fn status(&self) -> Value {
        let (code, body) = call(self.port, "GET", &format!("/api/users/{}/machine/resize", self.a_id), &self.admin, "").await;
        assert_eq!(code, 200, "{body}");
        parse(&body)
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        let (code, body) = call(self.port, "GET", &format!("/api/audit?action={action}&limit=200"), &self.admin, "").await;
        assert_eq!(code, 200, "{body}");
        audit_list(&body)
    }

    async fn set_tier(&self, tier: &str) {
        let body = json!({ "tier": tier }).to_string();
        let (code, res) = call(self.port, "PATCH", &format!("/api/users/{}", self.a_id), &self.admin, &body).await;
        assert_eq!(code, 200, "{res}");
    }

    fn plan(&self) -> String {
        self.app.db.user_machine(&self.a_id).unwrap().plan
    }
}

/// Ada's subscription moved to `price` at `created`, as event `id`.
fn moved_to(w: &World, id: &str, created: i64, price: &str) -> String {
    event(UPDATED, &w.a_id, id, created, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!(price))
}

#[tokio::test]
async fn an_upgrade_resizes_the_machine_once_however_often_stripe_says_so() {
    let w = world().await;
    let m = w.machine().await;
    assert_eq!((m.tier.as_str(), m.plan.as_str()), ("starter", "g6-standard-1"));
    assert!(w.status().await["resize"].is_null(), "never asked");

    // Stripe says Ada is on big: a resize is asked for, audited as billing for her.
    let body = event(UPDATED, &w.a_id, "evt_up", 1_795_000_000, |_| {});
    let (code, res) = deliver(w.port, &body, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("tier_changed")), "{res}");
    let queued = w.audit("machine.resize_queued").await;
    assert_eq!(queued.len(), 1, "{queued:?}");
    let q = &queued[0];
    assert_eq!((q["actorId"].as_str(), q["onBehalfOf"].as_str(), q["targetId"].as_str()), (Some("billing"), Some(w.a_id.as_str()), Some(m.id.as_str())), "{q}");
    let d = &q["details"];
    assert_eq!((d["fromTier"].as_str(), d["toTier"].as_str(), d["toPlan"].as_str(), d["cause"].as_str(), d["eventId"].as_str()), (Some("starter"), Some("pro"), Some("g6-standard-2"), Some("stripe"), Some("evt_up")));
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["toTier"].as_str(), s["plan"].as_str()), (Some("pending"), Some("pro"), Some("g6-standard-1")), "{s}");
    // Ada sees it on her machine and her plan, by tier.
    let (_, mine) = call(w.port, "GET", "/api/machine", &w.a, "").await;
    let mine = parse(&mine);
    assert_eq!(mine["resize"]["toTier"], "pro", "{mine}");
    assert!(mine["resize"].get("toPlan").is_none(), "no plans for users: {mine}");
    let (_, plan) = call(w.port, "GET", "/api/me/tier", &w.a, "").await;
    assert_eq!(parse(&plan)["machine"]["resize"]["state"], "pending", "{plan}");
    // Admins list what's open.
    let (_, open) = call(w.port, "GET", "/api/machines/resizes", &w.admin, "").await;
    assert_eq!(parse(&open)[0]["userId"], w.a_id.as_str(), "{open}");
    assert_eq!(call(w.port, "GET", "/api/machines/resizes", &w.a, "").await.0, 403);

    // Redelivered before the reconciler got to it: asked once.
    assert_eq!(deliver(w.port, &body, None).await.1["outcome"], "duplicate");
    assert_eq!(w.audit("machine.resize_queued").await.len(), 1);

    // The reconciler resizes it: no disk report needed to grow.
    w.reconcile().await;
    assert_eq!((w.fake.calls("resize"), w.plan()), (1, "g6-standard-2".to_string()));
    let s = w.status().await;
    assert_eq!((s["tier"].as_str(), s["resize"]["state"].as_str()), (Some("pro"), Some("done")), "{s}");
    let resized = w.audit("machine.resized").await;
    let d = &resized[0]["details"];
    assert_eq!((d["auto"].as_bool(), d["cause"].as_str(), d["eventId"].as_str(), d["toPlan"].as_str(), d["providerCall"].as_bool()), (Some(true), Some("stripe"), Some("evt_up"), Some("g6-standard-2"), Some(true)), "{d}");
    let (_, open) = call(w.port, "GET", "/api/machines/resizes", &w.admin, "").await;
    assert_eq!(parse(&open), json!([]));

    // Redelivered after: nothing more.
    assert_eq!(deliver(w.port, &body, None).await.1["outcome"], "duplicate");
    w.reconcile().await;
    assert_eq!((w.fake.calls("resize"), w.audit("machine.resize_queued").await.len()), (1, 1));
}

#[tokio::test]
async fn a_redelivery_asks_for_a_resize_the_first_delivery_never_did() {
    let w = world().await;
    let m = w.machine().await;
    // As if botd stopped between taking the event and asking: the tier is big, nothing asked.
    let body = event(UPDATED, &w.a_id, "evt_up", 1_795_000_000, |_| {});
    assert_eq!(deliver(w.port, &body, None).await.1["outcome"], "tier_changed");
    w.app.db.machine_resize_move(&m.id, "g6-standard-2", &["pending"], "cancelled", None, None, false, None);
    let (code, res) = deliver(w.port, &body, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("duplicate")));
    // A cancelled resize to the same size isn't asked for again by a redelivery...
    assert_eq!(w.status().await["resize"]["state"], "cancelled");
    // ...but one never asked for is.
    w.app.db.machine_resize_forget(&m.id);
    deliver(w.port, &body, None).await;
    assert_eq!(w.status().await["resize"]["state"], "pending");
    w.reconcile().await;
    assert_eq!(w.plan(), "g6-standard-2");
}

#[tokio::test]
async fn a_downgrade_waits_until_what_the_user_has_fits_the_smaller_tier() {
    let w = world().await;
    w.set_tier("big").await;
    let m = w.machine().await;
    assert_eq!(m.plan, "g6-standard-2");
    // Ada has 1.2 MB in her workspace; small allows 1 MB.
    let ws = w.app.workspace_for(&w.a_id).unwrap();
    std::fs::write(ws.join("big.bin"), vec![b'x'; 1_200_000]).unwrap();
    w.app.storage.forget(&w.a_id);

    // Stripe moves her to small: asked for, but it waits, saying why.
    let (_, res) = deliver(w.port, &moved_to(&w, "evt_down", 1_795_000_000, "price_small_monthly"), None).await;
    assert_eq!(res["outcome"], "tier_changed", "{res}");
    w.reconcile().await;
    let s = w.status().await;
    let r = &s["resize"];
    assert_eq!((r["state"].as_str(), r["reason"].as_str(), s["plan"].as_str()), (Some("waiting"), Some("storage_over"), Some("g6-standard-2")), "{s}");
    assert!(r["message"].as_str().unwrap().contains("Small plan's 1 MB"), "{s}");
    let (_, mine) = call(w.port, "GET", "/api/machine", &w.a, "").await;
    assert_eq!(parse(&mine)["resize"]["reason"], "storage_over", "{mine}");
    let (_, usage) = call(w.port, "GET", "/api/usage", &w.admin, "").await;
    let usage = parse(&usage);
    let ada = usage["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == w.a_id.as_str()).unwrap();
    assert_eq!(ada["machine"]["resize"]["reason"], "storage_over", "{ada}");
    // Said once, however many passes it waits.
    w.reconcile().await;
    let waiting = w.audit("machine.resize_waiting").await;
    assert_eq!((waiting.len(), waiting[0]["details"]["reason"].as_str()), (1, Some("storage_over")), "{waiting:?}");
    assert_eq!(w.fake.calls("resize"), 0);

    // An admin moves her back while it waits: nothing to do, so it's cancelled.
    w.set_tier("big").await;
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["reason"].as_str()), (Some("cancelled"), Some("already_that_size")), "{s}");
    assert_eq!(w.audit("machine.resize_cancelled").await.len(), 1);
    // And to small again: asked for afresh.
    w.set_tier("small").await;
    assert_eq!(w.status().await["resize"]["state"], "pending");
    assert_eq!(w.audit("machine.resize_queued").await[0]["details"]["cause"], "admin");

    // Deleted down below the cap: now it's the machine's disk botd doesn't know.
    std::fs::remove_file(ws.join("big.bin")).unwrap();
    w.app.storage.forget(&w.a_id);
    // While the provider can't say how big small's disk is, it isn't made smaller.
    w.fake.set_plan_disk("g6-standard-1", None);
    w.reconcile().await;
    assert_eq!(w.status().await["resize"]["reason"], "plan_disk_unknown");
    w.fake.set_plan_disk("g6-standard-1", Some(50 << 30));
    w.reconcile().await;
    assert_eq!(w.status().await["resize"]["reason"], "disk_unknown");
    // Its agent says 60 GB is on it: more than 90% of small's 50 GB disk.
    w.app.db.machine_disk_seen(&m.id, 60 * GB, 80 * GB);
    w.reconcile().await;
    let s = w.status().await;
    assert_eq!(s["resize"]["reason"], "disk_too_full", "{s}");
    assert!(s["resize"]["message"].as_str().unwrap().contains("below 48.3 GB"), "{s}");
    assert_eq!(w.fake.calls("resize"), 0, "nothing lost");
    // Then 10 GB: it fits, and the machine is made small.
    w.app.db.machine_disk_seen(&m.id, 10 * GB, 80 * GB);
    w.reconcile().await;
    assert_eq!((w.fake.calls("resize"), w.plan()), (1, "g6-standard-1".to_string()));
    assert_eq!(w.status().await["resize"]["state"], "done");
    assert_eq!(w.audit("machine.resized").await[0]["details"]["cause"], "admin");
}

#[tokio::test]
async fn a_failing_provider_is_tried_again_and_a_lost_answer_isnt_resized_twice() {
    let w = world().await;
    let m = w.machine().await;
    w.set_tier("big").await;
    // The provider is down: tried again after a backoff, not before.
    w.fake.fail_next("resize", ProviderError::Api { status: 503, message: "busy".into() });
    w.reconcile().await;
    let s = w.status().await;
    let r = &s["resize"];
    assert_eq!((r["state"].as_str(), r["attempts"].as_i64(), r["reason"].as_str()), (Some("pending"), Some(1), Some("provider")), "{s}");
    assert!(r["nextAt"].as_i64().unwrap() > db::now(), "{s}");
    let (_, mine) = call(w.port, "GET", "/api/machine", &w.a, "").await;
    assert_eq!(parse(&mine)["resize"]["message"], "The machine's provider didn't answer; it's tried again shortly.", "no provider details: {mine}");
    w.reconcile().await;
    assert_eq!(w.fake.calls("resize"), 1, "not before its time");
    // Its time comes; the resize is done but the answer lost: tried again, the provider
    // has it already, so it isn't sent twice.
    w.app.db.machine_resize_move(&m.id, "g6-standard-2", &["pending"], "pending", None, None, false, Some(0));
    w.fake.lose_next("resize");
    w.reconcile().await;
    assert_eq!(w.fake.calls("resize"), 2);
    w.app.db.machine_resize_move(&m.id, "g6-standard-2", &["pending"], "pending", None, None, false, Some(0));
    w.reconcile().await;
    assert_eq!((w.fake.calls("resize"), w.plan()), (2, "g6-standard-2".to_string()));
    let d = &w.audit("machine.resized").await[0]["details"];
    assert_eq!(d["providerCall"], false, "{d}");
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["reason"].as_str()), (Some("done"), None), "done, not cancelled: {s}");
    assert!(w.audit("machine.resize_cancelled").await.is_empty());

    // A failure that won't pass fails it at once, audited; a new tier change asks again.
    w.set_tier("small").await;
    w.app.db.machine_disk_seen(&m.id, GB, 80 * GB);
    w.fake.fail_next("resize", ProviderError::Api { status: 400, message: "no such plan".into() });
    w.reconcile().await;
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["reason"].as_str()), (Some("failed"), Some("provider")), "{s}");
    let failed = w.audit("machine.resize_failed").await;
    assert_eq!((failed.len(), failed[0]["outcome"].as_str()), (1, Some("failure")), "{failed:?}");
    assert!(s["resize"]["message"].as_str().unwrap().contains("no such plan"), "admins see the error: {s}");
    let (_, mine) = call(w.port, "GET", "/api/machine", &w.a, "").await;
    assert_eq!(parse(&mine)["resize"]["message"], "The machine couldn't be resized. An admin has been told.", "{mine}");
    // The reconciler doesn't ask again on its own...
    w.reconcile().await;
    assert_eq!(w.status().await["resize"]["state"], "failed");
    // ...a change of tier does.
    w.set_tier("big").await;
    w.set_tier("small").await;
    w.reconcile().await;
    assert_eq!((w.status().await["resize"]["state"].as_str(), w.plan()), (Some("done"), "g6-standard-1".to_string()));

    // Asking the provider for a plan's disk fails like a resize does: a missing plan
    // fails it, not a wait for ever.
    w.set_tier("big").await;
    w.fake.fail_next("plan_disk", ProviderError::NotFound);
    w.reconcile().await;
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["reason"].as_str()), (Some("failed"), Some("provider")), "{s}");
    assert_eq!((w.audit("machine.resize_failed").await.len(), w.fake.calls("resize")), (2, 4), "no resize sent");
}

#[tokio::test]
async fn a_tier_change_while_the_provider_resizes_is_followed_after() {
    let w = world().await;
    let m = w.machine().await;
    w.set_tier("big").await;
    // While the provider grows it to big, Ada is moved back to small: that cancels the
    // request against the size botd still has on record.
    let (app, a_id) = (w.app.clone(), w.a_id.clone());
    w.fake.during_next("resize", move || {
        app.db.update_user(&a_id, crate::db::UserPatch { tier: Some(Some("small".into())), ..Default::default() }).unwrap();
        crate::machines::resize::follow(&app, &crate::audit::Who::system("test"), &a_id, "admin", None, true);
    });
    w.reconcile().await;
    // The resize to big still landed, and small is asked for again against it.
    let s = w.status().await;
    assert_eq!((s["plan"].as_str(), s["resize"]["state"].as_str(), s["resize"]["toPlan"].as_str()), (Some("g6-standard-2"), Some("pending"), Some("g6-standard-1")), "{s}");
    w.app.db.machine_disk_seen(&m.id, GB, 80 * GB);
    w.reconcile().await;
    assert_eq!((w.status().await["resize"]["state"].as_str(), w.plan()), (Some("done"), "g6-standard-1".to_string()));
}

/// Where the fake provider has the machine now.
async fn provider_plan(w: &World, m: &crate::db::Machine) -> String {
    w.fake.get(m.provider_id.as_deref().unwrap()).await.unwrap().plan
}

#[tokio::test]
async fn a_tier_change_back_after_a_lost_answer_resizes_the_machine_back() {
    let w = world().await;
    let m = w.machine().await;
    w.set_tier("big").await;
    // The provider grows it to big, but the answer is lost: botd still records small.
    w.fake.lose_next("resize");
    w.reconcile().await;
    assert_eq!((provider_plan(&w, &m).await, w.plan()), ("g6-standard-2".to_string(), "g6-standard-1".to_string()));
    // Ada is moved back to small before the retry. The machine may be big, so this is
    // asked for, not cancelled as the size it is already.
    w.set_tier("small").await;
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["toPlan"].as_str()), (Some("pending"), Some("g6-standard-1")), "{s}");
    // The next pass finds big at the provider, records it, and makes it small again.
    w.app.db.machine_disk_seen(&m.id, GB, 80 * GB);
    w.reconcile().await;
    assert_eq!((provider_plan(&w, &m).await, w.plan()), ("g6-standard-1".to_string(), "g6-standard-1".to_string()));
    assert_eq!(w.status().await["resize"]["state"], "done");
    let resized = w.audit("machine.resized").await;
    assert!(resized.iter().any(|e| e["details"]["settled"] == true && e["details"]["toPlan"] == "g6-standard-2"), "{resized:?}");
    assert_eq!(w.fake.calls("resize"), 2);
}

#[tokio::test]
async fn a_settled_resize_doesnt_mark_a_request_for_another_tier_on_the_same_plan_done() {
    let w = world().await;
    let m = w.machine().await;
    w.set_tier("big").await;
    w.fake.lose_next("resize");
    w.reconcile().await;
    // Before the provider is checked, another tier sharing big's plan is asked for.
    assert!(w.app.db.machine_resize_queue(&m.id, "other", "g6-standard-2", ("starter", "g6-standard-1"), "admin", None));
    w.reconcile().await;
    // The lost resize is settled as pro; the request for `other` isn't taken as done by it.
    let s = w.status().await;
    assert_eq!((s["tier"].as_str(), s["plan"].as_str()), (Some("pro"), Some("g6-standard-2")), "{s}");
    assert_ne!(s["resize"]["state"], "done", "{s}");
}

#[tokio::test]
async fn a_tier_change_back_while_a_resize_answer_is_lost_still_ends_at_the_tier_size() {
    let w = world().await;
    let m = w.machine().await;
    w.set_tier("big").await;
    // While the provider grows it to big, Ada is moved back to small; then the answer
    // to the resize is lost.
    let (app, a_id) = (w.app.clone(), w.a_id.clone());
    w.fake.during_next("resize", move || {
        app.db.update_user(&a_id, crate::db::UserPatch { tier: Some(Some("small".into())), ..Default::default() }).unwrap();
        crate::machines::resize::follow(&app, &crate::audit::Who::system("test"), &a_id, "admin", None, true);
    });
    w.fake.lose_next("resize");
    w.reconcile().await;
    assert_eq!(provider_plan(&w, &m).await, "g6-standard-2");
    let s = w.status().await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["toPlan"].as_str()), (Some("pending"), Some("g6-standard-1")), "{s}");
    w.app.db.machine_disk_seen(&m.id, GB, 80 * GB);
    w.reconcile().await;
    assert_eq!((provider_plan(&w, &m).await, w.plan()), ("g6-standard-1".to_string(), "g6-standard-1".to_string()));
    assert_eq!(w.status().await["resize"]["state"], "done");
}

fn two_sizes() -> &'static str {
    r#"{"default":"small","tiers":[
      {"name":"small","label":"Small","routes":"any","limits":{"machineType":"c1-m2-d20"}},
      {"name":"big","label":"Big","routes":"any","limits":{"machineType":"c2-m4-d40"}}]}"#
}

#[tokio::test]
async fn a_resize_whose_answer_is_unknown_keeps_its_room_on_the_host() {
    // Room for three CPUs on host a.
    let env = serve_with(|a, _, _| Fleet::new(vec![sized(a, "c3-m6-d60")], DOWN_MS)).await;
    env.app.tiers.set(Arc::new(Tiers::parse(two_sizes(), None).unwrap())).unwrap();
    let (ada, m) = machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{ada}"), r#"{"tier":"big"}"#).await;
    assert_eq!(code, 200, "{r}");
    // The grow's outcome is unknown (Incus kept changing under it): it may have taken
    // big's room already.
    env.a.w().races = 3;
    reconcile(&env).await;
    let (_, s) = json_call(&env, "GET", &format!("/api/users/{ada}/machine/resize"), "").await;
    assert_eq!((s["resize"]["state"].as_str(), s["resize"]["reason"].as_str()), (Some("pending"), Some("provider")), "{s}");
    let (_, h) = json_call(&env, "GET", "/api/machines/hosts", "").await;
    let a = h["hosts"].as_array().unwrap().iter().find(|x| x["name"] == "a").unwrap();
    assert_eq!(a["load"]["allocated"]["cpus"], 2, "{h}");
    // So one more small machine fits, and not two.
    machine_on(&env, &env.a, "a", "bea@example.com", false).await;
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{cy}/machine"), "").await;
    assert_eq!(code, 409, "{e}");
    // Its own retry isn't held up by the room it holds.
    env.app.db.machine_resize_move(&m.id, "c2-m4-d40", &["pending"], "pending", Some("provider"), Some("lost"), false, Some(0));
    reconcile(&env).await;
    let (_, s) = json_call(&env, "GET", &format!("/api/users/{ada}/machine/resize"), "").await;
    assert_eq!((s["resize"]["state"].as_str(), s["plan"].as_str()), (Some("done"), Some("c2-m4-d40")), "{s}");
}

#[tokio::test]
async fn the_room_an_unknown_resize_holds_lasts_until_the_provider_is_checked() {
    // Room for three CPUs on host a.
    let env = serve_with(|a, _, _| Fleet::new(vec![sized(a, "c3-m6-d60")], DOWN_MS)).await;
    env.app.tiers.set(Arc::new(Tiers::parse(two_sizes(), None).unwrap())).unwrap();
    let (ada, _) = machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{ada}"), r#"{"tier":"big"}"#).await;
    assert_eq!(code, 200, "{r}");
    env.a.w().races = 3;
    reconcile(&env).await;
    // Ada moves back to small before the provider is checked: the grow may still have
    // landed, so her machine keeps big's room, and a big machine for Cy doesn't fit.
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{ada}"), r#"{"tier":"small"}"#).await;
    assert_eq!(code, 200, "{r}");
    let (_, h) = json_call(&env, "GET", "/api/machines/hosts", "").await;
    let a = h["hosts"].as_array().unwrap().iter().find(|x| x["name"] == "a").unwrap();
    assert_eq!(a["load"]["allocated"]["cpus"], 2, "{h}");
    let (cy, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{cy}"), r#"{"tier":"big"}"#).await;
    assert_eq!(code, 200, "{r}");
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{cy}/machine"), "").await;
    assert_eq!(code, 409, "{e}");
    // The next pass finds the grow never landed: the room is freed, and Cy's fits.
    reconcile(&env).await;
    let (_, s) = json_call(&env, "GET", &format!("/api/users/{ada}/machine/resize"), "").await;
    assert_eq!((s["resize"]["state"].as_str(), s["plan"].as_str()), (Some("cancelled"), Some("c1-m2-d20")), "{s}");
    let (_, h) = json_call(&env, "GET", "/api/machines/hosts", "").await;
    let a = h["hosts"].as_array().unwrap().iter().find(|x| x["name"] == "a").unwrap();
    assert_eq!(a["load"]["allocated"]["cpus"], 1, "{h}");
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{cy}/machine"), "").await;
    assert_eq!(code, 202, "{e}");
}

fn sized(m: Member, cap: &str) -> Member {
    Member { capacity: Some(capacity(cap).unwrap()), ..m }
}

#[tokio::test]
async fn an_incus_machine_grows_in_place_once_its_host_has_room() {
    // Room on host a for two small machines, and no more.
    let env = serve_with(|a, _, _| Fleet::new(vec![sized(a, "c2-m4-d40")], DOWN_MS)).await;
    env.app.tiers.set(Arc::new(Tiers::parse(two_sizes(), None).unwrap())).unwrap();
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&env, &mail);
    let (ada, m) = machine_on(&env, &env.a, "a", "ada@example.com", false).await;
    let (bea, _) = machine_on(&env, &env.a, "a", "bea@example.com", false).await;
    assert_eq!(m.plan, "c1-m2-d20");

    // Ada moves to big: her host is full, so it waits, and admins are told once.
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{ada}"), r#"{"tier":"big"}"#).await;
    assert_eq!(code, 200, "{r}");
    reconcile(&env).await;
    reconcile(&env).await;
    let (_, s) = json_call(&env, "GET", &format!("/api/users/{ada}/machine/resize"), "").await;
    let r = &s["resize"];
    assert_eq!((r["state"].as_str(), r["reason"].as_str()), (Some("waiting"), Some("no_room")), "{s}");
    assert!(r["message"].as_str().unwrap().contains("a has 0 of 2 CPUs free, 1 more needed"), "{s}");
    assert_eq!(events(&env, "machine.resize_waiting").await.len(), 1);
    let alert = mail_with(&mail, "A machine can't grow on its host").await;
    assert!(alert.body.contains("machine resize"), "{}", alert.body);
    // Ada is told without the host's details.
    let mine = crate::machines::resize::own_view(&env.app.db.machine(&m.id).unwrap());
    let text = mine["message"].as_str().unwrap_or_default().to_string();
    assert!(text.contains("hasn't room for the pro size") && !text.contains("CPUs"), "{text}");
    // An admin resizing by hand is refused too, and audited.
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{ada}/machine/resize"), r#"{"tier":"pro"}"#).await;
    assert_eq!(code, 409, "{e}");
    assert!(e["error"].as_str().unwrap().contains("hasn't room"), "{e}");
    assert_eq!(events(&env, "machine.resize_refused").await[0]["details"]["reason"], "no_room");
    assert_eq!(env.a.instance(&m.label).unwrap().body["config"]["limits.cpu"], "1");

    // Bea's machine goes: now there's room, and Ada's grows in place.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{bea}/machine"), "").await;
    assert_eq!(code, 200);
    until("bea's machine gone", || env.app.db.user_machine(&bea).is_none_or(|m| m.state == State::Destroyed)).await;
    reconcile(&env).await;
    let (_, s) = json_call(&env, "GET", &format!("/api/users/{ada}/machine/resize"), "").await;
    assert_eq!((s["resize"]["state"].as_str(), s["plan"].as_str()), (Some("done"), Some("c2-m4-d40")), "{s}");
    let c = &env.a.instance(&m.label).unwrap().body["config"];
    assert_eq!((c["limits.cpu"].as_str(), c["limits.memory"].as_str()), (Some("2"), Some("4GiB")), "{c}");
}
