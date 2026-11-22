//! Model routes held to a residency pin (ADR 0139), on the real router with a stand-in
//! `hermes`: a pinned person's runs take only routes whose provider the tiers file marks
//! as in their region, drop fallbacks outside it, keep Hermes's side tasks on the route
//! and get no built-in provider's key. With no such route the run is refused and
//! audited. Unpinned people's runs are as before. No provider is called.

use crate::acl::Visibility;
use crate::db::PinOn;
use crate::machines::ControlPlane;
use crate::tests::{audit_list, call, serve_app};
use crate::tiers::Tiers;
use crate::tiers_http_tests::run;
use crate::users_http_tests::user_with;
use crate::*;

const TIERS: &str = r#"{
  "providers": {
    "uk-claude": { "protocol": "anthropic-messages", "baseUrl": "https://uk.claude.example", "keySecret": "RESIDENCY_E2E_UK_KEY", "regions": ["gb-lon"] },
    "eu-gpt": { "protocol": "openai-chat", "baseUrl": "https://eu.gpt.example/v1", "keySecret": "RESIDENCY_E2E_EU_KEY", "regions": ["gb-lon", "de-fra-2"] },
    "us-gpt": { "protocol": "openai-chat", "baseUrl": "https://us.gpt.example/v1", "keySecret": "RESIDENCY_E2E_US_KEY" }
  },
  "tiers": [
    { "name": "pro", "label": "Pro", "routes": [
        { "harness": "hermes", "provider": "us-gpt", "model": "gpt-5", "fallback": [{ "provider": "eu-gpt", "model": "gpt-5" }] },
        { "harness": "hermes", "provider": "uk-claude", "model": "claude-sonnet-4-5",
          "fallback": [{ "provider": "us-gpt", "model": "gpt-5" }, { "provider": "eu-gpt", "model": "gpt-5-mini" }] },
        { "harness": "claude", "model": "claude-sonnet-4-5" }
    ] }
  ]
}"#;

/// A stand-in `hermes` that says the provider it was given, whether Hermes's built-in
/// OpenRouter key reached it, and how many side tasks its managed config keeps on the route.
fn fake_hermes(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("hermes");
    let script = r#"#!/bin/sh
[ "$1" = gateway ] && exit 0
cat >/dev/null
provider=none
while [ $# -gt 0 ]; do
  case "$1" in
    --provider) provider=$2; shift ;;
  esac
  shift
done
if [ -n "$OPENROUTER_API_KEY" ]; then or=set; else or=unset; fi
aux=$(grep -o '"provider":"main"' "$HERMES_MANAGED_DIR/config.yaml" | wc -l | tr -d ' ')
printf '{"type":"result","exit_code":0,"text":"provider=%s openrouter=%s aux=%s"}\n' "$provider" "$or" "$aux"
"#;
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn audit(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// Each person's own keys: the tier endpoints', and a built-in provider's.
async fn save_keys(port: u16, who: &str) {
    for name in ["RESIDENCY_E2E_UK_KEY", "RESIDENCY_E2E_EU_KEY", "RESIDENCY_E2E_US_KEY", "OPENROUTER_API_KEY"] {
        let (code, body) = call(port, "PUT", &format!("/api/me/secrets/{name}"), who, r#"{"value":"sk-test-not-real"}"#).await;
        assert_eq!(code, 200, "{name}: {body}");
    }
}

#[tokio::test]
async fn a_pinned_persons_runs_take_only_in_region_routes_or_are_refused() {
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    fake_hermes(&app);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea_id, bea) = user_with(port, &admin, "bea@example.com", "member").await;
    save_keys(port, &ada).await;
    save_keys(port, &bea).await;
    let ada_bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "hermes", None, false, &ada_id, Visibility::Private);
    let bea_bot = app.db.create_bot_owned("Bea's", "#fff", "waddle", "hermes", None, false, &bea_id, Visibility::Shared);

    // Unpinned: the plan's first route, its fallback, Hermes's own side tasks and keys.
    assert_eq!(run(port, &app, &ada, &ada_bot.id).await, "provider=superbot-us-gpt openrouter=set aux=0");
    let invoked = audit(port, &admin, &format!("action=harness.invoked&bot={}", ada_bot.id)).await;
    assert!(invoked[0]["details"].get("residency").is_none(), "{}", invoked[0]);

    // Pinned to London: the plan's London route instead, with only its in-region fallback,
    // side tasks on the route, and no OpenRouter key.
    app.db.pin_residency(PinOn::User, &ada_id, "gb-lon", "DPA-7", None).unwrap();
    assert_eq!(run(port, &app, &ada, &ada_bot.id).await, "provider=superbot-uk-claude openrouter=unset aux=12");
    let invoked = audit(port, &admin, &format!("action=harness.invoked&bot={}", ada_bot.id)).await;
    let d = &invoked[0]["details"];
    assert_eq!((d["provider"].as_str(), d["model"].as_str()), (Some("uk-claude"), Some("claude-sonnet-4-5")), "{d}");
    assert_eq!(d["fallback"], json!([{ "provider": "eu-gpt", "model": "gpt-5-mini" }]), "{d}");
    assert_eq!(d["residency"]["regions"], json!(["gb-lon"]));
    assert_eq!(d["residency"]["fallbackOutsideRegion"], json!([{ "provider": "us-gpt", "model": "gpt-5" }]));
    assert_eq!(d["residency"]["insteadOf"], json!({ "provider": "us-gpt", "model": "gpt-5" }));

    // A harness whose route has no provider from the tiers file: refused, audited, not counted.
    let runs = || async { parse_json(&call(port, "GET", "/api/me/tier", &ada, "").await.1)["usage"]["runs"].as_u64() };
    let before = runs().await;
    let claude = app.db.create_bot_owned("Claude", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    let said = run(port, &app, &ada, &claude.id).await;
    assert!(said.contains("pinned to gb-lon") && said.contains("Pro plan has no model provider marked as there for claude"), "{said}");
    assert!(!said.contains("DPA-7") && !said.contains("sonnet"), "no reference or model in the chat: {said}");
    let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={}", claude.id)).await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), refused[0]["outcome"].as_str()), (Some("residency_pinned"), Some("denied")), "{d}");
    assert_eq!((d["pinnedRegions"].clone(), d["pins"][0]["reference"].as_str(), d["pins"][0]["pinnedOn"].as_str()), (json!(["gb-lon"]), Some("DPA-7"), Some("user")));
    assert!(d["error"].as_str().unwrap().contains("names no provider from the tiers file"), "{d}");
    assert_eq!(runs().await, before, "a refused run isn't counted");

    // The asker's pin holds too: Ada asking Bea's Bot is held to London; Bea isn't.
    assert_eq!(run(port, &app, &bea, &bea_bot.id).await, "provider=superbot-us-gpt openrouter=set aux=0");
    assert_eq!(run(port, &app, &ada, &bea_bot.id).await, "provider=superbot-uk-claude openrouter=unset aux=12");
    let invoked = audit(port, &admin, &format!("action=harness.invoked&bot={}", bea_bot.id)).await;
    assert_eq!(invoked[0]["details"]["residency"]["regions"], json!(["gb-lon"]));
    assert!(invoked[1]["details"].get("residency").is_none());

    // Admins are warned about the plan's harness that can't run there, and about a
    // provider naming a region that isn't offered.
    let mut cp = ControlPlane::default();
    cp.regions = vec!["gb-lon".into()];
    let warnings = crate::machines::residency::warnings(&app, &cp);
    assert!(warnings.iter().any(|w| w.contains("eu-gpt names data region de-fra-2")), "{warnings:?}");
    let w = warnings.iter().find(|w| w.contains("User ada")).unwrap_or_else(|| panic!("{warnings:?}"));
    assert!(w.contains("pinned to gb-lon (DPA-7)") && w.contains("the Pro plan has no model route in gb-lon for claude") && w.contains("ADR 0139"), "{w}");

    // Unpinned: as before.
    assert!(app.db.unpin_residency(PinOn::User, &ada_id).unwrap());
    assert_eq!(run(port, &app, &ada, &ada_bot.id).await, "provider=superbot-us-gpt openrouter=set aux=0");
    assert!(crate::machines::residency::warnings(&app, &cp).iter().all(|w| !w.contains("User ada")));
}

#[tokio::test]
async fn a_team_pin_holds_its_members_runs() {
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    fake_hermes(&app);
    let (ada_id, ada) = user_with(port, &admin, "ada@example.com", "member").await;
    save_keys(port, &ada).await;
    let team = app.db.create_team("Fra", None);
    assert!(app.db.add_team_member(&team.id, &ada_id, "member", None));
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "hermes", None, false, &ada_id, Visibility::Private);

    // Frankfurt: eu-gpt serves it, but no route has it as its own provider.
    app.db.pin_residency(PinOn::Team, &team.id, "de-fra-2", "MSA-9", None).unwrap();
    let said = run(port, &app, &ada, &bot.id).await;
    assert!(said.contains("pinned to de-fra-2") && said.contains("for hermes"), "{said}");
    let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={}", bot.id)).await;
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["pins"][0]["pinnedOn"].as_str(), d["pins"][0]["subjectId"].as_str()), (Some("residency_pinned"), Some("team"), Some(team.id.as_str())), "{d}");
    assert!(d["error"].as_str().unwrap().contains("us-gpt has no regions"), "{d}");
}

fn parse_json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or(Value::Null)
}
