//! Observability (ADR 0089) on the real router and runner: `/metrics` is off unless
//! asked for, never on the main port, and needs its token when it has one; requests and
//! runs are counted by bounded labels and logged with their ids; approvals waiting and
//! machines show as gauges; and no email, name, message, path or token reaches a label
//! or a structured log line.

use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::ControlPlane;
use crate::obs::log::captured;
use crate::secrets::env::EnvStore;
use crate::tests::{call, call_with, serve_app, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

/// The sum of every sample whose line starts with `prefix`.
pub(crate) fn total(metrics: &str, prefix: &str) -> f64 {
    metrics.lines().filter(|l| l.starts_with(prefix)).filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok()).sum()
}

fn settings(vars: &[(&str, &str)]) -> Result<obs::Settings, String> {
    let store = EnvStore::fixed(vars);
    let get = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default();
    obs::Settings::from_env(&get, &store)
}

async fn metrics_on(app: &AppState, token: Option<&str>) -> u16 {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(obs::serve(l, app.clone(), token.map(secrets::Secret::new)));
    port
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

fn fake_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"On it."}]}}"#;
    std::fs::write(&path, format!("#!/bin/sh\necho '{reply}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn metrics_are_off_by_default_and_need_a_token_off_loopback() {
    let s = settings(&[]).unwrap();
    assert!(s.metrics.is_none() && s.log == obs::log::Format::Text, "{s:?}");
    assert!(settings(&[("METRICS_LISTEN", "off")]).unwrap().metrics.is_none());

    let on = settings(&[("METRICS_LISTEN", "on")]).unwrap().metrics.unwrap();
    assert_eq!(on.addr.to_string(), obs::DEFAULT_LISTEN);
    assert!(on.token.is_none());
    assert!(settings(&[("METRICS_LISTEN", "[::1]:9100")]).unwrap().metrics.unwrap().token.is_none());

    let open = settings(&[("METRICS_LISTEN", "0.0.0.0:9464")]).unwrap_err();
    assert!(open.contains("METRICS_TOKEN"), "{open}");
    let token = random_hex(16);
    let l = settings(&[("METRICS_LISTEN", "0.0.0.0:9464"), ("METRICS_TOKEN", &token)]).unwrap().metrics.unwrap();
    assert_eq!(l.token.as_ref().map(|t| t.expose().to_string()), Some(token.clone()));
    assert!(!format!("{l:?}").contains(&token), "a token never prints");
    assert!(settings(&[("METRICS_LISTEN", "0.0.0.0:9464"), ("METRICS_TOKEN", "short")]).unwrap_err().contains("at least"));

    let dir = std::env::temp_dir().join(format!("superbot-metrics-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, format!("{token}\n")).unwrap();
    let from_file = settings(&[("METRICS_LISTEN", "10.0.0.5:9464"), ("METRICS_TOKEN_FILE", file.to_str().unwrap())]).unwrap();
    assert_eq!(from_file.metrics.unwrap().token.map(|t| t.expose().to_string()), Some(token));

    assert!(settings(&[("METRICS_LISTEN", "everywhere")]).unwrap_err().contains("METRICS_LISTEN"));
    assert_eq!(settings(&[("LOG_FORMAT", "JSON")]).unwrap().log, obs::log::Format::Json);
    assert!(settings(&[("LOG_FORMAT", "xml")]).unwrap_err().contains("LOG_FORMAT"));
}

#[tokio::test]
async fn metrics_need_the_token_when_one_is_set_and_serve_nothing_else() {
    let (_, app, _, _) = serve_app().await;
    let token = random_hex(16);
    let port = metrics_on(&app, Some(&token)).await;
    let bearer = format!("Bearer {token}");
    assert_eq!(call(port, "GET", "/metrics", "", "").await.0, 401);
    assert_eq!(call(port, "GET", "/metrics", &format!("Bearer {}", random_hex(16)), "").await.0, 401);
    assert_eq!(call(port, "GET", "/metrics", &format!("Bearer {}", &token[..20]), "").await.0, 401);
    assert_eq!(call(port, "GET", "/metrics", &crate::tests::basic(&token), "").await.0, 401);
    let (code, head, body) = call_with(port, "GET", "/metrics", &bearer, "", "").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(header(&head, "content-type"), Some("text/plain; version=0.0.4; charset=utf-8"), "{head}");
    assert!(body.contains("# TYPE superbot_http_requests_total counter") && body.contains("superbot_build_info{version="), "{body}");
    for path in ["/", "/healthz", "/api/state", "/metrics/x"] {
        assert_eq!(call(port, "GET", path, &bearer, "").await.0, 404, "{path}");
    }

    // On loopback with no token, anyone on this computer may read it.
    let open = metrics_on(&app, None).await;
    assert_eq!(call(open, "GET", "/metrics", "", "").await.0, 200);
}

#[tokio::test]
async fn the_main_port_never_serves_metrics() {
    let (port, _, admin, key) = serve_app().await;
    let bot = key.auth("b1");
    for auth in ["", admin.as_str(), bot.as_str()] {
        let (_, body) = call(port, "GET", "/metrics", auth, "").await;
        assert!(!body.contains("superbot_"), "{body}");
    }
}

#[tokio::test]
async fn requests_are_counted_by_route_class_and_logged_with_an_id() {
    let (port, app, admin, _) = serve_app().await;
    let (code, head, _) = call_with(port, "GET", "/healthz", "", "", "").await;
    assert_eq!(code, 200);
    let made = header(&head, "x-request-id").unwrap();
    assert!(made.len() == 16 && made.bytes().all(|b| b.is_ascii_hexdigit()), "{head}");

    // A plain id from the proxy is kept and logged; anything else is replaced.
    let rid = format!("caddy-{}.1", random_hex(6));
    let (code, head, _) = call_with(port, "GET", "/api/state", &admin, &format!("X-Request-Id: {rid}\r\n"), "").await;
    assert_eq!((code, header(&head, "x-request-id")), (200, Some(rid.as_str())), "{head}");
    let (_, head, _) = call_with(port, "GET", "/api/state", &admin, "X-Request-Id: ada@example.com\r\n", "").await;
    let replaced = header(&head, "x-request-id").unwrap();
    assert!(!replaced.contains('@'), "{head}");

    let line = captured::with(&rid).into_iter().find(|l| l["msg"] == "http.request").expect("a request line");
    assert_eq!(line["requestId"], rid.as_str());
    assert_eq!((line["method"].as_str(), line["route"].as_str(), line["routeClass"].as_str(), line["status"].as_u64()), (Some("GET"), Some("/api/state"), Some("bots"), Some(200)), "{line}");
    assert!(line["ts"].as_str().is_some_and(|t| t.ends_with('Z')) && line["level"] == "info" && line["durationMs"].is_u64(), "{line}");

    // An email and a query in the path reach neither the log line nor a label.
    let rid = format!("t-{}", random_hex(8));
    call_with(port, "GET", "/api/users/ada%40example.com/bots?q=hunter2", &admin, &format!("X-Request-Id: {rid}\r\n"), "").await;
    let line = captured::with(&rid).into_iter().find(|l| l["msg"] == "http.request").expect("a request line");
    assert_eq!((line["route"].as_str(), line["routeClass"].as_str()), (Some("/api/users/{key}/bots"), Some("users")), "{line}");
    let text = line.to_string();
    assert!(!text.contains("ada") && !text.contains("hunter2") && !text.contains("example.com"), "{text}");
    // No route matched: no template, still a class.
    let rid = format!("t-{}", random_hex(8));
    call_with(port, "GET", "/api/nothing/ada@example.com", &admin, &format!("X-Request-Id: {rid}\r\n"), "").await;
    let line = captured::with(&rid).into_iter().find(|l| l["msg"] == "http.request").expect("a request line");
    assert!(line.get("route").is_none() && line["routeClass"] == "api_other" && !line.to_string().contains("ada"), "{line}");

    let m = obs::render(&app);
    assert_eq!(total(&m, r#"superbot_http_requests_total{route_class="healthz",method="GET",status_class="2xx"}"#), 1.0, "{m}");
    assert_eq!(total(&m, r#"superbot_http_requests_total{route_class="bots",method="GET",status_class="2xx"}"#), 2.0, "{m}");
    assert!(total(&m, r#"superbot_http_requests_total{route_class="users""#) >= 1.0, "{m}");
    assert_eq!(total(&m, r#"superbot_http_request_duration_seconds_count{route_class="healthz"}"#), 1.0, "{m}");
    assert_eq!(total(&m, r#"superbot_http_request_duration_seconds_bucket{route_class="healthz",le="+Inf"}"#), 1.0, "{m}");
    for bad in ["ada", "example.com", "hunter2", "nothing", rid.as_str()] {
        assert!(!m.contains(bad), "{bad} in {m}");
    }
}

#[tokio::test]
async fn runs_are_counted_by_harness_and_result_and_logged_with_their_ids() {
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let bot = app.db.create_bot("Project Falcon", "#fff", "waddle", "claude", None, false).id;
    let rid = format!("t-{}", random_hex(8));
    let text = json!({ "text": "email ada@example.com the key sk-test-4242" }).to_string();
    let (code, _, body) = call_with(port, "POST", &format!("/api/bots/{bot}/messages"), &admin, &format!("X-Request-Id: {rid}\r\n"), &text).await;
    assert_eq!(code, 202, "{body}");
    let mid = parse(&body)["id"].as_i64().unwrap();
    let done = r#"superbot_runs_total{harness="claude",result="done"}"#;
    for _ in 0..400 {
        if total(&obs::render(&app), done) >= 1.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let m = obs::render(&app);
    assert_eq!(total(&m, done), 1.0, "{m}");
    assert_eq!(total(&m, r#"superbot_run_duration_seconds_count{harness="claude"}"#), 1.0, "{m}");
    assert_eq!(total(&m, r#"superbot_runs_active{harness="claude"}"#), 0.0, "{m}");
    assert_eq!(total(&m, "superbot_runs_waiting"), 0.0, "{m}");

    // The request, the queued message and the run are tied by their ids.
    let queued = captured::with(&rid).into_iter().find(|l| l["msg"] == "message.queued").expect("message.queued");
    assert_eq!((queued["messageId"].as_i64(), queued["botId"].as_str(), queued["trigger"].as_str()), (Some(mid), Some(bot.as_str()), Some("user")), "{queued}");
    let lines = captured::with(&bot);
    let started = lines.iter().find(|l| l["msg"] == "run.started" && l["messageId"] == mid).expect("run.started");
    let finished = lines.iter().find(|l| l["msg"] == "run.finished" && l["messageId"] == mid).expect("run.finished");
    assert!(started["runId"].as_str().is_some_and(|r| r.starts_with('r')) && started["runId"] == finished["runId"], "{started} {finished}");
    assert_eq!((finished["harness"].as_str(), finished["result"].as_str(), finished["host"].as_str()), (Some("claude"), Some("done"), Some("server")), "{finished}");

    for l in lines.iter().chain(captured::with(&rid).iter()) {
        let l = l.to_string();
        for bad in ["ada@example.com", "sk-test-4242", "Falcon", "On it."] {
            assert!(!l.contains(bad), "{bad} in {l}");
        }
    }
    for bad in [bot.as_str(), "Falcon", "ada@", "sk-test"] {
        assert!(!m.contains(bad), "{bad} in {m}");
    }
}

#[tokio::test]
async fn approvals_waiting_show_as_queue_depth_and_age() {
    let (_, app, _, _) = serve_app().await;
    let m = obs::render(&app);
    assert_eq!((total(&m, "superbot_approvals_pending"), total(&m, "superbot_approvals_oldest_pending_age_seconds")), (0.0, 0.0), "{m}");
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, false);
    let far = db::now() + 3_600_000;
    let secret = "rm -rf /home/ada@example.com";
    app.db.add_approval(&bot.id, "claude", "Bash", "shell", secret, &json!({ "command": secret }), "shell", "ask", far);
    let done = app.db.add_approval(&bot.id, "claude", "Bash", "shell", "ls", &json!({}), "shell", "ask", far);
    assert!(app.db.finish_approval(&done.id, "approved", "owner", None, None));
    let m = obs::render(&app);
    assert_eq!(total(&m, "superbot_approvals_pending "), 1.0, "{m}");
    assert!(!m.contains("ada") && !m.contains(&bot.id), "{m}");
}

#[tokio::test]
async fn machines_and_the_reconciler_show_when_the_control_plane_is_on() {
    let (_, app, _, _) = serve_app().await;
    let m = obs::render(&app);
    assert!(!m.contains("superbot_machines{"), "no machine gauges without a control plane: {m}");

    let fake: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app2, admin, _) = serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(fake))).await;
    let (code, body) = call(port, "POST", "/api/machines/reconcile", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let m = obs::render(&app2);
    assert_eq!(total(&m, "superbot_machine_reconcile_passes_total"), 1.0, "{m}");
    assert!(total(&m, "superbot_machine_reconcile_last_pass_timestamp_seconds") > 1.0e9, "{m}");
    assert_eq!(total(&m, r#"superbot_machines{state="running"}"#), 0.0, "{m}");
    assert!(m.contains(r#"superbot_machines{state="pending"} 0"#) && !m.contains(r#"state="destroyed""#), "{m}");
}
