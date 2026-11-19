//! Linode API v4 behind `MachineProvider`. Only `https://api.linode.com/v4` in
//! production; tests point it at a local stand-in. The token goes in the
//! Authorization header and nowhere else: not in errors, logs, or `Debug`.

use super::provider::{CreateSpec, Fut, MachineProvider, ProviderError, ProviderMachine};
use base64::Engine;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::time::Duration;
use zeroize::Zeroizing;

pub const API_URL: &str = "https://api.linode.com/v4";
const PAGE_SIZE: u32 = 500;
/// 50,000 machines; past that something is wrong with the paging, not the fleet.
const MAX_PAGES: u32 = 100;

pub struct Linode {
    token: Zeroizing<String>,
    base: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Linode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Linode")
            .field("base", &self.base)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Linode {
    pub fn new(token: &str, base: &str) -> Linode {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client");
        Linode {
            token: Zeroizing::new(token.trim().to_string()),
            base: base.trim_end_matches('/').to_string(),
            http,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        filter: Option<&Value>,
        body: Option<&Value>,
    ) -> Result<Value, ProviderError> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token.as_str());
        if let Some(f) = filter {
            req = req.header("X-Filter", f.to_string());
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        // reqwest's errors name the URL, which holds no credentials.
        let res = req
            .send()
            .await
            .map_err(|e| ProviderError::Transport(e.without_url().to_string()))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| ProviderError::Transport(e.without_url().to_string()))?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(v);
        }
        Err(error(status, &v))
    }
}

/// Linode's `{"errors": [{"field", "reason"}]}`, as one of ours.
fn error(status: StatusCode, v: &Value) -> ProviderError {
    let errors = v["errors"].as_array().cloned().unwrap_or_default();
    let label_taken = errors.iter().any(|e| {
        e["field"] == "label"
            && e["reason"]
                .as_str()
                .is_some_and(|r| r.to_ascii_lowercase().contains("unique"))
    });
    match status {
        StatusCode::NOT_FOUND => ProviderError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        StatusCode::BAD_REQUEST if label_taken => ProviderError::LabelTaken,
        _ => {
            let reasons: Vec<String> = errors
                .iter()
                .filter_map(|e| {
                    let reason = e["reason"].as_str()?;
                    Some(match e["field"].as_str() {
                        Some(f) => format!("{f}: {reason}"),
                        None => reason.to_string(),
                    })
                })
                .collect();
            let message = if reasons.is_empty() {
                status.canonical_reason().unwrap_or("error").to_string()
            } else {
                reasons.join("; ")
            };
            ProviderError::Api {
                status: status.as_u16(),
                message: crate::audit::clip(&message, 300),
            }
        }
    }
}

fn machine(v: &Value) -> Result<ProviderMachine, ProviderError> {
    let bad = || ProviderError::Transport("Linode sent a machine we couldn't read".into());
    let id = v["id"].as_u64().ok_or_else(bad)?;
    let text = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Ok(ProviderMachine {
        id: id.to_string(),
        label: text("label"),
        status: text("status"),
        plan: text("type"),
        region: text("region"),
        ipv4: v["ipv4"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(String::from),
        backups: v["backups"]["enabled"].as_bool().unwrap_or(false),
        tags: v["tags"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Linode ids are numbers; anything else never reaches a URL path.
fn path_id(id: &str) -> Result<&str, ProviderError> {
    if !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(id)
    } else {
        Err(ProviderError::Api {
            status: 400,
            message: "not a Linode id".into(),
        })
    }
}

/// Linode wants a root password with any image. Nobody needs it: people come in with
/// `authorized_keys`, and the control plane through enrollment (ADR 0025). So it is
/// random, sent once, and kept nowhere.
fn root_pass() -> Zeroizing<String> {
    Zeroizing::new(format!(
        "Sb-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::random_bytes(32))
    ))
}

impl MachineProvider for Linode {
    fn name(&self) -> &'static str {
        "linode"
    }

    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let pass = root_pass();
            let mut body = json!({
                "label": spec.label,
                "region": spec.region,
                "type": spec.plan,
                "image": spec.image,
                "root_pass": pass.as_str(),
                "tags": spec.tags,
                "booted": true,
            });
            if !spec.authorized_keys.is_empty() {
                body["authorized_keys"] = json!(spec.authorized_keys);
            }
            machine(
                &self
                    .call(Method::POST, "/linode/instances", None, Some(&body))
                    .await?,
            )
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            machine(
                &self
                    .call(
                        Method::GET,
                        &format!("/linode/instances/{}", path_id(id)?),
                        None,
                        None,
                    )
                    .await?,
            )
        })
    }

    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>> {
        Box::pin(async move {
            let filter = json!({ "tags": tag });
            let mut out = Vec::new();
            for page in 1..=MAX_PAGES {
                let v = self
                    .call(
                        Method::GET,
                        &format!("/linode/instances?page={page}&page_size={PAGE_SIZE}"),
                        Some(&filter),
                        None,
                    )
                    .await?;
                for m in v["data"].as_array().map(Vec::as_slice).unwrap_or_default() {
                    out.push(machine(m)?);
                }
                if page >= v["pages"].as_u64().unwrap_or(1) as u32 {
                    break;
                }
            }
            Ok(out)
        })
    }

    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let body =
                json!({ "type": plan, "allow_auto_disk_resize": true, "migration_type": "cold" });
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/resize", path_id(id)?),
                None,
                Some(&body),
            )
            .await
            .map(drop)
        })
    }

    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/shutdown", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/boot", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/backups/enable", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self
                .call(
                    Method::DELETE,
                    &format!("/linode/instances/{}", path_id(id)?),
                    None,
                    None,
                )
                .await
            {
                Ok(_) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "linode-test-token-0123456789";

    /// What the stand-in saw: method, path, X-Filter, body.
    type Seen = Arc<Mutex<Vec<(String, String, Option<String>, Value)>>>;

    fn instance(id: u64, label: &str, status: &str) -> Value {
        json!({
            "id": id, "label": label, "status": status, "type": "g6-standard-1", "region": "gb-lon",
            "ipv4": ["192.0.2.10", "192.168.1.1"], "backups": { "enabled": false }, "tags": ["superbot"],
        })
    }

    /// A local stand-in for api.linode.com. It refuses any request without the token,
    /// says label "taken" is taken, and pages lists two at a time.
    async fn fake_api() -> (Linode, Seen) {
        let seen: Seen = Arc::default();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let record = |s: &Seen, method: &str, path: String, h: &HeaderMap, body: Value| {
            s.lock().unwrap().push((
                method.into(),
                path,
                h.get("x-filter").map(|v| v.to_str().unwrap().to_string()),
                body,
            ));
        };
        let authed = |h: &HeaderMap| {
            h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
        };
        let unauthorized = || {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "errors": [{ "reason": "Invalid Token" }] })),
            )
        };
        let r = Router::new()
            .route(
                "/v4/linode/instances",
                post(move |State(s): State<Seen>, h: HeaderMap, Json(b): Json<Value>| async move {
                    record(&s, "POST", "/linode/instances".into(), &h, b.clone());
                    if !authed(&h) {
                        return unauthorized();
                    }
                    if b["label"] == "taken" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "label", "reason": "Label must be unique among your linodes" }] })));
                    }
                    if b["type"] == "g6-nope" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "type", "reason": "A valid plan type by that ID was not found" }] })));
                    }
                    (StatusCode::OK, Json(json!({ "label": b["label"], "status": "provisioning", "id": 42, "type": b["type"], "region": b["region"], "ipv4": [], "backups": { "enabled": false }, "tags": b["tags"] })))
                })
                .get(move |State(s): State<Seen>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    let page: u64 = q["page"].parse().unwrap();
                    record(&s, "GET", format!("/linode/instances?page={page}&page_size={}", q["page_size"]), &h, Value::Null);
                    if !authed(&h) {
                        return unauthorized();
                    }
                    let all: Vec<Value> = (1..=3).map(|i| instance(i, &format!("superbot-m{i}"), "running")).collect();
                    let data: Vec<Value> = all.into_iter().skip((page as usize - 1) * 2).take(2).collect();
                    (StatusCode::OK, Json(json!({ "data": data, "page": page, "pages": 2, "results": 3 })))
                }),
            )
            .route(
                "/v4/linode/instances/{id}",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/linode/instances/{id}"), &h, Value::Null);
                    match id {
                        7 => (StatusCode::OK, Json(instance(7, "superbot-m7", "running"))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                })
                .delete(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "DELETE", format!("/linode/instances/{id}"), &h, Value::Null);
                    match id {
                        7 => (StatusCode::OK, Json(json!({}))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            .route(
                "/v4/linode/instances/{id}/{*action}",
                post(move |State(s): State<Seen>, h: HeaderMap, Path((id, action)): Path<(u64, String)>, body: axum::body::Bytes| async move {
                    let b = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    record(&s, "POST", format!("/linode/instances/{id}/{action}"), &h, b);
                    match id {
                        7 => (StatusCode::OK, Json(json!({}))),
                        8 => (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "errors": [{ "reason": "Too many requests" }] }))),
                        _ => (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "reason": "Linode busy." }] }))),
                    }
                }),
            )
            .with_state(seen.clone());
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (
            Linode::new(TOKEN, &format!("http://127.0.0.1:{port}/v4")),
            seen,
        )
    }

    fn spec(label: &str) -> CreateSpec {
        CreateSpec {
            label: label.into(),
            plan: "g6-standard-1".into(),
            region: "gb-lon".into(),
            image: "linode/ubuntu24.04".into(),
            tags: vec!["superbot".into(), "superbot-user-u1".into()],
            authorized_keys: vec!["ssh-ed25519 AAAAC3Nza test@example".into()],
        }
    }

    #[tokio::test]
    async fn create_sends_the_spec_and_a_random_root_password() {
        let (api, seen) = fake_api().await;
        let m = api.create(&spec("superbot-m1")).await.unwrap();
        assert_eq!(
            (
                m.id.as_str(),
                m.label.as_str(),
                m.status.as_str(),
                m.plan.as_str(),
                m.ipv4.as_deref()
            ),
            ("42", "superbot-m1", "provisioning", "g6-standard-1", None)
        );
        let again = api.create(&spec("superbot-m2")).await.unwrap();
        assert_eq!(again.id, "42");
        let seen = seen.lock().unwrap();
        let body = &seen[0].3;
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            ("POST", "/linode/instances")
        );
        assert_eq!(
            (
                body["type"].as_str(),
                body["region"].as_str(),
                body["image"].as_str(),
                body["booted"].as_bool()
            ),
            (
                Some("g6-standard-1"),
                Some("gb-lon"),
                Some("linode/ubuntu24.04"),
                Some(true)
            )
        );
        assert_eq!(body["tags"], json!(["superbot", "superbot-user-u1"]));
        assert_eq!(
            body["authorized_keys"],
            json!(["ssh-ed25519 AAAAC3Nza test@example"])
        );
        let (p1, p2) = (
            body["root_pass"].as_str().unwrap(),
            seen[1].3["root_pass"].as_str().unwrap(),
        );
        assert!(
            p1.len() >= 40 && p1 != p2,
            "a fresh strong password per machine"
        );
    }

    #[tokio::test]
    async fn errors_are_mapped_and_never_carry_the_token() {
        let (api, _) = fake_api().await;
        assert_eq!(
            api.create(&spec("taken")).await,
            Err(ProviderError::LabelTaken)
        );
        let mut s = spec("superbot-m3");
        s.plan = "g6-nope".into();
        let e = api.create(&s).await.unwrap_err();
        assert_eq!(
            e,
            ProviderError::Api {
                status: 400,
                message: "type: A valid plan type by that ID was not found".into()
            }
        );
        assert_eq!(api.get("9").await, Err(ProviderError::NotFound));
        assert_eq!(api.shutdown("8").await, Err(ProviderError::RateLimited));
        assert_eq!(
            api.boot("9").await,
            Err(ProviderError::Api {
                status: 400,
                message: "Linode busy.".into()
            })
        );
        assert!(
            matches!(
                api.get("../account").await,
                Err(ProviderError::Api { status: 400, .. })
            ),
            "ids never reach the path unchecked"
        );

        let wrong = Linode {
            token: Zeroizing::new("wrong".into()),
            ..Linode::new("x", &api.base)
        };
        let e = wrong.list("superbot").await.unwrap_err();
        assert_eq!(
            e,
            ProviderError::Api {
                status: 401,
                message: "Invalid Token".into()
            }
        );
        let unreachable = Linode::new(TOKEN, "http://127.0.0.1:1/v4");
        let e = unreachable.get("7").await.unwrap_err();
        assert!(matches!(e, ProviderError::Transport(_)), "{e:?}");
        for text in [e.to_string(), format!("{e:?}"), format!("{unreachable:?}")] {
            assert!(!text.contains(TOKEN), "{text}");
        }
    }

    #[tokio::test]
    async fn get_list_and_actions() {
        let (api, seen) = fake_api().await;
        let m = api.get("7").await.unwrap();
        assert_eq!(
            (
                m.id.as_str(),
                m.running(),
                m.ipv4.as_deref(),
                m.backups,
                m.region.as_str()
            ),
            ("7", true, Some("192.0.2.10"), false, "gb-lon")
        );

        let all = api.list("superbot").await.unwrap();
        assert_eq!(
            all.iter().map(|m| m.label.as_str()).collect::<Vec<_>>(),
            ["superbot-m1", "superbot-m2", "superbot-m3"],
            "every page"
        );

        api.resize("7", "g6-standard-2").await.unwrap();
        api.shutdown("7").await.unwrap();
        api.boot("7").await.unwrap();
        api.enable_backups("7").await.unwrap();
        api.delete("7").await.unwrap();
        api.delete("9").await.unwrap();

        let seen = seen.lock().unwrap();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|(m, p, _, _)| (m.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("GET", "/linode/instances/7"),
                ("GET", "/linode/instances?page=1&page_size=500"),
                ("GET", "/linode/instances?page=2&page_size=500"),
                ("POST", "/linode/instances/7/resize"),
                ("POST", "/linode/instances/7/shutdown"),
                ("POST", "/linode/instances/7/boot"),
                ("POST", "/linode/instances/7/backups/enable"),
                ("DELETE", "/linode/instances/7"),
                ("DELETE", "/linode/instances/9"),
            ]
        );
        assert_eq!(seen[1].2.as_deref(), Some(r#"{"tags":"superbot"}"#));
        assert_eq!(
            seen[3].3,
            json!({ "type": "g6-standard-2", "allow_auto_disk_resize": true, "migration_type": "cold" })
        );
    }
}
