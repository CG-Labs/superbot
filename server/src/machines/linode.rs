//! Linode API v4 behind `MachineProvider`. Only `https://api.linode.com/v4` in
//! production; tests point it at a local stand-in. The token goes in the
//! Authorization header and nowhere else: not in errors, logs, or `Debug`.

use super::provider::{
    CreateSpec, FirewallRule, Fut, MachineProvider, ProviderError, ProviderFirewall,
    ProviderMachine,
};
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

    /// Every item of a paged list.
    async fn all(&self, path: &str, filter: Option<&Value>) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let v = self
                .call(
                    Method::GET,
                    &format!("{path}?page={page}&page_size={PAGE_SIZE}"),
                    filter,
                    None,
                )
                .await?;
            out.extend(v["data"].as_array().cloned().unwrap_or_default());
            if page >= v["pages"].as_u64().unwrap_or(1) as u32 {
                break;
            }
        }
        Ok(out)
    }

    /// The firewall's devices that are Linodes, as (device id, Linode id).
    async fn linode_devices(&self, id: &str) -> Result<Vec<(u64, String)>, ProviderError> {
        Ok(self
            .all(&format!("/networking/firewalls/{}/devices", path_id(id)?), None)
            .await?
            .iter()
            .filter(|d| d["entity"]["type"] == "linode")
            .filter_map(|d| Some((d["id"].as_u64()?, d["entity"]["id"].as_u64()?.to_string())))
            .collect())
    }
}

/// Our rules as Linode's: inbound dropped but for each rule, outbound open.
fn rules_body(rules: &[FirewallRule]) -> Value {
    let inbound: Vec<Value> = rules
        .iter()
        .map(|r| {
            let (v6, v4): (Vec<&String>, Vec<&String>) =
                r.sources.iter().partition(|s| s.contains(':'));
            let mut addresses = json!({});
            if !v4.is_empty() {
                addresses["ipv4"] = json!(v4);
            }
            if !v6.is_empty() {
                addresses["ipv6"] = json!(v6);
            }
            json!({ "label": r.label, "action": "ACCEPT", "protocol": "TCP", "ports": r.ports, "addresses": addresses })
        })
        .collect();
    json!({ "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": inbound, "outbound": [] })
}

/// Linode's rules as ours, or None if they aren't of the shape we make.
fn our_rules(r: &Value) -> Option<Vec<FirewallRule>> {
    if r["inbound_policy"] != "DROP"
        || r["outbound_policy"] != "ACCEPT"
        || r["outbound"].as_array().is_some_and(|a| !a.is_empty())
    {
        return None;
    }
    r["inbound"]
        .as_array()?
        .iter()
        .map(|x| {
            if x["action"] != "ACCEPT" || x["protocol"] != "TCP" {
                return None;
            }
            let mut sources = Vec::new();
            for family in ["ipv4", "ipv6"] {
                for a in x["addresses"][family].as_array().into_iter().flatten() {
                    sources.push(super::firewall::cidr(a.as_str()?).ok()?);
                }
            }
            sources.sort();
            sources.dedup();
            Some(FirewallRule {
                label: x["label"].as_str()?.into(),
                ports: x["ports"].as_str()?.replace(' ', ""),
                sources,
            })
        })
        .collect()
}

fn firewall(v: &Value) -> Result<ProviderFirewall, ProviderError> {
    let id = v["id"]
        .as_u64()
        .ok_or_else(|| ProviderError::Transport("Linode sent a firewall we couldn't read".into()))?;
    Ok(ProviderFirewall {
        id: id.to_string(),
        label: v["label"].as_str().unwrap_or_default().into(),
        rules: our_rules(&v["rules"]),
    })
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
            if let Some(ud) = &spec.user_data {
                body["metadata"] = json!({
                    "user_data": base64::engine::general_purpose::STANDARD.encode(ud)
                });
            }
            if let Some(fw) = &spec.firewall_id {
                body["firewall_id"] = json!(path_id(fw)?.parse::<u64>().unwrap_or_default());
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
            self.all("/linode/instances", Some(&filter))
                .await?
                .iter()
                .map(machine)
                .collect()
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

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>> {
        Box::pin(async move {
            let filter = json!({ "label": label });
            for f in self.all("/networking/firewalls", Some(&filter)).await? {
                let f = firewall(&f)?;
                if f.label == label {
                    return Ok(Some(f));
                }
            }
            Ok(None)
        })
    }

    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let body = json!({ "label": label, "tags": tags, "rules": rules_body(rules) });
            firewall(
                &self
                    .call(Method::POST, "/networking/firewalls", None, Some(&body))
                    .await?,
            )
        })
    }

    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::PUT,
                &format!("/networking/firewalls/{}/rules", path_id(id)?),
                None,
                Some(&rules_body(rules)),
            )
            .await
            .map(drop)
        })
    }

    fn firewall_machines<'a>(&'a self, id: &'a str) -> Fut<'a, Vec<String>> {
        Box::pin(async move {
            Ok(self
                .linode_devices(id)
                .await?
                .into_iter()
                .map(|(_, linode)| linode)
                .collect())
        })
    }

    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let linode: u64 = path_id(machine)?.parse().unwrap_or_default();
            self.call(
                Method::POST,
                &format!("/networking/firewalls/{}/devices", path_id(id)?),
                None,
                Some(&json!({ "id": linode, "type": "linode" })),
            )
            .await
            .map(drop)
        })
    }

    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let devices = match self.linode_devices(id).await {
                Err(ProviderError::NotFound) => return Ok(()),
                d => d?,
            };
            let Some((device, _)) = devices.into_iter().find(|(_, l)| l == machine) else {
                return Ok(());
            };
            match self
                .call(
                    Method::DELETE,
                    &format!("/networking/firewalls/{}/devices/{device}", path_id(id)?),
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

    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self
                .call(
                    Method::DELETE,
                    &format!("/networking/firewalls/{}", path_id(id)?),
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
            .route(
                "/v4/networking/firewalls",
                post(move |State(s): State<Seen>, h: HeaderMap, Json(b): Json<Value>| async move {
                    record(&s, "POST", "/networking/firewalls".into(), &h, b.clone());
                    if b["label"] == "taken-fw" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "label", "reason": "Label must be unique" }] })));
                    }
                    (StatusCode::OK, Json(json!({ "id": 77, "label": b["label"], "rules": b["rules"], "status": "enabled", "tags": b["tags"] })))
                })
                .get(move |State(s): State<Seen>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    record(&s, "GET", format!("/networking/firewalls?page={}&page_size={}", q["page"], q["page_size"]), &h, Value::Null);
                    // As Linode answers: its own spellings of addresses and ports, and
                    // a near-namesake the filter would have matched as a prefix.
                    let ours = json!({ "id": 77, "label": "superbot-fw", "rules": {
                        "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [], "version": 3,
                        "inbound": [{ "label": "agent-from-control-plane", "action": "ACCEPT", "protocol": "TCP", "ports": "7443",
                            "addresses": { "ipv4": ["192.0.2.1/32"], "ipv6": ["2001:DB8::1/128"] } }] } });
                    let other = json!({ "id": 78, "label": "superbot-fw-old", "rules": { "inbound_policy": "ACCEPT", "outbound_policy": "ACCEPT", "inbound": [], "outbound": [] } });
                    (StatusCode::OK, Json(json!({ "data": [other, ours], "page": 1, "pages": 1, "results": 2 })))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}",
                axum::routing::delete(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "DELETE", format!("/networking/firewalls/{id}"), &h, Value::Null);
                    match id {
                        77 => (StatusCode::OK, Json(json!({}))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/rules",
                axum::routing::put(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "PUT", format!("/networking/firewalls/{id}/rules"), &h, b);
                    (StatusCode::OK, Json(json!({})))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/devices",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/networking/firewalls/{id}/devices"), &h, Value::Null);
                    match id {
                        77 => (StatusCode::OK, Json(json!({ "data": [
                            { "id": 9001, "entity": { "id": 7, "type": "linode", "label": "superbot-m7" } },
                            { "id": 9002, "entity": { "id": 3, "type": "nodebalancer", "label": "lb" } },
                        ], "page": 1, "pages": 1, "results": 2 }))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                })
                .post(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "POST", format!("/networking/firewalls/{id}/devices"), &h, b);
                    (StatusCode::OK, Json(json!({ "id": 9003 })))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/devices/{device}",
                axum::routing::delete(move |State(s): State<Seen>, h: HeaderMap, Path((id, device)): Path<(u64, u64)>| async move {
                    record(&s, "DELETE", format!("/networking/firewalls/{id}/devices/{device}"), &h, Value::Null);
                    (StatusCode::OK, Json(json!({})))
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
            user_data: None,
            firewall_id: None,
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
        {
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
            assert!(
                body.get("metadata").is_none(),
                "no user data unless enrollment is on"
            );
        }

        let with = CreateSpec {
            user_data: Some("#cloud-config\n".into()),
            ..spec("superbot-m3")
        };
        api.create(&with).await.unwrap();
        let sent = seen.lock().unwrap().last().unwrap().3.clone();
        assert_eq!(
            sent["metadata"]["user_data"],
            json!("I2Nsb3VkLWNvbmZpZwo="),
            "base64, as Linode wants"
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
    async fn firewalls() {
        let (api, seen) = fake_api().await;
        let rules = vec![
            FirewallRule {
                label: "agent-from-control-plane".into(),
                ports: "7443".into(),
                sources: vec!["192.0.2.1/32".into(), "2001:db8::1/128".into()],
            },
            FirewallRule {
                label: "ssh-from-operators".into(),
                ports: "22".into(),
                sources: vec!["203.0.113.0/24".into()],
            },
        ];
        let made = api
            .create_firewall("superbot-fw", &["superbot".into()], &rules)
            .await
            .unwrap();
        assert_eq!(
            (made.id.as_str(), made.rules.as_deref()),
            ("77", Some(&rules[..])),
            "what we sent reads back as ours"
        );
        assert_eq!(
            api.create_firewall("taken-fw", &[], &rules).await,
            Err(ProviderError::LabelTaken)
        );
        let found = api.find_firewall("superbot-fw").await.unwrap().unwrap();
        assert_eq!(found.id, "77", "the exact label, not a namesake");
        assert_eq!(
            found.rules,
            Some(vec![rules[0].clone()]),
            "Linode's spelling of an address is the same address"
        );
        assert_eq!(api.find_firewall("superbot-fw-x").await.unwrap(), None);
        api.set_firewall_rules("77", &rules[..1]).await.unwrap();
        assert_eq!(api.firewall_machines("77").await.unwrap(), ["7"], "Linodes only");
        api.attach_firewall("77", "8").await.unwrap();
        api.detach_firewall("77", "7").await.unwrap();
        api.detach_firewall("77", "8").await.unwrap();
        api.detach_firewall("79", "7").await.unwrap();
        api.delete_firewall("77").await.unwrap();
        api.delete_firewall("78").await.unwrap();
        assert!(api.attach_firewall("77", "../7").await.is_err());
        let behind = CreateSpec {
            firewall_id: Some("77".into()),
            ..spec("superbot-m9")
        };
        api.create(&behind).await.unwrap();

        let seen = seen.lock().unwrap();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|(m, p, _, _)| (m.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("POST", "/networking/firewalls"),
                ("POST", "/networking/firewalls"),
                ("GET", "/networking/firewalls?page=1&page_size=500"),
                ("GET", "/networking/firewalls?page=1&page_size=500"),
                ("PUT", "/networking/firewalls/77/rules"),
                ("GET", "/networking/firewalls/77/devices"),
                ("POST", "/networking/firewalls/77/devices"),
                ("GET", "/networking/firewalls/77/devices"),
                ("DELETE", "/networking/firewalls/77/devices/9001"),
                ("GET", "/networking/firewalls/77/devices"),
                ("GET", "/networking/firewalls/79/devices"),
                ("DELETE", "/networking/firewalls/77"),
                ("DELETE", "/networking/firewalls/78"),
                ("POST", "/linode/instances"),
            ],
            "detach finds the device for the Linode; one not behind it is left alone"
        );
        assert_eq!(
            seen[0].3,
            json!({ "label": "superbot-fw", "tags": ["superbot"], "rules": {
                "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [],
                "inbound": [
                    { "label": "agent-from-control-plane", "action": "ACCEPT", "protocol": "TCP", "ports": "7443",
                      "addresses": { "ipv4": ["192.0.2.1/32"], "ipv6": ["2001:db8::1/128"] } },
                    { "label": "ssh-from-operators", "action": "ACCEPT", "protocol": "TCP", "ports": "22",
                      "addresses": { "ipv4": ["203.0.113.0/24"] } },
                ] } })
        );
        assert_eq!(seen[2].2.as_deref(), Some(r#"{"label":"superbot-fw"}"#));
        assert_eq!(seen[4].3["inbound"].as_array().unwrap().len(), 1);
        assert_eq!(seen[6].3, json!({ "id": 8, "type": "linode" }));
        assert_eq!(seen[13].3["firewall_id"], json!(77), "behind it from the first boot");
    }

    #[test]
    fn only_our_shape_of_rules_reads_as_ours() {
        let base = json!({ "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [], "inbound": [
            { "label": "a", "action": "ACCEPT", "protocol": "TCP", "ports": "7443", "addresses": { "ipv4": ["192.0.2.1/32"] } }] });
        assert!(our_rules(&base).is_some());
        for (path, v) in [
            ("/inbound_policy", json!("ACCEPT")),
            ("/outbound_policy", json!("DROP")),
            ("/outbound", json!([{ "action": "DROP", "protocol": "TCP" }])),
            ("/inbound/0/action", json!("DROP")),
            ("/inbound/0/protocol", json!("UDP")),
            ("/inbound/0/addresses/ipv4/0", json!("not an address")),
        ] {
            let mut r = base.clone();
            *r.pointer_mut(path).unwrap() = v;
            assert_eq!(our_rules(&r), None, "{path}");
        }
    }

    #[test]
    fn a_create_spec_never_shows_its_user_data() {
        let s = CreateSpec {
            user_data: Some("enroll-token: sbe_secret".into()),
            ..spec("superbot-m1")
        };
        let d = format!("{s:?}");
        assert!(!d.contains("sbe_secret") && d.contains("[redacted]"), "{d}");
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
