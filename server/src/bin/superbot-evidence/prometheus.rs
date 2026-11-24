//! Prometheus' HTTP API, read only: instant queries of a range vector, so the probe's raw
//! samples come back with their own timestamps rather than values Prometheus evaluated on
//! a grid (which would carry a stopped probe's last answer for five minutes). A bearer
//! token, if any, comes from `PROMETHEUS_TOKEN` and never goes over plain HTTP off this
//! computer. Server errors and dropped connections are retried.

use serde_json::Value;
use std::time::Duration;

const RETRIES: u32 = 3;

/// What the uptime exporter needs from Prometheus; the tests answer it from fixtures.
pub trait Api {
    /// `GET /api/v1/query?query=<query>&time=<time_s>`: the `data` of a successful answer.
    fn query(&mut self, query: &str, time_s: i64) -> Result<Value, String>;
}

/// `--prometheus`: `http(s)://host[:port][/path]`, no query, fragment or credentials, no
/// trailing slash. A token needs `https`, or plain `http` to this computer.
pub fn base_url(raw: &str, has_token: bool) -> Result<String, String> {
    let raw = raw.trim();
    let u = url::Url::parse(raw).map_err(|e| format!("--prometheus {raw}: {e}"))?;
    if !matches!(u.scheme(), "https" | "http") {
        return Err(format!("--prometheus must be an http or https URL, not {raw}"));
    }
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return Err("--prometheus takes no credentials, query or fragment: a token goes in PROMETHEUS_TOKEN.".into());
    }
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if has_token && u.scheme() == "http" && !loopback {
        return Err("PROMETHEUS_TOKEN is set, so --prometheus must be https (plain http only to this computer): the token would cross the network in clear.".into());
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

pub struct Http {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
    rt: tokio::runtime::Runtime,
    pub requests: u64,
}

impl Http {
    pub fn new(base: &str, token: Option<String>) -> Result<Http, String> {
        let token = token.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        let base = base_url(base, token.is_some())?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let _in = rt.enter();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        drop(_in);
        Ok(Http { base, token, http, rt, requests: 0 })
    }
}

/// Prometheus' own reason for refusing a query, from its error body.
fn refusal(status: u16, text: &str) -> String {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    match v["error"].as_str() {
        Some(e) => format!("Prometheus answered {status}: {e}"),
        None => format!("Prometheus answered {status}: {}", text.chars().take(200).collect::<String>()),
    }
}

/// The `data` of a query's answer, or why it failed.
pub fn data(status: u16, text: &str) -> Result<Value, String> {
    if !(200..300).contains(&status) {
        return Err(refusal(status, text));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| format!("Prometheus' answer isn't JSON: {e}"))?;
    if v["status"] != "success" {
        return Err(refusal(status, text));
    }
    Ok(v["data"].clone())
}

impl Api for Http {
    fn query(&mut self, query: &str, time_s: i64) -> Result<Value, String> {
        let mut url = url::Url::parse(&format!("{}/api/v1/query", self.base)).map_err(|e| e.to_string())?;
        url.query_pairs_mut().append_pair("query", query).append_pair("time", &time_s.to_string());
        let _in = self.rt.enter();
        let mut attempt = 0;
        loop {
            let mut req = self
                .http
                .get(url.clone())
                .header(reqwest::header::USER_AGENT, concat!("superbot-evidence/", env!("CARGO_PKG_VERSION")));
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            self.requests += 1;
            let res = match self.rt.block_on(req.send()) {
                Ok(r) => r,
                Err(e) if attempt < RETRIES => {
                    eprintln!("Prometheus didn't answer ({e}); trying again.");
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                    continue;
                }
                Err(e) => return Err(format!("Prometheus didn't answer: {e}")),
            };
            let status = res.status().as_u16();
            let text = self.rt.block_on(res.text()).unwrap_or_default();
            if status >= 500 && attempt < RETRIES {
                attempt += 1;
                std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                continue;
            }
            return data(status, &text).map_err(|e| match status {
                401 | 403 => format!("{e}\nPrometheus refused the request: check PROMETHEUS_TOKEN."),
                _ => e,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_never_crosses_the_network_in_clear() {
        assert_eq!(base_url("https://prom.example.com/", true).unwrap(), "https://prom.example.com");
        assert_eq!(base_url("http://prometheus:9090", false).unwrap(), "http://prometheus:9090", "an internal Prometheus with no token");
        assert_eq!(base_url("http://127.0.0.1:9090/prom", true).unwrap(), "http://127.0.0.1:9090/prom");
        assert!(base_url("http://prometheus:9090", true).unwrap_err().contains("PROMETHEUS_TOKEN"));
        for bad in ["ftp://x", "https://u:p@prom.example.com", "https://prom.example.com/?q=1", "https://prom.example.com/#x", "not a url"] {
            assert!(base_url(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn answers_and_refusals() {
        assert_eq!(data(200, r#"{"status":"success","data":{"resultType":"matrix","result":[]}}"#).unwrap()["resultType"], "matrix");
        assert_eq!(data(400, r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#).unwrap_err(), "Prometheus answered 400: parse error");
        assert!(data(200, "<html>").unwrap_err().contains("isn't JSON"));
        assert!(data(502, "Bad Gateway").unwrap_err().contains("502: Bad Gateway"));
    }
}
