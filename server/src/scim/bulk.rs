//! SCIM Bulk (RFC 7644 section 3.7): `POST /scim/v2/Bulk` carries up to
//! MAX_OPERATIONS POST, PUT, PATCH and DELETE operations on `/Users` and `/Groups`.
//! Each operation goes to the handler a single request would reach, with the same
//! token, so validation, tenant scoping, deprovisioning and audit events are exactly
//! theirs. Operations run one at a time in the order sent, except that one using
//! `bulkId:<id>` waits for the POST that defines it. Nothing is rolled back: an
//! operation that succeeded stays done whatever the rest do.
//! Design: docs/adr/0149-scim-bulk.md.

use super::*;
use std::collections::HashSet;

/// Advertised in ServiceProviderConfig and enforced: more is a 413 and nothing runs.
pub const MAX_OPERATIONS: usize = 100;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
const RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
const MAX_BULK_ID: usize = 256;
const MAX_ID: usize = 256;
const BULK_ID: &str = "bulkId:";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Users,
    Groups,
}

impl Kind {
    fn endpoint(self) -> &'static str {
        match self {
            Kind::Users => "Users",
            Kind::Groups => "Groups",
        }
    }

    /// What one request to this endpoint may carry, so Bulk is never a way round it.
    fn max_body(self) -> usize {
        match self {
            Kind::Users => super::MAX_BODY,
            Kind::Groups => groups::MAX_BODY,
        }
    }
}

/// One operation, as checked before anything runs.
#[derive(Debug)]
struct Op {
    method: Method,
    kind: Kind,
    /// The resource in the path; None for a POST. May be `bulkId:<id>`.
    id: Option<String>,
    bulk_id: Option<String>,
    /// Null for a DELETE.
    data: Value,
    /// The `bulkId`s this operation refers to, in its path or data.
    refs: Vec<String>,
}

fn too_large(detail: String) -> ScimError {
    ScimError::new(StatusCode::PAYLOAD_TOO_LARGE, None, detail)
}

fn syntax(detail: String) -> ScimError {
    ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), detail)
}

/// `/Users` or `/Groups` for a POST, `/Users/{id}` or `/Groups/{id}` otherwise.
fn path(method: Method, p: &str) -> Option<(Kind, Option<String>)> {
    let (endpoint, id) = match p.strip_prefix('/')?.split_once('/') {
        Some((e, id)) => (e, Some(id)),
        None => (p.strip_prefix('/')?, None),
    };
    let kind = match endpoint {
        "Users" => Kind::Users,
        "Groups" => Kind::Groups,
        _ => return None,
    };
    match (method, id) {
        (Method::Post, None) => Some((kind, None)),
        (Method::Post, Some(_)) | (_, None) => None,
        (_, Some(id)) if id.is_empty() || id.chars().count() > MAX_ID || id.chars().any(|c| c.is_control() || matches!(c, '/' | '?' | '#')) => None,
        (_, Some(id)) => Some((kind, Some(id.to_string()))),
    }
}

/// The quoted `"bulkId:<id>"` values in a PATCH path filter such as
/// `members[value eq "bulkId:u"]`, as (start, end, id) with start..end covering the
/// quotes.
fn quoted_refs(s: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = s[from..].find(&format!("\"{BULK_ID}")).map(|n| from + n) {
        let id_at = at + 1 + BULK_ID.len();
        let Some(len) = s[id_at..].find('"') else { break };
        out.push((at, id_at + len + 1, &s[id_at..id_at + len]));
        from = id_at + len + 1;
    }
    out
}

/// Every `bulkId:<id>` in `v`, each once: whole string values, and quoted values inside
/// a PATCH operation's `path` filter.
fn refs_in(v: &Value, out: &mut Vec<String>) {
    fn add(out: &mut Vec<String>, id: &str) {
        if !out.iter().any(|r| r == id) {
            out.push(id.to_string());
        }
    }
    match v {
        Value::String(s) => {
            if let Some(id) = s.strip_prefix(BULK_ID) {
                add(out, id);
            }
        }
        Value::Array(l) => l.iter().for_each(|x| refs_in(x, out)),
        Value::Object(o) => {
            for (k, x) in o {
                match x.as_str() {
                    Some(s) if k.eq_ignore_ascii_case("path") => quoted_refs(s).into_iter().for_each(|(_, _, id)| add(out, id)),
                    _ => refs_in(x, out),
                }
            }
        }
        _ => {}
    }
}

/// `v` with each `bulkId:<id>` (as `refs_in` finds them) replaced by the id its POST
/// made. Every reference is resolved before this is called.
fn resolve(v: &Value, made: &HashMap<String, String>) -> Value {
    match v {
        Value::String(s) => match s.strip_prefix(BULK_ID).and_then(|id| made.get(id)) {
            Some(id) => json!(id),
            None => v.clone(),
        },
        Value::Array(l) => Value::Array(l.iter().map(|x| resolve(x, made)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| match x.as_str() {
                    Some(s) if k.eq_ignore_ascii_case("path") => (k.clone(), json!(resolve_quoted(s, made))),
                    _ => (k.clone(), resolve(x, made)),
                })
                .collect(),
        ),
        _ => v.clone(),
    }
}

fn resolve_quoted(s: &str, made: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut from = 0;
    for (start, end, id) in quoted_refs(s) {
        if let Some(new) = made.get(id) {
            out.push_str(&s[from..start]);
            out.push_str(&json!(new).to_string());
            from = end;
        }
    }
    out.push_str(&s[from..]);
    out
}

/// The whole request, checked before any operation runs: the envelope, each
/// operation's method, path, `bulkId` and `data`, and the limits. Any problem refuses
/// the request (400 or 413) with nothing done. Returns the operations and `failOnErrors`.
fn read(v: &Value) -> ScimRes<(Vec<Op>, Option<usize>)> {
    if !v.is_object() {
        return Err(syntax("Send the bulk request as a JSON object".into()));
    }
    let list = key(v, "Operations").and_then(Value::as_array).filter(|l| !l.is_empty()).ok_or_else(|| syntax("Operations must be a list of operations".into()))?;
    if list.len() > MAX_OPERATIONS {
        return Err(too_large(format!("The bulk request has {} operations, more than maxOperations ({MAX_OPERATIONS}).", list.len())));
    }
    let fail_on = match key(v, "failOnErrors") {
        None | Some(Value::Null) => None,
        Some(n) => Some(n.as_u64().filter(|n| *n >= 1).ok_or_else(|| invalid("failOnErrors must be a whole number, at least 1"))? as usize),
    };
    let mut ops = Vec::with_capacity(list.len());
    let mut defined = HashSet::new();
    for (i, op) in list.iter().enumerate() {
        let at = |d: &str| format!("Operations[{i}]: {d}");
        if !op.is_object() {
            return Err(syntax(at("each operation must be an object")));
        }
        let method = match attr(op, "method").as_str().map(str::to_ascii_uppercase).as_deref() {
            Some("POST") => Method::Post,
            Some("PUT") => Method::Put,
            Some("PATCH") => Method::Patch,
            Some("DELETE") => Method::Delete,
            _ => return Err(syntax(at("method must be POST, PUT, PATCH, or DELETE"))),
        };
        let p = attr(op, "path").as_str().map(str::trim).unwrap_or("");
        let (kind, id) = path(method, p).ok_or_else(|| {
            let want = if method == Method::Post { "/Users or /Groups" } else { "/Users/{id} or /Groups/{id}" };
            ScimError::new(StatusCode::BAD_REQUEST, Some("invalidPath"), at(&format!("path must be {want} for {}", method.name())))
        })?;
        let bulk_id = text(attr(op, "bulkId"), &at("bulkId"), MAX_BULK_ID)?;
        if method == Method::Post {
            let b = bulk_id.as_deref().ok_or_else(|| invalid(at("bulkId is required for POST")))?;
            if !defined.insert(b.to_string()) {
                return Err(invalid(at(&format!("bulkId {b} is used by another POST in this request"))));
            }
        }
        let data = match method {
            Method::Delete => Value::Null,
            _ => attr(op, "data").clone(),
        };
        if method != Method::Delete && !data.is_object() {
            return Err(syntax(at("data must be an object: the body a single request would send")));
        }
        let mut refs = Vec::new();
        refs_in(&json!(id), &mut refs);
        refs_in(&data, &mut refs);
        ops.push(Op { method, kind, id, bulk_id, data, refs });
    }
    Ok((ops, fail_on))
}

/// The order operations run in: as sent, except that a POST another operation refers to
/// by `bulkId` runs just before the first operation that needs it (after the POSTs it
/// refers to itself). Nothing else moves, so later writes never pass earlier ones.
/// `true` marks an operation that can't run: its references are circular, or wait on
/// ones that are.
fn order(ops: &[Op]) -> Vec<(usize, bool)> {
    #[derive(Clone, Copy, PartialEq)]
    enum Seen {
        No,
        Visiting,
        Ran,
        Stuck,
    }
    fn visit(i: usize, deps: &[Vec<usize>], seen: &mut [Seen], out: &mut Vec<(usize, bool)>) -> bool {
        match seen[i] {
            Seen::Ran => return true,
            Seen::Visiting | Seen::Stuck => return false,
            Seen::No => {}
        }
        seen[i] = Seen::Visiting;
        let mut ready = true;
        for &d in &deps[i] {
            ready &= visit(d, deps, seen, out);
        }
        seen[i] = if ready { Seen::Ran } else { Seen::Stuck };
        out.push((i, !ready));
        ready
    }
    let posts: HashMap<&str, usize> = ops.iter().enumerate().filter(|(_, o)| o.method == Method::Post).filter_map(|(i, o)| Some((o.bulk_id.as_deref()?, i))).collect();
    let deps: Vec<Vec<usize>> = ops.iter().map(|o| o.refs.iter().filter_map(|r| posts.get(r.as_str()).copied()).collect()).collect();
    let mut seen = vec![Seen::No; ops.len()];
    let mut out = Vec::with_capacity(ops.len());
    for i in 0..ops.len() {
        visit(i, &deps, &mut seen, &mut out);
    }
    out
}

/// Hands one operation to the endpoint's own handler.
async fn dispatch(app: &AppState, a: &Arc<Auth>, c: &Caller, headers: &HeaderMap, op: &Op, id: Option<String>, data: &Value) -> ScimRes {
    let body = || -> ScimRes<Result<Bytes, BytesRejection>> {
        let bytes = serde_json::to_vec(data).map_err(|e| server_error(e.to_string()))?;
        let max = op.kind.max_body();
        if bytes.len() > max {
            return Err(too_large(format!("data is {} bytes, more than one {} request may send ({max}).", bytes.len(), op.kind.endpoint())));
        }
        Ok(Ok(Bytes::from(bytes)))
    };
    let (st, ex, ca) = (State(app.clone()), Extension(a.clone()), Extension(c.clone()));
    let at = || Path(id.clone().unwrap_or_default());
    match (op.kind, op.method) {
        (Kind::Users, Method::Post) => create_user(st, ex, ca, headers.clone(), body()?).await,
        (Kind::Users, Method::Put) => replace_user(st, ex, ca, headers.clone(), at(), body()?).await,
        (Kind::Users, Method::Patch) => patch_user(st, ex, ca, headers.clone(), at(), body()?).await,
        (Kind::Users, Method::Delete) => delete_user(st, ex, ca, at()).await,
        (Kind::Groups, Method::Post) => groups::create(st, ex, ca, headers.clone(), body()?).await,
        (Kind::Groups, Method::Put) => groups::replace(st, ex, ca, headers.clone(), at(), body()?).await,
        (Kind::Groups, Method::Patch) => groups::patch(st, ex, ca, at(), body()?).await,
        (Kind::Groups, Method::Delete) => groups::delete(st, ex, ca, at()).await,
    }
}

/// One operation's result, as RFC 7644 section 3.7.3 shows it: the error body only on
/// failure, and a location for all but a failed POST.
struct Done {
    entry: Value,
    ok: bool,
    /// The id a successful POST made.
    made: Option<String>,
}

async fn done(op: &Op, location: Option<String>, res: ScimRes) -> Done {
    let mut entry = json!({ "method": op.method.name() });
    if let Some(b) = &op.bulk_id {
        entry["bulkId"] = json!(b);
    }
    let (status, location, body, ok) = match res {
        Ok(r) => {
            let status = r.status();
            let at = r.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).map(String::from);
            let bytes = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap_or_default();
            let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let at = at.or_else(|| body["meta"]["location"].as_str().map(String::from)).or(location);
            (status, at, body, status.is_success())
        }
        Err(e) => (e.status, location, e.body(), false),
    };
    entry["status"] = json!(status.as_u16().to_string());
    if let Some(l) = location {
        entry["location"] = json!(l);
    }
    let made = (ok && op.method == Method::Post).then(|| body["id"].as_str().map(String::from)).flatten();
    if !ok {
        entry["response"] = body;
    }
    Done { entry, ok, made }
}

/// Why processing ended before the last operation.
#[derive(Clone, Copy, PartialEq)]
enum Stopped {
    FailOnErrors,
    RateLimited,
}

/// `POST /scim/v2/Bulk`. 200 with a BulkResponse whenever the request was read, even if
/// every operation failed: each has its own status. The results are in the order the
/// operations ran; with `failOnErrors`, processing stops once that many have failed,
/// and the rest aren't run or listed. Each operation after the first counts against
/// the tenant's rate limit; one over it gets a 429 and processing stops there.
pub async fn bulk(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if let Err(e) = &body
        && e.status() == StatusCode::PAYLOAD_TOO_LARGE
    {
        return Err(too_large(format!("The size of the bulk operation exceeds the maxPayloadSize ({MAX_PAYLOAD}).")));
    }
    let (ops, fail_on) = read(&parse_body(body)?)?;
    let run = order(&ops);
    let base = base_url(&headers);
    let tenant = c.token.tenant.as_str();
    let posts: HashSet<&str> = ops.iter().filter(|o| o.method == Method::Post).filter_map(|o| o.bulk_id.as_deref()).collect();
    let mut made: HashMap<String, String> = HashMap::new();
    let (mut results, mut audit) = (Vec::new(), Vec::new());
    let (mut failed, mut stopped) = (0usize, None);
    for (n, &(i, circular)) in run.iter().enumerate() {
        if fail_on.is_some_and(|f| failed >= f) {
            stopped = Some(Stopped::FailOnErrors);
            break;
        }
        let op = &ops[i];
        let limited = if n == 0 { None } else { a.scim.limiter.hit(tenant, db::now()) };
        let unresolved = op.refs.iter().find(|r| !made.contains_key(r.as_str()));
        let id = op.id.as_deref().map(|id| resolve(&json!(id), &made).as_str().unwrap_or(id).to_string());
        let location = id.as_ref().map(|id| format!("{base}/{}/{id}", op.kind.endpoint()));
        let res = match (limited, unresolved) {
            (Some(retry), _) => {
                stopped = Some(Stopped::RateLimited);
                Err(ScimError::new(StatusCode::TOO_MANY_REQUESTS, None, format!("Too many requests. Send this operation and the rest again in {} seconds.", retry.max(1))))
            }
            (None, Some(r)) if circular => Err(ScimError::new(StatusCode::CONFLICT, None, format!("bulkId:{r}: this operation's bulkId references are circular, so it was not run."))),
            (None, Some(r)) if !posts.contains(r.as_str()) => Err(ScimError::new(StatusCode::CONFLICT, None, format!("bulkId:{r} isn't the bulkId of a POST in this request."))),
            (None, Some(r)) => Err(ScimError::new(StatusCode::CONFLICT, None, format!("bulkId:{r}: the POST that defines it failed, so this operation was not run."))),
            (None, None) => dispatch(&app, &a, &c, &headers, op, id.clone(), &resolve(&op.data, &made)).await,
        };
        let d = done(op, location, res).await;
        if let (Some(b), Some(new)) = (&op.bulk_id, &d.made) {
            made.insert(b.clone(), new.clone());
        }
        if !d.ok {
            failed += 1;
        }
        let path = match &id {
            Some(id) => format!("/{}/{id}", op.kind.endpoint()),
            None => format!("/{}", op.kind.endpoint()),
        };
        audit.push(json!({ "method": op.method.name(), "path": path, "bulkId": op.bulk_id, "status": d.entry["status"] }));
        results.push(d.entry);
        if stopped == Some(Stopped::RateLimited) {
            break;
        }
    }
    let stopped = stopped.map(|s| match s {
        Stopped::FailOnErrors => "failOnErrors",
        Stopped::RateLimited => "rateLimited",
    });
    let outcome = if failed == 0 { Outcome::Success } else { Outcome::Failure };
    app.db.record(&c.who.event("scim.bulk").outcome(outcome).details(json!({
        "tenant": tenant, "operations": ops.len(), "run": results.len(), "failed": failed, "failOnErrors": fail_on, "stopped": stopped, "results": audit,
    })));
    Ok(scim_json(StatusCode::OK, json!({ "schemas": [RESPONSE_SCHEMA], "Operations": results })))
}

/// Any other method on `/Bulk`.
pub async fn only_post() -> Response {
    let mut r = ScimError::new(StatusCode::METHOD_NOT_ALLOWED, None, "Bulk takes POST only").into_response();
    r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: &str, path: &str, extra: Value) -> Value {
        let mut o = json!({ "method": method, "path": path });
        o.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        o
    }

    fn req(ops: Vec<Value>) -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": ops })
    }

    #[test]
    fn paths_name_an_endpoint_or_one_resource() {
        assert_eq!(path(Method::Post, "/Users"), Some((Kind::Users, None)));
        assert_eq!(path(Method::Post, "/Groups"), Some((Kind::Groups, None)));
        assert_eq!(path(Method::Put, "/Users/u1"), Some((Kind::Users, Some("u1".into()))));
        assert_eq!(path(Method::Delete, "/Groups/bulkId:g"), Some((Kind::Groups, Some("bulkId:g".into()))));
        for (m, bad) in [
            (Method::Post, "/Users/u1"),
            (Method::Put, "/Users"),
            (Method::Patch, "/Users/"),
            (Method::Delete, "/Users/a/b"),
            (Method::Patch, "/Users/a?x=1"),
            (Method::Post, "Users"),
            (Method::Post, "/users"),
            (Method::Post, "/Bulk"),
            (Method::Post, "/Schemas"),
            (Method::Post, ""),
        ] {
            assert_eq!(path(m, bad), None, "{bad}");
        }
    }

    #[test]
    fn requests_are_checked_whole_before_anything_runs() {
        let user = json!({ "userName": "ada@example.com" });
        let (ops, fail_on) = read(&req(vec![
            op("post", "/Users", json!({ "bulkId": "u", "data": user })),
            op("PATCH", "/Users/bulkId:u", json!({ "data": { "Operations": [] }, "version": "W/\"1\"" })),
            op("DELETE", "/Users/x", json!({})),
        ]))
        .unwrap();
        assert_eq!((ops.len(), fail_on), (3, None));
        assert_eq!((ops[0].method, ops[1].refs.clone(), ops[2].data.clone()), (Method::Post, vec!["u".to_string()], Value::Null));
        let mut with = req(vec![op("DELETE", "/Users/x", json!({}))]);
        with["failOnErrors"] = json!(2);
        assert_eq!(read(&with).unwrap().1, Some(2));

        let post = |b: Value| op("POST", "/Users", json!({ "bulkId": b, "data": user }));
        for (bad, status) in [
            (json!([]), 400),
            (json!({}), 400),
            (json!({ "Operations": [] }), 400),
            (json!({ "Operations": {} }), 400),
            (req(vec![json!("POST /Users")]), 400),
            (req(vec![op("GET", "/Users/x", json!({}))]), 400),
            (req(vec![op("POST", "/Users", json!({ "data": user }))]), 400),
            (req(vec![post(json!("a")), post(json!("a"))]), 400),
            (req(vec![post(json!(7))]), 400),
            (req(vec![post(json!("x".repeat(257)))]), 400),
            (req(vec![op("PUT", "/Users/x", json!({}))]), 400),
            (req(vec![op("PATCH", "/Users/x", json!({ "data": [] }))]), 400),
            (req(vec![op("POST", "/Bulk", json!({ "bulkId": "b", "data": {} }))]), 400),
            (req((0..=MAX_OPERATIONS).map(|i| op("DELETE", &format!("/Users/{i}"), json!({}))).collect()), 413),
        ] {
            let e = read(&bad).unwrap_err();
            assert_eq!(e.status.as_u16(), status, "{bad}: {}", e.detail);
        }
        for f in [json!(0), json!(-1), json!(1.5), json!("1")] {
            let mut r = req(vec![op("DELETE", "/Users/x", json!({}))]);
            r["failOnErrors"] = f.clone();
            assert!(read(&r).is_err(), "{f}");
        }
        assert!(read(&req((0..MAX_OPERATIONS).map(|i| op("DELETE", &format!("/Users/{i}"), json!({}))).collect())).is_ok());
    }

    #[test]
    fn references_wait_for_their_post_and_cycles_never_run() {
        let ops = read(&req(vec![
            op("POST", "/Groups", json!({ "bulkId": "g", "data": { "displayName": "Eng", "members": [{ "value": "bulkId:a" }, { "value": "bulkId:b" }] } })),
            op("POST", "/Users", json!({ "bulkId": "a", "data": { "userName": "a" } })),
            op("PATCH", "/Users/bulkId:b", json!({ "data": { "Operations": [] } })),
            op("POST", "/Users", json!({ "bulkId": "b", "data": { "userName": "b" } })),
            op("POST", "/Users", json!({ "bulkId": "c", "data": { "userName": "c", "externalId": "bulkId:d" } })),
            op("POST", "/Users", json!({ "bulkId": "d", "data": { "userName": "d", "externalId": "bulkId:c" } })),
            op("DELETE", "/Users/bulkId:nobody", json!({})),
        ]))
        .unwrap()
        .0;
        assert_eq!(order(&ops), vec![(1, false), (3, false), (0, false), (2, false), (5, true), (4, true), (6, false)]);
        let made: HashMap<String, String> = [("a".to_string(), "u-a".to_string())].into();
        assert_eq!(resolve(&ops[0].data, &made)["members"], json!([{ "value": "u-a" }, { "value": "bulkId:b" }]));

        let ops = read(&req(vec![
            op("PATCH", "/Groups/g1", json!({ "data": { "Operations": [{ "op": "add", "path": "members", "value": [{ "value": "bulkId:u" }] }] } })),
            op("PUT", "/Groups/g1", json!({ "data": { "displayName": "Eng", "members": [] } })),
            op("POST", "/Users", json!({ "bulkId": "u", "data": { "userName": "u" } })),
            op("POST", "/Users", json!({ "bulkId": "me", "data": { "userName": "me", "externalId": "bulkId:me" } })),
        ]))
        .unwrap()
        .0;
        assert_eq!(order(&ops), vec![(2, false), (0, false), (1, false), (3, true)], "only the POST moves, so the PUT still runs last");
    }

    #[test]
    fn references_inside_patch_path_filters_resolve() {
        let data = json!({ "Operations": [
            { "op": "add", "path": "members", "value": [{ "value": "bulkId:u" }] },
            { "op": "remove", "path": "members[value eq \"bulkId:u\"]" },
            { "op": "remove", "path": "members[value eq \"bulkId:v\"] and members[value eq \"bulkId:u\"]" },
            { "op": "replace", "path": "displayName", "value": "says \"bulkId:w\"" },
        ] });
        let mut refs = Vec::new();
        refs_in(&data, &mut refs);
        assert_eq!(refs, vec!["u", "v"], "a quoted reference counts only inside a path");
        let made: HashMap<String, String> = [("u".to_string(), "u-1".to_string())].into();
        let out = resolve(&data, &made);
        assert_eq!(out["Operations"][0]["value"], json!([{ "value": "u-1" }]));
        assert_eq!(out["Operations"][1]["path"], json!("members[value eq \"u-1\"]"));
        assert_eq!(out["Operations"][2]["path"], json!("members[value eq \"bulkId:v\"] and members[value eq \"u-1\"]"));
        assert_eq!(out["Operations"][3]["value"], json!("says \"bulkId:w\""));
        assert_eq!(resolve_quoted("members[value eq \"bulkId:u", &made), "members[value eq \"bulkId:u", "unterminated");
    }
}
