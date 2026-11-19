//! Roles and permissions (RBAC v1). Every API request is mapped to one permission
//! by `classify`, in the auth middleware, before any handler runs. Anything not in
//! the table needs `Admin`, so a new route is closed until someone classifies it.
//! Design: docs/adr/0012-users-sessions-rbac.md.

use axum::http::Method;
use serde::{Deserialize, Serialize};

/// A person's role in the org. Bots are not users and have their own column in the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
    Readonly,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
            Role::Readonly => "readonly",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "member" => Some(Role::Member),
            "readonly" | "read-only" => Some(Role::Readonly),
            _ => None,
        }
    }
}

/// Who is calling: a signed-in person with a role, or a Bot (`botctl`, with the
/// per-start BOT_TOKEN that every Bot run can read).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Principal {
    User(Role),
    Bot,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// Your own session: who am I, sign out.
    Account,
    /// Look: state, Bots, chats, routines, policy, models, live events.
    Read,
    /// The approvals list. People only: it shows every Bot's pending tool calls.
    Review,
    /// Change things and make Bots act: chat, stop, create/edit/delete Bots and
    /// routines, open a screen (its link gives control), Bot-to-Bot and the hook.
    Write,
    /// Approve or deny a Bot's risky tool call. People only, or a Bot could approve itself.
    Approve,
    /// Policy and rules, the audit log, users, sessions, and secrets.
    Admin,
}

pub const PERMS: [Perm; 6] = [Perm::Account, Perm::Read, Perm::Review, Perm::Write, Perm::Approve, Perm::Admin];

impl Perm {
    pub fn as_str(self) -> &'static str {
        match self {
            Perm::Account => "account",
            Perm::Read => "read",
            Perm::Review => "review",
            Perm::Write => "write",
            Perm::Approve => "approve",
            Perm::Admin => "admin",
        }
    }
}

/// The whole matrix.
pub fn allows(p: Principal, perm: Perm) -> bool {
    use Perm::*;
    match p {
        Principal::User(Role::Admin) => true,
        Principal::User(Role::Member) => matches!(perm, Account | Read | Review | Write | Approve),
        Principal::User(Role::Readonly) => matches!(perm, Account | Read | Review),
        Principal::Bot => matches!(perm, Account | Read | Write),
    }
}

pub fn granted(p: Principal) -> Vec<&'static str> {
    PERMS.iter().filter(|&&perm| allows(p, perm)).map(|p| p.as_str()).collect()
}

/// The permission a request needs. `path` is the raw request path. Segments are
/// matched exactly, so an encoded or doubled slash falls through to `Admin`.
pub fn classify(method: &Method, path: &str) -> Perm {
    use Perm::*;
    let Some(api) = path.strip_prefix("/api/") else {
        // The embedded web app's files. Anything else is a 404 or 405 anyway.
        return if method == Method::GET || method == Method::HEAD { Read } else { Admin };
    };
    let s: Vec<&str> = api.split('/').collect();
    if s.iter().any(|seg| seg.is_empty()) {
        return Admin;
    }
    let m = if method == Method::HEAD { "GET" } else { method.as_str() };
    match (m, s.as_slice()) {
        // The admin portal (ADR 0021): users, sign-in codes, identities, sessions, and a
        // user's Bot access. First, so no broader arm added below can ever open them.
        (_, ["users", ..] | ["sessions", ..]) => Admin,

        ("GET", ["auth", "me"]) | ("POST", ["auth", "logout"]) => Account,

        ("GET", ["state" | "events" | "bots" | "policy"]) => Read,
        ("GET", ["harnesses", _, "models"]) => Read,
        ("GET", ["bots", _, "messages" | "routines" | "policy" | "access"]) => Read,
        ("GET", ["policy", "rules"]) => Read,
        ("GET", ["approvals"]) => Review,

        ("GET", ["bots", _, "screen"]) => Write,
        ("POST", ["bots"]) => Write,
        ("PATCH" | "DELETE", ["bots", _]) => Write,
        ("POST", ["bots", _, "messages" | "read" | "stop" | "routines"]) => Write,
        ("PATCH" | "DELETE", ["routines", _]) => Write,
        // Bot ACLs. Handlers also require the Bot's owner or an admin (ADR 0017).
        ("PATCH", ["bots", _, "access"]) => Write,
        ("PUT" | "DELETE", ["bots", _, "grants", _]) => Write,
        ("POST", ["ask" | "handoff"]) => Write,
        ("POST", ["approvals", "check"]) => Write,

        ("POST", ["approvals", _, "approve" | "deny"]) => Approve,

        _ => Admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: Principal = Principal::User(Role::Admin);
    const MEMBER: Principal = Principal::User(Role::Member);
    const READONLY: Principal = Principal::User(Role::Readonly);
    const BOT: Principal = Principal::Bot;

    #[test]
    fn the_matrix() {
        // (perm, admin, member, readonly, bot)
        let table = [
            (Perm::Account, true, true, true, true),
            (Perm::Read, true, true, true, true),
            (Perm::Review, true, true, true, false),
            (Perm::Write, true, true, false, true),
            (Perm::Approve, true, true, false, false),
            (Perm::Admin, true, false, false, false),
        ];
        for (perm, a, m, r, b) in table {
            assert_eq!([allows(ADMIN, perm), allows(MEMBER, perm), allows(READONLY, perm), allows(BOT, perm)], [a, m, r, b], "{perm:?}");
        }
        assert_eq!(granted(READONLY), ["account", "read", "review"]);
    }

    #[test]
    fn every_route_is_classified() {
        let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
        let cases = [
            ("GET", "/api/state", Perm::Read),
            ("GET", "/api/events", Perm::Read),
            ("GET", "/api/bots", Perm::Read),
            ("GET", "/api/harnesses/claude/models", Perm::Read),
            ("GET", "/api/bots/b1/messages", Perm::Read),
            ("GET", "/api/bots/b1/routines", Perm::Read),
            ("GET", "/api/bots/b1/policy", Perm::Read),
            ("GET", "/api/bots/b1/access", Perm::Read),
            ("PATCH", "/api/bots/b1/access", Perm::Write),
            ("PUT", "/api/bots/b1/grants/u1", Perm::Write),
            ("DELETE", "/api/bots/b1/grants/a%40example.com", Perm::Write),
            ("GET", "/api/policy", Perm::Read),
            ("GET", "/api/policy/rules", Perm::Read),
            ("GET", "/api/approvals", Perm::Review),
            ("GET", "/api/bots/b1/screen", Perm::Write),
            ("POST", "/api/bots", Perm::Write),
            ("PATCH", "/api/bots/b1", Perm::Write),
            ("DELETE", "/api/bots/b1", Perm::Write),
            ("POST", "/api/bots/b1/messages", Perm::Write),
            ("POST", "/api/bots/b1/read", Perm::Write),
            ("POST", "/api/bots/b1/stop", Perm::Write),
            ("POST", "/api/bots/b1/routines", Perm::Write),
            ("PATCH", "/api/routines/r1", Perm::Write),
            ("DELETE", "/api/routines/r1", Perm::Write),
            ("POST", "/api/ask", Perm::Write),
            ("POST", "/api/handoff", Perm::Write),
            ("POST", "/api/approvals/check", Perm::Write),
            ("POST", "/api/approvals/a1/approve", Perm::Approve),
            ("POST", "/api/approvals/a1/deny", Perm::Approve),
            ("PUT", "/api/policy", Perm::Admin),
            ("PUT", "/api/bots/b1/policy", Perm::Admin),
            ("DELETE", "/api/bots/b1/policy", Perm::Admin),
            ("POST", "/api/policy/rules", Perm::Admin),
            ("DELETE", "/api/policy/rules/r1", Perm::Admin),
            ("GET", "/api/audit", Perm::Admin),
            ("GET", "/api/audit/export.csv", Perm::Admin),
            ("GET", "/api/users", Perm::Admin),
            ("POST", "/api/users", Perm::Admin),
            ("GET", "/api/users/u1", Perm::Admin),
            ("PATCH", "/api/users/u1", Perm::Admin),
            ("POST", "/api/users/u1/login-codes", Perm::Admin),
            ("DELETE", "/api/users/u1/sessions", Perm::Admin),
            ("GET", "/api/users/u1/bots", Perm::Admin),
            ("GET", "/api/users/a%40example.com/bots", Perm::Admin),
            ("GET", "/api/users/u1/identities", Perm::Admin),
            ("POST", "/api/users/u1/identities", Perm::Admin),
            ("DELETE", "/api/users/u1/identities/i1", Perm::Admin),
            ("GET", "/api/sessions", Perm::Admin),
            ("DELETE", "/api/sessions/s1", Perm::Admin),
            ("GET", "/api/secrets", Perm::Admin),
            ("PUT", "/api/secrets/OPENAI_API_KEY", Perm::Admin),
            ("DELETE", "/api/secrets/OPENAI_API_KEY", Perm::Admin),
            // POST /api/signups and GET /api/signups/config are public; the auth middleware lets them through first.
            ("GET", "/api/signups", Perm::Admin),
            ("GET", "/api/signups/su1", Perm::Admin),
            ("POST", "/api/signups/su1/approve", Perm::Admin),
            ("POST", "/api/signups/su1/reject", Perm::Admin),
            ("GET", "/api/auth/me", Perm::Account),
            ("POST", "/api/auth/logout", Perm::Account),
            ("GET", "/", Perm::Read),
            ("GET", "/app.js", Perm::Read),
            ("HEAD", "/api/state", Perm::Read),
        ];
        for (method, path, want) in cases {
            assert_eq!(classify(&m(method), path), want, "{method} {path}");
        }
    }

    #[test]
    fn odd_paths_fail_closed() {
        let get = Method::GET;
        for p in [
            "/api/state/",
            "/api//state",
            "/api/bots//messages",
            "/api/bots/b1/messages/",
            "/api/%73tate",
            "/api/STATE",
            "/api/audit/../state",
            "/api/nope",
            "/api/",
        ] {
            assert_eq!(classify(&get, p), Perm::Admin, "{p}");
        }
        assert_eq!(classify(&Method::POST, "/api/approvals"), Perm::Admin);
        assert_eq!(classify(&Method::PUT, "/api/bots/b1"), Perm::Admin);
        assert_eq!(classify(&Method::PUT, "/api/bots/b1/access"), Perm::Admin);
        assert_eq!(classify(&Method::GET, "/api/bots/b1/grants/u1"), Perm::Admin);
        assert_eq!(classify(&Method::PUT, "/api/bots/b1/grants"), Perm::Admin);
        assert_eq!(classify(&Method::POST, "/"), Perm::Admin);
        assert_eq!(classify(&Method::OPTIONS, "/api/state"), Perm::Admin);
    }

    #[test]
    fn roles_parse() {
        assert_eq!(Role::parse(" Read-Only "), Some(Role::Readonly));
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("owner"), None);
        assert_eq!(serde_json::to_string(&Role::Readonly).unwrap(), "\"readonly\"");
    }
}
