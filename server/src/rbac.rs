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
/// BOT_TOKEN its run gets, live only while that run is, ADR 0083).
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
        // Your own machine (ADR 0025). Everyone else's, and every change, is under
        // `users` above or `machines`, which fall through to Admin.
        ("GET", ["machine"]) => Account,
        // Harness logins on your own machine (ADR 0041). Handlers refuse Bots.
        ("GET", ["machine", "harness-logins"]) => Account,
        ("POST", ["machine", "harness-login"] | ["machine", "harness-login", _, "input"]) => Write,
        ("DELETE", ["machine", "harness-login" | "harness-logins", _]) => Write,
        // Your own logins on a teammate's machine (ADR 0062). Handlers refuse Bots and
        // anyone who isn't the owner's teammate.
        ("GET", ["machine", "teammate", _, "harness-logins"]) => Account,
        ("POST", ["machine", "teammate", _, "harness-login"] | ["machine", "teammate", _, "harness-login", _, "input"]) => Write,
        ("DELETE", ["machine", "teammate", _, "harness-login" | "harness-logins", _]) => Write,
        // Your own secrets (ADR 0029). Handlers refuse Bots; anyone else's are under `users`.
        ("GET", ["me", "secrets"]) => Read,
        // Your own plan (ADR 0033). Every tier with its models is `tiers`, for admins.
        ("GET", ["me", "tier"]) => Read,
        ("GET", ["me", "usage"]) => Read,
        // Your own plan, and buying or managing it (ADR 0042). Handlers refuse Bots.
        ("GET", ["billing"]) => Read,
        ("POST", ["billing", "checkout" | "portal"]) => Write,
        ("PUT" | "DELETE", ["me", "secrets", _]) => Write,
        // Your own team (ADR 0087). Handlers refuse Bots, and leave managing it to the
        // team's owners and admins. Every team is under `teams`, for admins.
        ("GET", ["team"] | ["me", "team-invites"] | ["team", "members", _, "offboarding"]) => Account,
        ("POST", ["team", "leave"] | ["team", "invites"] | ["me", "team-invites", _, "accept"]) => Write,
        ("POST", ["team", "billing", "checkout" | "portal"]) => Write,
        ("DELETE", ["team", "invites", _] | ["me", "team-invites", _]) => Write,
        ("PATCH" | "DELETE", ["team", "members", _]) => Write,
        ("POST", ["team", "members", _, "machine"] | ["team", "members", _, "machine", "suspend" | "resume"]) => Write,
        // This session's phone for push notifications (ADR 0080). Handlers refuse Bots.
        // Read-only people can't decide approvals or run routines, so they don't add one;
        // anyone may remove theirs, as anyone may sign out.
        ("PUT", ["me", "push"]) => Write,
        ("GET" | "DELETE", ["me", "push"]) => Account,
        // Your own billing emails (ADR 0091). Handlers refuse Bots.
        ("PUT", ["me", "emails"]) => Write,
        ("GET", ["me", "emails"]) => Account,

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
            ("GET", "/api/notifications", Perm::Admin),
            ("PUT", "/api/notifications", Perm::Admin),
            ("POST", "/api/notifications/test", Perm::Admin),
            ("GET", "/api/bots/b1/notifications", Perm::Admin),
            ("PUT", "/api/bots/b1/notifications", Perm::Admin),
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
            ("GET", "/api/users/u1/routines", Perm::Admin),
            ("POST", "/api/users/u1/routines/resume", Perm::Admin),
            ("POST", "/api/users/u1/handover", Perm::Admin),
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
            // SCIM tokens are admin-only; /scim/v2 has its own guard and never reaches classify.
            ("GET", "/api/scim/tokens", Perm::Admin),
            ("POST", "/api/scim/tokens", Perm::Admin),
            ("DELETE", "/api/scim/tokens/st1", Perm::Admin),
            // So are the links between SCIM groups and teams (ADR 0095).
            ("GET", "/api/scim/groups", Perm::Admin),
            ("POST", "/api/scim/groups", Perm::Admin),
            ("DELETE", "/api/scim/groups/t1", Perm::Admin),
            ("GET", "/api/auth/me", Perm::Account),
            ("GET", "/api/machine", Perm::Account),
            ("GET", "/api/me/secrets", Perm::Read),
            ("GET", "/api/me/tier", Perm::Read),
            ("GET", "/api/tiers", Perm::Admin),
            // Moving a managed tier's Bots onto its default harness (ADR 0079).
            ("POST", "/api/tiers/pro/move-bots", Perm::Admin),
            // Everyone's plan and use, against their limits (ADR 0040).
            ("GET", "/api/usage", Perm::Admin),
            // Your own usage this billing period; anyone's is for admins (ADR 0050).
            ("GET", "/api/me/usage", Perm::Read),
            ("GET", "/api/users/u1/usage", Perm::Admin),
            // Your own plan's checkout and billing portal (ADR 0042).
            ("GET", "/api/billing", Perm::Read),
            ("POST", "/api/billing/checkout", Perm::Write),
            ("POST", "/api/billing/portal", Perm::Write),
            ("POST", "/api/billing", Perm::Admin),
            ("GET", "/api/billing/checkout", Perm::Admin),
            // The onboarding wizard (ADR 0034): what the server has set up, and its progress.
            ("GET", "/api/setup", Perm::Admin),
            ("PATCH", "/api/setup", Perm::Admin),
            // The self-host license (ADR 0038).
            ("GET", "/api/license", Perm::Admin),
            ("PUT", "/api/license", Perm::Admin),
            ("DELETE", "/api/license", Perm::Admin),
            ("PUT", "/api/me/secrets/OPENAI_API_KEY", Perm::Write),
            ("DELETE", "/api/me/secrets/OPENAI_API_KEY", Perm::Write),
            ("POST", "/api/me/secrets/OPENAI_API_KEY", Perm::Admin),
            ("GET", "/api/me/secrets/OPENAI_API_KEY", Perm::Admin),
            ("GET", "/api/users/u1/secrets", Perm::Admin),
            ("DELETE", "/api/users/u1/secrets", Perm::Admin),
            ("GET", "/api/machines", Perm::Admin),
            ("POST", "/api/machines/reconcile", Perm::Admin),
            ("GET", "/api/machines/placements", Perm::Admin),
            ("GET", "/api/machines/substrate", Perm::Admin),
            ("GET", "/api/machines/hosts", Perm::Admin),
            ("POST", "/api/machines/hosts/main/recover", Perm::Admin),
            ("PUT", "/api/machines/hosts/main/drain", Perm::Admin),
            ("DELETE", "/api/machines/hosts/main/drain", Perm::Admin),
            ("GET", "/api/users/u1/placement", Perm::Admin),
            ("PUT", "/api/users/u1/placement", Perm::Admin),
            ("DELETE", "/api/users/u1/placement", Perm::Admin),
            ("GET", "/api/users/u1/machine", Perm::Admin),
            ("POST", "/api/users/u1/machine", Perm::Admin),
            ("DELETE", "/api/users/u1/machine", Perm::Admin),
            ("POST", "/api/users/u1/machine/suspend", Perm::Admin),
            ("POST", "/api/users/u1/machine/enrollment", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/certificates", Perm::Admin),
            ("POST", "/api/users/u1/machine/resume", Perm::Admin),
            ("POST", "/api/users/u1/machine/resize", Perm::Admin),
            ("GET", "/api/users/u1/machine/agent", Perm::Admin),
            ("POST", "/api/users/u1/machine/agent/upgrade", Perm::Admin),
            ("PUT", "/api/users/u1/machine/agent/hold", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/agent/hold", Perm::Admin),
            ("POST", "/api/users/u1/machine/harnesses", Perm::Admin),
            ("GET", "/api/users/u1/machine/rebuild", Perm::Admin),
            ("POST", "/api/users/u1/machine/rebuild", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/rebuild", Perm::Admin),
            ("GET", "/api/users/u1/machine/backups", Perm::Admin),
            ("POST", "/api/users/u1/machine/backups", Perm::Admin),
            ("GET", "/api/users/u1/machine/restore", Perm::Admin),
            ("POST", "/api/users/u1/machine/restore", Perm::Admin),
            ("GET", "/api/machines/backups", Perm::Admin),
            ("GET", "/api/machines/recovery", Perm::Admin),
            ("GET", "/api/machines/legacy", Perm::Admin),
            ("POST", "/api/users/u1/machine/bot-user", Perm::Admin),
            ("POST", "/api/users/u1/machine/harness-login", Perm::Admin),
            ("POST", "/api/users/u1/machine/harness-login/l1/input", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/harness-login/l1", Perm::Admin),
            ("GET", "/api/users/u1/machine/harness-logins", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/harness-logins/claude", Perm::Admin),
            ("GET", "/api/users/u1/machine/teammates/u2/harness-logins", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/teammates/u2/harness-logins/claude", Perm::Admin),
            ("GET", "/api/users/u1/machine/folder-sync", Perm::Admin),
            ("POST", "/api/users/u1/machine/folder-sync", Perm::Admin),
            ("GET", "/api/users/u1/machine/teammates", Perm::Admin),
            ("POST", "/api/users/u1/machine/teammates/u2/remove", Perm::Admin),
            ("GET", "/api/machines/teammate-removals", Perm::Admin),
            ("GET", "/api/users/u1/teammate-accounts", Perm::Admin),
            ("POST", "/api/users/u1/teammate-accounts/u2/remove", Perm::Admin),
            ("GET", "/api/isolation/teammate-removals", Perm::Admin),
            ("GET", "/api/machine/harness-logins", Perm::Account),
            ("POST", "/api/machine/harness-login", Perm::Write),
            ("POST", "/api/machine/harness-login/l1/input", Perm::Write),
            ("DELETE", "/api/machine/harness-login/l1", Perm::Write),
            ("DELETE", "/api/machine/harness-logins/claude", Perm::Write),
            ("PUT", "/api/machine/harness-login", Perm::Admin),
            ("GET", "/api/machine/teammate/u1/harness-logins", Perm::Account),
            ("POST", "/api/machine/teammate/u1/harness-login", Perm::Write),
            ("POST", "/api/machine/teammate/u1/harness-login/l1/input", Perm::Write),
            ("DELETE", "/api/machine/teammate/u1/harness-login/l1", Perm::Write),
            ("DELETE", "/api/machine/teammate/u1/harness-logins/claude", Perm::Write),
            ("PUT", "/api/machine/teammate/u1/harness-login", Perm::Admin),
            ("GET", "/api/machine/teammate/u1", Perm::Admin),
            ("GET", "/api/machine/teammate//harness-logins", Perm::Admin),
            ("POST", "/api/machine/folder-sync", Perm::Admin),
            ("POST", "/api/auth/logout", Perm::Account),
            ("GET", "/api/me/emails", Perm::Account),
            ("PUT", "/api/me/emails", Perm::Write),
            ("POST", "/api/me/emails", Perm::Admin),
            ("GET", "/api/me/push", Perm::Account),
            ("PUT", "/api/me/push", Perm::Write),
            ("DELETE", "/api/me/push", Perm::Account),
            ("POST", "/api/me/push", Perm::Admin),
            // Teams (ADR 0087): your own, and every team for admins.
            ("GET", "/api/team", Perm::Account),
            ("POST", "/api/team/leave", Perm::Write),
            ("POST", "/api/team/invites", Perm::Write),
            ("DELETE", "/api/team/invites/ti1", Perm::Write),
            ("PATCH", "/api/team/members/u1", Perm::Write),
            ("DELETE", "/api/team/members/u1", Perm::Write),
            ("GET", "/api/team/members/u1/offboarding", Perm::Account),
            ("POST", "/api/team/members/u1/offboarding", Perm::Admin),
            ("POST", "/api/team/members/u1/machine", Perm::Write),
            ("POST", "/api/team/members/u1/machine/suspend", Perm::Write),
            ("POST", "/api/team/members/u1/machine/resume", Perm::Write),
            ("DELETE", "/api/team/members/u1/machine", Perm::Admin),
            ("POST", "/api/team/members/u1/machine/resize", Perm::Admin),
            ("GET", "/api/team/members/u1/machine", Perm::Admin),
            ("PATCH", "/api/team", Perm::Admin),
            // The team's plan (ADR 0093); handlers allow only its owners and admins.
            ("POST", "/api/team/billing/checkout", Perm::Write),
            ("POST", "/api/team/billing/portal", Perm::Write),
            ("GET", "/api/team/billing", Perm::Admin),
            ("POST", "/api/team/billing", Perm::Admin),
            ("GET", "/api/me/team-invites", Perm::Account),
            ("POST", "/api/me/team-invites/ti1/accept", Perm::Write),
            ("DELETE", "/api/me/team-invites/ti1", Perm::Write),
            ("GET", "/api/teams", Perm::Admin),
            ("POST", "/api/teams", Perm::Admin),
            ("GET", "/api/teams/t1", Perm::Admin),
            ("PATCH", "/api/teams/t1", Perm::Admin),
            ("DELETE", "/api/teams/t1", Perm::Admin),
            ("PUT", "/api/teams/t1/members/u1", Perm::Admin),
            ("DELETE", "/api/teams/t1/members/u1", Perm::Admin),
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
        assert_eq!(classify(&Method::POST, "/api/machine"), Perm::Admin);
        assert_eq!(classify(&Method::GET, "/api/machine/m1"), Perm::Admin);
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
