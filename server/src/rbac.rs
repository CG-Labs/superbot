//! Roles and permissions. Every API request is mapped to one permission by `classify`,
//! in the auth middleware, before any handler runs. Anything not in the table needs
//! `Admin`, so a new route is closed until someone classifies it.
//! Design: docs/adr/0012-users-sessions-rbac.md; custom roles built from a fixed set of
//! admin permissions (`DELEGABLE`): docs/adr/0123-custom-roles.md.

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
    /// People: list, add and edit users, make sign-in codes, end sessions. Never admins, or
    /// anyone with an admin permission, and never roles (ADR 0123).
    ManageUsers,
    /// People's Bots and routines: list them, resume paused routines, move a tier's Bots.
    ManageBots,
    /// The audit log and the access-review report, and their exports.
    ViewAudit,
    /// Everyone's plan and use, and the tiers.
    ManageBilling,
    /// The sign-up queue: see, approve (as a member or read-only) and reject.
    ApproveSignups,
    /// Machines' lifecycle: request, suspend, resume, resize, rebuild, back up, restore,
    /// placement and hosts. Never a machine's logins, screens or files.
    ManageMachines,
    /// Policy and rules, secrets, roles, and everything no other permission names.
    Admin,
}

pub const PERMS: [Perm; 12] = [
    Perm::Account,
    Perm::Read,
    Perm::Review,
    Perm::Write,
    Perm::Approve,
    Perm::ManageUsers,
    Perm::ManageBots,
    Perm::ViewAudit,
    Perm::ManageBilling,
    Perm::ApproveSignups,
    Perm::ManageMachines,
    Perm::Admin,
];

/// What a custom role can hold on top of its base role (ADR 0123). Fixed: a name that
/// isn't here is refused when a role is saved, and grants nothing if one is ever read.
pub const DELEGABLE: [Perm; 6] = [Perm::ManageUsers, Perm::ManageBots, Perm::ViewAudit, Perm::ManageBilling, Perm::ApproveSignups, Perm::ManageMachines];

/// The delegable permissions that mean something within one team, for a role given there:
/// its people (invites, removing members), its machines, and its plan.
pub const TEAM_SCOPED: [Perm; 3] = [Perm::ManageUsers, Perm::ManageMachines, Perm::ManageBilling];

/// What a SCIM group's role can never hold (ADR 0138), because its routes act on admins
/// with no delegate limit to stop them: anyone's Bots and routines, and anyone's machine,
/// admins' included. Within a team only the team's machines, which its owners' and
/// admins' are too. Every other delegable permission keeps its holder off admins.
pub const REACHES_ADMINS: [Perm; 2] = [Perm::ManageBots, Perm::ManageMachines];
pub const REACHES_ADMINS_IN_TEAM: [Perm; 1] = [Perm::ManageMachines];

impl Perm {
    pub fn as_str(self) -> &'static str {
        match self {
            Perm::Account => "account",
            Perm::Read => "read",
            Perm::Review => "review",
            Perm::Write => "write",
            Perm::Approve => "approve",
            Perm::ManageUsers => "users.manage",
            Perm::ManageBots => "bots.manage",
            Perm::ViewAudit => "audit.view",
            Perm::ManageBilling => "billing.manage",
            Perm::ApproveSignups => "signups.approve",
            Perm::ManageMachines => "machines.manage",
            Perm::Admin => "admin",
        }
    }

    /// A delegable permission by name. Anything else, built-in ones included, is None.
    pub fn delegable(name: &str) -> Option<Perm> {
        DELEGABLE.into_iter().find(|p| p.as_str() == name)
    }

    /// Any permission by name, built-in ones included.
    pub fn parse(name: &str) -> Option<Perm> {
        PERMS.into_iter().find(|p| p.as_str() == name)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Perm::Account => "Your own session, second factor and settings.",
            Perm::Read => "See Bots, chats, routines, policy and models.",
            Perm::Review => "See pending approvals.",
            Perm::Write => "Chat with Bots and change them, routines and your own settings.",
            Perm::Approve => "Approve or deny a Bot's risky tool call.",
            Perm::ManageUsers => "List, add, edit, enable and disable people, make sign-in codes and end sessions. Not admins or anyone with an admin permission, and not roles.",
            Perm::ManageBots => "List anyone's Bots and routines, resume paused routines, and move a tier's Bots to its default harness.",
            Perm::ViewAudit => "Read and export the audit log and the access-review report.",
            Perm::ManageBilling => "See everyone's plan and use, and the tiers.",
            Perm::ApproveSignups => "See, approve and reject sign-ups, as members or read-only.",
            Perm::ManageMachines => "Run machines' lifecycle, placement and hosts. Not their logins, screens or files.",
            Perm::Admin => "Everything, including policy, secrets and roles.",
        }
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// A set of delegable permissions, as a custom role holds them.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Perms(u16);

impl Perms {
    pub const NONE: Perms = Perms(0);

    /// Unknown names, and any that aren't delegable, are dropped: they grant nothing.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Perms {
        names.into_iter().filter_map(Perm::delegable).fold(Perms::NONE, Perms::with)
    }

    pub fn with(self, p: Perm) -> Perms {
        if DELEGABLE.contains(&p) { Perms(self.0 | p.bit()) } else { self }
    }

    pub fn has(self, p: Perm) -> bool {
        DELEGABLE.contains(&p) && self.0 & p.bit() != 0
    }

    /// Only what applies within a team (`TEAM_SCOPED`).
    pub fn in_team(self) -> Perms {
        TEAM_SCOPED.into_iter().filter(|p| self.has(*p)).fold(Perms::NONE, Perms::with)
    }

    pub fn names(self) -> Vec<&'static str> {
        DELEGABLE.iter().filter(|p| self.has(**p)).map(|p| p.as_str()).collect()
    }

    /// The permissions here that would let a SCIM group's members reach admins, across the
    /// server or (`team`) within the group's team. Empty: the IdP may give it (ADR 0138).
    pub fn reaching_admins(self, team: bool) -> Vec<&'static str> {
        let (held, reach) = if team { (self.in_team(), &REACHES_ADMINS_IN_TEAM[..]) } else { (self, &REACHES_ADMINS[..]) };
        reach.iter().filter(|p| held.has(**p)).map(|p| p.as_str()).collect()
    }
}

/// Any set of permissions, built-in ones included: what a service account's token may use,
/// and the most its owner holds (ADR 0143). It only ever narrows what a role grants.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Scope(u16);

impl Scope {
    pub const NONE: Scope = Scope(0);

    pub fn all() -> Scope {
        PERMS.into_iter().fold(Scope::NONE, Scope::with)
    }

    /// What `p` holds with `extra` on top, as `granted` lists it.
    pub fn of(p: Principal, extra: Perms) -> Scope {
        PERMS.into_iter().filter(|perm| permits(p, extra, *perm)).fold(Scope::NONE, Scope::with)
    }

    /// Team permissions, which mean something only within a team.
    pub fn team(perms: Perms) -> Scope {
        TEAM_SCOPED.into_iter().filter(|p| perms.has(*p)).fold(Scope::NONE, Scope::with)
    }

    pub fn with(self, p: Perm) -> Scope {
        Scope(self.0 | p.bit())
    }

    pub fn has(self, p: Perm) -> bool {
        self.0 & p.bit() != 0
    }

    pub fn and(self, o: Scope) -> Scope {
        Scope(self.0 & o.0)
    }

    pub fn or(self, o: Scope) -> Scope {
        Scope(self.0 | o.0)
    }

    pub fn names(self) -> Vec<&'static str> {
        PERMS.iter().filter(|p| self.has(**p)).map(|p| p.as_str()).collect()
    }
}

/// The built-in roles' matrix.
pub fn allows(p: Principal, perm: Perm) -> bool {
    use Perm::*;
    match p {
        Principal::User(Role::Admin) => true,
        Principal::User(Role::Member) => matches!(perm, Account | Read | Review | Write | Approve),
        Principal::User(Role::Readonly) => matches!(perm, Account | Read | Review),
        Principal::Bot => matches!(perm, Account | Read | Write),
    }
}

/// The matrix with a person's custom role on top (ADR 0123): its base role's permissions,
/// and the delegable ones it adds. Bots never get a custom role's.
pub fn permits(p: Principal, extra: Perms, perm: Perm) -> bool {
    allows(p, perm) || (matches!(p, Principal::User(_)) && extra.has(perm))
}

pub fn granted(p: Principal, extra: Perms) -> Vec<&'static str> {
    PERMS.iter().filter(|&&perm| permits(p, extra, perm)).map(|p| p.as_str()).collect()
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
        // Admin routes a custom role can be given (ADR 0123). Exact shapes only: anything
        // else under `users` or `sessions` stays Admin just below. Handlers add what a
        // delegate may not do on these (`users::Delegate`).
        ("GET" | "POST", ["users"]) | ("GET" | "PATCH", ["users", _]) => ManageUsers,
        ("POST", ["users", _, "login-codes"]) | ("DELETE", ["users", _, "sessions"]) => ManageUsers,
        ("GET", ["sessions"]) | ("DELETE", ["sessions", _]) => ManageUsers,
        // Service accounts (ADR 0143). Handlers keep a delegate to the ones they own, and
        // to no more than they hold themselves.
        ("GET" | "POST", ["service-accounts"]) | ("GET" | "PATCH" | "DELETE", ["service-accounts", _]) => ManageUsers,
        ("GET" | "POST", ["service-accounts", _, "tokens"]) | ("DELETE", ["service-accounts", _, "tokens", _]) => ManageUsers,
        ("POST", ["service-accounts", _, "tokens", _, "rotate"]) => ManageUsers,
        ("GET", ["users", _, "bots" | "routines"]) | ("POST", ["users", _, "routines", "resume"]) => ManageBots,
        ("POST", ["tiers", _, "move-bots"]) => ManageBots,
        ("GET", ["audit"] | ["audit", "export.csv"] | ["access-review"] | ["access-review", "export.csv"]) => ViewAudit,
        ("GET", ["usage"] | ["tiers"] | ["users", _, "usage"]) => ManageBilling,
        ("GET", ["signups"] | ["signups", _]) | ("POST", ["signups", _, "approve" | "reject"]) => ApproveSignups,
        // A machine's lifecycle, never its logins, screens, files or teammates, and never
        // deleting its backups: those stay Admin.
        ("GET" | "POST" | "DELETE", ["users", _, "machine"]) => ManageMachines,
        ("POST", ["users", _, "machine", "suspend" | "resume" | "enrollment" | "harnesses"]) => ManageMachines,
        ("GET" | "POST", ["users", _, "machine", "resize" | "rebuild" | "backups" | "restore"]) => ManageMachines,
        ("DELETE", ["users", _, "machine", "rebuild" | "certificates"]) => ManageMachines,
        ("GET", ["users", _, "machine", "agent"]) | ("POST", ["users", _, "machine", "agent", "upgrade"]) => ManageMachines,
        ("PUT" | "DELETE", ["users", _, "machine", "agent", "hold"]) => ManageMachines,
        ("GET" | "PUT" | "DELETE", ["users", _, "placement"]) | ("GET" | "PUT", ["users", _, "region"]) => ManageMachines,
        ("GET", ["machines"] | ["machines", "placements" | "resizes" | "backups" | "recovery" | "substrate" | "hosts" | "legacy"] | ["regions"]) => ManageMachines,
        ("POST", ["machines", "reconcile"] | ["machines", "hosts", _, "recover"]) | ("PUT" | "DELETE", ["machines", "hosts", _, "drain"]) => ManageMachines,

        // The admin portal (ADR 0021): users, sign-in codes, identities, sessions, and a
        // user's Bot access. Before every broader arm, so none added below can open them.
        (_, ["users", ..] | ["sessions", ..]) => Admin,

        ("GET", ["auth", "me"]) | ("POST", ["auth", "logout"]) => Account,
        // Your own second factor (ADR 0094). Handlers refuse Bots. The policy is for admins.
        ("GET", ["auth", "mfa"]) => Account,
        ("POST", ["auth", "mfa", "enroll" | "confirm" | "recovery-codes" | "disable"]) => Account,
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
        // Only admins hold the delegable permissions among the built-in roles; Bots never do.
        for perm in DELEGABLE {
            assert_eq!([allows(ADMIN, perm), allows(MEMBER, perm), allows(READONLY, perm), allows(BOT, perm)], [true, false, false, false], "{perm:?}");
        }
        assert_eq!(granted(READONLY, Perms::NONE), ["account", "read", "review"]);
        assert_eq!(granted(MEMBER, Perms::NONE), ["account", "read", "review", "write", "approve"]);
        assert_eq!(granted(ADMIN, Perms::NONE).len(), PERMS.len());
    }

    #[test]
    fn custom_roles_add_only_delegable_permissions() {
        let auditor = Perms::from_names(["audit.view", "signups.approve"]);
        assert_eq!(granted(READONLY, auditor), ["account", "read", "review", "audit.view", "signups.approve"]);
        assert!(permits(READONLY, auditor, Perm::ViewAudit) && !permits(READONLY, auditor, Perm::Write));
        assert!(!permits(READONLY, auditor, Perm::Admin) && !permits(MEMBER, auditor, Perm::ManageUsers));
        // A Bot never carries a custom role's permissions, even if handed one.
        assert!(!permits(BOT, auditor, Perm::ViewAudit));
        // Deny by default: unknown names, built-in ones and `admin` grant nothing.
        let odd = Perms::from_names(["admin", "write", "approve", "users.*", "Audit.View", " audit.view", "root", ""]);
        assert_eq!(odd, Perms::NONE);
        assert!(!Perms::NONE.with(Perm::Admin).has(Perm::Admin));
        for perm in PERMS {
            assert_eq!(Perm::delegable(perm.as_str()), DELEGABLE.contains(&perm).then_some(perm), "{perm:?}");
        }
        let all = DELEGABLE.into_iter().fold(Perms::NONE, Perms::with);
        assert_eq!(all.names().len(), DELEGABLE.len());
        assert_eq!(all.in_team().names(), ["users.manage", "billing.manage", "machines.manage"]);
    }

    #[test]
    fn scopes_only_narrow() {
        assert_eq!(Scope::all().names().len(), PERMS.len());
        assert_eq!(Scope::of(READONLY, Perms::NONE).names(), ["account", "read", "review"]);
        assert_eq!(Scope::of(ADMIN, Perms::NONE), Scope::all());
        let auditor = Perms::from_names(["audit.view"]);
        assert_eq!(Scope::of(READONLY, auditor).names(), ["account", "read", "review", "audit.view"]);
        // A Bot never carries a custom role's permissions, in a scope either.
        assert_eq!(Scope::of(BOT, auditor), Scope::of(BOT, Perms::NONE));
        let all = DELEGABLE.into_iter().fold(Perms::NONE, Perms::with);
        assert_eq!(Scope::team(all).names(), ["users.manage", "billing.manage", "machines.manage"]);
        let member = Scope::of(MEMBER, Perms::NONE);
        assert_eq!(member.and(Scope::of(READONLY, Perms::NONE)), Scope::of(READONLY, Perms::NONE));
        assert_eq!(Scope::all().and(member), member);
        assert!(!member.has(Perm::Admin) && Scope::all().has(Perm::Admin));
        assert_eq!(member.and(Scope::of(READONLY, auditor)).names(), ["account", "read", "review"]);
        assert_eq!(Scope::NONE.with(Perm::Read).or(Scope::NONE.with(Perm::Write)).names(), ["read", "write"]);
        for perm in PERMS {
            assert_eq!(Perm::parse(perm.as_str()), Some(perm));
        }
        assert_eq!(Perm::parse("Admin"), None);
        assert_eq!(Perm::parse(" read"), None);
    }

    #[test]
    fn scim_groups_never_get_permissions_that_reach_admins() {
        let all = DELEGABLE.into_iter().fold(Perms::NONE, Perms::with);
        assert_eq!(all.reaching_admins(false), ["bots.manage", "machines.manage"]);
        assert_eq!(all.reaching_admins(true), ["machines.manage"]);
        let helpdesk = Perms::from_names(["users.manage", "audit.view", "billing.manage", "signups.approve"]);
        assert!(helpdesk.reaching_admins(false).is_empty() && helpdesk.reaching_admins(true).is_empty());
        // Within a team, only what applies there counts: bots.manage does nothing in a team.
        assert!(Perms::from_names(["bots.manage"]).reaching_admins(true).is_empty());
        assert_eq!(Perms::from_names(["bots.manage"]).reaching_admins(false), ["bots.manage"]);
        assert!(Perms::NONE.reaching_admins(false).is_empty());
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
            ("GET", "/api/audit", Perm::ViewAudit),
            ("GET", "/api/audit/export.csv", Perm::ViewAudit),
            ("GET", "/api/audit/verify", Perm::Admin),
            ("GET", "/api/audit/siem", Perm::Admin),
            // The access-review report, its export and sign-off (ADR 0099).
            ("GET", "/api/access-review", Perm::ViewAudit),
            ("GET", "/api/access-review/export.csv", Perm::ViewAudit),
            ("POST", "/api/access-review/complete", Perm::Admin),
            ("GET", "/api/users", Perm::ManageUsers),
            ("POST", "/api/users", Perm::ManageUsers),
            ("GET", "/api/users/u1", Perm::ManageUsers),
            ("PATCH", "/api/users/u1", Perm::ManageUsers),
            ("POST", "/api/users/u1/login-codes", Perm::ManageUsers),
            ("DELETE", "/api/users/u1/sessions", Perm::ManageUsers),
            ("GET", "/api/users/u1/bots", Perm::ManageBots),
            ("GET", "/api/users/u1/routines", Perm::ManageBots),
            ("POST", "/api/users/u1/routines/resume", Perm::ManageBots),
            ("POST", "/api/users/u1/handover", Perm::Admin),
            ("GET", "/api/users/a%40example.com/bots", Perm::ManageBots),
            ("GET", "/api/users/u1/identities", Perm::Admin),
            ("POST", "/api/users/u1/identities", Perm::Admin),
            ("DELETE", "/api/users/u1/identities/i1", Perm::Admin),
            ("GET", "/api/sessions", Perm::ManageUsers),
            ("DELETE", "/api/sessions/s1", Perm::ManageUsers),
            ("GET", "/api/secrets", Perm::Admin),
            ("PUT", "/api/secrets/OPENAI_API_KEY", Perm::Admin),
            ("DELETE", "/api/secrets/OPENAI_API_KEY", Perm::Admin),
            // POST /api/signups and GET /api/signups/config are public; the auth middleware lets them through first.
            ("GET", "/api/signups", Perm::ApproveSignups),
            ("GET", "/api/signups/su1", Perm::ApproveSignups),
            ("POST", "/api/signups/su1/approve", Perm::ApproveSignups),
            ("POST", "/api/signups/su1/reject", Perm::ApproveSignups),
            // SCIM tokens are admin-only; /scim/v2 has its own guard and never reaches classify.
            ("GET", "/api/scim/tokens", Perm::Admin),
            ("POST", "/api/scim/tokens", Perm::Admin),
            ("DELETE", "/api/scim/tokens/st1", Perm::Admin),
            // So are the links between SCIM groups and teams (ADR 0095).
            ("GET", "/api/scim/groups", Perm::Admin),
            ("POST", "/api/scim/groups", Perm::Admin),
            ("DELETE", "/api/scim/groups/t1", Perm::Admin),
            // And mapping SCIM groups to custom roles (ADR 0138).
            ("GET", "/api/scim/role-mappings", Perm::Admin),
            ("POST", "/api/scim/role-mappings", Perm::Admin),
            ("GET", "/api/scim/role-mappings/sm1", Perm::Admin),
            ("DELETE", "/api/scim/role-mappings/sm1", Perm::Admin),
            ("GET", "/api/auth/me", Perm::Account),
            ("GET", "/api/machine", Perm::Account),
            ("GET", "/api/me/secrets", Perm::Read),
            ("GET", "/api/me/tier", Perm::Read),
            ("GET", "/api/tiers", Perm::ManageBilling),
            // Moving a managed tier's Bots onto its default harness (ADR 0079).
            ("POST", "/api/tiers/pro/move-bots", Perm::ManageBots),
            // Everyone's plan and use, against their limits (ADR 0040).
            ("GET", "/api/usage", Perm::ManageBilling),
            // Your own usage this billing period; anyone's is for admins (ADR 0050).
            ("GET", "/api/me/usage", Perm::Read),
            ("GET", "/api/users/u1/usage", Perm::ManageBilling),
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
            ("GET", "/api/machines", Perm::ManageMachines),
            ("POST", "/api/machines/reconcile", Perm::ManageMachines),
            ("GET", "/api/machines/placements", Perm::ManageMachines),
            ("GET", "/api/machines/substrate", Perm::ManageMachines),
            ("GET", "/api/machines/hosts", Perm::ManageMachines),
            ("POST", "/api/machines/hosts/main/recover", Perm::ManageMachines),
            ("PUT", "/api/machines/hosts/main/drain", Perm::ManageMachines),
            ("DELETE", "/api/machines/hosts/main/drain", Perm::ManageMachines),
            ("GET", "/api/users/u1/placement", Perm::ManageMachines),
            ("PUT", "/api/users/u1/placement", Perm::ManageMachines),
            ("DELETE", "/api/users/u1/placement", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine", Perm::ManageMachines),
            ("DELETE", "/api/users/u1/machine", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/suspend", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/enrollment", Perm::ManageMachines),
            ("DELETE", "/api/users/u1/machine/certificates", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/resume", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/resize", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/agent", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/agent/upgrade", Perm::ManageMachines),
            ("PUT", "/api/users/u1/machine/agent/hold", Perm::ManageMachines),
            ("DELETE", "/api/users/u1/machine/agent/hold", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/harnesses", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/rebuild", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/rebuild", Perm::ManageMachines),
            ("DELETE", "/api/users/u1/machine/rebuild", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/backups", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/backups", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/restore", Perm::ManageMachines),
            ("POST", "/api/users/u1/machine/restore", Perm::ManageMachines),
            ("GET", "/api/machines/backups", Perm::ManageMachines),
            ("DELETE", "/api/machines/m1/backups", Perm::Admin),
            ("GET", "/api/machines/recovery", Perm::ManageMachines),
            ("GET", "/api/machines/legacy", Perm::ManageMachines),
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
            // Your own second factor; the policy and anyone else's are for admins (ADR 0094).
            ("GET", "/api/auth/mfa", Perm::Account),
            ("POST", "/api/auth/mfa/enroll", Perm::Account),
            ("POST", "/api/auth/mfa/confirm", Perm::Account),
            ("POST", "/api/auth/mfa/recovery-codes", Perm::Account),
            ("POST", "/api/auth/mfa/disable", Perm::Account),
            ("PUT", "/api/auth/mfa/policy", Perm::Admin),
            ("GET", "/api/auth/mfa/policy", Perm::Admin),
            ("DELETE", "/api/auth/mfa", Perm::Admin),
            ("DELETE", "/api/users/u1/mfa", Perm::Admin),
            // Erasing a user's personal data (ADR 0102).
            ("POST", "/api/users/u1/erase", Perm::Admin),
            ("POST", "/api/users/a%40example.com/erase", Perm::Admin),
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
            // Custom roles (ADR 0123): routes a delegate may use, and what stays with admins.
            ("GET", "/api/regions", Perm::ManageMachines),
            ("GET", "/api/machines/resizes", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/resize", Perm::ManageMachines),
            ("GET", "/api/users/u1/region", Perm::ManageMachines),
            ("PUT", "/api/users/u1/region", Perm::ManageMachines),
            ("GET", "/api/users/u1/machine/screens", Perm::Admin),
            ("DELETE", "/api/users/u1/machine/screens/b1", Perm::Admin),
            ("POST", "/api/users/u1/handover", Perm::Admin),
            ("GET", "/api/users/u1/isolation", Perm::Admin),
            ("POST", "/api/users/u1/harness-login", Perm::Admin),
            ("DELETE", "/api/users/u1", Perm::Admin),
            ("PUT", "/api/users/u1", Perm::Admin),
            ("POST", "/api/users/u1/machine/screens", Perm::Admin),
            ("GET", "/api/users/u1/machine/certificates", Perm::Admin),
            ("GET", "/api/sessions/s1", Perm::Admin),
            ("POST", "/api/audit", Perm::Admin),
            ("DELETE", "/api/signups/su1", Perm::Admin),
            ("PUT", "/api/tiers", Perm::Admin),
            ("GET", "/api/roles", Perm::Admin),
            ("POST", "/api/roles", Perm::Admin),
            ("GET", "/api/roles/r1", Perm::Admin),
            ("PATCH", "/api/roles/r1", Perm::Admin),
            ("DELETE", "/api/roles/r1", Perm::Admin),
            ("PUT", "/api/roles/r1/users/u1", Perm::Admin),
            ("DELETE", "/api/roles/r1/users/u1", Perm::Admin),
            ("PUT", "/api/roles/r1/teams/t1/users/u1", Perm::Admin),
            ("DELETE", "/api/roles/r1/teams/t1/users/u1", Perm::Admin),
            // Service accounts (ADR 0143).
            ("GET", "/api/service-accounts", Perm::ManageUsers),
            ("POST", "/api/service-accounts", Perm::ManageUsers),
            ("GET", "/api/service-accounts/sa1", Perm::ManageUsers),
            ("PATCH", "/api/service-accounts/sa1", Perm::ManageUsers),
            ("DELETE", "/api/service-accounts/sa1", Perm::ManageUsers),
            ("GET", "/api/service-accounts/sa1/tokens", Perm::ManageUsers),
            ("POST", "/api/service-accounts/sa1/tokens", Perm::ManageUsers),
            ("DELETE", "/api/service-accounts/sa1/tokens/st1", Perm::ManageUsers),
            ("POST", "/api/service-accounts/sa1/tokens/st1/rotate", Perm::ManageUsers),
            ("PUT", "/api/service-accounts/sa1", Perm::Admin),
            ("GET", "/api/service-accounts/sa1/tokens/st1", Perm::Admin),
            ("PATCH", "/api/service-accounts/sa1/tokens/st1", Perm::Admin),
            ("GET", "/api/service-accounts//tokens", Perm::Admin),
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
            "/api/users/",
            "/api/users//bots",
            "/api/Users",
            "/api/audit/",
            "/api/machines/hosts//drain",
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
