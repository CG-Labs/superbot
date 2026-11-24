//! What a SCIM token may do (ADR 0224): read or write Users, read or write Groups. A
//! write scope includes reading the same resource, since an IdP looks a resource up
//! before it changes it. Discovery is open to every token; any other path neither Users
//! nor Groups needs every scope, so a route added later is closed to narrowed tokens
//! until it's given a scope. The guard checks each request under `/scim/v2` and Bulk
//! checks each operation, so neither path gets round the other. Tokens made before
//! scopes have all four.
//! Design: docs/adr/0224-scim-token-scopes.md.

use axum::http::Method;
use serde::{Serialize, Serializer};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Users,
    Groups,
}

impl Resource {
    /// As the IdP's admin calls it, for error messages.
    pub fn noun(self) -> &'static str {
        match self {
            Resource::Users => "users",
            Resource::Groups => "groups",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope(pub Resource, pub Access);

const EVERY: [Scope; 4] = [
    Scope(Resource::Users, Access::Read),
    Scope(Resource::Users, Access::Write),
    Scope(Resource::Groups, Access::Read),
    Scope(Resource::Groups, Access::Write),
];

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope(Resource::Users, Access::Read) => "users:read",
            Scope(Resource::Users, Access::Write) => "users:write",
            Scope(Resource::Groups, Access::Read) => "groups:read",
            Scope(Resource::Groups, Access::Write) => "groups:write",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        EVERY.into_iter().find(|x| x.name() == s)
    }

    fn bit(self) -> u8 {
        match self {
            Scope(Resource::Users, Access::Read) => 1,
            Scope(Resource::Users, Access::Write) => 2,
            Scope(Resource::Groups, Access::Read) => 4,
            Scope(Resource::Groups, Access::Write) => 8,
        }
    }

    /// The scope itself, and for a write the read of the same resource.
    fn with_implied(self) -> u8 {
        match self.1 {
            Access::Read => self.bit(),
            Access::Write => self.bit() | Scope(self.0, Access::Read).bit(),
        }
    }
}

/// A token's scopes, each write with its read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scopes(u8);

impl Default for Scopes {
    fn default() -> Scopes {
        Scopes::ALL
    }
}

impl Scopes {
    pub const ALL: Scopes = Scopes(15);

    pub fn of(list: &[Scope]) -> Scopes {
        Scopes(list.iter().fold(0, |b, s| b | s.with_implied()))
    }

    pub fn allows(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        EVERY.into_iter().filter(|s| self.allows(*s)).map(Scope::name).collect()
    }

    /// From an admin's request: None when it's left out (the caller picks the default),
    /// else a list of known names, at least one.
    pub fn from_request(v: &Value) -> Result<Option<Scopes>, String> {
        let list = match v {
            Value::Null => return Ok(None),
            Value::Array(l) if !l.is_empty() => l,
            _ => return Err(format!("scopes must be a list of one or more of: {}", Scopes::ALL.names().join(", "))),
        };
        let mut out = Vec::with_capacity(list.len());
        for s in list {
            let name = s.as_str().unwrap_or_default();
            out.push(Scope::parse(name).ok_or_else(|| format!("Unknown scope {s}: use {}", Scopes::ALL.names().join(", ")))?);
        }
        Ok(Some(Scopes::of(&out)))
    }

    /// As stored: a JSON list of names. A token from before scopes has none stored, and
    /// all four. A name this version doesn't know grants nothing.
    pub fn from_stored(s: Option<&str>) -> Scopes {
        let Some(s) = s else { return Scopes::ALL };
        let names: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        Scopes::of(&names.iter().filter_map(|n| Scope::parse(n)).collect::<Vec<_>>())
    }

    pub fn to_stored(self) -> String {
        serde_json::to_string(&self.names()).unwrap_or_else(|_| "[]".into())
    }
}

impl Serialize for Scopes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.names().serialize(s)
    }
}

/// What a request under `/scim/v2` needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// Discovery, and Bulk, whose operations are checked one by one.
    Open,
    One(Scope),
    /// Any other path: none is served today (404), and one added later without a scope
    /// is for tokens with every scope until it's given one.
    All,
}

/// Paths under `/scim/v2` whose first segment is exactly one of these are open.
const OPEN: [&str; 4] = ["ServiceProviderConfig", "ResourceTypes", "Schemas", "Bulk"];

/// What a request needs, from its method and path. Users and Groups are matched more
/// loosely than the router (any case, empty segments skipped), and open paths exactly,
/// so a path that reaches a handler is never under-checked.
pub fn needed(method: &Method, path: &str) -> Need {
    let first = path.strip_prefix("/scim/v2").and_then(|rest| rest.split('/').find(|s| !s.is_empty()));
    let resource = match first {
        Some(s) if s.eq_ignore_ascii_case("Users") => Resource::Users,
        Some(s) if s.eq_ignore_ascii_case("Groups") => Resource::Groups,
        Some(s) if OPEN.contains(&s) => return Need::Open,
        _ => return Need::All,
    };
    let access = if *method == Method::GET || *method == Method::HEAD { Access::Read } else { Access::Write };
    Need::One(Scope(resource, access))
}

impl Scopes {
    /// The first scope `need` asks for that these don't have.
    pub fn lacks(self, need: Need) -> Option<Scope> {
        match need {
            Need::Open => None,
            Need::One(s) => (!self.allows(s)).then_some(s),
            Need::All => EVERY.into_iter().find(|s| !self.allows(*s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_bring_their_reads_and_nothing_else() {
        let users = Scopes::of(&[Scope(Resource::Users, Access::Write)]);
        assert_eq!(users.names(), ["users:read", "users:write"]);
        assert!(!users.allows(Scope(Resource::Groups, Access::Read)));
        let read = Scopes::of(&[Scope(Resource::Users, Access::Read), Scope(Resource::Groups, Access::Read)]);
        assert_eq!(read.names(), ["users:read", "groups:read"]);
        assert!(!read.allows(Scope(Resource::Users, Access::Write)));
        assert_eq!(Scopes::ALL.names(), ["users:read", "users:write", "groups:read", "groups:write"]);
        assert_eq!(serde_json::to_value(users).unwrap(), json!(["users:read", "users:write"]));
    }

    #[test]
    fn requests_name_known_scopes_or_nothing() {
        assert_eq!(Scopes::from_request(&Value::Null), Ok(None));
        assert_eq!(Scopes::from_request(&json!(["groups:write"])).unwrap().unwrap().names(), ["groups:read", "groups:write"]);
        assert_eq!(Scopes::from_request(&json!(["users:read", "users:read"])).unwrap().unwrap().names(), ["users:read"]);
        for bad in [json!([]), json!("users:read"), json!(["users"]), json!(["Users:Read"]), json!(["admin"]), json!([7]), json!({})] {
            assert!(Scopes::from_request(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stored_scopes_fail_closed() {
        assert_eq!(Scopes::from_stored(None), Scopes::ALL, "tokens from before scopes");
        let users = Scopes::of(&[Scope(Resource::Users, Access::Write)]);
        assert_eq!(Scopes::from_stored(Some(&users.to_stored())), users);
        assert_eq!(Scopes::from_stored(Some(r#"["users:read","teams:write"]"#)).names(), ["users:read"], "unknown names grant nothing");
        assert_eq!(Scopes::from_stored(Some("not json")).names(), Vec::<&str>::new());
        assert_eq!(Scopes::from_stored(Some("[]")).names(), Vec::<&str>::new());
    }

    #[test]
    fn requests_need_the_scope_of_their_resource() {
        let need = |m: Method, p: &str| match needed(&m, p) {
            Need::One(s) => s.name(),
            Need::Open => "open",
            Need::All => "all",
        };
        assert_eq!(need(Method::GET, "/scim/v2/Users"), "users:read");
        assert_eq!(need(Method::HEAD, "/scim/v2/Users/u1"), "users:read");
        assert_eq!(need(Method::POST, "/scim/v2/Users"), "users:write");
        for m in [Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS] {
            assert_eq!(need(m.clone(), "/scim/v2/Users/u1"), "users:write", "{m}");
            assert_eq!(need(m.clone(), "/scim/v2/Groups/g1"), "groups:write", "{m}");
        }
        assert_eq!(need(Method::GET, "/scim/v2/Groups"), "groups:read");
        assert_eq!(need(Method::GET, "/scim/v2//groups/"), "groups:read", "looser than the router");
        assert_eq!(need(Method::GET, "/scim/v2/USERS/x/y"), "users:read");
        for open in ["/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes/User", "/scim/v2/Schemas/urn:x", "/scim/v2/Bulk", "/scim/v2//Bulk"] {
            assert_eq!(need(Method::POST, open), "open", "{open}");
        }
        for closed in ["/scim/v2", "/scim/v2/", "/scim/v2/Me", "/scim/v2/bulk", "/scim/v2/schemas", "/scim/v2/%55sers", "/api/users"] {
            assert_eq!(need(Method::GET, closed), "all", "fails closed: {closed}");
        }
    }

    #[test]
    fn a_token_lacks_the_first_scope_it_doesnt_have() {
        let users = Scopes::of(&[Scope(Resource::Users, Access::Write)]);
        assert_eq!(users.lacks(Need::Open), None);
        assert_eq!(users.lacks(Need::One(Scope(Resource::Users, Access::Read))), None);
        assert_eq!(users.lacks(Need::One(Scope(Resource::Groups, Access::Read))).map(Scope::name), Some("groups:read"));
        assert_eq!(users.lacks(Need::All).map(Scope::name), Some("groups:read"));
        assert_eq!(Scopes::ALL.lacks(Need::All), None);
    }
}
