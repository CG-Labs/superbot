//! Bot ACLs: who may see and use which Bot. Every Bot has an owner and a visibility
//! (private, or shared with the org), and the owner can grant others `viewer` or
//! `operator`. `access` is the whole model; handlers ask for the level they need with
//! `need_bot_access` in `main.rs`, and lists and the live stream keep only what the
//! caller may see. Roles (`rbac.rs`) still apply first. Design: docs/adr/0017-bot-acls.md.

use crate::db::{Bot, Db};
use crate::rbac::{Principal, Role};
use crate::users::Caller;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// What a caller may do with one Bot. Each level includes the ones below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// The Bot doesn't exist as far as the caller can tell: hidden from lists, 404 on its routes.
    None,
    /// Its chat, routines, policy, and approvals.
    View,
    /// Make it act: chat, stop, open its screen, answer its approvals and handoffs, routines.
    Operate,
    /// Its settings, deleting it, and who can see it.
    Manage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Only the owner, admins, and people with a grant.
    Private,
    /// Everyone in the org can use it, within their role.
    Shared,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Shared => "shared",
        }
    }

    pub fn parse(s: &str) -> Option<Visibility> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" => Some(Visibility::Private),
            "shared" | "org" => Some(Visibility::Shared),
            _ => None,
        }
    }
}

/// A per-user grant on one Bot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Grant {
    Viewer,
    Operator,
}

impl Grant {
    pub fn as_str(self) -> &'static str {
        match self {
            Grant::Viewer => "viewer",
            Grant::Operator => "operator",
        }
    }

    pub fn parse(s: &str) -> Option<Grant> {
        match s.trim().to_ascii_lowercase().as_str() {
            "viewer" | "view" => Some(Grant::Viewer),
            "operator" | "operate" => Some(Grant::Operator),
            _ => None,
        }
    }

    fn access(self) -> Access {
        match self {
            Grant::Viewer => Access::View,
            Grant::Operator => Access::Operate,
        }
    }
}

/// The whole model. Admins manage every Bot. Owners manage theirs. A shared Bot can be
/// used by everyone on its owner's team (`same_team`, ADR 0087); a grant adds its level
/// there. Read-only users never get past viewing.
pub fn access(user_id: &str, role: Role, owner_id: &str, visibility: Visibility, grant: Option<Grant>, same_team: bool) -> Access {
    if role == Role::Admin {
        return Access::Manage;
    }
    let shared = if visibility == Visibility::Shared { Access::Operate } else { Access::None };
    let base = if owner_id == user_id {
        Access::Manage
    } else if same_team {
        shared.max(grant.map_or(Access::None, Grant::access))
    } else {
        Access::None
    };
    if role == Role::Readonly { base.min(Access::View) } else { base }
}

/// Whether sharing reaches across two people's teams (ADR 0087): the same team, or both
/// in none unless `strict` (TEAMS=on), where no team is a team of one.
pub fn reaches(strict: bool, a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        (None, None) => !strict,
        _ => false,
    }
}

/// How a shared Bot behaves when someone other than its owner uses it (ADR 0046).
/// `SHARED_BOTS`; `isolated` unless MACHINE_ROUTING is off, and always with it on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SharedBots {
    /// As before: a Bot acts with its owner's access, keys and facts, whoever asked.
    #[default]
    Open,
    /// A run for someone else reaches no Bot that person can't, gets the server's keys
    /// but not its owner's own, nor its owner's facts; a disabled owner's Bots don't run;
    /// new Bots are private.
    Isolated,
}

impl SharedBots {
    /// `routed`: MACHINE_ROUTING isn't off. Bots on users' own machines need `isolated`.
    pub fn parse(raw: &str, routed: bool) -> Result<SharedBots, String> {
        match (raw.trim().to_ascii_lowercase().as_str(), routed) {
            ("", true) | ("isolated", _) => Ok(SharedBots::Isolated),
            ("", false) | ("open", false) => Ok(SharedBots::Open),
            ("open", true) => Err("SHARED_BOTS=open can't be used with MACHINE_ROUTING on or assigned: Bots on users' own machines need isolated shared Bots".into()),
            (v, _) => Err(format!("SHARED_BOTS must be open or isolated, not \"{v}\"")),
        }
    }
}

/// Whose access a request has, for ACL checks.
#[derive(Clone, Debug, PartialEq)]
pub enum Viewer {
    /// Admins and break-glass.
    All,
    User { id: String, role: Role },
    /// A person without a user record. Only reachable if the owner account is missing.
    Nobody,
    /// A Bot's run for someone other than its owner (ADR 0046): the lesser of its
    /// owner's access and theirs, Bot by Bot.
    Within(Box<Viewer>, Box<Viewer>),
}

impl Viewer {
    pub fn of(c: &Caller) -> Viewer {
        match (c.principal, &c.user) {
            (Principal::User(Role::Admin), _) => Viewer::All,
            // A Bot acts with its owner's access (`owner_of`), never more.
            (Principal::Bot, _) => Viewer::Nobody,
            (Principal::User(role), Some(u)) => Viewer::User { id: u.id.clone(), role },
            (Principal::User(_), None) => Viewer::Nobody,
        }
    }

    /// The access a Bot acts with toward other Bots: its owner's, as the user's role is now.
    /// A Bot whose owner is disabled or gone acts with none.
    pub fn owner_of(db: &Db, bot: &Bot) -> Viewer {
        Viewer::person(db, &bot.owner_id)
    }

    /// A user's access as their role is now. Disabled or gone: none.
    pub fn person(db: &Db, user_id: &str) -> Viewer {
        match db.user(user_id) {
            Some(u) if !u.active() => Viewer::Nobody,
            Some(u) if u.role == Role::Admin => Viewer::All,
            Some(u) => Viewer::User { id: u.id, role: u.role },
            None => Viewer::Nobody,
        }
    }

    /// No more than both: `self` capped by `other`.
    pub fn within(self, other: Viewer) -> Viewer {
        match (self, other) {
            (Viewer::Nobody, _) | (_, Viewer::Nobody) => Viewer::Nobody,
            (v, Viewer::All) | (Viewer::All, v) => v,
            (a, b) if a == b => a,
            (a, b) => Viewer::Within(Box::new(a), Box::new(b)),
        }
    }

    pub fn access(&self, db: &Db, bot: &Bot) -> Access {
        match self {
            Viewer::All => Access::Manage,
            Viewer::Nobody => Access::None,
            Viewer::User { id, role } => access(id, *role, &bot.owner_id, bot.visibility, db.grant(&bot.id, id), db.same_team(&bot.owner_id, id)),
            Viewer::Within(a, b) => a.access(db, bot).min(b.access(db, bot)),
        }
    }

    /// Every Bot this viewer can see, with its access, in the usual order.
    pub fn bots(&self, db: &Db) -> Vec<(Bot, Access)> {
        if let Viewer::Within(a, b) = self {
            return a
                .bots(db)
                .into_iter()
                .filter_map(|(bot, x)| {
                    let both = x.min(b.access(db, &bot));
                    (both > Access::None).then_some((bot, both))
                })
                .collect();
        }
        let (grants, teams) = match self {
            Viewer::User { id, .. } => (db.user_grants(id), db.team_ids()),
            _ => (HashMap::new(), HashMap::new()),
        };
        let strict = db.teams_strict();
        db.bots()
            .into_iter()
            .filter_map(|b| {
                let a = match self {
                    Viewer::All => Access::Manage,
                    Viewer::Nobody | Viewer::Within(..) => Access::None,
                    Viewer::User { id, role } => {
                        let same = b.owner_id == *id || reaches(strict, teams.get(&b.owner_id).map(String::as_str), teams.get(id).map(String::as_str));
                        access(id, *role, &b.owner_id, b.visibility, grants.get(&b.id).copied(), same)
                    }
                };
                (a > Access::None).then_some((b, a))
            })
            .collect()
    }
}

/// The Bot a live event is about, if any.
fn event_bot(v: &Value) -> Option<&str> {
    v["botId"].as_str().or_else(|| v["bot"]["id"].as_str()).or_else(|| v["message"]["botId"].as_str()).or_else(|| v["approval"]["botId"].as_str())
}

/// One viewer's slice of the live stream. Access is cached per Bot and forgotten on
/// `resync` (sent after every ACL change) and whenever `reset` is called.
pub struct StreamFilter {
    pub viewer: Viewer,
    seen: HashMap<String, Access>,
}

impl StreamFilter {
    pub fn new(viewer: Viewer) -> StreamFilter {
        StreamFilter { viewer, seen: HashMap::new() }
    }

    pub fn reset(&mut self, viewer: Viewer) {
        self.viewer = viewer;
        self.seen.clear();
    }

    /// The event as this viewer should get it: None to drop it, else with `access` set on
    /// the Bot view it carries. Events about no Bot (policy, resync) pass unchanged.
    pub fn apply(&mut self, db: &Db, data: &str) -> Option<String> {
        let Ok(mut v) = serde_json::from_str::<Value>(data) else { return Some(data.to_string()) };
        if v["type"] == "resync" {
            self.seen.clear();
            return Some(data.to_string());
        }
        // The Bot is gone, so its access can't be looked up; its id alone tells nothing.
        if v["type"] == "botDeleted" {
            if let Some(id) = v["botId"].as_str() {
                self.seen.remove(id);
            }
            return Some(data.to_string());
        }
        let Some(id) = event_bot(&v).map(String::from) else { return Some(data.to_string()) };
        let a = match self.seen.get(&id) {
            Some(a) => *a,
            None => {
                let a = db.bot(&id).map_or(Access::None, |b| self.viewer.access(db, &b));
                self.seen.insert(id, a);
                a
            }
        };
        if a == Access::None {
            return None;
        }
        if v["bot"].is_object() {
            v["bot"]["access"] = json!(a);
            return Some(v.to_string());
        }
        Some(data.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Access::{Manage, Operate, View};
    const HIDDEN: Access = Access::None;

    #[test]
    fn the_access_matrix() {
        use Role::{Admin as A, Member as M, Readonly as R};
        use Visibility::{Private as P, Shared as S};
        let (n, v, o) = (Option::None, Some(Grant::Viewer), Some(Grant::Operator));
        // (role, is owner, visibility, grant) -> access
        let table = [
            (A, false, P, n, Manage),
            (A, false, S, n, Manage),
            (M, true, P, n, Manage),
            (M, true, S, n, Manage),
            (M, false, P, n, HIDDEN),
            (M, false, P, v, View),
            (M, false, P, o, Operate),
            (M, false, S, n, Operate),
            (M, false, S, v, Operate),
            (M, false, S, o, Operate),
            (R, true, P, n, View),
            (R, false, P, n, HIDDEN),
            (R, false, P, v, View),
            (R, false, P, o, View),
            (R, false, S, n, View),
        ];
        for (role, owner, vis, grant, want) in table {
            let owner_id = if owner { "u1" } else { "someone" };
            assert_eq!(access("u1", role, owner_id, vis, grant, true), want, "{role:?} owner={owner} {vis:?} {grant:?}");
        }
        assert!(HIDDEN < View && View < Operate && Operate < Manage);

        // Another team's Bot (ADR 0087): neither sharing nor a grant reaches across.
        for (role, vis, grant, want) in [(M, S, n, HIDDEN), (M, P, o, HIDDEN), (M, S, o, HIDDEN), (R, S, v, HIDDEN), (A, P, n, Manage)] {
            assert_eq!(access("u1", role, "someone", vis, grant, false), want, "{role:?} {vis:?} {grant:?} across teams");
        }
        assert_eq!(access("u1", M, "u1", P, n, false), Manage, "an owner is on their own team");
    }

    #[test]
    fn sharing_reaches_only_the_same_team() {
        assert!(reaches(false, Some("t1"), Some("t1")));
        assert!(!reaches(false, Some("t1"), Some("t2")));
        assert!(!reaches(false, Some("t1"), None) && !reaches(false, None, Some("t1")));
        assert!(reaches(false, None, None), "one org, as before");
        assert!(!reaches(true, None, None), "TEAMS=on: no team is a team of one");
        assert!(reaches(true, Some("t1"), Some("t1")));
    }

    #[test]
    fn words_parse() {
        assert_eq!(Visibility::parse(" Shared "), Some(Visibility::Shared));
        assert_eq!(Visibility::parse("private"), Some(Visibility::Private));
        assert_eq!(Visibility::parse("public"), Option::None);
        assert_eq!(Grant::parse("operator"), Some(Grant::Operator));
        assert_eq!(Grant::parse("VIEWER"), Some(Grant::Viewer));
        assert_eq!(Grant::parse("owner"), Option::None);
        assert_eq!(serde_json::to_value(Access::Operate).unwrap(), json!("operate"));
    }

    #[test]
    fn shared_bots_are_isolated_whenever_bots_run_on_users_machines() {
        assert_eq!(SharedBots::parse("", false), Ok(SharedBots::Open), "self-host: as before");
        assert_eq!(SharedBots::parse("", true), Ok(SharedBots::Isolated));
        assert_eq!(SharedBots::parse(" Isolated ", false), Ok(SharedBots::Isolated), "self-host may opt in");
        assert_eq!(SharedBots::parse("open", false), Ok(SharedBots::Open));
        assert!(SharedBots::parse("open", true).unwrap_err().contains("MACHINE_ROUTING"));
        assert!(SharedBots::parse("team", false).is_err());
    }

    #[test]
    fn a_run_for_someone_else_reaches_no_more_than_both() {
        let db = Db::open(&crate::db::temp_path("acl-within").join("app.sqlite")).unwrap();
        for (id, role) in [("ada", Role::Member), ("bea", Role::Member), ("root", Role::Admin)] {
            db.create_user(Some(id), None, id, role).unwrap();
        }
        let team = db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, "ada", Visibility::Shared);
        let ledger = db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, "ada", Visibility::Private);
        let scout = db.create_bot_owned("Scout", "#fff", "waddle", "claude", None, false, "bea", Visibility::Private);
        let notes = db.create_bot_owned("Notes", "#fff", "waddle", "claude", None, false, "bea", Visibility::Shared);
        let (ada, bea) = (Viewer::person(&db, "ada"), Viewer::person(&db, "bea"));
        let capped = ada.clone().within(bea.clone());
        assert!(matches!(capped, Viewer::Within(..)));
        let names = |v: &Viewer| v.bots(&db).into_iter().map(|(b, a)| (b.name, a)).collect::<Vec<_>>();
        assert_eq!(names(&capped), vec![("Team".to_string(), Operate), ("Notes".to_string(), Operate)], "never Ada's private Bot or Bea's");
        assert_eq!(capped.access(&db, &ledger), HIDDEN);
        assert_eq!(capped.access(&db, &scout), HIDDEN, "nor a private Bot of the asker's that the owner can't see");
        assert_eq!(capped.access(&db, &team), Operate);
        assert_eq!(capped.access(&db, &notes), Operate, "both can use the asker's shared Bot");
        assert_eq!(ada.access(&db, &ledger), Manage, "Ada's own runs are unchanged");

        assert_eq!(ada.clone().within(Viewer::person(&db, "root")), ada, "an admin asking adds no cap");
        assert_eq!(Viewer::All.within(bea.clone()), bea);
        assert_eq!(ada.clone().within(ada.clone()), ada);
        db.update_user("bea", crate::db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
        assert_eq!(ada.within(Viewer::person(&db, "bea")), Viewer::Nobody, "a disabled asker reaches nothing");
    }

    #[test]
    fn the_stream_drops_hidden_bots_and_tags_the_rest() {
        let db = Db::open(&crate::db::temp_path("acl-stream").join("app.sqlite")).unwrap();
        for id in ["u1", "u2"] {
            db.create_user(Some(id), None, id, Role::Member).unwrap();
        }
        let mine = db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, "u1", Visibility::Private);
        let theirs = db.create_bot_owned("Theirs", "#fff", "waddle", "claude", None, false, "u2", Visibility::Private);
        let mut f = StreamFilter::new(Viewer::User { id: "u1".into(), role: Role::Member });
        let status = |id: &str| json!({ "type": "status", "botId": id, "working": true }).to_string();
        assert!(f.apply(&db, &status(&mine.id)).is_some());
        assert_eq!(f.apply(&db, &status(&theirs.id)), Option::None);
        let msg = json!({ "type": "message", "message": { "botId": theirs.id }, "bot": { "id": theirs.id } }).to_string();
        assert_eq!(f.apply(&db, &msg), Option::None);
        let bot = json!({ "type": "bot", "bot": { "id": mine.id } }).to_string();
        let out: Value = serde_json::from_str(&f.apply(&db, &bot).unwrap()).unwrap();
        assert_eq!(out["bot"]["access"], "manage");
        assert!(f.apply(&db, r#"{"type":"policy","policy":{}}"#).is_some());

        // Cached until the next resync, which every ACL change sends.
        db.set_grant(&theirs.id, "u1", Grant::Viewer, "u2");
        assert_eq!(f.apply(&db, &status(&theirs.id)), Option::None);
        assert!(f.apply(&db, r#"{"type":"resync"}"#).is_some());
        assert!(f.apply(&db, &status(&theirs.id)).is_some());
        assert!(f.apply(&db, &json!({ "type": "botDeleted", "botId": theirs.id }).to_string()).is_some());

        // A new viewer (a role change) starts over.
        f.reset(Viewer::User { id: "u3".into(), role: Role::Readonly });
        assert_eq!(f.apply(&db, &status(&mine.id)), Option::None);
    }
}
