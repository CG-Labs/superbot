//! Team accounts on managed tiers (ADR 0087). A team is a group of this server's users,
//! each in one team at most, with a role in it (`owner`, `admin`, `member`). Its data
//! (who's in it, their roles, invites, which machines it gave them) is the control
//! plane's, like users, roles and billing. Each member keeps a machine of their own
//! (ADR 0025's one computer per user): joining gives them one when the team has
//! `machines` on, and leaving suspends it and destroys it after TEAM_MACHINE_DAYS,
//! unless they join a team again first.
//!
//! What a team changes: sharing. A shared Bot, and a grant, reach only its owner's team
//! (`acl::reaches`); with TEAMS=on, people in no team share with nobody. So leaving a
//! team is losing access, and ADR 0052's and 0066's offboarding removes the leaver from
//! teammates' machines and accounts as it does for any other loss of access. While a
//! team pays for a plan (ADR 0093, `team_billing`), joining or leaving also moves the
//! member's tier and Stripe's seat count, and the team can't be emptied or deleted.
//!
//! Team owners and admins see each teammate's machine (its state, size, enrollment and
//! placement) and give them one, suspend or resume it. That is all: they get no Bot,
//! chat, workspace, harness login, secret or screen of a teammate's, which stay behind
//! the ACL and the server admins' routes as before.

use crate::audit::{Actor, Outcome, Source, Who};
use crate::db::{Team, TeamMember, User, now};
use crate::machines::{ControlPlane, State as MachineState, Step};
use crate::users::Caller;
use crate::{ApiError, AppState, Res, bad, need_user, not_found};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashSet;

pub const OWNER: &str = "owner";
pub const ADMIN: &str = "admin";
pub const MEMBER: &str = "member";

/// Why someone left a team, in `team.member_left` and as the offboarding reason.
pub const LEFT_TEAM: &str = "left_team";
/// Why someone lost access to Bots outside the team they joined.
pub const JOINED_TEAM: &str = "joined_team";

const DAY_MS: i64 = 86_400_000;
const INVITE_DAYS: i64 = 7;

/// TEAMS and TEAM_MACHINE_DAYS.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Settings {
    /// TEAMS=on: people in no team are a team of one, so their shared Bots reach nobody.
    pub strict: bool,
    /// How long a leaver's team machine stays suspended before it's destroyed. 0: at once.
    pub machine_days: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { strict: false, machine_days: 7 }
    }
}

impl Settings {
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let strict = match var("TEAMS").trim().to_ascii_lowercase().as_str() {
            "" | "off" | "0" | "false" => false,
            "on" | "1" | "true" => true,
            v => return Err(format!("TEAMS must be on or off, not \"{v}\"")),
        };
        let machine_days = match var("TEAM_MACHINE_DAYS").trim() {
            "" => 7,
            d => d.parse::<u32>().ok().filter(|d| *d <= 365).ok_or(format!("TEAM_MACHINE_DAYS must be 0 to 365, not \"{d}\""))?,
        };
        Ok(Settings { strict, machine_days })
    }

    pub fn describe(&self) -> String {
        let sharing = if self.strict {
            "a shared Bot reaches only its owner's team, and people in no team share with nobody"
        } else {
            "a shared Bot reaches only its owner's team; people in no team share with each other (TEAMS=on stops that)"
        };
        let machines = match self.machine_days {
            0 => "a leaver's team machine is destroyed at once".to_string(),
            d => format!("a leaver's team machine is suspended, then destroyed after {d} days"),
        };
        format!("{sharing}; {machines}")
    }
}

fn settings(app: &AppState) -> Settings {
    app.teams.get().copied().unwrap_or_default()
}

fn manages(role: &str) -> bool {
    role == OWNER || role == ADMIN
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, msg.into())
}

fn parse_role(v: &Value, allowed: &[&str]) -> Res<String> {
    let r = v["role"].as_str().unwrap_or(MEMBER).trim().to_ascii_lowercase();
    if allowed.contains(&r.as_str()) { Ok(r) } else { Err(bad(format!("role must be one of {}", allowed.join(", ")))) }
}

fn system(user_id: &str) -> Who {
    Who { actor: Actor::system("teams").on_behalf_of(user_id), source: Source::default() }
}

fn team_event(by: &Who, action: &str, team: &str, details: Value) -> crate::audit::Event {
    let mut d = json!({ "team": team });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    by.event(action).target("team", team).details(d)
}

fn control_plane(app: &AppState) -> Option<&ControlPlane> {
    app.control_plane.get().map(|cp| cp.as_ref()).filter(|cp| cp.enabled())
}

/// What a team's owners and admins see of a teammate's machine: its lifecycle, never
/// its address, provider ids, errors, files, logins or screens.
fn machine_view(app: &AppState, team_id: &str, user_id: &str) -> Value {
    let Some(m) = app.db.user_machine(user_id) else { return Value::Null };
    let tm = app.db.team_machine(&m.id);
    json!({
        "state": m.state, "tier": m.tier, "region": m.region, "enrollment": m.enrollment,
        "agentSeenAt": m.agent_seen_at, "assigned": m.assigned_at.is_some(), "backups": m.backups,
        "lastBackupAt": app.db.machine_last_backup(&m.id).map(|b| b.created_at), "createdAt": m.created_at,
        "team": tm.as_ref().is_some_and(|t| t.team_id == team_id),
        "releaseAt": tm.and_then(|t| t.release_at),
    })
}

fn member_view(app: &AppState, m: &TeamMember, machines: bool) -> Value {
    let u = app.db.user(&m.user_id);
    let mut v = json!({
        "id": m.user_id, "name": u.as_ref().map(|u| u.name.clone()), "email": u.as_ref().and_then(|u| u.email.clone()),
        "role": m.role, "joinedAt": m.joined_at, "active": u.as_ref().is_some_and(User::active),
    });
    if machines {
        v["machine"] = machine_view(app, &m.team_id, &m.user_id);
    }
    v
}

/// The team as a member sees it; with `manager`, teammates' machines and invites too.
fn team_view(app: &AppState, t: &Team, me: Option<&TeamMember>, manager: bool) -> Value {
    let members: Vec<Value> = app.db.team_members(&t.id).iter().map(|m| member_view(app, m, manager)).collect();
    let mut v = json!({ "id": t.id, "name": t.name, "machines": t.machines, "createdAt": t.created_at, "members": members });
    if let Some(me) = me {
        v["role"] = json!(me.role);
    }
    if manager {
        v["invites"] = json!(app.db.team_invites(&t.id));
        v["machineDays"] = json!(settings(app).machine_days);
    }
    if let Some(b) = crate::team_billing::view(app, &t.id, manager) {
        v["billing"] = b;
    }
    v
}

// Joining and leaving.

/// Gives `user` the machine their team pays for: a new one, or the one they had from a
/// team they left, if it hasn't been destroyed. A machine of their own stays theirs.
/// Never fails the join: what happened is in the answer and the audit log.
async fn provide(app: &AppState, by: &Who, team: &Team, user: &User) -> Value {
    let Some(cp) = control_plane(app) else { return json!("off") };
    if !team.machines {
        return json!("manual");
    }
    if let Some(m) = app.db.user_machine(&user.id) {
        // Under the lock the sweep destroys under, so a due machine is either taken back
        // or destroyed, never both.
        let guard = cp.lock_ops().await;
        let Some(tm) = app.db.team_machine(&m.id) else { return json!("own") };
        if tm.released_at.is_none() && tm.team_id == team.id {
            return json!("kept");
        }
        if !app.db.machine(&m.id).is_some_and(|m| matches!(m.state, MachineState::Running | MachineState::Suspended | MachineState::Provisioning | MachineState::Pending | MachineState::Error)) {
            return json!("failed");
        }
        app.db.team_machine_mark(&m.id, &team.id, &user.id);
        drop(guard);
        let resumed = match m.state {
            MachineState::Suspended => crate::machines::act_if(app, cp, by, &user.id, Step::Resume, None, &|x| ours(app, &team.id, x)).await.is_ok(),
            _ => false,
        };
        app.db.record(&team_event(by, "team.machine_kept", &team.id, json!({ "user": user.id, "machine": m.id, "fromTeam": tm.team_id, "resumed": resumed })));
        return json!("kept");
    }
    match crate::machines::request_as(app, cp, by, &user.id, &Bytes::new()).await {
        Ok(res) if res.status().is_success() => {
            let Some(m) = app.db.user_machine(&user.id) else { return json!("failed") };
            app.db.record(&team_event(by, "team.machine_requested", &team.id, json!({ "user": user.id, "machine": m.id, "tier": m.tier })));
            claim(app, by, &team.id, &user.id, &m.id).await;
            json!("requested")
        }
        res => {
            let error = match &res {
                Ok(r) => format!("the provider answered {}", r.status()),
                Err(e) => e.1.clone(),
            };
            // A machine that failed at the provider is still the team's to retry.
            app.db.record(&team_event(by, "team.machine_failed", &team.id, json!({ "user": user.id, "error": error })).outcome(Outcome::Failure));
            if let Some(m) = app.db.user_machine(&user.id) {
                claim(app, by, &team.id, &user.id, &m.id).await;
            }
            json!("failed")
        }
    }
}

/// Records a machine just made for `user_id` as `team_id`'s. Making it can take a
/// while: if they left the team meanwhile, it's released as their leaving would have.
/// Their current team takes it, even one a former team released; a former team's late
/// claim leaves alone a machine another team holds.
/// A machine already going is never claimed. Whether the team holds it after.
pub(crate) async fn claim(app: &AppState, by: &Who, team_id: &str, user_id: &str, machine_id: &str) -> bool {
    let Some(cp) = control_plane(app) else { return false };
    let left = {
        let _g = cp.lock_ops().await;
        if app.db.machine(machine_id).is_none_or(|m| matches!(m.state, MachineState::Destroying | MachineState::Destroyed)) {
            return false;
        }
        let left = app.db.team_id_of(user_id).as_deref() != Some(team_id);
        if left && app.db.team_machine(machine_id).is_some_and(|t| t.team_id != team_id) {
            return false;
        }
        app.db.team_machine_mark(machine_id, team_id, user_id);
        left
    };
    if left {
        release(app, by, team_id, user_id).await;
    }
    !left
}

/// Whether `m` is a machine `team_id` gave and hasn't released: the team's to manage.
fn ours(app: &AppState, team_id: &str, m: &crate::db::Machine) -> bool {
    app.db.team_machine(&m.id).is_some_and(|t| t.team_id == team_id && t.released_at.is_none())
}

/// Adds `user` to `team` with `role`, and gives them their machine.
async fn join(app: &AppState, by: &Who, team: &Team, user: &User, role: &str, via: &str) -> Res<Value> {
    if !user.active() {
        return Err(conflict("This person is disabled. Enable them first."));
    }
    let tier = app.tier_of(&user.id).name.clone();
    if !app.db.add_team_member(&team.id, &user.id, role, by.actor.id.as_deref()) {
        return Err(match app.db.team_id_of(&user.id) {
            Some(t) if t == team.id => conflict("They're on this team already."),
            _ => conflict("They're on another team. They have to leave it first."),
        });
    }
    if let Some(email) = &user.email {
        app.db.delete_team_invites_for(&team.id, email);
    }
    app.db.record(&team_event(by, "team.member_joined", &team.id, json!({ "user": user.id, "role": role, "via": via })));
    // Sharing now stops at the team, so people outside it lose access both ways.
    crate::machines::offboard::left(app, by, &user.id, JOINED_TEAM);
    crate::machines::offboard::check_owner(app, by, &user.id);
    for bot in app.db.bots() {
        let theirs = bot.owner_id == user.id;
        let had = bot.visibility == crate::acl::Visibility::Shared || app.db.grant(&bot.id, &user.id).is_some();
        if !theirs && !(had && !app.db.same_team(&bot.owner_id, &user.id)) {
            continue;
        }
        if app.live_run(&bot.id).is_some() {
            let for_user = app.requested_by(&bot);
            if (theirs || for_user == user.id) && !app.db.same_team(&bot.owner_id, &for_user) {
                app.stop(&bot.id);
            }
        }
        crate::acl_changed(app, by, &bot.id, true).await;
    }
    app.send(json!({ "type": "resync" }));
    let machine = provide(app, by, team, user).await;
    crate::team_billing::member_changed(app, &team.id, &user.id, &tier, "joined");
    let member = app.db.team_member(&user.id).ok_or_else(|| not_found("Member"))?;
    let mut v = member_view(app, &member, true);
    v["provisioned"] = machine;
    Ok(v)
}

/// Takes `user_id` off their team. Their grants to and from teammates go, runs between
/// them stop, ADR 0052's and 0066's offboarding removes them from teammates' machines
/// and accounts (and teammates from theirs), and the machine the team gave them is
/// suspended and, after TEAM_MACHINE_DAYS, destroyed.
pub async fn leave(app: &AppState, by: &Who, team_id: &str, user_id: &str, reason: &str) -> bool {
    let Some(member) = app.db.team_member(user_id).filter(|m| m.team_id == team_id) else { return false };
    let tier = app.tier_of(user_id).name.clone();
    if !app.db.remove_team_member(team_id, user_id, reason != "team_deleted") {
        return false;
    }
    let mates: HashSet<String> = app.db.team_members(team_id).into_iter().map(|m| m.user_id).collect();
    let mut touched = Vec::new();
    for bot in app.db.bots() {
        let theirs = bot.owner_id == user_id;
        if !theirs && !mates.contains(&bot.owner_id) {
            continue;
        }
        for g in app.db.grants(&bot.id) {
            if (theirs && mates.contains(&g.user_id)) || (!theirs && g.user_id == user_id) {
                app.db.remove_grant(&bot.id, &g.user_id);
                let d = json!({ "user": g.user_id, "level": g.level, "reason": LEFT_TEAM, "team": team_id });
                app.db.record(&by.event("bot.access_revoked").target("bot", &bot.id).bot(&bot.id).details(d));
            }
        }
        if app.live_run(&bot.id).is_some() {
            let for_user = app.requested_by(&bot);
            if (theirs && for_user != user_id) || (!theirs && for_user == user_id) {
                app.stop(&bot.id);
            }
        }
        touched.push(bot.id);
    }
    // Before acl_changed, whose own sweep would record the removals without the reason.
    crate::machines::offboard::left(app, by, user_id, LEFT_TEAM);
    crate::machines::offboard::check_owner(app, by, user_id);
    for id in &touched {
        crate::acl_changed(app, by, id, true).await;
    }
    app.db.record(&team_event(by, "team.member_left", team_id, json!({ "user": user_id, "role": member.role, "reason": reason })));
    release(app, by, team_id, user_id).await;
    crate::team_billing::member_changed(app, team_id, user_id, &tier, "left");
    app.send(json!({ "type": "resync" }));
    true
}

/// The machine `team_id` gave `user_id`, given back: suspended now, destroyed later.
async fn release(app: &AppState, by: &Who, team_id: &str, user_id: &str) {
    let Some(cp) = control_plane(app) else { return };
    let Some(m) = app.db.user_machine(user_id) else { return };
    if app.db.team_machine(&m.id).is_none_or(|t| t.team_id != team_id || t.released_at.is_some()) {
        return;
    }
    let days = settings(app).machine_days;
    let due = now() + days as i64 * DAY_MS;
    if !app.db.team_machine_release(&m.id, team_id, due) {
        return;
    }
    let suspended = match m.state {
        MachineState::Running if days > 0 => crate::machines::act_if(app, cp, by, user_id, Step::Suspend, None, &|x| released(app, &m.id, x)).await.is_ok(),
        _ => false,
    };
    app.db.record(&team_event(by, "team.machine_released", team_id, json!({ "user": user_id, "machine": m.id, "releaseAt": due, "suspended": suspended })));
    if days == 0 {
        destroy(app, cp, team_id, &m.id, user_id).await;
    }
}

/// Whether `m` is still `machine_id`, released and not taken back.
fn released(app: &AppState, machine_id: &str, m: &crate::db::Machine) -> bool {
    m.id == machine_id && app.db.team_machine(machine_id).is_some_and(|t| t.released_at.is_some())
}

async fn destroy(app: &AppState, cp: &ControlPlane, team_id: &str, machine_id: &str, user_id: &str) -> bool {
    let by = system(user_id);
    let due = |m: &crate::db::Machine| {
        m.id == machine_id
            && app.db.team_machine(machine_id).is_some_and(|t| t.team_id == team_id && t.released_at.is_some() && t.release_at.is_some_and(|d| d <= now()))
    };
    let res = crate::machines::destroy_as(app, cp, &by, user_id, &due).await;
    if res.as_ref().is_err_and(|e| e.0 == StatusCode::CONFLICT) && app.db.team_machine(machine_id).is_some_and(|t| t.released_at.is_none()) {
        return false;
    }
    let ok = res.is_ok();
    let gone = app.db.machine(machine_id).is_none_or(|m| m.state == MachineState::Destroyed);
    app.db.record(
        &team_event(&by, "team.machine_destroyed", team_id, json!({ "user": user_id, "machine": machine_id, "gone": gone }))
            .outcome(if ok { Outcome::Success } else { Outcome::Failure }),
    );
    if gone {
        app.db.team_machine_forget(machine_id);
    }
    ok
}

/// On every reconcile: destroys team machines whose leavers didn't come back in time,
/// and assigns members' team machines once they're running and enrolled, so their Bots
/// move there with no admin step.
pub async fn sweep(app: &AppState, cp: &ControlPlane) -> Value {
    let at = now();
    let (mut destroyed, mut assigned) = (0, 0);
    for tm in app.db.team_machines() {
        let Some(m) = app.db.machine(&tm.machine_id).filter(|m| m.state != MachineState::Destroyed) else {
            app.db.team_machine_forget(&tm.machine_id);
            continue;
        };
        match tm.release_at {
            Some(due) if due <= at => {
                if m.state != MachineState::Destroying && destroy(app, cp, &tm.team_id, &m.id, &m.user_id).await {
                    destroyed += 1;
                }
            }
            // Released but not due: keep it off, including one that was still being built
            // or that didn't power off the first time.
            Some(_) if m.state == MachineState::Running => {
                let _ = crate::machines::act_if(app, cp, &system(&m.user_id), &m.user_id, Step::Suspend, None, &|x| released(app, &m.id, x)).await;
            }
            Some(_) => {}
            None if cp.routing != crate::machines::route::Routing::Off && m.assigned_at.is_none() => {
                let _g = cp.lock_ops().await;
                let Some(m) = app.db.machine(&m.id) else { continue };
                if m.state == MachineState::Running
                    && m.enrollment == "enrolled"
                    && m.assigned_at.is_none()
                    && crate::machines::assign_now(app, cp, &system(&m.user_id), &m, json!({ "reason": "team", "team": tm.team_id }))
                {
                    assigned += 1;
                }
            }
            None => {}
        }
    }
    let mut out = json!({});
    if destroyed > 0 {
        out["machinesDestroyed"] = destroyed.into();
    }
    if assigned > 0 {
        out["machinesAssigned"] = assigned.into();
    }
    out
}

// The caller's own team: `/api/team` and `/api/me/team-invites`.

fn me(c: &Caller) -> Res<User> {
    need_user(c.principal)?;
    c.user.clone().ok_or_else(|| forbidden("Sign in as a person to use teams."))
}

fn my_team(app: &AppState, c: &Caller) -> Res<(User, TeamMember, Team)> {
    let u = me(c)?;
    let m = app.db.team_member(&u.id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "You aren't on a team.".into()))?;
    let t = app.db.team(&m.team_id).ok_or_else(|| not_found("Team"))?;
    Ok((u, m, t))
}

pub(crate) fn my_managed_team(app: &AppState, c: &Caller) -> Res<(User, TeamMember, Team)> {
    let (u, m, t) = my_team(app, c)?;
    if !manages(&m.role) {
        return Err(forbidden("Only the team's owners and admins can do this."));
    }
    Ok((u, m, t))
}

/// A member of `team_id`, by id or email. Anyone else is not found, so a team admin
/// learns nothing of people outside their team.
fn teammate(app: &AppState, team_id: &str, key: &str) -> Res<(User, TeamMember)> {
    let u = app.db.find_user(key).ok_or_else(|| not_found("Teammate"))?;
    let m = app.db.team_member(&u.id).filter(|m| m.team_id == team_id).ok_or_else(|| not_found("Teammate"))?;
    Ok((u, m))
}

fn owners(app: &AppState, team_id: &str) -> usize {
    app.db.team_members(team_id).iter().filter(|m| m.role == OWNER).count()
}

/// `GET /api/team`: your team, its members and your role; for its owners and admins,
/// each teammate's machine and the invites waiting.
pub async fn mine(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    let (_, m, t) = my_team(&app, &c)?;
    let mut v = team_view(&app, &t, Some(&m), manages(&m.role));
    if v.get("billing").is_some() {
        v["billing"]["canChange"] = json!(manages(&m.role) && crate::rbac::allows(c.principal, crate::rbac::Perm::Write));
    }
    Ok(Json(v))
}

/// `POST /api/team/leave`: off your team. Its last owner can't while others are on it.
pub async fn leave_mine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Res {
    let (u, m, t) = my_team(&app, &c)?;
    let others = app.db.team_members(&t.id).len() > 1;
    if m.role == OWNER && others && owners(&app, &t.id) == 1 {
        return Err(conflict("You're the team's only owner. Make someone else an owner first."));
    }
    let _billing = if others { None } else { crate::team_billing::may_delete(&app, &by, &t.id, "last_member_left").await? };
    if !leave(&app, &by, &t.id, &u.id, "left").await {
        return Err(conflict("You're the team's only owner. Make someone else an owner first."));
    }
    if !others && app.db.delete_team(&t.id) {
        app.db.record(&team_event(&by, "team.deleted", &t.id, json!({ "name": t.name, "reason": "empty" })));
    }
    Ok(Json(json!({ "ok": true })))
}

/// `POST /api/team/invites` `{email, role?}`: invites someone. They join when they accept.
pub async fn invite(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let (_, _, t) = my_managed_team(&app, &c)?;
    let email = v["email"].as_str().map(|e| e.trim().to_ascii_lowercase()).filter(|e| e.contains('@') && e.len() <= 254).ok_or_else(|| bad("Send an email address."))?;
    let role = parse_role(&v, &[ADMIN, MEMBER])?;
    if app.db.find_user(&email).is_some_and(|u| app.db.team_id_of(&u.id).as_deref() == Some(t.id.as_str())) {
        return Err(conflict("They're on this team already."));
    }
    let inv = app.db.put_team_invite(&t.id, &email, &role, by.actor.id.as_deref(), now() + INVITE_DAYS * DAY_MS);
    app.db.record(&team_event(&by, "team.invited", &t.id, json!({ "email": email, "role": role, "inviteId": inv.id })));
    Ok((StatusCode::CREATED, Json(json!(inv))))
}

/// `DELETE /api/team/invites/{id}`: withdraws an invite.
pub async fn uninvite(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let (_, _, t) = my_managed_team(&app, &c)?;
    let inv = app.db.team_invite(&id).filter(|i| i.team_id == t.id).ok_or_else(|| not_found("Invite"))?;
    app.db.delete_team_invite(&inv.id);
    app.db.record(&team_event(&by, "team.invite_cancelled", &t.id, json!({ "email": inv.email, "inviteId": inv.id })));
    Ok(Json(json!({ "ok": true })))
}

/// `PATCH /api/team/members/{user}` `{role}`. Only owners make or unmake owners, and a
/// team always keeps one.
pub async fn set_role(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
    let (_, me, t) = my_managed_team(&app, &c)?;
    let (u, m) = teammate(&app, &t.id, &key)?;
    let role = parse_role(&v, &[OWNER, ADMIN, MEMBER])?;
    if (role == OWNER || m.role == OWNER) && me.role != OWNER {
        return Err(forbidden("Only the team's owners can make or change owners."));
    }
    if m.role == OWNER && role != OWNER && owners(&app, &t.id) == 1 {
        return Err(conflict("A team needs an owner. Make someone else an owner first."));
    }
    if role != m.role {
        if !app.db.set_team_role(&t.id, &u.id, &role) {
            return Err(conflict("A team needs an owner. Make someone else an owner first."));
        }
        app.db.record(&team_event(&by, "team.role_changed", &t.id, json!({ "user": u.id, "from": m.role, "to": role })));
    }
    let m = app.db.team_member(&u.id).ok_or_else(|| not_found("Teammate"))?;
    Ok(Json(member_view(&app, &m, true)))
}

/// `DELETE /api/team/members/{user}`: takes a teammate off the team. Admins can't take
/// off owners; nobody takes off themselves this way (`POST /api/team/leave`).
pub async fn remove(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let (me_user, me, t) = my_managed_team(&app, &c)?;
    let (u, m) = teammate(&app, &t.id, &key)?;
    if u.id == me_user.id {
        return Err(conflict("To leave the team yourself, use leave."));
    }
    if m.role == OWNER && me.role != OWNER {
        return Err(forbidden("Only the team's owners can take an owner off the team."));
    }
    if !leave(&app, &by, &t.id, &u.id, "removed").await {
        return Err(conflict("A team needs an owner. Make someone else an owner first."));
    }
    Ok(Json(json!({ "ok": true })))
}

/// What offboarding does with a leaver's work: on teammates' machines (ADR 0052) and on
/// their accounts on this server (ADR 0066). Each has its own setting; null when off.
fn work_policies(app: &AppState) -> Value {
    let view = |o: &crate::machines::offboard::Settings| json!({ "files": o.files.as_str(), "graceDays": o.grace_days });
    let machines = app.control_plane.get().and_then(|cp| cp.enrollment.as_ref()).map(|e| view(&e.offboard));
    let accounts = app.isolation.get().filter(|i| i.teammates).map(|i| view(&i.offboard));
    json!({ "machines": machines, "accounts": accounts })
}

/// `GET /api/team/members/{user}/offboarding`: what taking a teammate off the team
/// would do, for the apps to say before they ask (ADR 0088): whether you may, how many
/// grants between them and teammates end, what becomes of their machine, and of their
/// work on teammates' machines and accounts. Counts and settings only: no Bot, file,
/// address or login of theirs. Changes nothing.
pub async fn offboarding(State(app): State<AppState>, Extension(c): Extension<Caller>, Path(key): Path<String>) -> Res {
    let (me_user, me, t) = my_managed_team(&app, &c)?;
    let (u, m) = teammate(&app, &t.id, &key)?;
    let blocked = if u.id == me_user.id {
        Some("self")
    } else if m.role == OWNER && me.role != OWNER {
        Some("owner")
    } else {
        None
    };
    let mates: HashSet<String> = app.db.team_members(&t.id).into_iter().map(|m| m.user_id).filter(|id| *id != u.id).collect();
    let mut grants = 0;
    for bot in app.db.bots() {
        let theirs = bot.owner_id == u.id;
        if !theirs && !mates.contains(&bot.owner_id) {
            continue;
        }
        grants += app.db.grants(&bot.id).iter().filter(|g| (theirs && mates.contains(&g.user_id)) || (!theirs && g.user_id == u.id)).count();
    }
    let days = settings(&app).machine_days;
    let machine = match app.db.user_machine(&u.id).filter(|x| x.state != MachineState::Destroyed) {
        None => json!({ "fate": "none" }),
        Some(x) if ours(&app, &t.id, &x) => json!({ "fate": if days == 0 { "destroy" } else { "suspend" }, "days": days }),
        Some(_) => json!({ "fate": "kept" }),
    };
    let work = work_policies(&app);
    Ok(Json(json!({
        "user": { "id": u.id, "name": u.name },
        "role": m.role,
        "allowed": blocked.is_none(),
        "blocked": blocked,
        "grants": grants,
        "machine": machine,
        "work": work,
    })))
}

/// The teammate's machine, if it's one the team gave them: only those are the team's
/// to manage. A machine they pay for themselves is theirs.
fn team_machine_of(app: &AppState, team_id: &str, user_id: &str) -> Res<()> {
    let m = app.db.user_machine(user_id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "They don't have a machine.".into()))?;
    match app.db.team_machine(&m.id) {
        Some(tm) if tm.team_id == team_id && tm.released_at.is_none() => Ok(()),
        _ => Err(forbidden("This machine isn't the team's. Its owner manages it.")),
    }
}

/// The teammate's machine after a step, with what went wrong in plain words: the
/// provider's and placement's details (host names, capacity) are for the server's
/// admins, in the audit log.
async fn machine_answer(app: &AppState, by: &Who, team_id: &str, user_id: &str, res: Res<axum::response::Response>) -> Res<(StatusCode, Json<Value>)> {
    let code = match res {
        Ok(r) => r.status(),
        Err(e) => {
            let d = json!({ "user": user_id, "status": e.0.as_u16(), "error": e.1 });
            app.db.record(&team_event(by, "team.machine_failed", team_id, d).outcome(Outcome::Failure));
            let msg = match e.0 {
                StatusCode::NOT_FOUND => "They don't have a machine.",
                StatusCode::SERVICE_UNAVAILABLE => "Machines are off on this server.",
                StatusCode::CONFLICT => "The machine can't do that now. Try again later, or ask the server's admins.",
                _ => "That didn't work. The server's admins can see why.",
            };
            return Err(ApiError(e.0, msg.into()));
        }
    };
    let mut v = json!({ "machine": machine_view(app, team_id, user_id) });
    if code == StatusCode::BAD_GATEWAY {
        v["error"] = json!("The provider couldn't do that just now. The server's admins can see why.");
    }
    Ok((code, Json(v)))
}

/// `POST /api/team/members/{user}/machine`: gives a teammate a machine, if they have none.
pub async fn give_machine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res<(StatusCode, Json<Value>)> {
    let (_, _, t) = my_managed_team(&app, &c)?;
    let (u, _) = teammate(&app, &t.id, &key)?;
    let cp = control_plane(&app).ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, crate::machines::NOT_CONFIGURED.into()))?;
    if let Some(m) = app.db.user_machine(&u.id) {
        if app.db.team_machine(&m.id).is_none() {
            return Err(conflict("They have a machine of their own already."));
        }
        // A machine the provider failed to build goes through the request's retry.
        if m.state != MachineState::Error {
            // One a former team released is this team's now, and back on.
            if !ours(&app, &t.id, &m) {
                if !claim(&app, &by, &t.id, &u.id, &m.id).await {
                    return Err(conflict("Their machine is being deleted. Ask again once it's gone."));
                }
                app.db.record(&team_event(&by, "team.machine_kept", &t.id, json!({ "user": u.id, "machine": m.id, "via": "admin" })));
                if app.db.machine(&m.id).is_some_and(|x| x.state == MachineState::Suspended) {
                    let res = crate::machines::act_if(&app, cp, &by, &u.id, Step::Resume, None, &|x| ours(&app, &t.id, x)).await;
                    return machine_answer(&app, &by, &t.id, &u.id, res).await;
                }
            }
            return Ok((StatusCode::OK, Json(json!({ "machine": machine_view(&app, &t.id, &u.id) }))));
        }
    }
    let res = crate::machines::request_as(&app, cp, &by, &u.id, &Bytes::new()).await;
    if let Some(m) = app.db.user_machine(&u.id) {
        app.db.record(&team_event(&by, "team.machine_requested", &t.id, json!({ "user": u.id, "machine": m.id, "tier": m.tier })));
        claim(&app, &by, &t.id, &u.id, &m.id).await;
    }
    machine_answer(&app, &by, &t.id, &u.id, res).await
}

async fn machine_step(app: AppState, c: Caller, by: Who, key: String, step: Step) -> Res<(StatusCode, Json<Value>)> {
    let (_, _, t) = my_managed_team(&app, &c)?;
    let (u, _) = teammate(&app, &t.id, &key)?;
    let cp = control_plane(&app).ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, crate::machines::NOT_CONFIGURED.into()))?;
    team_machine_of(&app, &t.id, &u.id)?;
    let by = Who { actor: by.actor.on_behalf_of(&u.id), source: by.source };
    let res = crate::machines::act_if(&app, cp, &by, &u.id, step, None, &|m| ours(&app, &t.id, m)).await;
    machine_answer(&app, &by, &t.id, &u.id, res).await
}

/// `POST /api/team/members/{user}/machine/suspend`: powers off a teammate's team machine.
pub async fn suspend(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res<(StatusCode, Json<Value>)> {
    machine_step(app, c, by, key, Step::Suspend).await
}

/// `POST /api/team/members/{user}/machine/resume`: boots it again.
pub async fn resume(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res<(StatusCode, Json<Value>)> {
    machine_step(app, c, by, key, Step::Resume).await
}

fn invite_view(app: &AppState, i: &crate::db::TeamInvite) -> Value {
    json!({ "id": i.id, "team": { "id": i.team_id, "name": app.db.team(&i.team_id).map(|t| t.name) }, "role": i.role, "expiresAt": i.expires_at })
}

fn my_invite(app: &AppState, u: &User, id: &str) -> Res<crate::db::TeamInvite> {
    let email = u.email.as_deref().unwrap_or_default();
    app.db
        .team_invite(id)
        .filter(|i| !email.is_empty() && i.email.eq_ignore_ascii_case(email) && i.expires_at > now())
        .ok_or_else(|| not_found("Invite"))
}

/// `GET /api/me/team-invites`: the teams waiting for you to accept.
pub async fn my_invites(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    let u = me(&c)?;
    let Some(email) = u.email.as_deref() else { return Ok(Json(json!([]))) };
    let at = now();
    let list: Vec<Value> = app.db.invites_for_email(email).iter().filter(|i| i.expires_at > at).map(|i| invite_view(&app, i)).collect();
    Ok(Json(json!(list)))
}

/// `POST /api/me/team-invites/{id}/accept`: joins the team, and gets your machine.
pub async fn accept(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let u = me(&c)?;
    let inv = my_invite(&app, &u, &id)?;
    let t = app.db.team(&inv.team_id).ok_or_else(|| not_found("Invite"))?;
    let v = join(&app, &by, &t, &u, &inv.role, "invite").await?;
    app.db.delete_team_invite(&inv.id);
    Ok(Json(v))
}

/// `DELETE /api/me/team-invites/{id}`: turns it down.
pub async fn decline(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let u = me(&c)?;
    let inv = my_invite(&app, &u, &id)?;
    app.db.delete_team_invite(&inv.id);
    app.db.record(&team_event(&by, "team.invite_declined", &inv.team_id, json!({ "user": u.id, "inviteId": inv.id })));
    Ok(Json(json!({ "ok": true })))
}

// Server admins: `/api/teams` (rbac::classify leaves it to Admin).

fn need_team(app: &AppState, id: &str) -> Res<Team> {
    app.db.team(id).ok_or_else(|| not_found("Team"))
}

/// `GET /api/teams`: every team, with its members.
pub async fn list(State(app): State<AppState>) -> Res {
    let list: Vec<Value> = app.db.teams().iter().map(|t| team_view(&app, t, None, true)).collect();
    Ok(Json(json!({ "teams": list, "settings": { "strict": settings(&app).strict, "machineDays": settings(&app).machine_days, "work": work_policies(&app) } })))
}

/// `POST /api/teams` `{name, owner}`: makes a team with its first owner.
pub async fn create(State(app): State<AppState>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let name = v["name"].as_str().map(str::trim).filter(|n| !n.is_empty() && n.chars().count() <= 100).ok_or_else(|| bad("Send a name (up to 100 characters)."))?;
    let owner = v["owner"].as_str().ok_or_else(|| bad("Send the owner's id or email."))?;
    let u = app.db.find_user(owner).ok_or_else(|| not_found("User"))?;
    if app.db.team_id_of(&u.id).is_some() {
        return Err(conflict("They're on another team. They have to leave it first."));
    }
    let t = app.db.create_team(name, by.actor.id.as_deref());
    if let Some(m) = v["machines"].as_bool() {
        app.db.update_team(&t.id, None, Some(m));
    }
    let t = need_team(&app, &t.id)?;
    app.db.record(&team_event(&by, "team.created", &t.id, json!({ "name": t.name, "owner": u.id, "machines": t.machines })));
    if let Err(e) = join(&app, &by, &t, &u, OWNER, "admin").await {
        app.db.delete_team(&t.id);
        return Err(e);
    }
    Ok((StatusCode::CREATED, Json(team_view(&app, &t, None, true))))
}

/// `GET /api/teams/{id}`.
pub async fn get(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    Ok(Json(team_view(&app, &need_team(&app, &id)?, None, true)))
}

/// `PATCH /api/teams/{id}` `{name?, machines?}`.
pub async fn update(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let t = need_team(&app, &id)?;
    let name = match v.get("name") {
        None => None,
        Some(n) => Some(n.as_str().map(str::trim).filter(|n| !n.is_empty() && n.chars().count() <= 100).ok_or_else(|| bad("name must be 1 to 100 characters"))?),
    };
    let machines = match v.get("machines") {
        None => None,
        Some(m) => Some(m.as_bool().ok_or_else(|| bad("machines must be true or false"))?),
    };
    app.db.update_team(&t.id, name, machines);
    app.db.record(&team_event(&by, "team.updated", &t.id, json!({ "name": name, "machines": machines })));
    Ok(Json(team_view(&app, &need_team(&app, &id)?, None, true)))
}

/// `DELETE /api/teams/{id}`: everyone leaves, as if each had, then the team goes.
pub async fn delete(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let t = need_team(&app, &id)?;
    let _billing = crate::team_billing::may_delete(&app, &by, &t.id, "admin").await?;
    for m in app.db.team_members(&t.id) {
        leave(&app, &by, &t.id, &m.user_id, "team_deleted").await;
    }
    app.db.delete_team(&t.id);
    app.db.record(&team_event(&by, "team.deleted", &t.id, json!({ "name": t.name, "reason": "admin" })));
    Ok(Json(json!({ "ok": true })))
}

/// `PUT /api/teams/{id}/members/{user}` `{role?}`: adds someone (no invite needed), or
/// changes their role.
pub async fn put_member(State(app): State<AppState>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>, Json(v): Json<Value>) -> Res {
    let t = need_team(&app, &id)?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    let role = parse_role(&v, &[OWNER, ADMIN, MEMBER])?;
    match app.db.team_member(&u.id) {
        Some(m) if m.team_id == t.id => {
            if m.role == OWNER && role != OWNER && owners(&app, &t.id) == 1 {
                return Err(conflict("A team needs an owner. Make someone else an owner first."));
            }
            if role != m.role {
                if !app.db.set_team_role(&t.id, &u.id, &role) {
                    return Err(conflict("A team needs an owner. Make someone else an owner first."));
                }
                app.db.record(&team_event(&by, "team.role_changed", &t.id, json!({ "user": u.id, "from": m.role, "to": role })));
            }
            let m = app.db.team_member(&u.id).ok_or_else(|| not_found("Member"))?;
            Ok(Json(member_view(&app, &m, true)))
        }
        _ => Ok(Json(join(&app, &by, &t, &u, &role, "admin").await?)),
    }
}

/// `DELETE /api/teams/{id}/members/{user}`: takes them off the team.
pub async fn delete_member(State(app): State<AppState>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>) -> Res {
    let t = need_team(&app, &id)?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    let m = app.db.team_member(&u.id).filter(|m| m.team_id == t.id).ok_or_else(|| not_found("Member"))?;
    let others = app.db.team_members(&t.id).len() > 1;
    if m.role == OWNER && others && owners(&app, &t.id) == 1 {
        return Err(conflict("They're the team's only owner. Make someone else an owner first, or delete the team."));
    }
    let _billing = if others { None } else { crate::team_billing::may_delete(&app, &by, &t.id, "last_member_removed").await? };
    if !leave(&app, &by, &t.id, &u.id, "removed").await {
        return Err(conflict("They're the team's only owner. Make someone else an owner first, or delete the team."));
    }
    if !others && app.db.delete_team(&t.id) {
        app.db.record(&team_event(&by, "team.deleted", &t.id, json!({ "name": t.name, "reason": "empty" })));
    }
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse() {
        let none = |_: &str| String::new();
        assert_eq!(Settings::from_env(&none), Ok(Settings { strict: false, machine_days: 7 }));
        let on = |k: &str| match k {
            "TEAMS" => "on".into(),
            "TEAM_MACHINE_DAYS" => "0".into(),
            _ => String::new(),
        };
        assert_eq!(Settings::from_env(&on), Ok(Settings { strict: true, machine_days: 0 }));
        assert!(Settings::from_env(&|k| if k == "TEAMS" { "yes please".into() } else { String::new() }).is_err());
        assert!(Settings::from_env(&|k| if k == "TEAM_MACHINE_DAYS" { "366".into() } else { String::new() }).is_err());
        assert!(Settings::default().describe().contains("after 7 days"));
    }
}
