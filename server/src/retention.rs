//! Chat retention (ADR 0098). `CHAT_RETENTION_DAYS` (unset or 0 = keep forever) deletes chat
//! messages older than that every few hours, a batch at a time, never one whose run is still
//! queued or running, and never one in or from the chat of a Bot an admin holds
//! (`/api/retention/holds/{bot}`, for a legal hold or any other reason). A held Bot can't be
//! deleted. Each pass is saved for admins to see, and one that deletes anything records
//! `chat.pruned` with the count.

use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{now, RetentionHold};
use crate::obs::log::log_warn;
use crate::runner::App;
use crate::{bad, not_found, AppState, Res};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_DAYS: u32 = 36_500;
const EVERY: Duration = Duration::from_secs(6 * 60 * 60);
/// Messages deleted per statement. Small enough that a batch holds the database for
/// milliseconds, so runs and requests get it between batches.
pub const BATCH: u32 = 500;
const PAUSE: Duration = Duration::from_millis(20);
const MAX_REASON: usize = 500;
const LAST_PASS: &str = "chat_retention_last_pass";

/// A retention setting in days: unset or 0 keeps forever.
pub fn days(name: &str, raw: &str) -> Result<Option<u32>, String> {
    match raw.trim() {
        "" | "0" => Ok(None),
        v => match v.parse::<u32>() {
            Ok(d) if (1..=MAX_DAYS).contains(&d) => Ok(Some(d)),
            _ => Err(format!("{name} must be a number of days from 1 to {MAX_DAYS}, or 0 to keep forever")),
        },
    }
}

/// Saves the setting, records a change, and prunes now and every few hours while it's on.
pub fn start(app: Arc<App>, days: Option<u32>) {
    let before = app.db.chat_retention();
    if before != days {
        app.db.set_chat_retention(days);
        app.db.record(&Event::new(Actor::system("retention"), "chat.retention_changed").details(json!({ "before": before, "after": days })));
    }
    let Some(days) = days else { return };
    tokio::spawn(async move {
        loop {
            prune(&app, days, now()).await;
            tokio::time::sleep(EVERY).await;
        }
    });
}

/// One pass: deletes every message older than `days` before `at`, a batch at a time.
/// Returns what it saved as the last pass.
pub async fn prune(app: &App, days: u32, at: i64) -> Value {
    let cutoff = at - i64::from(days) * 86_400_000;
    let (mut deleted, mut batches, mut error, mut after) = (0usize, 0u32, None, None);
    loop {
        match app.db.prune_chat_batch(cutoff, after, BATCH) {
            Ok((n, end)) => {
                deleted += n;
                batches += u32::from(n > 0);
                after = end;
                if n < BATCH as usize {
                    break;
                }
            }
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
        tokio::time::sleep(PAUSE).await;
    }
    let held = app.db.retention_hold_count();
    if let (Err(e), None) = (&held, &error) {
        error = Some(e.to_string());
    }
    let pass = json!({
        "at": at,
        "deleted": deleted,
        "batches": batches,
        "olderThan": cutoff,
        "retentionDays": days,
        "heldBots": held.ok(),
        "error": error,
    });
    // A failed write is logged and the worker carries on; the next pass tries again.
    if let Err(e) = app.db.try_set_setting(LAST_PASS, &pass.to_string()) {
        log_warn!("chat retention: couldn't save the last pass: {e}");
    }
    let event = Event::new(Actor::system("retention"), "chat.pruned").details(pass.clone());
    match &error {
        Some(e) => {
            log_warn!("chat retention: {e}");
            app.db.record(&event.outcome(Outcome::Failure));
        }
        None if deleted > 0 => app.db.record(&event),
        None => {}
    }
    pass
}

fn hold_view(app: &App, h: &RetentionHold) -> Value {
    let bot = app.db.bot(&h.bot_id);
    let owner = bot.as_ref().and_then(|b| app.db.user(&b.owner_id));
    json!({
        "botId": h.bot_id,
        "botName": bot.map(|b| b.name),
        "owner": owner.map(|u| json!({ "id": u.id, "email": u.email, "name": u.name })),
        "reason": h.reason,
        "heldBy": h.held_by,
        "heldAt": h.held_at,
    })
}

/// `GET /api/retention` (admins): what is kept for how long, the last pass, and the holds.
pub async fn get(State(app): State<AppState>) -> Json<Value> {
    let last: Option<Value> = app.db.setting(LAST_PASS).and_then(|s| serde_json::from_str(&s).ok());
    Json(json!({
        "chat": {
            "retentionDays": app.db.chat_retention(),
            "lastPass": last,
            "holds": app.db.retention_holds().iter().map(|h| hold_view(&app, h)).collect::<Vec<_>>(),
        },
        "audit": { "retentionDays": app.db.audit_retention() },
    }))
}

/// `PUT /api/retention/holds/{bot} {reason}` (admins): keeps the Bot's chat out of
/// retention, and the Bot from being deleted, until released.
pub async fn put_hold(State(app): State<AppState>, Extension(by): Extension<Who>, Path(bot): Path<String>, Json(v): Json<Value>) -> Res {
    let reason = v.get("reason").and_then(Value::as_str).map(str::trim).unwrap_or_default();
    if reason.is_empty() || reason.chars().count() > MAX_REASON {
        return Err(bad(format!("Send {{\"reason\": \"<why it's held>\"}}, up to {MAX_REASON} characters.")));
    }
    let b = app.db.bot(&bot).ok_or_else(|| not_found("Bot"))?;
    let before = app.db.retention_hold(&b.id);
    let hold = app.db.put_retention_hold(&b.id, reason, by.actor.id.as_deref()).ok_or_else(|| not_found("Bot"))?;
    if before.as_ref().is_none_or(|h| h.reason != hold.reason) {
        let action = if before.is_some() { "chat.hold_changed" } else { "chat.hold_placed" };
        app.db.record(&by.event(action).target("bot", &b.id).bot(&b.id).details(json!({ "reason": hold.reason, "before": before.map(|h| h.reason) })));
    }
    Ok(Json(hold_view(&app, &hold)))
}

/// `DELETE /api/retention/holds/{bot}` (admins): retention applies to the Bot's chat again.
pub async fn delete_hold(State(app): State<AppState>, Extension(by): Extension<Who>, Path(bot): Path<String>) -> Res {
    let hold = app.db.retention_hold(&bot).ok_or_else(|| not_found("Retention hold"))?;
    app.db.delete_retention_hold(&bot);
    app.db.record(&by.event("chat.hold_released").target("bot", &bot).bot(&bot).details(json!({ "reason": hold.reason, "heldAt": hold.held_at })));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting() {
        assert_eq!(days("CHAT_RETENTION_DAYS", ""), Ok(None));
        assert_eq!(days("CHAT_RETENTION_DAYS", " 0 "), Ok(None));
        assert_eq!(days("CHAT_RETENTION_DAYS", "90"), Ok(Some(90)));
        assert_eq!(days("CHAT_RETENTION_DAYS", "36500"), Ok(Some(MAX_DAYS)));
        for bad in ["-1", "forever", "36501", "1.5"] {
            let e = days("CHAT_RETENTION_DAYS", bad).unwrap_err();
            assert!(e.starts_with("CHAT_RETENTION_DAYS must be"), "{bad}: {e}");
        }
    }
}
