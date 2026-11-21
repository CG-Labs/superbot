//! The notification settings as the console and the client read and change them.
//! Admin-only: `rbac::classify` puts these routes under Admin. Webhook URLs are secrets
//! (they carry their own token): saved in the sealed store, never sent back, only their host.

use super::{apply_bot_patch, apply_patch, load, save, secret, secret_set, smtp, webhook, Settings};
use crate::audit::Who;
use crate::db::Bot;
use crate::runner::App;
use crate::secrets;
use serde_json::{json, Value};

fn webhook_view(name: &str) -> Value {
    let source = secrets::global().source(name).ok().flatten();
    json!({
        "set": source.is_some(),
        "host": secret(name).and_then(|u| webhook::host_of(u.expose())),
        "store": source.map(|(kind, _)| kind),
        // The env store owns a name it holds; the URL changes there.
        "writable": source.is_none_or(|(_, w)| w),
    })
}

fn links_view(app: &App) -> Value {
    let n = app.notifier.get();
    match n.and_then(|n| n.links.base.as_ref()) {
        Some(_) => json!({ "app": n.and_then(|n| n.links.app()), "console": n.and_then(|n| n.links.base.as_ref().map(|b| format!("{b}/console/"))) }),
        None => json!({ "problem": "Set PUBLIC_URL (or ALLOWED_HOSTS) so notices can link to the approval." }),
    }
}

pub fn view(app: &App) -> Value {
    let s = load(&app.db);
    let smtp = app.notifier.get().and_then(|n| n.smtp.as_ref());
    json!({
        "settings": s.global(),
        "email": {
            "configured": smtp.is_some(),
            "server": smtp.map(|m| m.describe()),
            "passwordSet": secret_set(smtp::PASSWORD),
        },
        "webhook": webhook_view(webhook::URL),
        "signing": secret_set(webhook::SIGNING),
        "links": links_view(app),
        "bots": s.bots.keys().collect::<Vec<_>>(),
    })
}

/// Saves `name`'s URL (a string) or removes it (null). None: not in the patch.
fn put_url(name: &str, v: Option<&Value>) -> Result<Option<&'static str>, String> {
    let Some(v) = v else { return Ok(None) };
    if let Some((store, false)) = secrets::global().source(name).map_err(|e| e.to_string())? {
        return Err(format!("{name} comes from the {store} store; change it there"));
    }
    match v {
        Value::Null => {
            secrets::global().delete(name).map_err(|e| e.to_string())?;
            Ok(Some("removed"))
        }
        Value::String(s) if s.trim().is_empty() => put_url(name, Some(&Value::Null)),
        Value::String(s) => {
            let url = webhook::check_url(s.trim())?;
            secrets::global().put(name, url.as_str()).map_err(|e| e.to_string())?;
            Ok(Some("set"))
        }
        _ => Err("The webhook URL must be a string, or null to remove it".into()),
    }
}

/// Whether `name` will have a URL once `v` (a patch's URL field) is saved.
fn will_have_url(name: &str, v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(u)) => !u.trim().is_empty(),
        Some(_) => false,
        None => secret_set(name),
    }
}

fn check(app: &App, s: &Settings, has_url: bool) -> Result<(), String> {
    if s.email.enabled {
        if app.notifier.get().is_none_or(|n| n.smtp.is_none()) {
            return Err("Email needs an SMTP server: set SMTP_HOST and SMTP_FROM, then restart".into());
        }
        if s.email.to.is_empty() && !s.email.deciders {
            return Err("Email needs an address, or the Bots' deciders".into());
        }
    }
    if s.webhook.enabled && !has_url {
        return Err("The webhook needs a URL".into());
    }
    Ok(())
}

/// `apply_patch`'s fields, plus `webhook.url`: a string saves it, null removes it.
pub fn update(app: &App, by: &Who, v: &Value) -> Result<Value, String> {
    let before = load(&app.db);
    let mut after = apply_patch(&before, v)?;
    let url = v.get("webhook").and_then(|w| w.get("url"));
    let has_url = will_have_url(webhook::URL, url);
    // Removing the URL turns the webhook off, unless the patch says otherwise (and fails).
    if !has_url && url.is_some() && !v["webhook"]["enabled"].is_boolean() {
        after.webhook.enabled = false;
    }
    check(app, &after, has_url)?;
    let changed = put_url(webhook::URL, url)?;
    save(&app.db, &after);
    let mut details = json!({ "before": before.global(), "after": after.global() });
    if let Some(c) = changed {
        details["webhookUrl"] = json!(c);
    }
    app.db.record(&by.event("notifications.updated").target("notifications", "global").details(details));
    Ok(view(app))
}

pub fn bot_view(app: &App, bot: &Bot) -> Value {
    let s = load(&app.db);
    let o = s.bots.get(&bot.id).cloned().unwrap_or_default();
    let plan = app.notifier.get().map(|n| n.plan(&app.db, Some(bot), &s)).unwrap_or_default();
    json!({
        "botId": bot.id,
        "override": o,
        "webhook": webhook_view(&webhook::bot_secret(&bot.id)),
        "global": { "email": s.email.enabled, "webhook": s.webhook.enabled && secret_set(webhook::URL), "format": s.webhook.format },
        // Where its next notice goes, as things are now.
        "reaches": {
            "email": plan.email.len(),
            "deciders": plan.deciders.iter().map(|u| json!({ "id": u.id, "name": u.name, "hasEmail": u.email.is_some() })).collect::<Vec<_>>(),
            "webhook": plan.webhook.as_ref().map(|(name, _)| if name == webhook::URL { "global" } else { "own" }),
        },
    })
}

/// `{email?, webhook?, format?}` (null follows the global settings), and `webhookUrl`:
/// the Bot's own URL, a string to save or null to remove.
pub fn update_bot(app: &App, by: &Who, bot: &Bot, v: &Value) -> Result<Value, String> {
    let mut s = load(&app.db);
    let before = s.bots.get(&bot.id).cloned().unwrap_or_default();
    let after = apply_bot_patch(&before, v)?;
    if after.email == Some(true) && app.notifier.get().is_none_or(|n| n.smtp.is_none()) {
        return Err("Email needs an SMTP server: set SMTP_HOST and SMTP_FROM, then restart".into());
    }
    let name = webhook::bot_secret(&bot.id);
    let url = v.get("webhookUrl");
    if after.webhook == Some(true) && !will_have_url(&name, url) && !secret_set(webhook::URL) {
        return Err("Set a webhook URL for this Bot, or a global one, first".into());
    }
    let changed = put_url(&name, url)?;
    if after.is_empty() {
        s.bots.remove(&bot.id);
    } else {
        s.bots.insert(bot.id.clone(), after.clone());
    }
    save(&app.db, &s);
    let mut details = json!({ "before": before, "after": after });
    if let Some(c) = changed {
        details["webhookUrl"] = json!(c);
    }
    app.db.record(&by.event("notifications.updated").target("notifications", &bot.id).bot(&bot.id).details(details));
    Ok(bot_view(app, bot))
}
