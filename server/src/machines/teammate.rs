//! Teammates' own OS users on machines (ADR 0047), botd's side. With
//! MACHINE_TEAMMATE_USERS=on, a run of a shared Bot for someone other than its owner
//! (ADR 0046) runs on the owner's machine as that teammate's own unprivileged user,
//! with its own home: not as the Bots' user, so it can't read the owner's folder,
//! harness logins or anything else the owner's runs keep there. Before such a run botd
//! asks the agent to make the user (`PUT /v1/teammates/{user}`), and the run is
//! refused, never run as the Bots' user, if the agent can't. Off, nothing here does
//! anything and teammates' runs stay as ADR 0046 has them.

use super::enroll::Enrollment;
use super::route::{Assigned, Refusal};
use super::wire::{self, Heartbeat, TeammateReply, TeammateRequest};

/// MACHINE_TEAMMATE_USERS: on or off (the default). Needs MACHINE_BOT_USER=on, so the
/// owner's own runs are never root and teammates' users have something to be kept from.
pub fn from_env(var: &dyn Fn(&str) -> String, bot_user: bool) -> Result<bool, String> {
    match var("MACHINE_TEAMMATE_USERS").trim() {
        "" | "off" => Ok(false),
        "on" if bot_user => Ok(true),
        "on" => Err("MACHINE_TEAMMATE_USERS=on needs MACHINE_BOT_USER=on".into()),
        v => Err(format!(
            "MACHINE_TEAMMATE_USERS must be on or off, not \"{v}\""
        )),
    }
}

/// Whether the agent can run a teammate's job as their own user. One that can't is
/// outdated: upgrading it (ADR 0039) is the way on, never the Bots' user instead.
pub fn fit(hb: &Heartbeat) -> Result<(), Refusal> {
    if hb.can.iter().any(|c| c == wire::CAN_TEAMMATES) {
        Ok(())
    } else {
        Err(Refusal::Outdated(hb.version.clone()))
    }
}

/// Asks `to`'s agent to make sure `user_id` has their own user there.
pub async fn ask(e: &Enrollment, to: &Assigned, user_id: &str) -> Result<TeammateReply, String> {
    if to.pins.is_empty() {
        return Err("it has no usable certificate".into());
    }
    if user_id.is_empty()
        || user_id.len() > 64
        || !user_id.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err("the teammate's id isn't a plain name".into());
    }
    let address = to.address.as_deref().ok_or("it has no address yet")?;
    // useradd can take a while on a busy machine.
    let client = e.upload_client(to.pins.clone(), 60)?;
    let mut r = client
        .put(e.agent_url(address, &format!("/v1/teammates/{user_id}")))
        .json(&TeammateRequest {
            owner_id: to.user_id.clone(),
        })
        .send()
        .await
        .map_err(|e| format!("its agent didn't answer: {}", super::enroll::without_url(e)))?;
    let code = r.status();
    let body = super::enroll::read_capped(&mut r, 64 << 10)
        .await
        .unwrap_or_default();
    if !code.is_success() {
        let said = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_default();
        return Err(format!(
            "its agent answered {}{}",
            code.as_u16(),
            if said.is_empty() {
                String::new()
            } else {
                format!(": {said}")
            }
        ));
    }
    let reply: TeammateReply = serde_json::from_slice(&body)
        .map_err(|e| format!("its agent's answer didn't parse: {e}"))?;
    let home = std::path::Path::new(&reply.home);
    for p in [&reply.workspace, &reply.bots] {
        if !std::path::Path::new(p).starts_with(home) || p.contains("/../") {
            return Err(format!(
                "its agent put the teammate's folders outside their home ({p})"
            ));
        }
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_unless_asked_and_only_with_the_bots_user() {
        let with = |v: &'static str| {
            move |k: &str| {
                if k == "MACHINE_TEAMMATE_USERS" {
                    v.to_string()
                } else {
                    String::new()
                }
            }
        };
        assert_eq!(from_env(&with(""), true), Ok(false));
        assert_eq!(from_env(&with("off"), false), Ok(false));
        assert_eq!(from_env(&with("on"), true), Ok(true));
        assert!(
            from_env(&with("on"), false)
                .unwrap_err()
                .contains("MACHINE_BOT_USER=on")
        );
        assert!(from_env(&with("yes"), true).is_err());
    }

    #[test]
    fn an_agent_that_cant_is_outdated() {
        let mut hb = Heartbeat {
            version: "0.9.0".into(),
            ..Heartbeat::default()
        };
        assert_eq!(fit(&hb), Err(Refusal::Outdated("0.9.0".into())));
        hb.can.push(wire::CAN_TEAMMATES.into());
        assert_eq!(fit(&hb), Ok(()));
    }
}
