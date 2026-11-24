//! Linode interfaces (ADR 0226), the newer kind beside configuration-profile ones. A
//! Linode has one kind or the other. With Linode interfaces, a firewall is assigned to
//! each public and VPC interface (a `linode_interface` device), not to the Linode, and
//! interfaces are added and removed only while the Linode is powered off. VLAN
//! interfaces take no firewall with either kind.

use super::{Linode, path_id};
use crate::machines::provider::ProviderError;
use reqwest::Method;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Which kind of interfaces new Linodes get (MACHINE_LINODE_INTERFACES).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Generation {
    /// Configuration-profile interfaces, behind the Linode's one firewall.
    #[default]
    Legacy,
    /// Linode interfaces, the machines' firewall on each.
    Linode,
}

impl Generation {
    pub fn as_str(self) -> &'static str {
        match self {
            Generation::Legacy => "legacy",
            Generation::Linode => "linode",
        }
    }

    pub fn parse(v: &str) -> Result<Generation, String> {
        match v.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "legacy" | "legacy-config" => Ok(Generation::Legacy),
            "linode" => Ok(Generation::Linode),
            v => Err(format!("MACHINE_LINODE_INTERFACES must be legacy or linode, not \"{}\"", crate::audit::clip(v, 20))),
        }
    }
}

/// Whether Linode `l`, as `GET /linode/instances/{id}` describes it, has Linode
/// interfaces.
pub(super) fn has_linode_interfaces(l: &Value) -> bool {
    l["interface_generation"] == "linode"
}

/// A VPC Linode interface on `subnet`, behind `firewall`: an address of the subnet's
/// picked by Linode, and no public address mapped onto it.
fn vpc(firewall: u64, subnet: u64) -> Value {
    json!({
        "firewall_id": firewall,
        "vpc": { "subnet_id": subnet, "ipv4": { "addresses": [{ "address": "auto", "primary": true, "nat_1_1_address": null }] } },
    })
}

/// Puts a create's interfaces in `body`, always saying which kind, so the account's
/// default never decides whether the firewall covers them. Configuration-profile
/// interfaces take the firewall on the Linode (a top-level `firewall_id` is for them
/// only) and, on a team network, public then VPC. Linode interfaces take it on each:
/// public, the default route, then VPC.
pub(super) fn create(body: &mut Value, g: Generation, firewall: Option<u64>, subnet: Option<u64>) -> Result<(), ProviderError> {
    match g {
        Generation::Legacy => {
            body["interface_generation"] = json!("legacy_config");
            if let Some(fw) = firewall {
                body["firewall_id"] = json!(fw);
            }
            if let Some(s) = subnet {
                body["interfaces"] = json!([{ "purpose": "public" }, { "purpose": "vpc", "subnet_id": s }]);
            }
        }
        Generation::Linode => {
            let fw = firewall.ok_or_else(|| ProviderError::Api {
                status: 400,
                message: "Linode interfaces each need the machines' firewall (MACHINE_FIREWALL=on)".into(),
            })?;
            body["interface_generation"] = json!("linode");
            let mut list = vec![json!({ "firewall_id": fw, "default_route": { "ipv4": true }, "public": {} })];
            if let Some(s) = subnet {
                list.push(vpc(fw, s));
            }
            body["interfaces"] = json!(list);
        }
    }
    Ok(())
}

/// The Linode in an interface device's URL, `/v4/linode/instances/{linode}/interfaces/{interface}`.
pub(super) fn linode_in_url(url: &str, interface: u64) -> Option<u64> {
    let rest = url.split_once("/linode/instances/")?.1;
    let (linode, tail) = rest.split_once("/interfaces/")?;
    (tail.trim_end_matches('/') == interface.to_string()).then(|| linode.parse().ok()).flatten()
}

/// One of a Linode's own interfaces.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Interface {
    pub id: u64,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Kind {
    Public,
    Vpc { subnet: Option<u64> },
    /// VLAN, or anything newer: no firewall covers it.
    Other,
}

fn read(v: &Value) -> Result<Vec<Interface>, ProviderError> {
    let bad = || ProviderError::Transport("Linode sent interfaces we couldn't read".into());
    v["interfaces"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|i| {
            let kind = if !i["public"].is_null() {
                Kind::Public
            } else if !i["vpc"].is_null() {
                Kind::Vpc { subnet: i["vpc"]["subnet_id"].as_u64() }
            } else {
                Kind::Other
            };
            Ok(Interface { id: i["id"].as_u64().ok_or_else(bad)?, kind })
        })
        .collect()
}

/// The interfaces a firewall can cover: public and VPC.
pub(super) fn filtered(all: &[Interface]) -> Vec<u64> {
    all.iter().filter(|i| i.kind != Kind::Other).map(|i| i.id).collect()
}

/// Whether every interface a firewall can cover is in `behind`, and there is one.
pub(super) fn all_behind(all: &[Interface], behind: &BTreeSet<u64>) -> bool {
    let f = filtered(all);
    !f.is_empty() && f.iter().all(|i| behind.contains(i))
}

impl Linode {
    pub(super) async fn linode_interfaces(&self, linode: &str) -> Result<Vec<Interface>, ProviderError> {
        read(&self.call(Method::GET, &format!("/linode/instances/{}/interfaces", path_id(linode)?), None, None).await?)
    }

    pub(super) async fn interface_firewalls(&self, linode: &str, interface: u64) -> Result<Vec<Value>, ProviderError> {
        self.all(&format!("/linode/instances/{}/interfaces/{interface}/firewalls", path_id(linode)?), None).await
    }

    /// Gives Linode `id` (described by `l`) a VPC Linode interface on `subnet`, behind
    /// the enabled firewall its public interface is behind, the machines' (the
    /// reconciler checks that first). Linode takes it only while the Linode is off.
    pub(super) async fn join_with_linode_interfaces(&self, id: &str, l: &Value, subnet: u64) -> Result<(), ProviderError> {
        let refused = |message: &str| ProviderError::Api { status: 409, message: message.into() };
        if l["status"] != "offline" {
            return Err(refused("it has Linode interfaces, which Linode adds only while it is powered off"));
        }
        let all = self.linode_interfaces(id).await?;
        if let Some(Kind::Vpc { subnet: on }) = all.iter().map(|i| &i.kind).find(|k| matches!(k, Kind::Vpc { .. })) {
            return if *on == Some(subnet) { Ok(()) } else { Err(refused("it is on another VPC; it leaves that one first")) };
        }
        let Some(public) = all.iter().find(|i| i.kind == Kind::Public) else {
            return Err(refused("it has no public interface, which must stay the primary"));
        };
        let fw = self
            .interface_firewalls(id, public.id)
            .await?
            .iter()
            .find(|f| f["status"] == "enabled")
            .and_then(|f| f["id"].as_u64())
            .ok_or_else(|| refused("its public interface isn't behind an enabled firewall for its VPC interface to share"))?;
        self.call(Method::POST, &format!("/linode/instances/{id}/interfaces"), None, Some(&vpc(fw, subnet))).await.map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::provider::{CreateSpec, MachineProvider, NetworkMember, TeamNetwork};
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "linode-interfaces-test-token-0123";
    const FW: u64 = 77;

    #[derive(Clone, Debug)]
    struct L {
        status: &'static str,
        linode_interfaces: bool,
        /// (id, kind, subnet): `public`, `vpc` or `vlan`.
        interfaces: Vec<(u64, &'static str, Option<u64>)>,
    }

    /// A firewall device: (device id, firewall, entity type, entity id, its Linode).
    type Dev = (u64, u64, &'static str, u64, u64);

    #[derive(Default)]
    struct World {
        linodes: BTreeMap<u64, L>,
        devices: Vec<Dev>,
        next: u64,
        /// Firewalls by id, and whether each is enabled.
        firewalls: BTreeMap<u64, bool>,
        seen: Vec<(String, String, Value)>,
    }

    type W = Arc<Mutex<World>>;

    fn err(code: StatusCode, reason: &str) -> (StatusCode, Json<Value>) {
        (code, Json(json!({ "errors": [{ "reason": reason }] })))
    }

    fn page(data: Vec<Value>) -> Json<Value> {
        Json(json!({ "data": data, "page": 1, "pages": 1, "results": 0 }))
    }

    fn interface_json(id: u64, kind: &str, subnet: Option<u64>) -> Value {
        let mut v = json!({ "id": id, "mac_address": "22:00:00:00:00:01", "public": null, "vpc": null, "vlan": null });
        match kind {
            "public" => v["public"] = json!({ "ipv4": { "addresses": [] } }),
            "vpc" => v["vpc"] = json!({ "vpc_id": 5, "subnet_id": subnet }),
            _ => v["vlan"] = json!({ "vlan_label": "lab" }),
        }
        v
    }

    /// A local stand-in for Linode's interfaces and firewall devices, with Linode's
    /// rules: one firewall per service, `linode` devices only for profile Linodes and
    /// `linode_interface` ones only for Linode interfaces, and interfaces changed only
    /// while the Linode is off.
    async fn stand_in(world: World) -> (Linode, W) {
        let w: W = Arc::new(Mutex::new(world));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authed = |h: &axum::http::HeaderMap| h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
        let r = Router::new()
            .route(
                "/v4/linode/instances",
                axum::routing::post(move |State(w): State<W>, h: axum::http::HeaderMap, Json(b): Json<Value>| async move {
                    if !authed(&h) {
                        return err(StatusCode::UNAUTHORIZED, "Invalid Token");
                    }
                    w.lock().unwrap().seen.push(("POST".into(), "/linode/instances".into(), b.clone()));
                    if b["interface_generation"] == "legacy_config" && b["label"] == "linode-only" {
                        return err(StatusCode::BAD_REQUEST, "interface_generation: Legacy configuration interfaces are not allowed on this account");
                    }
                    (StatusCode::OK, Json(json!({ "id": 42, "label": b["label"], "status": "provisioning", "type": b["type"], "region": b["region"], "ipv4": [], "tags": [] })))
                }),
            )
            .route(
                "/v4/linode/instances/{id}",
                get(move |State(w): State<W>, Path(id): Path<u64>| async move {
                    let w = w.lock().unwrap();
                    let Some(l) = w.linodes.get(&id) else { return err(StatusCode::NOT_FOUND, "Not found") };
                    let g = if l.linode_interfaces { "linode" } else { "legacy_config" };
                    (StatusCode::OK, Json(json!({ "id": id, "label": format!("superbot-m{id}"), "status": l.status, "interface_generation": g, "type": "g6-standard-1", "region": "gb-lon", "ipv4": [], "tags": [] })))
                }),
            )
            .route(
                "/v4/linode/instances/{id}/{*rest}",
                get(move |State(w): State<W>, Path((id, rest)): Path<(u64, String)>| async move {
                    let w = w.lock().unwrap();
                    let Some(l) = w.linodes.get(&id) else { return err(StatusCode::NOT_FOUND, "Not found") };
                    let parts: Vec<&str> = rest.split('/').collect();
                    let firewalls_of = |entity: &str, eid: u64| {
                        let fws: Vec<Value> = w.devices.iter().filter(|d| d.2 == entity && d.3 == eid).map(|d| json!({ "id": d.1, "label": "superbot-fw", "status": if w.firewalls[&d.1] { "enabled" } else { "disabled" } })).collect();
                        (StatusCode::OK, page(fws))
                    };
                    match parts.as_slice() {
                        ["interfaces"] if l.linode_interfaces => (StatusCode::OK, Json(json!({ "interfaces": l.interfaces.iter().map(|(i, k, s)| interface_json(*i, k, *s)).collect::<Vec<_>>() }))),
                        ["interfaces"] => err(StatusCode::BAD_REQUEST, "Linode uses legacy configuration interfaces"),
                        ["interfaces", i, "firewalls"] => firewalls_of("linode_interface", i.parse().unwrap()),
                        ["firewalls"] => firewalls_of("linode", id),
                        _ => err(StatusCode::NOT_FOUND, "Not found"),
                    }
                })
                .post(move |State(w): State<W>, Path((id, rest)): Path<(u64, String)>, Json(b): Json<Value>| async move {
                    let mut w = w.lock().unwrap();
                    w.seen.push(("POST".into(), format!("/linode/instances/{id}/{rest}"), b.clone()));
                    w.next += 1;
                    let new = 900 + w.next;
                    let Some(l) = w.linodes.get_mut(&id) else { return err(StatusCode::NOT_FOUND, "Not found") };
                    if rest != "interfaces" || !l.linode_interfaces {
                        return err(StatusCode::NOT_FOUND, "Not found");
                    }
                    if l.status != "offline" {
                        return err(StatusCode::BAD_REQUEST, "The Linode must be powered off to add interfaces.");
                    }
                    let (kind, subnet) = if !b["vpc"].is_null() { ("vpc", b["vpc"]["subnet_id"].as_u64()) } else { ("public", None) };
                    l.interfaces.push((new, kind, subnet));
                    if let Some(fw) = b["firewall_id"].as_u64() {
                        w.devices.push((new + 5000, fw, "linode_interface", new, id));
                    }
                    (StatusCode::OK, Json(interface_json(new, kind, subnet)))
                })
                .delete(move |State(w): State<W>, Path((id, rest)): Path<(u64, String)>| async move {
                    let mut w = w.lock().unwrap();
                    w.seen.push(("DELETE".into(), format!("/linode/instances/{id}/{rest}"), Value::Null));
                    let Some(l) = w.linodes.get_mut(&id) else { return err(StatusCode::NOT_FOUND, "Not found") };
                    let Some(i) = rest.strip_prefix("interfaces/").and_then(|i| i.parse::<u64>().ok()) else { return err(StatusCode::NOT_FOUND, "Not found") };
                    if l.status != "offline" {
                        return err(StatusCode::BAD_REQUEST, "The Linode must be powered off to delete interfaces.");
                    }
                    l.interfaces.retain(|x| x.0 != i);
                    w.devices.retain(|d| !(d.2 == "linode_interface" && d.3 == i));
                    (StatusCode::OK, Json(json!({})))
                }),
            )
            .route(
                "/v4/networking/firewalls/{fw}/devices",
                get(move |State(w): State<W>, Path(fw): Path<u64>| async move {
                    let w = w.lock().unwrap();
                    let data = w
                        .devices
                        .iter()
                        .filter(|d| d.1 == fw)
                        .map(|d| match d.2 {
                            "linode_interface" if d.4 % 2 == 0 => json!({ "id": d.0, "entity": { "id": d.3, "type": d.2, "url": format!("/v4/linode/instances/{}/interfaces/{}", d.4, d.3), "parent_entity": { "id": d.4, "type": "linode" } } }),
                            // Some answers carry no parent: the URL still says whose it is.
                            "linode_interface" => json!({ "id": d.0, "entity": { "id": d.3, "type": d.2, "url": format!("/v4/linode/instances/{}/interfaces/{}", d.4, d.3) } }),
                            t => json!({ "id": d.0, "entity": { "id": d.3, "type": t } }),
                        })
                        .collect();
                    (StatusCode::OK, page(data))
                })
                .post(move |State(w): State<W>, Path(fw): Path<u64>, Json(b): Json<Value>| async move {
                    let mut w = w.lock().unwrap();
                    w.seen.push(("POST".into(), format!("/networking/firewalls/{fw}/devices"), b.clone()));
                    let entity = b["id"].as_u64().unwrap();
                    let (kind, linode) = match b["type"].as_str().unwrap() {
                        "linode" => match w.linodes.get(&entity) {
                            Some(l) if l.linode_interfaces => return err(StatusCode::BAD_REQUEST, "type: linode is not allowed for Linodes using Linode interfaces"),
                            Some(_) => ("linode", entity),
                            None => return err(StatusCode::BAD_REQUEST, "id: Linode not found"),
                        },
                        "linode_interface" => match w.linodes.iter().find(|(_, l)| l.interfaces.iter().any(|i| i.0 == entity)) {
                            Some((lid, _)) => ("linode_interface", *lid),
                            None => return err(StatusCode::BAD_REQUEST, "id: Interface not found"),
                        },
                        _ => return err(StatusCode::BAD_REQUEST, "type: invalid"),
                    };
                    if w.devices.iter().any(|d| d.2 == kind && d.3 == entity) {
                        return err(StatusCode::BAD_REQUEST, "This service already has an active Firewall.");
                    }
                    w.next += 1;
                    let device = 9000 + w.next;
                    w.devices.push((device, fw, kind, entity, linode));
                    (StatusCode::OK, Json(json!({ "id": device })))
                }),
            )
            .route(
                "/v4/networking/firewalls/{fw}/devices/{device}",
                axum::routing::delete(move |State(w): State<W>, Path((_, device)): Path<(u64, u64)>| async move {
                    let mut w = w.lock().unwrap();
                    w.seen.push(("DELETE".into(), format!("/networking/firewalls/devices/{device}"), Value::Null));
                    w.devices.retain(|d| d.0 != device);
                    (StatusCode::OK, Json(json!({})))
                }),
            )
            .route(
                "/v4/vpcs/{id}/subnets",
                get(move |State(w): State<W>| async move {
                    let w = w.lock().unwrap();
                    let mut linodes = Vec::new();
                    for (id, l) in &w.linodes {
                        let on: Vec<Value> = l
                            .interfaces
                            .iter()
                            .filter(|i| i.1 == "vpc")
                            .map(|i| json!({ "id": i.0, "active": l.status == "running", "config_id": if l.linode_interfaces { Value::Null } else { json!(i.0 * 10) } }))
                            .collect();
                        if !on.is_empty() {
                            linodes.push(json!({ "id": id, "interfaces": on }));
                        }
                    }
                    (StatusCode::OK, page(vec![json!({ "id": 50, "label": "machines", "ipv4": "10.248.0.0/22", "linodes": linodes })]))
                }),
            )
            .with_state(w.clone());
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (Linode::new(TOKEN, &format!("http://127.0.0.1:{port}/v4")), w)
    }

    fn linode(status: &'static str, interfaces: &[(u64, &'static str, Option<u64>)]) -> L {
        L { status, linode_interfaces: true, interfaces: interfaces.to_vec() }
    }

    fn world(linodes: &[(u64, L)]) -> World {
        World { linodes: linodes.iter().cloned().collect(), firewalls: [(FW, true), (78, true), (79, false)].into(), ..Default::default() }
    }

    fn net() -> TeamNetwork {
        TeamNetwork { id: "5".into(), label: "superbot-team-a-gb-lon".into(), region: "gb-lon".into(), subnet_id: "50".into(), subnet: "10.248.0.0/22".into(), created: false }
    }

    #[test]
    fn the_kind_is_legacy_unless_linode_is_asked_for() {
        assert_eq!(Generation::parse("").unwrap(), Generation::Legacy);
        assert_eq!(Generation::parse(" Legacy_Config ").unwrap(), Generation::Legacy);
        assert_eq!(Generation::parse("LINODE").unwrap(), Generation::Linode);
        let e = Generation::parse("both").unwrap_err();
        assert!(e.contains("legacy or linode"), "{e}");
    }

    #[test]
    fn a_create_always_says_which_kind_and_puts_the_firewall_on_every_interface() {
        let made = |g, fw, subnet| {
            let mut b = json!({});
            create(&mut b, g, fw, subnet).map(|()| b)
        };
        let b = made(Generation::Legacy, Some(FW), None).unwrap();
        assert_eq!(b, json!({ "interface_generation": "legacy_config", "firewall_id": FW }), "so an account defaulting to Linode interfaces can't leave the firewall off");
        let b = made(Generation::Legacy, Some(FW), Some(50)).unwrap();
        assert_eq!(b["interfaces"], json!([{ "purpose": "public" }, { "purpose": "vpc", "subnet_id": 50 }]));
        assert_eq!(made(Generation::Legacy, None, None).unwrap(), json!({ "interface_generation": "legacy_config" }));

        let b = made(Generation::Linode, Some(FW), Some(50)).unwrap();
        assert_eq!(b["interface_generation"], "linode");
        assert!(b.get("firewall_id").is_none(), "Linode ignores it for Linode interfaces");
        let list = b["interfaces"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!((list[0]["firewall_id"].as_u64(), list[0]["default_route"]["ipv4"].as_bool(), list[0]["public"].is_object()), (Some(FW), Some(true), true), "public first, the default route");
        assert_eq!((list[1]["firewall_id"].as_u64(), list[1]["vpc"]["subnet_id"].as_u64()), (Some(FW), Some(50)));
        assert_eq!(list[1]["vpc"]["ipv4"]["addresses"][0]["nat_1_1_address"], Value::Null, "no public address onto the VPC one");
        assert!(list[1].get("default_route").is_none());
        assert_eq!(made(Generation::Linode, Some(FW), None).unwrap()["interfaces"].as_array().unwrap().len(), 1);
        let e = made(Generation::Linode, None, None).unwrap_err();
        assert!(e.to_string().contains("MACHINE_FIREWALL=on"), "{e}");
    }

    #[test]
    fn an_interface_devices_linode_is_read_from_its_url() {
        assert_eq!(linode_in_url("/v4/linode/instances/12/interfaces/1201", 1201), Some(12));
        assert_eq!(linode_in_url("https://api.linode.com/v4beta/linode/instances/12/interfaces/1201/", 1201), Some(12));
        for (url, i) in [("/v4/linode/instances/12/interfaces/1202", 1201), ("/v4/linode/instances/x/interfaces/1201", 1201), ("/v4/nodebalancers/3", 3)] {
            assert_eq!(linode_in_url(url, i), None, "{url}");
        }
    }

    #[tokio::test]
    async fn a_linode_with_linode_interfaces_is_covered_only_when_each_interface_is() {
        let (api, w) = stand_in(world(&[
            (11, linode("running", &[(111, "public", None), (112, "vpc", Some(50)), (113, "vlan", None)])),
            (12, linode("running", &[(121, "public", None)])),
            (13, L { status: "running", linode_interfaces: false, interfaces: vec![] }),
            (14, linode("running", &[(141, "vlan", None)])),
        ]))
        .await;
        w.lock().unwrap().devices = vec![(1, FW, "linode_interface", 111, 11), (2, FW, "linode", 13, 13), (3, 78, "linode_interface", 121, 12), (4, FW, "nodebalancer", 3, 3)];
        let d = api.firewall_devices(&FW.to_string()).await.unwrap();
        assert_eq!((d.machines.clone(), d.partly.clone(), d.others), (vec!["13".to_string()], vec!["11".to_string()], 1), "11 is only partly behind; the NodeBalancer is another's");
        for (m, want) in [("11", false), ("12", false), ("13", true), ("14", false), ("99", false)] {
            assert_eq!(api.firewall_covers(&FW.to_string(), m).await.unwrap(), want, "{m}");
        }

        // The sweep's attach puts the rest behind it, VPC included; VLANs take none.
        api.attach_firewall(&FW.to_string(), "11").await.unwrap();
        assert!(api.firewall_covers(&FW.to_string(), "11").await.unwrap());
        let d = api.firewall_devices(&FW.to_string()).await.unwrap();
        assert_eq!((d.machines, d.partly, d.others), (vec!["13".to_string(), "11".to_string()], vec![], 1));
        let posted: Vec<Value> = w.lock().unwrap().seen.iter().filter(|s| s.1.ends_with("/devices")).map(|s| s.2.clone()).collect();
        assert_eq!(posted, [json!({ "id": 112, "type": "linode_interface" })], "only the one not behind yet");
        api.attach_firewall(&FW.to_string(), "11").await.unwrap();
        assert_eq!(w.lock().unwrap().seen.iter().filter(|s| s.1.ends_with("/devices")).count(), 1, "nothing left to attach");

        // One behind another firewall: Linode's refusal is the sweep's to report.
        let e = api.attach_firewall(&FW.to_string(), "12").await.unwrap_err();
        assert!(e.to_string().contains("already has an active Firewall"), "{e}");
        let e = api.attach_firewall(&FW.to_string(), "14").await.unwrap_err();
        assert!(e.to_string().contains("no public or VPC interface"), "{e}");
        // A profile Linode is attached as before.
        w.lock().unwrap().linodes.insert(15, L { status: "running", linode_interfaces: false, interfaces: vec![] });
        api.attach_firewall(&FW.to_string(), "15").await.unwrap();
        assert!(api.firewall_covers(&FW.to_string(), "15").await.unwrap());
        assert!(api.attach_firewall(&FW.to_string(), "../1").await.is_err());

        // Deleting takes every device of the Linode's off.
        api.detach_firewall(&FW.to_string(), "11").await.unwrap();
        assert!(!w.lock().unwrap().devices.iter().any(|d| d.4 == 11), "{:?}", w.lock().unwrap().devices);
        assert!(w.lock().unwrap().devices.iter().any(|d| d.4 == 13), "others' stay");
    }

    #[tokio::test]
    async fn a_linode_with_linode_interfaces_joins_while_off_behind_its_public_interfaces_firewall() {
        let (api, w) = stand_in(world(&[
            (21, linode("running", &[(211, "public", None)])),
            (22, linode("offline", &[(221, "public", None), (222, "vpc", Some(70))])),
            (23, linode("offline", &[(231, "vlan", None)])),
            (24, linode("offline", &[(241, "public", None)])),
            (25, linode("offline", &[(251, "public", None)])),
            (26, L { status: "running", linode_interfaces: false, interfaces: vec![] }),
        ]))
        .await;
        w.lock().unwrap().devices = vec![(1, FW, "linode_interface", 211, 21), (2, 79, "linode_interface", 251, 25)];
        assert!(api.team_network_needs_power_off("21").await.unwrap());
        assert!(!api.team_network_needs_power_off("26").await.unwrap(), "profile interfaces join for the next boot");
        let refused = async |m: &str, why: &str| {
            let e = api.join_team_network(m, &net()).await.unwrap_err();
            assert!(matches!(e, ProviderError::Api { status: 409, .. }) && e.to_string().contains(why), "{m}: {e}");
        };
        refused("21", "only while it is powered off").await;
        refused("22", "another VPC").await;
        refused("23", "no public interface").await;
        refused("24", "isn't behind an enabled firewall").await;
        refused("25", "isn't behind an enabled firewall").await;
        assert!(!w.lock().unwrap().seen.iter().any(|s| s.0 == "POST"), "nothing sent for a refusal");

        w.lock().unwrap().linodes.get_mut(&21).unwrap().status = "offline";
        api.join_team_network("21", &net()).await.unwrap();
        let sent = w.lock().unwrap().seen.iter().find(|s| s.1 == "/linode/instances/21/interfaces").unwrap().2.clone();
        assert_eq!((sent["firewall_id"].as_u64(), sent["vpc"]["subnet_id"].as_u64()), (Some(FW), Some(50)), "{sent}");
        assert!(api.firewall_covers(&FW.to_string(), "21").await.unwrap(), "public and VPC both behind the machines' firewall");
        api.join_team_network("21", &net()).await.unwrap();
        assert_eq!(w.lock().unwrap().seen.iter().filter(|s| s.1 == "/linode/instances/21/interfaces").count(), 1, "on it already: nothing more");

        // Its membership has no profile: it is taken off only while off, by its own path.
        let members = api.team_network_members("5").await.unwrap();
        let mem = members.iter().find(|m| m.machine == "21").unwrap().clone();
        assert_eq!((mem.config.as_str(), mem.needs_power_off, mem.active), ("", true, false));
        w.lock().unwrap().linodes.get_mut(&21).unwrap().status = "running";
        let e = api.leave_team_network(&mem).await.unwrap_err();
        assert!(e.to_string().contains("powered off"), "{e}");
        w.lock().unwrap().linodes.get_mut(&21).unwrap().status = "offline";
        api.leave_team_network(&mem).await.unwrap();
        assert!(w.lock().unwrap().seen.iter().any(|s| s.0 == "DELETE" && s.1 == format!("/linode/instances/21/interfaces/{}", mem.interface)));
        assert!(!api.team_network_members("5").await.unwrap().iter().any(|m| m.machine == "21"));
        api.leave_team_network(&mem).await.unwrap();
        assert!(api.leave_team_network(&NetworkMember { interface: "../x".into(), ..mem }).await.is_err());
    }

    #[tokio::test]
    async fn creates_name_the_kind_and_an_account_that_refuses_it_says_which_setting() {
        let (api, w) = stand_in(world(&[])).await;
        let spec = |label: &str| CreateSpec {
            label: label.into(),
            plan: "g6-standard-1".into(),
            region: "gb-lon".into(),
            image: "linode/ubuntu24.04".into(),
            tags: vec!["superbot".into()],
            authorized_keys: Vec::new(),
            user_data: None,
            firewall_id: Some(FW.to_string()),
            subnet_id: Some("50".into()),
        };
        api.create(&spec("superbot-m1")).await.unwrap();
        let e = api.create(&spec("linode-only")).await.unwrap_err();
        assert!(e.to_string().contains("MACHINE_LINODE_INTERFACES=legacy"), "{e}");
        let api = api.with_interfaces(Generation::Linode);
        assert_eq!(api.settings()["interfaces"], "linode");
        api.create(&spec("linode-only")).await.unwrap();
        let bodies: Vec<Value> = w.lock().unwrap().seen.iter().filter(|s| s.1 == "/linode/instances").map(|s| s.2.clone()).collect();
        assert_eq!(bodies.iter().map(|b| b["interface_generation"].as_str().unwrap()).collect::<Vec<_>>(), ["legacy_config", "legacy_config", "linode"]);
        assert_eq!(bodies[2]["interfaces"][1]["firewall_id"].as_u64(), Some(FW));
    }
}
