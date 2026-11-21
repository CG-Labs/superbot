use super::*;
use crate::machines::incus_standin::{StandIn, self_signed};

fn incus(s: &StandIn) -> Incus {
    Incus::new(s.settings(None), s.credentials()).unwrap()
}

fn spec(label: &str, plan: &str) -> CreateSpec {
    CreateSpec {
        label: label.into(),
        plan: plan.into(),
        region: LOCAL.into(),
        image: DEFAULT_IMAGE.into(),
        tags: vec!["superbot".into(), "superbot-user-u1".into()],
        authorized_keys: vec!["ssh-ed25519 AAAAC3Nza admin@example".into()],
        user_data: Some("#cloud-config\nwrite_files: []\n".into()),
        firewall_id: Some("superbot-fw".into()),
    }
}

fn agent_rule() -> FirewallRule {
    FirewallRule {
        label: "agent-from-control-plane".into(),
        ports: "8445".into(),
        sources: vec!["192.0.2.10/32".into(), "2001:db8::10/128".into()],
    }
}

#[test]
fn plans_parse_strictly() {
    assert_eq!(
        Size::parse("c2-m4-d40").unwrap(),
        Size { cpus: 2, memory_gib: 4, disk_gib: 40 }
    );
    for bad in ["g6-standard-1", "c2-m4", "c0-m4-d40", "c02-m4-d40", "c2-m4-d40-x", "c-m4-d40", "c2-m4-d99999", "C2-M4-D40"] {
        assert!(Size::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(Size::parse("c1-m1-d10").unwrap().processes(), 2048, "a floor for small plans");
    assert_eq!(Size::parse("c4-m8-d80").unwrap().processes(), 8192);
    for (_, plan) in crate::machines::parse_tiers(DEFAULT_TIERS).unwrap() {
        Size::parse(&plan).unwrap();
    }
}

#[test]
fn egress_keeps_containers_off_private_and_host_addresses() {
    let deny: Vec<String> = PRIVATE.iter().map(|s| s.to_string()).chain(["203.0.113.5/32".to_string()]).collect();
    let rules = egress(&deny, None);
    assert_eq!(rules.len(), 4, "TCP and UDP, for each family: {rules:?}");
    assert!(rules.iter().all(|r| r.action == "drop" && r.enabled && r.destination_port.is_empty()));
    let v4 = &rules[0].destination;
    for c in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "203.0.113.5/32"] {
        assert!(v4.split(',').any(|d| d == c), "{c} in {v4}");
    }
    assert!(rules[2].destination.contains("fc00::/7") && !rules[2].destination.contains('.'));

    // botd on a private address: only its machine port is left open, over TCP.
    let control: IpAddr = "10.1.2.3".parse().unwrap();
    let rules = egress(&deny, Some((control, 8444)));
    let v4 = &rules[0].destination;
    assert!(!v4.split(',').any(|d| d == "10.0.0.0/8"));
    assert!(v4.split(',').any(|d| d == "10.0.0.0-10.1.2.2"), "{v4}");
    assert!(v4.split(',').any(|d| d == "10.1.2.4-10.255.255.255"), "{v4}");
    let port = rules.iter().find(|r| r.destination == "10.1.2.3" && r.protocol == "tcp").unwrap();
    assert_eq!(port.destination_port, "1-8443,8445-65535");
    assert!(rules.iter().any(|r| r.destination == "10.1.2.3" && r.protocol == "udp" && r.destination_port.is_empty()));

    // On a public address it was never denied, so nothing is carved.
    let public: IpAddr = "198.51.100.7".parse().unwrap();
    assert_eq!(egress(&deny, Some((public, 8444))), egress(&deny, None));

    // Ranges at either end of a block.
    assert_eq!(span("10.0.0.0/8"), Some((false, 0x0a00_0000, 0x0aff_ffff)));
    assert_eq!(span("fe80::/10").map(|s| s.0), Some(true));
    let edge = egress(&["10.0.0.0/8".into()], Some(("10.0.0.0".parse().unwrap(), 1)));
    assert_eq!(edge[0].destination, "10.0.0.1-10.255.255.255");
    assert_eq!(edge.iter().find(|r| !r.destination_port.is_empty()).unwrap().destination_port, "2-65535");
}

#[test]
fn settings_come_from_the_environment() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default()
    };
    assert!(Settings::from_env(&env(&[])).unwrap_err().contains("INCUS_URL"));
    let s = Settings::from_env(&env(&[
        ("INCUS_URL", "https://192.0.2.50"),
        ("MACHINE_CONTROL_URL", "https://10.9.8.7:8444"),
        ("INCUS_EGRESS_DENY", "198.51.100.0/24, 2001:db8::1"),
    ]))
    .unwrap();
    assert_eq!(s.url, "https://192.0.2.50:8443");
    assert_eq!((s.project.as_str(), s.network.as_str(), s.pool.as_str()), ("superbot", "incusbr0", "default"));
    assert_eq!(s.image_server.as_deref(), Some(DEFAULT_IMAGE_SERVER));
    for c in ["192.0.2.50/32", "198.51.100.0/24", "2001:db8::1/128", "10.0.0.0/8"] {
        assert!(s.deny.contains(&c.to_string()), "{c} denied: {:?}", s.deny);
    }
    assert_eq!(s.control, Some(("10.9.8.7".parse().unwrap(), 8444)));

    let local = Settings::from_env(&env(&[("INCUS_URL", "https://[2001:db8::50]:9443/"), ("INCUS_IMAGE_SERVER", "local")])).unwrap();
    assert_eq!(local.url, "https://[2001:db8::50]:9443");
    assert!(local.deny.contains(&"2001:db8::50/128".to_string()), "{:?}", local.deny);
    assert_eq!(local.image_server, None);
    assert_eq!(local.control, None);

    for (pairs, want) in [
        (&[("INCUS_URL", "https://incus.internal:8443")][..], "by IP address"),
        (&[("INCUS_URL", "http://192.0.2.50:8443")][..], "INCUS_URL"),
        (&[("INCUS_URL", "https://192.0.2.50:8443/1.0")][..], "INCUS_URL"),
        (&[("INCUS_URL", "https://user:pw@192.0.2.50")][..], "INCUS_URL"),
        (&[("INCUS_URL", "https://192.0.2.50"), ("INCUS_PROJECT", "default")][..], "default project"),
        (&[("INCUS_URL", "https://192.0.2.50"), ("INCUS_PROJECT", "Bad_Name")][..], "INCUS_PROJECT"),
        (&[("INCUS_URL", "https://192.0.2.50"), ("INCUS_EGRESS_DENY", "nope")][..], "INCUS_EGRESS_DENY"),
        (&[("INCUS_URL", "https://192.0.2.50"), ("INCUS_IMAGE_SERVER", "ftp://x")][..], "INCUS_IMAGE_SERVER"),
    ] {
        let pairs: &'static [(&'static str, &'static str)] = Box::leak(pairs.to_vec().into_boxed_slice());
        let e = Settings::from_env(&env(pairs)).unwrap_err();
        assert!(e.contains(want), "{pairs:?}: {e}");
    }
}

#[test]
fn credentials_come_from_the_secret_store_and_the_key_is_redacted() {
    let (cert, key) = self_signed("botd.test");
    let (server, _) = self_signed("incus.test");
    let store = crate::secrets::env::EnvStore::fixed(&[
        ("INCUS_CLIENT_CERT", &cert),
        ("INCUS_CLIENT_KEY", &key),
        ("INCUS_SERVER_CERT", &server),
    ]);
    Credentials::from_store(&store).unwrap();
    assert!(crate::secrets::redact::known().iter().any(|k| *k == key.trim()));
    let missing = crate::secrets::env::EnvStore::fixed(&[]);
    let e = Credentials::from_store(&missing).err().unwrap();
    assert!(e.contains("INCUS_CLIENT_KEY"), "{e}");
}

#[tokio::test]
async fn a_container_is_unprivileged_isolated_and_sized_by_its_plan() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    let m = p.create(&spec("superbot-m1", "c2-m4-d40")).await.unwrap();
    assert_eq!((m.id.as_str(), m.status.as_str(), m.plan.as_str(), m.region.as_str()), ("superbot-m1", "running", "c2-m4-d40", LOCAL));
    assert!(m.ipv4.as_deref().is_some_and(|ip| ip.starts_with("10.20.0.")), "{m:?}");
    assert_eq!(m.tags, ["superbot", "superbot-user-u1"]);
    assert!(!m.backups);

    let post = &s.calls("POST", "/1.0/instances")[0];
    assert!(post.query.contains("project=superbot"), "{}", post.query);
    assert!(!post.query.contains("target="), "no cluster member on a lone host");
    let b = &post.body;
    assert_eq!(b["type"], "container");
    assert_eq!(b["profiles"], json!([]), "no profile can add a device or loosen a setting");
    assert_eq!(b["source"]["alias"], DEFAULT_IMAGE);
    assert_eq!(b["source"]["protocol"], "simplestreams");
    let c = &b["config"];
    for (k, v) in [
        ("security.privileged", "false"),
        ("security.nesting", "false"),
        ("security.idmap.isolated", "true"),
        ("security.guestapi", "false"),
        ("limits.cpu", "2"),
        ("limits.memory", "4GiB"),
        ("limits.memory.enforce", "hard"),
        ("limits.processes", "4096"),
        ("user.superbot.tag", "superbot"),
    ] {
        assert_eq!(c[k], v, "{k}");
    }
    assert!(c.get("limits.memory.swap").is_none(), "a restricted project refuses it");
    assert!(c["cloud-init.user-data"].as_str().unwrap().starts_with("#cloud-config"));
    let vendor = c["cloud-init.vendor-data"].as_str().unwrap();
    assert!(vendor.contains("\"ssh-ed25519 AAAAC3Nza admin@example\"") && vendor.contains("disable_root: false"));
    let devices = b["devices"].as_object().unwrap();
    assert_eq!(devices.len(), 2, "a root disk and a NIC, nothing of the host's: {devices:?}");
    assert_eq!(b["devices"]["root"], json!({ "type": "disk", "path": "/", "pool": "default", "size": "40GiB" }));
    let nic = &b["devices"]["eth0"];
    for (k, v) in [
        ("network", "incusbr0"),
        ("security.port_isolation", "true"),
        ("security.mac_filtering", "true"),
        ("security.ipv4_filtering", "true"),
        ("security.ipv6_filtering", "true"),
        ("security.acls", "superbot-fw"),
        ("security.acls.default.ingress.action", "drop"),
        ("security.acls.default.egress.action", "allow"),
    ] {
        assert_eq!(nic[k], v, "{k}");
    }

    // The same label again is taken; listing finds it by tag, and only ours.
    assert!(matches!(p.create(&spec("superbot-m1", "c2-m4-d40")).await, Err(ProviderError::LabelTaken)));
    let listed = p.list("superbot").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(p.list("otherbot").await.unwrap().is_empty());
    assert!(matches!(p.get("superbot-m9").await, Err(ProviderError::NotFound)));

    // A cluster member is a region.
    let mut other = spec("superbot-m2", "c1-m2-d20");
    other.region = "node2".into();
    other.authorized_keys.clear();
    let m2 = p.create(&other).await.unwrap();
    assert_eq!(m2.region, "node2");
    let post = &s.calls("POST", "/1.0/instances")[2];
    assert!(post.query.contains("target=node2"));
    assert!(post.body["config"].get("cloud-init.vendor-data").is_none());
}

#[tokio::test]
async fn no_container_without_the_firewall_or_outside_a_restricted_project() {
    let s = StandIn::start().await;
    let p = incus(&s);
    let mut open = spec("superbot-m1", "c1-m2-d20");
    open.firewall_id = None;
    assert!(matches!(p.create(&open).await, Err(ProviderError::Api { status: 400, .. })));
    assert!(matches!(p.create(&spec("superbot-m1", "g6-standard-1")).await, Err(ProviderError::Api { status: 400, .. })));

    for (k, v, why) in [
        ("restricted", "false", "isn't restricted"),
        ("restricted.containers.privilege", "allow", "restricted.containers.privilege"),
        ("restricted.containers.nesting", "allow", "restricted.containers.nesting"),
        ("restricted.devices.disk", "allow", "restricted.devices.disk"),
        ("restricted.devices.disk.paths", "/srv", "host paths"),
        ("restricted.idmap.uid", "0", "host ids"),
    ] {
        s.w().projects.insert("superbot".into(), json!({ "restricted": "true", k: v }));
        match p.create(&spec("superbot-m1", "c1-m2-d20")).await {
            Err(ProviderError::Api { status: 409, message }) => assert!(message.contains(why), "{k}: {message}"),
            other => panic!("{k}={v}: {other:?}"),
        }
    }
    assert!(s.calls("POST", "/1.0/instances").is_empty(), "nothing was asked for");
    let checks = p.preflight().await.unwrap();
    let project = checks.iter().find(|c| c["check"] == "project").unwrap();
    assert_eq!(project["ok"], false);
}

#[tokio::test]
async fn suspend_resume_resize_backups_rebuild_and_delete() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();

    p.shutdown("superbot-m1").await.unwrap();
    let m = p.get("superbot-m1").await.unwrap();
    assert_eq!(m.status, "stopped");
    assert_eq!(m.ipv4, None);
    let stop = &s.calls("PUT", "/1.0/instances/superbot-m1/state")[0];
    assert_eq!((stop.body["action"].as_str(), stop.body["force"].as_bool()), (Some("stop"), Some(false)), "cleanly first");
    p.shutdown("superbot-m1").await.unwrap();
    assert_eq!(s.calls("PUT", "/1.0/instances/superbot-m1/state").len(), 1, "already stopped asks nothing");

    p.boot("superbot-m1").await.unwrap();
    assert_eq!(p.get("superbot-m1").await.unwrap().status, "running");

    p.resize("superbot-m1", "c4-m8-d80").await.unwrap();
    let i = s.instance("superbot-m1").unwrap();
    assert_eq!(i.body["config"]["limits.cpu"], "4");
    assert_eq!(i.body["config"]["limits.memory"], "8GiB");
    assert_eq!(i.body["config"]["limits.processes"], "8192");
    assert_eq!(i.body["devices"]["root"]["size"], "80GiB");
    assert_eq!(i.body["devices"]["eth0"]["security.acls"], "superbot-fw", "the rest is kept");
    assert_eq!(p.get("superbot-m1").await.unwrap().plan, "c4-m8-d80");
    let edit = s.calls("PUT", "/1.0/instances/superbot-m1").into_iter().find(|c| c.path == "/1.0/instances/superbot-m1").unwrap();
    assert!(edit.body["config"]["security.privileged"] == "false", "edits send the whole config back");

    p.enable_backups("superbot-m1").await.unwrap();
    let c = &s.instance("superbot-m1").unwrap().body["config"];
    assert_eq!((c["snapshots.schedule"].as_str(), c["snapshots.expiry"].as_str()), (Some("@daily"), Some("7d")));
    assert!(p.get("superbot-m1").await.unwrap().backups);

    let rb = RebuildSpec {
        image: "ubuntu/26.04/cloud".into(),
        authorized_keys: Vec::new(),
        user_data: "#cloud-config\n# again\n".into(),
    };
    p.rebuild("superbot-m1", &rb).await.unwrap();
    let i = s.instance("superbot-m1").unwrap();
    assert_eq!((i.rebuilt, i.status.as_str()), (1, "Running"), "rebuilt and started again");
    assert_eq!(i.source["alias"], "ubuntu/26.04/cloud");
    assert_eq!(i.body["config"]["cloud-init.user-data"], rb.user_data);
    assert!(i.body["config"].get("cloud-init.vendor-data").is_none(), "no keys, none left behind");

    p.delete("superbot-m1").await.unwrap();
    assert!(s.instance("superbot-m1").is_none());
    p.delete("superbot-m1").await.unwrap();
    assert!(matches!(p.get("superbot-m1").await, Err(ProviderError::NotFound)));
}

#[tokio::test]
async fn a_slow_rebuild_is_left_stopped_and_starts_only_once_incus_is_done() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();
    s.w().hold_rebuilds = true;
    let rb = RebuildSpec { image: "ubuntu/26.04/cloud".into(), authorized_keys: Vec::new(), user_data: "#cloud-config\n".into() };
    match p.rebuild("superbot-m1", &rb).await {
        Err(ProviderError::Transport(m)) => assert!(m.contains("still rebuilding"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.instance("superbot-m1").unwrap().status, "Stopped", "nothing starts it behind the control plane");
    match p.boot("superbot-m1").await {
        Err(ProviderError::Transport(m)) => assert!(m.contains("still working"), "{m}"),
        other => panic!("not started mid-rebuild: {other:?}"),
    }
    assert!(s.calls("PUT", "/1.0/instances/superbot-m1/state").iter().all(|c| c.body["action"] != "start"));
    s.release();
    p.boot("superbot-m1").await.unwrap();
    let i = s.instance("superbot-m1").unwrap();
    assert_eq!((i.status.as_str(), i.rebuilt), ("Running", 1));
    assert_eq!(i.source["alias"], "ubuntu/26.04/cloud");
}

fn edits(s: &StandIn, n: &str) -> Vec<crate::machines::incus_standin::Call> {
    let path = format!("/1.0/instances/{n}");
    s.calls("PUT", &path).into_iter().filter(|c| c.path == path).collect()
}

#[tokio::test]
async fn spent_user_data_is_cleared_in_place_and_nothing_else_changes() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    assert!(p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap().user_data, "made with it");
    let before = s.instance("superbot-m1").unwrap();
    assert_eq!((before.status.as_str(), before.boots), ("Running", 1));

    p.clear_user_data("superbot-m1").await.unwrap();
    let after = s.instance("superbot-m1").unwrap();
    assert!(after.body["config"].get(USER_DATA).is_none(), "{:?}", after.body["config"]);
    let mut want = before.body.clone();
    want["config"].as_object_mut().unwrap().remove(USER_DATA);
    assert_eq!(after.body, want, "everything else is as it was, the SSH keys' vendor data too");
    assert_eq!((after.status.as_str(), after.boots), ("Running", 1), "not restarted");
    assert!(s.calls("PUT", "/1.0/instances/superbot-m1/state").is_empty(), "never stopped or started");
    let put = edits(&s, "superbot-m1");
    assert_eq!(put.len(), 1);
    assert!(put[0].if_match.as_deref().is_some_and(|e| e.starts_with('"')), "sent with the ETag it read: {:?}", put[0].if_match);
    assert!(!p.get("superbot-m1").await.unwrap().user_data);
    assert!(!p.list("superbot").await.unwrap()[0].user_data);

    // Again, or on a container that's gone, it's done already.
    p.clear_user_data("superbot-m1").await.unwrap();
    assert_eq!(s.instance("superbot-m1").unwrap().body, want);
    p.clear_user_data("superbot-m9").await.unwrap();

    // A stopped one stays stopped; a rebuild brings fresh user data, cleared in turn.
    p.shutdown("superbot-m1").await.unwrap();
    let rb = RebuildSpec { image: DEFAULT_IMAGE.into(), authorized_keys: Vec::new(), user_data: "#cloud-config\n# again\n".into() };
    p.rebuild("superbot-m1", &rb).await.unwrap();
    assert!(p.get("superbot-m1").await.unwrap().user_data);
    p.shutdown("superbot-m1").await.unwrap();
    p.clear_user_data("superbot-m1").await.unwrap();
    let i = s.instance("superbot-m1").unwrap();
    assert_eq!((i.status.as_str(), i.body["config"].get(USER_DATA)), ("Stopped", None));
}

#[tokio::test]
async fn a_change_made_meanwhile_is_kept_not_overwritten() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();

    s.w().races = 1;
    p.clear_user_data("superbot-m1").await.unwrap();
    let c = s.instance("superbot-m1").unwrap().body["config"].clone();
    assert_eq!((c.get(USER_DATA), c["user.other-client"].as_str()), (None, Some("change 1")), "read again and kept: {c}");
    let put = edits(&s, "superbot-m1");
    assert_eq!(put.len(), 2, "the first was refused (412)");
    assert_ne!(put[0].if_match, put[1].if_match);

    // One that keeps changing is left for the reconciler, untouched.
    p.create(&spec("superbot-m2", "c1-m2-d20")).await.unwrap();
    s.w().races = 3;
    match p.clear_user_data("superbot-m2").await {
        Err(ProviderError::Transport(m)) => assert!(m.contains("kept changing"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(p.get("superbot-m2").await.unwrap().user_data);
}

#[tokio::test]
async fn the_stand_in_puts_and_patches_instances_as_incus_does() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();
    let path = "/1.0/instances/superbot-m1";
    let r = p.call(Method::GET, path, &[], None, None).await.unwrap();
    let tag = r.etag.clone().unwrap();

    // PATCH merges; an empty value unsets; a stale ETag is refused.
    let patch = json!({ "config": { "user.a": "1", "cloud-init.vendor-data": "" } });
    p.call(Method::PATCH, path, &[], Some(&patch), Some(&tag)).await.unwrap();
    let c = s.instance("superbot-m1").unwrap().body["config"].clone();
    assert_eq!((c["user.a"].as_str(), c.get("cloud-init.vendor-data")), (Some("1"), None));
    assert_eq!(c["limits.cpu"], "1", "the rest is kept");
    assert!(matches!(
        p.call(Method::PATCH, path, &[], Some(&patch), Some(&tag)).await,
        Err(ProviderError::Api { status: 412, .. })
    ));
    let nested = json!({ "config": { "security.nesting": "true" } });
    assert!(matches!(p.call(Method::PATCH, path, &[], Some(&nested), None).await, Err(ProviderError::Api { status: 400, .. })));

    // PUT replaces the writable fields: a key left out is gone, read-only ones ignored.
    let r = p.call(Method::GET, path, &[], None, None).await.unwrap();
    let mut put = r.metadata.clone();
    put["config"].as_object_mut().unwrap().remove("user.a");
    put["status"] = json!("Frozen");
    let op = p.call(Method::PUT, path, &[], Some(&put), r.etag.as_deref()).await.unwrap();
    p.finish(op, 5, "changing it").await.unwrap();
    let i = s.instance("superbot-m1").unwrap();
    assert!(i.body["config"].get("user.a").is_none());
    assert!(i.body.get("status").is_none() && i.body.get("name").is_none(), "{}", i.body);
    assert_eq!((i.status.as_str(), i.boots), ("Running", 1), "edits never restart it");
}

#[tokio::test]
async fn a_create_still_running_is_provisioning_and_a_failed_one_is_a_refusal() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    s.w().hold_creates = true;
    let m = p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();
    assert_eq!((m.id.as_str(), m.status.as_str()), ("superbot-m1", "provisioning"));
    assert_eq!(p.get("superbot-m1").await.unwrap().status, "provisioning", "not gone while it downloads");
    match p.delete("superbot-m1").await {
        Err(ProviderError::Transport(m)) => assert!(m.contains("still creating"), "not deleted while it may still appear: {m}"),
        other => panic!("{other:?}"),
    }
    s.release();
    assert_eq!(p.get("superbot-m1").await.unwrap().status, "running");
    p.delete("superbot-m1").await.unwrap();
    assert!(s.instance("superbot-m1").is_none(), "deleted once made");
    s.w().hold_creates = false;

    s.w().fail_op = Some("Failed getting remote image info: not found".into());
    match p.create(&spec("superbot-m2", "c1-m2-d20")).await {
        Err(ProviderError::Api { status: 400, message }) => assert!(message.contains("remote image"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(p.get("superbot-m2").await, Err(ProviderError::NotFound)));
}

#[tokio::test]
async fn the_firewall_is_a_network_acl() {
    let s = StandIn::start().await;
    let control: IpAddr = "10.1.2.3".parse().unwrap();
    let p = Incus::new(s.settings(Some((control, 8444))), s.credentials()).unwrap();
    assert!(p.find_firewall("superbot-fw").await.unwrap().is_none());
    let rules = vec![agent_rule()];
    let fw = p.create_firewall("superbot-fw", &["superbot".into()], &rules).await.unwrap();
    assert_eq!((fw.id.as_str(), fw.label.as_str(), fw.enabled), ("superbot-fw", "superbot-fw", true));
    assert_eq!(fw.rules.as_deref(), Some(&rules[..]), "read back as written");
    assert!(matches!(
        p.create_firewall("superbot-fw", &[], &rules).await,
        Err(ProviderError::LabelTaken)
    ));
    let acl = s.w().acls["superbot-fw"].clone();
    assert_eq!(acl["config"]["user.superbot.tag"], "superbot");
    let ingress_rules = acl["ingress"].as_array().unwrap();
    assert_eq!(ingress_rules.len(), 2, "one per address family");
    assert_eq!(ingress_rules[0]["source"], "192.0.2.10/32");
    assert_eq!(ingress_rules[0]["destination_port"], "8445");
    assert_eq!(ingress_rules[1]["source"], "2001:db8::10/128");
    let egress_rules = acl["egress"].as_array().unwrap();
    assert!(egress_rules.iter().all(|r| r["action"] == "drop"));
    assert!(egress_rules.iter().any(|r| r["destination"] == "10.1.2.3" && r["destination_port"] == "1-8443,8445-65535"));

    // Someone loosens the outbound rules at Incus: not ours any more, so it's set back.
    s.w().acls.get_mut("superbot-fw").unwrap()["egress"] = json!([]);
    assert_eq!(p.get_firewall("superbot-fw").await.unwrap().rules, None);
    p.set_firewall_rules("superbot-fw", &rules).await.unwrap();
    assert_eq!(p.get_firewall("superbot-fw").await.unwrap().rules.as_deref(), Some(&rules[..]));
    assert_eq!(s.w().acls["superbot-fw"]["egress"].as_array().unwrap().len(), egress_rules.len());

    // Or turns a rule off: still our rules, but not enabled until turned back on.
    s.w().acls.get_mut("superbot-fw").unwrap()["egress"][0]["state"] = json!("disabled");
    let off = p.get_firewall("superbot-fw").await.unwrap();
    assert!(!off.enabled);
    p.enable_firewall("superbot-fw").await.unwrap();
    assert!(p.get_firewall("superbot-fw").await.unwrap().enabled);

    // Machines behind it are those whose NIC names it.
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();
    let mut bare = spec("superbot-m2", "c1-m2-d20");
    bare.firewall_id = Some("superbot-fw".into());
    p.create(&bare).await.unwrap();
    s.w().instances.get_mut("superbot-m2").unwrap().body["devices"]["eth0"] = json!({ "type": "nic", "network": "incusbr0" });
    assert_eq!(p.firewall_devices("superbot-fw").await.unwrap().machines, ["superbot-m1"]);
    p.attach_firewall("superbot-fw", "superbot-m2").await.unwrap();
    let nic = s.instance("superbot-m2").unwrap().body["devices"]["eth0"].clone();
    assert_eq!(nic["security.acls"], "superbot-fw");
    assert_eq!(nic["security.port_isolation"], "true", "attaching restores the whole isolated NIC");
    let mut on = p.firewall_devices("superbot-fw").await.unwrap().machines;
    on.sort();
    assert_eq!(on, ["superbot-m1", "superbot-m2"]);

    // Still naming the ACL isn't enough: a NIC loosened in place, a second NIC, or a
    // profile means it's attached again.
    type Drift = fn(&mut Value);
    let drifts: [(&str, Drift); 4] = [
        ("open by default", |b| b["devices"]["eth0"]["security.acls.default.ingress.action"] = json!("allow")),
        ("no port isolation", |b| b["devices"]["eth0"]["security.port_isolation"] = json!("false")),
        ("a second NIC", |b| b["devices"]["eth1"] = json!({ "type": "nic", "network": "incusbr0" })),
        ("a profile", |b| b["profiles"] = json!(["default"])),
    ];
    for (what, drift) in drifts {
        drift(&mut s.w().instances.get_mut("superbot-m2").unwrap().body);
        let d = p.firewall_devices("superbot-fw").await.unwrap();
        assert_eq!((d.machines.as_slice(), d.others), (&["superbot-m1".to_string()][..], 1), "{what}");
        p.attach_firewall("superbot-fw", "superbot-m2").await.unwrap();
        let b = s.instance("superbot-m2").unwrap().body;
        assert_eq!(b["devices"]["eth0"], p.nic("superbot-fw"), "{what}");
        assert!(b["devices"].get("eth1").is_none() && b["profiles"] == json!([]), "{what}");
        assert_eq!(p.firewall_devices("superbot-fw").await.unwrap().machines.len(), 2, "{what}");
    }

    assert!(p.delete_firewall("superbot-fw").await.is_err(), "Incus keeps an ACL in use");
    p.delete("superbot-m1").await.unwrap();
    p.detach_firewall("superbot-fw", "superbot-m1").await.unwrap();
    p.detach_firewall("superbot-fw", "superbot-m2").await.unwrap();
    assert_eq!(s.instance("superbot-m2").unwrap().body["devices"]["eth0"]["security.acls"], "");
    assert_eq!(p.firewall_devices("superbot-fw").await.unwrap(), FirewallDevices::default());
    p.delete_firewall("superbot-fw").await.unwrap();
    p.delete_firewall("superbot-fw").await.unwrap();
    assert!(p.find_firewall("superbot-fw").await.unwrap().is_none());
}

#[tokio::test]
async fn only_the_pinned_host_and_a_trusted_certificate() {
    let s = StandIn::start().await;
    let ok = incus(&s);
    let checks = ok.preflight().await.unwrap();
    assert!(checks.iter().all(|c| c["ok"] == true), "{checks:?}");

    // An Incus too old for ACLs on a bridged NIC, such as Ubuntu 24.04's 6.0.0, is named.
    s.w().missing_extensions = vec!["network_bridge_acl_devices".into()];
    let checks = ok.preflight().await.unwrap();
    assert_eq!(checks[0]["ok"], false);
    assert!(checks[0]["detail"].as_str().unwrap().contains("lacks API extensions: network_bridge_acl_devices"), "{checks:?}");
    s.w().missing_extensions.clear();

    // Every 6.0 LTS release breaks ACL updates for containers in a restricted project.
    s.w().version = Some("6.0.7".into());
    let checks = ok.preflight().await.unwrap();
    assert_eq!(checks[0]["ok"], false);
    assert!(checks[0]["detail"].as_str().unwrap().contains("Incus 6.0.7 is too old: botd needs 7.0.1"), "{checks:?}");
    s.w().version = Some("7.0.1".into());
    assert_eq!(ok.preflight().await.unwrap()[0]["ok"], true);
    s.w().version = None;

    // Another server certificate: botd won't talk to it.
    let (other, _) = self_signed("incus.test");
    let mut c = s.credentials();
    c.server = pki::cert_der(&other).unwrap();
    let wrong_host = Incus::new(s.settings(None), c).unwrap();
    assert!(matches!(wrong_host.list("superbot").await, Err(ProviderError::Transport(_))));

    // A client certificate Incus doesn't trust gets nothing.
    let (cert, key) = self_signed("stranger.test");
    let mut c = s.credentials();
    c.cert = pki::cert_der(&cert).unwrap();
    c.key = pki::key_der(&key).unwrap();
    let stranger = Incus::new(s.settings(None), c).unwrap();
    match stranger.list("superbot").await {
        Err(ProviderError::Api { status: 403, .. }) => {}
        other => panic!("{other:?}"),
    }
    let checks = stranger.preflight().await.unwrap();
    assert_eq!(checks[0]["ok"], false);

    // A pool that can't hold a container to its disk size is flagged.
    let mut plain = s.settings(None);
    plain.pool = "plain".into();
    let checks = Incus::new(plain, s.credentials()).unwrap().preflight().await.unwrap();
    let pool = checks.iter().find(|c| c["check"] == "storage pool").unwrap();
    assert_eq!(pool["ok"], false);
    assert!(pool["detail"].as_str().unwrap().contains("doesn't enforce disk sizes"), "{pool}");

    // Nothing secret in what admins or logs see.
    let shown = format!("{ok:?} {}", ok.settings());
    assert!(!shown.contains("PRIVATE KEY") && !shown.contains(&s.key_pem));
    assert!(shown.contains(&pki::fingerprint(&pki::cert_der(&s.server_pem).unwrap())));
}

#[test]
fn incus_answers_are_read_as_ours() {
    let e = |code: u16, msg: &str| error(StatusCode::from_u16(code).unwrap(), &json!({ "type": "error", "error": msg, "error_code": code }));
    assert!(matches!(e(404, "Instance not found"), ProviderError::NotFound));
    assert!(matches!(e(500, "Instance \"superbot-m1\" already exists"), ProviderError::LabelTaken));
    assert!(matches!(e(400, "The network ACL already exists"), ProviderError::LabelTaken));
    assert!(matches!(e(429, "slow down"), ProviderError::RateLimited));
    assert!(matches!(e(403, "not authorized"), ProviderError::Api { status: 403, .. }));
    assert!(operation_id("/1.0/operations/../../instances").is_err());
    assert_eq!(operation_id("/1.0/operations/00000000-0000-4000-8000-000000000001").unwrap(), "00000000-0000-4000-8000-000000000001");
    assert_eq!(instance_of("/1.0/instances/superbot-m1?project=superbot"), Some(("superbot-m1".into(), "superbot".into())));
    assert_eq!(instance_of("/1.0/instances/c1"), Some(("c1".into(), "default".into())));
    assert_eq!(instance_of("/1.0/profiles/default"), None);
    for bad in ["", "Superbot", "1abc", "a-", "a/b", "a..b", &"a".repeat(64)] {
        assert!(name(bad).is_err(), "{bad}");
    }
    assert!(name("superbot-m1a2b3c4d").is_ok());
}

#[test]
fn incus_before_7_0_1_is_too_old() {
    for v in ["6.0.0", "6.0.7", "6.9", "7.0", "7.0.0"] {
        assert!(too_old(v), "{v}");
    }
    for v in ["7.0.1", "7.0.2", "7.1", "7.6", "10.0", "standin", "7.1-rc1", "?"] {
        assert!(!too_old(v), "{v}");
    }
}

#[tokio::test]
async fn no_container_on_an_incus_too_old_or_missing_extensions() {
    let s = StandIn::start().await;
    let p = incus(&s);
    p.create_firewall("superbot-fw", &["superbot".into()], &[agent_rule()]).await.unwrap();
    s.w().version = Some("6.0.7".into());
    match p.create(&spec("superbot-m1", "c1-m2-d20")).await {
        Err(ProviderError::Api { status: 400, message }) => assert!(message.contains("botd needs 7.0.1"), "{message}"),
        other => panic!("{other:?}"),
    }
    s.w().version = None;
    s.w().missing_extensions = vec!["network_bridge_acl_devices".into()];
    match p.create(&spec("superbot-m1", "c1-m2-d20")).await {
        Err(ProviderError::Api { status: 400, message }) => assert!(message.contains("network_bridge_acl_devices"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(s.calls("POST", "/1.0/instances").is_empty(), "nothing was asked for");
    s.w().missing_extensions.clear();
    p.create(&spec("superbot-m1", "c1-m2-d20")).await.unwrap();
}
