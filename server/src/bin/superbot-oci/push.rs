//! `superbot-oci push`: one or more bundles' images, their signed index when they make it up,
//! and their signatures and attestations, into a registry mirror.

use crate::fetch::{fallback_tag, parse};
use crate::layout::{Layout, REF_NAME, ROLE};
use crate::registry::{Client, OCI_INDEX, Repo, blobs_of, is_index, media_type};
use crate::{config::Settings, sha256_digest};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

struct Unit {
    dir: PathBuf,
    image: Layout,
    digest: String,
    bytes: Vec<u8>,
    platform: String,
    signatures: Option<Layout>,
}

/// A manifest we can push, and the layout that holds its blobs.
struct Source<'a> {
    bytes: Vec<u8>,
    manifest: Value,
    media_type: String,
    layout: &'a Layout,
}

fn platform_of(image: &Layout, m: &Value) -> String {
    let config = m["config"]["digest"].as_str().and_then(|d| image.read(d).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or_default();
    let mut p = format!("{}/{}", config["os"].as_str().unwrap_or("?"), config["architecture"].as_str().unwrap_or("?"));
    if let Some(v) = config["variant"].as_str() {
        p += &format!("/{v}");
    }
    p
}

fn platform_label(e: &Value) -> String {
    let p = &e["platform"];
    match (p["os"].as_str(), p["architecture"].as_str()) {
        (Some("unknown"), _) | (None, _) => format!("an attestation ({})", e["digest"].as_str().unwrap_or_default()),
        (Some(os), Some(arch)) => format!("{os}/{arch}{}", p["variant"].as_str().map(|v| format!("/{v}")).unwrap_or_default()),
        _ => e["digest"].as_str().unwrap_or_default().to_string(),
    }
}

fn load(dir: &Path) -> Result<Unit, String> {
    let image = Layout::open(&dir.join("image"))?;
    let [entry] = image.entries.as_slice() else {
        return Err(format!("{}/image holds {} manifests, not one image", dir.display(), image.entries.len()));
    };
    let digest = Layout::digest(entry).to_string();
    let bytes = image.read(&digest)?;
    let m = parse(&digest, &bytes)?;
    if is_index(&m) {
        return Err(format!("{}/image holds an index, not one image", dir.display()));
    }
    let platform = platform_of(&image, &m);
    let signatures = if dir.join("signatures").exists() { Some(Layout::open(&dir.join("signatures"))?) } else { None };
    Ok(Unit { dir: dir.to_path_buf(), image, digest, bytes, platform, signatures })
}

fn index_of(u: &Unit) -> Option<&Value> {
    u.signatures.as_ref()?.entries.iter().find(|e| Layout::role(e) == "index")
}

/// A descriptor as a referrers list holds it: without our annotations.
fn listed(e: &Value) -> Value {
    let mut d = e.clone();
    if let Some(a) = d["annotations"].as_object_mut() {
        a.remove(ROLE);
        a.remove(REF_NAME);
        if a.is_empty() {
            d.as_object_mut().expect("a descriptor").remove("annotations");
        }
    }
    d
}

async fn push_manifest(c: &Client, reference: &str, s: &Source<'_>) -> Result<crate::registry::Put, String> {
    for b in blobs_of(&s.manifest)? {
        c.push_blob(&b, &s.layout.path(&b)?).await?;
    }
    c.put_manifest(reference, &s.bytes, &s.media_type).await
}

/// With CHECK, only what can be checked here: the digest the tag would name, with no network.
/// Cosign's `.sig` and `.att` tags hold one signature or attestation per layer, and cosign adds a
/// layer when it signs again, so copies of one differ when signatures were added between them.
/// The tag gets every layer the bundles' copies and the mirror's hold. Other cosign tags (`.sbom`)
/// hold one thing: the first bundle's copy goes up. Says whether it pushed anything.
async fn push_cosign_tag(c: &Client, t: &str, copies: Vec<Source<'_>>) -> Result<bool, String> {
    let first = &copies[0];
    if !(t.ends_with(".sig") || t.ends_with(".att")) {
        push_manifest(c, t, first).await?;
        return Ok(true);
    }
    let mut parts: Vec<(Value, Vec<u8>, Option<&Layout>)> = Vec::new();
    if let Some(b) = c.manifest(t).await?
        && let Ok(m) = parse(t, &b)
        && m["layers"].is_array()
        && let Some(cd) = m["config"]["digest"].as_str()
    {
        let cfg = c.blob_bytes(cd, MAX_CONFIG).await?;
        parts.push((m, cfg, None));
    }
    for s in &copies {
        let cd = s.manifest["config"]["digest"].as_str().ok_or(format!("{t} has no config"))?;
        parts.push((s.manifest.clone(), s.layout.read(cd)?, Some(s.layout)));
    }
    let (manifest, config, from) = merge_cosign_tag(&parts)?;
    // A copy that already has every layer goes up as it is; the mirror's is left alone.
    let layers = manifest["layers"].as_array().map_or(0, Vec::len);
    if let Some((_, _, layout)) = parts.iter().find(|(m, _, _)| m["layers"].as_array().map_or(0, Vec::len) == layers) {
        let Some(layout) = layout else { return Ok(false) };
        let s = copies.iter().find(|s| std::ptr::eq(s.layout, *layout)).expect("a copy for each layout");
        push_manifest(c, t, s).await?;
        return Ok(true);
    }
    c.push_bytes(&sha256_digest(&config), &config).await?;
    for (l, i) in manifest["layers"].as_array().into_iter().flatten().zip(from) {
        if let (Some(d), Some(layout)) = (l["digest"].as_str(), parts[i].2) {
            c.push_blob(d, &layout.path(d)?).await?;
        }
    }
    let bytes = serde_json::to_vec(&manifest).expect("json");
    c.put_manifest(t, &bytes, &first.media_type).await?;
    Ok(true)
}

const MAX_CONFIG: usize = 1 << 20;

/// Copies of one cosign tag (manifest, config bytes) as one: every layer any of them has, by
/// digest, in the order first seen, with the config's `rootfs.diff_ids` and `history` kept in step
/// when they list one entry per layer. Says which copy each layer came from.
pub fn merge_cosign_tag<T>(parts: &[(Value, Vec<u8>, T)]) -> Result<(Value, Vec<u8>, Vec<usize>), String> {
    let configs = parts.iter().map(|(_, c, _)| serde_json::from_slice::<Value>(c).map_err(|e| format!("a cosign tag's config: {e}"))).collect::<Result<Vec<_>, _>>()?;
    let (mut layers, mut from, mut diff_ids, mut history) = (Vec::<Value>::new(), Vec::new(), Vec::new(), Vec::new());
    let mut per_layer = true;
    for (i, ((m, _, _), cfg)) in parts.iter().zip(&configs).enumerate() {
        let ls = m["layers"].as_array().cloned().unwrap_or_default();
        let ids = cfg["rootfs"]["diff_ids"].as_array().filter(|d| d.len() == ls.len());
        let hs = cfg["history"].as_array().filter(|h| h.len() == ls.len());
        per_layer &= ids.is_some();
        for (j, l) in ls.iter().enumerate() {
            if layers.iter().any(|x| x["digest"] == l["digest"]) {
                continue;
            }
            layers.push(l.clone());
            from.push(i);
            diff_ids.push(ids.and_then(|d| d.get(j)).cloned().unwrap_or(Value::Null));
            history.push(hs.and_then(|h| h.get(j)).cloned());
        }
    }
    let config = if per_layer {
        let mut cfg = configs[0].clone();
        cfg["rootfs"]["diff_ids"] = json!(diff_ids);
        if cfg.get("history").is_some() && history.iter().all(Option::is_some) {
            cfg["history"] = json!(history);
        }
        serde_json::to_vec(&cfg).expect("json")
    } else {
        parts[0].1.clone()
    };
    let mut m = parts[0].0.clone();
    m["layers"] = json!(layers);
    m["config"]["digest"] = json!(sha256_digest(&config));
    m["config"]["size"] = json!(config.len());
    Ok((m, config, from))
}

pub async fn push(settings: &Settings, repo: &Repo, tag: &str, dirs: &[PathBuf], check: bool) -> Result<String, String> {
    let units = dirs.iter().map(|d| load(d)).collect::<Result<Vec<_>, _>>()?;
    let mut images = HashSet::new();
    for u in &units {
        if !images.insert(u.digest.as_str()) {
            return Err(format!("Two of these hold the same image ({}, {}): give one bundle per arch", u.digest, u.platform));
        }
    }
    let mut sources: BTreeMap<String, Source> = BTreeMap::new();
    for u in &units {
        let manifest = parse(&u.digest, &u.bytes)?;
        let mt = u.image.entries[0]["mediaType"].as_str().unwrap_or(media_type(&manifest)).to_string();
        sources.insert(u.digest.clone(), Source { bytes: u.bytes.clone(), manifest, media_type: mt, layout: &u.image });
        for e in u.signatures.iter().flat_map(|s| s.entries.iter().map(move |e| (s, e))).filter(|(_, e)| matches!(Layout::role(e), "index" | "attestation" | "referrer")) {
            let (s, e) = e;
            let d = Layout::digest(e).to_string();
            let bytes = s.read(&d)?;
            let manifest = parse(&d, &bytes)?;
            let mt = e["mediaType"].as_str().unwrap_or(media_type(&manifest)).to_string();
            sources.entry(d).or_insert(Source { bytes, manifest, media_type: mt, layout: s });
        }
    }

    // The signed index, when the units make it up.
    let indexes: BTreeSet<&str> = units.iter().filter_map(index_of).map(Layout::digest).collect();
    if units.len() > 1 {
        if let Some(u) = units.iter().find(|u| index_of(u).is_none()) {
            return Err(format!(
                "{} ({}) has no signed multi-arch index with it (an unsigned image, or a bundle made before ADR 0147), so these can't make one: push each bundle to its own path",
                u.dir.display(),
                u.platform
            ));
        }
        if indexes.len() > 1 {
            return Err(format!("These images come from different multi-arch indexes ({}): give bundles of one release, one per arch", indexes.into_iter().collect::<Vec<_>>().join(", ")));
        }
    }
    let index = match indexes.into_iter().collect::<Vec<_>>().as_slice() {
        [one] => Some(one.to_string()),
        _ => None,
    };
    let entries: Vec<Value> = index.as_ref().map(|d| sources[d].manifest["manifests"].as_array().cloned().unwrap_or_default()).unwrap_or_default();
    let missing: Vec<String> = entries.iter().filter(|e| !e["digest"].as_str().is_some_and(|d| sources.contains_key(d))).map(platform_label).collect();
    let whole = index.is_some() && missing.is_empty();
    if units.len() > 1 && !whole {
        return Err(format!(
            "The signed index {} also lists {}, which none of these bundles holds: add the bundles for those arches, or push each bundle to its own path",
            index.unwrap_or_default(),
            missing.join(", ")
        ));
    }
    for u in &units {
        if whole && !entries.iter().any(|e| e["digest"] == u.digest.as_str()) {
            return Err(format!("{} ({}) isn't in the signed index {}", u.dir.display(), u.platform, index.clone().unwrap_or_default()));
        }
    }
    if check {
        return Ok(if whole { index.expect("whole needs an index") } else { units[0].digest.clone() });
    }

    let c = Client::new(settings, repo, true).await?;
    let mut pushed: HashSet<String> = HashSet::new();
    let mut platforms = Vec::new();
    for u in &units {
        push_manifest(&c, &u.digest, &sources[&u.digest]).await?;
        pushed.insert(u.digest.clone());
        platforms.push(u.platform.clone());
    }
    // Each image's own SBOM and provenance manifests, with the index or without it.
    for e in units.iter().filter_map(|u| u.signatures.as_ref()).flat_map(|s| s.entries.iter()).filter(|e| Layout::role(e) == "attestation") {
        let d = Layout::digest(e);
        if pushed.insert(d.to_string()) {
            push_manifest(&c, d, &sources[d]).await?;
        }
    }
    let top = if whole {
        let index = index.expect("whole needs an index");
        for e in &entries {
            let d = Layout::digest(e);
            if !pushed.contains(d) {
                push_manifest(&c, d, &sources[d]).await?;
                pushed.insert(d.to_string());
            }
        }
        push_manifest(&c, &index, &sources[&index]).await?;
        pushed.insert(index.clone());
        index
    } else {
        if index.is_some() {
            eprintln!("{repo}:{tag} will name the {} image alone: push the other arches' bundles with this one for the signed multi-arch index", units[0].platform);
        }
        units[0].digest.clone()
    };

    // Signatures and attestations: each once its subject is there, so referrers of referrers follow.
    let mut referrers: Vec<&Value> = Vec::new();
    for e in units.iter().filter_map(|u| u.signatures.as_ref()).flat_map(|s| s.entries.iter()).filter(|e| Layout::role(e) == "referrer") {
        if !referrers.iter().any(|r| r["digest"] == e["digest"]) {
            referrers.push(e);
        }
    }
    let mut unlisted: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut copied = 0;
    loop {
        let ready: Vec<&Value> = referrers
            .iter()
            .copied()
            .filter(|e| !pushed.contains(Layout::digest(e)) && sources[Layout::digest(e)].manifest["subject"]["digest"].as_str().is_some_and(|s| pushed.contains(s)))
            .collect();
        if ready.is_empty() {
            break;
        }
        for e in ready {
            let d = Layout::digest(e);
            let s = &sources[d];
            let put = push_manifest(&c, d, s).await?;
            pushed.insert(d.to_string());
            copied += 1;
            if !put.indexed_subject {
                unlisted.entry(s.manifest["subject"]["digest"].as_str().unwrap_or_default().to_string()).or_default().push(listed(e));
            }
        }
    }
    // A registry without the referrers API: list them under the subject's fallback tag, keeping
    // what is there already.
    for (subject, add) in unlisted {
        let t = fallback_tag(&subject);
        let mut list: Vec<Value> = match c.manifest(&t).await? {
            Some(b) => parse(&t, &b)?["manifests"].as_array().cloned().unwrap_or_default(),
            None => Vec::new(),
        };
        for d in add {
            if !list.iter().any(|l| l["digest"] == d["digest"]) {
                list.push(d);
            }
        }
        let bytes = serde_json::to_vec(&json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": list })).expect("json");
        c.put_manifest(&t, &bytes, OCI_INDEX).await?;
    }
    // Cosign's tags: each bundle has its own copy, and the mirror may have one already.
    let mut cosign_tags: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    for u in &units {
        let Some(s) = &u.signatures else { continue };
        for e in s.entries.iter().filter(|e| Layout::role(e) == "tag") {
            let t = e["annotations"][REF_NAME].as_str().unwrap_or_default();
            let subject = t.split_once('.').map(|(d, _)| d.replacen('-', ":", 1)).unwrap_or_default();
            if !pushed.contains(&subject) || !t.starts_with("sha256-") {
                continue;
            }
            let d = Layout::digest(e);
            let bytes = s.read(d)?;
            let manifest = parse(t, &bytes)?;
            let mt = e["mediaType"].as_str().unwrap_or(media_type(&manifest)).to_string();
            cosign_tags.entry(t.to_string()).or_default().push(Source { bytes, manifest, media_type: mt, layout: s });
        }
    }
    for (t, copies) in cosign_tags {
        if push_cosign_tag(&c, &t, copies).await? {
            copied += 1;
        }
    }

    // The tag last, so it never names an image whose signatures aren't there yet.
    let s = &sources[&top];
    c.put_manifest(tag, &s.bytes, &s.media_type).await?;
    let back = c.manifest(tag).await?.ok_or(format!("{repo}:{tag} isn't there after the push"))?;
    let got = sha256_digest(&back);
    if got != top {
        return Err(format!("{repo}:{tag} is {got} after the push, not {top}: don't use it"));
    }
    let what = if whole { format!("the signed multi-arch index for {}", platforms.join(", ")) } else { format!("the {} image", platforms.join(", ")) };
    eprintln!("Pushed {what} to {repo}:{tag} ({top}), with {copied} signatures and attestations");
    Ok(top)
}
