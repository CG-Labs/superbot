//! `superbot-oci fetch`: an image's signature graph, from its registry into an OCI layout.

use crate::layout::Writer;
use crate::registry::{Client, Repo, blobs_of, is_index, media_type};
use crate::{config::Settings, digest_ok, sha256_digest};
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};

/// More than any image has; a registry listing more is refused rather than copied.
const MAX_MANIFESTS: usize = 1000;
/// Attestation layers (an SBOM) can be large, but not this large.
const MAX_BLOB: u64 = 1 << 30;

#[derive(Debug, Default)]
pub struct Fetched {
    pub referrers: usize,
    pub tags: usize,
    pub attestations: usize,
}

/// The tag the referrers tag schema keeps DIGEST's referrers under; cosign's own tags add
/// `.sig`, `.att` or `.sbom` to it.
pub fn fallback_tag(digest: &str) -> String {
    digest.replacen(':', "-", 1)
}

pub fn parse(what: &str, bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("{what} isn't JSON: {e}"))
}

/// Stores a manifest and the blobs it names.
async fn store(c: &Client, w: &Writer, digest: &str, bytes: &[u8], m: &Value) -> Result<(), String> {
    for b in blobs_of(m)? {
        if !w.has(&b) {
            c.fetch_blob(&b, &w.blob_path(&b)?, MAX_BLOB).await?;
        }
    }
    w.put(digest, bytes)
}

pub async fn fetch(settings: &Settings, repo: &Repo, top: &str, image: &str, out: &std::path::Path) -> Result<Fetched, String> {
    let c = Client::new(settings, repo, false).await?;
    let mut w = Writer::create(out)?;
    let mut got = Fetched::default();
    let top_bytes = c.manifest(top).await?.ok_or(format!("{repo}@{top} isn't there"))?;
    let top_m = parse(&format!("{repo}@{top}"), &top_bytes)?;
    let mut subjects = Vec::new();
    if is_index(&top_m) {
        let entries = top_m["manifests"].as_array().cloned().unwrap_or_default();
        if !entries.iter().any(|e| e["digest"] == image) {
            return Err(format!("{repo}@{top} doesn't list {image}"));
        }
        w.put(top, &top_bytes)?;
        w.add(json!({ "mediaType": media_type(&top_m), "digest": top, "size": top_bytes.len() }), "index", None);
        subjects.extend([top.to_string(), image.to_string()]);
        let attestations = entries.iter().filter(|e| e["annotations"]["vnd.docker.reference.type"] == "attestation-manifest" && e["annotations"]["vnd.docker.reference.digest"] == image);
        for e in attestations {
            let d = e["digest"].as_str().filter(|d| digest_ok(d)).ok_or(format!("{repo}@{top} lists an attestation without a digest"))?;
            let bytes = c.manifest(d).await?.ok_or(format!("{repo}@{top} lists {d}, which isn't there"))?;
            store(&c, &w, d, &bytes, &parse(d, &bytes)?).await?;
            w.add(e.clone(), "attestation", None);
            subjects.push(d.to_string());
            got.attestations += 1;
        }
    } else if top != image {
        return Err(format!("{repo}@{top} is one image, not an index listing {image}"));
    } else {
        subjects.push(image.to_string());
    }

    let mut seen: HashSet<String> = subjects.iter().cloned().collect();
    let mut queue: VecDeque<String> = subjects.into();
    while let Some(subject) = queue.pop_front() {
        // Both: a registry may have gained the API after some referrers went into the tag.
        let mut listed = c.referrers(&subject).await?.unwrap_or_default();
        if let Some(b) = c.manifest(&fallback_tag(&subject)).await? {
            for d in parse(&fallback_tag(&subject), &b)?["manifests"].as_array().into_iter().flatten() {
                if !listed.iter().any(|l| l["digest"] == d["digest"]) {
                    listed.push(d.clone());
                }
            }
        }
        for d in listed {
            let Some(digest) = d["digest"].as_str().filter(|x| digest_ok(x)).map(String::from) else { continue };
            if !seen.insert(digest.clone()) {
                continue;
            }
            if seen.len() > MAX_MANIFESTS {
                return Err(format!("{repo} lists more than {MAX_MANIFESTS} signatures and attestations: refusing to copy them"));
            }
            let bytes = c.manifest(&digest).await?.ok_or(format!("{repo} lists {digest} as referring to {subject}, but it isn't there"))?;
            let m = parse(&digest, &bytes)?;
            if m["subject"]["digest"] != subject.as_str() {
                eprintln!("Skipping {digest}: listed for {subject}, but its subject is {}", m["subject"]["digest"]);
                continue;
            }
            if is_index(&m) {
                eprintln!("Skipping {digest}: an index referring to {subject} (only manifests are copied)");
                continue;
            }
            store(&c, &w, &digest, &bytes, &m).await?;
            let mut desc = json!({ "mediaType": media_type(&m), "digest": digest, "size": bytes.len() });
            if let Some(t) = d["artifactType"].as_str().or(m["artifactType"].as_str()).or(m["config"]["mediaType"].as_str()) {
                desc["artifactType"] = json!(t);
            }
            if let Some(a) = d["annotations"].as_object().or(m["annotations"].as_object()) {
                desc["annotations"] = Value::Object(a.clone());
            }
            w.add(desc, "referrer", None);
            got.referrers += 1;
            queue.push_back(digest);
        }
        for suffix in ["sig", "att", "sbom"] {
            let tag = format!("{}.{suffix}", fallback_tag(&subject));
            let Some(bytes) = c.manifest(&tag).await? else { continue };
            let digest = sha256_digest(&bytes);
            let m = parse(&tag, &bytes)?;
            if is_index(&m) {
                eprintln!("Skipping {repo}:{tag}: an index, not a cosign signature");
                continue;
            }
            store(&c, &w, &digest, &bytes, &m).await?;
            w.add(json!({ "mediaType": media_type(&m), "digest": digest, "size": bytes.len() }), "tag", Some(&tag));
            got.tags += 1;
        }
    }
    w.finish()?;
    Ok(got)
}
