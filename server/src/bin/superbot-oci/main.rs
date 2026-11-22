//! `superbot-oci`: an image's signatures and attestations, from its registry into an offline
//! bundle and from the bundle into a registry mirror (docs/adr/0147-signatures-and-multi-arch-indexes-in-mirrors.md).
//! `deploy/offline-bundle.sh` runs it; skopeo can't copy OCI 1.1 referrers.
//!   superbot-oci fetch --from HOST/PATH@DIGEST --image DIGEST --out DIR
//!   superbot-oci push [--check] --to HOST/PATH:TAG UNIT...
//!   superbot-oci --version
//!
//! `fetch` writes an OCI image layout holding what `--from` names (an index, or the image
//! itself), the attestation manifests in that index for `--image`, and every referrer (OCI 1.1
//! referrers API and its `sha256-<hex>` tag fallback) and cosign tag (`sha256-<hex>.sig`,
//! `.att`, `.sbom`) of those, with their blobs, each checked against its digest.
//!
//! `push` takes one or more UNITs, folders with `image/` (an image's OCI layout, as in a bundle)
//! and, if it was signed, `signatures/` (what `fetch` wrote). When the units hold every image
//! and attestation their index lists, the index goes up unchanged and the tag names it;
//! otherwise one unit's image does. Signatures and attestations follow, then the tag, last,
//! read back. Prints the digest the tag names. `--check` only checks the units, with no network,
//! and prints the digest the tag would name.

mod config;
mod fetch;
mod layout;
mod push;
mod registry;
#[cfg(test)]
mod tests;

use sha2::{Digest, Sha256};

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>())
}

pub fn digest_ok(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

/// A tag: what Docker and the distribution spec accept.
pub fn tag_ok(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty() && b.len() <= 128 && (b[0].is_ascii_alphanumeric() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

const USAGE: &str = "Usage:
  superbot-oci fetch --from HOST/PATH@DIGEST --image DIGEST --out DIR
  superbot-oci push [--check] --to HOST/PATH:TAG UNIT...
  superbot-oci --version";

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            let v = args.get(i + 1).filter(|v| !v.starts_with("--")).ok_or(format!("{name} needs a value"))?;
            if found.replace(v.as_str()).is_some() {
                return Err(format!("{name} is given twice"));
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    found.ok_or(format!("{name} is required\n{USAGE}"))
}

async fn run(args: &[String]) -> Result<Option<String>, String> {
    let settings = config::Settings::from_env();
    match args.first().map(String::as_str) {
        Some("--version" | "version") => Ok(Some(format!("superbot-oci {}", env!("CARGO_PKG_VERSION")))),
        Some("fetch") => {
            let rest = &args[1..];
            for (i, a) in rest.iter().enumerate() {
                let value = i > 0 && matches!(rest[i - 1].as_str(), "--from" | "--image" | "--out");
                if !value && !matches!(a.as_str(), "--from" | "--image" | "--out") {
                    return Err(format!("Unknown argument {a}\n{USAGE}"));
                }
            }
            let (repo, top) = registry::Repo::parse_digested(flag(rest, "--from")?)?;
            let image = flag(rest, "--image")?;
            if !digest_ok(image) {
                return Err(format!("--image {image} isn't a sha256 digest"));
            }
            let out = std::path::Path::new(flag(rest, "--out")?);
            let got = fetch::fetch(&settings, &repo, &top, image, out).await?;
            eprintln!(
                "Fetched {} signatures and attestations ({} referrers, {} cosign tags, {} attestation manifests) for {}@{image}",
                got.referrers + got.tags + got.attestations,
                got.referrers,
                got.tags,
                got.attestations,
                repo
            );
            Ok(None)
        }
        Some("push") => {
            let rest = &args[1..];
            let mut units = Vec::new();
            let mut check = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--to" => i += 2,
                    "--check" => {
                        check = true;
                        i += 1;
                    }
                    a if a.starts_with("--") => return Err(format!("Unknown option {a}\n{USAGE}")),
                    a => {
                        units.push(std::path::PathBuf::from(a));
                        i += 1;
                    }
                }
            }
            let (repo, tag) = registry::Repo::parse_tagged(flag(rest, "--to")?)?;
            if units.is_empty() {
                return Err(format!("push needs at least one UNIT\n{USAGE}"));
            }
            push::push(&settings, &repo, &tag, &units, check).await.map(Some)
        }
        _ => Err(USAGE.into()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(Some(out)) => println!("{out}"),
        Ok(None) => {}
        Err(e) => {
            eprintln!("superbot-oci: {e}");
            std::process::exit(1);
        }
    }
}
