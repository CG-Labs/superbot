//! Ubuntu's packages on users' machines from a mirror inside the operator's network
//! (ADR 0284). A machine's first boot installs what hardening and screens need with apt,
//! and unattended-upgrades takes security updates from the same sources, all from
//! Ubuntu's archive by default. With MACHINE_APT_MIRROR (amd64, a mirror of
//! archive.ubuntu.com/ubuntu) and MACHINE_APT_PORTS_MIRROR (arm64, of
//! ports.ubuntu.com/ubuntu-ports), first boot points apt at the mirror for its arch, for
//! the release, updates and security pockets, still signed by Ubuntu's archive keyring,
//! so a mirror can serve packages but not change them. MACHINE_MIRROR_CA_FILE is trusted
//! for those hosts only. cloud-init is told to leave the sources alone, so a container
//! restored onto another host, which cloud-init sees as a new instance, keeps them.
//!
//! `check` reads each pocket's InRelease from the mirror and the release's package
//! indexes, as apt would, and says what machines would miss.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::sync::{Arc, Mutex};

/// The Ubuntu release machines are made from (Incus's `ubuntu/24.04/cloud`, Linode's
/// `linode/ubuntu24.04`), whose suites the check reads.
pub const CODENAME: &str = "noble";
/// Where an Ubuntu machine's apt goes without a mirror, by arch.
pub const ARCHIVE: &str = "http://archive.ubuntu.com/ubuntu";
pub const PORTS: &str = "http://ports.ubuntu.com/ubuntu-ports";
/// The pockets first boot lists, as `<codename><pocket>`. Backports are left out: a
/// mirror needn't carry them, and apt fails on a listed suite it can't find.
pub const POCKETS: &[&str] = &["", "-updates", "-security"];
/// The components first boot lists, and those the check looks for packages in.
const COMPONENTS: &str = "main restricted universe multiverse";
const SEARCHED: &[&str] = &["main", "universe"];
/// Ubuntu's archive keyring, from the image's ubuntu-keyring package.
pub const KEYRING: &str = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";
pub const CA_PATH: &str = "/etc/superbot/mirror-ca.pem";
pub const CA_CONF_PATH: &str = "/etc/apt/apt.conf.d/60superbot-mirror-ca";
/// A pocket the mirror last changed longer ago than this is stale: machines get no
/// security update newer than it.
const STALE_DAYS: i64 = 7;
const MAX_RELEASE: u64 = 8 << 20;
const MAX_INDEX: u64 = 256 << 20;
/// The most a package index unpacks to that the check reads.
const MAX_UNPACKED: u64 = 2 << 30;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    /// MACHINE_APT_MIRROR, for amd64 machines, without its trailing `/`.
    pub amd64: Option<String>,
    /// MACHINE_APT_PORTS_MIRROR, for arm64 machines.
    pub arm64: Option<String>,
    /// MACHINE_MIRROR_CA_FILE's certificates, and the file they came from.
    pub ca: Option<(String, String)>,
}

/// A mirror's URL as first boot writes it into a shell script and apt's sources: only
/// characters that need no quoting in either.
fn mirror(key: &str, var: &dyn Fn(&str) -> String) -> Result<Option<String>, String> {
    let Some(u) = super::mirror::base(key, &var(key))? else { return Ok(None) };
    let safe = |c: char| c.is_ascii_alphanumeric() || "-._~:/%+[]".contains(c);
    if !u.chars().all(safe) {
        return Err(format!("{key} may have only letters, digits and - . _ ~ : / % + in it, not \"{}\"", crate::audit::clip(&u, 80)));
    }
    Ok(Some(u))
}

impl Settings {
    /// Settings from `var`. Only read where enrollment is on.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let amd64 = mirror("MACHINE_APT_MIRROR", var)?;
        let arm64 = mirror("MACHINE_APT_PORTS_MIRROR", var)?;
        if amd64.is_none() && arm64.is_none() {
            return Ok(None);
        }
        let ca = super::mirror::ca_file(var)?;
        let s = Settings { amd64, arm64, ca };
        if s.ca.is_some() {
            for (key, url) in s.mirrors() {
                if url::Url::parse(url).ok().and_then(|u| u.host().map(|h| matches!(h, url::Host::Ipv6(_)))).unwrap_or(false) {
                    return Err(format!(
                        "{key}: apt can't trust MACHINE_MIRROR_CA_FILE for an IPv6 address, as its per-host settings name hosts with ::. Name the mirror by DNS name or IPv4 address"
                    ));
                }
            }
        }
        Ok(Some(s))
    }

    /// Each mirror set: the setting, its URL and the Debian arch it serves.
    fn mirrors(&self) -> Vec<(&'static str, &str)> {
        let mut out = Vec::new();
        if let Some(u) = &self.amd64 {
            out.push(("MACHINE_APT_MIRROR", u.as_str()));
        }
        if let Some(u) = &self.arm64 {
            out.push(("MACHINE_APT_PORTS_MIRROR", u.as_str()));
        }
        out
    }

    fn by_arch(&self) -> Vec<(&'static str, &str)> {
        let mut out = Vec::new();
        if let Some(u) = &self.amd64 {
            out.push(("amd64", u.as_str()));
        }
        if let Some(u) = &self.arm64 {
            out.push(("arm64", u.as_str()));
        }
        out
    }

    /// The files first boot gets beside its script: the CA, and apt's setting trusting it
    /// for each mirror's host alone.
    pub fn files(&self) -> Vec<(&'static str, &'static str, String)> {
        let Some((pem, _)) = &self.ca else { return Vec::new() };
        let mut hosts: Vec<String> = self.mirrors().iter().filter_map(|(_, u)| url::Url::parse(u).ok()?.host_str().map(String::from)).collect();
        hosts.sort();
        hosts.dedup();
        let conf: String = hosts.iter().map(|h| format!("Acquire::https::{h}::CAInfo \"{CA_PATH}\";\n")).collect();
        vec![(CA_PATH, "0644", pem.clone()), (CA_CONF_PATH, "0644", conf)]
    }

    /// First boot's step, before anything runs apt: the machine's sources become the
    /// mirror for its arch, and cloud-init is told to keep them. A machine of another
    /// arch, or with no codename to list, keeps its sources and says so. Never fatal.
    pub fn firstboot(&self) -> String {
        FIRSTBOOT
            .replace("{amd64}", self.amd64.as_deref().unwrap_or(""))
            .replace("{arm64}", self.arm64.as_deref().unwrap_or(""))
            .replace("{pockets}", &POCKETS.iter().map(|p| format!("$codename{p}")).collect::<Vec<_>>().join(" "))
            .replace("{components}", COMPONENTS)
            .replace("{keyring}", KEYRING)
    }

    pub fn describe(&self) -> String {
        format!(
            "Ubuntu's packages on machines from {} (amd64) and {} (arm64){}",
            self.amd64.as_deref().unwrap_or(ARCHIVE),
            self.arm64.as_deref().unwrap_or(PORTS),
            self.ca.as_ref().map_or(String::new(), |(_, f)| format!(", their CA from {f}"))
        )
    }

    /// What `GET /api/machines/harness-mirror` says of the settings.
    pub fn shown(&self) -> Value {
        json!({ "amd64": self.amd64, "arm64": self.arm64 })
    }
}

const FIRSTBOOT: &str = r##"case $(dpkg --print-architecture 2>/dev/null || true) in
  amd64) apt_mirror='{amd64}' ;;
  arm64) apt_mirror='{arm64}' ;;
  *) apt_mirror= ;;
esac
codename=$( (. /etc/os-release && echo "${VERSION_CODENAME:-}") 2>/dev/null || true)
if [ -z "$apt_mirror" ]; then
  echo "superbot: no apt mirror for this machine's arch, so its packages come from Ubuntu's archive" >&2
elif [ -z "$codename" ]; then
  echo "superbot: /etc/os-release names no release, so apt's sources are left as they are" >&2
else
  mkdir -p /etc/apt/sources.list.d
  printf '%s\n' "# SuperBot (MACHINE_APT_MIRROR, ADR 0284): Ubuntu's packages from the operator's mirror." \
    "Types: deb" "URIs: $apt_mirror/" "Suites: {pockets}" \
    "Components: {components}" "Signed-By: {keyring}" > /etc/apt/sources.list.d/ubuntu.sources
  if [ -s /etc/apt/sources.list ]; then
    echo "# SuperBot: see /etc/apt/sources.list.d/ubuntu.sources" > /etc/apt/sources.list
  fi
  mkdir -p /etc/cloud/cloud.cfg.d
  printf 'apt:\n  preserve_sources_list: true\n' > /etc/cloud/cloud.cfg.d/90-superbot-apt.cfg
  echo "superbot: Ubuntu's packages from $apt_mirror"
fi
"##;

/// A Release file's fields; a field over several lines keeps them, `\n`-separated.
fn fields(text: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut last: Option<String> = None;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(v) = last.as_ref().and_then(|k| out.get_mut(k)) {
                v.push('\n');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.insert(k.trim().to_string(), v.trim().to_string());
            last = Some(k.trim().to_string());
        }
    }
    out
}

/// The signed text of a clearsigned InRelease, or why it isn't one.
fn signed_text(body: &str) -> Result<String, String> {
    let rest = body.strip_prefix("-----BEGIN PGP SIGNED MESSAGE-----").ok_or("it isn't clearsigned, as Ubuntu's InRelease is")?;
    let (head, text) = rest.split_once("\n\n").ok_or("it isn't clearsigned, as Ubuntu's InRelease is")?;
    if !head.lines().all(|l| l.trim().is_empty() || l.starts_with("Hash:")) {
        return Err("it isn't clearsigned, as Ubuntu's InRelease is".into());
    }
    let (text, _) = text.split_once("\n-----BEGIN PGP SIGNATURE-----").ok_or("it has no signature")?;
    Ok(text.lines().map(|l| l.strip_prefix("- ").unwrap_or(l)).collect::<Vec<_>>().join("\n"))
}

/// A Release file's `Date` or `Valid-Until`, as Ubuntu and Debian write them.
fn date(v: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc2822(v) {
        return Some(t.to_utc());
    }
    let v = v.trim().strip_suffix("UTC").or_else(|| v.trim().strip_suffix("GMT"))?.trim();
    chrono::NaiveDateTime::parse_from_str(v, "%a, %d %b %Y %H:%M:%S").ok().map(|t| t.and_utc())
}

struct Fetch {
    http: reqwest::Client,
}

impl Fetch {
    async fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, String> {
        let fail = |e: reqwest::Error| format!("couldn't fetch {url}: {}", chain(&e.without_url()));
        let mut r = self.http.get(url).send().await.map_err(fail)?.error_for_status().map_err(fail)?;
        let mut body = Vec::new();
        while let Some(chunk) = r.chunk().await.map_err(fail)? {
            if (body.len() + chunk.len()) as u64 > max {
                return Err(format!("{url} is over {} MiB", max >> 20));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let text = c.to_string();
        if !s.contains(&text) {
            s.push_str(&format!(": {text}"));
        }
        cause = c.source();
    }
    s
}

/// One pocket's InRelease: for `arch`, listing `main` and `universe`, not expired, and
/// for a pocket that gets updates, changed within `STALE_DAYS`. Its fields, and a
/// warning for a stale pocket.
async fn release(http: &Fetch, base: &str, suite: &str, arch: &str, now: chrono::DateTime<chrono::Utc>) -> Result<(BTreeMap<String, String>, Option<String>), String> {
    let url = format!("{base}/dists/{suite}/InRelease");
    let body = http.get(&url, MAX_RELEASE).await?;
    let text = String::from_utf8(body).map_err(|_| "its InRelease isn't text".to_string())?;
    let f = fields(&signed_text(&text)?);
    let codename = f.get("Codename").map_or("", String::as_str);
    if codename != CODENAME {
        return Err(format!("its InRelease is for {}, not {CODENAME}", if codename.is_empty() { "no release" } else { codename }));
    }
    let suite_listed = f.get("Suite").map_or("", String::as_str);
    if suite_listed != suite {
        return Err(format!("its InRelease is for the suite {suite_listed}, not {suite}"));
    }
    let listed = |k: &str| f.get(k).map(|v| v.split_whitespace().map(String::from).collect::<BTreeSet<_>>()).unwrap_or_default();
    if !listed("Architectures").contains(arch) {
        return Err(format!("it carries no {arch} packages (Architectures: {})", f.get("Architectures").map_or("", String::as_str)));
    }
    let missing: Vec<&str> = SEARCHED.iter().copied().filter(|c| !listed("Components").contains(*c)).collect();
    if !missing.is_empty() {
        return Err(format!("it lacks the {} component", missing.join(" and ")));
    }
    if let Some(until) = f.get("Valid-Until").and_then(|v| date(v))
        && until < now
    {
        return Err(format!("its InRelease expired at {until} (Valid-Until), so apt refuses it"));
    }
    let mut warning = None;
    if suite != CODENAME {
        match f.get("Date").and_then(|v| date(v)) {
            Some(d) if (now - d).num_days() > STALE_DAYS => {
                warning = Some(format!(
                    "the mirror last changed {suite} {} days ago ({d}): machines get no security update newer than that. Check it is kept in sync",
                    (now - d).num_days()
                ));
            }
            Some(_) => {}
            None => warning = Some(format!("its InRelease has no Date botd can read, so botd can't tell whether {suite} is kept in sync")),
        }
    }
    Ok((f, warning))
}

/// The packages `component`'s index for `arch` lists among `wanted`, read from its
/// Packages.gz, held to the SHA-256 and size the InRelease lists for it.
async fn index(http: &Fetch, base: &str, release: &BTreeMap<String, String>, component: &str, arch: &str, wanted: &BTreeSet<&str>) -> Result<BTreeSet<String>, String> {
    let path = format!("{component}/binary-{arch}/Packages.gz");
    let listed = release.get("SHA256").into_iter().flat_map(|v| v.lines()).find_map(|l| {
        let mut p = l.split_whitespace();
        let (sha, size, name) = (p.next()?, p.next()?, p.next()?);
        (name == path).then(|| (sha.to_ascii_lowercase(), size.parse::<u64>().ok()))
    });
    let Some((sha, size)) = listed else {
        return Err(format!("its InRelease lists no {path} with a SHA-256"));
    };
    let url = format!("{base}/dists/{CODENAME}/{path}");
    let body = http.get(&url, MAX_INDEX).await?;
    if size.is_some_and(|s| s != body.len() as u64) {
        return Err(format!("{url} is {} bytes, not the {} its InRelease lists", body.len(), size.unwrap_or_default()));
    }
    let got: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
    if got != sha {
        return Err(format!("{url} has SHA-256 {got}, not the {sha} its InRelease lists, so apt would refuse it"));
    }
    let reader = std::io::BufReader::new(std::io::Read::take(flate2::read::GzDecoder::new(body.as_slice()), MAX_UNPACKED));
    let mut found = BTreeSet::new();
    for line in reader.lines() {
        let line = line.map_err(|_| format!("{url} doesn't unpack"))?;
        if let Some(name) = line.strip_prefix("Package:").map(str::trim)
            && wanted.contains(name)
        {
            found.insert(name.to_string());
        }
    }
    Ok(found)
}

/// Reads every pocket machines would list from each mirror, and the release's indexes,
/// with the CA machines would trust, and checks `packages` are there. Its items, and
/// every redirect followed, for `mirror::reach`.
pub async fn check(s: &Settings, packages: &[&str]) -> (Vec<Value>, Vec<String>) {
    let hops = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = hops.clone();
    let follow = reqwest::redirect::Policy::custom(move |a| {
        seen.lock().unwrap().push(a.url().to_string());
        if a.previous().len() >= 10 { a.error("too many redirects") } else { a.follow() }
    });
    let built = super::tools::download_builder(None, s.ca.as_ref().map(|(pem, _)| pem.as_str())).and_then(|b| b.redirect(follow).build().map_err(|e| e.to_string()));
    let http = match built {
        Ok(h) => Fetch { http: h },
        Err(e) => return (vec![json!({ "name": "ubuntu", "ok": false, "error": format!("the mirrors' CA: {e}") })], Vec::new()),
    };
    let now = chrono::Utc::now();
    let wanted: BTreeSet<&str> = packages.iter().copied().collect();
    let mut items = Vec::new();
    for (arch, base) in s.by_arch() {
        let mut base_release = None;
        for pocket in POCKETS {
            let suite = format!("{CODENAME}{pocket}");
            let url = format!("{base}/dists/{suite}/InRelease");
            let mut v = json!({ "name": "ubuntu", "arch": arch, "suite": suite, "url": url });
            match release(&http, base, &suite, arch, now).await {
                Ok((f, warning)) => {
                    v["ok"] = json!(true);
                    if let Some(w) = warning {
                        v["warning"] = json!(w);
                    }
                    if pocket.is_empty() {
                        base_release = Some(f);
                    }
                }
                Err(e) => {
                    v["ok"] = json!(false);
                    v["error"] = json!(e);
                }
            }
            items.push(v);
        }
        if wanted.is_empty() {
            continue;
        }
        let mut v = json!({ "name": "ubuntu-packages", "arch": arch, "suite": CODENAME, "url": format!("{base}/dists/{CODENAME}/main/binary-{arch}/Packages.gz"), "packages": packages });
        let res = match &base_release {
            None => Err(format!("{CODENAME}'s InRelease didn't read, so its packages can't be checked")),
            Some(f) => {
                let mut found = BTreeSet::new();
                let mut err = None;
                for c in SEARCHED {
                    match index(&http, base, f, c, arch, &wanted).await {
                        Ok(names) => found.extend(names),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                match err {
                    Some(e) => Err(e),
                    None => {
                        let missing: Vec<&str> = packages.iter().copied().filter(|p| !found.contains(*p)).collect();
                        if missing.is_empty() { Ok(()) } else { Err(format!("its {CODENAME} main and universe don't list {}, which machines install", missing.join(", "))) }
                    }
                }
            }
        };
        v["ok"] = json!(res.is_ok());
        if let Err(e) = res {
            v["error"] = json!(e);
        }
        items.push(v);
    }
    let mut redirects = hops.lock().unwrap().clone();
    redirects.sort();
    redirects.dedup();
    (items, redirects)
}

#[cfg(test)]
pub(crate) mod tests;
