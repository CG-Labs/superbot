use super::*;
use crate::machines::standin_mirror::Mirror;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn env(pairs: &[(&str, String)]) -> impl Fn(&str) -> String {
    let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    move |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default()
}

fn gz(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// A clearsigned-looking InRelease: botd reads it, apt checks the signature.
pub(crate) fn unsigned(text: &str) -> String {
    format!("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{text}\n-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n")
}

/// A stand-in Ubuntu archive at `<mirror><root>`, laid out as archive.ubuntu.com's: each
/// pocket's InRelease, changed `age_days` ago, signed by `sign`, and each component's
/// Packages.gz for `arch`, with `debs` in the release's main.
pub(crate) fn publish(m: &Mirror, root: &str, arch: &str, debs: &[(&str, &[u8])], age_days: i64, sign: &dyn Fn(&str) -> String) {
    let date = (chrono::Utc::now() - chrono::Duration::days(age_days)).format("%a, %d %b %Y %H:%M:%S UTC");
    for pocket in POCKETS {
        let suite = format!("{CODENAME}{pocket}");
        let mut sums = String::new();
        for component in ["main", "restricted", "universe", "multiverse"] {
            let mut index = String::new();
            if pocket.is_empty() && component == "main" {
                for (name, deb) in debs {
                    let file = format!("pool/main/{}/{name}/{name}_99.0_{arch}.deb", &name[..1]);
                    m.file(&format!("{root}/{file}"), deb);
                    index.push_str(&format!(
                        "Package: {name}\nVersion: 99.0\nArchitecture: {arch}\nFilename: {file}\nSize: {}\nSHA256: {}\nDescription: stand-in {name}\n\n",
                        deb.len(),
                        hex(deb)
                    ));
                }
            }
            let path = format!("{component}/binary-{arch}/Packages");
            sums.push_str(&format!(" {} {} {path}\n", hex(index.as_bytes()), index.len()));
            let body = gz(index.as_bytes());
            sums.push_str(&format!(" {} {} {path}.gz\n", hex(&body), body.len()));
            m.file(&format!("{root}/dists/{suite}/{path}.gz"), &body);
        }
        let release = format!(
            "Origin: Ubuntu\nLabel: Ubuntu\nSuite: {suite}\nCodename: {CODENAME}\nDate: {date}\nArchitectures: {arch}\nComponents: main restricted universe multiverse\nSHA256:\n{sums}"
        );
        m.file(&format!("{root}/dists/{suite}/InRelease"), sign(&release).as_bytes());
    }
}

fn arch() -> &'static str {
    if std::env::consts::ARCH == "aarch64" { "arm64" } else { "amd64" }
}

fn settings(m: &Mirror, ca: bool) -> Settings {
    let url = Some(format!("{}/ubuntu", m.url));
    let (amd64, arm64) = if arch() == "amd64" { (url, None) } else { (None, url) };
    Settings { amd64, arm64, ca: ca.then(|| (m.ca_pem(), "/etc/superbot/corp-ca.pem".into())) }
}

#[test]
fn settings_are_checked_at_start() {
    let from = |pairs: &[(&str, String)]| Settings::from_env(&env(pairs));
    assert_eq!(from(&[]).unwrap(), None, "off by default");
    assert_eq!(from(&[("MACHINE_MIRROR_CA_FILE", "/nowhere.pem".into())]).unwrap(), None, "the CA alone is the harness mirrors' to refuse");
    let s = from(&[
        ("MACHINE_APT_MIRROR", " https://mirror.corp.example/ubuntu/ ".into()),
        ("MACHINE_APT_PORTS_MIRROR", "https://10.0.0.20:8443/artifactory/ubuntu-ports".into()),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(s.amd64.as_deref(), Some("https://mirror.corp.example/ubuntu"));
    assert_eq!(s.arm64.as_deref(), Some("https://10.0.0.20:8443/artifactory/ubuntu-ports"));
    assert!(s.ca.is_none() && s.files().is_empty());
    assert!(s.describe().contains("from https://mirror.corp.example/ubuntu (amd64)"), "{}", s.describe());
    let ports_only = from(&[("MACHINE_APT_PORTS_MIRROR", "https://mirror.corp.example/ubuntu-ports".into())]).unwrap().unwrap();
    assert!(ports_only.amd64.is_none() && ports_only.describe().contains(&format!("{ARCHIVE} (amd64)")));
    for (k, v, why) in [
        ("MACHINE_APT_MIRROR", "http://mirror.corp.example/ubuntu", "https URL"),
        ("MACHINE_APT_MIRROR", "mirror.corp.example/ubuntu", "https URL"),
        ("MACHINE_APT_MIRROR", "https://svc:secret@mirror.corp.example/ubuntu", "https URL"),
        ("MACHINE_APT_MIRROR", "https://mirror.corp.example/ubuntu?x=1", "https URL"),
        ("MACHINE_APT_PORTS_MIRROR", "https://mirror.corp.example/ubuntu#ports", "https URL"),
        ("MACHINE_APT_MIRROR", "https://mirror.corp.example/a'b", "only letters"),
        ("MACHINE_APT_MIRROR", "https://mirror.corp.example/$(reboot)", "only letters"),
        ("MACHINE_APT_PORTS_MIRROR", "https://mirror.corp.example/a;b", "only letters"),
    ] {
        let e = from(&[(k, v.into())]).unwrap_err();
        assert!(e.contains(k) && e.contains(why), "{k}={v}: {e}");
    }

    let dir = crate::db::temp_path("apt-ca");
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Mirror::ca_only();
    let file = dir.join("ca.pem");
    std::fs::write(&file, ca.ca_pem()).unwrap();
    let with_ca = |url: &str| from(&[("MACHINE_APT_MIRROR", url.into()), ("MACHINE_MIRROR_CA_FILE", file.display().to_string())]);
    let s = with_ca("https://mirror.corp.example/ubuntu").unwrap().unwrap();
    assert_eq!(s.ca.as_ref().map(|(p, f)| (p.as_str(), f.as_str())), Some((ca.ca_pem().as_str(), file.to_str().unwrap())));
    assert!(s.describe().ends_with(&format!("their CA from {}", file.display())), "{}", s.describe());
    let e = with_ca("https://[fd00::20]/ubuntu").unwrap_err();
    assert!(e.contains("IPv6") && e.contains("MACHINE_APT_MIRROR"), "{e}");
    assert!(from(&[("MACHINE_APT_MIRROR", "https://[fd00::20]/ubuntu".into())]).is_ok(), "an IPv6 mirror with a CA machines already trust");
    std::fs::write(&file, "not a certificate\n").unwrap();
    assert!(with_ca("https://mirror.corp.example/ubuntu").unwrap_err().contains("MACHINE_MIRROR_CA_FILE"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_ca_is_trusted_only_for_the_mirrors_hosts() {
    let s = Settings {
        amd64: Some("https://mirror.corp.example/ubuntu".into()),
        arm64: Some("https://mirror.corp.example:8443/ubuntu-ports".into()),
        ca: Some(("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(), "/etc/ssl/corp.pem".into())),
    };
    let files = s.files();
    assert_eq!(files.len(), 2);
    assert_eq!((files[0].0, files[0].1), (CA_PATH, "0644"));
    assert_eq!(files[1], (CA_CONF_PATH, "0644", format!("Acquire::https::mirror.corp.example::CAInfo \"{CA_PATH}\";\n")), "one line per host, whatever the port");
    let two = Settings { arm64: Some("https://10.0.0.20/ubuntu-ports".into()), ..s };
    assert_eq!(two.files()[1].2.lines().collect::<Vec<_>>(), [format!("Acquire::https::10.0.0.20::CAInfo \"{CA_PATH}\";"), format!("Acquire::https::mirror.corp.example::CAInfo \"{CA_PATH}\";")]);
}

/// The first-boot step, run as `sh -eu` (as the first boot runs it) in a stand-in root:
/// `/etc/apt`, `/etc/cloud` and `/etc/os-release` there, and `dpkg` saying `arch`.
fn run_step(step: &str, arch: &str, os_release: Option<&str>, sources_list: Option<&str>) -> (PathBuf, String, String) {
    let root = crate::db::temp_path("apt-step");
    for d in ["etc/apt/sources.list.d", "etc/cloud", "stubs"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let stub = root.join("stubs/dpkg");
    std::fs::write(&stub, format!("#!/bin/sh\n[ \"$1\" = --print-architecture ] && echo {arch}\n")).unwrap();
    std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    if let Some(o) = os_release {
        std::fs::write(root.join("os-release"), o).unwrap();
    }
    if let Some(l) = sources_list {
        std::fs::write(root.join("etc/apt/sources.list"), l).unwrap();
    }
    std::fs::write(root.join("etc/apt/sources.list.d/ubuntu.sources"), "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\n").unwrap();
    let r = root.display().to_string();
    let script = step.replace("/etc/os-release", &format!("{r}/os-release")).replace("/etc/apt", &format!("{r}/etc/apt")).replace("/etc/cloud", &format!("{r}/etc/cloud"));
    let out = Command::new("sh").args(["-eu", "-c", &script]).env("PATH", format!("{r}/stubs:/usr/bin:/bin")).output().unwrap();
    assert!(out.status.success(), "the step never stops the first boot: {}", String::from_utf8_lossy(&out.stderr));
    (root, String::from_utf8_lossy(&out.stdout).into(), String::from_utf8_lossy(&out.stderr).into())
}

const NOBLE: &str = "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\n";

#[test]
fn first_boot_points_apt_at_the_mirror_for_its_arch_and_keeps_cloud_init_off_it() {
    let s = Settings { amd64: Some("https://mirror.corp.example/ubuntu".into()), arm64: None, ca: None };
    let step = s.firstboot();
    for p in ["{amd64}", "{arm64}", "{pockets}", "{components}", "{keyring}"] {
        assert!(!step.contains(p), "{p}: {step}");
    }
    let check = Command::new("sh").args(["-n", "-c", &step]).output().unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));

    let (root, stdout, _) = run_step(&step, "amd64", Some(NOBLE), Some("deb http://archive.ubuntu.com/ubuntu jammy main\n"));
    let sources = std::fs::read_to_string(root.join("etc/apt/sources.list.d/ubuntu.sources")).unwrap();
    assert_eq!(
        sources.lines().skip(1).collect::<Vec<_>>(),
        [
            "Types: deb",
            "URIs: https://mirror.corp.example/ubuntu/",
            "Suites: noble noble-updates noble-security",
            "Components: main restricted universe multiverse",
            &format!("Signed-By: {KEYRING}"),
        ],
        "{sources}"
    );
    assert!(sources.starts_with("# SuperBot (MACHINE_APT_MIRROR"), "{sources}");
    assert_eq!(std::fs::read_to_string(root.join("etc/apt/sources.list")).unwrap(), "# SuperBot: see /etc/apt/sources.list.d/ubuntu.sources\n".replace("/etc/apt", &format!("{}/etc/apt", root.display())), "jammy's own list goes");
    assert_eq!(std::fs::read_to_string(root.join("etc/cloud/cloud.cfg.d/90-superbot-apt.cfg")).unwrap(), "apt:\n  preserve_sources_list: true\n");
    assert!(stdout.contains("Ubuntu's packages from https://mirror.corp.example/ubuntu"), "{stdout}");

    // noble's empty sources.list isn't made.
    let (root, ..) = run_step(&step, "amd64", Some(NOBLE), None);
    assert!(!root.join("etc/apt/sources.list").exists());

    // An arm64 machine with no ports mirror, and an image naming no release, keep
    // their sources, and say so.
    for (arch, os, says) in [("arm64", Some(NOBLE), "no apt mirror for this machine's arch"), ("amd64", Some("ID=ubuntu\n"), "names no release"), ("amd64", None, "names no release")] {
        let (root, _, stderr) = run_step(&step, arch, os, None);
        assert!(stderr.contains(says), "{arch} {os:?}: {stderr}");
        assert_eq!(std::fs::read_to_string(root.join("etc/apt/sources.list.d/ubuntu.sources")).unwrap(), "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\n");
        assert!(!root.join("etc/cloud/cloud.cfg.d").exists());
    }
    let both = Settings { arm64: Some("https://mirror.corp.example/ubuntu-ports".into()), ..s };
    let (root, ..) = run_step(&both.firstboot(), "arm64", Some(NOBLE), None);
    assert!(std::fs::read_to_string(root.join("etc/apt/sources.list.d/ubuntu.sources")).unwrap().contains("URIs: https://mirror.corp.example/ubuntu-ports/"));
}

fn item<'a>(items: &'a [Value], name: &str, suite: &str) -> &'a Value {
    items.iter().find(|i| i["name"] == name && i["suite"] == suite).unwrap_or_else(|| panic!("{name} {suite}: {items:?}"))
}

#[tokio::test]
async fn the_check_reads_every_pocket_and_the_packages_machines_install() {
    let m = Mirror::serve().await;
    publish(&m, "/ubuntu", arch(), &[("nftables", b"nft"), ("unattended-upgrades", b"uu")], 0, &unsigned);
    let s = settings(&m, true);
    let (items, redirects) = check(&s, &["nftables", "unattended-upgrades"]).await;
    assert_eq!(items.len(), 4, "{items:?}");
    assert!(items.iter().all(|i| i["ok"] == true && i["warning"].is_null() && i["arch"] == arch()), "{items:?}");
    assert_eq!(item(&items, "ubuntu", "noble-security")["url"], json!(format!("{}/ubuntu/dists/noble-security/InRelease", m.url)));
    assert!(redirects.is_empty());
    let calls = m.calls();
    for path in [format!("/ubuntu/dists/noble/main/binary-{}/Packages.gz", arch()), format!("/ubuntu/dists/noble/universe/binary-{}/Packages.gz", arch())] {
        assert!(calls.contains(&path), "{path}: {calls:?}");
    }
    assert!(!calls.iter().any(|c| c.contains("/pool/")), "no package is downloaded: {calls:?}");

    // A package the mirror doesn't carry, and no CA machines would trust.
    let (items, _) = check(&s, &["nftables", "openbox", "libx264-164"]).await;
    let p = item(&items, "ubuntu-packages", "noble");
    assert_eq!(p["ok"], false);
    assert!(p["error"].as_str().unwrap().contains("don't list openbox, libx264-164"), "{p}");
    let (items, _) = check(&settings(&m, false), &["nftables"]).await;
    assert!(items.iter().all(|i| i["ok"] == false), "{items:?}");
    assert!(items[0]["error"].as_str().unwrap().contains("couldn't fetch"), "{items:?}");

    // No packages to look for: the pockets alone.
    let (items, _) = check(&s, &[]).await;
    assert_eq!(items.len(), 3);
}

#[tokio::test]
async fn the_check_says_what_apt_would_refuse_and_when_the_mirror_falls_behind() {
    let m = Mirror::serve().await;
    let s = settings(&m, true);
    let a = arch();
    publish(&m, "/ubuntu", a, &[("nftables", b"nft")], 30, &unsigned);
    let (items, _) = check(&s, &["nftables"]).await;
    assert!(items.iter().all(|i| i["ok"] == true), "a stale mirror still serves: {items:?}");
    assert!(item(&items, "ubuntu", "noble")["warning"].is_null(), "the release pocket never changes");
    for suite in ["noble-updates", "noble-security"] {
        let w = item(&items, "ubuntu", suite)["warning"].as_str().unwrap_or_default().to_string();
        assert!(w.contains("30 days ago") && w.contains("security update"), "{suite}: {w}");
    }

    publish(&m, "/ubuntu", a, &[("nftables", b"nft")], 0, &unsigned);
    m.file(&format!("/ubuntu/dists/noble/main/binary-{a}/Packages.gz"), &gz(b"Package: nftables\n"));
    let (items, _) = check(&s, &["nftables"]).await;
    let e = item(&items, "ubuntu-packages", "noble")["error"].as_str().unwrap().to_string();
    assert!(e.contains("not the") && e.contains("its InRelease lists"), "{e}");
    publish(&m, "/ubuntu", a, &[("nftables", b"nft")], 0, &unsigned);

    let release = |suite: &str, codename: &str, archs: &str, components: &str, extra: &str| {
        format!("Suite: {suite}\nCodename: {codename}\nDate: {}\nArchitectures: {archs}\nComponents: {components}\n{extra}", chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S UTC"))
    };
    for (body, want) in [
        (unsigned(&release("noble-security", "jammy", a, "main universe", "")), "for jammy, not noble"),
        (unsigned(&release("noble-updates", "noble", a, "main universe", "")), "suite noble-updates, not noble-security"),
        (unsigned(&release("noble-security", "noble", "riscv64", "main universe", "")), &format!("carries no {a} packages") as &str),
        (unsigned(&release("noble-security", "noble", a, "main restricted", "")), "lacks the universe component"),
        (unsigned(&release("noble-security", "noble", a, "main universe", "Valid-Until: Mon, 02 Jan 2023 00:00:00 UTC\n")), "expired"),
        (release("noble-security", "noble", a, "main universe", ""), "isn't clearsigned"),
        (unsigned(&release("noble-security", "noble", a, "main universe", "")).replace("Hash: SHA512", "Hash: SHA512\nComment: x"), "isn't clearsigned"),
    ] {
        m.file("/ubuntu/dists/noble-security/InRelease", body.as_bytes());
        let (items, _) = check(&s, &["nftables"]).await;
        let sec = item(&items, "ubuntu", "noble-security");
        assert_eq!(sec["ok"], false, "{want}: {sec}");
        assert!(sec["error"].as_str().unwrap().contains(want), "{want}: {sec}");
        assert_eq!(item(&items, "ubuntu-packages", "noble")["ok"], true, "the release's own pocket still reads");
    }
    let (items, _) = check(&Settings { amd64: Some(format!("{}/elsewhere", m.url)), arm64: None, ca: s.ca.clone() }, &["nftables"]).await;
    assert!(items.iter().all(|i| i["ok"] == false && i["arch"] == "amd64"), "{items:?}");
    assert!(item(&items, "ubuntu-packages", "noble")["error"].as_str().unwrap().contains("didn't read"), "{items:?}");
}

#[test]
fn release_dates_read_as_ubuntu_and_debian_write_them() {
    let t = |s: &str| date(s).map(|d| d.to_rfc3339());
    assert_eq!(t("Thu, 25 Apr 2024 15:10:33 UTC").as_deref(), Some("2024-04-25T15:10:33+00:00"));
    assert_eq!(t("Sun, 22 Nov 2026 08:00:00 +0000").as_deref(), Some("2026-11-22T08:00:00+00:00"));
    assert_eq!(t("Sun, 22 Nov 2026 08:00:00 GMT").as_deref(), Some("2026-11-22T08:00:00+00:00"));
    assert_eq!(t("yesterday"), None);
    let f = fields("Suite: noble\nSHA256:\n abc 1 main/x\n def 2 universe/y\nCodename: noble\n");
    assert_eq!(f["SHA256"], "\nabc 1 main/x\ndef 2 universe/y");
    assert_eq!(f["Codename"], "noble");
}

/// `name` on PATH.
fn have(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

/// A throwaway gpg home with one signing key: its public keyring for `Signed-By`, and
/// a way to clearsign a Release with it. Short, so gpg-agent's socket path fits.
struct Signer {
    home: PathBuf,
}

impl Signer {
    fn new(tag: &str) -> Signer {
        let home = PathBuf::from(format!("/tmp/sbg-{tag}-{}", crate::short_id()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let s = Signer { home };
        s.gpg(&["--quick-gen-key", "SuperBot stand-in archive", "ed25519", "sign", "0"], None);
        s
    }

    fn gpg(&self, args: &[&str], input: Option<&str>) -> Vec<u8> {
        let mut c = Command::new("gpg");
        c.env("GNUPGHOME", &self.home).args(["--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", ""]).args(args);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.unwrap_or("").as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "gpg {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    fn sign(&self, text: &str) -> String {
        String::from_utf8(self.gpg(&["--clearsign", "--digest-algo", "SHA512"], Some(text))).unwrap()
    }

    fn keyring(&self, at: &Path) {
        std::fs::write(at, self.gpg(&["--export"], None)).unwrap();
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf").env("GNUPGHOME", &self.home).args(["--kill", "gpg-agent"]).output();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// The real apt, in a root of its own, with the sources and CA setting first boot writes:
/// it takes a package from the mirror over its CA, and refuses the mirror without the CA,
/// a Release signed by another key, and a package the mirror changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_apt_takes_packages_from_the_mirror_and_refuses_changed_ones() {
    if !(have("apt-get") && have("gpg") && have("gpgv") && have("dpkg")) {
        eprintln!("skipped: needs apt-get, gpg, gpgv and dpkg");
        return;
    }
    let a = String::from_utf8(Command::new("dpkg").arg("--print-architecture").output().unwrap().stdout).unwrap().trim().to_string();
    if a != "amd64" && a != "arm64" {
        eprintln!("skipped: machines are amd64 or arm64, not {a}");
        return;
    }
    let m = Mirror::serve().await;
    let (ubuntu, other) = (Signer::new("ubuntu"), Signer::new("other"));
    let deb: &[u8] = b"a stand-in nftables package";
    publish(&m, "/ubuntu", &a, &[("nftables", deb)], 0, &|r| ubuntu.sign(r));
    let url = Some(format!("{}/ubuntu", m.url));
    let s = if a == "amd64" { Settings { amd64: url, arm64: None, ca: None } } else { Settings { amd64: None, arm64: url, ca: None } };
    let s = Settings { ca: Some((m.ca_pem(), "corp.pem".into())), ..s };

    let root = crate::db::temp_path("real-apt");
    let r = root.display().to_string();
    for d in ["etc/apt/sources.list.d", "etc/apt/apt.conf.d", "etc/apt/preferences.d", "etc/cloud", "var/lib/apt/lists/partial", "var/cache/apt/archives/partial", "dl"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("os-release"), NOBLE).unwrap();
    std::fs::write(root.join("status"), "").unwrap();
    ubuntu.keyring(&root.join("ubuntu-archive-keyring.gpg"));
    let step = s
        .firstboot()
        .replace(KEYRING, &format!("{r}/ubuntu-archive-keyring.gpg"))
        .replace("/etc/os-release", &format!("{r}/os-release"))
        .replace("/etc/apt", &format!("{r}/etc/apt"))
        .replace("/etc/cloud", &format!("{r}/etc/cloud"));
    let out = Command::new("sh").args(["-eu", "-c", &step]).output().unwrap();
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Ubuntu's packages from"), "{out:?}");
    let ca_conf = || {
        for (path, _, content) in s.files() {
            let content = content.replace(CA_PATH, &format!("{r}/mirror-ca.pem"));
            let at = if path == CA_PATH { root.join("mirror-ca.pem") } else { root.join(path.trim_start_matches('/')) };
            std::fs::write(at, content).unwrap();
        }
    };
    ca_conf();
    let sandbox = if unsafe { libc::geteuid() } == 0 { "root" } else { "" };
    std::fs::write(
        root.join("apt.conf"),
        format!("Dir \"{r}/\";\nDir::State::status \"{r}/status\";\nDebug::NoLocking \"true\";\nAcquire::Languages \"none\";\nAPT::Sandbox::User \"{sandbox}\";\n"),
    )
    .unwrap();
    let apt = |args: &[&str]| {
        let out = Command::new("apt-get").args(args).env("APT_CONFIG", root.join("apt.conf")).current_dir(root.join("dl")).output().unwrap();
        (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    };
    let fresh = || {
        let _ = std::fs::remove_dir_all(root.join("var/lib/apt/lists"));
        std::fs::create_dir_all(root.join("var/lib/apt/lists/partial")).unwrap();
        let _ = std::fs::remove_file(root.join("dl").join(format!("nftables_99.0_{a}.deb")));
    };

    let (ok, update) = apt(&["update"]);
    assert!(ok && !update.contains("Err:"), "{update}");
    let (ok, log) = apt(&["download", "nftables"]);
    assert!(ok, "{update}\n{log}");
    assert_eq!(std::fs::read(root.join("dl").join(format!("nftables_99.0_{a}.deb"))).unwrap(), deb);
    assert!(m.calls().iter().any(|c| c == "/ubuntu/dists/noble-security/InRelease"), "the security pocket from the mirror too");

    // Without the CA setting, apt doesn't trust the mirror.
    fresh();
    std::fs::remove_file(root.join(CA_CONF_PATH.trim_start_matches('/'))).unwrap();
    let (_, log) = apt(&["update"]);
    assert!(log.to_ascii_lowercase().contains("certificate"), "{log}");
    assert!(!apt(&["download", "nftables"]).0, "nothing to take: {log}");
    ca_conf();

    // A Release signed by another key.
    fresh();
    publish(&m, "/ubuntu", &a, &[("nftables", deb)], 0, &|r| other.sign(r));
    let (ok, log) = apt(&["update"]);
    assert!(!ok && (log.contains("NO_PUBKEY") || log.contains("not signed")), "{log}");
    assert!(!apt(&["download", "nftables"]).0, "{log}");

    // A package the mirror changed after its index.
    fresh();
    publish(&m, "/ubuntu", &a, &[("nftables", deb)], 0, &|r| ubuntu.sign(r));
    let (ok, log) = apt(&["update"]);
    assert!(ok && !log.contains("Err:"), "{log}");
    m.file(&format!("/ubuntu/pool/main/n/nftables/nftables_99.0_{a}.deb"), b"a changed nftables package!");
    let (ok, log) = apt(&["download", "nftables"]);
    assert!(!ok && (log.contains("mismatch") || log.contains("unexpected size")), "{log}");
    let _ = std::fs::remove_dir_all(root);
}
