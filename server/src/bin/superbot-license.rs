//! superbot-license: CG-Labs's offline tool for self-host license keys (ADR 0038). It
//! makes signing keys and signs licenses with them; botd only ever has the public halves.
//! Run it on a machine you trust, never on a SuperBot server, and keep private keys out
//! of this repository.

#[path = "../license/token.rs"]
mod token;

use std::io::{Read, Write};
use token::{Claims, Key};

const HELP: &str = "superbot-license: make and check SuperBot self-host license keys (ADR 0038).

  keygen --out <file> [--kid <id>]   Make a signing key. The private key goes to <file>
                                     (mode 600, never overwritten); the line to add to
                                     TRUSTED in server/src/license/mod.rs is printed.
  public --key <file> [--kid <id>]   Print that line again for an existing key.
  sign --key <file> --kid <id> --licensee <name> (--expires <YYYY-MM-DD> | --days <n>)
       [--seats <n>] [--edition <name>] [--feature <name>]... [--id <id>] [--starts <YYYY-MM-DD>]
                                     Print a license. It's valid through --expires (UTC).
                                     No --seats: unlimited. Edition defaults to business.
  verify (--key <file> | --public <kid>=<key>) [--at <YYYY-MM-DD>] [<license> | -]
                                     Check a license and print what it grants.

The kid defaults to cg-<year>. Keep old keys in TRUSTED until every license they signed has ended.";

type Res<T> = Result<T, String>;

struct Args(Vec<String>);

impl Args {
    /// Takes `--name <value>`. Err when it's given without a value.
    fn take(&mut self, name: &str) -> Res<Option<String>> {
        let Some(i) = self.0.iter().position(|a| a == name) else { return Ok(None) };
        if i + 1 >= self.0.len() || self.0[i + 1].starts_with("--") {
            return Err(format!("{name} needs a value"));
        }
        let v = self.0.remove(i + 1);
        self.0.remove(i);
        Ok(Some(v))
    }

    fn need(&mut self, name: &str) -> Res<String> {
        self.take(name)?.ok_or_else(|| format!("{name} is required"))
    }

    fn all(&mut self, name: &str) -> Res<Vec<String>> {
        let mut out = Vec::new();
        while let Some(v) = self.take(name)? {
            out.push(v);
        }
        Ok(out)
    }

    /// The one positional argument left, if any. Err on anything unrecognised.
    fn rest(self, max: usize) -> Res<Vec<String>> {
        if let Some(f) = self.0.iter().find(|a| a.starts_with("--") && *a != "-") {
            return Err(format!("unknown option {f}"));
        }
        if self.0.len() > max {
            return Err(format!("unexpected argument {}", self.0[max]));
        }
        Ok(self.0)
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Midnight UTC at the start of `d`, as unix seconds.
fn day(d: &str) -> Res<i64> {
    let date = chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| format!("{d}: expected a date like 2027-12-31"))?;
    Ok(date.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp())
}

fn read_key(path: &str) -> Res<aws_lc_rs::signature::Ed25519KeyPair> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    token::key_from_pem(&pem).map_err(|e| format!("{path}: {e}"))
}

fn default_kid() -> String {
    format!("cg-{}", chrono::Utc::now().format("%Y"))
}

/// Dated for people, with a random tail so licenses signed together still differ.
fn default_id() -> Res<String> {
    use aws_lc_rs::rand::SecureRandom;
    let mut tail = [0u8; 4];
    aws_lc_rs::rand::SystemRandom::new().fill(&mut tail).map_err(|_| "no randomness for the license id")?;
    let tail: String = tail.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("lic-{}-{tail}", chrono::Utc::now().format("%Y%m%d")))
}

fn key_entry(kid: &str, key: &aws_lc_rs::signature::Ed25519KeyPair) -> String {
    format!("(\"{kid}\", \"{}\"),", token::public_b64(key))
}

fn keygen(mut a: Args) -> Res<String> {
    let out = a.need("--out")?;
    let kid = a.take("--kid")?.unwrap_or_else(default_kid);
    a.rest(0)?;
    if !token::valid_kid(&kid) {
        return Err("--kid must be 1 to 32 lowercase letters, digits, or - _ .".into());
    }
    let pem = token::generate_pem()?;
    let key = token::key_from_pem(&pem)?;
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&out).map_err(|e| format!("{out}: {e}"))?
    };
    f.write_all(pem.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("{out}: {e}"))?;
    eprintln!("Private key saved to {out}. Keep it offline and backed up; never commit it.");
    eprintln!("Add this to TRUSTED in server/src/license/mod.rs:");
    Ok(key_entry(&kid, &key))
}

fn public(mut a: Args) -> Res<String> {
    let key = read_key(&a.need("--key")?)?;
    let kid = a.take("--kid")?.unwrap_or_else(default_kid);
    a.rest(0)?;
    Ok(key_entry(&kid, &key))
}

fn sign(mut a: Args) -> Res<String> {
    let key = read_key(&a.need("--key")?)?;
    let kid = a.need("--kid")?;
    let licensee = a.need("--licensee")?;
    let at = now();
    let exp = match (a.take("--expires")?, a.take("--days")?) {
        (Some(d), None) => day(&d)? + 86_400,
        (None, Some(n)) => at + n.parse::<i64>().ok().filter(|n| (1..=3660).contains(n)).ok_or("--days must be 1 to 3660")? * 86_400,
        _ => return Err("give one of --expires or --days".into()),
    };
    let seats = a.take("--seats")?.map(|s| s.parse::<u32>().ok().filter(|n| *n > 0).ok_or("--seats must be a whole number above 0")).transpose()?;
    let claims = Claims {
        iss: token::ISSUER.into(),
        aud: token::AUDIENCE.into(),
        sub: licensee,
        jti: match a.take("--id")? {
            Some(id) => id,
            None => default_id()?,
        },
        iat: at,
        nbf: a.take("--starts")?.map(|d| day(&d)).transpose()?,
        exp,
        seats,
        edition: a.take("--edition")?.unwrap_or_else(|| "business".into()),
        features: a.all("--feature")?,
    };
    a.rest(0)?;
    if exp <= at {
        return Err("that license would have ended already".into());
    }
    let t = token::sign(&key, &kid, &claims)?;
    // Our own check, as botd will make it.
    token::verify(&t, &[Key::parse(&kid, &token::public_b64(&key))?], at.max(claims.nbf.unwrap_or(at))).map_err(|e| e.text().to_string())?;
    eprintln!("{}", describe(&claims));
    Ok(t)
}

fn describe(c: &Claims) -> String {
    let date = |s: i64| chrono::DateTime::from_timestamp(s, 0).unwrap_or_default().format("%Y-%m-%d %H:%M UTC").to_string();
    format!(
        "License {} for {}: {} edition, {}, features [{}], from {} until {}.",
        c.jti,
        c.sub,
        c.edition,
        c.seats.map_or("unlimited seats".into(), |s| format!("{s} seats")),
        c.features.join(", "),
        date(c.nbf.unwrap_or(c.iat)),
        date(c.exp)
    )
}

fn verify(mut a: Args) -> Res<String> {
    let key = match (a.take("--key")?, a.take("--public")?) {
        (Some(path), None) => {
            let k = read_key(&path)?;
            (None, token::public_b64(&k))
        }
        (None, Some(p)) => {
            let (kid, public) = p.split_once('=').ok_or("--public takes <kid>=<key>")?;
            (Some(kid.to_string()), public.to_string())
        }
        _ => return Err("give one of --key or --public".into()),
    };
    let at = a.take("--at")?.map(|d| day(&d)).transpose()?.unwrap_or_else(now);
    let rest = a.rest(1)?;
    let t = match rest.first().map(String::as_str) {
        None | Some("-") => {
            let mut s = String::new();
            std::io::stdin().take(token::MAX_TOKEN as u64 + 1).read_to_string(&mut s).map_err(|e| e.to_string())?;
            s
        }
        Some(t) => t.to_string(),
    };
    // With a private key file, the token's own kid is the one to check.
    let kid = key.0.or_else(|| token::kid_of(&t)).ok_or("the license names no key")?;
    let c = token::verify(&t, &[Key::parse(&kid, &key.1)?], at).map_err(|e| e.text().to_string())?;
    let shown = serde_json::to_string_pretty(&c).map_err(|e| e.to_string())?;
    let state = if at < c.exp { "valid" } else { "ended" };
    eprintln!("{} Signature good; {state} on {}.", describe(&c), chrono::DateTime::from_timestamp(at, 0).unwrap_or_default().format("%Y-%m-%d"));
    if at >= c.exp {
        return Err("the license has ended".into());
    }
    Ok(shown)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = if args.is_empty() { String::new() } else { args.remove(0) };
    let a = Args(args);
    let res = match cmd.as_str() {
        "keygen" => keygen(a),
        "public" => public(a),
        "sign" => sign(a),
        "verify" => verify(a),
        "" | "help" | "-h" | "--help" => Ok(HELP.to_string()),
        other => Err(format!("unknown command {other}. Run superbot-license help.")),
    };
    match res {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("superbot-license: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Args {
        Args(s.iter().map(|a| a.to_string()).collect())
    }

    #[test]
    fn keygen_sign_and_verify_round_trip() {
        let dir = std::env::temp_dir().join(format!("superbot-license-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("cg.pem");
        let k = key.to_str().unwrap();
        let line = keygen(args(&["--out", k, "--kid", "cg-test"])).unwrap();
        assert!(line.starts_with("(\"cg-test\", \"") && line.ends_with("\"),"), "{line}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(keygen(args(&["--out", k])).unwrap_err().contains("exists"), "never overwrites a key");
        assert_eq!(public(args(&["--key", k, "--kid", "cg-test"])).unwrap(), line);

        let t = sign(args(&["--key", k, "--kid", "cg-test", "--licensee", "Acme Ltd", "--days", "365", "--seats", "50", "--feature", "sso", "--feature", "scim", "--id", "lic-acme-1"])).unwrap();
        let public_key = line.split('"').nth(3).unwrap();
        let shown = verify(args(&["--public", &format!("cg-test={public_key}"), &t])).unwrap();
        let c: Claims = serde_json::from_str(&shown).unwrap();
        assert_eq!((c.sub.as_str(), c.seats, c.jti.as_str(), c.edition.as_str(), c.aud.as_str()), ("Acme Ltd", Some(50), "lic-acme-1", "business", token::AUDIENCE));
        assert_eq!(c.features, ["sso", "scim"]);
        assert!(verify(args(&["--key", k, &t])).is_ok());
        // Checked as it will be on a date after it ends.
        assert!(verify(args(&["--key", k, "--at", "2999-01-01", &t])).unwrap_err().contains("ended"));
        // Through a date: valid all of that day, UTC.
        let dated = sign(args(&["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--expires", "2999-12-31"])).unwrap();
        let c: Claims = serde_json::from_str(&verify(args(&["--key", k, &dated])).unwrap()).unwrap();
        assert_eq!((c.exp, c.seats), (day("3000-01-01").unwrap(), None));
        // Signed in the same second, still two licenses.
        let again = sign(args(&["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--expires", "2999-12-31"])).unwrap();
        let c2: Claims = serde_json::from_str(&verify(args(&["--key", k, &again])).unwrap()).unwrap();
        assert!(c.jti.starts_with("lic-") && c.jti != c2.jti, "{} {}", c.jti, c2.jti);

        for bad in [
            vec!["--key", k, "--kid", "cg-test", "--licensee", "Acme"],
            vec!["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--days", "0"],
            vec!["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--days", "9", "--seats", "0"],
            vec!["--key", k, "--kid", "Not OK", "--licensee", "Acme", "--days", "9"],
            vec!["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--expires", "2001-01-01"],
            vec!["--key", k, "--kid", "cg-test", "--licensee", "Acme", "--days", "9", "--bogus"],
        ] {
            assert!(sign(args(&bad)).is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
