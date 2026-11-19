//! Secrets from the environment: `NAME`, or `NAME_FILE` naming a file that holds the
//! value (Docker and Kubernetes secrets, systemd credentials). Read-only. An empty
//! value counts as unset, like the rest of botd's settings.

use super::{redact, Error, Secret, SecretStore};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// The process environment, or a fixed set of variables (tests).
pub struct EnvStore(Option<HashMap<String, String>>);

impl EnvStore {
    pub const fn process() -> EnvStore {
        EnvStore(None)
    }

    #[cfg(test)]
    pub fn fixed(vars: &[(&str, &str)]) -> EnvStore {
        EnvStore(Some(vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()))
    }

    fn var(&self, k: &str) -> Option<String> {
        match &self.0 {
            Some(vars) => vars.get(k).cloned(),
            None => std::env::var(k).ok(),
        }
        .filter(|v| !v.is_empty())
    }

    fn keys(&self) -> Vec<String> {
        match &self.0 {
            Some(vars) => vars.keys().cloned().collect(),
            None => std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect(),
        }
    }
}

impl SecretStore for EnvStore {
    fn kind(&self) -> &'static str {
        "env"
    }

    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        let file_var = format!("{name}_FILE");
        match (self.var(name), self.var(&file_var)) {
            (Some(_), Some(_)) => Err(Error::Invalid(format!("Set {name} or {file_var}, not both."))),
            (Some(v), None) => Ok(Some(Secret::new(v))),
            (None, Some(path)) => {
                let text = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| Error::Store(format!("{file_var} ({path}): {e}")))?);
                // Files usually end with a newline that isn't part of the secret.
                let v = text.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&text);
                Ok((!v.is_empty()).then(|| Secret::new(v)))
            }
            (None, None) => Ok(None),
        }
    }

    /// Set variables whose names look like secrets (`*_API_KEY`, `*_TOKEN`, ...), with or without `_FILE`.
    fn names(&self) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = self
            .keys()
            .into_iter()
            .filter(|k| self.var(k).is_some())
            .map(|k| k.strip_suffix("_FILE").map(String::from).unwrap_or(k))
            .filter(|k| redact::looks_secret(k))
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_file_values() {
        let f = crate::db::temp_path("env").join("secret");
        std::fs::write(&f, "from-file\r\n").unwrap();
        let f = f.to_str().unwrap();
        let env = EnvStore::fixed(&[
            ("A_TOKEN", "value-1"),
            ("B_TOKEN_FILE", f),
            ("C_TOKEN", "x"),
            ("C_TOKEN_FILE", f),
            ("D_TOKEN", ""),
            ("E_TOKEN_FILE", "/nonexistent/superbot-secret"),
            ("TZ", "UTC"),
        ]);
        assert_eq!(env.get("A_TOKEN").unwrap().unwrap().expose(), "value-1");
        assert_eq!(env.get("B_TOKEN").unwrap().unwrap().expose(), "from-file");
        assert!(matches!(env.get("C_TOKEN"), Err(Error::Invalid(_))));
        assert!(env.get("D_TOKEN").unwrap().is_none());
        assert!(matches!(env.get("E_TOKEN"), Err(Error::Store(_))));
        assert!(env.get("NOPE").unwrap().is_none());
        assert_eq!(env.names().unwrap(), ["A_TOKEN", "B_TOKEN", "C_TOKEN", "E_TOKEN"]);
    }
}
