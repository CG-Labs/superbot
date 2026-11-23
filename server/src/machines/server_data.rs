//! botd's own data region (ADR 0184). A residency pin (ADR 0129) holds a person's machine
//! and its backups; botd's own database (accounts, chats, routines, the audit log), its
//! files and the server's backups are wherever the operator runs botd. The operator says
//! which data region that is with SERVER_DATA_REGION, and where server backups' off-host
//! copies (ADR 0109) go with SERVER_BACKUP_S3_DATA_REGION, or MACHINE_BACKUP_S3_DATA_REGION
//! when they go to the machine backups' store. botd can't see where its own disk is, so
//! this is the operator's word, as a host's INCUS_REGION tag is.
//!
//! With RESIDENCY_SERVER_DATA=report (the default) it is only shown: residency reports, the
//! app and `GET /api/regions` say whether botd's own data is in a pin's region. With
//! `require`, every pin is held to it: botd won't start unless the region is stated and
//! server backups' off-host store is in it, a pin to another region is refused, and one
//! made elsewhere before is a pin botd can't keep (warned about, or with
//! RESIDENCY_STARTUP=refuse, botd won't start).

use crate::audit::clip;
use crate::runner::App;
use crate::server_backups::Source;
use serde_json::{Value, json};

/// RESIDENCY_SERVER_DATA: whether pins are held to botd's own data region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    Report,
    Require,
}

impl Policy {
    pub fn parse(v: &str) -> Result<Policy, String> {
        match v.trim().to_ascii_lowercase().as_str() {
            "" | "report" => Ok(Policy::Report),
            "require" => Ok(Policy::Require),
            v => Err(format!("RESIDENCY_SERVER_DATA must be report or require, not \"{}\"", clip(v, 20))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Report => "report",
            Policy::Require => "require",
        }
    }
}

/// Where server backups are kept besides botd's host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Copies {
    /// Nowhere: archives stay in BACKUP_DIR, on botd's host.
    #[default]
    OnHost,
    /// Copied to a store said (by `setting`) to be in `region`, or in none.
    Store { setting: &'static str, region: Option<String> },
}

#[derive(Clone, Debug, Default)]
pub struct ServerData {
    /// SERVER_DATA_REGION. None: not stated.
    pub region: Option<String>,
    pub copies: Copies,
    /// Where copies go now (`server_backups::Target::destination`), to tell copies made
    /// to another store before. Never shown: it names the endpoint and bucket.
    pub destination: Option<String>,
    pub policy: Policy,
}

impl ServerData {
    /// SERVER_DATA_REGION, SERVER_BACKUP_S3_DATA_REGION (or MACHINE_BACKUP_S3_DATA_REGION
    /// for copies in the machine backups' store) and RESIDENCY_SERVER_DATA. `regions`:
    /// MACHINE_REGIONS, which each region must be one of when there are any. `off_host`:
    /// which settings name the store server backups are copied to, and where in it.
    pub fn from_env(var: &dyn Fn(&str) -> String, regions: &[String], off_host: Option<(Source, String)>) -> Result<ServerData, String> {
        let region_of = |name: &str| -> Result<Option<String>, String> {
            let raw = var(name);
            let r = raw.trim();
            if r.is_empty() {
                return Ok(None);
            }
            if !super::slug(r, 32) {
                return Err(format!("{name}: \"{}\" isn't a region id", clip(r, 32)));
            }
            if !regions.is_empty() && !regions.iter().any(|x| x == r) {
                return Err(format!("{name}: \"{r}\" isn't one of MACHINE_REGIONS ({})", regions.join(", ")));
            }
            Ok(Some(r.to_string()))
        };
        let region = region_of("SERVER_DATA_REGION")?;
        let own = region_of("SERVER_BACKUP_S3_DATA_REGION")?;
        if own.is_some() && var("SERVER_BACKUP_S3_BUCKET").trim().is_empty() {
            return Err("SERVER_BACKUP_S3_DATA_REGION is set but SERVER_BACKUP_S3_BUCKET isn't; copies in the machine backups' store are in MACHINE_BACKUP_S3_DATA_REGION".into());
        }
        let (copies, destination) = match off_host {
            None => (Copies::OnHost, None),
            Some((Source::Own, dest)) => (Copies::Store { setting: "SERVER_BACKUP_S3_DATA_REGION", region: own }, Some(dest)),
            Some((Source::Machines, dest)) => (Copies::Store { setting: "MACHINE_BACKUP_S3_DATA_REGION", region: region_of("MACHINE_BACKUP_S3_DATA_REGION")? }, Some(dest)),
        };
        let policy = Policy::parse(&var("RESIDENCY_SERVER_DATA"))?;
        let sd = ServerData { region, copies, destination, policy };
        if policy == Policy::Require {
            let Some(r) = sd.region.as_deref() else {
                return Err("RESIDENCY_SERVER_DATA=require needs SERVER_DATA_REGION: the data region botd's own database and files are in".into());
            };
            if let Some(why) = sd.copies_outside(r) {
                return Err(format!("RESIDENCY_SERVER_DATA=require, but {why}; botd's own data is in {r}"));
            }
        }
        Ok(sd)
    }

    /// Why server backups' off-host copies aren't in `region`. None: they are, or there are none.
    fn copies_outside(&self, region: &str) -> Option<String> {
        match &self.copies {
            Copies::OnHost => None,
            Copies::Store { region: Some(r), .. } if r == region => None,
            Copies::Store { setting, region: Some(r) } => Some(format!("server backups are copied off the host to a store in {r} ({setting})")),
            Copies::Store { setting, region: None } => Some(format!("server backups are copied off the host to a store that isn't said to be in any region ({setting})")),
        }
    }

    /// Whether server backups' off-host copies, if any, are in `region`.
    pub fn backups_in(&self, region: &str) -> bool {
        self.copies_outside(region).is_none()
    }

    /// Why botd's own data isn't in `region`, as the operator states it. Empty: it is.
    pub fn outside(&self, region: &str) -> Vec<String> {
        let mut out = Vec::new();
        match self.region.as_deref() {
            None => out.push("botd's own data region isn't stated (SERVER_DATA_REGION)".to_string()),
            Some(r) if r != region => out.push(format!("botd's own database and files are in {r}")),
            Some(_) => {}
        }
        out.extend(self.copies_outside(region));
        out
    }

    /// Why a pin to `region` can't be kept for botd's own data, under `require` only.
    pub fn refuses(&self, region: &str) -> Vec<String> {
        match self.policy {
            Policy::Require => self.outside(region),
            Policy::Report => Vec::new(),
        }
    }

    /// Server backup copies botd made to a store it no longer copies to, not known to be
    /// deleted. botd neither deletes them nor knows their region.
    pub fn earlier_copies(&self, app: &App) -> i64 {
        app.db.server_backups_done_elsewhere(self.destination.as_deref())
    }

    /// For the startup log.
    pub fn describe(&self) -> String {
        let copies = match &self.copies {
            Copies::OnHost => "kept on this host".to_string(),
            Copies::Store { region: Some(r), .. } => format!("copied to a store in {r}"),
            Copies::Store { setting, region: None } => format!("copied to a store in no stated region ({setting})"),
        };
        format!(
            "{}; server backups {copies}; RESIDENCY_SERVER_DATA={}",
            self.region.as_deref().map_or("not stated (SERVER_DATA_REGION)".to_string(), |r| format!("in {r}")),
            self.policy.as_str()
        )
    }

    fn backups_view(&self) -> Value {
        match &self.copies {
            Copies::OnHost => json!({ "offHost": false, "setting": null, "region": null }),
            Copies::Store { setting, region } => json!({ "offHost": true, "setting": setting, "region": region }),
        }
    }

    /// For `GET /api/regions`: the region, the copies' store and the policy.
    pub fn summary(&self, app: &App) -> Value {
        json!({ "region": self.region, "backups": self.backups_view(), "earlierCopies": self.earlier_copies(app), "policy": self.policy.as_str() })
    }

    /// Against a pin to `region`: whether botd's own data is in it and, if not, why.
    pub fn against(&self, app: &App, region: &str) -> Value {
        let outside = self.outside(region);
        json!({
            "region": self.region, "backups": self.backups_view(), "policy": self.policy.as_str(),
            "inRegion": outside.is_empty(), "outside": outside, "earlierCopies": self.earlier_copies(app),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with(pairs: &[(&str, &str)], off_host: Option<Source>) -> Result<ServerData, String> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let regions = vec!["gb-lon".to_string(), "de-fra-2".to_string()];
        ServerData::from_env(&|k| env.get(k).cloned().unwrap_or_default(), &regions, off_host.map(|s| (s, "https://s3/b/server/".to_string())))
    }

    #[test]
    fn residency_server_data_is_report_unless_set_to_require() {
        assert_eq!(Policy::parse(""), Ok(Policy::Report));
        assert_eq!(Policy::parse(" Require "), Ok(Policy::Require));
        assert!(Policy::parse("strict").unwrap_err().contains("must be report or require, not \"strict\""));
        assert_eq!(Policy::default().as_str(), "report");
    }

    #[test]
    fn regions_are_checked_against_machine_regions_and_need_the_store_they_describe() {
        let sd = with(&[], None).unwrap();
        assert_eq!((sd.region, sd.copies, sd.policy), (None, Copies::OnHost, Policy::Report));
        assert!(with(&[("SERVER_DATA_REGION", "us-east")], None).unwrap_err().contains("isn't one of MACHINE_REGIONS (gb-lon, de-fra-2)"));
        assert!(with(&[("SERVER_DATA_REGION", "GB LON")], None).unwrap_err().contains("isn't a region id"));
        assert!(with(&[("SERVER_BACKUP_S3_DATA_REGION", "gb-lon")], None).unwrap_err().contains("SERVER_BACKUP_S3_BUCKET isn't"));
        let own = [("SERVER_BACKUP_S3_BUCKET", "b"), ("SERVER_BACKUP_S3_DATA_REGION", "gb-lon"), ("MACHINE_BACKUP_S3_DATA_REGION", "de-fra-2")];
        let sd = with(&own, Some(Source::Own)).unwrap();
        assert_eq!(sd.copies, Copies::Store { setting: "SERVER_BACKUP_S3_DATA_REGION", region: Some("gb-lon".into()) });
        assert_eq!(sd.destination.as_deref(), Some("https://s3/b/server/"));
        let sd = with(&own, Some(Source::Machines)).unwrap();
        assert_eq!(sd.copies, Copies::Store { setting: "MACHINE_BACKUP_S3_DATA_REGION", region: Some("de-fra-2".into()) }, "the machine backups' store says where it is");
        let sd = with(&own, None).unwrap();
        assert_eq!((sd.copies, sd.destination), (Copies::OnHost, None), "SERVER_BACKUP_OFF_HOST=off copies nothing");
    }

    #[test]
    fn botds_own_data_is_in_a_region_once_its_database_and_backup_copies_are() {
        let sd = with(&[], None).unwrap();
        assert_eq!(sd.outside("gb-lon"), vec!["botd's own data region isn't stated (SERVER_DATA_REGION)"]);
        let sd = with(&[("SERVER_DATA_REGION", "gb-lon")], None).unwrap();
        assert!(sd.outside("gb-lon").is_empty(), "archives on botd's host are where botd is");
        assert_eq!(sd.outside("de-fra-2"), vec!["botd's own database and files are in gb-lon"]);
        let sd = with(&[("SERVER_DATA_REGION", "gb-lon"), ("SERVER_BACKUP_S3_BUCKET", "b")], Some(Source::Own)).unwrap();
        assert_eq!(sd.outside("gb-lon"), vec!["server backups are copied off the host to a store that isn't said to be in any region (SERVER_BACKUP_S3_DATA_REGION)"]);
        let sd = with(&[("SERVER_DATA_REGION", "gb-lon"), ("MACHINE_BACKUP_S3_DATA_REGION", "de-fra-2")], Some(Source::Machines)).unwrap();
        assert_eq!(sd.outside("gb-lon"), vec!["server backups are copied off the host to a store in de-fra-2 (MACHINE_BACKUP_S3_DATA_REGION)"]);
        assert!(sd.refuses("gb-lon").is_empty() && sd.refuses("de-fra-2").is_empty(), "report only shows, never refuses");
        assert!(!sd.backups_in("gb-lon") && sd.backups_in("de-fra-2"), "botd's region can match while its backups are elsewhere");
        assert!(with(&[], None).unwrap().backups_in("gb-lon"), "archives kept on botd's host are where botd is");
    }

    #[test]
    fn require_needs_the_region_stated_and_backup_copies_in_it() {
        assert!(with(&[("RESIDENCY_SERVER_DATA", "require")], None).unwrap_err().contains("needs SERVER_DATA_REGION"));
        let e = with(&[("RESIDENCY_SERVER_DATA", "require"), ("SERVER_DATA_REGION", "gb-lon"), ("SERVER_BACKUP_S3_BUCKET", "b")], Some(Source::Own)).unwrap_err();
        assert!(e.contains("isn't said to be in any region (SERVER_BACKUP_S3_DATA_REGION); botd's own data is in gb-lon"), "{e}");
        let e = with(&[("RESIDENCY_SERVER_DATA", "require"), ("SERVER_DATA_REGION", "gb-lon"), ("MACHINE_BACKUP_S3_DATA_REGION", "de-fra-2")], Some(Source::Machines)).unwrap_err();
        assert!(e.contains("a store in de-fra-2 (MACHINE_BACKUP_S3_DATA_REGION)"), "{e}");
        let sd = with(&[("RESIDENCY_SERVER_DATA", "require"), ("SERVER_DATA_REGION", "gb-lon"), ("SERVER_BACKUP_S3_BUCKET", "b"), ("SERVER_BACKUP_S3_DATA_REGION", "gb-lon")], Some(Source::Own)).unwrap();
        assert!(sd.refuses("gb-lon").is_empty());
        assert_eq!(sd.refuses("de-fra-2"), vec!["botd's own database and files are in gb-lon", "server backups are copied off the host to a store in gb-lon (SERVER_BACKUP_S3_DATA_REGION)"]);
        assert!(sd.describe().contains("in gb-lon; server backups copied to a store in gb-lon; RESIDENCY_SERVER_DATA=require"), "{}", sd.describe());
    }
}
