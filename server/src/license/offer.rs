//! The licensed self-host plan as buyers see it (ADR 0348): botd's `/pricing` and
//! `/api/plans`, and the public site's plans, say it in these words. No dependencies, so
//! `superbot-site` and `superbot-license` include it with `#[path]`. Every line is
//! something a license gives today (ADR 0038, ADR 0068); prices are never here.

pub const LABEL: &str = "Self-host";

/// The edition `superbot-license sign` writes when none is given.
pub const EDITION: &str = "business";

/// How a license counts people (ADR 0038's seats).
pub const SEATS: &str = "Per seat: one for each active person, none for the owner account";

/// What a license includes, in order.
pub const INCLUDES: &[&str] = &[
    "Your servers and your data, even air-gapped",
    "Every feature in the open source code",
    "Single sign-on, SCIM, approvals and audit",
    "A license key checked offline",
];

/// The kind line above the plan's name.
pub fn kind() -> String {
    format!("Licensed, {EDITION} edition")
}
