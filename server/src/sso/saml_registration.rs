//! What botd's SP metadata tells a federation about the service (ADR 0323), so a research and
//! education federation (InCommon, eduGAIN's) can register it and its IdPs release attributes
//! to it: a name and links for people (`mdui:UIInfo`), who runs it (`md:Organization`), whom to
//! write to (`md:ContactPerson`, the REFEDS security contact among them), a Sirtfi
//! self-assertion, and the attributes it reads (`md:RequestedAttribute`). Entity categories
//! such as Research and Scholarship are the registrar's to add: botd only says which settings
//! each still needs (`About::missing`).

use super::provider::secure_url;
use super::saml_sp::{ATTRNAME_URI, Attributes, EDU_PERSON_ASSURANCE, MDUI, escape};

/// The eduPerson attributes federations release email and display name as, which botd asks
/// for when no attribute is configured (it reads these among others).
pub const MAIL: &str = "urn:oid:0.9.2342.19200300.100.1.3";
pub const DISPLAY_NAME: &str = "urn:oid:2.16.840.1.113730.3.1.241";
/// The REFEDS security contact: a `ContactPerson` of type `other` with this `remd:contactType`.
const REMD: &str = "http://refeds.org/metadata";
pub const SECURITY_CONTACT: &str = "http://refeds.org/metadata/contactType/security";
/// The values of the assurance-certification entity attribute for Sirtfi v1 and v2.
pub const SIRTFI: &str = "https://refeds.org/sirtfi";
pub const SIRTFI2: &str = "https://refeds.org/sirtfi2";
pub const RESEARCH_AND_SCHOLARSHIP: &str = "http://refeds.org/category/research-and-scholarship";
pub const CODE_OF_CONDUCT: &str = "https://refeds.org/category/code-of-conduct/v2";

/// The longest display name and organization name, and description, in characters.
pub const MAX_NAME: usize = 100;
pub const MAX_DESCRIPTION: usize = 500;
const MAX_URL: usize = 2048;

/// How a native provider's SP metadata describes SuperBot. Nothing is published that isn't set,
/// so metadata with none of it set is as before.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct About {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub information_url: Option<String>,
    pub privacy_url: Option<String>,
    pub organization: Option<Organization>,
    /// At most one of each type, in `ContactType::ALL`'s order.
    pub contacts: Vec<Contact>,
    pub sirtfi: Sirtfi,
    /// Published, with the display name as the service's name, only when that is set.
    pub requested: Vec<Requested>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Organization {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContactType {
    Technical,
    Support,
    Administrative,
    Security,
}

impl ContactType {
    pub const ALL: [ContactType; 4] = [ContactType::Technical, ContactType::Support, ContactType::Administrative, ContactType::Security];

    pub fn as_str(self) -> &'static str {
        match self {
            ContactType::Technical => "technical",
            ContactType::Support => "support",
            ContactType::Administrative => "administrative",
            ContactType::Security => "security",
        }
    }

    /// The setting, without `SSO_<ID>_`.
    pub fn setting(self) -> &'static str {
        match self {
            ContactType::Technical => "SP_CONTACT_TECHNICAL",
            ContactType::Support => "SP_CONTACT_SUPPORT",
            ContactType::Administrative => "SP_CONTACT_ADMINISTRATIVE",
            ContactType::Security => "SP_CONTACT_SECURITY",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Contact {
    pub kind: ContactType,
    pub name: Option<String>,
    pub email: String,
}

/// `SSO_<ID>_SP_SIRTFI`: whoever runs SuperBot attests to the Sirtfi framework, v1 or v2.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Sirtfi {
    #[default]
    Off,
    V1,
    V2,
}

impl Sirtfi {
    pub fn parse(s: &str) -> Option<Sirtfi> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(Sirtfi::Off),
            "v1" => Some(Sirtfi::V1),
            "v2" => Some(Sirtfi::V2),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Sirtfi::Off => "off",
            Sirtfi::V1 => "v1",
            Sirtfi::V2 => "v2",
        }
    }

    /// The assurance-certification values published. Sirtfi v2 implies v1, and REFEDS says an
    /// entity with v2's value must have v1's too.
    pub fn values(self) -> &'static [&'static str] {
        match self {
            Sirtfi::Off => &[],
            Sirtfi::V1 => &[SIRTFI],
            Sirtfi::V2 => &[SIRTFI2, SIRTFI],
        }
    }
}

/// An attribute botd reads, as our metadata asks for it. `required`: sign-in fails without it.
#[derive(Clone, Debug, PartialEq)]
pub struct Requested {
    pub name: String,
    pub friendly: Option<&'static str>,
    pub required: bool,
}

/// What botd reads from assertions: the email (required when only listed domains get in), the
/// display name, the groups and authentication methods attributes when named (groups
/// required with `REQUIRED_GROUPS`), and the assurance attribute, required, when identity
/// assurance is (ADR 0328). A subject identifier is asked for by `subject-id:req`
/// instead, as the profile says.
pub fn requested(attributes: &Attributes, email_required: bool, groups_required: bool) -> Vec<Requested> {
    let named = |a: &Option<String>, default: &str, friendly: &'static str, required: bool| match a {
        Some(n) => Requested { name: n.clone(), friendly: None, required },
        None => Requested { name: default.into(), friendly: Some(friendly), required },
    };
    let mut out = vec![named(&attributes.email, MAIL, "mail", email_required), named(&attributes.name, DISPLAY_NAME, "displayName", false)];
    out.extend(attributes.groups.iter().map(|g| Requested { name: g.clone(), friendly: None, required: groups_required }));
    out.extend(attributes.authn_methods.iter().map(|m| Requested { name: m.clone(), friendly: None, required: false }));
    // Read only when identity assurance is required (ADR 0328), so sign-in fails without it.
    out.extend(attributes.assurance.iter().map(|a| Requested { name: a.clone(), friendly: (a == EDU_PERSON_ASSURANCE).then_some("eduPersonAssurance"), required: true }));
    out
}

/// Text people read in a federation's listings and an IdP's consent page: trimmed, at most
/// `max` characters, no control characters.
pub fn text(raw: &str, max: usize) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() || t.chars().count() > max || t.chars().any(char::is_control) {
        return Err(format!("must be text of at most {max} characters, on one line"));
    }
    Ok(t.to_string())
}

/// A page people open from a listing: an https URL. Not `http://localhost` as `secure_url`
/// allows: the link is opened on other people's machines.
pub fn link(raw: &str) -> Result<String, String> {
    let u = raw.trim();
    if u.len() > MAX_URL || !u.starts_with("https://") || !secure_url(u) {
        return Err("must be an https URL".into());
    }
    Ok(u.to_string())
}

/// A contact, as `Name <email>` or a bare email. A `mailto:` before the email is dropped: the
/// metadata adds its own.
pub fn contact(kind: ContactType, raw: &str) -> Result<Contact, String> {
    let raw = raw.trim();
    let (name, email) = match raw.strip_suffix('>').and_then(|r| r.rsplit_once('<')) {
        Some((name, email)) => (Some(text(name, MAX_NAME).map_err(|_| "the name before <email> must be text of at most 100 characters".to_string())?), email.trim()),
        None => (None, raw),
    };
    let email = email.strip_prefix("mailto:").unwrap_or(email);
    if !crate::users::valid_email(email) || email.contains(['<', '>']) || name.as_deref().is_some_and(|n| n.contains(['<', '>'])) {
        return Err("must be an email, or Name <email>, like Platform Team <platform@example.com>".into());
    }
    // REFEDS: GivenName and EmailAddress are mandatory for a security contact.
    if kind == ContactType::Security && name.is_none() {
        return Err("needs a name, like Security Team <security@example.com>: a REFEDS security contact has one".into());
    }
    Ok(Contact { kind, name, email: email.to_string() })
}

/// The categories a federation's registrar can add, and their names.
pub const CATEGORIES: [(&str, &str); 2] = [(RESEARCH_AND_SCHOLARSHIP, "Research and Scholarship"), (CODE_OF_CONDUCT, "Code of Conduct v2")];

impl About {
    /// The settings (without `SSO_<ID>_`) still to set before applying for `category`, from
    /// what its specification says an SP's metadata must have. `posts`: the ACS takes
    /// HTTP-POST, which R&S requires.
    pub fn missing(&self, category: &str, posts: bool) -> Vec<&'static str> {
        let has_contact = |k: ContactType| self.contacts.iter().any(|c| c.kind == k);
        let needs: Vec<(&'static str, bool)> = match category {
            RESEARCH_AND_SCHOLARSHIP => vec![
                ("SP_DISPLAY_NAME", self.display_name.is_some()),
                ("SP_INFORMATION_URL", self.information_url.is_some()),
                ("SP_CONTACT_TECHNICAL", has_contact(ContactType::Technical)),
                ("RESPONSE_BINDING=post", posts),
            ],
            CODE_OF_CONDUCT => vec![("SP_DISPLAY_NAME", self.display_name.is_some()), ("SP_DESCRIPTION", self.description.is_some()), ("SP_PRIVACY_URL", self.privacy_url.is_some())],
            _ => vec![],
        };
        needs.into_iter().filter(|(_, met)| !met).map(|(s, _)| s).collect()
    }

    /// Entity attributes for the `EntityDescriptor`'s `mdattr:EntityAttributes`: Sirtfi.
    pub(super) fn entity_attributes(&self) -> String {
        let values = self.sirtfi.values();
        if values.is_empty() {
            return String::new();
        }
        let values: String = values.iter().map(|v| format!("<saml:AttributeValue>{v}</saml:AttributeValue>")).collect();
        format!(
            r#"<saml:Attribute xmlns:saml="{}" Name="{}" NameFormat="{ATTRNAME_URI}">{values}</saml:Attribute>"#,
            super::saml_sp::ASSERTION,
            super::saml_sp::ASSURANCE_CERTIFICATION
        )
    }

    /// `mdui:UIInfo` for the SP role's `Extensions`, in English.
    pub(super) fn ui_info(&self) -> String {
        let Some(name) = &self.display_name else { return String::new() };
        let mut ui = format!(r#"<mdui:DisplayName xml:lang="en">{}</mdui:DisplayName>"#, escape(name));
        for (tag, v) in [("Description", &self.description), ("InformationURL", &self.information_url), ("PrivacyStatementURL", &self.privacy_url)] {
            if let Some(v) = v {
                ui += &format!(r#"<mdui:{tag} xml:lang="en">{}</mdui:{tag}>"#, escape(v));
            }
        }
        format!(r#"<mdui:UIInfo xmlns:mdui="{MDUI}">{ui}</mdui:UIInfo>"#)
    }

    /// The `AttributeConsumingService`, last in the SP role, named by the display name.
    pub(super) fn attribute_consuming_service(&self) -> String {
        let Some(name) = self.display_name.as_ref().filter(|_| !self.requested.is_empty()) else { return String::new() };
        let mut out = format!("\n    <md:AttributeConsumingService index=\"0\" isDefault=\"true\"><md:ServiceName xml:lang=\"en\">{}</md:ServiceName>", escape(name));
        for r in &self.requested {
            let friendly = r.friendly.map(|f| format!(r#" FriendlyName="{f}""#)).unwrap_or_default();
            // A URI or URN says what it is; a short name (Okta's email) has no format to name.
            let format = if r.name.contains(':') { format!(r#" NameFormat="{ATTRNAME_URI}""#) } else { String::new() };
            out += &format!(r#"<md:RequestedAttribute{friendly} Name="{}"{format} isRequired="{}"/>"#, escape(&r.name), r.required);
        }
        out + "</md:AttributeConsumingService>"
    }

    /// `md:Organization` and the `md:ContactPerson`s, after the role, as the schema orders them.
    pub(super) fn organization_and_contacts(&self) -> String {
        let mut out = String::new();
        if let Some(o) = &self.organization {
            let (name, url) = (escape(&o.name), escape(&o.url));
            out += &format!(
                r#"
  <md:Organization><md:OrganizationName xml:lang="en">{name}</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">{name}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">{url}</md:OrganizationURL></md:Organization>"#
            );
        }
        for c in &self.contacts {
            let open = match c.kind {
                ContactType::Security => format!(r#"<md:ContactPerson xmlns:remd="{REMD}" contactType="other" remd:contactType="{SECURITY_CONTACT}">"#),
                k => format!(r#"<md:ContactPerson contactType="{}">"#, k.as_str()),
            };
            let name = c.name.as_ref().map(|n| format!("<md:GivenName>{}</md:GivenName>", escape(n))).unwrap_or_default();
            out += &format!("\n  {open}{name}<md:EmailAddress>mailto:{}</md:EmailAddress></md:ContactPerson>", escape(&c.email));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_contacts_as_an_email_or_a_name_and_email() {
        let c = contact(ContactType::Technical, " Platform Team <platform@example.com> ").unwrap();
        assert_eq!((c.name.as_deref(), c.email.as_str()), (Some("Platform Team"), "platform@example.com"));
        let c = contact(ContactType::Support, "mailto:help@example.com").unwrap();
        assert_eq!((c.name, c.email.as_str()), (None, "help@example.com"), "mailto: is the metadata's to add");
        assert_eq!(contact(ContactType::Security, "CSIRT <mailto:csirt@example.com>").unwrap().email, "csirt@example.com");
        assert!(contact(ContactType::Security, "csirt@example.com").unwrap_err().contains("needs a name"), "REFEDS: GivenName is mandatory");
        for bad in ["not an email", "<a@example.com>", "Ops <ops>", "Ops <a@b.example> <c@d.example>", "A\u{7}B <a@example.com>", "a@example.com>"] {
            assert!(contact(ContactType::Technical, bad).is_err(), "{bad}");
        }
        let long = format!("{} <a@example.com>", "x".repeat(MAX_NAME + 1));
        assert!(contact(ContactType::Technical, &long).is_err());
    }

    #[test]
    fn text_and_links_are_checked() {
        assert_eq!(text("  SuperBot at Uni A ", MAX_NAME).unwrap(), "SuperBot at Uni A");
        assert_eq!(text(&"é".repeat(MAX_NAME), MAX_NAME).unwrap().chars().count(), MAX_NAME, "characters, not bytes");
        for bad in ["", "  ", "two\nlines"] {
            assert!(text(bad, MAX_NAME).is_err(), "{bad:?}");
        }
        assert!(text(&"x".repeat(MAX_NAME + 1), MAX_NAME).is_err());
        assert_eq!(link(" https://superbot.example.edu/privacy ").unwrap(), "https://superbot.example.edu/privacy");
        for bad in ["http://superbot.example.edu/", "http://localhost/privacy", "http://127.0.0.1:8080/", "superbot.example.edu", "javascript:alert(1)", ""] {
            assert!(link(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn asks_for_the_attributes_botd_reads() {
        let names = |r: &[Requested]| r.iter().map(|r| (r.name.clone(), r.friendly, r.required)).collect::<Vec<_>>();
        let plain = requested(&Attributes::default(), false, false);
        assert_eq!(names(&plain), [(MAIL.to_string(), Some("mail"), false), (DISPLAY_NAME.to_string(), Some("displayName"), false)]);
        let named = Attributes { email: Some("email".into()), name: None, groups: Some("groups".into()), authn_methods: Some("http://schemas.microsoft.com/claims/authnmethodsreferences".into()), ..Attributes::default() };
        assert_eq!(
            names(&requested(&named, true, true)),
            [
                ("email".to_string(), None, true),
                (DISPLAY_NAME.to_string(), Some("displayName"), false),
                ("groups".to_string(), None, true),
                ("http://schemas.microsoft.com/claims/authnmethodsreferences".to_string(), None, false)
            ],
            "the configured names, required when sign-in needs them"
        );
        let assured = |a: &str| requested(&Attributes { assurance: Some(a.into()), ..Attributes::default() }, false, false).pop().map(|r| (r.name, r.friendly, r.required));
        assert_eq!(assured(EDU_PERSON_ASSURANCE), Some((EDU_PERSON_ASSURANCE.to_string(), Some("eduPersonAssurance"), true)), "required: sign-in needs it");
        assert_eq!(assured("assurance"), Some(("assurance".to_string(), None, true)));
    }

    #[test]
    fn says_what_each_category_still_needs() {
        let mut a = About::default();
        assert_eq!(a.missing(RESEARCH_AND_SCHOLARSHIP, true), ["SP_DISPLAY_NAME", "SP_INFORMATION_URL", "SP_CONTACT_TECHNICAL"]);
        assert_eq!(a.missing(CODE_OF_CONDUCT, true), ["SP_DISPLAY_NAME", "SP_DESCRIPTION", "SP_PRIVACY_URL"]);
        a.display_name = Some("SuperBot".into());
        a.information_url = Some("https://superbot.example.edu/".into());
        a.contacts.push(Contact { kind: ContactType::Technical, name: None, email: "ops@example.edu".into() });
        assert!(a.missing(RESEARCH_AND_SCHOLARSHIP, true).is_empty());
        assert_eq!(a.missing(RESEARCH_AND_SCHOLARSHIP, false), ["RESPONSE_BINDING=post"], "R&S needs the HTTP-POST binding");
        a.description = Some("AI teammates".into());
        a.privacy_url = Some("https://superbot.example.edu/privacy".into());
        assert!(a.missing(CODE_OF_CONDUCT, false).is_empty());
        assert!(a.missing("https://example.org/other", true).is_empty());
    }

    #[test]
    fn sirtfi_v2_also_asserts_v1() {
        assert_eq!(Sirtfi::V2.values(), [SIRTFI2, SIRTFI]);
        assert_eq!(Sirtfi::V1.values(), [SIRTFI]);
        assert!(Sirtfi::Off.values().is_empty() && About::default().entity_attributes().is_empty());
        assert_eq!(Sirtfi::parse("V2"), Some(Sirtfi::V2));
        assert_eq!(Sirtfi::parse("yes"), None);
    }

    #[test]
    fn writes_nothing_when_nothing_is_set() {
        let a = About { requested: requested(&Attributes::default(), false, false), ..About::default() };
        assert_eq!((a.ui_info(), a.attribute_consuming_service(), a.organization_and_contacts(), a.entity_attributes()), (String::new(), String::new(), String::new(), String::new()));
    }
}
