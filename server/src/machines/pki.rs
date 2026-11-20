//! Certificates and mutual TLS between the control plane and each user's machine
//! (ADR 0031). Shared by botd and the machine agent (`superbot-machine`), so it uses
//! nothing else of botd's.
//!
//! One CA signs every certificate. Its Ed25519 key is derived from botd's master key
//! (ADR 0010), so it lives where that key does, never in DATA_DIR or a backup, and its
//! certificate is byte-for-byte the same on every start. Identities are URIs in the
//! subject alt name: `spiffe://superbot/control-plane` for botd, and
//! `spiffe://superbot/user/<user>/machine/<machine>` for a machine.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub const CONTROL_PLANE_URI: &str = "spiffe://superbot/control-plane";
const USER_PREFIX: &str = "spiffe://superbot/user/";

pub fn machine_uri(user_id: &str, machine_id: &str) -> String {
    format!("{USER_PREFIX}{user_id}/machine/{machine_id}")
}

fn id_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `(user, machine)` from a machine's URI.
pub fn parse_machine_uri(uri: &str) -> Option<(String, String)> {
    let (user, machine) = uri.strip_prefix(USER_PREFIX)?.split_once("/machine/")?;
    (id_like(user) && id_like(machine)).then(|| (user.into(), machine.into()))
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

/// SHA-256 of a certificate's DER, in hex: how botd pins and looks up a certificate.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a certificate says about itself. Times are unix ms.
#[derive(Clone, Debug, PartialEq)]
pub struct Facts {
    pub uris: Vec<String>,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    /// The certified public key (SubjectPublicKeyInfo, DER).
    pub spki: Vec<u8>,
}

pub fn facts(der: &[u8]) -> Option<Facts> {
    use x509_parser::extensions::GeneralName;
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let uris = c
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Facts {
        uris,
        serial: c.raw_serial().iter().map(|b| format!("{b:02x}")).collect(),
        not_before: c.validity().not_before.timestamp() * 1000,
        not_after: c.validity().not_after.timestamp() * 1000,
        spki: c.public_key().raw.to_vec(),
    })
}

/// The first certificate in a PEM text.
pub fn cert_der(pem: &str) -> Result<CertificateDer<'static>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| "not a PEM certificate".to_string())
}

pub fn key_der(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| "not a PEM private key".to_string())
}

/// A certificate as issued: what botd stores and the machine keeps.
#[derive(Clone, Debug)]
pub struct Issued {
    pub pem: String,
    pub fingerprint: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
}

fn issued(cert: &rcgen::Certificate) -> Result<Issued, String> {
    let f = facts(cert.der()).ok_or("the new certificate doesn't parse")?;
    Ok(Issued {
        pem: cert.pem(),
        fingerprint: fingerprint(cert.der()),
        serial: f.serial,
        not_before: f.not_before,
        not_after: f.not_after,
    })
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::OrganizationName, "SuperBot");
    d.push(DnType::CommonName, cn);
    d
}

fn serial() -> SerialNumber {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).expect("system randomness");
    b[0] &= 0x7f;
    b[0] |= 0x01;
    SerialNumber::from_slice(&b)
}

/// A leaf certificate's settings: valid from a few minutes ago (clock skew) for `days`.
fn leaf(cn: &str, days: i64) -> CertificateParams {
    let now = time::OffsetDateTime::now_utc();
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(cn);
    p.not_before = now - time::Duration::minutes(5);
    p.not_after = now + time::Duration::days(days);
    p.serial_number = Some(serial());
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.use_authority_key_identifier_extension = true;
    p
}

fn uri(s: &str) -> Result<SanType, String> {
    Ok(SanType::URI(
        s.try_into().map_err(|_| format!("bad URI {s}"))?,
    ))
}

/// RFC 8410's PKCS#8 wrapping of a raw Ed25519 seed.
const ED25519_PKCS8: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The control plane's certificate authority.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    pem: String,
}

impl Ca {
    /// The same seed gives the same CA, certificate included (Ed25519 signatures are
    /// deterministic, and every field is fixed), so nothing about it needs saving.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Ca, String> {
        let mut der = Zeroizing::new(ED25519_PKCS8.to_vec());
        der.extend_from_slice(seed);
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(der.as_slice()),
            &rcgen::PKCS_ED25519,
        )
        .map_err(|e| format!("CA key: {e}"))?;
        let mut p = CertificateParams::default();
        p.distinguished_name = dn("SuperBot machine CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2066, 1, 1);
        p.serial_number = Some(SerialNumber::from(1u64));
        let cert = p.self_signed(&key).map_err(|e| format!("CA: {e}"))?;
        Ok(Ca {
            pem: cert.pem(),
            der: cert.der().clone(),
            issuer: Issuer::new(p, key),
        })
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// Signs the key in `csr_pem` as `user_id`'s machine `machine_id`. Only the key is
    /// taken from the request (its signature proves the machine holds it); the names,
    /// usages, and lifetime are ours.
    pub fn issue_machine(
        &self,
        csr_pem: &str,
        user_id: &str,
        machine_id: &str,
        days: i64,
    ) -> Result<Issued, String> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| "the certificate request isn't a valid, signed CSR".to_string())?;
        let mut p = leaf(machine_id, days);
        p.subject_alt_names = vec![uri(&machine_uri(user_id, machine_id))?];
        let req = CertificateSigningRequestParams {
            params: p,
            public_key: csr.public_key,
        };
        issued(&req.signed_by(&self.issuer).map_err(|e| e.to_string())?)
    }

    /// botd's own certificate and a fresh key: its server name `host` for machines
    /// calling in, and the control-plane URI for when it calls them.
    pub fn issue_control_plane(&self, host: &str, days: i64) -> Result<(Issued, KeyPair), String> {
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut p = leaf("SuperBot control plane", days);
        let name = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into().map_err(|_| format!("bad host {host}"))?),
        };
        p.subject_alt_names = vec![name, uri(CONTROL_PLANE_URI)?];
        let cert = p.signed_by(&key, &self.issuer).map_err(|e| e.to_string())?;
        Ok((issued(&cert)?, key))
    }
}

/// A new key and a request for it, as a machine sends at enrollment and rotation.
pub fn new_request(machine_id: &str) -> Result<(KeyPair, String), String> {
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut p = CertificateParams::default();
    p.distinguished_name = dn(machine_id);
    let csr = p.serialize_request(&key).map_err(|e| e.to_string())?;
    Ok((key, csr.pem().map_err(|e| e.to_string())?))
}

fn roots(ca: &CertificateDer<'static>) -> Result<Arc<RootCertStore>, String> {
    let mut r = RootCertStore::empty();
    r.add(ca.clone()).map_err(|e| format!("CA: {e}"))?;
    Ok(Arc::new(r))
}

/// A TLS 1.3 server with `chain` and `key`. Client certificates must chain to `ca`;
/// with `client_required` off a client may also send none (enrollment).
pub fn server_config(
    ca: &CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_required: bool,
) -> Result<ServerConfig, String> {
    let b = WebPkiClientVerifier::builder_with_provider(roots(ca)?, provider());
    let verifier = if client_required {
        b
    } else {
        b.allow_unauthenticated()
    }
    .build()
    .map_err(|e| e.to_string())?;
    ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())
}

/// A machine calling the control plane: trusts only `ca` (and checks the server's
/// name), and shows its own certificate when it has one.
pub fn client_config(
    ca: &CertificateDer<'static>,
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig, String> {
    let b = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots(ca)?);
    match identity {
        Some((chain, key)) => b
            .with_client_auth_cert(chain, key)
            .map_err(|e| e.to_string()),
        None => Ok(b.with_no_client_auth()),
    }
}

/// Accepts a server only if its certificate is one of `pins`, and remembers which.
#[derive(Debug)]
pub struct Pinned {
    pins: Vec<String>,
    pub seen: Mutex<Option<String>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use rustls::CertificateError;
        let fp = fingerprint(end_entity);
        if !self.pins.contains(&fp) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let f = facts(end_entity).ok_or(rustls::Error::InvalidCertificate(
            CertificateError::BadEncoding,
        ))?;
        let now = now.as_secs() as i64 * 1000;
        if now >= f.not_after {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
        }
        if now < f.not_before {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet,
            ));
        }
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The control plane calling a machine: the machine must show one of the certificates
/// botd issued it (`pins`, by fingerprint), not merely any from the CA, so one
/// machine can never stand in for another. botd shows its own certificate.
pub fn pinned_client_config(
    pins: Vec<String>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(ClientConfig, Arc<Pinned>), String> {
    let verifier = Arc::new(Pinned {
        pins,
        seen: Mutex::new(None),
        algs: algorithms(),
    });
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(chain, key)
        .map_err(|e| e.to_string())?;
    Ok((config, verifier))
}

/// Who is on the other end of a TLS connection: the certificate the TLS layer
/// accepted, if any, and the address.
#[derive(Clone, Debug)]
pub struct Peer {
    pub cert: Option<CertificateDer<'static>>,
    pub addr: SocketAddr,
}

/// The server config to use for the next connection, so a renewed certificate takes
/// effect without a restart.
pub type Tls = Arc<dyn Fn() -> Arc<ServerConfig> + Send + Sync>;

/// Connections served at once; more are closed as they arrive. The ports are open to
/// the internet, so a flood of slow clients mustn't grow without bound.
const MAX_CONNECTIONS: usize = 256;
/// The longest a connection without a client certificate lives, slow downloads of
/// the agent included.
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(600);
/// The longest one with a certificate lives: a Bot's run streams over it, and an
/// approval it waits on can take a day (`policy::MAX_TIMEOUT_MINUTES`).
pub const AUTHENTICATED_LIFETIME: Duration = Duration::from_secs(25 * 3600);

/// How long a connection from a peer may live: none if it shows no certificate.
pub fn lifetime(peer: &Peer) -> Option<Duration> {
    Some(if peer.cert.is_some() {
        AUTHENTICATED_LIFETIME
    } else {
        CONNECTION_LIFETIME
    })
}

/// Serves `router` over TLS on `listener`. Each request carries the connection's
/// `Peer` as an extension. `admit` says how long a connection may live, right after
/// the handshake; None drops it.
pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: Tls,
    router: axum::Router,
    admit: fn(&Peer) -> Option<Duration>,
) {
    serve_with(listener, tls, router, admit, false).await
}

/// `serve`, letting a handler take over its connection with an HTTP upgrade. The
/// connection stops counting toward the limit, and its lifetime, once it's upgraded.
pub async fn serve_with(
    listener: tokio::net::TcpListener,
    tls: Tls,
    router: axum::Router,
    admit: fn(&Peer) -> Option<Duration>,
    upgrades: bool,
) {
    let open = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = open.clone().try_acquire_owned() else {
            continue;
        };
        let (tls, router) = (tls.clone(), router.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let acceptor = tokio_rustls::TlsAcceptor::from(tls());
            let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
            else {
                return;
            };
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.clone().into_owned());
            let peer = Peer { cert, addr };
            let Some(lifetime) = admit(&peer) else {
                return;
            };
            let svc = tower::ServiceExt::map_request(
                router,
                move |mut r: axum::http::Request<hyper::body::Incoming>| {
                    r.extensions_mut().insert(peer.clone());
                    r
                },
            );
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            let conn = http.serve_connection(
                hyper_util::rt::TokioIo::new(stream),
                hyper_util::service::TowerToHyperService::new(svc),
            );
            if upgrades {
                let _ = tokio::time::timeout(lifetime, conn.with_upgrades()).await;
            } else {
                let _ = tokio::time::timeout(lifetime, conn).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_is_the_same_from_the_same_seed() {
        let a = Ca::from_seed(&[7; 32]).unwrap();
        let b = Ca::from_seed(&[7; 32]).unwrap();
        let c = Ca::from_seed(&[8; 32]).unwrap();
        assert_eq!(a.der(), b.der(), "nothing about the CA needs saving");
        assert_ne!(a.der(), c.der());
        assert!(a.pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn a_machine_gets_our_names_whatever_it_asks_for() {
        let ca = Ca::from_seed(&[1; 32]).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["control.example".to_string()]).unwrap();
        p.distinguished_name = dn("SuperBot control plane");
        let sneaky = p.serialize_request(&key).unwrap().pem().unwrap();
        let cert = ca.issue_machine(&sneaky, "u1", "m1", 30).unwrap();
        let f = facts(cert_der(&cert.pem).unwrap().as_ref()).unwrap();
        assert_eq!(f.uris, [machine_uri("u1", "m1")]);
        assert!(!f.uris.contains(&CONTROL_PLANE_URI.to_string()));
        assert_eq!(f.serial, cert.serial);
        assert!(f.not_after - f.not_before > 29 * 86_400_000);
        assert!(ca.issue_machine("not a csr", "u1", "m1", 30).is_err());

        let (_, csr) = new_request("m1").unwrap();
        let mut tampered = csr.clone();
        tampered.replace_range(80..84, "AAAA");
        assert!(
            ca.issue_machine(&tampered, "u1", "m1", 30).is_err(),
            "the CSR's signature is checked"
        );
    }

    #[test]
    fn machine_uris_round_trip_strictly() {
        assert_eq!(
            parse_machine_uri(&machine_uri("u1a2", "m9f")),
            Some(("u1a2".into(), "m9f".into()))
        );
        for bad in [
            CONTROL_PLANE_URI,
            "spiffe://superbot/user//machine/m1",
            "spiffe://superbot/user/u1/machine/",
            "spiffe://superbot/user/u1/machine/m1/../m2",
            "spiffe://other/user/u1/machine/m1",
        ] {
            assert_eq!(parse_machine_uri(bad), None, "{bad}");
        }
    }
}
