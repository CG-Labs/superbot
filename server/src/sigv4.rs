//! AWS Signature Version 4, for the S3 backup client (ADR 0071) and AWS Secrets Manager
//! (ADR 0146). Only the header form, signed with HMAC-SHA256 from `aws-lc-rs`; the
//! secret key signs and goes nowhere else.

use aws_lc_rs::{digest, hmac};

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, b).as_ref())
}

fn mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg).as_ref().to_vec()
}

/// URI-encodes as SigV4 wants: everything but unreserved characters, and `/` too
/// unless `keep_slash`.
pub fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The canonical query string: each name and value encoded, sorted.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (encode(k, false), encode(v, false))).collect();
    q.sort();
    q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// The date, region and service a signature is for.
pub struct Scope<'a> {
    /// `20150830T123600Z`.
    pub amz_date: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

impl Scope<'_> {
    fn credential(&self) -> String {
        format!("{}/{}/{}/aws4_request", &self.amz_date[..8], self.region, self.service)
    }

    /// The `Authorization` header for a signature from `signature`.
    pub fn authorization(&self, access_key: &str, signed: &str, sig: &str) -> String {
        format!("AWS4-HMAC-SHA256 Credential={access_key}/{}, SignedHeaders={signed}, Signature={sig}", self.credential())
    }
}

/// A request's SigV4 signature, and the signed header names. `uri` is already
/// encoded; `headers` are lowercase names with trimmed values, `host` among them.
pub fn signature(secret: &str, scope: &Scope, method: &str, uri: &str, query: &str, headers: &[(&str, &str)], payload_hash: &str) -> (String, String) {
    let mut h: Vec<(&str, &str)> = headers.to_vec();
    h.sort();
    let signed = h.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let canonical = format!("{method}\n{uri}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", scope.amz_date, scope.credential(), sha256_hex(canonical.as_bytes()));
    let k = mac(format!("AWS4{secret}").as_bytes(), scope.amz_date[..8].as_bytes());
    let k = mac(&k, scope.region.as_bytes());
    let k = mac(&k, scope.service.as_bytes());
    let k = mac(&k, b"aws4_request");
    (signed, hex(&mac(&k, to_sign.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AKID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /// AWS's own example: GET Object, from the SigV4 documentation for S3.
    #[test]
    fn signs_s3_as_aws_documents() {
        let scope = Scope { amz_date: "20130524T000000Z", region: "us-east-1", service: "s3" };
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let headers = [("host", "examplebucket.s3.amazonaws.com"), ("range", "bytes=0-9"), ("x-amz-content-sha256", empty), ("x-amz-date", "20130524T000000Z")];
        let (signed, sig) = signature("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", &scope, "GET", "/test.txt", "", &headers, empty);
        assert_eq!(signed, "host;range;x-amz-content-sha256;x-amz-date");
        assert_eq!(sig, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
    }

    /// AWS's SigV4 test suite (`get-vanilla`) and the IAM example from the SigV4 guide.
    #[test]
    fn signs_other_services_as_aws_documents() {
        let scope = Scope { amz_date: "20150830T123600Z", region: "us-east-1", service: "service" };
        let (signed, sig) = signature(SECRET, &scope, "GET", "/", "", &[("host", "example.amazonaws.com"), ("x-amz-date", scope.amz_date)], &sha256_hex(b""));
        assert_eq!(
            scope.authorization(AKID, &signed, &sig),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        let scope = Scope { service: "iam", ..scope };
        let query = canonical_query(&[("Version", "2010-05-08"), ("Action", "ListUsers")]);
        let headers = [("content-type", "application/x-www-form-urlencoded; charset=utf-8"), ("host", "iam.amazonaws.com"), ("x-amz-date", scope.amz_date)];
        let (_, sig) = signature(SECRET, &scope, "GET", "/", &query, &headers, &sha256_hex(b""));
        assert_eq!(sig, "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    }

    /// Secrets Manager's JSON requests, as botocore 1.44 signs them: with a session token,
    /// and to a host with a port.
    #[test]
    fn signs_secrets_manager_requests_as_botocore_does() {
        let scope = Scope { amz_date: "20261122T215100Z", region: "eu-west-2", service: "secretsmanager" };
        let body = br#"{"SecretId":"superbot/bots/OPENAI_API_KEY"}"#;
        let headers = [
            ("content-type", "application/x-amz-json-1.1"),
            ("host", "secretsmanager.eu-west-2.amazonaws.com"),
            ("x-amz-date", scope.amz_date),
            ("x-amz-security-token", "session-token-example"),
            ("x-amz-target", "secretsmanager.GetSecretValue"),
        ];
        let (signed, sig) = signature(SECRET, &scope, "POST", "/", "", &headers, &sha256_hex(body));
        assert_eq!(signed, "content-type;host;x-amz-date;x-amz-security-token;x-amz-target");
        assert_eq!(sig, "4a2e94838951e22d671193f8b24db687d8c0aefff4a2cab8152ec9d086047500");
        let scope = Scope { region: "us-east-1", ..scope };
        let headers = [("content-type", "application/x-amz-json-1.1"), ("host", "127.0.0.1:8443"), ("x-amz-date", scope.amz_date), ("x-amz-target", "secretsmanager.ListSecrets")];
        let (_, sig) = signature(SECRET, &scope, "POST", "/", "", &headers, &sha256_hex(br#"{"MaxResults":100}"#));
        assert_eq!(sig, "d2a1d92b9804bc05dac1c77c4e763ca0fac09eb2b327bc069bf3ff4e20f2b1ca");
    }

    #[test]
    fn encodes_keys_and_queries() {
        assert_eq!(encode("a b/c~d+e", true), "a%20b/c~d%2Be");
        assert_eq!(encode("a/b", false), "a%2Fb");
        assert_eq!(canonical_query(&[("uploadId", "x/y"), ("partNumber", "2")]), "partNumber=2&uploadId=x%2Fy");
        assert_eq!(canonical_query(&[("uploads", "")]), "uploads=");
    }
}
