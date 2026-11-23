//! Vault's Kubernetes and JWT sign-in (ADR 0159), on the real router: against a stand-in
//! Vault, botd's logins and the reads they allow reach the audit log admins read, with
//! the method, role and namespace and never a JWT, a Vault token or a value; a JWT file
//! that can't be used is a failed login there too, and only admins see any of it.

use crate::secrets::external::tests::flush_audit_for;
use crate::secrets::vault::tests::{jwt, put, stand_in, token_file, vault};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::user_with;
use crate::*;
use std::time::Duration;

async fn events(port: u16, auth: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), auth, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

#[tokio::test]
async fn admins_see_kubernetes_and_jwt_logins_never_the_tokens() {
    let (port, app, admin, _) = serve_app().await;
    let (url, f) = stand_in();
    let k8s_mount = format!("k8s-http-{}", random_hex(6));
    let jwt_mount = format!("jwt-http-{}", random_hex(6));
    let name = format!("K8S_HTTP_{}_TOKEN", random_hex(4).to_uppercase());
    let value = format!("k8s-http-value-{}", random_hex(8));
    put(&f, &format!("bots/{name}"), &value);

    // Kubernetes: the pod's service account token, in the secrets' own namespace.
    let sa = jwt("system:serviceaccount:superbot:botd", 3600);
    f.jwts.lock().unwrap().push((k8s_mount.clone(), Some("superbot".into()), sa.clone()));
    let sa_file = token_file("vault-http-k8s", &sa);
    let k8s = vault(
        &url,
        &[("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "superbot"), ("VAULT_KUBERNETES_MOUNT", &k8s_mount), ("VAULT_KUBERNETES_TOKEN_FILE", sa_file.to_str().unwrap()), ("VAULT_NAMESPACE", "admin/team-a")],
        Duration::from_secs(60),
    );
    use crate::secrets::SecretStore;
    assert_eq!(k8s.get(&name).unwrap().unwrap().expose(), value);

    // JWT: a token whose time is up is refused before it is sent.
    let expired = jwt("repo:acme/infra:ref:refs/heads/main", -60);
    let jwt_file = token_file("vault-http-jwt", &expired);
    let ci = vault(&url, &[("VAULT_AUTH", "jwt"), ("VAULT_JWT_ROLE", "ci"), ("VAULT_JWT_MOUNT", &jwt_mount), ("VAULT_JWT_FILE", jwt_file.to_str().unwrap()), ("VAULT_AUTH_NAMESPACE", "admin")], Duration::ZERO);
    assert!(ci.check().is_err());
    assert_eq!(f.logins.load(std::sync::atomic::Ordering::SeqCst), 1, "only the Kubernetes login reached Vault");

    flush_audit_for(&app.db, &[&k8s_mount, &jwt_mount, &name]);
    let logins: Vec<Value> = events(port, &admin, "action=secret.vault_login").await.into_iter().filter(|e| e["targetId"] == k8s_mount.as_str() || e["targetId"] == jwt_mount.as_str()).collect();
    let got: Vec<_> = logins.iter().map(|e| (e["targetId"].as_str().unwrap(), e["outcome"].as_str(), e["actorId"].as_str(), e["details"].clone())).collect();
    assert_eq!(got.len(), 2, "{logins:?}");
    assert!(got.contains(&(k8s_mount.as_str(), Some("success"), Some("secrets"), json!({ "method": "kubernetes", "role": "superbot", "namespace": "admin/team-a" }))), "{got:?}");
    assert!(got.contains(&(jwt_mount.as_str(), Some("failure"), Some("secrets"), json!({ "method": "jwt", "role": "ci", "namespace": "admin", "error": "unavailable" }))), "{got:?}");

    let reads: Vec<Value> = events(port, &admin, "action=secret.read").await.into_iter().filter(|e| e["targetId"] == name.as_str()).collect();
    assert_eq!(reads.len(), 1, "one read reached Vault; the next would be cached: {reads:?}");
    assert_eq!(reads[0]["details"], json!({ "store": "vault", "scope": "bots", "op": "read", "found": true, "error": null }));

    let (_, all) = call(port, "GET", "/api/audit?action=secret.*&limit=500", &admin, "").await;
    for leaked in [sa.as_str(), expired.as_str(), value.as_str(), "hvs."] {
        assert!(!all.contains(leaked), "{leaked} reached the audit log");
    }

    // Members don't read the audit log, so they don't see botd's sign-ins either.
    let (_, member) = user_with(port, &admin, "kai@example.com", "member").await;
    let (code, body) = call(port, "GET", "/api/audit?action=secret.vault_login", &member, "").await;
    assert_eq!(code, 403, "{body}");
    assert!(!body.contains(&k8s_mount));
    crate::secrets::redact::forget(&value);
}
