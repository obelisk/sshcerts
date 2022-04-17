use sshcerts::ssh::Certificate;

#[test]
fn parse_ed15519_signed_by_sk_ed25519() {
    let cert = Certificate::from_string(include_str!("certs/ed25519_sk_signed_by_ed25519_sk-cert.pub"));
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(cert.key.fingerprint().hash, "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA");
    assert_eq!(cert.signature_key.fingerprint().hash, "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA");
}