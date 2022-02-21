use sshcerts::ssh::Certificate;

#[test]
fn parse_ed15519_signed_by_sk_ecdsa() {
    let cert = Certificate::from_string(include_str!("certs/ed25519_signed_by_ecdsa_sk-cert.pub"));
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(cert.key.fingerprint().hash, "tUSfkfiocNgVTbFE2caqokLbZlw7G6qwMHLFZRAn2yk");
    assert_eq!(cert.signature_key.fingerprint().hash, "Ylfgx0U2M9/IVN0+b5/IxdNeVCotsdrRZ5lu5FG2ouc");
}