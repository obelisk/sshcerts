use sshcerts::ssh::Certificate;

#[test]
fn check_pubkey_extracts_from_certificate_correctly_ed25519() {
    let cert = Certificate::from_string(include_str!("certs/ed25519_signed_by_ed25519-cert.pub"));
    let user_pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRlrLwx21DZPH4pLkK6cJBn2bvGS3PGqwqa61XgwVkH";
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(format!("{}", cert.key), user_pubkey);
}

#[test]
fn check_pubkey_extracts_from_certificate_correctly_ecdsa384() {
    let cert = Certificate::from_string(include_str!("certs/ecdsa384_signed_by_ecdsa384-cert.pub"));
    let user_pubkey = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFLokpkryGhSfa6c1XkoYYdSghpoc5OAKn+y3vTAfw6Bi+Q6Y1vJV81jCoTPWQoxgp4wZ+2vXYytUuaiwAc03KHKazsCCTUUR9FHKafx8E20Pub67yTRpBCU9JTF2lIjkw==";
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(format!("{}", cert.key), user_pubkey);
}

#[test]
fn check_pubkey_extracts_from_certificate_correctly_eed25519_sk() {
    let cert = Certificate::from_string(include_str!("certs/ed25519_sk_signed_by_ecdsa384-cert.pub"));
    let user_pubkey = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIGYMHSzST3lQhQKYYSdosWFQZiP2YSFwCySgOyC93jWCAAAABHNzaDo=";
    assert!(cert.is_ok());
    let cert = cert.unwrap();
    assert_eq!(format!("{}", cert.key), user_pubkey);
}