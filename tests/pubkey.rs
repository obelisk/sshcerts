use sshcerts::ssh::{PublicKey};

// Test PublicKey parsing
#[test]
fn parse_ecdsa256_publickey() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());
    let ssh_pubkey = ssh_pubkey.unwrap();

    assert_eq!(ssh_pubkey.fingerprint().hash, "BAJ7Md5+hfu6I6ojHoJpSNVXNRnxM8XfNnA8Pf1X/2I");
}