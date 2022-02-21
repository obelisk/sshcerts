use sshcerts::ssh::{PrivateKey};

#[test]
fn parse_sk_ed25519_private_key() {
    let privkey = PrivateKey::from_string(include_str!("keys/sk_ed25519"));
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA");
}

#[test]
fn parse_sk_ecdsa_256_private_key() {
    let privkey = PrivateKey::from_string(include_str!("keys/sk_ecdsa"));
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "Ylfgx0U2M9/IVN0+b5/IxdNeVCotsdrRZ5lu5FG2ouc");
}