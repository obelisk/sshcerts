use sshcerts::ssh::{PrivateKey};
use std::io::BufWriter;

#[test]
fn parse_sk_ed25519_private_key() {
    let privkey = PrivateKey::from_string(include_str!("keys/sk/ed25519"));
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/sk/ed25519"), serialized);
}

#[test]
fn parse_sk_ecdsa_256_private_key() {
    let privkey = PrivateKey::from_string(include_str!("keys/sk/ecdsa"));
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(privkey.pubkey.fingerprint().hash, "Ylfgx0U2M9/IVN0+b5/IxdNeVCotsdrRZ5lu5FG2ouc");

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/sk/ecdsa"), serialized);
}