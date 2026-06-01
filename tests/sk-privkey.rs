use sshcerts::ssh::{PrivateKey, PrivateKeyKind};
use std::io::BufWriter;

#[test]
fn parse_sk_ed25519_private_key() {
    let privkey = PrivateKey::from_string(include_str!("keys/sk/ed25519"));
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();
    assert_eq!(
        privkey.pubkey.fingerprint().hash,
        "GlvFAEnledYF0XG1guJ7dT2d0Mk88GmPAiHk8+zCBlA"
    );
    assert!(privkey.requires_touch());

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
    assert_eq!(
        privkey.pubkey.fingerprint().hash,
        "Ylfgx0U2M9/IVN0+b5/IxdNeVCotsdrRZ5lu5FG2ouc"
    );
    assert!(privkey.requires_touch());

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/sk/ecdsa"), serialized);
}

#[test]
fn sk_private_key_requires_touch_follows_flags() {
    let mut privkey = PrivateKey::from_string(include_str!("keys/sk/ed25519")).unwrap();

    if let PrivateKeyKind::Ed25519Sk(key) = &mut privkey.kind {
        key.flags = 0x00;
        assert!(!key.requires_touch());
    } else {
        panic!("expected ed25519-sk private key");
    }
    assert!(!privkey.requires_touch());

    if let PrivateKeyKind::Ed25519Sk(key) = &mut privkey.kind {
        key.flags = 0x01;
        assert!(key.requires_touch());
    } else {
        panic!("expected ed25519-sk private key");
    }
    assert!(privkey.requires_touch());

    let mut privkey = PrivateKey::from_string(include_str!("keys/sk/ecdsa")).unwrap();

    if let PrivateKeyKind::EcdsaSk(key) = &mut privkey.kind {
        key.flags = 0x00;
        assert!(!key.requires_touch());
    } else {
        panic!("expected ecdsa-sk private key");
    }
    assert!(!privkey.requires_touch());

    if let PrivateKeyKind::EcdsaSk(key) = &mut privkey.kind {
        key.flags = 0x01;
        assert!(key.requires_touch());
    } else {
        panic!("expected ecdsa-sk private key");
    }
    assert!(privkey.requires_touch());
}

#[test]
fn non_sk_private_key_does_not_require_touch() {
    let privkey = PrivateKey::from_string(include_str!("keys/unencrypted/ed25519_1")).unwrap();

    assert!(!privkey.requires_touch());
}
