use sshcerts::ssh::{PrivateKey, PrivateKeyKind, TouchRequirement};
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
    assert_eq!(privkey.touch_requirement(), TouchRequirement::Required);

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
    assert_eq!(privkey.touch_requirement(), TouchRequirement::Required);

    let mut buf = BufWriter::new(Vec::new());
    privkey.write(&mut buf).unwrap();
    let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
    assert_eq!(include_str!("keys/sk/ecdsa"), serialized);
}

#[test]
fn sk_private_key_touch_requirement_follows_flags() {
    let mut privkey = PrivateKey::from_string(include_str!("keys/sk/ed25519")).unwrap();

    if let PrivateKeyKind::Ed25519Sk(key) = &mut privkey.kind {
        key.flags = 0x00;
        assert_eq!(key.touch_requirement(), TouchRequirement::NotRequired);
    } else {
        panic!("expected ed25519-sk private key");
    }
    assert_eq!(privkey.touch_requirement(), TouchRequirement::NotRequired);

    if let PrivateKeyKind::Ed25519Sk(key) = &mut privkey.kind {
        key.flags = 0x01;
        assert_eq!(key.touch_requirement(), TouchRequirement::Required);
    } else {
        panic!("expected ed25519-sk private key");
    }
    assert_eq!(privkey.touch_requirement(), TouchRequirement::Required);

    let mut privkey = PrivateKey::from_string(include_str!("keys/sk/ecdsa")).unwrap();

    if let PrivateKeyKind::EcdsaSk(key) = &mut privkey.kind {
        key.flags = 0x00;
        assert_eq!(key.touch_requirement(), TouchRequirement::NotRequired);
    } else {
        panic!("expected ecdsa-sk private key");
    }
    assert_eq!(privkey.touch_requirement(), TouchRequirement::NotRequired);

    if let PrivateKeyKind::EcdsaSk(key) = &mut privkey.kind {
        key.flags = 0x01;
        assert_eq!(key.touch_requirement(), TouchRequirement::Required);
    } else {
        panic!("expected ecdsa-sk private key");
    }
    assert_eq!(privkey.touch_requirement(), TouchRequirement::Required);
}

#[test]
fn non_sk_private_key_touch_requirement_is_not_required() {
    let privkey = PrivateKey::from_string(include_str!("keys/unencrypted/ed25519_1")).unwrap();

    assert_eq!(privkey.touch_requirement(), TouchRequirement::NotRequired);
}
