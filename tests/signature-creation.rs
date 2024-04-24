use sshcerts::{
    ssh::{SshSignature, VerifiedSshSignature},
    PrivateKey,
};

#[test]
fn check_basic_creation_ed25519() {
    let private_key = PrivateKey::from_string(include_str!("keys/unencrypted/ed25519_1")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();

    let _ =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();
}

#[test]
fn check_basic_creation_ecdsa256() {
    let private_key =
        PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_256_1")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();

    let _ =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();
}

#[test]
fn check_basic_creation_ecdsa384() {
    let private_key =
        PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_384_1")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();

    let _ =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();
}

#[test]
fn check_basic_creation_ed25519_full_loop() {
    let private_key = PrivateKey::from_string(include_str!("keys/unencrypted/ed25519_1")).unwrap();
    let public_key = private_key.pubkey.clone();

    let message = include_bytes!("messages/Test").to_vec();

    let vss =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();

    let armored_signature = format!("{}", vss);

    let fl_vss = VerifiedSshSignature::from_ssh_signature(
        &message,
        SshSignature::from_armored_string(&armored_signature).unwrap(),
        Some(public_key),
    );

    assert!(fl_vss.is_ok());
}

#[test]
fn check_basic_creation_ecdsa_256_full_loop() {
    let private_key =
        PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_256_1")).unwrap();
    let public_key = private_key.pubkey.clone();

    let message = include_bytes!("messages/Test").to_vec();

    let vss =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();

    let armored_signature = format!("{}", vss);

    let fl_vss = VerifiedSshSignature::from_ssh_signature(
        &message,
        SshSignature::from_armored_string(&armored_signature).unwrap(),
        Some(public_key),
    );

    assert!(fl_vss.is_ok());
}

#[test]
fn check_basic_creation_ecdsa_384_full_loop() {
    let private_key =
        PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_384_1")).unwrap();
    let public_key = private_key.pubkey.clone();

    let message = include_bytes!("messages/Test").to_vec();

    let vss =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();

    let armored_signature = format!("{}", vss);

    let fl_vss = VerifiedSshSignature::from_ssh_signature(
        &message,
        SshSignature::from_armored_string(&armored_signature).unwrap(),
        Some(public_key),
    );

    assert!(fl_vss.is_ok());
}
