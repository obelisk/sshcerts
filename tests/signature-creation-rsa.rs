use sshcerts::{
    ssh::{SshSignature, VerifiedSshSignature},
    PrivateKey,
};

#[test]
fn check_basic_creation_rsa_2048_1() {
    let private_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa_2048_1")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();

    let _ =
        VerifiedSshSignature::new_with_private_key(&message, "file", private_key, None).unwrap();
}

#[test]
fn check_basic_creation_rsa_2048_1_full_loop() {
    let private_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa_2048_1")).unwrap();
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
