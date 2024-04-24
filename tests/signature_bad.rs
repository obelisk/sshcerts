use sshcerts::{
    ssh::{SshSignature, VerifiedSshSignature},
    PrivateKey,
};

#[test]
fn ensure_verification_fail_ecdsa_256_bitflip() {
    let signature = SshSignature::from_armored_string(include_str!(
        "signatures_bad/ecdsa_256_1_bitflip_Test.sig"
    ))
    .unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_256_1"))
        .unwrap()
        .pubkey
        .clone();

    let vs =
        VerifiedSshSignature::from_ssh_signature(message.as_slice(), signature, Some(public_key));

    assert!(vs.is_err());
}

#[test]
fn ensure_parse_fail_ed25519_emptynamespace() {
    let signature = SshSignature::from_armored_string(include_str!(
        "signatures_bad/ed25519_1_empty-namespace_Test.sig"
    ));

    assert!(signature.is_err());
}
