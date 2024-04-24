use sshcerts::{
    ssh::{SshSignature, VerifiedSshSignature},
    PrivateKey,
};

#[test]
fn check_basic_parsing_ed25519() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/ed25519_1_Test.sig")).unwrap();
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/ed25519_2_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_sk_ed25519() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/sk_ed25519_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_ecdsa256() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/ecdsa_256_1_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_sk_ecdsa() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/sk_ecdsa_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_ecdsa384() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/ecdsa_384_1_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_rsa_2048() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/rsa_2048_1_Test.sig")).unwrap();
}

#[test]
fn check_basic_parsing_rsa_sha2_256() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-256-4096_Test.sig"))
            .unwrap();
}

#[test]
fn check_basic_parsing_rsa_sha2_512() {
    let _ =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-512-4096_Test.sig"))
            .unwrap();

    let _ =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-512-8192_Test.sig"))
            .unwrap();
}

#[test]
fn check_verification_ed25519() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/ed25519_1_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/ed25519_1"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_sk_ed25519() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/sk_ed25519_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/sk/ed25519"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_ecdsa_256() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/ecdsa_256_1_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_256_1"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_sk_ecdsa() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/sk_ecdsa_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/sk/ecdsa"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_ecdsa_384() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/ecdsa_384_1_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/ecdsa_384_1"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_rsa_2048() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/rsa_2048_1_Test.sig")).unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa_2048_1"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_rsa_sha2_256() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-256-4096_Test.sig"))
            .unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa-sha2-256-4096"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}

#[test]
fn check_verification_rsa_sha2_512() {
    let signature =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-512-4096_Test.sig"))
            .unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa-sha2-512-4096"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");

    let signature =
        SshSignature::from_armored_string(include_str!("signatures/rsa-sha2-512-8192_Test.sig"))
            .unwrap();

    let message = include_bytes!("messages/Test").to_vec();
    let public_key = PrivateKey::from_string(include_str!("keys/unencrypted/rsa-sha2-512-8192"))
        .unwrap()
        .pubkey
        .clone();

    let _verified_signature = VerifiedSshSignature::from_ssh_signature(
        message.as_slice(),
        signature,
        "file",
        Some(public_key),
    )
    .expect("Failed to verify signature");
}
