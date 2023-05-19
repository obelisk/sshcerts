use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};

// Constants available for multiple tests
const RSA2048_CA_PRIVATE_KEY: &str = include_str!("keys/unencrypted/rsa-2048");

const LEGACY_RSA4096_SHA2_512_PUBLIC_KEY: &str = include_str!("keys/public/rsa-sha2-512-4096.pub");
const RSA4096_SHA2_512_PRIVATE_KEY: &str = include_str!("keys/unencrypted/rsa-sha2-512-4096");
const RSA4096_CA_PRIVATE_KEY: &str = include_str!("keys/unencrypted/rsa-sha2-256-4096");
// End constants

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ecdsa384_rsa2048ca() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();

    let private_key = PrivateKey::from_string(RSA2048_CA_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    assert!(user_cert.is_ok());
    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "n3kYx3FlLBGcCJWtzkm1YF6vIvtJcp3m+H7u3SnaGxc"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ed25519_rsa2048ca() {
    let ssh_pubkey = PublicKey::from_string(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHHgBVMG7TU30Z8lFfHPwBx98w3wkhoaybFc6/tjasI",
    );
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();

    let private_key = PrivateKey::from_string(RSA2048_CA_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    assert!(user_cert.is_ok());
    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "n3kYx3FlLBGcCJWtzkm1YF6vIvtJcp3m+H7u3SnaGxc"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn sign_and_certify_rsa_sha2_256() {
    let private_key = PrivateKey::from_string(RSA4096_CA_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&private_key.pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "sqSMm4+0OSx6UlrEUW7Khu40yymOGt9nkF2U2/ixHKQ"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn check_legacy_signing_sha2_512_signing() {
    let ssh_pubkey = PublicKey::from_string(LEGACY_RSA4096_SHA2_512_PUBLIC_KEY).unwrap();

    let private_key = PrivateKey::from_string(RSA4096_SHA2_512_PRIVATE_KEY).unwrap();
    let ca_pubkey = private_key.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .sign(&private_key);

    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "A+mZxJjDySutGP+sUtDX2KkZPxKloVLev+bDoJWhLn0"
    );

    // Check User fields
    assert_eq!(
        user_cert.key.fingerprint().hash,
        "A+mZxJjDySutGP+sUtDX2KkZPxKloVLev+bDoJWhLn0"
    );


    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}