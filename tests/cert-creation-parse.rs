use ring::{rand, signature};

use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};
use sshcerts::utils::format_signature_for_ssh;

use std::collections::HashMap;

// Constants available for multiple tests
const ECDSA256_CA_PRIVATE_KEY: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02",
    "0101042063b3b4925287d2d20fd53c297ef80cdcd438764d40999ba60f6f1b08",
    "14e3b49ea14403420004dc3f4472cea77335a6ef9ac7bc73a37aac9f234a58d6",
    "0566a1946b135879db89a0a346fbc6f4db9ee5c30380f479280d62c9a65b6f50",
    "81fbc6b6f70048c6290f"
);

const ECDSA256_SSH_PUBLIC_KEY: &str = concat!(
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy",
    "NTYAAABBBNw/RHLOp3M1pu+ax7xzo3qsnyNKWNYFZqGUaxNYeduJoKNG+8b0257l",
    "wwOA9HkoDWLJpltvUIH7xrb3AEjGKQ8= obelisk@exclave.lan"
);

const ECDSA384_CA_PRIVATE_KEY: &str = concat!(
    "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020",
    "1010430ed4d1e49a2b25dcde5091f5104d3c1647336ac44afad699728a9f0c9",
    "e3b0ce39b49927f80f38398f72365014b74933c5a16403620004c895d0676a6",
    "a550c09e41bd0b68eea4e6697a060ac43933cb1c544d99155cd93cf2ef9f041",
    "429a99ee3443f6c1a574d00ba03c32cfc23386759ea60f1d43413deb4c86c2f",
    "326fd575b1a2f43e706df2fb6b228275aad698f79aefa622f663e4a"
);

const ECDSA384_SSH_PUBLIC_KEY: &str = concat!(
    "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAz",
    "ODQAAABhBMiV0GdqalUMCeQb0LaO6k5ml6BgrEOTPLHFRNmRVc2Tzy758EFCmpnu",
    "NEP2waV00AugPDLPwjOGdZ6mDx1DQT3rTIbC8yb9V1saL0PnBt8vtrIoJ1qtaY95",
    "rvpiL2Y+Sg== obelisk@exclave.lan"
);
// End constants

// Test signing and parsing work together
fn test_ecdsa256_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let pkcs8_bytes = hex::decode(ECDSA256_CA_PRIVATE_KEY).unwrap();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
    )
    .unwrap();
    let rng = rand::SystemRandom::new();

    let pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY).unwrap();
    format_signature_for_ssh(&pubkey, key_pair.sign(&rng, buf).ok()?.as_ref())
}

// Test signing and parsing work together
fn test_ecdsa384_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let pkcs8_bytes = hex::decode(ECDSA384_CA_PRIVATE_KEY).unwrap();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
    )
    .unwrap();
    let rng = rand::SystemRandom::new();

    let pubkey = PublicKey::from_string(ECDSA384_SSH_PUBLIC_KEY).unwrap();
    format_signature_for_ssh(&pubkey, key_pair.sign(&rng, buf).ok()?.as_ref())
}

#[test]
fn create_and_reparse_sign_parse_verify_ed25519ca() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
        "QyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FAAAAJiT9ajkk/Wo\n",
        "5AAAAAtzc2gtZWQyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FA\n",
        "AAAED6HgUU3Ps5TVdFCVO8uTpbfVdg3JBxnOz3DIWO1u1Xbc0JfpeVmfRBExbXgAFlrkZl\n",
        "zrpT5ywSIqyCRnAYrT4UAAAAE29iZWxpc2tAZXhjbGF2ZS5sYW4BAg==\n",
        "-----END OPENSSH PRIVATE KEY-----"
    );

    let privkey = PrivateKey::from_string(privkey);
    match &privkey {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    };
    assert!(privkey.is_ok());
    let privkey = privkey.unwrap();

    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let pubkey = privkey.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .key_id("overwrite_key_id")
        .principal("obelisk")
        .principal("mitchell")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_critical_options(HashMap::new())
        .critical_option("test", "test_value")
        .set_extensions(Certificate::standard_extensions())
        .extension("extension_test", "extension_test_value")
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(
        user_cert.key.fingerprint().hash,
        "uzOtIxALSM+OuY+LmdU1xFLzY4zBvom/1Etb385O0ek"
    );
    assert_eq!(user_cert.key_id, String::from("overwrite_key_id"));
    assert_eq!(user_cert.principals, vec!["obelisk", "mitchell"]);
    assert_eq!(user_cert.critical_options.len(), 1);
    assert!(user_cert.critical_options.get("test").is_some());
    assert_eq!(
        user_cert.critical_options.get("test").unwrap(),
        &String::from("test_value")
    );
    assert_eq!(user_cert.extensions.len(), 6);
    assert!(user_cert.extensions.get("extension_test").is_some());
    assert_eq!(
        user_cert.extensions.get("extension_test").unwrap(),
        &String::from("extension_test_value")
    );
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "XfK1zRAFSKTh7bYdKwli8mJ0P4q/bV2pXdmjyw5p0DI"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ecdsa256ca() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY).unwrap();

    let user_cert_partial = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF);

    let signature = test_ecdsa256_signer(&user_cert_partial.tbs_certificate());
    assert!(signature.is_some());

    let user_cert = user_cert_partial.add_signature(&signature.unwrap());
    assert!(user_cert.is_ok());

    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "7mPQx8ezzmG9QpBbAVaA4kBwiWoNmIYodjlng3xzw4o"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}

#[test]
fn create_and_reparse_sign_parse_verify_minimal_ecdsa384ca() {
    let ssh_pubkey = PublicKey::from_string(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHHgBVMG7TU30Z8lFfHPwBx98w3wkhoaybFc6/tjasI testuser",
    );
    assert!(ssh_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = PublicKey::from_string(ECDSA384_SSH_PUBLIC_KEY).unwrap();

    let user_cert_partial = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .key_id("key_id")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF);

    let signature = test_ecdsa384_signer(&user_cert_partial.tbs_certificate());
    assert!(signature.is_some());

    let user_cert = user_cert_partial.add_signature(&signature.unwrap());
    assert!(user_cert.is_ok());
    let user_cert = user_cert.unwrap();

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "gxy7uWVVeYxXSb6Op57fSDdzSWF9T7HwqnDr7IID1m8"
    );

    // Check that we can correctly reparse the serialized certificate
    let cert = format!("{}", user_cert);

    let cert = Certificate::from_string(&cert);
    assert!(cert.is_ok());
}
