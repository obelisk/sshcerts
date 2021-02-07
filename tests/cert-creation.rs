use ring::{rand, signature};

use sshcerts::ssh::{Certificate, CertType, CriticalOptions, Extensions, PublicKey};
use sshcerts::utils::signature_convert_asn1_ecdsa_to_ssh;

// Constants available for multiple tests
const ECDSA256_CA_PRIVATE_KEY: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02",
    "0101042063b3b4925287d2d20fd53c297ef80cdcd438764d40999ba60f6f1b08",
    "14e3b49ea14403420004dc3f4472cea77335a6ef9ac7bc73a37aac9f234a58d6",
    "0566a1946b135879db89a0a346fbc6f4db9ee5c30380f479280d62c9a65b6f50",
    "81fbc6b6f70048c6290f");

const ECDSA256_SSH_PUBLIC_KEY: &str = concat!(
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy",
    "NTYAAABBBNw/RHLOp3M1pu+ax7xzo3qsnyNKWNYFZqGUaxNYeduJoKNG+8b0257l",
    "wwOA9HkoDWLJpltvUIH7xrb3AEjGKQ8= obelisk@exclave.lan");

const ECDSA384_CA_PRIVATE_KEY: &str = concat!(
    "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020",
    "1010430ed4d1e49a2b25dcde5091f5104d3c1647336ac44afad699728a9f0c9",
    "e3b0ce39b49927f80f38398f72365014b74933c5a16403620004c895d0676a6",
    "a550c09e41bd0b68eea4e6697a060ac43933cb1c544d99155cd93cf2ef9f041",
    "429a99ee3443f6c1a574d00ba03c32cfc23386759ea60f1d43413deb4c86c2f",
    "326fd575b1a2f43e706df2fb6b228275aad698f79aefa622f663e4a");

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
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();
    let rng = rand::SystemRandom::new();
    let signature = key_pair.sign(&rng, buf).unwrap();

    let sig_type = "ecdsa-sha2-nistp256";
    let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(sig_type.as_bytes());
    encoded.extend(signature_convert_asn1_ecdsa_to_ssh(&signature.as_ref()).unwrap());

    Some(encoded)
}

// Test signing and parsing work together
fn test_ecdsa384_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = hex::decode(ECDSA384_CA_PRIVATE_KEY).unwrap();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let signature = key_pair.sign(&rng, buf).unwrap();

    let sig_type = "ecdsa-sha2-nistp384";
    let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(sig_type.as_bytes());
    encoded.extend(signature_convert_asn1_ecdsa_to_ssh(&signature.as_ref()).unwrap());

    Some(encoded)
}

#[test]
fn create_sign_parse_verify_ecdsa256() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert = Certificate::new(
        ssh_pubkey.clone(),
        CertType::User,
        0xFEFEFEFEFEFEFEFE,
        String::from("key_id"),
        vec![String::from("obelisk")],
        0,
        0xFFFFFFFFFFFFFFFF,
        CriticalOptions::None,
        Extensions::Standard,
        ca_pubkey.clone(),
        test_ecdsa256_signer,
    );

    assert!(user_cert.is_ok());

    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn create_sign_parse_verify_ecdsa384() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(&ECDSA384_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert = Certificate::new(
        ssh_pubkey.clone(),
        CertType::User,
        0xFEFEFEFEFEFEFEFE,
        String::from("key_id"),
        vec![String::from("obelisk")],
        0,
        0xFFFFFFFFFFFFFFFF,
        CriticalOptions::None,
        Extensions::Standard,
        ca_pubkey.clone(),
        test_ecdsa384_signer,
    );

    assert!(user_cert.is_ok());

    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);
}