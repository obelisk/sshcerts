use ring::{rand, signature};

use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};
use sshcerts::utils::format_signature_for_ssh;

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
    let rng = rand::SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
    	&rng,
    )
    .unwrap();

    let pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY).unwrap();
    format_signature_for_ssh(&pubkey, key_pair.sign(&rng, buf).ok()?.as_ref())
}

// Test signing and parsing work together
fn test_ecdsa384_signer(buf: &[u8]) -> Option<Vec<u8>> {
    let pkcs8_bytes = hex::decode(ECDSA384_CA_PRIVATE_KEY).unwrap();
    let rng = rand::SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
	&rng,
    )
    .unwrap();

    let pubkey = PublicKey::from_string(ECDSA384_SSH_PUBLIC_KEY).unwrap();
    format_signature_for_ssh(&pubkey, key_pair.sign(&rng, buf).ok()?.as_ref())
}

#[test]
fn create_sign_parse_verify_ecdsa256_static_function() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(ECDSA256_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert_partial = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions());

    let signature = test_ecdsa256_signer(&user_cert_partial.tbs_certificate());
    assert!(signature.is_some());

    let user_cert = user_cert_partial.add_signature(&signature.unwrap());
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
fn create_sign_parse_verify_ecdsa384_static_function() {
    let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCEPn99p8iLo9pyPBW0MzsWdWtvlvGKfnFKc/pOF3sV2mCNYp06mgfXm3ZPKioIjYHjj9Y1E4W8x1uRUfk/MM7ZGe3prAEHs4evenCMNRqHmrTDRSxle8A7s5vUrECtiVA== obelisk@exclave.lan");
    assert!(ssh_pubkey.is_ok());

    let ca_pubkey = PublicKey::from_string(ECDSA384_SSH_PUBLIC_KEY);
    assert!(ca_pubkey.is_ok());

    let ssh_pubkey = ssh_pubkey.unwrap();
    let ca_pubkey = ca_pubkey.unwrap();

    let user_cert_partial = Certificate::builder(&ssh_pubkey, CertType::User, &ca_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions());

    let signature = test_ecdsa384_signer(&user_cert_partial.tbs_certificate());
    assert!(signature.is_some());

    let user_cert = user_cert_partial.add_signature(&signature.unwrap());
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
fn create_sign_parse_verify_ed25519ca_into_impl() {
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
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "XfK1zRAFSKTh7bYdKwli8mJ0P4q/bV2pXdmjyw5p0DI"
    );
}

#[test]
fn create_sign_parse_verify_ed25519ca_create_signer() {
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
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "XfK1zRAFSKTh7bYdKwli8mJ0P4q/bV2pXdmjyw5p0DI"
    );
}

#[test]
fn create_sign_parse_verify_ecdsa256_into_impl() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ+A6+/rZaiAvELSLxcG+N34qmUwbWi\n",
        "R/ggELvNm/GnIIVtdBXwGAHfxHUptyglzGGXmFe6OvYcjVIND21cI8sjAAAAsCCyPOAgsj\n",
        "zgAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD4Dr7+tlqIC8QtI\n",
        "vFwb43fiqZTBtaJH+CAQu82b8acghW10FfAYAd/EdSm3KCXMYZeYV7o69hyNUg0PbVwjyy\n",
        "MAAAAgZh56NkYn+PWxxMI3Xg5CpKTjuSh07cxm4ZOUgj95xz4AAAATb2JlbGlza0BleGNs\n",
        "YXZlLmxhbgECAwQF\n",
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
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "4iFrRMN31rjtQtvJyC/Y3Wg9mKAjQnZtZ2wFNWYzrb8"
    );
}

#[test]
fn create_sign_parse_verify_ecdsa256_create_signer() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ+A6+/rZaiAvELSLxcG+N34qmUwbWi\n",
        "R/ggELvNm/GnIIVtdBXwGAHfxHUptyglzGGXmFe6OvYcjVIND21cI8sjAAAAsCCyPOAgsj\n",
        "zgAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD4Dr7+tlqIC8QtI\n",
        "vFwb43fiqZTBtaJH+CAQu82b8acghW10FfAYAd/EdSm3KCXMYZeYV7o69hyNUg0PbVwjyy\n",
        "MAAAAgZh56NkYn+PWxxMI3Xg5CpKTjuSh07cxm4ZOUgj95xz4AAAATb2JlbGlza0BleGNs\n",
        "YXZlLmxhbgECAwQF\n",
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

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &privkey.pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "4iFrRMN31rjtQtvJyC/Y3Wg9mKAjQnZtZ2wFNWYzrb8"
    );
}

#[test]
fn create_sign_parse_verify_ecdsa384_into_impl() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQRwh+P50KGZBX79jg6paL1AwkQHMlKo\n",
        "HbPRdKnhWcg1aD0QNPnzOz03Lr0hZideAdpCIhH7H9vy/Yc9FZpwTLjhcRT/YLidZTo58Q\n",
        "8ociEb1JRck8cCqgcleugInh0rmaQAAADgPCAojjwgKI4AAAATZWNkc2Etc2hhMi1uaXN0\n",
        "cDM4NAAAAAhuaXN0cDM4NAAAAGEEcIfj+dChmQV+/Y4OqWi9QMJEBzJSqB2z0XSp4VnINW\n",
        "g9EDT58zs9Ny69IWYnXgHaQiIR+x/b8v2HPRWacEy44XEU/2C4nWU6OfEPKHIhG9SUXJPH\n",
        "AqoHJXroCJ4dK5mkAAAAMQCzbv+cwLvqN5gEqlicsecYiDm6TsSqu6/vK+uZMXVMnWIvdH\n",
        "pkgBFrUy28lE5LJBoAAAATb2JlbGlza0BleGNsYXZlLmxhbgECAwQ=\n",
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
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "xHlYNJvliHr0AMuGYs+4SK3N0PqiaI6jbQMZlKWC1Is"
    );
}

#[test]
fn create_sign_parse_verify_ecdsa384_create_signer() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n",
        "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQRwh+P50KGZBX79jg6paL1AwkQHMlKo\n",
        "HbPRdKnhWcg1aD0QNPnzOz03Lr0hZideAdpCIhH7H9vy/Yc9FZpwTLjhcRT/YLidZTo58Q\n",
        "8ociEb1JRck8cCqgcleugInh0rmaQAAADgPCAojjwgKI4AAAATZWNkc2Etc2hhMi1uaXN0\n",
        "cDM4NAAAAAhuaXN0cDM4NAAAAGEEcIfj+dChmQV+/Y4OqWi9QMJEBzJSqB2z0XSp4VnINW\n",
        "g9EDT58zs9Ny69IWYnXgHaQiIR+x/b8v2HPRWacEy44XEU/2C4nWU6OfEPKHIhG9SUXJPH\n",
        "AqoHJXroCJ4dK5mkAAAAMQCzbv+cwLvqN5gEqlicsecYiDm6TsSqu6/vK+uZMXVMnWIvdH\n",
        "pkgBFrUy28lE5LJBoAAAATb2JlbGlza0BleGNsYXZlLmxhbgECAwQ=\n",
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

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &privkey.pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    assert!(user_cert.is_ok());

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "xHlYNJvliHr0AMuGYs+4SK3N0PqiaI6jbQMZlKWC1Is"
    );
}

#[cfg(feature = "rsa-signing")]
#[test]
fn create_sign_parse_verify_rsa4096_impl_into() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "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\n",
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
    let priv_pubkey = privkey.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &priv_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    match &user_cert {
        Ok(_) => (),
        Err(e) => {
            println!("Error: {}", e);
            assert!(user_cert.is_ok());
        }
    }

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "+9NkmQZUWidGVFdel/s8bjQtVgthWEILEX2DtAZST5c"
    );
}

#[cfg(feature = "rsa-signing")]
#[test]
fn create_sign_parse_verify_rsa3072_impl_into() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n",
        "NhAAAAAwEAAQAAAYEArDFpYTR0sS6IpcPIRZUf7qNEK6tMTRDuI8bAMsZ28QnJMZhj1EUe\n",
        "bdislEtB+5BqAqBufvDuHZjc7U8txjwVwvrJxaW4bQgFLz6N7hFZv1R1xIV8ThtLOkYwGd\n",
        "rwRhA+QIcetxGEXw3mK+W87ias38OBCwhRJa3Id1fmFjIM3hdFmFWK60vZR68zzhNK/bSW\n",
        "hWesj8VUY/zgoh152PoBJVNcVI5ngAn4q+M9R8rw4twt73DCpdeQEQy84QAeE55yMtiOQo\n",
        "BFWoHuZ8kjO5bbXo7zI8ATrwIqNWGTvBeOtCDu1MpN2OgRDvqiG7bjdb717zoZBzfyWWRQ\n",
        "kzkAx0kcLnPTpbCsQhYH/153cR01UpYZRGlhRl8w/B0uscIkNuDOXOAzp68Ri61FcY1Ne+\n",
        "9+jwJlui9lrMtwvv+p7OCvpTjtSEuVeBWnbX+RRm5UgFP/GqR9hDvtCpHaiPtguJiKsrta\n",
        "B030ASeqwP+CWUzwHYdumAPvC+WQDVpHrITjd0x1AAAFkNP5f67T+X+uAAAAB3NzaC1yc2\n",
        "EAAAGBAKwxaWE0dLEuiKXDyEWVH+6jRCurTE0Q7iPGwDLGdvEJyTGYY9RFHm3YrJRLQfuQ\n",
        "agKgbn7w7h2Y3O1PLcY8FcL6ycWluG0IBS8+je4RWb9UdcSFfE4bSzpGMBna8EYQPkCHHr\n",
        "cRhF8N5ivlvO4mrN/DgQsIUSWtyHdX5hYyDN4XRZhViutL2UevM84TSv20loVnrI/FVGP8\n",
        "4KIdedj6ASVTXFSOZ4AJ+KvjPUfK8OLcLe9wwqXXkBEMvOEAHhOecjLYjkKARVqB7mfJIz\n",
        "uW216O8yPAE68CKjVhk7wXjrQg7tTKTdjoEQ76ohu243W+9e86GQc38llkUJM5AMdJHC5z\n",
        "06WwrEIWB/9ed3EdNVKWGURpYUZfMPwdLrHCJDbgzlzgM6evEYutRXGNTXvvfo8CZbovZa\n",
        "zLcL7/qezgr6U47UhLlXgVp21/kUZuVIBT/xqkfYQ77QqR2oj7YLiYirK7WgdN9AEnqsD/\n",
        "gllM8B2HbpgD7wvlkA1aR6yE43dMdQAAAAMBAAEAAAGAKyG1Y8Pf9wHQ+LSx1bwk44HB8a\n",
        "5WzncPL6b5Pb64zGfHHcUuPF2T4bAEiqDPRlRGOaI2C1YOTxubO1Y6AQ3L5assH3YDXExG\n",
        "AC+LHbb65BIj7bYCDQ6JKW+rXM6aoPIwpbky2Ghq3+R7Y0OIr57Absxp5nmO2gFN1ZcO60\n",
        "BeOMNbi2zh/05gfrREJbpvbl1t1rzBXMHxAZq2KeV4QAFfiBn5ZrTE+C2HPIcPMoyDClBc\n",
        "sT1thF0amSq3pSSCZCerycLtTtlCOIoQA+NKrxY9jdlqQnLpXUCHruNuSQaD4T/TZlQJDt\n",
        "mzCN6ILCUQM6dexsN8Hxj7g/JRSxbvYzzUqXpSlBfNycMQoa4sO7edVZM3vzCOUBNRXj3U\n",
        "xDJ0OnJ7Hd7ui/ORVVC4WQ5QN+2f5hbwZnniEfsJzYTJdfO8uANBywJSgYv6uIDvAmjIpf\n",
        "W5g9qunmTldtRSof26VM3/5tKh6qAnqeGXoVTkvYoi0B0+SdJNqncuPoJkdWiSlDgBAAAA\n",
        "wQDaBVJzHqMVrNr56JB3FLYX6ZOzUKlY+d4ahII2wmucKoyeUgDtRlkN78CkDGhWWocmGH\n",
        "MvFiAXgjVOYrOZMlKbK5FlwcXB9xdvHSvd4cdQ7UMccVWuL+VCZykUhfiJLz9co1c4HInK\n",
        "PgRdkAnkvQyCnkh90cDJbXCUmPqWUwXZmo07KoRodS2ZwreNCP7J8XxX4yclbFhU4/n3FH\n",
        "rUpqlcjskdjbBv38e7jVH4EFWOLTXeLYx2PgbABKbDTaHbjlMAAADBAORYFqO0lHc3YjZW\n",
        "fUS6Zg49GFAtRJDErhFk3jCJG64XyBuJJSPQv3IdB1BiigPO3v8kAgc1Tmuc5GZuomjT6P\n",
        "Uq8QyylJbPlxU5mI0KSvwGhfRGPNnGhTQoq9McA208mASOW0t+7ePvneLX2DLzJTM+n7Tj\n",
        "9+bj5BczhbpOH3O5oe8W2h33sFSjeWnJILT+w6mm/S2xPTuNR03wsUWLILQF6FTow2Qro6\n",
        "C66XXzWPobS0NXJNxrnOGVH0AzsZXjRQAAAMEAwQxVaMxsPmvZUxSasvqzoM28c05CJBL9\n",
        "pY93eMSkTlYtnTFzBGSjabDs94lNlQBFIHTcEySod8sVYo6SW8WrY/ebAx9/cSAagl2K5o\n",
        "JOb8DFbXNGWRvkZWj8mau8SEoNK4APlQtA9Y6IdyaXntoLM/xPyr+RhJPHaDGVju+W/xiX\n",
        "ehPVvXJb1I+gCy7CyNz5q49te6oQr60ZHtdX1LtAQEqENBwMByHuIRIZ2SMw7YbcW+bPOe\n",
        "FcoEha89lN4D9xAAAAE29iZWxpc2tAZXhjbGF2ZS5sYW4BAgMEBQYH\n",
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
    let priv_pubkey = privkey.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &priv_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    match &user_cert {
        Ok(_) => (),
        Err(e) => {
            println!("Error: {}", e);
            assert!(user_cert.is_ok());
        }
    }

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "YlmcNWmmzkuy/5oIlCoqyd5JkIaa/RgzjlF7nFzsZ3o"
    );
}

#[cfg(feature = "rsa-signing")]
#[test]
fn create_sign_parse_verify_rsa2048_impl_into() {
    let privkey = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n",
        "NhAAAAAwEAAQAAAQEAw36k9Ml2c6B2K0wwa7xW464zlUPcAzi+jxJhE6D1azWr41zgH5mQ\n",
        "y3emsymA4n73lV4wVFfkbpu3M+TFxwYdOOjcXxuIOjlZlUMRfnM1j9Dpcty+FcMd0OJmw9\n",
        "7IUyxd+mL9xIW+g8xo/0g7whYE42Ks5LrqTeyiq5OA1MU2wr4KAO1tEiBmA+36yMOuCsad\n",
        "TG+wAMoec9Fks2MpdeZUVRpxAUW+QRBDEDvHL5JlBFL5dIwC2PoWsHo43nc1o14kHf8TuB\n",
        "PBXyjbiHtElEx2TNA23gb1m7Hn+TyNfx8N0wrRVxDgbDGE0MEmwxohRA6jUPve3YXLSsrn\n",
        "qBXX26HZBQAAA8guZeGKLmXhigAAAAdzc2gtcnNhAAABAQDDfqT0yXZzoHYrTDBrvFbjrj\n",
        "OVQ9wDOL6PEmEToPVrNavjXOAfmZDLd6azKYDifveVXjBUV+Rum7cz5MXHBh046NxfG4g6\n",
        "OVmVQxF+czWP0Oly3L4Vwx3Q4mbD3shTLF36Yv3Ehb6DzGj/SDvCFgTjYqzkuupN7KKrk4\n",
        "DUxTbCvgoA7W0SIGYD7frIw64Kxp1Mb7AAyh5z0WSzYyl15lRVGnEBRb5BEEMQO8cvkmUE\n",
        "Uvl0jALY+hawejjedzWjXiQd/xO4E8FfKNuIe0SUTHZM0DbeBvWbsef5PI1/Hw3TCtFXEO\n",
        "BsMYTQwSbDGiFEDqNQ+97dhctKyueoFdfbodkFAAAAAwEAAQAAAQBQY1JnijRYJaKR+Vlr\n",
        "492C8E4r0eS1um65nGAo1yYz+LT+4GEU/WvKDyCQSb/C41zhogKTnDTFuuhhwXAGgCAiF7\n",
        "cOsN6aupx4wUR/T9a1lb15SwYrIrmu/HovjvunH/ZhELWzSx/lSHfgiY5xJ+bIrfnUcHwK\n",
        "oQTfMt9mHtZ+yzd3X5KbV5JPbCFj9L1rCS4x9yG8jAUhLsFR+kDXkWVtvl8KMvp5z5ptCz\n",
        "9QcL/EN120y+p2EqvSHnclkUIeCzjuFMQrY3MqSDgi7fbNEmB5yGU1Se3cmaNMggKCRYcz\n",
        "k4Cw6xprLRJmo26XioTYIOTYLTn5976lXBEV2kdPMzF9AAAAgEEG2EONFQeeYnitQOZcTR\n",
        "XYL9ifG3Np8IMa+X3wDRZASw0Z1lMBj3M9IxKhKynPxrkVYgTAjnPwJ92zTe7BuGTD2qKS\n",
        "Zi6PgS72dOta6eHIJCgvOAeZ2atuCcbUy7eddGbu2d7rwHBlGIPKNKBWCALcLsZxCYLblF\n",
        "xqSQtr0/O/AAAAgQD5TbiYzf26CzbVUIwyWI7nlvSa3au/QI24xCnESKx9hLJTQnQ0r6MQ\n",
        "mONvZbjJ9Dci1/BWRy9HDA5VILN0FA4ohyAnV7iEr4i1yVtuB9jcQsjKxbEQZ8GSPn1N2j\n",
        "BC5/zEnpJEi+uz5KlPOH6krYEIXsV3SckH22dq9LxxvLD+KwAAAIEAyL7rNXSg2K92Dt6g\n",
        "+ILgVPcjQPOa1h8i2xeXX+9HJdkU4mDIlR8SXIOVXSO+Ewzs2GyyU+lWcbRW+pZKbEVnV5\n",
        "Qx4SMZJPClPqI3dzi40Z5pRqHgW4XPQkOGvvGB3iTfBmZJ2vpkN+E3xt7FbrZ5RGpLSGrJ\n",
        "uWv2SXiQNYRrHY8AAAATb2JlbGlza0BleGNsYXZlLmxhbg==\n",
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
    let priv_pubkey = privkey.pubkey.clone();

    let user_cert = Certificate::builder(&ssh_pubkey, CertType::User, &priv_pubkey)
        .unwrap()
        .serial(0xFEFEFEFEFEFEFEFE)
        .key_id("key_id")
        .principal("obelisk")
        .valid_after(0)
        .valid_before(0xFFFFFFFFFFFFFFFF)
        .set_extensions(Certificate::standard_extensions())
        .sign(&privkey);

    match &user_cert {
        Ok(_) => (),
        Err(e) => {
            println!("Error: {}", e);
            assert!(user_cert.is_ok());
        }
    }

    // Check user fields
    let user_cert = user_cert.unwrap();
    assert_eq!(user_cert.principals, vec!["obelisk"]);
    assert_eq!(user_cert.critical_options, std::collections::HashMap::new());
    assert_eq!(user_cert.extensions.len(), 5);
    assert_eq!(user_cert.serial, 0xFEFEFEFEFEFEFEFE);
    assert_eq!(user_cert.valid_after, 0);
    assert_eq!(user_cert.valid_before, 0xFFFFFFFFFFFFFFFF);

    // Check CA fields
    assert_eq!(
        user_cert.signature_key.fingerprint().hash,
        "A7S6yWfLWgKphtN5UzBbKbhSE71bK/NB6x6NE0DJOpU"
    );
}

#[test]
fn create_sign_parse_verify_ed25519ca_chained_method_invocation() {
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
}
