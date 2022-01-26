use crate::ssh::{CurveKind, PrivateKey, PrivateKeyKind, PublicKeyKind};

use ring::{rand, signature};

/// Take in a private key and return a function that can be passed to Certificate::new
/// for generating newly signed certificates. Generally this function is not needed
/// as the impl on PrivateKey for Into can be more easily used.
/// 
/// # Example
/// ```rust
/// use sshcerts::ssh::{PrivateKey, SigningFunction};
/// 
/// let privkey = concat!(
/// "-----BEGIN OPENSSH PRIVATE KEY-----\n",
/// "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
/// "QyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FAAAAJiT9ajkk/Wo\n",
/// "5AAAAAtzc2gtZWQyNTUxOQAAACDNCX6XlZn0QRMW14ABZa5GZc66U+csEiKsgkZwGK0+FA\n",
/// "AAAED6HgUU3Ps5TVdFCVO8uTpbfVdg3JBxnOz3DIWO1u1Xbc0JfpeVmfRBExbXgAFlrkZl\n",
/// "zrpT5ywSIqyCRnAYrT4UAAAAE29iZWxpc2tAZXhjbGF2ZS5sYW4BAg==\n",
/// "-----END OPENSSH PRIVATE KEY-----");
/// 
/// let privkey = PrivateKey::from_string(privkey).unwrap();
/// let signer:SigningFunction = privkey.into();
/// ```
pub fn create_signer(privkey: PrivateKey) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
    Box::new(move |buf: &[u8]| {
        ssh_cert_signer(buf, &privkey)
    })
}

/// This is in this file to prevent a circular dependency between PrivateKey
/// and the signer module.
impl From<PrivateKey> for Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
    fn from(priv_key: PrivateKey) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
        Box::new(move |buf: &[u8]| {
            ssh_cert_signer(buf, &priv_key)
        }) 
    }
}

/// Take a buffer and generate an SSH certificate style signature for it from
/// a PrivateKey type
pub fn ssh_cert_signer(buf: &[u8], privkey: &PrivateKey) -> Option<Vec<u8>> {
    let rng = rand::SystemRandom::new();

    match &privkey.kind {
        #[cfg(feature = "rsa-signing")]
        PrivateKeyKind::Rsa(key) => {
            let asn_privkey = match simple_asn1::der_encode(key) {
                Ok(apk) => apk,
                Err(_) => return None,
            };

            let keypair = match signature::RsaKeyPair::from_der(&asn_privkey) {
                Ok(kp) => kp,
                Err(_) => return None,
            };

            let rng = rand::SystemRandom::new();
            let mut signature = vec![0; keypair.public_modulus_len()];

            keypair.sign(&signature::RSA_PKCS1_SHA512, &rng, buf, &mut signature).ok()?;

            Some(signature)
        },
        #[cfg(not(feature = "rsa-signing"))]
        PrivateKeyKind::Rsa(_) => return None,
        PrivateKeyKind::Ecdsa(key) => {
            let alg = match key.curve.kind {
                CurveKind::Nistp256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                CurveKind::Nistp384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                CurveKind::Nistp521 => return None
            };

            let pubkey = match &privkey.pubkey.kind {
                PublicKeyKind::Ecdsa(key) => &key.key,
                _ => return None,
            };

            let key = if key.key[0] == 0x0_u8 {&key.key[1..]} else {&key.key};
            let key_pair = match signature::EcdsaKeyPair::from_private_key_and_public_key(alg, key, pubkey) {
                Ok(kp) => kp,
                Err(_) => return None,
            };

            match key_pair.sign(&rng, buf) {
                Ok(sig) => Some(sig.as_ref().to_vec()),
                Err(_) => None,
            }
        },
        PrivateKeyKind::Ed25519(key) => {
            let public_key = match &privkey.pubkey.kind {
                PublicKeyKind::Ed25519(key) => &key.key,
                _ => return None,
            };

            let key_pair = match signature::Ed25519KeyPair::from_seed_and_public_key(&key.key[..32], public_key) {
                Ok(kp) => kp,
                Err(_) => return None,
            };

            Some(key_pair.sign(buf).as_ref().to_vec())
        },
    }
}