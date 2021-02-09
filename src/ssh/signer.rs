use crate::ssh::{CurveKind, PrivateKey, PrivateKeyKind, PublicKeyKind};
use crate::utils::signature_convert_asn1_ecdsa_to_ssh;

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

impl Into<Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>> for PrivateKey {
    fn into(self) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
        Box::new(move |buf: &[u8]| {
            ssh_cert_signer(buf, &self)
        })
    }
}

/// Take a buffer and generate an SSH certificate style signature for it from
/// a PrivateKey type
pub fn ssh_cert_signer(buf: &[u8], privkey: &PrivateKey) -> Option<Vec<u8>> {
    let rng = rand::SystemRandom::new();

    let (signature, sig_type) = match &privkey.kind {
        PrivateKeyKind::Rsa(_) => return None,
        PrivateKeyKind::Ecdsa(key) => {
            let (alg, alg_name) = match key.curve.kind {
                CurveKind::Nistp256 => (&signature::ECDSA_P256_SHA256_ASN1_SIGNING, "ecdsa-sha2-nistp256"),
                CurveKind::Nistp384 => (&signature::ECDSA_P384_SHA384_ASN1_SIGNING, "ecdsa-sha2-nistp384"),
                CurveKind::Nistp521 => return None
            };

            let pubkey = match &privkey.pubkey.kind {
                PublicKeyKind::Ecdsa(key) => &key.key,
                _ => return None,
            };

            let key = if key.key[0] == 0x0_u8 {&key.key[1..]} else {&key.key};
            let key_pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &key, &pubkey).unwrap();
            let signature = key_pair.sign(&rng, &buf).unwrap().as_ref().to_vec();
            let signature = signature_convert_asn1_ecdsa_to_ssh(&signature).unwrap();
            (signature, alg_name)
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

            let signature = key_pair.sign(&buf).as_ref().to_vec();
            let mut encoding = (signature.len() as u32).to_be_bytes().to_vec();
            encoding.extend(signature);

            (encoding, "ssh-ed25519")
        },
    };

    let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(sig_type.as_bytes());
    encoded.extend(signature);

    Some(encoded)
}