use yubikey_piv::key::{AlgorithmId, SlotId};
use yubikey_piv::certificate::PublicKeyInfo;

use crate::yubikey::management::{fetch_pubkey, sign_data};

use crate::ssh::{
    Curve,
    CurveKind,
    EcdsaPublicKey,
    KeyType,
    PublicKey,
    PublicKeyKind,
};

use crate::utils::signature_convert_asn1_ecdsa_to_ssh;

/// Pull the public key from the YubiKey and wrap it in a Rustica
/// PublicKey object.
pub fn ssh_cert_fetch_pubkey(slot: SlotId) -> Option<PublicKey> {
    match fetch_pubkey(slot) {
        //Ok(hsm::PublicKeyInfo::Rsa { pubkey, .. }) => pubkey,
        Ok(PublicKeyInfo::EcP256(pubkey)) => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
            let curve = Curve::from_identifier("nistp256").unwrap();
            let kind = EcdsaPublicKey {
                curve,
                key: pubkey.as_bytes().to_vec(),
            };

            Some(PublicKey {
                key_type,
                kind: PublicKeyKind::Ecdsa(kind),
                comment: None,
            })
        },
        Ok(PublicKeyInfo::EcP384(pubkey)) => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
            let curve = Curve::from_identifier("nistp384").unwrap();
            let kind = EcdsaPublicKey {
                curve,
                key: pubkey.as_bytes().to_vec(),
            };

            Some(PublicKey {
                key_type,
                kind: PublicKeyKind::Ecdsa(kind),
                comment: None,
            })
        }
        _ => None,
    }
}

/// Sign the provided buffer of data and return it in an SSH Certificiate
/// signature formatted byte vector
pub fn ssh_cert_signer(buf: &[u8], slot: SlotId) -> Option<Vec<u8>> {
    let pubkey = match ssh_cert_fetch_pubkey(slot) {
        None => return None,
        Some(pk) => pk,
    };

    let (alg, sig_type) = match pubkey.kind {
        PublicKeyKind::Ecdsa(x) => {
            match x.curve.kind {
                CurveKind::Nistp256 => (AlgorithmId::EccP256, "ecdsa-sha2-nistp256"),
                CurveKind::Nistp384 => (AlgorithmId::EccP384, "ecdsa-sha2-nistp384"),
                CurveKind::Nistp521 => return None,
            }
        },
        PublicKeyKind::Rsa(_) => return None,
        PublicKeyKind::Ed25519(_) => return None,
    };

    match sign_data(&buf, alg, slot) {
        Ok(signature) => {
            let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
            encoded.extend_from_slice(sig_type.as_bytes());
            let sig_encoding = match signature_convert_asn1_ecdsa_to_ssh(&signature) {
                Some(se) => se,
                None => return None,
            };

            encoded.extend(sig_encoding);
            Some(encoded)
        },
        Err(e) => {
            error!("SSH Cert Signer Error: {:?}", e);
            None
        },
    }
}
