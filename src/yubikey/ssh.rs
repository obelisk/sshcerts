use yubikey_piv::key::{AlgorithmId, SlotId};
use yubikey_piv::certificate::{Certificate, PublicKeyInfo};

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

/// This function is used to convert the Yubikey PIV type, to the internal
/// PublicKey type.
pub fn convert_to_ssh_pubkey(pki: &PublicKeyInfo) -> Option<PublicKey> {
    match pki {
        //Ok(hsm::PublicKeyInfo::Rsa { pubkey, .. }) => pubkey,
        PublicKeyInfo::EcP256(pubkey) => {
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
        PublicKeyInfo::EcP384(pubkey) => {
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

/// This function is used to convert a der encoded certificate to the internal
/// PublicKey type.
pub fn convert_x509_to_ssh_pubkey(certificate: &[u8]) -> Option<PublicKey> {
    let certificate = match Certificate::from_bytes(certificate.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            error!("Parsing Error: {:?}", e);
            return None
        }
    };
    convert_to_ssh_pubkey(certificate.subject_pki())
}


/// Pull the public key from the YubiKey and wrap it in a sshcerts
/// PublicKey object.
pub fn ssh_cert_fetch_pubkey(slot: SlotId) -> Option<PublicKey> {
    match fetch_pubkey(slot) {
        Ok(pki) => convert_to_ssh_pubkey(&pki),
        _ => None,
    }
}

/// Returns the AlgorithmId of the kind of key stored in the given
/// slot. This could return RSA key types as they are valid but
/// currently it only differentiates between no key, and ECCP256 and ECCP384
pub fn get_ssh_key_type(slot: SlotId) -> Option<AlgorithmId> {
    let pubkey = match ssh_cert_fetch_pubkey(slot) {
        None => return None,
        Some(pk) => pk,
    };

     match pubkey.kind {
        PublicKeyKind::Ecdsa(x) => {
            match x.curve.kind {
                CurveKind::Nistp256 => Some(AlgorithmId::EccP256),
                CurveKind::Nistp384 => Some(AlgorithmId::EccP384),
                CurveKind::Nistp521 => None,
            }
        },
        PublicKeyKind::Rsa(_) => None,
        PublicKeyKind::Ed25519(_) => None,
    }
}

/// Sign the provided buffer of data and return it in an SSH Certificiate
/// signature formatted byte vector
pub fn ssh_cert_signer(buf: &[u8], slot: SlotId) -> Option<Vec<u8>> {
    let (alg, sig_type) = match get_ssh_key_type(slot) {
        Some(AlgorithmId::EccP256) => (AlgorithmId::EccP256, "ecdsa-sha2-nistp256"),
        Some(AlgorithmId::EccP384) => (AlgorithmId::EccP384, "ecdsa-sha2-nistp384"),
        _ => return None,
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
