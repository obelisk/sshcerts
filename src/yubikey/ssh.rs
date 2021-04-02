use yubikey_piv::key::{AlgorithmId, SlotId};
use yubikey_piv::certificate::{Certificate, PublicKeyInfo};

use crate::ssh::{
    Curve,
    CurveKind,
    EcdsaPublicKey,
    KeyType,
    PublicKey,
    PublicKeyKind,
};

use crate::utils::signature_convert_asn1_ecdsa_to_ssh;

use super::Error;

impl crate::yubikey::Yubikey {
    /// Pull the public key from the YubiKey and wrap it in a sshcerts
    /// PublicKey object.
    pub fn ssh_cert_fetch_pubkey(&mut self, slot: &SlotId) -> Result<PublicKey, Error> {
        convert_to_ssh_pubkey(&self.fetch_pubkey(slot)?)
    }

    /// Returns the AlgorithmId of the kind of key stored in the given
    /// slot. This could return RSA key types as they are valid but
    /// currently it only differentiates between no key, and ECCP256 and ECCP384
    pub fn get_ssh_key_type(&mut self, slot: &SlotId) -> Result<AlgorithmId, Error> {
        let pubkey = self.ssh_cert_fetch_pubkey(slot)?;

        match pubkey.kind {
            PublicKeyKind::Ecdsa(x) => {
                match x.curve.kind {
                    CurveKind::Nistp256 => Ok(AlgorithmId::EccP256),
                    CurveKind::Nistp384 => Ok(AlgorithmId::EccP384),
                    CurveKind::Nistp521 => Err(Error::Unsupported),
                }
            },
            PublicKeyKind::Rsa(_) => Err(Error::Unsupported),
            PublicKeyKind::Ed25519(_) => Err(Error::Unsupported),
        }
    }

    /// Sign the provided buffer of data and return it in an SSH Certificiate
    /// signature formatted byte vector. 
    /// 
    /// TODO: Consider if this is the right move or if the public api of New cert should change
    /// to also take a function that returns a result instead of an option.
    pub fn ssh_cert_signer(&mut self, buf: &[u8], slot: &SlotId) -> Result<Vec<u8>, Error> {
        let (alg, sig_type) = match self.get_ssh_key_type(slot) {
            Ok(AlgorithmId::EccP256) => (AlgorithmId::EccP256, "ecdsa-sha2-nistp256"),
            Ok(AlgorithmId::EccP384) => (AlgorithmId::EccP384, "ecdsa-sha2-nistp384"),
            _ => return Err(Error::Unsupported),
        };

        match self.sign_data(&buf, alg, slot) {
            Ok(signature) => {
                let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
                encoded.extend_from_slice(sig_type.as_bytes());
                let sig_encoding = match signature_convert_asn1_ecdsa_to_ssh(&signature) {
                    Some(se) => se,
                    None => return Err(Error::InternalYubiKeyError(String::from("Could not convert signature type"))),
                };

                encoded.extend(sig_encoding);
                Ok(encoded)
            },
            Err(e) => {
                error!("SSH Cert Signer Error: {:?}", e);
                Err(e)
            },
        }
    }

}

/// This function is used to convert the Yubikey PIV type, to the internal
/// PublicKey type.
pub fn convert_to_ssh_pubkey(pki: &PublicKeyInfo) -> Result<PublicKey, Error> {
    match pki {
        //Ok(hsm::PublicKeyInfo::Rsa { pubkey, .. }) => pubkey,
        PublicKeyInfo::EcP256(pubkey) => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
            let curve = Curve::from_identifier("nistp256").unwrap();
            let kind = EcdsaPublicKey {
                curve,
                key: pubkey.as_bytes().to_vec(),
            };

            Ok(PublicKey {
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

            Ok(PublicKey {
                key_type,
                kind: PublicKeyKind::Ecdsa(kind),
                comment: None,
            })
        }
        _ => Err(Error::Unsupported),
    }
}

/// This function is used to convert a der encoded certificate to the internal
/// PublicKey type.
pub fn convert_x509_to_ssh_pubkey(certificate: &[u8]) -> Result<PublicKey, Error> {
    let certificate = match Certificate::from_bytes(certificate.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            error!("Parsing Error: {:?}", e);
            return Err(Error::ParsingError)
        }
    };
    convert_to_ssh_pubkey(certificate.subject_pki())
}