use yubikey::piv::{AlgorithmId, SlotId};
use crate::ssh::{
    CurveKind,
    PublicKey,
    PublicKeyKind,
};

use crate::utils::signature_convert_asn1_ecdsa_to_ssh;
use crate::x509::extract_ssh_pubkey_from_x509_certificate;

use super::{Error, Result};

impl super::Yubikey {
    /// Pull the public key from the YubiKey and wrap it in a sshcerts
    /// PublicKey object.
    pub fn ssh_cert_fetch_pubkey(&mut self, slot: &SlotId) -> Result<PublicKey> {
        match extract_ssh_pubkey_from_x509_certificate(&self.fetch_certificate(slot)?) {
            Ok(public_key) => Ok(public_key),
            Err(crate::error::Error::ParsingError) => Err(super::Error::ParsingError),
            Err(crate::error::Error::KeyTypeMismatch) => Err(super::Error::WrongKeyType),
            Err(_) => Err(super::Error::Unsupported),
        }
    }

    /// Returns the AlgorithmId of the kind of key stored in the given
    /// slot. This could return RSA key types as they are valid but
    /// currently it only differentiates between no key, and ECCP256 and ECCP384
    pub fn get_ssh_key_type(&mut self, slot: &SlotId) -> Result<AlgorithmId> {
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
    pub fn ssh_cert_signer(&mut self, buf: &[u8], slot: &SlotId) -> Result<Vec<u8>> {
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