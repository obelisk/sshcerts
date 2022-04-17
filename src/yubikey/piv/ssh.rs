use yubikey::piv::{AlgorithmId, SlotId};
use crate::ssh::{
    CurveKind,
    PublicKey,
    PublicKeyKind,
};

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

    /// Sign the provided buffer of data
    pub fn ssh_cert_signer(&mut self, buf: &[u8], slot: &SlotId) -> Result<Vec<u8>> {
        let alg = match self.get_ssh_key_type(slot) {
            Ok(x) => x,
            _ => return Err(Error::Unsupported),
        };

        let buf = self.sign_data(buf, alg, slot)?;
        let pub_key = self.ssh_cert_fetch_pubkey(&slot)?;

        match crate::utils::format_signature_for_ssh(&pub_key, &buf) {
            Some(x) => Ok(x),
            None => Err(super::Error::ParsingError),
        }
    }
}