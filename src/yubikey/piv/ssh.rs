use x509_parser::prelude::FromDer;

use yubikey::piv::{AlgorithmId, SlotId};
use crate::ssh::{
    Curve,
    CurveKind,
    EcdsaPublicKey,
    KeyType,
    PublicKey,
    PublicKeyKind,
};

use crate::utils::signature_convert_asn1_ecdsa_to_ssh;

use super::{Error, Result};

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";

impl super::Yubikey {
    /// Pull the public key from the YubiKey and wrap it in a sshcerts
    /// PublicKey object.
    pub fn ssh_cert_fetch_pubkey(&mut self, slot: &SlotId) -> Result<PublicKey> {
        extract_ssh_pubkey_from_x509_certificate(&self.fetch_certificate(slot)?)
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

/// This function is used to extract an SSH public key from an x509
/// certificate signing request
pub fn extract_ssh_pubkey_from_x509_certificate(cert: &[u8]) -> Result<PublicKey> {
    let parsed_cert = match x509_parser::parse_x509_certificate(&cert) {
        Ok((_, c)) => c,
        Err(e) => {
            error!("Parsing Error: {:?}", e);
            return Err(Error::ParsingError)
        }
    };
    let pki = &parsed_cert.tbs_certificate.subject_pki;
    convert_x509_pki_to_pubkey(pki)
}

/// This function is used to extract an SSH public key from an x509
/// certificate signing request
pub fn extract_ssh_pubkey_from_x509_csr(csr: &[u8]) -> Result<PublicKey> {
    let parsed_csr = match x509_parser::certification_request::X509CertificationRequest::from_der(&csr) {
        Ok((_, csr)) => csr,
        Err(e) => {
            error!("Parsing Error: {:?}", e);
            return Err(Error::ParsingError)
        }
    };
    let pki = &parsed_csr.certification_request_info.subject_pki;
    convert_x509_pki_to_pubkey(pki)
}

fn convert_x509_pki_to_pubkey(pki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Result<PublicKey> {
    return match pki.algorithm.algorithm.to_string().as_str() {
        OID_RSA_ENCRYPTION => {
            error!("RSA keys are not yet supported");
            Err(Error::Unsupported)
        },
        OID_EC_PUBLIC_KEY => {
            let key_bytes = &pki.subject_public_key.data;
            let algorithm_parameters = pki
                .algorithm
                .parameters
                .as_ref()
                .ok_or(Error::ParsingError)?;

            let curve_oid = algorithm_parameters.as_oid_val().map_err(|_| Error::ParsingError)?;

            match curve_oid.to_string().as_str() {
                OID_NIST_P256 => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
                    let curve = Curve::from_identifier("nistp256").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes.to_vec(),
                    };
        
                    Ok(PublicKey {
                        key_type,
                        kind: PublicKeyKind::Ecdsa(kind),
                        comment: None,
                    })
                },
                OID_NIST_P384 => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
                    let curve = Curve::from_identifier("nistp384").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes.to_vec(),
                    };
        
                    Ok(PublicKey {
                        key_type,
                        kind: PublicKeyKind::Ecdsa(kind),
                        comment: None,
                    })
                }
                _ => Err(Error::WrongKeyType),
            }
        }
        _ => Err(Error::ParsingError),
    }
}