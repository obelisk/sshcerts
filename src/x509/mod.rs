use x509_parser::prelude::FromDer;

use crate::error::Error;
use crate::ssh::{
    Curve,
    EcdsaPublicKey,
    KeyType,
    PublicKey,
    PublicKeyKind,
};

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";

/// This function is used to extract an SSH public key from an x509
/// certificate signing request
pub fn extract_ssh_pubkey_from_x509_certificate(cert: &[u8]) -> Result<PublicKey, Error> {
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
pub fn extract_ssh_pubkey_from_x509_csr(csr: &[u8]) -> Result<PublicKey, Error> {
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

fn convert_x509_pki_to_pubkey(pki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Result<PublicKey, Error> {
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
                _ => Err(Error::KeyTypeMismatch),
            }
        }
        _ => Err(Error::ParsingError),
    }
}