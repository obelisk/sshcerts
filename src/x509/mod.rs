use x509_parser::prelude::FromDer;

use crate::error::Error;
use crate::ssh::{Curve, EcdsaPublicKey, KeyType, PublicKey, PublicKeyKind};

use der_parser::der::parse_der_sequence;
use der_parser::error::BerError;

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";

impl From<x509_parser::nom::Err<BerError>> for Error {
    fn from(_: x509_parser::nom::Err<BerError>) -> Error {
        Error::ParsingError
    }
}

impl From<BerError> for Error {
    fn from(_: BerError) -> Error {
        Error::ParsingError
    }
}

/// Helper function to convert a DER encoded public key, into an SSH formatted
/// public key that can be used with the rest of the SSHCerts library. This
/// function only supports NISTP256 and NISTP384 Ecdsa keys
pub fn der_encoding_to_ssh_public_key(key: &[u8]) -> Result<PublicKey, Error> {
    let (_rem, parsed) = parse_der_sequence(key).map_err(|_| Error::ParsingError)?;
    let parsed = parsed.as_sequence().map_err(|_| Error::ParsingError)?;

    if parsed.len() != 2 {
        return Err(Error::ParsingError);
    }

    let oids = &parsed[0].as_sequence()?;
    if oids.len() != 2 {
        return Err(Error::ParsingError);
    }

    let type_oid = oids[0].as_oid()?;
    let key_size_oid = oids[1].as_oid()?;
    if type_oid.to_id_string() != OID_EC_PUBLIC_KEY {
        return Err(Error::ParsingError);
    }

    let data = &parsed[1].as_bitstring()?.data;
    let (key_type, curve) = match key_size_oid.to_id_string().as_str() {
        OID_NIST_P256 => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
            let curve = Curve::from_identifier("nistp256").unwrap();
            (key_type, curve)
        }
        OID_NIST_P384 => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
            let curve = Curve::from_identifier("nistp384").unwrap();
            (key_type, curve)
        }
        _ => return Err(Error::KeyTypeMismatch),
    };

    let kind = EcdsaPublicKey {
        curve,
        key: data.to_vec(),
        sk_application: None,
    };

    Ok(PublicKey {
        key_type,
        kind: PublicKeyKind::Ecdsa(kind),
        comment: None,
    })
}

/// This function is used to extract an SSH public key from an x509
/// certificate
pub fn extract_ssh_pubkey_from_x509_certificate(cert: &[u8]) -> Result<PublicKey, Error> {
    let parsed_cert = match x509_parser::parse_x509_certificate(cert) {
        Ok((_, c)) => c,
        Err(_) => return Err(Error::ParsingError),
    };
    let pki = &parsed_cert.tbs_certificate.subject_pki;
    convert_x509_pki_to_pubkey(pki)
}

/// This function is used to extract an SSH public key from an x509
/// certificate signing request
pub fn extract_ssh_pubkey_from_x509_csr(csr: &[u8]) -> Result<PublicKey, Error> {
    let parsed_csr =
        match x509_parser::certification_request::X509CertificationRequest::from_der(csr) {
            Ok((_, csr)) => csr,
            Err(_) => return Err(Error::ParsingError),
        };
    let pki = &parsed_csr.certification_request_info.subject_pki;
    convert_x509_pki_to_pubkey(pki)
}

fn convert_x509_pki_to_pubkey(
    pki: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> Result<PublicKey, Error> {
    return match pki.algorithm.algorithm.to_string().as_str() {
        OID_RSA_ENCRYPTION => Err(Error::Unsupported),
        OID_EC_PUBLIC_KEY => {
            let key_bytes = &pki.subject_public_key.data;
            let algorithm_parameters = pki
                .algorithm
                .parameters
                .as_ref()
                .ok_or(Error::ParsingError)?;

            let curve_oid = algorithm_parameters
                .as_oid_val()
                .map_err(|_| Error::ParsingError)?;

            match curve_oid.to_string().as_str() {
                OID_NIST_P256 => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
                    let curve = Curve::from_identifier("nistp256").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes.to_vec(),
                        sk_application: None,
                    };

                    Ok(PublicKey {
                        key_type,
                        kind: PublicKeyKind::Ecdsa(kind),
                        comment: None,
                    })
                }
                OID_NIST_P384 => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
                    let curve = Curve::from_identifier("nistp384").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes.to_vec(),
                        sk_application: None,
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
    };
}
