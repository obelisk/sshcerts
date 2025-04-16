use crate::error::Error;
use crate::ssh::{Curve, EcdsaPublicKey, KeyType, PublicKey, PublicKeyKind};

use x509_cert::der::Encode;
use x509_cert::{
    der::{oid::ObjectIdentifier, Decode},
    spki::SubjectPublicKeyInfo,
};

const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const NISTP256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const NISTP384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");


/// Helper function to convert a DER encoded public key, into an SSH formatted
/// public key that can be used with the rest of the SSHCerts library. This
/// function only supports NISTP256 and NISTP384 Ecdsa keys
pub fn der_encoding_to_ssh_public_key(key: &[u8]) -> Result<PublicKey, Error> {
    let spki = SubjectPublicKeyInfo::from_der(key).map_err(|_| Error::ParsingError)?;

    let oid_alg = spki
        .algorithm
        .parameters_oid()
        .map_err(|_| Error::ParsingError)?;

    let (key_type, curve) = match oid_alg {
        NISTP256_OID => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
            let curve = Curve::from_identifier("nistp256").unwrap();
            (key_type, curve)
        }
        NISTP384_OID => {
            let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
            let curve = Curve::from_identifier("nistp384").unwrap();
            (key_type, curve)
        }
        _ => return Err(Error::KeyTypeMismatch),
    };

    let kind = EcdsaPublicKey {
        curve,
        key: spki.subject_public_key,
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
    let cert  = x509_cert::Certificate::from_der(cert)
        .map_err(|_| Error::ParsingError)?;
    let spki = cert.tbs_certificate.subject_public_key_info.to_der()
        .map_err(|_| Error::ParsingError)?;
    let spki = SubjectPublicKeyInfo::<ObjectIdentifier, Vec<u8>>::from_der(&spki)
        .map_err(|_| Error::ParsingError)?;
    convert_x509_pki_to_pubkey(spki)
}

/// This function is used to extract an SSH public key from an x509
/// certificate signing request
pub fn extract_ssh_pubkey_from_x509_csr(csr: &[u8]) -> Result<PublicKey, Error> {
    let parsed_csr = x509_cert::request::CertReqInfo::from_der(csr)
        .map_err(|_| Error::ParsingError)?;
    let spki = &parsed_csr.public_key.to_der()
        .map_err(|_| Error::ParsingError)?;
    let spki = SubjectPublicKeyInfo::<ObjectIdentifier, Vec<u8>>::from_der(&spki)
        .map_err(|_| Error::ParsingError)?;
    convert_x509_pki_to_pubkey(spki)
}

fn convert_x509_pki_to_pubkey<Key: Into<Vec<u8>>>(
    pki: SubjectPublicKeyInfo<ObjectIdentifier, Key>,
) -> Result<PublicKey, Error> {
    return match pki.algorithm.oid {
        RSA_ENCRYPTION_OID => Err(Error::Unsupported),
        EC_PUBLIC_KEY_OID => {
            let key_bytes: Vec<u8> = pki.subject_public_key.into();
            let curve_oid = pki
                .algorithm
                .parameters
                .ok_or(Error::ParsingError)?;

            match curve_oid {
                NISTP256_OID => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
                    let curve = Curve::from_identifier("nistp256").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes,
                        sk_application: None,
                    };

                    Ok(PublicKey {
                        key_type,
                        kind: PublicKeyKind::Ecdsa(kind),
                        comment: None,
                    })
                }
                NISTP384_OID => {
                    let key_type = KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
                    let curve = Curve::from_identifier("nistp384").unwrap();
                    let kind = EcdsaPublicKey {
                        curve,
                        key: key_bytes,
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
