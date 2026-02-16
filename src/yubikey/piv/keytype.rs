use crate::yubikey::piv::management::{NISTP256_OID, SECP384_OID};
use ring::digest;
use signature::Error as SignatureError;
use x509_cert::der::{asn1::BitString, Decode, Encode};
use x509_cert::spki;
use x509_cert::spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, ObjectIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoRef,
};
use yubikey::certificate::yubikey_signer::KeyType;
use yubikey::piv::AlgorithmId;

/// DER-encoded signature as returned by the YubiKey
#[derive(Clone, Debug)]
pub struct EcdsaSignature(pub Vec<u8>);

impl TryFrom<&[u8]> for EcdsaSignature {
    type Error = SignatureError;
    fn try_from(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(EcdsaSignature(bytes.to_vec()))
    }
}

impl SignatureBitStringEncoding for EcdsaSignature {
    fn to_bitstring(&self) -> x509_cert::der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

/// This serves as both PublicKey and VerifyingKey for KeyType.
#[derive(Clone, Debug)]
pub struct EcdsaKey {
    der: Vec<u8>,
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for EcdsaKey {
    type Error = spki::Error;
    fn try_from(spki_ref: SubjectPublicKeyInfoRef<'_>) -> Result<Self, spki::Error> {
        let der = spki_ref.to_der().map_err(spki::Error::Asn1)?;
        Ok(EcdsaKey { der })
    }
}

impl EncodePublicKey for EcdsaKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        spki::Document::try_from(self.der.as_slice()).map_err(spki::Error::Asn1)
    }
}

impl DynSignatureAlgorithmIdentifier for EcdsaKey {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        const ECDSA_SHA256_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384_OID: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

        let spki_ref =
            SubjectPublicKeyInfoRef::from_der(self.der.as_slice()).map_err(spki::Error::Asn1)?;
        let curve_oid = spki_ref
            .algorithm
            .parameters_oid()
            .map_err(|_| spki::Error::AlgorithmParametersMissing)?;
        let sig_oid = match curve_oid {
            oid if oid == NISTP256_OID => ECDSA_SHA256_OID,
            oid if oid == SECP384_OID => ECDSA_SHA384_OID,
            _ => return Err(spki::Error::OidUnknown { oid: curve_oid }),
        };
        Ok(AlgorithmIdentifier {
            oid: sig_oid,
            parameters: None,
        })
    }
}

/// P-256 (secp256r1) key type
#[derive(Debug)]
pub struct NistP256;

impl KeyType for NistP256 {
    type Error = SignatureError;
    type Signature = EcdsaSignature;
    type VerifyingKey = EcdsaKey;
    type PublicKey = EcdsaKey;

    const ALGORITHM: AlgorithmId = AlgorithmId::EccP256;

    fn prepare(input: &[u8]) -> Result<Vec<u8>, SignatureError> {
        Ok(digest::digest(&digest::SHA256, input).as_ref().to_vec())
    }

    fn read_signature(input: &[u8]) -> Result<Self::Signature, SignatureError> {
        EcdsaSignature::try_from(input)
    }
}

/// P-384 (secp384r1) key type
#[derive(Debug)]
pub struct NistP384;

impl KeyType for NistP384 {
    type Error = SignatureError;
    type Signature = EcdsaSignature;
    type VerifyingKey = EcdsaKey;
    type PublicKey = EcdsaKey;

    const ALGORITHM: AlgorithmId = AlgorithmId::EccP384;

    fn prepare(input: &[u8]) -> Result<Vec<u8>, SignatureError> {
        Ok(digest::digest(&digest::SHA384, input).as_ref().to_vec())
    }

    fn read_signature(input: &[u8]) -> Result<Self::Signature, SignatureError> {
        EcdsaSignature::try_from(input)
    }
}
