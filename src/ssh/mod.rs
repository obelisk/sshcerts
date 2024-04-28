/*
Copyright (c) 2017 Marin Atanasov Nikolov <dnaeon@gmail.com>
All rights reserved.
*/

//! This module is a heavily modified version of the `sshkeys` crate
//! that adds certificate verification, and many other things to
//! support that. The original licence for the code is in the source
//! code provided

mod allowed_signer;
mod cert;
mod keytype;
mod privkey;
mod pubkey;
mod reader;
mod signature;
mod writer;

/// Types that implement this trait can be used to sign SSH certificates using
/// the Certificate::sign function.
pub trait SSHCertificateSigner {
    /// This function is called when signing an SSH certificate.
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>>;
}

pub use self::allowed_signer::{AllowedSigner, AllowedSigners};
pub use self::cert::{CertType, Certificate};
pub use self::keytype::{Curve, CurveKind, KeyType, KeyTypeKind};
pub use self::privkey::{
    EcdsaPrivateKey, EcdsaSkPrivateKey, Ed25519PrivateKey, Ed25519SkPrivateKey, PrivateKey,
    PrivateKeyKind, RsaPrivateKey,
};
pub use self::pubkey::{
    EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind, PublicKey, PublicKeyKind,
    RsaPublicKey,
};
pub use self::reader::Reader;
pub use self::signature::{HashAlgorithm, SshSignature, VerifiedSshSignature};
pub use self::writer::Writer;
