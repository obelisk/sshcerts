/*
Copyright (c) 2017 Marin Atanasov Nikolov <dnaeon@gmail.com>
All rights reserved.
*/

//! This module is a heavily modified version of the `sshkeys` crate
//! that adds certificate verification, and many other things to
//! support that. The original licence for the code is in the source
//! code provided

mod cert;
mod keytype;
mod privkey;
mod pubkey;
mod reader;
mod writer;

/// Types that implement this trait can be used to sign SSH certificates using
/// the Certificate::sign function.
pub trait SSHCertificateSigner {
    /// This function is called when signing an SSH certificate.
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>>;
}

pub use self::cert::{CertType, Certificate};
pub use self::keytype::{KeyType, KeyTypeKind, Curve, CurveKind};
pub use self::privkey::{PrivateKey, PrivateKeyKind, RsaPrivateKey, EcdsaPrivateKey, Ed25519PrivateKey};
pub use self::pubkey::{
    EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind,
    PublicKey, PublicKeyKind, RsaPublicKey,
};
pub use self::reader::Reader;
pub use self::writer::Writer;
