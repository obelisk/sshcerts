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
mod signer;
mod writer;

/// This is a type that can be used for certificate signing when passed
/// to Certificate::new
pub type SigningFunction = Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

pub use self::cert::{CertType, Certificate, CriticalOptions, Extensions};
pub use self::keytype::{KeyType, KeyTypeKind, Curve, CurveKind};
pub use self::privkey::{PrivateKey, PrivateKeyKind, RsaPrivateKey, EcdsaPrivateKey, Ed25519PrivateKey};
pub use self::pubkey::{
    EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind,
    PublicKey, PublicKeyKind, RsaPublicKey,
};
pub use self::reader::Reader;
pub use self::signer::{create_signer, ssh_cert_signer};
pub use self::writer::Writer;
