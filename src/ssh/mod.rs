/*
Copyright (c) 2017 Marin Atanasov Nikolov <dnaeon@gmail.com>
All rights reserved.
*/

//! This module is a heavily modified version of the `sshkeys` crate
//! that adds certificate verification, and many other things to
//! support that. The original licence for the code is in the source
//! code provided

mod cert;
mod error;
mod keytype;
mod pubkey;
mod reader;
mod writer;

pub use self::cert::{CertType, Certificate, CriticalOptions, Extensions};
pub use self::error::{Error, Result};
pub use self::keytype::{KeyType, KeyTypeKind};
pub use self::pubkey::{
    Curve, CurveKind, EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind,
    PublicKey, PublicKeyKind, RsaPublicKey,
};
pub use self::reader::Reader;
pub use self::writer::Writer;
