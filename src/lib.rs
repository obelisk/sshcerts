//!
//! The 'sshcerts` crate provides types and methods for parsing
//! OpenSSH keys, and parsing, verifying, and creating SSH certificates.
//!
//! The following OpenSSH key types are supported.
//!
//! - RSA
//! - ECDSA
//! - ED25519
//!
//! The following OpenSSH certificate types are supported.
//!
//! - ssh-rsa-cert-v01@openssh.com
//! - ecdsa-sha2-nistp256-cert-v01@openssh.com
//! - ecdsa-sha2-nistp384-cert-v01@openssh.com
//! - ssh-ed25519-cert-v01@openssh.com
//!
//! ### Why no ecdsa-sha2-nistp521-cert-v01@openssh.com?
//! That curve is not supported on a standard yubikey nor in `ring`. This
//! means I cannot implement any signing or verification routines. If this
//! changes, I will update this crate with support.
//!
//! The crate also provides functionality for provision key slots on
//! Yubikeys to handle signing operations. This is provided in the
//! optional `yubikey` submodule
//!

#![deny(
    anonymous_parameters,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_qualifications
)]
#![feature(async_fn_in_trait)]


/// The `sshcerts` error enum
pub mod error;

type Result<T> = std::result::Result<T, error::Error>;

pub use ssh::{CertType, Certificate, PrivateKey, PublicKey};

/// Functions or structs for dealing with SSH Certificates.
/// Parsing, and creating certs happens here.
pub mod ssh;

/// Utility functions for dealing with SSH certificates, signatures
/// or conversions
pub mod utils;

/// Functions for dealing with Yubikey signing.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
#[cfg(any(feature = "yubikey-lite", feature = "yubikey-support"))]
pub mod yubikey;

/// Contains some helper functions for pulling SSH public keys from x509
/// certificates and CSRs. Is enabled whenever yubikey_support is enabled
/// because some functionality is currently shared.
#[cfg(any(feature = "x509-support", feature = "yubikey-support"))]
pub mod x509;

/// For dealing with FIDO/U2F tokens such as generating new SSH keys
#[cfg(any(feature = "fido-lite", feature = "fido-support"))]
pub mod fido;
