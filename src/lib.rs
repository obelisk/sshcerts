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
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

#[cfg(feature = "yubikey")]
#[macro_use]
extern crate log;

/// Functions or structs for dealing with SSH Certificates.
/// Parsing, and creating certs happens here.
pub mod ssh;

/// Utility functions for dealing with SSH certificates, signatures
/// or conversions
pub mod utils;

/// Functions for dealing with Yubikey signing.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
#[cfg(feature = "yubikey")]
pub mod yubikey;

pub use ssh::{Certificate, PublicKey, PrivateKey};