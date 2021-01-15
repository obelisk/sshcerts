//! 
//! The `rustica-keys` crate provides types and methods for parsing
//! OpenSSH public keys, and parsing then verifying SSH certificates.
//!
//! The following public key types are supported.
//!
//! - RSA
//! - ECDSA
//! - ED25519
//!
//! The following OpenSSH certificate types are supported as well.
//!
//! - ssh-rsa-cert-v01@openssh.com
//! - ecdsa-sha2-nistp256-cert-v01@openssh.com
//! - ecdsa-sha2-nistp384-cert-v01@openssh.com  (Not yet)
//! - ecdsa-sha2-nistp512-cert-v01@openssh.com  (Not yet)
//! - ssh-ed25519-cert-v01@openssh.com          (Not yet)
//!
//! The crate also provides functionality for provision key slots on
//! Yubikeys to handle signing operations. This is provided in `yubikey`
//! module.
//! 
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

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
pub mod yubikey;

pub use ssh::{Certificate, PublicKey};