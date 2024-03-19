#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
/// For generating new SSH keys on FIDO devices
pub mod generate;

/// For handling FIDO related errors
#[derive(Debug)]
pub enum Error {
    /// An operation errored because the incorrect pin was provided
    InvalidPin(Option<u8>),
    /// An operation failed because a pin was required but not provided
    PinRequired,
    /// The key is temporarily locked because the incorrect pin was provided too many times
    KeyLocked,
    /// The key is permanently locked because the incorrect pin was provided too many times
    KeyBlocked,
    /// A CBOR formatting error occured
    CborFormat(String),
    /// An unknown error occured
    Unknown(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidPin(attempts) => {
                if let Some(attempts) = attempts {
                    format!("Invalid pin: {} attempts remaining", attempts)
                } else {
                    "Invalid pin".to_owned()
                }
            }
            Self::PinRequired => String::from("Pin required for operation"),
            Self::KeyLocked => String::from("Key locked"),
            Self::KeyBlocked => String::from("Key blocked"),
            Self::CborFormat(s) => s.to_string(),
            Self::Unknown(s) => s.to_string(),
        };
        write!(f, "s{}", msg)
    }
}

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
/// For parsing FIDO related data
pub mod parsing;

/// Contains utility functions for dealing with FIDO keys
#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
mod utils;
#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
pub use utils::*;

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
pub use parsing::{AuthData, CoseKey};

/// For handling signing operations with FIDO keys
#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
pub mod signing;

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
/// For code relating to the verification of FIDO certificate chains and
/// certificate parsing
pub mod verification;

#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
pub use generate::FIDOSSHKey;
