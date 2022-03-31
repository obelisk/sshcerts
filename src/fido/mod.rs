#[cfg(feature = "fido-support")]
/// For generating new SSH keys on FIDO devices
pub mod generate;

#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
/// For parsing FIDO related data
pub mod parsing;
#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
pub use parsing::{
    CoseKey,
    AuthData,
};

#[cfg(feature = "fido-support")]
/// For signing related code
pub mod signing;

#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
/// For code relating to the verification of FIDO certificate chains and
/// certificate parsing
pub mod verification;

#[cfg(feature = "fido-support")]
pub use generate::FIDOSSHKey;