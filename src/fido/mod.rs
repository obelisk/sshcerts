#[cfg(feature = "fido-full")]
/// For generating new SSH keys on FIDO devices
pub mod generate;

#[cfg(any(feature = "fido-full", feature = "fido-lite"))]
/// For parsing FIDO related data
pub mod parsing;

#[cfg(feature = "fido-full")]
/// For signing related code
pub mod signing;

#[cfg(feature = "fido-full")]
pub use generate::FIDOSSHKey;