/// Functions for dealing with Yubikey signing using PIV.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
#[cfg(any(feature = "yubikey-support"))]
pub mod piv;

/// For verifying attestation chains of Yubikey PIV keys
#[cfg(any(feature = "yubikey-lite", feature = "yubikey-support"))]
pub mod verification;
