/// Functions for dealing with Yubikey signing using PIV.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
#[cfg(feature = "yubikey_piv")]
pub mod piv;

/// Functions for dealing with Yubikey signing using FIDO.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
#[cfg(feature = "yubikey_fido")]
pub mod fido;

/// Errors when interacting with the Yubikey.
#[derive(Debug)]
pub enum Error {
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    #[cfg(feature = "yubikey_piv")]
    PivError(piv::Error),
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    #[cfg(feature = "yubikey_fido")]
    FidoError(fido::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            #[cfg(feature = "yubikey_piv")]
            Error::PivError(ref e) => write!(f, "{}", e.to_string()),
            #[cfg(feature = "yubikey_fido")]
            Error::FidoError(ref e) => write!(f, "{}", e.to_string()),
        }
    }
}
