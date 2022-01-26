/// Functions for dealing with Yubikey signing using PIV.
/// Also contains an SSH submodule containing helper functions to generate
/// SSH encoded versions of it's normal functions.
pub mod piv;

/// Errors when interacting with the Yubikey.
#[derive(Debug)]
pub enum Error {
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    PivError(piv::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::PivError(ref e) => write!(f, "{}", e),
        }
    }
}
