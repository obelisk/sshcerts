/// The SSH submodule contains functions relevant to SSH uses that are backed
/// by the Yubikey. This includes things like signing and SSH public key
/// export.
pub mod ssh;
mod management;

/// Errors when interacting with the Yubikey.
#[derive(Debug)]
pub enum Error {
    /// Generally this occurs when a slot is asked to return or process data
    /// when it has no certificate or private key.
    Unprovisioned,
    /// This occurs when the signature type requested does not match the key
    /// in the slot on the key
    WrongKeyType,
    /// This occurs when you try to use a feature that should technically work
    /// but is currently unimplemented or unsupported on the hardware connected.
    /// For example, RSA signing will currently throw this error.
    Unsupported,
    /// If you pass a management key into the provision function that does not
    /// deserialize from bytes, you will get this error.
    InvalidManagementKey,
    /// If you provide invalid bytes that cannot be converted from an x509 to
    /// a SSH key.
    ParsingError,
    /// The requested key could not be found connected to the system. It's
    /// possible it was removed while running.
    NoSuchYubikey,
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    InternalYubiKeyError(String),
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

// Re-export because it's used as a parameter in `sign_data`
pub use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};

/// Structure to wrap a yubikey and abstract actions
pub struct Yubikey {
    yk: yubikey_piv::yubikey::YubiKey,
}

impl std::fmt::Debug for Yubikey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "YubiKey: {}", self.yk.serial().to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::Unprovisioned => write!(f, "Slot is unprovisioned for signing"),
            Error::WrongKeyType => write!(f, "Wrong key type was provided for requested signing operation"),
            Error::Unsupported => write!(f, "This key is not supported the way you tried to use it"),
            Error::InvalidManagementKey => write!(f, "Could not use the management key as provided"),
            Error::ParsingError => write!(f, "Could not parse data"),
            Error::NoSuchYubikey => write!(f, "Could not find the requested Yubikey"),
            Error::InternalYubiKeyError(ref err) => write!(f, "Yubikey error: {}", err),
        }
    }
}
