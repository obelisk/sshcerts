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
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    InternalYubiKeyError(String),
}

// Re-export because it's used as a parameter in `sign_data`
pub use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};

/// Structure to wrap a yubikey and abstract actions
pub struct Yubikey {
    yk: yubikey_piv::yubikey::YubiKey,
}

//TODO @obelisk Fix this
impl std::fmt::Debug for Yubikey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SSHCerts YubiKey")
    }
}