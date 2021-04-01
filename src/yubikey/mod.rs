/// The SSH submodule contains functions relevant to SSH uses that are backed
/// by the Yubikey. This includes things like signing and SSH public key
/// export.
pub mod ssh;
mod management;

// Re-export because it's used as a parameter in `sign_data`
pub use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};

pub use management::Error;

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