/// The SSH submodule contains functions relevant to SSH uses that are backed
/// by the Yubikey. This includes things like signing and SSH public key
/// export.
pub mod ssh;
mod management;

// Re-export because it's used as a parameter in `sign_data`
pub use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};

pub use management::Error;
pub use management::{configured, fetch_attestation, fetch_pubkey, fetch_subject, provision, sign_data};