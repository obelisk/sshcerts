mod ssh;
mod management;

// Re-export because it's used as a parameter in `sign_data`
pub use yubikey_piv::key::{AlgorithmId, RetiredSlotId, SlotId};

pub use management::Error;
pub use management::{configured, fetch_pubkey, provision, sign_data};
pub use ssh::{ssh_cert_fetch_pubkey, ssh_cert_signer};