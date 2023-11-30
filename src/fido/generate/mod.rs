use crate::PrivateKey;

#[cfg(any(feature = "fido-support"))]
mod ctap2_hid;
#[cfg(any(feature = "fido-support"))]
pub use ctap2_hid::generate_new_ssh_key;

#[cfg(any(feature = "fido-support-mozilla"))]
mod mozilla;
#[cfg(any(feature = "fido-support-mozilla"))]
pub use mozilla::generate_new_ssh_key;

use super::verification::{verify_auth_data, ValidAttestation};

/// The attestation data, signature, and chain for a generated SSH key
#[derive(Debug)]
pub struct U2FAttestation {
    /// A blob that contains all public information that we can also verify with
    /// the attestation chain
    pub auth_data: Vec<u8>,
    /// The signature over the hash of the auth data
    pub auth_data_sig: Vec<u8>,
    /// The certificate that generated the signature over the auth data
    pub intermediate: Vec<u8>,
    /// The challenge that generated and is included in the signature
    pub challenge: Vec<u8>,
    /// The algorithm that was used to generate the signature (COSE value)
    pub alg: i32,
}

/// A generated SSH key that was generated with a FIDO/U2F key
#[derive(Debug)]
pub struct FIDOSSHKey {
    /// Private key handle to the new SSH Key on the hardware token
    pub private_key: PrivateKey,
    /// The U2F attestation data
    pub attestation: U2FAttestation,
}

impl U2FAttestation {
    /// Verify the attestation data, signature, and chain are valid
    pub fn verify(&self) -> Result<ValidAttestation, crate::error::Error> {
        verify_auth_data(
            &self.auth_data,
            &self.auth_data_sig,
            &self.challenge,
            self.alg,
            &self.intermediate,
            None,
        )
    }
}
