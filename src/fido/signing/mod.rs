//! For signing data with FIDO-backed SSH keys
//!
//! # Blocking
//!
//! Signing requires user presence, so every backend blocks until the user
//! touches the device. With the `fido-support-mozilla` backend the wait is
//! bounded by a 15 second operation timeout; with the `fido-support` backend
//! the wait is typically bounded by the device's own user-presence timeout
//! (about 30 seconds). Run signing on a worker thread if a different timeout
//! is needed.

#[cfg(any(feature = "fido-support"))]
mod ctap2_hid;
#[cfg(any(feature = "fido-support"))]
pub use ctap2_hid::sign_with_private_key;

#[cfg(any(feature = "fido-support-mozilla"))]
mod mozilla;
#[cfg(any(feature = "fido-support-mozilla"))]
pub use mozilla::sign_with_private_key;
