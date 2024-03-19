#[cfg(any(feature = "fido-support"))]
mod ctap2_hid;
#[cfg(any(feature = "fido-support"))]
pub use ctap2_hid::sign_with_private_key;

#[cfg(any(feature = "fido-support-mozilla"))]
mod mozilla;
#[cfg(any(feature = "fido-support-mozilla"))]
pub use mozilla::sign_with_private_key;
