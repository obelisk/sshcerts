#[cfg(any(feature = "fido-support"))]
mod ctap2_hid;
#[cfg(any(feature = "fido-support"))]
pub use ctap2_hid::*;

#[cfg(any(feature = "fido-support-mozilla"))]
mod mozilla;
#[cfg(any(feature = "fido-support-mozilla"))]
pub use mozilla::*;

/// Defines a FIDO device with name and path. The path can be
/// used in PrivateKey to route the request to a particular device.
///
/// These paths are only valid while a device is connected continuously.
/// Disconnected and reconnecting will result in a new path and a key
/// must be updated accordingly.
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct FidoDeviceDescriptor {
    /// Product name that the device reports
    pub product_string: String,
    /// Path to be used for connecting to this particular device
    pub path: String,
}
