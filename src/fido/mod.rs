#[cfg(feature = "fido-support")]
/// For generating new SSH keys on FIDO devices
pub mod generate;

#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
/// For parsing FIDO related data
pub mod parsing;
#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
pub use parsing::{AuthData, CoseKey};

#[cfg(feature = "fido-support")]
/// For signing related code
pub mod signing;

#[cfg(any(feature = "fido-support", feature = "fido-lite"))]
/// For code relating to the verification of FIDO certificate chains and
/// certificate parsing
pub mod verification;

#[cfg(feature = "fido-support")]
pub use generate::FIDOSSHKey;

#[cfg(feature = "fido-support")]
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

#[cfg(feature = "fido-support")]
/// For listing all connected FIDO2 devices. The pathes returned
/// in the descriptors can be used in private keys to route calls
/// to the correct device.
pub fn list_fido_devices() -> Vec<FidoDeviceDescriptor> {
    use ctap_hid_fido2::HidParam;

    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .filter_map(|x| match x.param {
            HidParam::Path(p) => Some(FidoDeviceDescriptor {
                path: p,
                product_string: x.product_string,
            }),
            _ => None,
        })
        .collect()
}
