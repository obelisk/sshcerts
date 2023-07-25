#[cfg(any(feature = "fido-support"))]
use crate::error::Error;

#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
/// For generating new SSH keys on FIDO devices
pub mod generate;

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
/// For parsing FIDO related data
pub mod parsing;

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
pub use parsing::{AuthData, CoseKey};

/// For handling signing operations with FIDO keys
#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
pub mod signing;

#[cfg(any(
    feature = "fido-support",
    feature = "fido-support-mozilla",
    feature = "fido-lite"
))]
/// For code relating to the verification of FIDO certificate chains and
/// certificate parsing
pub mod verification;

#[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
pub use generate::FIDOSSHKey;

#[cfg(any(feature = "fido-support"))]
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

#[cfg(feature = "fido-support")]
/// Determine if the given device path requires a pin
pub fn device_requires_pin(path: &str) -> Result<bool, Error> {
    use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHid, HidParam};

    let device = match FidoKeyHid::new(&[HidParam::Path(path.to_string())], &Cfg::init()) {
        Ok(dev) => dev,
        Err(e) => return Err(Error::FidoError(e.to_string())),
    };

    match device.enable_info_option(&InfoOption::ClientPin) {
        Ok(Some(result)) => Ok(result),
        Ok(None) => return Err(Error::FidoError("Could not get pin status".to_owned())),
        Err(e) => return Err(Error::FidoError(e.to_string())),
    }
}

#[cfg(feature = "fido-support")]
/// Determine if the given device path requires a pin
pub fn device_pin_retries(path: &str) -> Result<i32, Error> {
    use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};

    let device = match FidoKeyHid::new(&[HidParam::Path(path.to_string())], &Cfg::init()) {
        Ok(dev) => dev,
        Err(e) => return Err(Error::FidoError(e.to_string())),
    };

    device
        .get_pin_retries()
        .map_err(|e| Error::FidoError(e.to_string()))
}
