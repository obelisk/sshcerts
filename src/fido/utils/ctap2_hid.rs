use super::FidoDeviceDescriptor;
use crate::error::Error;
use crate::fido::Error as FidoError;

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
        Err(e) => return Err(Error::FidoError(FidoError::Unknown(e.to_string()))),
    };

    match device.enable_info_option(&InfoOption::ClientPin) {
        Ok(Some(result)) => Ok(result),
        Ok(None) => {
            return Err(Error::FidoError(FidoError::Unknown(
                "Could not get pin status".to_owned(),
            )))
        }
        Err(e) => return Err(Error::FidoError(FidoError::Unknown(e.to_string()))),
    }
}

#[cfg(feature = "fido-support")]
/// Determine if the given device path requires a pin
pub fn device_pin_retries(path: &str) -> Result<i32, Error> {
    use ctap_hid_fido2::{Cfg, FidoKeyHid, HidParam};

    let device = match FidoKeyHid::new(&[HidParam::Path(path.to_string())], &Cfg::init()) {
        Ok(dev) => dev,
        Err(e) => return Err(Error::FidoError(FidoError::Unknown(e.to_string()))),
    };

    device
        .get_pin_retries()
        .map_err(|e| Error::FidoError(FidoError::Unknown(e.to_string())))
}
