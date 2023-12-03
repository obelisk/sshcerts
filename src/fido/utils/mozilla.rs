use super::FidoDeviceDescriptor;
use crate::error::Error;
use crate::fido::Error as FidoError;

/// List the connected FIDO devices. This returns a empty
/// vector as Mozilla does not support listing devices.
pub fn list_fido_devices() -> Vec<FidoDeviceDescriptor> {
    vec![]
}

/// Determine if the given device path requires a pin
pub fn device_requires_pin(_: &str) -> Result<bool, Error> {
    Err(Error::FidoError(FidoError::Unknown(
        "Not currently supported directly fetching key PIN status".to_owned(),
    )))
}
