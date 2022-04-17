use crate::PrivateKey;
use crate::ssh::PublicKeyKind;
use crate::ssh::PrivateKeyKind;
use crate::utils::format_signature_for_ssh;

use ctap_hid_fido2::{
    Cfg,
    HidParam,
    FidoKeyHid,
    fidokey::{
        GetAssertionArgsBuilder,
    },
};


/// Sign data with a SK type private key
pub fn sign_with_private_key(private_key: &PrivateKey, challenge: &[u8]) -> Option<Vec<u8>> {
    let (handle, pin, device_path): (&Vec<u8>, _, _) = match &private_key.kind {
        PrivateKeyKind::EcdsaSk(key) => (key.handle.as_ref(), key.pin.as_ref(), key.device_path.as_ref()),
        PrivateKeyKind::Ed25519Sk(key) => (key.handle.as_ref(), key.pin.as_ref(), key.device_path.as_ref()),
        _ => return None,
    };

    // It should be safe to unwrap here because we've already determined
    // the PrivateKey is of SK type
    let sk_application = match &private_key.pubkey.kind {
        PublicKeyKind::Ed25519(key) => key.sk_application.as_ref().unwrap(),
        PublicKeyKind::Ecdsa(key) => key.sk_application.as_ref().unwrap(),
        _ => return None,
    };

    let device = if let Some(path) = &device_path {
        FidoKeyHid::new(&[HidParam::Path(path.to_string())], &Cfg::init())
    } else {
        let fido_devices: Vec<HidParam> = ctap_hid_fido2::get_fidokey_devices().into_iter().map(|x| x.param).collect();
        FidoKeyHid::new(&fido_devices, &Cfg::init())
    };

    let device = device.ok()?;

    let args = GetAssertionArgsBuilder::new(&sk_application, &challenge).credential_id(handle);

    let args = if let Some(pin) = pin {
        args.pin(pin)
    } else {
        args.without_pin_and_uv()
    };

    let mut assert = device.get_assertion_with_args(&args.build()).ok()?;
    let assert = assert.pop()?;

    let signature = &assert.signature;
    let mut format = format_signature_for_ssh(&private_key.pubkey, &signature).unwrap();
    format.push(assert.flags.as_u8());
    format.extend_from_slice(&assert.sign_count.to_be_bytes());
    
    Some(format)
}