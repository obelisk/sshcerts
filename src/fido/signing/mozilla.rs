use crate::ssh::PrivateKeyKind;
use crate::ssh::PublicKeyKind;
use crate::utils::format_signature_for_ssh;
use crate::PrivateKey;

use ring::digest;

use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::{commands::get_assertion::*, server::*},
    errors::{AuthenticatorError, PinError},
    statecallback::StateCallback,
    Pin, SignResult, StatusUpdate,
};
use std::sync::mpsc::channel;

/// Sign data with a SK type private key
pub fn sign_with_private_key(private_key: &PrivateKey, challenge: &[u8]) -> Option<Vec<u8>> {
    let (handle, pin): (&[u8], _) = match &private_key.kind {
        PrivateKeyKind::EcdsaSk(key) => (key.handle.as_ref(), key.pin.as_ref()),
        PrivateKeyKind::Ed25519Sk(key) => (key.handle.as_ref(), key.pin.as_ref()),
        _ => return None,
    };

    let pin: Option<Pin> = pin.map(|x| Pin::new(x));

    // It should be safe to unwrap here because we've already determined
    // the PrivateKey is of SK type
    let sk_application = match &private_key.pubkey.kind {
        PublicKeyKind::Ed25519(key) => key.sk_application.as_ref().unwrap(),
        PublicKeyKind::Ecdsa(key) => key.sk_application.as_ref().unwrap(),
        _ => return None,
    };

    let allow_list = vec![PublicKeyCredentialDescriptor {
        id: handle.to_vec(),
        transports: vec![Transport::USB],
    }];

    let chall_bytes: [u8; 32] = digest::digest(&digest::SHA256, challenge)
        .as_ref()
        .try_into()
        .unwrap(); // This should be safe as SHA256 will always be 32 bytes

    let ctap_args = SignArgs {
        client_data_hash: chall_bytes,
        origin: format!(""),
        relying_party_id: sk_application.clone(),
        allow_list,
        extensions: GetAssertionExtensions::default(),
        pin,
        user_presence_req: true,
        use_ctap1_fallback: false,
        alternate_rp_id: None,
        user_verification_req: UserVerificationRequirement::Discouraged,
    };

    let mut manager = match AuthenticatorService::new() {
        Ok(m) => m,
        Err(_) => return None,
    };
    manager.add_u2f_usb_hid_platform_transports();

    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    let (status_tx, _status_rx) = channel::<StatusUpdate>();
    if let Err(e) = manager.sign(
        15_000,
        ctap_args.clone().into(),
        status_tx.clone(),
        callback,
    ) {
        panic!("Couldn't sign: {:?}", e);
    }
    let sign_result = sign_rx
        .recv()
        .expect("Problem receiving, unable to continue");

    let assertion = match sign_result {
        Ok(SignResult::CTAP2(assertion_object)) => assertion_object,
        Ok(_) => {
            println!("Wrong CTAP response");
            return None;
        }
        Err(AuthenticatorError::PinError(PinError::PinRequired)) => {
            println!("PIN needed but not provided!");
            return None;
        }
        Err(e) => {
            println!("Some other error: {}", e);
            return None;
        }
    };
    let mut format = format_signature_for_ssh(&private_key.pubkey, &assertion.0[0].signature)?;
    format.push(assertion.0[0].auth_data.flags.bits());
    format.extend_from_slice(&assertion.0[0].auth_data.counter.to_be_bytes());
    Some(format)
}
