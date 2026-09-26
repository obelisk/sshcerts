use crate::ssh::PrivateKeyKind;
use crate::ssh::PublicKeyKind;
use crate::utils::format_signature_for_ssh;
use crate::PrivateKey;

use ring::digest;

use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::*,
    errors::{AuthenticatorError, PinError},
    statecallback::StateCallback,
    Pin, StatusUpdate,
};
use std::sync::mpsc::{channel, Receiver};
use std::thread;

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
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin,
        user_presence_req: true,
        use_ctap1_fallback: false,
        user_verification_req: UserVerificationRequirement::Discouraged,
    };

    let mut manager = match AuthenticatorService::new() {
        Ok(m) => m,
        Err(_) => return None,
    };
    manager.add_u2f_usb_hid_platform_transports();

    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

    // Consume PIN-related status updates and drop their embedded PIN sender.
    // If the sender were left unread, the authenticator crate's device thread
    // would stay blocked waiting for a PIN that will never arrive, and its
    // join during transaction cleanup would deadlock this function.
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || drain_pin_statuses(status_rx));

    if manager
        .sign(15_000, ctap_args.clone().into(), status_tx, callback)
        .is_err()
    {
        return None;
    }
    let sign_result = match sign_rx.recv() {
        Ok(result) => result,
        Err(_) => return None,
    };

    let assertion = match sign_result {
        Ok(assertion_object) => assertion_object.assertion,
        Err(AuthenticatorError::PinError(PinError::PinRequired)) => {
            println!("PIN needed but not provided!");
            return None;
        }
        Err(e) => {
            println!("Some other error: {}", e);
            return None;
        }
    };
    let mut format = format_signature_for_ssh(&private_key.pubkey, &assertion.signature)?;
    format.push(assertion.auth_data.flags.bits());
    format.extend_from_slice(&assertion.auth_data.counter.to_be_bytes());
    Some(format)
}

/// Drain PIN-related status updates until the operation ends, dropping any
/// embedded PIN sender so the authenticator crate's device thread is never
/// left blocked waiting for a PIN that will not arrive
fn drain_pin_statuses(status_rx: Receiver<StatusUpdate>) {
    loop {
        match status_rx.recv() {
            Ok(StatusUpdate::PinUvError(_)) => return,
            Ok(_) => (),
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticator::StatusPinUv;

    fn dropped_pin_sender_status() -> (Receiver<Pin>, StatusUpdate) {
        let (pin_tx, pin_rx) = channel::<Pin>();
        (
            pin_rx,
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(pin_tx)),
        )
    }

    #[test]
    fn pin_required_status_drops_the_pin_sender() {
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (pin_rx, status) = dropped_pin_sender_status();
        status_tx.send(status).unwrap();
        drain_pin_statuses(status_rx);
        assert!(pin_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn invalid_pin_status_drops_the_pin_sender() {
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (pin_tx, pin_rx) = channel::<Pin>();
        status_tx
            .send(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(
                pin_tx,
                Some(3),
            )))
            .unwrap();
        drain_pin_statuses(status_rx);
        assert!(pin_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn drain_exits_when_the_status_channel_closes() {
        let (_status_tx, status_rx) = channel::<StatusUpdate>();
        drop(_status_tx);
        drain_pin_statuses(status_rx);
    }
}
