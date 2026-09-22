use crate::{
    error::Error,
    fido::{
        generate::{FIDOSSHKey, U2FAttestation},
        AuthData,
    },
    ssh::{Ed25519SkPrivateKey, KeyType, PrivateKeyKind},
    PrivateKey,
};

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use crate::fido::Error as FidoError;

use authenticator::ctap2::attestation::AttestationStatement;
use authenticator::ctap2::server::PublicKeyCredentialParameters;
use authenticator::ctap2::server::RelyingParty;
use authenticator::ctap2::server::ResidentKeyRequirement;
use authenticator::ctap2::server::UserVerificationRequirement;
use authenticator::statecallback::StateCallback;
use authenticator::Pin;
use authenticator::StatusUpdate;
use authenticator::{
    authenticatorservice::AuthenticatorService, ctap2::server::AuthenticationExtensionsClientInputs,
};
use authenticator::{
    authenticatorservice::RegisterArgs, ctap2::server::PublicKeyCredentialUserEntity,
};
use authenticator::{crypto::COSEAlgorithm, StatusPinUv};

use std::{
    fmt::Display,
    sync::{
        mpsc::{channel, Receiver, RecvError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

/// How long to keep waiting for a late PIN error report after the operation
/// already failed for another reason
const PIN_ERROR_BUDGET: Duration = Duration::from_millis(250);

/// Generate a new SSH key on a FIDO/U2F device
pub fn generate_new_ssh_key(
    application: &str,
    comment: &str,
    pin: Option<String>,
    _: Option<String>,
) -> Result<FIDOSSHKey, Error> {
    let mut manager = match AuthenticatorService::new() {
        Ok(m) => m,
        Err(e) => return Err(Error::FidoError(FidoError::Unknown(e.to_string()))),
    };
    manager.add_u2f_usb_hid_platform_transports();

    // This forms the challenge
    let mut client_data = [0u8; 32];
    // Fill it with random data because we don't support taking in
    // challenge data at this point.
    if let Err(e) = SystemRandom::new().fill(&mut client_data) {
        return Err(Error::FidoError(FidoError::Unknown(e.to_string())));
    }

    // Hash the data because that is what will actually be signed
    let client_data_digest = digest::digest(&digest::SHA256, &client_data);
    let mut client_data_hash = [0u8; 32];
    client_data_hash.copy_from_slice(client_data_digest.as_ref());

    let origin = application.to_string();
    let ctap_args = RegisterArgs {
        client_data_hash,
        relying_party: RelyingParty {
            id: origin.clone(),
            name: None,
        },
        origin,
        user: PublicKeyCredentialUserEntity {
            id: application.as_bytes().to_vec(),
            name: Some(application.to_string()),
            display_name: None,
        },
        pub_cred_params: vec![PublicKeyCredentialParameters {
            alg: COSEAlgorithm::EDDSA,
        }],
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Discouraged,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: pin.as_ref().map(|x| Pin::new(x)),
        use_ctap1_fallback: false,
    };

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = register_tx.send(rv);
    }));

    if let Err(e) = manager.register(15_000, ctap_args, status_tx, callback) {
        return Err(Error::FidoError(FidoError::Unknown(e.to_string())));
    };

    // PIN failures are recorded in shared state rather than on a second
    // blocking channel: once the result channel has yielded an error, a PIN
    // status may never arrive (for example on a touch timeout), so waiting
    // for one can deadlock.
    let (pin_error_tx, pin_error_rx) = channel::<()>();
    let pin_error = Arc::new(Mutex::new(None::<FidoError>));
    let status_pin_error = Arc::clone(&pin_error);
    thread::spawn(move || loop {
        let error = match status_rx.recv() {
            // Dropping the embedded PIN sender unblocks the authenticator
            // crate's device thread, which is otherwise waiting for a PIN
            // that will never arrive.
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(_sender))) => {
                Some(FidoError::PinRequired)
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => Some(FidoError::KeyLocked),
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => Some(FidoError::KeyBlocked),
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(_sender, attempts))) => {
                Some(FidoError::InvalidPin(attempts))
            }
            Ok(_) => None,
            Err(RecvError) => return,
        };
        let Some(error) = error else {
            continue;
        };
        store_pin_error(&status_pin_error, error);
        let _ = pin_error_tx.send(());
        return;
    });

    let attestation_object =
        wait_for_result(register_rx, &pin_error, pin_error_rx, PIN_ERROR_BUDGET)?;

    let raw_auth_data = attestation_object.att_obj.auth_data.to_vec();

    let auth_data = AuthData::parse(&raw_auth_data)?;

    let key_type = KeyType::from_name("sk-ssh-ed25519@openssh.com")?;
    let kind = PrivateKeyKind::Ed25519Sk(Ed25519SkPrivateKey {
        flags: auth_data.flags,
        handle: auth_data.credential_id.clone(),
        reserved: vec![],
        pin,
        device_path: None,
    });

    let private_key = PrivateKey {
        key_type,
        kind,
        pubkey: auth_data.ssh_public_key(application)?,
        magic: 0x0,
        comment: comment.to_string(),
    };

    let (auth_data_sig, intermediate_certs, alg) = match attestation_object.att_obj.att_stmt {
        AttestationStatement::Packed(packed) => (
            packed.sig.0.to_vec(),
            packed.attestation_cert,
            packed.alg as i32,
        ),
        _ => {
            return Err(Error::FidoError(FidoError::Unknown(
                "Wrong attestation format".to_owned(),
            )))
        }
    };

    let intermediate = if intermediate_certs.is_empty() {
        vec![]
    } else {
        intermediate_certs[0].0.clone()
    };

    let attestation = U2FAttestation {
        auth_data: raw_auth_data,
        auth_data_sig,
        intermediate,
        challenge: client_data_hash.into(),
        alg,
    };

    let _ = attestation.verify()?;

    Ok(FIDOSSHKey {
        private_key,
        attestation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fido_error(result: Result<u8, Error>) -> FidoError {
        match result {
            Err(Error::FidoError(e)) => e,
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn successful_result_passes_through() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (_wake_tx, wake_rx) = channel::<()>();
        tx.send(Ok(42)).unwrap();
        let result = wait_for_result(rx, &Mutex::new(None), wake_rx, Duration::from_millis(1));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn propagated_error_without_pin_error_is_unknown() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (_wake_tx, wake_rx) = channel::<()>();
        tx.send(Err("token error".to_string())).unwrap();
        let result = wait_for_result(rx, &Mutex::new(None), wake_rx, Duration::from_millis(1));
        match fido_error(result) {
            FidoError::Unknown(msg) => assert!(msg.contains("token error")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn recorded_pin_error_wins_over_propagated_error() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (_wake_tx, wake_rx) = channel::<()>();
        tx.send(Err("token error".to_string())).unwrap();
        let pin_error = Mutex::new(Some(FidoError::PinRequired));
        let result = wait_for_result(rx, &pin_error, wake_rx, Duration::from_millis(1));
        assert!(matches!(fido_error(result), FidoError::PinRequired));
    }

    #[test]
    fn recorded_pin_error_survives_recv_error() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (_wake_tx, wake_rx) = channel::<()>();
        drop(tx);
        let pin_error = Mutex::new(Some(FidoError::KeyLocked));
        let result = wait_for_result(rx, &pin_error, wake_rx, Duration::from_millis(1));
        assert!(matches!(fido_error(result), FidoError::KeyLocked));
    }

    #[test]
    fn missing_pin_error_falls_back_after_budget() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (_wake_tx, wake_rx) = channel::<()>();
        tx.send(Err("token error".to_string())).unwrap();
        let result = wait_for_result(rx, &Mutex::new(None), wake_rx, Duration::from_millis(10));
        match fido_error(result) {
            FidoError::Unknown(msg) => assert!(msg.contains("token error")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn late_pin_error_is_detected_within_budget() {
        let (tx, rx) = channel::<Result<u8, String>>();
        let (wake_tx, wake_rx) = channel::<()>();
        let pin_error = Arc::new(Mutex::new(None));
        let late_pin_error = Arc::clone(&pin_error);
        tx.send(Err("token error".to_string())).unwrap();
        // Record the PIN error from another thread, at a point unrelated to
        // the waiter's progress. The wake signal is buffered and the final
        // check re-reads the shared state, so every interleaving detects it.
        let handle = thread::spawn(move || {
            store_pin_error(&late_pin_error, FidoError::PinRequired);
            wake_tx.send(()).unwrap();
        });
        let result = wait_for_result(rx, &pin_error, wake_rx, Duration::from_secs(2));
        handle.join().unwrap();
        assert!(matches!(fido_error(result), FidoError::PinRequired));
    }
}

fn store_pin_error(pin_error: &Mutex<Option<FidoError>>, error: FidoError) {
    let mut guard = pin_error.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(error);
}

fn take_pin_error(pin_error: &Mutex<Option<FidoError>>) -> Option<FidoError> {
    pin_error.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Wait for the result of a FIDO operation, preferring a recorded PIN error
/// over the propagated authenticator error because it describes the failure
/// more precisely
fn wait_for_result<T, E: Display>(
    result_rx: Receiver<Result<T, E>>,
    pin_error: &Mutex<Option<FidoError>>,
    pin_error_rx: Receiver<()>,
    pin_error_budget: Duration,
) -> Result<T, Error> {
    let error = match result_rx.recv() {
        Ok(Ok(value)) => return Ok(value),
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    let recorded = take_pin_error(pin_error);
    if recorded.is_none() {
        // PinAuthBlocked and PinBlocked are reported on the status channel
        // independently of the result, so give a late report a bounded chance
        // to arrive. The signal is buffered, and the final check below re-reads
        // the shared state, so a report recorded at any point during the wait
        // is observed.
        let _ = pin_error_rx.recv_timeout(pin_error_budget);
    }
    match recorded.or_else(|| take_pin_error(pin_error)) {
        Some(error) => Err(Error::FidoError(error)),
        None => Err(Error::FidoError(FidoError::Unknown(error))),
    }
}
