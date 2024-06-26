use crate::{
    error::Error,
    fido::{
        generate::{FIDOSSHKey, U2FAttestation},
        AuthData,
    },
    ssh::{Ed25519SkPrivateKey, KeyType, PrivateKeyKind},
    PrivateKey,
};

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

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
    sync::mpsc::{channel, RecvError},
    thread,
};

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

    let mut chall_bytes = [0u8; 32];
    SystemRandom::new().fill(&mut chall_bytes).unwrap();

    let origin = application.to_string();
    let ctap_args = RegisterArgs {
        client_data_hash: chall_bytes,
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
    let (error_tx, error_rx) = channel::<FidoError>();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = register_tx.send(rv);
    }));

    if let Err(e) = manager.register(15_000, ctap_args, status_tx.clone(), callback) {
        return Err(Error::FidoError(FidoError::Unknown(e.to_string())));
    };

    thread::spawn(move || loop {
        let msg = status_rx.recv();
        match msg {
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(_))) => {
                let _ = error_tx.send(FidoError::PinRequired);
                return;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                let _ = error_tx.send(FidoError::KeyLocked);
                return;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                let _ = error_tx.send(FidoError::KeyBlocked);
                return;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(_sender, attempts))) => {
                let _ = error_tx.send(FidoError::InvalidPin(attempts));
                return;
            }
            Ok(_) => (),
            Err(RecvError) => {
                return;
            }
        }
    });

    let register_result = register_rx
        .recv()
        .map_err(|e| Error::FidoError(FidoError::Unknown(e.to_string())))?;
    let attestation_object = match register_result {
        Ok(attestation) => attestation,
        Err(e) => {
            if let Ok(error) = error_rx.recv() {
                return Err(Error::FidoError(error));
            } else {
                return Err(Error::FidoError(FidoError::Unknown(e.to_string())));
            }
        }
    };

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
        challenge: chall_bytes.to_vec(),
        alg,
    };

    let _ = attestation.verify()?;

    Ok(FIDOSSHKey {
        private_key,
        attestation,
    })
}
