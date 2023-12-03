use ctap_hid_fido2::{
    fidokey::make_credential::{CredentialSupportedKeyType, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHid, HidParam,
};
use ring::digest;

use crate::{
    error::Error,
    fido::{
        generate::{FIDOSSHKey, U2FAttestation},
        AuthData,
    },
    ssh::{Ed25519SkPrivateKey, KeyType, PrivateKeyKind},
    PrivateKey,
};

/// Generate a new SSH key on a FIDO/U2F device
pub fn generate_new_ssh_key(
    application: &str,
    comment: &str,
    pin: Option<String>,
    device_path: Option<String>,
) -> Result<FIDOSSHKey, Error> {
    let device = if let Some(path) = &device_path {
        FidoKeyHid::new(&[HidParam::Path(path.to_string())], &Cfg::init())
    } else {
        let fido_devices: Vec<HidParam> = ctap_hid_fido2::get_fidokey_devices()
            .into_iter()
            .map(|x| x.param)
            .collect();
        FidoKeyHid::new(&fido_devices, &Cfg::init())
    };

    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new(&application, &challenge)
        .key_type(CredentialSupportedKeyType::Ed25519);

    let args = if let Some(pin) = &pin {
        args.pin(pin)
    } else {
        args.without_pin_and_uv()
    };

    let device = device.map_err(|e| Error::FidoError(FidoError::Unknown(e.to_string())))?;
    let att = device
        .make_credential_with_args(&args.build())
        .map_err(|e| Error::FidoError(FidoError::Unknown(e.to_string())))?;

    let mut ret = 0x0;
    if att.flags_user_present_result {
        ret = ret | 0x01;
    }
    if att.flags_user_verified_result {
        ret = ret | 0x04;
    }
    if att.flags_attested_credential_data_included {
        ret = ret | 0x40;
    }
    if att.flags_extension_data_included {
        ret = ret | 0x80;
    }

    let key_type = KeyType::from_name("sk-ssh-ed25519@openssh.com")?;
    let kind = PrivateKeyKind::Ed25519Sk(Ed25519SkPrivateKey {
        flags: ret,
        handle: att.credential_descriptor.id.clone(),
        reserved: vec![],
        pin,
        device_path,
    });

    let auth_data = AuthData::parse(&att.auth_data)?;

    let private_key = PrivateKey {
        key_type,
        kind,
        pubkey: auth_data.ssh_public_key(application)?,
        magic: 0x0,
        comment: comment.to_string(),
    };

    let intermediate = if att.attstmt_x5c.is_empty() {
        vec![]
    } else {
        att.attstmt_x5c[0].clone()
    };

    // Take a SHA256 of the challenge because that's what's part of
    // the signed data
    let challenge = digest::digest(&digest::SHA256, &challenge)
        .as_ref()
        .to_vec();

    let attestation = U2FAttestation {
        auth_data: att.auth_data,
        auth_data_sig: att.attstmt_sig,
        intermediate,
        challenge,
        alg: att.attstmt_alg,
    };

    let _ = attestation.verify()?;

    Ok(FIDOSSHKey {
        private_key,
        attestation,
    })
}
