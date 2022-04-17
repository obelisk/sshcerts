use ctap_hid_fido2::{
    fidokey::make_credential::{CredentialSupportedKeyType, MakeCredentialArgsBuilder},
    verifier, Cfg, FidoKeyHid, HidParam,
};

use super::AuthData;

use crate::{
    error::Error,
    ssh::{Ed25519SkPrivateKey, KeyType, PrivateKeyKind},
    PrivateKey,
};

/// The attestation data, signature, and chain for a generated SSH key
#[derive(Debug)]
pub struct U2FAttestation {
    /// A blob that contains all public information that we can also verify with
    /// the attestation chain
    pub auth_data: Vec<u8>,
    /// The signature over the hash of the auth data
    pub auth_data_sig: Vec<u8>,
    /// The certificate that generated the signature over the auth data
    pub intermediate: Vec<u8>,
    /// The challenge that generated and is included in the signature
    pub challenge: Vec<u8>,
    /// The algorithm that was used to generate the signature (COSE value)
    pub alg: i32,
}

/// A generated SSH key that was generated with a FIDO/U2F key
#[derive(Debug)]
pub struct FIDOSSHKey {
    /// Private key handle to the new SSH Key on the hardware token
    pub private_key: PrivateKey,
    /// The U2F attestation data
    pub attestation: U2FAttestation,
}

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

    let device = device.map_err(|e| Error::FidoError(e.to_string()))?;
    let att = device
        .make_credential_with_args(&args.build())
        .map_err(|e| Error::FidoError(e.to_string()))?;

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

    Ok(FIDOSSHKey {
        private_key,
        attestation: U2FAttestation {
            auth_data: att.auth_data,
            auth_data_sig: att.attstmt_sig,
            intermediate,
            challenge: challenge.to_vec(),
            alg: att.attstmt_alg,
        },
    })
}
