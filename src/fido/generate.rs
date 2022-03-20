use ctap_hid_fido2::{
    Cfg,
    verifier,
    make_credential_params::CredentialSupportedKeyType,
};

use super::parsing;

use crate::{
    error::Error,
    PrivateKey,
    ssh::{
        KeyType,
        PrivateKeyKind,
        Ed25519SkPrivateKey,
    },
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
pub fn generate_new_ssh_key(application: &str, pin: Option<String>) -> Result<FIDOSSHKey, Error> {
    let challenge = verifier::create_challenge();
    let att = ctap_hid_fido2::make_credential_with_key_type(
        &Cfg::init(),
        &application,
        &challenge,
        pin.as_ref().map(|x| &**x),
        Some(CredentialSupportedKeyType::Ed25519),
    ).map_err(|e| Error::FidoError(e.to_string()))?;

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

    let key_type = KeyType::from_name("sk-ssh-ed25519@openssh.com").unwrap();
    let kind = PrivateKeyKind::Ed25519Sk(Ed25519SkPrivateKey {
        flags: ret,
        handle: att.credential_descriptor.id.clone(),
        reserved: vec![],
        pin,
    });

    let auth_data = parsing::parse_auth_data(&att.auth_data, application.as_bytes()).unwrap();

    let private_key = PrivateKey {
        key_type,
        kind,
        pubkey: auth_data.public_key,
        magic: 0x0,
        comment: None,
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
        }
    })
}