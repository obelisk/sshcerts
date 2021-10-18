use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::HidParam;

use super::Error;

use crate::PublicKey;
use crate::ssh::PublicKeyKind;
use crate::ssh::KeyType;
use crate::ssh::Ed25519PublicKey;

/// Contains information regarding a newly registered FIDO key
#[derive(Debug)]
pub struct Registration {
    /// An SSHCerts structure representing the SSH Public Key
    pub public_key: PublicKey,
    /// The attestation of the newly generated key
    pub attestation: Vec<u8>,
}

impl super::Device {
    /// Generate a new resident key on the device with the given
    /// identifications
    pub fn register(&self, id: &str, name: &str, display_name: &str, rpid: &str, pin: Option<&str>) -> Result<Registration, Error> {
        let challenge = verifier::create_challenge();
        let rkparam = PublicKeyCredentialUserEntity::new(Some(id.as_bytes()), Some(name), Some(display_name));

        let att = match ctap_hid_fido2::make_credential_rk(
            &HidParam::get_default_params(),
            rpid,
            &challenge,
            pin,
            &rkparam,
        ) {
            Ok(att) => att,
            Err(e) => return Err(Error::MakeCredentialError(e.to_string())),
        };

        let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

        if !verify_result.is_success {
            return Err(Error::VerificationError)
        }

        let key_type = KeyType::from_name("ssh-ed25519").unwrap();
        let kind = Ed25519PublicKey {
            // Remove the 0x04 prefix
            key: verify_result.credential_publickey_der[1..].to_vec(),
        };

        let public_key = PublicKey {
            key_type,
            kind: PublicKeyKind::Ed25519(kind),
            comment: None,
        };

        Ok(Registration {
            public_key,
            attestation: att.auth_data,
        })
    }
}