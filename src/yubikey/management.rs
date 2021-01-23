use sha2::{Digest, Sha256, Sha384};

use yubikey_piv::{MgmKey, YubiKey};
use yubikey_piv::policy::{PinPolicy, TouchPolicy};
use yubikey_piv::key::{attest, AlgorithmId, sign_data as yk_sign_data, SlotId};
use yubikey_piv::certificate::{Certificate, PublicKeyInfo};


/// Errors when interacting with the Yubikey.
#[derive(Debug)]
pub enum Error {
    /// Generally this occurs when a slot is asked to return or process data
    /// when it has no certificate or private key.
    Unprovisioned,
    /// This occurs when the signature type requested does not match the key
    /// in the slot on the key
    WrongKeyType,
    /// This occurs when you try to use a feature that should technically work
    /// but is currently unimplemented or unsupported on the hardware connected.
    /// For example, RSA signing will currently throw this error.
    Unsupported,
    /// If you pass a management key into the provision function that does not
    /// deserialize from bytes, you will get this error.
    InvalidManagementKey,
    /// If the Yubikey throws an error we don't recognize, it's encapsulated
    /// and returned
    InternalYubiKeyError(yubikey_piv::error::Error),
}

/// Check to see that a provided Yubikey and slot is configured for signing
pub fn configured(yk: &mut YubiKey, slot: SlotId) -> Result<PublicKeyInfo, Error> {
    match yubikey_piv::certificate::Certificate::read(yk, slot) {
        Ok(cert) => {Ok(cert.subject_pki().clone())},
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}

/// Check to see that a provided Yubikey and slot is configured for signing
fn subject(yk: &mut YubiKey, slot: SlotId) -> Result<String, Error> {
    match yubikey_piv::certificate::Certificate::read(yk, slot) {
        Ok(cert) => {Ok(cert.subject().to_owned())},
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}

/// Fetch a public key from the provided slot. If there is not exactly one
/// Yubikey this will fail.
pub fn fetch_pubkey(slot: SlotId) -> Result<PublicKeyInfo, Error> {
    let mut yubikey = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };
    configured(&mut yubikey, slot)
}

/// Fetch a certificate subject from a yubikey slot
pub fn fetch_subject(slot: SlotId) -> Result<String, Error> {
    let mut yubikey = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };
    subject(&mut yubikey, slot)
}

/// Generate attestation for a slot
pub fn fetch_attestation(slot: SlotId) -> Option<Vec<u8>> {
    let mut yubikey = match YubiKey::open() {
        Ok(yk) => yk,
        Err(_e) => return None,
    };

    match attest(&mut yubikey, slot) {
        Ok(buf) => Some(buf.to_vec()),
        Err(_) => None
    }
}

/// This provisions the YubiKey with a new certificate. It is generally not advisable
/// to use as this means there is no backup of the key should it be lost.
/// It is however provided as an easy method quickly get a YubiKey properly configured
/// for use with Rustica.
pub fn provision(pin: &[u8], mgm_key: &[u8], slot: SlotId, subject: &str, alg: AlgorithmId, require_touch: TouchPolicy) -> Result<PublicKeyInfo, Error> {
    let mut yk = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };

    match yk.verify_pin(pin) {
        Ok(_) => (),
        Err(e) => {
            println!("Error in verify pin: {}", e);
            return Err(Error::InternalYubiKeyError(e))
        },
    }

    let mgm_key = match MgmKey::from_bytes(mgm_key) {
        Ok(mgm) => mgm,
        Err(_) => return Err(Error::InvalidManagementKey),
    };

    match yk.authenticate(mgm_key) {
        Ok(_) => (),
        Err(e) => {
            println!("Error in MGM Key Authentication: {}", e);
            return Err(Error::InternalYubiKeyError(e));
        },
    }

    let key_info = match yubikey_piv::key::generate(&mut yk, slot, alg, PinPolicy::Never, require_touch) {
        Ok(ki) => ki,
        Err(e) => {
            println!("Error in provisioning new key: {}", e);
            return Err(Error::InternalYubiKeyError(e));
        },
    };

    // Generate a self-signed certificate for the new key.
    if let Err(e) = Certificate::generate_self_signed(
        &mut yk,
        slot,
        [0u8; 20],
        None,
        subject.to_string(),
        key_info,
    ) {
        return Err(Error::InternalYubiKeyError(e));
    }

    configured(&mut yk, slot)
}

/// Take an data, an algorithm, and a slot and attempt to sign the data field
/// 
/// If the requested algorithm doesn't match the key in the slot (or the slot
/// is empty) this will return an error.
pub fn sign_data(data: &[u8], alg: AlgorithmId, slot: SlotId) -> Result<Vec<u8>, Error> {
    let mut yk = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };

    let slot_alg = match configured(&mut yk, slot) {
        Ok(PublicKeyInfo::EcP256(_)) => AlgorithmId::EccP256,
        Ok(PublicKeyInfo::EcP384(_)) => AlgorithmId::EccP384,
        Ok(_) => AlgorithmId::Rsa2048,  // RSAish
        Err(_) => return Err(Error::Unprovisioned),
    };

    if slot_alg != alg {
        return Err(Error::WrongKeyType);
    }

    let hash = match slot_alg {
        AlgorithmId::EccP256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        },
        AlgorithmId::EccP384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => return Err(Error::Unsupported),
    };


    match yk_sign_data(&mut yk, &hash[..], alg, slot) {
        Ok(sig) => Ok(sig.to_vec()),
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}
