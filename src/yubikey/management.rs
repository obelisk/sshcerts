use ring::digest;

use yubikey_piv::{MgmKey, YubiKey};
use yubikey_piv::policy::{PinPolicy, TouchPolicy};
use yubikey_piv::key::{attest, AlgorithmId, sign_data as yk_sign_data, SlotId};
use yubikey_piv::certificate::{Certificate, PublicKeyInfo};

use super::{Error, Result};

impl crate::yubikey::Yubikey {
    /// Create a new YubiKey. Assumes there is only one Yubikey connected
    pub fn new() -> Result<Self> {
        Ok(Self {
            yk: YubiKey::open()?,
        })
    }

    /// Reconnet to the Yubikey (if possible, if it's disconnected)
    pub fn reconnect(&mut self) -> Result <()> {
        match self.yk.reconnect() {
            Ok(()) => Ok(()),
            Err(_) => Err(Error::NoSuchYubikey)
        }
    }

    /// Unlock the yubikey for signing or provisioning operations
    pub fn unlock(&mut self, pin: &[u8], mgm_key: &[u8]) -> Result<()> {
        self.yk.verify_pin(pin)?;

        match MgmKey::from_bytes(mgm_key) {
            Ok(mgm) => self.yk.authenticate(mgm)?,
            Err(_) => return Err(Error::InvalidManagementKey),
        };
        Ok(())
    }

    /// Check to see that a provided Yubikey and slot is configured for signing
    pub fn configured(&mut self, slot: &SlotId) -> Result<PublicKeyInfo> {
        let cert = yubikey_piv::certificate::Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.subject_pki().clone())
    }

    /// Check to see that a provided Yubikey and slot is configured for signing
    pub fn fetch_subject(&mut self, slot: &SlotId) -> Result<String> {
        let cert = yubikey_piv::certificate::Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.subject().to_string())
    }

    /// Fetch the certificate from a given Yubikey slot. If there is not one, this
    /// will fail
    pub fn fetch_certificate(&mut self, slot: &SlotId) -> Result<Vec<u8>> {
        let cert = yubikey_piv::certificate::Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.as_ref().to_vec())
    }

    /// Fetch a public key from the provided slot. If there is not exactly one
    /// Yubikey this will fail.
    pub fn fetch_pubkey(&mut self, slot: &SlotId) -> Result<PublicKeyInfo> {
        self.configured(slot)
    }

    /// Generate attestation for a slot
    pub fn fetch_attestation(&mut self, slot: &SlotId) -> Result<Vec<u8>> {
        Ok(attest(&mut self.yk, *slot)?.to_vec())
    }

    /// This provisions the YubiKey with a new certificate generated on the device.
    /// Only keys that are generate this way can use the attestation functionality.
    pub fn provision(&mut self, slot: &SlotId, subject: &str, alg: AlgorithmId, touch_policy: TouchPolicy, pin_policy: PinPolicy) -> Result<PublicKeyInfo> {
        let key_info = yubikey_piv::key::generate(&mut self.yk, *slot, alg, pin_policy, touch_policy)?;

        // Generate a self-signed certificate for the new key.
        Certificate::generate_self_signed(
            &mut self.yk,
            *slot,
            [0u8; 20],
            None,
            subject.to_string(),
            key_info,
        )?;

        self.configured(slot)
    }

    /// Take data, an algorithm, and a slot and attempt to sign the data field
    /// 
    /// If the requested algorithm doesn't match the key in the slot (or the slot
    /// is empty) this will return an error.
    pub fn sign_data(&mut self, data: &[u8], alg: AlgorithmId, slot: &SlotId) -> Result<Vec<u8>> {
        let (slot_alg, hash_alg) = match self.configured(slot) {
            Ok(PublicKeyInfo::EcP256(_)) => (AlgorithmId::EccP256, &digest::SHA256),
            Ok(PublicKeyInfo::EcP384(_)) => (AlgorithmId::EccP384, &digest::SHA384),
            Ok(_) => (AlgorithmId::Rsa2048, &digest::SHA256), // RSAish
            Err(_) => return Err(Error::Unprovisioned),
        };

        if slot_alg != alg {
            return Err(Error::WrongKeyType);
        }
        let signature = yk_sign_data(&mut self.yk, digest::digest(hash_alg, data).as_ref(), alg, *slot)?;
        Ok(signature.to_vec())
    }
}