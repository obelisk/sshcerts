use crate::PublicKey;

use ring::digest;

use yubikey::{MgmKey, YubiKey};
use yubikey::{PinPolicy, TouchPolicy};
use yubikey::piv::{attest, AlgorithmId, sign_data as yk_sign_data, SlotId};
use yubikey::certificate::{Certificate, PublicKeyInfo};

use x509::RelativeDistinguishedName;

use super::{Error, Result};

#[derive(Debug)]
/// A struct that allows the generation of CSRs via the rcgen library. This is
/// only used when calling the `generate_csr` function.
pub struct CSRSigner {
    slot: SlotId,
    serial: u32,
    public_key: Vec<u8>,
    algorithm: AlgorithmId,
}

impl CSRSigner {
    fn new(serial: u32, slot: SlotId) -> Self {
        let mut yk = super::Yubikey::open(serial).unwrap();
        let pki = yk.configured(&slot).unwrap();
        let (public_key, algorithm) = match pki {
            PublicKeyInfo::Rsa { pubkey: _, .. } => panic!("RSA keys not supported"),
            PublicKeyInfo::EcP256(pubkey) => (pubkey.as_bytes().to_vec(), AlgorithmId::EccP256),
            PublicKeyInfo::EcP384(pubkey) => (pubkey.as_bytes().to_vec(), AlgorithmId::EccP384),
        };

        Self {
            slot,
            serial,
            public_key,
            algorithm
        }
    }
}

impl rcgen::RemoteKeyPair for CSRSigner {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::RcgenError> {
        let mut yk = super::Yubikey::open(self.serial).unwrap();
        Ok(yk.sign_data(message, self.algorithm, &self.slot).unwrap())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.algorithm {
            AlgorithmId::EccP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            AlgorithmId::EccP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => panic!("Unimplemented")
        }
    }
}

impl super::Yubikey {
    /// Create a new YubiKey. Assumes there is only one Yubikey connected
    pub fn new() -> Result<Self> {
        Ok(Self {
            yk: YubiKey::open()?,
        })
    }

    /// Open a Yubikey from a serial
    pub fn open(serial: u32) -> Result<Self> {
        match YubiKey::open_by_serial(serial.into()){
            Ok(yk) => Ok(Self {
                yk,
            }),
            Err(_) => Err(Error::NoSuchYubikey),
        }
    }

    /// Reconnet to the Yubikey (if possible, if it's disconnected)
    pub fn reconnect(&mut self) -> Result <()> {
        match self.yk.reconnect() {
            Ok(()) => Ok(()),
            Err(_) => match YubiKey::open_by_serial(self.yk.serial()){
                Ok(yk) => {
                    self.yk = yk;
                    Ok(())
                },
                Err(_) => Err(Error::NoSuchYubikey),
            }
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
        let cert = Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.subject_pki().clone())
    }

    /// Check to see that a provided Yubikey and slot is configured for signing
    pub fn fetch_subject(&mut self, slot: &SlotId) -> Result<String> {
        let cert = Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.subject().to_string())
    }

    /// Fetch the certificate from a given Yubikey slot.
    pub fn fetch_certificate(&mut self, slot: &SlotId) -> Result<Vec<u8>> {
        let cert = Certificate::read(&mut self.yk, *slot)?;
        Ok(cert.as_ref().to_vec())
    }

    /// Write the certificate from a given Yubikey slot.
    pub fn write_certificate(&mut self, slot: &SlotId, data: &[u8]) -> Result<()> {
        Ok(Certificate::from_bytes(data.to_vec())?.write(&mut self.yk, *slot, yubikey::certificate::CertInfo::Uncompressed)?)
    }

    /// Generate attestation for a slot
    pub fn fetch_attestation(&mut self, slot: &SlotId) -> Result<Vec<u8>> {
        Ok(attest(&mut self.yk, *slot)?.to_vec())
    }

    /// Generate CSR for slot
    pub fn generate_csr(&mut self, slot: &SlotId, common_name: &str,) -> Result<Vec<u8>> {
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = match self.configured(&slot)? {
            PublicKeyInfo::EcP256(_) => &rcgen::PKCS_ECDSA_P256_SHA256,
            PublicKeyInfo::EcP384(_) => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => return Err(Error::Unsupported),
        };
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name.to_string());

        let csr_signer = CSRSigner::new(self.yk.serial().into(), slot.clone());
        params.key_pair = Some(rcgen::KeyPair::from_remote(Box::new(csr_signer)).unwrap());

        let csr = rcgen::Certificate::from_params(params).unwrap();
        let csr = csr.serialize_request_der().unwrap();
    
        Ok(csr)
    }

    /// Provisions the YubiKey with a new certificate generated on the device.
    /// Only keys that are generated this way can use the attestation functionality.
    pub fn provision(&mut self, slot: &SlotId, common_name: &str, alg: AlgorithmId, touch_policy: TouchPolicy, pin_policy: PinPolicy) -> Result<PublicKey> {
        let key_info = yubikey::piv::generate(&mut self.yk, *slot, alg, pin_policy, touch_policy)?;
        let extensions: &[x509::Extension<'_, &[u64]>] = &[];
        // Generate a self-signed certificate for the new key.
        Certificate::generate_self_signed(
            &mut self.yk,
            *slot,
            [0u8; 20],
            None,
            &[RelativeDistinguishedName::common_name(common_name)],
            key_info,
            extensions,
        )?;

        self.ssh_cert_fetch_pubkey(slot)
    }

    /// Take data, an algorithm, and a slot and attempt to sign the data field
    /// 
    /// If the requested algorithm doesn't match the key in the slot (or the slot
    /// is empty) this will error.
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