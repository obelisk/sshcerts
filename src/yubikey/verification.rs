use crate::{error::Error, x509::{self, extract_ssh_pubkey_from_x509_certificate}, PublicKey};

use x509_cert::{der::{self, Decode, DecodePem, ObjectIdentifier}, Certificate};

use std::convert::TryInto;

const FIRMWARE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
const SERIAL_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
const POLICY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

const YUBICO_PIV_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----";

/// Represents the collection of data that has been validated from
/// the client leaf certificate, all the way up to the root CA.
#[derive(Debug)]
pub struct ValidPIVKey {
    /// An SSHPublic key usable with the rest of this crate's
    /// functionality
    pub public_key: PublicKey,
    /// The firmware on the key
    pub firmware: String,
    /// The key's serial number
    pub serial: u64,
    /// The touch policy for the given key
    pub touch_policy: u8,
    /// The pin policy for the given key
    pub pin_policy: u8,
}

fn extract_certificate_extension_data(
    public_key: PublicKey,
    certificate: x509_cert::Certificate,
) -> Result<ValidPIVKey, Error> {
    let mut firmware: Option<String> = None;
    let mut serial: Option<u64> = None;
    let mut policies: Option<[u8; 2]> = None;

    let extensions = certificate.tbs_certificate.extensions
        .ok_or_else(|| Error::ParsingError)?;

    for ext in extensions.iter() {
        match ext.extn_id {
            FIRMWARE_OID => {
                if ext.extn_value.len().into() != 3 {
                    continue;
                }
                let value = ext.extn_value.as_bytes();
                firmware = Some(format!(
                    "{}.{}.{}",
                    value[0], value[1], value[2]
                ));
            }
            // Serial
            SERIAL_OID => {
                let value = der::asn1::Int::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| Error::ParsingError)?;
                if value.len().into() > 8 {
                    continue;
                }
                let mut padded_serial = vec![0; 8 - value.len().into()];
                padded_serial.extend_from_slice(s);
                serial = Some(u64::from_be_bytes(
                    padded_serial.try_into().map_err(|_| Error::ParsingError)?,
                ));
            }
            // Policy
            POLICY_OID => {
                let value = ext.extn_value.as_bytes();
                policies = Some([value[0], value[1]]);
            }
            _ => (),
        }
    }

    if firmware.is_none() || serial.is_none() || policies.is_none() {
        return Err(Error::ParsingError);
    }

    let policies = policies.unwrap();
    let pin_policy = policies[0];
    let touch_policy = policies[1];

    Ok(ValidPIVKey {
        public_key,
        firmware: firmware.unwrap(),
        serial: serial.unwrap(),
        touch_policy,
        pin_policy,
    })
}

/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation Root CA.
pub fn verify_certificate_chain(
    client: &[u8],
    intermediate: &[u8],
    root_pem: Option<&str>,
) -> Result<ValidPIVKey, Error> {
    let root_ca_pem = root_pem.unwrap_or(YUBICO_PIV_ROOT_CA);

    // Parse the root ca
    let parsed_root_ca = x509_cert::Certificate::from_pem(root_ca_pem.as_bytes())
        .map_err(|_| Error::ParsingError)?;

    // Parse the intermediate and client certificates
    let parsed_intermediate = x509_cert::Certificate::from_der(intermediate)
        .map_err(|_| Error::ParsingError)?;
    let parsed_client = x509_cert::Certificate::from_der(client)
        .map_err(|_| Error::ParsingError)?;

    // Validate that the provded intermediate certificate is signed by the Yubico Attestation Root CA
    parsed_intermediate
        .verify_signature(Some(&root_ca.tbs_certificate.subject_pki))
        .map_err(|_| Error::InvalidSignature)?;

    // Validate that the provided certificate is signed by the intermediate CA
    parsed_client
        .verify_signature(Some(&parsed_intermediate.tbs_certificate.subject_pki))
        .map_err(|_| Error::InvalidSignature)?;

    // Extract the certificate public key and convert to an sshcerts PublicKey
    let public_key = match extract_ssh_pubkey_from_x509_certificate(client) {
        Ok(ssh) => ssh,
        Err(_) => return Err(Error::ParsingError),
    };

    extract_certificate_extension_data(public_key, parsed_client)
}
