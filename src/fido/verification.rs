use x509_parser::der_parser::ber::{parse_ber_bitstring, BerObjectContent};
use x509_parser::der_parser::der::parse_der_octetstring;
use x509_parser::prelude::*;

use crate::error::Error;

use std::convert::TryFrom;

use super::AuthData;

use ring::{
    digest,
    signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1},
};

const YUBICO_U2F_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----";

/// Defines the transports supported by the FIDO standard
#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    /// "Classic" bluetooth
    Bluetooth = 0,
    /// Bluetooth low energe
    BluetoothLE = 1,
    /// USB
    USB = 2,
    /// Near field communication
    NFC = 3,
    /// USB (internal)
    USBInternal = 4,
}

impl TryFrom<usize> for Transport {
    type Error = ();

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::Bluetooth as usize => Ok(Self::Bluetooth),
            x if x == Self::BluetoothLE as usize => Ok(Self::BluetoothLE),
            x if x == Self::USB as usize => Ok(Self::USB),
            x if x == Self::NFC as usize => Ok(Self::NFC),
            x if x == Self::USBInternal as usize => Ok(Self::USBInternal),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
/// Represents a validated attestation and all the extracted data.
pub struct ValidAttestation {
    /// The verified authentication data from the attestation
    pub auth_data: AuthData,
    /// The extracted firmware from the certificate
    pub firmware: Option<String>,
    /// The device AAGUID
    pub aaguid: Option<Vec<u8>>,
    /// The transports the device supports
    pub transports: Option<Vec<Transport>>,
}

fn extract_certificate_extension_data(
    auth_data: AuthData,
    certificate: &X509Certificate<'_>,
) -> Result<ValidAttestation, Error> {
    let mut valid_attestation = ValidAttestation {
        auth_data,
        firmware: None,
        aaguid: None,
        transports: None,
    };

    let extensions = certificate.extensions();
    for ext in extensions.iter() {
        match ext.oid.to_id_string().as_str() {
            // Yubico Serial Number
            "1.3.6.1.4.1.41482.13.1" => {
                let (_, obj) = parse_der_octetstring(ext.value).map_err(|_| Error::ParsingError)?;
                if let BerObjectContent::OctetString(s) = obj.content {
                    if s.len() != 3 {
                        continue;
                    }
                    valid_attestation.firmware = Some(format!("{}.{}.{}", s[0], s[1], s[2]));
                }
            }

            // FIDO AAGUID
            "1.3.6.1.4.1.45724.1.1.4" => {
                let (_, obj) = parse_der_octetstring(ext.value).map_err(|_| Error::ParsingError)?;
                if let BerObjectContent::OctetString(s) = obj.content {
                    if s.len() != 16 {
                        continue;
                    }
                    valid_attestation.aaguid = Some(s.to_vec());
                }
            }

            // fidoU2FTransports
            "1.3.6.1.4.1.45724.2.1.1" => {
                let (_, obj) = parse_ber_bitstring(ext.value).map_err(|_| Error::ParsingError)?;
                if let BerObjectContent::BitString(_, bs) = obj.content {
                    let mut transports = vec![];
                    for transport in 0..4 {
                        if !bs.is_set(transport) {
                            continue;
                        }
                        if let Ok(t) = Transport::try_from(transport) {
                            transports.push(t);
                        }
                    }
                    valid_attestation.transports = Some(transports);
                }
            }
            _ => (),
        }
    }

    Ok(valid_attestation)
}

/// Verify a provided U2F attestation, signature, and certificate are valid
/// against the root. If no root is given, the Yubico U2F Root is used.
pub fn verify_auth_data(
    auth_data: &[u8],
    auth_data_signature: &[u8],
    challenge: &[u8],
    alg: i32,
    intermediate: &[u8],
    root_pem: Option<&str>,
) -> Result<ValidAttestation, Error> {
    match alg {
        // Verify using ECDSA256
        -7 => {
            let root_ca_pem = root_pem.unwrap_or(YUBICO_U2F_ROOT_CA);

            // Parse the U2F root CA
            let (_, root_ca) =
                parse_x509_pem(root_ca_pem.as_bytes()).map_err(|_| Error::ParsingError)?;
            let root_ca = Pem::parse_x509(&root_ca).map_err(|_| Error::ParsingError)?;

            let (_, parsed_intermediate) =
                X509Certificate::from_der(intermediate).map_err(|_| Error::ParsingError)?;

            // Check the root CA has signed the intermediate, return error if not
            parsed_intermediate
                .verify_signature(Some(&root_ca.tbs_certificate.public_key()))
                .map_err(|_| Error::InvalidSignature)?;

            // Extract public key from verified intermediate certificate
            let key_bytes = parsed_intermediate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .to_vec();

            // Generate the data that was signed by the intermediate
            let mut signed_data = auth_data.to_vec();
            signed_data.append(&mut digest::digest(&digest::SHA256, challenge).as_ref().to_vec());

            // Validate signature was generated by the now validated intermediate
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &key_bytes)
                .verify(&signed_data, auth_data_signature)
                .map_err(|_| Error::InvalidSignature)?;

            let auth_data = AuthData::parse(auth_data)?;

            extract_certificate_extension_data(auth_data, &parsed_intermediate)
        }
        // Verify using Ed25519
        -8 => return Err(Error::Unsupported),
        _ => return Err(Error::InvalidFormat),
    }
}
