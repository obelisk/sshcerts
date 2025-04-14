use x509_parser::der_parser::ber::{parse_ber_bitstring, BerObjectContent};
use x509_parser::der_parser::der::parse_der_octetstring;
use x509_parser::prelude::*;

use crate::error::Error;

use std::convert::TryFrom;

use super::AuthData;

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

/// From https://developers.yubico.com/PKI/yubico-ca-certs.txt
const YUBICO_U2F_ROOT_CA_457200631: &str = "-----BEGIN CERTIFICATE-----
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

/// From https://developers.yubico.com/PKI/yubico-ca-certs.txt
const YUBICO_ATTESTATION_ROOT_1: &str = "-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQEN
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0
dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXvl12LUhBZ5LmiBScI
Zd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G74b/
U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAu
csrbE485HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyC
imJukhYy6KoqNMKQEdpNiSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdw
MRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNmMGQwHQYDVR0OBBYEFNLu71oijTptXCOX
PfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOXPfKF1SbxJXuSMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4IB
AQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1
XnquB5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIF
TWeIhMNcZKsDZrFAyPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7V
olBNlld6pRFKlX8ust6OTMOeADl2xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3i
roRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/HqaUYCA/L8ldRk6H7Xk35D+W
Vpmq2Sh/xT5HiFuhf4wJb0bK
-----END CERTIFICATE-----";

/// From https://developers.yubico.com/PKI/yubico-intermediate.pem
const YUBICO_ATTESTATION_INTERMEDIATE_A_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIUUcmMXzRIFOgGTK0Tb3gEuZYZkBIwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowLjEsMCoGA1UEAwwjWXViaWNvIEF0
dGVzdGF0aW9uIEludGVybWVkaWF0ZSBBIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDm555bWY9WW+tOY0rIWHldh+aNanoCZCFh7Gk3YZrQmPUw0hkS
G6qYHQtP+fZyS33VErvg+BQqnmumgNhfxFrkwEZELeidBcC8C4Ag4nqqiPWpzsvI
17NcxYlInLNLFcZY/+gOiN6ZOTihO5/vBZMbj9riaAcqliYmNGJPgTcMGaEAyMzE
MNy2nm6Ep+pjP5aF6gi21t/UQFsuJ1j2Rj/ynM/SdRt+ecal5OYotxHkFbL9vvv2
A2Ov5ITZClw4bOS9npypQimOZ5QAYytmYaQpWl/pMYz6zSj8RqkVDNEJGqNfTKA2
ivLYwX6lSttMPapg0J84l9X0voVN/FpS4VCVAgMBAAGjZjBkMB0GA1UdDgQWBBQg
KFAhG6RaW+hTy52dxeT8bC96HzAfBgNVHSMEGDAWgBTS7u9aIo06bVwjlz3yhdUm
8SV7kjASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG
9w0BAQsFAAOCAQEAYMzgLrJLIr0OovQnAZrRIGuabiHSUKSmbLRWpRkWeAtsChDE
HpXcJ/bgDNKYWoHqQ8xRUjB4CyepYevc3YlrG8o7zHxpfVcaoL5SeuJkzHxKn4bT
aSp9+Mvwamnp64kZMiNbFLknfP9kYKoRHkMWheRJ1UsP1z4ScmkCeILfsMs6vqov
qjWClFsJpBcsluYHWF7bBJ1n4Rwg+ATEopY4IgGv6Zvwc+A9r+AT2hqpoSkYoAl+
ANYwgslOf9sJe0V+TA9YY/UlaBmPPTd0//r9wvcePWZkPjKoAC/zUNhfDbh4LV8G
Hs3lyX2XomL/LNc8JYzyIaDEhGQveoPhh/tr1g==
-----END CERTIFICATE-----";

/// From https://developers.yubico.com/PKI/yubico-intermediate.pem
const YUBICO_ATTESTATION_INTERMEDIATE_B_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIUDqERw+4RnGSggxgUewJFEPDRZ3YwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowLjEsMCoGA1UEAwwjWXViaWNvIEF0
dGVzdGF0aW9uIEludGVybWVkaWF0ZSBCIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDI7XnH+ZvDwMCQU8M8ZeV5qscublvVYaaRt3Ybaxn9godLx5sw
H0lXrdgjh5h7FpVgCgYYX7E4bl1vbzULemrMWT8N3WMGUe8QAJbBeioV7W/E+hTZ
P/0SKJVa3ewKBo6ULeMnfQZDrVORAk8wTLq2v5Llj5vMj7JtOotKa9J7nHS8kLmz
XXSaj0SwEPh5OAZUTNV4zs1bvoTAQQWrL4/J9QuKt6WCFE5nUNiRQcEbVF8mlqK2
bx2z6okVltyDVLCxYbpUTELvY1usR3DTGPUoIClOm4crpwnDRLVHvjYePGBB//pE
yzxA/gcScxjwaH1ZUw9bnSbHyurKqbTa1KvjAgMBAAGjZjBkMB0GA1UdDgQWBBTq
t0KQngx7ZHrbVHwDunxOn9ihYTAfBgNVHSMEGDAWgBTS7u9aIo06bVwjlz3yhdUm
8SV7kjASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG
9w0BAQsFAAOCAQEAqQaCWMxTGqVVX7Sk7kkJmUueTSYKuU6+KBBSgwIRnlw9K7He
1IpxZ0hdwpPNikKjmcyFgFPzhImwHJgxxuT90Pw3vYOdcJJNktDg35PXOfzSn15c
FAx1RO0mPTmIb8dXiEWOpzoXvdwXDM41ZaCDYMT7w4IQtMyvE7xUBZq2bjtAnq/N
DUA7be4H8H3ipC+/+NKlUrcUh+j48K67WI0u1m6FeQueBA7n06j825rqDqsaLs9T
b7KAHAw8PmrWaNPG2kjKerxPEfecivlFawp2RWZvxrVtn3TV2SBxyCJCkXsND05d
CErVHSJIs+BdtTVNY9AwtyPmnyb0v4mSTzvWdw==
-----END CERTIFICATE-----";

/// From https://developers.yubico.com/PKI/yubico-intermediate.pem
const YUBICO_FIDO_ATTESTATION_A_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIUTnbbGIR2NHvzqIKFAeQwG1XBis0wDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBB
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCYxJDAiBgNVBAMM
G1l1YmljbyBGSURPIEF0dGVzdGF0aW9uIEEgMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOsXj3k04Ban4TYdtZKqD/OPJxyDyaPmCBUFUiaZIgTteZnj
3X25DhgpZZXsC4D0ydIcrlA6wNUInORL/L9zBbTEIMAVMGo6g7UKAmb2MF6AHbnh
YJd9eikupVNWShHNYNc4GBdO1YN6AfUqvJhHbe3V4SNMPmBREKJPVz7ThwgmggTe
8Ws2K0/wsqv2wSE7pbCBsUZhIX51bZM3pqDwJPTmRFEvt0/6tG5eO8F3j14OXqfE
hmjn1VvxKDYQOLZAxCwwgC0P4CdfWv3y8PSR8I354hO1Y+GzNjvIqX38NKLywuIY
HFerOxNlxEMBvFhYBuRuYAkkgUaPqN6UBhsILrsCAwEAAaNmMGQwHQYDVR0OBBYE
FCCoRHhiyNnbnXRWIL6ZBXoBX9YTMB8GA1UdIwQYMBaAFCAoUCEbpFpb6FPLnZ3F
5PxsL3ofMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqG
SIb3DQEBCwUAA4IBAQCQFafJI1/5Wg9CEEimE1RP54RgQwTNTOOQsLACTe+rItlF
QzC9ZDhrV828yX7jzy+AAsp3izK7T1th2dl7m+tu0sw2Pa/olc02nt6PyIw348ga
HzhI1+0KE45qxvFDeL2lMxbPfCYvyEEaYzjiQELU5951pXGWyKMa/4fLtO+ZKOXh
MuVeq4rXDPI54W6JHOiAaiKdiw+5e3c2kt/jFIQtM6vMXg9LNFzdjETNt20VX9Qe
vRpFZfucMG9wCaQDoFlPzpTMJKhPev/imJmZYhKfr0lLcemtqjIxLAoqZdOYfHBg
6+vAcdPI/iauGpUAv7X+UKNmDwjZ2BaH4sLwhB2m
-----END CERTIFICATE-----";

/// From https://developers.yubico.com/PKI/yubico-intermediate.pem
const YUBICO_FIDO_ATTESTATION_B_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIUR38mq26Sf2szVV2BdG6WEN7kuWUwDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBC
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCYxJDAiBgNVBAMM
G1l1YmljbyBGSURPIEF0dGVzdGF0aW9uIEIgMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBANY0Wb9oPoRoKoQyWPaJpz11vrWTg6zTtmNj2VoKRnyvKGRq
pzb83w5l6YA96UYkYBDQP0ilO2DPe6wWqVR5zDfRzdcH8bh+L7dGGvae6hRTZhkF
kCpXDs4HccknrDf8FClJ7He39Jf42/G1Qm2zz9WWmrPXtgiK/x05GjsQfGuDG1zf
5QTUUie8lwymK3TfdOvNeeJAAPe2pn7ItfRb+rVrNWiDzlRn2vNnZ2wPo4wH/WJ6
dhXZG+rMWT+a6Bocg1UfIw6kdunG4bTpZzsvacFYyR0mpf+DeOnpSWAmywJWHvTl
f2YXxFyeXcTACdQlcMNGJ2VhZQ48xtP5/RBP/8kCAwEAAaNmMGQwHQYDVR0OBBYE
FChy42okiqcTS1iqa/HRWjkBn4H/MB8GA1UdIwQYMBaAFOq3QpCeDHtkettUfAO6
fE6f2KFhMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqG
SIb3DQEBCwUAA4IBAQAn+RHIPbtMEDNdT1g8H/RitAkUdLgAt1tWGWnlj9knbv4/
4GlX7C9p45efPO9/aZL6OV1XRKBi6KmtBW5K7nuYEnMx/5BqBSbLT7rhduC49TBe
Mb9PHdXsTlSVNYefr1dGidr4j0xVBQLb1rknDAbdWDzKfvnayKO8Frwe7Hx843MG
/rJ+c0XruUvbfVTCHLiIWhM7oNDhL8xob6xUo9KLKcSL+ItYsO3/9Wb8Q9GjsqL4
FXsDcG1SaYh7KpfuMmOixqzJZO2nIicPYRg1I2SuiUfYO70tmdHcbl+kSQmSYt7r
q4viILg2Gx3j9rITuWTjbaUaSSQxgOmMSHuyzMAC
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

/// Verify that the intermediates are chained to the root CA.
fn verify_intermediates(
    parsed_intermediate: &X509Certificate<'_>,
    ca_pems: Vec<&str>,
) -> Result<(), Error> {
    // There has to be at least the root CA
    if ca_pems.is_empty() {
        return Err(Error::InvalidSignature);
    }

    let mut ca_parsed_pems = vec![];

    // Parse all the pems
    for pem in ca_pems {
        let (_, parsed_pem) = parse_x509_pem(pem.as_bytes()).map_err(|_| Error::ParsingError)?;
        ca_parsed_pems.push(parsed_pem);
    }

    // Parse the root CA
    let root_ca = ca_parsed_pems.first().ok_or(Error::ParsingError)?;
    let mut parent_ca = Pem::parse_x509(&root_ca).map_err(|_| Error::ParsingError)?;

    // Iteratively verify the chain
    for intermediate_ca in ca_parsed_pems.iter().skip(1) {
        let intermediate_ca = Pem::parse_x509(&intermediate_ca).map_err(|_| Error::ParsingError)?;

        // Check the parent CA has signed this intermediate, return error if not
        intermediate_ca
            .verify_signature(Some(&parent_ca.tbs_certificate.public_key()))
            .map_err(|_| Error::InvalidSignature)?;

        parent_ca = intermediate_ca;
    }

    // Check the parent intermediate CA has signed the final intermediate, return error if not
    parsed_intermediate
        .verify_signature(Some(&parent_ca.tbs_certificate.public_key()))
        .map_err(|_| Error::InvalidSignature)?;

    Ok(())
}

/// Verify that the intermediate chains to some Yubico root CA for FIDO attestation
/// We try all known Yubico Root CAs for backward compatibility
fn verify_yubico_intermediate(parsed_intermediate: &X509Certificate<'_>) -> Result<(), Error> {
    if verify_intermediates(
        &parsed_intermediate,
        vec![
            YUBICO_ATTESTATION_ROOT_1,
            YUBICO_ATTESTATION_INTERMEDIATE_A_1,
            YUBICO_FIDO_ATTESTATION_A_1,
        ],
    )
    .is_ok()
    {
        return Ok(());
    }

    if verify_intermediates(
        &parsed_intermediate,
        vec![
            YUBICO_ATTESTATION_ROOT_1,
            YUBICO_ATTESTATION_INTERMEDIATE_B_1,
            YUBICO_FIDO_ATTESTATION_B_1,
        ],
    )
    .is_ok()
    {
        return Ok(());
    }

    verify_intermediates(&parsed_intermediate, vec![YUBICO_U2F_ROOT_CA_457200631])
}

/// Verify a provided U2F attestation, signature, and certificate are valid
/// against the root. If no root is given, the Yubico U2F Root and FIDO root are used.
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
            let (_, parsed_intermediate) =
                X509Certificate::from_der(intermediate).map_err(|_| Error::ParsingError)?;

            // If a custom root CA is provided, we use that for verification.
            // If not, we will try all the known Yubico Root CAs for backward compatibility
            if let Some(pem) = root_pem {
                verify_intermediates(&parsed_intermediate, vec![pem])?;
            } else {
                verify_yubico_intermediate(&parsed_intermediate)?;
            }

            // Extract public key from verified intermediate certificate
            let key_bytes = parsed_intermediate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .to_vec();

            // Generate the data that was signed by the intermediate
            let mut signed_data = auth_data.to_vec();
            signed_data.extend(challenge);

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
