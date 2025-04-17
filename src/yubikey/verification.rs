use crate::{error::Error, x509::extract_ssh_pubkey_from_x509_certificate, PublicKey};

use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::der::parse_der_integer;
use x509_parser::prelude::*;

use std::convert::TryInto;

/// From https://developers.yubico.com/PKI/yubico-ca-certs.txt
const YUBICO_PIV_ROOT_CA_263751: &str = "-----BEGIN CERTIFICATE-----
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
const YUBICO_PIV_ATTESTATION_A_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUSiefkiKiicP9B63XwO7fKqevCkQwDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBB
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCUxIzAhBgNVBAMM
Gll1YmljbyBQSVYgQXR0ZXN0YXRpb24gQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAyGCyrZjNrdPfChdDe4JWd+4TMLr8nbugcKJz12egglWi7oy5
L9GT99/if9i1OrONdpEt0YrCa+qMb+dJJ0WUa8M5zXYnUDpn72vhFjH+Anb9P9+v
+ZrRqaj/jnR/MYP7NpVpeLHiH2dRCe/PX/NH1XE41GvdUEncDtqUUGaXUea0DfDY
McRDpPT2Qn5e8rn9FjzDA37SbOVuws5VlFTDzDdqR0FnqeWeIW0DFu17rzCqXcaB
VRDnQLTc5EEPDTpiRrQE/Ag+7Wg9ieLrueos75YMQ1EIkfjL49OBVogU1A7kwRGv
OnG8l7sYaY8LZ2b5FROe2hKqmsIy600qjn6b/QIDAQABo2YwZDAdBgNVHQ4EFgQU
hAuLXXtpQVBkcsbqyFlj6LVAadgwHwYDVR0jBBgwFoAUIChQIRukWlvoU8udncXk
/Gwveh8wEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
hvcNAQELBQADggEBAFxL/2oFjxkLh2KVnFKdhy7Nf7MmEfYXDDFSx1rFDn445jHO
UP5kxQPbZc9r53jdvL5W0SQBqBjqA95PYh0r1CPMFsFJdiFXli8Hf3NQ0bTkeFSN
G3LsQCOKMb+o2WjYU3vHkRVjKgKGLxysxxKxGfMUcXdJ0qM6ZVeRHehC2zy7XuI6
TQn7/V0ZHXjk7So7dUV55xQde094/3cCTnh9Q3j2aqMjkGx6tDboCsz/+W+tne7W
nMHG92ZiAAmOkP2bABjan461Qty/qBXPHomkfjqNbjUTluPXiMLYKCXHIyKwdkX6
cphouSMU3QOTsb35Y2PeWNk54xu+Eds/3nhRMso=
-----END CERTIFICATE-----";

/// From https://developers.yubico.com/PKI/yubico-intermediate.pem
const YUBICO_PIV_ATTESTATION_B_1: &str = "-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUWVf2oJG+t1qP8t8TicWgJ2KYan4wDQYJKoZIhvcNAQEL
BQAwLjEsMCoGA1UEAwwjWXViaWNvIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBC
IDEwIBcNMjQxMjAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMCUxIzAhBgNVBAMM
Gll1YmljbyBQSVYgQXR0ZXN0YXRpb24gQiAxMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAv7WBL9/5AKxSpCMoL63183WqRtFrOHY7tdyuGtoidoYWQrxV
aV9S+ZwH0aynh0IzD5A/PvCtuxdtL5w2cAI3tgsborOlEert4IZ904CZQfq3ooar
1an/wssbtMpPOQkC3MQiqrUyHlFS2BTbuwbBXY66lSVX/tGRuUgnBdfBJtcQKS6M
O4bU5ndPQqhGPyzcyY1LvlfzK7KJ1r/bixCRFqjhJRnPs0Czpg6rkRrFgC6cd5bK
1UgTsJy+3wrIqkv4CeV3EhSVnhnQjZgIrdIcI5WZ8T1Oq3OhMlWmY0K0dy/oZdP/
bpbG2qbyHLa6gprLT/qChQWLmffxn6D2DAB1zQIDAQABo2YwZDAdBgNVHQ4EFgQU
M0Nt3QHo7eGzaKMZn2SmXT74vpcwHwYDVR0jBBgwFoAU6rdCkJ4Me2R621R8A7p8
Tp/YoWEwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
hvcNAQELBQADggEBAI0HwoS84fKMUyIof1LdUXvyeAMmEwW7+nVETvxNNlTMuwv7
zPJ4XZAm9Fv95tz9CqZBj6l1PAPQn6Zht9LQA92OF7W7buuXuxuusBTgLM0C1iX2
CGXqY/k/uSNvi3ZYfrpd44TIrfrr8bCG9ux7B5ZCRqb8adDUm92Yz3lK1aX2M6Cw
jC9IZVTXQWhLyP8Ys3p7rb20CO2jJzV94deJ/+AsEb+bnCQImPat1GDKwrBosar+
BxtU7k6kgkxZ0G384O59GFXqnwkbw2b5HhORvOsX7nhOUhePFufzi1vT1g8Tzbwr
+TUfTwo2biKHHcI762KGtp8o6Bcv5y8WgExFuWY=
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
    certificate: &X509Certificate<'_>,
) -> Result<ValidPIVKey, Error> {
    let mut firmware: Option<String> = None;
    let mut serial: Option<u64> = None;
    let mut policies: Option<[u8; 2]> = None;

    let extensions = certificate.extensions();
    for ext in extensions.iter() {
        match ext.oid.to_id_string().as_str() {
            // Firmware
            "1.3.6.1.4.1.41482.3.3" => {
                if ext.value.len() != 3 {
                    continue;
                }
                firmware = Some(format!(
                    "{}.{}.{}",
                    ext.value[0], ext.value[1], ext.value[2]
                ));
            }
            // Serial
            "1.3.6.1.4.1.41482.3.7" => {
                let (_, obj) = parse_der_integer(ext.value).map_err(|_| Error::ParsingError)?;
                if let BerObjectContent::Integer(s) = obj.content {
                    if s.len() > 8 {
                        continue;
                    }

                    let mut padded_serial = vec![0; 8 - s.len()];
                    padded_serial.extend_from_slice(s);
                    serial = Some(u64::from_be_bytes(
                        padded_serial.try_into().map_err(|_| Error::ParsingError)?,
                    ));
                }
            }
            // Policy
            "1.3.6.1.4.1.41482.3.8" => {
                policies = Some([ext.value[0], ext.value[1]]);
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

/// Verify a provided Yubikey attestation certification and intermediate
/// certificate are valid against the Yubico Attestation Root CA.
fn verify_yubico_intermediates(parsed_intermediate: &X509Certificate<'_>) -> Result<(), Error> {
    if verify_intermediates(
        &parsed_intermediate,
        vec![
            YUBICO_ATTESTATION_ROOT_1,
            YUBICO_ATTESTATION_INTERMEDIATE_A_1,
            YUBICO_PIV_ATTESTATION_A_1,
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
            YUBICO_PIV_ATTESTATION_B_1,
        ],
    )
    .is_ok()
    {
        return Ok(());
    }

    verify_intermediates(&parsed_intermediate, vec![YUBICO_PIV_ROOT_CA_263751])
}

/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation Root CA.
pub fn verify_certificate_chain(
    client: &[u8],
    intermediate: &[u8],
    root_pem: Option<&str>,
) -> Result<ValidPIVKey, Error> {
    let (_, parsed_intermediate) = X509Certificate::from_der(intermediate)
        .map_err(|_| Error::ParsingError)?;

    // If a custom root CA is provided, we use that for verification.
    // If not, we will try all the known Yubico Root CAs for backward compatibility
    if let Some(pem) = root_pem {
        verify_intermediates(&parsed_intermediate, vec![pem])?;
    } else {
        verify_yubico_intermediates(&parsed_intermediate)?;
    }

    // Parse the client cert
    let (_, parsed_client) = parse_x509_certificate(client).map_err(|_| Error::ParsingError)?;

    // Validate that the provided client certificate is signed by the intermediate CA
    parsed_client
        .verify_signature(Some(&parsed_intermediate.tbs_certificate.subject_pki))
        .map_err(|_| Error::InvalidSignature)?;

    println!("Extract public key from client cert");

    // Extract the certificate public key and convert to an sshcerts PublicKey
    let public_key = match extract_ssh_pubkey_from_x509_certificate(client) {
        Ok(ssh) => ssh,
        Err(_) => return Err(Error::ParsingError),
    };

    println!("Extract extensions from client cert");

    extract_certificate_extension_data(public_key, &parsed_client)
}
