use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ring::signature::{
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P384_SHA384_FIXED,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA512,
    UnparsedPublicKey,
    RsaPublicKeyComponents};

use ring::rand::{SystemRandom, SecureRandom};

use super::error::{Error, ErrorKind, Result};
use super::keytype::{KeyType};
use super::pubkey::{PublicKey, PublicKeyKind};
use super::reader::Reader;


/// Represents the different types a certificate can be.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CertType {
    /// Represents a user certificate.
    User = 1,

    /// Represents a host certificate.
    Host = 2,
}

impl fmt::Display for CertType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CertType::User => write!(f, "user certificate"),
            CertType::Host => write!(f, "host certificate"),
        }
    }
}

const STANDARD_EXTENSIONS: [(&str, &str); 5] = [
    ("permit-agent-forwarding", ""),
    ("permit-port-forwarding", ""),
    ("permit-pty", ""),
    ("permit-user-rc", ""),
    ("permit-X11-forwarding", ""),
];

/// Type that encapsulates the normal usage of the extensions field.
#[derive(Debug)]
pub enum Extensions {
    /// Contains the five standard extensions: agent-forwarding, port-forwarding, pty, user-rc, X11-forwarding
    Standard,
    /// Allows a completely custom set of extensions to be passed in. This does not contain the standard
    /// extensions
    Custom(HashMap<String, String>)
}

/// Type that encapsulates the normal usage of the critical options field.
/// I used a structure instead of an Option for consistency and possible future
/// expansion into a ForceCommand type.
#[derive(Debug)]
pub enum CriticalOptions {
    /// Don't use any critical options
    None,
    /// Allows a custom set of critical options. Does not contain any standard options.
    Custom(HashMap<String, String>)
}

/// A type which represents an OpenSSH certificate key.
/// Please refer to [PROTOCOL.certkeys] for more details about OpenSSH certificates.
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[derive(Debug)]
pub struct Certificate {
    /// Type of key.
    pub key_type: KeyType,

    /// Cryptographic nonce.
    pub nonce: Vec<u8>,

    /// Public key part of the certificate.
    pub key: PublicKey,

    /// Serial number of certificate.
    pub serial: u64,

    /// Represents the type of the certificate.
    pub cert_type: CertType,

    /// Key identity.
    pub key_id: String,

    /// The list of valid principals for the certificate.
    pub principals: Vec<String>,

    /// Time after which certificate is considered as valid.
    pub valid_after: u64,

    /// Time before which certificate is considered as valid.
    pub valid_before: u64,

    /// Critical options of the certificate. Generally used to
    /// control features which restrict access.
    pub critical_options: HashMap<String, String>,

    /// Certificate extensions. Extensions are usually used to
    /// enable features that grant access.
    pub extensions: HashMap<String, String>,

    /// The `reserved` field is currently unused and is ignored in this version of the protocol.
    pub reserved: Vec<u8>,

    /// Signature key contains the CA public key used to sign the certificate.
    pub signature_key: PublicKey,

    /// Signature of the certificate.
    pub signature: Vec<u8>,

    /// Associated comment, if any.
    pub comment: Option<String>,

    /// The entire serialized certificate, used for exporting
    pub serialized: Vec<u8>,
}

impl Certificate {
    /// Reads an OpenSSH certificate from a given path.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustica_keys::Certificate;
    /// # fn example() {
    ///     let cert = Certificate::from_path("/path/to/id_ed25519-cert.pub").unwrap();
    ///     println!("{}", cert);
    /// # }
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Certificate> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        Certificate::from_string(&contents)
    }

    /// Reads an OpenSSH certificate from a given string.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustica_keys::Certificate;
    /// # fn example() {
    ///     let cert = Certificate::from_string("ssh-rsa AAAAB3NzaC1yc2EAAAA...").unwrap();
    ///     println!("{}", cert);
    /// # }
    /// ```
    pub fn from_string(s: &str) -> Result<Certificate> {
        let mut iter = s.split_whitespace();

        let kt_name = iter
            .next()
            .ok_or_else(|| Error::with_kind(ErrorKind::InvalidFormat))?;

        let key_type = KeyType::from_name(&kt_name)?;
        if !key_type.is_cert {
            return Err(Error::with_kind(ErrorKind::NotCertificate));
        }

        let data = iter
            .next()
            .ok_or_else(|| Error::with_kind(ErrorKind::InvalidFormat))?;

        let comment = iter.next().map(String::from);
        let decoded = base64::decode(&data)?;
        let mut reader = Reader::new(&decoded);

        // Validate key types before reading the rest of the data
        let kt_from_reader = reader.read_string()?;
        if kt_name != kt_from_reader {
            return Err(Error::with_kind(ErrorKind::KeyTypeMismatch));
        }

        let nonce = reader.read_bytes()?;
        let key = PublicKey::from_reader(&kt_name, &mut reader)?;
        let serial = reader.read_u64()?;

        let cert_type = match reader.read_u32()? {
            1 => CertType::User,
            2 => CertType::Host,
            n => return Err(Error::with_kind(ErrorKind::InvalidCertType(n))),
        };

        let key_id = reader.read_string()?;
        let principals = reader.read_bytes().and_then(|v| read_principals(&v))?;
        let valid_after = reader.read_u64()?;
        let valid_before = reader.read_u64()?;
        let critical_options = reader.read_bytes().and_then(|v| read_options(&v))?;
        let extensions = reader.read_bytes().and_then(|v| read_options(&v))?;
        let reserved = reader.read_bytes()?;
        let signature_key = reader
            .read_bytes()
            .and_then(|v| PublicKey::from_bytes(&v))?;

        let signed_len = reader.get_offset();
        let signature = reader.read_bytes()?;

        reader.set_offset(0).unwrap();
        let signed_bytes = reader.read_raw_bytes(signed_len).unwrap();

        // Verify the certificate is properly signed
        verify_signature(&signature, &signed_bytes, &signature_key)?;

        let cert = Certificate {
            key_type,
            nonce,
            key,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            reserved,
            signature_key,
            signature,
            comment,
            serialized: decoded,
        };

        Ok(cert)
    }

    /// Create a new SSH certificate from the provided values. It takes
    /// two function pointers to retrieve the signing public key as well
    /// as a function to do the actual signing. This function pointed to is 
    /// responsible for hashing the data as no hashing is done Certificate::new
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustica_keys::{Certificate, PublicKey};
    /// # use rustica_keys::ssh::{CertType, CriticalOptions, Extensions};
    /// fn test_signer(buf: &[u8]) -> Option<Vec<u8>> { None }
    /// fn test_pubkey() -> Option<Vec<u8>> { None }
    /// # fn example() {
    ///   let cert = Certificate::new(
    ///      PublicKey::from_string("AAA...").unwrap(),
    ///      CertType::User,
    ///      0xFEFEFEFEFEFEFEFE,
    ///      String::from("obelisk@exclave"),
    ///      vec![String::from("obelisk2")],
    ///      0,
    ///      0xFFFFFFFFFFFFFFFF,
    ///      CriticalOptions::None,
    ///      Extensions::Standard,
    ///      PublicKey::from_string("AAA...").unwrap(),
    ///      test_signer,
    ///   );
    /// 
    ///   match cert {
    ///      Ok(cert) => println!("{}", cert),
    ///      Err(e) => println!("Encountered an error while creating certificate: {}", e),
    ///   }
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pubkey: PublicKey,
        cert_type: CertType,
        serial: u64,
        key_id: String,
        principals: Vec<String>,
        valid_after: u64,
        valid_before: u64,
        critical_options: CriticalOptions,
        extensions: Extensions,
        ca_pubkey: PublicKey,
        signer: fn(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<Certificate> {
        let mut writer = super::Writer::new();
        let kt_name = format!("{}-cert-v01@openssh.com", pubkey.key_type.name);
        // Write the cert type
        writer.write_string(kt_name.as_str());
        
        // Generate the nonce
        let mut nonce = [0x0u8; 32];
        let rng = SystemRandom::new();
        match SecureRandom::fill(&rng, &mut nonce) {
            Ok(()) => (),
            Err(_) => return Err(Error::with_kind(ErrorKind::UnexpectedEof)),
        };
        // Write the nonce
        writer.write_bytes(&nonce);

        // Write the user public key
        writer.write_pub_key(&pubkey);

        // Write the serial number
        writer.write_u64(serial);

        // Write what kind of cert this is
        writer.write_u32(cert_type as u32);

        // Write the key id
        writer.write_string(&key_id);

        // Write the principals
        writer.write_string_vec(&principals);

        // Write valid after
        writer.write_u64(valid_after);

        // Write valid before
        writer.write_u64(valid_before);

        // Write critical options
        let critical_options = match critical_options {
            CriticalOptions::None => {
                writer.write_string_map(&HashMap::new());
                HashMap::new()
            },
            CriticalOptions::Custom(co) => {
                writer.write_string_map(&co);
                co
            },
        };

        // Write extensions
        let extensions = match extensions {
            Extensions::Standard => {
                let stdex = STANDARD_EXTENSIONS.iter().map(|x| (String::from(x.0), String::from(x.1))).collect();
                writer.write_string_map(&stdex);
                stdex
            },
            Extensions::Custom(co) => {
                writer.write_string_map(&co);
                co
            },
        };

        // Write the unused reserved bytes
        writer.write_u32(0x0);

        // Write the CA public key
        writer.write_bytes(&ca_pubkey.encode());

        // Sign the data and write it to the cert
        let signature =  match signer(writer.as_bytes()) {
            Some(sig) => sig,
            None => return Err(Error::with_kind(ErrorKind::SigningError)),
        };

        match verify_signature(&signature, &writer.as_bytes(), &ca_pubkey) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        writer.write_bytes(&signature);

        Ok(Certificate {
            key_type: KeyType::from_name(kt_name.as_str()).unwrap(),
            nonce: nonce.to_vec(),
            key: pubkey,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            reserved: vec![0,0,0,0,0,0,0,0],
            signature_key: ca_pubkey,
            signature,
            comment: None,
            serialized: writer.into_bytes(),
        })
    }
}

// Reads `option` values from a byte sequence.
// The `option` values are used to represent the `critical options` and
// `extensions` in an OpenSSH certificate key, which are represented as tuples
// containing the `name` and `data` values of type `string`.
// Some `options` are `flags` only (e.g. the certificate extensions) and the
// associated value with them is the empty string (""), while others are `string`
// options and have an associated value, which is a `string`.
// The `critical options` of a certificate are always `string` options, since they
// have an associated `string` value, which is embedded in a separate buffer, so
// in order to extract the associated value we need to read the buffer first and then
// read the `string` value itself.
fn read_options(buf: &[u8]) -> Result<HashMap<String, String>> {
    let mut reader = Reader::new(&buf);
    let mut options = HashMap::new();

    // Use a `Reader` and loop until EOF is reached, so that we can
    // read all options from the provided byte slice.
    loop {
        let name = match reader.read_string() {
            Ok(v) => v,
            Err(e) => match e.kind {
                ErrorKind::UnexpectedEof => break,
                _ => return Err(e),
            },
        };

        // If we have a `string` option extract the value from the buffer,
        // otherwise we have a `flag` option which is the `empty` string.
        let value_buf = reader.read_bytes()?;
        let value = if !value_buf.is_empty() {
            Reader::new(&value_buf).read_string()?
        } else {
            "".to_string()
        };

        options.insert(name, value);
    }

    Ok(options)
}

// Reads the `principals` field of a certificate key.
// The `principals` are represented as a sequence of `string` values
// embedded in a buffer.
// This function reads the whole byte slice until EOF is reached in order to
// ensure all principals are read from the byte slice.
fn read_principals(buf: &[u8]) -> Result<Vec<String>> {
    let mut reader = Reader::new(&buf);
    let mut items = Vec::new();

    loop {
        let principal = match reader.read_string() {
            Ok(v) => v,
            Err(e) => match e.kind {
                ErrorKind::UnexpectedEof => break,
                _ => return Err(e),
            },
        };

        items.push(principal);
    }

    Ok(items)
}

// Verifies the certificate's signature is valid.
// Appended to the end of every SSH Cert is a signature for the preceding data,
// depending on the key, the signature could be any of the following:
//
// ECDSA
//  ecdsa-sha2-nistp256
//  ecdsa-sha2-nistp384
//  ecdsa-sha2-nistp521 (but this is unsupported in Ring so not supported)
//
// RSA
//  rsa-sha2-256
//  rsa-sha2-512
//
// Ed25519
//  Incomplete
//
// We then take the public key of the CA (immiediately preceeding the signature and part of the signed data)
// and verify the signature accordingly. If the signature is not valid, this function errors.
fn verify_signature(signature_buf: &[u8], signed_bytes: &[u8], public_key: &PublicKey) -> Result<Vec<u8>> {
    let mut reader = Reader::new(&signature_buf);
    let sig_type = reader.read_string().and_then(|v| KeyType::from_name(&v))?;

    match &public_key.kind {
         PublicKeyKind::Ecdsa(key) => {
            let sig_reader = reader.read_bytes()?;
            let mut reader = Reader::new(&sig_reader);

            // Read the R value
            let mut sig = reader.read_mpint()?;
            // Read the S value
            sig.extend(reader.read_mpint()?);

            let alg = match sig_type.name {
                "ecdsa-sha2-nistp256" => &ECDSA_P256_SHA256_FIXED,
                "ecdsa-sha2-nistp384" => &ECDSA_P384_SHA384_FIXED,
                _ => return Err(Error::with_kind(ErrorKind::KeyTypeMismatch)), 
            };

            let result = UnparsedPublicKey::new(alg, &key.key).verify(&signed_bytes, &sig);
            match result {
                Ok(()) => Ok(signature_buf.to_vec()),
                Err(_) => Err(Error::with_kind(ErrorKind::CertificateInvalidSignature)),
            }
        },
        PublicKeyKind::Rsa(key) => {
            let alg = match sig_type.name {
                "rsa-sha2-256" => &RSA_PKCS1_2048_8192_SHA256,
                "rsa-sha2-512" => &RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(Error::with_kind(ErrorKind::KeyTypeMismatch)), 
            };
            let signature = reader.read_bytes()?;
            let public_key = RsaPublicKeyComponents { n: &key.n, e: &key.e };
            let result = public_key.verify(alg, &signed_bytes, &signature);
            match result {
                Ok(()) => Ok(signature_buf.to_vec()),
                Err(e) => {
                    println!("Error: {}", e);
                    Err(Error::with_kind(ErrorKind::CertificateInvalidSignature))
                }
            }
        },
        PublicKeyKind::Ed25519(_key) => {
            Err(Error::with_kind(ErrorKind::CertificateInvalidSignature))
        },
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !f.alternate() {
            write!(f, "{} {} {}", &self.key_type.name, base64::encode(&self.serialized), &self.key_id)
        } else {
            writeln!(f, "Type: {} {}", self.key_type, self.cert_type).unwrap();
            writeln!(f, "Public Key: {} {}:{}", self.key_type.short_name, self.key.fingerprint().kind, self.key.fingerprint().hash).unwrap();
            writeln!(f, "Signing CA: {} {}:{} (using {})", self.signature_key.key_type.short_name, self.signature_key.fingerprint().kind, self.signature_key.fingerprint().hash, self.signature_key.key_type).unwrap();
            writeln!(f, "Key ID: \"{}\"", self.key_id).unwrap();
            writeln!(f, "Serial: {}", self.serial).unwrap();

            if self.valid_before == 0xFFFFFFFFFFFFFFFF && self.valid_after == 0x0 {
                writeln!(f, "Valid: forever").unwrap();
            } else {
                writeln!(f, "Valid between: {} and {}", self.valid_after, self.valid_before).unwrap();
            }

            if self.principals.is_empty() {
                writeln!(f, "Principals: (none)").unwrap();
            } else {
                writeln!(f, "Principals:").unwrap();
                for principal in &self.principals {
                    writeln!(f, "\t{}", principal).unwrap();
                }
            }

            if self.critical_options.is_empty() {
                writeln!(f, "Critical Options: (none)").unwrap();
            } else {
                writeln!(f, "Critical Options:").unwrap();
                for (name, value) in &self.critical_options {
                    writeln!(f, "\t{} {}", name, value).unwrap();
                }
            }

            if self.extensions.is_empty() {
                writeln!(f, "Extensions: (none)").unwrap();
            } else {
                writeln!(f, "Extensions:").unwrap();
                for name in self.extensions.keys() {
                    writeln!(f, "\t{}", name).unwrap();
                }
            }

            write!(f, "")
        }
    }
}