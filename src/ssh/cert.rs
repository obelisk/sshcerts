use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ring::signature::{
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P384_SHA384_FIXED,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA512,
    ED25519,
    UnparsedPublicKey,
    RsaPublicKeyComponents};

use ring::rand::{SystemRandom, SecureRandom};

use crate::{error::Error, Result};
use super::{
    keytype::KeyType,
    pubkey::{PublicKey, PublicKeyKind},
    reader::Reader,
    writer::Writer
};

use std::convert::TryFrom;

/// Represents the different types a certificate can be.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CertType {
    /// Represents a user certificate.
    User = 1,

    /// Represents a host certificate.
    Host = 2,
}

impl TryFrom<&str> for CertType {
    type Error = &'static str;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match s {
            "user" | "User" => Ok(CertType::User),
            "host" | "Host" => Ok(CertType::Host),
            _ => Err("Unknown certificate type"),
        }
    }
}

impl fmt::Display for CertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl From<Extensions> for HashMap<String, String> {
    fn from(extensions: Extensions) -> Self {
        match extensions {
            Extensions::Standard => {
                let mut hm = HashMap::new();
                for extension in &STANDARD_EXTENSIONS {
                    hm.insert(String::from(extension.0), String::from(extension.1));
                }
                hm
            },
            Extensions::Custom(co) => co,
        }
    }
}

/// Type that encapsulates the normal usage of the extensions field.
#[derive(Clone, Debug)]
pub enum Extensions {
    /// Contains the five standard extensions: agent-forwarding, port-forwarding, pty, user-rc, X11-forwarding
    Standard,
    /// Allows a custom set of extensions to be passed in. This does not contain the standard extensions
    Custom(HashMap<String, String>)
}

/// Type that encapsulates the normal usage of the critical options field.
/// I used a structure instead of an Option for consistency and possible future
/// expansion into a ForceCommand type.
#[derive(Clone, Debug)]
pub enum CriticalOptions {
    /// Don't use any critical options
    None,
    /// Allows a custom set of critical options. Does not contain any standard options.
    Custom(HashMap<String, String>)
}

impl From<CriticalOptions> for HashMap<String, String> {
    fn from(critical_options: CriticalOptions) -> Self {
        match critical_options {
            CriticalOptions::None => HashMap::new(),
            CriticalOptions::Custom(co) => co,
        }
    }
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
    /// # use sshcerts::Certificate;
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
    /// use sshcerts::Certificate;
    ///
    /// let cert = Certificate::from_string(concat!(
    ///     "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGZlEWgv+aRvfJZiREMOKR0PVSTEstkuSeOyRgx",
    ///     "wI1v2AAAAIAwPJZIwmYs+W7WHNPneMUIAkQnBVw1LP0yQdfh7lT/S/v7+/v7+/v4AAAABAAAADG9iZWxpc2tAdGVzdAAAAAsAAAAHb2JlbGlzawAAAAAAAAAA///",
    ///     "///////8AAAAiAAAADWZvcmNlLWNvbW1hbmQAAAANAAAACS9iaW4vdHJ1ZQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQ",
    ///     "tZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADM",
    ///     "AAAALc3NoLWVkMjU1MTkAAAAgXRsP8RFzML3wJDAqm2ENwOrRAHez5QqtcEpyBvwvniYAAABTAAAAC3NzaC1lZDI1NTE5AAAAQMo0Akv0eyr269StM2zBd0Alzjx",
    ///     "XAC6krgBQex2O31at8r550oCIelfgj8YwZIaXG9DmleP525LcseJ16Z8e5Aw= obelisk@exclave.lan"
    /// )).unwrap();
    /// println!("{:?}", cert);
    /// ```
    pub fn from_string(s: &str) -> Result<Certificate> {
        let mut iter = s.split_whitespace();

        let kt_name = iter
            .next()
            .ok_or_else(|| Error::InvalidFormat)?;

        let key_type = KeyType::from_name(&kt_name)?;
        if !key_type.is_cert {
            return Err(Error::NotCertificate);
        }

        let data = iter
            .next()
            .ok_or_else(|| Error::InvalidFormat)?;

        let comment = iter.next().map(String::from);
        let decoded = base64::decode(&data)?;
        let mut reader = Reader::new(&decoded);

        // Validate key types before reading the rest of the data
        let kt_from_reader = reader.read_string()?;
        if kt_name != kt_from_reader {
            return Err(Error::KeyTypeMismatch);
        }

        let nonce = reader.read_bytes()?;
        let key = PublicKey::from_reader(&kt_name, &mut reader)?;
        let serial = reader.read_u64()?;

        let cert_type = match reader.read_u32()? {
            1 => CertType::User,
            2 => CertType::Host,
            n => return Err(Error::InvalidCertType(n)),
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

        reader.set_offset(0)?;
        let signed_bytes = reader.read_raw_bytes(signed_len)?;

        // Verify the certificate is properly signed
        verify_signature(&signature, &signed_bytes, &signature_key)?;

        Ok(Certificate {
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
        })
    }

    /// Create a new empty SSH certificate. Values must then be filled in using
    /// the mutator methods below.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshcerts::{Certificate, PublicKey};
    /// # use sshcerts::ssh::{CertType, CriticalOptions, Extensions};
    /// # fn test_signer(buf: &[u8]) -> Option<Vec<u8>> { None }
    /// # fn test_pubkey() -> Option<Vec<u8>> { None }
    /// # fn example() {
    ///     let ssh_pubkey = PublicKey::from_string("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOhHAGJtT9s6zPW4OdQMzGbXEyj0ntkESrE1IZBgaCUSh9fWK1gRz+UJOcCB1JTC/kF2EPlwkX6XEpQToZl51oo= obelisk@exclave.lan").unwrap();
    ///     let cert = Certificate::builder(&ssh_pubkey, CertType::User, &ssh_pubkey).unwrap()
    ///        .serial(0xFEFEFEFEFEFEFEFE)
    ///        .key_id("key_id")
    ///        .principal("obelisk")
    ///        .valid_after(0)
    ///        .valid_before(0xFFFFFFFFFFFFFFFF)
    ///        .set_critical_options(CriticalOptions::None)
    ///        .set_extensions(Extensions::Standard)
    ///        .sign(test_signer);
    /// 
    ///        match cert {
    ///            Ok(cert) => println!("{}", cert),
    ///            Err(e) => println!("Encountered an error while creating certificate: {}", e),
    ///        }
    /// # }
    /// ```
    pub fn builder(pubkey: &PublicKey, cert_type: CertType, signing_key: &PublicKey) -> Result<Certificate> {
        let kt_name = format!("{}-cert-v01@openssh.com", pubkey.key_type.name);
        let key_type = KeyType::from_name(kt_name.as_str()).unwrap();
        let rng = SystemRandom::new();

        let mut nonce = [0x0u8; 32];
        match SecureRandom::fill(&rng, &mut nonce) {
            Ok(()) => (),
            Err(_) => return Err(Error::UnexpectedEof),
        };

        let mut serial = [0x0u8; 8];
        match SecureRandom::fill(&rng, &mut serial) {
            Ok(()) => (),
            Err(_) => return Err(Error::UnexpectedEof),
        };
        let serial = u64::from_be_bytes(serial);

        Ok(Certificate {
            nonce: nonce.to_vec(),
            key: pubkey.clone(),
            key_type,
            serial,
            cert_type,
            key_id: String::new(),
            principals: vec![],
            valid_after: 0,
            valid_before: 0,
            critical_options: HashMap::new(),
            extensions: HashMap::new(),
            reserved: vec![0,0,0,0,0,0,0,0],
            signature_key: signing_key.clone(),
            signature: vec![],
            comment: None,
            serialized: vec![],
        })
    }

    /// Set the serial of a certificate builder
    pub fn serial(mut self, serial: u64) -> Self {
        self.serial = serial;
        self
    }

    /// Set the Key ID of a certificate builder
    pub fn key_id<S: AsRef<str>>(mut self, key_id: S) -> Self {
        self.key_id = key_id.as_ref().to_owned();
        self
    }
    
    /// Add a principal to the certificate
    pub fn principal<S: AsRef<str>>(mut self, principal: S) -> Self {
        self.principals.push(principal.as_ref().to_owned());
        self
    }

    /// Set the principals of the certificate
    pub fn set_principals(mut self, principals: &[String]) -> Self {
        self.principals = principals.to_vec();
        self
    }

    /// Set the initial validity time of the certificate
    pub fn valid_after(mut self, valid_after: u64) -> Self {
        self.valid_after = valid_after;
        self
    }

    /// Set the expiry of the certificate
    pub fn valid_before(mut self, valid_before: u64) -> Self {
        self.valid_before = valid_before;
        self
    }

    /// Add a critical option to the certificate
    pub fn critical_option<S: AsRef<str>>(mut self, option: S, value: S) -> Self {
        self.critical_options.insert(option.as_ref().to_owned(), value.as_ref().to_owned());
        self
    }

    /// Set the critical options of the certificate
    pub fn set_critical_options(mut self, critical_options: CriticalOptions) -> Self {
        self.critical_options = critical_options.into();
        self
    }

    /// Add a critical option to the certificate
    pub fn extension<S: AsRef<str>>(mut self, option: S, value: S) -> Self {
        self.extensions.insert(option.as_ref().to_owned(), value.as_ref().to_owned());
        self
    }

    /// Set the critical options of the certificate
    pub fn set_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = extensions.into();
        self
    }

    /// Set the critical options of the certificate
    pub fn comment<S: AsRef<str>>(mut self, comment: S) -> Self {
        self.comment = Some(comment.as_ref().to_owned());
        self
    }

    /// Get the certificate data without the signature field at the end.
    pub fn tbs_certificate(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        let kt_name = format!("{}-cert-v01@openssh.com", self.key.key_type.name);
        // Write the cert type
        writer.write_string(kt_name.as_str());

        // Write the nonce
        writer.write_bytes(&self.nonce);

        // Write the user public key
        writer.write_pub_key(&self.key);

        // Write the serial number
        writer.write_u64(self.serial);

        // Write what kind of cert this is
        writer.write_u32(self.cert_type as u32);

        // Write the key id
        writer.write_string(&self.key_id);

        // Write the principals
        writer.write_string_vec(&self.principals);

        // Write valid after
        writer.write_u64(self.valid_after);

        // Write valid before
        writer.write_u64(self.valid_before);

        // Write the critical options
        writer.write_string_map(&self.critical_options);

        // Write the extensions
        writer.write_string_map(&self.extensions);

        // Write the unused reserved bytes
        writer.write_u32(0x0);

        // Write the CA public key
        writer.write_bytes(&self.signature_key.encode());

        // Return the tbs certificate data
        writer.as_bytes().to_vec()
    }

    /// Attempts to add the given signature to the certificate. This function
    /// returns an error if the signature provided is not valid for the
    /// certificate under the set CA key.
    pub fn add_signature(mut self, signature: &[u8]) -> Result<Self> {
        let mut writer = Writer::new();

        match &self.signature_key.kind {
            PublicKeyKind::Ecdsa(_) => {
                writer.write_string(&self.signature_key.key_type.name);
                if let Some(signature) = crate::utils::signature_convert_asn1_ecdsa_to_ssh(signature) {
                    writer.write_bytes(&signature);
                } else {
                    return Err(Error::SigningError);
                }
            },
            PublicKeyKind::Rsa(_) => {
                writer.write_string("rsa-sha2-512");
                writer.write_bytes(&signature);
            },
            _ => {
                writer.write_string(&self.signature_key.key_type.name);
                writer.write_bytes(&signature);
            }
        };
        
        let signature = writer.into_bytes();

        let mut tbs = self.tbs_certificate();
        if let Err(e) = verify_signature(&signature, &tbs, &self.signature_key) {
            // Could not verify the certificate
            return Err(e)
        }

        let mut wrapped_writer = Writer::new();
        wrapped_writer.write_bytes(&signature);

        // After this it's no longer "tbs"
        tbs.extend_from_slice(&wrapped_writer.into_bytes());

        self.signature = signature.to_vec();
        self.serialized = tbs;

        Ok(self)
    }

    /// Take the certificate settings and generate a valid signature using the provided signer function
    pub fn sign(self, signer: impl FnOnce(&[u8]) -> Option<Vec<u8>>) -> Result<Self> {
        let tbs_certificate = self.tbs_certificate();

        // Sign the data and write it to the cert
        let signature =  match signer(&tbs_certificate) {
            Some(sig) => sig,
            None => return Err(Error::SigningError),
        };
        self.add_signature(&signature)
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
            Err(e) => match e {
                Error::UnexpectedEof => break,
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
            Err(e) => match e {
                Error::UnexpectedEof => break,
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
//  ecdsa-sha2-nistp521 (but this is unsupported in Ring so not supported here)
//
// RSA
//  rsa-sha2-256
//  rsa-sha2-512
//
// Ed25519
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

            let (alg, len) = match sig_type.name {
                "ecdsa-sha2-nistp256" => (&ECDSA_P256_SHA256_FIXED, 32),
                "ecdsa-sha2-nistp384" => (&ECDSA_P384_SHA384_FIXED, 48),
                _ => return Err(Error::KeyTypeMismatch),
            };

            // Read the R value
            let r_bytes = reader.read_mpint()?;
            // Read the S value
            let s_bytes = reader.read_mpint()?;

            // (r/s)_bytes are user controlled so ensure maliciously signatures
            // can't cause integer underflow.
            if r_bytes.len() > len || s_bytes.len() > len {
                return Err(Error::InvalidFormat);
            }

            // Determine and create the padding required
            let mut r = vec![0; len - r_bytes.len()];
            let mut s = vec![0; len - s_bytes.len()];

            // Pad *_bytes
            r.extend(r_bytes);
            s.extend(s_bytes);

            // Build a properly padded signature
            let mut sig = r;
            sig.extend(s);

            UnparsedPublicKey::new(alg, &key.key).verify(&signed_bytes, &sig)?;
            Ok(signature_buf.to_vec())
        },
        PublicKeyKind::Rsa(key) => {
            let alg = match sig_type.name {
                "rsa-sha2-256" => &RSA_PKCS1_2048_8192_SHA256,
                "rsa-sha2-512" => &RSA_PKCS1_2048_8192_SHA512,
                "ssh-rsa" => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                _ => return Err(Error::KeyTypeMismatch),
            };
            let signature = reader.read_bytes()?;
            let public_key = RsaPublicKeyComponents { n: &key.n, e: &key.e };
            public_key.verify(alg, &signed_bytes, &signature)?;
            Ok(signature_buf.to_vec())
        },
        PublicKeyKind::Ed25519(key) => {
            let alg = &ED25519;
            let signature = reader.read_bytes()?;
            let peer_public_key = UnparsedPublicKey::new(alg, &key.key);
            peer_public_key.verify(&signed_bytes, &signature)?;
            Ok(signature_buf.to_vec())
        },
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            write!(f, "{} {} {}", &self.key_type.name, base64::encode(&self.serialized), &self.key_id)
        } else {
            let mut pretty: String = format!("Type: {} {}\n", self.key_type, self.cert_type);
            pretty.push_str(&format!("Public Key: {} {}:{}\n", self.key_type.short_name, self.key.fingerprint().kind, self.key.fingerprint().hash));
            pretty.push_str(&format!("Signing CA: {} {}:{} (using {})\n", self.signature_key.key_type.short_name, self.signature_key.fingerprint().kind, self.signature_key.fingerprint().hash, self.signature_key.key_type));
            pretty.push_str(&format!("Key ID: \"{}\"\n", self.key_id));
            pretty.push_str(&format!("Serial: {}\n", self.serial));
            if self.valid_before == 0xFFFFFFFFFFFFFFFF && self.valid_after == 0x0 {
                pretty.push_str("Valid: forever\n");
            } else {
                pretty.push_str(&format!("Valid between: {} and {}\n", self.valid_after, self.valid_before));
            }

            if self.principals.is_empty() {
                pretty.push_str("Principals: (none)\n");
            } else {
                pretty.push_str("Principals\n");
                for principal in &self.principals {
                    pretty.push_str(&format!("\t{}\n", principal));
                }
            }

            if self.critical_options.is_empty() {
                pretty.push_str("Critical Options: (none)\n");
            } else {
                pretty.push_str("Critical Options:\n");
                for (name, value) in &self.critical_options {
                    pretty.push_str(&format!("\t{} {}\n", name, value));
                }
            }

            if self.extensions.is_empty() {
                pretty.push_str("Extensions: (none)\n");
            } else {
                pretty.push_str("Extensions:\n");
                for name in self.extensions.keys() {
                    pretty.push_str(&format!("\t{}\n", &name));
                }
            }

            write!(f, "{}", pretty)
        }
    }
}
