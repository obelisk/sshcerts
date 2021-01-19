use super::keytype::{Curve, KeyType, KeyTypeKind};
use super::error::{Error, ErrorKind};
use super::PublicKey;
use super::reader::Reader;

//use std::fmt;
use std::fs::File;
use std::io::{Read};
use std::path::Path;

/// RSA private key.
#[derive(Debug, PartialEq, Clone)]
pub struct RsaPrivateKey {
    /// Private key exponent.
    pub d: Vec<u8>,

    /// Modulus of key.
    pub n: Vec<u8>,
}

/// ECDSA private key.
#[derive(Debug, PartialEq, Clone)]
pub struct EcdsaPrivateKey {
    /// The curve being used.
    pub curve: Curve,

    /// The private key.
    pub key: Vec<u8>,
}

/// ED25519 private key.
#[derive(Debug, PartialEq, Clone)]
pub struct Ed25519PrivateKey {
    /// The private key.
    pub key: Vec<u8>,
}

/// A type which represents the different kinds a public key can be.
#[derive(Debug, PartialEq, Clone)]
pub enum PrivateKeyKind {
    /// Represents an RSA public key.
    Rsa(RsaPrivateKey),

    /// Represents an ECDSA public key.
    Ecdsa(EcdsaPrivateKey),

    /// Represents an ED25519 public key.
    Ed25519(Ed25519PrivateKey),
}

/// A type which represents an OpenSSH public key.
#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey {
    /// Key type.
    pub key_type: KeyType,

    /// The kind of public key.
    pub kind: PrivateKeyKind,

    /// The corresponding public key
    pub pubkey: PublicKey,

    /// Associated comment, if any.
    pub comment: Option<String>,
}

impl PrivateKey {
    /// Reads an OpenSSH private key from a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<PrivateKey, Error> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        PrivateKey::from_string(&contents)
    }

    /// Reads an OpenSSH private key from a given string.
    pub fn from_string(contents: &str) -> Result<PrivateKey, Error> {
        let mut iter = contents.lines();
        let header = iter.next().unwrap_or("");
        if header != "-----BEGIN OPENSSH PRIVATE KEY-----" {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let mut encoded_key = String::new();
        loop {
            let part = match iter.next() {
                Some(p) => p,
                None => return Err(Error::with_kind(ErrorKind::InvalidFormat)),
            };

            if part == "-----END OPENSSH PRIVATE KEY-----" {
                break;
            }
            encoded_key.extend(part.chars());
        }

        let decoded = base64::decode(encoded_key)?;
        let mut reader = Reader::new(&decoded);

        // Construct a new `PrivateKey`
        let k = PrivateKey::from_reader(&mut reader)?;

        Ok(k)
    }

    // This function is used for extracting a public key from an existing reader, e.g.
    // we already have a reader for reading an OpenSSH certificate key and
    // we want to extract the public key information from it.
    pub(crate) fn from_reader(reader: &mut Reader) -> Result<PrivateKey, Error> {
        let preamble = reader.read_cstring()?;

        if preamble != "openssh-key-v1" {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let cipher_name = reader.read_string()?;
        let kdf = reader.read_string()?;
        if cipher_name != "none" || kdf != "none" {
            return Err(Error::with_kind(ErrorKind::EncryptedPrivateKeyNotSupported));
        }
        // This appears to be en empty value
        reader.read_string()?;

        let number_of_keys = reader.read_u32()?;

        if number_of_keys != 1 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let pubkey = reader
        .read_bytes()
        .and_then(|v| PublicKey::from_bytes(&v))?;

        let _remaining_length = reader.read_u32()?;

        let c1 = reader.read_u32()?;
        let c2 = reader.read_u32()?;

        if c1 != c2 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let key_type = reader.read_string()?;
        let kt = KeyType::from_name(&key_type)?;
        
        let kind = match kt.kind {
            /*KeyTypeKind::Rsa => {
                let k = RsaPublicKey {
                    e: reader.read_mpint()?,
                    n: reader.read_mpint()?,
                };

                PublicKeyKind::Rsa(k)
            }*/
            KeyTypeKind::Ecdsa => {
                let identifier = reader.read_string()?;
                let curve = Curve::from_identifier(&identifier)?;
                let _pubkey = reader.read_bytes()?;
                let key = reader.read_bytes()?;
                let k = EcdsaPrivateKey {
                    curve,
                    key,
                };

                PrivateKeyKind::Ecdsa(k)
            }
            /*KeyTypeKind::Ed25519 => {
                let k = Ed25519PrivateKey {
                    key: reader.read_bytes()?,
                };

                PrivateKeyKind::Ed25519(k)
            }*/
            _ => return Err(Error::with_kind(ErrorKind::UnknownKeyType(kt.name.to_string()))),
        };

        Ok(PrivateKey {
            key_type: kt,
            kind,
            pubkey,
            comment: None,
        })
    }
}

