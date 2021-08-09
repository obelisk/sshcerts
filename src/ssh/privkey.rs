use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::{error::Error, Result};
use super::{
    EcdsaPublicKey,
    Ed25519PublicKey,
    PublicKey,
    PublicKeyKind,
    RsaPublicKey,
    keytype::{Curve, KeyType, KeyTypeKind},
    reader::Reader,
};

#[cfg(feature = "rsa-signing")]
use num_bigint::{BigInt, BigUint, Sign};

#[cfg(feature = "rsa-signing")]
use simple_asn1::{ASN1Block, ASN1Class, ToASN1};

#[cfg(feature = "encrypted-keys")]
use aes::{
    Aes256Ctr,
    cipher::{NewCipher, generic_array::GenericArray, StreamCipher},
};

#[cfg(feature = "encrypted-keys")]
use bcrypt_pbkdf::bcrypt_pbkdf;


/// RSA private key.
#[derive(Debug, PartialEq, Clone)]
pub struct RsaPrivateKey {
    /// Modulus of key.
    pub n: Vec<u8>,

    /// Public key exponent
    pub e: Vec<u8>,

    /// Private key exponent.
    pub d: Vec<u8>,

    /// CRT coefficient q^(-1) mod p.
    pub coefficient: Vec<u8>,

    /// Prime factor p of n
    pub p: Vec<u8>,

    /// Prime factor q of n
    pub q: Vec<u8>,

    /// Exponent using p
    pub exp: Option<Vec<u8>>,

    /// Exponent using q
    pub exq: Option<Vec<u8>>,
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

#[cfg(feature = "rsa-signing")]
impl ToASN1 for RsaPrivateKey {
    type Error = Error;

    fn to_asn1_class(&self, _class: ASN1Class) -> std::result::Result<Vec<ASN1Block>, Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                vec![ASN1Block::Integer(0, BigInt::new(Sign::Plus, vec![0]))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.n))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.e))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.d))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.p))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.q))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.exp.as_ref().unwrap()))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.exq.as_ref().unwrap()))],
                vec![ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, &self.coefficient))],
                Vec::new(),
            ]
            .concat(),
        )])
    }
}

fn read_private_key(reader: &mut Reader<'_>) -> Result<PrivateKey> {
    let key_type = reader.read_string()?;
    let kt = KeyType::from_name(&key_type)?;

    let (kind, pubkey) = match kt.kind {
        KeyTypeKind::Rsa => {
            let n = reader.read_mpint()?;
            let e = reader.read_mpint()?;
            let d = reader.read_mpint()?;
            let coefficient = reader.read_mpint()?;
            let p = reader.read_mpint()?;
            let q = reader.read_mpint()?;

            #[cfg(feature = "rsa-signing")]
            let exp = Some(BigUint::from_bytes_be(&d)
                .modpow(
                    &BigUint::from_slice(&[0x1]),
                    &(BigUint::from_bytes_be(&p) - 1_u8)
                ).to_bytes_be());
            #[cfg(not(feature = "rsa-signing"))]
            let exp = None;

            #[cfg(feature = "rsa-signing")]
            let exq = Some(BigUint::from_bytes_be(&d)
                .modpow(
                    &BigUint::from_slice(&[0x1]),
                    &(BigUint::from_bytes_be(&q) - 1_u8)
                ).to_bytes_be());
            #[cfg(not(feature = "rsa-signing"))]
            let exq = None;

            (
                PrivateKeyKind::Rsa(RsaPrivateKey {
                    n: n.clone(),
                    e: e.clone(),
                    d,
                    coefficient,
                    p,
                    q,
                    exp: exp,
                    exq: exq,
                }
            ),
                PublicKey {
                    key_type: kt.clone(),
                    kind: PublicKeyKind::Rsa(RsaPublicKey{
                        e,
                        n
                    }),
                    comment: None,
                }
            )
        },
        KeyTypeKind::Ecdsa => {
            let identifier = reader.read_string()?;
            let curve = Curve::from_identifier(&identifier)?;
            let pubkey = reader.read_bytes()?;
            let key = reader.read_bytes()?;
            let k = EcdsaPrivateKey {
                curve: curve.clone(),
                key,
            };

            (
                PrivateKeyKind::Ecdsa(k),
                PublicKey {
                    key_type: kt.clone(),
                    kind: PublicKeyKind::Ecdsa(EcdsaPublicKey {
                        curve,
                        key: pubkey,
                    }),
                    comment: None,
                }
            )
        }
        KeyTypeKind::Ed25519 => {
            let pubkey = reader.read_bytes()?;
            let k = Ed25519PrivateKey {
                key: reader.read_bytes()?,
            };

            (
                PrivateKeyKind::Ed25519(k),
                PublicKey {
                    key_type: kt.clone(),
                    kind: PublicKeyKind::Ed25519(Ed25519PublicKey {
                        key: pubkey,
                    }),
                    comment: None,
                }
            )
        }
        _ => return Err(Error::UnknownKeyType(kt.name.to_string())),
    };

    let comment = reader.read_string()?;

    Ok(PrivateKey {
        key_type: kt,
        kind,
        pubkey,
        comment: if comment.len() == 0 {None} else {Some(comment)},
    })
}

impl PrivateKey {
    /// Reads an OpenSSH private key from a given path and passphrase
    pub fn from_path_with_passphrase<P: AsRef<Path>>(path: P, passphrase: Option<String>) -> Result<PrivateKey> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        PrivateKey::from_string_with_passphrase(&contents, passphrase)
    }

    /// Reads an OpenSSH private key from a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<PrivateKey> {
        PrivateKey::from_path_with_passphrase(path, None)
    }

    /// Reads an OpenSSH private key from a given string and passphrase
    pub fn from_string_with_passphrase(contents: &str, passphrase: Option<String>) -> Result<PrivateKey> {
        let mut iter = contents.lines();
        let header = iter.next().unwrap_or("");
        if header != "-----BEGIN OPENSSH PRIVATE KEY-----" {
            return Err(Error::InvalidFormat);
        }

        let mut encoded_key = String::new();
        loop {
            let part = match iter.next() {
                Some(p) => p,
                None => return Err(Error::InvalidFormat),
            };

            if part == "-----END OPENSSH PRIVATE KEY-----" {
                break;
            }
            encoded_key.push_str(part);
        }

        let decoded = base64::decode(encoded_key)?;
        let mut reader = Reader::new(&decoded);
        // Construct a new `PrivateKey`
        let k = PrivateKey::from_reader(&mut reader, passphrase)?;

        Ok(k)
    }

    /// Reads an OpenSSH private key from a given string.
    pub fn from_string(contents: &str) -> Result<PrivateKey> {
        PrivateKey::from_string_with_passphrase(contents, None)
    }

    /// Create a private key from just the decrypted private bytes
    pub fn from_bytes<T: ?Sized + AsRef<[u8]>>(buffer: &T) -> Result<PrivateKey> {
        let mut reader = Reader::new(buffer);
        read_private_key(&mut reader)
    }

    /// This function is used for extracting a private key from an existing reader.
    pub(crate) fn from_reader(reader: &mut Reader<'_>, passphrase: Option<String>) -> Result<PrivateKey> {
        let preamble = reader.read_cstring()?;

        if preamble != "openssh-key-v1" {
            return Err(Error::InvalidFormat);
        }

        // These values are for encrypted keys which are not supported
        let cipher_name = reader.read_string()?;
        let kdf = reader.read_string()?;

        #[allow(unused_variables)]
        let encryption_data = reader.read_bytes()?;

        // This seems to be hardcoded into the standard
        let number_of_keys = reader.read_u32()?;
        if number_of_keys != 1 {
            return Err(Error::InvalidFormat);
        }

        // A full pubkey with the same format as seen in certificates
        let pubkey = reader
        .read_bytes()
        .and_then(|v| PublicKey::from_bytes(&v))?;

        let remaining_length = match reader.read_u32()?.try_into() {
            Ok(rl) => rl,
            Err(_) => return Err(Error::InvalidFormat),
        };

        #[allow(unused_mut)]
        let mut remaining_bytes = reader.read_raw_bytes(remaining_length)?;

        match (cipher_name.as_str(), kdf.as_str(), passphrase) {
            ("none", "none", _) => (),
            #[cfg(feature = "encrypted-keys")]
            ("aes256-ctr", "bcrypt", Some(passphrase)) => {
                let mut enc_reader = Reader::new(&encryption_data);
                let salt = enc_reader.read_bytes()?;
                let rounds = enc_reader.read_u32()?;
                let mut output = [0; 48];
                if let Err(_) = bcrypt_pbkdf(passphrase.as_str(), &salt, rounds, &mut output) {
                    return Err(Error::InvalidFormat);
                }

                let mut cipher = Aes256Ctr::new(
                    &GenericArray::from_slice(&output[..32]),
                    &GenericArray::from_slice(&output[32..]),
                );

                match cipher.try_apply_keystream(&mut remaining_bytes) {
                    Ok(_) => (),
                    Err(_) => return Err(Error::InvalidFormat),
                }
            },
            ("aes256-ctr", "bcrypt", None) => return Err(Error::EncryptedPrivateKey),
            _ => return Err(Error::EncryptedPrivateKeyNotSupported),
        };

        let mut reader = Reader::new(&remaining_bytes);

        // These four bytes are repeated and are used to checks that a key has
        // been decrypted successfully
        if reader.read_u32()? != reader.read_u32()? {
            return Err(Error::InvalidFormat);
        }
        
        let private_key = read_private_key(&mut reader)?;

        if private_key.pubkey != pubkey {
            return Err(Error::InvalidFormat);
        }

        Ok(private_key)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", &self.pubkey.fingerprint(), self.comment.as_ref().unwrap_or(&String::new()))
    }
}
