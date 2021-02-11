use super::keytype::{Curve, KeyType, KeyTypeKind};
use super::error::{Error, ErrorKind};
#[cfg(feature = "rsa-signing")]
use num_bigint::{BigInt, BigUint, Sign};
use super::PublicKey;
use super::reader::Reader;
#[cfg(feature = "rsa-signing")]
use simple_asn1::{ASN1Block, ASN1Class, ToASN1};

use std::fs::File;
use std::io::{Read};
use std::path::Path;


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

    fn to_asn1_class(&self, _class: ASN1Class) -> Result<Vec<simple_asn1::ASN1Block>, Self::Error> {
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
            encoded_key.push_str(part);
        }

        let decoded = base64::decode(encoded_key)?;
        let mut reader = Reader::new(&decoded);
        // Construct a new `PrivateKey`
        let k = PrivateKey::from_reader(&mut reader)?;

        Ok(k)
    }

    /// This function is used for extracting a private key from an existing reader.
    pub(crate) fn from_reader(reader: &mut Reader) -> Result<PrivateKey, Error> {
        let preamble = reader.read_cstring()?;

        if preamble != "openssh-key-v1" {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        // These values are for encrypted keys which are not supported
        let cipher_name = reader.read_string()?;
        let kdf = reader.read_string()?;
        if cipher_name != "none" || kdf != "none" {
            return Err(Error::with_kind(ErrorKind::EncryptedPrivateKeyNotSupported));
        }

        // This appears to be en empty value
        reader.read_string()?;

        // This seems to be hardcoded into the standard
        let number_of_keys = reader.read_u32()?;
        if number_of_keys != 1 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        // A full pubkey with the same format as seen in certificates
        let pubkey = reader
        .read_bytes()
        .and_then(|v| PublicKey::from_bytes(&v))?;

        // This contains the length of the rest of the bytes in the key
        // We could use this to do a read bytes into a new reader but I don't
        // think there is an advantage to that right now (other than verifying)
        // that this value is correct.
        let _remaining_length = reader.read_u32()?;

        // These four bytes are repeated and I'm not sure what they do
        let c1 = reader.read_u32()?;
        let c2 = reader.read_u32()?;

        if c1 != c2 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        // The key type is repeated here.
        let key_type = reader.read_string()?;
        let kt = KeyType::from_name(&key_type)?;
        
        let kind = match kt.kind {
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

                let k = RsaPrivateKey {
                    n,
                    e,
                    d,
                    coefficient,
                    p,
                    q,
                    exp: exp,
                    exq: exq,
                };

                let pubkey = match &pubkey.kind {
                    crate::ssh::pubkey::PublicKeyKind::Rsa(pubkey) => pubkey,
                    _ => return Err(Error::with_kind(ErrorKind::InvalidFormat)),
                };

                if k.n != pubkey.n {
                    return Err(Error::with_kind(ErrorKind::InvalidFormat));
                }

                if k.e != pubkey.e {
                    return Err(Error::with_kind(ErrorKind::InvalidFormat));
                }

                PrivateKeyKind::Rsa(k)
            },
            KeyTypeKind::Ecdsa => {
                let identifier = reader.read_string()?;
                let curve = Curve::from_identifier(&identifier)?;
                // The pub key is also repeated here
                let _pubkey = reader.read_bytes()?;
                let key = reader.read_bytes()?;
                let k = EcdsaPrivateKey {
                    curve,
                    key,
                };

                PrivateKeyKind::Ecdsa(k)
            }
            KeyTypeKind::Ed25519 => {
                let _pubkey = reader.read_bytes()?;
                let k = Ed25519PrivateKey {
                    key: reader.read_bytes()?,
                };

                PrivateKeyKind::Ed25519(k)
            }
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

