use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use ring::signature::Ed25519KeyPair;
use ring::{rand, signature, signature::KeyPair};

use zeroize::Zeroize;

use crate::{
    error::Error,
    ssh::{
        keytype::{Curve, KeyType, KeyTypeKind},
        reader::Reader,
        writer::Writer,
        CurveKind, EcdsaPublicKey, Ed25519PublicKey, PublicKey, PublicKeyKind, RsaPublicKey,
    },
    utils::format_signature_for_ssh,
    Result,
};

#[cfg(feature = "rsa-signing")]
use num_bigint::{BigInt, BigUint, Sign};

#[cfg(feature = "rsa-signing")]
use simple_asn1::{ASN1Block, ASN1Class, ToASN1};

#[cfg(feature = "encrypted-keys")]
use aes::{
    cipher::{generic_array::GenericArray, NewCipher, StreamCipher},
    Aes256Ctr,
};

#[cfg(feature = "encrypted-keys")]
use bcrypt_pbkdf::bcrypt_pbkdf;

/// RSA private key.
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
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
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub struct EcdsaPrivateKey {
    /// The curve being used.
    pub curve: Curve,

    /// The private key.
    pub key: Vec<u8>,
}

/// Hardware backed ECDSA private key.
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub struct EcdsaSkPrivateKey {
    /// Flags set on the private key
    pub flags: u8,

    /// The private key handle
    pub handle: Vec<u8>,

    /// Space reserved for future use
    pub reserved: Vec<u8>,

    /// Pin to use with external device when doing signing
    /// operations
    pub pin: Option<String>,

    /// Path to hardware device to use for signing. If not
    /// provided, the system will choose one (either randomly
    /// or by user selection)
    pub device_path: Option<String>,
}

/// ED25519 private key.
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub struct Ed25519PrivateKey {
    /// The private key.
    pub key: Vec<u8>,
}

/// Hardware backed Ed25519 private key.
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub struct Ed25519SkPrivateKey {
    /// Flags set on the private key
    pub flags: u8,

    /// The private key handle
    pub handle: Vec<u8>,

    /// Space reserved for future use
    pub reserved: Vec<u8>,

    /// Pin to use with external device when doing signing
    /// operations
    pub pin: Option<String>,

    /// Path to hardware device to use for signing. If not
    /// provided, the system will choose one (either randomly
    /// or by user selection)
    pub device_path: Option<String>,
}

/// A type which represents the different kinds a public key can be.
#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub enum PrivateKeyKind {
    /// Represents an RSA prviate key.
    Rsa(RsaPrivateKey),

    /// Represents an ECDSA private key.
    Ecdsa(EcdsaPrivateKey),

    /// Represents an ECDSA private key stored in a hardware device
    EcdsaSk(EcdsaSkPrivateKey),

    /// Represents an Ed25519 private key.
    Ed25519(Ed25519PrivateKey),

    /// Represents an Ed25519 private key stored in a hardware device
    Ed25519Sk(Ed25519SkPrivateKey),
}

/// A type which represents an OpenSSH private key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivateKey {
    /// Key type.
    pub key_type: KeyType,

    /// The kind of public key.
    pub kind: PrivateKeyKind,

    /// The corresponding public key
    pub pubkey: PublicKey,

    /// This is the magic value used to ensure decoding happens correctly.
    /// We store it so that we can guarantee reserialization of unencrypted
    /// keys is bytes for byte.
    pub magic: u32,

    /// Associated comment. It appears, unlike public keys, private keys must
    /// have comments to be valid.
    pub comment: String,
}

#[cfg(feature = "rsa-signing")]
impl ToASN1 for RsaPrivateKey {
    type Error = Error;

    fn to_asn1_class(&self, _class: ASN1Class) -> std::result::Result<Vec<ASN1Block>, Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                vec![ASN1Block::Integer(0, BigInt::new(Sign::Plus, vec![0]))],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.n),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.e),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.d),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.p),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.q),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, self.exp.as_ref().unwrap()),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, self.exq.as_ref().unwrap()),
                )],
                vec![ASN1Block::Integer(
                    0,
                    BigInt::from_bytes_be(Sign::Plus, &self.coefficient),
                )],
                Vec::new(),
            ]
            .concat(),
        )])
    }
}

impl super::SSHCertificateSigner for PrivateKey {
    fn sign(&self, buffer: &[u8]) -> Option<Vec<u8>> {
        let rng = rand::SystemRandom::new();

        match &self.kind {
            #[cfg(feature = "rsa-signing")]
            PrivateKeyKind::Rsa(key) => {
                let asn_privkey = match simple_asn1::der_encode(key) {
                    Ok(apk) => apk,
                    Err(_) => return None,
                };

                let keypair = match signature::RsaKeyPair::from_der(&asn_privkey) {
                    Ok(kp) => kp,
                    Err(_) => return None,
                };

                let mut signature = vec![0; keypair.public().modulus_len()];

                keypair
                    .sign(&signature::RSA_PKCS1_SHA512, &rng, buffer, &mut signature)
                    .ok()?;

                format_signature_for_ssh(&self.pubkey, &signature)
            }
            #[cfg(not(feature = "rsa-signing"))]
            PrivateKeyKind::Rsa(_) => return None,
            PrivateKeyKind::Ecdsa(key) => {
                let alg = match key.curve.kind {
                    CurveKind::Nistp256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    CurveKind::Nistp384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    CurveKind::Nistp521 => return None,
                };

                let pubkey = match &self.pubkey.kind {
                    PublicKeyKind::Ecdsa(key) => &key.key,
                    _ => return None,
                };

                let key = if key.key[0] == 0x0_u8 {
                    &key.key[1..]
                } else {
                    &key.key
                };
                let key_pair = match signature::EcdsaKeyPair::from_private_key_and_public_key(
                    alg, key, pubkey, &rng,
                ) {
                    Ok(kp) => kp,
                    Err(_) => return None,
                };

                format_signature_for_ssh(&self.pubkey, key_pair.sign(&rng, buffer).ok()?.as_ref())
            }
            PrivateKeyKind::Ed25519(key) => {
                let public_key = match &self.pubkey.kind {
                    PublicKeyKind::Ed25519(key) => &key.key,
                    _ => return None,
                };

                let key_pair =
                    match Ed25519KeyPair::from_seed_and_public_key(&key.key[..32], public_key) {
                        Ok(kp) => kp,
                        Err(_) => return None,
                    };

                format_signature_for_ssh(&self.pubkey, key_pair.sign(buffer).as_ref())
            }
            #[cfg(any(feature = "fido-support", feature = "fido-support-mozilla"))]
            PrivateKeyKind::Ed25519Sk(_) | PrivateKeyKind::EcdsaSk(_) => {
                crate::fido::signing::sign_with_private_key(&self, buffer)
            }
            #[cfg(not(any(feature = "fido-support", feature = "fido-support-mozilla")))]
            PrivateKeyKind::Ed25519Sk(_) | PrivateKeyKind::EcdsaSk(_) => None,
        }
    }
}
impl PrivateKey {
    fn read_private_key(reader: &mut Reader<'_>) -> Result<Self> {
        let key_type = reader.read_string()?;
        let kt = KeyType::from_name(&key_type)?;

        let (kind, pubkey) = match kt.kind {
            KeyTypeKind::Rsa => {
                let n = reader.read_positive_mpint()?;
                let e = reader.read_positive_mpint()?;
                let d = reader.read_positive_mpint()?;
                let coefficient = reader.read_positive_mpint()?;
                let p = reader.read_positive_mpint()?;
                let q = reader.read_positive_mpint()?;

                #[cfg(feature = "rsa-signing")]
                let exp = Some(
                    BigUint::from_bytes_be(&d)
                        .modpow(
                            &BigUint::from_slice(&[0x1]),
                            &(BigUint::from_bytes_be(&p) - 1_u8),
                        )
                        .to_bytes_be(),
                );
                #[cfg(not(feature = "rsa-signing"))]
                let exp = None;

                #[cfg(feature = "rsa-signing")]
                let exq = Some(
                    BigUint::from_bytes_be(&d)
                        .modpow(
                            &BigUint::from_slice(&[0x1]),
                            &(BigUint::from_bytes_be(&q) - 1_u8),
                        )
                        .to_bytes_be(),
                );
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
                        exp,
                        exq,
                    }),
                    PublicKey {
                        key_type: kt.clone(),
                        kind: PublicKeyKind::Rsa(RsaPublicKey { e, n }),
                        comment: None,
                    },
                )
            }
            KeyTypeKind::Ecdsa => {
                let identifier = reader.read_string()?;
                let curve = Curve::from_identifier(&identifier)?;
                let pubkey = reader.read_bytes()?;

                let (private_key, sk_application) = match kt.is_sk {
                    true => {
                        let sk_application = Some(reader.read_string()?);
                        let k = EcdsaSkPrivateKey {
                            flags: reader.read_raw_bytes(1)?[0],
                            handle: reader.read_bytes()?,
                            reserved: reader.read_bytes()?,
                            pin: None,
                            device_path: None,
                        };

                        (PrivateKeyKind::EcdsaSk(k), sk_application)
                    }
                    false => {
                        let key = reader.read_bytes()?;
                        let k = EcdsaPrivateKey {
                            curve: curve.clone(),
                            key,
                        };
                        (PrivateKeyKind::Ecdsa(k), None)
                    }
                };
                (
                    private_key,
                    PublicKey {
                        key_type: kt.clone(),
                        kind: PublicKeyKind::Ecdsa(EcdsaPublicKey {
                            curve,
                            key: pubkey,
                            sk_application,
                        }),
                        comment: None,
                    },
                )
            }
            KeyTypeKind::Ed25519 => {
                let pubkey = reader.read_bytes()?;

                let (private_key, sk_application) = match kt.is_sk {
                    true => {
                        let sk_application = Some(reader.read_string()?);
                        let k = Ed25519SkPrivateKey {
                            flags: reader.read_raw_bytes(1)?[0],
                            handle: reader.read_bytes()?,
                            reserved: reader.read_bytes()?,
                            pin: None,
                            device_path: None,
                        };

                        (PrivateKeyKind::Ed25519Sk(k), sk_application)
                    }
                    false => {
                        let k = Ed25519PrivateKey {
                            key: reader.read_bytes()?,
                        };

                        (PrivateKeyKind::Ed25519(k), None)
                    }
                };
                (
                    private_key,
                    PublicKey {
                        key_type: kt.clone(),
                        kind: PublicKeyKind::Ed25519(Ed25519PublicKey {
                            key: pubkey,
                            sk_application,
                        }),
                        comment: None,
                    },
                )
            }
            _ => return Err(Error::UnknownKeyType(kt.name.to_string())),
        };

        let comment = reader.read_string()?;

        Ok(Self {
            key_type: kt,
            kind,
            pubkey,
            magic: 0x0,
            comment,
        })
    }

    /// Generate a new SSH private key. Currently this only supports Ed25519.
    pub fn new(kind: KeyTypeKind, comment: &str) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        match kind {
            KeyTypeKind::Ed25519 => {
                let key_type = KeyType::from_name("ssh-ed25519").unwrap();
                // Ring does not expose access to the private key without
                // PKCS#8 wrapping. So we either need to do this, or write/pull
                // in code to parse it.
                let seed: [u8; 32] = rand::generate(&rng).unwrap().expose();
                let magic: [u8; 4] = rand::generate(&rng).unwrap().expose();
                let public_key_bytes = Ed25519KeyPair::from_seed_unchecked(&seed)
                    .unwrap()
                    .public_key()
                    .as_ref()
                    .to_vec();
                let key = Ed25519PrivateKey { key: seed.to_vec() };

                let pubkey = PublicKey {
                    key_type: key_type.clone(),
                    kind: PublicKeyKind::Ed25519(Ed25519PublicKey {
                        key: public_key_bytes,
                        sk_application: None,
                    }),
                    comment: None,
                };

                Ok(Self {
                    key_type,
                    kind: PrivateKeyKind::Ed25519(key),
                    pubkey,
                    magic: u32::from_be_bytes(magic),
                    comment: comment.to_owned(),
                })
            }
            KeyTypeKind::Ecdsa => Err(Error::Unsupported),
            KeyTypeKind::Rsa => Err(Error::Unsupported),
            _ => Err(Error::KeyTypeMismatch),
        }
    }

    /// Reads an OpenSSH private key from a given path and passphrase
    pub fn from_path_with_passphrase<P: AsRef<Path>>(
        path: P,
        passphrase: Option<String>,
    ) -> Result<Self> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        PrivateKey::from_string_with_passphrase(&contents, passphrase)
    }

    /// Reads an OpenSSH private key from a given path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        PrivateKey::from_path_with_passphrase(path, None)
    }

    /// Reads an OpenSSH private key from a given string and passphrase
    pub fn from_string_with_passphrase(contents: &str, passphrase: Option<String>) -> Result<Self> {
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
        PrivateKey::read_private_key(&mut reader)
    }

    /// This function is used for extracting a private key from an existing reader.
    pub(crate) fn from_reader(
        reader: &mut Reader<'_>,
        passphrase: Option<String>,
    ) -> Result<PrivateKey> {
        let preamble = reader.read_cstring()?;

        if preamble != "openssh-key-v1" {
            return Err(Error::InvalidFormat);
        }

        // These values are for encrypted keys
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
                if bcrypt_pbkdf(passphrase.as_str(), &salt, rounds, &mut output).is_err() {
                    return Err(Error::InvalidFormat);
                }

                let mut cipher = Aes256Ctr::new(
                    GenericArray::from_slice(&output[..32]),
                    GenericArray::from_slice(&output[32..]),
                );

                match cipher.try_apply_keystream(&mut remaining_bytes) {
                    Ok(_) => (),
                    Err(_) => return Err(Error::InvalidFormat),
                }
            }
            ("aes256-ctr", "bcrypt", None) => return Err(Error::EncryptedPrivateKey),
            _ => return Err(Error::EncryptedPrivateKeyNotSupported),
        };

        let mut reader = Reader::new(&remaining_bytes);

        // These four bytes are repeated and are used to check that a key has
        // been decrypted successfully
        let m1 = reader.read_u32()?;
        let m2 = reader.read_u32()?;

        if m1 != m2 {
            return Err(Error::InvalidFormat);
        }

        let mut private_key = PrivateKey::read_private_key(&mut reader)?;
        private_key.magic = m1;

        if private_key.pubkey != pubkey {
            return Err(Error::InvalidFormat);
        }

        Ok(private_key)
    }

    /// If using an SK key, this allows you set the pin to use when communicating with the
    /// external device
    pub fn set_pin(&mut self, pin: &str) {
        match &mut self.kind {
            PrivateKeyKind::EcdsaSk(key) => {
                key.pin = Some(pin.to_string());
            }
            PrivateKeyKind::Ed25519Sk(key) => {
                key.pin = Some(pin.to_string());
            }
            _ => (),
        };
    }

    /// If using an SK key, this allows you specify a hardware device path to use for the
    /// signing operation
    pub fn set_device_path(&mut self, path: &str) {
        match &mut self.kind {
            PrivateKeyKind::EcdsaSk(key) => {
                key.device_path = Some(path.to_string());
            }
            PrivateKeyKind::Ed25519Sk(key) => {
                key.device_path = Some(path.to_string());
            }
            _ => (),
        };
    }

    /// Encode the PrivateKey into a bytes representation
    pub fn encode(&self) -> Vec<u8> {
        let mut serializer = Writer::new();
        serializer.write_cstring("openssh-key-v1"); // Preamble
        serializer.write_string("none"); // cipher_namer
        serializer.write_string("none"); // kdf
        serializer.write_bytes(&[]); // encryption_data
        serializer.write_u32(1); // number_of_keys
        serializer.write_pub_key(&self.pubkey); // public key

        let mut w = Writer::new();
        w.write_u32(self.magic); // magic
        w.write_u32(self.magic); // repeated magic

        w.write_string(self.pubkey.key_type.name);
        match &self.kind {
            PrivateKeyKind::Rsa(rsa) => {
                w.write_mpint(&rsa.n); // These are in fact in a diff-
                w.write_mpint(&rsa.e); // erent order than a public key
                w.write_mpint(&rsa.d);
                w.write_mpint(&rsa.coefficient);
                w.write_mpint(&rsa.p);
                w.write_mpint(&rsa.q);
            }
            PrivateKeyKind::Ecdsa(ecdsa) => {
                w.write_pub_key_data(&self.pubkey);
                w.write_bytes(&ecdsa.key);
            }
            PrivateKeyKind::EcdsaSk(ecdsask) => {
                w.write_pub_key_data(&self.pubkey);
                w.write_raw_bytes(&[ecdsask.flags]);
                w.write_bytes(&ecdsask.handle);
                w.write_bytes(&[]);
            }
            PrivateKeyKind::Ed25519(ed25519) => {
                w.write_pub_key_data(&self.pubkey);
                w.write_bytes(&ed25519.key);
            }
            PrivateKeyKind::Ed25519Sk(ed25519sk) => {
                w.write_pub_key_data(&self.pubkey);
                w.write_raw_bytes(&[ed25519sk.flags]);
                w.write_bytes(&ed25519sk.handle);
                w.write_bytes(&[]);
            }
        };

        w.write_string(&self.comment);

        // Padding to make the length of the private key part of the file
        // congruent to 8
        let pad_bytes = (8 - (w.as_bytes().len() % 8)) % 8;
        let padding = vec![0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7];
        w.write_raw_bytes(&padding[..pad_bytes]);

        serializer.write_bytes(w.as_bytes());
        serializer.into_bytes()
    }

    /// Writes the private key to a given writer.
    pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        let encoded = self.encode();
        let data = base64::encode(&encoded);
        let split = data
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i != 0 && i % 70 == 0 {
                    Some('\n')
                } else {
                    None
                }
                .into_iter()
                .chain(std::iter::once(c))
            })
            .collect::<String>();
        write!(
            w,
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            split
        )
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", &self.pubkey.fingerprint(), self.comment)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.kind.zeroize();
    }
}
