use ring::{
    digest,
    signature::{
        RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
        ECDSA_P384_SHA384_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512,
    },
};

use crate::{error::Error, ssh::Writer, PrivateKey, PublicKey, Result};

use super::{KeyType, PublicKeyKind, Reader, SSHCertificateSigner};

/// The hash algorithm used to sign the data in the SshSignature
#[derive(Debug)]
pub enum HashAlgorithm {
    /// SHA256
    Sha256,
    /// SHA512
    Sha512,
}

impl HashAlgorithm {
    /// Returns the name of the hash algorithm
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }
}

/// An SSH signature object from signing arbitrary data. This object
/// has not been verified against a message so it is untrusted.
#[derive(Debug)]
pub struct SshSignature {
    /// The public key used to sign the data
    pub pubkey: PublicKey,
    /// The namespace of the signature
    pub namespace: String,
    /// The hash algorithm used to sign the data
    pub hash_algorithm: HashAlgorithm,
    /// The signature itself
    pub signature: Vec<u8>,
}

impl std::fmt::Display for SshSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writer = Writer::new();
        writer.write_raw_bytes(&[0x53, 0x53, 0x48, 0x53, 0x49, 0x47]);
        writer.write_u32(1);
        writer.write_pub_key(&self.pubkey);
        writer.write_string(&self.namespace);
        writer.write_bytes(&[]);
        writer.write_string(self.hash_algorithm.as_str());
        writer.write_bytes(&self.signature);

        let encoded = base64::encode(&writer.into_bytes());

        let lines: Vec<_> = encoded
            .chars()
            .collect::<Vec<char>>()
            .chunks(76)
            .map(|chunk| chunk.into_iter().collect::<String>())
            .collect();

        write!(
            f,
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
            lines.join("\n")
        )
    }
}

/// An SSH signature that has an attached message we've successfully
/// verified against the signature.
#[derive(Debug)]
pub struct VerifiedSshSignature {
    /// The contents of the signature
    pub signature: SshSignature,
    /// The message that was signed
    pub message: Vec<u8>,
}

impl std::fmt::Display for VerifiedSshSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.signature)
    }
}

/// Implement the SSHSIG specification as closely as possible:
/// https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.sshsig?rev=1.4&content-type=text/x-cvsweb-markup
impl SshSignature {
    /// Parses an armored SSH signature. This function does not take in
    /// data to verify and only parses the signature data, returning an
    /// error if it is malformed.
    pub fn from_armored_string(contents: &str) -> Result<Self> {
        let mut iter = contents.lines();
        let header = iter.next().unwrap_or("");
        if header != "-----BEGIN SSH SIGNATURE-----" {
            return Err(Error::InvalidFormat);
        }

        let mut encoded_signature = String::new();
        loop {
            let part = match iter.next() {
                Some(p) => p,
                None => return Err(Error::InvalidFormat),
            };

            if part == "-----END SSH SIGNATURE-----" {
                break;
            }
            encoded_signature.push_str(part);
        }

        let decoded = base64::decode(encoded_signature)?;
        let mut reader = Reader::new(&decoded);
        // Construct a new `SshSignature`
        let k = Self::from_reader(&mut reader)?;

        Ok(k)
    }

    pub(crate) fn from_reader(reader: &mut Reader<'_>) -> Result<Self> {
        let preamble = reader.read_raw_bytes(6)?;

        // SSHSIG magic. Unlike with some other types, this is not a cstring so we
        // need to read raw bytes.
        if preamble != [0x53, 0x53, 0x48, 0x53, 0x49, 0x47] {
            return Err(Error::InvalidFormat);
        }

        let version = reader.read_u32()?;

        // According to the specification:
        // Verifiers MUST reject signatures with versions greater than those they support.
        // We only support 1.
        if version != 1 {
            return Err(Error::Unsupported);
        }

        // Next in the specification is the public key
        let pubkey = reader
            .read_bytes()
            .and_then(|v| PublicKey::from_bytes(&v))?;

        // The SSHSIG namespace. You can read more about this in the specification but the
        // goal is to lock signatures to certain domains.
        let namespace = reader.read_string()?;

        if namespace.is_empty() {
            return Err(Error::InvalidFormat);
        }

        // Reserved space for future expansion. According to the specification, this should be
        // ignored even if it is not empty.
        let _reserved = reader.read_string()?;

        // The hash algorithm used to sign the data. This must be one of sha256 or sha512.
        let hash_algorithm = match reader.read_string()?.as_str() {
            "sha256" => HashAlgorithm::Sha256,
            "sha512" => HashAlgorithm::Sha512,
            _ => return Err(Error::Unsupported),
        };

        // Read in the sigature itself which is the final field.
        let signature = reader.read_bytes()?;

        Ok(Self {
            pubkey,
            namespace,
            hash_algorithm,
            signature,
        })
    }

    fn to_signed_format(&self, message: &[u8]) -> Vec<u8> {
        let mut signed_message = Writer::new();
        // Magic preamble
        signed_message.write_raw_bytes(&[0x53, 0x53, 0x48, 0x53, 0x49, 0x47]);
        // Namespace
        signed_message.write_string(&self.namespace);
        // Reserved space
        signed_message.write_bytes(&[]);
        // Hash algorithm
        signed_message.write_string(self.hash_algorithm.as_str());

        let algorithm = match self.hash_algorithm {
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha512 => &digest::SHA512,
        };

        signed_message.write_bytes(digest::digest(algorithm, message).as_ref());

        signed_message.into_bytes()
    }
}

impl VerifiedSshSignature {
    /// Converts an `SshSignature` into a `VerifiedSshSignature` by checking the signature
    /// against the provided message.
    pub fn from_ssh_signature(
        message: &[u8],
        ssh_signature: SshSignature,
        pub_key: Option<PublicKey>,
    ) -> Result<Self> {
        // If a public key is provided, then we will check the signature also contains that same
        // public key before verification. This is useful when you have a signature but additionally
        // need to check the signature is from it.
        if let Some(pub_key) = pub_key {
            if ssh_signature.pubkey != pub_key {
                return Err(Error::InvalidSignature);
            }
        }

        match verify_signature(
            &ssh_signature.signature,
            &ssh_signature.to_signed_format(message),
            &ssh_signature.pubkey,
        ) {
            Ok(_) => Ok(Self {
                signature: ssh_signature,
                message: message.to_vec(),
            }),
            Err(_) => Err(Error::InvalidSignature),
        }
    }

    /// Create a new `VerifiedSshSignature` from a message, namespace, public key, and hash algorithm.
    ///
    /// This can then be exported into the armored SSHSignature format which is compatible with tools
    /// like ssh-keygen.
    pub fn new_with_private_key(
        message: &[u8],
        namespace: &str,
        private_key: PrivateKey,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Self> {
        let hash_algorithm = hash_algorithm.unwrap_or(HashAlgorithm::Sha512);

        let mut ssh_signature = SshSignature {
            pubkey: private_key.pubkey.clone(),
            namespace: namespace.to_string(),
            hash_algorithm,
            signature: vec![],
        };

        let tbs_message = ssh_signature.to_signed_format(message);

        let signature = private_key.sign(&tbs_message).ok_or(Error::SigningError)?;

        ssh_signature.signature = signature;

        VerifiedSshSignature::from_ssh_signature(
            message,
            ssh_signature,
            Some(private_key.pubkey.clone()),
        )
    }
}

/// Verify an SSH key signature. This is used when validating both SSH Certificates
/// as well as detached SSHSIG signatures. This function is pub(crate) because it should
/// not be used directly, instead it should be integrated through different types provided
/// by the library.
pub(crate) fn verify_signature(
    // The signature buffer in SSH format
    signature_buf: &[u8],
    // The message that is signed. In an SSH Certificate this is the TBS data.
    // In an SSHSIG signature this is a complex type created by `from_ssh_siganature` in
    // the `VerifiedSshSignature` type.
    signed_bytes: &[u8],
    // The public key to verify the signature against.
    public_key: &PublicKey,
) -> Result<Vec<u8>> {
    let mut reader = Reader::new(&signature_buf);
    let sig_type = reader.read_string().and_then(|v| KeyType::from_name(&v))?;

    if public_key.key_type.kind != sig_type.kind {
        return Err(Error::KeyTypeMismatch);
    }

    match &public_key.kind {
        PublicKeyKind::Ecdsa(key) => {
            let sig_reader = reader.read_bytes()?;
            let mut sig_reader = Reader::new(&sig_reader);

            let (alg, len) = match sig_type.name {
                "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => {
                    (&ECDSA_P256_SHA256_FIXED, 32)
                }
                "ecdsa-sha2-nistp384" => (&ECDSA_P384_SHA384_FIXED, 48),
                _ => return Err(Error::KeyTypeMismatch),
            };

            // Read the R value
            let r_bytes = sig_reader.read_positive_mpint()?;
            // Read the S value
            let s_bytes = sig_reader.read_positive_mpint()?;

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

            if let Some(sk_application) = &key.sk_application {
                let flags = reader.read_raw_bytes(1)?[0];
                let signature_counter = reader.read_u32()?;

                let mut app_hash = digest::digest(&digest::SHA256, sk_application.as_bytes())
                    .as_ref()
                    .to_vec();
                let mut data_hash = digest::digest(&digest::SHA256, signed_bytes)
                    .as_ref()
                    .to_vec();

                app_hash.push(flags);
                app_hash.extend_from_slice(&signature_counter.to_be_bytes());
                app_hash.append(&mut data_hash);

                UnparsedPublicKey::new(alg, &key.key).verify(&app_hash, &sig)?;
            } else {
                UnparsedPublicKey::new(alg, &key.key).verify(signed_bytes, &sig)?;
            }

            Ok(signature_buf.to_vec())
        }
        PublicKeyKind::Rsa(key) => {
            let alg = match sig_type.name {
                "rsa-sha2-256" => &RSA_PKCS1_2048_8192_SHA256,
                "rsa-sha2-512" => &RSA_PKCS1_2048_8192_SHA512,
                "ssh-rsa" => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                _ => return Err(Error::KeyTypeMismatch),
            };
            let signature = reader.read_bytes()?;
            let public_key = RsaPublicKeyComponents {
                n: &key.n,
                e: &key.e,
            };
            public_key.verify(alg, signed_bytes, &signature)?;
            Ok(signature_buf.to_vec())
        }
        PublicKeyKind::Ed25519(key) => {
            match sig_type.name {
                "ssh-ed25519" => (),
                "sk-ssh-ed25519@openssh.com" => (),
                _ => return Err(Error::KeyTypeMismatch),
            };

            let alg = &ED25519;
            let signature = reader.read_bytes()?;
            let peer_public_key = UnparsedPublicKey::new(alg, &key.key);

            if let Some(sk_application) = &key.sk_application {
                let flags = reader.read_raw_bytes(1)?[0];
                let signature_counter = reader.read_u32()?;

                let mut app_hash = digest::digest(&digest::SHA256, sk_application.as_bytes())
                    .as_ref()
                    .to_vec();
                let mut data_hash = digest::digest(&digest::SHA256, signed_bytes)
                    .as_ref()
                    .to_vec();

                app_hash.push(flags);
                app_hash.extend_from_slice(&signature_counter.to_be_bytes());
                app_hash.append(&mut data_hash);

                peer_public_key.verify(&app_hash, &signature)?;
            } else {
                peer_public_key.verify(signed_bytes, &signature)?;
            }

            Ok(signature_buf.to_vec())
        }
    }
}
