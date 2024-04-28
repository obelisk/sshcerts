use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::pubkey::PublicKey;
use crate::{error::Error, Result};

/// A type which represents an allowed signer entry.
/// Please refer to [ssh-keygen-1.ALLOWED_SIGNERS] for more details about the format.
/// [ssh-keygen-1.ALLOWED_SIGNERS]: https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS
#[derive(Debug, PartialEq, Eq)]
pub struct AllowedSigner {
    /// A list of principals, each in the format USER@DOMAIN.
    pub principals: Vec<String>,

    /// Indicates that this key is accepted as a CA.
    /// This is a standard option.
    pub cert_authority: bool,

    /// Specifies a list of namespaces that are accepted for this key.
    /// This is a standard option.
    ///
    /// Note: The specification allows spaces inside double quotes. However, in this
    /// implementation, spaces would cause the parser to reject the input.
    pub namespaces: Option<Vec<String>>,

    /// Time at or after which the key is valid.
    /// This is a standard option.
    pub valid_after: Option<u64>,

    /// Time at or before which the key is valid.
    /// This is a standard option.
    pub valid_before: Option<u64>,

    /// Public key of the entry.
    pub key: PublicKey,
}

/// A type which represents a collection of allowed signer entries.
/// Please refer to [ssh-keygen-1.ALLOWED_SIGNERS] for more details about the format.
/// [ssh-keygen-1.ALLOWED_SIGNERS]: https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS
#[derive(Debug, PartialEq, Eq)]
pub struct AllowedSigners {
    /// A collection of allowed signers
    pub allowed_signers: Vec<AllowedSigner>,
}

impl AllowedSigner {
    /// Parse an allowed signer entry from a given string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sshcerts::ssh::AllowedSigner;
    ///
    /// let allowed_signer = AllowedSigner::from_string(concat!(
    ///     "user@domain.tld ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGJe",
    ///     "+IDGRhlQdDp+/AIsTXGaVhWaQUbHJwqLDlQIh7V4xatO6E/4Uva+f70WzxgM7xHPGUqafqNAcxxVBP4jkx3HVDRSr7C3",
    ///     "NVBpr0ZaKXu/hFiCo/4kry4H5MGMEvKATA=="
    /// )).unwrap();
    /// println!("{:?}", allowed_signer);
    /// ```
    pub fn from_string(s: &str) -> Result<AllowedSigner> {
        let mut parts: VecDeque<&str> = s.split_whitespace().collect();

        // An allowed signer must contian at least 3 parts: principals, key type and pubkey data
        if parts.len() < 3 {
            return Err(Error::InvalidFormat);
        }

        let principals = parts.pop_front().ok_or(Error::InvalidFormat)?;
        let principals: Vec<&str> = principals.split(',').collect();
        let principals = principals.iter().map(|s| s.to_string()).collect();

        let key_data = parts.pop_back().ok_or(Error::InvalidFormat)?;
        let kt = parts.pop_back().ok_or(Error::InvalidFormat)?;
        let key = PublicKey::from_string(format!("{} {}", kt, key_data).as_str())?;

        let mut cert_authority = false;
        let mut namespaces = None;
        let mut valid_after = None;
        let mut valid_before = None;

        for option in parts {
            let option = option.to_lowercase();
            let (key, value) = match option.split_once('=') {
                Some(v) => v,
                None => (option.as_str(), ""),
            };
            match key {
                "cert-authority" => cert_authority = true,
                "namespaces" => {
                    if namespaces.is_some() {
                        return Err(Error::InvalidFormat);
                    }
                    let namespaces_inner: Vec<&str> = value.trim_matches('"')
                            .split(',')
                            .collect();
                    namespaces = Some(
                        namespaces_inner.iter()
                            .map(|s| s.to_string())
                            .collect()
                    );
                },
                "valid-after" => {
                    if valid_after.is_some() {
                        return Err(Error::InvalidFormat);
                    }
                    valid_after = Some(parse_timestamp(value)?);
                },
                "valid-before" => {
                    if valid_before.is_some() {
                        return Err(Error::InvalidFormat);
                    }
                    valid_before = Some(parse_timestamp(value)?);
                },
                _ => return Err(Error::InvalidFormat),
            };
        }

        Ok(AllowedSigner{
            principals,
            cert_authority,
            namespaces,
            valid_after,
            valid_before,
            key,
        })
    }
}

impl fmt::Display for AllowedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();

        output.push_str(&self.principals.join(","));
        
        if self.cert_authority {
            output.push_str(" cert-authority");
        }

        if let Some(ref namespaces) = self.namespaces {
            output.push_str(&format!(" namespaces={}", namespaces.join(",")));
        }

        if let Some(valid_after) = self.valid_after {
            output.push_str(&format!(" valid-after={}", valid_after));
        }

        if let Some(valid_before) = self.valid_before {
            output.push_str(&format!(" valid-before={}", valid_before));
        }

        output.push_str(&format!(" {}", self.key));

        write!(f, "{}", output)
    }
}

impl AllowedSigners {
    /// Reads AllowedSigners from a given path.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sshcerts::ssh::AllowedSigners;
    /// fn example() {
    ///     let allowed_signers = AllowedSigners::from_path("/path/to/allowed_signers").unwrap();
    ///     println!("{:?}", allowed_signers);
    /// }
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<AllowedSigners> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        AllowedSigners::from_string(&contents)
    }

    /// Parse a collection of allowed signers from a given string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sshcerts::ssh::AllowedSigners;
    ///
    /// let allowed_signers = AllowedSigners::from_string(concat!(
    ///     "user@domain.tld ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGJe",
    ///     "+IDGRhlQdDp+/AIsTXGaVhWaQUbHJwqLDlQIh7V4xatO6E/4Uva+f70WzxgM7xHPGUqafqNAcxxVBP4jkx3HVDRSr7C3",
    ///     "NVBpr0ZaKXu/hFiCo/4kry4H5MGMEvKATA==\n",
    ///     "user@domain.tld ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGJe",
    ///     "+IDGRhlQdDp+/AIsTXGaVhWaQUbHJwqLDlQIh7V4xatO6E/4Uva+f70WzxgM7xHPGUqafqNAcxxVBP4jkx3HVDRSr7C3",
    ///     "NVBpr0ZaKXu/hFiCo/4kry4H5MGMEvKATA==\n"
    /// )).unwrap();
    /// println!("{:?}", allowed_signers);
    /// ```
    pub fn from_string(s: &str) -> Result<AllowedSigners> {
        let mut allowed_signers = Vec::new();

        for line in s.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with("#") {
                continue;
            }
            let allowed_signer = AllowedSigner::from_string(line)?;
            allowed_signers.push(allowed_signer);
        }

        Ok(AllowedSigners{allowed_signers})
    }
}

/// Parse a string into a u64 representing a timestamp.
/// The timestamp can be enclosed by quotation marks.
fn parse_timestamp(s: &str) -> Result<u64> {
    let s = s.trim_matches('"');
    Ok(s.parse::<u64>().map_err(|_| Error::InvalidFormat)?)
}
