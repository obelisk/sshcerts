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
    ///       implementation, we don't support spaces.
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
pub struct AllowedSigners(pub Vec<AllowedSigner>);

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
        let (mut head, mut rest) = s.split_once(char::is_whitespace)
            .ok_or(Error::InvalidAllowedSigner("missing key data".to_string()))?;
        rest = rest.trim_start();

        let principals: Vec<&str> = head.split(',').collect();
        if principals.iter().any(|p| p.is_empty()) {
            return Err(Error::InvalidAllowedSigner("principal cannot be empty".to_string()));
        }
        let principals = principals.iter().map(|s| s.to_string()).collect();

        let mut cert_authority = false;
        let mut namespaces = None;
        let mut valid_after = None;
        let mut valid_before = None;

        (head, rest) = rest.split_once(char::is_whitespace)
                .ok_or(Error::InvalidAllowedSigner("missing key data".to_string()))?;
        rest = rest.trim_start();
        loop {
            // Check if this is a valid option
            let (option_key, option_value) = match head.split_once('=') {
                Some(v) => v,
                None => (head, ""),
            };
            match option_key.to_lowercase().as_str() {
                "cert-authority" => cert_authority = true,
                "namespaces" => {
                    if namespaces.is_some() {
                        return Err(Error::InvalidAllowedSigner("multiple \"namespaces\" clauses".to_string()));
                    }
                    let option_value = dequote_option(option_value)
                        .map_err(|_| Error::InvalidAllowedSigner("invalid \"namespaces\" clause".to_string()))?;
                    let namespaces_inner: Vec<&str> = option_value.split(',')
                        .collect();
                    namespaces = Some(
                        namespaces_inner.iter()
                            .map(|s| s.to_string())
                            .collect()
                    );
                },
                "valid-after" => {
                    if valid_after.is_some() {
                        return Err(Error::InvalidAllowedSigner("multiple \"valid-after\" clauses".to_string()));
                    }
                    valid_after = Some(parse_timestamp(option_value)
                        .map_err(|_| Error::InvalidAllowedSigner("invalid \"valid-after\" time".to_string()))?);
                },
                "valid-before" => {
                    if valid_before.is_some() {
                        return Err(Error::InvalidAllowedSigner("multiple \"valid-before\" clauses".to_string()));
                    }
                    valid_before = Some(parse_timestamp(option_value)
                        .map_err(|_| Error::InvalidAllowedSigner("invalid \"valid-before\" time".to_string()))?);
                },
                // If option_key does not match any valid option, we test if it's the key data
                _ => break,
            };

            (head, rest) = rest.split_once(char::is_whitespace)
                .ok_or(Error::InvalidAllowedSigner("missing key data".to_string()))?;
            rest = rest.trim_start();
        }

        let kt = head;

        (head, rest) = match rest.split_once(char::is_whitespace) {
            Some(v) => v,
            None => (rest, ""),
        };
        let key_data = head;

        let key = PublicKey::from_string(format!("{} {}", kt, key_data).as_str())?;

        // Timestamp sanity check
        if let (Some(valid_before), Some(valid_after)) = (valid_before, valid_after) {
            if valid_before <= valid_after {
                return Err(Error::InvalidAllowedSigner("\"valid-before\" time is before \"valid-after\"".to_string()));
            }
        }

        // After key data, there must be only comment or nothing
        rest = rest.trim_start();
        if !rest.is_empty() && !rest.starts_with('#') {
            return Err(Error::InvalidAllowedSigner("unexpected data after key data".to_string()));
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

        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("#") {
                continue;
            }
            allowed_signers.push(AllowedSigner::from_string(line)?);
        }

        Ok(AllowedSigners(allowed_signers))
    }
}

/// Parse a string into a u64 representing a timestamp.
/// The timestamp can be enclosed by quotation marks.
fn parse_timestamp(s: &str) -> Result<u64> {
    let s = s.trim_matches('"');
    Ok(s.parse::<u64>().map_err(|_| Error::InvalidFormat)?)
}

/// Remove enclosing pair of double quotes if applicable.
/// If enclosing double quotes are malformed, return error.
/// If the content inside the quotes contains quotes, return error.
fn dequote_option(s: &str) -> Result<String> {
    let mut s = s.to_string();
    if s.starts_with('"') &&  s.ends_with('"') {
        s = s[1..s.len() - 1].to_string();
    } else if s.starts_with('"') || s.ends_with('"') {
        return Err(Error::InvalidFormat);
    }

    if s.contains('"') {
        return Err(Error::InvalidFormat);
    }

    Ok(s)
}
