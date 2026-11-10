use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::prelude::Local;
use chrono::{Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone};

use super::pubkey::PublicKey;
use crate::{error::Error, Result};

/// A type to represent the different kinds of errors.
#[derive(Debug)]
pub enum AllowedSignerParsingError {
    /// Parsing failed because of double quotes
    InvalidQuotes,
    /// Parsing failed because principals was missing
    MissingPrincipals,
    /// Principals is invalid
    InvalidPrincipals,
    /// Public key data is missing
    MissingKey,
    /// Some option was specified twice
    DuplicateOptions(String),
    /// An option has invalid format
    InvalidOption(String),
    /// Invalid key
    InvalidKey,
    /// valid-before and valid-after are conflicting
    InvalidTimestamps,
}

impl fmt::Display for AllowedSignerParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllowedSignerParsingError::InvalidQuotes => write!(f, "error parsing quotes"),
            AllowedSignerParsingError::MissingPrincipals => write!(f, "missing principals"),
            AllowedSignerParsingError::InvalidPrincipals => write!(f, "invalid principals"),
            AllowedSignerParsingError::MissingKey => write!(f, "missing public key data"),
            AllowedSignerParsingError::DuplicateOptions(ref v) => write!(f, "option {} specified more than once", v),
            AllowedSignerParsingError::InvalidOption(ref v) => write!(f, "invalid option {}", v),
            AllowedSignerParsingError::InvalidKey => write!(f, "invalid public key"),
            AllowedSignerParsingError::InvalidTimestamps => write!(f, "conflicting valid-before and valid-after options"),
        }
    }
}

/// A type which represents an allowed signer entry.
/// Please refer to [ssh-keygen-1.ALLOWED_SIGNERS] for more details about the format.
/// [ssh-keygen-1.ALLOWED_SIGNERS]: https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS
#[derive(Debug, PartialEq, Eq)]
pub struct AllowedSigner {
    /// A list of principals, each in the format USER@DOMAIN.
    pub principals: Vec<String>,

    /// Indicates that this key is accepted as a CA.
    pub cert_authority: bool,

    /// Specifies a list of namespaces that are accepted for this key.
    pub namespaces: Option<Vec<String>>,

    /// UNIX timestamp at or after which the key is valid.
    pub valid_after: Option<i64>,

    /// UNIX timestamp at or before which the key is valid.
    pub valid_before: Option<i64>,

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
        // This follows OpenSSH's parse_principals_key_and_options() and sshsigopt_parse() so that
        // a line means the same thing here as it does to ssh-keygen.
        let line = s.trim_start_matches(WHITESPACE);
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::MissingPrincipals));
        }

        // Format: identity[,identity...] [option[,option...]] key
        let (principals, rest) = split_field(line)
            .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))?;

        let principals: Vec<String> = principals.split(',').map(String::from).collect();
        if principals.iter().any(|p| p.is_empty()) {
            return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidPrincipals));
        }

        // The options field is optional, so first try to read the key
        let (options, key) = match parse_key(rest) {
            Some(key) => ("", key),
            None => {
                let (options, rest) = split_options(rest)
                    .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))?;
                if rest.is_empty() {
                    return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::MissingKey));
                }
                (options, parse_key(rest).ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidKey))?)
            },
        };

        let mut cert_authority = false;
        let mut namespaces = None;
        let mut valid_after = None;
        let mut valid_before = None;

        // Mirrors the option loop in sshsigopt_parse(). Option names are case-insensitive, and
        // cert-authority has no "no-" form.
        let mut rest = options;
        while !rest.is_empty() {
            let (name, after) = rest.split_at(rest.find(['=', ',']).unwrap_or(rest.len()));
            rest = after;
            // Options other than cert-authority take a value after '='
            let has_value = rest.starts_with('=');

            match name.to_ascii_lowercase().as_str() {
                // Like OpenSSH, skip an empty option between two commas
                "" => {},
                "cert-authority" => cert_authority = true,
                "namespaces" if has_value => {
                    if namespaces.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("namespaces".to_string()))
                        );
                    }
                    let (value, after) = split_quoted(&rest[1..])?;
                    namespaces = Some(value.split(',').filter(|n| !n.is_empty()).map(String::from).collect());
                    rest = after;
                },
                "valid-after" if has_value => {
                    if valid_after.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("valid-after".to_string()))
                        );
                    }
                    let (value, after) = split_quoted(&rest[1..])?;
                    valid_after = Some(parse_timestamp(&value)
                        .ok_or_else(
                            || Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption("valid-after".to_string())))?
                        );
                    rest = after;
                },
                "valid-before" if has_value => {
                    if valid_before.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("valid-before".to_string()))
                        );
                    }
                    let (value, after) = split_quoted(&rest[1..])?;
                    valid_before = Some(parse_timestamp(&value)
                        .ok_or_else(
                            || Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption("valid-before".to_string())))?
                        );
                    rest = after;
                },
                _ => {
                    return Err(
                        Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(name.to_string()))
                    );
                },
            }

            // Anything other than a comma means an unknown option, and a trailing comma isn't allowed
            rest = match rest.strip_prefix(',') {
                Some(after) if !after.is_empty() => after,
                None if rest.is_empty() => break,
                _ => {
                    return Err(
                        Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(name.to_string()))
                    );
                },
            };
        }

        // Timestamp sanity check
        if let (Some(valid_before), Some(valid_after)) = (&valid_before, &valid_after) {
            if valid_before <= valid_after {
                return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamps));
            }
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

        if let Some(ref valid_after) = self.valid_after {
            output.push_str(&format!(" valid-after={}", valid_after));
        }

        if let Some(ref valid_before) = self.valid_before {
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

        for (line_number, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("#") {
                continue;
            }
            let allowed_signer = match AllowedSigner::from_string(line) {
                Ok(v) => v,
                Err(Error::InvalidAllowedSigner(e)) => {
                    return Err(Error::InvalidAllowedSigners(e, line_number));
                },
                Err(_) => {
                    return Err(Error::ParsingError);
                },
            };
            allowed_signers.push(allowed_signer);
        }

        Ok(AllowedSigners(allowed_signers))
    }
}

/// OpenSSH's WHITESPACE (misc.h)
const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];

/// Split off the first field of a line and skip the whitespace after it. A field ends at
/// whitespace, or at the closing quote of a quoted section. Returns None if a quote is left open.
/// Port of OpenSSH's strdelimw() (misc.c).
fn split_field(s: &str) -> Option<(String, &str)> {
    let (field, rest) = match s.find(|c| WHITESPACE.contains(&c) || c == '"') {
        None => (s.to_string(), ""),
        Some(i) if s[i..].starts_with('"') => {
            let (quoted, rest) = s[i + 1..].split_once('"')?;
            (format!("{}{}", &s[..i], quoted), rest)
        },
        Some(i) => (s[..i].to_string(), &s[i + 1..]),
    };
    Some((field, rest.trim_start_matches(WHITESPACE)))
}

/// Read "keytype base64" the way OpenSSH's sshkey_read() does. Anything after it is a comment.
fn parse_key(s: &str) -> Option<PublicKey> {
    let mut fields = s.split([' ', '\t']).filter(|f| !f.is_empty());
    PublicKey::from_string(&format!("{} {}", fields.next()?, fields.next()?)).ok()
}

/// Split the options field off the front of `s`. It ends at the first space or tab outside double
/// quotes, and `\"` never opens or closes a quote. Returns None if a quote is left open.
/// Port of OpenSSH's sshkey_advance_past_options() (authfile.c).
fn split_options(s: &str) -> Option<(&str, &str)> {
    let mut quoted = false;
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            ' ' | '\t' if !quoted => return Some(s.split_at(i)),
            '\\' if chars.as_str().starts_with('"') => {
                chars.next();
            },
            '"' => quoted = !quoted,
            _ => {},
        }
    }
    if quoted {
        None
    } else {
        Some((s, ""))
    }
}

/// Split a double-quoted value off the front of `s`. Inside it, `\"` is a literal quote.
/// Port of OpenSSH's opt_dequote() (misc.c).
fn split_quoted(s: &str) -> Result<(String, &str)> {
    let mut chars = s.strip_prefix('"')
        .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))?
        .chars();
    let mut value = String::new();
    loop {
        match chars.next().ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))? {
            '"' => return Ok((value, chars.as_str())),
            '\\' if chars.as_str().starts_with('"') => {
                chars.next();
                value.push('"');
            },
            c => value.push(c),
        }
    }
}

/// Parse a `YYYYMMDD[HHMM[SS]][Z|UTC]` timestamp (suffix case-insensitive) into a UNIX timestamp.
/// Like OpenSSH 10.2's parse_absolute_time(), a time with no suffix is local, and the epoch and
/// anything before it are rejected.
fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.to_ascii_lowercase();
    let (s, is_utc) = match s.strip_suffix('z').or_else(|| s.strip_suffix("utc")) {
        Some(s) => (s, true),
        None => (s.as_str(), false),
    };
    let datetime = match s.len() {
        8 => NaiveDate::parse_from_str(s, "%Y%m%d").ok()?.and_hms_opt(0, 0, 0)?,
        12 => NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M").ok()?,
        14 => NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S").ok()?,
        _ => return None,
    };

    let timestamp = if is_utc {
        datetime.and_utc()
            .timestamp()
    } else {
        // OpenSSH leaves DST changes to mktime(), which doesn't always agree with this
        match datetime.and_local_timezone(Local) {
            LocalResult::Single(dt) => dt.timestamp(),
            LocalResult::Ambiguous(a, b) => a.timestamp().min(b.timestamp()),
            // The time falls in a DST gap. Like mktime, use the offset from before the gap.
            LocalResult::None => {
                let before = Local.offset_from_utc_datetime(&(datetime - Duration::days(1)));
                datetime.and_utc().timestamp() - i64::from(before.local_minus_utc())
            },
        }
    };

    if timestamp > 0 {
        Some(timestamp)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cases from OpenSSH's regress/unittests/misc/test_strdelim.c. strdelimw() doesn't split on
    // '=', so this leaves out the strdelim() cases that do.
    #[test]
    fn split_field_matches_openssh() {
        for (s, expected) in [
            ("", Some(("", ""))),
            ("\t", Some(("", ""))),
            ("blob", Some(("blob", ""))),
            ("blob   ", Some(("blob", ""))),
            ("blob1 blob2", Some(("blob1", "blob2"))),
            ("blob1\t \tblob2  \t \t", Some(("blob1", "blob2  \t \t"))),
            ("blob1=blob2", Some(("blob1=blob2", ""))),
            ("\"blob\"", Some(("blob", ""))),
            ("\"blob1\" blob2", Some(("blob1", "blob2"))),
            ("blob1 \"blob2\"", Some(("blob1", "\"blob2\""))),
            ("\"blob", None),
            ("\"blob\\\"", Some(("blob\\", ""))),
        ] {
            let actual = split_field(s);
            assert_eq!(actual.as_ref().map(|(token, rest)| (token.as_str(), *rest)), expected, "{:?}", s);
        }
    }
}
