use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::prelude::Local;
use chrono::{Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};

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
    /// Invalid timestamp
    InvalidTimestamp,
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
            AllowedSignerParsingError::InvalidTimestamp => write!(f, "invalid timestamp"),
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
        use AllowedSignerParsingError::*;

        // This follows OpenSSH's parse_principals_key_and_options() and sshsigopt_parse() so that
        // a line means the same thing here as it does to ssh-keygen.
        let line = s.trim_start_matches(WHITESPACE);
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::InvalidAllowedSigner(MissingPrincipals));
        }

        // Format: identity[,identity...] [option[,option...]] key
        let (principals, rest) = strdelimw(line)
            .ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?;

        let principals: Vec<String> = principals.split(',')
            .map(|s| s.to_string())
            .collect();
        if principals.iter().any(|p| p.is_empty()) {
            return Err(Error::InvalidAllowedSigner(InvalidPrincipals));
        }

        // The options field is optional, so first try to read the key
        let (options, key) = match read_key(rest) {
            Some(key) => ("", key),
            None => {
                let end = advance_past_options(rest)
                    .ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?;
                let (options, key) = rest.split_at(end);
                if key.is_empty() {
                    return Err(Error::InvalidAllowedSigner(MissingKey));
                }
                let key = read_key(key[1..].trim_start_matches([' ', '\t']))
                    .ok_or(Error::InvalidAllowedSigner(InvalidKey))?;
                (options, key)
            },
        };

        let mut cert_authority = false;
        let mut namespaces = None;
        let mut valid_after = None;
        let mut valid_before = None;

        // Mirrors the option loop in sshsigopt_parse()
        let mut opts = options;
        while !opts.is_empty() {
            let option_start = opts;

            if opt_flag(&mut opts, "cert-authority") {
                cert_authority = true;
            } else if opt_match(&mut opts, "namespaces") {
                if namespaces.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("namespaces".to_string())));
                }
                namespaces = Some(
                    opt_dequote(&mut opts)?
                        .split(',')
                        .filter(|e| !e.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                );
            } else if opt_match(&mut opts, "valid-after") {
                if valid_after.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("valid-after".to_string())));
                }
                valid_after = Some(opt_timestamp(&mut opts, "valid-after")?);
            } else if opt_match(&mut opts, "valid-before") {
                if valid_before.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("valid-before".to_string())));
                }
                valid_before = Some(opt_timestamp(&mut opts, "valid-before")?);
            }

            if opts.is_empty() {
                break;
            }
            // Anything other than a comma means an unknown option. Like OpenSSH, skip an empty
            // option between two commas.
            if !opts.starts_with(',') {
                let name = option_start.split_once(['=', ',']).map_or(option_start, |(name, _)| name);
                return Err(Error::InvalidAllowedSigner(InvalidOption(name.to_string())));
            }
            opts = &opts[1..];
            // OpenSSH: "unexpected end-of-options"
            if opts.is_empty() {
                return Err(Error::InvalidAllowedSigner(InvalidOption(options.to_string())));
            }
        }

        // Timestamp sanity check
        if let (Some(valid_before), Some(valid_after)) = (&valid_before, &valid_after) {
            if valid_before <= valid_after {
                return Err(Error::InvalidAllowedSigner(InvalidTimestamps));
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

/// Port of OpenSSH's strdelimw() (misc.c). Split off the first token and skip the whitespace after it. The
/// token ends at whitespace or at the closing quote of a quoted section. Returns None if a quote is
/// left open.
fn strdelimw(s: &str) -> Option<(String, &str)> {
    let Some(index) = s.find(|c| WHITESPACE.contains(&c) || c == '"') else {
        return Some((s.to_string(), ""));
    };

    if s[index..].starts_with('"') {
        let (quoted, rest) = s[index + 1..].split_once('"')?;
        return Some((format!("{}{}", &s[..index], quoted), rest.trim_start_matches(WHITESPACE)));
    }

    Some((s[..index].to_string(), s[index + 1..].trim_start_matches(WHITESPACE)))
}

/// Read "keytype base64" the way OpenSSH's sshkey_read() does. Anything after it is a comment.
fn read_key(s: &str) -> Option<PublicKey> {
    let mut fields = s.split([' ', '\t']).filter(|f| !f.is_empty());
    let key = format!("{} {}", fields.next()?, fields.next()?);
    PublicKey::from_string(&key).ok()
}

/// Port of OpenSSH's sshkey_advance_past_options() (sshkey.c). Returns the length of the options
/// field, which ends at the first whitespace outside double quotes, or None if a quote is left open.
/// The index is always at ' ', '\t' or the end, so it's a char boundary.
fn advance_past_options(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut quoted = false;
    let mut index = 0;

    while index < bytes.len() && (quoted || (bytes[index] != b' ' && bytes[index] != b'\t')) {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'"') {
            index += 1;
        } else if bytes[index] == b'"' {
            quoted = !quoted;
        }
        index += 1;
    }

    // A quote left open runs to the end of the string
    (!quoted).then_some(index)
}

/// Port of OpenSSH's opt_flag() (auth-options.c), without the "no-" negation that
/// sshsigopt_parse() doesn't allow. Consume a case-insensitive flag option.
fn opt_flag(opts: &mut &str, flag: &str) -> bool {
    match opts.get(..flag.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(flag) => {
            *opts = &opts[flag.len()..];
            true
        },
        _ => false,
    }
}

/// Port of OpenSSH's opt_match() (auth-options.c). Consume a case-insensitive option name and the
/// '=' after it.
fn opt_match(opts: &mut &str, name: &str) -> bool {
    let mut rest = *opts;
    match opt_flag(&mut rest, name).then(|| rest.strip_prefix('=')).flatten() {
        Some(rest) => {
            *opts = rest;
            true
        },
        None => false,
    }
}

/// Port of OpenSSH's opt_dequote() (auth-options.c). Consume a double-quoted value, in which \" is a literal quote.
fn opt_dequote(opts: &mut &str) -> Result<String> {
    use AllowedSignerParsingError::*;

    let mut chars = opts.strip_prefix('"')
        .ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?
        .chars();

    let mut value = String::new();
    loop {
        match chars.next() {
            Some('"') => break,
            Some('\\') if chars.as_str().starts_with('"') => {
                chars.next();
                value.push('"');
            },
            Some(c) => value.push(c),
            None => return Err(Error::InvalidAllowedSigner(InvalidQuotes)),
        }
    }

    *opts = chars.as_str();
    Ok(value)
}

/// Consume a quoted valid-after or valid-before value. Like OpenSSH 10.2's parse_absolute_time(),
/// reject the epoch and anything before it.
fn opt_timestamp(opts: &mut &str, name: &str) -> Result<i64> {
    use AllowedSignerParsingError::*;

    match parse_timestamp(&opt_dequote(opts)?) {
        Ok(timestamp) if timestamp > 0 => Ok(timestamp),
        _ => Err(Error::InvalidAllowedSigner(InvalidOption(name.to_string()))),
    }
}

/// Parse a `YYYYMMDD[HHMM[SS]][Z|UTC]` timestamp (suffix case-insensitive) into a UNIX timestamp.
/// Like OpenSSH's parse_absolute_time(), a time with no suffix is local.
fn parse_timestamp(s: &str) -> Result<i64> {
    let s = s.to_ascii_lowercase();
    let (s, is_utc) = match s.strip_suffix('z').or_else(|| s.strip_suffix("utc")) {
        Some(s) => (s, true),
        None => (s.as_str(), false),
    };
    let datetime = match s.len() {
        8 => {
            let date = NaiveDate::parse_from_str(s, "%Y%m%d")
                .map_err(|_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamp))?;
            date.and_time(NaiveTime::from_hms_opt(0, 0, 0).expect("initializing NaiveTime from constants should not fail"))
        },
        12 => {
            NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M")
                .map_err(|_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamp))?
        },
        14 => {
            NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S")
                .map_err(|_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamp))?
        },
        _ => return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamp)),
    };

    let timestamp = if is_utc {
        datetime.and_utc()
            .timestamp()
    } else {
        // Match OpenSSH, which lets mktime resolve DST edge cases.
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

    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cases from OpenSSH's regress/unittests/misc/test_strdelim.c. strdelimw() doesn't split on
    // '=', so this leaves out the strdelim() cases that do.
    #[test]
    fn strdelimw_matches_openssh() {
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
            let actual = strdelimw(s);
            assert_eq!(actual.as_ref().map(|(token, rest)| (token.as_str(), *rest)), expected, "{:?}", s);
        }
    }
}
