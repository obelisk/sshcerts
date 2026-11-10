use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::prelude::Local;
use chrono::{DateTime, Duration, LocalResult, NaiveDate, NaiveDateTime, TimeZone};

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
        use AllowedSignerParsingError::*;

        // This follows OpenSSH's parse_principals_key_and_options() and sshsigopt_parse() so that
        // a line means the same thing here as it does to ssh-keygen.
        let line = s.trim_start_matches(WHITESPACE);
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::InvalidAllowedSigner(MissingPrincipals));
        }

        // Format: identity[,identity...] [option[,option...]] key
        let (principals, rest) = split_field(line).ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?;

        let principals: Vec<String> = principals.split(',').map(String::from).collect();
        if principals.iter().any(|p| p.is_empty()) {
            return Err(Error::InvalidAllowedSigner(InvalidPrincipals));
        }

        // The options field is optional, so first try to read the key
        let (options, key) = match parse_key(rest) {
            Some(key) => ("", key),
            None => {
                let (options, rest) = split_options(rest).ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?;
                if rest.is_empty() {
                    return Err(Error::InvalidAllowedSigner(MissingKey));
                }
                (options, parse_key(rest).ok_or(Error::InvalidAllowedSigner(InvalidKey))?)
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
            let option_start = rest;

            if let Some(after) = strip_prefix_ignore_case(rest, "cert-authority") {
                cert_authority = true;
                rest = after;
            } else if let Some(after) = strip_prefix_ignore_case(rest, "namespaces=") {
                if namespaces.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("namespaces".to_string())));
                }
                let (value, after) = split_quoted(after)?;
                namespaces = Some(value.split(',').filter(|n| !n.is_empty()).map(String::from).collect());
                rest = after;
            } else if let Some(after) = strip_prefix_ignore_case(rest, "valid-after=") {
                if valid_after.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("valid-after".to_string())));
                }
                let (value, after) = split_quoted(after)?;
                valid_after = Some(parse_timestamp(&value).ok_or_else(|| Error::InvalidAllowedSigner(InvalidOption("valid-after".to_string())))?);
                rest = after;
            } else if let Some(after) = strip_prefix_ignore_case(rest, "valid-before=") {
                if valid_before.is_some() {
                    return Err(Error::InvalidAllowedSigner(DuplicateOptions("valid-before".to_string())));
                }
                let (value, after) = split_quoted(after)?;
                valid_before = Some(parse_timestamp(&value).ok_or_else(|| Error::InvalidAllowedSigner(InvalidOption("valid-before".to_string())))?);
                rest = after;
            }

            // Anything other than a comma means an unknown option. Like OpenSSH, skip an empty
            // option between two commas, but not a trailing comma.
            rest = match rest.strip_prefix(',') {
                Some(after) if !after.is_empty() => after,
                None if rest.is_empty() => break,
                _ => {
                    let name = option_start.split_once(['=', ',']).map_or(option_start, |(name, _)| name);
                    return Err(Error::InvalidAllowedSigner(InvalidOption(name.to_string())));
                },
            };
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

    /// Write the entry as a line that OpenSSH reads back as the same entry. The key's comment is
    /// left out.
    ///
    /// Fails when no such line exists:
    /// - `principals` is empty, or a principal is empty or contains `,`, `"`, a line feed or NUL
    /// - a namespace is empty or contains `,`, a line feed or NUL
    /// - `valid_before <= valid_after`, or a timestamp is not after the epoch or is past year 9999
    /// - the key is a certificate
    pub fn to_line(&self) -> Result<String> {
        use AllowedSignerParsingError::*;

        if self.key.key_type.is_cert {
            return Err(Error::InvalidAllowedSigner(InvalidKey));
        }

        // A quoted principals field ends at the next double quote (split_field)
        if self.principals.is_empty() || !self.principals.iter().all(|p| is_list_item(p) && !p.contains('"')) {
            return Err(Error::InvalidAllowedSigner(InvalidPrincipals));
        }
        let principals = self.principals.join(",");
        // AllowedSigners trims any leading whitespace off a line
        let mut line = if principals.contains([' ', '\t', '\r', '#']) || principals.starts_with(char::is_whitespace) {
            format!("\"{}\"", principals)
        } else {
            principals
        };

        // OpenSSH requires comma-separated options with quoted values
        let mut options = Vec::new();

        if self.cert_authority {
            options.push("cert-authority".to_string());
        }

        if let Some(namespaces) = &self.namespaces {
            if !namespaces.iter().all(|n| is_list_item(n)) {
                return Err(Error::InvalidAllowedSigner(InvalidOption("namespaces".to_string())));
            }
            let mut value = namespaces.join(",").replace('"', "\\\"");
            // A trailing backslash would escape the closing quote (split_quoted). An empty item after
            // it is skipped when reading.
            if value.ends_with('\\') {
                value.push(',');
            }
            options.push(format!("namespaces=\"{}\"", value));
        }

        // sshsigopt_parse() rejects this pair
        if let (Some(valid_before), Some(valid_after)) = (self.valid_before, self.valid_after) {
            if valid_before <= valid_after {
                return Err(Error::InvalidAllowedSigner(InvalidTimestamps));
            }
        }

        for (name, timestamp) in [("valid-after", self.valid_after), ("valid-before", self.valid_before)] {
            if let Some(timestamp) = timestamp {
                let timestamp = format_timestamp(timestamp).ok_or_else(|| Error::InvalidAllowedSigner(InvalidOption(name.to_string())))?;
                options.push(format!("{}=\"{}\"", name, timestamp));
            }
        }

        if !options.is_empty() {
            line.push(' ');
            line.push_str(&options.join(","));
        }

        // encode() writes the plain key type. from_string ignores the comment, and a line break in
        // it would start a new entry.
        line.push_str(&format!(" {} {}", self.key.key_type.plain, base64::encode(self.key.encode())));

        Ok(line)
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

/// Whether OpenSSH reads `s` back as one item of a comma-separated list. It doesn't escape commas,
/// a line feed would start a new entry, and it reads a line as a C string.
fn is_list_item(s: &str) -> bool {
    !s.is_empty() && !s.contains([',', '\n', '\0'])
}

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
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            ' ' | '\t' if !quoted => return Some(s.split_at(i)),
            '\\' => {
                chars.next_if(|&(_, c)| c == '"');
            },
            '"' => quoted = !quoted,
            _ => {},
        }
    }
    (!quoted).then_some((s, ""))
}

/// Strip `prefix` off the front of `s`, ignoring ASCII case. This covers OpenSSH's opt_flag() and
/// opt_match() (misc.c).
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// Split a double-quoted value off the front of `s`. Inside it, `\"` is a literal quote.
/// Port of OpenSSH's opt_dequote() (misc.c).
fn split_quoted(s: &str) -> Result<(String, &str)> {
    use AllowedSignerParsingError::*;

    let mut chars = s.strip_prefix('"').ok_or(Error::InvalidAllowedSigner(InvalidQuotes))?.chars();
    let mut value = String::new();
    loop {
        match chars.next().ok_or(Error::InvalidAllowedSigner(InvalidQuotes))? {
            '"' => return Ok((value, chars.as_str())),
            '\\' if chars.as_str().starts_with('"') => {
                chars.next();
                value.push('"');
            },
            c => value.push(c),
        }
    }
}

/// Format a UNIX timestamp as YYYYMMDDHHMMSSZ. Returns None if OpenSSH can't read the timestamp
/// back, since it rejects the epoch and anything before it, and needs a four-digit year.
fn format_timestamp(timestamp: i64) -> Option<String> {
    // 99991231235959Z is the last one with a four-digit year
    if !(1..=253_402_300_799).contains(&timestamp) {
        return None;
    }
    DateTime::from_timestamp(timestamp, 0).map(|datetime| datetime.format("%Y%m%d%H%M%SZ").to_string())
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

    (timestamp > 0).then_some(timestamp)
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
