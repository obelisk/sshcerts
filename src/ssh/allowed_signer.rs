use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::prelude::Local;
use chrono::{DateTime, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};

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
    /// Unexpected end of allowed signer
    UnexpectedEnd,
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
            AllowedSignerParsingError::UnexpectedEnd => write!(f, "unexpected data at the end"),
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
        let mut tokenizer = AllowedSignerSplitter::new(s);

        let principals = tokenizer.next(true)?
            .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::MissingPrincipals))?;
        let principals = principals.trim_matches('"');
        if principals.contains('"') {
            return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes));
        }
        let principals: Vec<String> = principals.split(',')
            .map(|s| s.to_string())
            .collect();
        if principals.iter().any(|p| p.is_empty()) {
            return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidPrincipals));
        }

        let mut cert_authority = false;
        let mut namespaces = None;
        let mut valid_after = None;
        let mut valid_before = None;

        let field = tokenizer.next(false)?
            .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::MissingKey))?;

        // The options field is optional. Key types never contain '=' or ',', and the only option
        // without either is cert-authority.
        let options = if field.contains(['=', ',']) || field.eq_ignore_ascii_case("cert-authority") {
            split_options(&field)
        } else {
            Vec::new()
        };

        for option in &options {
            let (option_key, option_value) = match option.split_once('=') {
                Some(v) => v,
                None => (option.as_str(), ""),
            };
            let option_value = option_value.trim_matches('"');
            if option_value.contains("\"") {
                return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes));
            }

            match option_key.to_lowercase().as_str() {
                "cert-authority" => {
                    if option.contains('=') {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption("cert-authority".to_string()))
                        );
                    }
                    cert_authority = true;
                },
                "namespaces" => {
                    if namespaces.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("namespaces".to_string()))
                        );
                    }

                    let namespaces_value: Vec<&str> = option_value.split(',')
                        .filter(|e| !e.is_empty())
                        .collect();
                    namespaces = Some(
                        namespaces_value.iter()
                            .map(|s| s.to_string())
                            .collect()
                    );
                },
                "valid-after" => {
                    if valid_after.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("valid-after".to_string()))
                        );
                    }
                    valid_after = Some(parse_timestamp(option_value)
                        .map_err(
                            |_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption("valid-after".to_string())))?
                        );
                },
                "valid-before" => {
                    if valid_before.is_some() {
                        return Err(
                            Error::InvalidAllowedSigner(AllowedSignerParsingError::DuplicateOptions("valid-before".to_string()))
                        );
                    }
                    valid_before = Some(parse_timestamp(option_value)
                        .map_err(
                            |_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption("valid-before".to_string())))?
                        );
                },
                // An empty option comes from a stray comma, so report the whole field
                "" => {
                    return Err(
                        Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(field.clone()))
                    );
                },
                _ => {
                    return Err(
                        Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(option_key.to_string()))
                    );
                },
            };
        }

        let kt = if options.is_empty() {
            field
        } else {
            tokenizer.next(false)?
                .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::MissingKey))?
        };

        let key_data = tokenizer.next(false)?
            .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidKey))?;

        let key = PublicKey::from_string(format!("{} {}", kt, key_data).as_str())
            .map_err(|_| Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidKey))?;

        // Timestamp sanity check
        if let (Some(valid_before), Some(valid_after)) = (&valid_before, &valid_after) {
            if valid_before <= valid_after {
                return Err(
                    Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidTimestamps),
                );
            }
        }

        // After key data, there must be only comment or nothing
        if !tokenizer.is_empty_after_trim() {
            return Err(
                Error::InvalidAllowedSigner(AllowedSignerParsingError::UnexpectedEnd),
            );
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

        let principals = self.principals.join(",");
        if principals.contains([' ', '\t', '#']) {
            output.push_str(&format!("\"{}\"", principals));
        } else {
            output.push_str(&principals);
        }
        
        // OpenSSH requires comma-separated options with quoted values
        let mut options = Vec::new();

        if self.cert_authority {
            options.push("cert-authority".to_string());
        }

        if let Some(ref namespaces) = self.namespaces {
            options.push(format!("namespaces=\"{}\"", namespaces.join(",").replace('"', "\\\"")));
        }

        if let Some(valid_after) = self.valid_after {
            options.push(format!("valid-after=\"{}\"", format_timestamp(valid_after)));
        }

        if let Some(valid_before) = self.valid_before {
            options.push(format!("valid-before=\"{}\"", format_timestamp(valid_before)));
        }

        if !options.is_empty() {
            output.push_str(&format!(" {}", options.join(",")));
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

/// A type used to split the allowed signer segments, abstracting out the handling of double quotes.
/// The splitter is highly aware of the allowed_signer format and will catch certain invalid
/// formats.
///
/// For example: "principals   option1=\"value1   value2\",option2,option3=value kt key_data" is split into
/// ["principals", "option1=\"value1   value2\",option2,option3=value", "kt", "key_data"]
struct AllowedSignerSplitter {
    /// A buffer of remaining tokens in reverse order.
    buffer: Vec<String>,
}

impl AllowedSignerSplitter {
    /// Split the string by delimiters but keep the delimiters.
    fn new(s: &str) -> Self {
        let mut buffer = Vec::new();
        let mut last = 0;

        for (index, matched) in s.match_indices([' ', '\t', '"', '#']) {
            // Push the new text before the delimiter
            if last != index {
                buffer.push(s[last..index].to_owned());
            }
            // Push the delimiter
            buffer.push(matched.to_owned());
            last = index + matched.len();
        }

        // Push the remaining text
        if last < s.len() {
            buffer.push(s[last..].to_owned());
        }

        // We parse from left to right so reversing allow us to use Vec's last() and pop()
        buffer.reverse();

        Self { buffer }
    }

    fn is_empty_after_trim(&mut self) -> bool {
        self.trim();
        return self.buffer.is_empty();
    }

    /// Get the next whitespace-separated field (principals, options, key type, key data)
    /// If opening_quotes_allowed is set to false, we reject the next token if it starts with ".
    fn next(&mut self, opening_quotes_allowed: bool) -> Result<Option<String>> {
        if self.is_empty_after_trim() {
            return Ok(None);
        }

        // If the next token starts with a double quote, then the closing double quote is also
        // the end of the token
        if self.buffer[0] == "\"" {
            if opening_quotes_allowed {
                return self.split_quote().map(|v| Some(v));
            } else {
                return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes));
            }
        }

        // If the next token doesn't start with a double quote, the token can represent the options.
        // Only the options token can contain double quotes in the middle (e.g. a="b c",d="e").
        // Otherwise, we greedily parse the token until the next whitespace.
        let mut s = String::new();
        while let Some(last) = self.buffer.pop() {
            match last.as_str() {
                " " | "\t" | "#" => {
                    self.buffer.push(last);
                    break;
                },
                "\"" => {
                    self.buffer.push(last);
                    s.push_str(self.split_quote()?.as_str());

                    // A closing double quote must end the token or the option
                    if let Some(last) = self.buffer.last() {
                        if ![" ", "\t", "#"].contains(&last.as_str()) && !last.starts_with(',') {
                            return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes));
                        }
                    }
                },
                _ => s.push_str(&last),
            }
        }

        Ok(Some(s))
    }

    /// Trim comment and whitespaces
    fn trim(&mut self) {
        while let Some(last) = self.buffer.last(){
            match last.as_str() {
                " " | "\t" => {
                    self.buffer.pop();
                },
                // Comment detected
                "#" => {
                    self.buffer.clear()
                },
                _ => break,
            };
        }
    }

    /// Extract content inside the double quotes.
    /// This function assumes buffer starst with a ".
    fn split_quote(&mut self) -> Result<String> {
        match self.buffer.pop() {
            Some(v) => {
                if v != "\"" {
                    return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes));
                }
            },
            None => return Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes)),
        }

        let mut s = String::from("\"");
        loop {
            let token = self.buffer.pop()
                .ok_or(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidQuotes))?;
            s.push_str(&token);
            if token == "\"" {
                break;
            }
        }

        Ok(s)
    }
}

/// Split the options field on commas that are not inside double quotes.
fn split_options(field: &str) -> Vec<String> {
    let mut options = Vec::new();
    let mut option = String::new();
    let mut in_quotes = false;

    for c in field.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                option.push(c);
            },
            ',' if !in_quotes => options.push(std::mem::take(&mut option)),
            _ => option.push(c),
        }
    }
    options.push(option);

    options
}

/// Format a UNIX timestamp as YYYYMMDDHHMMSSZ.
/// OpenSSH rejects timestamps at or before the epoch and needs a four-digit year, so this clamps
/// the timestamp between 19700101000001Z and 99991231235959Z.
fn format_timestamp(timestamp: i64) -> String {
    let timestamp = timestamp.clamp(1, 253402300799);
    DateTime::from_timestamp(timestamp, 0)
        .expect("clamped timestamp should be in range")
        .format("%Y%m%d%H%M%SZ")
        .to_string()
}

/// Parse a string into a u64 representing a timestamp.
/// The timestamp has format YYYYMMDD[HHMM[SS]][Z|UTC], with a case-insensitive suffix.
/// The timestamp can be enclosed by quotation marks.
fn parse_timestamp(s: &str) -> Result<i64> {
    let s = s.trim_matches('"').to_ascii_lowercase();
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
