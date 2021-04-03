use std::{fmt, io, string};

/// A type to represent the different kinds of errors.
#[derive(Debug)]
pub enum Error {
    /// There was an error reading from or writing to an external source
    Io(io::Error),
    /// Data was improperly encoded as base64
    Decode(base64::DecodeError),
    /// Data was not a valid UTF8 string.
    Utf8Error(string::FromUtf8Error),
    /// A certificate type that doesn't exist was requested. Should be either 1 or 2
    InvalidCertType(u32),
    /// The format of a certificate was incorrect
    InvalidFormat,
    /// The stream ended unexpectedly
    UnexpectedEof,
    /// The provided data was not a certificate
    NotCertificate,
    /// The requested signature or key was incompatible with what was previously specified
    KeyTypeMismatch,
    /// The certificate is not signed correctly and invalid
    CertificateInvalidSignature,
    /// A cryptographic operation failed.
    SigningError,
    /// An encrypted private key was supplied and is not supported
    EncryptedPrivateKeyNotSupported,
    /// The key type is unknown
    UnknownKeyType(String),
    /// The curve in an ECC public/private key/signature is unknown
    UnknownCurve(String),
    /// An error occured in the yubikey module
    #[cfg(feature = "yubikey")]
    YubikeyError(crate::yubikey::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(ref err) => err.fmt(f),
            Error::Decode(ref err) => err.fmt(f),
            Error::Utf8Error(ref err) => err.fmt(f),
            Error::InvalidFormat => write!(f, "Invalid format"),
            Error::InvalidCertType(v) => write!(f, "Invalid certificate type with value {}", v),
            Error::UnexpectedEof => write!(f, "Unexpected EOF reached while reading data"),
            Error::NotCertificate => write!(f, "Not a certificate"),
            Error::KeyTypeMismatch => write!(f, "Key type mismatch"),
            Error::CertificateInvalidSignature => write!(f, "Certificate is improperly signed"),
            Error::SigningError => write!(f, "Could not sign data"),
            Error::EncryptedPrivateKeyNotSupported => write!(f, "Encrypted private keys are not supported"),
            Error::UnknownKeyType(ref v) => write!(f, "Unknown key type {}", v),
            Error::UnknownCurve(ref v) => write!(f, "Unknown curve {}", v),
            #[cfg(feature = "yubikey")]
            Error::YubikeyError(ref e) => write!(f, "{}", e), 
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(ref e) => e.source(),
            Error::Decode(ref e) => e.source(),
            Error::Utf8Error(ref e) => e.source(),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Error {
        Error::Decode(error)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Error {
        Error::Utf8Error(error)
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Error{
        Error::CertificateInvalidSignature
    }
}

#[cfg(feature = "rsa-signing")]
impl From<simple_asn1::ASN1EncodeErr> for Error {
    fn from(_e: simple_asn1::ASN1EncodeErr) -> Self {
        Error::InvalidFormat
    }
}
