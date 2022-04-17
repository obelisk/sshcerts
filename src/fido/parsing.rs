use crate::error::Error;

use crate::{
    PublicKey,
    ssh::{
        Curve,
        KeyType,
        PublicKeyKind,
        EcdsaPublicKey,
        Ed25519PublicKey,
    },
};

use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;

use minicbor::Decoder;


/// A struct used to hold data about the key we are extracting from the authentication
/// data
#[derive(Debug, Default, Clone)]
pub struct CoseKey {
    /// The COSE key type
    pub key_type: i128,
    /// The COSE key algorithm
    pub algorithm: i128,
    /// The key value
    pub key: Vec<u8>,
    /// Any extra parameters
    pub parameters: HashMap<i128, String>,
}

/// A parsed representation of the authentication data provided by a FIDO/U2F
/// token at key generation
#[derive(Debug, Clone)]
pub struct AuthData {
    /// A hash of the RPID (in our use case, sk_application)
    pub rpid_hash: Vec<u8>,
    /// Flags
    pub flags: u8,
    /// Sign Count
    pub sign_count: u32,
    /// An identifier that is unique to the type of authentictor used.
    pub aaguid: Vec<u8>,
    /// Credential ID
    pub credential_id: Vec<u8>,
    /// COSE Key
    pub cose_key: CoseKey,
}

fn read_integer(decoder: &mut Decoder<'_>) -> Result<i128, Error> {
    let t = decoder.datatype().map_err(|_| Error::ParsingError)?;
    let v = match t {
        minicbor::data::Type::U8 => decoder.u8().unwrap() as i128,
        minicbor::data::Type::U16 => decoder.u16().unwrap() as i128,
        minicbor::data::Type::U32 => decoder.u32().unwrap() as i128,
        minicbor::data::Type::U64 => decoder.u64().unwrap() as i128,
        minicbor::data::Type::I8 => decoder.i8().unwrap() as i128,
        minicbor::data::Type::I16 => decoder.i16().unwrap() as i128,
        minicbor::data::Type::I32 => decoder.i32().unwrap() as i128,
        minicbor::data::Type::I64 => decoder.i64().unwrap() as i128,
        _ => return Err(Error::ParsingError)
    };

    Ok(v)
}

impl AuthData {
    /// Parse an attestation statement to extract the encoded information
    pub fn parse(auth_data_raw: &[u8]) -> Result<Self, Error> {
        let mut auth_data = Cursor::new(auth_data_raw);

        // RPID Hash
        let mut rpid_hash = [0; 32];
        if auth_data.read_exact(&mut rpid_hash).is_err() {
            return Err(Error::ParsingError)
        }

        // Flags
        let mut flags = [0; 1];
        if auth_data.read_exact(&mut flags).is_err() {
            return Err(Error::ParsingError)
        }
        let credential_data_included = matches!(flags[0] & 0x40, 0x40);

        // Sign Count
        let mut sign_count = [0; 4];
        if auth_data.read_exact(&mut sign_count).is_err() {
            return Err(Error::ParsingError)
        }

        // AAGUID
        let mut aaguid = [0; 16];
        if auth_data.read_exact(&mut aaguid).is_err() {
            return Err(Error::ParsingError)
        }

        // Credential ID Length
        let mut cred_id_len = [0; 2];
        if auth_data.read_exact(&mut cred_id_len).is_err() {
            return Err(Error::ParsingError)
        }
        let cred_id_len = u16::from_be_bytes(cred_id_len) as usize;

        // Credential ID
        let mut credential_id = vec![0; cred_id_len];
        if auth_data.read_exact(&mut credential_id).is_err() {
            return Err(Error::ParsingError)
        }

        // Start decoding CBOR objects from after where we got with the cursor
        let cose_key = if credential_data_included {
            // Create a new decoder for the COSE data
            let mut decoder = Decoder::new(&auth_data_raw[auth_data.position() as usize..]);

            // We only deal with maps of definite length
            let len = match decoder.map() {
                Ok(Some(len)) => len,
                _ => return Err(Error::ParsingError),
            };


            let mut parsed_key = CoseKey::default();
            let mut idx = 0;

            // Multiply by two because maps have two entries per element
            while idx < len * 2 {
                let key = read_integer(&mut decoder)?;
                match key {
                    -1 => {
                        let value = read_integer(&mut decoder).map_err(|_| Error::ParsingError)?;
                        parsed_key.parameters.insert(key, value.to_string());
                    },
                    1 => parsed_key.key_type = read_integer(&mut decoder).map_err(|_| Error::ParsingError)?,
                    3 => parsed_key.algorithm = read_integer(&mut decoder).map_err(|_| Error::ParsingError)?,
                    -2 | -3 => parsed_key.key = decoder.bytes().map_err(|_| Error::ParsingError)?.to_vec(),
                    _ => decoder.undefined().map_err(|_| Error::ParsingError)?,
                };
                idx += 2;
            }
            Some(parsed_key)
        } else {
            None
        };

        let cose_key = cose_key.ok_or(Error::ParsingError)?;

        Ok(AuthData {
            rpid_hash: rpid_hash.to_vec(),
            aaguid: aaguid.to_vec(),
            flags: flags[0],
            sign_count: u32::from_be_bytes(sign_count),
            credential_id,
            cose_key,
        })
    }

    /// Get an SSH formatted public key for the given auth data. The plaintext application
    /// is needed to ensure the fingerprint is properly computed.
    pub fn ssh_public_key(&self, app: &str) -> Result<PublicKey, Error> {
        let (kind, key_type) = match self.cose_key.algorithm {
            // ECDSA
            -7 => {
                let k = EcdsaPublicKey {
                    curve: Curve::from_identifier("nistp256").unwrap(),
                    key: self.cose_key.key.clone(),
                    sk_application: Some(app.to_owned()),
                };
                (PublicKeyKind::Ecdsa(k), KeyType::from_name("sk-ecdsa-sha2-nistp256@openssh.com").unwrap())
            },

            // Ed25519
            -8 => {
                let k = Ed25519PublicKey {
                    key: self.cose_key.key.clone(),
                    sk_application: Some(app.to_owned()),
                };

                (PublicKeyKind::Ed25519(k), KeyType::from_name("sk-ssh-ed25519@openssh.com").unwrap())
            },

            // Unknown
            _n => return Err(Error::ParsingError),
        };

        Ok(PublicKey {
            key_type,
            kind, 
            comment: None,
        })
    }
}
