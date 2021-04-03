//use super::error::{Error, ErrorKind, Result};
use crate::{error::Error, Result};
use std::convert::TryInto;

/// A `Reader` is used for reading from a byte sequence
/// representing an encoded OpenSSH public key or certificate.
#[derive(Debug)]
pub struct Reader<'a> {
    inner: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new `Reader` instance from the given byte sequence.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn new<T: ?Sized + AsRef<[u8]>>(inner: &T) -> Reader {
        Reader {
            inner: inner.as_ref(),
            offset: 0,
        }
    }

    /// Sets the `Reader` current offset to a given position.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// reader.set_offset(0);
    /// let num_42_again = reader.read_u32().unwrap();
    /// assert_eq!(num_42_again, 42);
    /// ```
    pub fn set_offset(&mut self, offset: usize) -> Result<()> {
        self.offset = offset;

        Ok(())
    }

    /// Gets the `Reader` current offset.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// assert_eq!(reader.get_offset(), 4);
    /// ```
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Reads a byte buffer from the wrapped byte sequence and
    /// returns it as a `Vec<u8>`.
    /// The buffer is represented by it's length as `u32` value
    /// followed by the actual bytes to read.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = Reader::new(&data);
    /// let bytes = reader.read_bytes().unwrap();
    /// assert_eq!(bytes, [97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103]);
    /// ```
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self.offset >= self.inner.len() {
            return Err(Error::UnexpectedEof);
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 4 {
            return Err(Error::InvalidFormat);
        }

        let size = u32::from_be_bytes(slice[..4].try_into().unwrap()) as usize;
        if slice.len() < size + 4 {
            return Err(Error::InvalidFormat);
        }

        self.offset += size + 4;
        let result = slice[4..size + 4].to_vec();

        Ok(result)
    }

    /// Reads `len` bytes from the wrapped buffer as raw data
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = Reader::new(&data);
    /// let bytes = reader.read_raw_bytes(4).unwrap();
    /// assert_eq!(bytes, [0, 0, 0, 13]);
    /// ```
    pub fn read_raw_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.offset >= self.inner.len() {
            return Err(Error::UnexpectedEof);
        }

        if len + self.offset > self.inner.len() {
            return Err(Error::UnexpectedEof);
        }

        let slice = &self.inner[self.offset..];

        self.offset += len;
        let result = slice[..len].to_vec();

        Ok(result)
    }

    /// Reads an `mpint` value from the wrapped byte sequence.
    ///
    /// Drops the leading byte if it's value is zero according to the RFC 4251, section 5.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 3, 1, 0, 1];
    /// let mut reader = Reader::new(&data);
    /// let mpint = reader.read_mpint().unwrap();
    /// assert_eq!(mpint, [1, 0, 1]);
    /// ```
    pub fn read_mpint(&mut self) -> Result<Vec<u8>> {
        let bytes = self.read_bytes()?;

        if bytes[0] == 0 {
            return Ok(bytes[1..].to_vec());
        }

        Ok(bytes)
    }

    /// Reads a `string` value from the wrapped byte sequence and
    /// returns it as a `String`. The value that we read should be a valid UTF-8.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = Reader::new(&data);
    /// let result = reader.read_string().unwrap();
    /// assert_eq!(result, "a test string");
    /// ```
    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        let result = String::from_utf8(bytes)?;

        Ok(result)
    }

    /// Read a null terminated string from the reader's buffer.
    /// This is different than read_string in that the length
    /// is unknown and will continue until it reads a null byte
    /// or reaches the end of the data.
    /// 
    /// In the event the buffer runs out before a null byte, the offset will be
    /// reset and an error returned.
    pub fn read_cstring(&mut self) -> Result<String> {
        let original_offset = self.offset;
        let mut s = String::new();

        while self.offset < self.inner.len() {
            let chr = self.inner[self.offset];
            if chr == 0x0 {
                // Count the final null byte as read
                self.offset += 1;
                return Ok(s);
            }

            s.push(chr as char);
            self.offset += 1;
        }
        self.offset = original_offset;
        Err(Error::UnexpectedEof)
    }

    /// Reads an `u32` value from the wrapped byte sequence and returns it.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.offset >= self.inner.len() {
            return Err(Error::UnexpectedEof);
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 4 {
            return Err(Error::InvalidFormat);
        }

        self.offset += 4;
        let value = u32::from_be_bytes(slice[..4].try_into().unwrap());

        Ok(value)
    }

    /// Reads an `u64` value from the wrapped byte sequence and returns it.
    ///
    /// # Example
    /// ```rust
    /// # use sshcerts::ssh::Reader;
    /// let data = vec![0, 0, 0, 0, 0, 0, 0, 42];
    /// let mut reader = Reader::new(&data);
    /// let num = reader.read_u64().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn read_u64(&mut self) -> Result<u64> {
        if self.offset >= self.inner.len() {
            return Err(Error::UnexpectedEof);
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 8 {
            return Err(Error::InvalidFormat);
        }

        self.offset += 8;
        let value = u64::from_be_bytes(slice[..8].try_into().unwrap());

        Ok(value)
    }
}
