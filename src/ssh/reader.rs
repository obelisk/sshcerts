use crate::{error::Error, Result};
use std::convert::TryInto;

/// A `Reader` is used for reading from a byte sequence
/// representing an encoded OpenSSH public/private key or certificate.
#[derive(Debug)]
pub struct Reader<'a> {
    inner: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
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
    pub fn new<T: ?Sized + AsRef<[u8]>>(inner: &T) -> Reader<'_> {
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
        
        // Similar to below, this is a rearrangement so we do not have to do
        // math on possibly untrusted inputs.
        //
        // It's easier to look at this as:
        // slice.len() < size + 4
        if slice.len() - 4 < size {
            return Err(Error::InvalidFormat);
        }

        // In theory it could still overflow here but this would require we've read
        // in 4 GiB of data. It's likely that if you're reading in a 4GiB SSH key or
        // certificate, checking elsewhere in the stack should have occured.
        //
        // This is also only relevant to 32bit systems where usize is 32 bits.
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

        // Rearranged in a strange way to prevent us from doing
        // math on an untrusted value. This will prevent panics
        // in debug and wraps in release.
        //
        // It's easier to look at this as:
        // len + self.offset > self.inner.len()
        if len > self.inner.len() - self.offset {
            return Err(Error::UnexpectedEof);
        }

        let slice = &self.inner[self.offset..];

        // This should be fine now because we've validated our
        // lengths above.
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
    /// let mpint = reader.read_positive_mpint().unwrap();
    /// assert_eq!(mpint, [1, 0, 1]);
    /// ```
    pub fn read_positive_mpint(&mut self) -> Result<Vec<u8>> {
        let bytes = self.read_bytes()?;

        if bytes.is_empty() {
            return Ok(bytes);
        }

        match bytes[0] {
            // Likely a positive number with the leading 0 set
            0x00 => {
                // The specification says that 0 should be represented as the empty string
                // Thus a 0 byte here is not a valid numerical representation.
                if bytes.len() == 1 {
                    return Err(Error::InvalidFormat); 
                }

                // This first byte is not large enough to warrant the leading 0x00 byte.
                // Something is likely wrong.
                if bytes[1] < 0x80 {
                    return Err(Error::InvalidFormat); 
                }

                return Ok(bytes[1..].to_vec())
            },

            // A positive number where the first byte has a low enough value
            0x01..=0x7F => return Ok(bytes.to_vec()),

            // This is the format of a negative number
            0x80..=0xFF => return Err(Error::InvalidFormat),
        }
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
