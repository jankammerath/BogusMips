//! Bounds-checked little-endian byte reader shared by the binary format parsers.
//!
//! Android packages are frequently crafted to crash analysis tools, so every
//! read is checked and reported as an error instead of panicking.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

pub type Result<T> = std::result::Result<T, ParseError>;

pub fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ParseError(msg.into()))
}

#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Result<Self> {
        if pos > data.len() {
            return err(format!(
                "offset 0x{pos:x} is outside of the data (length 0x{:x})",
                data.len()
            ));
        }
        Ok(Self { data, pos })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return err(format!(
                "unexpected end of data reading {n} bytes at offset 0x{:x}",
                self.pos
            ));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn uleb128(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        for i in 0..5 {
            let byte = self.u8()?;
            result |= u32::from(byte & 0x7f).wrapping_shl(7 * i);
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        err(format!("malformed uleb128 at offset 0x{:x}", self.pos))
    }

    pub fn sleb128(&mut self) -> Result<i32> {
        let mut result: i32 = 0;
        let mut shift = 0;
        for _ in 0..5 {
            let byte = self.u8()?;
            result |= i32::from(byte & 0x7f).wrapping_shl(shift);
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 32 && byte & 0x40 != 0 {
                    result |= -1i32 << shift;
                }
                return Ok(result);
            }
        }
        err(format!("malformed sleb128 at offset 0x{:x}", self.pos))
    }

    /// Reads `n` (1..=8) bytes as a little-endian unsigned integer.
    pub fn uint_sized(&mut self, n: usize) -> Result<u64> {
        let bytes = self.bytes(n)?;
        Ok(bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }
}

pub fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    Reader::at(data, off)?.u16()
}

pub fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    Reader::at(data, off)?.u32()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128() {
        assert_eq!(Reader::new(&[0x00]).uleb128().unwrap(), 0);
        assert_eq!(Reader::new(&[0x7f]).uleb128().unwrap(), 127);
        assert_eq!(Reader::new(&[0x80, 0x7f]).uleb128().unwrap(), 16256);
        assert_eq!(Reader::new(&[0x7f]).sleb128().unwrap(), -1);
        assert_eq!(Reader::new(&[0x80, 0x7f]).sleb128().unwrap(), -128);
        assert_eq!(Reader::new(&[0x3f]).sleb128().unwrap(), 63);
        assert!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80])
                .uleb128()
                .is_err()
        );
    }

    #[test]
    fn bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(r.u16().is_err());
        assert!(Reader::at(&[1], 2).is_err());
    }
}
