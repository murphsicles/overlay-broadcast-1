//! A bounds-checked read cursor over untrusted bytes: no panic, no out-of-bounds
//! indexing, no unbounded allocation (REQ-BSV-012, REQ-GOV-011/013).
use crate::error::BsvError;
use crate::hash::Hash256;

/// A forward-only cursor that yields typed reads or a typed error.
#[derive(Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, off: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.off)
    }

    /// Whether all bytes have been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take exactly `n` bytes, or error if fewer remain.
    ///
    /// # Errors
    /// [`BsvError::Truncated`] / [`BsvError::OutOfRange`].
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], BsvError> {
        let end = self.off.checked_add(n).ok_or(BsvError::OutOfRange)?;
        let slice = self.data.get(self.off..end).ok_or(BsvError::Truncated)?;
        self.off = end;
        Ok(slice)
    }

    /// Read one byte.
    ///
    /// # Errors
    /// [`BsvError::Truncated`].
    pub fn u8(&mut self) -> Result<u8, BsvError> {
        self.take(1)?.first().copied().ok_or(BsvError::Truncated)
    }

    /// Read a little-endian u32.
    ///
    /// # Errors
    /// [`BsvError::Truncated`].
    pub fn u32_le(&mut self) -> Result<u32, BsvError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| BsvError::Truncated)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Read a little-endian i32.
    ///
    /// # Errors
    /// [`BsvError::Truncated`].
    pub fn i32_le(&mut self) -> Result<i32, BsvError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| BsvError::Truncated)?;
        Ok(i32::from_le_bytes(b))
    }

    /// Read a little-endian u64.
    ///
    /// # Errors
    /// [`BsvError::Truncated`].
    pub fn u64_le(&mut self) -> Result<u64, BsvError> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| BsvError::Truncated)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Read a 32-byte hash in internal order.
    ///
    /// # Errors
    /// [`BsvError::Truncated`].
    pub fn hash256(&mut self) -> Result<Hash256, BsvError> {
        let b: [u8; 32] = self.take(32)?.try_into().map_err(|_| BsvError::Truncated)?;
        Ok(Hash256::from_internal(b))
    }

    /// Read a CompactSize varint.
    ///
    /// # Errors
    /// [`BsvError::Truncated`] / [`BsvError::OutOfRange`].
    pub fn varint(&mut self) -> Result<u64, BsvError> {
        match self.u8()? {
            0xFF => self.uint(8),
            0xFE => self.uint(4),
            0xFD => self.uint(2),
            n => Ok(u64::from(n)),
        }
    }

    /// Read a varint-prefixed byte run.
    ///
    /// # Errors
    /// [`BsvError::Truncated`] / [`BsvError::OutOfRange`].
    pub fn varint_bytes(&mut self) -> Result<&'a [u8], BsvError> {
        let len = self.varint()?;
        let n = usize::try_from(len).map_err(|_| BsvError::OutOfRange)?;
        self.take(n)
    }

    fn uint(&mut self, n: usize) -> Result<u64, BsvError> {
        let mut value = 0u64;
        for (i, b) in self.take(n)?.iter().enumerate() {
            let shift = u32::try_from(i)
                .ok()
                .and_then(|i| i.checked_mul(8))
                .ok_or(BsvError::OutOfRange)?;
            let term = u64::from(*b)
                .checked_shl(shift)
                .ok_or(BsvError::OutOfRange)?;
            value |= term;
        }
        Ok(value)
    }
}

/// Append a CompactSize varint to `out`.
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value < 0xFD {
        out.push(u8::try_from(value).unwrap_or(0));
    } else if value <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&u16::try_from(value).unwrap_or(0).to_le_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&u32::try_from(value).unwrap_or(0).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&value.to_le_bytes());
    }
}
