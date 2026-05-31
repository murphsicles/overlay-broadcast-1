//! Hashing and the internal/display byte-order distinction (REQ-BSV-001/002/003).
use crate::error::BsvError;
use core::fmt;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// A 256-bit hash stored in INTERNAL byte order. Display order is the reverse
/// (big-endian), the conventional block/tx-id presentation. The conversion lives in
/// EXACTLY one place — [`Hash256::from_display_hex`] / [`Hash256::to_display_hex`] —
/// so byte-order is never reversed ad hoc elsewhere (REQ-BSV-001).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Construct from raw internal-order bytes.
    #[must_use]
    pub const fn from_internal(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the internal-order bytes.
    #[must_use]
    pub const fn internal(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse from display (big-endian) hex, reversing to internal order.
    ///
    /// # Errors
    /// Returns [`BsvError::Hex`] / [`BsvError::Length`] for malformed input.
    pub fn from_display_hex(s: &str) -> Result<Self, BsvError> {
        let mut bytes = hex_to_array32(s)?;
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Format as display (big-endian) hex.
    #[must_use]
    pub fn to_display_hex(&self) -> String {
        let mut rev = self.0;
        rev.reverse();
        bytes_to_hex(&rev)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_display_hex())
    }
}

/// SHA-256 applied twice (REQ-BSV-002). Output is internal byte order.
#[must_use]
pub fn double_sha256(data: &[u8]) -> Hash256 {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(second.as_slice());
    Hash256(out)
}

/// SHA-256 once (REQ-BSV-003).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// SHA-256 then RIPEMD-160 (REQ-BSV-003), for P2PKH.
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(rip.as_slice());
    out
}

/// Decode hex to bytes without panicking or indexing out of bounds.
///
/// # Errors
/// Returns [`BsvError::Hex`] on odd length or a non-hex character.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, BsvError> {
    if !s.len().is_multiple_of(2) {
        return Err(BsvError::Hex);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_val(*pair.first().ok_or(BsvError::Hex)?)?;
        let lo = hex_val(*pair.get(1).ok_or(BsvError::Hex)?)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Encode bytes to lower-hex.
#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn hex_to_array32(s: &str) -> Result<[u8; 32], BsvError> {
    let v = hex_to_bytes(s)?;
    v.as_slice().try_into().map_err(|_| BsvError::Length {
        expected: 32,
        got: v.len(),
    })
}

fn hex_val(c: u8) -> Result<u8, BsvError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(BsvError::Hex),
    }
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0' + n),
        _ => char::from(b'a' + (n - 10)),
    }
}
