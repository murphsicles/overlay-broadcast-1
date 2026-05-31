//! Block header parse/serialise/hash and proof-of-work target (REQ-BSV-040).
use crate::error::BsvError;
use crate::hash::{double_sha256, Hash256};

/// The fixed serialized length of a BSV block header.
pub const HEADER_LEN: usize = 80;

/// An 80-byte BSV block header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block version.
    pub version: i32,
    /// Hash of the previous block's header (internal order).
    pub prev_block_hash: Hash256,
    /// Merkle root of the block's transactions (internal order).
    pub merkle_root: Hash256,
    /// Block timestamp (seconds).
    pub time: u32,
    /// Compact proof-of-work target.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl BlockHeader {
    /// Parse from exactly 80 bytes.
    ///
    /// # Errors
    /// Returns [`BsvError::Length`] / [`BsvError::Truncated`] for malformed input.
    pub fn parse(raw: &[u8]) -> Result<Self, BsvError> {
        if raw.len() != HEADER_LEN {
            return Err(BsvError::Length {
                expected: HEADER_LEN,
                got: raw.len(),
            });
        }
        Ok(Self {
            version: i32::from_le_bytes(read4(raw, 0)?),
            prev_block_hash: Hash256::from_internal(read32(raw, 4)?),
            merkle_root: Hash256::from_internal(read32(raw, 36)?),
            time: u32::from_le_bytes(read4(raw, 68)?),
            bits: u32::from_le_bytes(read4(raw, 72)?),
            nonce: u32::from_le_bytes(read4(raw, 76)?),
        })
    }

    /// Serialise to exactly 80 bytes (round-trips with [`BlockHeader::parse`]).
    #[must_use]
    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        write_at(&mut out, 0, &self.version.to_le_bytes());
        write_at(&mut out, 4, self.prev_block_hash.internal());
        write_at(&mut out, 36, self.merkle_root.internal());
        write_at(&mut out, 68, &self.time.to_le_bytes());
        write_at(&mut out, 72, &self.bits.to_le_bytes());
        write_at(&mut out, 76, &self.nonce.to_le_bytes());
        out
    }

    /// The block hash: double-SHA-256 of the serialized header (internal order).
    #[must_use]
    pub fn block_hash(&self) -> Hash256 {
        double_sha256(&self.serialize())
    }

    /// Whether the block hash meets the target encoded in `bits`.
    #[must_use]
    pub fn meets_target(&self) -> bool {
        let target = target_from_bits(self.bits);
        let mut hash_be = *self.block_hash().internal();
        hash_be.reverse();
        hash_be <= target
    }
}

fn read4(raw: &[u8], off: usize) -> Result<[u8; 4], BsvError> {
    let end = off.checked_add(4).ok_or(BsvError::OutOfRange)?;
    raw.get(off..end)
        .ok_or(BsvError::Truncated)?
        .try_into()
        .map_err(|_| BsvError::Truncated)
}

fn read32(raw: &[u8], off: usize) -> Result<[u8; 32], BsvError> {
    let end = off.checked_add(32).ok_or(BsvError::OutOfRange)?;
    raw.get(off..end)
        .ok_or(BsvError::Truncated)?
        .try_into()
        .map_err(|_| BsvError::Truncated)
}

fn write_at(out: &mut [u8], off: usize, src: &[u8]) {
    if let Some(end) = off.checked_add(src.len()) {
        if let Some(dst) = out.get_mut(off..end) {
            dst.copy_from_slice(src);
        }
    }
}

/// Decode the compact `bits` into a big-endian 256-bit target.
fn target_from_bits(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) & 0xff;
    let mantissa = bits & 0x007f_ffff;
    let m = mantissa.to_le_bytes(); // m[0] LSB .. m[2] MSB, m[3] = 0
    let mut be = [0u8; 32];
    let base = 32i64 - i64::from(exponent);
    // Most-significant mantissa byte at big-endian index (32 - exponent), then the
    // next two bytes after it.
    for (k, mb) in [m.get(2), m.get(1), m.first()]
        .into_iter()
        .flatten()
        .enumerate()
    {
        let offset = i64::try_from(k).unwrap_or(0);
        let idx = base + offset;
        if (0..32).contains(&idx) {
            if let Ok(u) = usize::try_from(idx) {
                if let Some(slot) = be.get_mut(u) {
                    *slot = *mb;
                }
            }
        }
    }
    be
}
