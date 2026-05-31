//! The header chain: the single root of trust (REQ-BSV-041/042).
use crate::error::BsvError;
use crate::hash::Hash256;
use crate::header::BlockHeader;
use std::collections::HashMap;

/// An append-only, validated chain of block headers. Validation enforces previous-
/// hash linkage, proof-of-work meeting the encoded target, and monotonic
/// non-decreasing height. `merkle_root_at_height` is what every chain-terminating
/// inclusion check resolves against (REQ-BSV-042).
#[derive(Debug, Default)]
pub struct HeaderChain {
    headers: Vec<BlockHeader>,
    start_height: u64,
    by_root: HashMap<Hash256, u64>,
}

impl HeaderChain {
    /// Create a chain whose first added header sits at `start_height`.
    #[must_use]
    pub fn new(start_height: u64) -> Self {
        Self {
            headers: Vec::new(),
            start_height,
            by_root: HashMap::new(),
        }
    }

    /// Validate-and-append a header. The first header sets the base; each later
    /// header must link to the current tip and meet its target.
    ///
    /// # Errors
    /// [`BsvError::ChainNotLinked`] / [`BsvError::ChainBadPow`] / [`BsvError::OutOfRange`].
    pub fn add(&mut self, header: BlockHeader) -> Result<(), BsvError> {
        if let Some(tip) = self.headers.last() {
            if header.prev_block_hash != tip.block_hash() {
                return Err(BsvError::ChainNotLinked);
            }
        }
        if !header.meets_target() {
            return Err(BsvError::ChainBadPow);
        }
        let height = self.next_height()?;
        self.by_root.insert(header.merkle_root, height);
        self.headers.push(header);
        Ok(())
    }

    /// Append, asserting the new header sits at exactly `expected` height.
    ///
    /// # Errors
    /// [`BsvError::ChainNonMonotonic`] if the next height is not `expected`.
    pub fn add_at_height(&mut self, header: BlockHeader, expected: u64) -> Result<(), BsvError> {
        if self.next_height()? != expected {
            return Err(BsvError::ChainNonMonotonic);
        }
        self.add(header)
    }

    /// The height of the tip, or `None` if empty.
    #[must_use]
    pub fn tip_height(&self) -> Option<u64> {
        let len = u64::try_from(self.headers.len()).ok()?;
        len.checked_sub(1)
            .and_then(|d| self.start_height.checked_add(d))
    }

    /// The merkle root committed by the header at `height`, if present.
    #[must_use]
    pub fn merkle_root_at_height(&self, height: u64) -> Option<Hash256> {
        let idx = height.checked_sub(self.start_height)?;
        let i = usize::try_from(idx).ok()?;
        self.headers.get(i).map(|h| h.merkle_root)
    }

    /// The height of a header committing to `root`, if any.
    #[must_use]
    pub fn contains_merkle_root(&self, root: &Hash256) -> Option<u64> {
        self.by_root.get(root).copied()
    }

    fn next_height(&self) -> Result<u64, BsvError> {
        let len = u64::try_from(self.headers.len()).map_err(|_| BsvError::OutOfRange)?;
        self.start_height
            .checked_add(len)
            .ok_or(BsvError::OutOfRange)
    }
}
