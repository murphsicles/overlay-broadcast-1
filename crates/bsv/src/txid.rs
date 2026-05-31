//! Transaction id: a hash with display-order formatting and a total order for
//! deterministic sorting (REQ-BSV-010).
use crate::error::BsvError;
use crate::hash::{double_sha256, Hash256};
use core::fmt;

/// A transaction id (double-SHA-256 of the raw transaction, internal order).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txid(Hash256);

impl Txid {
    /// Wrap a hash as a txid.
    #[must_use]
    pub const fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Parse from display (big-endian) hex.
    ///
    /// # Errors
    /// Propagates [`Hash256::from_display_hex`] errors.
    pub fn from_display_hex(s: &str) -> Result<Self, BsvError> {
        Ok(Self(Hash256::from_display_hex(s)?))
    }

    /// Format as display (big-endian) hex.
    #[must_use]
    pub fn to_display_hex(&self) -> String {
        self.0.to_display_hex()
    }

    /// Borrow as a [`Hash256`] (e.g. to use as a merkle leaf).
    #[must_use]
    pub const fn as_hash(&self) -> &Hash256 {
        &self.0
    }

    /// Compute the txid of raw transaction bytes.
    #[must_use]
    pub fn of_tx_bytes(raw: &[u8]) -> Self {
        Self(double_sha256(raw))
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({})", self.0.to_display_hex())
    }
}
