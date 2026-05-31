//! Zeroizing secret byte buffer with constant-time equality and best-effort page
//! locking (REQ-SECMEM-002/003/004).
use crate::error::RandError;
use crate::lock;
use crate::random::SecureRandom;
use core::fmt;
use std::sync::Once;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

static LOCK_WARN: Once = Once::new();

/// A secret byte buffer: zeroized on drop, compared in constant time, and (best
/// effort) locked into RAM. Constructed only from a [`SecureRandom`] source or an
/// explicit key-import (`from_slice`), so secret bytes never rest in a non-zeroizing
/// temporary (REQ-SECMEM-004).
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SecretBytes {
    /// Import secret bytes from a caller-owned slice (an explicit key-import API).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }

    /// Generate `len` secret bytes from a secure random source.
    ///
    /// # Errors
    /// Returns [`RandError`] if the random source fails.
    pub fn random(rng: &mut impl SecureRandom, len: usize) -> Result<Self, RandError> {
        // The zeroed buffer is filled in place and then MOVED (not copied) into the
        // zeroizing container, so the secret never exists in a separate temporary.
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf)?;
        Ok(Self::from_vec(buf))
    }

    fn from_vec(buf: Vec<u8>) -> Self {
        let bytes = Zeroizing::new(buf);
        let locked = match lock::lock_region(bytes.as_ptr(), bytes.len()) {
            Ok(()) => true,
            Err(_) => {
                LOCK_WARN.call_once(|| {
                    eprintln!("secmem: memory locking unavailable; secrets may be swappable");
                });
                false
            }
        };
        Self { bytes, locked }
    }

    /// Borrow the secret bytes (an auditable point of exposure).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// The length in bytes (length is not secret).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Constant-time equality over the contents (length is compared first and is not
    /// secret). REQ-SECMEM-002.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        bool::from(self.bytes.as_slice().ct_eq(other.bytes.as_slice()))
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        if self.locked {
            // Best-effort unlock before the Zeroizing buffer zeroes and frees the
            // pages; an unlock failure here is non-fatal (REQ-GOV-018 discard).
            let _ = lock::unlock_region(self.bytes.as_ptr(), self.bytes.len());
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted; {} bytes>)", self.bytes.len())
    }
}
