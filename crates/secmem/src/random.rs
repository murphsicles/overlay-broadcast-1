//! Secure randomness (REQ-SECMEM-005). Production uses the OS CSPRNG. A
//! deterministic, seedable variant exists ONLY under `cfg(test)` or the
//! `test-deterministic` feature, so it is compiled out of — and unreachable from —
//! production builds.
use crate::error::RandError;

/// A source of cryptographically secure random bytes.
pub trait SecureRandom {
    /// Fill `dst` entirely with secure random bytes, or return a typed error.
    ///
    /// # Errors
    /// Returns [`RandError::Os`] if the underlying entropy source fails.
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), RandError>;
}

/// The production source: the operating-system CSPRNG.
#[derive(Debug, Default)]
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), RandError> {
        getrandom::getrandom(dst).map_err(|_| RandError::Os)
    }
}

/// A deterministic, seedable SplitMix64 source for reproducible tests ONLY. Never
/// compiled into production (REQ-SECMEM-005). NOT cryptographically secure.
#[cfg(any(test, feature = "test-deterministic"))]
#[derive(Debug)]
pub struct DeterministicRng {
    state: u64,
}

#[cfg(any(test, feature = "test-deterministic"))]
impl DeterministicRng {
    /// Create a deterministic source from a seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

#[cfg(any(test, feature = "test-deterministic"))]
impl SecureRandom for DeterministicRng {
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), RandError> {
        for chunk in dst.chunks_mut(8) {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            for (d, s) in chunk.iter_mut().zip(z.to_le_bytes().iter()) {
                *d = *s;
            }
        }
        Ok(())
    }
}
