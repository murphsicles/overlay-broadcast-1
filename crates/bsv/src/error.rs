//! Typed, non-secret BSV errors (REQ-GOV-012).
use thiserror::Error;

/// Errors from BSV parsing, hashing, and chain validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BsvError {
    /// Input was not valid hexadecimal.
    #[error("invalid hex")]
    Hex,
    /// A fixed-length field had the wrong length.
    #[error("invalid length: expected {expected}, got {got}")]
    Length {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },
    /// Input ended before a required field was complete.
    #[error("truncated input")]
    Truncated,
    /// A header did not link to the current chain tip.
    #[error("header does not link to chain tip")]
    ChainNotLinked,
    /// A header's proof-of-work did not meet its encoded target.
    #[error("insufficient proof-of-work")]
    ChainBadPow,
    /// A header was added at a non-monotonic height.
    #[error("non-monotonic height")]
    ChainNonMonotonic,
    /// A merkle root or proof did not verify.
    #[error("merkle verification failed")]
    MerkleMismatch,
    /// A numeric value exceeded its valid range / a bound was exceeded.
    #[error("value out of range")]
    OutOfRange,
    /// A transaction was malformed.
    #[error("malformed transaction")]
    MalformedTx,
    /// A script was malformed.
    #[error("malformed script")]
    MalformedScript,
    /// SIGHASH_SINGLE was requested for an input with no corresponding output
    /// (the classic SIGHASH_SINGLE bug); refused (REQ-BSV-031).
    #[error("SIGHASH_SINGLE input index has no corresponding output")]
    SighashSingleIndex,
}
