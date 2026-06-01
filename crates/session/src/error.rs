//! Typed session errors (REQ-GOV-012).
use thiserror::Error;

/// Errors from the GB session lifecycle.
#[derive(Debug, Error)]
pub enum SesError {
    /// A BSV construction/sighash operation failed.
    #[error("bsv error: {0}")]
    Bsv(#[from] bsv::BsvError),
    /// A signing operation failed.
    #[error("signing failed: {0}")]
    Ckd(#[from] ckd::CkdError),
    /// The session structure was invalid (e.g. no members).
    #[error("invalid session structure")]
    BadStructure,
    /// A member/broadcaster index was out of range.
    #[error("index out of range")]
    BadIndex,
    /// The subscription has no further funded sessions.
    #[error("subscription exhausted")]
    Exhausted,
    /// An invalid (zero) member fee.
    #[error("invalid member fee")]
    BadFee,
}
