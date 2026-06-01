//! Typed KeyStore errors (REQ-KST-001). No secret material appears in any message.
use thiserror::Error;

/// Errors from a [`crate::KeyStore`] backend.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KstError {
    /// A backend operation failed (the message names the cause, never a secret).
    #[error("keystore backend error: {0}")]
    Backend(&'static str),
    /// The supplied key/passphrase did not authenticate the material (wrong KEK).
    #[error("wrong key or passphrase")]
    WrongKey,
    /// No entry exists for the given key id.
    #[error("key not found")]
    NotFound,
    /// Invalid parameters (e.g. Shamir threshold > shares).
    #[error("invalid parameters")]
    BadParams,
    /// Too few shares to reconstruct.
    #[error("insufficient shares")]
    InsufficientShares,
    /// The requested key is marked non-exportable and cannot be exported.
    #[error("key is non-exportable")]
    NonExportable,
    /// A cryptographic operation failed.
    #[error("crypto failure")]
    Crypto,
    /// A randomness draw failed.
    #[error("randomness failure")]
    Random,
}
