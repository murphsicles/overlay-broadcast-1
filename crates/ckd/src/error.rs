//! Typed CKD errors (REQ-GOV-012); no secret material in any message.
use thiserror::Error;

/// Errors from child key derivation and the signature pin.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CkdError {
    /// A private key was not a valid secp256k1 scalar.
    #[error("invalid private key")]
    BadKey,
    /// A public key was not a valid secp256k1 point.
    #[error("invalid public key")]
    BadPublicKey,
    /// A derivation index was invalid for the requested mode.
    #[error("invalid derivation index")]
    InvalidIndex,
    /// A derivation produced an invalid child (negligible probability); the caller
    /// should advance to the next index per BIP32.
    #[error("derivation produced an invalid child")]
    DerivationFailed,
    /// Hardened derivation was requested without the parent private key.
    #[error("hardened derivation requires the parent private key")]
    HardenedNeedsPrivate,
}
