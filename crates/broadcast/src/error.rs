//! Typed broadcast errors (REQ-GOV-012).
use thiserror::Error;

/// Errors from the GB broadcast layer.
#[derive(Debug, Error)]
pub enum BcsError {
    /// The requested graph structure is unsupported (e.g. not a power-of-two user set).
    #[error("unsupported broadcast graph structure")]
    BadStructure,
    /// A node key was missing during item generation or decryption.
    #[error("missing node key")]
    MissingKey,
    /// The user is not eligible (not in the graph, or holds a wrong/revoked key).
    #[error("user is not eligible to decrypt")]
    NotEligible,
    /// A cipher (wrap/unwrap/AEAD) operation failed.
    #[error("cipher failure: {0}")]
    Cipher(#[from] cipher::CipherError),
    /// A graph operation failed.
    #[error("graph error: {0}")]
    Graph(#[from] keygraph::KgError),
    /// A secure-random draw failed.
    #[error("randomness failure")]
    Random,
}
