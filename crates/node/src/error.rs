//! Typed node-client errors.
use thiserror::Error;

/// Errors from the node-submission client.
#[derive(Debug, Error)]
pub enum NodeError {
    /// HTTP transport failure (unreachable node, timeout).
    #[error("node transport error")]
    Http,
    /// The node returned a JSON-RPC error.
    #[error("node rpc error: {0}")]
    Rpc(String),
    /// A malformed or unexpected response.
    #[error("malformed node response")]
    Decode,
}
