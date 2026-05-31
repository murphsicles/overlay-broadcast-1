//! Typed, non-secret errors (REQ-GOV-012): no error message embeds secret material.
use thiserror::Error;

/// Memory-locking failure (best-effort; callers treat as non-fatal, REQ-SECMEM-003).
#[derive(Debug, Error)]
pub enum LockError {
    /// The OS refused to lock the region into RAM.
    #[error("memory lock failed")]
    Lock,
    /// The OS refused to unlock the region.
    #[error("memory unlock failed")]
    Unlock,
}

/// Random-source failure (REQ-SECMEM-005).
#[derive(Debug, Error)]
pub enum RandError {
    /// The OS CSPRNG could not provide entropy.
    #[error("OS CSPRNG failure")]
    Os,
}
