//! The generic secret container (REQ-SECMEM-001).
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A container for a secret value that: zeroizes its contents on drop; prints only
/// `Secret(<redacted>)` in `Debug`; and implements neither `Display`, `Serialize`,
/// nor `Clone`, so the contents cannot leak through a trait. Access is explicit and
/// auditable via [`Secret::expose`].
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Wrap a secret value.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Borrow the secret. Every call site is an auditable point of exposure.
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the secret (e.g. to fill it in place).
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// The Drop above fulfils the ZeroizeOnDrop contract.
impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
