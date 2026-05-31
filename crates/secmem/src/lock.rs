//! Best-effort memory locking (REQ-SECMEM-003). This is the SINGLE unsafe-bearing
//! module in the workspace (REQ-GOV-010): the crate root denies `unsafe_code` and
//! each FFI call below is individually re-enabled with `#[allow(unsafe_code)]` and a
//! `// SAFETY:` justification. Locking keeps secret pages out of swap; where it is
//! unavailable the caller falls back safely (no panic, one structured warning).
use crate::error::LockError;

/// Pin the region `[ptr, ptr + len)` into RAM. A zero-length region is a no-op.
pub fn lock_region(ptr: *const u8, len: usize) -> Result<(), LockError> {
    if len == 0 {
        return Ok(());
    }
    platform_lock(ptr, len)
}

/// Release a previously pinned region. A zero-length region is a no-op.
pub fn unlock_region(ptr: *const u8, len: usize) -> Result<(), LockError> {
    if len == 0 {
        return Ok(());
    }
    platform_unlock(ptr, len)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_lock(ptr: *const u8, len: usize) -> Result<(), LockError> {
    use windows_sys::Win32::System::Memory::VirtualLock;
    // SAFETY: `ptr`/`len` describe a live, owned allocation (a `Zeroizing<Vec<u8>>`
    // buffer the caller keeps alive for the lock's whole lifetime). `VirtualLock`
    // only pins the existing pages; it never writes, frees, or aliases the memory.
    let ok = unsafe { VirtualLock(ptr.cast::<core::ffi::c_void>(), len) };
    if ok != 0 {
        Ok(())
    } else {
        Err(LockError::Lock)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_unlock(ptr: *const u8, len: usize) -> Result<(), LockError> {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    // SAFETY: the same region was previously locked by `platform_lock`; `VirtualUnlock`
    // only unpins existing pages and does not write, free, or alias the memory.
    let ok = unsafe { VirtualUnlock(ptr.cast::<core::ffi::c_void>(), len) };
    if ok != 0 {
        Ok(())
    } else {
        Err(LockError::Unlock)
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn platform_lock(ptr: *const u8, len: usize) -> Result<(), LockError> {
    // SAFETY: `ptr`/`len` describe a live, owned allocation; `mlock` only pins the
    // existing pages into RAM and never writes, frees, or aliases the memory.
    let rc = unsafe { libc::mlock(ptr.cast::<core::ffi::c_void>(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(LockError::Lock)
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn platform_unlock(ptr: *const u8, len: usize) -> Result<(), LockError> {
    // SAFETY: the same region was previously locked by `platform_lock`; `munlock`
    // only unpins existing pages and does not write, free, or alias the memory.
    let rc = unsafe { libc::munlock(ptr.cast::<core::ffi::c_void>(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(LockError::Unlock)
    }
}

#[cfg(not(any(windows, unix)))]
fn platform_lock(_ptr: *const u8, _len: usize) -> Result<(), LockError> {
    Err(LockError::Lock)
}

#[cfg(not(any(windows, unix)))]
fn platform_unlock(_ptr: *const u8, _len: usize) -> Result<(), LockError> {
    Err(LockError::Unlock)
}
