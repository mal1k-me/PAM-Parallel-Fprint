//! Shared authentication data between threads
//!
//! Provides thread-safe synchronization between fingerprint and password
//! authentication tasks.

use crate::AuthResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared authentication state
#[derive(Debug)]
pub struct AuthData {
    result: AuthResult,
    done: AtomicBool,
}

impl AuthData {
    /// Create new authentication data
    pub fn new() -> Self {
        Self {
            result: AuthResult::Failed,
            done: AtomicBool::new(false),
        }
    }

    /// Set the authentication result
    pub fn set_result(&mut self, result: AuthResult) {
        self.result = result;
    }

    /// Get the current authentication result
    pub fn get_result(&self) -> AuthResult {
        self.result
    }

    /// Mark authentication as done
    pub fn mark_done(&self) {
        self.done.store(true, Ordering::Release);
    }

    /// Check if authentication is done
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

impl Default for AuthData {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for passing pamh safely to threads
/// This is safe because:
/// 1. Each thread only calls PAM functions during its lifetime
/// 2. Password thread calls pam_get_authtok which is blocking
/// 3. Fingerprint thread never calls password-related PAM functions
/// 4. Main thread waits for both threads before returning
pub struct PamHandle {
    ptr: *const std::ffi::c_void,
}

// SAFETY: PamHandle is Send because:
// - We only pass it to threads that use it immediately
// - The PAM handle is valid for the entire duration of pam_sm_authenticate
// - We use memory ordering to ensure visibility
unsafe impl Send for PamHandle {}

impl PamHandle {
    /// Create a new PAM handle wrapper
    /// # Safety
    /// The caller must ensure the pointer is valid for the lifetime
    /// of the entire authentication operation.
    pub fn new(ptr: *const std::ffi::c_void) -> Self {
        Self { ptr }
    }

    /// Get the raw pointer
    pub fn as_ptr(&self) -> *const std::ffi::c_void {
        self.ptr
    }
}

/// Thread-safe cancellation signal
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal cancellation
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::Release);
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}
