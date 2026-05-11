//! Authentication data shared between threads
//!
//! Provides a thread-safe way to share authentication state between
//! fingerprint and password authentication tasks.

use crate::AuthResult;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared authentication data
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
