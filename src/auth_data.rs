//! Shared authentication data structure with thread-safe synchronization

use crate::AuthResult;

/// Thread-safe authentication state
#[derive(Debug)]
pub struct AuthData {
    result: AuthResult,
    done: bool,
}

impl AuthData {
    /// Create a new authentication data structure
    pub fn new() -> Self {
        Self {
            result: AuthResult::Failed,
            done: false,
        }
    }

    /// Check if authentication is complete
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Get the authentication result
    pub fn get_result(&self) -> AuthResult {
        self.result
    }

    /// Set fingerprint match result
    pub fn set_fingerprint_match(&mut self) {
        self.result = AuthResult::FingerprintMatch;
        self.done = true;
    }

    /// Set password entered result
    pub fn set_password_entered(&mut self) {
        self.result = AuthResult::PasswordEntered;
        self.done = true;
    }

    /// Mark authentication as failed
    pub fn set_failed(&mut self) {
        self.result = AuthResult::Failed;
        self.done = true;
    }
}

impl Default for AuthData {
    fn default() -> Self {
        Self::new()
    }
}
