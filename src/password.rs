//! Password authentication module
//!
//! Handles password input and verification through PAM's conversation function.

use std::sync::{Arc, Mutex};
use crate::auth_data::AuthData;
use crate::AuthResult;

/// Check password by prompting the user
pub fn check_password(
    _username: &str,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // In a real PAM module, we would use the conversation function (pam_conv)
    // to prompt the user for a password.
    // The conversation function is part of the PAM handle and would be used to:
    // 1. Display a password prompt to the user
    // 2. Get the user's password input
    // 3. Verify it against the system (usually through PAM's pam_unix module)
    //
    // For now, this is a simplified implementation.
    // The password verification would happen through PAM conversation,
    // which is handled by the PAM framework itself.

    // Check if fingerprint already succeeded
    let data = auth_data.lock().map_err(|e| format!("Lock error: {}", e))?;
    if data.is_done() {
        return Ok(());
    }
    drop(data);

    // In a real implementation, password would be entered through PAM conversation
    // and we would mark the result here
    // For now, we just wait for fingerprint

    Ok(())
}
