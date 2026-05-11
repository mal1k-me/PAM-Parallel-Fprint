//! Password authentication via PAM

use crate::{AuthData, AuthError};
use pam::module::PamHandle;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Check password authentication
///
/// Prompts the user for a password and sets it in the PAM handle.
/// Returns immediately with password set if successful.
pub fn check_password(
    _username: &str,
    pamh: &PamHandle,
    auth_data: &Arc<Mutex<AuthData>>,
    _notify: &Arc<Notify>,
) -> Result<(), AuthError> {
    // Get authentication token from user
    let password = pamh
        .get_authtok("Fingerprint or Password: ")
        .map_err(|e| AuthError::PamError(format!("Failed to get auth token: {}", e)))?;

    // Set the token in PAM for the next module (pam_unix.so)
    pamh.set_item(pam::module::PamItem::AuthTok(password.to_string()))
        .map_err(|e| AuthError::PamError(format!("Failed to set auth token: {}", e)))?;

    // Mark password as entered
    let mut data = auth_data.lock().map_err(|e| {
        AuthError::ThreadError(format!("Failed to lock auth data: {}", e))
    })?;
    data.set_password_entered();

    Ok(())
}
