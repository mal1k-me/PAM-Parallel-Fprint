#![deny(warnings)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! PAM Parallel Fprint Module
//!
//! A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel.
//! Users can authenticate using either a fingerprint match or by entering their password.

use pam::module::{PamHandle, PamError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use thiserror::Error;

mod fprint;
mod password;
mod auth_data;
mod logging;

pub use auth_data::AuthData;
pub use fprint::check_fingerprint;
pub use password::check_password;
pub use logging::init_logging;

/// Result type for PAM operations
pub type PamResult<T> = Result<T, PamError>;

/// Authentication result variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Fingerprint matched successfully
    FingerprintMatch,
    /// Password was entered
    PasswordEntered,
    /// No authentication method succeeded
    Failed,
}

/// Custom error types for authentication module
#[derive(Debug, Error)]
pub enum AuthError {
    /// D-Bus communication error
    #[error("D-Bus error: {0}")]
    DBusError(String),
    
    /// Fingerprint device error
    #[error("Fingerprint device error: {0}")]
    DeviceError(String),
    
    /// Timeout during authentication
    #[error("Authentication timeout")]
    Timeout,
    
    /// Thread communication error
    #[error("Thread communication error: {0}")]
    ThreadError(String),
    
    /// PAM error
    #[error("PAM error: {0}")]
    PamError(String),
}

/// Timeout constants
pub const GLOBAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEVICE_CLAIM_RETRY_TIMEOUT: Duration = Duration::from_millis(1000);
pub const MAX_DEVICE_CLAIM_RETRIES: u32 = 5;
pub const DBUS_WAIT_TIMEOUT: Duration = Duration::from_millis(100);

/// Main PAM authentication entry point
/// 
/// # Arguments
/// * `pamh` - PAM handle
/// * `flags` - PAM flags
/// * `_argc` - Argument count (unused)
/// * `_argv` - Argument array (unused)
///
/// # Returns
/// * `PAM_SUCCESS` - Fingerprint matched
/// * `PAM_IGNORE` - Password entered, pass to next module
/// * `PAM_AUTH_ERR` - Authentication failed or timeout
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam::bindings::pam_handle_t,
    flags: pam::bindings::c_int,
    _argc: pam::bindings::c_int,
    _argv: *const *const pam::bindings::c_char,
) -> pam::bindings::c_int {
    init_logging();
    
    let handle = match PamHandle::new(pamh) {
        Ok(h) => h,
        Err(e) => {
            log_error(&format!("Failed to create PAM handle: {}", e));
            return PamError::User as pam::bindings::c_int;
        }
    };

    // Get username
    let username = match handle.get_user(None) {
        Ok(u) => u.to_string(),
        Err(e) => {
            log_error(&format!("Failed to get username: {}", e));
            return PamError::User as pam::bindings::c_int;
        }
    };

    // Create shared authentication data
    let auth_data = Arc::new(Mutex::new(AuthData::new()));
    let notify = Arc::new(Notify::new());

    // Spawn fingerprint authentication task
    let fp_data = Arc::clone(&auth_data);
    let fp_notify = Arc::clone(&notify);
    let fp_username = username.clone();
    
    let fp_handle = std::thread::spawn(move || {
        if let Err(e) = check_fingerprint(&fp_username, &fp_data, &fp_notify) {
            log_error(&format!("Fingerprint check failed: {}", e));
        }
    });

    // Spawn password authentication task
    let pwd_data = Arc::clone(&auth_data);
    let pwd_notify = Arc::clone(&notify);
    let pwd_username = username.clone();
    let pwd_handle_clone = unsafe {
        // SAFETY: We're creating a handle just for passing to the password thread.
        // The original handle remains valid in this function scope.
        std::mem::transmute::<*mut pam::bindings::pam_handle_t, *mut pam::bindings::pam_handle_t>(pamh)
    };
    
    let pwd_handle = std::thread::spawn(move || {
        let pam_h = PamHandle::new(pwd_handle_clone);
        if let Ok(h) = pam_h {
            if let Err(e) = check_password(&pwd_username, &h, &pwd_data, &pwd_notify) {
                log_error(&format!("Password check failed: {}", e));
            }
        }
    });

    // Wait for either thread to complete or timeout
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > GLOBAL_TIMEOUT {
            log_error("Authentication timeout exceeded");
            let _ = notify.notify_waiters();
            break;
        }

        let data = auth_data.lock().unwrap();
        if data.is_done() {
            drop(data);
            break;
        }
        drop(data);

        std::thread::sleep(Duration::from_millis(50));
    }

    // Signal threads to shutdown
    notify.notify_waiters();

    // Wait for threads to complete
    let _ = fp_handle.join();
    let _ = pwd_handle.join();

    // Get final authentication result
    let data = auth_data.lock().unwrap();
    let result = match data.get_result() {
        AuthResult::FingerprintMatch => {
            log_info("Authentication successful via fingerprint");
            PamError::Success as pam::bindings::c_int
        }
        AuthResult::PasswordEntered => {
            log_info("Password entered, passing to next module");
            PamError::Ignore as pam::bindings::c_int
        }
        AuthResult::Failed => {
            log_error("Authentication failed");
            PamError::Auth as pam::bindings::c_int
        }
    };

    result
}

/// Set credentials PAM function (required stub)
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam::bindings::pam_handle_t,
    _flags: pam::bindings::c_int,
    _argc: pam::bindings::c_int,
    _argv: *const *const pam::bindings::c_char,
) -> pam::bindings::c_int {
    PamError::Success as pam::bindings::c_int
}

/// Account management PAM function (required stub)
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam::bindings::pam_handle_t,
    _flags: pam::bindings::c_int,
    _argc: pam::bindings::c_int,
    _argv: *const *const pam::bindings::c_char,
) -> pam::bindings::c_int {
    PamError::Success as pam::bindings::c_int
}

/// Log info level message
fn log_info(msg: &str) {
    logging::log(syslog::Facility::AuthPriv.to_string(), syslog::Severity::Informational, msg);
}

/// Log error level message
fn log_error(msg: &str) {
    logging::log(syslog::Facility::AuthPriv.to_string(), syslog::Severity::Error, msg);
}
