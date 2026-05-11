#![warn(missing_docs)]

//! PAM Parallel Fprint Module
//!
//! A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel.
//! Users can authenticate using either a fingerprint match or by entering their password.
//!
//! ## Architecture
//!
//! The module spawns two concurrent threads:
//! 1. **Fingerprint Thread**: Connects to fprintd via D-Bus, monitors for fingerprint matches
//! 2. **Password Thread**: Prompts user via PAM conversation function
//!
//! The first to complete sets the authentication result and cancels the other thread.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::ffi::CStr;
use libc::{c_int, c_char};

mod auth_data;
mod fprint;
mod password;

pub use auth_data::{AuthData, CancellationToken, PamHandle};

/// Timeout constants
pub const GLOBAL_TIMEOUT: Duration = Duration::from_secs(30);

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

/// PAM error codes
const PAM_SUCCESS: c_int = 0;
#[allow(dead_code)] // For future use
const PAM_OPEN_ERR: c_int = 1;
#[allow(dead_code)] // For future use
const PAM_SYMBOL_ERR: c_int = 2;
#[allow(dead_code)] // For future use
const PAM_SERVICE_ERR: c_int = 3;
#[allow(dead_code)] // For future use
const PAM_SYSTEM_ERR: c_int = 4;
#[allow(dead_code)] // For future use
const PAM_BUF_ERR: c_int = 5;
#[allow(dead_code)] // For future use
const PAM_PERM_DENIED: c_int = 6;
const PAM_AUTH_ERR: c_int = 7;
#[allow(dead_code)] // For future use
const PAM_CRED_INSUFFICIENT: c_int = 8;
#[allow(dead_code)] // For future use
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_USER_UNKNOWN: c_int = 10;
#[allow(dead_code)] // For future use
const PAM_MAXTRIES: c_int = 11;
#[allow(dead_code)] // For future use
const PAM_NEW_AUTHTOK_REQD: c_int = 12;
#[allow(dead_code)] // For future use
const PAM_ACCT_EXPIRED: c_int = 13;
#[allow(dead_code)] // For future use
const PAM_SESSION_ERR: c_int = 14;
#[allow(dead_code)] // For future use
const PAM_CRED_UNAVAIL: c_int = 15;
#[allow(dead_code)] // For future use
const PAM_CRED_EXPIRED: c_int = 16;
#[allow(dead_code)] // For future use
const PAM_CRED_ERR: c_int = 17;
#[allow(dead_code)] // For future use
const PAM_NO_MODULE_DATA: c_int = 18;
const PAM_IGNORE: c_int = 25;

// C extern functions for PAM
extern "C" {
    /// Get user from PAM handle
    pub fn pam_get_user(
        pamh: *const std::ffi::c_void,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    /// Check if file descriptor is a terminal
    pub fn isatty(fd: c_int) -> c_int;

    /// Flush terminal input
    pub fn tcflush(fd: c_int, queue_selector: c_int) -> c_int;
}

const TCIFLUSH: c_int = 0;
const STDIN_FILENO: c_int = 0;

/// Helper function to get username from PAM handle
fn get_pam_user(pamh: *const std::ffi::c_void) -> Option<String> {
    // SAFETY: This is safe because we're calling a well-defined C FFI function
    // with valid pointers. The PAM library guarantees user_ptr will be valid
    // if the call succeeds.
    unsafe {
        let mut user_ptr: *const c_char = std::ptr::null();
        let ret = pam_get_user(pamh, &mut user_ptr as *mut _, std::ptr::null());
        
        if ret == PAM_SUCCESS && !user_ptr.is_null() {
            CStr::from_ptr(user_ptr)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        } else {
            None
        }
    }
}

/// Check if running in a terminal
fn is_terminal() -> bool {
    unsafe { isatty(STDIN_FILENO) == 1 }
}

/// Flush terminal input buffer
fn flush_terminal() {
    unsafe {
        let _ = tcflush(STDIN_FILENO, TCIFLUSH);
    }
}

/// Main PAM authentication entry point
///
/// This function implements true parallel authentication:
/// - Spawns fingerprint thread for D-Bus/fprintd communication
/// - Spawns password thread for PAM conversation prompting
/// - Waits for either to complete within 30-second timeout
/// - Returns appropriate PAM code based on which succeeded
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
    pamh: *const std::ffi::c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let in_terminal = is_terminal();

    // Get username
    let username = match get_pam_user(pamh) {
        Some(u) => u,
        None => return PAM_USER_UNKNOWN,
    };

    // Create shared authentication data and cancellation token
    let auth_data = Arc::new(Mutex::new(AuthData::new()));
    let cancel_token = CancellationToken::new();
    let pam_handle = PamHandle::new(pamh);

    // Spawn fingerprint authentication thread
    let fp_data = Arc::clone(&auth_data);
    let fp_cancel = cancel_token.clone();
    let fp_username = username.clone();
    
    let fp_handle = std::thread::spawn(move || {
        let _ = fprint::check_fingerprint(&fp_username, fp_data, fp_cancel);
    });

    // Spawn password authentication thread
    let pwd_data = Arc::clone(&auth_data);
    let pwd_cancel = cancel_token.clone();
    let pwd_username = username.clone();
    
    let pwd_handle = std::thread::spawn(move || {
        let _ = password::check_password(&pwd_username, pam_handle, pwd_data, pwd_cancel);
    });

    // Wait for either thread to complete or timeout
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > GLOBAL_TIMEOUT {
            cancel_token.cancel();
            break;
        }

        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                cancel_token.cancel();
                drop(data);
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    // Wait for both threads to complete
    let _ = fp_handle.join();
    let _ = pwd_handle.join();

    // Get final authentication result
    let data = auth_data.lock().unwrap();
    let result = match data.get_result() {
        AuthResult::FingerprintMatch => {
            if in_terminal {
                println!();
            }
            PAM_SUCCESS
        }
        AuthResult::PasswordEntered => PAM_IGNORE,
        AuthResult::Failed => PAM_AUTH_ERR,
    };

    drop(data);

    // Flush terminal if in terminal
    if in_terminal {
        flush_terminal();
    }

    result
}

/// Set credentials PAM function (required stub)
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *const std::ffi::c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Account management PAM function (required stub)
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *const std::ffi::c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
