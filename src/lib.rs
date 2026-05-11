#![deny(warnings)]
#![warn(missing_docs)]

//! PAM Parallel Fprint Module
//!
//! A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel.
//! Users can authenticate using either a fingerprint match or by entering their password.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::ffi::CStr;
use libc::{c_int, c_char};

mod auth_data;
mod fprint;
mod password;

pub use auth_data::AuthData;

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
const PAM_OPEN_ERR: c_int = 1;
const PAM_SYMBOL_ERR: c_int = 2;
const PAM_SERVICE_ERR: c_int = 3;
const PAM_SYSTEM_ERR: c_int = 4;
const PAM_BUF_ERR: c_int = 5;
const PAM_PERM_DENIED: c_int = 6;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CRED_INSUFFICIENT: c_int = 8;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_USER_UNKNOWN: c_int = 10;
const PAM_MAXTRIES: c_int = 11;
const PAM_NEW_AUTHTOK_REQD: c_int = 12;
const PAM_ACCT_EXPIRED: c_int = 13;
const PAM_SESSION_ERR: c_int = 14;
const PAM_CRED_UNAVAIL: c_int = 15;
const PAM_CRED_EXPIRED: c_int = 16;
const PAM_CRED_ERR: c_int = 17;
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
}

/// Helper function to get username from PAM handle
fn get_pam_user(pamh: *const std::ffi::c_void) -> Option<String> {
    // SAFETY: This is safe because we're calling a well-defined C FFI function
    // with valid pointers. The PAM library guarantees user_ptr will be valid
    // if the call succeeds.
    #[allow(unsafe_code)]
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
    pamh: *const std::ffi::c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // Get username
    let username = match get_pam_user(pamh) {
        Some(u) => u,
        None => return PAM_USER_UNKNOWN,
    };

    // Create shared authentication data
    let auth_data = Arc::new(Mutex::new(AuthData::new()));

    // Spawn fingerprint authentication task
    let fp_data = Arc::clone(&auth_data);
    let fp_username = username.clone();
    
    let fp_handle = std::thread::spawn(move || {
        let _ = fprint::check_fingerprint(&fp_username, &fp_data);
    });

    // Spawn password authentication task
    let pwd_data = Arc::clone(&auth_data);
    let pwd_username = username.clone();
    
    let pwd_handle = std::thread::spawn(move || {
        let _ = password::check_password(&pwd_username, &pwd_data);
    });

    // Wait for either thread to complete or timeout
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > GLOBAL_TIMEOUT {
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

    // Wait for threads to complete with timeout
    let _ = fp_handle.join();
    let _ = pwd_handle.join();

    // Get final authentication result
    let data = auth_data.lock().unwrap();
    match data.get_result() {
        AuthResult::FingerprintMatch => PAM_SUCCESS,
        AuthResult::PasswordEntered => PAM_IGNORE,
        AuthResult::Failed => PAM_AUTH_ERR,
    }
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
