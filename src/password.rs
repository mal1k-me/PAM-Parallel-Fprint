//! Password authentication module
//!
//! Handles password input and verification through PAM's conversation function.

use std::ffi::{CStr, CString};
use libc::c_char;
use crate::AuthResult;
use crate::AuthData;
use crate::auth_data::{PamHandle, CancellationToken};
use std::sync::{Arc, Mutex};

/// PAM conversation item types
const PAM_PROMPT_ECHO_OFF: i32 = 1;

/// PAM conversation response type
#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: i32,
}

/// PAM conversation message type
#[repr(C)]
pub struct PamMessage {
    pub msg_style: i32,
    pub msg: *const c_char,
}

extern "C" {
    /// Set PAM item
    pub fn pam_set_item(
        pamh: *const std::ffi::c_void,
        item_type: i32,
        item: *const std::ffi::c_void,
    ) -> i32;

    /// Get PAM item
    pub fn pam_get_item(
        pamh: *const std::ffi::c_void,
        item_type: i32,
        item: *mut *const std::ffi::c_void,
    ) -> i32;
}

const PAM_CONV: i32 = 2;
const PAM_AUTHTOK: i32 = 6;
const PAM_SUCCESS: i32 = 0;

/// Check password by prompting the user through PAM conversation
pub fn check_password(
    _username: &str,
    pamh: PamHandle,
    auth_data: Arc<Mutex<AuthData>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    // Check if fingerprint already succeeded
    {
        let data = auth_data.lock().map_err(|e| format!("Lock error: {}", e))?;
        if data.is_done() {
            return Ok(());
        }
    }

    // Get the PAM conversation function
    let conv_ptr = unsafe {
        let mut conv_ptr: *const std::ffi::c_void = std::ptr::null();
        let ret = pam_get_item(pamh.as_ptr(), PAM_CONV, &mut conv_ptr as *mut _);
        if ret != PAM_SUCCESS || conv_ptr.is_null() {
            return Err("Failed to get PAM conversation function".to_string());
        }
        conv_ptr
    };

    // Prompt for password
    let prompt = CString::new("Fingerprint or Password: ")
        .map_err(|_| "Failed to create prompt string".to_string())?;

    // Call conversation function
    unsafe {
        // Define conversation function type
        type PamConvFn = extern "C" fn(
            num_msg: i32,
            msg: *const *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut std::ffi::c_void,
        ) -> i32;

        let conv_fn: PamConvFn = std::mem::transmute(conv_ptr);

        // Prepare message
        let msg = PamMessage {
            msg_style: PAM_PROMPT_ECHO_OFF,
            msg: prompt.as_ptr(),
        };
        let msg_ptr = &msg as *const _;
        let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

        let ret = conv_fn(
            1,
            &msg_ptr as *const _,
            &mut resp_ptr as *mut _,
            std::ptr::null_mut(),
        );

        if ret == PAM_SUCCESS && !resp_ptr.is_null() && !(*resp_ptr).resp.is_null() {
            // Get the password from response
            let password_cstr = CStr::from_ptr((*resp_ptr).resp);
            let password_cstring = CString::from(password_cstr);

            // Set the password in PAM
            pam_set_item(
                pamh.as_ptr(),
                PAM_AUTHTOK,
                password_cstring.as_ptr() as *const std::ffi::c_void,
            );

            // Mark as password entered
            if let Ok(mut data) = auth_data.lock() {
                data.set_result(AuthResult::PasswordEntered);
                data.mark_done();
                cancel_token.cancel();
            }
        }
    }

    Ok(())
}
