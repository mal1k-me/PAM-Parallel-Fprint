//! Fingerprint authentication module
//!
//! Handles fingerprint verification through fprintd D-Bus service.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use zbus::blocking::Connection;
use zbus::zvariant::ObjectPath;
use crate::auth_data::AuthData;
use crate::AuthResult;

const FPRINTD_SERVICE: &str = "net.reactivated.Fprint";
const FPRINTD_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINTD_MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const FPRINTD_DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";
const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Check fingerprint authentication
pub fn check_fingerprint(
    username: &str,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // Connect to system D-Bus
    let conn = Connection::system()
        .map_err(|e| format!("Failed to connect to D-Bus: {}", e))?;

    // Get default device path
    let device_path = get_default_device(&conn)?;

    // Claim device with retry logic
    let mut retries = 0;
    loop {
        match claim_device(&conn, &device_path, username) {
            Ok(_) => break,
            Err(e) if e.contains("AlreadyInUse") && retries < MAX_RETRIES => {
                retries += 1;
                thread::sleep(RETRY_DELAY);
            }
            Err(e) => return Err(format!("Failed to claim device: {}", e)),
        }
    }

    // Start verification
    start_verification(&conn, &device_path)?;

    // Wait for fingerprint result via D-Bus signals
    wait_for_fingerprint(&conn, &device_path, auth_data)?;

    // Release device
    let _ = release_device(&conn, &device_path);

    Ok(())
}

/// Get default fingerprint device path from fprintd
fn get_default_device(conn: &Connection) -> Result<ObjectPath, String> {
    conn.call_method(
        Some(FPRINTD_SERVICE),
        FPRINTD_MANAGER_PATH,
        Some(FPRINTD_MANAGER_IFACE),
        "GetDefaultDevice",
        &(),
    )
    .map_err(|e| format!("Failed to get default device: {}", e))
}

/// Claim the fingerprint device for authentication
fn claim_device(conn: &Connection, device_path: &ObjectPath, username: &str) -> Result<(), String> {
    conn.call_method(
        Some(FPRINTD_SERVICE),
        device_path,
        Some(FPRINTD_DEVICE_IFACE),
        "Claim",
        &(username,),
    )
    .map_err(|e| {
        let err_msg = e.to_string();
        if err_msg.contains("AlreadyInUse") {
            "AlreadyInUse".to_string()
        } else {
            err_msg
        }
    })
}

/// Start fingerprint verification on the device
fn start_verification(conn: &Connection, device_path: &ObjectPath) -> Result<(), String> {
    conn.call_method(
        Some(FPRINTD_SERVICE),
        device_path,
        Some(FPRINTD_DEVICE_IFACE),
        "VerifyStart",
        &("any",),
    )
    .map_err(|e| format!("Failed to start verification: {}", e))
}

/// Wait for fingerprint verification result via D-Bus signals
fn wait_for_fingerprint(
    conn: &Connection,
    device_path: &ObjectPath,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // Set up match rule for VerifyStatus signals
    let match_rule = format!(
        "type='signal',interface='{}',member='VerifyStatus',path='{}'",
        FPRINTD_DEVICE_IFACE,
        device_path.as_str()
    );

    let _rule = conn
        .add_match(&match_rule)
        .map_err(|e| format!("Failed to add D-Bus match rule: {}", e))?;

    // Listen for signals with timeout
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(30);

    loop {
        if start.elapsed() > timeout {
            break; // Timeout reached
        }

        // Check if already authenticated
        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                return Ok(());
            }
        }

        // Try to receive messages with short timeout
        match conn.receive_message(Duration::from_millis(100)) {
            Ok(msg) => {
                if check_verify_status_signal(&msg, auth_data) {
                    return Ok(());
                }
            }
            Err(_) => {
                // Timeout on receive, continue polling
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    Ok(())
}

/// Check if a D-Bus message is a VerifyStatus signal with a match result
fn check_verify_status_signal(
    msg: &zbus::Message,
    auth_data: &Arc<Mutex<AuthData>>,
) -> bool {
    // Try to parse the signal
    if let Ok(body) = msg.body::<(String, bool)>() {
        if body.0 == "verify-match" {
            // Fingerprint matched!
            if let Ok(mut data) = auth_data.lock() {
                data.set_result(AuthResult::FingerprintMatch);
                data.mark_done();
                return true;
            }
        }
    }
    false
}

/// Release the fingerprint device
fn release_device(conn: &Connection, device_path: &ObjectPath) -> Result<(), String> {
    conn.call_method(
        Some(FPRINTD_SERVICE),
        device_path,
        Some(FPRINTD_DEVICE_IFACE),
        "Release",
        &(),
    )
    .map_err(|e| format!("Failed to release device: {}", e))
}
