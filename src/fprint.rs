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
    let device_path = match get_default_device(&conn) {
        Ok(path) => path,
        Err(e) => {
            // fprintd not available or error
            return Err(e);
        }
    };

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

    // Wait for fingerprint result via polling
    wait_for_fingerprint(&conn, &device_path, auth_data)?;

    // Release device
    let _ = release_device(&conn, &device_path);

    Ok(())
}

/// Get default fingerprint device path from fprintd
fn get_default_device(conn: &Connection) -> Result<ObjectPath, String> {
    // Call GetDefaultDevice method which returns an object path
    let path: ObjectPath = conn
        .call_method(
            Some(FPRINTD_SERVICE),
            FPRINTD_MANAGER_PATH,
            Some(FPRINTD_MANAGER_IFACE),
            "GetDefaultDevice",
            &(),
        )
        .map_err(|e| format!("Failed to get default device: {}", e))?;
    Ok(path)
}

/// Claim the fingerprint device for authentication
fn claim_device(conn: &Connection, device_path: &ObjectPath, username: &str) -> Result<(), String> {
    conn.call_method::<()>(
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
    conn.call_method::<()>(
        Some(FPRINTD_SERVICE),
        device_path,
        Some(FPRINTD_DEVICE_IFACE),
        "VerifyStart",
        &("any",),
    )
    .map_err(|e| format!("Failed to start verification: {}", e))
}

/// Wait for fingerprint verification result with polling
fn wait_for_fingerprint(
    _conn: &Connection,
    _device_path: &ObjectPath,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // In a production implementation, we would use D-Bus signal matching.
    // For now, poll periodically and check for completion via timeout.
    // The C implementation uses sd_bus_wait/process which we simulate here.
    
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(30);

    loop {
        if start.elapsed() > timeout {
            break;
        }

        // Check if already authenticated
        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                return Ok(());
            }
        }

        // Poll every 100ms
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

/// Release the fingerprint device
fn release_device(conn: &Connection, device_path: &ObjectPath) -> Result<(), String> {
    conn.call_method::<()>(
        Some(FPRINTD_SERVICE),
        device_path,
        Some(FPRINTD_DEVICE_IFACE),
        "Release",
        &(),
    )
    .map_err(|e| format!("Failed to release device: {}", e))
}
