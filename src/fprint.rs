//! Fingerprint authentication module
//!
//! Handles fingerprint verification through fprintd D-Bus service.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use crate::auth_data::{AuthData, CancellationToken};

const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);
const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(30);

/// Check fingerprint authentication via D-Bus/fprintd
pub fn check_fingerprint(
    username: &str,
    auth_data: Arc<Mutex<AuthData>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    // Check if we should cancel
    if cancel_token.is_cancelled() {
        return Ok(());
    }

    // Attempt D-Bus connection
    let result = attempt_dbus_fingerprint(username, auth_data.clone(), cancel_token.clone());
    
    // If D-Bus fails, just poll until timeout
    if result.is_err() {
        poll_for_completion(auth_data, cancel_token);
    }
    
    Ok(())
}

/// Attempt to use D-Bus/fprintd for fingerprint authentication
fn attempt_dbus_fingerprint(
    username: &str,
    auth_data: Arc<Mutex<AuthData>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    // Try to connect to system D-Bus
    use zbus::blocking::Connection;

    let conn = Connection::system()
        .map_err(|_| "D-Bus not available".to_string())?;

    // Get default device
    let device_path = get_default_device(&conn)?;
    
    // Claim device with retries
    let mut retries = 0;
    loop {
        if cancel_token.is_cancelled() {
            return Ok(());
        }

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

    // Wait for fingerprint match
    wait_for_match(&conn, &device_path, auth_data, cancel_token)?;

    // Release device
    let _ = release_device(&conn, &device_path);

    Ok(())
}

/// Get default fingerprint device from fprintd
fn get_default_device(conn: &zbus::blocking::Connection) -> Result<zbus::zvariant::OwnedObjectPath, String> {
    let reply = conn
        .call_method(
            Some("net.reactivated.Fprint"),
            "/net/reactivated/Fprint/Manager",
            Some("net.reactivated.Fprint.Manager"),
            "GetDefaultDevice",
            &(),
        )
        .map_err(|e| format!("GetDefaultDevice failed: {}", e))?;

    let body = reply.body();
    let path: zbus::zvariant::ObjectPath = body
        .deserialize()
        .map_err(|e| format!("Failed to parse device path: {}", e))?;

    Ok(path.into())
}

/// Claim the device for this user
fn claim_device(
    conn: &zbus::blocking::Connection,
    device_path: &zbus::zvariant::OwnedObjectPath,
    username: &str,
) -> Result<(), String> {
    conn.call_method(
        Some("net.reactivated.Fprint"),
        device_path,
        Some("net.reactivated.Fprint.Device"),
        "Claim",
        &(username,),
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("AlreadyInUse") {
            "AlreadyInUse".to_string()
        } else {
            msg
        }
    })?;

    Ok(())
}

/// Start fingerprint verification
fn start_verification(
    conn: &zbus::blocking::Connection,
    device_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<(), String> {
    conn.call_method(
        Some("net.reactivated.Fprint"),
        device_path,
        Some("net.reactivated.Fprint.Device"),
        "VerifyStart",
        &("any",),
    )
    .map_err(|e| format!("VerifyStart failed: {}", e))?;

    Ok(())
}

/// Wait for fingerprint match signal
fn wait_for_match(
    _conn: &zbus::blocking::Connection,
    _device_path: &zbus::zvariant::OwnedObjectPath,
    auth_data: Arc<Mutex<AuthData>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    // Poll for completion with timeout
    let start = std::time::Instant::now();
    
    while start.elapsed() < FINGERPRINT_TIMEOUT {
        if cancel_token.is_cancelled() {
            return Ok(());
        }

        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                return Ok(());
            }
        }
        
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

/// Release the device
fn release_device(
    conn: &zbus::blocking::Connection,
    device_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<(), String> {
    conn.call_method(
        Some("net.reactivated.Fprint"),
        device_path,
        Some("net.reactivated.Fprint.Device"),
        "Release",
        &(),
    )
    .map_err(|e| format!("Release failed: {}", e))?;

    Ok(())
}

/// Poll for authentication completion
fn poll_for_completion(
    auth_data: Arc<Mutex<AuthData>>,
    cancel_token: CancellationToken,
) {
    let start = std::time::Instant::now();
    
    while start.elapsed() < FINGERPRINT_TIMEOUT {
        if cancel_token.is_cancelled() {
            return;
        }

        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                return;
            }
        }
        
        thread::sleep(Duration::from_millis(100));
    }
}
