//! Fingerprint authentication via fprintd D-Bus service

use crate::{AuthData, AuthError, DEVICE_CLAIM_RETRY_TIMEOUT, MAX_DEVICE_CLAIM_RETRIES, DBUS_WAIT_TIMEOUT};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Check fingerprint authentication
///
/// Connects to fprintd via D-Bus, claims the device, starts verification,
/// and waits for the verify-match signal.
pub fn check_fingerprint(
    username: &str,
    auth_data: &Arc<Mutex<AuthData>>,
    notify: &Arc<Notify>,
) -> Result<(), AuthError> {
    // Connect to system D-Bus
    let conn = zbus::blocking::Connection::system()
        .map_err(|e| AuthError::DBusError(format!("Failed to connect to system bus: {}", e)))?;

    // Get default fingerprint device
    let device_path = get_device_path(&conn)
        .map_err(|e| {
            crate::logging::log(
                "auth".to_string(),
                syslog::Severity::Error,
                &format!("Failed to get device path: {}", e),
            );
            e
        })?;

    // Claim the device with retry logic
    claim_device(&conn, &device_path, username)
        .map_err(|e| {
            crate::logging::log(
                "auth".to_string(),
                syslog::Severity::Error,
                &format!("Failed to claim device: {}", e),
            );
            e
        })?;

    // Start fingerprint verification
    start_verification(&conn, &device_path)
        .map_err(|e| {
            crate::logging::log(
                "auth".to_string(),
                syslog::Severity::Error,
                &format!("Failed to start verification: {}", e),
            );
            let _ = release_device(&conn, &device_path);
            e
        })?;

    // Listen for verification result signals
    wait_for_verification(&conn, &device_path, auth_data, notify)
        .map_err(|e| {
            crate::logging::log(
                "auth".to_string(),
                syslog::Severity::Error,
                &format!("Verification wait failed: {}", e),
            );
            let _ = release_device(&conn, &device_path);
            e
        })?;

    // Release the device
    release_device(&conn, &device_path).ok();

    Ok(())
}

/// Get the default fingerprint device path from fprintd
fn get_device_path(conn: &zbus::blocking::Connection) -> Result<String, AuthError> {
    let proxy = zbus::blocking::Proxy::new(
        conn,
        "net.reactivated.Fprint",
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
    )
    .map_err(|e| AuthError::DBusError(format!("Failed to create proxy: {}", e)))?;

    let result: String = proxy
        .call_method("GetDefaultDevice", &())
        .map_err(|e| AuthError::DBusError(format!("GetDefaultDevice failed: {}", e)))?;

    Ok(result)
}

/// Claim the fingerprint device for the user
///
/// Retries up to MAX_DEVICE_CLAIM_RETRIES times if device is already in use.
fn claim_device(conn: &zbus::blocking::Connection, device_path: &str, username: &str) -> Result<(), AuthError> {
    for attempt in 0..MAX_DEVICE_CLAIM_RETRIES {
        let proxy = zbus::blocking::Proxy::new(
            conn,
            "net.reactivated.Fprint",
            device_path,
            "net.reactivated.Fprint.Device",
        )
        .map_err(|e| AuthError::DBusError(format!("Failed to create device proxy: {}", e)))?;

        match proxy.call_method("Claim", &(username,)) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < MAX_DEVICE_CLAIM_RETRIES - 1 {
                    crate::logging::log(
                        "auth".to_string(),
                        syslog::Severity::Warning,
                        &format!("Device in use, retrying ({}/{})", attempt + 1, MAX_DEVICE_CLAIM_RETRIES),
                    );
                    std::thread::sleep(DEVICE_CLAIM_RETRY_TIMEOUT);
                } else {
                    return Err(AuthError::DeviceError(format!("Failed to claim device: {}", e)));
                }
            }
        }
    }

    Err(AuthError::DeviceError("Max device claim retries exceeded".to_string()))
}

/// Start fingerprint verification
fn start_verification(conn: &zbus::blocking::Connection, device_path: &str) -> Result<(), AuthError> {
    let proxy = zbus::blocking::Proxy::new(
        conn,
        "net.reactivated.Fprint",
        device_path,
        "net.reactivated.Fprint.Device",
    )
    .map_err(|e| AuthError::DBusError(format!("Failed to create device proxy: {}", e)))?;

    proxy
        .call_method("VerifyStart", &("any",))
        .map_err(|e| AuthError::DBusError(format!("VerifyStart failed: {}", e)))?;

    Ok(())
}

/// Wait for fingerprint verification result
///
/// Monitors D-Bus signals for VerifyStatus and marks authentication as complete
/// when a "verify-match" signal is received.
fn wait_for_verification(
    conn: &zbus::blocking::Connection,
    device_path: &str,
    auth_data: &Arc<Mutex<AuthData>>,
    notify: &Arc<Notify>,
) -> Result<(), AuthError> {
    // Create a match rule for VerifyStatus signals
    let match_rule = format!(
        "type='signal',path='{}',interface='net.reactivated.Fprint.Device',member='VerifyStatus'",
        device_path
    );

    conn.add_match(&match_rule)
        .map_err(|e| AuthError::DBusError(format!("Failed to add match rule: {}", e)))?;

    // Set up signal stream
    let stream = conn
        .add_match_no_cache(&match_rule)
        .map_err(|e| AuthError::DBusError(format!("Failed to set up signal stream: {}", e)))?;

    // Monitor signals for verification result
    let start_time = std::time::Instant::now();
    loop {
        // Check if authentication is already complete (from other thread)
        {
            let data = auth_data.lock().map_err(|e| {
                AuthError::ThreadError(format!("Failed to lock auth data: {}", e))
            })?;
            if data.is_done() {
                return Ok(());
            }
        }

        // Check if global timeout exceeded
        if start_time.elapsed() > crate::GLOBAL_TIMEOUT {
            let mut data = auth_data.lock().map_err(|e| {
                AuthError::ThreadError(format!("Failed to lock auth data: {}", e))
            })?;
            data.set_failed();
            return Err(AuthError::Timeout);
        }

        // Poll D-Bus for incoming signals
        match conn.receive_message_with_timeout(DBUS_WAIT_TIMEOUT) {
            Ok(Some(msg)) => {
                // Check if this is a VerifyStatus signal
                if let Ok((result, done)) = msg.body::<(String, bool)>() {
                    if result == "verify-match" {
                        let mut data = auth_data.lock().map_err(|e| {
                            AuthError::ThreadError(format!("Failed to lock auth data: {}", e))
                        })?;
                        data.set_fingerprint_match();
                        notify.notify_waiters();
                        return Ok(());
                    } else if done {
                        let mut data = auth_data.lock().map_err(|e| {
                            AuthError::ThreadError(format!("Failed to lock auth data: {}", e))
                        })?;
                        if !data.is_done() {
                            data.set_failed();
                        }
                        notify.notify_waiters();
                        return Ok(());
                    }
                }
            }
            Ok(None) => {
                // Timeout, continue waiting
                std::thread::sleep(DBUS_WAIT_TIMEOUT);
            }
            Err(e) => {
                return Err(AuthError::DBusError(format!("Failed to receive message: {}", e)));
            }
        }
    }
}

/// Release the fingerprint device
fn release_device(conn: &zbus::blocking::Connection, device_path: &str) -> Result<(), AuthError> {
    let proxy = zbus::blocking::Proxy::new(
        conn,
        "net.reactivated.Fprint",
        device_path,
        "net.reactivated.Fprint.Device",
    )
    .map_err(|e| AuthError::DBusError(format!("Failed to create device proxy: {}", e)))?;

    proxy
        .call_method("Release", &())
        .map_err(|e| AuthError::DBusError(format!("Release failed: {}", e)))?;

    Ok(())
}
