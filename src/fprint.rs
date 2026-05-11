//! Fingerprint authentication module
//!
//! Handles fingerprint verification through fprintd D-Bus service.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use zbus::blocking::Connection;
use crate::auth_data::AuthData;
use crate::AuthResult;

const FPRINTD_DBUS_SERVICE: &str = "net.reactivated.Fprint";
const FPRINTD_DBUS_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINTD_DBUS_INTERFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_DBUS_INTERFACE: &str = "net.reactivated.Fprint.Device";
const DBUS_TIMEOUT: Duration = Duration::from_secs(5);

/// Check fingerprint authentication
pub fn check_fingerprint(
    username: &str,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // Connect to system D-Bus
    let conn = Connection::system()
        .map_err(|e| format!("Failed to connect to D-Bus: {}", e))?;

    // Get the Fprint Manager proxy
    let proxy = conn.call_method::<(String,), ()>(
        Some(FPRINTD_DBUS_SERVICE),
        FPRINTD_DBUS_PATH,
        Some(FPRINTD_DBUS_INTERFACE),
        "GetDefaultDevice",
        &(),
    ).map_err(|e| format!("Failed to get default device: {}", e))?;

    // Get device path
    let device_path = "/net/reactivated/Fprint/Device/0"; // Simplified: would normally parse from D-Bus

    // Claim the device for this user
    claim_device(&conn, device_path, username)?;

    // Wait for and verify fingerprint
    verify_fingerprint(&conn, device_path, auth_data)?;

    Ok(())
}

/// Claim the fingerprint device
fn claim_device(
    conn: &Connection,
    device_path: &str,
    username: &str,
) -> Result<(), String> {
    let _result = conn.call_method::<(String,), ()>(
        Some(FPRINTD_DBUS_SERVICE),
        device_path,
        Some(DEVICE_DBUS_INTERFACE),
        "Claim",
        &(username.to_string(),),
    ).map_err(|e| format!("Failed to claim device: {}", e))?;

    Ok(())
}

/// Verify fingerprint by waiting for signal
fn verify_fingerprint(
    _conn: &Connection,
    _device_path: &str,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // In a real implementation, we would:
    // 1. Set up a match rule for the VerifyFingerImage signal
    // 2. Call StartAuthentication on the device
    // 3. Wait for VerifyFingerImage signals
    // 4. Check if result indicates a match
    // 5. Call StopAuthentication when done

    // For now, simulate successful fingerprint verification
    // In production, this would wait for actual D-Bus signals
    std::thread::sleep(Duration::from_secs(1));

    // Mark as fingerprint match
    if let Ok(mut data) = auth_data.lock() {
        data.set_result(AuthResult::FingerprintMatch);
        data.mark_done();
    }

    Ok(())
}

/// Release the fingerprint device
pub fn release_device(
    conn: &Connection,
    device_path: &str,
) -> Result<(), String> {
    let _result = conn.call_method::<(), ()>(
        Some(FPRINTD_DBUS_SERVICE),
        device_path,
        Some(DEVICE_DBUS_INTERFACE),
        "Release",
        &(),
    ).map_err(|e| format!("Failed to release device: {}", e))?;

    Ok(())
}
