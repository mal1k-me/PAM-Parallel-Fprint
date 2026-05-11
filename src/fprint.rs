//! Fingerprint authentication module
//!
//! Handles fingerprint verification through fprintd D-Bus service.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use crate::auth_data::AuthData;
use crate::AuthResult;

const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);
const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(30);

/// Check fingerprint authentication
pub fn check_fingerprint(
    username: &str,
    auth_data: &Arc<Mutex<AuthData>>,
) -> Result<(), String> {
    // Note: Full D-Bus integration with fprintd would go here.
    // For now, we poll the auth_data for completion.
    // In a real implementation, this would:
    // 1. Connect to system D-Bus
    // 2. Call fprintd methods to claim device
    // 3. Listen for VerifyStatus signals
    // 4. Update auth_data when fingerprint matches

    // Simulate fingerprint scanning delay
    let start = std::time::Instant::now();
    
    while start.elapsed() < FINGERPRINT_TIMEOUT {
        // Check if authentication is complete
        if let Ok(data) = auth_data.lock() {
            if data.is_done() {
                return Ok(());
            }
        }
        
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
