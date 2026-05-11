//! Logging utilities for syslog integration

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize logging to syslog
pub fn init_logging() {
    INIT.call_once(|| {
        let _ = syslog::init(
            syslog::Facility::AuthPriv,
            log::LevelFilter::Info,
            Some("pam_parallel_fprint"),
        );
    });
}

/// Log a message to syslog
pub fn log(facility: String, severity: syslog::Severity, msg: &str) {
    let _ = syslog::log(severity, msg);
}
