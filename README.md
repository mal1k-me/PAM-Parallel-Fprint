# PAM Parallel Fprint

Caution: This project is a proof of concept implementation created as a learning exercise. It is not production-ready and should not be used in production environments without significant additional testing, security auditing, and hardening.

## Overview

PAM Parallel Fprint is a Linux PAM (Pluggable Authentication Modules) module that enables concurrent fingerprint and password authentication. The module allows users to authenticate using either method - whichever completes first within the configured timeout.

## Features

- Parallel authentication execution using system threads
- Support for both fingerprint (via fprintd) and password authentication
- Configurable authentication timeout (default: 30 seconds)
- Thread-safe shared state management
- Pure Rust implementation with minimal dependencies

## Current Status

This is a proof of concept implementation. The following limitations apply:

- Integration with SDDM is not supported due to how SDDM handles PAM authorization
- Fingerprint authentication is currently a placeholder implementation
- Password authentication requires integration with the PAM conversation function
- No production security hardening or extensive testing has been performed

## Project Structure

The project maintains two implementations:

- master branch: Original C implementation
- rust branch: Modern Rust implementation with improved safety

## Installation (Not Recommended)

If you wish to experiment with this proof of concept:

1. Build the module: `cargo build --release`
2. The compiled library is located at: `target/release/libpam_parallel_fprint.so`
3. Review the `add_to_pam` file for PAM configuration guidance
4. Apply configuration changes to files in `/etc/pam.d/`

## Development

### Requirements

- Rust 1.92.0 or later
- Linux development headers
- D-Bus development libraries (for fprintd integration)

### Building

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release
```

### Module Components

The Rust implementation consists of:

- `lib.rs`: PAM module entry points and authentication orchestration
- `auth_data.rs`: Thread-safe shared authentication state
- `fprint.rs`: Fingerprint authentication handler (placeholder)
- `password.rs`: Password authentication handler (placeholder)

## Security Considerations

Before using this module in any context:

- Review the source code for potential security issues
- Conduct security testing appropriate for your use case
- Consider the implications of parallel authentication attempts
- Ensure proper timeout configuration to prevent denial of service
- Test thoroughly in isolated environments

## Limitations and Future Work

- Complete fprintd D-Bus integration
- PAM conversation function integration for password prompts
- Support for additional authentication methods
- Comprehensive test suite
- Security audit
- Performance optimization

## License

GPL-3.0
