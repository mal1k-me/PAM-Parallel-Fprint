# PAM Parallel Fprint - Rust Implementation

A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel, written in Rust with zero unsafe code and strict compiler settings.

## Features

- **Parallel Authentication**: Users can authenticate using either fingerprint or password simultaneously
- **Thread-Safe**: Uses Rust's type system for memory safety and thread-safe synchronization
- **Timeout Protection**: Global 30-second timeout prevents indefinite hangs
- **D-Bus Integration**: Communicates with fprintd via system D-Bus
- **Zero Warnings**: Compiled with strict Rust compiler settings (`#![deny(warnings)]`)
- **No Unsafe Code**: 100% safe Rust (`#![forbid(unsafe_code)]`)

## Requirements

- Linux system with PAM
- fprintd service installed and configured
- Rust 1.70+
- libpam-dev headers
- systemd-devel headers

## Building

```bash
cargo build --release
```

The compiled PAM module will be located at `target/release/libpam_parallel_fprint.so`

## Installation

1. Build the project:
   ```bash
   cargo build --release
   ```

2. Copy the compiled module to PAM directory:
   ```bash
   sudo cp target/release/libpam_parallel_fprint.so /usr/lib/security/
   ```

3. Add to your PAM configuration file (e.g., `/etc/pam.d/sudo` or `/etc/pam.d/polkit-1`):
   ```
   auth    [success=done default=ignore]   pam_parallel_fprint.so
   auth    required    pam_unix.so try_first_pass
   ```

## How It Works

1. When authentication is requested, the module spawns two concurrent threads:
   - **Fingerprint Thread**: Connects to fprintd via D-Bus, claims the device, and waits for a fingerprint match
   - **Password Thread**: Prompts the user for a password

2. Whichever method succeeds first determines the result:
   - **Fingerprint Match** → Returns `PAM_SUCCESS` (user authenticated)
   - **Password Entered** → Returns `PAM_IGNORE` (passes to next PAM module, typically `pam_unix.so`)
   - **Timeout or Failure** → Returns `PAM_AUTH_ERR` (authentication failed)

3. All operations are protected by timeouts:
   - Global timeout: 30 seconds
   - Device claim retry: 1 second (max 5 attempts)

## Limitations

- Does not work with SDDM due to its PAM handling approach
- Best suited for CLI applications like `sudo`, `su`, or `polkit-1`
- Requires fprintd to be properly configured on your system

## Security Notes

- **No unsafe code**: The module uses only safe Rust constructs
- **Mutex-protected state**: All shared data is protected by mutexes
- **Timeout mechanisms**: Prevents indefinite hangs
- **Error logging**: All authentication failures are logged to syslog

## Troubleshooting

Check syslog for errors:
```bash
sudo journalctl -u pam_parallel_fprint -f
# or
tail -f /var/log/auth.log | grep pam_parallel_fprint
```

## License

GNU General Public License v3.0 - See LICENSE file
