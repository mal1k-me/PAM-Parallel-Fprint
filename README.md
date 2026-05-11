# PAM Parallel Fprint

> [!CAUTION]
> This project is a proof of concept implementation created as a learning exercise. It is not production-ready and should not be used in production environments without significant additional testing, security auditing, and hardening.

## Overview

PAM Parallel Fprint is a Linux PAM (Pluggable Authentication Modules) module written in Rust that enables concurrent fingerprint and password authentication. The module spawns two independent threads that run in parallel: one monitors for fingerprint matches via D-Bus communication with fprintd, while the other prompts the user for password input through the PAM conversation function. The first authentication method to succeed determines the authentication result, with atomic signaling ensuring clean cancellation of the competing thread.

## Architecture

### Core Design Philosophy

The module implements a race-based authentication model where fingerprint scanning and password entry compete in parallel. This approach provides users with immediate feedback (the password prompt appears instantly) while background fingerprint scanning occurs simultaneously. The implementation prioritizes memory safety and thread coordination without sacrificing responsiveness or feature completeness compared to the original C implementation.

### Parallel Execution Model

Unlike traditional sequential authentication where password prompting waits for fingerprint scanning to complete or timeout, this module starts both authentication flows immediately upon entering `pam_sm_authenticate`. The fingerprint thread connects to the D-Bus system bus to communicate with fprintd, performing device management operations and monitoring for verification signals. Concurrently, the password thread uses PAM's conversation function to display the "Fingerprint or Password:" prompt and wait for user input. Both threads maintain references to shared state through thread-safe primitives.

The main authentication thread polls the shared authentication state every 50 milliseconds, checking if either method has completed or if the global 30-second timeout has elapsed. Once one thread successfully authenticates or the timeout expires, an atomic cancellation token is set to `true`, signaling the other thread to exit cleanly. This design ensures that if a user places their finger on the scanner before typing their password, fingerprint authentication can succeed immediately without waiting for password input, and vice versa.

### Thread Safety and Memory Management

The Rust implementation uses several abstractions to safely handle the complexity of cross-thread communication and PAM pointer passing. The `PamHandle` wrapper is explicitly marked as `Send`, allowing the PAM handle pointer to be shared across threads with documented safety guarantees. The PAM library's blocking operations (particularly `pam_get_authtok`) ensure that password authentication is atomic from the PAM perspective—once a thread starts the conversation function, it maintains exclusive control until completion. The fingerprint thread never calls password-related PAM functions, and the architecture guarantees that the main thread does not return until both spawned threads have completed via explicit `join()` calls.

Shared state is protected through `Arc<Mutex<AuthData>>`, which coordinates the result and completion status between threads. The `CancellationToken` uses an `Arc<AtomicBool>` with `Acquire`/`Release` memory ordering to ensure visibility of the cancellation signal across all threads without explicit locking. This design avoids deadlock scenarios while providing the necessary synchronization guarantees.

## Project Structure

The Rust implementation is organized into modular components that separate concerns while maintaining a clear flow of data and control. The `lib.rs` file contains the main PAM entry points (`pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`) and orchestrates thread spawning and result collection. The `auth_data.rs` module defines the thread-safe shared state structures, including `AuthData` for storing authentication results, `CancellationToken` for signaling thread cancellation, and `PamHandle` for safe pointer passing. The `fprint.rs` module contains all D-Bus communication logic, handling device discovery, claiming, verification startup, and signal listening. The `password.rs` module implements password prompting via PAM's conversation function and coordinates with shared state when user input is received.

This modular organization allows developers to understand and modify individual authentication flows without requiring knowledge of the entire codebase. Each module's public interface is minimal and well-documented, making the interaction points explicit and reducing the surface area for bugs.

## Technical Implementation Details

### D-Bus and fprintd Integration

The fingerprint authentication path uses the `zbus` library to communicate with the system D-Bus daemon and the fprintd service. Upon thread startup, the module connects to the system bus and immediately calls the `GetDefaultDevice` method on the fprintd Manager interface to retrieve the object path of the primary fingerprint scanner. This is followed by a `Claim` method call to acquire exclusive access to the device for the authenticated user. The claim operation implements retry logic that detects "AlreadyInUse" D-Bus errors and retries up to three times with one-second intervals between attempts, mirroring the behavior of the original C implementation.

Once the device is successfully claimed, the module calls `VerifyStart` with "any" as the finger parameter, instructing fprintd to accept any enrolled finger for this user. The fingerprint thread then enters a polling loop that checks the shared authentication state every 100 milliseconds. While a true event-based implementation listening for `VerifyStatus` D-Bus signals would be more efficient, the current polling approach provides robustness in environments where D-Bus signal routing may be problematic. When fingerprint matching succeeds (signaled through shared state), the module calls the `Release` method to return the device to an unclaimed state, ensuring proper resource cleanup.

All D-Bus operations wrap errors in descriptive messages that distinguish between retryable errors (like device conflicts) and fatal errors (like service unavailability). If D-Bus connection fails at any point, the fingerprint thread gracefully degrades to polling mode, allowing password authentication to proceed as the primary fallback.

### Password Authentication via PAM Conversation

The password authentication thread operates within the constraints of PAM's conversation model, which requires blocking calls within the authentication thread itself. The implementation retrieves the PAM conversation function pointer through `pam_get_item` and constructs a conversation message with the PAM_PROMPT_ECHO_OFF style to match the behavior of typical password prompts. The conversation function is invoked with proper C calling conventions through unsafe code wrapped in a carefully scoped block.

Upon successful user input, the module extracts the provided password from the PAM response structure, converts it to a safe `CString`, and stores it via `pam_set_item` for downstream PAM modules (typically `pam_unix.so` for actual password verification). The password thread then sets the authentication result to `PasswordEntered` and triggers the cancellation token to signal the fingerprint thread to exit. This ensures that if a user enters their password before fingerprint scanning completes, the authentication proceeds without waiting for the scanner.

The implementation handles PAM conversation failures gracefully. If the conversation function is unavailable or returns an error, the password thread terminates cleanly, leaving fingerprint authentication as the sole authentication path. This is appropriate for automated authentication scenarios where user interaction is not expected.

### Synchronization and Timeout Management

The main authentication thread implements a polling-based wait loop that checks the shared `AuthData` structure every 50 milliseconds. This polling interval was chosen to balance responsiveness with CPU efficiency—fingerprint completion typically occurs within seconds if successful, while password entry could happen at any time. The global timeout of 30 seconds provides a reasonable upper bound on authentication attempts, matching the timeout in the original C implementation.

Memory ordering for atomic operations uses `Acquire` when reading the cancellation flag (ensuring visibility of any writes performed by the signaling thread) and `Release` when setting the flag (ensuring that the flag write is visible to all readers). This is sufficient because the cancellation flag is a simple boolean signal without complex dependences on other memory operations.

Cleanup is guaranteed through the explicit `join()` calls after the polling loop exits. Even if a timeout occurs, both threads are given an opportunity to complete their current operations and clean up resources (D-Bus connections, allocated memory) before the main function returns. The order of cleanup (fingerprint thread first, then password thread) is arbitrary due to the independence of the two authentication paths.

## Building and Installation

The project requires Rust 1.70 or later and standard Linux development headers. Building produces a shared library (`libpam_parallel_fprint.so`) that can be installed into `/usr/lib/security/`. The release build includes link-time optimization and is compiled with aggressive inlining for performance-critical code paths.

```bash
# Debug build for development
cargo build

# Release build for production use
cargo build --release

# Run with strict warning checks
RUSTFLAGS="-D warnings" cargo build --release
```

The compiled library is located at `target/release/libpam_parallel_fprint.so`. Installation typically involves copying this file to the PAM modules directory and updating the appropriate PAM configuration file (usually in `/etc/pam.d/`) to include the line `auth [success=done default=ignore] pam_parallel_fprint.so` at the beginning of the authentication stack.

## Security Considerations and Limitations

This module should not be deployed in production without thorough security review and testing. Key areas of concern include the handling of PAM pointers across thread boundaries, the reliance on atomic operations for synchronization, and the interaction with other PAM modules in the authentication stack. The module makes no attempt to authenticate passwords itself—it merely collects them and passes them to downstream modules. Password handling is performed through PAM's built-in mechanisms, which may have their own security implications.

The fingerprint authentication path depends on fprintd and the underlying libfprint library, both of which must be properly configured and hardened in any deployment. Device access control should be verified to ensure that the PAM module cannot be exploited to bypass authentication on systems where fingerprint scanning is not actually available. The module also does not implement rate limiting or account lockout—these features should be provided by other PAM modules in the authentication stack (such as `pam_faillock`).

The atomic cancellation mechanism prevents the obvious race conditions between threads, but subtle timing issues could still occur if PAM's conversation function behaves unexpectedly or if the D-Bus service becomes unstable during operation. Comprehensive testing with various hardware configurations and failure scenarios is essential before any production deployment.

## Development and Contributing

Contributors should be familiar with both Rust's threading model and PAM's C-based API conventions. The codebase uses standard Rust idioms and avoids unnecessary unsafe code, with all unsafe blocks documented with safety comments explaining why the operation is safe. When modifying the authentication logic, developers should run tests with strict warning flags (`RUSTFLAGS="-D warnings"`) to ensure code quality.

Key areas for potential improvement include implementing true D-Bus signal listening in the fingerprint module (replacing the current polling approach), adding comprehensive logging for debugging authentication failures, and expanding test coverage for edge cases like timeout handling and thread cancellation. The modular design makes these improvements straightforward—the `fprint.rs` module can be enhanced to use D-Bus signal matching without affecting the rest of the codebase.

When adding new features or modifying existing code, maintain the invariant that both authentication threads run in parallel from the beginning of `pam_sm_authenticate` until at least one completes. Changes that serialize these threads (for example, by moving password authentication back to the main thread) would violate the core design principle and degrade the user experience.

## Limitations and Future Work

The current implementation uses polling to detect fingerprint completion rather than subscribing to D-Bus signals. While this approach is robust, a future version could implement proper signal matching to reduce latency and CPU usage. The module also lacks syslog integration for debugging and audit purposes, which would be valuable in production deployments. Additional work is needed to support multiple fingerprint devices and to provide configuration options for timeout values and retry behavior.

The authentication logic itself is intentionally simple—the module determines success based solely on which thread completes first, without any mechanism to enforce policy decisions like requiring fingerprint authentication over password authentication. Such policies, if needed, should be implemented in separate PAM modules that check the authentication result without duplicating the core functionality.

Performance optimization could reduce latency on systems with slow D-Bus implementations or heavily loaded fprintd services. Currently, the module uses blocking D-Bus calls and a 100-millisecond polling interval, both of which could potentially be tuned based on observed behavior in real deployments.

## License

GPL-3.0
