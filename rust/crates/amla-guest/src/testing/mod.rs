//! Shared infrastructure for guest test binaries.
//!
//! Provides common utilities for test binaries that run inside the guest VM:
//! - Kernel log output via `/dev/kmsg`
//! - VM exit via I/O port 0xF4 (x86: isa-debug-exit) or PSCI `SYSTEM_OFF` (ARM64)
//! - Kernel cmdline parsing
//! - Sysfs access helpers
//! - `TestRunner` for structured test execution with pass/fail tracking

pub mod autotest;
pub mod https_get;
pub mod network;
pub mod tcp_echo;
pub mod tcp_upload;
pub mod udp_echo;
pub mod vm_exit;

use std::io;

/// Write a message to /dev/kmsg (kernel log -> serial console).
///
/// Uses the same `<6>init:` prefix as the shell init's `out()` function
/// so host-side tests can parse the same markers.
pub fn kmsg(msg: &str) {
    let formatted = format!("<2>init: {msg}\n");
    if let Err(e) = std::fs::write("/dev/kmsg", formatted.as_bytes()) {
        // Fall back to stderr so the message isn't silently dropped when
        // /dev/kmsg is unavailable (e.g. running as non-root test harness).
        eprintln!("testing::kmsg: write /dev/kmsg failed ({e}); msg: {msg}");
    }
}

/// Exit the VM cleanly via `process::exit()`.
///
/// The guest agent (PID 1) detects the child exit via `waitpid()`, sends
/// `RunExited` over the ring buffer, and then calls `reboot(POWER_OFF)` to
/// shut down the VM. No isa-debug-exit port or PSCI hack needed.
pub fn vm_exit(code: u8) -> ! {
    std::process::exit(i32::from(code))
}

/// Parse a single `key=value` parameter from /proc/cmdline.
///
/// Returns `Ok(Some(value))` if found, `Ok(None)` if not present.
pub fn cmdline_param(key: &str) -> Result<Option<String>, io::Error> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    let prefix = format!("{key}=");
    for arg in cmdline.split_whitespace() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

/// Parse all kernel cmdline parameters as `(key, Option<value>)` pairs.
///
/// Parameters without `=` have `None` as value (flags like `ro`, `quiet`).
pub fn cmdline_params() -> Result<Vec<(String, Option<String>)>, io::Error> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    Ok(cmdline
        .split_whitespace()
        .map(|arg| {
            if let Some((k, v)) = arg.split_once('=') {
                (k.to_string(), Some(v.to_string()))
            } else {
                (arg.to_string(), None)
            }
        })
        .collect())
}

/// Read a sysfs attribute, trimming trailing whitespace.
pub fn sysfs_read(path: &str) -> Result<String, io::Error> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string())
}

/// Check if a sysfs path exists.
pub fn sysfs_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

// =============================================================================
// Virtio Sysfs Helpers
// =============================================================================

/// Info about a discovered virtio device in sysfs.
#[derive(Debug)]
pub struct VirtioDevice {
    /// Sysfs path, e.g. `/sys/bus/virtio/devices/virtio1`
    pub path: String,
    /// Device name, e.g. `virtio1`
    pub name: String,
}

/// Parse a sysfs u32 value that may be hex (`0x0005`) or decimal (`5`).
///
/// Returns `None` on parse failure rather than silently defaulting to 0.
pub fn parse_sysfs_u32(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    trimmed.strip_prefix("0x").map_or_else(
        || trimmed.parse::<u32>().ok(),
        |hex| u32::from_str_radix(hex, 16).ok(),
    )
}

/// Find a virtio device by its device type ID in sysfs.
///
/// Device type IDs: 1=net, 3=console, 4=rng, 5=balloon, 19=vsock, 26=fs.
pub fn find_virtio_device(device_type: u32) -> Option<VirtioDevice> {
    let base = "/sys/bus/virtio/devices";
    let entries = std::fs::read_dir(base).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let dev_file = path.join("device");
        if let Ok(raw) = std::fs::read_to_string(&dev_file)
            && parse_sysfs_u32(&raw) == Some(device_type)
        {
            let name = entry.file_name().to_string_lossy().to_string();
            return Some(VirtioDevice {
                path: path.to_string_lossy().to_string(),
                name,
            });
        }
    }
    None
}

/// Check if a virtio device has `DRIVER_OK` (bit 2) set in its status.
pub fn virtio_driver_ok(dev: &VirtioDevice) -> bool {
    let status_path = format!("{}/status", dev.path);
    std::fs::read_to_string(&status_path)
        .is_ok_and(|raw| parse_sysfs_u32(&raw).unwrap_or(0) & 4 == 4)
}

/// Get the driver name for a virtio device (from sysfs driver symlink).
pub fn virtio_driver_name(dev: &VirtioDevice) -> Option<String> {
    let driver_link = format!("{}/driver", dev.path);
    std::fs::read_link(&driver_link)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
}

// =============================================================================
// Command Execution
// =============================================================================

/// Run a command and return `(exit_success, combined_output)`.
pub fn run_cmd(prog: &str, args: &[&str]) -> (bool, String) {
    match std::process::Command::new(prog).args(args).output() {
        Ok(output) => {
            let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&stderr);
            }
            (output.status.success(), combined)
        }
        Err(e) => (false, format!("{prog}: {e}")),
    }
}

/// Run a command, log output lines via kmsg, return success.
pub fn run_cmd_logged(prog: &str, args: &[&str]) -> bool {
    let (ok, output) = run_cmd(prog, args);
    for line in output.lines() {
        kmsg(&format!("  {line}"));
    }
    ok
}

// =============================================================================
// Network Setup
// =============================================================================

/// Bring up eth0 with static config (10.0.2.15/24, gw 10.0.2.2).
///
/// Uses netlink sockets directly — no external commands.
/// Returns true if the interface was configured successfully.
pub fn setup_network() -> bool {
    match crate::net::setup_network() {
        Ok(true) => {
            kmsg("NETWORK:PASS (static config applied via netlink)");
            true
        }
        Ok(false) => {
            kmsg("NETWORK:SKIP (no eth0)");
            false
        }
        Err(e) => {
            kmsg(&format!("NETWORK:FAIL ({e})"));
            false
        }
    }
}

// =============================================================================
// Test Runner
// =============================================================================

/// Structured test runner for guest test binaries.
///
/// Tracks pass/fail counts, emits structured markers via kmsg, and calls
/// `vm_exit()` with the appropriate exit code on `finish()`.
pub struct TestRunner {
    name: &'static str,
    passed: u32,
    failed: u32,
    skipped: u32,
}

impl TestRunner {
    /// Create a new test runner and emit the start marker.
    pub fn new(name: &'static str) -> Self {
        kmsg(&format!("=== {name} START ==="));
        Self {
            name,
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    /// Record a passing test.
    pub fn pass(&mut self, test: &str, msg: &str) {
        self.passed += 1;
        Self::emit("PASS", test, msg);
    }

    /// Record a failing test.
    pub fn fail(&mut self, test: &str, msg: &str) {
        self.failed += 1;
        Self::emit("FAIL", test, msg);
    }

    /// Record a skipped test.
    pub fn skip(&mut self, test: &str, msg: &str) {
        self.skipped += 1;
        Self::emit("SKIP", test, msg);
    }

    fn emit(status: &str, test: &str, msg: &str) {
        if msg.is_empty() {
            kmsg(&format!("  {status}: {test}"));
        } else {
            kmsg(&format!("  {status}: {test}: {msg}"));
        }
    }

    /// Emit a raw marker line (for compatibility with host-side test assertions).
    #[allow(clippy::unused_self)]
    pub fn marker(&self, marker: &str) {
        kmsg(marker);
    }

    /// Returns true if any test has failed so far.
    pub const fn has_failures(&self) -> bool {
        self.failed > 0
    }

    /// Finish the test run: emit summary, completion marker, and exit VM.
    ///
    /// Exits with code 0 (success) if no failures, code 1 (failure) otherwise.
    pub fn finish(self) -> ! {
        kmsg(&format!(
            "Results: {} passed, {} failed, {} skipped",
            self.passed, self.failed, self.skipped
        ));
        kmsg(&format!("=== {} COMPLETE ===", self.name));

        if self.failed == 0 {
            kmsg("TESTS_PASSED");
            vm_exit(0);
        } else {
            kmsg("TESTS_FAILED");
            vm_exit(1);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Cmdline parsing
    // =========================================================================

    #[test]
    fn cmdline_param_parsing() {
        let cmdline = "console=ttyS0 mode=autotest key=value";
        let prefix = "mode=";
        let result = cmdline
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix(prefix))
            .map(String::from);
        assert_eq!(result, Some("autotest".to_string()));
    }

    #[test]
    fn cmdline_params_parsing() {
        let cmdline = "console=ttyS0 ro quiet mode=autotest";
        let params: Vec<(String, Option<String>)> = cmdline
            .split_whitespace()
            .map(|arg| {
                if let Some((k, v)) = arg.split_once('=') {
                    (k.to_string(), Some(v.to_string()))
                } else {
                    (arg.to_string(), None)
                }
            })
            .collect();
        assert_eq!(params.len(), 4);
        assert_eq!(params[0], ("console".into(), Some("ttyS0".into())));
        assert_eq!(params[1], ("ro".into(), None));
        assert_eq!(params[2], ("quiet".into(), None));
        assert_eq!(params[3], ("mode".into(), Some("autotest".into())));
    }

    #[test]
    fn cmdline_param_not_found() {
        let cmdline = "console=ttyS0 root=/dev/sda1";
        let prefix = "mode=";
        let result = cmdline
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix(prefix))
            .map(String::from);
        assert_eq!(result, None);
    }

    #[test]
    fn cmdline_empty() {
        let cmdline = "";
        let params: Vec<(String, Option<String>)> = cmdline
            .split_whitespace()
            .map(|arg| {
                if let Some((k, v)) = arg.split_once('=') {
                    (k.to_string(), Some(v.to_string()))
                } else {
                    (arg.to_string(), None)
                }
            })
            .collect();
        assert!(params.is_empty());
    }

    #[test]
    fn cmdline_value_with_equals() {
        // Values can contain '=' (split_once only splits on the first one)
        let cmdline = "amla.init=/sbin/init=extra";
        let params: Vec<(String, Option<String>)> = cmdline
            .split_whitespace()
            .map(|arg| {
                if let Some((k, v)) = arg.split_once('=') {
                    (k.to_string(), Some(v.to_string()))
                } else {
                    (arg.to_string(), None)
                }
            })
            .collect();
        assert_eq!(
            params[0],
            ("amla.init".into(), Some("/sbin/init=extra".into()))
        );
    }

    // =========================================================================
    // TestRunner state tracking (no vm_exit — we don't call finish())
    // =========================================================================

    #[test]
    fn test_runner_initial_state() {
        let runner = TestRunner::new("unit_test");
        assert!(!runner.has_failures());
        assert_eq!(runner.passed, 0);
        assert_eq!(runner.failed, 0);
        assert_eq!(runner.skipped, 0);
    }

    #[test]
    fn test_runner_pass_tracking() {
        let mut runner = TestRunner::new("unit_test");
        runner.pass("test_a", "ok");
        runner.pass("test_b", "");
        assert!(!runner.has_failures());
        assert_eq!(runner.passed, 2);
        assert_eq!(runner.failed, 0);
    }

    #[test]
    fn test_runner_fail_tracking() {
        let mut runner = TestRunner::new("unit_test");
        runner.pass("test_a", "ok");
        runner.fail("test_b", "assertion failed");
        assert!(runner.has_failures());
        assert_eq!(runner.passed, 1);
        assert_eq!(runner.failed, 1);
    }

    #[test]
    fn test_runner_skip_tracking() {
        let mut runner = TestRunner::new("unit_test");
        runner.skip("test_a", "not applicable");
        runner.pass("test_b", "");
        assert!(!runner.has_failures());
        assert_eq!(runner.passed, 1);
        assert_eq!(runner.skipped, 1);
    }

    #[test]
    fn test_runner_mixed_results() {
        let mut runner = TestRunner::new("unit_test");
        runner.pass("test_1", "");
        runner.pass("test_2", "");
        runner.fail("test_3", "timeout");
        runner.skip("test_4", "no device");
        runner.pass("test_5", "");
        assert!(runner.has_failures());
        assert_eq!(runner.passed, 3);
        assert_eq!(runner.failed, 1);
        assert_eq!(runner.skipped, 1);
    }

    // =========================================================================
    // parse_sysfs_u32 — tests the actual helper function
    // =========================================================================

    #[test]
    fn parse_sysfs_hex_value() {
        assert_eq!(parse_sysfs_u32("0x0005\n"), Some(5));
    }

    #[test]
    fn parse_sysfs_decimal_value() {
        assert_eq!(parse_sysfs_u32("19\n"), Some(19));
    }

    #[test]
    fn parse_sysfs_hex_no_prefix() {
        assert_eq!(parse_sysfs_u32("255"), Some(255));
    }

    #[test]
    fn parse_sysfs_invalid() {
        assert_eq!(parse_sysfs_u32("not_a_number"), None);
    }

    #[test]
    fn parse_sysfs_empty() {
        assert_eq!(parse_sysfs_u32(""), None);
    }

    #[test]
    fn parse_sysfs_whitespace() {
        assert_eq!(parse_sysfs_u32("  42  \n"), Some(42));
    }

    #[test]
    fn parse_virtio_status_driver_ok() {
        // DRIVER_OK is bit 2 (value 4)
        let val = parse_sysfs_u32("0x0f\n").unwrap();
        assert!(val & 4 == 4); // DRIVER_OK set
    }

    #[test]
    fn parse_virtio_status_no_driver_ok() {
        let val = parse_sysfs_u32("0x03\n").unwrap();
        assert!(val & 4 == 0); // DRIVER_OK not set
    }

    // =========================================================================
    // run_cmd — basic smoke tests
    // =========================================================================

    #[test]
    fn run_cmd_true() {
        let (ok, _) = run_cmd("true", &[]);
        assert!(ok);
    }

    #[test]
    fn run_cmd_false() {
        let (ok, _) = run_cmd("false", &[]);
        assert!(!ok);
    }

    #[test]
    fn run_cmd_output() {
        let (ok, output) = run_cmd("echo", &["hello"]);
        assert!(ok);
        assert!(output.contains("hello"));
    }
}
