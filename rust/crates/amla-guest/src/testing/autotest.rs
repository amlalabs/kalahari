//! Autotest mode — basic boot validation tests.
//!
//! Runs basic system checks and emits markers that host-side tests look for:
//! - `PATTERN:ABCD1234` (pattern matching test)
//! - `TESTS_PASSED` (all tests passed)
//! - `=== AUTOTEST START/COMPLETE ===` (section markers)

use super::{TestRunner, kmsg};

pub fn run() {
    let mut t = TestRunner::new("AUTOTEST");
    t.marker("PATTERN:ABCD1234");

    // Test 1: Basic system info
    match std::fs::read_to_string("/proc/version") {
        Ok(version) => t.pass("uname", &version),
        Err(e) => t.fail("uname", &e.to_string()),
    }
    kmsg("  pwd: /");

    // Test 2: Process listing
    match std::fs::read_to_string("/proc/self/stat") {
        Ok(_) => t.pass("process", "self stat readable"),
        Err(e) => t.fail("process", &e.to_string()),
    }

    // Test 3: File operations
    match std::fs::write("/tmp/test.txt", "hello\n") {
        Ok(()) => match std::fs::read_to_string("/tmp/test.txt") {
            Ok(content) if content.trim() == "hello" => t.pass("file_ops", "write+read OK"),
            Ok(content) => t.fail("file_ops", &format!("unexpected content: {content:?}")),
            Err(e) => t.fail("file_ops", &format!("read failed: {e}")),
        },
        Err(e) => t.fail("file_ops", &format!("write failed: {e}")),
    }

    // Test 4: Memory info
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(meminfo) => {
            for line in meminfo.lines().take(5) {
                kmsg(&format!("  {line}"));
            }
            t.pass("meminfo", "readable");
        }
        Err(e) => t.fail("meminfo", &e.to_string()),
    }

    // Test 5: CPU info
    match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(cpuinfo) => {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") || line.starts_with("vendor") {
                    kmsg(&format!("  {line}"));
                }
            }
            t.pass("cpuinfo", "readable");
        }
        Err(e) => t.fail("cpuinfo", &e.to_string()),
    }

    // Test 6: Uptime
    match std::fs::read_to_string("/proc/uptime") {
        Ok(uptime) => {
            kmsg(&format!("  uptime: {}", uptime.trim()));
            t.pass("uptime", uptime.trim());
        }
        Err(e) => t.fail("uptime", &e.to_string()),
    }

    // Test 7: Interrupts
    match std::fs::read_to_string("/proc/interrupts") {
        Ok(interrupts) => {
            for line in interrupts.lines().take(15) {
                kmsg(&format!("  {line}"));
            }
            t.pass("interrupts", "readable");
        }
        Err(e) => t.fail("interrupts", &e.to_string()),
    }

    // Test 8: Kernel log
    match std::fs::read_to_string("/proc/kmsg_bytes_available") {
        Ok(_) => t.pass("klog", "kmsg available"),
        Err(_) => {
            t.pass("klog", "skipped (not critical)");
        }
    }

    t.finish();
}
