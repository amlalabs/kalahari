// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for PTY command execution.
//!
//! Exercises `VmHandle::exec_pty()` --- the PTY path used by interactive
//! agents (Claude Code, etc.). PTY mode allocates a pseudo-terminal in
//! the guest, giving the child `isatty() == true`, and merges stdout+stderr
//! into a single stream.
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test exec_pty -- --nocapture
//! ```

mod common;

use std::time::Duration;

use amla_vmm::{Backends, ConsoleStream, VirtualMachine};

const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// Boot a VM then run an async closure that exercises PTY execution.
async fn with_pty_vm<F>(f: F)
where
    F: AsyncFnOnce(amla_vmm::VmHandle<'_>),
{
    let pools = common::pools();
    let kernel = common::kernel();
    let image = common::rootfs_handle();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64());

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            f(vm).await;
        })
        .await
        .expect("run VM");
}

/// PTY `echo` produces stdout output and exits 0.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_echo() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "echo", "pty-hello"])
            .await
            .expect("start pty command");
        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out")
            .expect("collect failed");

        assert_eq!(output.exit_code, 0, "expected exit 0");
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("pty-hello"),
            "expected 'pty-hello' in PTY output, got: {stdout:?}"
        );
    })
    .await;
}

/// PTY reports the correct exit code for non-zero exits.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_exit_code() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "exit-with", "77"])
            .await
            .expect("start pty command");
        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out")
            .expect("collect failed");

        assert_eq!(output.exit_code, 77, "expected exit 77");
    })
    .await;
}

/// Environment variables are passed to PTY sessions.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_env_vars() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "printenv", "MY_VAR"])
            .env(["MY_VAR=pty-test-42"])
            .await
            .expect("start pty command");
        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out")
            .expect("collect failed");

        assert_eq!(output.exit_code, 0, "expected exit 0");
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("pty-test-42"),
            "expected env var value in PTY output, got: {stdout:?}"
        );
    })
    .await;
}

/// PTY stdin is forwarded to the child process.
///
/// Uses `dd` to read a fixed number of bytes from stdin and write to stdout,
/// verifying that PTY stdin delivery works.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_stdin_echo() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        // dd reads exactly 15 bytes (length of "pty-input-test\n") then exits.
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "dd", "bs=15", "count=1"])
            .await
            .expect("start pty command");

        cmd.write_stdin(b"pty-input-test\n")
            .await
            .expect("write stdin");
        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out")
            .expect("collect failed");

        assert_eq!(output.exit_code, 0, "expected exit 0");
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("pty-input-test"),
            "expected stdin echo in PTY output, got: {stdout:?}"
        );
    })
    .await;
}

/// Closing PTY stdin sends EOF to canonical-mode programs and allows exit.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_close_stdin_sends_eof() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "cat"])
            .await
            .expect("start pty cat");

        cmd.write_stdin(b"pty-eof-test\n")
            .await
            .expect("write stdin");
        cmd.close_stdin().await.expect("close stdin");

        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out after stdin close")
            .expect("collect failed");

        assert_eq!(output.exit_code, 0, "expected exit 0");
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("pty-eof-test"),
            "expected stdin echo before EOF, got: {stdout:?}"
        );
    })
    .await;
}

/// `StdinWriter::resize()` sends a `TIOCSWINSZ` ioctl to the PTY.
///
/// Verifies the resize message round-trips through the agent protocol
/// without error and the PTY command still produces output normally.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_resize() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "echo", "resize-ok"])
            .await
            .expect("start pty command");

        // Resize the PTY --- verifies the message round-trips without error.
        cmd.resize(40, 120).await.expect("resize should not error");

        let output = tokio::time::timeout(EXEC_TIMEOUT, cmd.collect_output())
            .await
            .expect("pty timed out")
            .expect("collect failed");

        assert_eq!(output.exit_code, 0, "expected exit 0");
        let stdout = output.stdout_str();
        assert!(
            stdout.contains("resize-ok"),
            "PTY command should produce output after resize, got: {stdout:?}"
        );
    })
    .await;
}

/// `stdin_writer()` can be used for concurrent stdin/stdout access in PTY mode.
///
/// Takes a writer, spawns it to a separate task for input, and reads
/// stdout on the main task --- verifying the split-ownership pattern
/// that the agent layer uses.
#[tokio::test(flavor = "multi_thread")]
async fn test_pty_stdin_writer_concurrent() {
    if common::skip() {
        return;
    }

    with_pty_vm(async move |vm| {
        // Use dd to read exactly 14 bytes then exit (avoids cat hanging on PTY EOF).
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "dd", "bs=14", "count=1"])
            .await
            .expect("start pty dd");

        let writer = cmd.stdin_writer();
        let mut stdout = cmd.take_stdout().expect("take stdout");
        let exit = cmd.take_exit().expect("take exit");

        // Send data from a separate task.
        let input_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            writer.write(b"concurrent-ok\n").await.expect("write data");
        });

        // Collect stdout on this task.
        let mut output_bytes = Vec::new();
        let deadline = tokio::time::Instant::now() + EXEC_TIMEOUT;
        while let Ok(Some(data)) = tokio::time::timeout_at(deadline, stdout.recv()).await {
            output_bytes.extend_from_slice(&data);
        }

        let exit_code = tokio::time::timeout(EXEC_TIMEOUT, exit)
            .await
            .expect("exit timed out")
            .expect("exit channel closed");

        input_task.await.expect("input task panicked");

        assert_eq!(exit_code, 0, "expected exit 0");
        let stdout_str = String::from_utf8_lossy(&output_bytes);
        assert!(
            stdout_str.contains("concurrent-ok"),
            "expected 'concurrent-ok' in output, got: {stdout_str:?}"
        );
    })
    .await;
}
