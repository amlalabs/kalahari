// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for command execution — programmatic command execution in the guest.
//!
//! All tests share the common pool to avoid fd exhaustion under concurrent execution.

mod common;

use std::time::Duration;

use amla_constants::protocol::ExecId;
use amla_vmm::{
    Backends, CommandExecutionHandle, ConsoleStream, SpawnBackends, VirtualMachine, Zygote,
};

const SHORT_PARKED_RUN_TIMEOUT: Duration = Duration::from_secs(15);
const SHORT_PARKED_STRESS_RUNS: usize = 30;

/// Boot a VM then run an async closure that exercises command execution.
async fn with_exec_vm(f: impl AsyncFnOnce(amla_vmm::VmHandle<'_>)) {
    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
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

/// Boot a VM with an isolated backend pool, start a long-running command, and
/// verify explicit VM shutdown does not wait for that command to exit.
///
/// Direct VMM runs require active host command handles to be quiescent before a
/// run returns, so the command is detached after exec acceptance. The guest
/// process is still active when shutdown is requested.
#[tokio::test(flavor = "multi_thread")]
async fn test_shutdown_while_long_running_command_active() {
    if common::skip() {
        return;
    }

    let config = common::default_config();
    let pools = common::backend_pools(1, &config);
    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(&pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    tokio::time::timeout(common::boot_timeout(), async move {
        vm.run(async move |vm| {
            let mut vm = vm.start();
            let command = vm
                .exec(["/bin/amla-guest", "sleep", "300"])
                .await
                .expect("start long-running command");
            let _command = command
                .into_handle()
                .expect("long-running command should detach before producing output");
            tokio::time::timeout(Duration::from_secs(10), vm.shutdown())
                .await
                .expect("VM shutdown should not wait for long-running command exit");
        })
        .await
    })
    .await
    .expect("VM run with shutdown timed out")
    .expect("VM run with shutdown");
}

/// Run a command on a spawned-from-zygote VM and collect its output.
async fn exec_on_spawned(vm: &amla_vmm::VmHandle<'_>, args: &[&str]) -> amla_vmm::CollectedOutput {
    let cmd = vm.exec(args).await.expect("start command");
    tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
        .await
        .expect("exec timed out")
}

/// Boot, freeze, spawn, then run the closure on the spawned VM.
async fn with_spawned_exec_vm(f: impl AsyncFnOnce(amla_vmm::VmHandle<'_>)) {
    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load kernel");
    let timeout = common::boot_timeout();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("boot VM");
    let zygote = vm.freeze().await.expect("freeze");

    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let spawned = zygote
        .spawn(common::pools(), backends)
        .await
        .expect("spawn");
    let (_spawned, ()) = spawned
        .run(async move |vm| {
            let vm = vm.start();
            f(vm).await;
        })
        .await
        .expect("run on spawned VM");
}

async fn assert_attached_cat_echoes(
    zygote: &VirtualMachine<Zygote>,
    handle: CommandExecutionHandle,
    cmd_id: ExecId,
    input: &'static str,
) {
    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let spawned = zygote
        .spawn(common::pools(), backends)
        .await
        .expect("spawn");

    let (_spawned, ()) = spawned
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            let mut cmd = vm
                .take_attached(cmd_id)
                .expect("attached session not found");

            cmd.write_stdin(input).await.expect("write");
            cmd.close_stdin().await.expect("close");
            let output = tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
                .await
                .expect("timed out")
                .expect("collect");
            assert_eq!(output.exit_code, 0);
            assert!(output.stdout_str().contains(input.trim()));
        })
        .await
        .expect("spawned run");
}

async fn detached_cat_zygote() -> (VirtualMachine<Zygote>, CommandExecutionHandle, ExecId) {
    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load");

    let (vm, handle) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat"])
                .await
                .expect("start cat");
            cmd.into_handle().expect("command should be reattachable")
        })
        .await
        .expect("first run");
    let cmd_id = handle.id();
    let zygote = vm.freeze().await.expect("freeze");

    (zygote, handle, cmd_id)
}

// =============================================================================
// Basic tests
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_echo_stdout() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "echo", "hello"])
            .await
            .expect("start command");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("exec timed out");
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains("hello"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_env_vars() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "printenv", "FOO"])
            .env(["FOO=bar"])
            .await
            .expect("start");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains("bar"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_cwd() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "ls", "/tmp"])
            .cwd("/tmp")
            .await
            .expect("start");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_exit_code() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "exit-with", "42"])
            .await
            .expect("start");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 42);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_output_auto_closes_stdin() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("start");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_stdin_passthrough() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("start");
        cmd.write_stdin(b"hello from stdin\n").await.expect("write");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains("hello from stdin"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_stderr_capture() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "exit-with", "1"])
            .await
            .expect("start");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 1);
    })
    .await;
}

// =============================================================================
// Snapshot / restore
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_echo_after_spawn() {
    if common::skip() {
        return;
    }
    with_spawned_exec_vm(async move |vm| {
        let output = exec_on_spawned(&vm, &["/bin/amla-guest", "echo", "hello-from-spawn"]).await;
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains("hello-from-spawn"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_exit_code_after_spawn() {
    if common::skip() {
        return;
    }
    with_spawned_exec_vm(async move |vm| {
        let output = exec_on_spawned(&vm, &["/bin/amla-guest", "exit-with", "77"]).await;
        assert_eq!(output.exit_code, 77);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_guest_state_survives_spawn() {
    if common::skip() {
        return;
    }

    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load");

    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "tee", "/tmp/state_marker"])
                .await
                .expect("tee");
            cmd.write_stdin(b"freeze-token-42\n").await.expect("write");
            let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
                .await
                .expect("timed out");
            assert_eq!(output.exit_code, 0);
        })
        .await
        .expect("boot");

    let zygote = vm.freeze().await.expect("freeze");
    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let spawned = zygote
        .spawn(common::pools(), backends)
        .await
        .expect("spawn");
    let (_spawned, ()) = spawned
        .run(async move |vm| {
            let vm = vm.start();
            let output =
                exec_on_spawned(&vm, &["/bin/amla-guest", "cat", "/tmp/state_marker"]).await;
            assert_eq!(output.exit_code, 0);
            assert!(output.stdout_str().contains("freeze-token-42"));
        })
        .await
        .expect("spawned run");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_multiple_commands_after_spawn() {
    if common::skip() {
        return;
    }
    with_spawned_exec_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "tee", "/tmp/multi_test"])
            .await
            .expect("tee");
        cmd.write_stdin(b"abc\ndef\n").await.expect("write");
        let output = tokio::time::timeout(common::boot_timeout(), common::collect_output(cmd))
            .await
            .expect("timed out");
        assert_eq!(output.exit_code, 0);

        let output = exec_on_spawned(&vm, &["/bin/amla-guest", "cat", "/tmp/multi_test"]).await;
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains("abc"));
        assert!(output.stdout_str().contains("def"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_concurrent_commands() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let (a, b, c) = tokio::join!(
            vm.exec(["/bin/amla-guest", "echo", "marker-alpha"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-bravo"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-charlie"]),
        );
        let (oa, ob, oc) = tokio::join!(
            tokio::time::timeout(common::boot_timeout(), common::collect_output(a.unwrap())),
            tokio::time::timeout(common::boot_timeout(), common::collect_output(b.unwrap())),
            tokio::time::timeout(common::boot_timeout(), common::collect_output(c.unwrap())),
        );
        let (oa, ob, oc) = (oa.unwrap(), ob.unwrap(), oc.unwrap());
        assert!(oa.stdout_str().contains("marker-alpha"));
        assert!(ob.stdout_str().contains("marker-bravo"));
        assert!(oc.stdout_str().contains("marker-charlie"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_on_successive_spawns() {
    if common::skip() {
        return;
    }

    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load");
    let timeout = common::boot_timeout();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("boot");
    let zygote = vm.freeze().await.expect("freeze");

    for i in 0..3 {
        let console = ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let spawned = zygote
            .spawn(common::pools(), backends)
            .await
            .unwrap_or_else(|e| panic!("spawn {i}: {e}"));
        let (_spawned, ()) = spawned
            .run(async move |vm| {
                let vm = vm.start();
                let marker = format!("spawn-{i}");
                let output = exec_on_spawned(&vm, &["/bin/amla-guest", "echo", &marker]).await;
                assert_eq!(output.exit_code, 0, "spawn {i}");
                assert!(output.stdout_str().contains(&marker), "spawn {i}");
            })
            .await
            .unwrap_or_else(|e| panic!("run {i}: {e}"));
    }
}

// =============================================================================
// Back-to-back runs + attach
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_run_back_to_back_with_exec() {
    if common::skip() {
        return;
    }

    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load");

    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm
                .exec(["/bin/amla-guest", "tee", "/tmp/b2b_test"])
                .await
                .expect("exec");
            cmd.write_stdin(b"run1-marker\n").await.expect("write");
            let _ = tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
                .await
                .expect("timed out")
                .expect("collect");
        })
        .await
        .expect("first run");

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm
                .exec(["/bin/amla-guest", "cat", "/tmp/b2b_test"])
                .await
                .expect("exec");
            let output = tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
                .await
                .expect("timed out")
                .expect("collect");
            assert_eq!(output.exit_code, 0);
            assert!(output.stdout_str().contains("run1-marker"));
        })
        .await
        .expect("second run");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_command_attach_across_spawn() {
    if common::skip() {
        return;
    }

    let (zygote, handle, cmd_id) = detached_cat_zygote().await;
    assert_attached_cat_echoes(&zygote, handle, cmd_id, "attach-test\n").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_command_attach_across_back_to_back_runs() {
    if common::skip() {
        return;
    }

    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(common::default_config())
        .await
        .expect("create");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load");

    let (vm, handle) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat"])
                .await
                .expect("start cat");
            cmd.into_handle().expect("command should be reattachable")
        })
        .await
        .expect("first run");
    let cmd_id = handle.id();

    let (_vm, ()) = vm
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            let mut cmd = vm
                .take_attached(cmd_id)
                .expect("reattached command should be present");

            cmd.write_stdin(b"same-vm-reattach\n").await.expect("write");
            cmd.close_stdin().await.expect("close");
            let output = tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
                .await
                .expect("timed out")
                .expect("collect");
            assert_eq!(output.exit_code, 0);
            assert!(output.stdout_str().contains("same-vm-reattach"));
        })
        .await
        .expect("second run");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn test_detached_command_survives_repeated_short_parked_runs() {
    if common::skip() {
        return;
    }
    common::init_logging();

    let config = common::default_config();
    let pools = common::backend_pools(1, &config);
    let image = common::rootfs_handle();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(config).await.expect("create");
    let vm = vm
        .load_kernel(&pools, common::kernel(), backends)
        .await
        .expect("load");

    let (vm, handle) = tokio::time::timeout(common::boot_timeout(), async move {
        vm.run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat"])
                .await
                .expect("start cat");
            cmd.into_handle()
                .expect("newly-started cat should be reattachable")
        })
        .await
    })
    .await
    .expect("initial detached run timed out")
    .expect("initial detached run");
    let cmd_id = handle.id();
    let mut parked = vm.park().await.expect("park after initial detach");
    let mut handle = Some(handle);

    for cycle in 0..SHORT_PARKED_STRESS_RUNS {
        let console = ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let ready = parked
            .resume(&pools, backends)
            .await
            .expect("resume parked VM");
        let current_handle = handle.take().expect("detached handle");

        let (ready, next_handle) = tokio::time::timeout(SHORT_PARKED_RUN_TIMEOUT, async move {
            ready
                .run(async move |mut vm| {
                    vm.attach(current_handle).unwrap();
                    let mut vm = vm.start();
                    let cmd = vm
                        .take_attached(cmd_id)
                        .expect("reattached command should be present");

                    tokio::time::sleep(Duration::from_millis(50)).await;
                    cmd.into_handle()
                        .expect("quiet cat should remain reattachable")
                })
                .await
        })
        .await
        .unwrap_or_else(|_| panic!("short parked run {cycle} timed out"))
        .unwrap_or_else(|error| panic!("short parked run {cycle} failed: {error}"));

        handle = Some(next_handle);
        parked = ready
            .park()
            .await
            .unwrap_or_else(|error| panic!("park after short run {cycle} failed: {error}"));
        tokio::time::sleep(Duration::from_millis((cycle % 4) as u64)).await;
    }

    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let ready = parked
        .resume(&pools, backends)
        .await
        .expect("final resume parked VM");
    let handle = handle.expect("detached handle after stress runs");

    let (_ready, ()) = tokio::time::timeout(SHORT_PARKED_RUN_TIMEOUT, async move {
        ready
            .run(async move |mut vm| {
                vm.attach(handle).unwrap();
                let mut vm = vm.start();
                let mut cmd = vm
                    .take_attached(cmd_id)
                    .expect("final attached command should be present");

                cmd.write_stdin(b"primitive-stress-marker\n")
                    .await
                    .expect("write stdin");
                cmd.close_stdin().await.expect("close stdin");
                let output = tokio::time::timeout(SHORT_PARKED_RUN_TIMEOUT, cmd.collect_output())
                    .await
                    .expect("final collect timed out")
                    .expect("collect output");
                assert_eq!(output.exit_code, 0);
                assert!(output.stdout_str().contains("primitive-stress-marker"));
            })
            .await
    })
    .await
    .expect("final attach run timed out")
    .expect("final attach run");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_command_attach_handle_clones_across_spawns() {
    if common::skip() {
        return;
    }

    let (zygote, handle, cmd_id) = detached_cat_zygote().await;

    for (handle, input) in [
        (handle.clone(), "first-clone\n"),
        (handle, "second-clone\n"),
    ] {
        assert_attached_cat_echoes(&zygote, handle, cmd_id, input).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_exec_take_exit() {
    if common::skip() {
        return;
    }
    with_exec_vm(async move |vm| {
        let mut cmd = vm
            .exec(["/bin/amla-guest", "echo", "take_exit_test"])
            .await
            .expect("start");
        let mut stdout_rx = cmd.take_stdout().expect("take stdout");
        let exit_rx = cmd.take_exit().expect("take exit");

        assert!(cmd.wait().await.is_err());
        assert!(cmd.take_exit().is_none());

        let mut stdout = Vec::new();
        while let Some(data) = stdout_rx.recv().await {
            stdout.extend_from_slice(&data);
        }
        let exit_code = tokio::time::timeout(common::boot_timeout(), exit_rx)
            .await
            .expect("exit timed out")
            .expect("exit closed");
        assert_eq!(exit_code, 0);
        assert!(String::from_utf8_lossy(&stdout).contains("take_exit_test"));
    })
    .await;
}
