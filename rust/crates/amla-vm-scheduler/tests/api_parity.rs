// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Behavior parity checks between direct VMM execution and scheduler execution.

#[path = "../../amla-vm-vmm/tests/common/mod.rs"]
mod common;

use std::future::IntoFuture;
use std::time::Duration;

use amla_vm_scheduler::{
    CommandExecution as ScheduledCommandExecution, CommandSpec, ConsoleStream, LiveShellLimit,
    VmBackends, VmConfig, VmScheduler,
};
use amla_vmm::{Backends, CommandExecution as DirectCommandExecution};

fn scheduler_with_limit(limit: usize) -> VmScheduler {
    VmScheduler::new(
        LiveShellLimit::try_from(limit).unwrap(),
        common::worker_config(),
    )
}

fn scheduler_backends(config: &VmConfig) -> VmBackends {
    VmBackends::new(ConsoleStream::new()).with_pmem(
        config
            .pmem_disks
            .iter()
            .map(|_| common::rootfs_handle())
            .collect(),
    )
}

async fn with_phase_timeout<T, F>(phase: &'static str, future: F) -> T
where
    F: IntoFuture<Output = T>,
{
    with_timeout(phase, common::boot_timeout(), future).await
}

async fn with_timeout<T, F>(phase: &'static str, timeout: Duration, future: F) -> T
where
    F: IntoFuture<Output = T>,
{
    tokio::time::timeout(timeout, future.into_future())
        .await
        .unwrap_or_else(|_| panic!("{phase} timed out after {timeout:?}"))
}

async fn with_direct_vm<R>(f: impl AsyncFnOnce(amla_vmm::VmHandle<'_>) -> R) -> R {
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = amla_vmm::VirtualMachine::create(config)
        .await
        .expect("create direct VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load direct VM");
    let (vm, result) = vm
        .run(async move |vm| {
            let vm = vm.start();
            f(vm).await
        })
        .await
        .expect("run direct VM");
    let _parked = vm.park().await.expect("park direct VM");
    result
}

async fn with_scheduled_vm<R>(f: impl AsyncFnOnce(amla_vm_scheduler::VmHandle<'_>) -> R) -> R {
    let scheduler = scheduler_with_limit(1);
    let config = common::default_config();
    let vm = scheduler
        .create_vm(config.clone(), scheduler_backends(&config))
        .await
        .expect("create scheduler VM");
    let vm = vm
        .load_kernel(common::kernel())
        .await
        .expect("load scheduler VM");
    let (_vm, result) = vm
        .run(async move |vm| {
            let vm = vm.start();
            f(vm).await
        })
        .await
        .expect("run scheduler VM");
    result
}

async fn collect_direct(mut cmd: DirectCommandExecution) -> amla_vmm::CollectedOutput {
    tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
        .await
        .expect("direct command timed out")
        .expect("collect direct output")
}

async fn collect_scheduled(
    mut cmd: ScheduledCommandExecution,
) -> amla_vm_scheduler::CollectedOutput {
    tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
        .await
        .expect("scheduled command timed out")
        .expect("collect scheduled output")
}

async fn direct_exec(argv: &[&str]) -> amla_vmm::CollectedOutput {
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = amla_vmm::VirtualMachine::create(config)
        .await
        .expect("create direct VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load direct VM");
    let (vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(argv).await.expect("direct exec");
            collect_direct(cmd).await
        })
        .await
        .expect("run direct VM");
    let _parked = vm.park().await.expect("park direct VM");
    output
}

async fn scheduled_exec(argv: &[&str]) -> amla_vm_scheduler::CollectedOutput {
    let scheduler = scheduler_with_limit(1);
    let config = common::default_config();
    let vm = scheduler
        .create_vm(config.clone(), scheduler_backends(&config))
        .await
        .expect("create scheduler VM");
    let vm = vm
        .load_kernel(common::kernel())
        .await
        .expect("load scheduler VM");
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(argv).await.expect("scheduled exec");
            collect_scheduled(cmd).await
        })
        .await
        .expect("run scheduler VM");
    output
}

async fn direct_env() -> amla_vmm::CollectedOutput {
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = amla_vmm::VirtualMachine::create(config)
        .await
        .expect("create direct VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load direct VM");
    let (vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "printenv", "PARITY_ENV"])
                .env(["PARITY_ENV=direct-shape"])
                .await
                .expect("direct env exec");
            collect_direct(cmd).await
        })
        .await
        .expect("run direct VM");
    let _parked = vm.park().await.expect("park direct VM");
    output
}

async fn scheduled_env() -> amla_vm_scheduler::CollectedOutput {
    let scheduler = scheduler_with_limit(1);
    let config = common::default_config();
    let vm = scheduler
        .create_vm(config.clone(), scheduler_backends(&config))
        .await
        .expect("create scheduler VM");
    let vm = vm
        .load_kernel(common::kernel())
        .await
        .expect("load scheduler VM");
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "printenv", "PARITY_ENV"])
                .env(["PARITY_ENV=direct-shape"])
                .await
                .expect("scheduled env exec");
            collect_scheduled(cmd).await
        })
        .await
        .expect("run scheduler VM");
    output
}

async fn direct_cat(input: &'static str) -> amla_vmm::CollectedOutput {
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = amla_vmm::VirtualMachine::create(config)
        .await
        .expect("create direct VM");
    let vm = vm
        .load_kernel(common::pools(), common::kernel(), backends)
        .await
        .expect("load direct VM");
    let (vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat"])
                .await
                .expect("direct cat");
            cmd.write_stdin(input).await.expect("direct write stdin");
            cmd.close_stdin().await.expect("direct close stdin");
            collect_direct(cmd).await
        })
        .await
        .expect("run direct VM");
    let _parked = vm.park().await.expect("park direct VM");
    output
}

async fn scheduled_cat(input: &'static str) -> amla_vm_scheduler::CollectedOutput {
    let scheduler = scheduler_with_limit(1);
    let config = common::default_config();
    let vm = scheduler
        .create_vm(config.clone(), scheduler_backends(&config))
        .await
        .expect("create scheduler VM");
    let vm = vm
        .load_kernel(common::kernel())
        .await
        .expect("load scheduler VM");
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat"])
                .await
                .expect("scheduled cat");
            cmd.write_stdin(input).await.expect("scheduled write stdin");
            cmd.close_stdin().await.expect("scheduled close stdin");
            collect_scheduled(cmd).await
        })
        .await
        .expect("run scheduler VM");
    output
}

async fn direct_cwd() -> amla_vmm::CollectedOutput {
    with_direct_vm(async move |vm| {
        let setup = vm
            .exec(["/bin/amla-guest", "mkdir", "/tmp/parity-cwd-marker"])
            .await
            .expect("direct mkdir");
        assert_eq!(collect_direct(setup).await.exit_code, 0);
        let cmd = vm
            .exec(["/bin/amla-guest", "ls", "."])
            .cwd("/tmp")
            .await
            .expect("direct cwd exec");
        collect_direct(cmd).await
    })
    .await
}

async fn scheduled_cwd() -> amla_vm_scheduler::CollectedOutput {
    let scheduler = scheduler_with_limit(1);
    let config = common::default_config();
    let vm = with_phase_timeout(
        "scheduled cwd create VM",
        scheduler.create_vm(config.clone(), scheduler_backends(&config)),
    )
    .await
    .expect("create scheduler VM");
    let vm = with_phase_timeout(
        "scheduled cwd load kernel",
        vm.load_kernel(common::kernel()),
    )
    .await
    .expect("load scheduler VM");
    let (_vm, output) = with_timeout(
        "scheduled cwd run",
        common::boot_timeout() + common::boot_timeout(),
        vm.run(async move |vm| {
            let vm = vm.start();
            let setup = with_phase_timeout(
                "scheduled cwd mkdir exec",
                vm.exec(["/bin/amla-guest", "mkdir", "/tmp/parity-cwd-marker"]),
            )
            .await
            .expect("scheduled mkdir");
            assert_eq!(
                with_phase_timeout("scheduled cwd mkdir collect", collect_scheduled(setup))
                    .await
                    .exit_code,
                0
            );
            let cmd = with_phase_timeout(
                "scheduled cwd ls exec",
                vm.exec(["/bin/amla-guest", "ls", "."]).cwd("/tmp"),
            )
            .await
            .expect("scheduled cwd exec");
            with_phase_timeout("scheduled cwd ls collect", collect_scheduled(cmd)).await
        }),
    )
    .await
    .expect("run scheduler VM");
    output
}

async fn direct_spec() -> amla_vmm::CollectedOutput {
    with_direct_vm(async move |vm| {
        let spec = CommandSpec::new(["/bin/amla-guest", "printenv", "SPEC_PARITY"])
            .expect("spec")
            .with_env(["SPEC_PARITY=spec-ok"])
            .expect("spec env");
        let cmd = vm.exec_spec(spec).await.expect("direct exec_spec");
        collect_direct(cmd).await
    })
    .await
}

async fn scheduled_spec() -> amla_vm_scheduler::CollectedOutput {
    with_scheduled_vm(async move |vm| {
        let spec = CommandSpec::new(["/bin/amla-guest", "printenv", "SPEC_PARITY"])
            .expect("spec")
            .with_env(["SPEC_PARITY=spec-ok"])
            .expect("spec env");
        let cmd = vm.exec_spec(spec).await.expect("scheduled exec_spec");
        collect_scheduled(cmd).await
    })
    .await
}

async fn direct_pty() -> amla_vmm::CollectedOutput {
    with_direct_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "echo", "pty-parity"])
            .await
            .expect("direct pty");
        tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
            .await
            .expect("direct pty timed out")
            .expect("direct pty collect")
    })
    .await
}

async fn scheduled_pty() -> amla_vm_scheduler::CollectedOutput {
    with_scheduled_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "echo", "pty-parity"])
            .await
            .expect("scheduled pty");
        tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
            .await
            .expect("scheduled pty timed out")
            .expect("scheduled pty collect")
    })
    .await
}

async fn direct_auto_eof_cat() -> amla_vmm::CollectedOutput {
    with_direct_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "cat"])
            .await
            .expect("direct cat");
        collect_direct(cmd).await
    })
    .await
}

async fn scheduled_auto_eof_cat() -> amla_vm_scheduler::CollectedOutput {
    with_scheduled_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "cat"])
            .await
            .expect("scheduled cat");
        collect_scheduled(cmd).await
    })
    .await
}

async fn direct_stderr() -> amla_vmm::CollectedOutput {
    with_direct_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "cat", "/definitely-missing-parity-file"])
            .await
            .expect("direct stderr cat");
        collect_direct(cmd).await
    })
    .await
}

async fn scheduled_stderr() -> amla_vm_scheduler::CollectedOutput {
    with_scheduled_vm(async move |vm| {
        let cmd = vm
            .exec(["/bin/amla-guest", "cat", "/definitely-missing-parity-file"])
            .await
            .expect("scheduled stderr cat");
        collect_scheduled(cmd).await
    })
    .await
}

async fn direct_concurrent_commands() -> Vec<(i32, Vec<u8>, Vec<u8>)> {
    with_direct_vm(async move |vm| {
        let (a, b, c) = tokio::join!(
            vm.exec(["/bin/amla-guest", "echo", "marker-alpha"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-bravo"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-charlie"]),
        );
        let (a, b, c) = tokio::join!(
            collect_direct(a.expect("direct alpha")),
            collect_direct(b.expect("direct bravo")),
            collect_direct(c.expect("direct charlie")),
        );
        vec![
            (a.exit_code, a.stdout, a.stderr),
            (b.exit_code, b.stdout, b.stderr),
            (c.exit_code, c.stdout, c.stderr),
        ]
    })
    .await
}

async fn scheduled_concurrent_commands() -> Vec<(i32, Vec<u8>, Vec<u8>)> {
    with_scheduled_vm(async move |vm| {
        let (a, b, c) = tokio::join!(
            vm.exec(["/bin/amla-guest", "echo", "marker-alpha"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-bravo"]),
            vm.exec(["/bin/amla-guest", "echo", "marker-charlie"]),
        );
        let (a, b, c) = tokio::join!(
            collect_scheduled(a.expect("scheduled alpha")),
            collect_scheduled(b.expect("scheduled bravo")),
            collect_scheduled(c.expect("scheduled charlie")),
        );
        vec![
            (a.exit_code, a.stdout, a.stderr),
            (b.exit_code, b.stdout, b.stderr),
            (c.exit_code, c.stdout, c.stderr),
        ]
    })
    .await
}

async fn direct_split_stdout_exit() -> (Vec<u8>, i32) {
    with_direct_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "dd", "bs=14", "count=1"])
            .await
            .expect("direct pty dd");
        let writer = cmd.stdin_writer();
        let mut stdout = cmd.take_stdout().expect("direct take stdout");
        let exit = cmd.take_exit().expect("direct take exit");

        writer
            .write(b"concurrent-ok\n")
            .await
            .expect("direct write");

        let exit_code = tokio::time::timeout(common::boot_timeout(), exit)
            .await
            .expect("direct exit timed out")
            .expect("direct exit channel");
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_millis(100), stdout.recv())
            .await
            .unwrap_or(None)
        {
            bytes.extend_from_slice(&chunk);
        }
        (bytes, exit_code)
    })
    .await
}

async fn scheduled_split_stdout_exit() -> (Vec<u8>, i32) {
    with_scheduled_vm(async move |vm| {
        let mut cmd = vm
            .exec_pty(["/bin/amla-guest", "dd", "bs=14", "count=1"])
            .await
            .expect("scheduled pty dd");
        let writer = cmd.stdin_writer();
        let mut stdout = cmd.take_stdout().expect("scheduled take stdout");
        let exit = cmd.take_exit().expect("scheduled take exit");

        writer
            .write(b"concurrent-ok\n")
            .await
            .expect("scheduled write");

        let exit_code = tokio::time::timeout(common::boot_timeout(), exit)
            .await
            .expect("scheduled exit timed out")
            .expect("scheduled exit channel");
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_millis(100), stdout.recv())
            .await
            .unwrap_or(None)
        {
            bytes.extend_from_slice(&chunk);
        }
        (bytes, exit_code)
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_echo_matches_direct_vmm_echo() {
    if common::skip() {
        return;
    }

    let argv = ["/bin/amla-guest", "echo", "api-parity"];
    let direct = with_phase_timeout("direct echo parity", direct_exec(&argv)).await;
    let scheduled = with_phase_timeout("scheduled echo parity", scheduled_exec(&argv)).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_exit_status_matches_direct_vmm_exit_status() {
    if common::skip() {
        return;
    }

    let argv = ["/bin/amla-guest", "exit-with", "37"];
    let direct = with_phase_timeout("direct exit-status parity", direct_exec(&argv)).await;
    let scheduled = with_phase_timeout("scheduled exit-status parity", scheduled_exec(&argv)).await;

    assert_eq!(scheduled.exit_code, 37);
    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stderr, direct.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_env_builder_matches_direct_vmm_env_builder() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct env parity", direct_env()).await;
    let scheduled = with_phase_timeout("scheduled env parity", scheduled_env()).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_stdin_matches_direct_vmm_stdin() {
    if common::skip() {
        return;
    }

    let input = "stdin parity\n";
    let direct = with_phase_timeout("direct stdin parity", direct_cat(input)).await;
    let scheduled = with_phase_timeout("scheduled stdin parity", scheduled_cat(input)).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_cwd_builder_matches_direct_vmm_cwd_builder() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct cwd parity", direct_cwd()).await;
    let scheduled = scheduled_cwd().await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert!(scheduled.stdout_str().contains("parity-cwd-marker"));
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_exec_spec_matches_direct_vmm_exec_spec() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct exec_spec parity", direct_spec()).await;
    let scheduled = with_phase_timeout("scheduled exec_spec parity", scheduled_spec()).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
    assert!(scheduled.stdout_str().contains("spec-ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_pty_matches_direct_vmm_pty() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct pty parity", direct_pty()).await;
    let scheduled = with_phase_timeout("scheduled pty parity", scheduled_pty()).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert!(scheduled.stdout_str().contains("pty-parity"));
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_collect_output_auto_eof_matches_direct_vmm() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct auto-eof parity", direct_auto_eof_cat()).await;
    let scheduled = with_phase_timeout("scheduled auto-eof parity", scheduled_auto_eof_cat()).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
    assert!(scheduled.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_stderr_capture_matches_direct_vmm() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout("direct stderr parity", direct_stderr()).await;
    let scheduled = with_phase_timeout("scheduled stderr parity", scheduled_stderr()).await;

    assert_eq!(scheduled.exit_code, direct.exit_code);
    assert_eq!(scheduled.stdout, direct.stdout);
    assert_eq!(scheduled.stderr, direct.stderr);
    assert!(
        scheduled
            .stderr_str()
            .contains("definitely-missing-parity-file")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_concurrent_exec_matches_direct_vmm() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout(
        "direct concurrent exec parity",
        direct_concurrent_commands(),
    )
    .await;
    let scheduled = with_phase_timeout(
        "scheduled concurrent exec parity",
        scheduled_concurrent_commands(),
    )
    .await;

    assert_eq!(scheduled, direct);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduled_split_stdout_and_exit_match_direct_vmm() {
    if common::skip() {
        return;
    }

    let direct = with_phase_timeout(
        "direct split stdout/exit parity",
        direct_split_stdout_exit(),
    )
    .await;
    let scheduled = with_phase_timeout(
        "scheduled split stdout/exit parity",
        scheduled_split_stdout_exit(),
    )
    .await;

    assert_eq!(scheduled.1, direct.1);
    assert_eq!(scheduled.0, direct.0);
    assert!(String::from_utf8_lossy(&scheduled.0).contains("concurrent-ok"));
}
