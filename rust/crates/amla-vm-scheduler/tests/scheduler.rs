// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for scheduler-owned logical VMs.

#[path = "../../amla-vm-vmm/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use amla_constants::net::DEFAULT_GUEST_MAC;
use amla_core::backends::{NetBackend, NoRxPacket};
use amla_vm_scheduler::{
    CommandExecution, ConsoleStream, LiveShellLimit, NetConfig, RuntimeBackends,
    SchedulerOperationError, VirtualMachine, VmBackends, VmConfig, VmScheduler,
};

const MISMATCHED_GUEST_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

struct FlakyMacNet {
    mismatch: Arc<AtomicBool>,
}

impl FlakyMacNet {
    const fn new(mismatch: Arc<AtomicBool>) -> Self {
        Self { mismatch }
    }
}

impl NetBackend for FlakyMacNet {
    type RxPacket<'a> = NoRxPacket;

    fn guest_mac(&self) -> Option<[u8; 6]> {
        Some(if self.mismatch.load(Ordering::Acquire) {
            MISMATCHED_GUEST_MAC
        } else {
            DEFAULT_GUEST_MAC
        })
    }

    fn send(&self, _bufs: &[IoSlice<'_>]) -> io::Result<()> {
        Ok(())
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Ok(None)
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

fn scheduler_with_limit(limit: usize) -> VmScheduler {
    init_logging();
    VmScheduler::new(
        LiveShellLimit::try_from(limit).unwrap(),
        common::worker_config(),
    )
}

fn init_logging() {
    drop(env_logger::builder().is_test(true).try_init());
}

fn backends_for(config: &VmConfig) -> VmBackends {
    VmBackends::new(ConsoleStream::new()).with_pmem(
        config
            .pmem_disks
            .iter()
            .map(|_| common::rootfs_handle())
            .collect(),
    )
}

async fn parked_vm(
    scheduler: &VmScheduler,
    config: VmConfig,
) -> VirtualMachine<amla_vm_scheduler::Parked> {
    let vm = scheduler
        .create_vm(config.clone(), backends_for(&config))
        .await
        .expect("create scheduler VM");
    vm.load_kernel(common::kernel())
        .await
        .expect("load scheduler VM")
}

async fn parked_flaky_net_vm(
    scheduler: &VmScheduler,
    mismatch: Arc<AtomicBool>,
) -> VirtualMachine<
    amla_vm_scheduler::Parked<
        amla_fuse::NullFsBackend,
        amla_vm_scheduler::NetworkSession<FlakyMacNet>,
    >,
> {
    let config = common::default_config().net(
        NetConfig::default()
            .queue_pairs(1)
            .expect("valid net queue count")
            .mac(DEFAULT_GUEST_MAC),
    );
    let backends = VmBackends::new(ConsoleStream::new())
        .with_pmem(
            config
                .pmem_disks
                .iter()
                .map(|_| common::rootfs_handle())
                .collect(),
        )
        .with_net(FlakyMacNet::new(mismatch));
    scheduler
        .create_vm(config, backends)
        .await
        .expect("create flaky-net VM")
        .load_kernel(common::kernel())
        .await
        .expect("load flaky-net VM")
}

async fn collect_output(mut cmd: CommandExecution) -> amla_vm_scheduler::CollectedOutput {
    tokio::time::timeout(common::boot_timeout(), cmd.collect_output())
        .await
        .expect("command timed out")
        .expect("collect output")
}

async fn wait_for_pending_stdout(stdout: &amla_vm_scheduler::CountedReceiver, context: &str) {
    tokio::time::timeout(common::boot_timeout(), async {
        loop {
            if stdout.has_pending() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: stdout was not buffered before timeout"));
}

async fn wait_for_noisy_output_first_chunk<R, D>(
    run: &mut Pin<&mut R>,
    drain: &mut Pin<&mut D>,
    drain_done: &mut bool,
    first_chunk: tokio::sync::oneshot::Receiver<()>,
) where
    R: Future,
    D: Future<Output = ()>,
{
    let timeout = tokio::time::sleep(common::boot_timeout());
    tokio::pin!(timeout);
    tokio::pin!(first_chunk);
    loop {
        tokio::select! {
            _result = run.as_mut() => {
                panic!("noisy run completed before the command produced stdout");
            }
            () = drain.as_mut(), if !*drain_done => {
                *drain_done = true;
            }
            result = &mut first_chunk => {
                result.expect("stdout drain ended before first output");
                return;
            }
            () = &mut timeout => {
                panic!("noisy command did not produce initial output");
            }
        }
    }
}

async fn wait_for_noisy_output_user_ready<R, D>(
    run: &mut Pin<&mut R>,
    drain: &mut Pin<&mut D>,
    drain_done: &mut bool,
    user_ready: tokio::sync::oneshot::Receiver<()>,
) where
    R: Future,
    D: Future<Output = ()>,
{
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);
    tokio::pin!(user_ready);
    loop {
        tokio::select! {
            _result = run.as_mut() => {
                panic!("noisy run completed before the user future reached its ready point");
            }
            () = drain.as_mut(), if !*drain_done => {
                *drain_done = true;
            }
            result = &mut user_ready => {
                result.expect("noisy user future ended before ready signal");
                return;
            }
            () = &mut timeout => {
                panic!("ready user future should not starve behind output");
            }
        }
    }
}

async fn wait_for_noisy_output_run_result<R, D>(
    run: &mut Pin<&mut R>,
    drain: &mut Pin<&mut D>,
    drain_done: &mut bool,
) -> R::Output
where
    R: Future,
    D: Future<Output = ()>,
{
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            result = run.as_mut() => return result,
            () = drain.as_mut(), if !*drain_done => {
                *drain_done = true;
            }
            () = &mut timeout => {
                panic!("ready run should resolve after user future returned");
            }
        }
    }
}

async fn run_uniform_vm(
    index: usize,
    vm: VirtualMachine<amla_vm_scheduler::Parked>,
) -> (usize, amla_vm_scheduler::CollectedOutput) {
    let marker = format!("many-vm-marker-{index}");
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", marker.as_str()])
                .await
                .expect("exec uniform marker");
            collect_output(cmd).await
        })
        .await
        .expect("run uniform VM");
    (index, output)
}

#[tokio::test(flavor = "multi_thread")]
async fn load_kernel_returns_parked_scheduler_vm() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, output) = tokio::time::timeout(
        common::boot_timeout(),
        vm.run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("exec true");
            collect_output(cmd).await
        }),
    )
    .await
    .expect("loaded VM could not reacquire a shell")
    .expect("run loaded VM");

    assert_eq!(output.exit_code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn load_validation_error_releases_shell_budget() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let config = common::default_config().net(NetConfig::default());
    let vm = scheduler
        .create_vm(config.clone(), backends_for(&config))
        .await
        .expect("create VM");
    let Err(err) = vm.load_kernel(common::kernel()).await else {
        panic!("load without required net backend should fail");
    };

    assert!(matches!(
        err,
        SchedulerOperationError::Vmm(amla_vm_scheduler::Error::Config(
            amla_vm_scheduler::ConfigError::MissingNetBackend,
        ))
    ));
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("exec true");
            collect_output(cmd).await
        })
        .await
        .expect("run after failed load");
    assert_eq!(output.exit_code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_exec_collects_output() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "scheduler-owned-api"])
                .await
                .expect("exec echo");
            collect_output(cmd).await
        })
        .await
        .expect("run VM");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("scheduler-owned-api"));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_accepts_multiple_execs_in_one_epoch() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, (first, second)) = tokio::time::timeout(common::boot_timeout(), async move {
        vm.run(async move |vm| {
            let vm = vm.start();
            let first = vm
                .exec(["/bin/amla-guest", "echo", "first-scheduler-exec"])
                .await
                .expect("exec first command");
            let first = collect_output(first).await;
            let second = vm
                .exec(["/bin/amla-guest", "echo", "second-scheduler-exec"])
                .await
                .expect("exec second command");
            let second = collect_output(second).await;
            (first, second)
        })
        .await
    })
    .await
    .expect("multiple exec run timed out")
    .expect("run multiple execs");

    assert_eq!(first.exit_code, 0);
    assert_eq!(second.exit_code, 0);
    assert!(first.stdout_str().contains("first-scheduler-exec"));
    assert!(second.stdout_str().contains("second-scheduler-exec"));
}

#[tokio::test(flavor = "multi_thread")]
async fn escaped_exec_only_handle_closes_when_run_parks() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, mut escaped) = vm
        .run(async move |vm| {
            let vm = vm.start();
            vm.into_exec_only()
        })
        .await
        .expect("run returns escaped exec-only handle");

    tokio::time::timeout(Duration::from_secs(1), escaped.wait_for_exit())
        .await
        .expect("escaped handle should close when run parks");
    assert!(escaped.has_exited());
    let Err(err) = escaped.exec(["/bin/amla-guest", "true"]).await else {
        panic!("escaped handle should not accept exec after run parks");
    };
    assert!(matches!(err, amla_vm_scheduler::ExecError::Disconnected));
    let pressure = tokio::time::timeout(Duration::from_secs(1), escaped.recv_memory_pressure())
        .await
        .expect("escaped memory-pressure receiver should close");
    assert!(pressure.is_none());
    tokio::time::timeout(Duration::from_secs(1), escaped.shutdown())
        .await
        .expect("escaped shutdown should not hang");

    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "parked-vm-still-runs"])
                .await
                .expect("exec after escaped handle closes");
            collect_output(cmd).await
        })
        .await
        .expect("parked VM should remain usable");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("parked-vm-still-runs"));
}

#[tokio::test(flavor = "multi_thread")]
async fn escaped_run_handle_closes_after_post_preemption_resume_failure() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let mismatch = Arc::new(AtomicBool::new(false));
    let first = parked_flaky_net_vm(&scheduler, Arc::clone(&mismatch)).await;
    let second = parked_vm(&scheduler, common::default_config()).await;

    let (escaped_tx, escaped_rx) = tokio::sync::oneshot::channel();
    let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
    let first_run = first.run(async move |vm| {
        let vm = vm.start();
        let escaped = vm.into_exec_only();
        assert!(
            escaped_tx.send(escaped).is_ok(),
            "escaped handle receiver dropped"
        );
        assert!(
            first_started_tx.send(()).is_ok(),
            "first-start receiver dropped"
        );
        std::future::pending::<()>().await;
    });

    let driver = async move {
        first_started_rx.await.expect("first run did not start");
        let escaped = escaped_rx.await.expect("escaped handle sender dropped");
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let second_run = second.run(async move |vm| {
            let _vm = vm.start();
            assert!(
                second_started_tx.send(()).is_ok(),
                "second-start receiver dropped"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        tokio::pin!(second_run);
        tokio::pin!(second_started_rx);
        tokio::select! {
            _result = second_run.as_mut() => {
                panic!("second run completed before it started");
            }
            result = &mut second_started_rx => {
                result.expect("second run did not start after preemption");
            }
        }
        mismatch.store(true, Ordering::Release);
        let (_second, ()) = second_run.await.expect("second run should finish");
        escaped
    };

    let (first_result, mut escaped) = tokio::time::timeout(common::boot_timeout(), async {
        tokio::join!(first_run, driver)
    })
    .await
    .expect("first run did not fail after resume became invalid");
    let Err(err) = first_result else {
        panic!("first run should fail on post-preemption resume");
    };
    assert!(matches!(
        err,
        amla_vm_scheduler::SchedulerRunError::Resume(_)
    ));

    tokio::time::timeout(Duration::from_secs(1), escaped.wait_for_exit())
        .await
        .expect("escaped run handle should be marked exited on resume failure");
    assert!(escaped.has_exited());
    let pressure = tokio::time::timeout(Duration::from_secs(1), escaped.recv_memory_pressure())
        .await
        .expect("escaped memory pressure receiver should close after resume failure");
    assert!(pressure.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn noisy_output_does_not_starve_ready_run_completion() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (stdout_tx, stdout_rx) =
        tokio::sync::oneshot::channel::<amla_vm_scheduler::CountedReceiver>();
    let (first_chunk_for_run_tx, first_chunk_for_run_rx) = tokio::sync::oneshot::channel();
    let (first_chunk_for_test_tx, first_chunk_for_test_rx) = tokio::sync::oneshot::channel();
    let (user_ready_tx, user_ready_rx) = tokio::sync::oneshot::channel();
    let drain = async move {
        let Ok(mut stdout) = stdout_rx.await else {
            return;
        };
        if stdout.recv().await.is_some() {
            let _sent = first_chunk_for_run_tx.send(());
            let _sent = first_chunk_for_test_tx.send(());
        }
        while stdout.recv().await.is_some() {}
    };
    tokio::pin!(drain);

    let run = vm.run(async move |vm| {
        let vm = vm.start();
        let mut cmd = vm
            .exec([
                "/bin/amla-guest",
                "dd",
                "if=/dev/zero",
                "bs=64K",
                "count=16384",
            ])
            .await
            .expect("exec noisy dd");
        let stdout = cmd.take_stdout().expect("take stdout");
        assert!(stdout_tx.send(stdout).is_ok(), "stdout drain dropped");
        first_chunk_for_run_rx
            .await
            .expect("noisy command did not produce output");
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _sent = user_ready_tx.send(());
        cmd
    });
    tokio::pin!(run);

    let mut drain_done = false;
    wait_for_noisy_output_first_chunk(
        &mut run,
        &mut drain,
        &mut drain_done,
        first_chunk_for_test_rx,
    )
    .await;
    wait_for_noisy_output_user_ready(&mut run, &mut drain, &mut drain_done, user_ready_rx).await;
    let result = wait_for_noisy_output_run_result(&mut run, &mut drain, &mut drain_done).await;

    let Err(_err) = result else {
        panic!("active command should prevent successful run completion");
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_builder_supports_env_like_vmm() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "printenv", "SCHEDULER_ENV_TEST"])
                .env(["SCHEDULER_ENV_TEST=builder-ok"])
                .await
                .expect("exec printenv");
            collect_output(cmd).await
        })
        .await
        .expect("run VM");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("builder-ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_handle_attaches_across_scheduler_run_calls() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, handle) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            cmd.into_handle().expect("cat should be reattachable")
        })
        .await
        .expect("run cat");

    let id = handle.id();
    let (_vm, output) = vm
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            let cmd = vm.take_attached(id).expect("attached cat");
            cmd.write_stdin("durable scheduler stdin\n")
                .await
                .expect("write cat stdin");
            cmd.close_stdin().await.expect("close cat stdin");
            collect_output(cmd).await
        })
        .await
        .expect("reattach cat");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("durable scheduler stdin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_handle_can_be_detached_before_run_returns() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, handle) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            let handle = cmd.into_handle().expect("cat should be reattachable");
            tokio::time::sleep(Duration::from_millis(100)).await;
            handle
        })
        .await
        .expect("run cat after early detach");

    let id = handle.id();
    let (_vm, output) = vm
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            let cmd = vm.take_attached(id).expect("attached cat");
            cmd.write_stdin("early detached stdin\n")
                .await
                .expect("write cat stdin");
            cmd.close_stdin().await.expect("close cat stdin");
            collect_output(cmd).await
        })
        .await
        .expect("reattach early-detached cat");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("early detached stdin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_can_detach_while_internally_preempted() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let first = parked_vm(&scheduler, common::default_config()).await;
    let second = parked_vm(&scheduler, common::default_config()).await;
    let (cmd_tx, cmd_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();

    let first_run = first.run(async move |vm| {
        let vm = vm.start();
        let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
        assert!(cmd_tx.send(cmd).is_ok(), "command receiver dropped");
        finish_rx.await.expect("finish signal dropped");
    });

    let driver = async move {
        let cmd = cmd_rx.await.expect("command sender dropped");
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let second_run = second.run(async move |vm| {
            let _vm = vm.start();
            assert!(
                second_started_tx.send(()).is_ok(),
                "second-start receiver dropped"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let detach = async move {
            second_started_rx.await.expect("second run did not start");
            let handle = cmd
                .into_handle()
                .expect("preempted command should still be reattachable");
            finish_tx.send(()).expect("finish receiver dropped");
            handle
        };
        let (second_result, handle) = tokio::join!(second_run, detach);
        let (second, ()) = second_result.expect("second run should finish");
        (second, handle)
    };

    let (first_result, driver_result) = tokio::join!(first_run, driver);
    let (first, ()) = first_result.expect("first run should finish");
    let (_second, handle) = driver_result;
    let id = handle.id();

    let (_first, output) = first
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            let cmd = vm.take_attached(id).expect("attached cat");
            cmd.write_stdin("preempted detach stdin\n")
                .await
                .expect("write cat stdin");
            cmd.close_stdin().await.expect("close cat stdin");
            collect_output(cmd).await
        })
        .await
        .expect("reattach preempted cat");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("preempted detach stdin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn start_only_run_without_extra_yield_keeps_vm_usable() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, ()) = vm
        .run(async move |vm| {
            let _vm = vm.start();
        })
        .await
        .expect("start-only run");

    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "start-only-still-usable"])
                .await
                .expect("exec after start-only run");
            collect_output(cmd).await
        })
        .await
        .expect("run after start-only");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("start-only-still-usable"));
}

#[tokio::test(flavor = "multi_thread")]
async fn returning_attached_command_without_yield_after_start_is_rejected() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, handle) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            cmd.into_handle().expect("cat should be reattachable")
        })
        .await
        .expect("run cat");
    let id = handle.id();

    let result = vm
        .run(async move |mut vm| {
            vm.attach(handle).unwrap();
            let mut vm = vm.start();
            vm.take_attached(id).expect("attached cat")
        })
        .await;

    let Err(_err) = result else {
        panic!("active attached command must not escape a completed scheduler run");
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_long_running_command_does_not_block_run_return() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (vm, ()) = tokio::time::timeout(Duration::from_secs(10), async move {
        vm.run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "sleep", "300"])
                .await
                .expect("exec long sleep");
            drop(cmd);
        })
        .await
    })
    .await
    .expect("dropping a command should let scheduler run return")
    .expect("run with dropped command");

    let (_vm, output) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("exec after dropped command");
            collect_output(cmd).await
        })
        .await
        .expect("VM remains runnable after dropped command");
    assert_eq!(output.exit_code, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_while_long_running_command_active_does_not_wait_for_command_exit() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
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
                .expect("scheduler VM shutdown should not wait for long-running command exit");
        })
        .await
    })
    .await
    .expect("scheduler VM run with shutdown timed out")
    .expect("scheduler VM run with shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_stdin_command_gets_eof_across_internal_preemption() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let first = parked_vm(&scheduler, common::default_config()).await;
    let second = parked_vm(&scheduler, common::default_config()).await;
    let (command_ready_tx, command_ready_rx) = tokio::sync::oneshot::channel();
    let (drop_command_tx, drop_command_rx) = tokio::sync::oneshot::channel();
    let (second_done_tx, second_done_rx) = tokio::sync::oneshot::channel();

    let first_run = first.run(async move |vm| {
        let vm = vm.start();
        let cmd = vm
            .exec(["/bin/amla-guest", "eof-marker", "/tmp/drop-eof-marker"])
            .await
            .expect("exec eof-sensitive command");
        cmd.write_stdin("payload before drop\n")
            .await
            .expect("write stdin before drop");
        assert!(
            command_ready_tx.send(()).is_ok(),
            "command-ready receiver dropped"
        );
        drop_command_rx.await.expect("drop signal dropped");
        drop(cmd);
        second_done_rx.await.expect("second-run signal dropped");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let marker = vm
                .exec(["/bin/amla-guest", "cat", "/tmp/drop-eof-marker"])
                .await
                .expect("exec marker cat");
            let output = collect_output(marker).await;
            if output.exit_code == 0 && output.stdout_str().contains("eof-seen") {
                break output;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "dropped command did not observe scheduler-sent EOF before preemption"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let second_run = async move {
        command_ready_rx
            .await
            .expect("command did not become ready");
        let run = second.run(async move |vm| {
            let _vm = vm.start();
        });
        tokio::pin!(run);
        let drop_after_pressure = tokio::task::yield_now();
        tokio::pin!(drop_after_pressure);
        let mut drop_command_tx = Some(drop_command_tx);
        loop {
            tokio::select! {
                biased;

                result = run.as_mut() => {
                    if let Some(sender) = drop_command_tx.take() {
                        assert!(sender.send(()).is_ok(), "drop receiver dropped");
                    }
                    assert!(second_done_tx.send(()).is_ok(), "second-done receiver dropped");
                    break result;
                }
                () = &mut drop_after_pressure, if drop_command_tx.is_some() => {
                    let sender = drop_command_tx.take().expect("drop sender should be present");
                    assert!(sender.send(()).is_ok(), "drop receiver dropped");
                }
            }
        }
    };

    let (first_result, second_result) = tokio::time::timeout(common::boot_timeout(), async {
        tokio::join!(first_run, second_run)
    })
    .await
    .expect("dropped stdin preemption test timed out");
    let (_second, ()) = second_result.expect("second run should finish");
    let (_first, output) = first_result.expect("first run should finish");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("eof-seen"));
}

#[tokio::test(flavor = "multi_thread")]
async fn split_stdout_keeps_unread_output_visible_to_reattach_checks() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            let mut stdout = cmd.take_stdout().expect("take stdout");

            cmd.write_stdin("first split chunk\n")
                .await
                .expect("write first chunk");
            let first = tokio::time::timeout(common::boot_timeout(), stdout.recv())
                .await
                .expect("first stdout chunk timed out")
                .expect("first stdout chunk");
            assert!(String::from_utf8_lossy(&first).contains("first split chunk"));

            for _ in 0..16 {
                cmd.write_stdin("unread split chunk\n")
                    .await
                    .expect("write unread chunk");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;

            let err = cmd
                .into_handle()
                .expect_err("unread split stdout must prevent reattach");
            assert!(matches!(
                err.source(),
                amla_vm_scheduler::ExecError::NotReattachable { .. }
            ));

            let mut cmd = err.into_command();
            drop(stdout);
            cmd.close_stdin().await.expect("close stdin");
            let code = tokio::time::timeout(common::boot_timeout(), cmd.wait())
                .await
                .expect("cat exit timed out")
                .expect("cat exit");
            assert_eq!(code, 0);
        })
        .await
        .expect("run split stdout reattach check");
}

#[tokio::test(flavor = "multi_thread")]
async fn command_collect_output_with_limit_matches_vmm_limit_behavior() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, err) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm
                .exec(["/bin/amla-guest", "echo", "limit-output"])
                .await
                .expect("exec echo");
            let err =
                tokio::time::timeout(common::boot_timeout(), cmd.collect_output_with_limit(1))
                    .await
                    .expect("echo timed out")
                    .expect_err("small limit should reject captured output");
            while let Some(event) = cmd.recv_output().await {
                if matches!(event, amla_vm_scheduler::OutputEvent::Exit(_)) {
                    break;
                }
            }
            err
        })
        .await
        .expect("run VM");

    assert!(matches!(
        err,
        amla_vm_scheduler::ExecError::OutputLimitExceeded { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduler_preempts_yielding_run_to_release_shell_budget() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let first = parked_vm(&scheduler, common::default_config()).await;
    let second = parked_vm(&scheduler, common::default_config()).await;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let first_run = first.run(async move |vm| {
        let _vm = vm.start();
        assert!(started_tx.send(()).is_ok(), "start receiver dropped");
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let second_run = async move {
        started_rx.await.expect("first run started");
        tokio::time::timeout(
            Duration::from_secs(10),
            second.run(async move |vm| {
                let _vm = vm.start();
            }),
        )
        .await
    };

    let (first_result, second_result) = tokio::join!(first_run, second_run);
    let (_second, ()) = second_result
        .expect("second logical VM should run during first VM sleep")
        .expect("second run succeeds");
    let (_first, ()) = first_result.expect("first run succeeds");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_logical_vms_share_smaller_shell_limit_uniformly() {
    const VM_COUNT: usize = 8;
    const SHELL_LIMIT: usize = 2;

    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(SHELL_LIMIT);
    let mut vms = Vec::with_capacity(VM_COUNT);
    for _ in 0..VM_COUNT {
        vms.push(parked_vm(&scheduler, common::default_config()).await);
    }

    let vm0 = vms.remove(0);
    let vm1 = vms.remove(0);
    let vm2 = vms.remove(0);
    let vm3 = vms.remove(0);
    let vm4 = vms.remove(0);
    let vm5 = vms.remove(0);
    let vm6 = vms.remove(0);
    let vm7 = vms.remove(0);

    let results = tokio::time::timeout(common::boot_timeout(), async move {
        tokio::join!(
            run_uniform_vm(0, vm0),
            run_uniform_vm(1, vm1),
            run_uniform_vm(2, vm2),
            run_uniform_vm(3, vm3),
            run_uniform_vm(4, vm4),
            run_uniform_vm(5, vm5),
            run_uniform_vm(6, vm6),
            run_uniform_vm(7, vm7),
        )
    })
    .await
    .expect("many logical VMs should all complete under shell limit");

    let outputs: [_; 8] = results.into();
    for (index, output) in outputs {
        assert_eq!(output.exit_code, 0, "VM {index} failed: {output:?}");
        let expected = format!("many-vm-marker-{index}");
        assert!(
            output.stdout_str().contains(&expected),
            "VM {index} output did not contain {expected:?}: {output:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn active_command_survives_internal_preemption() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let first = parked_vm(&scheduler, common::default_config()).await;
    let second = parked_vm(&scheduler, common::default_config()).await;
    let (command_started_tx, command_started_rx) = tokio::sync::oneshot::channel();
    let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();

    let first_run = first.run(async move |vm| {
        let vm = vm.start();
        let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
        assert!(
            command_started_tx.send(()).is_ok(),
            "command-start receiver dropped"
        );
        second_started_rx
            .await
            .expect("second run did not start during command lifetime");
        cmd.write_stdin("after-preempt\n")
            .await
            .expect("write after preempt");
        cmd.close_stdin().await.expect("close stdin");
        collect_output(cmd).await
    });
    let second_run = async move {
        command_started_rx.await.expect("command did not start");
        second
            .run(async move |vm| {
                let _vm = vm.start();
                assert!(
                    second_started_tx.send(()).is_ok(),
                    "second-start receiver dropped"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            })
            .await
    };

    let (first_result, second_result) = tokio::time::timeout(common::boot_timeout(), async {
        tokio::join!(first_run, second_run)
    })
    .await
    .expect("active command preemption test timed out");
    let (_second, ()) = second_result.expect("second run should finish");
    let (_first, output) = first_result.expect("run command across internal preemption");

    assert_eq!(output.exit_code, 0);
    let stdout = output.stdout_str();
    assert!(stdout.contains("after-preempt"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn active_vm_is_not_preempted_without_shell_pressure() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let mismatch = Arc::new(AtomicBool::new(false));
    let vm = parked_flaky_net_vm(&scheduler, Arc::clone(&mismatch)).await;
    let (_vm, output) = tokio::time::timeout(common::boot_timeout(), async move {
        vm.run(async move |vm| {
            let vm = vm.start();
            mismatch.store(true, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(150)).await;
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "no-pressure-still-running"])
                .await
                .expect("exec after idle quantum");
            collect_output(cmd).await
        })
        .await
    })
    .await
    .expect("run without shell pressure timed out")
    .expect("run without shell pressure");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("no-pressure-still-running"));
}

#[tokio::test(flavor = "multi_thread")]
async fn full_scheduler_output_buffer_does_not_deadlock_preemption() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, total_stdout) = tokio::time::timeout(common::boot_timeout(), async move {
        vm.run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm
                .exec([
                    "/bin/amla-guest",
                    "dd",
                    "if=/dev/zero",
                    "bs=64K",
                    "count=128",
                ])
                .await
                .expect("exec dd");
            let mut stdout = cmd.take_stdout().expect("take dd stdout");

            tokio::time::sleep(Duration::from_millis(200)).await;

            let mut total_stdout = 0usize;
            while let Some(chunk) = stdout.recv().await {
                total_stdout += chunk.len();
            }
            while cmd.recv_stderr().await.is_some() {}
            let code = cmd.wait().await.expect("dd exit");
            assert_eq!(code, 0);
            total_stdout
        })
        .await
    })
    .await
    .expect("full scheduler output should not deadlock preemption")
    .expect("run full-output command");

    assert_eq!(total_stdout, 8 * 1024 * 1024);
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduler_buffered_output_blocks_visible_reattach_after_preemption() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let vm = parked_vm(&scheduler, common::default_config()).await;
    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let mut cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            let mut stdout = cmd.take_stdout().expect("take stdout");
            cmd.write_stdin("first-across-preempt\n")
                .await
                .expect("write first line");
            let first = tokio::time::timeout(common::boot_timeout(), stdout.recv())
                .await
                .expect("first stdout timed out")
                .expect("first stdout chunk");
            assert!(String::from_utf8_lossy(&first).contains("first-across-preempt"));

            for _ in 0..16 {
                cmd.write_stdin("buffered-across-preempt\n")
                    .await
                    .expect("write buffered line");
            }
            wait_for_pending_stdout(&stdout, "scheduler buffered detach test").await;

            let err = cmd
                .into_handle()
                .expect_err("scheduler-buffered stdout must prevent visible reattach");
            assert!(matches!(
                err.source(),
                amla_vm_scheduler::ExecError::NotReattachable { .. }
            ));

            let mut cmd = err.into_command();
            drop(stdout);
            let first = tokio::time::timeout(common::boot_timeout(), cmd.recv_stdout())
                .await
                .expect("recv_stdout after taken stdout timed out");
            assert!(first.is_none());
            cmd.close_stdin().await.expect("close stdin");
            let code = tokio::time::timeout(common::boot_timeout(), cmd.wait())
                .await
                .expect("cat wait timed out")
                .expect("cat exit");
            assert_eq!(code, 0);
        })
        .await
        .expect("run buffered output preemption test");
}

#[tokio::test(flavor = "multi_thread")]
async fn zygote_spawn_uses_scheduler_owned_runtime_backends() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let parked = parked_vm(&scheduler, common::default_config()).await;
    let zygote = parked.freeze().await.expect("freeze scheduler VM");
    let child = zygote
        .spawn(RuntimeBackends::new(ConsoleStream::new()))
        .await
        .expect("spawn scheduler child");
    let (_child, output) = child
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "scheduler-spawn-ok"])
                .await
                .expect("exec child echo");
            collect_output(cmd).await
        })
        .await
        .expect("run child");
    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("scheduler-spawn-ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn zygote_spawn_preserves_guest_state() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let parked = parked_vm(&scheduler, common::default_config()).await;
    let (parked, ()) = parked
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "tee", "/tmp/scheduler_state_marker"])
                .await
                .expect("exec tee");
            cmd.write_stdin(b"scheduler-freeze-token\n")
                .await
                .expect("write marker");
            let output = collect_output(cmd).await;
            assert_eq!(output.exit_code, 0);
        })
        .await
        .expect("write state marker");

    let zygote = parked.freeze().await.expect("freeze scheduler VM");
    let child = zygote
        .spawn(RuntimeBackends::new(ConsoleStream::new()))
        .await
        .expect("spawn scheduler child");
    let (_child, output) = child
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "cat", "/tmp/scheduler_state_marker"])
                .await
                .expect("exec cat");
            collect_output(cmd).await
        })
        .await
        .expect("run child");

    assert_eq!(output.exit_code, 0);
    assert!(output.stdout_str().contains("scheduler-freeze-token"));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_handle_clones_attach_across_scheduler_zygote_spawns() {
    if common::skip() {
        return;
    }

    let scheduler = scheduler_with_limit(1);
    let parked = parked_vm(&scheduler, common::default_config()).await;
    let (parked, handle) = parked
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(["/bin/amla-guest", "cat"]).await.expect("exec cat");
            cmd.into_handle().expect("cat should be reattachable")
        })
        .await
        .expect("run cat");
    let id = handle.id();

    let zygote = parked.freeze().await.expect("freeze scheduler VM");

    for (handle, input) in [
        (handle.clone(), "first zygote attach stdin\n"),
        (handle, "second zygote attach stdin\n"),
    ] {
        let child = zygote
            .spawn(RuntimeBackends::new(ConsoleStream::new()))
            .await
            .expect("spawn scheduler child");
        let (_child, output) = child
            .run(async move |mut vm| {
                vm.attach(handle).unwrap();
                let mut vm = vm.start();
                let cmd = vm.take_attached(id).expect("attached cat");
                cmd.write_stdin(input).await.expect("write cat stdin");
                cmd.close_stdin().await.expect("close cat stdin");
                collect_output(cmd).await
            })
            .await
            .expect("reattach cat on spawned child");

        assert_eq!(output.exit_code, 0);
        assert!(output.stdout_str().contains(input));
    }
}
