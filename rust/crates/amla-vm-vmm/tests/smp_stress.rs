// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! SMP stress test for multi-vCPU interrupt delivery.
//!
//! Boots a multi-vCPU VM and runs concurrent CPU-bound work that forces
//! the in-guest scheduler to bounce tasks across CPUs. On macOS/HVF this
//! exercises userspace-GIC cross-vCPU SGI delivery while the target vCPU is
//! in `hv_vcpu_run`; on Linux/KVM it is a generic in-kernel irqchip SMP
//! regression/stress test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use amla_fuse::NullFsBackend;
use amla_vmm::Backends;

mod common;

/// 2-vCPU VM, manually offline/online CPU1 through guest sysfs.
///
/// On aarch64 this exercises PSCI `CPU_OFF`/`CPU_ON` from the guest kernel and
/// catches stale persisted power-state bugs across the VMM `CPU_ON` bus.
#[tokio::test(flavor = "multi_thread")]
async fn test_smp_cpu_hotplug_sysfs_off_on() {
    common::init_logging();
    if common::skip() {
        return;
    }
    if !cfg!(target_arch = "aarch64") {
        eprintln!("Skipping: PSCI CPU_ON sysfs hotplug test is aarch64-specific");
        return;
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        eprintln!("Skipping: CPU hotplug test currently targets Linux/KVM or macOS/HVF");
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(256)
        .vcpu_count(2)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = common::backend_pools(2, &config);

    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };

    let vm = common::boot_to_ready(&pools, config, backends).await;

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cpu1_online = vm
                .exec([
                    "/bin/amla-guest",
                    "cat",
                    "/sys/devices/system/cpu/cpu1/online",
                ])
                .await
                .expect("read cpu1 online");
            let cpu1_online = collect_smp_output(cpu1_online).await;
            if cpu1_online.exit_code != 0 {
                eprintln!(
                    "Skipping: guest kernel does not expose writable cpu1 online state: {}",
                    cpu1_online.stderr_str()
                );
                return;
            }

            wait_for_nproc(&vm, 2).await;

            if let Err(err) = write_guest_file(
                &vm,
                "/sys/devices/system/cpu/cpu1/online",
                b"0\n",
                "offline cpu1",
            )
            .await
            {
                eprintln!("Skipping: guest CPU hotplug offline is unsupported: {err}");
                return;
            }
            wait_for_nproc(&vm, 1).await;

            write_guest_file(
                &vm,
                "/sys/devices/system/cpu/cpu1/online",
                b"1\n",
                "online cpu1",
            )
            .await
            .expect("online cpu1");
            wait_for_nproc(&vm, 2).await;
        })
        .await
        .expect("CPU hotplug run");
}

/// 4-vCPU VM, 8 concurrent CPU-bound `dd` invocations.
#[tokio::test(flavor = "multi_thread")]
async fn test_smp_concurrent_cpu_load() {
    if common::skip() {
        return;
    }
    if !cfg!(any(
        target_os = "linux",
        all(target_os = "macos", target_arch = "aarch64")
    )) {
        eprintln!("Skipping: SMP stress currently targets Linux/KVM or macOS-aarch64/HVF");
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(256)
        .vcpu_count(4)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = common::backend_pools(4, &config);

    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };

    let vm = common::boot_to_ready(&pools, config, backends).await;

    // Confirm SMP came up.
    let (vm, nproc_out): (_, Vec<u8>) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "nproc"])
                .await
                .expect("exec nproc");
            common::collect_output(cmd).await.stdout
        })
        .await
        .expect("nproc run");
    let nproc_str = String::from_utf8_lossy(&nproc_out);
    assert_eq!(nproc_str.trim(), "4", "nproc must report 4 vCPUs");

    // Concurrent CPU-bound load.
    let timeout = Duration::from_mins(1);
    let start = std::time::Instant::now();

    let (_vm, ()) = vm.run(async move |vm| {
        let vm = vm.start();

        let before_interrupts = collect_success(
            vm.exec(["/bin/amla-guest", "cat", "/proc/interrupts"])
                .await
                .expect("read interrupts before load"),
            "read interrupts before load",
        )
        .await;
        let before_interrupts = before_interrupts.stdout_str().into_owned();
        let before_ipis = total_ipi_interrupts(&before_interrupts);

        // 8 concurrent dd invocations, each 64 MiB.
        // With 4 vCPUs and 8 tasks, the scheduler must time-slice and
        // migrate tasks across cores → RESCHED SGIs to busy peer vCPUs.
        // /dev/urandom forces real per-byte CSPRNG work in the kernel,
        // unlike /dev/zero. 64 MiB × 8 procs = 512 MiB of CSPRNG output.
        let dd_args = [
            "/bin/amla-guest",
            "dd",
            "if=/dev/urandom",
            "of=/dev/null",
            "bs=64K",
            "count=1024",
        ];

        let mut cmds = Vec::with_capacity(8);
        for _ in 0..8 {
            cmds.push(vm.exec(dd_args).await.expect("exec dd"));
        }

        // Drain all in parallel.
        let mut handles = Vec::with_capacity(8);
        for c in cmds {
            handles.push(tokio::spawn(async move {
                tokio::time::timeout(timeout, common::collect_output(c)).await
            }));
        }
        let mut outputs = Vec::with_capacity(8);
        for h in handles {
            outputs.push(h.await.expect("join"));
        }

        for (i, out) in outputs.into_iter().enumerate() {
            let out = out.unwrap_or_else(|_| panic!("dd {i} timed out"));
            assert_dd_output(i, &out);
        }

        let after_interrupts = collect_success(
            vm.exec(["/bin/amla-guest", "cat", "/proc/interrupts"])
                .await
                .expect("read interrupts after load"),
            "read interrupts after load",
        )
        .await;
        let after_interrupts = after_interrupts.stdout_str().into_owned();
        let after_ipis = total_ipi_interrupts(&after_interrupts);
        assert!(
            after_ipis > before_ipis,
            "IPI counters should increase during SMP load: before={before_ipis} after={after_ipis}\n\
             before /proc/interrupts:\n{before_interrupts}\n\
             after /proc/interrupts:\n{after_interrupts}"
        );
    })
    .await
    .expect("concurrent dd run");

    let elapsed = start.elapsed();
    eprintln!("8x concurrent dd on 4 vCPUs: {elapsed:?}");
    assert!(
        elapsed < timeout,
        "concurrent dd should complete well under {timeout:?}"
    );
}

async fn collect_success(
    cmd: amla_vmm::CommandExecution,
    context: &str,
) -> amla_vmm::CollectedOutput {
    let output = collect_smp_output(cmd).await;
    assert_eq!(output.exit_code, 0, "{context}");
    output
}

fn assert_dd_output(index: usize, output: &amla_vmm::CollectedOutput) {
    assert_eq!(output.exit_code, 0, "dd {index} exit code");
    assert!(
        output.stderr_str().contains("67108864 bytes copied"),
        "dd {index} should copy exactly 64 MiB; stderr={}",
        output.stderr_str()
    );
}

fn total_ipi_interrupts(interrupts: &str) -> u64 {
    interrupts
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with("IPI") || line.starts_with("RES:") || line.starts_with("CAL:")
        })
        .flat_map(|line| line.split_whitespace().skip(1))
        .filter_map(|token| token.parse::<u64>().ok())
        .sum()
}

async fn write_guest_file(
    vm: &amla_vmm::VmHandle<'_, amla_vmm::Running>,
    path: &str,
    contents: &[u8],
    context: &str,
) -> Result<(), String> {
    let cmd = vm
        .exec(["/bin/amla-guest", "tee", path])
        .await
        .map_err(|e| format!("start tee: {e}"))?;
    cmd.write_stdin(contents)
        .await
        .map_err(|e| format!("write stdin: {e}"))?;
    cmd.close_stdin()
        .await
        .map_err(|e| format!("close stdin: {e}"))?;
    let output = collect_smp_output(cmd).await;
    if output.exit_code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{context}: exit={} stderr={}",
            output.exit_code,
            output.stderr_str()
        ))
    }
}

async fn guest_nproc(vm: &amla_vmm::VmHandle<'_, amla_vmm::Running>) -> u32 {
    let output = collect_smp_output(
        vm.exec(["/bin/amla-guest", "nproc"])
            .await
            .expect("exec nproc"),
    )
    .await;
    assert_eq!(output.exit_code, 0, "nproc");
    output
        .stdout_str()
        .trim()
        .parse()
        .expect("parse nproc output")
}

async fn wait_for_nproc(vm: &amla_vmm::VmHandle<'_, amla_vmm::Running>, expected: u32) {
    let mut last = 0;
    for _ in 0..50 {
        last = guest_nproc(vm).await;
        if last == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for nproc={expected}; last={last}");
}

async fn collect_smp_output(mut exec: amla_vmm::CommandExecution) -> amla_vmm::CollectedOutput {
    let timeout = if cfg!(target_arch = "aarch64") {
        Duration::from_mins(3)
    } else {
        Duration::from_mins(1)
    };
    tokio::time::timeout(timeout, exec.collect_output())
        .await
        .expect("collect_output timed out")
        .expect("collect_output failed")
}
