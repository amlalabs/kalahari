// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// Test multiple fresh VMs with the same pools

use std::time::{Duration, Instant};

use amla_mem::MemHandle;
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, VirtualMachine, VmConfig};

fn main() {
    eprintln!("Creating pools...");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let kernel = amla_guest_rootfs::KERNEL;
    let prepared = amla_guest_rootfs::RootfsBuilder::base()
        .build()
        .expect("finalize rootfs");
    let rootfs = MemHandle::allocate_and_write(c"erofs", prepared.image_size(), |buf| {
        prepared.write_to(buf).map_err(std::io::Error::other)
    })
    .expect("rootfs handle");

    let layout_config = VmConfig::default()
        .memory_mb(128)
        .vcpu_count(1)
        .pmem_root(rootfs.size().as_u64());
    let pools = BackendPools::new(
        4,
        &layout_config,
        amla_vmm::WorkerProcessConfig::path("unused-example-worker"),
    )
    .expect("Failed to create pools");

    for i in 0..3 {
        eprintln!("\n=== Creating VM {} ===", i + 1);
        let start = Instant::now();

        let config = VmConfig::default()
            .memory_mb(128)
            .vcpu_count(1)
            .pmem_root(rootfs.size().as_u64());

        let vm = rt.block_on(async { VirtualMachine::create(config).await.expect("create") });

        let console = amla_vmm::ConsoleStream::new();
        let pmem_images: Vec<MemHandle> = vm
            .config()
            .pmem_disks
            .iter()
            .map(|_| rootfs.try_clone().expect("clone rootfs"))
            .collect();
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem: pmem_images,
        };
        let vm = rt
            .block_on(vm.load_kernel(&pools, kernel, backends))
            .expect("load_kernel");

        let (_vm, ()) = rt
            .block_on(async {
                vm.run(async move |vm| {
                    let vm = vm.start();
                    let mut autotest: amla_vmm::CommandExecution = vm
                        .exec(["/bin/amla-guest", "test-autotest"])
                        .await
                        .expect("autotest");
                    drop(autotest.close_stdin().await);
                    drop(tokio::time::timeout(Duration::from_secs(30), autotest.wait()).await);
                })
                .await
            })
            .expect("run");

        eprintln!("  VM {} exited, elapsed={:?}", i + 1, start.elapsed());
    }
    eprintln!("\nAll done!");
}
