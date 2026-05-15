// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(dead_code)]

use std::time::Duration;

use std::sync::LazyLock;

use amla_mem::MemHandle;

pub fn hypervisor_available() -> bool {
    amla_vmm::available()
}

pub fn rootfs_handle() -> MemHandle {
    static BENCH_ROOTFS: LazyLock<MemHandle> = LazyLock::new(|| {
        let prepared = amla_guest_rootfs::RootfsBuilder::base()
            .build()
            .expect("finalize bench rootfs");
        MemHandle::allocate_and_write(c"erofs", prepared.image_size(), |buf| {
            prepared.write_to(buf).map_err(std::io::Error::other)
        })
        .expect("bench rootfs handle")
    });
    BENCH_ROOTFS.try_clone().expect("clone bench rootfs handle")
}

pub fn worker_config() -> amla_vmm::WorkerProcessConfig {
    amla_vmm::WorkerProcessConfig::path("unused-bench-worker")
}

pub fn backend_pools(
    pool_size: usize,
    config: &amla_vmm::VmConfig,
) -> amla_vmm::backend::BackendPools {
    amla_vmm::backend::BackendPools::new(pool_size, config, worker_config()).expect("create pools")
}

pub fn skip_checks() -> Option<&'static str> {
    if !hypervisor_available() {
        return Some("Hypervisor not available (KVM/HVF/WHP)");
    }
    None
}

pub fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros == 0 {
        format!("{}ns", d.as_nanos())
    } else if micros < 1_000 {
        format!("{micros}µs")
    } else if micros < 1_000_000 {
        let ms = d.as_secs_f64() * 1000.0;
        format!("{ms:.2}ms")
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

pub fn percentile(data: &mut [Duration], p: f64) -> Duration {
    if data.is_empty() {
        return Duration::ZERO;
    }
    data.sort();
    let len = data.len();
    // p is 0-100, data.len() is small (< 100 samples), so precision loss is irrelevant
    #[allow(clippy::cast_precision_loss)]
    let idx = (p * (len - 1) as f64 / 100.0).round();
    // Clamp to valid range — idx is non-negative after round() since p >= 0
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let idx = (idx as usize).min(len - 1);
    data[idx]
}
