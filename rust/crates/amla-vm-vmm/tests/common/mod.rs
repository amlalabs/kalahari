// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use amla_mem::MemHandle;
use amla_vmm::backend::BackendPools;
use amla_vmm::{
    Backends, CollectedOutput, CommandExecution, ConsoleStream, NetConfig, Ready, VirtualMachine,
    VmConfig, Zygote,
};

/// Shared rootfs built at runtime from embedded binaries.
///
/// Built once via `LazyLock` on first access. Includes test binaries
/// when the `test-binaries` feature is enabled on `amla-guest-rootfs`.
static TEST_ROOTFS: LazyLock<MemHandle> = LazyLock::new(|| {
    let prepared = build_test_rootfs();
    // Page-align the handle size: the vmstate mapping layer rounds image_size
    // up to PAGE_SIZE (16 KiB) for KVM, so the backing handle must be at
    // least that large.
    #[allow(clippy::cast_possible_truncation)] // 64-bit only
    let aligned_size = amla_core::vm_state::page_align(prepared.image_size() as u64) as usize;
    MemHandle::allocate_and_write(c"erofs", aligned_size, |buf| {
        prepared
            .write_to(&mut buf[..prepared.image_size()])
            .map_err(std::io::Error::other)
    })
    .expect("test rootfs handle")
});

/// Shared kernel bytes.
static KERNEL: &[u8] = amla_guest_rootfs::KERNEL;

/// Shared pool for 1-vCPU tests (most test suites).
///
/// Created lazily on first access. All tests using `pools()` share the
/// same KVM shells, avoiding fd exhaustion under concurrent test execution.
static POOLS: LazyLock<BackendPools> = LazyLock::new(|| {
    init_logging();
    let config = default_config();
    BackendPools::new(4, &config, worker_config()).expect("create shared pools")
});

/// Shared pool for 1-vCPU tests with networking (net + pmem device layout).
///
/// Network tests need a different device layout than `POOLS` because they
/// include a virtio-net device. All network test files share this pool.
static NET_POOLS: LazyLock<BackendPools> = LazyLock::new(|| {
    init_logging();
    let config = test_vm_config()
        .memory_mb(128)
        .pmem_root(rootfs_handle().size().as_u64())
        .net(NetConfig::default());
    BackendPools::new(4, &config, worker_config()).expect("create shared net pools")
});

pub fn worker_config() -> amla_vmm::WorkerProcessConfig {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        platform_worker_config("AMLA_HVF_WORKER", "amla-hvf-worker")
    }

    #[cfg(all(target_os = "linux", feature = "subprocess"))]
    {
        platform_worker_config("AMLA_KVM_WORKER", "amla-kvm-worker")
    }

    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", feature = "subprocess")
    )))]
    {
        amla_vmm::WorkerProcessConfig::path("unused-test-worker")
    }
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", feature = "subprocess")
))]
fn platform_worker_config(env_var: &str, binary_name: &str) -> amla_vmm::WorkerProcessConfig {
    if let Some(path) = std::env::var_os(env_var) {
        return amla_vmm::WorkerProcessConfig::path(path);
    }

    amla_vmm::WorkerProcessConfig::path(worker_path_next_to_target_dir(binary_name))
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", feature = "subprocess")
))]
fn worker_path_next_to_target_dir(binary_name: &str) -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("resolve test executable path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.push(binary_name);
    path
}

pub fn backend_pools(pool_size: usize, config: &amla_vmm::VmConfig) -> BackendPools {
    BackendPools::new(pool_size, config, worker_config()).expect("create pools")
}

fn build_test_rootfs() -> amla_erofs::BuiltImage {
    // All test subcommands are compiled into the single /bin/amla-guest binary
    // (via the test-binaries feature). No separate files needed.
    amla_guest_rootfs::RootfsBuilder::base()
        .build()
        .expect("finalize test rootfs")
}

/// Collect all output from a streaming `CommandExecution` until exit.
///
/// Delegates to [`CommandExecution::collect_output()`] — the canonical
/// concurrent-drain implementation. This wrapper just unwraps the `Result`
/// for test ergonomics.
pub async fn collect_output(mut exec: CommandExecution) -> CollectedOutput {
    tokio::time::timeout(std::time::Duration::from_mins(1), exec.collect_output())
        .await
        .expect("collect_output timed out (guest exec unresponsive after 60s)")
        .expect("collect_output failed")
}

/// Run a tiny guest command to prove the VM has actually started.
pub async fn run_true(vm: &amla_vmm::VmHandle<'_>, timeout: Duration) {
    let cmd = vm
        .exec(["/bin/amla-guest", "true"])
        .await
        .expect("probe exec");
    let output = tokio::time::timeout(timeout, collect_output(cmd))
        .await
        .expect("probe exec timed out");
    assert_eq!(output.exit_code, 0, "probe exec failed");
}

/// Check if the platform hypervisor is available.
///
/// Delegates to [`amla_vmm::available()`] which probes the backend
/// (KVM on Linux, HVF on macOS, WHP on Windows).
pub fn hypervisor_available() -> bool {
    amla_vmm::available()
}

/// EROFS rootfs image (fd-backed handle built from embedded binaries).
pub fn rootfs_handle() -> MemHandle {
    TEST_ROOTFS.try_clone().expect("clone test rootfs handle")
}

/// Check if test prerequisites are met.
pub fn skip_checks() -> Option<&'static str> {
    if !hypervisor_available() {
        return Some("Hypervisor not available (KVM/HVF/WHP)");
    }
    None
}

/// Initialize logging for tests.
///
/// Logs to `/tmp/amla-test-<pid>.log`. Includes thread name in each line
/// so you can grep by test name.
pub fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        env_logger::try_init().ok();
    });
}

/// Assert that serial output contains a marker string.
pub fn assert_serial(output: &str, marker: &str, context: &str) {
    assert!(
        output.contains(marker),
        "{context}\nExpected marker: {marker}\nSerial output:\n{output}",
    );
}

/// Boot timeout accounting for emulation overhead.
///
/// ARM64 tests run under QEMU TCG (software CPU emulation) which is ~5-10x
/// slower than native KVM. Multi-vCPU tests are even slower because TCG
/// serializes vCPU execution. Cumulative test runs also slow down later tests
/// due to memory pressure in the QEMU VM.
///
/// Returns 600s on ARM64 (QEMU TCG is extremely slow), 60s elsewhere.
pub const fn boot_timeout() -> Duration {
    if cfg!(target_arch = "aarch64") {
        Duration::from_mins(10)
    } else {
        Duration::from_mins(1)
    }
}

/// Drain all buffered console output from a `ConsoleStream` as a string.
///
/// Drains the output buffer and returns lossy UTF-8.
pub fn drainconsole(console: &mut ConsoleStream) -> String {
    String::from_utf8_lossy(&console.drain()).to_string()
}

/// Assert that a spawn closure completed before the timeout.
pub fn assert_not_timed_out(start: Instant, timeout: Duration, context: &str) {
    assert!(
        start.elapsed() < timeout,
        "{context}: timed out after {:.1}s (limit={:.1}s)",
        start.elapsed().as_secs_f64(),
        timeout.as_secs_f64()
    );
}

/// Get the host's routable IPv4 address (UDP socket trick).
pub fn get_host_ip() -> Ipv4Addr {
    use std::net::{SocketAddr, UdpSocket};
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind UDP socket");
    socket.connect("8.8.8.8:53").expect("connect UDP socket");
    match socket.local_addr().expect("local addr") {
        SocketAddr::V4(addr) => *addr.ip(),
        SocketAddr::V6(_) => panic!("Expected IPv4 address"),
    }
}

/// `VmConfig` with seccomp disabled for tests.
///
/// Seccomp is permanent and process-wide (TSYNC). Enabling it in tests
/// blocks coverage tools (tarpaulin, llvm-cov) and can interfere with
/// Base test config with defaults.
pub fn test_vm_config() -> VmConfig {
    VmConfig::default()
}

/// Standard test config: 128 MB, pmem root (EROFS via virtio-pmem).
///
/// Uses `image_size` only — actual image handles are passed via [`default_backends`].
pub fn default_config() -> VmConfig {
    test_vm_config()
        .memory_mb(128)
        .pmem_root(rootfs_handle().size().as_u64())
}

/// Default backends for a config that uses the standard rootfs image.
///
/// Returns `(console, pmem_images)` — caller constructs `Backends` from these.
pub fn default_backends(config: &VmConfig) -> (ConsoleStream, Vec<MemHandle>) {
    let console = ConsoleStream::new();
    let pmem: Vec<MemHandle> = config.pmem_disks.iter().map(|_| rootfs_handle()).collect();
    (console, pmem)
}

/// Shared pool for 1-vCPU tests.
pub fn pools() -> &'static BackendPools {
    &POOLS
}

/// Shared pool for 1-vCPU tests with networking.
pub fn net_pools() -> &'static BackendPools {
    &NET_POOLS
}

/// Shared kernel bytes.
pub fn kernel() -> &'static [u8] {
    KERNEL
}

/// Return true (and print reason) if tests should be skipped.
pub fn skip() -> bool {
    if let Some(reason) = skip_checks() {
        eprintln!("Skipping: {reason}");
        return true;
    }
    false
}

/// Boot a VM through the full lifecycle to Ready state.
///
/// Caller owns the backends (console, pmem images) and passes them in.
/// The returned `VirtualMachine<Ready<'a>>` borrows from the caller's
/// `backends`, which must outlive the returned VM. Backend pool handles are
/// cloned into the VM shell and need not be borrowed by `Ready`.
pub async fn boot_to_ready<'a, F: amla_fuse::fuse::FsBackend>(
    pools: &'a BackendPools,
    config: VmConfig,
    backends: Backends<'a, F>,
) -> VirtualMachine<Ready<'a, F>> {
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(pools, kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = boot_timeout();
    let start = Instant::now();
    let (vm, ()) = vm
        .run(async move |handle| {
            let handle = handle.start();
            let mut cmd = handle
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("probe exec");
            drop(cmd.close_stdin().await);
            drop(tokio::time::timeout(timeout, cmd.wait()).await);
        })
        .await
        .expect("run VM");
    assert_not_timed_out(start, timeout, "boot_to_ready");
    vm
}

/// Boot a VM and freeze it into a zygote.
///
/// Creates its own console and backends internally — the zygote doesn't
/// borrow from them (freeze drops the Ready state).
pub async fn create_zygote(pools: &BackendPools, config: VmConfig) -> VirtualMachine<Zygote> {
    let (console, pmem) = default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = boot_to_ready(pools, config, backends).await;
    vm.freeze().await.expect("freeze to zygote")
}
