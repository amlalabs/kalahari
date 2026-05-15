//! Reusable container engine: image resolution, VM boot, overlay capture.
//!
//! This crate extracts the generic "resolve image → boot VM → run container"
//! pipeline so it can be shared by multiple consumers.
//!
//! # What this crate provides
//!
//! - [`VmResources`]: pre-built kernel + rootfs handles
//! - [`ResolvedImage`]: image layers loaded into memory, ready for VM boot
//! - [`resolve_image`]: query the container store and open layer `MemHandle`s
//! - [`boot_vm`]: boot a VM, init the container, and call a user closure
//! - [`create_derived_image`]: capture overlay writes as a new EROFS layer

pub use amla_container::{self, DirectContainerHandle, KERNEL};
pub use amla_container_store::{self as container_store, ContainerStore, Sha256Digest};
pub use amla_vm_redbfs::RedbFsQuota;
pub use amla_vmm::{self as vmm, MemHandle, VmHandle};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, FsConfig, GuestPath, VirtioFsTag, VirtualMachine, VmConfig};

/// Argument used by the container CLI to dispatch the current executable into
/// the VMM subprocess worker entrypoint.
pub const VM_WORKER_ROLE_ARG: &str = "--amla-container-vm-worker";

/// Worker process launch configuration for the container engine.
#[must_use]
pub fn worker_process_config() -> amla_vmm::WorkerProcessConfig {
    amla_vmm::WorkerProcessConfig::current_exe(VM_WORKER_ROLE_ARG)
}

/// VM boot options for embedders that need explicit process wiring.
#[derive(Clone, Debug)]
pub struct BootOptions {
    /// Worker subprocess used by the platform hypervisor backend.
    ///
    /// Single-binary embedders can use [`worker_process_config`]. Native
    /// library embedders, such as Node addons, should point this at a bundled
    /// worker binary with [`amla_vmm::WorkerProcessConfig::path`].
    pub worker_process: amla_vmm::WorkerProcessConfig,
}

impl Default for BootOptions {
    fn default() -> Self {
        Self {
            worker_process: worker_process_config(),
        }
    }
}

/// Run the platform VMM worker loop. Never returns.
pub async fn worker_main() -> ! {
    amla_vmm::worker_main().await
}

// ─── Error ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("vm: {0}")]
    Vm(String),
    #[error("image: {0}")]
    Image(String),
}

fn vm_err(e: impl std::fmt::Display) -> Error {
    Error::Vm(e.to_string())
}

fn img_err(e: impl std::fmt::Display) -> Error {
    Error::Image(e.to_string())
}

// ─── VmResources ───────────────────────────────────────────────────────

/// Pre-built VM resources: kernel bytes and rootfs image handle.
pub struct VmResources {
    pub kernel_bytes: &'static [u8],
    pub rootfs: MemHandle,
    pub image_store_dir: PathBuf,
}

/// VM sizing parameters (vCPU count, guest memory).
///
/// Defaults match the historical hardcoded values (`1` vCPU, 2048 MB).
/// The underlying `VmConfig` enforces `memory_mb >= MIN_MEMORY_MB` and
/// `memory_mb % BLOCK_SIZE_MB == 0`; callers should validate at their
/// own boundary (e.g. CLI flag parsing) to surface errors earlier.
#[derive(Debug, Clone, Copy)]
pub struct VmSizing {
    pub vcpu_count: u32,
    pub memory_mb: usize,
}

impl Default for VmSizing {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_mb: 2048,
        }
    }
}

/// Build VM resources (kernel + rootfs) for container execution.
///
/// `image_store_dir` is the path to the container image store
/// (e.g. `<root>/.amla-container/images`).
pub fn build_vm_resources(image_store_dir: &Path) -> Result<VmResources, Error> {
    if !amla_vmm::available() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hypervisor not available",
        )));
    }

    let kernel_bytes = amla_container::KERNEL;

    let rootfs =
        amla_container::build_rootfs().map_err(|e| std::io::Error::other(e.to_string()))?;
    let rootfs = MemHandle::allocate_and_write(c"rootfs", rootfs.image_size(), |buf| {
        rootfs
            .write_to(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    })
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    log::info!("vm resources ready");
    Ok(VmResources {
        kernel_bytes,
        rootfs,
        image_store_dir: image_store_dir.to_path_buf(),
    })
}

// ─── ResolvedImage ─────────────────────────────────────────────────────

/// A container image resolved from the store: layer handles + OCI config.
pub struct ResolvedImage {
    pub manifest_digest: Sha256Digest,
    pub layers: Vec<MemHandle>,
    pub config: serde_json::Value,
}

/// Resolve a container image from the store, returning layer `MemHandle`s
/// and container uid/gid from the OCI config.
///
/// `image_query` can be a digest prefix or name substring. `None` uses
/// the store's default image.
pub fn resolve_image(store_dir: &Path, image_query: Option<&str>) -> Result<ResolvedImage, Error> {
    resolve_image_for(store_dir, image_query, None)
}

/// Like [`resolve_image`], but when `image_query` is `None`, checks for
/// a per-`default_key` default before falling back to the global default.
///
/// `default_key` is typically the agent type (e.g. `"claude"`, `"copilot"`).
pub fn resolve_image_for(
    store_dir: &Path,
    image_query: Option<&str>,
    default_key: Option<&str>,
) -> Result<ResolvedImage, Error> {
    let store = ContainerStore::open(store_dir)
        .map_err(|e| img_err(format!("opening image store: {e}")))?;

    let digest = if let Some(query) = image_query {
        let images = store
            .list()
            .map_err(|e| img_err(format!("listing images: {e}")))?;
        let img = images
            .into_iter()
            .find(|img| {
                img.manifest_digest.hex().starts_with(query)
                    || img.container_id.as_str().contains(query)
            })
            .ok_or_else(|| img_err(format!("no image matching {query:?}")))?;
        img.manifest_digest
    } else {
        // Try per-key default first, then fall back to global default.
        // A read error on either lookup must propagate — "no override
        // configured" (`Ok(None)`) is the only thing that legitimately
        // falls through.
        let per_key = match default_key {
            Some(key) => store
                .default_image_for(key)
                .map_err(|e| img_err(format!("reading default image for {key}: {e}")))?,
            None => None,
        };
        match per_key {
            Some(d) => d,
            None => store
                .default_image()
                .map_err(|e| img_err(format!("reading default image: {e}")))?
                .ok_or_else(|| img_err("no default image set — import an image first"))?,
        }
    };

    let meta = store
        .read_metadata(&digest)
        .map_err(|e| img_err(format!("reading image metadata: {e}")))?;

    let mut layers = Vec::with_capacity(meta.layers.len());
    for layer_digest in &meta.layers {
        let blob_path = store.blob_path(layer_digest);
        let handle = MemHandle::from_file(&blob_path)
            .map_err(|e| img_err(format!("opening layer blob {}: {e}", blob_path.display())))?;
        layers.push(handle);
    }

    log::info!(
        "resolved image {} ({} layers)",
        digest.short(),
        layers.len(),
    );

    Ok(ResolvedImage {
        manifest_digest: digest,
        layers,
        config: meta.config,
    })
}

// ─── VM config ─────────────────────────────────────────────────────────

/// Build a VM config for booting a container image.
///
/// When `fs_tag` is provided, it is used as the virtiofs tag for the
/// overlay upper directory (writes captured by the host). When `None`,
/// a tmpfs upper is used inside the guest.
///
/// # Errors
///
/// Returns an error if the built-in guest paths or virtio-fs tag fail VMM
/// config validation.
pub fn vm_config(
    rootfs: &MemHandle,
    image: &ResolvedImage,
    sizing: &VmSizing,
    fs: Option<FsConfig>,
) -> Result<VmConfig, amla_vmm::ConfigError> {
    let mut cfg = VmConfig::default()
        .memory_mb(sizing.memory_mb)
        .vcpu_count(sizing.vcpu_count)
        .pmem_root(rootfs.size().as_u64())
        .net(amla_vmm::NetConfig::default());

    let layer_images: Vec<amla_vmm::PmemImageConfig> = image
        .layers
        .iter()
        .map(|h| amla_vmm::PmemImageConfig::overlay(h.size().as_u64()))
        .collect();

    let overlay_target = GuestPath::new("/mnt")?;
    if let Some(ref fs) = fs {
        cfg = cfg.pmem_overlay_with_upper(layer_images, overlay_target, fs.tag.clone());
    } else {
        cfg = cfg.pmem_overlay(layer_images, overlay_target);
    }

    if let Some(fs) = fs {
        cfg = cfg.fs(fs);
    }
    Ok(cfg)
}

// ─── boot_vm ───────────────────────────────────────────────────────────

/// Boot a VM, initialize the container, and run a user-provided closure.
///
/// This is the direct-VMM boot pipeline. The closure receives a
/// [`DirectContainerHandle`] for running commands inside the container namespace.
/// The container's `amla-init` stdout/stderr are drained automatically.
///
/// For more complex setups (display loops, WebSocket bridges), callers
/// should use the lower-level `amla_vmm` and `amla_container` APIs directly.
#[allow(clippy::too_many_lines)]
pub async fn boot_vm<'fs, F, N, R>(
    vm: &VmResources,
    image: &ResolvedImage,
    sizing: &VmSizing,
    net: N,
    fs_backend: Option<&'fs F>,
    bundle: &str,
    f: impl AsyncFnOnce(&DirectContainerHandle<'_, '_>) -> Result<R, Error> + Send,
) -> Result<R, Error>
where
    F: amla_fuse::fuse::FsBackend,
    N: amla_core::backends::NetBackend,
    R: Send,
{
    boot_vm_with_options(
        vm,
        image,
        sizing,
        net,
        fs_backend,
        bundle,
        BootOptions::default(),
        f,
    )
    .await
}

/// Boot a VM with explicit embedder options.
///
/// This is the same pipeline as [`boot_vm`], but lets callers select the VMM
/// worker subprocess. That is required for native library embedders whose
/// process image cannot dispatch [`VM_WORKER_ROLE_ARG`] itself.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn boot_vm_with_options<'fs, F, N, R>(
    vm: &VmResources,
    image: &ResolvedImage,
    sizing: &VmSizing,
    net: N,
    fs_backend: Option<&'fs F>,
    bundle: &str,
    options: BootOptions,
    f: impl AsyncFnOnce(&DirectContainerHandle<'_, '_>) -> Result<R, Error> + Send,
) -> Result<R, Error>
where
    F: amla_fuse::fuse::FsBackend,
    N: amla_core::backends::NetBackend,
    R: Send,
{
    let t_boot = std::time::Instant::now();

    let virtiofs_tag = "upper";
    let fs_config = if fs_backend.is_some() {
        Some(FsConfig::new(
            VirtioFsTag::new(virtiofs_tag).map_err(vm_err)?,
            GuestPath::new("/unused").map_err(vm_err)?,
        ))
    } else {
        None
    };
    let config = vm_config(&vm.rootfs, image, sizing, fs_config).map_err(vm_err)?;

    // Run pool allocation, VM creation, and backend assembly in parallel:
    //   - `BackendPools::new` is CPU-bound, ~5–10ms
    //   - `VirtualMachine::create` has real awaits, ~10–30ms
    //   - backend assembly is cheap fd-cloning, ~1ms
    // They share only immutable references to `config`/`vm`/`image`.
    let t0 = std::time::Instant::now();
    let (pools_res, backends_res, machine_res) = tokio::join!(
        async {
            BackendPools::new(0, &config, options.worker_process.clone())
                .map_err(|e| Error::Vm(e.to_string()))
        },
        async {
            let mut pmem = vec![
                vm.rootfs
                    .try_clone()
                    .map_err(|e| Error::Vm(e.to_string()))?,
            ];
            for layer in &image.layers {
                pmem.push(layer.try_clone().map_err(|e| Error::Vm(e.to_string()))?);
            }
            Ok::<Vec<MemHandle>, Error>(pmem)
        },
        async { VirtualMachine::create(config.clone()).await.map_err(vm_err) }
    );
    let pools = pools_res?;
    let pmem = backends_res?;
    let machine = machine_res?;
    log::info!("[boot_vm] parallel_setup={:?}", t0.elapsed());

    let console = amla_vmm::ConsoleStream::new();
    let backends = Backends {
        console: &console,
        net: Some(&net),
        fs: fs_backend,
        pmem,
    };

    let t0 = std::time::Instant::now();
    let machine = machine
        .load_kernel(&pools, vm.kernel_bytes, backends)
        .await
        .map_err(vm_err)?;
    log::info!("[boot_vm] load_kernel={:?}", t0.elapsed());

    log::info!("[boot_vm] pre_run_total={:?}", t_boot.elapsed());

    let (_machine, result) = machine
        .run(async move |handle| {
            let mut handle = handle.start();
            let t_inside = std::time::Instant::now();
            let config_json = serde_json::to_string(&image.config)
                .map_err(|e| Error::Vm(format!("serialize config: {e}")))?;
            let mut container = amla_container::init_container(&handle, bundle, &config_json)
                .await
                .map_err(|e| Error::Vm(e.to_string()))?;
            log::info!("[boot_vm] inside_run: init_ready={:?}", t_inside.elapsed());

            // Drain init stdout (display frames) — discard in generic mode.
            if let Some(mut stdout) = container.init.take_stdout() {
                tokio::spawn(async move { while stdout.recv().await.is_some() {} });
            }

            let result = f(&container.handle).await;

            // Graceful shutdown: send Shutdown to guest agent, which calls
            // sync() and triggers a clean VM exit. This ensures the
            // filesystem is fully flushed before we capture it.
            let t_shutdown = std::time::Instant::now();
            if let Err(e) = container.init.close_stdin().await {
                log::debug!("amla-init close_stdin during shutdown: {e}");
            }
            let init_exit = container.init.wait().await;
            drop(container);
            handle.shutdown().await;
            log::info!(
                "[boot_vm] VM shutdown complete ({:?})",
                t_shutdown.elapsed()
            );

            match (result, init_exit) {
                (Ok(value), Ok(_)) => Ok(value),
                (Err(e), _) => Err(e),
                (Ok(_), Err(e)) => Err(Error::Vm(format!("amla-init shutdown: {e}"))),
            }
        })
        .await
        .map_err(vm_err)?;
    result
}

// ─── create_derived_image ──────────────────────────────────────────────

/// Capture overlay writes from a `RedbFs` as a new EROFS layer and store
/// a derived image in the container store.
///
/// Returns the manifest digest and layer count of the new image.
pub fn create_derived_image(
    redb_path: &Path,
    base_digest: &Sha256Digest,
    store_dir: &Path,
    source_label: &str,
) -> Result<(Sha256Digest, usize), Error> {
    // Re-open RedbFs and export the overlay upper subtree as EROFS.
    let redb_fs = amla_vm_redbfs::RedbFs::open(redb_path)
        .map_err(|e| img_err(format!("reopen redbfs: {e}")))?;
    let mut buf = std::io::Cursor::new(Vec::new());
    redb_fs
        .to_erofs_subtree("upper", &mut buf)
        .map_err(|e| img_err(format!("to_erofs: {e}")))?;
    let erofs_bytes = buf.into_inner();

    // Store new layer blob.
    let layer_digest = Sha256Digest::of(&erofs_bytes);
    let store = ContainerStore::open(store_dir).map_err(|e| img_err(format!("open store: {e}")))?;
    let mut writer = store
        .blob_writer(&layer_digest)
        .map_err(|e| img_err(format!("blob write: {e}")))?;
    std::io::Write::write_all(&mut writer, &erofs_bytes)
        .map_err(|e| img_err(format!("blob write: {e}")))?;
    amla_container_store::Finalize::commit(writer)
        .map_err(|e| img_err(format!("blob commit: {e}")))?;

    // Build derived image metadata.
    let base_meta = store
        .read_metadata(base_digest)
        .map_err(|e| img_err(format!("read base metadata: {e}")))?;
    let mut new_layers = base_meta.layers;
    new_layers.push(layer_digest);
    let layer_count = new_layers.len();
    let new_meta = amla_container_store::ContainerMetadata {
        source: format!("{} + {source_label}", base_meta.source),
        architecture: base_meta.architecture,
        os: base_meta.os,
        config: base_meta.config,
        layers: new_layers,
    };

    let manifest_bytes =
        serde_json::to_vec(&new_meta).map_err(|e| img_err(format!("serialize: {e}")))?;
    let manifest_digest = Sha256Digest::of(&manifest_bytes);

    store
        .write_metadata(&manifest_digest, &new_meta)
        .map_err(|e| img_err(format!("write metadata: {e}")))?;
    store
        .set_default(&manifest_digest)
        .map_err(|e| img_err(format!("set default: {e}")))?;

    log::info!(
        "created derived image {} ({layer_count} layers)",
        manifest_digest.short()
    );

    Ok((manifest_digest, layer_count))
}

// ─── Overlay FS helpers ────────────────────────────────────────────────

/// Create a `RedbFs` overlay filesystem for capturing container writes.
///
/// Returns the `RedbFs` instance and its path. The caller is responsible
/// for cleanup.
///
/// Uses `RedbFsQuota::default()` — see [`create_overlay_redbfs_with_quota`]
/// for explicit quota control (used by the CLI's `--max-disk-usage` flag).
pub fn create_overlay_redbfs(
    store_dir: &Path,
    id: &str,
) -> Result<(amla_vm_redbfs::RedbFs, PathBuf), Error> {
    create_overlay_redbfs_with_quota(store_dir, id, amla_vm_redbfs::RedbFsQuota::default())
}

/// Like [`create_overlay_redbfs`] but with a caller-supplied quota.
pub fn create_overlay_redbfs_with_quota(
    store_dir: &Path,
    id: &str,
    quota: amla_vm_redbfs::RedbFsQuota,
) -> Result<(amla_vm_redbfs::RedbFs, PathBuf), Error> {
    let redb_dir = store_dir.join("redb");
    std::fs::create_dir_all(&redb_dir)?;
    let redb_path = redb_dir.join(format!("{id}.redb"));
    let redb_fs = amla_vm_redbfs::RedbFs::create_with_quota(&redb_path, quota)
        .map_err(|e| Error::Vm(format!("redbfs create: {e}")))?;
    Ok((redb_fs, redb_path))
}

/// Build the unfiltered network backend used by `amla-container`.
///
/// This intentionally permits outbound TCP/UDP NAT to any destination and
/// DNS forwarding to the host resolver. Callers that need filtering should
/// construct an `amla_usernet::UserNetConfig` directly.
pub fn unrestricted_net() -> Result<amla_usernet::SharedBackend, Error> {
    let config = amla_usernet::UserNetConfig::try_default()
        .map_err(|e| Error::Vm(format!("usernet config: {e}")))?
        .with_unrestricted_egress()
        .with_unrestricted_dns_forwarding();
    let backend = amla_usernet::UserNetBackend::try_new(config)
        .map_err(|e| Error::Vm(format!("usernet unrestricted: {e}")))?;
    Ok(amla_usernet::SharedBackend(Arc::new(backend)))
}
