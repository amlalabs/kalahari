// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kvm_ioctls::Kvm;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::shell::{HardwareLayout, Shell};

// ============================================================================
// VmPools
// ============================================================================

/// Shared resource pools for VM shell creation.
///
/// Each shell gets a fresh KVM VM fd, fresh vCPU fds, and clean kernel
/// state. After use, shells are destroyed and the pool creates replacements.
///
/// Each shell gets pre-registered hardware (ioeventfds + irqfds) for
/// zero-ioctl freeze/spawn cycles.
///
/// The pool uses a background tokio task to pre-create shells into a bounded
/// mpsc channel. `acquire_shell()` pops from the channel if one is ready,
/// otherwise creates a shell inline (never blocks).
///
/// There is no hard limit on concurrent shells — `pool_size` controls the
/// pre-warm target only.
///
/// # Thread Safety
///
/// `VmPools` is `Clone + Send + Sync` via `Arc<VmPoolsInner>`.
#[derive(Clone, Debug)]
pub struct VmPools {
    inner: Arc<VmPoolsInner>,
    _owner: Arc<VmPoolsOwner>,
}

struct VmPoolsInner {
    shell_tx: mpsc::Sender<Shell>,
    shell_rx: tokio::sync::Mutex<mpsc::Receiver<Shell>>,
    refill_notify: Notify,
    kvm: Arc<Kvm>,
    vcpu_count: u32,
    layout: Arc<HardwareLayout>,
    pool_size: usize,
    kvm_run_size: usize,
    refill_started: AtomicBool,
    shutdown: CancellationToken,
}

#[derive(Debug)]
struct VmPoolsOwner {
    shutdown: CancellationToken,
}

impl Drop for VmPoolsOwner {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl std::fmt::Debug for VmPoolsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmPoolsInner")
            .field("vcpu_count", &self.vcpu_count)
            .field("pool_size", &self.pool_size)
            .field("kvm_run_size", &self.kvm_run_size)
            .finish_non_exhaustive()
    }
}

// Static assertion: VmPools must be Send + Sync (documented contract).
#[allow(dead_code)]
const _ASSERT_VM_POOLS_SEND_SYNC: fn() = || {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VmPools>();
};

impl VmPools {
    /// Check if KVM is available on this system.
    ///
    /// Attempts to open `/dev/kvm` and issue `KVM_GET_API_VERSION`. Returns
    /// `true` if both succeed, `false` otherwise. This is a cheap probe —
    /// the file descriptor is closed immediately.
    pub fn available() -> bool {
        Kvm::new().is_ok()
    }

    /// Create new VM pools.
    ///
    /// All shells created by this pool will have `vcpu_count` vCPUs.
    ///
    /// # Arguments
    /// - `pool_size`: Number of shells to pre-warm in the background. This is
    ///   a target, not a hard cap — `acquire_shell()` creates shells inline
    ///   if the pool is empty.
    /// - `vcpu_count`: Number of vCPUs per shell (must be >= 1)
    /// - `layout`: Hardware layout for permanent eventfd registration.
    ///   Every shell gets pre-registered ioeventfds and irqfds.
    ///   Use `HardwareLayout::empty()` for tests that don't use devices.
    pub fn new(pool_size: usize, vcpu_count: u32, layout: HardwareLayout) -> Result<Self> {
        if vcpu_count == 0 {
            return Err(crate::error::VmmError::Config(
                "vcpu_count must be >= 1".into(),
            ));
        }

        let kvm = Arc::new(Kvm::new()?);
        let kvm_run_size = kvm.get_vcpu_mmap_size()?;

        let (shell_tx, shell_rx) = mpsc::channel(pool_size.max(1));

        let shutdown = CancellationToken::new();

        Ok(Self {
            inner: Arc::new(VmPoolsInner {
                shell_tx,
                shell_rx: tokio::sync::Mutex::new(shell_rx),
                refill_notify: Notify::new(),
                kvm,
                vcpu_count,
                layout: Arc::new(layout),
                pool_size,
                kvm_run_size,
                refill_started: AtomicBool::new(false),
                shutdown: shutdown.clone(),
            }),
            _owner: Arc::new(VmPoolsOwner { shutdown }),
        })
    }

    // =========================================================================
    // Shell acquisition and release
    // =========================================================================

    /// Acquire a shell for a VM.
    ///
    /// Tries the pre-warmed pool first (instant). If the pool is empty,
    /// creates a shell inline via `spawn_blocking` (~3-5ms). Never blocks
    /// waiting for another shell to be released.
    ///
    /// Starts the background refill task lazily on first call.
    pub async fn acquire_shell(&self) -> Result<Shell> {
        if self.inner.pool_size > 0 {
            self.ensure_refill_started();
        }

        // Try the pool first.
        let mut rx = self.inner.shell_rx.lock().await;
        if let Ok(shell) = rx.try_recv() {
            drop(rx);
            self.inner.refill_notify.notify_one();
            Ok(shell)
        } else {
            // Pool empty — create inline.
            drop(rx);
            let kvm = Arc::clone(&self.inner.kvm);
            let vcpu_count = self.inner.vcpu_count;
            let layout = Arc::clone(&self.inner.layout);
            let kvm_run_size = self.inner.kvm_run_size;
            tokio::task::spawn_blocking(move || Shell::new(&kvm, vcpu_count, &layout, kvm_run_size))
                .await
                .map_err(|e| {
                    crate::error::VmmError::Config(format!("spawn_blocking panicked: {e}"))
                })?
        }
    }

    /// Drop a shell on a background thread.
    ///
    /// `Shell::drop` joins vCPU threads and closes KVM fds (~25ms). Running
    /// this in the background avoids blocking the caller.
    pub fn drop_shell(&self, shell: Shell) {
        self.drop_shell_retaining(shell, ());
    }

    /// Drop a shell on a background thread while retaining additional
    /// resources until after the shell and its KVM fds are fully torn down.
    pub fn drop_shell_retaining<T>(&self, shell: Shell, retained: T)
    where
        T: Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let do_drop = move || {
            drop(shell);
            drop(retained);
            inner.refill_notify.notify_one();
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // spawn_blocking alone is sufficient — no need for an outer
            // spawn(async { spawn_blocking(...) }) wrapper.
            drop(handle.spawn_blocking(do_drop));
        } else {
            std::thread::spawn(do_drop);
        }
    }

    /// Drop a shell and retained mappings, waiting until KVM teardown is complete.
    pub async fn close_shell_retaining<T>(&self, shell: Shell, retained: T) -> Result<()>
    where
        T: Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            drop(shell);
            drop(retained);
            inner.refill_notify.notify_one();
        })
        .await
        .map_err(|e| crate::error::VmmError::Config(format!("shell teardown panicked: {e}")))?;
        Ok(())
    }

    // =========================================================================
    // Prewarm
    // =========================================================================

    /// Synchronously pre-create shells into the ready queue.
    ///
    /// Returns the number of shells actually created (may be less than
    /// `count` if the channel is full).
    pub fn prewarm(&self, count: usize) -> Result<usize> {
        let mut created = 0;
        for _ in 0..count {
            let shell = Shell::new(
                &self.inner.kvm,
                self.inner.vcpu_count,
                &self.inner.layout,
                self.inner.kvm_run_size,
            )?;
            if self.inner.shell_tx.try_send(shell).is_err() {
                // Channel full — stop.
                break;
            }
            created += 1;
        }
        Ok(created)
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Get the vCPU count for shells in this pool.
    pub fn vcpu_count(&self) -> u32 {
        self.inner.vcpu_count
    }

    /// Get the `kvm_run` mmap size.
    pub fn kvm_run_size(&self) -> usize {
        self.inner.kvm_run_size
    }

    /// Shutdown the pool (cancels the background refill task).
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    // =========================================================================
    // Refill task
    // =========================================================================

    /// Start the background refill task if not already running.
    fn ensure_refill_started(&self) {
        if self
            .inner
            .refill_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let inner = Arc::clone(&self.inner);
            // lifetime: detached. Loop exits when `inner.shutdown`
            // (tokio_util CancellationToken) is cancelled via
            // VmPools::shutdown(), or when `inner.shell_tx.send()` fails
            // (receiver dropped). No JoinHandle retained; `refill_started`
            // gate prevents duplicate spawns.
            tokio::spawn(async move {
                Self::refill_task(inner).await;
            });
        }
    }

    /// Background task that keeps the ready queue stocked.
    ///
    /// Creates shells via `spawn_blocking` (`Shell::new` takes ~3-5ms) and
    /// pushes them to the channel. The channel is bounded to `pool_size`,
    /// so `send()` naturally blocks when the pool is full. Wakes on
    /// `refill_notify` (fired after every acquire and release).
    async fn refill_task(inner: Arc<VmPoolsInner>) {
        // Exponential backoff for persistent Shell::new failures (e.g.
        // transient ENOMEM). Previously we `break`'d out to an outer
        // refill_notify wait — but refill_notify only fires on acquire/
        // release, and after an error the pool was empty with nothing to
        // acquire and nothing to release, so the task stalled for process
        // lifetime. We now retry with backoff; backpressure from the bounded
        // channel (`shell_tx.send().await`) naturally throttles us when the
        // pool is full.
        const BASE_BACKOFF_MS: u64 = 100;
        const MAX_BACKOFF_MS: u64 = 5_000;
        let mut backoff_ms = BASE_BACKOFF_MS;

        loop {
            let permit = tokio::select! {
                biased;
                () = inner.shutdown.cancelled() => return,
                permit = inner.shell_tx.reserve() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };

            let kvm = Arc::clone(&inner.kvm);
            let vcpu_count = inner.vcpu_count;
            let layout = Arc::clone(&inner.layout);
            let kvm_run_size = inner.kvm_run_size;

            let shell_result = tokio::task::spawn_blocking(move || {
                Shell::new(&kvm, vcpu_count, &layout, kvm_run_size)
            })
            .await;

            match shell_result {
                Ok(Ok(shell)) => {
                    if inner.shutdown.is_cancelled() {
                        return;
                    }
                    permit.send(shell);
                    backoff_ms = BASE_BACKOFF_MS;
                }
                Ok(Err(e)) => {
                    drop(permit);
                    log::error!("refill_task: Shell::new failed: {e}; retrying in {backoff_ms}ms");
                    tokio::select! {
                        () = tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)) => {}
                        () = inner.shutdown.cancelled() => return,
                    }
                    backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                }
                Err(e) => {
                    drop(permit);
                    // A panic in spawn_blocking is a bug, not a transient
                    // condition — back off at max so we don't pin a CPU
                    // logging the same panic while a human investigates.
                    log::error!(
                        "refill_task: spawn_blocking panicked: {e}; retrying in {MAX_BACKOFF_MS}ms",
                    );
                    tokio::select! {
                        () = tokio::time::sleep(std::time::Duration::from_millis(MAX_BACKOFF_MS)) => {}
                        () = inner.shutdown.cancelled() => return,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_pool_clone_does_not_cancel_refill_owner() {
        let Ok(pools) = VmPools::new(1, 1, HardwareLayout::empty()) else {
            return;
        };
        let clone = pools.clone();

        drop(clone);

        assert!(!pools.inner.shutdown.is_cancelled());
    }
}
