// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

/// Generates `BackendPools` and `BackendVm` types that delegate to a
/// platform-specific hypervisor crate (`amla_kvm`, `amla_hvf`, `amla_hyperv`).
///
/// All backend methods are generated here — per-backend files only need
/// `define_backend!(crate_name);`.
#[allow(unused_macros)]
macro_rules! define_backend {
    ($crate_name:ident) => {
        /// Subprocess worker entry point. Never returns.
        pub async fn worker_main() -> ! {
            $crate_name::worker_main().await
        }

        /// Resource pools for VM creation.
        pub struct BackendPools {
            inner: $crate_name::VmPools,
            device_layout: crate::devices::DeviceLayout,
        }

        impl BackendPools {
            /// Check if the platform hypervisor is available.
            pub fn available() -> bool {
                $crate_name::VmPools::available()
            }

            /// Create new pools.
            pub fn new(
                pool_size: usize,
                config: &crate::VmConfig,
                worker: amla_core::WorkerProcessConfig,
            ) -> Result<Self> {
                config.validate()?;
                let device_layout = crate::devices::DeviceLayout::from_config(config)?;
                let queue_wakes = crate::devices::QueueWakeMap::new(&device_layout)?;
                let device_slots: Vec<_> = device_layout
                    .kinds()
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| {
                        let irq = crate::devices::device_irq_line(idx).map_err(|e| {
                            Error::Config(crate::ConfigError::IrqAllocation {
                                reason: e.to_string(),
                            })
                        })?;
                        let resample_wake = queue_wakes.device_wake_indices(idx).next();
                        Ok((irq, resample_wake))
                    })
                    .collect::<Result<_>>()?;
                let io_slots: Vec<_> = queue_wakes
                    .iter()
                    .map(|wake| {
                        let queue_idx = u32::try_from(wake.queue).map_err(|_| {
                            Error::Config(crate::ConfigError::IrqAllocation {
                                reason: format!("queue index {} does not fit u32", wake.queue),
                            })
                        })?;
                        Ok((
                            wake.device,
                            amla_virtio_mmio::device_mmio_addr(wake.device)
                                + amla_virtio_mmio::QUEUE_NOTIFY,
                            queue_idx,
                            wake.wake,
                        ))
                    })
                    .collect::<Result<_>>()?;
                let layout = $crate_name::HardwareLayout::from_device_and_queue_slots(
                    device_slots,
                    io_slots,
                );
                let inner = new_backend_pools(pool_size, config.vcpu_count, layout, worker)
                    .map_err(Error::Backend)?;
                Ok(Self {
                    inner,
                    device_layout,
                })
            }

            /// Get the inner pools.
            #[allow(dead_code)]
            pub(crate) const fn inner(&self) -> &$crate_name::VmPools {
                &self.inner
            }

            /// vCPU count for shells in this pool.
            pub fn vcpu_count(&self) -> u32 {
                self.inner.vcpu_count()
            }

            /// Device layout this pool pre-registered.
            pub(crate) const fn device_layout(&self) -> &crate::devices::DeviceLayout {
                &self.device_layout
            }

            /// Pre-create shells.
            pub fn prewarm(&self, count: usize) -> Result<usize> {
                self.inner.prewarm(count).map_err(Error::Backend)
            }
        }

        /// Platform-agnostic VM handle wrapping the backend's Vm.
        pub struct BackendVm {
            inner: $crate_name::Vm,
        }

        impl BackendVm {
            /// Build a VM: shell + vCPU threads.
            pub async fn build(pools: &BackendPools) -> Result<Self> {
                let vm = $crate_name::Vm::builder(pools.inner())
                    .build_shell()
                    .await
                    .map_err(Error::Backend)?;
                Ok(Self { inner: vm })
            }

            /// Register guest memory with the hypervisor.
            pub async fn map_memory(
                &mut self,
                handles: &[&amla_mem::MemHandle],
                mappings: &[amla_core::MemoryMapping],
            ) -> Result<()> {
                self.inner
                    .map_memory(handles, mappings)
                    .await
                    .map_err(Error::Backend)
            }

            /// Restore all VM state from `VmState` to hypervisor.
            pub async fn restore_state(
                &self,
                view: &mut amla_core::vm_state::VmState<'_>,
            ) -> Result<()> {
                self.inner.restore_state(view).await.map_err(Error::Backend)
            }

            /// Save all VM state from hypervisor to `VmState`.
            pub async fn save_state(
                &self,
                view: &mut amla_core::vm_state::VmState<'_>,
            ) -> Result<()> {
                self.inner.save_state(view).await.map_err(Error::Backend)
            }

            /// Write initial boot vCPU state.
            pub async fn write_boot_state(
                &self,
                view: &mut amla_core::vm_state::VmState<'_>,
                boot_result: &amla_boot::BootResult,
            ) -> Result<()> {
                self.inner
                    .write_boot_state(view, boot_result)
                    .await
                    .map_err(Error::Backend)
            }

            /// Resume a vCPU: send response, await next exit.
            ///
            /// The caller must preempt via `preempt_vcpu` before dropping
            /// this future — there is no implicit cancellation guard.
            pub async fn resume(
                &self,
                id: amla_core::VcpuId,
                info: Option<amla_core::VcpuResponse>,
            ) -> Result<amla_core::VcpuExit> {
                self.inner.resume(id, info).await.map_err(Error::Backend)
            }

            /// Preempt a vCPU by ID, kicking it out of the hypervisor.
            pub fn preempt_vcpu(&self, id: amla_core::VcpuId) {
                self.inner.preempt_vcpu(id);
            }

            /// Number of vCPUs.
            pub fn vcpu_count(&self) -> u32 {
                self.inner.vcpu_count()
            }

            /// Create a backend-specific device waker.
            pub async fn create_device_waker(
                &self,
            ) -> crate::Result<Arc<dyn amla_core::DeviceWaker>> {
                Ok(self.inner.create_device_waker().await?)
            }

            /// Drain buffered UART console output from the worker process.
            /// Returns empty in direct mode (serial is inline in `vcpu_run_loop`).
            // Reason: native clippy admits `const`, but the cross-build
            // matrix (aarch64-apple-darwin etc.) targets a backend impl
            // whose `drain_console_output` isn't `const fn`.
            #[allow(clippy::missing_const_for_fn)]
            pub fn drain_console_output(&self) -> Vec<u8> {
                self.inner.drain_console_output()
            }

            /// Close the backend VM and wait until backend-owned mappings and
            /// hypervisor state are fully torn down.
            pub(crate) async fn close(self) -> Result<crate::state::BackendClosed> {
                self.inner.close().await.map_err(Error::Backend)?;
                Ok(crate::state::BackendClosed::new())
            }
        }

        impl IrqFactory for BackendVm {
            fn create_resampled_irq_line(
                &self,
                gsi: u32,
            ) -> std::result::Result<
                Box<dyn amla_core::IrqLine>,
                Box<dyn std::error::Error + Send + Sync>,
            > {
                IrqFactory::create_resampled_irq_line(&self.inner, gsi)
            }
        }
    };
}
