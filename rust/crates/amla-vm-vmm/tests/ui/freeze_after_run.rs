// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

/// `run()` consumes a healthy Ready VM and returns it only on success.
/// The original binding cannot be frozen after the run transition.
use amla_vmm::{Ready, VirtualMachine};

async fn try_freeze_after_run(vm: VirtualMachine<Ready<'_, amla_fuse::NullFsBackend>>) {
    let _ = vm.run(async |_vm| ()).await;
    // ERROR: use of moved value: `vm`
    let _ = vm.freeze().await;
}

fn main() {}
