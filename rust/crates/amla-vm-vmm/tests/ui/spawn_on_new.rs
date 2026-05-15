// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

/// Attempting to call `run()` on a `New` VM must fail.
/// `run()` is only available on `VirtualMachine<Ready>`.
use amla_vmm::{New, VirtualMachine};

async fn try_run(vm: VirtualMachine<New>) {
    // ERROR: no method named `run` found for `VirtualMachine<New>`
    vm.run(async |_vm| ()).await.unwrap();
}

fn main() {}
