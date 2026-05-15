// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

/// Attempting to call `load_kernel()` on a `Ready` VM must fail.
/// `load_kernel()` is only available on `VirtualMachine<New>`.
use amla_vmm::{Ready, VirtualMachine};

fn try_load_kernel(vm: VirtualMachine<Ready<'_, amla_fuse::NullFsBackend>>) {
    // ERROR: no method named `load_kernel` found for `VirtualMachine<Ready>`
    vm.load_kernel(&[]);
}

fn main() {}
