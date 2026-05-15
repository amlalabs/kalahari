// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg(not(feature = "subprocess"))]

use crate::HardwareLayout;

// ============================================================================
// Builder validation tests
// ============================================================================

#[test]
fn test_builder_rejects_zero_vcpu_count() {
    // Pool with vcpu_count=0 should fail at pool creation.
    let result = crate::VmPools::new(1, 0, HardwareLayout::empty());
    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("vcpu_count"));
}

#[tokio::test]
async fn test_builder_shell_only() {
    let Ok(pools) = crate::VmPools::new(1, 1, HardwareLayout::empty()) else {
        return;
    };
    let vm = crate::Vm::builder(&pools).build_shell().await.unwrap();
    assert_eq!(vm.vcpu_count(), 1);
}

#[tokio::test]
async fn test_builder_shell_only_multi_vcpu() {
    let Ok(pools) = crate::VmPools::new(1, 4, HardwareLayout::empty()) else {
        return;
    };
    let vm = crate::Vm::builder(&pools).build_shell().await.unwrap();
    assert_eq!(vm.vcpu_count(), 4);
}
