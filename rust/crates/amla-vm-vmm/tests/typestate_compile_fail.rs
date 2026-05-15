// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Compile-fail tests for the typestate API.
//!
//! These tests verify that invalid state transitions are caught at compile time.
//! Each `.rs` file in `tests/ui/` must fail to compile with a specific error.
//!
//! To update `.stderr` expectations after a Rust toolchain upgrade:
//! ```sh
//! TRYBUILD=overwrite cargo test -p amla-vmm --test typestate_compile_fail
//! ```

#[test]
fn typestate_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
