// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#[test]
fn queue_view_unchecked_constructor_is_not_public_api() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/readable_chain_cannot_complete_nonzero.rs");
    t.compile_fail("tests/ui/completion_cannot_cross_queue_brand.rs");
    t.compile_fail("tests/ui/deferred_completion_cannot_cross_pop_context_brand.rs");
    t.compile_fail("tests/ui/writable_addr_is_not_public.rs");
    t.compile_fail("tests/ui/writable_descriptor_cannot_escape_pop_view.rs");
    t.compile_fail("tests/ui/descriptor_write_guard_is_not_public.rs");
}
