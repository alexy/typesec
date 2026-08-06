//! Public cognition receipts must remain opaque after validation.

#[test]
fn cognition_receipt_sealing_holds() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/cannot_construct_cognition_receipt.rs");
    t.compile_fail("tests/ui/cannot_mutate_cognition_receipt.rs");
}
