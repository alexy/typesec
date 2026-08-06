//! The memory boundaries that must not be bypassable, enforced at compile
//! time. If any of these starts compiling, an invariant has regressed.

#[test]
fn memory_boundaries_hold() {
    let t = trybuild::TestCases::new();
    // Record content is crate-private: you cannot read it out of a StoredRecord.
    t.compile_fail("tests/ui/cannot_read_record_content.rs");
    // Only a vault-verified ingestion path can attach a governed source scope.
    t.compile_fail("tests/ui/cannot_set_governed_source_scope.rs");
    // Recalls of different clearances are different types: no mixing.
    t.compile_fail("tests/ui/cannot_mix_recall_clearances.rs");
}
