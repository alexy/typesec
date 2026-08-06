// Ordinary external code cannot read content through direct field access.
// Trusted store serde and Debug are separate documented plaintext surfaces.
// This compile-fail case covers only the direct-field API guarantee.

use typesec_memory::StoredRecord;

fn leak(record: &StoredRecord) {
    // `content` is pub(crate); this must not compile.
    let _stolen = &record.content;
}

fn main() {}
