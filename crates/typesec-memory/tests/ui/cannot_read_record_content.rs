// A StoredRecord round-trips through a store opaquely, but its content is the
// vault's private path. External code must not be able to read it — that is
// the single-rehydration-site invariant.

use typesec_memory::StoredRecord;

fn leak(record: &StoredRecord) {
    // `content` is pub(crate); this must not compile.
    let _stolen = &record.content;
}

fn main() {}
