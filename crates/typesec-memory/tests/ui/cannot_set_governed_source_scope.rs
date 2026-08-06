// External callers cannot attach or replace a scope through ordinary field
// access. This test does not claim authenticity against trusted serde/storage.

use typesec_memory::{GovernedSourceScope, StoredRecord};

fn forge(record: &mut StoredRecord, scope: GovernedSourceScope) {
    record.governed_source_scope = Some(scope);
}

fn main() {}
