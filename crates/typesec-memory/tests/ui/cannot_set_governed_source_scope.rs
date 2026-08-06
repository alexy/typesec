// External callers may inspect a verified scope but cannot attach or replace
// one on a StoredRecord. Only TypeSec's governed vault path owns that write.

use typesec_memory::{GovernedSourceScope, StoredRecord};

fn forge(record: &mut StoredRecord, scope: GovernedSourceScope) {
    record.governed_source_scope = Some(scope);
}

fn main() {}
