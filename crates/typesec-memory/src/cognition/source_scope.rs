//! Exact governed-source matching shared by reveal and authoritative reload.

use super::CognitionApplyError;
use crate::StoredRecord;
use crate::governed::{GovernedSourceScope, records_match_source_scope};

pub(super) fn validate_source_scope(
    records: &[StoredRecord],
    expected: Option<&GovernedSourceScope>,
) -> Result<(), CognitionApplyError> {
    if records_match_source_scope(records, expected) {
        Ok(())
    } else {
        Err(CognitionApplyError::SourceScopeMismatch)
    }
}
