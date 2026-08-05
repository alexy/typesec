//! Shared record-visibility rules for every vault read path.

use chrono::{DateTime, Utc};

use super::{RecalledMemory, RedactedHit};
use crate::label::Label;
use crate::record::StoredRecord;

/// Why a stored record cannot participate in an authorized read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordRejection {
    OutsideSpace,
    Quarantined,
    NotValid,
    RetentionExpired,
    PurposeDenied,
}

impl RecordRejection {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::OutsideSpace => "outside target space",
            Self::Quarantined => "quarantined",
            Self::NotValid => "not valid at the requested time",
            Self::RetentionExpired => "retention expired",
            Self::PurposeDenied => "purpose is not allowed",
        }
    }
}

/// Immutable context used to re-check records returned by stores and indexes.
pub(crate) struct RecordVisibility<'a> {
    space_id: &'a str,
    purpose: Option<&'a str>,
    valid_at: DateTime<Utc>,
    retention_at: DateTime<Utc>,
    include_quarantined: bool,
}

impl<'a> RecordVisibility<'a> {
    pub(crate) fn new(
        space_id: &'a str,
        purpose: Option<&'a str>,
        valid_at: DateTime<Utc>,
        retention_at: DateTime<Utc>,
        include_quarantined: bool,
    ) -> Self {
        Self {
            space_id,
            purpose: purpose.filter(|value| !value.trim().is_empty()),
            valid_at,
            retention_at,
            include_quarantined,
        }
    }

    pub(crate) fn check(&self, record: &StoredRecord) -> Result<(), RecordRejection> {
        if record.space_id != self.space_id {
            return Err(RecordRejection::OutsideSpace);
        }
        if record.quarantined && !self.include_quarantined {
            return Err(RecordRejection::Quarantined);
        }
        if !record.is_valid_at(self.valid_at) {
            return Err(RecordRejection::NotValid);
        }
        if record.is_expired_at(self.retention_at) {
            return Err(RecordRejection::RetentionExpired);
        }
        if !record.purposes.is_empty()
            && !self
                .purpose
                .is_some_and(|purpose| record.purposes.iter().any(|allowed| allowed == purpose))
        {
            return Err(RecordRejection::PurposeDenied);
        }
        Ok(())
    }
}

pub(super) fn split_visible(
    records: impl IntoIterator<Item = StoredRecord>,
    visibility: &RecordVisibility<'_>,
    ceiling: Label,
    limit: Option<usize>,
) -> (Vec<RecalledMemory>, Vec<RedactedHit>) {
    let mut hits = Vec::new();
    let mut redacted = Vec::new();
    for record in records
        .into_iter()
        .filter(|record| visibility.check(record).is_ok())
        .take(limit.unwrap_or(usize::MAX))
    {
        if record.label <= ceiling {
            hits.push(RecalledMemory::from_record(&record));
        } else {
            redacted.push(RedactedHit::from_record(&record));
        }
    }
    (hits, redacted)
}
