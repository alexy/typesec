//! Strict validated decoding for signed cognition receipt bytes.

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{CognitionCommitReceipt, CognitionEffect};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CognitionCommitReceiptWire {
    schema_version: u32,
    effect: CognitionEffect,
    subject: String,
    resource: String,
    job_id: String,
    #[serde(default)]
    governed_source_scope: Option<String>,
    typedid_request_digest: String,
    proposal_digest: String,
    governed_scan_digest: String,
    input_snapshot_digest: String,
    policy_decision_digest: String,
    authorization_receipt_digest: String,
    prior_version: String,
    resulting_version: String,
    affected_ids: Vec<String>,
    backend_commit_id: String,
    authority_revalidated_at: DateTime<Utc>,
    prepared_at: DateTime<Utc>,
    committed_at: DateTime<Utc>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for CognitionCommitReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CognitionCommitReceiptWire::deserialize(deserializer)?;
        let receipt = Self {
            schema_version: wire.schema_version,
            effect: wire.effect,
            subject: wire.subject,
            resource: wire.resource,
            job_id: wire.job_id,
            governed_source_scope: wire.governed_source_scope,
            typedid_request_digest: wire.typedid_request_digest,
            proposal_digest: wire.proposal_digest,
            governed_scan_digest: wire.governed_scan_digest,
            input_snapshot_digest: wire.input_snapshot_digest,
            policy_decision_digest: wire.policy_decision_digest,
            authorization_receipt_digest: wire.authorization_receipt_digest,
            prior_version: wire.prior_version,
            resulting_version: wire.resulting_version,
            affected_ids: wire.affected_ids,
            backend_commit_id: wire.backend_commit_id,
            authority_revalidated_at: wire.authority_revalidated_at,
            prepared_at: wire.prepared_at,
            committed_at: wire.committed_at,
            issued_at: wire.issued_at,
            expires_at: wire.expires_at,
        };
        receipt.validate().map_err(D::Error::custom)?;
        Ok(receipt)
    }
}
