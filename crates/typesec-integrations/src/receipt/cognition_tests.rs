use super::*;
use chrono::{TimeDelta, TimeZone, Utc};

fn receipt() -> CognitionCommitReceipt {
    CognitionCommitReceipt::new(complete_claims(), TimeDelta::minutes(5)).unwrap()
}

fn complete_claims() -> CognitionCommitReceiptClaims {
    CognitionCommitReceiptClaims {
        effect: CognitionEffect::Mutated,
        subject: "did:key:agent".into(),
        resource: "memory/did:key:agent/research".into(),
        job_id: "job-42".into(),
        governed_source_scope: None,
        typedid_request_digest: digest('1'),
        proposal_digest: digest('2'),
        governed_scan_digest: digest('3'),
        input_snapshot_digest: digest('4'),
        policy_decision_digest: digest('5'),
        authorization_receipt_digest: digest('6'),
        prior_version: "version-41".into(),
        resulting_version: "version-42".into(),
        affected_ids: vec!["mem-01".into(), "mem-02".into()],
        backend_commit_id: "commit-42".into(),
        authority_revalidated_at: Utc.with_ymd_and_hms(2026, 8, 5, 11, 59, 0).unwrap(),
        prepared_at: Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap(),
        committed_at: Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 2).unwrap(),
        issued_at: Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 3).unwrap(),
    }
}

fn digest(hex: char) -> String {
    format!("sha256:{}", hex.to_string().repeat(64))
}

fn assert_fixed_error(error: ReceiptError, message: &str) {
    assert_eq!(
        error.to_string(),
        format!("invalid receipt claims: {message}")
    );
}

mod bounds;
mod construction;
mod golden;
mod issuance;
mod no_change;
mod round_trip;
mod validation;
mod wire;
