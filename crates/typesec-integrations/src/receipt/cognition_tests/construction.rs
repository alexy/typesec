use super::*;
use chrono::DateTime;

#[test]
fn constructor_rejects_incomplete_claims_immediately() {
    let mut incomplete = complete_claims();
    incomplete.proposal_digest.clear();
    assert_fixed_error(
        CognitionCommitReceipt::new(incomplete, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt digest",
    );
}

#[test]
fn constructor_rejects_invalid_expiry_windows_without_panicking() {
    for ttl in [TimeDelta::zero(), TimeDelta::seconds(-1)] {
        let error = CognitionCommitReceipt::new(complete_claims(), ttl).unwrap_err();
        assert_fixed_error(error, "invalid cognition receipt validity window");
    }

    let mut overflow = complete_claims();
    overflow.prepared_at = DateTime::<Utc>::MAX_UTC;
    overflow.committed_at = DateTime::<Utc>::MAX_UTC;
    overflow.issued_at = DateTime::<Utc>::MAX_UTC;
    let error = CognitionCommitReceipt::new(overflow, TimeDelta::seconds(1)).unwrap_err();
    assert_fixed_error(error, "invalid cognition receipt validity window");
}

#[test]
fn constructor_rejects_inverted_phase_times() {
    let mut future_authority = complete_claims();
    future_authority.authority_revalidated_at =
        future_authority.prepared_at + TimeDelta::nanoseconds(1);
    assert_fixed_error(
        CognitionCommitReceipt::new(future_authority, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt validity window",
    );

    let mut early_commit = complete_claims();
    early_commit.committed_at = early_commit.prepared_at - TimeDelta::nanoseconds(1);
    assert_fixed_error(
        CognitionCommitReceipt::new(early_commit, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt validity window",
    );

    let mut early_issue = complete_claims();
    early_issue.issued_at = early_issue.committed_at - TimeDelta::nanoseconds(1);
    assert_fixed_error(
        CognitionCommitReceipt::new(early_issue, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt validity window",
    );
}

#[test]
fn issued_at_may_equal_committed_at() {
    let mut claims = complete_claims();
    claims.issued_at = claims.committed_at;

    let receipt = CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap();

    assert_eq!(receipt.issued_at(), receipt.committed_at());
}

#[test]
fn issued_at_may_not_equal_expiry() {
    let mut claims = complete_claims();
    claims.issued_at = claims.prepared_at + TimeDelta::minutes(5);
    assert_fixed_error(
        CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt validity window",
    );
}

#[test]
fn receipt_schema_is_required_and_exact() {
    let mut encoded = serde_json::to_value(receipt()).unwrap();
    encoded.as_object_mut().unwrap().remove("schemaVersion");
    assert!(serde_json::from_value::<CognitionCommitReceipt>(encoded).is_err());

    let mut unsupported = serde_json::to_value(receipt()).unwrap();
    unsupported["schemaVersion"] = serde_json::json!(CognitionCommitReceipt::SCHEMA_VERSION + 1);
    assert!(serde_json::from_value::<CognitionCommitReceipt>(unsupported).is_err());
}
