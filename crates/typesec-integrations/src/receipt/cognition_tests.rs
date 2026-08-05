use super::*;
use chrono::TimeZone;

fn claims() -> CognitionCommitReceipt {
    let committed_at = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    let mut receipt = CognitionCommitReceipt::new(
        "did:key:agent",
        "memory/did:key:agent/research",
        "job-42",
        "commit-42",
        committed_at,
        TimeDelta::minutes(5),
    );
    receipt.typedid_request_digest = "sha256:request".into();
    receipt.proposal_digest = "sha256:proposal".into();
    receipt.input_snapshot_digest = "sha256:snapshot".into();
    receipt.policy_decision_digest = "sha256:policy".into();
    receipt.authorization_receipt_digest = "sha256:authorization".into();
    receipt.prior_version = "version-41".into();
    receipt.resulting_version = "version-42".into();
    receipt.affected_ids = vec!["mem-old".into(), "mem-new".into()];
    receipt
}

#[test]
fn cognition_receipt_round_trips_all_commit_evidence() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = claims();
    let token = issuer.issue_cognition(&receipt).unwrap();
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify_cognition(&token, receipt.committed_at + TimeDelta::seconds(1))
        .unwrap();
    assert_eq!(verified, receipt);
}

#[test]
fn cognition_receipt_rejects_missing_or_tampered_evidence() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let mut incomplete = claims();
    incomplete.proposal_digest.clear();
    assert!(matches!(
        issuer.issue_cognition(&incomplete),
        Err(ReceiptError::InvalidClaims(_))
    ));

    let token = issuer.issue_cognition(&claims()).unwrap();
    let forged_claims = B64.encode(serde_json::to_vec(&incomplete).unwrap());
    let signature = token.split_once('.').unwrap().1;
    let forged = format!("{forged_claims}.{signature}");
    assert!(matches!(
        ReceiptVerifier::new(issuer.verifying_key())
            .verify_cognition(&forged, claims().committed_at),
        Err(ReceiptError::BadSignature)
    ));
}
