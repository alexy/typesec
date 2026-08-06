use super::*;

#[test]
fn cognition_receipt_round_trips_all_commit_evidence() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = claims();
    let token = issuer.issue_cognition(&receipt).unwrap();
    assert_eq!(token, issuer.issue_cognition(&receipt).unwrap());
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify_cognition(&token, receipt.prepared_at + TimeDelta::seconds(1))
        .unwrap();
    assert_eq!(verified, receipt);
}

#[test]
fn cognition_receipt_round_trips_composite_governed_source_scope() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[12; 32]));
    let mut complete = complete_claims();
    complete.governed_source_scope = Some(digest('a'));
    let receipt = CognitionCommitReceipt::new(complete, TimeDelta::minutes(5)).unwrap();
    let token = issuer.issue_cognition(&receipt).unwrap();
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify_cognition(&token, receipt.prepared_at)
        .unwrap();
    assert_eq!(
        verified.governed_source_scope,
        receipt.governed_source_scope
    );
}

#[test]
fn local_v2_receipt_may_omit_the_optional_governed_scope() {
    let receipt = claims();
    let mut encoded = serde_json::to_value(receipt).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .remove("governedSourceScope");
    let decoded: CognitionCommitReceipt = serde_json::from_value(encoded).unwrap();
    assert!(decoded.governed_source_scope.is_none());
    decoded.validate().unwrap();
}

#[test]
fn wire_distinguishes_revalidation_preparation_commit_and_expiry() {
    let receipt = claims();
    let encoded = serde_json::to_value(&receipt).unwrap();
    assert_eq!(
        encoded
            .get("schemaVersion")
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        encoded
            .get("authorityRevalidatedAt")
            .and_then(|value| value.as_str()),
        Some("2026-08-05T11:59:00Z")
    );
    assert_eq!(
        encoded.get("preparedAt").and_then(|value| value.as_str()),
        Some("2026-08-05T12:00:00Z")
    );
    assert_eq!(
        encoded.get("committedAt").and_then(|value| value.as_str()),
        Some("2026-08-05T12:00:02Z")
    );
    assert_eq!(
        receipt.expires_at,
        receipt.prepared_at + TimeDelta::minutes(5)
    );
    assert_ne!(
        receipt.expires_at,
        receipt.committed_at + TimeDelta::minutes(5)
    );
    assert_ne!(receipt.governed_scan_digest, receipt.input_snapshot_digest);
}

#[test]
fn verification_enforces_the_preparation_anchored_window() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = claims();
    let token = issuer.issue_cognition(&receipt).unwrap();
    let verifier = ReceiptVerifier::new(issuer.verifying_key());

    assert_eq!(
        verifier
            .verify_cognition(&token, receipt.prepared_at)
            .unwrap(),
        receipt
    );
    assert!(matches!(
        verifier.verify_cognition(&token, receipt.prepared_at - TimeDelta::nanoseconds(1)),
        Err(ReceiptError::NotYetValid { .. })
    ));
    assert!(matches!(
        verifier.verify_cognition(&token, receipt.expires_at),
        Err(ReceiptError::Expired { .. })
    ));
}
