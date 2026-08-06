use super::*;

#[test]
fn no_change_receipt_round_trips_explicit_effect() {
    let mut complete = complete_claims();
    complete.effect = CognitionEffect::NoChange;
    complete
        .resulting_version
        .clone_from(&complete.prior_version);
    complete.affected_ids.clear();

    let receipt = CognitionCommitReceipt::new(complete, TimeDelta::minutes(5)).unwrap();
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[13; 32]));
    let token = issuer
        .issue_cognition(&receipt, receipt.issued_at())
        .unwrap();
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify_cognition(&token, receipt.issued_at())
        .unwrap();

    assert_eq!(verified.effect(), CognitionEffect::NoChange);
    assert!(verified.affected_ids().is_empty());
    assert_eq!(verified.prior_version(), verified.resulting_version());
}

#[test]
fn effect_must_match_versions_and_affected_ids() {
    let mut no_change = complete_claims();
    no_change.effect = CognitionEffect::NoChange;
    assert_fixed_error(
        CognitionCommitReceipt::new(no_change, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt versions",
    );

    let mut no_change = complete_claims();
    no_change.effect = CognitionEffect::NoChange;
    no_change
        .resulting_version
        .clone_from(&no_change.prior_version);
    assert_fixed_error(
        CognitionCommitReceipt::new(no_change, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt affected IDs",
    );

    let mut mutated = complete_claims();
    mutated.affected_ids.clear();
    assert_fixed_error(
        CognitionCommitReceipt::new(mutated, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt affected IDs",
    );
}

#[test]
fn current_receipt_wire_requires_effect() {
    let mut encoded = serde_json::to_value(receipt()).unwrap();
    encoded.as_object_mut().unwrap().remove("effect");

    assert!(serde_json::from_value::<CognitionCommitReceipt>(encoded).is_err());
}
