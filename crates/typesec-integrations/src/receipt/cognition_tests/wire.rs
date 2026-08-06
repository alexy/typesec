use super::*;

#[test]
fn wire_rejects_unversioned_and_legacy_receipts() {
    let current = serde_json::to_value(receipt()).unwrap();

    let mut unversioned = current.clone();
    unversioned.as_object_mut().unwrap().remove("schemaVersion");
    assert!(serde_json::from_value::<CognitionCommitReceipt>(unversioned).is_err());

    for schema_version in [1, 2] {
        let mut legacy = current.clone();
        legacy["schemaVersion"] = serde_json::json!(schema_version);
        assert!(serde_json::from_value::<CognitionCommitReceipt>(legacy).is_err());
    }

    let mut legacy_v2_shape = current;
    legacy_v2_shape["schemaVersion"] = serde_json::json!(2);
    legacy_v2_shape.as_object_mut().unwrap().remove("issuedAt");
    assert!(serde_json::from_value::<CognitionCommitReceipt>(legacy_v2_shape).is_err());
}

#[test]
fn wire_rejects_unknown_fields() {
    let mut encoded = serde_json::to_value(receipt()).unwrap();
    encoded["unexpectedEvidence"] = serde_json::json!("must-not-be-ignored");

    assert!(serde_json::from_value::<CognitionCommitReceipt>(encoded).is_err());
}

#[test]
fn wire_rejects_invalid_claim_shapes_during_deserialization() {
    let current = serde_json::to_value(receipt()).unwrap();
    let invalid_values = [
        ("proposalDigest", serde_json::json!("sha256:invalid")),
        ("resultingVersion", serde_json::json!("version-41")),
        ("affectedIds", serde_json::json!([])),
        ("issuedAt", serde_json::json!("2026-08-05T11:59:59Z")),
        ("expiresAt", serde_json::json!("2026-08-05T12:00:03Z")),
    ];

    for (field, value) in invalid_values {
        let mut invalid = current.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<CognitionCommitReceipt>(invalid).is_err(),
            "{field} must be rejected"
        );
    }
}

#[test]
fn verifier_rejects_signed_but_semantically_invalid_wire_claims() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = receipt();
    let mut invalid = serde_json::to_value(&receipt).unwrap();
    invalid["issuedAt"] = serde_json::json!("2026-08-05T11:59:59Z");
    let token = issuer.issue_claims(&invalid);

    assert!(matches!(
        ReceiptVerifier::new(issuer.verifying_key()).verify_cognition(&token, receipt.issued_at()),
        Err(ReceiptError::Malformed(_))
    ));
}
