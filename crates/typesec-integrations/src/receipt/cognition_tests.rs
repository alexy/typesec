use super::*;
use chrono::TimeZone;

fn claims() -> CognitionCommitReceipt {
    let prepared_at = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    let mut receipt = CognitionCommitReceipt::new(
        "did:key:agent",
        "memory/did:key:agent/research",
        "job-42",
        "commit-42",
        prepared_at,
        TimeDelta::minutes(5),
    )
    .unwrap();
    receipt.typedid_request_digest = digest('1');
    receipt.proposal_digest = digest('2');
    receipt.input_snapshot_digest = digest('3');
    receipt.policy_decision_digest = digest('4');
    receipt.authorization_receipt_digest = digest('5');
    receipt.prior_version = "version-41".into();
    receipt.resulting_version = "version-42".into();
    receipt.affected_ids = vec!["mem-01".into(), "mem-02".into()];
    receipt
}

fn digest(hex: char) -> String {
    format!("sha256:{}", hex.to_string().repeat(64))
}

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
fn cognition_receipt_round_trips_and_validates_governed_source_scope() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[12; 32]));
    let mut receipt = claims();
    receipt.governed_source_scope = Some(digest('a'));
    let token = issuer.issue_cognition(&receipt).unwrap();
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify_cognition(&token, receipt.prepared_at)
        .unwrap();
    assert_eq!(
        verified.governed_source_scope,
        receipt.governed_source_scope
    );

    for invalid in [
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "g".repeat(64)),
        "scope:local".to_owned(),
    ] {
        let mut invalid_receipt = claims();
        invalid_receipt.governed_source_scope = Some(invalid);
        assert_fixed_error(
            invalid_receipt.validate().unwrap_err(),
            "invalid cognition receipt digest",
        );
    }
}

#[test]
fn legacy_local_receipt_without_scope_still_deserializes() {
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
fn cognition_receipt_wire_names_the_trusted_preparation_time() {
    let encoded = serde_json::to_value(claims()).unwrap();
    assert_eq!(
        encoded
            .get("preparedAt")
            .and_then(serde_json::Value::as_str),
        Some("2026-08-05T12:00:00Z")
    );
    assert!(encoded.get("committedAt").is_none());
}

#[test]
fn cognition_receipt_verification_enforces_the_preparation_window() {
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
            .verify_cognition(&forged, claims().prepared_at),
        Err(ReceiptError::BadSignature)
    ));
}

#[test]
fn cognition_receipt_constructor_rejects_invalid_windows_without_panicking() {
    let prepared_at = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    for ttl in [TimeDelta::zero(), TimeDelta::seconds(-1)] {
        let error =
            CognitionCommitReceipt::new("subject", "resource", "job", "commit", prepared_at, ttl)
                .unwrap_err();
        assert_fixed_error(error, "invalid cognition receipt validity window");
    }

    let error = CognitionCommitReceipt::new(
        "subject",
        "resource",
        "job",
        "commit",
        DateTime::<Utc>::MAX_UTC,
        TimeDelta::seconds(1),
    )
    .unwrap_err();
    assert_fixed_error(error, "invalid cognition receipt validity window");
}

#[test]
fn cognition_receipt_requires_bounded_canonical_identities() {
    let setters: [fn(&mut CognitionCommitReceipt, String); 6] = [
        |receipt, value| receipt.subject = value,
        |receipt, value| receipt.resource = value,
        |receipt, value| receipt.job_id = value,
        |receipt, value| receipt.backend_commit_id = value,
        |receipt, value| receipt.prior_version = value,
        |receipt, value| receipt.resulting_version = value,
    ];
    for setter in setters {
        for invalid_identity in [
            "".to_owned(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\ncharacter".to_owned(),
            "x".repeat(cognition::validation::MAX_IDENTITY_BYTES + 1),
        ] {
            let mut receipt = claims();
            setter(&mut receipt, invalid_identity);
            let error = receipt.validate().unwrap_err();
            assert_fixed_error(error, "invalid cognition receipt identity");
        }
    }
}

#[test]
fn cognition_receipt_accepts_each_identity_at_the_inclusive_byte_limit() {
    let setters: [fn(&mut CognitionCommitReceipt, String); 6] = [
        |receipt, value| receipt.subject = value,
        |receipt, value| receipt.resource = value,
        |receipt, value| receipt.job_id = value,
        |receipt, value| receipt.backend_commit_id = value,
        |receipt, value| receipt.prior_version = value,
        |receipt, value| receipt.resulting_version = value,
    ];
    for setter in setters {
        let mut receipt = claims();
        setter(
            &mut receipt,
            "x".repeat(cognition::validation::MAX_IDENTITY_BYTES),
        );
        receipt.validate().unwrap();
    }
}

#[test]
fn cognition_receipt_requires_canonical_lowercase_sha256_evidence() {
    let setters: [fn(&mut CognitionCommitReceipt, String); 5] = [
        |receipt, value| receipt.typedid_request_digest = value,
        |receipt, value| receipt.proposal_digest = value,
        |receipt, value| receipt.input_snapshot_digest = value,
        |receipt, value| receipt.policy_decision_digest = value,
        |receipt, value| receipt.authorization_receipt_digest = value,
    ];
    for setter in setters {
        for invalid_digest in [
            "sha256:abc".to_owned(),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{} ", "a".repeat(64)),
        ] {
            let mut receipt = claims();
            setter(&mut receipt, invalid_digest);
            let error = receipt.validate().unwrap_err();
            assert_fixed_error(error, "invalid cognition receipt digest");
        }
    }
}

#[test]
fn cognition_receipt_requires_distinct_opaque_versions() {
    let mut receipt = claims();
    receipt.resulting_version = receipt.prior_version.clone();
    let error = receipt.validate().unwrap_err();
    assert_fixed_error(error, "invalid cognition receipt versions");
}

#[test]
fn cognition_receipt_requires_sorted_unique_nonempty_affected_ids() {
    for affected_ids in [
        vec![],
        vec!["mem-02".into(), "mem-01".into()],
        vec!["mem-01".into(), "mem-01".into()],
        vec!["invalid\nid".into()],
    ] {
        let mut receipt = claims();
        receipt.affected_ids = affected_ids;
        let error = receipt.validate().unwrap_err();
        assert_fixed_error(error, "invalid cognition receipt affected IDs");
    }
}

#[test]
fn cognition_receipt_accepts_the_exact_affected_id_count_limit() {
    let mut receipt = claims();
    receipt.affected_ids = (0..cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    receipt.validate().unwrap();
}

#[test]
fn cognition_receipt_bounds_affected_id_count_and_aggregate_bytes() {
    let mut receipt = claims();
    receipt.affected_ids = (0..=cognition::validation::MAX_AFFECTED_ID_COUNT)
        .map(|index| format!("id-{index:04}"))
        .collect();
    let error = receipt.validate().unwrap_err();
    assert_fixed_error(error, "invalid cognition receipt affected IDs");

    let exact_aggregate =
        cognition::validation::MAX_AFFECTED_ID_BYTES / cognition::validation::MAX_IDENTITY_BYTES;
    receipt.affected_ids = large_sorted_ids(exact_aggregate);
    receipt.validate().unwrap();

    receipt.affected_ids = large_sorted_ids(exact_aggregate + 1);
    let error = receipt.validate().unwrap_err();
    assert_fixed_error(error, "invalid cognition receipt affected IDs");
}

fn large_sorted_ids(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| {
            let prefix = format!("{index:04}:");
            format!(
                "{prefix}{}",
                "x".repeat(cognition::validation::MAX_IDENTITY_BYTES - prefix.len())
            )
        })
        .collect()
}

fn assert_fixed_error(error: ReceiptError, message: &str) {
    assert_eq!(
        error.to_string(),
        format!("invalid receipt claims: {message}")
    );
}
