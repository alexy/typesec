use super::*;

#[test]
fn signatures_bind_exact_opaque_claim_bytes() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = receipt();
    let token = issuer
        .issue_cognition(&receipt, receipt.issued_at())
        .unwrap();
    let mut forged_receipt = serde_json::to_value(&receipt).unwrap();
    forged_receipt["proposalDigest"] = serde_json::json!(digest('a'));
    let forged_claims = B64.encode(serde_json::to_vec(&forged_receipt).unwrap());
    let signature = token.split_once('.').unwrap().1;
    let forged = format!("{forged_claims}.{signature}");

    assert!(matches!(
        ReceiptVerifier::new(issuer.verifying_key()).verify_cognition(&forged, receipt.issued_at()),
        Err(ReceiptError::BadSignature)
    ));
}

#[test]
fn receipt_requires_bounded_canonical_identities() {
    let setters: [fn(&mut CognitionCommitReceiptClaims, String); 6] = [
        |claims, value| claims.subject = value,
        |claims, value| claims.resource = value,
        |claims, value| claims.job_id = value,
        |claims, value| claims.backend_commit_id = value,
        |claims, value| claims.prior_version = value,
        |claims, value| claims.resulting_version = value,
    ];
    for setter in setters {
        for invalid_identity in [
            "".to_owned(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\ncharacter".to_owned(),
            "x".repeat(cognition::validation::MAX_IDENTITY_BYTES + 1),
        ] {
            let mut claims = complete_claims();
            setter(&mut claims, invalid_identity);
            assert_fixed_error(
                CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
                "invalid cognition receipt identity",
            );
        }
    }
}

#[test]
fn receipt_requires_canonical_lowercase_sha256_evidence() {
    let setters: [fn(&mut CognitionCommitReceiptClaims, String); 6] = [
        |claims, value| claims.typedid_request_digest = value,
        |claims, value| claims.proposal_digest = value,
        |claims, value| claims.governed_scan_digest = value,
        |claims, value| claims.input_snapshot_digest = value,
        |claims, value| claims.policy_decision_digest = value,
        |claims, value| claims.authorization_receipt_digest = value,
    ];
    for setter in setters {
        for invalid_digest in [
            "sha256:abc".to_owned(),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{} ", "a".repeat(64)),
        ] {
            let mut claims = complete_claims();
            setter(&mut claims, invalid_digest);
            assert_fixed_error(
                CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
                "invalid cognition receipt digest",
            );
        }
    }
}

#[test]
fn governed_grant_cannot_be_substituted_for_the_input_snapshot() {
    let mut claims = complete_claims();
    claims.input_snapshot_digest = claims.governed_scan_digest.clone();
    assert_fixed_error(
        CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt digest",
    );
}

#[test]
fn receipt_validates_optional_scope_versions_and_affected_ids() {
    let mut claims = complete_claims();
    claims.governed_source_scope = Some("scope:local".into());
    assert_fixed_error(
        CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt digest",
    );

    let mut claims = complete_claims();
    claims.resulting_version = claims.prior_version.clone();
    assert_fixed_error(
        CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
        "invalid cognition receipt versions",
    );

    for affected_ids in [
        vec![],
        vec!["mem-02".into(), "mem-01".into()],
        vec!["mem-01".into(), "mem-01".into()],
        vec!["invalid\nid".into()],
    ] {
        let mut claims = complete_claims();
        claims.affected_ids = affected_ids;
        assert_fixed_error(
            CognitionCommitReceipt::new(claims, TimeDelta::minutes(5)).unwrap_err(),
            "invalid cognition receipt affected IDs",
        );
    }
}
