use super::*;

#[test]
fn issuer_rejects_mutated_evidence_and_signatures_bind_claim_bytes() {
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
fn receipt_requires_bounded_canonical_identities() {
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
            assert_fixed_error(
                receipt.validate().unwrap_err(),
                "invalid cognition receipt identity",
            );
        }
    }
}

#[test]
fn receipt_requires_canonical_lowercase_sha256_evidence() {
    let setters: [fn(&mut CognitionCommitReceipt, String); 6] = [
        |receipt, value| receipt.typedid_request_digest = value,
        |receipt, value| receipt.proposal_digest = value,
        |receipt, value| receipt.governed_scan_digest = value,
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
            assert_fixed_error(
                receipt.validate().unwrap_err(),
                "invalid cognition receipt digest",
            );
        }
    }
}

#[test]
fn governed_grant_cannot_be_substituted_for_the_input_snapshot() {
    let mut receipt = claims();
    receipt.input_snapshot_digest = receipt.governed_scan_digest.clone();
    assert_fixed_error(
        receipt.validate().unwrap_err(),
        "invalid cognition receipt digest",
    );
}

#[test]
fn receipt_validates_optional_scope_versions_and_affected_ids() {
    let mut receipt = claims();
    receipt.governed_source_scope = Some("scope:local".into());
    assert_fixed_error(
        receipt.validate().unwrap_err(),
        "invalid cognition receipt digest",
    );

    let mut receipt = claims();
    receipt.resulting_version = receipt.prior_version.clone();
    assert_fixed_error(
        receipt.validate().unwrap_err(),
        "invalid cognition receipt versions",
    );

    for affected_ids in [
        vec![],
        vec!["mem-02".into(), "mem-01".into()],
        vec!["mem-01".into(), "mem-01".into()],
        vec!["invalid\nid".into()],
    ] {
        let mut receipt = claims();
        receipt.affected_ids = affected_ids;
        assert_fixed_error(
            receipt.validate().unwrap_err(),
            "invalid cognition receipt affected IDs",
        );
    }
}
