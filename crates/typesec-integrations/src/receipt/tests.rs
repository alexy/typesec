use super::*;

#[test]
fn every_semantic_action_round_trips_as_signed_model_bound_claims() {
    let now = Utc::now();
    let issuer = ReceiptIssuer::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let verifier = ReceiptVerifier::new(issuer.verifying_key());
    for action in [
        SemanticDecisionAction::PublishModel,
        SemanticDecisionAction::ConsumeModel,
        SemanticDecisionAction::AccessField,
        SemanticDecisionAction::ExecuteMetric,
        SemanticDecisionAction::ExecuteSemanticQuery,
        SemanticDecisionAction::AccessAiContext,
    ] {
        let receipt = SemanticDecisionReceipt::new(
            "did:key:publisher",
            action,
            "semantic://tpcds/store_sales",
            "tpcds",
            1,
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
            Some(format!("sha256:{}", "3".repeat(64))),
            now,
            TimeDelta::minutes(5),
        )
        .unwrap();
        let token = issuer.issue_semantic(&receipt);
        assert_eq!(verifier.verify_semantic(&token, now).unwrap(), receipt);
    }
}

#[test]
fn semantic_receipt_rejects_unbound_or_tampered_claims() {
    let now = Utc::now();
    assert!(
        SemanticDecisionReceipt::new(
            "agent",
            SemanticDecisionAction::ConsumeModel,
            "semantic://m",
            "m",
            0,
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
            None,
            now,
            TimeDelta::minutes(1),
        )
        .is_err()
    );

    let issuer = ReceiptIssuer::new(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
    let verifier = ReceiptVerifier::new(issuer.verifying_key());
    let receipt = SemanticDecisionReceipt::new(
        "agent",
        SemanticDecisionAction::AccessField,
        "semantic://m/f",
        "m",
        1,
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        None,
        now,
        TimeDelta::minutes(1),
    )
    .unwrap();
    let mut token = issuer.issue_semantic(&receipt).into_bytes();
    token[5] = if token[5] == b'A' { b'B' } else { b'A' };
    assert!(matches!(
        verifier.verify_semantic(std::str::from_utf8(&token).unwrap(), now),
        Err(ReceiptError::BadSignature)
    ));
}
use chrono::TimeZone;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 3, 12, 0, 0).unwrap()
}

fn issuer() -> ReceiptIssuer {
    ReceiptIssuer::new(SigningKey::from_bytes(&[7u8; 32]))
}

fn receipt() -> DecisionReceipt {
    DecisionReceipt::new(
        "agent:analyst",
        "read",
        "reports/q1",
        now(),
        TimeDelta::seconds(300),
    )
    .for_tool_call("read_report", Some("call_1"))
}

#[test]
fn round_trip_verifies_and_preserves_claims() {
    let issuer = issuer();
    let token = issuer.issue(&receipt());
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify(&token, now() + TimeDelta::seconds(10))
        .expect("fresh receipt verifies");
    assert_eq!(verified, receipt());
    assert_eq!(verified.tool_name.as_deref(), Some("read_report"));
    assert_eq!(verified.call_id.as_deref(), Some("call_1"));
}

#[test]
fn expired_and_future_receipts_are_rejected() {
    let issuer = issuer();
    let token = issuer.issue(&receipt());
    let verifier = ReceiptVerifier::new(issuer.verifying_key());

    assert!(matches!(
        verifier.verify(&token, now() + TimeDelta::seconds(300)),
        Err(ReceiptError::Expired { .. })
    ));
    assert!(matches!(
        verifier.verify(&token, now() - TimeDelta::seconds(1)),
        Err(ReceiptError::NotYetValid { .. })
    ));
}

#[test]
fn wrong_key_and_tampered_claims_are_rejected() {
    let issuer = issuer();
    let token = issuer.issue(&receipt());

    let other_key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    assert!(matches!(
        ReceiptVerifier::new(other_key).verify(&token, now()),
        Err(ReceiptError::BadSignature)
    ));

    // Swap the claims for different ones signed under the same structure:
    // the original signature must not cover them.
    let inflated = DecisionReceipt::new(
        "agent:analyst",
        "delete",
        "reports/*",
        now(),
        TimeDelta::seconds(300),
    );
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&inflated).unwrap());
    let signature = token.split_once('.').unwrap().1;
    let forged = format!("{claims}.{signature}");
    assert!(matches!(
        ReceiptVerifier::new(issuer.verifying_key()).verify(&forged, now()),
        Err(ReceiptError::BadSignature)
    ));
}

#[test]
fn malformed_tokens_error_cleanly() {
    let verifier = ReceiptVerifier::new(issuer().verifying_key());
    for token in ["", "no-separator", "a.b", "!!!.???"] {
        assert!(matches!(
            verifier.verify(token, now()),
            Err(ReceiptError::Malformed(_) | ReceiptError::BadSignature)
        ));
    }
}
