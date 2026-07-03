use super::*;
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
