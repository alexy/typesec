use super::*;

#[test]
fn issuer_rejects_receipts_outside_their_issuance_window() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = receipt();

    assert!(matches!(
        issuer.issue_cognition(&receipt, receipt.issued_at() - TimeDelta::nanoseconds(1)),
        Err(ReceiptError::NotYetValid { .. })
    ));
    assert!(matches!(
        issuer.issue_cognition(&receipt, receipt.expires_at()),
        Err(ReceiptError::Expired { .. })
    ));
}

#[test]
fn future_backend_and_first_issuance_times_fail_closed_until_local_time_catches_up() {
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));
    let receipt = receipt();
    let local_now = receipt.committed_at() - TimeDelta::nanoseconds(1);

    assert!(matches!(
        issuer.issue_cognition(&receipt, local_now),
        Err(ReceiptError::NotYetValid { .. })
    ));
    issuer
        .issue_cognition(&receipt, receipt.issued_at())
        .unwrap();
}
