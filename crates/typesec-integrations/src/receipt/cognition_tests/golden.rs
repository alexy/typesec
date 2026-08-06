use super::*;

const RECEIPT_V3_JSON: &str = include_str!("fixtures/receipt-v3.json");
const RECEIPT_V3_TOKEN: &str = include_str!("fixtures/receipt-v3.token");

#[test]
fn receipt_v3_wire_and_token_match_the_exact_golden_fixture() {
    let receipt = receipt();
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));

    assert_eq!(serde_json::to_string(&receipt).unwrap(), fixture_json());
    assert_eq!(
        issuer
            .issue_cognition(&receipt, receipt.issued_at())
            .unwrap(),
        fixture_token()
    );
}

#[test]
fn decoded_golden_receipt_resigns_to_byte_identical_token() {
    let receipt: CognitionCommitReceipt = serde_json::from_str(fixture_json()).unwrap();
    let issuer = ReceiptIssuer::new(SigningKey::from_bytes(&[11; 32]));

    let resigned = issuer
        .issue_cognition(&receipt, receipt.issued_at() + TimeDelta::seconds(1))
        .unwrap();

    assert_eq!(resigned, fixture_token());
    assert_eq!(
        ReceiptVerifier::new(issuer.verifying_key())
            .verify_cognition(fixture_token(), receipt.issued_at())
            .unwrap(),
        receipt
    );
}

fn fixture_json() -> &'static str {
    RECEIPT_V3_JSON.trim_end()
}

fn fixture_token() -> &'static str {
    RECEIPT_V3_TOKEN.trim_end()
}
