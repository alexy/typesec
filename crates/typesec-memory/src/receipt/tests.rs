use crate::vault::Tombstone;
use crate::{MemoryId, MemorySpace};
use chrono::{TimeDelta, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use typesec_integrations::receipt::{ReceiptIssuer, ReceiptVerifier};

fn issuer() -> ReceiptIssuer {
    ReceiptIssuer::new(SigningKey::from_bytes(&[9u8; 32]))
}

#[test]
fn deletion_receipt_verifies_and_records_what_was_forgotten() {
    let at = Utc.with_ymd_and_hms(2026, 7, 4, 12, 0, 0).unwrap();
    let tomb = Tombstone {
        forgotten: vec![
            MemoryId::from_string("mem-1"),
            MemoryId::from_string("mem-2"),
        ],
        at,
    };
    let space = MemorySpace::new("user:alice", "profile");
    let issuer = issuer();

    let token = tomb.issue_receipt(&issuer, "agent:keeper", &space, TimeDelta::seconds(300));
    let verified = ReceiptVerifier::new(issuer.verifying_key())
        .verify(&token, at + TimeDelta::seconds(10))
        .expect("fresh deletion receipt verifies");

    assert_eq!(verified.action, "forget");
    assert_eq!(verified.resource, "memory/user:alice/profile");
    assert_eq!(verified.call_id.as_deref(), Some("mem-1,mem-2"));
}
