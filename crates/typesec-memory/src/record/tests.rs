use super::*;
use chrono::TimeZone;

fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

#[test]
fn provenance_drives_birth_label_and_quarantine() {
    assert!(!Provenance::Operator.is_untrusted());
    assert!(
        !Provenance::Envelope {
            envelope_id: "e1".into()
        }
        .is_untrusted()
    );
    assert!(
        Provenance::ModelText.is_untrusted(),
        "raw model text is quarantined"
    );
    assert_eq!(Provenance::Operator.default_label(), Label::Internal);
}

#[test]
fn bitemporal_validity_and_expiry() {
    let base = StoredRecord {
        id: MemoryId::from_string("mem-1"),
        space_id: "memory/user:alice/profile".into(),
        kind: MemoryKind::Semantic,
        label: Label::Internal,
        quarantined: false,
        entities: vec![],
        provenance: Provenance::Operator,
        observed_at: at(2024, 1, 1),
        valid_from: at(2023, 1, 1),
        invalid_at: Some(at(2026, 1, 1)),
        expires_at: Some(at(2027, 1, 1)),
        purposes: vec![],
        content: MemoryContent::text("Alice lives in Venice"),
    };

    assert!(base.is_valid_at(at(2024, 6, 1)), "within validity window");
    assert!(!base.is_valid_at(at(2026, 6, 1)), "after invalidation");
    assert!(!base.is_valid_at(at(2022, 1, 1)), "before it became true");

    assert!(!base.is_expired_at(at(2026, 6, 1)));
    assert!(base.is_expired_at(at(2027, 6, 1)));
}

#[test]
fn draft_builder_carries_intent() {
    let draft = MemoryDraft::new(
        MemoryKind::Profile,
        MemoryContent::text("prefers dark mode"),
        Provenance::Operator,
    )
    .with_label(Label::Sensitive)
    .with_entities([EntityRef::new("Alice", "person")])
    .for_purposes(["personalization"]);
    assert_eq!(draft.label, Some(Label::Sensitive));
    assert_eq!(draft.entities.len(), 1);
    assert_eq!(draft.purposes, ["personalization"]);
}
