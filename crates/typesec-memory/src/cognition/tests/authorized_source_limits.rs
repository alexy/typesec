use super::*;

#[test]
fn authorized_record_metadata_bytes_are_fully_bounded() {
    assert_authorized_record_boundary(SourcePayload::Metadata);
}

#[test]
fn authorized_record_entity_bytes_are_fully_bounded() {
    assert_authorized_record_boundary(SourcePayload::Entity);
}

#[test]
fn authorized_record_provenance_bytes_are_fully_bounded() {
    assert_authorized_record_boundary(SourcePayload::Provenance);
}

#[test]
fn oversized_authorized_record_stops_before_loading_another_clone() {
    let fixture = Fixture::new();
    {
        let mut state = fixture.store.state();
        let record = state.records.get_mut(&fixture.source).expect("source");
        record.provenance = Provenance::GuardedTool {
            tool: "x".repeat(MAX_COGNITION_SOURCE_BYTES + 1),
            call_id: None,
        };
    }
    let never_read = MemoryId::from_string("mem-never-read");
    let before_gets = fixture.store.state().get_calls;

    assert!(matches!(
        super::super::validate::load_sources(
            &fixture.vault,
            &fixture.space,
            &[fixture.source.clone(), never_read],
            "research",
            Utc::now(),
        ),
        Err(MemoryError::Cognition(CognitionApplyError::LimitExceeded(
            "source bytes"
        )))
    ));
    assert_eq!(fixture.store.state().get_calls, before_gets + 1);
}

#[test]
fn source_loading_stops_at_the_first_aggregate_byte_overflow() {
    let fixture = Fixture::new();
    let template = fixture
        .store
        .get(&fixture.source)
        .expect("store")
        .expect("source record");
    let source_ids: Vec<_> = (0..3)
        .map(|index| MemoryId::from_string(format!("mem-large-{index}")))
        .collect();
    for id in &source_ids {
        let mut record = template.clone();
        record.id = id.clone();
        record.content.text = "x".repeat(MAX_COGNITION_SOURCE_BYTES / 2);
        fixture.store.put(record).expect("large source");
    }

    let read = mint::<CanRead>(&fixture.policy, &fixture.space, &fixture.context);
    let before = fixture.store.state().get_calls;
    assert!(matches!(
        fixture.vault.cognition_source_manifest(
            &fixture.space,
            &read,
            &source_ids,
            &fixture.context
        ),
        Err(MemoryError::Cognition(CognitionApplyError::LimitExceeded(
            "source bytes"
        )))
    ));
    assert_eq!(fixture.store.state().get_calls - before, 2);
}

#[derive(Clone, Copy, Debug)]
enum SourcePayload {
    Metadata,
    Entity,
    Provenance,
}

fn assert_authorized_record_boundary(payload: SourcePayload) {
    let fixture = Fixture::new();
    let mut record = fixture.store.state().records[&fixture.source].clone();
    set_source_payload(&mut record, payload, String::new());
    let base = authorized_projection_bytes(&record);
    let padding = MAX_COGNITION_SOURCE_BYTES
        .checked_sub(base)
        .expect("fixture projection fits source budget");

    set_source_payload(&mut record, payload, "x".repeat(padding));
    assert_eq!(
        authorized_projection_bytes(&record),
        MAX_COGNITION_SOURCE_BYTES,
        "exact {payload:?} projection envelope"
    );
    let mut exact = CognitionSourceBudget::new();
    assert!(exact.try_add_record(&record).is_ok());

    set_source_payload(&mut record, payload, "x".repeat(padding + 1));
    assert_eq!(
        authorized_projection_bytes(&record),
        MAX_COGNITION_SOURCE_BYTES + 1,
        "over-limit {payload:?} projection envelope"
    );
    let mut over = CognitionSourceBudget::new();
    assert!(matches!(
        over.try_add_record(&record),
        Err(CognitionApplyError::LimitExceeded("source bytes"))
    ));
}

fn set_source_payload(record: &mut StoredRecord, payload: SourcePayload, value: String) {
    match payload {
        SourcePayload::Metadata => {
            record
                .content
                .attributes
                .insert("padding".into(), serde_json::Value::String(value));
        }
        SourcePayload::Entity => {
            record.entities = vec![crate::EntityRef::new(value, "test")];
        }
        SourcePayload::Provenance => {
            record.provenance = Provenance::GuardedTool {
                tool: value,
                call_id: None,
            };
        }
    }
}

fn authorized_projection_bytes(record: &StoredRecord) -> usize {
    super::super::limits::authorized_source_projection_bytes(record)
        .expect("authorized projection serialization")
}
