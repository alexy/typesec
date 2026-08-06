use super::*;

#[test]
fn every_serialized_proposal_requires_an_explicit_effect() {
    let fixture = Fixture::new();
    let bound_v4 = fixture.no_change_proposal();
    let unbound_v1 = CognitionProposal::new(
        "job-construction-only",
        digest("snapshot"),
        digest("source manifest"),
        "marciana.test",
        "1",
        vec![MemoryId::from_string("mem-source")],
        Label::Internal,
    );

    for proposal in [unbound_v1, bound_v4] {
        let mut encoded = serde_json::to_value(proposal).unwrap();
        encoded.as_object_mut().unwrap().remove("effect");
        assert!(matches!(
            CognitionProposal::from_json_slice(&serde_json::to_vec(&encoded).unwrap()),
            Err(CognitionApplyError::Serialization(message))
                if message == "invalid proposal JSON"
        ));
    }
}

#[test]
fn bound_v1_v2_and_v3_wires_are_never_reinterpreted() {
    let fixture = Fixture::new();
    for schema in [1, 2, 3] {
        let mut encoded = serde_json::to_value(fixture.no_change_proposal()).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("schema_version".into(), serde_json::json!(schema));

        assert!(matches!(
            CognitionProposal::from_json_slice(&serde_json::to_vec(&encoded).unwrap()),
            Err(CognitionApplyError::UnsupportedSchema(found)) if found == schema
        ));
    }
}

#[test]
fn unbound_v1_is_a_construction_state_not_a_supported_wire() {
    let proposal = CognitionProposal::new(
        "job-construction-only",
        digest("snapshot"),
        digest("source manifest"),
        "marciana.test",
        "1",
        vec![MemoryId::from_string("mem-source")],
        Label::Internal,
    );
    let encoded = serde_json::to_vec(&proposal).unwrap();

    assert!(matches!(
        CognitionProposal::from_json_slice(&encoded),
        Err(CognitionApplyError::UnsupportedSchema(1))
    ));
    assert!(proposal.canonical_digest().is_ok());
}
