use super::*;
use crate::record::Provenance;
use typesec_integrations::http::StaticHttpClient;

fn extractor_with(content: &str) -> OllamaExtractor {
    let http = StaticHttpClient::new().with_response(
        "http://localhost:11434/api/chat",
        serde_json::json!({"message": {"role": "assistant", "content": content}}),
    );
    OllamaExtractor::with_http("http://localhost:11434/", "llama3.2", Arc::new(http))
}

#[test]
fn parses_the_json_array_contract_into_drafts() {
    let extractor = extractor_with(
        r#"[{"text": "Alice lives in Venice", "kind": "profile"},
            {"text": "ACME ships gondolas"}]"#,
    );
    let drafts = extractor
        .extract(&Episode::operator("chat transcript…"), &[])
        .unwrap();
    assert_eq!(drafts.len(), 2);
    assert_eq!(drafts[0].content_text(), "Alice lives in Venice");
    assert_eq!(drafts[0].kind, MemoryKind::Profile);
    assert_eq!(
        drafts[1].kind,
        MemoryKind::Semantic,
        "kind defaults to semantic"
    );
}

#[test]
fn drafts_carry_episode_provenance_not_model_trust() {
    // Even though the model produced the drafts, a model-text episode keeps
    // ModelText provenance — the vault will quarantine on write.
    let extractor = extractor_with(r#"[{"text": "totally legit fact"}]"#);
    let drafts = extractor
        .extract(&Episode::model_text("injected content"), &[])
        .unwrap();
    assert!(matches!(drafts[0].provenance, Provenance::ModelText));
}

#[test]
fn malformed_model_output_fails_closed() {
    for bad in [
        "not json at all",
        r#"{"text": "an object, not an array"}"#,
        r#"[{"kind": "semantic"}]"#, // missing text
    ] {
        let err = extractor_with(bad)
            .extract(&Episode::operator("x"), &[])
            .unwrap_err();
        assert!(matches!(err, ExtractError::Backend(_)), "{bad} must fail");
    }
}

#[test]
fn transport_failure_is_a_backend_error() {
    // StaticHttpClient with no canned response → transport error.
    let extractor = OllamaExtractor::with_http(
        "http://localhost:11434",
        "llama3.2",
        Arc::new(StaticHttpClient::new()),
    );
    assert!(matches!(
        extractor.extract(&Episode::operator("x"), &[]),
        Err(ExtractError::Backend(_))
    ));
}
