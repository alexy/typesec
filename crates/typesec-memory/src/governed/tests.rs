use super::*;
use crate::{MemoryContent, MemoryKind, Provenance};

fn scope(hex: char) -> String {
    format!("sha256:{}", hex.to_string().repeat(64))
}

#[test]
fn scope_accepts_only_canonical_lowercase_sha256() {
    let canonical = scope('a');
    let parsed = GovernedSourceScope::from_digest(canonical.clone()).unwrap();
    assert_eq!(parsed.as_str(), canonical);
    assert_eq!(
        serde_json::from_str::<GovernedSourceScope>(&format!("\"{canonical}\"")).unwrap(),
        parsed
    );

    for invalid in [
        "sha256:abc".to_owned(),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{} ", "a".repeat(64)),
    ] {
        assert!(GovernedSourceScope::from_digest(&invalid).is_err());
        assert!(serde_json::from_str::<GovernedSourceScope>(&format!("\"{invalid}\"")).is_err());
    }
}

#[test]
fn draft_digest_is_stable_and_binds_the_exact_draft() {
    let draft = MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("governed fact"),
        Provenance::Operator,
    );
    let first = governed_source_draft_digest(&draft).unwrap();
    assert_eq!(governed_source_draft_digest(&draft).unwrap(), first);

    let changed = MemoryDraft::new(
        MemoryKind::Semantic,
        MemoryContent::text("different fact"),
        Provenance::Operator,
    );
    assert_ne!(governed_source_draft_digest(&changed).unwrap(), first);
    assert!(is_canonical_sha256(&first));
}
