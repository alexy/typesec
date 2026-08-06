use typesec_memory::{CognitionCommitStatus, CognitionEffect};

use super::support::Fixture;

#[test]
fn proposal_free_recovery_preserves_no_change_effect() {
    let fixture = Fixture::new_no_change();

    let first = fixture.recover().expect("recover no-change outcome");
    let second = fixture.recover().expect("repeat no-change recovery");

    assert_eq!(first, second);
    assert_eq!(first.status, CognitionCommitStatus::AlreadyApplied);
    assert_eq!(first.effect, CognitionEffect::NoChange);
    assert_eq!(first.audit.effect, CognitionEffect::NoChange);
    assert!(first.affected_ids.is_empty());
    assert_eq!(first.prior_version, first.resulting_version);
    assert_eq!(fixture.store.counts().0, 1, "recovery must not reapply");
    assert_eq!(fixture.authority_calls(), 1);
}
