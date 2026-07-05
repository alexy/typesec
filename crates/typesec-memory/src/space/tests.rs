use super::*;

#[test]
fn resource_id_scheme_supports_glob_policies() {
    let space = MemorySpace::new("user:alice", "profile");
    assert_eq!(space.resource_id(), "memory/user:alice/profile");
    assert_eq!(space.owner().as_str(), "user:alice");
    assert_eq!(space.space(), "profile");
    assert_eq!(MemorySpace::resource_type(), "MemorySpace");

    let id = MemoryId::from_string("mem-42");
    assert_eq!(
        space.record_resource_id(&id),
        "memory/user:alice/profile/mem-42"
    );
}

#[test]
fn memory_ids_are_unique_and_monotonic() {
    let a = MemoryId::next();
    let b = MemoryId::next();
    assert_ne!(a, b);
    assert!(a.as_str().starts_with("mem-"));
}
