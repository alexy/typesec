use std::sync::Arc;

use super::super::crypto::unix_time;
use super::super::*;
use super::common::ed25519_fixture;

#[test]
fn verified_context_borrows_the_authenticated_claim_map() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::typedid(
        "borrowed-claims",
        alice,
        agent.clone(),
        DidMessageBody::agent_delegate("memory/acme/research", "sensitive")
            .with_claim("org", "acme")
            .with_claim("purpose", "research"),
        TypeDidConversation::new(
            "conversation/borrowed-claims",
            TypeDidMode::RequestReply,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "a2a",
        )
        .with_expires_at(unix_time() + 120),
        b"protected request",
        &resolver,
        &keys,
    )
    .expect("seal claims fixture");
    let verified = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent)
        .open_message(&envelope)
        .expect("verify claims fixture");
    let context = verified.verified_context();

    assert!(std::ptr::eq(context.claims(), &verified.body().claims));
    assert_eq!(
        context
            .claims()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>(),
        [("org", "acme"), ("purpose", "research")]
    );
    assert_eq!(context.claim("purpose"), Some("research"));
}
