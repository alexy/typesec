use std::sync::Arc;

use super::super::envelope::{PROMPT_MESSAGE_TYPE, TYPEDID_MESSAGE_TYPE};
use super::super::*;
use super::common::ed25519_fixture;

#[test]
fn did_gateway_rejects_a_signed_typedid_envelope_without_consuming_replay() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::typedid(
        "cross-protocol-typedid",
        alice,
        agent.clone(),
        DidMessageBody::agent_message("room/cross-protocol", "internal"),
        TypeDidConversation::new(
            "conversation/cross-protocol",
            TypeDidMode::Send,
            TypeDidProfile::ed25519_x25519_chacha20().id,
            "a2a",
        ),
        [0xff],
        &resolver,
        &keys,
    )
    .expect("seal signed TypeDID envelope");
    let replay_store: Arc<dyn ReplayStore> = Arc::new(InMemoryReplayStore::new());

    let mut invalid_signature = envelope.clone();
    invalid_signature.signature = "00".into();
    assert!(matches!(
        DidMessageGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        )
        .with_replay_store(Arc::clone(&replay_store))
        .open_prompt(&invalid_signature),
        Err(DidError::InvalidSignature)
    ));

    assert!(matches!(
        DidMessageGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        )
        .with_replay_store(Arc::clone(&replay_store))
        .open_prompt(&envelope),
        Err(DidError::UnexpectedMessageType { expected, actual })
            if expected == "prompt or reply" && actual == TYPEDID_MESSAGE_TYPE
    ));

    TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent)
        .with_replay_store(replay_store)
        .open_message(&envelope)
        .expect("cross-protocol rejection must not consume the replay claim");
}

#[test]
fn typedid_gateway_rejects_a_signed_prompt_without_consuming_replay() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::prompt(
        "cross-protocol-prompt",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/cross-protocol"),
        b"signed prompt",
        &resolver,
        &keys,
    )
    .expect("seal signed prompt envelope");
    let replay_store: Arc<dyn ReplayStore> = Arc::new(InMemoryReplayStore::new());

    assert!(matches!(
        TypeDidGateway::new(
            Arc::new(resolver.clone()),
            Arc::new(keys.clone()),
            agent.clone(),
        )
        .with_replay_store(Arc::clone(&replay_store))
        .open_message(&envelope),
        Err(DidError::UnexpectedMessageType { expected, actual })
            if expected == "TypeDID" && actual == PROMPT_MESSAGE_TYPE
    ));

    DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), agent)
        .with_replay_store(replay_store)
        .open_prompt(&envelope)
        .expect("cross-protocol rejection must not consume the replay claim");
}
