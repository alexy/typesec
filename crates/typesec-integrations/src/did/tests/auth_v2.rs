use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::super::auth::{TranscriptKind, canonical_transcript};
use super::super::crypto::unix_time;
use super::super::*;
use super::common::ed25519_fixture;

#[test]
fn adding_a_claim_breaks_authentication() {
    let (mut envelope, agent, resolver, keys) = signed_claim_envelope();
    envelope.body.claims.insert("role".into(), "admin".into());
    assert_invalid_signature(&envelope, agent, resolver, keys);
}

#[test]
fn removing_a_claim_breaks_authentication() {
    let (mut envelope, agent, resolver, keys) = signed_claim_envelope();
    envelope.body.claims.remove("purpose");
    assert_invalid_signature(&envelope, agent, resolver, keys);
}

#[test]
fn changing_a_claim_breaks_authentication() {
    let (mut envelope, agent, resolver, keys) = signed_claim_envelope();
    envelope
        .body
        .claims
        .insert("purpose".into(), "marketing".into());
    assert_invalid_signature(&envelope, agent, resolver, keys);
}

#[test]
fn claim_order_is_canonical() {
    let mut left = golden_envelope();
    left.body.claims.clear();
    left.body.claims.insert("zeta".into(), "last".into());
    left.body.claims.insert("alpha".into(), "first".into());
    let mut right = golden_envelope();
    right.body.claims.clear();
    right.body.claims.insert("alpha".into(), "first".into());
    right.body.claims.insert("zeta".into(), "last".into());
    assert_eq!(
        canonical_transcript(&left, TranscriptKind::Header),
        canonical_transcript(&right, TranscriptKind::Header)
    );
}

#[test]
fn length_framing_disambiguates_delimiters() {
    let mut left = golden_envelope();
    let mut right = golden_envelope();
    left.id = "field-one\nfield-two".into();
    left.message_type = "field-three".into();
    right.id = "field-one".into();
    right.message_type = "field-two\nfield-three".into();
    assert_ne!(
        canonical_transcript(&left, TranscriptKind::Header),
        canonical_transcript(&right, TranscriptKind::Header),
        "length framing must distinguish values that collide under newline joining"
    );
}

#[test]
fn missing_legacy_auth_version_fails_closed() {
    let (envelope, agent, resolver, keys) = versioned_prompt();
    let mut legacy_json = serde_json::to_value(&envelope).expect("serialize envelope");
    legacy_json
        .as_object_mut()
        .expect("envelope object")
        .remove("authVersion");
    let legacy: DidEnvelope = serde_json::from_value(legacy_json).expect("parse legacy envelope");
    assert!(matches!(
        prompt_gateway(agent, resolver, keys).open_prompt(&legacy),
        Err(DidError::MissingEnvelopeAuthVersion)
    ));
}

#[test]
fn authentication_version_downgrade_fails_closed() {
    let (mut envelope, agent, resolver, keys) = versioned_prompt();
    envelope.auth_version = "typesec.did-envelope-auth.v1".into();
    assert!(matches!(
        prompt_gateway(agent, resolver, keys).open_prompt(&envelope),
        Err(DidError::UnsupportedEnvelopeAuthVersion(version))
            if version == "typesec.did-envelope-auth.v1"
    ));
}

#[test]
fn unknown_authentication_version_fails_closed() {
    let (mut envelope, agent, resolver, keys) = versioned_prompt();
    envelope.auth_version = "typesec.did-envelope-auth.v3".into();
    assert!(matches!(
        prompt_gateway(agent, resolver, keys).open_prompt(&envelope),
        Err(DidError::UnsupportedEnvelopeAuthVersion(version))
            if version == "typesec.did-envelope-auth.v3"
    ));
}

#[test]
fn verified_context_exposes_only_authenticated_policy_metadata() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::typedid(
        "verified-accessors",
        alice.clone(),
        agent.clone(),
        DidMessageBody::agent_delegate("memory/acme/research", "sensitive")
            .with_claim("purpose", "research"),
        conversation(unix_time() + 120),
        b"secret request body",
        &resolver,
        &keys,
    )
    .expect("seal accessor fixture");
    let verified = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent)
        .open_message(&envelope)
        .expect("open accessor fixture");
    let context = verified.verified_context();
    assert_eq!(context.subject(), &alice);
    assert_eq!(context.action(), "agent:delegate");
    assert_eq!(context.resource(), "memory/acme/research");
    assert_eq!(context.privacy(), "sensitive");
    assert_eq!(context.purpose(), Some("research"));
    assert_eq!(context.request_digest(), envelope.reference().digest);
    assert!(is_canonical_sha256(context.request_digest()));
    assert_eq!(
        context.effective_expires_at(),
        verified.effective_expires_at()
    );

    let serialized = serde_json::to_string(&context.attestation()).expect("serialize attestation");
    assert!(!serialized.contains("secret request body"));
    assert!(!serialized.contains(&envelope.signature));
}

#[test]
fn expired_conversation_is_rejected() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let expired = DidEnvelope::typedid(
        "expired-conversation",
        alice,
        agent.clone(),
        DidMessageBody::agent_message("room/expired", "internal"),
        conversation(unix_time().saturating_sub(1)),
        b"payload",
        &resolver,
        &keys,
    )
    .expect("seal expired conversation");
    assert!(matches!(
        TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent).open_message(&expired),
        Err(DidError::Expired)
    ));
}

#[test]
fn effective_expiry_uses_earliest_authenticated_bound() {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let conversation_expiry = unix_time() + 90;
    let bounded = DidEnvelope::typedid(
        "bounded-conversation",
        alice.clone(),
        agent.clone(),
        DidMessageBody::agent_message("room/bounded", "internal"),
        conversation(conversation_expiry),
        b"payload",
        &resolver,
        &keys,
    )
    .expect("seal bounded conversation");
    let expected = conversation_expiry.min(bounded.expires_time);
    let verified = TypeDidGateway::new(
        Arc::new(resolver.clone()),
        Arc::new(keys.clone()),
        agent.clone(),
    )
    .open_message(&bounded)
    .expect("open bounded conversation");
    assert_eq!(verified.effective_expires_at(), expected);
    assert_eq!(verified.verified_context().effective_expires_at(), expected);
    assert_eq!(verified.attestation().expires_at, Some(expected));

    let outer_bounded = DidEnvelope::typedid(
        "outer-bounded-conversation",
        alice,
        agent.clone(),
        DidMessageBody::agent_message("room/outer-bounded", "internal"),
        conversation(unix_time() + 600),
        b"payload",
        &resolver,
        &keys,
    )
    .expect("seal outer-bounded conversation");
    let verified = TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), agent)
        .open_message(&outer_bounded)
        .expect("open outer-bounded conversation");
    assert_eq!(verified.effective_expires_at(), outer_bounded.expires_time);
    assert_eq!(
        verified.verified_context().effective_expires_at(),
        outer_bounded.expires_time
    );
    assert_eq!(
        verified.attestation().expires_at,
        Some(outer_bounded.expires_time)
    );
}

#[test]
fn canonical_transcript_and_reference_match_golden_fixture() {
    let fixture: GoldenFixture = serde_json::from_str(include_str!(
        "../../../tests/fixtures/did-envelope-auth-v2.json"
    ))
    .expect("parse golden envelope fixture");
    assert_eq!(
        sha256(&canonical_transcript(
            &fixture.envelope,
            TranscriptKind::Header
        )),
        fixture.authenticated_header_sha256
    );
    assert_eq!(
        sha256(&canonical_transcript(
            &fixture.envelope,
            TranscriptKind::Signature
        )),
        fixture.signature_transcript_sha256
    );
    let reference = fixture.envelope.reference();
    assert_eq!(reference.id, fixture.reference_id);
    assert_eq!(reference.digest, fixture.reference_digest);
    assert!(is_canonical_sha256(&reference.digest));
}

fn signed_claim_envelope() -> (DidEnvelope, Did, StaticDidResolver, Ed25519DidKeyStore) {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::typedid(
        "claim-tamper",
        alice,
        agent.clone(),
        DidMessageBody::agent_delegate("memory/acme/research", "sensitive")
            .with_claim("org", "acme")
            .with_claim("purpose", "research"),
        conversation(unix_time() + 120),
        b"protected request",
        &resolver,
        &keys,
    )
    .expect("seal claims");
    (envelope, agent, resolver, keys)
}

fn assert_invalid_signature(
    envelope: &DidEnvelope,
    recipient: Did,
    resolver: StaticDidResolver,
    keys: Ed25519DidKeyStore,
) {
    assert!(matches!(
        TypeDidGateway::new(Arc::new(resolver), Arc::new(keys), recipient).open_message(envelope),
        Err(DidError::InvalidSignature)
    ));
}

fn versioned_prompt() -> (DidEnvelope, Did, StaticDidResolver, Ed25519DidKeyStore) {
    let (alice, agent, resolver, keys) = ed25519_fixture();
    let envelope = DidEnvelope::prompt(
        "auth-version",
        alice,
        agent.clone(),
        DidMessageBody::infer_prompt("prompt/auth-version"),
        b"payload",
        &resolver,
        &keys,
    )
    .expect("seal versioned envelope");
    (envelope, agent, resolver, keys)
}

fn prompt_gateway(
    recipient: Did,
    resolver: StaticDidResolver,
    keys: Ed25519DidKeyStore,
) -> DidMessageGateway {
    DidMessageGateway::new(Arc::new(resolver), Arc::new(keys), recipient)
}

fn conversation(expires_at: u64) -> TypeDidConversation {
    TypeDidConversation::new(
        "conversation/auth-v2",
        TypeDidMode::RequestReply,
        TypeDidProfile::ed25519_x25519_chacha20().id,
        "a2a",
    )
    .with_expires_at(expires_at)
}

fn golden_envelope() -> DidEnvelope {
    serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../tests/fixtures/did-envelope-auth-v2.json"
        ))
        .expect("parse golden JSON")["envelope"]
            .clone(),
    )
    .expect("parse golden envelope")
}

fn sha256(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenFixture {
    envelope: DidEnvelope,
    authenticated_header_sha256: String,
    signature_transcript_sha256: String,
    reference_id: String,
    reference_digest: String,
}
