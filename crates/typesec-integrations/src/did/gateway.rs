//! Envelope-verifying gateways and the verified-message/attestation types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use typesec_core::{SecureValue, resource::GenericResource, secure_value::Secret};

use super::auth::DID_ENVELOPE_AUTH_V2;
use super::crypto::{hex_decode, unix_time};
use super::document::DidResolver;
use super::envelope::{
    DidEnvelope, DidMessageBody, DidMessageReference, PROMPT_MESSAGE_TYPE, REPLY_MESSAGE_TYPE,
    TYPEDID_MESSAGE_TYPE,
};
use super::error::DidError;
use super::identifier::Did;
use super::keystore::DidKeyStore;
use super::replay::{InMemoryReplayStore, ReplayStore};
use super::typedid::{TypeDidConversation, TypeDidMode};

/// Verified and decrypted TypeDID agent message.
///
/// Only [`TypeDidGateway::open_message`] can construct this provenance type.
/// Its private fields prevent downstream crates from laundering caller-created
/// metadata into a [`crate::VerifiedTypeDidContext`].
///
/// ```compile_fail,E0451
/// use typesec_integrations::{VerifiedTypeDidMessage, Did};
///
/// let _forged = VerifiedTypeDidMessage {
///     subject: Did::parse("did:web:forged.example").unwrap(),
///     message_ref: unimplemented!(),
///     body: unimplemented!(),
///     conversation: unimplemented!(),
///     resource: unimplemented!(),
///     payload: unimplemented!(),
///     effective_expires_at: u64::MAX,
/// };
/// ```
#[derive(Debug)]
pub struct VerifiedTypeDidMessage {
    /// Verified DID subject.
    subject: Did,
    /// Stable reference to the verified envelope.
    message_ref: DidMessageReference,
    /// Policy-visible message metadata.
    body: DidMessageBody,
    /// TypeDID conversation/profile metadata.
    conversation: TypeDidConversation,
    /// Resource associated with the payload.
    resource: GenericResource,
    /// Secret opaque payload bytes.
    payload: SecureValue<Secret, Vec<u8>, GenericResource>,
    /// Minimum of the authenticated outer and conversation expiries.
    effective_expires_at: u64,
}

/// Policy/audit-safe attestation derived from a verified TypeDID message.
///
/// This contains no plaintext payload and no raw signature material. It is the
/// compact boundary object downstream systems can persist after a
/// [`TypeDidGateway`] has verified the envelope signature, recipient, expiry,
/// conversation metadata, and payload authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDidAttestation {
    /// Verified sender DID.
    pub subject: Did,
    /// Stable signed envelope id.
    pub envelope_id: String,
    /// SHA-256 digest of the signed envelope reference.
    pub envelope_digest: String,
    /// Policy-visible requested action.
    pub action: String,
    /// Policy-visible requested resource.
    pub resource: String,
    /// Policy-visible privacy class.
    pub privacy: String,
    /// Signed, policy-visible claims required by the negotiated profile.
    /// These may include purpose, organization, and agent identity, but never
    /// payload plaintext or raw signature material.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
    /// TypeDID conversation id.
    pub conversation_id: String,
    /// TypeDID transport/protocol family.
    pub protocol: String,
    /// TypeDID delivery mode.
    pub mode: TypeDidMode,
    /// Negotiated TypeDID crypto/profile id.
    pub profile: String,
    /// Effective verified expiry: the minimum of outer-envelope and optional
    /// conversation expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl VerifiedTypeDidMessage {
    /// Cryptographically verified sender DID.
    pub fn subject(&self) -> &Did {
        &self.subject
    }

    /// Stable reference to the authenticated envelope.
    pub fn message_ref(&self) -> &DidMessageReference {
        &self.message_ref
    }

    /// Authenticated, policy-visible action, resource, privacy, and claims.
    pub fn body(&self) -> &DidMessageBody {
        &self.body
    }

    /// Authenticated TypeDID conversation/profile metadata.
    pub fn conversation(&self) -> &TypeDidConversation {
        &self.conversation
    }

    /// Runtime resource protecting the opaque payload.
    pub fn resource(&self) -> &GenericResource {
        &self.resource
    }

    /// Capability-protected opaque payload.
    pub fn payload(&self) -> &SecureValue<Secret, Vec<u8>, GenericResource> {
        &self.payload
    }

    /// Minimum authenticated expiry for this verified message.
    pub fn effective_expires_at(&self) -> u64 {
        self.effective_expires_at
    }

    /// Return an audit-safe attestation for this verified message.
    pub fn attestation(&self) -> TypeDidAttestation {
        TypeDidAttestation {
            subject: self.subject.clone(),
            envelope_id: self.message_ref.id.clone(),
            envelope_digest: self.message_ref.digest.clone(),
            action: self.body.action.clone(),
            resource: self.body.resource.clone(),
            privacy: self.body.privacy.clone(),
            claims: self.body.claims.clone(),
            conversation_id: self.conversation.conversation_id.clone(),
            protocol: self.conversation.protocol.clone(),
            mode: self.conversation.mode,
            profile: self.conversation.profile.clone(),
            expires_at: Some(self.effective_expires_at),
        }
    }
}

/// Verified and decrypted DID prompt.
///
/// ```compile_fail,E0451
/// use typesec_integrations::{VerifiedDidPrompt, Did};
///
/// let _forged = VerifiedDidPrompt {
///     subject: Did::parse("did:web:forged.example").unwrap(),
///     prompt_ref: unimplemented!(),
///     body: unimplemented!(),
///     resource: unimplemented!(),
///     prompt: unimplemented!(),
///     effective_expires_at: u64::MAX,
/// };
/// ```
#[derive(Debug)]
pub struct VerifiedDidPrompt {
    /// Verified DID subject.
    subject: Did,
    /// Stable reference to the verified prompt envelope.
    prompt_ref: DidMessageReference,
    /// Policy-visible metadata.
    body: DidMessageBody,
    /// Resource associated with the payload.
    resource: GenericResource,
    /// Secret prompt payload.
    prompt: SecureValue<Secret, String, GenericResource>,
    effective_expires_at: u64,
}

impl VerifiedDidPrompt {
    /// Cryptographically verified sender DID.
    pub fn subject(&self) -> &Did {
        &self.subject
    }

    /// Stable reference to the authenticated prompt envelope.
    pub fn prompt_ref(&self) -> &DidMessageReference {
        &self.prompt_ref
    }

    /// Authenticated policy-visible prompt metadata.
    pub fn body(&self) -> &DidMessageBody {
        &self.body
    }

    /// Runtime resource protecting the prompt.
    pub fn resource(&self) -> &GenericResource {
        &self.resource
    }

    /// Capability-protected prompt plaintext.
    pub fn prompt(&self) -> &SecureValue<Secret, String, GenericResource> {
        &self.prompt
    }

    /// Authenticated outer-envelope expiry.
    pub fn effective_expires_at(&self) -> u64 {
        self.effective_expires_at
    }
}

/// Tolerated clock skew (seconds) for an envelope dated in the future.
const CLOCK_SKEW_SECS: u64 = 300;

const DID_MESSAGE_TYPES: &[&str] = &[PROMPT_MESSAGE_TYPE, REPLY_MESSAGE_TYPE];
const TYPEDID_MESSAGE_TYPES: &[&str] = &[TYPEDID_MESSAGE_TYPE];

fn validate_message_type(
    envelope: &DidEnvelope,
    expected: &'static str,
    accepted: &[&str],
) -> Result<(), DidError> {
    if accepted.contains(&envelope.message_type.as_str()) {
        Ok(())
    } else {
        Err(DidError::UnexpectedMessageType {
            expected,
            actual: envelope.message_type.clone(),
        })
    }
}

fn validate_did_message(envelope: &DidEnvelope) -> Result<(), DidError> {
    validate_message_type(envelope, "prompt or reply", DID_MESSAGE_TYPES)
}

fn validate_typedid_message(envelope: &DidEnvelope) -> Result<TypeDidConversation, DidError> {
    validate_message_type(envelope, "TypeDID", TYPEDID_MESSAGE_TYPES)?;
    envelope
        .typedid
        .clone()
        .ok_or(DidError::MissingTypeDidMetadata)
}

/// Verifies DID envelopes and converts encrypted payloads into `SecureValue`s.
pub struct DidMessageGateway {
    resolver: Arc<dyn DidResolver>,
    key_store: Arc<dyn DidKeyStore>,
    recipient: Did,
    replay_store: Arc<dyn ReplayStore>,
}

impl DidMessageGateway {
    /// Create a gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            resolver,
            key_store,
            recipient,
            replay_store: Arc::new(InMemoryReplayStore::new()),
        }
    }

    /// Use a shared replay authority. Production replicas should inject a
    /// durable, strongly consistent implementation.
    #[must_use]
    pub fn with_replay_store(mut self, replay_store: Arc<dyn ReplayStore>) -> Self {
        self.replay_store = replay_store;
        self
    }

    /// Reject an envelope already opened within its validity window (replay).
    /// Call only after the signature has verified, so the cache holds only
    /// authentic envelopes.
    fn guard_replay(
        &self,
        envelope: &DidEnvelope,
        effective_expires_at: u64,
        now: u64,
    ) -> Result<(), DidError> {
        let claimed = self
            .replay_store
            .claim(&envelope.signature, effective_expires_at, now)
            .map_err(DidError::ReplayStore)?;
        if !claimed {
            return Err(DidError::Replayed(envelope.id.clone()));
        }
        Ok(())
    }

    /// Verify, decrypt, and protect a DID prompt envelope.
    pub fn open_prompt(&self, envelope: &DidEnvelope) -> Result<VerifiedDidPrompt, DidError> {
        let (opened, ()) = self.open_bytes(envelope, validate_did_message)?;
        let prompt = String::from_utf8(opened.plaintext).map_err(|_| DidError::InvalidUtf8)?;
        Ok(VerifiedDidPrompt {
            subject: opened.subject,
            prompt_ref: opened.message_ref,
            body: opened.body,
            prompt: SecureValue::protect(prompt, &opened.resource),
            resource: opened.resource,
            effective_expires_at: opened.effective_expires_at,
        })
    }

    fn open_bytes<T>(
        &self,
        envelope: &DidEnvelope,
        validate_semantics: impl FnOnce(&DidEnvelope) -> Result<T, DidError>,
    ) -> Result<(OpenedDidEnvelope, T), DidError> {
        match envelope.auth_version.as_str() {
            "" => return Err(DidError::MissingEnvelopeAuthVersion),
            DID_ENVELOPE_AUTH_V2 => {}
            other => {
                return Err(DidError::UnsupportedEnvelopeAuthVersion(other.to_owned()));
            }
        }
        if !envelope.to.iter().any(|did| did == &self.recipient) {
            return Err(DidError::WrongRecipient(self.recipient.to_string()));
        }
        let now = unix_time();
        let effective_expires_at = envelope.effective_expires_at();
        if effective_expires_at <= now {
            return Err(DidError::Expired);
        }
        // Reject envelopes dated implausibly far in the future (clock skew or a
        // forged timestamp), which bounds the replay window from both ends.
        if envelope.created_time > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(DidError::NotYetValid {
                created: envelope.created_time,
                now,
            });
        }

        let sender_document = self.resolver.resolve(&envelope.from)?;
        let sender_key = sender_document.authentication_key(&envelope.kid)?;
        self.key_store
            .verify(sender_key, &envelope.signing_input(), &envelope.signature)?;
        // Semantic routing is meaningful only after `message_type` has been
        // authenticated. Reject cross-protocol envelopes before key agreement,
        // decryption, or replay-store consumption.
        let semantics = validate_semantics(envelope)?;

        // Decryption uses the sender's *key-agreement* key, which may be a
        // different key (X25519) than the authentication key (Ed25519). During
        // key rotation, older in-flight envelopes may have used a previous
        // sender agreement key, so try every non-retired key advertised by the
        // sender document.
        let sender_agreement_keys = sender_document.key_agreement_keys()?;
        let nonce = hex_decode(&envelope.nonce)?;
        let aad = envelope.associated_data();
        let mut plaintext = None;
        for sender_agreement_key in sender_agreement_keys {
            match self.key_store.decrypt_for(
                &self.recipient,
                &sender_agreement_key.public_key()?,
                &nonce,
                &envelope.ciphertext,
                &aad,
            ) {
                Ok(opened) => {
                    plaintext = Some(opened);
                    break;
                }
                Err(DidError::DecryptionFailed) => {}
                Err(err) => return Err(err),
            }
        }
        let plaintext = plaintext.ok_or(DidError::DecryptionFailed)?;
        // Consume the replay claim only after the authenticated ciphertext has
        // decrypted successfully. A valid signature over an undecryptable
        // envelope must not poison a later delivery attempt.
        self.guard_replay(envelope, effective_expires_at, now)?;
        let resource = GenericResource::new(&envelope.body.resource, "did-prompt");

        Ok((
            OpenedDidEnvelope {
                subject: envelope.from.clone(),
                message_ref: envelope.reference(),
                body: envelope.body.clone(),
                resource,
                plaintext,
                effective_expires_at,
            },
            semantics,
        ))
    }
}

#[derive(Debug)]
pub(super) struct OpenedDidEnvelope {
    pub(super) subject: Did,
    pub(super) message_ref: DidMessageReference,
    pub(super) body: DidMessageBody,
    pub(super) resource: GenericResource,
    pub(super) plaintext: Vec<u8>,
    pub(super) effective_expires_at: u64,
}

/// Verifies TypeDID envelopes and protects arbitrary agent payload bytes.
pub struct TypeDidGateway {
    inner: DidMessageGateway,
}

impl TypeDidGateway {
    /// Create a TypeDID gateway for one local recipient DID.
    pub fn new(
        resolver: Arc<dyn DidResolver>,
        key_store: Arc<dyn DidKeyStore>,
        recipient: Did,
    ) -> Self {
        Self {
            inner: DidMessageGateway::new(resolver, key_store, recipient),
        }
    }

    /// Use a shared replay authority for this TypeDID gateway.
    #[must_use]
    pub fn with_replay_store(mut self, replay_store: Arc<dyn ReplayStore>) -> Self {
        self.inner = self.inner.with_replay_store(replay_store);
        self
    }

    /// Verify, decrypt, and protect a TypeDID message envelope.
    pub fn open_message(&self, envelope: &DidEnvelope) -> Result<VerifiedTypeDidMessage, DidError> {
        let (opened, conversation) = self.inner.open_bytes(envelope, validate_typedid_message)?;
        Ok(VerifiedTypeDidMessage {
            subject: opened.subject,
            message_ref: opened.message_ref,
            body: opened.body,
            conversation,
            payload: SecureValue::protect(opened.plaintext, &opened.resource),
            resource: opened.resource,
            effective_expires_at: opened.effective_expires_at,
        })
    }
}
