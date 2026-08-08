//! DID message bodies, references, and the encrypted envelope type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::auth::{
    DID_ENVELOPE_AUTH_V2, authenticated_header, reference_sha256, signature_transcript_from_header,
};
use super::crypto::{hex_encode, random_nonce, unix_time};
use super::document::DidResolver;
use super::error::DidError;
use super::gateway::{VerifiedDidPrompt, VerifiedTypeDidMessage};
use super::identifier::Did;
use super::keystore::DidKeyStore;
use super::typedid::{TypeDidConversation, TypeDidMode};

pub(super) const PROMPT_MESSAGE_TYPE: &str = "https://typesec.dev/did/message/v1/prompt";
pub(super) const REPLY_MESSAGE_TYPE: &str = "https://typesec.dev/did/message/v1/reply";
pub(super) const TYPEDID_MESSAGE_TYPE: &str = "https://typesec.dev/did/message/v1/typedid";

/// Message metadata that policy engines evaluate before payload use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageBody {
    /// Requested Typesec action, such as `ai:infer`.
    pub action: String,
    /// Resource identifier for policy evaluation.
    pub resource: String,
    /// Payload privacy label, such as `secret`.
    pub privacy: String,
    /// Verifiable or policy-visible claims required by the negotiated TypeDID
    /// profile. Values are application-defined; transports must not invent
    /// missing claims during negotiation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
    /// Prompt envelope this message is bound to, for reply envelopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<DidMessageReference>,
}

impl DidMessageBody {
    /// Create a prompt body for AI inference.
    pub fn infer_prompt(resource: impl Into<String>) -> Self {
        Self {
            action: "ai:infer".to_owned(),
            resource: resource.into(),
            privacy: "secret".to_owned(),
            claims: BTreeMap::new(),
            reply_to: None,
        }
    }

    /// Create a reply body that inherits the prompt's policy-visible metadata.
    pub fn reply_to_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            action: prompt.body().action.clone(),
            resource: prompt.body().resource.clone(),
            privacy: prompt.body().privacy.clone(),
            claims: prompt.body().claims.clone(),
            reply_to: Some(prompt.prompt_ref().clone()),
        }
    }

    /// Create a general agent message body.
    pub fn agent_message(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:message".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            claims: BTreeMap::new(),
            reply_to: None,
        }
    }

    /// Create an agent delegation body.
    pub fn agent_delegate(resource: impl Into<String>, privacy: impl Into<String>) -> Self {
        Self {
            action: "agent:delegate".to_owned(),
            resource: resource.into(),
            privacy: privacy.into(),
            claims: BTreeMap::new(),
            reply_to: None,
        }
    }

    /// Attach a claim for TypeDID profile-obligation validation.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }
}

/// The prompt context a reply envelope is bound to.
#[derive(Debug, Clone)]
pub struct DidReplyBinding {
    /// Policy-visible metadata of the prompt being answered.
    pub prompt_body: DidMessageBody,
    /// Stable reference to the signed prompt envelope.
    pub prompt_ref: DidMessageReference,
}

impl DidReplyBinding {
    /// Bind a reply to a verified prompt.
    pub fn for_prompt(prompt: &VerifiedDidPrompt) -> Self {
        Self {
            prompt_body: prompt.body().clone(),
            prompt_ref: prompt.prompt_ref().clone(),
        }
    }
}

/// Stable reference to a DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidMessageReference {
    /// Referenced DID message id.
    pub id: String,
    /// Canonical lowercase `sha256:<64 hex>` digest of the referenced signed
    /// envelope transcript.
    pub digest: String,
}

/// Encrypted DID message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidEnvelope {
    /// Versioned authentication transcript required to verify this envelope.
    /// Missing and unknown versions fail closed at every gateway.
    #[serde(rename = "authVersion", default)]
    pub auth_version: String,
    /// Message id.
    pub id: String,
    /// Message type URI.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Sender DID.
    pub from: Did,
    /// Recipient DIDs.
    pub to: Vec<Did>,
    /// Creation time as unix seconds.
    pub created_time: u64,
    /// Expiration time as unix seconds.
    pub expires_time: u64,
    /// Policy-visible message metadata.
    pub body: DidMessageBody,
    /// Optional TypeDID conversation/profile metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typedid: Option<TypeDidConversation>,
    /// Key id used for authentication.
    pub kid: String,
    /// Hex-encoded nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded signature over the envelope signing input.
    pub signature: String,
}

impl DidEnvelope {
    /// Resolve recipient/sender, encrypt, and sign one envelope.
    ///
    /// The single home for the prompt / reply / typedid construction path: it
    /// resolves the recipient's key-agreement key and the sender's authentication
    /// `kid`, builds the envelope with an empty ciphertext, computes the AEAD
    /// associated data over its routing/timing identity, then encrypts and signs.
    /// The four public constructors differ only in `id`, `message_type`, `body`,
    /// and whether a `typedid` conversation is attached.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        id: String,
        message_type: &str,
        from: Did,
        to: Did,
        body: DidMessageBody,
        typedid: Option<TypeDidConversation>,
        plaintext: &[u8],
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let now = unix_time();
        let recipient_document = resolver.resolve(&to)?;
        let recipient_public = recipient_document.key_agreement_key()?.public_key()?;
        let sender_document = resolver.resolve(&from)?;
        let kid = sender_document
            .authentication
            .first()
            .cloned()
            .ok_or(DidError::MissingAuthentication)?;
        let nonce = random_nonce()?;
        // Build the envelope first (empty ciphertext) so the AEAD can bind to its
        // routing/timing identity, then encrypt and sign.
        let mut envelope = Self {
            auth_version: DID_ENVELOPE_AUTH_V2.to_owned(),
            id,
            message_type: message_type.to_owned(),
            from,
            to: vec![to],
            created_time: now,
            expires_time: now + 300,
            body,
            typedid,
            kid,
            nonce: hex_encode(&nonce),
            ciphertext: String::new(),
            signature: String::new(),
        };
        let aad = envelope.associated_data();
        envelope.ciphertext =
            key_store.encrypt_for(&envelope.from, &recipient_public, plaintext, &nonce, &aad)?;
        envelope.signature =
            key_store.sign(&envelope.from, &envelope.signing_input_from_header(&aad))?;
        Ok(envelope)
    }

    /// Create an encrypted prompt envelope.
    pub fn prompt(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        Self::seal(
            id.into(),
            PROMPT_MESSAGE_TYPE,
            from,
            to,
            body,
            None,
            plaintext.as_ref(),
            resolver,
            key_store,
        )
    }

    /// Create an encrypted reply envelope bound to a verified prompt envelope.
    pub fn reply(
        reply_did: Did,
        from: Did,
        to: Did,
        binding: DidReplyBinding,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let DidReplyBinding {
            prompt_body,
            prompt_ref,
        } = binding;
        Self::seal(
            reply_did.to_string(),
            REPLY_MESSAGE_TYPE,
            from,
            to,
            DidMessageBody {
                action: prompt_body.action.clone(),
                resource: prompt_body.resource.clone(),
                privacy: prompt_body.privacy.clone(),
                claims: prompt_body.claims.clone(),
                reply_to: Some(prompt_ref),
            },
            None,
            plaintext.as_ref(),
            resolver,
            key_store,
        )
    }

    /// Create an encrypted TypeDID agent-message envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn typedid(
        id: impl Into<String>,
        from: Did,
        to: Did,
        body: DidMessageBody,
        typedid: TypeDidConversation,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        Self::seal(
            id.into(),
            TYPEDID_MESSAGE_TYPE,
            from,
            to,
            body,
            Some(typedid),
            plaintext.as_ref(),
            resolver,
            key_store,
        )
    }

    /// Create an encrypted TypeDID reply envelope bound to a verified request.
    pub fn typedid_reply(
        id: impl Into<String>,
        from: Did,
        to: Did,
        request: &VerifiedTypeDidMessage,
        plaintext: impl AsRef<[u8]>,
        resolver: &dyn DidResolver,
        key_store: &dyn DidKeyStore,
    ) -> Result<Self, DidError> {
        let mut body = request.body().clone();
        body.reply_to = Some(request.message_ref().clone());
        let request_conversation = request.conversation();
        let conversation = TypeDidConversation {
            conversation_id: request_conversation.conversation_id.clone(),
            mode: TypeDidMode::RequestReply,
            profile: request_conversation.profile.clone(),
            protocol: request_conversation.protocol.clone(),
            expires_at: request_conversation.expires_at,
        };
        Self::typedid(
            id,
            from,
            to,
            body,
            conversation,
            plaintext,
            resolver,
            key_store,
        )
    }

    /// Stable reference to this signed envelope for reply binding.
    pub fn reference(&self) -> DidMessageReference {
        DidMessageReference {
            id: self.id.clone(),
            digest: format!("sha256:{}", hex_encode(&reference_sha256(self))),
        }
    }

    /// Canonical AEAD header binding every field available before encryption.
    ///
    /// The length-framed v2 header includes routing, timing, policy-visible
    /// body and claims, TypeDID conversation, reply binding, key id, and nonce.
    pub(super) fn associated_data(&self) -> Vec<u8> {
        authenticated_header(self)
    }

    /// Canonical bytes the sender signs and the recipient verifies.
    ///
    /// The signature transcript nests the exact AEAD header and appends the
    /// ciphertext as one additional length-framed field.
    #[cfg(test)]
    pub(super) fn signing_input(&self) -> Vec<u8> {
        let header = self.associated_data();
        self.signing_input_from_header(&header)
    }

    pub(super) fn signing_input_from_header(&self, header: &[u8]) -> Vec<u8> {
        signature_transcript_from_header(self, header)
    }

    pub(super) fn effective_expires_at(&self) -> u64 {
        self.typedid
            .as_ref()
            .and_then(|conversation| conversation.expires_at)
            .map_or(self.expires_time, |expires_at| {
                expires_at.min(self.expires_time)
            })
    }
}
