//! Canonical TypeDID envelope-authentication transcripts.

use super::envelope::DidEnvelope;
use super::typedid::TypeDidMode;

/// Wire identifier for the only accepted envelope authentication protocol.
pub const DID_ENVELOPE_AUTH_V2: &str = "typesec.did-envelope-auth.v2";

const HEADER_DOMAIN: &str = "typesec.did-envelope-auth.v2/header";
const SIGNATURE_DOMAIN: &str = "typesec.did-envelope-auth.v2/signature";
const REFERENCE_DOMAIN: &str = "typesec.did-envelope-auth.v2/reference";

#[derive(Clone, Copy)]
pub(super) enum TranscriptKind {
    Header,
    Signature,
    Reference,
}

/// Produce one length-framed transcript family for AEAD, signatures, and
/// stable references. Signature and reference transcripts nest the exact bytes
/// from the preceding stage so the authenticated header has one definition.
pub(super) fn canonical_transcript(envelope: &DidEnvelope, kind: TranscriptKind) -> Vec<u8> {
    let header = authenticated_header(envelope);
    match kind {
        TranscriptKind::Header => header,
        TranscriptKind::Signature => signature_transcript(envelope, &header),
        TranscriptKind::Reference => {
            let signature = signature_transcript(envelope, &header);
            reference_transcript(envelope, &signature)
        }
    }
}

fn authenticated_header(envelope: &DidEnvelope) -> Vec<u8> {
    let mut transcript = Transcript::new(HEADER_DOMAIN);
    transcript.string("authVersion", &envelope.auth_version);
    transcript.string("id", &envelope.id);
    transcript.string("messageType", &envelope.message_type);
    transcript.string("from", envelope.from.as_str());
    transcript.count("recipientCount", envelope.to.len());
    for recipient in &envelope.to {
        transcript.string("recipient", recipient.as_str());
    }
    transcript.u64("createdTime", envelope.created_time);
    transcript.u64("expiresTime", envelope.expires_time);
    transcript.string("action", &envelope.body.action);
    transcript.string("resource", &envelope.body.resource);
    transcript.string("privacy", &envelope.body.privacy);
    transcript.count("claimCount", envelope.body.claims.len());
    for (name, value) in &envelope.body.claims {
        transcript.string("claimName", name);
        transcript.string("claimValue", value);
    }
    transcript.optional_reference(envelope.body.reply_to.as_ref());
    transcript.optional_conversation(envelope.typedid.as_ref());
    transcript.string("kid", &envelope.kid);
    transcript.string("nonce", &envelope.nonce);
    transcript.finish()
}

fn signature_transcript(envelope: &DidEnvelope, header: &[u8]) -> Vec<u8> {
    let mut transcript = Transcript::new(SIGNATURE_DOMAIN);
    transcript.bytes("authenticatedHeader", header);
    transcript.string("ciphertext", &envelope.ciphertext);
    transcript.finish()
}

fn reference_transcript(envelope: &DidEnvelope, signature: &[u8]) -> Vec<u8> {
    let mut transcript = Transcript::new(REFERENCE_DOMAIN);
    transcript.bytes("signedEnvelope", signature);
    transcript.string("signature", &envelope.signature);
    transcript.finish()
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &str) -> Self {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.string("domain", domain);
        transcript
    }

    fn string(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        frame(&mut self.bytes, name.as_bytes());
        frame(&mut self.bytes, value);
    }

    fn u64(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    fn count(&mut self, name: &str, value: usize) {
        self.u64(name, value as u64);
    }

    fn boolean(&mut self, name: &str, value: bool) {
        self.bytes(name, &[u8::from(value)]);
    }

    fn optional_reference(&mut self, reference: Option<&super::DidMessageReference>) {
        self.boolean("hasReplyTo", reference.is_some());
        if let Some(reference) = reference {
            self.string("replyToId", &reference.id);
            self.string("replyToDigest", &reference.digest);
        }
    }

    fn optional_conversation(&mut self, conversation: Option<&super::TypeDidConversation>) {
        self.boolean("hasTypeDid", conversation.is_some());
        if let Some(conversation) = conversation {
            self.string("conversationId", &conversation.conversation_id);
            self.string("deliveryMode", mode_name(conversation.mode));
            self.string("profile", &conversation.profile);
            self.string("protocol", &conversation.protocol);
            self.boolean("hasConversationExpiry", conversation.expires_at.is_some());
            if let Some(expires_at) = conversation.expires_at {
                self.u64("conversationExpiresAt", expires_at);
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn mode_name(mode: TypeDidMode) -> &'static str {
    match mode {
        TypeDidMode::Send => "send",
        TypeDidMode::RequestReply => "request_reply",
    }
}

fn frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
