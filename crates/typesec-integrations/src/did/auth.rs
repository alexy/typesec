//! Canonical TypeDID envelope-authentication transcripts.

use super::envelope::DidEnvelope;
use super::typedid::TypeDidMode;
use sha2::Digest as _;

/// Wire identifier for the only accepted envelope authentication protocol.
pub const DID_ENVELOPE_AUTH_V2: &str = "typesec.did-envelope-auth.v2";

const HEADER_DOMAIN: &str = "typesec.did-envelope-auth.v2/header";
const SIGNATURE_DOMAIN: &str = "typesec.did-envelope-auth.v2/signature";
const REFERENCE_DOMAIN: &str = "typesec.did-envelope-auth.v2/reference";

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum TranscriptKind {
    Header,
    Signature,
}

/// Produce one length-framed transcript family for AEAD, signatures, and
/// stable references. Signature and reference transcripts nest the exact bytes
/// from the preceding stage so the authenticated header has one definition.
#[cfg(test)]
pub(super) fn canonical_transcript(envelope: &DidEnvelope, kind: TranscriptKind) -> Vec<u8> {
    let mut transcript = Vec::new();
    match kind {
        TranscriptKind::Header => write_authenticated_header(envelope, &mut transcript),
        TranscriptKind::Signature => write_signature_transcript(envelope, &mut transcript),
    }
    transcript
}

pub(super) fn authenticated_header(envelope: &DidEnvelope) -> Vec<u8> {
    let mut header = Vec::new();
    write_authenticated_header(envelope, &mut header);
    header
}

pub(super) fn signature_transcript_from_header(envelope: &DidEnvelope, header: &[u8]) -> Vec<u8> {
    let mut signature = Vec::new();
    let mut transcript = Transcript::new(&mut signature, SIGNATURE_DOMAIN);
    transcript.bytes("authenticatedHeader", header);
    transcript.string("ciphertext", &envelope.ciphertext);
    signature
}

pub(super) fn reference_sha256(envelope: &DidEnvelope) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    write_reference_transcript(envelope, &mut hasher);
    hasher.finalize().into()
}

fn write_authenticated_header<S: TranscriptSink>(envelope: &DidEnvelope, sink: &mut S) {
    let mut transcript = Transcript::new(sink, HEADER_DOMAIN);
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
}

fn write_signature_transcript<S: TranscriptSink>(envelope: &DidEnvelope, sink: &mut S) {
    let header_bytes = encoded_len(|counter| write_authenticated_header(envelope, counter));
    let mut transcript = Transcript::new(sink, SIGNATURE_DOMAIN);
    transcript.nested("authenticatedHeader", header_bytes, |sink| {
        write_authenticated_header(envelope, sink);
    });
    transcript.string("ciphertext", &envelope.ciphertext);
}

fn write_reference_transcript<S: TranscriptSink>(envelope: &DidEnvelope, sink: &mut S) {
    let signature_bytes = encoded_len(|counter| write_signature_transcript(envelope, counter));
    let mut transcript = Transcript::new(sink, REFERENCE_DOMAIN);
    transcript.nested("signedEnvelope", signature_bytes, |sink| {
        write_signature_transcript(envelope, sink);
    });
    transcript.string("signature", &envelope.signature);
}

fn encoded_len(write: impl FnOnce(&mut ByteCount)) -> usize {
    let mut counter = ByteCount::default();
    write(&mut counter);
    counter.0
}

struct Transcript<'a, S> {
    sink: &'a mut S,
}

impl<'a, S: TranscriptSink> Transcript<'a, S> {
    fn new(sink: &'a mut S, domain: &str) -> Self {
        let mut transcript = Self { sink };
        transcript.string("domain", domain);
        transcript
    }

    fn string(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        frame(self.sink, name.as_bytes());
        frame(self.sink, value);
    }

    fn nested(&mut self, name: &str, value_len: usize, write: impl FnOnce(&mut S)) {
        frame(self.sink, name.as_bytes());
        write_len(self.sink, value_len);
        write(self.sink);
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
}

fn mode_name(mode: TypeDidMode) -> &'static str {
    match mode {
        TypeDidMode::Send => "send",
        TypeDidMode::RequestReply => "request_reply",
    }
}

trait TranscriptSink {
    fn write(&mut self, bytes: &[u8]);
}

impl TranscriptSink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl TranscriptSink for sha2::Sha256 {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

#[derive(Default)]
struct ByteCount(usize);

impl TranscriptSink for ByteCount {
    fn write(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

fn frame(output: &mut impl TranscriptSink, value: &[u8]) {
    write_len(output, value.len());
    output.write(value);
}

fn write_len(output: &mut impl TranscriptSink, value_len: usize) {
    output.write(&(value_len as u64).to_be_bytes());
}
