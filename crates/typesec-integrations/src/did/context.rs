//! Non-forgeable, borrow-scoped access to verified TypeDID policy context.

use super::{Did, TypeDidAttestation, VerifiedTypeDidMessage};

/// Policy context available only from a gateway-verified TypeDID message.
///
/// Unlike [`TypeDidAttestation`], this type is not serializable and has no
/// public constructor. Application code can therefore require fresh verified
/// gateway state while persisting the attestation separately as audit evidence.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedTypeDidContext<'a> {
    message: &'a VerifiedTypeDidMessage,
}

impl VerifiedTypeDidMessage {
    /// Borrow the verified identity and negotiated policy claims.
    pub fn verified_context(&self) -> VerifiedTypeDidContext<'_> {
        VerifiedTypeDidContext { message: self }
    }
}

impl VerifiedTypeDidContext<'_> {
    /// Cryptographically verified sender DID.
    pub fn subject(&self) -> &Did {
        self.message.subject()
    }

    /// A signed policy-visible claim from the verified envelope.
    pub fn claim(&self, name: &str) -> Option<&str> {
        self.message.body().claims.get(name).map(String::as_str)
    }

    /// Signed purpose claim, when supplied by the negotiated profile.
    pub fn purpose(&self) -> Option<&str> {
        self.claim("purpose")
    }

    /// Stable signed-envelope digest for downstream binding.
    pub fn request_digest(&self) -> &str {
        &self.message.message_ref().digest
    }

    /// Authenticated policy-visible action.
    pub fn action(&self) -> &str {
        &self.message.body().action
    }

    /// Authenticated policy-visible resource identifier.
    pub fn resource(&self) -> &str {
        &self.message.body().resource
    }

    /// Authenticated policy-visible privacy class.
    pub fn privacy(&self) -> &str {
        &self.message.body().privacy
    }

    /// Minimum authenticated outer-envelope and conversation expiry.
    pub fn effective_expires_at(&self) -> u64 {
        self.message.effective_expires_at()
    }

    /// Produce the audit-safe serializable evidence for this verified context.
    pub fn attestation(&self) -> TypeDidAttestation {
        self.message.attestation()
    }
}
