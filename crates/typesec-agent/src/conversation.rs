//! Conversation typestate: "ask before acting" as a compile-time obligation.
//!
//! Multi-turn agent protocols routinely require consent before sensitive
//! actions — and routinely forget to check it on some code path. This module
//! extends the `SecureAgent<S>` idea to conversations: the *state of the
//! consent handshake is part of the type*, and consent itself is not a
//! boolean but a minted [`Capability<CanDelegate, GenericResource>`] over the
//! resource `conversation/<peer>` — unforgeable, policy-checked, audited,
//! and expiring like every other capability.
//!
//! ```text
//! Conversation<Proposed> ──request_consent(scopes)──▶ Conversation<AwaitingConsent>
//!                                                          │ grant_via(engine, subject)
//!                                                          ▼   (policy check mints the proof)
//!                                                Conversation<Consented>
//!                                                          └─ consent() / consented_scopes()
//! ```
//!
//! `Conversation<Proposed>` has no `consent()`; `Conversation<AwaitingConsent>`
//! has no way to *become* consented except through a policy engine. Skipping
//! the handshake is a type error, not a code-review finding.

use std::marker::PhantomData;

use typesec_core::policy::{CapabilityError, MintOptions, PolicyEngine, mint_capability_for_id};
use typesec_core::resource::GenericResource;
use typesec_core::{CanDelegate, Capability, SubjectId};

/// Sealed state trait for the conversation typestate machine.
pub trait ConversationState: private::Sealed + Send + Sync + 'static {}

mod private {
    pub trait Sealed {}
}

/// Initial state: a peer has been named, nothing has been asked.
#[derive(Debug)]
pub struct Proposed;

/// Consent has been requested for specific scopes but not yet granted.
#[derive(Debug)]
pub struct AwaitingConsent;

/// Consent is held as a minted capability; scoped actions may proceed.
#[derive(Debug)]
pub struct Consented;

impl private::Sealed for Proposed {}
impl private::Sealed for AwaitingConsent {}
impl private::Sealed for Consented {}
impl ConversationState for Proposed {}
impl ConversationState for AwaitingConsent {}
impl ConversationState for Consented {}

/// A conversation with `peer`, parameterized by its consent state.
pub struct Conversation<S: ConversationState> {
    peer: String,
    purpose: Option<String>,
    scopes: Vec<String>,
    consent: Option<Capability<CanDelegate, GenericResource>>,
    _state: PhantomData<fn() -> S>,
}

impl<S: ConversationState> std::fmt::Debug for Conversation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("peer", &self.peer)
            .field("purpose", &self.purpose)
            .field("scopes", &self.scopes)
            .field("state", &std::any::type_name::<S>())
            .finish_non_exhaustive()
    }
}

impl<S: ConversationState> Conversation<S> {
    /// The peer this conversation addresses.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// The declared purpose, if any.
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// The resource id consent is minted against: `conversation/<peer>`.
    pub fn resource_id(&self) -> String {
        format!("conversation/{}", self.peer)
    }

    fn transition<T: ConversationState>(self) -> Conversation<T> {
        Conversation {
            peer: self.peer,
            purpose: self.purpose,
            scopes: self.scopes,
            consent: self.consent,
            _state: PhantomData,
        }
    }
}

impl Conversation<Proposed> {
    /// Open a conversation proposal with `peer`.
    pub fn propose(peer: impl Into<String>) -> Self {
        Self {
            peer: peer.into(),
            purpose: None,
            scopes: Vec::new(),
            consent: None,
            _state: PhantomData,
        }
    }

    /// Declare the purpose of the conversation.
    #[must_use]
    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Ask for consent to the named action scopes. The conversation can no
    /// longer be treated as consent-free — and is not yet consented.
    pub fn request_consent<I, T>(mut self, scopes: I) -> Conversation<AwaitingConsent>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self.transition()
    }
}

impl Conversation<AwaitingConsent> {
    /// The scopes consent was requested for.
    pub fn requested_scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Resolve the consent request through a policy engine.
    ///
    /// Consent is granted only if `engine` allows `subject` the `delegate`
    /// action on `conversation/<peer>` — the decision is audited and the
    /// resulting capability expires like any other. On deny, the
    /// conversation is returned unchanged so the caller can renegotiate.
    // The Err variant intentionally carries the conversation back to the
    // caller; its size is the conversation itself, not incidental baggage.
    #[allow(clippy::result_large_err)]
    pub fn grant_via(
        self,
        engine: &dyn PolicyEngine,
        subject: impl Into<SubjectId>,
    ) -> Result<Conversation<Consented>, (Self, CapabilityError)> {
        match mint_capability_for_id::<CanDelegate, GenericResource>(
            engine,
            subject,
            self.resource_id(),
            &MintOptions::default(),
        ) {
            Ok(consent) => {
                let mut conversation = self.transition::<Consented>();
                conversation.consent = Some(consent);
                Ok(conversation)
            }
            Err(err) => Err((self, err)),
        }
    }
}

impl Conversation<Consented> {
    /// The scopes this conversation is consented for.
    pub fn consented_scopes(&self) -> &[String] {
        &self.scopes
    }

    /// `true` if `action` is within the consented scopes.
    pub fn covers(&self, action: &str) -> bool {
        self.scopes.iter().any(|scope| scope == action)
    }

    /// The consent proof: a real capability, checkable and expiring.
    pub fn consent(&self) -> &Capability<CanDelegate, GenericResource> {
        self.consent
            .as_ref()
            .expect("Consented state always holds the minted capability")
    }
}

#[cfg(test)]
mod tests;
