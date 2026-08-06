use chrono::Utc;
use typesec_core::policy::RequestContext;
use typesec_core::{CanRead, CanWrite, Capability};

use super::digest::source_manifest;
use super::identity::CognitionCommitIdentity;
use super::outcome::{validate_commit_outcome, validate_preflight_outcome};
use super::prepare::prepare_commit;
use super::source_scope::validate_source_scope;
use super::types::{
    CognitionApplyError, CognitionCommitOutcome, CognitionCommitStore, CognitionSourceManifest,
};
use super::validate::{
    load_sources, required_purpose, validate_authority, validate_proposal_for_application,
    validate_request_binding,
};
use crate::CognitionProposal;
use crate::error::MemoryError;
use crate::governed::GovernedSourceScope;
use crate::space::{MemoryId, MemorySpace};
use crate::store::MemoryStore;
use crate::vault::MemoryVault;

impl<S: MemoryStore> MemoryVault<S> {
    /// Compute the opaque source manifest a cognition job must echo.
    ///
    /// Content is hashed inside the vault and is never returned. Application
    /// recomputes the same manifest and the authoritative transaction compares
    /// every record precondition again to close the validation/commit race.
    pub fn cognition_source_manifest(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
    ) -> Result<CognitionSourceManifest, MemoryError> {
        self.cognition_source_manifest_for_scope(space, capability, source_ids, context, None)
    }

    /// Compute a source manifest only when every record has the exact
    /// governed scope supplied by the trusted composition layer.
    pub fn governed_cognition_source_manifest(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
        scope: &GovernedSourceScope,
    ) -> Result<CognitionSourceManifest, MemoryError> {
        self.cognition_source_manifest_for_scope(
            space,
            capability,
            source_ids,
            context,
            Some(scope),
        )
    }

    fn cognition_source_manifest_for_scope(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanRead, MemorySpace>,
        source_ids: &[MemoryId],
        context: &RequestContext,
        scope: Option<&GovernedSourceScope>,
    ) -> Result<CognitionSourceManifest, MemoryError> {
        self.authorize(space, capability, context)?;
        let purpose = required_purpose(context)?;
        let records = load_sources(self, space, source_ids, purpose, Utc::now())?;
        validate_source_scope(&records, scope)?;
        source_manifest(&records).map_err(Into::into)
    }
}

impl<S: CognitionCommitStore> MemoryVault<S> {
    /// Revalidate and atomically commit one inert cognition proposal.
    ///
    /// The configured policy and authority verifier are mandatory. The backing
    /// store must implement an actual transaction through
    /// [`CognitionCommitStore`]; there is no sequential fallback. Explicit
    /// no-change decisions traverse the same authority, source-reload, and
    /// preparation path before committing durable evidence without record or
    /// outbox mutations.
    pub fn apply_cognition(
        &self,
        space: &MemorySpace,
        capability: &Capability<CanWrite, MemorySpace>,
        proposal: &CognitionProposal,
        context: &RequestContext,
    ) -> Result<CognitionCommitOutcome, MemoryError> {
        if !self.has_policy() {
            return Err(CognitionApplyError::PolicyUnavailable.into());
        }
        let verifier = self
            .cognition_authority()
            .ok_or(CognitionApplyError::AuthorityVerifierUnavailable)?;
        validate_proposal_for_application(proposal)?;
        let binding = proposal
            .binding
            .as_ref()
            .ok_or(CognitionApplyError::MissingBinding)?;
        binding.validate()?;

        let purpose = required_purpose(context)?;
        validate_request_binding(space, capability, proposal, binding, purpose)?;
        self.authorize(space, capability, context)?;
        let authority = verifier
            .revalidate(binding, context)
            .map_err(|_| CognitionApplyError::Authority)?;
        validate_authority(proposal, binding, &authority, Utc::now())?;

        let identity = CognitionCommitIdentity::from_validated(space, proposal, binding)?;
        if let Some(recovered) = self
            .store()
            .recover_cognition(&identity.key, &identity.proposal_digest)?
        {
            validate_preflight_outcome(&recovered, &identity)?;
            return Ok(recovered);
        }

        let now = Utc::now();
        let sources = load_sources(self, space, &proposal.source_ids, purpose, now)?;
        validate_source_scope(&sources, binding.governed_source_scope.as_ref())?;
        let manifest = source_manifest(&sources)?;
        if manifest.digest != binding.source_manifest_digest
            || manifest.digest != proposal.source_digest
        {
            return Err(CognitionApplyError::SourceManifestMismatch.into());
        }
        if manifest.joined_label != proposal.joined_label {
            return Err(CognitionApplyError::JoinedLabelMismatch.into());
        }

        let prepared = prepare_commit(
            space, proposal, binding, &authority, &sources, manifest, &identity, now,
        )?;
        let prepared_audit = prepared.audit().clone();
        let outcome = self.store().commit_cognition(prepared)?;
        validate_commit_outcome(&outcome, &identity, &prepared_audit)?;
        Ok(outcome)
    }
}
