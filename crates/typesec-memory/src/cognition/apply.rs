use chrono::Utc;
use typesec_core::policy::RequestContext;
use typesec_core::{CanRead, CanWrite, Capability};

use super::digest::{proposal_digest, source_manifest};
use super::prepare::prepare_commit;
use super::types::{
    CognitionApplyError, CognitionCommitOutcome, CognitionCommitStore, CognitionIdempotencyKey,
    CognitionSourceManifest,
};
use super::validate::{
    load_sources, required_purpose, validate_authority, validate_proposal_shape,
    validate_request_binding,
};
use crate::CognitionProposal;
use crate::error::MemoryError;
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
        self.authorize(space, capability, context)?;
        let purpose = required_purpose(context)?;
        let records = load_sources(self, space, source_ids, purpose, Utc::now())?;
        source_manifest(&records).map_err(Into::into)
    }
}

impl<S: CognitionCommitStore> MemoryVault<S> {
    /// Revalidate and atomically apply one inert cognition proposal.
    ///
    /// The configured policy and authority verifier are mandatory. The backing
    /// store must implement an actual transaction through
    /// [`CognitionCommitStore`]; there is no sequential fallback.
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
        validate_proposal_shape(proposal)?;
        let binding = proposal
            .binding
            .as_ref()
            .ok_or(CognitionApplyError::MissingBinding)?;
        binding.validate()?;

        let purpose = required_purpose(context)?;
        validate_request_binding(space, capability, proposal, binding, purpose)?;
        self.authorize(space, capability, context)?;
        let authority = verifier.revalidate(binding, context)?;
        validate_authority(binding, &authority)?;

        let proposal_digest = proposal_digest(proposal)?;
        let idempotency_key = CognitionIdempotencyKey {
            space_id: binding.space_id.clone(),
            job_id: proposal.job_id.clone(),
        };
        if let Some(recovered) = self
            .store()
            .recover_cognition(&idempotency_key, &proposal_digest)?
        {
            return Ok(recovered);
        }

        let now = Utc::now();
        let sources = load_sources(self, space, &proposal.source_ids, purpose, now)?;
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
            space,
            proposal,
            binding,
            &authority,
            &sources,
            manifest,
            proposal_digest,
            now,
        )?;
        self.store().commit_cognition(prepared).map_err(Into::into)
    }
}
