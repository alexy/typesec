//! Non-forgeable vault provenance for authoritative cognition commits.

use crate::index::IndexMutation;
use crate::store::StoreBatchOp;

use super::CognitionEffect;
use super::types::{
    CognitionApplyError, CognitionAuditEvidence, CognitionIdempotencyKey,
    CognitionSourcePrecondition,
};

/// Vault-prepared input to one authoritative cognition transaction.
///
/// Only TypeSec's guarded cognition preparation path can construct this token.
/// It deliberately implements neither `Debug` nor serde traits: operations can
/// contain protected memory plaintext and must not acquire a logging or generic
/// serialization escape hatch. Trusted [`super::CognitionCommitStore`]
/// backends receive the token by value and may borrow only the fields needed to
/// execute their atomic transaction.
///
/// External field construction is forbidden:
///
/// ```compile_fail,E0451
/// use typesec_memory::PreparedCognitionCommit;
///
/// let _forged = PreparedCognitionCommit {
///     idempotency_key: unimplemented!(),
///     proposal_digest: unimplemented!(),
///     source_preconditions: unimplemented!(),
///     operations: unimplemented!(),
///     index_outbox: unimplemented!(),
///     audit: unimplemented!(),
/// };
/// ```
///
/// The token cannot be logged through `Debug`:
///
/// ```compile_fail,E0277
/// use typesec_memory::PreparedCognitionCommit;
///
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<PreparedCognitionCommit>();
/// ```
///
/// The token cannot be cloned outside the vault boundary:
///
/// ```compile_fail,E0277
/// use typesec_memory::PreparedCognitionCommit;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedCognitionCommit>();
/// ```
///
/// Serialization cannot export protected operations:
///
/// ```compile_fail,E0277
/// use typesec_memory::PreparedCognitionCommit;
///
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<PreparedCognitionCommit>();
/// ```
///
/// Deserialization cannot manufacture vault provenance:
///
/// ```compile_fail,E0277
/// use typesec_memory::PreparedCognitionCommit;
///
/// let _: PreparedCognitionCommit = serde_json::from_str("{}").unwrap();
/// ```
pub struct PreparedCognitionCommit {
    idempotency_key: CognitionIdempotencyKey,
    proposal_digest: String,
    source_preconditions: Vec<CognitionSourcePrecondition>,
    operations: Vec<StoreBatchOp>,
    index_outbox: Vec<IndexMutation>,
    audit: CognitionAuditEvidence,
}

impl PreparedCognitionCommit {
    pub(super) fn new(
        idempotency_key: CognitionIdempotencyKey,
        proposal_digest: String,
        source_preconditions: Vec<CognitionSourcePrecondition>,
        operations: Vec<StoreBatchOp>,
        index_outbox: Vec<IndexMutation>,
        audit: CognitionAuditEvidence,
    ) -> Self {
        Self {
            idempotency_key,
            proposal_digest,
            source_preconditions,
            operations,
            index_outbox,
            audit,
        }
    }

    /// Borrow the durable idempotency identity for trusted backend execution.
    pub fn idempotency_key(&self) -> &CognitionIdempotencyKey {
        &self.idempotency_key
    }

    /// Borrow the proposal digest used to detect conflicting retries.
    pub fn proposal_digest(&self) -> &str {
        &self.proposal_digest
    }

    /// Return the explicit authoritative memory effect of this transaction.
    pub fn effect(&self) -> CognitionEffect {
        self.audit.effect
    }

    /// Borrow the exact source revisions an atomic backend must compare.
    pub fn source_preconditions(&self) -> &[CognitionSourcePrecondition] {
        &self.source_preconditions
    }

    /// Borrow the atomic record operations for trusted backend execution.
    ///
    /// Put operations may contain protected memory plaintext. Backends must not
    /// log or generically serialize them and should retain them only as required
    /// by the authoritative transaction. This slice is empty exactly when
    /// [`Self::effect`] is [`CognitionEffect::NoChange`].
    pub fn operations(&self) -> &[StoreBatchOp] {
        &self.operations
    }

    /// Borrow the ID-only semantic-index outbox work.
    ///
    /// This slice is empty exactly when [`Self::effect`] is
    /// [`CognitionEffect::NoChange`].
    pub fn index_outbox(&self) -> &[IndexMutation] {
        &self.index_outbox
    }

    /// Borrow the plaintext-free evidence persisted with the transaction.
    pub fn audit(&self) -> &CognitionAuditEvidence {
        &self.audit
    }

    /// Return the canonical domain-separated digest of the complete token.
    ///
    /// TypeSec owns the private serialization used for this digest. Backends
    /// receive only canonical `sha256:` text, never the serialized bytes.
    pub fn canonical_digest(&self) -> Result<String, CognitionApplyError> {
        super::digest::prepared_commit_digest(self)
    }
}
