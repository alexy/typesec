//! Taint guarded tool output: results enter the prompt as labeled data.
//!
//! Tool output flowing back into the model's context is the classic
//! prompt-injection channel. [`GuardedToolCall::protect_output`] closes the
//! loop with `typesec-core`'s information-flow machinery: the output of an
//! *allowed* call is wrapped in a [`SecureValue`] labeled at a caller-chosen
//! privacy level and tied to the call's resolved resource id. From there the
//! usual rules apply — the value can be transformed (`map`/`zip`) but
//! revealing or declassifying it requires a typed capability minted for that
//! same resource.

use thiserror::Error;
use typesec_core::SecureValue;
use typesec_core::resource::GenericResource;
use typesec_core::secure_value::PrivacyLevel;

use super::call::{GuardedToolCall, ToolCallVerdict};

/// Resource kind attached to tool-output resources.
pub const TOOL_OUTPUT_KIND: &str = "tool_output";

/// Why tool output could not be protected.
#[derive(Debug, Error)]
pub enum TaintError {
    /// Only allowed calls have output worth labeling; refusing here keeps
    /// "we ran a denied tool anyway" from being papered over.
    #[error("cannot protect output of a call that was not allowed: {reason}")]
    NotAllowed {
        /// The verdict's rationale.
        reason: String,
    },
    /// The call never resolved a resource (unbound tool or failed
    /// resource-argument resolution), so there is nothing to tie the label to.
    #[error("call has no resolved resource to tie the output to")]
    UnresolvedResource,
}

impl GuardedToolCall {
    /// Label the output of an allowed call as protected data tied to the
    /// call's resolved resource.
    ///
    /// The label `L` is chosen by the caller (e.g.
    /// [`Sensitive`](typesec_core::secure_value::Sensitive)); revealing the
    /// value downstream requires a `Capability<CanReadSensitive, GenericResource>`
    /// minted for the *same resource id* this call was checked against.
    pub fn protect_output<L: PrivacyLevel, T>(
        &self,
        output: T,
    ) -> Result<SecureValue<L, T, GenericResource>, TaintError> {
        if let ToolCallVerdict::Deny { reason } | ToolCallVerdict::Delegate { reason } =
            &self.verdict
        {
            return Err(TaintError::NotAllowed {
                reason: reason.clone(),
            });
        }
        let resource_id = self
            .resource
            .as_deref()
            .ok_or(TaintError::UnresolvedResource)?;
        let resource = GenericResource::new(resource_id, TOOL_OUTPUT_KIND);
        Ok(SecureValue::protect(output, &resource))
    }
}
