use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::ReceiptError;

/// Closed decision vocabulary for governed semantic-model operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticDecisionAction {
    /// Publish a new immutable model version.
    PublishModel,
    /// Consume a published model version.
    ConsumeModel,
    /// Read one governed semantic field.
    AccessField,
    /// Execute one governed metric definition.
    ExecuteMetric,
    /// Execute a composed semantic query.
    ExecuteSemanticQuery,
    /// Expose model AI context to an agent or model.
    AccessAiContext,
}

/// Positive-only signed claims bound to one immutable semantic model version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticDecisionReceipt {
    /// Authorized principal.
    pub subject: String,
    /// Exact allowed operation.
    pub action: SemanticDecisionAction,
    /// Dataset, field, metric, query, or AI-context resource.
    pub resource: String,
    /// Stable semantic model identity.
    pub model_id: String,
    /// Positive immutable publication version.
    pub model_version: u64,
    /// Hash of the exact model artifact.
    pub artifact_hash: String,
    /// Hash of the policy input used for the decision.
    pub policy_hash: String,
    /// Optional hash of the validated physical binding set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_binding_hash: Option<String>,
    /// Receipt issuance time.
    pub issued_at: DateTime<Utc>,
    /// Exclusive receipt expiry.
    pub expires_at: DateTime<Utc>,
}

impl SemanticDecisionReceipt {
    /// Construct validated positive claims for one immutable model version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: impl Into<String>,
        action: SemanticDecisionAction,
        resource: impl Into<String>,
        model_id: impl Into<String>,
        model_version: u64,
        artifact_hash: impl Into<String>,
        policy_hash: impl Into<String>,
        physical_binding_hash: Option<String>,
        now: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> Result<Self, ReceiptError> {
        let receipt = Self {
            subject: subject.into(),
            action,
            resource: resource.into(),
            model_id: model_id.into(),
            model_version,
            artifact_hash: artifact_hash.into(),
            policy_hash: policy_hash.into(),
            physical_binding_hash,
            issued_at: now,
            expires_at: now + ttl,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> Result<(), ReceiptError> {
        for (name, value) in [
            ("subject", self.subject.as_str()),
            ("resource", self.resource.as_str()),
            ("model id", self.model_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ReceiptError::InvalidClaims(format!(
                    "{name} must not be empty"
                )));
            }
        }
        if self.model_version == 0 {
            return Err(ReceiptError::InvalidClaims(
                "model version must be positive".into(),
            ));
        }
        for (name, value) in [
            ("artifact hash", Some(self.artifact_hash.as_str())),
            ("policy hash", Some(self.policy_hash.as_str())),
            (
                "physical binding hash",
                self.physical_binding_hash.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
                if !valid {
                    return Err(ReceiptError::InvalidClaims(format!(
                        "{name} must be sha256"
                    )));
                }
            }
        }
        if self.expires_at <= self.issued_at {
            return Err(ReceiptError::InvalidClaims(
                "semantic receipt expiry must follow issuance".into(),
            ));
        }
        Ok(())
    }
}
