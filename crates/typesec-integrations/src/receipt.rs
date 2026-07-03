//! Signed decision receipts: portable, offline-verifiable proof that a
//! policy decision allowed one specific action.
//!
//! A [`GuardedToolCall`](https://docs.rs/typesec-agent) verdict is honored
//! only inside the process that produced it. A receipt extends the
//! "unforgeable capability" invariant across process boundaries: the guard's
//! host mints a short-lived ed25519-signed token binding `(subject, action,
//! resource, tool, call_id)` with an expiry, and any downstream service
//! holding the verifying key can check it offline — no shared policy file,
//! no callback to the issuer.
//!
//! Receipts are deliberately *positive-only*: only allowed decisions are
//! worth carrying, so [`ReceiptIssuer::issue`] is the single mint path and
//! verification proves "this exact call was allowed before `expires_at`".

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

/// The signed claims: one allowed decision, bounded in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Subject the decision was made for.
    pub subject: String,
    /// Action that was allowed.
    pub action: String,
    /// Resource the action was allowed on.
    pub resource: String,
    /// Tool the call came through, if it was a tool call.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_name: Option<String>,
    /// Framework call id, binding the receipt to one specific invocation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub call_id: Option<String>,
    /// When the receipt was issued.
    pub issued_at: DateTime<Utc>,
    /// When the receipt stops verifying.
    pub expires_at: DateTime<Utc>,
}

impl DecisionReceipt {
    /// Claims for an allowed `(subject, action, resource)` valid for `ttl`
    /// from `now`.
    pub fn new(
        subject: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        now: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> Self {
        Self {
            subject: subject.into(),
            action: action.into(),
            resource: resource.into(),
            tool_name: None,
            call_id: None,
            issued_at: now,
            expires_at: now + ttl,
        }
    }

    /// Bind the receipt to the tool call it authorizes.
    #[must_use]
    pub fn for_tool_call(
        mut self,
        tool_name: impl Into<String>,
        call_id: Option<impl Into<String>>,
    ) -> Self {
        self.tool_name = Some(tool_name.into());
        self.call_id = call_id.map(Into::into);
        self
    }
}

/// Why a receipt token failed verification.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// The token is not `base64url(claims).base64url(signature)`.
    #[error("malformed receipt token: {0}")]
    Malformed(String),
    /// The signature does not verify against the trusted key.
    #[error("receipt signature is invalid")]
    BadSignature,
    /// The receipt has expired.
    #[error("receipt expired at {expires_at} (now {now})")]
    Expired {
        /// When the receipt stopped being valid.
        expires_at: DateTime<Utc>,
        /// The verification time.
        now: DateTime<Utc>,
    },
    /// The receipt claims to be issued in the future.
    #[error("receipt issued in the future ({issued_at}, now {now})")]
    NotYetValid {
        /// The claimed issue time.
        issued_at: DateTime<Utc>,
        /// The verification time.
        now: DateTime<Utc>,
    },
}

/// Mints signed receipt tokens for allowed decisions.
pub struct ReceiptIssuer {
    key: SigningKey,
}

impl ReceiptIssuer {
    /// Create an issuer from an ed25519 signing key.
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// The verifying key downstream services pin.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign the claims into a `base64url(claims).base64url(signature)` token.
    pub fn issue(&self, receipt: &DecisionReceipt) -> String {
        let claims = serde_json::to_vec(receipt)
            .expect("DecisionReceipt serialization cannot fail: all fields are JSON-safe");
        let signature = self.key.sign(&claims);
        format!(
            "{}.{}",
            B64.encode(&claims),
            B64.encode(signature.to_bytes())
        )
    }
}

/// Verifies receipt tokens against a pinned issuer key.
pub struct ReceiptVerifier {
    key: VerifyingKey,
}

impl ReceiptVerifier {
    /// Create a verifier for one trusted issuer key.
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    /// Verify signature and validity window, returning the claims.
    ///
    /// `now` is explicit so callers control the clock (and tests are
    /// deterministic); pass `Utc::now()` in production.
    pub fn verify(&self, token: &str, now: DateTime<Utc>) -> Result<DecisionReceipt, ReceiptError> {
        let (claims_b64, signature_b64) = token
            .split_once('.')
            .ok_or_else(|| ReceiptError::Malformed("missing '.' separator".into()))?;
        let claims = B64
            .decode(claims_b64)
            .map_err(|err| ReceiptError::Malformed(format!("claims are not base64url: {err}")))?;
        let signature_bytes: [u8; 64] = B64
            .decode(signature_b64)
            .map_err(|err| ReceiptError::Malformed(format!("signature is not base64url: {err}")))?
            .try_into()
            .map_err(|_| ReceiptError::Malformed("signature is not 64 bytes".into()))?;
        self.key
            .verify(&claims, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| ReceiptError::BadSignature)?;
        // Only parse after the signature is trusted.
        let receipt: DecisionReceipt = serde_json::from_slice(&claims)
            .map_err(|err| ReceiptError::Malformed(format!("claims are not valid JSON: {err}")))?;
        if receipt.issued_at > now {
            return Err(ReceiptError::NotYetValid {
                issued_at: receipt.issued_at,
                now,
            });
        }
        if receipt.expires_at <= now {
            return Err(ReceiptError::Expired {
                expires_at: receipt.expires_at,
                now,
            });
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
