//! Signed deletion receipts (`receipts` feature).
//!
//! Forgetting is provable: a [`Tombstone`] can be turned into a short-lived
//! ed25519-signed receipt binding *what was forgotten, from which space, by
//! whom, and when* — an offline-verifiable erasure proof for a counterparty
//! or a GDPR audit. Reuses `typesec-integrations`' `ReceiptIssuer`.

use chrono::TimeDelta;
use typesec_core::SubjectId;
use typesec_integrations::receipt::{DecisionReceipt, ReceiptIssuer};

use crate::space::MemorySpace;
use crate::vault::Tombstone;
use typesec_core::Resource;

impl Tombstone {
    /// Mint a signed erasure receipt for this tombstone, valid for `ttl`.
    ///
    /// The receipt records the forget as a decision (`action = "forget"`) on
    /// the space, with the forgotten record ids joined into the receipt's
    /// tool/call fields so a verifier can confirm exactly what was destroyed.
    pub fn issue_receipt(
        &self,
        issuer: &ReceiptIssuer,
        subject: impl Into<SubjectId>,
        space: &MemorySpace,
        ttl: TimeDelta,
    ) -> String {
        let ids = self
            .forgotten
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let receipt = DecisionReceipt::new(
            subject.into().as_str(),
            "forget",
            space.resource_id(),
            self.at,
            ttl,
        )
        .for_tool_call("memory.forget", Some(ids));
        issuer.issue(&receipt)
    }
}

#[cfg(test)]
mod tests;
