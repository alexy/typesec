//! Runtime sensitivity labels and their bridge to core's type-level lattice.
//!
//! A store holds records of mixed sensitivity, so each record carries a
//! *runtime* [`Label`]. Recall, by contrast, is typed: the caller states a
//! compile-time *clearance* (a [`PrivacyLevel`]), and the vault returns only
//! records whose runtime label is at or below it. [`Clearance`] is the bridge
//! — it maps each type-level label to its runtime rank so the vault can
//! compare the two.

use serde::{Deserialize, Serialize};
use typesec_core::secure_value::{Internal, Public, Secret, Sensitive};
pub use typesec_core::secure_value::{PrivacyLevel, Public as PublicLevel};

/// A record's sensitivity, ordered least→most restrictive.
///
/// `Ord` follows declaration order, so `Public < Internal < Sensitive <
/// Secret`, and `record.label <= ceiling` is exactly "label ⊑ clearance".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    /// Safe to reveal without a capability.
    Public,
    /// Not public, below sensitive.
    #[default]
    Internal,
    /// PII or confidential business data.
    Sensitive,
    /// Credentials or highly restricted inputs.
    Secret,
}

impl Label {
    /// Stable lowercase name (matches core's `PrivacyLevel::name`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }

    /// Parse a label name; unknown names fail closed to the most restrictive
    /// level so a typo can never widen access.
    pub fn from_name(name: &str) -> Self {
        match name {
            "public" => Self::Public,
            "internal" => Self::Internal,
            "sensitive" => Self::Sensitive,
            _ => Self::Secret,
        }
    }

    /// The type-level least upper bound of two runtime labels.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }
}

/// A type-level privacy label usable as a recall *clearance ceiling*.
///
/// Implemented for core's four sealed [`PrivacyLevel`] markers; the sealed
/// bound means no external label can be smuggled in as a clearance.
pub trait Clearance: PrivacyLevel {
    /// This clearance's runtime rank.
    fn ceiling() -> Label;
}

impl Clearance for Public {
    fn ceiling() -> Label {
        Label::Public
    }
}
impl Clearance for Internal {
    fn ceiling() -> Label {
        Label::Internal
    }
}
impl Clearance for Sensitive {
    fn ceiling() -> Label {
        Label::Sensitive
    }
}
impl Clearance for Secret {
    fn ceiling() -> Label {
        Label::Secret
    }
}

#[cfg(test)]
mod tests;
