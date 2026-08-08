//! RBAC policy engine — implements [`PolicyEngine`] for [`RbacPolicy`].

mod flatten;

use std::collections::HashMap;

use tracing::debug;
use typesec_core::{
    ResourceId, SubjectId,
    glob::{GlobPattern, is_glob_pattern},
    policy::{PolicyEngine, PolicyResult},
};

use crate::model::RbacPolicy;
use flatten::flatten_role;

/// A compiled, fast-lookup RBAC engine.
///
/// After construction from an [`RbacPolicy`], the engine pre-computes:
/// - Effective permissions per role (with inheritance flattened).
/// - Subject → role mappings.
///
/// Exact-subject checks use a compact permission lookup followed by only that
/// permission's resource patterns. Wildcard-subject assignments are evaluated
/// separately because their subject globs necessarily depend on the request.
pub struct RbacEngine {
    /// Subject → compact, permission-indexed compiled resource grants.
    subject_grants: HashMap<String, CompiledGrants>,
    /// Glob subject pattern → set of effective grants.
    wildcard_subject_grants: Vec<(GlobPattern, CompiledGrants)>,
}

/// A permission and its resource patterns, all compiled at policy load.
#[derive(Debug)]
struct CompiledGrant {
    permission: String,
    resource_patterns: Vec<GlobPattern>,
}

/// Sorted effective grants. Tiny policies stay on a one-or-two-comparison
/// linear path; larger policies use binary search without a second hash lookup.
#[derive(Debug, Default)]
struct CompiledGrants {
    grants: Vec<CompiledGrant>,
}

impl CompiledGrants {
    const LINEAR_SEARCH_LIMIT: usize = 8;

    fn insert(&mut self, permission: String, patterns: Vec<GlobPattern>) {
        if let Some(existing) = self
            .grants
            .iter_mut()
            .find(|grant| grant.permission == permission)
        {
            existing.resource_patterns.extend(patterns);
        } else {
            self.grants.push(CompiledGrant {
                permission,
                resource_patterns: patterns,
            });
        }
    }

    fn extend(&mut self, other: Self) {
        for grant in other.grants {
            self.insert(grant.permission, grant.resource_patterns);
        }
        self.sort();
    }

    fn sort(&mut self) {
        self.grants
            .sort_unstable_by(|left, right| left.permission.cmp(&right.permission));
    }

    fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    fn allows(&self, action: &str, resource: &str) -> bool {
        let grant = if self.grants.len() <= Self::LINEAR_SEARCH_LIMIT {
            self.grants.iter().find(|grant| grant.permission == action)
        } else {
            self.grants
                .binary_search_by(|grant| grant.permission.as_str().cmp(action))
                .ok()
                .map(|index| &self.grants[index])
        };
        grant.is_some_and(|grant| {
            grant
                .resource_patterns
                .iter()
                .any(|pattern| pattern.matches(resource))
        })
    }
}

impl RbacEngine {
    /// Build an engine from a validated [`RbacPolicy`].
    ///
    /// Returns an error if the policy fails validation.
    pub fn new(policy: RbacPolicy) -> Result<Self, String> {
        policy.validate()?;

        // Step 1: flatten role inheritance into effective (permission, resources) pairs.
        let effective_roles: HashMap<String, Vec<flatten::Grant>> = {
            let mut map = HashMap::new();
            for role in &policy.roles {
                let grants = flatten_role(&role.name, &policy);
                map.insert(role.name.clone(), grants);
            }
            map
        };

        // Step 2: build subject → grants mapping, compiling patterns up front
        // so invalid globs fail the policy load instead of silently denying.
        let mut subject_grants: HashMap<String, CompiledGrants> = HashMap::new();
        let mut wildcard_subject_grants: Vec<(GlobPattern, CompiledGrants)> = Vec::new();
        for assignment in &policy.assignments {
            let mut all_grants = CompiledGrants::default();
            for role_name in &assignment.roles {
                if let Some(grants) = effective_roles.get(role_name) {
                    for grant in grants {
                        all_grants.insert(
                            grant.permission.clone(),
                            grant
                                .resource_patterns
                                .iter()
                                .map(|p| GlobPattern::compile(p, "resource"))
                                .collect::<Result<Vec<_>, _>>()?,
                        );
                    }
                }
            }
            all_grants.sort();
            if is_glob_pattern(&assignment.subject) {
                wildcard_subject_grants.push((
                    GlobPattern::compile(&assignment.subject, "subject")?,
                    all_grants,
                ));
            } else {
                let subject = subject_grants
                    .entry(assignment.subject.clone())
                    .or_default();
                subject.extend(all_grants);
            }
        }

        Ok(Self {
            subject_grants,
            wildcard_subject_grants,
        })
    }

    /// Load an engine directly from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let policy = RbacPolicy::from_yaml(yaml).map_err(|e| format!("YAML parse error: {e}"))?;
        Self::new(policy)
    }
}

impl PolicyEngine for RbacEngine {
    fn check(&self, subject: &SubjectId, action: &str, resource: &ResourceId) -> PolicyResult {
        let subject = subject.as_str();
        let resource = resource.as_str();
        debug!(subject, action, resource, "rbac check");

        let mut matched_subject = false;
        if let Some(grants) = self.subject_grants.get(subject) {
            matched_subject = !grants.is_empty();
            if grants.allows(action, resource) {
                return PolicyResult::Allow;
            }
        }

        for (subject_pattern, grants) in &self.wildcard_subject_grants {
            if !subject_pattern.matches(subject) {
                continue;
            }
            matched_subject |= !grants.is_empty();
            if grants.allows(action, resource) {
                return PolicyResult::Allow;
            }
        }

        if !matched_subject {
            return PolicyResult::Deny(format!("no role assignments for subject '{subject}'"));
        }

        PolicyResult::Deny(format!(
            "no rule grants '{subject}' permission '{action}' on '{resource}'"
        ))
    }
}

#[cfg(test)]
mod tests;
