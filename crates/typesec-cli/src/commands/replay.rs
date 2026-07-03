//! `typesec replay` — re-evaluate a recorded decision log against a policy.
//!
//! `typesec check --audit-log decisions.jsonl` appends one JSONL
//! [`DecisionRecord`] per decision. `typesec replay --policy new.yaml --log
//! decisions.jsonl` re-runs every recorded question against the (presumably
//! edited) policy and reports verdicts that changed — so a policy change is
//! testable against real traffic *before* rollout. Exit code 0 means no
//! drift; 1 means at least one verdict changed.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use typesec_core::policy::{PolicyEngine, PolicyResult};
use typesec_core::{ResourceId, SubjectId};

use super::engine::{detect_format, load_engine, request_context};

/// One recorded policy decision (one JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// RFC 3339 timestamp of the original decision.
    pub ts: String,
    /// Subject the decision was made for.
    pub subject: String,
    /// Action that was requested.
    pub action: String,
    /// Resource the action targeted.
    pub resource: String,
    /// Purpose context, when one was supplied.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub purpose: Option<String>,
    /// Verdict kind: `allow`, `deny`, or `delegate`.
    pub decision: String,
    /// Deny/delegate rationale, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

impl DecisionRecord {
    /// Build a record for a decision made now.
    pub fn new(
        subject: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
        result: &PolicyResult,
    ) -> Self {
        let (decision, reason) = decision_parts(result);
        Self {
            ts: chrono_now_rfc3339(),
            subject: subject.to_owned(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            purpose: purpose.map(str::to_owned),
            decision: decision.to_owned(),
            reason,
        }
    }
}

fn chrono_now_rfc3339() -> String {
    typesec_core::policy::format_audit_timestamp(&chrono::Utc::now())
}

/// Map a verdict to its recorded kind and rationale.
pub fn decision_parts(result: &PolicyResult) -> (&'static str, Option<String>) {
    match result {
        PolicyResult::Allow => ("allow", None),
        PolicyResult::Deny(reason) => ("deny", Some(reason.clone())),
        PolicyResult::Delegate(reason) => ("delegate", Some(reason.to_string())),
        _ => ("unknown", None),
    }
}

/// Append one record to a JSONL decision log, creating the file if needed.
pub fn append_record(path: &PathBuf, record: &DecisionRecord) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open audit log {}", path.display()))?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    Ok(())
}

/// A recorded decision whose verdict changed under the new policy.
#[derive(Debug, Serialize)]
pub struct ReplayChange {
    /// The original record.
    #[serde(flatten)]
    pub record: DecisionRecord,
    /// The verdict the new policy produces.
    pub new_decision: String,
    /// The new deny/delegate rationale, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_reason: Option<String>,
}

/// Re-evaluate every record against `engine`; return `(replayed, changes)`.
pub fn replay_records(
    engine: &dyn PolicyEngine,
    records: impl IntoIterator<Item = DecisionRecord>,
) -> (usize, Vec<ReplayChange>) {
    let mut replayed = 0;
    let mut changes = Vec::new();
    for record in records {
        replayed += 1;
        let ctx = request_context(record.purpose.as_deref());
        let result = engine.check_with_context(
            &SubjectId::from(record.subject.as_str()),
            &record.action,
            &ResourceId::from(record.resource.as_str()),
            &ctx,
        );
        let (new_decision, new_reason) = decision_parts(&result);
        if new_decision != record.decision {
            changes.push(ReplayChange {
                record,
                new_decision: new_decision.to_owned(),
                new_reason,
            });
        }
    }
    (replayed, changes)
}

/// CLI arguments for `typesec replay`.
#[derive(Args)]
pub struct ReplayArgs {
    /// The (edited) policy to replay the log against.
    #[arg(long)]
    pub policy: PathBuf,
    /// Policy format: `rbac`, `odrl`, or `graph`.
    #[arg(long)]
    pub format: Option<String>,
    /// JSONL decision log written by `typesec check --audit-log`.
    #[arg(long)]
    pub log: PathBuf,
    /// Print changes as JSON lines instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: ReplayArgs) -> Result<()> {
    let yaml = std::fs::read_to_string(&args.policy)?;
    let format = detect_format(&args.format, &yaml);
    let engine = load_engine(format.as_deref(), &yaml)?;

    let log = std::fs::read_to_string(&args.log)
        .with_context(|| format!("failed to read decision log {}", args.log.display()))?;
    let records: Vec<DecisionRecord> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("malformed decision log line"))
        .collect::<Result<_>>()?;

    let (replayed, changes) = replay_records(engine.as_ref(), records);

    if args.json {
        for change in &changes {
            println!("{}", serde_json::to_string(change)?);
        }
    } else {
        for change in &changes {
            println!(
                "CHANGED {} → {}  {} {} {}{}",
                change.record.decision,
                change.new_decision,
                change.record.subject,
                change.record.action,
                change.record.resource,
                change
                    .new_reason
                    .as_deref()
                    .map(|r| format!("  ({r})"))
                    .unwrap_or_default(),
            );
        }
        println!("{replayed} decision(s) replayed, {} changed", changes.len());
    }
    if !changes.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
