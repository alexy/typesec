//! `OllamaExtractor` (`ollama` feature): local-model memory extraction.
//!
//! Runs the extraction prompt against a **local** Ollama instance, so raw —
//! possibly sensitive — episodes never leave the boundary. Like every
//! [`Extractor`], it is untrusted by construction: it emits drafts carrying
//! the *episode's* provenance (a model-text episode still quarantines no
//! matter what the model says), and nothing is written except through the
//! capability-gated vault.
//!
//! Output contract with the model: a JSON array of `{"text": ..., "kind"?:
//! episodic|semantic|procedural|profile}` objects. Anything else is an
//! [`ExtractError`] — malformed model output fails the extraction rather
//! than smuggling free text into memory.

use std::sync::Arc;

use serde_json::{Value, json};
use typesec_integrations::{HttpClient, ReqwestHttpClient};

use super::{Episode, ExtractError, Extractor, MemorySummary};
use crate::record::{MemoryContent, MemoryDraft};
use crate::space::MemoryKind;

/// Extraction system prompt: forces the JSON-array output contract.
const SYSTEM_PROMPT: &str = "You extract durable memories from an episode. \
Respond with ONLY a JSON array; each element is an object with a \"text\" \
field (one self-contained fact) and an optional \"kind\" field, one of \
\"episodic\", \"semantic\", \"procedural\", \"profile\". Do not repeat facts \
already known. No prose, no code fences.";

/// An [`Extractor`] backed by a local Ollama model.
pub struct OllamaExtractor {
    base_url: String,
    model: String,
    http: Arc<dyn HttpClient>,
}

impl OllamaExtractor {
    /// Create an extractor for `model` at `base_url` (e.g.
    /// `http://localhost:11434`) using reqwest.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self::with_http(base_url, model, Arc::new(ReqwestHttpClient::new()))
    }

    /// Create an extractor with an injected HTTP client (tests).
    pub fn with_http(
        base_url: impl Into<String>,
        model: impl Into<String>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            model: model.into(),
            http,
        }
    }

    fn chat_endpoint(&self) -> String {
        format!("{}/api/chat", self.base_url)
    }

    fn request_body(&self, episode: &Episode, existing: &[MemorySummary]) -> Value {
        let known = if existing.is_empty() {
            String::from("(none)")
        } else {
            existing
                .iter()
                .map(|m| format!("- {}", m.gist))
                .collect::<Vec<_>>()
                .join("\n")
        };
        json!({
            "model": self.model,
            "stream": false,
            "format": "json",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",
                 "content": format!("Already known:\n{known}\n\nEpisode:\n{}", episode.text)},
            ],
        })
    }
}

/// Parse the model's `message.content` under the output contract.
fn parse_drafts(response: &Value, episode: &Episode) -> Result<Vec<MemoryDraft>, ExtractError> {
    let content = response
        .pointer("/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Backend("ollama response has no message.content".into()))?;
    let items: Vec<Value> = serde_json::from_str(content)
        .map_err(|err| ExtractError::Backend(format!("model output is not a JSON array: {err}")))?;

    items
        .iter()
        .map(|item| {
            let text = item.get("text").and_then(Value::as_str).ok_or_else(|| {
                ExtractError::Backend("extracted item is missing string 'text'".into())
            })?;
            let kind = match item.get("kind").and_then(Value::as_str) {
                Some("episodic") => MemoryKind::Episodic,
                Some("procedural") => MemoryKind::Procedural,
                Some("profile") => MemoryKind::Profile,
                _ => MemoryKind::Semantic,
            };
            // The draft carries the *episode's* provenance — the model cannot
            // upgrade its own trust.
            Ok(MemoryDraft::new(
                kind,
                MemoryContent::text(text),
                episode.provenance.clone(),
            ))
        })
        .collect()
}

impl Extractor for OllamaExtractor {
    fn extract(
        &self,
        episode: &Episode,
        existing: &[MemorySummary],
    ) -> Result<Vec<MemoryDraft>, ExtractError> {
        let response = self
            .http
            .post_json(
                &self.chat_endpoint(),
                &[],
                &self.request_body(episode, existing),
            )
            .map_err(|err| ExtractError::Backend(format!("ollama request failed: {err}")))?;
        parse_drafts(&response, episode)
    }
}

#[cfg(test)]
mod tests;
