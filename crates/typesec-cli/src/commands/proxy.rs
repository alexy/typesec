//! `typesec proxy` — an OpenAI/Anthropic-compatible enforcement proxy.
//!
//! Point any SDK's base URL at the proxy and every request flows to the real
//! upstream — except that tool authority is enforced in both directions:
//!
//! - **Requests** (`--filter-tools`): the `tools` array is filtered
//!   policy-aware, so the model is never offered a tool the subject may not
//!   call.
//! - **Responses**: denied tool calls are scrubbed — removed from the
//!   message and replaced with a visible `[typesec]` refusal — so the client
//!   never executes them.
//!
//! Chat Completions (`…/chat/completions`, OpenAI dialect) and Messages
//! (`…/messages`, Anthropic dialect) are enforced; every other path is
//! passed through untouched. Streaming responses are not yet supported on
//! enforced paths: requests with `"stream": true` are rejected with 400.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use clap::Args;
use serde_json::Value;
use typesec_agent::interop::ToolCallGuard;
use typesec_agent::interop::dialects::{Dialect, dialect};
use typesec_core::policy::{RequestContext, SubjectId};

use super::engine::{detect_format, load_engine, request_context};

mod scrub;
use scrub::{filter_request_tools, scrub_response};

/// CLI arguments for `typesec proxy`.
#[derive(Args)]
pub struct ProxyArgs {
    /// Policy file (RBAC, ODRL, or graph YAML).
    #[arg(long)]
    policy: PathBuf,
    /// Policy format override: rbac | odrl | graph.
    #[arg(long)]
    format: Option<String>,
    /// Subject the proxied agent acts as.
    #[arg(long)]
    subject: String,
    /// Tool bindings YAML (same schema as `mcp-gate --bindings`).
    #[arg(long)]
    bindings: PathBuf,
    /// Upstream base URL, e.g. https://api.openai.com or https://api.anthropic.com.
    #[arg(long)]
    upstream: String,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8095")]
    listen: String,
    /// Purpose attached to every policy check.
    #[arg(long)]
    purpose: Option<String>,
    /// Also filter request `tools` arrays down to callable tools.
    #[arg(long)]
    filter_tools: bool,
}

/// Shared proxy state: the guard plus forwarding machinery.
pub(crate) struct ProxyState {
    pub(crate) guard: ToolCallGuard,
    pub(crate) subject: SubjectId,
    pub(crate) ctx: RequestContext,
    pub(crate) filter_tools: bool,
    upstream: String,
    client: reqwest::Client,
}

/// Which enforcement dialect a request path gets, if any.
fn dialect_for_path(path: &str) -> Option<&'static Dialect> {
    if path.ends_with("/chat/completions") {
        dialect("openai")
    } else if path.ends_with("/messages") {
        dialect("anthropic")
    } else {
        None
    }
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let policy_yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("failed to read policy {}", args.policy.display()))?;
    let format = detect_format(&args.format, &policy_yaml);
    let engine = load_engine(format.as_deref(), &policy_yaml)?;
    let bindings_yaml = std::fs::read_to_string(&args.bindings)
        .with_context(|| format!("failed to read bindings {}", args.bindings.display()))?;
    let bindings = serde_yaml::from_str(&bindings_yaml).context("failed to parse bindings YAML")?;
    let guard = super::mcp_gate::build_guard(engine, bindings)?;

    let state = Arc::new(ProxyState {
        guard,
        subject: SubjectId::from(args.subject.as_str()),
        ctx: request_context(args.purpose.as_deref()),
        filter_tools: args.filter_tools,
        upstream: args.upstream.trim_end_matches('/').to_string(),
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
    });

    let app = axum::Router::new()
        .fallback(axum::routing::any(handle))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    tracing::info!(listen = %args.listen, upstream = %args.upstream, "typesec proxy ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(
    State(state): State<Arc<ProxyState>>,
    method: axum::http::Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match forward(&state, method, &uri, headers, body).await {
        Ok(response) => response,
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("typesec proxy error: {err}"),
        )
            .into_response(),
    }
}

async fn forward(
    state: &ProxyState,
    method: axum::http::Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), ToString::to_string);
    let enforced = dialect_for_path(uri.path());

    // Rewrite the request body when this path is enforced.
    let body = match (enforced, method == axum::http::Method::POST) {
        (Some(codec), true) => {
            let mut request: Value =
                serde_json::from_slice(&body).context("request body is not valid JSON")?;
            if request.get("stream").and_then(Value::as_bool) == Some(true) {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    "typesec proxy does not yet enforce streaming responses; \
                     set stream=false or use an unenforced path",
                )
                    .into_response());
            }
            filter_request_tools(state, codec, &mut request);
            Bytes::from(serde_json::to_vec(&request)?)
        }
        _ => body,
    };

    let mut upstream_headers = headers.clone();
    upstream_headers.remove(axum::http::header::HOST);
    upstream_headers.remove(axum::http::header::CONTENT_LENGTH);
    let upstream_response = state
        .client
        .request(method, format!("{}{path_and_query}", state.upstream))
        .headers(upstream_headers)
        .body(body)
        .send()
        .await
        .context("upstream request failed")?;

    let status = upstream_response.status();
    let mut response_headers = upstream_response.headers().clone();
    response_headers.remove(axum::http::header::CONTENT_LENGTH);
    response_headers.remove(axum::http::header::TRANSFER_ENCODING);
    let response_body = upstream_response
        .bytes()
        .await
        .context("failed to read upstream response")?;

    // Scrub denied tool calls out of enforced JSON responses.
    let response_body = match (enforced, status.is_success()) {
        (Some(codec), true) => match serde_json::from_slice::<Value>(&response_body) {
            Ok(mut json) => {
                scrub_response(state, codec, &mut json);
                Bytes::from(serde_json::to_vec(&json)?)
            }
            Err(_) => response_body, // non-JSON success (unexpected): pass through
        },
        _ => response_body,
    };

    let mut response = Response::new(axum::body::Body::from(response_body));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}

#[cfg(test)]
mod tests;
