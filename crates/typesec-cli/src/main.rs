//! # typesec CLI
//!
//! Commands:
//! - `validate` — parse and validate a policy YAML file
//! - `check`    — evaluate a single (subject, action, resource) query
//! - `generate` — emit typed Rust code from an RBAC policy
//! - `run`      — simulate agent execution under a policy

#![forbid(unsafe_code)]
#![warn(clippy::all)]

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "typesec",
    about = "Type-level AI security policy enforcement CLI",
    version
)]
struct Cli {
    /// Enable verbose logging (set RUST_LOG=debug for full detail).
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and validate a policy YAML file.
    Validate(commands::validate::ValidateArgs),
    /// Check whether a subject may perform an action on a resource.
    Check(commands::check::CheckArgs),
    /// Generate typed Rust code from an RBAC policy.
    Generate(commands::generate::GenerateArgs),
    /// Simulate agent execution under a policy.
    Run(commands::run::RunArgs),
    /// Front an MCP server, enforcing a policy on every tools/call.
    McpGate(commands::mcp_gate::McpGateArgs),
    /// Re-evaluate a recorded decision log against an edited policy.
    Replay(commands::replay::ReplayArgs),
    /// Run an OpenAI/Anthropic-compatible enforcement proxy.
    Proxy(commands::proxy::ProxyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise tracing. RUST_LOG env var takes precedence; default to info.
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Validate(args) => commands::validate::run(args),
        Commands::Check(args) => commands::check::run(args),
        Commands::Generate(args) => commands::generate::run(args),
        Commands::Run(args) => commands::run::run(args).await,
        Commands::McpGate(args) => commands::mcp_gate::run(args).await,
        Commands::Replay(args) => commands::replay::run(args),
        Commands::Proxy(args) => commands::proxy::run(args).await,
    }
}
