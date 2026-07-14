//! AutoLSM daemon — adaptive SELinux policy management via eBPF + LLM.
//!
//! Architecture: three-layer closed loop
//!   Loop A (Discovery): eBPF collect → normalize → LLM → validate → semodule
//!   Loop B (Drift):     AVC denied → PreFilter → normalize → LLM → Δpolicy
//!   Loop C (Alert):     LLM anomaly + PreFilter deny → alert channel

mod audit;
mod collector;
mod llm;
mod normalizer;
mod resolver;
mod selinux;
mod store;
mod validator;

use anyhow::Context;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Adaptive SELinux policy management daemon
#[derive(Parser, Debug)]
#[command(name = "autolsm", version, about)]
struct Cli {
    /// Comma-separated cgroup IDs to observe (e.g. "1234,5678")
    #[arg(long, value_delimiter = ',')]
    target_cgroups: Vec<u64>,

    /// LLM API endpoint (OpenAI-compatible)
    #[arg(long, default_value = "http://localhost:11434/v1")]
    llm_endpoint: String,

    /// LLM model name
    #[arg(long, default_value = "gpt-4o")]
    llm_model: String,

    /// LLM API key (or set AUTOLSM_LLM_KEY env var)
    #[arg(long, env = "AUTOLSM_LLM_KEY")]
    llm_key: Option<String>,

    /// Normalizer batch window in seconds
    #[arg(long, default_value = "60")]
    batch_window_s: u64,

    /// Audit log path
    #[arg(long, default_value = "/var/log/audit/audit.log")]
    audit_log: String,

    /// Temporary directory for CIL module files
    #[arg(long, default_value = "/tmp/autolsm")]
    tmp_dir: String,

    /// Ring buffer size in bytes
    #[arg(long, default_value = "262144")]
    ringbuf_size: u32,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    tracing::info!("AutoLSM daemon starting (version {})", env!("CARGO_PKG_VERSION"));

    // ── Initialize components ───────────────────────────────────────────

    let (normalizer_tx, normalizer_rx) = mpsc::channel::<autolsm_common::NormalizerInput>(4096);
    let (llm_tx, llm_rx) = mpsc::channel::<Vec<autolsm_common::NormalizedAccess>>(64);

    // LLM backend
    let policy_gen: Arc<dyn llm::PolicyGenerator> = if let Some(key) = cli.llm_key.clone() {
        Arc::new(llm::OpenAiPolicyGenerator::new(&cli.llm_endpoint, &cli.llm_model, &key))
    } else {
        Arc::new(llm::NoOpGenerator)
    };

    // Policy store (versioned, with rollback)
    let policy_store = Arc::new(Mutex::new(store::PolicyStore::new(10)));
    let policy_loader = Arc::new(Mutex::new(selinux::PolicyLoader::new(
        &cli.tmp_dir,
        policy_store.clone(),
    )));

    // Resolver (shared by collector and normalizer)
    let resolver = Arc::new(Mutex::new(resolver::Resolver::new()));

    // ── Spawn tasks ─────────────────────────────────────────────────────

    // Collector: loads eBPF, reads RingBuf, sends to normalizer
    let collector_handle = {
        let normalizer_tx = normalizer_tx.clone();
        let resolver = resolver.clone();
        let cgroups = cli.target_cgroups.clone();
        tokio::spawn(async move {
            if let Err(e) = collector::run(cgroups, cli.ringbuf_size, normalizer_tx, resolver).await {
                tracing::error!("Collector task failed: {e}");
            }
        })
    };

    // Audit consumer: reads audit.log, applies PreFilter, sends to normalizer
    let audit_handle = {
        let normalizer_tx = normalizer_tx.clone();
        let audit_path = cli.audit_log.clone();
        tokio::spawn(async move {
            if let Err(e) = audit::run(&audit_path, normalizer_tx).await {
                tracing::error!("Audit consumer failed: {e}");
            }
        })
    };

    // Normalizer: deduplicates, batches, sends to LLM
    let normalizer_handle = {
        let llm_tx = llm_tx.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = normalizer::run(
                normalizer_rx,
                llm_tx,
                resolver,
                cli.batch_window_s,
            )
            .await
            {
                tracing::error!("Normalizer failed: {e}");
            }
        })
    };

    // LLM loop: receives batches, calls LLM, validates, installs policy
    let llm_handle = tokio::spawn(async move {
        if let Err(e) = llm::run(
            llm_rx,
            policy_gen,
            policy_loader,
            cli.llm_model.clone(),
        )
        .await
        {
            tracing::error!("LLM loop failed: {e}");
        }
    });

    // ── Wait for shutdown signal ────────────────────────────────────────

    tracing::info!("All tasks started — waiting for Ctrl+C");

    tokio::signal::ctrl_c().await.context("failed to listen for Ctrl+C")?;

    tracing::info!("Shutting down...");
    collector_handle.abort();
    audit_handle.abort();
    normalizer_handle.abort();
    llm_handle.abort();

    Ok(())
}
