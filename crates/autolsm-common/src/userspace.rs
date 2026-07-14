//! Types only used on the userspace side of the AutoLSM framework.
//!
//! Gated behind `feature = "userspace"` — these types are never compiled
//! for the eBPF target.

use serde::{Deserialize, Serialize};

// ── Normalized Access Record ───────────────────────────────────────────────

/// A deduplicated access pattern observed in a time window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedAccess {
    /// Full SELinux security context of the subject (e.g. "system_u:system_r:httpd_t:s0")
    pub scontext: String,
    /// Short type name extracted from scontext (e.g. "httpd_t")
    pub scontext_type: String,
    /// Full SELinux security context of the target/object
    pub tcontext: String,
    /// Short type name extracted from tcontext
    pub tcontext_type: String,
    /// SELinux object class (e.g. "file", "tcp_socket", "process")
    pub tclass: String,
    /// SELinux permission (e.g. "open", "read", "write")
    pub perm: String,
    /// The hook that generated this observation
    pub hook_id: u32,
    /// How many times this access pattern was observed in the window
    pub count: u64,
    /// First observation timestamp (ns)
    pub first_seen_ns: u64,
    /// Last observation timestamp (ns)
    pub last_seen_ns: u64,
    /// Whether this access pattern is newly discovered (not in SeenSet)
    pub is_new: bool,
}

// ── Normalizer Input ───────────────────────────────────────────────────────

/// Unified input type that feeds into the Normalizer.
///
/// Two sources converge here:
/// - Collector sends `Observation` from the eBPF RingBuf
/// - AuditConsumer sends `Denial` from the audit log
#[derive(Clone, Debug)]
pub enum NormalizerInput {
    /// A raw eBPF observation — needs PID→context resolution + hook→class mapping
    Observation(super::ObservationEvent),
    /// A parsed SELinux AVC denial — already has scontext/tcontext/tclass/perm
    Denial(AvcDenial),
}

// ── AVC Denial Record ──────────────────────────────────────────────────────

/// A parsed SELinux Access Vector Cache denial from audit.log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvcDenial {
    /// Unix timestamp from the audit message
    pub timestamp_sec: f64,
    /// Serial number from the audit message (msg=audit(timestamp:serial))
    pub serial: u64,
    /// Subject context (scontext= field)
    pub scontext: String,
    /// Short type name from scontext
    pub scontext_type: String,
    /// Target context (tcontext= field)
    pub tcontext: String,
    /// Short type name from tcontext
    pub tcontext_type: String,
    /// Object class (tclass= field)
    pub tclass: String,
    /// Denied permissions (parsed from the denied { … } block)
    pub perms: Vec<String>,
    /// Process ID that triggered the denial
    pub pid: u32,
    /// Command name (comm= field)
    pub comm: String,
    /// Raw audit message for debugging
    pub raw: String,
}

// ── LLM I/O Types ──────────────────────────────────────────────────────────

/// Request sent to the LLM for policy generation or refinement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmRequest {
    pub task: LlmTask,
    pub context: LlmContext,
    /// Unique access patterns observed in the current window
    pub normalized_events: Vec<NormalizedAccess>,
    /// Denials detected in the current window (only for drift/refine tasks)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub drift_denials: Vec<AvcDenial>,
    /// Previously approved rules (only for refine tasks)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub current_rules: Vec<AllowRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmTask {
    GenerateMinimalPolicy,
    RefinePolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmContext {
    /// The SELinux domain being analyzed (e.g. "container_t")
    pub workload_domain: String,
    /// Human-readable description of the workload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_type: Option<String>,
    /// Duration of the observation window in seconds
    pub observed_window_s: u64,
}

/// Response from the LLM containing generated policy rules and alerts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmResponse {
    /// Allow rules that the LLM recommends to install
    pub allow_rules: Vec<AllowRule>,
    /// Anomalous behaviors flagged as potential threats
    #[serde(default)]
    pub alerts: Vec<LlmAlert>,
    /// LLM's confidence in this response [0.0, 1.0]
    pub confidence: f64,
    /// Optional explanation / chain-of-thought
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// A single SELinux allow rule recommendation from the LLM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowRule {
    /// Source type (the subject domain, e.g. "httpd_t")
    pub source_type: String,
    /// Target type (the object type, e.g. "var_log_t")
    pub target_type: String,
    /// SELinux object class (e.g. "file", "dir", "tcp_socket")
    pub tclass: String,
    /// Permissions to allow (e.g. ["read", "open", "getattr"])
    pub perms: Vec<String>,
    /// Brief human rationale for this rule
    pub rationale: String,
}

/// An anomaly / potential attack flagged by the LLM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmAlert {
    pub severity: AlertSeverity,
    pub scontext_type: String,
    pub tcontext_type: String,
    pub tclass: String,
    pub perm: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}
