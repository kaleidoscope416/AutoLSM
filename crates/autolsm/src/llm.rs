use async_trait::async_trait;
use autolsm_common::{LlmRequest, LlmResponse, LlmTask, NormalizedAccess};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::selinux::PolicyLoader;
use crate::validator::{self, default_deny_sources};

/// Trait abstracting the LLM backend for policy generation.
#[async_trait]
pub trait PolicyGenerator: Send + Sync {
    /// Generate a new minimal-privilege policy from observed behavior.
    async fn generate(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError>;

    /// Refine an existing policy based on new drift denials.
    async fn refine(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError>;
}

/// OpenAI-compatible API backend.
pub struct OpenAiPolicyGenerator {
    endpoint: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl OpenAiPolicyGenerator {
    pub fn new(endpoint: &str, model: &str, api_key: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PolicyGenerator for OpenAiPolicyGenerator {
    async fn generate(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        self.call_api(req).await
    }

    async fn refine(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        self.call_api(req).await
    }
}

impl OpenAiPolicyGenerator {
    async fn call_api(&self, req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let system_prompt = Self::system_prompt();
        let user_prompt = serde_json::to_string(req)
            .map_err(|e| LlmError::Serialization(e.to_string()))?;

        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user", "content": user_prompt }
            ],
            "temperature": 0.1,
            "response_format": { "type": "json_object" }
        });

        let url = format!("{}/chat/completions", self.endpoint);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Http(e.to_string()))?;

        let status = response.status();
        let text = response.text().await.map_err(|e| LlmError::Http(e.to_string()))?;

        if !status.is_success() {
            return Err(LlmError::Api(format!("HTTP {}: {}", status.as_u16(), text)));
        }

        // Extract the assistant's message content from the OpenAI response
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| LlmError::Serialization(e.to_string()))?;

        let content = parsed["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| LlmError::Serialization("missing choices[0].message.content".into()))?;

        let llm_response: LlmResponse = serde_json::from_str(content)
            .map_err(|e| LlmError::Serialization(format!("failed to parse LLM output: {}", e)))?;

        Ok(llm_response)
    }

    fn system_prompt() -> &'static str {
        r#"You are a SELinux policy generator. Given observed process behaviors (from eBPF LSM hooks),
produce a minimal-privilege set of allow rules in JSON format.

Key rules:
1. Only produce standard CIL allow rules. Do NOT generate:
   - type_transition, type_change, or type_member rules
   - capability rules using wildcards
   - new type declarations (use only existing types from the input)
   - wildcards ("*") in any field

2. Each allow rule MUST include a concise "rationale" field explaining why this access is needed.

3. Flag any anomalous access patterns as "alerts":
   - Access to sensitive paths (/etc/shadow, /etc/passwd, /root)
   - Access outside the workload's expected scope
   - Suspicious socket connections

4. Provide a "confidence" score (0.0-1.0) for your response.

5. Group related permissions for the same (source_type, target_type, tclass) into one rule.

6. Alert severities: "low", "medium", "high", or "critical".

Output EXACTLY this JSON schema, no extra text outside the JSON object:
{
  "allow_rules": [
    {
      "source_type": "<string>",
      "target_type": "<string>",
      "tclass": "<string>",
      "perms": ["<string>"],
      "rationale": "<string>"
    }
  ],
  "alerts": [
    {
      "severity": "<low|medium|high|critical>",
      "scontext_type": "<string>",
      "tcontext_type": "<string>",
      "tclass": "<string>",
      "perm": "<string>",
      "reason": "<string>"
    }
  ],
  "confidence": 0.0,
  "summary": "<optional string>"
}
"#      }
}

/// No-op generator for testing without an LLM backend.
pub struct NoOpGenerator;

#[async_trait]
impl PolicyGenerator for NoOpGenerator {
    async fn generate(&self, _req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        tracing::info!("NoOpGenerator: returning empty policy (no LLM backend)");
        Ok(LlmResponse {
            allow_rules: vec![],
            alerts: vec![],
            confidence: 1.0,
            summary: Some("no-op generator — no LLM backend configured".into()),
        })
    }

    async fn refine(&self, _req: &LlmRequest) -> Result<LlmResponse, LlmError> {
        self.generate(_req).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("validation error: {0}")]
    Validation(#[from] crate::validator::ValidationError),
}

/// Main LLM processing loop.
///
/// 1. Receives batches from the Normalizer
/// 2. Builds LlmRequest, calls PolicyGenerator
/// 3. Validates response
/// 4. Installs approved rules via PolicyLoader
pub async fn run(
    mut rx: mpsc::Receiver<Vec<NormalizedAccess>>,
    generator: Arc<dyn PolicyGenerator>,
    policy_loader: Arc<Mutex<PolicyLoader>>,
    _model: String,
) -> anyhow::Result<()> {
    tracing::info!("LLM loop started");

    let deny_sources = default_deny_sources();

    while let Some(batch) = rx.recv().await {
        tracing::info!("LLM loop: received batch of {} events", batch.len());

        if batch.is_empty() {
            continue;
        }

        // Build the request
        let scontext_types: Vec<&str> = batch
            .iter()
            .map(|e| e.scontext_type.as_str())
            .collect();
        let main_domain = scontext_types.first().copied().unwrap_or("unknown_t");

        let request = LlmRequest {
            task: LlmTask::GenerateMinimalPolicy,
            context: autolsm_common::LlmContext {
                workload_domain: main_domain.to_string(),
                workload_type: None,
                observed_window_s: 60,
            },
            normalized_events: batch.clone(),
            drift_denials: vec![],
            current_rules: vec![],
        };

        // Call the LLM
        let response = match generator.generate(&request).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("LLM generate failed: {}", e);
                continue;
            }
        };

        tracing::info!(
            "LLM response: {} allow rules, {} alerts, confidence={:.2}",
            response.allow_rules.len(),
            response.alerts.len(),
            response.confidence,
        );

        // Check confidence threshold
        if response.confidence < 0.7 {
            tracing::warn!(
                "LLM confidence ({:.2}) below threshold — skipping install",
                response.confidence,
            );
            for alert in &response.alerts {
                tracing::warn!(
                    "alert [{:?}]: {} → {} : {} {} — {}",
                    alert.severity,
                    alert.scontext_type,
                    alert.tcontext_type,
                    alert.tclass,
                    alert.perm,
                    alert.reason,
                );
            }
            continue;
        }

        // Build known_types from the batch
        let mut known_types = std::collections::HashSet::new();
        for event in &batch {
            known_types.insert(event.scontext_type.clone());
            known_types.insert(event.tcontext_type.clone());
        }

        // Validate
        match validator::validate(&response.allow_rules, &known_types, &deny_sources) {
            Ok(()) => {
                tracing::info!("validation passed — {} rules approved", response.allow_rules.len());
            }
            Err(e) => {
                tracing::error!("validation failed: {} — skipping install", e);
                continue;
            }
        }

        // Install
        if !response.allow_rules.is_empty() {
            let mut loader = policy_loader.lock().await;
            match loader.install(&response.allow_rules).await {
                Ok(version) => {
                    tracing::info!("policy installed: {}", version);
                }
                Err(e) => {
                    tracing::error!("policy install failed: {} — rolling back", e);
                    let _ = loader.rollback().await;
                }
            }
        }
    }

    tracing::info!("LLM loop exiting");
    Ok(())
}
