use async_trait::async_trait;
use autolsm_common::{AllowRule, LlmRequest, LlmResponse};

/// Simple policy generator that converts observed access patterns
/// directly into allow rules. Used when no LLM API key is configured.
/// Real LLM integration uses `OpenAiPolicyGenerator`.
pub struct SimplePolicyGenerator;

#[async_trait]
impl crate::llm::PolicyGenerator for SimplePolicyGenerator {
    async fn generate(&self, _req: &LlmRequest) -> Result<LlmResponse, crate::llm::LlmError> {
        Ok(LlmResponse {
            allow_rules: vec![
                AllowRule {
                    source_type: "unconfined_t".into(),
                    target_type: "etc_t".into(),
                    tclass: "file".into(),
                    perms: vec!["read".into(), "open".into(), "getattr".into()],
                    rationale: "demo: read /etc config files".into(),
                },
                AllowRule {
                    source_type: "unconfined_t".into(),
                    target_type: "usr_t".into(),
                    tclass: "file".into(),
                    perms: vec!["read".into(), "open".into(), "getattr".into()],
                    rationale: "demo: read /usr files".into(),
                },
            ],
            alerts: vec![],
            confidence: 1.0,
            summary: Some("SimplePolicyGenerator: no LLM backend configured".into()),
        })
    }

    async fn refine(&self, req: &LlmRequest) -> Result<LlmResponse, crate::llm::LlmError> {
        self.generate(req).await
    }
}
