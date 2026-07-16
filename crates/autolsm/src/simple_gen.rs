use async_trait::async_trait;
use autolsm_common::{AllowRule, LlmRequest, LlmResponse};

/// Deterministic policy generator: converts each observed access pattern
/// into a corresponding allow rule. Used when no LLM API key is configured.
///
/// Unlike audit2allow, this generator:
/// - Groups perms for the same (source, target, class) into a single rule
/// - Skips unresolved/generic/unknown types (no matchpathcon resolution)
/// - Marks the first occurrence as rationale
///
/// For semantic analysis (distinguishing legitimate access from attack),
/// configure --llm-key to use OpenAiPolicyGenerator.
pub struct SimplePolicyGenerator;

#[async_trait]
impl crate::llm::PolicyGenerator for SimplePolicyGenerator {
    async fn generate(&self, req: &LlmRequest) -> Result<LlmResponse, crate::llm::LlmError> {
        use std::collections::HashMap;

        // Group perms by (source, target, class)
        let mut grouped: HashMap<(&str, &str, &str), (Vec<String>, &str)> = HashMap::new();

        for evt in &req.normalized_events {
            // Skip unresolved/generic/unknown types — these mean matchpathcon or resolver failed
            if evt.scontext_type == "unknown_t"
                || evt.tcontext_type == "unknown_t"
                || evt.tcontext_type == "generic_t"
                || evt.tcontext_type == "unresolved_t"
            {
                continue;
            }

            let key = (
                evt.scontext_type.as_str(),
                evt.tcontext_type.as_str(),
                evt.tclass.as_str(),
            );

            let entry = grouped
                .entry(key)
                .or_insert_with(|| (Vec::new(), evt.scontext_type.as_str()));
            if !entry.0.contains(&evt.perm) {
                entry.0.push(evt.perm.clone());
            }
        }

        let rules: Vec<AllowRule> = grouped
            .into_iter()
            .map(|((src, tgt, cls), (perms, _))| {
                let mut sorted_perms = perms;
                sorted_perms.sort();
                AllowRule {
                    source_type: src.to_string(),
                    target_type: tgt.to_string(),
                    tclass: cls.to_string(),
                    perms: sorted_perms,
                    rationale: format!("observed from {}", src),
                }
            })
            .collect();

        let rule_count = rules.len();
        let event_count = req.normalized_events.len();
        Ok(LlmResponse {
            allow_rules: rules,
            alerts: vec![],
            confidence: 1.0,
            summary: Some(format!(
                "SimplePolicyGenerator: {} rules from {} events (no LLM)",
                rule_count, event_count
            )),
        })
    }

    async fn refine(&self, req: &LlmRequest) -> Result<LlmResponse, crate::llm::LlmError> {
        self.generate(req).await
    }
}
