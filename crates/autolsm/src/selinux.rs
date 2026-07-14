use autolsm_common::AllowRule;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::store::{PolicyStore, StoreError};

/// Manages SELinux policy installation and rollback via `semodule`.
pub struct PolicyLoader {
    tmp_dir: String,
    store: Arc<Mutex<PolicyStore>>,
}

impl PolicyLoader {
    pub fn new(tmp_dir: &str, store: Arc<Mutex<PolicyStore>>) -> Self {
        // Ensure tmp directory exists
        let _ = std::fs::create_dir_all(tmp_dir);
        Self {
            tmp_dir: tmp_dir.to_string(),
            store,
        }
    }

    /// Install a set of allow rules as a CIL policy module.
    ///
    /// Returns the module version name on success.
    pub async fn install(&mut self, rules: &[AllowRule]) -> Result<String, PolicyError> {
        if rules.is_empty() {
            tracing::debug!("empty rule set — skipping install");
            return Err(PolicyError::EmptyRules);
        }

        let cil = Self::to_cil(rules);
        let module_name = self.store.lock().await.next_module_name();
        let file_path = format!("{}/{}.cil", self.tmp_dir, module_name);

        tracing::info!(
            "installing policy module {} ({} rules, {} bytes CIL)",
            module_name,
            rules.len(),
            cil.len(),
        );

        // Write CIL file
        tokio::fs::write(&file_path, &cil)
            .await
            .map_err(|e| PolicyError::Io(e.to_string()))?;

        // Install via semodule -i with 10s timeout
        let output = Command::new("semodule")
            .args(["-i", &file_path])
            .output();

        let status = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            output,
        )
        .await
        {
            Ok(Ok(out)) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::error!("semodule -i failed: {}", stderr);
                    // Clean up the failed module
                    let _ = Command::new("semodule")
                        .args(["-r", &module_name])
                        .output()
                        .await;
                    return Err(PolicyError::InstallFailed(stderr.to_string()));
                }
                out.status
            }
            Ok(Err(e)) => return Err(PolicyError::Io(e.to_string())),
            Err(_) => {
                tracing::error!("semodule -i timed out after 10s");
                return Err(PolicyError::Timeout);
            }
        };

        if status.success() {
            let mut store = self.store.lock().await;
            store.commit(module_name.clone(), cil);
            tracing::info!("policy module {} installed successfully", module_name);
            Ok(module_name)
        } else {
            Err(PolicyError::InstallFailed("unknown error".into()))
        }
    }

    /// Roll back to the previous policy version.
    pub async fn rollback(&mut self) -> Result<(), PolicyError> {
        let bad_version = {
            let mut store = self.store.lock().await;
            store.rollback()?
        };

        tracing::warn!("removing policy module: {}", bad_version);
        let output = Command::new("semodule")
            .args(["-r", &bad_version])
            .output()
            .await
            .map_err(|e| PolicyError::Io(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("semodule -r {} failed: {}", bad_version, stderr);
            return Err(PolicyError::InstallFailed(stderr.to_string()));
        }

        tracing::info!("rollback complete: removed {}", bad_version);
        Ok(())
    }

    /// Convert a slice of AllowRules into CIL (Common Intermediate Language) text.
    fn to_cil(rules: &[AllowRule]) -> String {
        let mut cil = String::new();
        cil.push_str("(handleunknown allow)\n\n");

        // Group rules by (source_type, target_type, tclass) to merge perms
        let mut grouped: std::collections::HashMap<
            (&str, &str, &str),
            Vec<&str>,
        > = std::collections::HashMap::new();

        for rule in rules {
            let key = (
                rule.source_type.as_str(),
                rule.target_type.as_str(),
                rule.tclass.as_str(),
            );
            for perm in &rule.perms {
                grouped.entry(key).or_default().push(perm.as_str());
            }
        }

        // Deduplicate perms and sort
        for ((src, tgt, class), mut perms) in grouped {
            perms.sort();
            perms.dedup();
            let perms_str = perms.join(" ");
            cil.push_str(&format!(
                "(allow {} {} ({}{}{}))\n",
                src, tgt, class,
                if perms_str.is_empty() { "" } else { " " },
                perms_str,
            ));
        }

        cil
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("empty rule set")]
    EmptyRules,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("semodule install failed: {0}")]
    InstallFailed(String),
    #[error("semodule timed out")]
    Timeout,
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_cil_single_rule() {
        let rules = vec![AllowRule {
            source_type: "httpd_t".into(),
            target_type: "var_log_t".into(),
            tclass: "file".into(),
            perms: vec!["read".into(), "append".into()],
            rationale: "test".into(),
        }];
        let cil = PolicyLoader::to_cil(&rules);
        assert!(cil.contains("(handleunknown allow)"));
        assert!(cil.contains("(allow httpd_t var_log_t (file (append read)))"));
    }

    #[test]
    fn test_to_cil_merges_same_target() {
        let rules = vec![
            AllowRule {
                source_type: "httpd_t".into(),
                target_type: "var_log_t".into(),
                tclass: "file".into(),
                perms: vec!["read".into()],
                rationale: "r1".into(),
            },
            AllowRule {
                source_type: "httpd_t".into(),
                target_type: "var_log_t".into(),
                tclass: "file".into(),
                perms: vec!["append".into()],
                rationale: "r2".into(),
            },
        ];
        let cil = PolicyLoader::to_cil(&rules);
        // Should produce exactly one allow statement with both perms
        let allow_count = cil.matches("(allow").count();
        assert_eq!(allow_count, 1);
        assert!(cil.contains("append read") || cil.contains("read append"));
    }
}
