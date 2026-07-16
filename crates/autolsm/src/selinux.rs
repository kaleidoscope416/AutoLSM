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
        let _ = std::fs::create_dir_all(tmp_dir);
        Self { tmp_dir: tmp_dir.to_string(), store }
    }

    /// Install a set of allow rules as a CIL policy module.
    pub async fn install(&mut self, rules: &[AllowRule]) -> Result<String, PolicyError> {
        if rules.is_empty() {
            return Err(PolicyError::EmptyRules);
        }

        let cil = Self::to_cil(rules);
        let module_name = self.store.lock().await.next_module_name();

        tracing::info!(
            "installing policy module {} ({} rules, {} bytes CIL)",
            module_name, rules.len(), cil.len(),
        );

        // Write CIL to temp file (semodule on some systems doesn't support stdin)
        let cil_path = format!("{}/{}.cil", self.tmp_dir, module_name);
        tokio::fs::write(&cil_path, &cil).await
            .map_err(|e| PolicyError::Io(e.to_string()))?;

        let mut child = Command::new("semodule")
            .arg("-i")
            .arg(&cil_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| PolicyError::Io(e.to_string()))?;

        let child_id = child.id().ok_or(PolicyError::Io("child has no pid".into()))?;

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            child.wait_with_output(),
        ).await;

        // Kill the child if it timed out
        match output {
            Ok(Ok(out)) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::error!("semodule -i failed: {}", stderr);
                    let _ = tokio::fs::remove_file(&cil_path).await;
                    return Err(PolicyError::InstallFailed(stderr.to_string()));
                }
                // Clean up temp file
                let _ = tokio::fs::remove_file(&cil_path).await;
                let mut store = self.store.lock().await;
                store.commit(module_name.clone(), cil);
                tracing::info!("policy module {} installed successfully", module_name);
                Ok(module_name)
            }
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&cil_path).await;
                Err(PolicyError::Io(e.to_string()))
            }
            Err(_) => {
                let _ = tokio::process::Command::new("kill")
                    .arg("-9")
                    .arg(child_id.to_string())
                    .output().await;
                let _ = tokio::fs::remove_file(&cil_path).await;
                tracing::error!("semodule -i timed out after 10s — killed pid {}", child_id);
                Err(PolicyError::Timeout)
            }
        }
    }

    pub async fn rollback(&mut self) -> Result<(), PolicyError> {
        let bad_version = {
            let mut store = self.store.lock().await;
            store.rollback()?
        };
        tracing::warn!("removing policy module: {}", bad_version);
        let output = Command::new("semodule")
            .args(["-r", &bad_version]).output().await
            .map_err(|e| PolicyError::Io(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("semodule -r {} failed: {}", bad_version, stderr);
            return Err(PolicyError::InstallFailed(stderr.to_string()));
        }
        tracing::info!("rollback complete: removed {}", bad_version);
        Ok(())
    }

    fn to_cil(rules: &[AllowRule]) -> String {
        let mut cil = String::new();
        let mut grouped: std::collections::HashMap<(&str, &str, &str), Vec<&str>> =
            std::collections::HashMap::new();
        for rule in rules {
            let key = (rule.source_type.as_str(), rule.target_type.as_str(), rule.tclass.as_str());
            for perm in &rule.perms {
                grouped.entry(key).or_default().push(perm.as_str());
            }
        }
        for ((src, tgt, class), mut perms) in grouped {
            perms.sort();
            perms.dedup();
            // CIL format: (allow src tgt (class (perm1 perm2 ...)))
            let perm_list: Vec<String> = perms.iter().map(|p| format!("({})", p)).collect();
            cil.push_str(&format!(
                "(allow {} {} ({} ({})))\n",
                src, tgt, class, perm_list.join(" ")
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
    fn test_to_cil_merges() {
        let rules = vec![
            AllowRule { source_type: "httpd_t".into(), target_type: "var_log_t".into(),
                tclass: "file".into(), perms: vec!["read".into()], rationale: "r1".into() },
            AllowRule { source_type: "httpd_t".into(), target_type: "var_log_t".into(),
                tclass: "file".into(), perms: vec!["append".into()], rationale: "r2".into() },
        ];
        let cil = PolicyLoader::to_cil(&rules);
        assert_eq!(cil.matches("(allow").count(), 1);
        assert!(cil.contains("(read)") && cil.contains("(append)"));
    }
}
