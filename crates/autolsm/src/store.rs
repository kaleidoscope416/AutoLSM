//! Policy store for versioned CIL module management with rollback.

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Stores versioned CIL policy modules with bounded history for rollback.
pub struct PolicyStore {
    activations: VecDeque<Activation>,
    max_history: usize,
}

struct Activation {
    version: String,
    cil_content: String,
    installed_at: Instant,
}

impl PolicyStore {
    pub fn new(max_history: usize) -> Self {
        Self {
            activations: VecDeque::new(),
            max_history,
        }
    }

    /// Generate the next module name: `autolsm_<unix_timestamp>`
    pub fn next_module_name(&self) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("autolsm_{}", ts)
    }

    /// Commit a newly installed module to the version history.
    /// Oldest entries are evicted when max_history is exceeded.
    pub fn commit(&mut self, name: String, cil: String) {
        self.activations.push_back(Activation {
            version: name,
            cil_content: cil,
            installed_at: Instant::now(),
        });
        while self.activations.len() > self.max_history {
            self.activations.pop_front();
        }
        tracing::info!(
            "policy committed: {} (history: {}/{})",
            self.activations.back().unwrap().version,
            self.activations.len(),
            self.max_history,
        );
    }

    /// Return the currently active version name, if any.
    pub fn current_version(&self) -> Option<&str> {
        self.activations.back().map(|a| a.version.as_str())
    }

    /// Roll back: remove the latest activation and return its name for `semodule -r`.
    ///
    /// Returns `Err` if there are fewer than 2 versions (nothing to roll back to).
    pub fn rollback(&mut self) -> Result<String, StoreError> {
        if self.activations.len() < 2 {
            return Err(StoreError::InsufficientHistory);
        }
        let bad = self.activations.pop_back().unwrap();
        tracing::warn!(
            "rolling back policy {} (reverting to {})",
            bad.version,
            self.activations.back().map(|a| a.version.as_str()).unwrap_or("none"),
        );
        Ok(bad.version)
    }

    /// List all versions for introspection.
    pub fn versions(&self) -> Vec<String> {
        self.activations.iter().map(|a| a.version.clone()).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("insufficient history for rollback")]
    InsufficientHistory,
}
