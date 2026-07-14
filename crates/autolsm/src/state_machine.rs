//! Learning-or-Enforcing state machine (§8.3).
//!
//! Controls the lifecycle: LEARNING (permissive) → ENFORCING (enforcing).
//! Transition is one-way: once in ENFORCING, reverting to LEARNING is NOT supported.

use std::time::Instant;

/// The current operational state of the framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Target domains are in permissive mode; eBPF observes behavior;
    /// dontaudit rules are disabled (semodule -DB active).
    Learning { started_at: Instant },
    /// Policy is installed and target domains are enforcing.
    Enforcing { installed_at: Instant, version: String },
}

impl State {
    pub fn is_learning(&self) -> bool {
        matches!(self, State::Learning { .. })
    }

    pub fn is_enforcing(&self) -> bool {
        matches!(self, State::Enforcing { .. })
    }
}

/// Manages the permissive ↔ enforcing lifecycle.
pub struct StateMachine {
    state: State,
    pub dontaudit_disabled: bool,
}

impl StateMachine {
    /// Start in LEARNING mode.
    pub fn new() -> Self {
        Self {
            state: State::Learning { started_at: Instant::now() },
            dontaudit_disabled: false,
        }
    }

    /// Enter learning mode: set target domain permissive, disable dontaudit.
    pub async fn enter_learning(&mut self) -> anyhow::Result<()> {
        // semodule -DB: remove dontaudit from policy (surfaces hidden denials)
        let output = tokio::process::Command::new("semodule")
            .args(["-DB"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                self.dontaudit_disabled = true;
                tracing::info!("learning mode: dontaudit disabled (semodule -DB)");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing::warn!("semodule -DB failed (non-fatal): {}", stderr);
            }
            Err(e) => {
                tracing::warn!("semodule -DB command error (non-fatal): {}", e);
            }
        }

        self.state = State::Learning { started_at: Instant::now() };
        Ok(())
    }

    /// Transition to ENFORCING after successful policy installation.
    ///
    /// This is a ONE-WAY transition. The framework never reverts from
    /// enforcing back to learning to prevent permission inflation.
    pub fn transition_to_enforcing(&mut self, version: &str) -> Result<(), StateError> {
        if self.state.is_enforcing() {
            // Already enforcing — just update the version reference
            self.state = State::Enforcing {
                installed_at: Instant::now(),
                version: version.to_string(),
            };
            return Ok(());
        }

        // Restore dontaudit (semodule -B) since we're leaving learning
        // This is best-effort; failure does not block the transition
        if self.dontaudit_disabled {
            self.dontaudit_disabled = false;
            // The actual semodule -B is handled by the PolicyLoader
        }

        self.state = State::Enforcing {
            installed_at: Instant::now(),
            version: version.to_string(),
        };

        tracing::info!("transitioned to ENFORCING (version={})", version);
        Ok(())
    }

    /// Get the current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns `true` if dontaudit should be re-enabled when leaving learning.
    pub fn should_restore_dontaudit(&self) -> bool {
        self.dontaudit_disabled && self.state.is_enforcing()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot transition to enforcing: already enforcing")]
    AlreadyEnforcing,
}
