/// Path: PanicMode/src/action/builder.rs
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::detector::CircuitBreaker;
use crate::storage::IncidentStorage;

use super::executor::ActionExecutor;
use super::middleware::BreakerWrapped;
use super::registry::ActionRegistry;
use super::r#trait::ActionType;
use super::implementations::{FirewallAction, ProcessAction, SnapshotAction, ScriptAction};

/// Single place for creating and wiring all dependencies.
///
/// # Principles:
/// - Composition root: creates actions, breakers, wraps them in middleware
/// - Fluent API: builder.with_firewall().with_process().build()
/// - **Fail-fast**: build() validates consistency and returns Err
///   if the system cannot serve any of the configured actions
///
/// # Guarantee:
/// If `build()` returns `Ok` — the system is fully consistent.
/// If not — the system does not start.
pub struct ActionExecutorBuilder {
    config: Arc<Config>,
    registry: ActionRegistry,
    errors: Vec<String>,
}

impl ActionExecutorBuilder {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            registry: ActionRegistry::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_firewall(mut self, storage: Arc<IncidentStorage>) -> Self {
        match FirewallAction::new(self.config.clone(), storage) {
            Ok(action) => {
                let breaker = self.default_breaker();
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::BlockIp, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("FirewallAction: {}", e));
            }
        }
        self
    }

    pub fn with_process(mut self) -> Self {
        match ProcessAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    self.base_breaker()
                        .with_concurrency_limit(3)
                        .with_timeout(Duration::from_secs(5)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::FreezeTopProcess, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("ProcessAction: {}", e));
            }
        }
        self
    }

    pub fn with_snapshot(mut self) -> Self {
        match SnapshotAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    CircuitBreaker::new(
                        3,
                        self.config.circuit_breakers.failure_window,
                        self.config.circuit_breakers.open_duration,
                    )
                    .with_concurrency_limit(self.config.circuit_breakers.max_concurrency)
                    .with_timeout(Duration::from_secs(30)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::Snapshot, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("SnapshotAction: {}", e));
            }
        }
        self
    }

    pub fn with_script(mut self) -> Self {
        match ScriptAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    self.base_breaker()
                        .with_timeout(Duration::from_secs(60)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::RunScript, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("ScriptAction: {}", e));
            }
        }
        self
    }

    /// Build the executor with two-level validation.
    ///
    /// # Fatal (Err):
    /// - No actions could be created (registry is empty)
    ///
    /// # Degradable (warn + continue):
    /// - A specific action failed to initialize (missing binary, no permission)
    /// - Monitor is partially covered — as long as alerts work, the system is useful
    ///
    /// If `build()` returns `Ok` — the system can handle at least something.
    pub fn build(self) -> Result<ActionExecutor> {
        // Degradable: log initialization errors but do not crash
        if !self.errors.is_empty() {
            for err in &self.errors {
                tracing::warn!("⚠️  Action creation failed (degraded): {}", err);
            }
        }

        // Fatal: registry is empty — system is completely blind
        let registered = self.registry.registered_types();
        if registered.is_empty() {
            bail!("No actions registered — system cannot handle any incidents");
        }

        // Degradable: warn about partial action coverage.
        //
        // Bug #10: AlertCritical / AlertWarning / AlertInfo are NOT
        // ActionExecutor actions — they're routed through AlertDispatcher
        // via the alert_tx channel. Filter them out of the missing set
        // so genuine misconfiguration isn't drowned in cosmetic noise.
        //
        // Bug #26: several action variants are documented in examples and
        // accepted by the parser, but no implementation exists in the
        // registry yet (mass_freeze, mass_freeze_top, mass_freeze_cluster,
        // kill_process, rate_limit). A user copying from examples/config.yaml
        // would see a generic "missing actions" warning and reasonably
        // assume they typed a name wrong, when in fact the feature itself
        // is not yet shipped. Split the report so each kind gets the
        // correct treatment and message.
        let is_dispatcher_action = |at: &crate::action::ActionType| -> bool {
            use crate::action::ActionType::*;
            matches!(at, AlertCritical | AlertWarning | AlertInfo)
        };
        let is_unimplemented = |at: &crate::action::ActionType| -> bool {
            use crate::action::ActionType::*;
            matches!(
                at,
                MassFreeze
                    | MassFreezeTop
                    | MassFreezeCluster(_)
                    | KillProcess
                    | RateLimit
            )
        };

        for monitor in &self.config.monitors {
            if !monitor.enabled {
                continue;
            }

            let unimplemented: Vec<_> = monitor
                .actions
                .iter()
                .filter(|at| is_unimplemented(at))
                .collect();

            let missing: Vec<_> = monitor
                .actions
                .iter()
                .filter(|at| {
                    !is_dispatcher_action(at)
                        && !is_unimplemented(at)
                        && self.registry.resolve(at).is_none()
                })
                .collect();

            if !unimplemented.is_empty() {
                tracing::warn!(
                    "⚠️  Monitor '{}': actions {:?} are NOT YET IMPLEMENTED — they will silently no-op until shipped. Remove them from your config or use freeze_top_process/run_script as a substitute.",
                    monitor.name,
                    unimplemented,
                );
            }

            if !missing.is_empty() {
                tracing::warn!(
                    "⚠️  Monitor '{}': missing actions {:?} (degraded, {} of {} available)",
                    monitor.name,
                    missing,
                    monitor.actions.len() - missing.len(),
                    monitor.actions.len(),
                );
            }
        }

        tracing::info!(
            "✅ ActionExecutor built with {} actions: {:?}",
            registered.len(),
            registered,
        );

        Ok(ActionExecutor::new(self.registry))
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    fn default_breaker(&self) -> Arc<CircuitBreaker> {
        Arc::new(
            self.base_breaker()
                .with_concurrency_limit(self.config.circuit_breakers.max_concurrency)
                .with_timeout(self.config.circuit_breakers.timeout),
        )
    }

    fn base_breaker(&self) -> CircuitBreaker {
        CircuitBreaker::new(
            self.config.circuit_breakers.max_failures,
            self.config.circuit_breakers.failure_window,
            self.config.circuit_breakers.open_duration,
        )
    }
}