/// Path: PanicMode/src/action/implementations/script.rs
use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::action::r#trait::{Action, ActionContext};
use crate::config::Config;

/// Hard ceiling on each PANIC_* environment variable passed to user scripts.
///
/// Two reasons:
/// 1. Some incident metadata (snapshot dumps, auth-log excerpts) can be huge
///    — most kernels cap total argv+envp at ~128 KB (MAX_ARG_STRLEN is 32 pages).
///    Without a cap, an oversized PANIC_DETAILS could fail the exec with E2BIG.
/// 2. SECURITY NOTE for users writing scripts:
///    PANIC_DESCRIPTION / PANIC_DETAILS may contain attacker-influenced text
///    (e.g. usernames extracted from /var/log/auth.log). They are passed
///    via env, not argv, so they are NOT shell-evaluated by Command::env().
///    BUT — if your script does `eval "$PANIC_DETAILS"` or pipes the value
///    into a shell-interpreted context, you reintroduce the injection.
///    Treat env values as untrusted strings: quote them, never eval them.
const MAX_ENV_BYTES: usize = 8 * 1024;

fn truncate_env(s: &str) -> std::borrow::Cow<'_, str> {
    if s.len() <= MAX_ENV_BYTES {
        std::borrow::Cow::Borrowed(s)
    } else {
        // Truncate at a char boundary
        let mut end = MAX_ENV_BYTES;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        std::borrow::Cow::Owned(format!("{}...[truncated]", &s[..end]))
    }
}

/// Runs a user-supplied script when an incident fires.
///
/// Incident data is passed via environment variables:
/// - PANIC_INCIDENT_NAME
/// - PANIC_SEVERITY
/// - PANIC_DESCRIPTION
/// - PANIC_DETAILS
/// - PANIC_THRESHOLD
/// - PANIC_CURRENT_VALUE
///
/// Each variable is truncated to MAX_ENV_BYTES. See the constant for the
/// security caveat: env values may be attacker-influenced — never eval them.
pub struct ScriptAction {
    config: Arc<Config>,
}

impl ScriptAction {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    /// Find a Script-type config entry in the actions HashMap.
    fn script_path(&self) -> Option<String> {
        use crate::config::OldActionType;
        self.config
            .actions
            .values()
            .find(|a| a.action_type == OldActionType::Script)
            .map(|a| a.action.clone())
            .filter(|s| !s.is_empty())
    }
}

#[async_trait]
impl Action for ScriptAction {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        let script_path = match self.script_path() {
            Some(p) => p,
            None => {
                tracing::warn!("ScriptAction: no script_path configured, skipping");
                return Ok(());
            }
        };

        let incident = ctx.incident;

        tracing::info!("🔧 Running script: {}", script_path);

        // Truncate untrusted/large fields (description, details) to prevent
        // E2BIG on exec. Threshold/current_value are floats — bounded.
        let result = timeout(
            Duration::from_secs(60),
            Command::new(&script_path)
                .env("PANIC_INCIDENT_NAME", truncate_env(&incident.name).as_ref())
                .env("PANIC_SEVERITY", format!("{:?}", incident.severity))
                .env("PANIC_DESCRIPTION", truncate_env(&incident.description).as_ref())
                .env("PANIC_DETAILS", truncate_env(&incident.metadata.details).as_ref())
                .env(
                    "PANIC_THRESHOLD",
                    incident.metadata.threshold.to_string(),
                )
                .env(
                    "PANIC_CURRENT_VALUE",
                    incident.metadata.current_value.to_string(),
                )
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if output.status.success() {
                    tracing::info!("🔧 Script succeeded: {}", stdout.trim());
                } else {
                    tracing::error!(
                        "🔧 Script failed (exit {}): {}{}",
                        output.status.code().unwrap_or(-1),
                        stderr.trim(),
                        if !stdout.is_empty() {
                            format!("\nstdout: {}", stdout.trim())
                        } else {
                            String::new()
                        }
                    );
                    bail!(
                        "Script exited with code {}",
                        output.status.code().unwrap_or(-1)
                    );
                }
            }
            Ok(Err(e)) => {
                bail!("Failed to run script '{}': {}", script_path, e);
            }
            Err(_) => {
                bail!("Script '{}' timed out after 60s", script_path);
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "run_script"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::r#trait::ActionContext;
    use crate::config::{Config, ActionConfig, OldActionType};
    use crate::detector::{Incident, IncidentMetadata, IncidentSeverity};
    use crate::config::MonitorType;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn make_incident() -> Incident {
        Incident {
            name: "test".into(),
            severity: IncidentSeverity::Critical,
            description: "unit test".into(),
            actions: vec![],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 90.0,
                current_value: 95.0,
                details: "details".into(),
            },
        }
    }

    fn config_with_script(path: &str) -> Arc<Config> {
        let mut actions = HashMap::new();
        actions.insert(
            "run_script".to_string(),
            ActionConfig {
                action_type: OldActionType::Script,
                action: path.to_string(),
                duration: None,
                rate: None,
                capture: vec![],
            },
        );
        Arc::new(Config {
            actions,
            ..Config::default()
        })
    }

    fn write_script(content: &str) -> tempfile::TempPath {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o755);
        f.as_file().set_permissions(perms).unwrap();
        // Close the write handle so Linux won't return ETXTBSY when we exec the script.
        f.into_temp_path()
    }

    #[tokio::test]
    async fn test_script_success() {
        let script = write_script("#!/bin/sh\nexit 0\n");
        let config = config_with_script(script.to_str().unwrap());
        let action = ScriptAction::new(config).unwrap();
        let incident = make_incident();
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_script_receives_env_vars() {
        // Script that fails unless PANIC_INCIDENT_NAME is set
        let script = write_script(
            "#!/bin/sh\n[ -n \"$PANIC_INCIDENT_NAME\" ] && exit 0 || exit 1\n",
        );
        let config = config_with_script(script.to_str().unwrap());
        let action = ScriptAction::new(config).unwrap();
        let incident = make_incident();
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_script_bad_exit_code_returns_err() {
        let script = write_script("#!/bin/sh\nexit 42\n");
        let config = config_with_script(script.to_str().unwrap());
        let action = ScriptAction::new(config).unwrap();
        let incident = make_incident();
        let ctx = ActionContext::new(&incident);
        let result = action.execute(&ctx).await;
        assert!(result.is_err(), "non-zero exit must return Err");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("42"), "expected error containing '42', got: {err}");
    }

    #[tokio::test]
    async fn test_no_script_configured_returns_ok() {
        // No script in actions map → should warn and return Ok
        let config = Arc::new(Config::default());
        let action = ScriptAction::new(config).unwrap();
        let incident = make_incident();
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }
}
