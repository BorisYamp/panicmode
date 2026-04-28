/// Path: PanicMode/src/action/implementations/process.rs
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::action::r#trait::{Action, ActionContext};
use crate::config::{Config, MassFreezeConfig};

/// Process names that must NEVER be frozen, regardless of user config.
///
/// Freezing any of these will brick the server:
///   - sshd: lose remote access (only console recovery left)
///   - systemd / init: PID 1 — kernel panics if init stops on most distros
///   - kthreadd: kernel thread parent
///   - dbus: most desktop/system services depend on it
///   - getty / agetty: console fallback if SSH is also down
///   - panicmode: don't freeze ourselves (also protected by own_pid check)
///
/// Substring match is used downstream, so "systemd" also covers systemd-*
/// services (systemd-networkd, systemd-resolved, etc.) — intentional.
const HARDCODED_PROTECTED: &[&str] = &[
    "sshd",
    "systemd",
    "init",
    "kthreadd",
    "dbus",
    "getty",
    "panicmode",
];

/// Freezes the top CPU-consuming processes via SIGSTOP.
///
/// This is PanicMode's primary protective action: when the server is under load,
/// we immediately stop the offenders so the server can "catch its breath"
/// while the team investigates.
///
/// Processes can be unfrozen via SIGCONT or `kill -CONT <pid>`.
pub struct ProcessAction {
    _config: Arc<Config>,
    whitelist: Vec<String>,
    freeze_count: usize,
}

impl ProcessAction {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        // Load whitelist and top_cpu.count from mass_freeze.yaml.
        // On any error fall back to defaults so sshd and panicmode are always protected.
        let freeze_cfg = MassFreezeConfig::load_from_path_or_default("/etc/panicmode")
            .unwrap_or_default();

        // Merge user whitelist with the hardcoded never-freeze list.
        // This is a safety floor: even a misconfigured user-supplied YAML
        // (or one that omits sshd by mistake) cannot freeze critical processes.
        let merged_whitelist = Self::merge_whitelist(&freeze_cfg.whitelist);

        tracing::info!(
            "ProcessAction: freeze_count={}, whitelist={:?} (hardcoded protected: {:?})",
            freeze_cfg.top_cpu.count,
            merged_whitelist,
            HARDCODED_PROTECTED,
        );

        Ok(Self {
            _config: config,
            whitelist: merged_whitelist,
            freeze_count: freeze_cfg.top_cpu.count,
        })
    }

    /// Returns user_whitelist ∪ HARDCODED_PROTECTED, deduplicated, lowercased.
    fn merge_whitelist(user_whitelist: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for name in user_whitelist
            .iter()
            .map(|s| s.to_lowercase())
            .chain(HARDCODED_PROTECTED.iter().map(|s| s.to_string()))
        {
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }

        out
    }
}

#[async_trait]
impl Action for ProcessAction {
    async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
        let freeze_count = self.freeze_count;
        let own_pid = std::process::id();
        let whitelist = self.whitelist.clone();

        tokio::task::spawn_blocking(move || {
            use sysinfo::System;

            // sysinfo::Process::cpu_usage() returns 0 on first refresh — it
            // needs two samples (delta over an interval) to report a real
            // value. Without the second refresh, every process looks idle
            // and the freeze action skips everything.
            let mut system = System::new();
            system.refresh_processes();
            std::thread::sleep(std::time::Duration::from_millis(200));
            system.refresh_processes();

            let mut processes: Vec<_> = system.processes().values().collect();
            processes.sort_by(|a, b| {
                b.cpu_usage()
                    .partial_cmp(&a.cpu_usage())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Helper: is this PID a thread of OUR process? sysinfo enumerates
            // Linux threads as separate Process entries (each TID gets its own
            // entry). Without this check we'll SIGSTOP our own tokio runtime
            // workers — bug #16.
            let is_our_thread = |pid: u32| -> bool {
                if pid == own_pid {
                    return true;
                }
                let path = format!("/proc/{}/status", pid);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        if let Some(rest) = line.strip_prefix("Tgid:") {
                            if let Ok(tgid) = rest.trim().parse::<u32>() {
                                return tgid == own_pid;
                            }
                        }
                    }
                }
                false
            };

            // Helper: is this PID a kernel thread? On Linux, all kernel
            // threads are children of kthreadd (PID 2). Reading /proc/<pid>/stat
            // is more reliable than checking name patterns — bug #17.
            //
            // /proc/<pid>/stat format: `pid (comm) state ppid pgrp ...`
            // `comm` is wrapped in parens and CAN contain spaces or ')'
            // characters, so we anchor on the LAST ')' before splitting.
            // We previously tried `Process::cmd().is_empty()` from sysinfo,
            // but that API can return empty for normal processes on some
            // Linux/sysinfo combinations — false-positive filtered out
            // stress-ng and broke the whole freeze action.
            let is_kernel_thread = |pid: u32| -> bool {
                let stat_path = format!("/proc/{}/stat", pid);
                let Ok(content) = std::fs::read_to_string(&stat_path) else {
                    return false;
                };
                let Some(end_paren) = content.rfind(')') else {
                    return false;
                };
                let after_comm = &content[end_paren + 1..];
                let mut fields = after_comm.split_whitespace();
                let _state = fields.next();
                let Some(ppid_str) = fields.next() else {
                    return false;
                };
                matches!(ppid_str.parse::<u32>(), Ok(2))
            };

            let to_freeze: Vec<_> = processes
                .iter()
                .filter(|p| {
                    let pid = p.pid().as_u32();
                    let name = p.name().to_string().to_lowercase();
                    // Skip our own process AND any of our threads (Linux
                    // threads share TGID with the leader; sysinfo lists them
                    // as separate Process entries with distinct TIDs).
                    if is_our_thread(pid) {
                        return false;
                    }
                    // Skip kernel threads (children of kthreadd, PID 2).
                    // Names like "kworker/u8:1", "kcompactd0", "ksoftirqd/0"
                    // — SIGSTOP'ing them can wedge the kernel. Substring
                    // whitelist is fragile for these names — bug #17.
                    if is_kernel_thread(pid) {
                        tracing::debug!("Skipping kernel thread: {} (pid {})", name, pid);
                        return false;
                    }
                    // Skip processes below the CPU threshold
                    if p.cpu_usage() <= 1.0 {
                        return false;
                    }
                    // Check whitelist: substring match (case-insensitive)
                    let is_whitelisted = whitelist
                        .iter()
                        .any(|w| name.contains(w.to_lowercase().as_str()));

                    if is_whitelisted {
                        tracing::debug!("Skipping whitelisted process: {} (pid {})", name, pid);
                    }

                    !is_whitelisted
                })
                .take(freeze_count)
                .collect();

            if to_freeze.is_empty() {
                tracing::info!("No processes to freeze (none above threshold or all whitelisted)");
                return Ok(());
            }

            for proc in &to_freeze {
                let pid = proc.pid().as_u32() as i32;
                #[cfg(unix)]
                unsafe {
                    if libc::kill(pid, libc::SIGSTOP) == 0 {
                        tracing::warn!(
                            "FROZEN: {} (pid {}, cpu {:.1}%)",
                            proc.name(),
                            pid,
                            proc.cpu_usage()
                        );
                    } else {
                        tracing::warn!(
                            "Failed to freeze {} (pid {}): permission denied or process gone",
                            proc.name(),
                            pid
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    tracing::warn!(
                        "SIGSTOP not supported on this platform, skipping {} (pid {})",
                        proc.name(),
                        pid
                    );
                }
            }

            tracing::warn!(
                "Frozen {} process(es). To resume: kill -CONT <pid>",
                to_freeze.len()
            );

            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    fn name(&self) -> &str {
        "process_freeze"
    }
}
