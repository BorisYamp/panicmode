/// Path: PanicMode/src/monitor/auth.rs
///
/// SSH auth event source — reads ONLY journald entries attributed by the
/// kernel to the sshd systemd unit.
///
/// SECURITY (bug #19 fix):
///   The previous implementation read /var/log/auth.log line-by-line and
///   regex-matched `"Failed password ... from <IP>"`. That file is the
///   destination of *every* program that calls libc syslog() or `logger -p
///   auth.warn`, including unprivileged users — anyone who could run
///   `logger` could craft fake brute-force entries naming any public IP
///   and PanicMode would happily ban it. We confirmed exploitability with
///   a `nobody`-equivalent user on a real VPS: 16 fake lines from
///   192.0.2.123 → instant iptables DROP rule.
///
///   Journald, in contrast, attaches `_SYSTEMD_UNIT=...` to every entry
///   based on the cgroup of the originating PID — kernel-side metadata
///   that user-space cannot spoof. By spawning journalctl with `-u
///   ssh.service` we restrict ingestion to entries that genuinely came
///   from the sshd unit's processes. `logger` from another user lands in
///   syslog/auth.log but never carries the right unit attribution, so it
///   is invisible here.
///
/// Design:
///   - Each tick runs `journalctl -u <ssh-unit> --since=<N seconds ago>`
///     in spawn_blocking. Sliding window is wider than the rule's
///     intended firing window so we never miss events on tick boundaries.
///   - Unit name auto-detected at construction (Debian/Ubuntu use
///     `ssh.service`; RHEL/CentOS use `sshd.service`).
///   - No `last_position` cursor — the time-window naturally bounds work,
///     and sidesteps the file-rotation edge cases of the old design.
use anyhow::Result;
use super::{AuthMetrics, AuthFailureInfo};
use std::collections::HashMap;
use std::process::Command;
use std::time::SystemTime;
use regex::Regex;

const JOURNALCTL: &str = "/usr/bin/journalctl";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Sliding window for journald query. Wider than typical rule windows
/// (60s) so events near a tick boundary aren't undercounted.
const DEFAULT_WINDOW_SECS: u64 = 120;

#[derive(Clone)]
pub struct AuthMonitor {
    /// Detected sshd unit name (`ssh.service` on Debian/Ubuntu,
    /// `sshd.service` on RHEL/CentOS).
    sshd_unit: String,
    window_secs: u64,
    ssh_failure_regex: Regex,
    ssh_success_regex: Regex,
}

impl AuthMonitor {
    pub fn new() -> Result<Self> {
        let sshd_unit = detect_sshd_unit();
        tracing::info!("AuthMonitor: using systemd unit '{}' for journald query", sshd_unit);

        Ok(Self {
            sshd_unit,
            window_secs: DEFAULT_WINDOW_SECS,
            ssh_failure_regex: Regex::new(
                r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
            )?,
            ssh_success_regex: Regex::new(
                r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
            )?,
        })
    }

    pub fn collect(&self) -> Result<AuthMetrics> {
        let since = format!("{} seconds ago", self.window_secs);

        // `--output=cat` strips the leading timestamp/host/unit, leaving
        // just the sshd message body. Our existing regexes already match
        // that body; no need to keep timestamp parsing in this path.
        let output = Command::new(JOURNALCTL)
            .args([
                "-u", &self.sshd_unit,
                "--since", &since,
                "--output=cat",
                "--no-pager",
                // Disable color/escape codes (some journalctl builds emit them
                // even with --output=cat under certain TERM values).
                "--no-hostname",
            ])
            .output();

        let stdout = match output {
            Ok(out) if out.status.success() => out.stdout,
            Ok(out) => {
                tracing::warn!(
                    "journalctl exited with {:?}; auth metrics will be zero this tick. stderr: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim(),
                );
                return Ok(AuthMetrics::default());
            }
            Err(e) => {
                tracing::warn!("Cannot spawn journalctl: {} — auth metrics will be zero", e);
                return Ok(AuthMetrics::default());
            }
        };

        let content = String::from_utf8_lossy(&stdout);
        let now = SystemTime::now();

        let mut failures: HashMap<String, FailureInfo> = HashMap::new();
        let mut total_failures = 0u64;
        let mut successful_logins = 0u64;

        for line in content.lines() {
            // Failures
            if let Some(caps) = self.ssh_failure_regex.captures(line) {
                let username = caps.name("user").map_or("unknown", |m| m.as_str()).to_string();
                let ip = caps.name("ip").map_or("unknown", |m| m.as_str()).to_string();
                total_failures += 1;
                let key = format!("{}@{}", username, ip);
                failures
                    .entry(key)
                    .and_modify(|info| {
                        info.count += 1;
                        info.last_attempt = now;
                    })
                    .or_insert(FailureInfo {
                        ip,
                        username,
                        count: 1,
                        last_attempt: now,
                    });
            }
            // Successes
            if self.ssh_success_regex.is_match(line) {
                successful_logins += 1;
            }
        }

        let mut failures_by_ip: Vec<AuthFailureInfo> = failures
            .into_iter()
            .map(|(_, info)| AuthFailureInfo {
                ip: info.ip,
                username: info.username,
                attempt_count: info.count,
                last_attempt: info.last_attempt,
            })
            .collect();
        failures_by_ip.sort_by(|a, b| b.attempt_count.cmp(&a.attempt_count));
        failures_by_ip.truncate(20);

        Ok(AuthMetrics {
            failed_attempts: total_failures,
            failures_by_ip,
            successful_logins,
        })
    }
}

/// Probe `systemctl cat <unit>` to find which sshd unit name this distro uses.
/// Default to `ssh.service` if probing fails (Debian/Ubuntu naming).
fn detect_sshd_unit() -> String {
    for unit in ["ssh.service", "sshd.service"] {
        let r = Command::new(SYSTEMCTL).args(["cat", unit]).output();
        if matches!(r, Ok(out) if out.status.success()) {
            return unit.to_string();
        }
    }
    "ssh.service".to_string()
}

#[derive(Debug)]
struct FailureInfo {
    ip: String,
    username: String,
    count: u64,
    last_attempt: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_regex_basic() {
        let monitor = AuthMonitor::new().unwrap();
        let line = "Failed password for invalid user testuser from 192.0.2.5 port 22 ssh2";
        let caps = monitor.ssh_failure_regex.captures(line).unwrap();
        assert_eq!(&caps["user"], "testuser");
        assert_eq!(&caps["ip"], "192.0.2.5");
        assert_eq!(&caps["port"], "22");
    }

    #[test]
    fn test_failure_regex_publickey() {
        let monitor = AuthMonitor::new().unwrap();
        let line = "Failed publickey for root from 192.0.2.4 port 51234 ssh2";
        let caps = monitor.ssh_failure_regex.captures(line).unwrap();
        assert_eq!(&caps["user"], "root");
        assert_eq!(&caps["ip"], "192.0.2.4");
    }

    #[test]
    fn test_success_regex() {
        let monitor = AuthMonitor::new().unwrap();
        let line = "Accepted publickey for testuser from 192.0.2.42 port 51234 ssh2";
        assert!(monitor.ssh_success_regex.is_match(line));
    }

    #[test]
    fn test_ipv6_address() {
        let monitor = AuthMonitor::new().unwrap();
        let line = "Failed password for user from 2001:db8::1 port 22 ssh2";
        let caps = monitor.ssh_failure_regex.captures(line).unwrap();
        assert_eq!(&caps["ip"], "2001:db8::1");
    }

    #[test]
    fn test_collect_runs_without_panicking() {
        // Even on a system where journalctl fails (no systemd, missing unit),
        // collect must return a value rather than propagating an error.
        let monitor = AuthMonitor::new().unwrap();
        let _ = monitor.collect().unwrap();
    }
}
