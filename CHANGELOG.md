# Changelog

All notable changes to PanicMode are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- `freeze_top_process` no longer SIGSTOPs innocent observation tools (htop,
  journalctl, editors) that briefly land in "top by CPU" after the real
  culprits have already been frozen. Surfaced while preparing the v0.1
  demo recording: stress-ng workers were correctly frozen, then htop at
  ~6% CPU was caught in the next tick because the previous floor was a
  hardcoded 1.0%.

### Added

- `mass_freeze.yaml → top_cpu.min_cpu_to_freeze` — minimum CPU percentage
  a process must use to be eligible for freezing (default 50.0%).
  Replaces the hardcoded 1.0% floor.

---

## [0.1.0] — 2026-04-29

First public release. Built on a fresh Contabo VPS, hardened over four
testing rounds (code review → adversarial probes → white-spot coverage
→ clean regression). 28 bugs found and fixed before this tag; the
project actively blocked 26+ real botnet IPs hitting SSH during the
test window.

### Added — monitoring

- CPU usage (rolling window over `/proc/stat`)
- Memory + swap (`/proc/meminfo`)
- Load average (`/proc/loadavg`)
- Per-mount disk usage (sysinfo)
- Disk I/O `%util` (computed from `/proc/diskstats`, NVMe-friendly tuning recommended)
- Network connection rate (`/proc/net/tcp[6]`, EST. only)
- SSH auth failures — reads journald with `_SYSTEMD_UNIT=ssh.service` filter (kernel-attributed, not spoof-able from non-root `logger`)
- File modification watcher (inotify via `notify`)
- Custom metric runner (any shell command, output_format `number` or `json`)

### Added — detection

- Per-rule threshold evaluation
- Built-in anomaly detector (CPU/memory spikes, suspicious IP clusters, load avg)
- Incident deduplication (5 min default, configurable; persists across restarts via state file)
- Per-incident rate limit
- Circuit breaker around the action executor

### Added — actions (implemented, see Known Limitations for the rest)

- `freeze_top_process` — SIGSTOP top CPU consumers
- `block_ip` — call user firewall script per public IP extracted from incident details
- `snapshot` — `ps` / `ss` / `free` / `df` / `uptime` capture to a timestamped file
- `run_script` — execute user-provided script; incident context via `PANIC_*` env vars (truncated to 8 KB each)
- `alert_critical` / `alert_warning` / `alert_info` — route to AlertDispatcher

### Added — alerting

- Telegram bot (UTF-16-aware truncation at the 4096-char cap)
- ntfy (any server, optional bearer token)
- Discord webhook (channel-level OR `integrations.discord.webhook_url` accepted)
- Email via SMTP (lettre; TLS optional; empty creds correctly skip AUTH)
- Twilio voice/SMS (optional feature flag, untested in this release)

### Added — operations

- `panicmode --validate <config>` — parse-and-exit so operators can verify before `systemctl restart panicmode`
- `panicmode --help` — usage + examples
- `panicmode-ctl list` / `unblock <IP>` — Unix-socket CLI; pipes cleanly to `head`/`grep`
- systemd unit with hardening: `RuntimeDirectory=panicmode`, `NoNewPrivileges`, `PrivateTmp`, `ReadOnlyPaths=/`, restricted `SystemCallFilter` and `RestrictAddressFamilies`
- Reference iptables-based `block_ip.sh` / `unblock_ip.sh` in `examples/` (idempotent, work under the unit's hardening)

### Added — storage

- SQLite incident log + blocked-IPs table (graceful fallback to in-memory if path unwritable)
- Daily rotating file logs via `tracing-appender`
- `state.json` for incident dedup state, atomic-rename writes with per-call unique tmp suffix

### Fixed (production hardening pass)

The "1.0 ship list" — 28 bugs found through code review and live-server
testing. Highlights below; full per-bug commit messages on the branch
history.

**Critical**

- Log-injection vector closed by switching auth_monitor to journald
  with `_SYSTEMD_UNIT=ssh.service` (was reading `/var/log/auth.log`
  which any non-root user can write via `logger -p auth.warn`)
- `ctl` socket umask race fixed (was world-readable for the window
  between `bind()` and `set_permissions()`)
- `sshd` / `systemd` / `init` / `kthreadd` / `dbus` / `getty` /
  `panicmode` are now hard-coded freeze whitelist on top of any user
  config — a misconfigured `mass_freeze.yaml` can no longer SIGSTOP
  the operator out of the box
- Freeze action now skips own tokio runtime threads (Tgid match) and
  Linux kernel threads (PPID == 2) — earlier versions could SIGSTOP
  `kcompactd` / `kworker` / its own tokio workers
- Three "delta" monitors (DiskIo, Network, Auth) now share state
  across `spawn_blocking` clones via `Arc<Mutex<>>`. Without this,
  every tick saw a fresh "first sample" baseline — `disk_io` always
  reported 0% util, `connection_rate` was permanently near zero,
  and `auth_monitor` re-read the entire log file every tick

**High**

- Telegram messages truncated to 4096 UTF-16 code units (emoji-aware)
- `restore_blocked_ips` pre-flights the firewall script and ERROR-logs
  failures with the full IP list (was a silent `warn`)
- `IncidentState::save()` writes to a unique tmp filename — no race
  when several incidents fire in the same millisecond
- `disk_cache_ttl` default 60 s → 5 s (a runaway log file can no
  longer hide a full minute behind a stale cache reading)
- `auth_failures` incident details now include the offending IPs;
  `block_ip` extracts them and bans the public ones (was reporting
  only counts, leaving the action with nothing to ban)
- sysinfo cold-start fixed in the freeze action (two refreshes with
  a 200 ms gap so `cpu_usage()` returns real values)
- `block_ip.sh` example is idempotent — uses `iptables -C` before
  `-I` so `restore_blocked_ips` doesn't compound duplicates each
  restart
- File-monitor inotify watches now actually start at boot (the
  `start_file_monitoring()` method existed but had no caller); event
  matching uses directory containment so configured `paths: [/etc/...]`
  finds events keyed under file children
- Self-check task now has per-condition cooldown (default 5 min) and
  realistic FD/thread thresholds (1000 / 200 — not 100 / 20)

**Operational / packaging**

- systemd unit: added `RuntimeDirectory=panicmode`, `AF_NETLINK` to
  `RestrictAddressFamilies`, `/run` to `ReadWritePaths` so iptables-
  based block scripts work under the unit's hardening
- Tunable thresholds (`self_fd_threshold`, `self_thread_threshold`,
  `self_alert_cooldown`, `disk_cache_ttl`) — operators can adjust
  without rebuilding
- `panicmode-ctl` no longer panics on broken pipe (`SIGPIPE` handler
  restored to default — pipes to `head`/`grep` work normally)
- Discord channel works whether the webhook URL is set at the channel
  level or in `integrations.discord` (was requiring both)
- Email with empty `smtp_username`/`smtp_password` skips AUTH instead
  of attempting empty-PLAIN (was failing as "no compatible auth
  mechanism")

**Cosmetic**

- `script env vars truncated + security note (#5)`: `PANIC_*` env vars
  capped at 8 KB each; long doc comment on the security model
  (`Command::env` is not shell-evaluated, but user scripts must not
  `eval` the values themselves)
- Repo-wide path comment typos (`scr/`, `exampels/`) corrected; orphan
  `src/mass_freez.yaml` removed
- "Missing actions" startup spam silenced for `AlertCritical` /
  `AlertWarning` / `AlertInfo` (those route through AlertDispatcher,
  not the action executor — the warning was always misleading)

### Known limitations

- **Five action variants are documented in `examples/config.yaml` and
  accepted by the parser, but not yet implemented**: `mass_freeze`,
  `mass_freeze_top`, `mass_freeze_cluster:<name>`, `kill_process`,
  `rate_limit`. Builder logs a clear "NOT YET IMPLEMENTED — will
  silently no-op until shipped" warning at startup if any of these
  appear in a config. Use `freeze_top_process` and `run_script` until
  these land.
- **No SIGHUP hot-reload**: config changes apply via
  `systemctl restart panicmode` (~1-2 s gap). True zero-downtime
  reload would need an `arc-swap` migration; planned for v0.2.
- **`Many Connections` semantic mismatch**: monitor name suggests
  absolute count but the metric is rate (new conns/sec). At
  threshold 1000 it only triggers on DDoS-level bursts; lower the
  threshold or rename for clarity.
- **NVMe `%util` is naturally low**: kernel `time_doing_io_ms` is
  queue-time-based, so even saturated NVMe rarely crosses 50%.
  Operators on NVMe hosts should pick a low `disk_io` threshold
  (~30%) or watch IOPS via `custom_metrics`.
- **Twilio**: optional, untested in this release. Treat as
  experimental.

[0.1.0]: https://github.com/BorisYamp/panicmode/releases/tag/v0.1.0
