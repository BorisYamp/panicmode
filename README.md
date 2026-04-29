# PanicMode

> Self-hosted Linux server protector that **acts** when something goes wrong — `SIGSTOP`s runaway processes, `iptables`-bans brute-forcers, snapshots the box for post-mortem — locally, in a single ~9 MB Rust binary, no SaaS phones home.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/BorisYamp/panicmode)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/BorisYamp/panicmode)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

```text
[CRITICAL] CPU Spike: 100.0% (threshold: 95%) | server: 198.51.100.7
  → snapshot saved /var/log/panicmode/snapshots/panicmode-snapshot-1777330622.txt
  → FROZEN: stress-ng-cpu (pid 13006, cpu 101.7%)
  → Telegram alert delivered

[CRITICAL] SSH Brute Force: 91 fails from 161.132.4.167(6), 198.51.100.1(35)
  → block_ip → iptables -I INPUT 1 -s 161.132.4.167 -j DROP
  → block_ip → iptables -I INPUT 1 -s 198.51.100.1 -j DROP
```

Most server monitors page you. PanicMode pages you _and_ buys you 60 seconds to look at the snapshot before the box is back to a known-good state. Built for solo operators and small teams who run their own boxes and want active defence without standing up a Wazuh/ELK stack.

**Status:** v0.1.0, Linux-only, single binary + sample systemd unit.  
Production-tested on a fresh VPS through 4 hardening rounds (see [CHANGELOG](CHANGELOG.md)). 28 bugs found and fixed before tag; 26+ real botnet IPs blocked during the test window.

---

## What It Does

- **Monitors** CPU, memory, disk, network connections, SSH auth failures, file modifications, and custom metrics
- **Detects** threshold breaches and anomalies (spikes, suspicious IPs, brute-force attempts) with built-in dedup and rate-limit
- **Acts** immediately — freeze runaway processes, block attacking IPs, take system snapshots, run user scripts
- **Alerts** you via Telegram, ntfy, Discord, email, or phone call (Twilio, experimental)
- **Persists** every incident to SQLite + replays IP blocks across reboots
- **Survives** failures — each task is supervised and restarted on crash; daemon hardened under systemd

---

## Quick Start

### Prerequisites

- Linux (x86\_64 or aarch64)
- Rust 1.88+ (`curl https://sh.rustup.rs -sSf | sh`)

### Build & Install

```bash
git clone https://github.com/BorisYamp/panicmode.git
cd panicmode
cargo build --release
sudo cp target/release/panicmode /usr/local/bin/
sudo cp target/release/panicmode-ctl /usr/local/bin/
```

### Minimal Configuration

Create `/etc/panicmode/config.yaml`:

```yaml
performance:
  cpu_limit: 5.0
  memory_limit_mb: 50
  check_interval: "5s"

monitors:
  - name: "High CPU"
    type: cpu_usage
    threshold: 90.0
    actions: [alert_critical]
    enabled: true

  - name: "High Memory"
    type: memory_usage
    threshold: 85.0
    actions: [alert_warning]
    enabled: true

alerts:
  critical:
    - channel: telegram
  warning:
    - channel: telegram

integrations:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

### Run

```bash
sudo panicmode /etc/panicmode/config.yaml
```

Logs go to `/var/log/panicmode/panicmode.log` (daily rotation) and stdout. Override log level with `RUST_LOG=debug`.

See [QUICKSTART.md](QUICKSTART.md) for detailed setup of each alert channel.

---

## Try It on Windows (Docker)

The [`docker-win`](https://github.com/BorisYamp/panicmode/tree/docker-win) branch contains a ready-to-run Docker Compose setup with a pre-built test configuration — no Rust toolchain required.

```bash
git clone -b docker-win https://github.com/BorisYamp/panicmode.git
cd panicmode
docker compose up
```

That's it. PanicMode will start, begin collecting metrics from inside the container, and you will see alerts firing in the console. Everything works out of the box — no configuration needed to verify the system is alive.

> **Note:** On Windows, Docker Desktop with WSL2 backend is required.

---

## Alert Channels

| Channel | Free | Setup time |
|---|---|---|
| Telegram | ✅ | ~2 min |
| ntfy (push) | ✅ | ~1 min |
| Discord webhook | ✅ | ~2 min |
| Email (SMTP) | ✅ | ~5 min |
| Twilio phone call | 💰 ~$1/mo | ~5 min |

---

## What Gets Monitored

| Monitor type | What it tracks | Source |
|---|---|---|
| `cpu_usage` | CPU % over a rolling window | sysinfo |
| `memory_usage` | RAM utilization | `/proc/meminfo` |
| `swap_usage` | Swap utilization | `/proc/meminfo` |
| `load_average` | 1/5/15 min load averages | `/proc/loadavg` |
| `disk_usage` | Per-mount disk fill % | sysinfo |
| `disk_io` | Per-device I/O `%util` (NVMe-friendly tuning recommended) | `/proc/diskstats` |
| `connection_rate` | New connections per second | `/proc/net/tcp[6]` |
| `auth_failures` | Failed SSH logins + brute-force IPs | **journald** with `_SYSTEMD_UNIT=ssh.service` filter (kernel-attributed, can't be spoofed via local `logger`) |
| `file_monitor` | Modifications under watched directories | inotify (`notify` crate) |
| `custom` | Output of your own script (number or JSON `{"value": …}`) | shell command |

---

## Protective Actions

When an incident fires, PanicMode runs the actions you list on that monitor. v0.1.0 ships:

- **`freeze_top_process`** — SIGSTOP the top CPU offenders. Hardcoded protection for `sshd`, `systemd`, `init`, `kthreadd`, `dbus`, `getty`, `panicmode` is merged on top of any user whitelist (a misconfigured `mass_freeze.yaml` can't lock you out of the box). Skips its own tokio runtime threads and Linux kernel threads.
- **`block_ip`** — Calls your firewall script per public IP extracted from the incident. Blocks persist in SQLite and replay through `restore_blocked_ips` after reboot. Manage with `panicmode-ctl list` / `panicmode-ctl unblock <IP>`. Reference scripts in [`examples/`](examples/) use `iptables` and are idempotent.
- **`snapshot`** — Capture `ps`, `ss`, `free`, `df`, `uptime` to a timestamped file under `snapshot_dir`.
- **`run_script`** — Execute any user script. Incident context arrives as env vars `PANIC_INCIDENT_NAME`, `PANIC_SEVERITY`, `PANIC_DESCRIPTION`, `PANIC_DETAILS`, `PANIC_THRESHOLD`, `PANIC_CURRENT_VALUE` (each capped at 8 KB). **Never `eval` these in your script** — they may contain attacker-influenced text.
- **`alert_critical` / `alert_warning` / `alert_info`** — Route to AlertDispatcher; sent over the channels configured under `alerts:`.

**Documented in `examples/config.yaml` but not yet implemented** — the parser accepts them and the daemon prints a clear "NOT YET IMPLEMENTED" warning at startup; until shipped they no-op:

| Action | Status | Workaround |
|---|---|---|
| `mass_freeze` | not yet | use `freeze_top_process` |
| `mass_freeze_top` | not yet | use `freeze_top_process` |
| `mass_freeze_cluster:<name>` | not yet | use `freeze_top_process` |
| `kill_process` | not yet | `run_script` with `kill -KILL <pid>` |
| `rate_limit` | not yet | `run_script` with `iptables`/`nft` |

---

## Configuration Reference

See [examples/config.yaml](examples/config.yaml) for a fully-annotated example.

Key sections:

```yaml
storage:        # paths for DB, snapshots, logs
monitors:       # which metrics to watch and thresholds
alerts:         # Telegram / email / Discord / ntfy / Twilio
integrations:   # credentials for each alert channel
performance:    # polling intervals, timeouts
firewall:       # block_ip script paths, whitelist, restore_on_startup
actions:        # per-action settings (script paths, etc.)
```

For process freeze whitelist, create `/etc/panicmode/mass_freeze.yaml` (see [examples/mass_freeze.yaml](examples/mass_freeze.yaml)).

---

## Architecture

PanicMode runs five supervised async tasks plus one auxiliary (ctl socket):

```
MonitorEngine ──metrics──▶ Detector ──incidents──▶ IncidentHandler
                                                         │
                                               ActionExecutor  AlertDispatcher
                                                    │    │
                                             FirewallAction  (other actions)
                                                    │
                                             IncidentStorage (SQLite)
                                                    │
                                             CtlServer ◀── panicmode-ctl (CLI)
                                          (Unix socket, aux)
```

See [arch.txt](arch.txt) for the full architecture document.

---

## Roadmap

Ordered by likelihood of landing first:

- **Implement the no-op actions** above — `mass_freeze` / `mass_freeze_top` / `mass_freeze_cluster:<name>` / `kill_process` / `rate_limit`
- **SIGHUP hot-reload** so config changes apply without `systemctl restart` (~1-2 s gap today). Needs an `arc-swap` migration.
- **Rename `Many Connections` semantics** — name suggests absolute count but the metric is rate (new connections per second). Either rename or add an absolute-count monitor type.
- **First-class IPv6 brute-force testing path** — IPv6 components are wired (the `block_ip.sh` reference handles `:` addresses), but end-to-end testing on this VPS keeps hitting `sshd MaxStartups` / fail2ban rate-limits before we cross the threshold. Need either a controlled second host or a synthetic injection harness.
- **NVMe-friendly disk_io metric** — `time_doing_io_ms` is queue-time-based; on NVMe with high parallelism even saturated workloads stay under 50%. Either expose IOPS/bandwidth as separate monitor types, or document the expected threshold range for SSD/NVMe deployments.
- **Twilio coverage** — currently optional, untested in v0.1.0.

PRs welcome on any of these, or open an issue first to discuss the design.

---

## Acknowledgements

PanicMode v0.1.0 went through a 4-round hardening pass before this release. The full story is in [CHANGELOG.md](CHANGELOG.md); commits on the merged `production-hardening-2026-04` branch each carry a self-contained explanation of one or more of the 28 fixes. Highlights worth singling out:

- **Log-injection fix (#19)** — auth monitor now reads journald with `_SYSTEMD_UNIT=ssh.service` filter, closing a path where any local non-root user could `logger`-spoof a brute-force entry and trick PanicMode into iptables-banning arbitrary public IPs.
- **State-across-Clone bug family (#20–#22)** — three monitors maintained per-tick state via `#[derive(Clone)]`. Each clone updated its own state and was dropped, so the original baseline never moved → `disk_io` permanently 0%, `connection_rate` permanently 0, `auth_monitor` re-reading the entire log every tick. Fixed by sharing state via `Arc<Mutex<>>`.
- **systemd hardening + iptables (#13/#14)** — the unit's `RestrictAddressFamilies` blocked `AF_NETLINK` (which iptables needs to talk to kernel netfilter), and UFW's locks under `/run/ufw.lock` were unwritable under `ReadOnlyPaths=/`. Switched the example to direct `iptables`, broadened `ReadWritePaths`, added `AF_NETLINK` and `RuntimeDirectory`.

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
