# PanicMode

> Self-hosted server monitoring with intelligent panic mode and automatic alerts

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/BorisYamp/panicmode)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/BorisYamp/panicmode)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

PanicMode watches your Linux server and takes action the moment something goes wrong — before you even check your phone.

---

## What It Does

- **Monitors** CPU, memory, disk, network connections, authentication failures, and custom metrics
- **Detects** threshold breaches and anomalies (spikes, suspicious IPs, brute-force attempts)
- **Acts** immediately — freeze runaway processes, block attacking IPs, take system snapshots
- **Alerts** you via Telegram, email, Discord, ntfy, or phone call (Twilio)
- **Persists** every incident to SQLite for post-mortem analysis
- **Survives** failures — each task is supervised and restarted on crash

---

## Quick Start

### Prerequisites

- Linux (x86\_64 or aarch64)
- Rust 1.75+ (`curl https://sh.rustup.rs -sSf | sh`)

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

## Running with Docker

No Rust installation required — Docker builds everything inside the container.

```bash
# 1. Create config dir and copy the example config
mkdir config
cp examples/config.yaml config/config.yaml
# Edit config/config.yaml — fill in bot tokens, chat IDs, etc.

# 2. Build and start
docker compose up -d

# 3. View logs
docker compose logs -f
```

**Using panicmode-ctl from Docker:**

```bash
docker exec panicmode panicmode-ctl list
docker exec panicmode panicmode-ctl unblock 1.2.3.4
```

**How it works:** The container runs with `--pid=host` and `--network=host`, so it sees and can act on the real host system — process freezing (SIGSTOP), IP blocking (iptables), and `/proc` metrics all work exactly as in a native install.

**Auth log path:** `docker-compose.yml` mounts `/var/log/auth.log` (Debian/Ubuntu). For RHEL/CentOS/Fedora, change it to `/var/log/secure`.

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

| Monitor | What it tracks |
|---|---|
| `cpu_usage` | CPU % over a rolling window |
| `memory_usage` | RAM + swap utilization |
| `swap_usage` | Swap pressure |
| `load_average` | 1/5/15 min load averages |
| `disk_usage` | Per-mount disk fill % |
| `disk_io` | Read/write throughput and IOPS |
| `connection_rate` | Total open connections and new connection rate |
| `auth_failures` | Failed SSH/sudo logins, brute-force IPs |
| `file_monitor` | Modifications to watched paths |
| `custom` | Output of your own scripts |
| `process_count` | Number of running processes |

---

## Protective Actions

When an incident fires, PanicMode can:

- **`freeze_top_process`** — SIGSTOP the single top CPU offender (whitelists `sshd`, `panicmode`, etc.)
- **`mass_freeze`** — SIGSTOP all non-whitelisted processes (emergency measure)
- **`mass_freeze_top`** — SIGSTOP the top N CPU offenders (configurable in `mass_freeze.yaml`)
- **`mass_freeze_cluster:<name>`** — SIGSTOP a named group of processes (defined in `mass_freeze.yaml`)
- **`block_ip`** — Run your firewall script to drop the attacking IP; blocks are persisted in SQLite and restored after reboot; manage with `panicmode-ctl list` / `panicmode-ctl unblock <IP>`
- **`snapshot`** — Capture `ps`, `netstat`, `free`, `df`, `uptime` to a timestamped file
- **`run_script`** — Execute any custom script with incident context in environment variables
- **`alert_critical` / `alert_warning`** — Send notifications through configured channels

---

## Configuration Reference

See [examples/config.yaml](examples/config.yaml) for a fully-annotated example.

Key sections:

```yaml
storage:          # paths for DB, snapshots, logs
performance:      # polling interval, CPU/memory limits for PanicMode itself
monitors:         # which metrics to watch and thresholds
alerts:           # Telegram / email / Discord / ntfy / Twilio routing by severity
integrations:     # credentials for each alert channel
actions:          # custom script definitions for run_script action
anomaly:          # spike detection thresholds (runs alongside monitor rules)
circuit_breakers: # fault tolerance for action execution
firewall:         # block_ip script paths, whitelist, restore_on_startup
http_api:         # optional healthcheck endpoint (GET /health)
custom_metrics:   # arbitrary shell commands to collect extra metrics
file_monitor:     # settings for the file_monitor monitor type
```

For process freeze whitelist, create `/etc/panicmode/mass_freeze.yaml` (see [examples/mass_freeze.yaml](examples/mass_freeze.yaml)).

---

## Architecture

PanicMode runs four supervised async tasks plus one auxiliary (ctl socket) and an optional HTTP API task:

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

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
