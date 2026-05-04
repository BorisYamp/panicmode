# /r/rust post draft

**Subreddit:** r/rust (~250K members)
**Tone:** technical, humble, code-quality-focused
**Angle:** async Rust, 28 bugs caught in 4 hardening rounds, the engineering story

## Title

```
[Show] PanicMode v0.1.1 — async-Rust Linux server protector (single 9 MB binary, ~15 MB RAM, 28 bugs caught in 4 hardening rounds)
```

## Body

```
Hey /r/rust,

Shipping v0.1.1 of PanicMode — an active server protection daemon
for Linux. Single binary, async Rust on top of Tokio, ~9 MB stripped,
~15 MB resident memory steady-state.

The pitch in one sentence: it watches CPU / memory / disk / SSH auth
failures, and when something genuinely critical happens, it *acts* —
SIGSTOPs runaway processes, iptables-bans brute-forcers, takes a
snapshot, and pings you on Telegram. Most monitors stop at "page
the human"; this one tries to buy the human time before they get
to a keyboard.

This isn't really a /r/rust pitch though — there are plenty of
"single-binary self-hosted X" projects. What might be more
interesting here is what shipping a Rust system daemon to bare
production actually looked like.

I ran 4 hardening rounds before tagging v0.1: a code review pass,
an adversarial probe pass (people deliberately trying to brick the
daemon), a white-spot pass (looking for un-tested edges), and a
clean regression pass. 28 bugs found and fixed before tag, all
documented in CHANGELOG.md. A few that might amuse this audience:

- **Three monitors silently broken by `#[derive(Clone)]`.**
  DiskIoMonitor / NetworkMonitor / AuthMonitor each kept
  per-tick state for delta calculations, but the engine
  cloned them on every tick. Each clone updated *its own*
  state and was dropped, the original baseline never moved.
  disk_io permanently 0%, connection_rate permanently 0,
  auth_monitor re-reading the entire log file every tick.
  Fix: state into Arc<Mutex<>>. Pattern to remember: derive
  Clone on a struct with cross-tick state is a footgun;
  either share state via Arc or refactor to recompute deltas
  inside one call.

- **Log injection in the auth monitor.** First version parsed
  /var/log/auth.log directly. Any local non-root user could
  forge brute-force entries via `logger -p auth.warn -t
  "sshd[X]" "Failed password from <victim_ip>"` and trick
  PanicMode into iptables-banning a public IP. Fixed by
  switching to journalctl with `_SYSTEMD_UNIT=ssh.service`
  filter — the kernel-attributed unit field is unforgeable
  from userspace. Pattern: never trust /var/log/auth.log
  on systemd Linux for security decisions; always go through
  journald with unit filter.

- **freeze_top_process catching innocent processes.**
  This was the v0.1 → v0.1.1 fix that surfaced *while
  preparing the demo recording*. The hardcoded 1.0% CPU
  floor meant that after the actual culprits at 100% were
  SIGSTOPped, observation tools at 5-10% CPU became "top of
  remaining" and got SIGSTOPped too. Replaced with a
  configurable `min_cpu_to_freeze` field (default 50.0%).
  Genuine offenders qualify; htop and journalctl don't.

Some other things worth flagging:

- Each task supervised under tokio::spawn, restart on panic.
  The supervisor itself is a tiny loop in main.rs.
- systemd hardening: NoNewPrivileges, ProtectSystem=strict,
  ReadWritePaths only what's needed. Found out the hard way
  that RestrictAddressFamilies blocks AF_NETLINK which iptables
  requires (bug #14).
- Unix-socket control plane (panicmode-ctl) for managing
  blocks / unfreezing / inspecting state without restarting
  the daemon.
- ~10K LOC, 32 .rs files. Cargo.toml dependencies kept lean —
  the heaviest one is sysinfo for cross-platform metric
  collection.

Repo: https://github.com/BorisYamp/panicmode
v0.1.1 release with stripped Linux binary: https://github.com/BorisYamp/panicmode/releases/tag/v0.1.1
Live VPS stats during the test window (98 unique source IPs
blocked, 19 countries, 37 ASNs, methodology included): docs/threat-stats.md

Happy to discuss the design, the bugs, or anything else. First
real Rust shipped to production, so I'd take "you should have
done X instead" feedback gladly.
```

## Notes

- /r/rust is **technically picky**. Common pushback to expect:
  - "Why not Go?" — fair. Honest answer: I knew Rust better, and the
    type-system caught several state-management bugs that Go would
    have let through.
  - "Why sysinfo? Just read /proc directly." — sysinfo is genuinely
    cross-platform; not all metrics live in /proc; we DO read /proc
    directly for the things sysinfo doesn't expose well.
  - "Tokio is overkill for this." — fair. Each monitor is its own
    spawned task with channels for incident signals; without async
    you'd be juggling threads + Mutex on every metric. Could have
    done it with std + threads, but not obviously simpler.
- They like:
  - Real engineering stories (the bug post-mortems above)
  - Honesty about the not-yet-implemented parts
  - Code-level details
- Don't:
  - Lead with a marketing pitch
  - Use phrases like "blazingly fast" or "memory-safe" — /r/rust
    has T-shirts about how tired they are of those phrases
- Best window: weekday morning ET (mid-day UTC), same as HN
- Use the "Show" or "Project" flair (subreddit rules require this)
