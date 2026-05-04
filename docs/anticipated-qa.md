# Anticipated Q&A — Show HN / Reddit launch

Open this file in a second window during the launch. Each question
gets a short, ready-to-paste answer. Tighten or personalise as you
go.

---

## Tooling comparison questions

### "Why not Falco?"

> Different temperament rather than different scope. Falco does
> kernel-level syscall audit and emits events; you bolt on
> Falcosidekick + a controller to actually act on them. PanicMode
> watches less, alerts less, and acts directly in-process. If you
> have a SOC team to triage the firehose, Falco is the better
> choice. If you're one person with one VPS, Falco is heavy and
> noisy by default. They're not strictly competing.

### "Why not just fail2ban?"

> fail2ban does one thing very well — banning IPs based on log
> patterns. PanicMode's `block_ip` action is essentially the same
> thing. Where it goes wider: also watches CPU / memory / disk,
> can SIGSTOP runaway processes, takes snapshots, routes alerts to
> Telegram / Discord / ntfy / email — all in one binary and one
> YAML. They coexist fine. The production VPS in the README runs
> both side-by-side; numbers in the README are the combined output.

### "Why not monit?"

> monit was the inspiration honestly. PanicMode is structurally
> the same shape — watch + trigger + act + alert. The differences
> are mostly modernisation: parses journald with a kernel-attributed
> unit filter (auth log can't be `logger`-spoofed), ships
> Telegram/Discord/ntfy out of the box instead of email-only, and
> the config is YAML instead of monit's bespoke DSL.

### "Why not Wazuh?"

> Wazuh wants Elasticsearch + a manager + agents per host — that's
> a whole stack to operate. PanicMode is one ~9 MB binary with one
> YAML and one systemd unit. They're solving different problems:
> Wazuh is a SIEM (full audit, compliance reports, fleet view),
> PanicMode is a single-host watchdog that acts. If you need
> compliance reporting Wazuh wins; if you have one VPS PanicMode
> is enough.

### "Why not Datadog / New Relic / hosted X?"

> Personal-use cost-benefit. $15-30/host/month adds up fast across
> a few servers, and your metrics flow on someone else's wire.
> PanicMode is the "I just want my one box to not die quietly"
> solution that doesn't require a SaaS subscription or telemetry.

### "vs Uptime Kuma / Healthchecks / hosted uptime monitors?"

> Different layer. Uptime Kuma polls your endpoint over HTTP and
> alerts when it stops responding. PanicMode runs *on* the box and
> sees what's happening internally before the endpoint dies. They
> stack nicely — if you want belt-and-suspenders, run both and
> Kuma will verify that PanicMode is actually keeping the box up.

---

## Implementation questions

### "Why Rust and not Go?"

> Honest answer: I knew Rust better and the type system caught
> several state-management bugs in the hardening pass that Go
> would have let through (the `#[derive(Clone)]`-with-state bug
> family on monitors, for example, would have been silent
> data-race-y in Go). Memory footprint comes out roughly the same.
> Go would have shipped faster initially but I'm not sure I'd
> trust it as much for a daemon that runs as root with iptables
> permissions.

### "How is the freeze non-destructive? Won't SIGSTOP'd processes
get OOM-killed eventually?"

> SIGSTOP suspends a process — it doesn't release its memory. If
> the box is genuinely out of RAM, the OOM killer can still pick
> it. In practice for our use case (CPU-bound runaway, not
> memory-bound), the freeze stops the CPU spike immediately,
> memory pressure doesn't grow, and the engineer logs in to a
> stopped-but-intact process they can either kill cleanly or
> resume to capture more state.

### "Does it run in containers?"

> Not currently. The design is host-level — process freezing,
> iptables rules, file integrity monitoring all need real Linux
> capabilities, not container ones. A `docker-win` branch in
> the repo runs it inside a Docker container for *demo* purposes
> on Windows, but it can only see container-internal metrics,
> not the host. Running PanicMode-in-Kubernetes is on the
> "interesting but probably needs a different design" pile.

### "Doesn't it need root? That's scary."

> Yes, it needs root. SIGSTOP-ing arbitrary processes and editing
> iptables both require root. The systemd unit applies a fairly
> aggressive sandbox (NoNewPrivileges, ProtectSystem=strict,
> RestrictAddressFamilies, etc.) so even with root, the daemon's
> filesystem and network access is narrowed. There's a hardcoded
> protection list (sshd, systemd, init, kthreadd, dbus, getty,
> panicmode itself) that even a misconfigured user whitelist
> can't override — the goal is "you can't lock yourself out of
> your own box."

### "What if the daemon itself crashes?"

> Each task in PanicMode is supervised under tokio::spawn — if
> any one task panics, the supervisor restarts it. If the whole
> binary segfaults, systemd restarts it (Restart=on-failure with
> a 5-second backoff in the unit file). I haven't seen it crash
> during the test window, but if it did, recovery would be
> ~5 seconds.

### "How do I unfreeze a process that PanicMode SIGSTOP'd?"

> Two ways:
>
> 1. From shell: `kill -CONT <pid>` — works fine, you'll see the
>    process resume.
> 2. From the CLI: `panicmode-ctl unfreeze <pid>` — also clears
>    the entry from PanicMode's tracking SQLite so it won't be
>    re-frozen on the next tick if CPU is still high.

### "What about IPv6?"

> Wired but not end-to-end validated. The `block_ip.sh` reference
> script handles `:` addresses correctly, but every brute-force
> test I tried hit sshd's MaxStartups limit or fail2ban's rate
> limit before crossing PanicMode's auth_failure threshold. So
> the code path exists, the path is right, but I haven't watched
> it ban a real IPv6 source under load yet. On the roadmap.

### "What's in the config? Show me the smallest viable example."

```yaml
monitors:
  - name: "Critical CPU"
    type: cpu_usage
    threshold: 95
    actions: [snapshot, alert_critical, freeze_top_process]
    enabled: true

alerts:
  critical:
    - channel: telegram

integrations:
  telegram:
    enabled: true
    bot_token: "..."
    chat_id: "..."
```

> ~10 lines of YAML for "alert me on Telegram + freeze the
> offender + take a snapshot when CPU goes above 95%". Full
> example with all fields in `examples/config.yaml`.

---

## Skeptical questions

### "Looks cool but I don't trust 28 bugs found before v0.1 means
no bugs. What did you miss?"

> Honest answer: probably a lot. The four hardening rounds were
> review / adversarial / white-spot / regression — that catches
> 80% of the obvious stuff but I didn't have a fuzzer, didn't
> stress the daemon at scale (>1 VPS), and didn't test on every
> distro. Things I'd guess might still be broken:
>
> - aarch64 builds (untested in CI, only x86_64 verified)
> - Ubuntu 20.04 and older (compiles, runs, but journald API
>   surface differs in ways I haven't validated)
> - Very high incident rate (>100/min) — incident dedup window
>   is 5min default; haven't stress-tested the SQLite write path
>
> Open issues welcome. v0.1 means "first cut, plausible production,
> not battle-tested across the population".

### "How do I trust a random Rust binary on the internet?"

> SHA256SUMS in the release. Source is open, you can build the
> same binary and compare. The build is deterministic-ish in
> Rust if you control toolchain version (Rust 1.88, locked
> Cargo.lock). I'm not signing releases yet — that's on the
> v0.2 list.

### "Why not WireGuard / Tailscale for SSH access instead?"

> Different problem. WireGuard hides SSH from internet brute-force,
> which is great. PanicMode also handles CPU spikes, memory leaks,
> disk fill, custom alerts — none of which WireGuard touches.
> They stack: WG hides SSH, PanicMode catches everything else.
> The README examples show SSH brute-force because it's the most
> universally-recognised threat, not because that's all PanicMode
> does.

### "0 false positives in 5 days — convince me."

> 5 days is short, you're right. The "0 FPs" claim is specifically
> about ban_ip and freeze_top_process actions: nothing innocent
> got banned, nothing innocent got frozen. But the *alert* count
> includes some "high CPU" warnings that turned out to be normal
> nightly cron jobs (logrotate, fstrim, etc). With longer running
> time we'll get a clearer picture. v0.1 stat is "no actions
> against innocents during the soak"; the alert noise floor is
> tunable per deployment.

### "I want PanicMode but configurable from a UI, not YAML."

> Not on the roadmap. The design assumption is that the operator
> already has SSH and a YAML editor — adding a web UI would mean
> another port, another auth surface, another set of bugs. If
> you want a UI, the closest thing is `panicmode-ctl` which gives
> you a CLI for runtime ops (list blocks, unfreeze, status).

---

## Process / dev-experience questions

### "Why MIT/Apache and not GPL/AGPL?"

> Permissive on purpose. The use case is "drop on a server, never
> upstream a change." If someone forks it for their corporate
> infra, that's fine. The cost of GPL would be making companies
> avoid even reading the code, which doesn't help anyone.

### "Will you take PRs?"

> Yes — there's a CONTRIBUTING.md. The roadmap section in README
> lists open work explicitly. Two things I'd love help with:
> implementing mass_freeze / kill_process / rate_limit actions,
> and the IPv6 brute-force test path.

### "How do I sponsor this?"

> Don't, please. It's a hobby project, not a startup. If you want
> to help, run it on your VPS and file issues with anything weird
> you find. That's worth more than money to me at this stage.
