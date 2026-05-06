# /r/selfhosted post draft

**Subreddit:** r/selfhosted (~600K members)
**Tone:** warm, "I built", genuinely seeking feedback
**Angle:** self-hostable, no SaaS, single binary

## Title

```
PanicMode v0.1.2 — Linux server protector that auto-bans brute-forcers and freezes runaway processes (single Rust binary, MIT/Apache, no SaaS)
```

## Body

```
Hey r/selfhosted,

I built a thing for the "I run my own VPS and don't want to pay
Datadog" crowd. PanicMode is a single ~9 MB Rust binary that does
three things at once on a Linux box:

- watches CPU / memory / disk / SSH auth failures
- when something crosses a threshold, *acts* — SIGSTOPs runaway
  processes, iptables-bans brute-forcers, takes a state snapshot
- alerts you on Telegram / Discord / ntfy / email — pick one,
  no third-party uptime service, no monthly bill

The "act" part is what makes it different from monit + fail2ban
stitched together. Specifically: the freeze action SIGSTOPs the
offending process instead of killing it. So when you log in to
investigate, you're not staring at a clean restarted box that's
already lost its evidence — the broken state is right there in
memory, you can look at it.

Some honesty:

- Linux only. Uses journald (so SSH brute-force detection can't
  be spoofed via local `logger` — that was bug #19 in the
  hardening pass) and iptables.
- v0.1.2, just shipped after 4 review rounds caught 28 bugs.
  CHANGELOG.md has the autopsy if you like that genre.
- Live on a Contabo VPS for 8+ days, currently standalone (started
  with fail2ban as a second layer, dropped it once PanicMode proved
  it handles SSH brute-force on its own). 122 unique attacker IPs
  in the permanent blacklist, 17,889 brute-force attempts repelled,
  zero false positives. ~27 MB RAM, ~1% CPU steady.
- mass_freeze / kill_process actions are parsed but not yet
  implemented (daemon prints a warning at startup).
- Two safety floors prevent it from accidentally freezing things
  it shouldn't: a hardcoded protection list (sshd, systemd,
  panicmode itself) plus a configurable `min_cpu_to_freeze`
  threshold so observation tools at low CPU don't get caught
  in the next sweep.

Repo: https://github.com/BorisYamp/panicmode
Pre-built x86_64 Linux binary in releases (no Rust toolchain
needed): https://github.com/BorisYamp/panicmode/releases/tag/v0.1.2

Happy to answer questions / take feedback. Especially curious
how this lands against your existing fail2ban + monit / fail2ban
+ uptime-kuma setups.
```

## Notes for posting

- /r/selfhosted is friendly. They like:
  - Self-hostable (we are)
  - Open source (we are, MIT/Apache)
  - Lightweight (we are)
  - Coexists with existing stack (we do — fail2ban explicitly mentioned)
- Common comments to expect:
  - "Why not just monit?" → see Why-PanicMode in README
  - "How is this different from Uptime Kuma?" → UK is uptime monitoring (HTTP polls), PanicMode is host-level + acts
  - "Does it run in Docker?" → no, host-only by design (`docker-win` branch is preview)
  - "What about ARM/Raspberry Pi?" → aarch64 builds from source work; pre-built binary is x86_64 only for now
- Use the "Self-Promotion" or "Release" flair as required by the sub
- Post 2-4 hours after Show HN to give that thread time to gather initial momentum
