# /r/sysadmin post draft

**Subreddit:** r/sysadmin (~900K members)
**Tone:** dry, practical, cynical
**Angle:** "fail2ban + monit + Telegram in one binary, with actions"

## Title

```
Released PanicMode v0.1.1 — fail2ban + monit + Telegram alerts in one Rust binary, with auto-mitigation
```

## Body

```
For the "I have one VPS and don't want to stand up Wazuh" crowd.

PanicMode is a single Linux binary (~9 MB) that does the boring
sysadmin trifecta:

- watches CPU / memory / disk / load / SSH auth / file changes /
  custom scripts
- when something exceeds a threshold, it *does something* —
  SIGSTOP the offender, iptables-ban a brute-forcer, take a
  snapshot of ps/ss/free/df for forensics, run any script you
  hand it
- alerts you somewhere you'll actually read it (Telegram by
  default; Discord, ntfy, email, or Twilio if you really want
  a phone call at 3am)

What's different from running fail2ban + monit + a Telegram bot
stitched together (which is what most of us are doing today):

- One YAML config instead of three. One systemd unit instead of
  three. One log stream.
- The freeze action is non-destructive. SIGSTOP keeps the broken
  state in memory so you can poke at it when you log in, instead
  of looking at a clean restarted box that already lost its
  evidence.
- The auth monitor reads journald with a `_SYSTEMD_UNIT` filter,
  not /var/log/auth.log. So local non-root users can't `logger`
  spoof brute-force entries and trick the daemon into banning
  random public IPs. (Bug #19 in the hardening pass — relevant
  if your machine has any kind of multi-user surface.)
- IP blocks persist in SQLite and get replayed by an init script
  after reboot, so the iptables rules don't disappear on you.

What it isn't:

- Not a SIEM. No central manager, no Elasticsearch, no fleet
  view. One host, one daemon. Coexists fine with fail2ban
  (we run both on the test box).
- Not a hosted service. No phone-home, no monthly bill, no
  vendor account.
- Not Windows. Linux only. Uses journald + iptables. Not
  containers either — design is host-level.

Production-tested for 5 days on a Contabo VPS in France.
Stack of fail2ban + PanicMode caught 98 unique source IPs across
19 countries / 37 ASNs (top: Romania, China, Vietnam — pattern
is the standard 2026 SSH brute-force shape: bulletproof hosting
+ compromised cloud + compromised consumer). 7,259 brute-force
attempts repelled. PanicMode itself ate ~15 MB RAM and ~1% CPU.
Zero false positives, zero crashes during the window.

Repo: https://github.com/BorisYamp/panicmode
Pre-built x86_64 Linux binary: https://github.com/BorisYamp/panicmode/releases/tag/v0.1.1
(no Rust toolchain needed; tarball with two binaries, ~4 MB)

Known limitations honestly:

- Linux only (not on roadmap to fix)
- mass_freeze / kill_process actions parsed but not yet implemented
- IPv6 brute-force testing path is hooked up but not end-to-end
  validated yet (sshd MaxStartups / fail2ban rate-limits keep
  getting hit before threshold)

Open to feedback. Especially the "you reinvented X" comments —
I genuinely went looking for a single-binary modern monit
replacement before writing this and couldn't find one, but I
might have missed it.
```

## Notes

- /r/sysadmin is **practical and skeptical**. Common reactions:
  - "vs fail2ban?" — covered explicitly in the post body
  - "vs monit?" — covered (we're the modern reimagining)
  - "vs Wazuh?" — covered (we're not a SIEM)
  - "Just use Datadog." — covered (no SaaS)
  - "Show me a runbook for incident X." — answer with link to
    examples/ in the repo
  - "What about Ansible/Puppet integration?" — not on roadmap
    but a `run_script` action can fire any external command
- Avoid:
  - Marketing language ("revolutionary", "next-gen")
  - Long stories — this audience wants tradeoffs and tables
- The dry tone of the post is intentional — /r/sysadmin doesn't
  reward enthusiasm, it rewards "here's what works, here are
  the limits"
- Use the appropriate flair (Self-Promotion or General Discussion
  depending on subreddit rules at the time)
- Post 1-2 days after Show HN, when discussion has cooled enough
  that this isn't a duplicate
