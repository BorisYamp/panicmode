# Show HN draft — PanicMode v0.1.0

**Status:** draft, not yet posted.

## Title (one line, ≤ 80 chars)

```
Show HN: PanicMode – Linux server protector that acts, not just alerts
```

## Link

`https://github.com/BorisYamp/panicmode`

## First comment (post immediately as author once submitted)

```
Hi HN,

I'm Boris. I built PanicMode after watching a small dev shop I know
lose ~30 minutes of work every single morning for a week.

The setup: one VPS running everything, juniors writing most of the
server code, no on-call rotation. Two failure modes were chewing
through productivity:

1. A junior pushes a regression late at night. The server hangs at
   2am. Nobody notices until the first person walks in at 9am, sees
   the website is down, calls the manager, who calls a mid-level
   engineer, who SSHes in and manually restarts everything.
2. Botnets brute-force SSH or flood the box. Same outcome, different
   cause.

Two compounding problems:

- The team had no idea the server was down for hours. Lost work,
  missed calls, calls *from* clients asking why the website was dead.
- By the time the engineer logged in, the restart cycle had wiped any
  in-memory state. They were debugging blind every time.

They tried fail2ban + monit + a Telegram bot stitched together. It
worked badly. After the third "thanks but it broke again" I sat down
and built PanicMode — a single binary that does three things in this
priority order:

1. Pages a human immediately, on a channel they already read
   (Telegram by default — no SaaS uptime monitor, no third-party
   server, no monthly bill).
2. Auto-handles the things that don't need a human — SSH brute-forcers
   get iptables-banned, runaway memory hogs get SIGSTOP'd before the
   OOM killer triggers a cascade.
3. Freezes the broken state instead of killing it. This is the piece
   I'm most proud of. SIGSTOP keeps the offending process suspended
   in memory with all its logs and stack intact. The engineer logs in
   to a frozen-in-place crime scene, not a clean server that's
   already restarted and lost its evidence.

Some specifics worth flagging up front:

- Single ~9 MB Rust binary, one YAML config, no daemon-of-daemons stack
- v0.1.0, hardened across 4 review rounds before tag — 28 bugs found
  and fixed (CHANGELOG.md has the full autopsy)
- Live on a public VPS for 5+ days at the time of release alongside
  fail2ban: between them, 946 botnet IPs blocked, 7,259 brute-force
  attempts repelled. PanicMode itself: ~15 MB RAM steady, ~1 % CPU,
  zero crashes, zero false positives.
- Linux-only for now (journald + iptables); Windows/macOS not on the
  near roadmap

Things I'd love feedback on:

- The freeze-don't-kill design — anyone tried something similar?
  I haven't found prior art outside of k8s-specific tooling.
- The "Why not X" section in the README — is the comparison fair,
  especially against Falco?
- mass_freeze / kill_process actions are documented and parsed but
  not yet implemented (daemon prints "NOT YET IMPLEMENTED" warning
  at startup). Acceptable for v0.1, or should I have shipped them
  before tagging?

Repo: https://github.com/BorisYamp/panicmode
```

## Posting checklist

- [ ] GIF recorded and committed to `docs/demo.gif`
- [ ] Pre-built binaries uploaded to `v0.1.0` release on GitHub (x86_64, aarch64)
- [ ] README rendered correctly on github.com (image loads, badges OK)
- [ ] First comment text saved locally in case HN markdown chokes mid-edit
- [ ] At keyboard for the next 2-3 hours after submission to reply to comments

## Timing

- **Best window:** Tuesday / Wednesday / Thursday, 13:00–16:00 UTC (≈ 9:00–12:00 ET, EU still working)
- **Avoid:** Mondays before noon, Fridays after 17:00 UTC, weekends

## Reddit cross-post sequence (after HN submit)

| When | Subreddit | Angle |
|---|---|---|
| Same day, 2-4h after HN | /r/selfhosted | Self-hostable, single binary, no SaaS |
| Day +1 | /r/rust | async Rust, 28 bugs caught, single binary |
| Day +2-3 | /r/sysadmin | fail2ban + monit + alerter in one binary |
| Day +7 (optional) | /r/opensource, /r/homelab | if first-week traction is good |

**Do not paste the same body to multiple subreddits.** Rewrite the title and first paragraph for each — Reddit penalises identical cross-posts.

## What not to do

- Don't post twice. One Show HN per project, ever (until v1.0 / v2.0).
- Don't repost if first attempt flops. Accept it and move on.
- Don't ask friends for upvotes — vote manipulation = ban.
- Don't argue defensively in comments. Engage humbly: "good point, here's the trade-off."
- Don't promise features in comments unless you actually mean to ship them.
