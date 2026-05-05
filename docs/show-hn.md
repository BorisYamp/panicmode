# Show HN draft — PanicMode v0.1.1

**Status:** ready, not yet posted.

## Title (one line, ≤ 80 chars)

```
Show HN: PanicMode – freezes broken Linux processes instead of killing them
```

Tilde-dash (`–`), not hyphen. No emojis. No CAPS.

The earlier draft (`Linux server protector that acts, not just alerts`) was
too generic — HN reads titles like an RSS feed and skips anything that
sounds like one of the 200 monitoring tools they've seen this year. The
freeze-vs-kill angle is contrarian, concrete, and remembered.

Backup variants if this one doesn't feel right on the day:

- `Show HN: PanicMode – auto-freezes crashed services so you can debug them later`
- `Show HN: PanicMode – a self-hosted server watchdog that freezes failures`

## Link

`https://github.com/BorisYamp/panicmode`

## First comment (post immediately as author once submitted)

```
Hi HN,

I'm Boris. I built PanicMode to solve a specific problem I watched
a friend's company hit, and which I think a lot of small ops teams
hit too: when something on the server goes sideways, the restart
cycle that brings it back online destroys the evidence before anyone
can debug what happened. systemd restarts the service, the OOM
killer reclaims memory, the engineer who finally SSHes in to look
sees a clean box that has no idea what it was doing wrong an hour
ago.

So PanicMode does the opposite. When something goes wrong, instead
of restarting the offender, it SIGSTOPs it. The broken process stays
suspended in memory exactly where it was — its open file descriptors,
its memory, its in-flight syscalls, all paused mid-step. The engineer
logs in to a frozen-in-place crime scene, not a clean server that
already lost its clues.

The story it grew out of:

A small dev shop a friend works at was getting hit with DDoS attacks
for a week straight. The actual outage wasn't the scariest part — the
scary part was that *nobody knew the box was down* until people walked
into the office at 9am and found nothing working. Then the chain would
start: whoever noticed called the manager, manager called a friend who
happened to be a mid-level engineer at another company, that friend
SSHed in out of goodwill and restarted everything by hand. Up to
30 minutes of every workday went to this routine before the team could
even begin. The company was bleeding money the whole time the chain was
running.

The shop also had juniors writing most of the server code. Every time
one of them shipped a small mistake, the same chain played out — same
9am discovery, same phone tree, same friend, same wait. Mistakes that
should have been a 5-minute fix were costing the whole company an hour
of operation.

They asked me for a real solution. PanicMode is what came out of it —
three things in priority order:

1. Get a human onto the box the instant something breaks, without
   paying for a SaaS uptime monitor and without routing alerts
   through anyone else's server. Telegram by default — already in
   everyone's pocket, instant, free.
2. Auto-handle the obvious stuff so the human doesn't have to be
   the first responder. SSH-flood DDoS gets iptables-banned at the
   first round of failures. Runaway processes get SIGSTOP'd before
   the cascade brings everything down.
3. Freeze, don't kill. The crime-scene point above. The freeze
   matters specifically because the original failure usually doesn't
   get a chance to flush its logs to disk before a restart cycle
   would wipe them — keeping the process suspended in RAM keeps the
   evidence accessible to whoever shows up.

Some specifics worth flagging up front:

- Single ~9 MB Rust binary, one YAML config, no daemon-of-daemons stack
- v0.1.1, hardened across 4 review rounds before tag — 28 bugs found
  and fixed (CHANGELOG.md has the autopsy)
- Live on a Contabo VPS for 7+ days at the time of release alongside
  fail2ban — between them, 115 unique source IPs blocked over 1,790
  ban events, 13,191 brute-force attempts repelled. Top sources:
  Romania, China, Vietnam (full ASN/country breakdown in
  docs/threat-stats.md with the methodology so anyone can reproduce).
  PanicMode itself: ~27 MB RAM, ~1% CPU, zero crashes, zero false
  positives.
- Linux-only for now (journald + iptables); Windows/macOS not on the
  near roadmap

Things I'd love feedback on:

- The freeze-don't-kill design — anyone tried something similar?
  I haven't found prior art outside of k8s-specific tooling.
- The "Why not X" section in the README — is the comparison fair,
  especially against Falco?
- mass_freeze / kill_process actions are documented and parsed but
  not yet implemented (daemon prints "NOT YET IMPLEMENTED" warning at
  startup). Acceptable for v0.1, or should I have shipped them?

Repo: https://github.com/BorisYamp/panicmode
```

## Posting checklist

- [x] GIF recorded and committed to `docs/demo.gif`
- [x] Pre-built binaries uploaded to `v0.1.1` release on GitHub (x86_64)
- [x] README updated with corrected stats (98, not 946)
- [x] threat-stats.md with Team Cymru methodology
- [ ] Final visual check on github.com (24h before launch)
- [ ] First comment text saved locally in case HN markdown chokes mid-edit
- [ ] At keyboard for the next 2-3 hours after submission to reply to comments
- [ ] anticipated-qa.md open in second window for fast replies

## Timing

- **Best window:** Tuesday / Wednesday / Thursday, 13:00–16:00 UTC (≈ 9:00–12:00 ET, EU still working)
- **Avoid:** Mondays before noon, Fridays after 17:00 UTC, weekends

Recommended slot: **Wednesday 13:00 UTC** — full 2.5 days of soak after final commit, peak HN activity, EU + US both working.

## Reddit cross-post sequence (after HN submit)

| When | Subreddit | Draft file |
|---|---|---|
| Same day, 2-4h after HN | /r/selfhosted | `reddit-selfhosted.md` |
| Day +1 | /r/rust | `reddit-rust.md` |
| Day +2-3 | /r/sysadmin | `reddit-sysadmin.md` |
| Day +7 (optional) | /r/opensource, /r/homelab | improvise based on first-week traction |

Do not paste the same body to multiple subreddits — Reddit penalises identical cross-posts.

## What not to do

- Don't post twice. One Show HN per project, ever (until v1.0 / v2.0).
- Don't repost if first attempt flops. Accept it and move on.
- Don't ask friends for upvotes — vote manipulation = ban.
- Don't argue defensively in comments. Engage humbly: "good point, here's the trade-off."
- Don't promise features in comments unless you actually mean to ship them.
- Don't fix typos with edits during peak traffic — Markdown re-renders inconsistently.
