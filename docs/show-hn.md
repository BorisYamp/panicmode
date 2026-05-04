# Show HN draft — PanicMode v0.1.1

**Status:** ready, not yet posted.

## Title (one line, ≤ 80 chars)

```
Show HN: PanicMode – Linux server protector that acts, not just alerts
```

Tilde-dash (`–`), not hyphen. No emojis. No CAPS.

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

1. A junior pushed a regression late at night. The server hung at
   2am. Nobody found out until the first person walked in at 9am, saw
   the website was down, called the manager, who called a mid-level
   engineer, who SSHed in and manually restarted everything.
2. Botnets brute-forced SSH or flooded the box. Same outcome,
   different cause.

Two compounding problems:

- Hours of downtime nobody knew about. Lost work, missed calls,
  inbound calls *from* clients asking why the website was dead.
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
   I'm most proud of. SIGSTOP keeps the offending process suspended in
   memory with all its logs and stack intact. The engineer logs in to
   a frozen-in-place crime scene, not a clean server that's already
   restarted and lost its evidence.

Some specifics worth flagging up front:

- Single ~9 MB Rust binary, one YAML config, no daemon-of-daemons stack
- v0.1.1, hardened across 4 review rounds before tag — 28 bugs found
  and fixed (CHANGELOG.md has the autopsy)
- Live on a Contabo VPS for 5+ days at the time of release alongside
  fail2ban — between them, 98 unique source IPs blocked over 946 ban
  events, 7,259 brute-force attempts repelled. Top sources: Romania,
  China, Vietnam (full ASN/country breakdown in docs/threat-stats.md
  with the methodology so anyone can reproduce). PanicMode itself:
  ~15 MB RAM steady, ~1% CPU, zero crashes, zero false positives.
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
