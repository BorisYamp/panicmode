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

I'm Boris. I built PanicMode for a problem I kept watching small dev
shops hit: when one process on a Linux server starts misbehaving, the
typical restart-on-failure cycle does two bad things at once — it
takes the whole box offline for the duration, and it wipes the
in-flight evidence before anyone can debug what happened.

PanicMode does the opposite. It SIGSTOPs only the offending process.
The rest of the box keeps serving everyone else, and the broken
process stays suspended in memory with all its state, logs, and file
descriptors intact. The engineer logs in not to a clean restarted box
that already lost its clues, but to a server that's still serving —
with the broken piece frozen in place exactly where it failed.

The story it grew out of:

A small dev shop I know was losing ~30 minutes of work every morning
for a week. One VPS ran their internal CRM, code mostly written by
juniors, no on-call rotation. Two failure modes were grinding through
them, alternating night by night:

1. The CRM kept getting hit by DDoS probes and brute-force traffic.
   Their only defence was a country-level firewall — it helped a
   little, but determined attackers got around it routinely.
2. The juniors would push small mistakes that the already-stressed
   box couldn't absorb. A bug that should have been a 5-minute fix
   would knock everything over instead.

The scary part wasn't the outages themselves — it was that *the only
way to know whether the box was alive was to log in and check by
hand*. The office opened at 7am, so they settled into a daily 6am
ritual: somebody had to connect from home an hour before the doors
unlocked, just to verify the CRM was still up. The ritual itself
became the new problem — someone always had to be the early-rising
server-babysitter, every day including weekends. And on the
mornings when it wasn't alive, the chain would start: that person
called the manager, manager called a friend at another company who
happened to be a mid-level engineer, that friend SSHed in out of
goodwill and restarted everything by hand. Up to 30 minutes of
every workday was burned on this routine before the team could
even begin. The company was bleeding money the whole time the
chain was running.

They asked me for a solution with one hard constraint: no extra
servers, no SaaS subscriptions, no recurring costs, nothing new to
secure. Whatever it was had to run on the same VPS they already paid
for, in the same single process. PanicMode is what came out of it —
three priorities in this order:

1. Get a human onto the box the moment something breaks, without
   paying for an uptime monitor and without routing alerts through
   anyone else's infrastructure. Telegram is already in everyone's
   pocket — the box sends the message itself, nobody else in the
   loop, nothing recurring to pay for.
2. Auto-handle the obvious stuff so the human doesn't have to be the
   first responder. SSH brute-force / DDoS sources get
   iptables-banned at the first round of failures.
3. Freeze the broken process, not kill it. This is the bit I'm most
   proud of, and it does two things at once:
   - The rest of the box stays alive. A runaway process gets
     SIGSTOP'd before it eats all the CPU/RAM and takes the whole
     server down with it. The team can deal with the incident
     during business hours instead of at 2am.
   - The logs survive. When a process crashes hard, its in-flight
     log buffers usually don't get a chance to flush to disk before
     the restart cycle wipes everything. With SIGSTOP, the process
     stays in memory exactly where it was — frozen-in-place crime
     scene, all evidence intact.

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
