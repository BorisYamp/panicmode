# Sample output

What PanicMode looks like in practice. Captured from the production
VPS that's been running v0.1.x alongside fail2ban for the
launch-validation period. Last octets are masked because the source
hosts are mostly compromised innocents — see `threat-stats.md` for
why we don't publish the raw IP list.

## `panicmode-ctl list`

```
IP               Blocked At            Reason
───────────────────────────────────────────────────────────────────────────────
203.0.113.xxx    5d ago                SSH Brute Force exceeded threshold: 16 > 15
192.0.2.xxx     5d ago                SSH Brute Force exceeded threshold: 293 > 15
198.51.100.xxx    6d ago                SSH Brute Force exceeded threshold: 283 > 15
203.0.113.xxx    6d ago                SSH Brute Force exceeded threshold: 283 > 15
198.51.100.xxx    6d ago                SSH Brute Force exceeded threshold: 283 > 15
192.0.2.xxx     6d ago                SSH Brute Force exceeded threshold: 199 > 15
203.0.113.xxx    6d ago                SSH Brute Force exceeded threshold: 187 > 15
198.51.100.xxx    6d ago                SSH Brute Force exceeded threshold: 175 > 15
192.0.2.xxx     6d ago                SSH Brute Force exceeded threshold: 167 > 15
... + 89 more
```

The threshold is `auth_failures: threshold: 20` in this configuration —
so each line corresponds to a host that hit at least 20 failed SSH
logins within a one-minute window. The "exceeded threshold: 293 > 15"
detail is the value at the moment of detection (some hosts were
hammering harder than others).

## Live incident in journal

What hits `journalctl -u panicmode -f` when a critical event fires.
Capture from a `stress-ng --cpu 4 --timeout 60s` run on the
production VPS:

```
ERROR panicmode::detector: CRITICAL: Critical CPU
INFO  panicmode::detector: Description: Critical CPU exceeded threshold: 100.00 > 95.00
WARN  panicmode::action::implementations::process: FROZE: stress-ng-cpu (pid 271004, cpu 103.3%)
WARN  panicmode::action::implementations::process: FROZE: stress-ng-cpu (pid 271007, cpu 100.0%)
WARN  panicmode::action::implementations::process: FROZE: stress-ng-cpu (pid 271006, cpu  96.7%)
WARN  panicmode::action::implementations::process: FROZE: stress-ng-cpu (pid 271005, cpu  93.3%)
INFO  panicmode::action::executor: ✅ process_freeze succeeded
INFO  panicmode::action::implementations::process: No processes to freeze (none above threshold or all whitelisted)
INFO  panicmode::action::executor: ✅ process_freeze succeeded
WARN  panicmode::detector: WARNING: High CPU
INFO  panicmode::detector: Description: High CPU exceeded threshold: 100.00 > 80.00
```

End-to-end: 4 stress-ng CPU workers spawned → CPU hits 100% → CPU Spike
threshold exceeded → 4 worker PIDs SIGSTOP'd → Telegram alert delivered →
CPU returns to ~0% within ~2 seconds.

The second `process_freeze succeeded` is a no-op: a separate anomaly
detector also fires on the same tick, but since all real culprits are
already frozen and no remaining process is above `min_cpu_to_freeze`
(50.0%), the action correctly does nothing.
