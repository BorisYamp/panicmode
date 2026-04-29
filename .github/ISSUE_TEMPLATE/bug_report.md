---
name: Bug report
about: Something doesn't work the way the docs / examples say it should
title: "[bug] "
labels: bug
---

<!--
Before filing: please reproduce against the latest `main`. v0.1.0
went through a 4-round hardening pass and many of the period's
obvious bugs are already fixed — see CHANGELOG.md.

If the bug is security-sensitive, do NOT post here. Use GitHub's
private security advisory flow or email the maintainer.
-->

## What happened

<!-- One paragraph describing the behaviour you observed. -->

## What you expected

<!-- One paragraph describing what should have happened. -->

## How to reproduce

1.
2.
3.

## Environment

- **Distro + kernel + systemd**: <!-- run `uname -srv && systemctl --version | head -1` -->
- **PanicMode commit / tag**: <!-- `git rev-parse HEAD` from the build, or "v0.1.0" -->
- **Where it runs**: bare metal / VPS provider / container / Docker (`docker-win` branch)

## Logs

```
# `journalctl -u panicmode --since "10 minutes ago" --no-pager` around the failure
```

## Config (redacted)

```yaml
# Paste the relevant subset of your config.yaml.
# Redact: bot_token, webhook_url, smtp_password, twilio creds, real IPs.
```

## Anything else

<!-- Workarounds you tried, related issues, hunches about root cause. -->
