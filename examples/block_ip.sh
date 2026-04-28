#!/bin/bash
# PanicMode example block_ip script — iptables backend.
#
# Invoked by the BlockIp action as: block_ip.sh <IP>
#
# Why iptables (not UFW):
#   - UFW writes its rule state to /etc/ufw/user.rules. Under the
#     systemd hardening shipped with panicmode.service (ReadOnlyPaths=/),
#     /etc/ufw is not writable, so every UFW invocation from the
#     daemon fails and brute-force IPs are never actually blocked.
#   - iptables keeps rules in kernel netfilter, no /etc state. Persistence
#     across reboots is handled by panicmode itself (SQLite + the
#     restore_blocked_ips path on startup).
#
# Why idempotent:
#   - restore_blocked_ips re-runs this script for every stored IP on
#     each daemon start. Without an existence check, every restart would
#     append another duplicate DROP rule. After N restarts you end up
#     with N copies of each rule, polluting iptables and slowing rule
#     evaluation. `iptables -C` returns 0 if the rule already exists,
#     so we no-op cleanly.
#
# Required systemd hardening (already in panicmode.service):
#   RestrictAddressFamilies must include AF_NETLINK (iptables uses it
#   to talk to kernel netfilter), and ReadWritePaths must include /run
#   (iptables takes /run/xtables.lock during rule changes).

set -euo pipefail
IP="${1:?Usage: block_ip.sh <IP>}"

# Pick the right tool based on address family.
if [[ "$IP" =~ : ]]; then
    IPT=/usr/sbin/ip6tables
else
    IPT=/usr/sbin/iptables
fi

# Already blocked? Nothing to do.
if "$IPT" -C INPUT -s "$IP" -j DROP 2>/dev/null; then
    exit 0
fi

# Insert at position 1 so the deny takes priority over any allow rules.
"$IPT" -I INPUT 1 -s "$IP" -j DROP
exit 0
