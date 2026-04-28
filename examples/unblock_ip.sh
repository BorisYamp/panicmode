#!/bin/bash
# PanicMode example unblock_ip script — iptables backend.
#
# Invoked by the panicmode-ctl `unblock` command as: unblock_ip.sh <IP>
#
# Idempotent: if the rule does not exist, the script still exits 0.
# panicmode-ctl will then remove the IP from SQLite without surprise.

set -uo pipefail
IP="${1:?Usage: unblock_ip.sh <IP>}"

if [[ "$IP" =~ : ]]; then
    IPT=/usr/sbin/ip6tables
else
    IPT=/usr/sbin/iptables
fi

# `-D` returns non-zero if the rule is absent — that's fine, we want
# unblock to be idempotent. Suppress its noise.
"$IPT" -D INPUT -s "$IP" -j DROP 2>/dev/null || true
exit 0
