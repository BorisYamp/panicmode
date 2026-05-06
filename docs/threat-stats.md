# Threat statistics — production VPS, days 1-8

Aggregated from a Contabo VPS in France running PanicMode v0.1.x. SSH on
port 22, no other ports exposed publicly. No advertised activity, no
sites, no mentions of the IP anywhere — purely passive exposure to the
IPv4 background noise.

The first ~8 days the box ran PanicMode alongside `fail2ban` as
defense-in-depth during early validation. Once PanicMode's
auth_failures monitor was tuned to the same threshold as fail2ban
(3 failures / 10 min) and demonstrated it caught the same attackers
*and* banned them permanently instead of cycling, fail2ban was
removed and PanicMode became the sole defender.

---

## Headline

| | |
|---|---|
| Unique attacker IPs in permanent blacklist | **122** |
| Total SSH brute-force attempts repelled | **17,889** |
| Source ASNs | **42** |
| Source countries | **19** |
| False positives | **0** |
| Crashes | **0** |
| PanicMode footprint | ~27 MB RAM, ~1 % CPU steady |

There's deliberately no "ban events" count here — once an IP is
permanently blocked, the kernel drops its packets at INPUT before they
hit sshd, so there's nothing to count beyond the first ban. The earlier
fail2ban-only days had a "ban events" stat (each cycle through the
10-minute timeout counted) but that metric is meaningless for a
permanent-ban model — and a worse signal anyway, since high event
counts mostly mean the same handful of IPs kept coming back, not that
the system was catching new attackers.

PanicMode's memory grew from ~15 MB on day 1 to ~27 MB on day 8 — the
growth is the in-memory state for the accumulating block list and is
linear in the number of blocked IPs, not in the daily attack volume.

---

## Top 10 source ASNs

| Bans | ASN | Country (allocated) | Operator |
|---:|---|---|---|
|  24 | AS47890 | RO | UNMANAGED-DEDICATED-SERVERS (UK-registered, RO-hosted) |
|  10 | AS24086 | VN | Viettel Corporation (Vietnamese state telecom) |
|   6 | AS7552  | VN | Viettel Group AP |
|   6 | AS48090 | RO | DMZHOST (UK-registered, RO-hosted) |
|   5 | AS14061 | US | DigitalOcean |
|   4 | AS4837  | CN | China Unicom |
|   4 | AS16276 | FR | OVH |
|   3 | AS38365 | CN | Baidu |
|   3 | AS23724 | CN | China Telecom IDC (Beijing) |
|   3 | AS4766  | KR | Korea Telecom |

The pattern is the standard 2026 SSH-brute-force shape:

- **Bulletproof / abuse-tolerant hosting** at the top — `UNMANAGED-DEDICATED-SERVERS`, `DMZHOST`, `PFCLOUD` are all known to refuse abuse-complaint takedowns. Together they account for ~38 % of all unique source IPs.
- **Compromised commercial cloud** in the middle — DigitalOcean, OVH, Oracle BMC. These are mainstream providers; the IPs are almost certainly hijacked instances or expired-credential takeovers, not the providers themselves.
- **Compromised consumer / corporate networks** in the tail — Viettel (VN), Baidu (CN), Korea Telecom (KR), Telenor (SE). End-user devices behind these ISPs were almost certainly recruited into botnets without their owners' knowledge.

---

## Top 10 source countries

| IPs | Country |
|---:|---|
| 30 | 🇷🇴 Romania |
| 22 | 🇨🇳 China |
| 16 | 🇻🇳 Vietnam |
| 11 | 🇺🇸 United States |
|  9 | 🇩🇪 Germany |
|  5 | 🇧🇬 Bulgaria |
|  4 | 🇫🇷 France |
|  3 | 🇰🇷 South Korea |
|  2 | 🇮🇳 India |
|  2 | 🇦🇪 United Arab Emirates |

Romania at the top is the bulletproof-hosting effect — it's where most
of the AS47890 / AS48090 IPs physically live, even though those ASes are
registered in the UK.

---

## How this was generated

```bash
# 1. Extract all unique source IPs from fail2ban logs
grep -hoE 'Ban [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /var/log/fail2ban.log* \
  | awk '{print $2}' | sort -u > banned_ips.txt
# (98 IPs in our case)

# 2. Bulk ASN/country lookup via Team Cymru's free whois service
( echo 'begin'
  echo 'verbose'
  cat banned_ips.txt
  echo 'end' ) | nc whois.cymru.com 43 > asn_lookup.txt

# 3. Aggregate (Python here, awk works too)
python3 -c "
from collections import Counter
asn_counts, country_counts = Counter(), Counter()
asn_names = {}
with open('asn_lookup.txt') as f:
    next(f)
    for line in f:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 7: continue
        asn_counts[(parts[0], parts[3])] += 1
        country_counts[parts[3]] += 1
        asn_names[parts[0]] = parts[6]
for (asn, cc), n in asn_counts.most_common(10):
    print(f'{n:3d}  AS{asn:6}  {cc}  {asn_names[asn][:60]}')
"
```

Total runtime: under 5 seconds for 98 IPs. Team Cymru bulk whois is the
standard way to do this — they maintain it precisely so people can
generate stats like these without per-lookup API rate limits.

---

## Why we don't publish the raw IP list

We deliberately don't ship `banned_ips.txt` itself. Most of those IPs
belong to **compromised** consumer routers, IoT devices, or hijacked
cloud instances — the actual owners are victims, not attackers.
Publishing the raw list would mark innocent third parties as malicious
and would arguably qualify as personal-data publication under GDPR
(Breyer v Germany, 2016).

If you want to verify the underlying claims:

1. Drop a fresh Linux VPS on any public IP. Wait 24-48 hours.
2. `grep -c sshd /var/log/auth.log | sort | uniq -c` — you will see
   hundreds of brute-force attempts from ~20-40 distinct IPs per day.
3. Run a few of them through [AbuseIPDB](https://www.abuseipdb.com/)
   or `whois`. The same ASNs will show up.

This isn't unique data — it's the IPv4 background hum. PanicMode just
stops it from reaching anything actionable on your box.
