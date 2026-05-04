# Threat statistics — production VPS, days 1-5

Aggregated from a Contabo VPS in France running PanicMode v0.1.x alongside
`fail2ban` for the first five days after deployment. SSH on port 22, no
other ports exposed publicly. No advertised activity, no sites, no
mentions of the IP anywhere — purely passive exposure to the IPv4
background noise.

These numbers are from the 28 April → 3 May window, the same period
referenced in the README's status block.

---

## Headline

| | |
|---|---|
| Unique source IPs blocked | **98** |
| Total ban events | **946** (same IPs returned and were re-banned after `bantime` expired) |
| Total SSH brute-force attempts | **7,259** |
| Source ASNs | **37** |
| Source countries | **19** |
| False positives | **0** |
| Crashes | **0** |

The 946-vs-98 ratio (≈ 9.6 ban events per unique IP) shows the
"persistent retry" pattern — most attackers came back multiple times
across the window, often within an hour of `bantime` expiring.

---

## Top 10 source ASNs

| Bans | ASN | Country (allocated) | Operator |
|---:|---|---|---|
|  23 | AS47890 | RO | UNMANAGED-DEDICATED-SERVERS (UK-registered, RO-hosted) |
|   8 | AS24086 | VN | Viettel Corporation (Vietnamese state telecom) |
|   6 | AS48090 | RO | DMZHOST (UK-registered, RO-hosted) |
|   4 | AS14061 | US | DigitalOcean |
|   4 | AS7552  | VN | Viettel Group AP |
|   3 | AS4837  | CN | China Unicom |
|   3 | AS38365 | CN | Baidu |
|   3 | AS16276 | FR | OVH |
|   3 | AS51396 | DE | PFCLOUD |
|   2 | AS4766  | KR | Korea Telecom |

The pattern is the standard 2026 SSH-brute-force shape:

- **Bulletproof / abuse-tolerant hosting** at the top — `UNMANAGED-DEDICATED-SERVERS`, `DMZHOST`, `PFCLOUD` are all known to refuse abuse-complaint takedowns. Together they account for ~38 % of all unique source IPs.
- **Compromised commercial cloud** in the middle — DigitalOcean, OVH, Oracle BMC. These are mainstream providers; the IPs are almost certainly hijacked instances or expired-credential takeovers, not the providers themselves.
- **Compromised consumer / corporate networks** in the tail — Viettel (VN), Baidu (CN), Korea Telecom (KR), Telenor (SE). End-user devices behind these ISPs were almost certainly recruited into botnets without their owners' knowledge.

---

## Top 10 source countries

| IPs | Country |
|---:|---|
| 29 | 🇷🇴 Romania |
| 18 | 🇨🇳 China |
| 12 | 🇻🇳 Vietnam |
|  9 | 🇺🇸 United States |
|  7 | 🇩🇪 Germany |
|  5 | 🇧🇬 Bulgaria |
|  3 | 🇫🇷 France |
|  2 | 🇳🇱 Netherlands |
|  2 | 🇰🇷 South Korea |
|  2 | 🇮🇳 India |

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
