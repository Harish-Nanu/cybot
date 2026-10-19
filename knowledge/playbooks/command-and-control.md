---
title: Playbook - Command and Control (C2) Beaconing
type: playbook
tags: [network, c2, cobalt-strike, beacon]
mitre: [T1071, T1071.001, T1071.004, T1573, T1105]
---

## Indicators
- Periodic outbound connections with regular intervals and jitter to rare domains or IPs.
- IDS signatures for known frameworks (Cobalt Strike, Sliver, Metasploit, Brute Ratel).
- Newly registered or typosquatted domains mimicking CDNs/updates; long or random subdomains (DNS C2).

## Triage
1. Identify the internal host and process making the connections (EDR network telemetry).
2. Determine first-seen time and how many hosts contact the same destination.
3. Correlate with endpoint alerts (credential dumping, suspicious PowerShell) on the same host and
   with large outbound transfers to the same destination (exfiltration over C2, T1041).

## Risk guidance
- Single signature hit, no endpoint corroboration: medium to high.
- Confirmed beacon with endpoint malicious activity: critical.

## Containment
- Isolate the host; block the domain and IP at DNS, proxy, and firewall.
- Sinkhole the domain internally to find other infected hosts.

## Eradication and recovery
- Identify persistence (services, scheduled tasks, run keys, WMI subscriptions) and reimage.
