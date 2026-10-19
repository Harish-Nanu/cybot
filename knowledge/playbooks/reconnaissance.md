---
title: Playbook - Network Scanning and Reconnaissance
type: playbook
tags: [network, scanning, discovery]
mitre: [T1046, T1595, T1595.001, T1590]
---

## Indicators
- One source touching many ports or many hosts in a short window (nmap, masscan, zmap).
- IDS signatures such as "ET SCAN" categories.

## Triage
1. External scanning of internet-facing assets is constant background noise; on its own it is
   informational to low risk.
2. Raise priority when the same source later attempts authentication or exploitation, or when
   the scan originates from an **internal** host (possible compromised host performing discovery).

## Risk guidance
- External scan, no follow-up activity: informational or low.
- Scan followed by brute force or exploit attempts from the same IP: medium to high.
- Internal host scanning the network: high (possible lateral movement preparation).

## Response
- Block persistent external scanners at the perimeter.
- For internal scanning, identify the process responsible and treat the host as potentially compromised.
