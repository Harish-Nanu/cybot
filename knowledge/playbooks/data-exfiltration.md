---
title: Playbook - Data Exfiltration
type: playbook
tags: [exfiltration, dlp, network]
mitre: [T1041, T1048, T1567, T1567.002, T1560]
---

## Indicators
- Outbound volume far above the host's or user's baseline, especially outside business hours.
- Uploads to cloud storage, paste sites, or to the same destination used for C2.
- Archive creation (7z, rar, zip) of sensitive directories shortly before transfer (T1560).

## Triage
1. Identify the data source: which host, user, and directories; classify the data sensitivity.
2. Check whether the destination is a known business service or attacker infrastructure.
3. Correlate with prior C2 or credential-access alerts on the same host; exfiltration is usually
   a late-stage action in an intrusion chain.

## Risk guidance
- Large transfer to a sanctioned service by an expected user: low to medium.
- Large transfer to unknown/attacker infrastructure from a host with prior malicious activity: critical.
- Involves regulated data (PII, PCI, financial records): critical and triggers legal/privacy notification.

## Containment
- Block the destination; isolate the host; suspend the user's sessions and access tokens.
- Preserve proxy/firewall logs and netflow for scoping the volume and content exfiltrated.

## Recovery
- Engage legal and privacy teams to evaluate breach-notification obligations.
