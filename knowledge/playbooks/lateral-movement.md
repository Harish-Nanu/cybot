---
title: Playbook - Lateral Movement
type: playbook
tags: [windows, lateral-movement, smb, rdp, psexec]
mitre: [T1021, T1021.001, T1021.002, T1021.006, T1550.002, T1569.002]
---

## Indicators
- PsExec/remote service creation, WMI or WinRM remote execution, admin share (C$, ADMIN$) access.
- NTLM logons (type 3) from workstations to many other workstations; pass-the-hash patterns.
- RDP between workstations, which is rare in most environments.

## Triage
1. Map the source host and account; check if the account was exposed in a credential-dumping alert.
2. Build a timeline of hosts accessed by the account in the last 24 to 72 hours.

## Risk guidance
- Lateral movement with credentials stolen from another host is high to critical.

## Containment
- Isolate source and destination hosts; disable the account; block SMB/RDP between workstations.
