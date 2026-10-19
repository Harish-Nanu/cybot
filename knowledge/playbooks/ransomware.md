---
title: Playbook - Ransomware
type: playbook
tags: [ransomware, impact, malware]
mitre: [T1486, T1490, T1489]
---

## Indicators
- Mass file renames/modifications with new extensions, ransom notes, vssadmin/wbadmin shadow copy deletion.
- Precursors: credential dumping, lateral movement, disabling security tools.

## Response
1. Risk is always critical. Isolate affected hosts and segments immediately.
2. Disable compromised accounts; protect and verify offline backups.
3. Engage incident response retainer, legal, and executive leadership per the escalation policy.
