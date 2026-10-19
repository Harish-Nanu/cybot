---
title: Organization - Incident Escalation Policy
type: policy
tags: [escalation, sla, communication]
mitre: []
---

## Response SLAs
- Critical: page the on-call incident commander immediately; containment within 1 hour;
  notify CISO. If regulated data may be affected, notify Legal and Privacy within 24 hours.
- High: SOC tier-2 engages within 4 hours; notify the asset owner.
- Medium: investigate within 1 business day.
- Low / informational: weekly review and tuning.

## Approval rules
- SOC analysts may isolate workstations and block external IPs/domains without approval.
- Isolating production servers (e.g., web-srv-01) requires approval from the service owner or
  incident commander, unless active data destruction or exfiltration is in progress.
- Password resets for executives and service accounts are coordinated with the IAM team.
