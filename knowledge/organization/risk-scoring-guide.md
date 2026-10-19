---
title: Organization - Risk Scoring Guide
type: policy
tags: [risk, scoring, triage]
mitre: []
---

## Score bands
- 0-19 informational: benign or expected activity, no action beyond logging.
- 20-39 low: suspicious but blocked or unlikely to succeed; review in daily triage.
- 40-59 medium: plausible malicious activity without evidence of success; investigate within 24 hours.
- 60-79 high: likely malicious with partial success or a high-value target; respond within 4 hours.
- 80-100 critical: confirmed compromise, active attacker, or regulated data at risk; respond immediately.

## Factors that raise the score
- Evidence of success (successful login, code execution, data transfer) rather than an attempt.
- Asset criticality HIGH or CRITICAL (see the asset inventory) or privileged accounts involved.
- Correlated alerts on the same host, user, or indicator forming a kill-chain progression
  (e.g., phishing -> execution -> credential dumping -> C2 -> exfiltration).
- Known-malicious tooling (Mimikatz, Cobalt Strike) or known-bad infrastructure.

## Factors that lower the score
- Activity blocked by a preventive control with no follow-up.
- Matching an approved change ticket or known scanner/vulnerability-management source.
- Isolated single low-fidelity signature with no corroboration.
