---
title: Playbook - Phishing and Malicious Attachments
type: playbook
tags: [email, initial-access, phishing]
mitre: [T1566, T1566.001, T1566.002, T1204.002]
---

## Indicators
- Lookalike or newly registered sender domains; display-name spoofing of finance or IT.
- Macro-enabled Office documents (.docm, .xlsm), ISO/LNK/HTML attachments, or credential-harvesting links.
- Urgent payment, invoice, or password-expiry themes.

## Triage
1. Determine whether the message was **delivered** and whether the user opened the attachment or
   clicked the link (proxy, EDR process tree: WINWORD.EXE spawning powershell/cmd/mshta).
2. Find all recipients of the same sender, subject, or attachment hash.
3. If endpoint execution occurred, escalate to malware/intrusion handling for that host.

## Risk guidance
- Blocked/quarantined, not delivered: low.
- Delivered, no interaction: medium.
- Attachment opened or credentials entered: high; followed by endpoint alerts on the same host: critical.

## Containment
- Purge the message from all mailboxes; block sender domain, URLs, and attachment hash.
- If credentials were entered: reset password, revoke sessions and tokens, review MFA methods
  and mailbox rules (forwarding rules are a common persistence trick).

## Prevention
- Block macros from the internet; sandbox attachments; tag external email; user awareness training.
