---
title: ATT&CK T1078 - Valid Accounts
type: technique
tags: [initial-access, persistence, privilege-escalation, defense-evasion]
mitre: [T1078]
---

## Description
Adversaries obtain and abuse credentials of existing accounts to gain initial access, persist,
escalate privileges, or evade defenses. Activity blends in with legitimate use.

## Detection
Look for logons from unusual sources, geographies, or times; logons following brute force or
phishing; and service accounts used interactively.

## Mitigation
M1032 MFA, M1026 Privileged Account Management, M1018 User Account Management.
