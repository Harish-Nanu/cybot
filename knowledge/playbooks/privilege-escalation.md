---
title: Playbook - Privilege Escalation
type: playbook
tags: [privilege-escalation, linux, windows]
mitre: [T1068, T1548, T1548.002, T1548.003, T1134]
---

## Indicators
- Unexpected sudo usage, new sudoers entries, setuid binaries, or kernel exploit tooling on Linux.
- UAC bypass techniques (fodhelper, eventvwr), token manipulation, or exploitation of vulnerable drivers on Windows.

## Triage
1. Determine the user and process that gained elevated rights and whether the activity was authorized change management.
2. Check for preceding initial-access alerts (successful brute force, phishing execution) on the host.

## Risk guidance
- Successful escalation by an unknown process or after a suspicious login: high to critical.

## Response
- Isolate the host, revoke the account's sessions, and capture memory before reimaging.
