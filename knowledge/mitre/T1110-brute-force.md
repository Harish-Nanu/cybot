---
title: ATT&CK T1110 - Brute Force
type: technique
tags: [credential-access]
mitre: [T1110, T1110.001, T1110.003, T1110.004]
---

## Description
Adversaries use brute force to obtain access to accounts when passwords are unknown or hashes are
obtained. Sub-techniques: Password Guessing (T1110.001), Password Cracking (T1110.002),
Password Spraying (T1110.003), Credential Stuffing (T1110.004). Tactic: Credential Access.

## Detection
Monitor authentication logs for many failures per source or per account, and failures across many
accounts from one source. Correlate failures with subsequent successful logons.

## Mitigation
M1032 Multi-factor Authentication, M1036 Account Use Policies (lockout), M1027 Password Policies.
