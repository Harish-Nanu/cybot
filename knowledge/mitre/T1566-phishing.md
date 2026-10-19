---
title: ATT&CK T1566 - Phishing
type: technique
tags: [initial-access]
mitre: [T1566, T1566.001, T1566.002, T1566.003]
---

## Description
Adversaries send phishing messages to gain access. Sub-techniques: Spearphishing Attachment
(T1566.001), Spearphishing Link (T1566.002), Spearphishing via Service (T1566.003).
User Execution: Malicious File (T1204.002) usually follows.

## Detection
Email gateway detonation, URL inspection, monitoring of Office applications spawning child processes.

## Mitigation
M1049 Antivirus/Antimalware, M1031 Network Intrusion Prevention, M1017 User Training,
M1054 Software Configuration (disable macros).
