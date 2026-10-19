---
title: ATT&CK T1003 - OS Credential Dumping
type: technique
tags: [credential-access]
mitre: [T1003, T1003.001, T1003.002, T1003.003]
---

## Description
Adversaries dump credentials from the operating system to obtain account login material.
LSASS Memory (T1003.001) is the most common sub-technique, typically via Mimikatz or minidumps.
Others include Security Account Manager (T1003.002) and NTDS (T1003.003).

## Detection
Monitor process access to lsass.exe, creation of lsass dump files, and command lines containing
sekurlsa, MiniDump, or procdump targeting lsass.

## Mitigation
M1043 Credential Access Protection (Credential Guard), M1025 Privileged Process Integrity (RunAsPPL),
M1026 Privileged Account Management.
