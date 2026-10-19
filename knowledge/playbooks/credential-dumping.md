---
title: Playbook - Credential Dumping (LSASS / Mimikatz)
type: playbook
tags: [credential-access, windows, edr, mimikatz]
mitre: [T1003, T1003.001, T1550.002, T1078]
---

## Indicators
- Process access to lsass.exe with PROCESS_VM_READ by non-system binaries.
- Known tooling: mimikatz (sekurlsa::logonpasswords), procdump -ma lsass, comsvcs.dll MiniDump,
  nanodump, or renamed copies of these.
- Execution from user-writable paths (Temp, Downloads, AppData) and `privilege::debug` usage.

## Triage
1. Treat confirmed LSASS dumping as an **active intrusion**: the attacker already has local admin
   or SYSTEM on the host. Default risk is critical.
2. Identify the parent process chain to find initial access (e.g., Office macro -> PowerShell).
3. Enumerate accounts with cached credentials on the host; assume they are compromised.
4. Look for subsequent lateral movement (T1021) and pass-the-hash (T1550.002) from the host.

## Containment
- Network-isolate the host via EDR immediately.
- Disable and reset passwords for all accounts that logged on to the host; reset krbtgt twice if a
  domain admin credential was exposed.
- Block the file hash organization-wide.

## Eradication and recovery
- Reimage the host rather than cleaning it.
- Hunt for the same hash, command line, and parent chain across all endpoints.

## Prevention
- Enable LSA Protection (RunAsPPL) and Credential Guard.
- Remove local admin rights from standard users; enable ASR rule "Block credential stealing from LSASS".
