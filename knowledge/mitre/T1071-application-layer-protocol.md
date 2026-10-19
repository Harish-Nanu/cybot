---
title: ATT&CK T1071 - Application Layer Protocol (C2)
type: technique
tags: [command-and-control]
mitre: [T1071, T1071.001, T1071.004]
---

## Description
Adversaries communicate with compromised systems using application-layer protocols (HTTP/S
T1071.001, DNS T1071.004) to blend in with normal traffic. Tactic: Command and Control.

## Detection
Analyze network data for uncommon flows, beaconing periodicity, rare destinations, and
mismatched protocol behavior. IDS signatures for known C2 frameworks.

## Mitigation
M1031 Network Intrusion Prevention, M1037 Filter Network Traffic.
