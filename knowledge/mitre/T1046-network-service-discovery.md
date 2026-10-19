---
title: ATT&CK T1046 - Network Service Discovery
type: technique
tags: [discovery]
mitre: [T1046, T1595]
---

## Description
Adversaries enumerate services running on remote hosts and devices (port scanning) to identify
targets for remote exploitation or lateral movement. Active Scanning (T1595) is the pre-compromise
equivalent performed from external infrastructure.

## Detection
Network IDS and flow data showing one source connecting to many ports or hosts.

## Mitigation
M1042 Disable or Remove Feature or Program, M1031 Network Intrusion Prevention, M1030 Network Segmentation.
