---
title: ATT&CK T1041 - Exfiltration Over C2 Channel
type: technique
tags: [exfiltration]
mitre: [T1041]
---

## Description
Adversaries steal data by exfiltrating it over an existing command and control channel, encoding
data into normal C2 communications.

## Detection
Detect hosts sending significantly more data than they receive to a destination, particularly
when the destination is associated with C2 activity.

## Mitigation
M1057 Data Loss Prevention, M1031 Network Intrusion Prevention.
