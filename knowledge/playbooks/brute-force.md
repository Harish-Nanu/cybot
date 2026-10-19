---
title: Playbook - Brute Force and Password Spraying
type: playbook
tags: [authentication, ssh, rdp, credential-access]
mitre: [T1110, T1110.001, T1110.003, T1110.004, T1078]
---

## Indicators
- Many failed authentications from one source against one or many accounts (guessing).
- Few failures per account but across many accounts from one source (password spraying).
- Failures against non-existent or default accounts (admin, root, test, oracle).
- Internet-facing services (SSH, RDP, VPN, OWA, SSO portals) are the most common targets.

## Triage
1. Determine whether any authentication **succeeded** from the same source IP or for the targeted
   accounts after the failures. A success following a burst of failures is a strong indicator of
   compromise (T1078 Valid Accounts) and should raise risk to high or critical.
2. Check source IP reputation and geolocation; note hosting/VPS providers and TOR exit nodes.
3. Identify whether the target account is privileged, a service account, or disabled.
4. Correlate with reconnaissance alerts (port scans) from the same source shortly before.

## Risk guidance
- Failed attempts only, blocked at perimeter, no success: low to medium.
- Sustained attempts against an internet-facing production server: medium.
- Successful login after brute force: high; if the account is privileged or the host is critical: critical.

## Containment
- Block the source IP/range at the firewall or WAF; enable fail2ban / account lockout thresholds.
- If a login succeeded: disable or reset the affected account, terminate active sessions,
  and isolate the host if post-login activity is observed.

## Eradication and recovery
- Review authorized_keys, cron jobs, new users, and sudoers on Linux hosts for persistence.
- Rotate credentials for any account that authenticated from the attacker source.

## Prevention
- Disable password authentication for SSH; require keys or MFA.
- Restrict management services to VPN or bastion hosts; enforce MFA on all remote access.
