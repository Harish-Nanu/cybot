---
title: Organization - Critical Asset Inventory
type: asset
tags: [assets, criticality, context]
mitre: []
---

## Internet-facing servers
- **web-srv-01** (10.0.1.20): production customer web portal, Ubuntu 22.04, SSH exposed for the
  deploy pipeline. Criticality: HIGH. Owner: Platform team. The `deploy` account has passwordless sudo.
- **vpn-gw-01** (10.0.0.5): remote-access VPN concentrator. Criticality: CRITICAL.

## Finance department
- **WS-FIN-07** (10.0.2.57): finance workstation used by j.doe (Accounts Payable). Has access to the
  ERP payment module and the finance file share containing payroll and vendor banking data.
  Criticality: HIGH; data classification: Confidential / regulated financial data.
- Finance users are frequent targets of invoice-themed phishing.

## Identity
- **dc-01 / dc-02**: Active Directory domain controllers. Criticality: CRITICAL. Any credential
  exposure of Domain Admins requires a krbtgt reset.

## Network ranges
- 10.0.1.0/24 DMZ servers, 10.0.2.0/24 corporate workstations, 10.0.9.0/24 management.
- External IP ranges 203.0.113.0/24 and 198.51.100.0/24 are not owned by the organization.
