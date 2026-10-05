# Nexcore Alliance - Simulated SOC Incident

## Incident ID

NEX-2026-001

## Incident Type

Windows Workstation Compromise

## Affected Host

- Hostname: WIN-CLIENT01
- IP Address: 192.168.10.25
- Domain: CORP.LOCAL
- User: ahmed

## Simulated Attacker Infrastructure

- C2 IP: 203.0.113.50
- C2 Domain: update-check.example

## Attack Scenario

A user on WIN-CLIENT01 opens a malicious Office document.

The document launches PowerShell, which executes a suspicious command.

The attacker then performs credential-access activity.

Suspicious authentication activity is subsequently observed.

The compromised workstation makes DNS requests to suspicious infrastructure and establishes repeated network communication with the simulated C2 server.

The SOC receives alerts and begins an investigation.

## Investigation Objectives

1. Reconstruct the attack timeline.
2. Identify the initial compromise.
3. Correlate authentication events.
4. Analyse the process tree.
5. Investigate PowerShell activity.
6. Investigate potential credential access.
7. Analyse network communication.
8. Identify potential C2 activity.
9. Extract IOCs.
10. Identify affected accounts and systems.
11. Map observed behaviour to MITRE ATT&CK.
12. Identify detection gaps.
13. Create two Sigma rules.
14. Create corresponding KQL queries.
15. Explain potential false positives.
16. Recommend detection improvements.
17. Determine incident severity.
18. Recommend containment and recovery actions.
19. Produce a final SOC incident report.