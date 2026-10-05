# Attack Timeline

## Incident ID
NEX-2026-001

## Affected Host
- Hostname: WIN-CLIENT01
- IP Address: 192.168.10.25
- Domain: CORP.LOCAL
- User: ahmed

## Timeline

| Time | Source | Event | Assessment |
|---|---|---|---|
| 10:01:12 | Windows Security | Successful interactive logon for ahmed | Normal user activity / session start |
| 10:01:12 | Sysmon Event ID 1 | WINWORD.EXE launched malicious_document.docm | Potential initial compromise |
| 10:01:14 | Sysmon Event ID 1 | WINWORD.EXE spawned PowerShell with encoded command | Suspicious execution |
| 10:01:14 | SIEM | Office Application Spawning PowerShell alert | Detection triggered |
| 10:02:05 | Sysmon Event ID 10 | credential_tool.exe accessed LSASS | Potential credential access |
| 10:02:05 | SIEM | Potential Credential Access alert | Detection triggered |
| 10:03:11 | Windows Security 4625 | Failed network logon for ahmed from 192.168.10.50 | Suspicious authentication activity |
| 10:03:12 | Windows Security 4624 | Successful network logon for ahmed from 192.168.10.50 | Possible account misuse; requires investigation |
| 10:04:20 | Sysmon | PowerShell executed Invoke-WebRequest | Potential network retrieval |
| 10:04:20 | DNS | update-check.example resolved to 203.0.113.50 | Suspicious external infrastructure |
| 10:04:20 | SIEM | Suspicious DNS Request alert | Detection triggered |
| 10:04:21 | Network | WIN-CLIENT01 connected to 203.0.113.50:443 | Potential C2 communication |
| 10:04:21 | SIEM | Potential C2 Communication alert | Detection triggered |
| 10:05:21 | Network | Repeated connection to 203.0.113.50:443 | Potential beaconing |
| 10:06:21 | Network | Repeated connection to 203.0.113.50:443 | Potential beaconing |

## Attack Chain

User
↓
malicious_document.docm
↓
WINWORD.EXE
↓
PowerShell
↓
Potential LSASS access
↓
Suspicious authentication activity
↓
PowerShell network activity
↓
Suspicious DNS resolution
↓
Repeated outbound HTTPS communication
↓
Potential C2

## Initial Compromise Assessment

The earliest suspicious activity is WINWORD.EXE opening
malicious_document.docm and spawning PowerShell with an encoded
command.

This is assessed as the likely initial execution/compromise point
within the available simulated telemetry.

## Credential Access Assessment

At 10:02:05, credential_tool.exe executed from a PowerShell parent
process and accessed the LSASS process.

This represents potential credential-access activity.

The telemetry does not by itself prove successful credential theft.

## Authentication Assessment

A failed network logon followed one second later by a successful
network logon for the same account from 192.168.10.50 is suspicious.

The source IP should be investigated to determine whether it belongs
to an authorized system.

The failed login alone is not sufficient evidence to identify an
attacker.

## C2 Assessment

The workstation resolved update-check.example to 203.0.113.50 and
then established repeated TCP connections to port 443.

The repeated outbound communication is consistent with potential
command-and-control or beaconing behavior.

Because this is a simulated dataset, 203.0.113.50 and
update-check.example represent simulated attacker infrastructure.

## Confidence

Overall assessment: HIGH

Reasoning:
- Office application spawned PowerShell.
- PowerShell used an encoded command.
- A child process accessed LSASS.
- Suspicious authentication activity followed.
- PowerShell performed network activity.
- Suspicious DNS resolution occurred.
- Repeated outbound connections followed.

These events form a correlated attack chain rather than isolated alerts.