# SOC Incident Report

## Incident Information

- Incident ID: NEX-2026-001
- Incident Type: Windows Workstation Compromise
- Severity: HIGH
- Affected Host: WIN-CLIENT01
- Host IP: 192.168.10.25
- Domain: CORP.LOCAL
- Affected Account: ahmed
- Status: Simulated investigation

---

## Executive Summary

WIN-CLIENT01 shows a sequence of suspicious activities beginning with
a malicious Office document execution.

WINWORD.EXE spawned PowerShell with an encoded command. Shortly
afterwards, a suspicious process accessed LSASS, indicating potential
credential-access activity.

Authentication telemetry then showed a failed network authentication
followed one second later by a successful authentication for the same
account from 192.168.10.50.

The workstation subsequently performed PowerShell network activity,
resolved a suspicious domain to 203.0.113.50, and established repeated
outbound TCP connections to port 443.

The combined activity is consistent with a simulated workstation
compromise involving execution, potential credential access, suspicious
authentication activity, and potential command-and-control
communication.

---

## Initial Compromise

The earliest suspicious activity is:

10:01:12 - WINWORD.EXE opened malicious_document.docm.

10:01:14 - WINWORD.EXE spawned powershell.exe using an encoded
PowerShell command.

This Office-to-PowerShell execution chain is assessed as the likely
initial compromise/execution point within the available telemetry.

---

## Authentication Analysis

At 10:03:11, account ahmed experienced a failed network logon from
192.168.10.50.

At 10:03:12, the same account successfully authenticated from
192.168.10.50.

The one-second transition from failure to success is suspicious and
should be investigated.

The authentication events alone do not prove attacker activity.
192.168.10.50 should be validated against known corporate assets and
authorized users.

---

## Process Analysis

Observed process chain:

explorer.exe
└── WINWORD.EXE
    └── powershell.exe
        └── credential_tool.exe

The Office application spawning PowerShell is suspicious.

The subsequent credential_tool.exe process originated from PowerShell
and attempted to access LSASS.

---

## PowerShell Investigation

PowerShell was executed by WINWORD.EXE using:

- -NoProfile
- -EncodedCommand

Later PowerShell activity used:

- Invoke-WebRequest

The combination of encoded PowerShell execution, suspicious parent
process, and subsequent network activity increases the confidence that
the PowerShell activity was part of the simulated attack chain.

---

## Credential Access

At 10:02:05, credential_tool.exe attempted to access:

C:\Windows\System32\lsass.exe

This is consistent with potential credential-access activity.

The telemetry does not prove that credentials were successfully
extracted.

---

## Network and C2 Analysis

At 10:04:20:

update-check.example

resolved to:

203.0.113.50

The workstation then established repeated TCP connections:

192.168.10.25 → 203.0.113.50:443

at:

- 10:04:21
- 10:05:21
- 10:06:21

The repeated outbound communication is consistent with potential
command-and-control or beaconing behavior.

The infrastructure is simulated for this assignment.

---

## Indicators of Compromise

| Type | Indicator |
|---|---|
| Host | WIN-CLIENT01 |
| IP | 203.0.113.50 |
| Domain | update-check.example |
| Source IP | 192.168.10.50 |
| Account | ahmed |
| Process | powershell.exe |
| Process | credential_tool.exe |
| File | malicious_document.docm |

---

## MITRE ATT&CK Mapping

- T1204.002 - User Execution: Malicious File
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1003.001 - OS Credential Dumping: LSASS Memory
- T1105 - Ingress Tool Transfer
- T1071.004 - Application Layer Protocol: DNS
- T1071.001 - Application Layer Protocol: Web Protocols

---

## Detection Coverage

Two detection rules were developed:

### Detection 1

Office applications spawning PowerShell.

Files:

- detections/office_spawns_powershell.yml
- detections/office_spawns_powershell.kql

### Detection 2

Suspicious access to LSASS.

Files:

- detections/credential_access_lsass.yml
- detections/credential_access_lsass.kql

Both detections include false-positive considerations.

---

## Incident Severity

### Severity: HIGH

Reasoning:

- Suspicious Office-to-PowerShell execution
- Encoded PowerShell command
- Potential LSASS credential access
- Suspicious authentication activity
- Suspicious DNS resolution
- Repeated outbound communication to simulated C2 infrastructure

The combination of these events represents a potentially compromised
workstation and potentially exposed credentials.

---

## Containment Strategy

1. Isolate WIN-CLIENT01 from the network.
2. Prevent further communication with the simulated C2 IP and domain.
3. Disable or temporarily restrict the affected account if compromise
   is confirmed.
4. Preserve relevant Windows, Sysmon, DNS, and network telemetry.
5. Identify whether 192.168.10.50 is an authorized corporate system.
6. Search other systems for the identified IOCs.
7. Prevent execution of the malicious document.

---

## Recovery Strategy

1. Perform a full endpoint investigation.
2. Reset credentials associated with the affected account if credential
   compromise is confirmed or suspected.
3. Remove malicious files and unauthorized tooling.
4. Verify persistence mechanisms have not been established.
5. Patch affected software and operating systems.
6. Restore the workstation from a known-good state if required.
7. Reconnect the workstation only after security validation.
8. Monitor the affected host and account for recurring suspicious
   activity.

---

## Lessons Learned

The incident demonstrates the value of correlating multiple telemetry
sources instead of investigating individual alerts independently.

Important correlations include:

Office → PowerShell
PowerShell → LSASS access
Authentication → suspicious source
DNS → external infrastructure
Network → repeated outbound communication

Future detection improvements should prioritize behavioral correlation,
process context, authentication context, and network enrichment.

---

## Conclusion

The simulated investigation identified a coherent attack chain involving
initial Office document execution, PowerShell activity, potential
credential access, suspicious authentication, and potential C2
communication.

The incident should be treated as a HIGH-severity simulated security
incident requiring endpoint isolation, credential investigation,
IOC hunting, and controlled recovery.