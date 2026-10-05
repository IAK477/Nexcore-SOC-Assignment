# Nexcore SOC Attack Reconstruction & Detection Engineering

## Overview

This project was created for the Nexcore Alliance Cyber Security Analyst
Intern assignment.

The assignment required reconstruction of a Windows workstation
compromise using security telemetry, identification of the attack chain,
IOC extraction, MITRE ATT&CK mapping, and detection engineering.

> **Note:** No telemetry dataset was provided with the assignment.
> Therefore, this repository uses a clearly labelled synthetic telemetry
> dataset created for investigation and detection-engineering practice.
> All attacker infrastructure indicators are simulated.

## Incident Summary

- **Incident ID:** NEX-2026-001
- **Affected Host:** WIN-CLIENT01
- **IP Address:** 192.168.10.25
- **Domain:** CORP.LOCAL
- **Affected User:** ahmed
- **Severity:** HIGH

### Simulated Attack Chain

```text
User
 ↓
malicious_document.docm
 ↓
WINWORD.EXE
 ↓
PowerShell
 ↓
Potential LSASS Access
 ↓
Suspicious Authentication
 ↓
PowerShell Network Activity
 ↓
Suspicious DNS Resolution
 ↓
Repeated HTTPS Communication
 ↓
Potential C2
````

## Investigation Objectives

* Attack timeline reconstruction
* Initial compromise identification
* Authentication correlation
* Process tree analysis
* PowerShell investigation
* Credential-access investigation
* Network communication analysis
* Potential C2 identification
* IOC extraction
* Affected account/system identification
* MITRE ATT&CK mapping
* Detection gap analysis
* Sigma detection rules
* KQL detection queries
* False-positive analysis
* Detection improvements
* Incident severity assessment
* Containment and recovery
* Final SOC incident report

## Repository Structure

```text
Nexcore-SOC-Assignment/
├── analysis/
│   ├── attack_timeline.md
│   ├── detection_gaps.md
│   ├── iocs.csv
│   ├── mitre_mapping.md
│   └── process_tree.md
│
├── data/
│   ├── dns.csv
│   ├── network.csv
│   ├── siem_alerts.csv
│   ├── sysmon.csv
│   └── windows_security.csv
│
├── detections/
│   ├── credential_access_lsass.kql
│   ├── credential_access_lsass.yml
│   ├── office_spawns_powershell.kql
│   └── office_spawns_powershell.yml
│
├── report/
│   └── final_soc_incident_report.md
│
├── scripts/
│   ├── generate_telemetry.py
│   └── investigate.py
│
└── scenario.md
```

## Key Findings

### Initial Compromise

WINWORD.EXE opened `malicious_document.docm` and spawned PowerShell
using an encoded command.

### Credential Access

A simulated process attempted to access:

```text
C:\Windows\System32\lsass.exe
```

This represents potential credential-access activity.

### Authentication

A failed network authentication was followed one second later by a
successful authentication for the same account from `192.168.10.50`.

This was treated as suspicious activity requiring investigation rather
than definitive proof of attacker activity.

### Potential C2

The workstation resolved:

```text
update-check.example → 203.0.113.50
```

and subsequently established repeated TCP connections to:

```text
203.0.113.50:443
```

These indicators are simulated for this assignment.

## Detection Engineering

Exactly **two Sigma rules** and their corresponding KQL queries were
developed.

### 1. Office Application Spawning PowerShell

Detects Office applications spawning PowerShell.

```text
detections/office_spawns_powershell.yml
detections/office_spawns_powershell.kql
```

### 2. Suspicious LSASS Access

Detects processes accessing the Windows LSASS process.

```text
detections/credential_access_lsass.yml
detections/credential_access_lsass.kql
```

## MITRE ATT&CK

The investigation mapped observed behavior to:

| Technique                           | ID        |
| ----------------------------------- | --------- |
| User Execution: Malicious File      | T1204.002 |
| PowerShell                          | T1059.001 |
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Ingress Tool Transfer               | T1105     |
| DNS                                 | T1071.004 |
| Web Protocols                       | T1071.001 |

## Severity

**HIGH**

The severity assessment is based on the combination of suspicious
Office-to-PowerShell execution, potential LSASS access, suspicious
authentication, DNS activity, and repeated outbound communication.

## Containment & Recovery

Recommended actions include:

1. Isolate the affected workstation.
2. Restrict communication with identified suspicious infrastructure.
3. Investigate and reset affected credentials where appropriate.
4. Preserve relevant telemetry.
5. Hunt for the identified IOCs across the environment.
6. Investigate potential persistence.
7. Patch affected systems.
8. Restore from a known-good state if required.
9. Validate the system before reconnecting it.
10. Continue monitoring the affected host and account.

## Disclaimer

This is a **synthetic cybersecurity investigation project** created for
educational and interview-assignment purposes.

The telemetry, attacker infrastructure, domain, IP addresses, and attack
scenario are simulated and should not be interpreted as evidence of a
real-world compromise.

````

