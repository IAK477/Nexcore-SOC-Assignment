# Detection Gaps, False Positives & Improvements

## 1. Detection Gaps

### Gap 1 — Office-to-PowerShell Detection

The environment should detect Office applications spawning
PowerShell.

Risk:
An attacker can abuse trusted Office applications to execute
malicious scripts.

Current evidence:
WINWORD.EXE spawned powershell.exe.

Improvement:
Monitor parent-child process relationships and prioritize Office
applications spawning scripting interpreters.

---

### Gap 2 — Encoded PowerShell Detection

Encoded PowerShell commands can hide the actual command content.

Current evidence:
PowerShell was launched using `-EncodedCommand`.

Improvement:
Monitor PowerShell command-line arguments, encoded commands,
PowerShell logging, and suspicious parent processes.

---

### Gap 3 — LSASS Access Monitoring

Access to LSASS can indicate credential-access activity.

Current evidence:
credential_tool.exe accessed lsass.exe.

Improvement:
Enable and monitor Sysmon Process Access events and correlate the
source process, target process, user, command line, and parent process.

---

### Gap 4 — Suspicious Authentication Correlation

A failed authentication was followed one second later by a successful
authentication from the same source address.

Current evidence:
192.168.10.50 generated Event ID 4625 followed by Event ID 4624.

Improvement:
Correlate authentication failures and successes with source IP,
account, workstation, time interval, and known asset information.

---

### Gap 5 — DNS and Network Correlation

DNS resolution and subsequent network connections should be correlated.

Current evidence:
update-check.example resolved to 203.0.113.50 followed by repeated
connections to 203.0.113.50:443.

Improvement:
Correlate DNS, proxy/firewall, endpoint, and network telemetry to
identify suspicious infrastructure and beaconing behavior.

---

## 2. False-Positive Scenarios

### Office → PowerShell

Possible legitimate causes:

- Authorized Office automation
- Administrative scripts
- Enterprise macros
- Security testing

### LSASS Access

Possible legitimate causes:

- Endpoint security software
- EDR/security agents
- Authorized diagnostic tools
- System administration

### Failed → Successful Authentication

Possible legitimate causes:

- User entering an incorrect password
- Cached or outdated credentials
- Automated services
- Authorized remote administration

### Suspicious DNS / C2-Like Traffic

Possible legitimate causes:

- Security research
- Internal testing infrastructure
- Software update systems
- Authorized monitoring systems

---

## 3. Detection Improvements

### Correlation

Combine multiple weak signals into a stronger detection:

Office → PowerShell → LSASS access → DNS request → outbound connection

This reduces reliance on a single event.

### Process Context

Include:

- Parent process
- Child process
- Command line
- User
- Host
- Process ID

### Network Context

Include:

- Destination IP
- Destination domain
- Destination port
- Connection frequency
- DNS resolution
- Known-good/known-bad infrastructure

### Authentication Context

Include:

- Source IP
- Username
- Logon type
- Failure count
- Successful authentication
- Source workstation

### Risk-Based Alerting

Increase severity when multiple suspicious behaviors occur on the
same host within a short time window.

Example:

Office spawning PowerShell alone → investigate.

Office spawning PowerShell + LSASS access + suspicious DNS +
repeated outbound communication → high-priority incident.

---

## 4. Recommended SOC Improvements

1. Enable detailed PowerShell logging.
2. Maintain Sysmon process creation and process access telemetry.
3. Centralize Windows authentication logs.
4. Correlate endpoint, DNS, and network telemetry.
5. Maintain allowlists for legitimate administrative/security tools.
6. Enrich alerts with asset and user context.
7. Create automated isolation procedures for confirmed compromise.
8. Regularly test detections against simulated attack scenarios.