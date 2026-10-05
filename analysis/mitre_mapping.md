# MITRE ATT&CK Mapping

| Attack Activity | MITRE ATT&CK Technique | Technique ID | Evidence |
|---|---|---|---|
| Malicious Office document execution | User Execution: Malicious File | T1204.002 | malicious_document.docm opened by WINWORD.EXE |
| Office application spawning PowerShell | Command and Scripting Interpreter: PowerShell | T1059.001 | WINWORD.EXE → powershell.exe |
| Encoded PowerShell command | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell executed with -EncodedCommand |
| LSASS access | OS Credential Dumping: LSASS Memory | T1003.001 | credential_tool.exe accessed lsass.exe |
| PowerShell network retrieval | Ingress Tool Transfer | T1105 | PowerShell executed Invoke-WebRequest |
| Suspicious DNS resolution | Application Layer Protocol: DNS | T1071.004 | update-check.example resolved to 203.0.113.50 |
| C2 over HTTPS/TCP 443 | Application Layer Protocol: Web Protocols | T1071.001 | Repeated outbound communication to port 443 |

## Notes

The technique mappings are based on the behavior represented in the
simulated telemetry.

The telemetry supports potential credential-access activity involving
LSASS, but does not prove that credentials were successfully dumped.

The repeated outbound connections to 203.0.113.50 are assessed as
potential C2 communication based on the simulated scenario.

The authentication events are treated as suspicious activity requiring
investigation rather than definitive proof of lateral movement.