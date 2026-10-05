import csv
import os
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(DATA_DIR, exist_ok=True)

HOST = "WIN-CLIENT01"
HOST_IP = "192.168.10.25"
DOMAIN = "CORP.LOCAL"
USER = "ahmed"

C2_IP = "203.0.113.50"
C2_DOMAIN = "update-check.example"

START = datetime(2026, 10, 5, 10, 1, 12)


def write_csv(filename, fieldnames, rows):
    path = os.path.join(DATA_DIR, filename)

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Created: {path}")


# ---------------------------------------------------------
# WINDOWS SECURITY EVENTS
# ---------------------------------------------------------

windows_events = [
    {
        "timestamp": START.strftime("%Y-%m-%d %H:%M:%S"),
        "host": HOST,
        "event_id": "4624",
        "username": USER,
        "source_ip": HOST_IP,
        "logon_type": "2",
        "description": "Interactive logon"
    },
    {
        "timestamp": (START + timedelta(seconds=119)).strftime("%Y-%m-%d %H:%M:%S"),
        "host": HOST,
        "event_id": "4625",
        "username": USER,
        "source_ip": "192.168.10.50",
        "logon_type": "3",
        "description": "Failed network logon"
    },
    {
        "timestamp": (START + timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S"),
        "host": HOST,
        "event_id": "4624",
        "username": USER,
        "source_ip": "192.168.10.50",
        "logon_type": "3",
        "description": "Successful network logon"
    },
]

write_csv(
    "windows_security.csv",
    [
        "timestamp",
        "host",
        "event_id",
        "username",
        "source_ip",
        "logon_type",
        "description",
    ],
    windows_events,
)


# ---------------------------------------------------------
# SYSMON EVENTS
# ---------------------------------------------------------

sysmon_events = [
    {
        "timestamp": START.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": "1",
        "host": HOST,
        "process_id": "4100",
        "parent_process_id": "3900",
        "parent_image": "explorer.exe",
        "image": "WINWORD.EXE",
        "command_line": '"C:\\Program Files\\Microsoft Office\\WINWORD.EXE" malicious_document.docm',
        "user": f"{DOMAIN}\\{USER}",
    },
    {
        "timestamp": (START + timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": "1",
        "host": HOST,
        "process_id": "4200",
        "parent_process_id": "4100",
        "parent_image": "WINWORD.EXE",
        "image": "powershell.exe",
        "command_line": 'powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==',
        "user": f"{DOMAIN}\\{USER}",
    },
        {
        "timestamp": (START + timedelta(seconds=53)).strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": "10",
        "host": HOST,
        "process_id": "4300",
        "parent_process_id": "4200",
        "parent_image": "powershell.exe",
        "image": "credential_tool.exe",
        "command_line": "credential_tool.exe --access-lsass",
        "source_image": r"C:\Users\ahmed\AppData\Local\Temp\credential_tool.exe",
        "target_image": r"C:\Windows\System32\lsass.exe",
        "granted_access": "0x1010",
        "user": f"{DOMAIN}\\{USER}",
    },
    {
        "timestamp": (START + timedelta(seconds=188)).strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": "3",
        "host": HOST,
        "process_id": "4200",
        "parent_process_id": "4100",
        "parent_image": "WINWORD.EXE",
        "image": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -Command Invoke-WebRequest",
        "user": f"{DOMAIN}\\{USER}",
    },
]

write_csv(
    "sysmon.csv",
    [
        "timestamp",
        "event_id",
        "host",
        "process_id",
        "parent_process_id",
        "parent_image",
        "image",
        "command_line",
        "source_image",
        "target_image",
        "granted_access",
        "user",
    ],
    sysmon_events,
)


# ---------------------------------------------------------
# DNS EVENTS
# ---------------------------------------------------------

dns_events = [
    {
        "timestamp": (START + timedelta(seconds=188)).strftime("%Y-%m-%d %H:%M:%S"),
        "host": HOST,
        "source_ip": HOST_IP,
        "query": C2_DOMAIN,
        "query_type": "A",
        "response": C2_IP,
    }
]

write_csv(
    "dns.csv",
    [
        "timestamp",
        "host",
        "source_ip",
        "query",
        "query_type",
        "response",
    ],
    dns_events,
)


# ---------------------------------------------------------
# NETWORK EVENTS
# ---------------------------------------------------------

network_events = []

for seconds in [189, 249, 309]:
    network_events.append(
        {
            "timestamp": (START + timedelta(seconds=seconds)).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "source_ip": HOST_IP,
            "destination_ip": C2_IP,
            "destination_port": "443",
            "protocol": "TCP",
            "bytes_out": "842",
            "bytes_in": "1260",
            "connection_status": "ESTABLISHED",
        }
    )

write_csv(
    "network.csv",
    [
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "protocol",
        "bytes_out",
        "bytes_in",
        "connection_status",
    ],
    network_events,
)


# ---------------------------------------------------------
# SIEM ALERTS
# ---------------------------------------------------------

siem_alerts = [
    {
        "timestamp": (START + timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": "ALERT-001",
        "severity": "High",
        "host": HOST,
        "rule": "Office Application Spawning PowerShell",
        "description": "WINWORD.EXE spawned PowerShell with an encoded command.",
    },
    {
        "timestamp": (START + timedelta(seconds=53)).strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": "ALERT-002",
        "severity": "High",
        "host": HOST,
        "rule": "Potential Credential Access",
        "description": "Suspicious process attempted access to LSASS.",
    },
    {
        "timestamp": (START + timedelta(seconds=188)).strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": "ALERT-003",
        "severity": "Medium",
        "host": HOST,
        "rule": "Suspicious DNS Request",
        "description": f"Host queried suspicious domain {C2_DOMAIN}.",
    },
    {
        "timestamp": (START + timedelta(seconds=189)).strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": "ALERT-004",
        "severity": "High",
        "host": HOST,
        "rule": "Potential C2 Communication",
        "description": f"Repeated outbound connections to {C2_IP}:443 detected.",
    },
]

write_csv(
    "siem_alerts.csv",
    [
        "timestamp",
        "alert_id",
        "severity",
        "host",
        "rule",
        "description",
    ],
    siem_alerts,
)


print("\n[+] Telemetry generation completed.")
print(f"[+] Data directory: {DATA_DIR}")