import csv
import os
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ANALYSIS_DIR = os.path.join(BASE_DIR, "analysis")

os.makedirs(ANALYSIS_DIR, exist_ok=True)


def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)

    with open(path, newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


security = load_csv("windows_security.csv")
sysmon = load_csv("sysmon.csv")
dns = load_csv("dns.csv")
network = load_csv("network.csv")
alerts = load_csv("siem_alerts.csv")


print("=" * 70)
print("NEXCORE SOC INVESTIGATION")
print("=" * 70)

print("\n[1] AFFECTED SYSTEM")
print("-" * 70)

hosts = set()

for event in security:
    hosts.add(event["host"])

for event in sysmon:
    hosts.add(event["host"])

for event in dns:
    hosts.add(event["host"])

print("Hosts observed:", ", ".join(sorted(hosts)))


print("\n[2] AUTHENTICATION ANALYSIS")
print("-" * 70)

for event in security:
    if event["event_id"] == "4624":
        print(
            f'{event["timestamp"]} | SUCCESS | '
            f'User={event["username"]} | '
            f'Source={event["source_ip"]}'
        )

    elif event["event_id"] == "4625":
        print(
            f'{event["timestamp"]} | FAILED  | '
            f'User={event["username"]} | '
            f'Source={event["source_ip"]}'
        )


print("\n[3] PROCESS TREE")
print("-" * 70)

processes = {}

for event in sysmon:
    if event["event_id"] == "1":
        processes[event["process_id"]] = event

for pid, event in processes.items():

    parent_pid = event["parent_process_id"]

    print(
        f'PID {pid}: {event["image"]} '
        f'-> Parent PID {parent_pid} '
        f'({event["parent_image"]})'
    )

    print(f'   Command: {event["command_line"]}')


print("\n[4] POWERSHELL ACTIVITY")
print("-" * 70)

for event in sysmon:

    command = event["command_line"].lower()

    if "powershell" in event["image"].lower() or "powershell" in command:

        print(
            f'{event["timestamp"]} | '
            f'{event["image"]} | '
            f'{event["command_line"]}'
        )


print("\n[5] POTENTIAL CREDENTIAL ACCESS")
print("-" * 70)

credential_events = []

for event in sysmon:

    text = (
        event["image"]
        + " "
        + event["command_line"]
    ).lower()

    if "lsass" in text or "credential" in text:

        credential_events.append(event)

        print(
            f'{event["timestamp"]} | '
            f'{event["image"]} | '
            f'{event["command_line"]}'
        )


print("\n[6] DNS ANALYSIS")
print("-" * 70)

for event in dns:

    print(
        f'{event["timestamp"]} | '
        f'{event["host"]} | '
        f'{event["query"]} -> {event["response"]}'
    )


print("\n[7] NETWORK ANALYSIS")
print("-" * 70)

for event in network:

    print(
        f'{event["timestamp"]} | '
        f'{event["source_ip"]} -> '
        f'{event["destination_ip"]}:'
        f'{event["destination_port"]} | '
        f'{event["protocol"]}'
    )


print("\n[8] SIEM ALERTS")
print("-" * 70)

for alert in alerts:

    print(
        f'{alert["timestamp"]} | '
        f'{alert["severity"]} | '
        f'{alert["rule"]}'
    )


print("\n[9] INITIAL INVESTIGATION ASSESSMENT")
print("-" * 70)

print("Potential initial compromise:")
print(
    "WINWORD.EXE spawning PowerShell with an encoded command."
)

print("\nPotential credential access:")
print(
    "Suspicious process activity involving LSASS."
)

print("\nPotential C2:")
print(
    "Repeated outbound TCP connections from the workstation "
    "to the simulated external infrastructure."
)

print("\nInvestigation completed.")