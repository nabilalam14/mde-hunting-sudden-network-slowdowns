Final README.md (with embedded screengrabs)
# Threat Hunting Lab 02 – Internal Network Port Scanning Detection

## Overview
This project documents a threat-hunting investigation conducted using **Microsoft Defender for Endpoint (MDE)** after internal teams reported significant network slowdowns. The hunt identified unauthorized internal port-scanning activity originating from a compromised endpoint.

The investigation demonstrates practical threat-hunting techniques including telemetry correlation, KQL analysis, and MITRE ATT&CK mapping.

---

## Environment
- Microsoft Defender for Endpoint (Advanced Hunting)
- Windows virtual machines
- Internal network: 10.0.0.0/16
- KQL (Kusto Query Language)

---

## Timeline Summary & Findings

### 1. Detection of Anomalous Network Activity
Initial analysis of `DeviceNetworkEvents` revealed a large volume of failed connection attempts originating from internal hosts.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount desc


📸 Observed failed connection volume across multiple internal hosts:

### 2. Identification of Port Scanning Behavior

After sorting events chronologically, one internal host (10.0.0.202) displayed sequential failed connection attempts across increasing port numbers — a strong indicator of automated port scanning.

📸 Failed connections attributed to the suspected host:

This behavior is inconsistent with normal application traffic and aligns with reconnaissance activity.

### 3. Endpoint Process Correlation

To determine the source of the network activity, the investigation pivoted to endpoint process telemetry during the time of the scan.

let VMName = "vm-mde";
let specificTime = datetime(2026-01-28T04:28:43.3403645Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 15m) .. (specificTime + 15m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine


📸 PowerShell process launching the port scan script:

A PowerShell script named portscan.ps1 executed during the same timeframe as the anomalous network activity.

### 4. Script Analysis & Privilege Context

Manual inspection of the endpoint confirmed the presence of the PowerShell port scanning script.

📸 Observed port scanning script (portscan.ps1):

Key findings:

Script scanned a defined IP range and common ports

Execution occurred under the SYSTEM account

Activity was not authorized or scheduled by administrators

Response Actions

Isolated the affected endpoint using Microsoft Defender for Endpoint

Performed a full malware scan (no malware detected)

Maintained isolation due to SYSTEM-level execution

Submitted the device for reimaging/rebuild as a precaution

MITRE ATT&CK Mapping
Tactic	Technique	Description
Reconnaissance	T1046 – Network Service Discovery	Sequential internal port scanning detected
Execution	T1059.001 – PowerShell	PowerShell used to execute scanning script
Privilege Escalation / Defense Evasion (Contextual)	T1078 – Valid Accounts (SYSTEM)	Script executed under SYSTEM context
Discovery	T1049 – System Network Connections Discovery	Internal network enumeration
Lateral Movement (Potential)	T1021 – Remote Services	Activity could enable lateral movement
Final Assessment

Unauthorized internal reconnaissance activity confirmed

No evidence of lateral movement or data exfiltration

Early detection prevented escalation

Endpoint remediation improved security posture

Skills Demonstrated

Threat hunting with Microsoft Defender for Endpoint

Advanced KQL querying and pivoting

Network + endpoint telemetry correlation

MITRE ATT&CK framework mapping

Incident response and containment
