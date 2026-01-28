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
```

![Failed connection summary](images/network-failed-connections-summary.png)

---

### 2. Identification of Port Scanning Behavior
After sorting events chronologically, one internal host (**10.0.0.202**) displayed sequential failed connection attempts across increasing port numbers — a strong indicator of automated port scanning.

![Failed connections by host](images/failed-connections-by-host.png)

---

### 3. Endpoint Process Correlation
Endpoint process telemetry was reviewed during the timeframe of the scan.

```kql
let VMName = "vm-mde";
let specificTime = datetime(2026-01-28T04:28:43.3403645Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 15m) .. (specificTime + 15m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

![PowerShell port scan process](images/powershell-portscan-process.png)

---

### 4. Script Analysis & Privilege Context
Manual inspection confirmed a PowerShell script (`portscan.ps1`) executed under the SYSTEM account.

![Port scan script](images/portscan-script-code.png)

---

## Response Actions
- Isolated the affected endpoint using MDE
- Performed a full malware scan (no malware detected)
- Maintained isolation due to SYSTEM-level execution
- Submitted the device for reimaging/rebuild

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|----------|------------|
| Reconnaissance | T1046 | Network Service Discovery |
| Execution | T1059.001 | PowerShell |
| Privilege Escalation / Defense Evasion | T1078 | Valid Accounts (SYSTEM) |
| Discovery | T1049 | System Network Connections Discovery |
| Lateral Movement (Potential) | T1021 | Remote Services |

---

## Final Assessment
- Unauthorized internal reconnaissance activity confirmed
- No lateral movement or data exfiltration observed
- Early detection prevented escalation
- Security posture improved

---

## Skills Demonstrated
- Microsoft Defender for Endpoint threat hunting
- Advanced KQL analysis
- Network + endpoint telemetry correlation
- MITRE ATT&CK mapping
- Incident response and remediation

