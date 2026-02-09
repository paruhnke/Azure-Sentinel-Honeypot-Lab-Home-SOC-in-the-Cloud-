# Azure Sentinel Honeypot Lab (Home SOC in the Cloud)

This project is a hands-on cybersecurity lab that simulates a basic Security Operations Center using Microsoft Azure.  
A Windows virtual machine is intentionally exposed to the public internet as a honeypot to capture real-world attack activity, forward logs to Azure, enrich them with geographic data, and visualize attacker locations using **Microsoft Sentinel**.

> ⚠️ **Important:** This lab intentionally weakens security controls (open NSG rules and disabled Windows Firewall) to generate telemetry. This configuration is for **learning purposes only** and should never be used in production.

---

## Skills & Technologies Demonstrated

- Microsoft Azure (VMs, VNets, NSGs, Resource Groups)
- Windows Security Event Logging
- Azure Monitor Agent (AMA) & Data Collection Rules (DCR)
- Log Analytics Workspace (LAW)
- Microsoft Sentinel (SIEM)
- KQL (Kusto Query Language)
- Log enrichment using Sentinel Watchlists
- SOC-style log analysis and visualization
- Cloud cost awareness and resource teardown

---

## Architecture Overview

1. Azure Windows 10 Virtual Machine deployed as a honeypot
2. Network Security Group configured to allow all inbound traffic
3. Windows Defender Firewall disabled on the VM
4. Azure Monitor Agent forwards security logs
5. Log Analytics Workspace stores centralized logs
6. Microsoft Sentinel connected as the SIEM
7. GeoIP Watchlist enriches attacker IP addresses
8. Sentinel Workbook visualizes global attack activity

---

## Part 1: Honeypot Virtual Machine Deployment

- Created a **Windows 10 Azure Virtual Machine**
- Selected a cost-conscious VM size
- Configured the VM’s **Network Security Group** to allow **all inbound traffic**
- Logged into the VM and disabled **Windows Defender Firewall**:
  - `Start → wf.msc → Firewall Properties → Turn Off (All Profiles)`

This configuration ensures the VM is easily discoverable by automated scanners and attackers.

---

## Part 2: Local Log Generation & Inspection

- Attempted **three failed logins** using a fake username (`employee`)
- Logged into the VM with valid credentials
- Opened **Event Viewer → Windows Logs → Security**
- Verified failed authentication events:
  - **Event ID 4625** (Account failed to log on)

This confirmed that authentication failures were being logged locally.

---

## Part 3: Log Forwarding & KQL Analysis

- Created a **Log Analytics Workspace (LAW)** as a central log repository
- Created a **Microsoft Sentinel** instance and connected it to the LAW
- Configured the **Windows Security Events via Azure Monitor Agent** connector
- Created a **Data Collection Rule (DCR)** to forward logs from the VM
- Verified log ingestion into the LAW

### Example KQL – Failed Logons

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress
| order by TimeGenerated desc
