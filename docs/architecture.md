# Architecture Overview – Azure Sentinel Honeypot Lab

This document explains the architecture and data flow of the Azure Sentinel Honeypot Lab, focusing on **why each component exists** and how security telemetry moves through the environment.

---

## High-Level Design

The lab simulates a minimal cloud-based SOC by intentionally exposing a Windows virtual machine to the public internet and observing real-world attack behavior.

The architecture follows this flow:

Internet
↓
Azure Public IP
↓
Network Security Group (Allow All - Lab Only)
↓
Windows 10 VM (Honeypot)
↓
Azure Monitor Agent (AMA)
↓
Log Analytics Workspace (LAW)
↓
Microsoft Sentinel (SIEM)
↓
KQL Queries & Workbook Visualizations


---

## Core Components

### Azure Virtual Machine (Honeypot)
- **OS:** Windows 10
- **Purpose:** Attract and record unauthorized authentication attempts
- **Configuration (Lab Only):**
  - NSG allows all inbound traffic
  - Windows Defender Firewall disabled

This setup ensures the VM is quickly discovered by automated scanners and bots.

---

### Network Security Group (NSG)
- Configured with an inbound rule allowing **ANY / ANY**
- Used to demonstrate how exposed cloud resources are rapidly attacked
- In production, this would be restricted to specific IPs and ports

---

### Azure Monitor Agent (AMA)
- Installed on the VM via a Data Collection Rule (DCR)
- Responsible for forwarding Windows Security Events to Azure
- Replaces legacy agents and is the current Microsoft standard

---

### Log Analytics Workspace (LAW)
- Central repository for all collected logs
- Stores `SecurityEvent` data from the Windows VM
- Enables querying using KQL

This acts as the single source of truth for security telemetry.

---

### Microsoft Sentinel (SIEM)
- Connected directly to the Log Analytics Workspace
- Provides:
  - Centralized log analysis
  - Detection logic via KQL
  - Visualizations via Workbooks

Sentinel is used as the SIEM layer in this lab.

---

### GeoIP Watchlist
- Imported as a Sentinel Watchlist
- Contains IP ranges mapped to geographic locations
- Used to enrich attacker IP addresses with:
  - Country
  - City
  - Latitude / Longitude

In real-world environments, this data would typically come from a live or continuously updated provider.

---

## Data Flow Summary

1. Attacker attempts to authenticate to the exposed VM
2. Windows logs the failed login (Event ID 4625)
3. Azure Monitor Agent forwards logs to LAW
4. Logs are queried using KQL
5. GeoIP Watchlist enriches attacker IP data
6. Sentinel Workbook visualizes attack sources globally

---

## Security Considerations

This architecture intentionally reduces security controls to generate telemetry.  
In a production environment, the following changes would be required:

- Restrict NSG inbound rules
- Re-enable Windows Firewall
- Enable Just-In-Time (JIT) VM access
- Integrate Defender for Endpoint
- Configure Sentinel analytic rules and automated response

---

## Purpose of This Design

The goal of this architecture is not prevention, but **visibility**.  
It demonstrates how security teams:
- Collect raw telemetry
- Centralize logs
- Enrich data
- Detect and visualize malicious activity

This mirrors real SOC workflows in a controlled learning environment.
