# KQL Detections – Azure Sentinel Honeypot Lab

This document contains KQL queries used to analyze authentication attacks against an Azure honeypot virtual machine.
All queries are compatible with Log Analytics Workspace and Microsoft Sentinel.

---

## Failed Logons (Event ID 4625)

Query:
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress
| order by TimeGenerated desc

---

## Failed Logons with GeoIP Enrichment

Query:
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, Computer, IpAddress, cityname, countryname, latitude, longitude
| order by TimeGenerated desc

---

## Brute-Force Detection (High Volume Failures)

Detects IP addresses generating more than 20 failed logons within a 5-minute window.

Query:
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 20
| order by FailedAttempts desc

---

## Failed Logons from Rare Countries

Identifies authentication failures originating from countries that are uncommon in the environment.

Query:
let GeoIPDB_FULL = _GetWatchlist("geoip");
let CommonCountries =
    SecurityEvent
    | where EventID == 4625
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
    | summarize Count = count() by countryname
    | top 5 by Count
    | project countryname;

SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| where countryname !in (CommonCountries)
| project TimeGenerated, IpAddress, countryname
| order by TimeGenerated desc

---

## Failed Logons – Last 5 Minutes

Query:
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(5m)
| project TimeGenerated, Computer, Account, IpAddress
| order by TimeGenerated desc

---

## Correlate Failed vs Successful Logons (4625 vs 4624)

Query:
SecurityEvent
| where EventID in (4624, 4625)
| summarize Count = count() by EventID, Account
| order by Count desc

---

## SOC Use Case Summary

- Detect brute-force and credential-stuffing attacks
- Enrich attacker IPs with geographic context
- Identify anomalous authentication behavior
- Serve as a foundation for Sentinel analytic rules and incident creation
