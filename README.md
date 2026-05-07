# splunk-detection-content

A collection of Splunk SPL detection queries organized by [MITRE ATT&CK](https://attack.mitre.org/) tactic. Written for Windows-centric enterprise environments with Active Directory, Sysmon (Event ID schema), and standard Windows Security event logging.

Each query includes:
- **What it detects** — the behavior or indicator being hunted
- **ATT&CK mapping** — tactic and technique reference
- **Required data sources** — index/sourcetype assumptions
- **SPL** — copy-paste ready, with field assumptions called out
- **Tuning notes** — known FP sources and how to reduce noise

---

## Data Source Assumptions

| Log Source | Sourcetype | Notes |
|---|---|---|
| Windows Security Events | `WinEventLog:Security` | Audit policy: logon, account mgmt, object access |
| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Config: SwiftOnSecurity or olafhartong |
| PowerShell | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | Script block logging enabled |
| Windows System | `WinEventLog:System` | Service installs, task scheduler |
| DNS | `stream:dns` or vendor-specific | Forward + reverse lookups |

---

## Query Index

| File | Tactic | Techniques Covered |
|---|---|---|
| [persistence.md](queries/persistence.md) | Persistence | T1053.005, T1547.001, T1543.003 |
| [credential-access.md](queries/credential-access.md) | Credential Access | T1110.001, T1558.003, T1003.001 |
| [lateral-movement.md](queries/lateral-movement.md) | Lateral Movement | T1021.002, T1021.006, T1550.002 |
| [defense-evasion.md](queries/defense-evasion.md) | Defense Evasion | T1070.001, T1562.001, T1036.005 |
| [discovery.md](queries/discovery.md) | Discovery | T1135, T1087.002, T1046 |

---

## Usage

All queries target a `index=wineventlog` or `index=sysmon` baseline. Adjust index names and field mappings to match your environment before deploying.

Queries are written for **Splunk Enterprise** and **Splunk Cloud** with standard CIM-compliant field naming where possible.

---

## Author

David Sarkisyan · Cybersecurity Analyst · Brooklyn, NY
[github.com/srkyn](https://github.com/srkyn) · Splunk Core Certified User
