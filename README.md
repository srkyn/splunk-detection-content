# splunk-detection-content

A working collection of Splunk SPL detections organized by [MITRE ATT&CK](https://attack.mitre.org/) tactic. The content is written for Windows-centric environments with Active Directory, Sysmon, PowerShell logging, and standard Windows Security events.

The point of this repository is not to dump searches. Each detection is written as an analyst note: what behavior it looks for, what data it assumes, what tends to be noisy, and what I would check next before escalating.

Each query includes:
- **What it detects** — the behavior or indicator being hunted
- **ATT&CK mapping** — tactic and technique reference
- **Required data sources** — index/sourcetype assumptions
- **SPL** — copy-paste ready, with field assumptions called out
- **Tuning notes** — known FP sources and how to reduce noise
- **Analyst next steps** — pivots I would use before calling something suspicious

---

## How I Review A Detection

1. Start with behavior, not a tool name.
2. Confirm the data source can actually see that behavior.
3. Write the first SPL version as a visibility search.
4. Add grouping, thresholds, and fields that help a human decide.
5. Tune known-good admin activity without hiding rare activity.
6. Document what to check next so the alert does not stop at "interesting."

That last part matters. A detection that does not tell the next analyst where to pivot is only half finished.

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
| [execution.md](queries/execution.md) | Execution | T1059.001, T1059.003, T1204 |
| [initial-access.md](queries/initial-access.md) | Initial Access | T1566.001, T1566.002 |
| [exfiltration.md](queries/exfiltration.md) | Exfiltration | T1041, T1567.002 |

---

## Usage

All queries target a `index=wineventlog` or `index=sysmon` baseline. Adjust index names and field mappings to match your environment before deploying.

Queries are written for **Splunk Enterprise** and **Splunk Cloud** with standard CIM-style field naming where possible.

Recommended workflow:

```spl
<run the base search for 7-30 days>
| stats count dc(host) as host_count values(host) as hosts by user, Image, CommandLine
| sort - count
```

Use the broad version first to understand normal activity, then tighten the query. Do not turn a detection into an alert until the false-positive path is understood.

---

## Portfolio Notes

This is a defensive content repository. The searches are meant to show security operations thinking: what signal matters, what context is needed, and what I would do next during triage.

I intentionally avoid environment-specific allowlists, real hostnames, internal domains, usernames, ticket numbers, and screenshots from private systems.

---

## Author

David Sarkisyan · Cybersecurity Analyst · Brooklyn, NY
[github.com/srkyn](https://github.com/srkyn) · Splunk Core Certified User
