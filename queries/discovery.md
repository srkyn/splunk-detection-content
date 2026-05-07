# Discovery Detections

## Network Share Discovery

**What it detects:** Commands used to enumerate remote shares or network resources.

**ATT&CK mapping:** T1135 - Network Share Discovery

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*net view*" OR CommandLine="*Get-SmbShare*" OR CommandLine="*Get-ChildItem \\\\*"
| eval technique="T1135 Network Share Discovery"
| table _time host user Image ParentImage CommandLine technique
| sort - _time
```

**Tuning notes:** Admin scripts and helpdesk troubleshooting may trigger this. Prioritize discovery from non-admin users, new hosts, or post-compromise sequences.

## Domain Account Enumeration

**What it detects:** Commands used to enumerate domain users or groups.

**ATT&CK mapping:** T1087.002 - Account Discovery: Domain Account

**Required data sources:** Sysmon Event ID 1 and PowerShell logs.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*net user /domain*" OR CommandLine="*net group /domain*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-ADGroup*"
| eval technique="T1087.002 Domain Account Discovery"
| table _time host user Image ParentImage CommandLine technique
| sort - _time
```

**Tuning notes:** Identity admins and inventory jobs may be expected. Look for discovery from workstations, unusual service accounts, or immediately after phishing alerts.

## Port Scanning Behavior

**What it detects:** Potential internal scanning tools or PowerShell-based port checks.

**ATT&CK mapping:** T1046 - Network Service Discovery

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*nmap*" OR CommandLine="*Test-NetConnection*" OR CommandLine="*PortScanner*" OR CommandLine="*masscan*"
| eval technique="T1046 Network Service Discovery"
| table _time host user Image ParentImage CommandLine technique
| sort - _time
```

**Tuning notes:** Approved vulnerability scanning should come from known scanner hosts. Escalate scanning from user endpoints, servers that do not normally scan, or commands launched by Office/script interpreters.
