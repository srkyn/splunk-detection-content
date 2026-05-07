# Defense Evasion Detections

## Windows Event Log Cleared

**What it detects:** Security or system log clearing.

**ATT&CK mapping:** T1070.001 - Indicator Removal: Clear Windows Event Logs

**Required data sources:** Windows Security and System logs.

```spl
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval technique="T1070.001 Clear Windows Event Logs"
| table _time host user EventCode LogName Message technique
| sort - _time
```

**Tuning notes:** Log clearing should be rare. Validate whether the action came from an approved admin process or incident-response activity.

## Security Tool Service Stopped

**What it detects:** Stopped services with names commonly associated with security tooling.

**ATT&CK mapping:** T1562.001 - Impair Defenses: Disable or Modify Tools

**Required data sources:** Windows System Event ID 7036.

```spl
index=wineventlog sourcetype="WinEventLog:System" EventCode=7036
| search Message="*stopped*" (Message="*defender*" OR Message="*crowdstrike*" OR Message="*sentinel*" OR Message="*carbon black*" OR Message="*tanium*" OR Message="*splunk*")
| eval technique="T1562.001 Disable Security Tools"
| table _time host Message technique
| sort - _time
```

**Tuning notes:** Tune product names to the environment. Correlate with service-control events, change tickets, and process creation.

## Suspicious Process Masquerading

**What it detects:** Windows binaries executing from suspicious paths.

**ATT&CK mapping:** T1036.005 - Masquerading: Match Legitimate Name or Location

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_lc=lower(Image)
| where match(image_lc, "\\\\(svchost|lsass|spoolsv|services|winlogon)\\.exe$") AND NOT like(image_lc, "c:\\\\windows\\\\system32\\\\%")
| eval technique="T1036.005 Masquerading"
| table _time host user Image ParentImage CommandLine technique
| sort - _time
```

**Tuning notes:** Confirm the real path and signature. Many false positives come from test labs or copied binaries; production hits deserve fast review.
