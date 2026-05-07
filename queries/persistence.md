# Persistence Detections

## Scheduled Task Created Or Updated

**What it detects:** Windows scheduled task creation or modification events that may indicate persistence.

**ATT&CK mapping:** T1053.005 - Scheduled Task/Job: Scheduled Task

**Required data sources:** Windows Security events with task scheduler auditing enabled.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4698, 4702)
| eval technique="T1053.005 Scheduled Task"
| table _time host user EventCode Task_Name Command technique
| sort - _time
```

**Tuning notes:** Baseline known software updaters, endpoint management tooling, and administrative maintenance windows. Prioritize new tasks created by non-admin users, unusual paths, or unsigned binaries.

**Analyst next steps:** Review the task action, author, run context, creation time, and binary path. Pivot to process creation, file creation, and recent logons on the same host.

## Run Key Persistence

**What it detects:** Sysmon registry modifications to common Run and RunOnce keys.

**ATT&CK mapping:** T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Required data sources:** Sysmon Event ID 13.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
TargetObject IN ("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*")
| eval technique="T1547.001 Run Key"
| table _time host user Image TargetObject Details technique
| sort - _time
```

**Tuning notes:** Browser updaters, Teams, OneDrive, and device agents commonly write here. Investigate unsigned binaries, user-writable paths, temp directories, and newly observed values.

**Analyst next steps:** Check whether the referenced binary exists, where it was written from, whether it is signed, and whether the same user recently opened email attachments or downloads.

## New Service Installed

**What it detects:** Windows service creation events.

**ATT&CK mapping:** T1543.003 - Create or Modify System Process: Windows Service

**Required data sources:** Windows System event log.

```spl
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
| eval technique="T1543.003 Windows Service"
| table _time host Service_Name Service_File_Name Service_Type Start_Type Account_Name technique
| sort - _time
```

**Tuning notes:** Filter approved deployment tools and known enterprise agents. Escalate services running from user profiles, downloads, temp paths, or unusual network shares.

**Analyst next steps:** Review service account, service path, parent process, file hash, signer, and whether the service started immediately after creation.
