# Exfiltration Detections

## Suspicious Archive Creation In User Paths

**What it detects:** Archive tools creating compressed files from user-accessible paths.

**ATT&CK mapping:** T1560.001 - Archive Collected Data: Archive via Utility

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image IN ("*\\7z.exe", "*\\7za.exe", "*\\rar.exe", "*\\winrar.exe", "*\\powershell.exe")
| eval cmd_lc=lower(CommandLine)
| where like(cmd_lc, "%.zip%") OR like(cmd_lc, "%.7z%") OR like(cmd_lc, "%.rar%")
| eval technique="T1560.001 Archive Collected Data"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** Compression is common. Prioritize archives created from sensitive folders, large collections, unusual users, or shortly before external network activity.

**Analyst next steps:** Identify archive path and size, review file access around the same time, and check whether the archive was uploaded or copied externally.

## Large External Transfer From Workstation

**What it detects:** High outbound byte counts from workstation hosts to external destinations.

**ATT&CK mapping:** T1041 - Exfiltration Over C2 Channel

**Required data sources:** Network telemetry with bytes, source, destination, and action fields.

```spl
index=network (action=allowed OR action=success)
| stats sum(bytes_out) as bytes_out values(dest_port) as dest_ports values(app) as apps by src_ip, dest_ip, user
| where bytes_out > 500000000
| eval mb_out=round(bytes_out/1024/1024, 2)
| table src_ip user dest_ip dest_ports apps mb_out
| sort - mb_out
```

**Tuning notes:** Field names vary by firewall, proxy, or EDR source. Baseline cloud backup, software updates, video calls, and sanctioned SaaS traffic.

**Analyst next steps:** Resolve destination ownership, check whether the user normally transfers large files, and pivot to file/archive creation before the transfer.

## Cloud Storage Upload Tool Usage

**What it detects:** Command-line tools or sync clients commonly used to move files to external cloud storage.

**ATT&CK mapping:** T1567.002 - Exfiltration to Cloud Storage

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_lc=lower(Image), cmd_lc=lower(CommandLine)
| where match(image_lc, "\\\\(rclone|mega|dropbox|onedrive|googledrive|gdrive)\\.exe$")
  OR like(cmd_lc, "%rclone copy%")
  OR like(cmd_lc, "%mega-put%")
| eval technique="T1567.002 Exfiltration to Cloud Storage"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** Some sync clients are approved. Prioritize portable binaries, unusual paths, first-seen tools, and commands run from user profile folders.

**Analyst next steps:** Check file staging activity, destination domains, process ancestry, and whether the account recently triggered unusual authentication events.
