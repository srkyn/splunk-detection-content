# Execution Detections

## Encoded PowerShell Command

**What it detects:** PowerShell launched with encoded command arguments.

**ATT&CK mapping:** T1059.001 - Command and Scripting Interpreter: PowerShell

**Required data sources:** Sysmon Event ID 1 or Windows process creation logs.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| eval cmd_lc=lower(CommandLine)
| where like(cmd_lc, "%-enc%") OR like(cmd_lc, "%-encodedcommand%") OR like(cmd_lc, "%frombase64string%")
| eval technique="T1059.001 PowerShell"
| table _time host user Image ParentImage CommandLine technique
| sort - _time
```

**Tuning notes:** Some admin tools use encoded PowerShell legitimately. Baseline deployment tools, EDR response actions, and software management platforms.

**Analyst next steps:** Decode the payload, review parent process, check whether the host recently opened Office documents or browser downloads, and pivot to network connections from the same process tree.

## Suspicious Script Interpreter Parent

**What it detects:** Script interpreters launched by Office, browsers, archive tools, or email clients.

**ATT&CK mapping:** T1204 - User Execution

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image IN ("*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe")
| eval parent_lc=lower(ParentImage)
| where match(parent_lc, "\\\\(winword|excel|powerpnt|outlook|chrome|msedge|firefox|7zfm|winrar)\\.exe$")
| eval technique="T1204 User Execution"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** Helpdesk tools and business macros can create noise. Prioritize internet-facing parents, recently downloaded files, and commands reaching out to external URLs.

**Analyst next steps:** Pull file creation events around the same timestamp, review browser/download history if available, and check whether the child process spawned another interpreter.

## LOLBin Download Or Execute Pattern

**What it detects:** Native Windows binaries commonly abused to download or execute content.

**ATT&CK mapping:** T1059.003 - Command and Scripting Interpreter: Windows Command Shell

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image IN ("*\\certutil.exe", "*\\bitsadmin.exe", "*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe")
| eval cmd_lc=lower(CommandLine)
| where like(cmd_lc, "%http://%") OR like(cmd_lc, "%https://%") OR like(cmd_lc, "%urlcache%") OR like(cmd_lc, "%scrobj.dll%")
| eval technique="T1059.003 Command Shell"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** These binaries can be used by administrators, but internet URLs and user-writable paths raise priority.

**Analyst next steps:** Extract URLs, check reputation, review DNS/proxy logs, and look for dropped files or subsequent process execution on the same host.
