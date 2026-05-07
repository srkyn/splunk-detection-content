# Initial Access Detections

## Office Document Spawns Script Interpreter

**What it detects:** Microsoft Office spawning script interpreters or shell processes.

**ATT&CK mapping:** T1566.001 - Phishing: Spearphishing Attachment

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent_lc=lower(ParentImage), image_lc=lower(Image)
| where match(parent_lc, "\\\\(winword|excel|powerpnt|onenote)\\.exe$")
  AND match(image_lc, "\\\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$")
| eval technique="T1566.001 Phishing Attachment"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** Business macros can be legitimate. Focus on documents from external email, commands with download URLs, encoded payloads, or child process chains.

**Analyst next steps:** Review email gateway logs, file origin metadata, downloaded payloads, and subsequent network connections from the host.

## Browser Download Followed By Script Execution

**What it detects:** A browser spawning a script interpreter or LOLBin shortly after user-driven web activity.

**ATT&CK mapping:** T1566.002 - Phishing: Spearphishing Link

**Required data sources:** Sysmon Event ID 1.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent_lc=lower(ParentImage), image_lc=lower(Image)
| where match(parent_lc, "\\\\(chrome|msedge|firefox|iexplore)\\.exe$")
  AND match(image_lc, "\\\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\\.exe$")
| eval technique="T1566.002 Phishing Link"
| table _time host user ParentImage Image CommandLine technique
| sort - _time
```

**Tuning notes:** Browser-launched helpers may be expected for some enterprise workflows. Prioritize commands touching Downloads, Temp, AppData, or external URLs.

**Analyst next steps:** Check proxy/DNS logs for the user, identify recently downloaded files, and review whether the process tree created persistence or credential-access behavior.
