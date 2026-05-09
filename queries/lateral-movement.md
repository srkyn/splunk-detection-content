# Lateral Movement Detections

## SMB Admin Share Access

**What it detects:** Access to administrative shares that may support remote execution or file transfer.

**ATT&CK mapping:** T1021.002 - Remote Services: SMB/Windows Admin Shares

**Required data sources:** Windows Security Event ID 5140.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5140 Share_Name IN ("*\\ADMIN$", "*\\C$", "*\\IPC$")
| stats count values(Share_Name) as shares values(host) as targets by Account_Name, Source_Address
| where count >= 3
| table Account_Name Source_Address targets shares count
| sort - count
```

**Tuning notes:** Admin tools, software deployment, and backup agents may be noisy. Focus on unusual users, new source hosts, or spikes outside maintenance windows.

**Analyst next steps:** Compare the source host to known admin jump boxes, review destination hosts, and pivot to 4624 logon type 3/10 plus service creation or remote execution events.

## Remote PowerShell Session

**What it detects:** PowerShell remoting activity.

**ATT&CK mapping:** T1021.006 - Remote Services: Windows Remote Management

**Required data sources:** PowerShell Operational logs.

```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (400, 403, 600)
| search HostApplication="*wsmprovhost*" OR HostName="ServerRemoteHost"
| eval technique="T1021.006 WinRM"
| table _time host user EventCode HostApplication HostName technique
| sort - _time
```

**Tuning notes:** Approved admin automation may use WinRM heavily. Baseline known admin jump boxes and look for non-admin endpoints initiating sessions.

**Analyst next steps:** Identify the initiating account and source host, check whether the account recently authenticated from a new location, and review commands run in the session.

## Explicit Credential Logon

**What it detects:** Logon events where explicit credentials were used.

**ATT&CK mapping:** T1550.002 - Use Alternate Authentication Material: Pass the Hash

**Required data sources:** Windows Security Event ID 4648.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4648
| stats count values(Target_Server_Name) as target_servers values(Process_Name) as processes by Account_Name, SubjectUserName, host
| where count >= 3
| table host SubjectUserName Account_Name target_servers processes count
| sort - count
```

**Tuning notes:** This is not proof of pass-the-hash by itself. Use it as a pivot with logon type, source host, destination host, and unusual account use.

**Analyst next steps:** Correlate with 4624 logon type, NTLM/Kerberos context, target servers, process names, and whether explicit credentials were used by an account that does not normally administer that host.
