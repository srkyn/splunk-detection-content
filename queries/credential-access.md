# Credential Access Detections

## Brute Force Logon Failures

**What it detects:** Multiple failed logons from the same source or against the same account.

**ATT&CK mapping:** T1110.001 - Brute Force: Password Guessing

**Required data sources:** Windows Security Event ID 4625.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen values(host) as hosts by Account_Name, Source_Network_Address
| where count >= 10
| convert ctime(first_seen) ctime(last_seen)
| table first_seen last_seen Account_Name Source_Network_Address hosts count
| sort - count
```

**Tuning notes:** Watch for service accounts, scanners, lockout storms, and VPN gateways. Pair with successful logons after the failure burst.

## Kerberoasting Indicators

**What it detects:** Kerberos service ticket requests that use RC4 encryption.

**ATT&CK mapping:** T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

**Required data sources:** Windows Security Event ID 4769.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17
| stats count values(Service_Name) as services values(Client_Address) as client_addresses by Account_Name
| where count >= 5
| table Account_Name client_addresses services count
| sort - count
```

**Tuning notes:** Some legacy services still use RC4. Prioritize service accounts with SPNs, old passwords, and requests from unusual hosts.

## LSASS Access From Unusual Process

**What it detects:** Processes opening LSASS with access rights commonly associated with credential dumping.

**ATT&CK mapping:** T1003.001 - OS Credential Dumping: LSASS Memory

**Required data sources:** Sysmon Event ID 10.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
| search GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x1f0fff")
| eval technique="T1003.001 LSASS Memory"
| table _time host user SourceImage TargetImage GrantedAccess CallTrace technique
| sort - _time
```

**Tuning notes:** Security tools and EDR products may inspect LSASS legitimately. Baseline approved tools and escalate unknown binaries, admin utilities, and user-writable paths.
