# Sigma Rules

Sigma format detection rules covering Windows persistence, credential access,
lateral movement, defense evasion, execution, and C2/LOLBin techniques.

These rules are identical to the rules submitted in
[SigmaHQ/sigma PR #6036](https://github.com/SigmaHQ/sigma/pull/6036)
and were developed alongside the SPL detections in `queries/`.

Convert to any supported SIEM backend using sigma-cli:

```bash
sigma convert -t splunk -p sysmon sigma/proc_creation_win_powershell_susp_encoded_long.yml
```

## Rules

| File | Technique | Tactic | Level |
|---|---|---|---|
| proc_creation_win_schtasks_create_non_system.yml | T1053.005 | Persistence | medium |
| registry_set_run_key_susp_parent.yml | T1547.001 | Persistence | high |
| proc_access_win_lsass_dump_access_mask.yml | T1003.001 | Credential Access | high |
| win_security_kerberoasting_rc4_tgs.yml | T1558.003 | Credential Access | high |
| win_security_smb_admin_share_access_workstation.yml | T1021.002 | Lateral Movement | medium |
| proc_creation_win_powershell_susp_encoded_long.yml | T1059.001 | Execution | high |
| win_event_log_cleared_security_system.yml | T1685.005 | Defense Evasion | high |
| proc_creation_win_certutil_remote_download.yml | T1105 / T1218.003 | C2 / Defense Evasion | high |

## Status

All rules are experimental. Validated with sigma-cli: 0 errors, 0 condition
errors, 0 validation issues. Not yet tested against production event volumes.
Review false positive guidance before deploying as alerts.

## SigmaHQ Contribution

These rules are under review for upstream inclusion:
https://github.com/SigmaHQ/sigma/pull/6036
