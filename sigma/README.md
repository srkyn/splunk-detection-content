# Sigma Rules

Sigma format versions of the detections in this repository.

These rules were developed from the SPL detections and analyst notes in
`queries/`. Each rule maps to a MITRE ATT&CK technique, includes false
positive guidance, and targets Windows environments with Sysmon or standard
Windows event logging.

## Rules

| File | Technique | Tactic | Level |
|---|---|---|---|
| proc_creation_win_schtasks_create_non_system.yml | T1053.005 | Persistence | medium |
| registry_set_run_key_susp_parent.yml | T1547.001 | Persistence | high |
| proc_access_win_lsass_dump_access_mask.yml | T1003.001 | Credential Access | high |
| win_security_kerberoasting_rc4_tgs.yml | T1558.003 | Credential Access | high |
| win_security_smb_admin_share_access_workstation.yml | T1021.002 | Lateral Movement | medium |
| proc_creation_win_powershell_susp_encoded_long.yml | T1059.001 | Execution | high |
| win_event_log_cleared_security_system.yml | T1685.005 | Defense Impairment | high |
| proc_creation_win_certutil_remote_download.yml | T1105 / T1218.003 | C2 / System Binary Proxy Execution | high |

## Converting to SPL

```bash
sigma convert -t splunk -p sysmon sigma/proc_creation_win_powershell_susp_encoded_long.yml
```

## Status

All rules are `experimental`. Validated with `sigma check` and YAML syntax checks.
Not yet tested against production log volumes. Review false positive guidance before deploying as alerts.

The corresponding SPL detections with tuning notes and analyst pivots are in `queries/`.
