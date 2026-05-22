# Persistence Triage

## Scope

Use this playbook for detections involving scheduled task creation or updates, Run/RunOnce registry changes, and new Windows service installation.

Related notes: `queries/persistence.md`

## Triage flow

1. Confirm the host, user, timestamp, and persistence mechanism.
2. Review the task action, registry value, or service path.
3. Check parent process, signer, hash, and file creation time where available.
4. Pivot to recent logons, process creation, network connections, and downloaded files on the same host.
5. Compare the path and account to known deployment tooling, endpoint agents, and maintenance windows.

## Key pivots

- `host`, `user`, `Task_Name`, `Command`, `TargetObject`, `Details`
- `Service_Name`, `Service_File_Name`, `Account_Name`
- Sysmon process creation and file creation around the same timestamp
- Recent interactive logons and remote logons on the host

## Escalate when

- The binary runs from a user profile, temp path, downloads folder, or unusual network share.
- The author or run context does not match normal administration.
- Persistence appears shortly after document execution, PowerShell, credential access, or lateral movement.
- The binary is unsigned, newly written, or rare in the environment.

## Close as likely noise when

- The event matches approved deployment tooling, software updates, EDR actions, or a documented maintenance window.
- The file path, signer, run context, and parent process match a known-good pattern.
- The same mechanism is common across similarly managed hosts.

## Limitations

This playbook does not prove malicious intent. It only organizes persistence-shaped signals so an analyst can decide what needs deeper review.
