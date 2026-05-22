# Lateral Movement Triage

## Scope

Use this playbook for SMB admin share access, remote PowerShell sessions, and explicit credential logons.

Related notes: `queries/lateral-movement.md`

## Triage flow

1. Identify source host, destination host, account, logon type, and time window.
2. Check whether the source is an approved admin host, jump box, scanner, or management server.
3. Review commands or processes launched after the connection.
4. Pivot backward to credential-access signals and forward to service creation, scheduled tasks, file writes, and remote execution.
5. Compare the account-to-host relationship against normal administration patterns.

## Key pivots

- `src`, `dest`, `user`, `LogonType`, `AuthenticationPackageName`, `ProcessName`
- PowerShell remoting logs and command history where available
- Admin share access, service creation, scheduled task events, and process creation
- Recent account changes, password resets, group membership changes, and source geography

## Escalate when

- A non-admin workstation accesses admin shares or starts remote sessions.
- Explicit credentials are used by an account that does not normally administer the destination.
- Lateral movement follows credential-access, discovery, or unusual logon behavior.
- Remote activity creates a service, scheduled task, or executable file on the destination.

## Close as likely noise when

- The source is a known jump box, management server, EDR process, vulnerability scanner, or deployment tool.
- The account, source, and destination match documented administrative workflow.
- The activity occurs during approved maintenance with expected commands.

## Limitations

Lateral-movement detections need environment baselines. This playbook should be used to decide whether the path is normal, not to assume movement from one event.
