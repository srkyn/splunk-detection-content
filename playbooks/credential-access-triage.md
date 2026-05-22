# Credential Access Triage

## Scope

Use this playbook for failed logon clusters, Kerberoasting-style service ticket requests, and suspicious LSASS access.

Related notes: `queries/credential-access.md`

## Triage flow

1. Identify the source host, target account, destination, and time window.
2. Check whether failures became successes from the same source.
3. Review account type, role, password age, SPN status, and normal login geography.
4. Pivot to domain discovery, process creation, remote access, and service creation after the credential signal.
5. Separate scanners, service accounts, and known admin workflows from unusual endpoints or user behavior.

## Key pivots

- `src`, `user`, `dest`, `EventCode`, `ServiceName`, `TicketEncryptionType`
- Account role, group membership, password age, and SPN ownership
- Process signer, command line, parent process, and dump file creation for LSASS access
- Subsequent successful logons, lateral movement, or privilege changes

## Escalate when

- Failed attempts are followed by a successful login from the same source.
- Service ticket requests target high-value or stale service accounts.
- LSASS access comes from unknown binaries, user-writable paths, or unexpected admin tools.
- Credential signals are followed by discovery, remote execution, or persistence.

## Close as likely noise when

- The source is an approved scanner, identity tool, VPN concentrator, jump box, EDR process, or documented admin host.
- The account and source match expected service behavior.
- The event is explained by a password rotation, lockout troubleshooting, or approved security tooling.

## Limitations

Credential-access detections need identity context. This playbook should not label an event suspicious without role, source, baseline, and follow-on activity.
