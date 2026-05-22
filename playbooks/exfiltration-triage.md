# Exfiltration Triage

## Scope

Use this playbook for suspicious archive creation, large external transfers, and cloud storage upload tool activity.

Related notes: `queries/exfiltration.md`

## Triage flow

1. Identify the user, host, archive path, process, destination, and transfer window.
2. Review file access, staging directory, archive size, and process ancestry before the transfer.
3. Resolve external destination ownership and compare it to normal business use.
4. Pivot to recent authentication anomalies, privilege changes, unusual discovery, and endpoint alerts.
5. Preserve enough context for follow-up without exposing sensitive file names publicly.

## Key pivots

- Archive path, file size, process name, command line, destination domain/IP, byte count
- File access events, proxy/DNS logs, cloud storage client logs, and EDR process trees
- Recent login anomalies, new OAuth grants, credential-access signals, and endpoint persistence
- User role, department, expected data movement, and approved cloud applications

## Escalate when

- Archive creation is followed by a large external transfer or unknown cloud upload.
- The destination is new, personal, rare, or unrelated to normal business use.
- The account recently had unusual authentication, privilege changes, or endpoint execution.
- The staged files appear sensitive or outside the user's normal access pattern.

## Close as likely noise when

- The transfer matches approved backup, reporting, support, engineering, or business workflow.
- The destination is sanctioned and normal for the user/team.
- The archive path, process, timing, and destination match a documented job.

## Limitations

This playbook does not inspect file contents. It organizes metadata and context so a reviewer can decide whether data movement needs escalation.
