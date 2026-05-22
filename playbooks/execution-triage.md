# Execution Triage

## Scope

Use this playbook for suspicious PowerShell, script interpreter parent processes, LOLBin download/execute behavior, and initial access patterns from Office documents or browser downloads.

Related notes: `queries/execution.md`, `queries/initial-access.md`

## Triage flow

1. Identify the process tree: parent, child, command line, user, host, and timestamp.
2. Decode or normalize command content where possible.
3. Check file origin, downloaded files, document activity, and browser history if available.
4. Pivot to DNS, proxy, network connections, file writes, persistence, and credential-access signals.
5. Compare the pattern to known admin scripts, software deployment, EDR actions, and automation.

## Key pivots

- `Image`, `ParentImage`, `CommandLine`, `ParentCommandLine`, `OriginalFileName`
- PowerShell script block logs and encoded command content
- File creation, downloaded payloads, DNS/proxy logs, and outbound connections
- Follow-on persistence, credential access, or lateral movement detections

## Escalate when

- Office or browser activity spawns PowerShell, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, or similar tooling.
- Encoded or obfuscated commands reach external URLs or write executable content.
- A suspicious interpreter chain is followed by persistence, credential access, or remote connections.
- The same command appears rarely or only on one host/user.

## Close as likely noise when

- The command is tied to approved software deployment, endpoint management, helpdesk tooling, or EDR response.
- The parent/child relationship is expected for a known business application.
- The URL, file hash, signer, and path match approved internal tooling.

## Limitations

Execution signals can be noisy. This playbook focuses on process context and follow-on behavior, not a single command string in isolation.
