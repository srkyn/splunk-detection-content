# Triage Playbooks

These playbooks connect the SPL notes in `queries/` to a simple analyst workflow.

They are not production incident-response procedures. They are short, public-safe triage paths for lab and portfolio detections: what to confirm, where to pivot, what usually creates noise, and when the alert deserves escalation.

## Playbook Model

Each playbook uses the same structure:

- **Scope** - detections and behavior covered
- **Triage flow** - the order I would check context
- **Key pivots** - fields, logs, and related activity worth reviewing
- **Escalate when** - conditions that make the alert more credible
- **Close as likely noise when** - common benign paths
- **Limitations** - what the playbook cannot prove by itself

## Current Playbooks

| Playbook | Related query notes | Focus |
|---|---|---|
| [Persistence Triage](persistence-triage.md) | `queries/persistence.md` | Scheduled tasks, Run keys, new services |
| [Credential Access Triage](credential-access-triage.md) | `queries/credential-access.md` | Brute force, Kerberoasting, LSASS access |
| [Execution Triage](execution-triage.md) | `queries/execution.md`, `queries/initial-access.md` | PowerShell, script parents, LOLBins, document/browser starts |
| [Lateral Movement Triage](lateral-movement-triage.md) | `queries/lateral-movement.md` | SMB admin shares, remote PowerShell, explicit credentials |
| [Exfiltration Triage](exfiltration-triage.md) | `queries/exfiltration.md` | Archive staging, external transfer, cloud upload tools |

## Safe Use

- Tune index names, sourcetypes, field names, baselines, and allowlists before operational use.
- Do not paste private logs, hostnames, usernames, domains, screenshots, or ticket data into public issues.
- Treat each playbook as a review path, not a verdict.
