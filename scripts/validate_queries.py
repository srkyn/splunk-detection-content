"""Validate the public detection and playbook writeups."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_PHRASES = (
    "What it detects",
    "ATT&CK mapping",
    "Required data sources",
    "Tuning notes",
    "Analyst next steps",
)

REQUIRED_PLAYBOOK_PHRASES = (
    "Scope",
    "Triage flow",
    "Key pivots",
    "Escalate when",
    "Close as likely noise when",
    "Limitations",
)


def validate_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []

    for phrase in REQUIRED_PHRASES:
        if phrase not in text:
            errors.append(f"{path}: missing section phrase: {phrase}")

    if not re.search(r"T\d{4}(?:\.\d{3})?", text):
        errors.append(f"{path}: missing MITRE ATT&CK technique ID")

    if "```spl" not in text:
        errors.append(f"{path}: missing fenced spl block")

    return errors


def validate_playbook(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []

    for phrase in REQUIRED_PLAYBOOK_PHRASES:
        if phrase not in text:
            errors.append(f"{path}: missing playbook section phrase: {phrase}")

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    query_files = sorted((root / "queries").glob("*.md"))
    if not query_files:
        print("No query files found", file=sys.stderr)
        return 1

    errors: list[str] = []
    for path in query_files:
        errors.extend(validate_file(path))

    playbook_files = sorted((root / "playbooks").glob("*-triage.md"))
    if not playbook_files:
        errors.append("No playbook files found")
    for path in playbook_files:
        errors.extend(validate_playbook(path))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"Validated {len(query_files)} detection writeups and {len(playbook_files)} playbooks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
