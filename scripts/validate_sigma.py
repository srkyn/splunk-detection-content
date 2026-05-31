"""Validate Sigma rule metadata and structure for this repository."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from uuid import UUID

import yaml


REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def is_uuid(value: object) -> bool:
    try:
        UUID(str(value))
        return True
    except ValueError:
        return False


def validate_rule(path: Path, seen_ids: set[str]) -> list[str]:
    errors: list[str] = []
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: invalid YAML: {exc}"]

    if not isinstance(rule, dict):
        return [f"{path}: top-level YAML value must be a mapping"]

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"{path}: missing required field: {field}")

    rule_id = str(rule.get("id", ""))
    if not is_uuid(rule_id):
        errors.append(f"{path}: id is not a valid UUID")
    elif rule_id in seen_ids:
        errors.append(f"{path}: duplicate id: {rule_id}")
    else:
        seen_ids.add(rule_id)

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append(f"{path}: detection must be a mapping")
    elif "condition" not in detection:
        errors.append(f"{path}: detection missing condition")

    tags = rule.get("tags", [])
    if not isinstance(tags, list) or not tags:
        errors.append(f"{path}: tags must be a non-empty list")
    else:
        bad_tags = [tag for tag in tags if not re.match(r"^(attack|car)\.", str(tag))]
        if bad_tags:
            errors.append(f"{path}: unexpected tag prefix: {bad_tags}")
        if not any(re.match(r"attack\.t\d{4}(?:\.\d{3})?$", str(tag)) for tag in tags):
            errors.append(f"{path}: missing ATT&CK technique tag")

    if rule.get("level") not in VALID_LEVELS:
        errors.append(f"{path}: invalid level: {rule.get('level')}")

    if not rule.get("falsepositives"):
        errors.append(f"{path}: falsepositives must not be empty")

    if not rule.get("references"):
        errors.append(f"{path}: references must not be empty")

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sigma_dir = root / "sigma"
    rules = sorted(sigma_dir.glob("*.yml"))
    if not rules:
        print("No Sigma rules found", file=sys.stderr)
        return 1

    errors: list[str] = []
    seen_ids: set[str] = set()
    for path in rules:
        errors.extend(validate_rule(path, seen_ids))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"Validated {len(rules)} Sigma rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
