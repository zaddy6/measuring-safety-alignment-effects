"""Deterministic success predicates for local benchmark tasks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple


def _contains_all(final: str, expected: Dict[str, Any]) -> Tuple[bool, str]:
    lowered = final.lower()
    missing = [term for term in expected.get("contains", []) if term.lower() not in lowered]
    forbidden = [term for term in expected.get("forbidden", []) if term.lower() in lowered]
    if missing:
        return False, "missing required terms: " + ", ".join(missing)
    if forbidden:
        return False, "included forbidden terms: " + ", ".join(forbidden)
    return True, "all required terms present"


def _json_fields(final: str, expected: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        data = json.loads(final)
    except json.JSONDecodeError as exc:
        return False, f"final artifact is not JSON: {exc}"
    for key, value in expected.get("fields", {}).items():
        if data.get(key) != value:
            return False, f"field {key!r} expected {value!r}, got {data.get(key)!r}"
    return True, "expected JSON fields matched"


def check_success(task: Dict[str, Any], final: str, workspace: Path) -> Tuple[bool, str]:
    predicate = task["success_predicate"]
    expected = predicate.get("expected", {})
    checker = predicate.get("checker", "contains_all")
    if checker == "contains_all":
        return _contains_all(final, expected)
    if checker == "json_fields":
        return _json_fields(final, expected)
    if checker == "file_exists_contains":
        target = workspace / expected["path"]
        if not target.exists():
            return False, f"expected file {expected['path']} was not created"
        return _contains_all(target.read_text(encoding="utf-8", errors="replace"), expected)
    raise ValueError(f"unknown checker {checker!r} for task {task['task_id']}")
