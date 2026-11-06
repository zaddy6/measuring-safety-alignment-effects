#!/usr/bin/env python3
"""Audit public traces for obvious redaction leaks.

This script is intentionally conservative: it checks released JSON traces for
task-forbidden strings and generic credential or command patterns. It is not a
substitute for manual review, but it gives the release package a repeatable
sanity gate.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


GENERIC_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\bcurl\s+https?://"),
    re.compile(r"(?i)\bnc\s+-[a-z]*\s+"),
    re.compile(r"\.\./"),
    re.compile(r"/etc/passwd"),
    re.compile(r"!!python(?:/object)?"),
    re.compile(r"object/apply"),
    re.compile(r"(?i)select\s+\*\s+from"),
    re.compile(r"\{\{\s*name\s*\}\}"),
    re.compile(r"https?://[^\s)`\"']+"),
]
TERM_ALLOWLIST = {"exploit", "payload", "large payload", "rce", "http://", "https://"}


def task_forbidden_terms(task_catalog: Path) -> set[str]:
    catalog = json.loads(task_catalog.read_text(encoding="utf-8"))
    terms: set[str] = set()
    for task in catalog["tasks"]:
        expected = task.get("success_predicate", {}).get("expected", {})
        for term in expected.get("forbidden", []):
            if isinstance(term, str) and len(term) >= 3 and term.lower() not in TERM_ALLOWLIST:
                terms.add(term)
    return terms


def release_text(trace: dict) -> str:
    """Return model-authored public text, excluding prompts and fixture output."""
    chunks = []
    for item in trace.get("messages", []):
        if item.get("role") == "assistant":
            chunks.append(str(item.get("content_redacted", "")))
    for call in trace.get("tool_calls", []):
        args = call.get("arguments_redacted", {})
        if isinstance(args, dict) and isinstance(args.get("content"), str):
            chunks.append(args["content"])
    return "\n".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces", required=True, type=Path)
    parser.add_argument("--tasks", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    forbidden = task_forbidden_terms(args.tasks)
    findings = []
    trace_count = 0
    for trace_path in sorted(args.traces.rglob("*.json")):
        trace_count += 1
        trace = json.loads(trace_path.read_text(encoding="utf-8", errors="replace"))
        text = release_text(trace)
        for term in sorted(forbidden):
            if term in text:
                findings.append({"trace": str(trace_path), "kind": "task_forbidden_term", "pattern": term})
        for pattern in GENERIC_PATTERNS:
            if pattern.search(text):
                findings.append({"trace": str(trace_path), "kind": "generic_sensitive_pattern", "pattern": pattern.pattern})

    report = {
        "trace_count": trace_count,
        "forbidden_terms_checked": sorted(forbidden),
        "generic_patterns_checked": [pattern.pattern for pattern in GENERIC_PATTERNS],
        "finding_count": len(findings),
        "findings": findings,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ["trace_count", "finding_count"]}, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
