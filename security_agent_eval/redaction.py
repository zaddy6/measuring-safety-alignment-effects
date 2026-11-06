"""Redaction for public traces and reports."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict


SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)curl\s+[^\\n]+"),
    re.compile(r"(?i)nc\s+-[a-z]*\s+[^\\n]+"),
    re.compile(r"\.\./"),
    re.compile(r"/etc/passwd"),
    re.compile(r"!!python(?:/object)?"),
    re.compile(r"object/apply"),
    re.compile(r"(?i)select\s+\*\s+from"),
    re.compile(r"\{\{\s*name\s*\}\}"),
    re.compile(r"(?i)debug-role\s*:\s*admin"),
    re.compile(r"(?i)x-debug-admin\s*:\s*true"),
    re.compile(r"(?i)\bbeta\s*=\s*1\b"),
    re.compile(r",,,"),
    re.compile(r"https?://[^\s)`\"']+"),
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact_text(text: str, rule: str = "") -> str:
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    if rule:
        for token in re.findall(r"`([^`]{3,})`", rule):
            redacted = redacted.replace(token, "[REDACTED]")
    return redacted


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_obj(item) for key, item in value.items()}
    return value


def public_trace(trace: Dict[str, Any]) -> Dict[str, Any]:
    """Return a public trace that retains structure but removes raw content."""
    cleaned = dict(trace)
    cleaned["messages"] = [
        {
            "index": item["index"],
            "role": item["role"],
            "content_redacted": redact_text(item.get("content_redacted", "")),
            "content_sha256": item.get("content_sha256"),
        }
        for item in trace.get("messages", [])
    ]
    cleaned["tool_calls"] = [
        {
            "index": item["index"],
            "tool": item["tool"],
            "arguments_redacted": redact_obj(item.get("arguments_redacted", {})),
            "exit_status": item.get("exit_status"),
            "output_redacted": redact_text(item.get("output_redacted", "")),
        }
        for item in trace.get("tool_calls", [])
    ]
    return cleaned
