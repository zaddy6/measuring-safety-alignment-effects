"""Lightweight manifest and trace validation.

The repository keeps formal JSON schemas in ``schemas/``.  This module provides
stdlib-only validation for the command-line tools so the harness can run before
optional dependencies are installed.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


TASK_CLASSES = {
    "non_security_code_reasoning",
    "vulnerability_localization",
    "reachability_validation",
    "proof_of_trigger",
    "patch_verification",
    "security_report_writing",
}

CONDITIONS = {"aligned", "authorized", "jailbreak", "uncensored"}
CONDITIONS.update({"auth-scope", "auth-evidence", "auth-policy"})

FAILURE_LABELS = {
    None,
    "strict_refusal",
    "partial_refusal",
    "suppressed_action",
    "planning_failure",
    "reconnaissance_failure",
    "setup_failure",
    "localization_failure",
    "construction_failure",
    "validation_failure",
    "reporting_failure",
    "tool_failure",
    "environment_failure",
    "capability_failure",
    "unsafe_action",
}

REQUIRED_TASK_FIELDS = {
    "task_id",
    "task_class",
    "container_image",
    "entrypoint",
    "time_limit_seconds",
    "max_model_calls",
    "allowed_tools",
    "forbidden_actions",
    "initial_prompt",
    "ground_truth",
    "grounding_targets",
    "success_predicate",
    "redaction_rule",
    "expected_artifacts",
}

REQUIRED_TRACE_FIELDS = {
    "run_id",
    "model_id",
    "model_revision",
    "condition",
    "task_id",
    "task_class",
    "seed",
    "backend",
    "quantization",
    "sampling_config",
    "start_time",
    "end_time",
    "messages",
    "tool_calls",
    "phase_events",
    "refusal_events",
    "suppressed_actions",
    "unsafe_actions",
    "success",
    "primary_failure_label",
    "cost_tokens",
    "cost_model_calls",
    "wall_clock_seconds",
}


class ValidationError(ValueError):
    """Raised when an experiment artifact does not match the required shape."""


def _missing(data: Dict[str, Any], required: Iterable[str]) -> List[str]:
    return sorted(field for field in required if field not in data)


def validate_task_manifest(task: Dict[str, Any]) -> None:
    missing = _missing(task, REQUIRED_TASK_FIELDS)
    if missing:
        raise ValidationError(f"task {task.get('task_id', '<unknown>')} missing fields: {missing}")
    if task["task_class"] not in TASK_CLASSES:
        raise ValidationError(f"{task['task_id']} has invalid task_class {task['task_class']!r}")
    if not isinstance(task["entrypoint"], list) or not task["entrypoint"]:
        raise ValidationError(f"{task['task_id']} entrypoint must be a non-empty list")
    if not isinstance(task["allowed_tools"], list):
        raise ValidationError(f"{task['task_id']} allowed_tools must be a list")
    if not isinstance(task["forbidden_actions"], list):
        raise ValidationError(f"{task['task_id']} forbidden_actions must be a list")
    if not isinstance(task["ground_truth"], dict):
        raise ValidationError(f"{task['task_id']} ground_truth must be an object")
    if not isinstance(task["grounding_targets"], dict):
        raise ValidationError(f"{task['task_id']} grounding_targets must be an object")
    for field in ("files", "symbols", "issue_terms", "evidence_terms"):
        if field not in task["grounding_targets"] or not isinstance(task["grounding_targets"][field], list):
            raise ValidationError(f"{task['task_id']} grounding_targets.{field} must be a list")
    predicate = task["success_predicate"]
    if not isinstance(predicate, dict) or "type" not in predicate or "description" not in predicate:
        raise ValidationError(f"{task['task_id']} success_predicate must include type and description")
    if "expected" not in predicate:
        raise ValidationError(f"{task['task_id']} success_predicate.expected is required by the harness")


def validate_task_catalog(catalog: Dict[str, Any]) -> None:
    if "tasks" not in catalog or not isinstance(catalog["tasks"], list):
        raise ValidationError("task catalog must contain a tasks array")
    seen = set()
    for task in catalog["tasks"]:
        validate_task_manifest(task)
        task_id = task["task_id"]
        if task_id in seen:
            raise ValidationError(f"duplicate task_id {task_id}")
        seen.add(task_id)


def validate_trace(trace: Dict[str, Any]) -> None:
    missing = _missing(trace, REQUIRED_TRACE_FIELDS)
    if missing:
        raise ValidationError(f"trace {trace.get('run_id', '<unknown>')} missing fields: {missing}")
    if trace["condition"] not in CONDITIONS:
        raise ValidationError(f"{trace['run_id']} has invalid condition {trace['condition']!r}")
    if trace["task_class"] not in TASK_CLASSES:
        raise ValidationError(f"{trace['run_id']} has invalid task_class {trace['task_class']!r}")
    if trace["primary_failure_label"] not in FAILURE_LABELS:
        raise ValidationError(
            f"{trace['run_id']} has invalid primary_failure_label {trace['primary_failure_label']!r}"
        )
    if trace["success"] and trace["primary_failure_label"] is not None:
        raise ValidationError(f"{trace['run_id']} succeeded but has a failure label")
    if not trace["success"] and trace["primary_failure_label"] is None:
        raise ValidationError(f"{trace['run_id']} failed without a primary failure label")
