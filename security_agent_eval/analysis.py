"""Stdlib analysis for completed run traces."""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import read_json, write_json
from .schema import validate_trace


CONDITION_ORDER = ["aligned", "authorized", "auth-scope", "auth-evidence", "auth-policy", "jailbreak", "uncensored"]
TASK_CLASS_ORDER = [
    "non_security_code_reasoning",
    "vulnerability_localization",
    "reachability_validation",
    "proof_of_trigger",
    "patch_verification",
    "security_report_writing",
]
GROUNDING_FIELDS = [
    "read_expected_file",
    "named_expected_file",
    "named_expected_symbol",
    "named_issue",
    "provided_evidence",
]
FAILURE_LABEL_ORDER = [
    "success",
    "capability_failure",
    "localization_failure",
    "validation_failure",
    "reporting_failure",
    "tool_failure",
    "unsafe_action",
]
FAILURE_LABEL_HEADERS = {
    "success": "Success",
    "capability_failure": "Capability",
    "localization_failure": "Localization",
    "validation_failure": "Validation",
    "reporting_failure": "Reporting",
    "tool_failure": "Tool",
    "unsafe_action": "Unsafe",
}


def ordered_conditions(conditions: Iterable[str]) -> List[str]:
    present = set(conditions)
    return [condition for condition in CONDITION_ORDER if condition in present] + sorted(present - set(CONDITION_ORDER))


def condition_header(condition: str) -> str:
    return {
        "aligned": "Aligned",
        "authorized": "Authorized",
        "auth-scope": "Auth scope",
        "auth-evidence": "Auth evidence",
        "auth-policy": "Auth policy",
        "jailbreak": "Placeholder",
        "uncensored": "Uncensored",
    }.get(condition, condition.replace("_", " ").replace("-", " "))


def ordered_task_classes(classes: Iterable[str]) -> List[str]:
    present = set(classes)
    return [task_class for task_class in TASK_CLASS_ORDER if task_class in present] + sorted(present - set(TASK_CLASS_ORDER))


def load_traces(path: Path) -> List[Dict]:
    traces = []
    for item in sorted(path.rglob("*.json")):
        with item.open("r", encoding="utf-8") as handle:
            trace = json.load(handle)
        validate_trace(trace)
        traces.append(trace)
    return traces


def _contains(text: str, terms: Iterable[str]) -> bool:
    lowered = text.lower()
    return bool(terms) and any(str(term).lower() in lowered for term in terms)


def _all_catalog_paths() -> List[Path]:
    return [Path("tasks/catalog.json"), Path("tasks/sanity_catalog.json")]


def load_task_targets(tasks_path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    paths = [tasks_path] if tasks_path else _all_catalog_paths()
    tasks: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        if path is None or not path.exists():
            continue
        catalog = read_json(path)
        for task in catalog.get("tasks", []):
            tasks[task["task_id"]] = task
    return tasks


def final_artifact_text(trace: Dict) -> str:
    """Recover final artifact text from redacted traces for deterministic analysis."""
    texts: List[str] = []
    for call in trace.get("tool_calls", []):
        if call.get("tool") == "write_file":
            args = call.get("arguments_redacted") or {}
            content = args.get("content")
            if isinstance(content, str):
                texts.append(content)
    for message in trace.get("messages", []):
        if message.get("role") != "assistant":
            continue
        content = message.get("content_redacted") or ""
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            final = parsed.get("final")
            if isinstance(final, str) and "\n" in final:
                texts.append(final)
            for value in parsed.values():
                if isinstance(value, str) and "\n" in value:
                    texts.append(value)
                elif isinstance(value, dict):
                    nested_content = value.get("content")
                    if isinstance(nested_content, str):
                        texts.append(nested_content)
    return "\n".join(texts)


def grounding_for_trace(trace: Dict, task: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    targets = (task or {}).get("grounding_targets", {})
    files = [str(item) for item in targets.get("files", [])]
    symbols = [str(item) for item in targets.get("symbols", [])]
    issue_terms = [str(item) for item in targets.get("issue_terms", [])]
    evidence_terms = [str(item) for item in targets.get("evidence_terms", [])]

    read_paths = []
    tool_outputs = []
    for call in trace.get("tool_calls", []):
        args = call.get("arguments_redacted") or {}
        if call.get("tool") == "read_file" and isinstance(args.get("path"), str):
            read_paths.append(args["path"])
        tool_outputs.append(str(call.get("output_redacted", "")))

    final_text = final_artifact_text(trace)
    final_and_outputs = final_text + "\n" + "\n".join(tool_outputs)
    result = {
        "run_id": trace["run_id"],
        "task_id": trace["task_id"],
        "task_class": trace.get("task_class", ""),
        "seed": trace["seed"],
        "condition": trace["condition"],
        "success": int(bool(trace["success"])),
        "read_expected_file": int(_contains("\n".join(read_paths), files)),
        "named_expected_file": int(_contains(final_text, files)),
        "named_expected_symbol": int(_contains(final_text, symbols)),
        "named_issue": int(_contains(final_text, issue_terms)),
        "provided_evidence": int(_contains(final_and_outputs, evidence_terms)),
    }
    result["grounding_score"] = sum(result[field] for field in GROUNDING_FIELDS)
    return result


def bootstrap_ci(values: List[float], iterations: int = 5000, seed: int = 2026) -> Tuple[float, float]:
    if not values:
        return (math.nan, math.nan)
    rng = random.Random(seed)
    means = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        means.append(sum(sample) / len(sample))
    means.sort()
    return means[int(0.025 * iterations)], means[int(0.975 * iterations)]


def exact_mcnemar_p(b: int, c: int) -> float:
    """Two-sided exact binomial McNemar p-value for discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    prob = sum(math.comb(n, i) * (0.5**n) for i in range(k + 1))
    return min(1.0, 2 * prob)


def success_by_condition(traces: Iterable[Dict]) -> Dict[str, Dict]:
    grouped = defaultdict(list)
    for trace in traces:
        grouped[trace["condition"]].append(1.0 if trace["success"] else 0.0)
    summary = {}
    for condition, values in grouped.items():
        lo, hi = bootstrap_ci(values)
        summary[condition] = {
            "runs": len(values),
            "success_rate": sum(values) / len(values) if values else math.nan,
            "bootstrap_95_low": lo,
            "bootstrap_95_high": hi,
        }
    return summary


def paired_mcnemar(traces: Iterable[Dict], left: str = "aligned", right: str = "uncensored") -> Dict:
    by_pair = {}
    for trace in traces:
        key = (trace["task_id"], trace["seed"])
        by_pair.setdefault(key, {})[trace["condition"]] = trace["success"]
    b = c = paired = 0
    for result in by_pair.values():
        if left in result and right in result:
            paired += 1
            if result[left] and not result[right]:
                b += 1
            elif result[right] and not result[left]:
                c += 1
    return {"left": left, "right": right, "paired_runs": paired, "b": b, "c": c, "exact_p": exact_mcnemar_p(b, c)}


def label_counts(traces: Iterable[Dict]) -> Dict[str, Dict[str, int]]:
    counts = defaultdict(Counter)
    for trace in traces:
        label = trace["primary_failure_label"] or "success"
        counts[trace["condition"]][label] += 1
    return {condition: dict(counter) for condition, counter in counts.items()}


def success_by_task_class_condition(traces: Iterable[Dict]) -> Dict[str, Dict[str, Dict[str, float]]]:
    grouped = defaultdict(lambda: defaultdict(list))
    for trace in traces:
        grouped[trace["task_class"]][trace["condition"]].append(1.0 if trace["success"] else 0.0)
    summary = {}
    for task_class, by_condition in grouped.items():
        summary[task_class] = {}
        for condition, values in by_condition.items():
            summary[task_class][condition] = {
                "runs": len(values),
                "successes": int(sum(values)),
                "success_rate": sum(values) / len(values) if values else math.nan,
            }
    return summary


def cost_by_condition(traces: Iterable[Dict]) -> Dict[str, Dict[str, float]]:
    grouped = defaultdict(list)
    for trace in traces:
        grouped[trace["condition"]].append(trace)
    summary = {}
    for condition, values in grouped.items():
        walls = [float(trace.get("wall_clock_seconds") or 0.0) for trace in values]
        summary[condition] = {
            "runs": len(values),
            "total_model_calls": int(sum(int(trace.get("cost_model_calls") or 0) for trace in values)),
            "total_tokens": int(sum(int(trace.get("cost_tokens") or 0) for trace in values)),
            "median_wall_clock_seconds": statistics.median(walls) if walls else math.nan,
            "total_wall_clock_hours": sum(walls) / 3600 if walls else math.nan,
        }
    return summary


def grounding_rows(traces: Iterable[Dict], tasks: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [grounding_for_trace(trace, tasks.get(trace["task_id"])) for trace in traces]


def grounding_by_condition(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["condition"]].append(row)
    summary = {}
    for condition, values in grouped.items():
        count = len(values)
        summary[condition] = {"runs": count}
        for field in GROUNDING_FIELDS:
            summary[condition][field] = sum(row[field] for row in values) / count if count else math.nan
        summary[condition]["mean_grounding_score"] = (
            sum(row["grounding_score"] for row in values) / count if count else math.nan
        )
        summary[condition]["success_rate"] = sum(row["success"] for row in values) / count if count else math.nan
    return summary


def grounding_by_task_class_condition(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, float]]]:
    grouped = defaultdict(lambda: defaultdict(list))
    for row in rows:
        grouped[row["task_class"]][row["condition"]].append(row)
    summary = {}
    for task_class, by_condition in grouped.items():
        summary[task_class] = {}
        for condition, values in by_condition.items():
            count = len(values)
            summary[task_class][condition] = {
                "runs": count,
                "mean_grounding_score": sum(row["grounding_score"] for row in values) / count if count else math.nan,
                "success_rate": sum(row["success"] for row in values) / count if count else math.nan,
            }
    return summary


def write_grounding_run_level(out_dir: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "run_id",
        "task_id",
        "task_class",
        "seed",
        "condition",
        "success",
        *GROUNDING_FIELDS,
        "grounding_score",
    ]
    with (out_dir / "grounding_run_level.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def write_grounding_by_condition(out_dir: Path, summary: Dict[str, Dict[str, float]]) -> None:
    csv_fields = ["condition", "runs", *GROUNDING_FIELDS, "mean_grounding_score", "success_rate"]
    with (out_dir / "grounding_by_condition.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        for condition in CONDITION_ORDER:
            row = summary.get(condition)
            if row:
                writer.writerow({"condition": condition, **row})

    lines = [
        "\\begin{tabular}{lrrrrrrrr}",
        "\\toprule",
        "Condition & Runs & Read & File & Symbol & Issue & Evidence & Score & Success \\\\",
        "\\midrule",
    ]
    for condition in CONDITION_ORDER:
        row = summary.get(condition)
        if not row:
            continue
        lines.append(
            f"{condition} & {row['runs']} & {row['read_expected_file']:.2f} & "
            f"{row['named_expected_file']:.2f} & {row['named_expected_symbol']:.2f} & "
            f"{row['named_issue']:.2f} & {row['provided_evidence']:.2f} & "
            f"{row['mean_grounding_score']:.2f} & {row['success_rate']:.2f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "grounding_by_condition.tex").write_text("\n".join(lines), encoding="utf-8")


def write_grounding_by_task_class_condition(out_dir: Path, summary: Dict[str, Dict[str, Dict[str, float]]]) -> None:
    conditions = ordered_conditions(
        condition for by_condition in summary.values() for condition in by_condition
    )
    with (out_dir / "grounding_by_task_class_condition.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["task_class", "condition", "runs", "mean_grounding_score", "success_rate"],
        )
        writer.writeheader()
        for task_class in ordered_task_classes(summary):
            for condition in conditions:
                row = summary.get(task_class, {}).get(condition)
                if row:
                    writer.writerow({"task_class": task_class, "condition": condition, **row})

    lines = [
        "\\begin{tabular}{l" + "r" * len(conditions) + "}",
        "\\toprule",
        "Task class & " + " & ".join(condition_header(condition) for condition in conditions) + " \\\\",
        "\\midrule",
    ]
    for task_class in ordered_task_classes(summary):
        if task_class not in summary:
            continue
        cells = []
        for condition in conditions:
            row = summary.get(task_class, {}).get(condition)
            cells.append("--" if not row else f"{row['mean_grounding_score']:.2f}")
        lines.append(task_class.replace("_", " ") + " & " + " & ".join(cells) + " \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "grounding_by_task_class_condition.tex").write_text("\n".join(lines), encoding="utf-8")


def write_csv_summary(out_dir: Path, summary: Dict[str, Dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "success_by_condition.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["condition", "runs", "success_rate", "bootstrap_95_low", "bootstrap_95_high"],
        )
        writer.writeheader()
        for condition, row in sorted(summary.items()):
            writer.writerow({"condition": condition, **row})


def write_latex_success_table(out_dir: Path, summary: Dict[str, Dict]) -> None:
    lines = [
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Condition & Runs & Success & 95\\% CI low & 95\\% CI high \\\\",
        "\\midrule",
    ]
    for condition, row in sorted(summary.items()):
        lines.append(
            f"{condition} & {row['runs']} & {row['success_rate']:.3f} & "
            f"{row['bootstrap_95_low']:.3f} & {row['bootstrap_95_high']:.3f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "success_by_condition.tex").write_text("\n".join(lines), encoding="utf-8")


def write_label_counts(out_dir: Path, counts: Dict[str, Dict[str, int]]) -> None:
    labels = sorted({label for rows in counts.values() for label in rows})
    with (out_dir / "primary_failure_labels.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["condition", *labels])
        writer.writeheader()
        for condition, row in sorted(counts.items()):
            writer.writerow({"condition": condition, **{label: row.get(label, 0) for label in labels}})


def write_latex_label_counts(out_dir: Path, counts: Dict[str, Dict[str, int]]) -> None:
    labels = [label for label in FAILURE_LABEL_ORDER if any(label in row for row in counts.values())]
    lines = [
        "\\begin{tabular}{l" + "r" * len(labels) + "}",
        "\\toprule",
        "Condition & " + " & ".join(FAILURE_LABEL_HEADERS.get(label, label) for label in labels) + " \\\\",
        "\\midrule",
    ]
    for condition in CONDITION_ORDER:
        if condition not in counts:
            continue
        row = counts[condition]
        lines.append(condition + " & " + " & ".join(str(row.get(label, 0)) for label in labels) + " \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "primary_failure_labels.tex").write_text("\n".join(lines), encoding="utf-8")


def write_task_class_success_tables(out_dir: Path, summary: Dict[str, Dict[str, Dict[str, float]]]) -> None:
    conditions = ordered_conditions(
        condition for by_condition in summary.values() for condition in by_condition
    )
    with (out_dir / "success_by_task_class_condition.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["task_class", "condition", "runs", "successes", "success_rate"],
        )
        writer.writeheader()
        for task_class in ordered_task_classes(summary):
            for condition in conditions:
                row = summary.get(task_class, {}).get(condition)
                if row:
                    writer.writerow({"task_class": task_class, "condition": condition, **row})

    lines = [
        "\\begin{tabular}{l" + "r" * len(conditions) + "}",
        "\\toprule",
        "Task class & " + " & ".join(condition_header(condition) for condition in conditions) + " \\\\",
        "\\midrule",
    ]
    for task_class in ordered_task_classes(summary):
        cells = []
        for condition in conditions:
            row = summary.get(task_class, {}).get(condition)
            cells.append("--" if not row else f"{row['successes']}/{row['runs']}")
        lines.append(task_class.replace("_", " ") + " & " + " & ".join(cells) + " \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "success_by_task_class_condition.tex").write_text("\n".join(lines), encoding="utf-8")


def write_cost_tables(out_dir: Path, summary: Dict[str, Dict[str, float]]) -> None:
    fields = [
        "condition",
        "runs",
        "total_model_calls",
        "total_tokens",
        "median_wall_clock_seconds",
        "total_wall_clock_hours",
    ]
    with (out_dir / "cost_by_condition.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for condition in CONDITION_ORDER:
            row = summary.get(condition)
            if row:
                writer.writerow({"condition": condition, **row})

    lines = [
        "\\begin{tabular}{lrrrrr}",
        "\\toprule",
        "Condition & Runs & Calls & Tokens & Median s & Total h \\\\",
        "\\midrule",
    ]
    for condition in CONDITION_ORDER:
        row = summary.get(condition)
        if not row:
            continue
        lines.append(
            f"{condition} & {row['runs']} & {row['total_model_calls']} & "
            f"{row['total_tokens']} & {row['median_wall_clock_seconds']:.1f} & "
            f"{row['total_wall_clock_hours']:.2f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    (out_dir / "cost_by_condition.tex").write_text("\n".join(lines), encoding="utf-8")


def write_run_level_csv(out_dir: Path, traces: List[Dict]) -> None:
    with (out_dir / "run_level.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_id",
                "task_id",
                "task_class",
                "seed",
                "condition",
                "success",
                "primary_failure_label",
                "cost_tokens",
                "cost_model_calls",
                "wall_clock_seconds",
            ],
        )
        writer.writeheader()
        for trace in traces:
            writer.writerow(
                {
                    "run_id": trace["run_id"],
                    "task_id": trace["task_id"],
                    "task_class": trace.get("task_class", ""),
                    "seed": trace["seed"],
                    "condition": trace["condition"],
                    "success": int(bool(trace["success"])),
                    "primary_failure_label": trace["primary_failure_label"] or "",
                    "cost_tokens": trace["cost_tokens"],
                    "cost_model_calls": trace["cost_model_calls"],
                    "wall_clock_seconds": trace["wall_clock_seconds"],
                }
            )


def analyze(runs_dir: Path, out_dir: Path, tasks_path: Optional[Path] = None) -> Dict:
    traces = load_traces(runs_dir)
    tasks = load_task_targets(tasks_path)
    grounding = grounding_rows(traces, tasks)
    summary = {
        "trace_count": len(traces),
        "success_by_condition": success_by_condition(traces),
        "success_by_task_class_condition": success_by_task_class_condition(traces),
        "cost_by_condition": cost_by_condition(traces),
        "mcnemar_aligned_vs_uncensored": paired_mcnemar(traces),
        "primary_failure_labels": label_counts(traces),
        "grounding_by_condition": grounding_by_condition(grounding),
        "grounding_by_task_class_condition": grounding_by_task_class_condition(grounding),
    }
    write_json(out_dir / "summary.json", summary)
    write_csv_summary(out_dir, summary["success_by_condition"])
    write_latex_success_table(out_dir, summary["success_by_condition"])
    write_label_counts(out_dir, summary["primary_failure_labels"])
    write_latex_label_counts(out_dir, summary["primary_failure_labels"])
    write_task_class_success_tables(out_dir, summary["success_by_task_class_condition"])
    write_cost_tables(out_dir, summary["cost_by_condition"])
    write_run_level_csv(out_dir, traces)
    write_grounding_run_level(out_dir, grounding)
    write_grounding_by_condition(out_dir, summary["grounding_by_condition"])
    write_grounding_by_task_class_condition(out_dir, summary["grounding_by_task_class_condition"])
    return summary
