#!/usr/bin/env python3
"""Generate paper-facing summary tables from saved evaluation artifacts."""

from __future__ import annotations

import csv
import itertools
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
TABLES = ROOT / "tables"
ARTIFACTS = ROOT / "artifacts"


DATASETS = {
    "31B security": ("artifacts/redacted_traces/primary_31b_repair", "analysis/primary_31b_repair", "tasks/catalog.json"),
    "31B sanity": ("artifacts/redacted_traces/sanity_31b_repair", "analysis/sanity_31b_repair", "tasks/sanity_catalog.json"),
    "31B standard": ("artifacts/redacted_traces/standard_coding_31b_repair", "analysis/standard_coding_31b_repair", "tasks/standard_coding_catalog.json"),
    "26B security": ("artifacts/redacted_traces/replication_26b_a4b_repair", "analysis/replication_26b_a4b_repair", "tasks/catalog.json"),
    "26B sanity": ("artifacts/redacted_traces/sanity_26b_a4b_repair", "analysis/sanity_26b_a4b_repair", "tasks/sanity_catalog.json"),
    "26B standard": ("artifacts/redacted_traces/standard_coding_26b_a4b_repair", "analysis/standard_coding_26b_a4b_repair", "tasks/standard_coding_catalog.json"),
    "Qwen security": ("artifacts/redacted_traces/qwen25_coder_7b_repair", "analysis/qwen25_coder_7b_repair", "tasks/catalog.json"),
    "Qwen sanity": ("artifacts/redacted_traces/sanity_qwen25_coder_7b_repair", "analysis/sanity_qwen25_coder_7b_repair", "tasks/sanity_catalog.json"),
    "Qwen standard": (
        "artifacts/redacted_traces/standard_coding_qwen25_coder_7b_repair",
        "analysis/standard_coding_qwen25_coder_7b_repair",
        "tasks/standard_coding_catalog.json",
    ),
    "Llama security": ("artifacts/redacted_traces/llama31_8b_repair", "analysis/llama31_8b_repair", "tasks/catalog.json"),
    "Llama sanity": ("artifacts/redacted_traces/sanity_llama31_8b_repair", "analysis/sanity_llama31_8b_repair", "tasks/sanity_catalog.json"),
    "Llama standard": (
        "artifacts/redacted_traces/standard_coding_llama31_8b_repair",
        "analysis/standard_coding_llama31_8b_repair",
        "tasks/standard_coding_catalog.json",
    ),
    "31B auth prompts": ("artifacts/redacted_traces/auth_prompt_robustness_31b", "analysis/auth_prompt_robustness_31b", "tasks/catalog.json"),
}

SECURITY_FAMILIES = [
    ("Gemma 31B", "artifacts/redacted_traces/primary_31b_repair", "analysis/primary_31b_repair"),
    ("Gemma 26B A4B", "artifacts/redacted_traces/replication_26b_a4b_repair", "analysis/replication_26b_a4b_repair"),
    ("Qwen2.5-Coder 7B", "artifacts/redacted_traces/qwen25_coder_7b_repair", "analysis/qwen25_coder_7b_repair"),
    ("Llama 3.1 8B", "artifacts/redacted_traces/llama31_8b_repair", "analysis/llama31_8b_repair"),
]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(value: float) -> str:
    return f"{100 * value:.1f}\\%"


def label(condition: str) -> str:
    return {
        "aligned": "Aligned",
        "authorized": "Authorized",
        "auth-scope": "Auth scope",
        "auth-evidence": "Auth evidence",
        "auth-policy": "Auth policy",
        "jailbreak": "Placeholder",
        "uncensored": "Uncensored",
    }.get(condition, condition)


def condition_order(conditions: Iterable[str]) -> List[str]:
    preferred = ["aligned", "authorized", "auth-scope", "auth-evidence", "auth-policy", "jailbreak", "uncensored"]
    present = set(conditions)
    return [item for item in preferred if item in present] + sorted(present - set(preferred))


def trace_condition_from_path(path: str) -> str:
    parts = Path(path).parts
    for marker in (
        "primary_31b_repair",
        "replication_26b_a4b_repair",
        "standard_coding_31b_repair",
        "auth_prompt_robustness_31b",
    ):
        if marker in parts:
            idx = parts.index(marker)
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return ""


def load_traces(runs_dir: Path) -> List[Dict[str, Any]]:
    traces = []
    if not runs_dir.exists():
        return traces
    for path in sorted(runs_dir.rglob("*.json")):
        traces.append(read_json(path))
    return traces


def redaction_findings_by_condition(report_path: Path) -> Counter:
    counts = Counter()
    if not report_path.exists():
        return counts
    report = read_json(report_path)
    for finding in report.get("findings", []):
        condition = trace_condition_from_path(finding.get("trace", ""))
        if condition:
            counts[condition] += 1
    return counts


def safety_outcome_table(runs_dir: Path, analysis_dir: Path, redaction_report: Path, out_path: Path) -> None:
    traces = load_traces(runs_dir)
    summary = read_json(analysis_dir / "summary.json")
    redaction_counts = redaction_findings_by_condition(redaction_report)
    grouped = defaultdict(list)
    for trace in traces:
        grouped[trace["condition"]].append(trace)

    lines = [
        "\\begin{tabular}{@{}lrrrrrr@{}}",
        "\\toprule",
        "Condition & Success & Ground. & Refusal & Suppressed & Unsafe & Redact. \\\\",
        "\\midrule",
    ]
    for condition in condition_order(grouped):
        rows = grouped[condition]
        n = len(rows)
        grounding = summary["grounding_by_condition"][condition]["mean_grounding_score"]
        refusal = sum(1 for row in rows if row.get("refusal_events")) / n
        suppressed = sum(1 for row in rows if row.get("suppressed_actions")) / n
        unsafe = sum(1 for row in rows if row.get("unsafe_actions")) / n
        redactions = redaction_counts.get(condition, 0)
        success = summary["success_by_condition"][condition]["success_rate"]
        lines.append(
            f"{label(condition)} & {pct(success)} & {grounding:.2f} & {pct(refusal)} & "
            f"{pct(suppressed)} & {pct(unsafe)} & {redactions} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def paired_task_diffs(run_rows: List[Dict[str, str]], value_by_run: Dict[str, float]) -> List[float]:
    by_task = defaultdict(list)
    by_pair = defaultdict(dict)
    for row in run_rows:
        if row["condition"] not in {"aligned", "uncensored"}:
            continue
        key = (row["task_id"], row["seed"])
        by_pair[key][row["condition"]] = row["run_id"]
    for (task_id, _seed), pair in by_pair.items():
        if "aligned" in pair and "uncensored" in pair:
            by_task[task_id].append(value_by_run[pair["uncensored"]] - value_by_run[pair["aligned"]])
    return [sum(values) / len(values) for _task, values in sorted(by_task.items()) if values]


def sign_permutation_p(task_diffs: List[float], iterations: int = 100000, seed: int = 2026) -> Tuple[float, float, int]:
    if not task_diffs:
        return math.nan, math.nan, 0
    observed = sum(task_diffs) / len(task_diffs)
    abs_observed = abs(observed)
    n = len(task_diffs)
    if n <= 20:
        signs = itertools.product([-1, 1], repeat=n)
        null = [sum(sign * diff for sign, diff in zip(choice, task_diffs)) / n for choice in signs]
    else:
        rng = random.Random(seed)
        null = [
            sum((1 if rng.randrange(2) else -1) * diff for diff in task_diffs) / n
            for _ in range(iterations)
        ]
    p = sum(abs(value) >= abs_observed for value in null) / len(null)
    return observed, p, n


def format_p(p: float) -> str:
    # Monte Carlo sign-permutation p-values of zero mean none of the 100,000 draws matched.
    return "$<10^{-5}$" if p == 0 else f"{p:.4f}"


def robustness_table(items: List[Tuple[str, Path]], out_path: Path) -> None:
    lines = [
        "\\begin{tabular}{@{}lrrrr@{}}",
        "\\toprule",
        "Suite & Tasks & Success diff. & Success p & Grounding p \\\\",
        "\\midrule",
    ]
    for name, analysis_dir in items:
        if not (analysis_dir / "run_level.csv").exists():
            continue
        run_rows = read_csv(analysis_dir / "run_level.csv")
        grounding_rows = read_csv(analysis_dir / "grounding_run_level.csv")
        success_values = {row["run_id"]: float(row["success"]) for row in run_rows}
        grounding_values = {row["run_id"]: float(row["grounding_score"]) for row in grounding_rows}
        success_obs, success_p, tasks = sign_permutation_p(paired_task_diffs(run_rows, success_values))
        _ground_obs, grounding_p, _ = sign_permutation_p(paired_task_diffs(run_rows, grounding_values))
        lines.append(f"{name} & {tasks} & {success_obs:.3f} & {format_p(success_p)} & {format_p(grounding_p)} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def aligned_failure_taxonomy(out_path: Path) -> None:
    run_rows = [row for row in read_csv(ROOT / "analysis/primary_31b_repair/run_level.csv") if row["condition"] == "aligned" and row["success"] == "0"]
    grounding = {row["run_id"]: row for row in read_csv(ROOT / "analysis/primary_31b_repair/grounding_run_level.csv")}
    counts = Counter()
    for row in run_rows:
        grow = grounding[row["run_id"]]
        label_name = row["primary_failure_label"]
        if row["task_class"] in {"proof_of_trigger", "patch_verification"} and label_name == "validation_failure":
            counts["No executable proof or patch verification"] += 1
        if grow["named_expected_symbol"] == "0":
            counts["Missing or wrong expected symbol"] += 1
        if grow["named_issue"] == "0":
            counts["Missing expected issue term"] += 1
        if int(grow["grounding_score"]) <= 2:
            counts["Low/generic grounding"] += 1
        if label_name == "tool_failure":
            counts["Malformed tool or interface use"] += 1
        if grow["read_expected_file"] == "1" and grow["named_expected_file"] == "1" and grow["named_expected_symbol"] == "0":
            counts["File-only evidence without symbol"] += 1
    total = len(run_rows)
    lines = [
        "\\begin{tabular}{@{}lrr@{}}",
        "\\toprule",
        "Failure pattern & Runs & Share \\\\",
        "\\midrule",
    ]
    for name, count in counts.most_common():
        lines.append(f"{name} & {count} & {pct(count / total)} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def cross_study_table(out_path: Path) -> None:
    rows = []
    for name, (_runs, analysis, _tasks) in DATASETS.items():
        path = ROOT / analysis / "summary.json"
        if not path.exists():
            continue
        summary = read_json(path)
        if "aligned" not in summary["success_by_condition"] or "uncensored" not in summary["success_by_condition"]:
            continue
        aligned_runs = summary["success_by_condition"]["aligned"]["runs"]
        rows.append(
            (
                name,
                aligned_runs,
                summary["success_by_condition"]["aligned"]["success_rate"],
                summary["success_by_condition"]["uncensored"]["success_rate"],
                summary["grounding_by_condition"]["aligned"]["mean_grounding_score"],
                summary["grounding_by_condition"]["uncensored"]["mean_grounding_score"],
            )
        )
    lines = [
        "\\begin{tabular}{@{}lrrrrr@{}}",
        "\\toprule",
        "Suite & Runs/cond. & Aligned succ. & Less succ. & Aligned ground. & Less ground. \\\\",
        "\\midrule",
    ]
    for name, runs, aligned_success, uncensored_success, aligned_ground, uncensored_ground in rows:
        lines.append(
            f"{name} & {runs} & {pct(aligned_success)} & {pct(uncensored_success)} & "
            f"{aligned_ground:.2f} & {uncensored_ground:.2f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _unsafe_rate(runs_dir: Path, condition: str) -> float:
    rows = [trace for trace in load_traces(runs_dir) if trace.get("condition") == condition]
    if not rows:
        return math.nan
    return sum(1 for row in rows if row.get("unsafe_actions")) / len(rows)


def model_family_security_table(out_path: Path) -> None:
    lines = [
        "\\begin{tabular}{@{}lrrrrrr@{}}",
        "\\toprule",
        "Model pair & Align succ. & Less succ. & $\\Delta$ succ. & Align ground. & Less ground. & Less unsafe \\\\",
        "\\midrule",
    ]
    for name, runs, analysis in SECURITY_FAMILIES:
        summary_path = ROOT / analysis / "summary.json"
        if not summary_path.exists():
            continue
        summary = read_json(summary_path)
        aligned = summary["success_by_condition"]["aligned"]["success_rate"]
        uncensored = summary["success_by_condition"]["uncensored"]["success_rate"]
        aligned_ground = summary["grounding_by_condition"]["aligned"]["mean_grounding_score"]
        uncensored_ground = summary["grounding_by_condition"]["uncensored"]["mean_grounding_score"]
        unsafe = _unsafe_rate(ROOT / runs, "uncensored")
        lines.append(
            f"{name} & {pct(aligned)} & {pct(uncensored)} & {100 * (uncensored - aligned):+.1f} & "
            f"{aligned_ground:.2f} & {uncensored_ground:.2f} & {pct(unsafe)} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def model_family_figure(out_path: Path) -> None:
    rows = []
    label_map = {
        "Gemma 31B": "Gemma 31B",
        "Gemma 26B A4B": "Gemma 26B A4B",
        "Qwen2.5-Coder 7B": "Qwen2.5-Coder 7B",
        "Llama 3.1 8B": "Llama 3.1 8B",
    }
    for name, _runs, analysis in SECURITY_FAMILIES:
        summary_path = ROOT / analysis / "summary.json"
        if not summary_path.exists():
            continue
        summary = read_json(summary_path)
        rows.append(
            {
                "name": name,
                "aligned_success": 100 * summary["success_by_condition"]["aligned"]["success_rate"],
                "uncensored_success": 100 * summary["success_by_condition"]["uncensored"]["success_rate"],
                "aligned_success_low": 100 * summary["success_by_condition"]["aligned"]["bootstrap_95_low"],
                "aligned_success_high": 100 * summary["success_by_condition"]["aligned"]["bootstrap_95_high"],
                "uncensored_success_low": 100 * summary["success_by_condition"]["uncensored"]["bootstrap_95_low"],
                "uncensored_success_high": 100 * summary["success_by_condition"]["uncensored"]["bootstrap_95_high"],
                "aligned_ground": summary["grounding_by_condition"]["aligned"]["mean_grounding_score"],
                "uncensored_ground": summary["grounding_by_condition"]["uncensored"]["mean_grounding_score"],
            }
        )
    row_ys = [4.38, 3.38, 2.38, 1.38]
    label_x = 2.55
    success_x = 3.10
    ground_x = 9.15
    success_width = 4.45
    ground_width = 4.45
    success_max = 20.0
    ground_max = 5.0
    axis_y = 0.92
    grid_top = 4.78
    condition_offset = 0.13

    def scale_x(base_x: float, width: float, max_value: float, value: float) -> float:
        value = max(0.0, min(value, max_value))
        return base_x + (value / max_value) * width

    def add_point(lines: List[str], x: float, y: float, color: str) -> None:
        lines.append(
            f"\\filldraw[fill={color},draw=white,line width=0.25pt] "
            f"({x:.3f},{y:.3f}) circle (0.075);"
        )

    def add_ci(lines: List[str], x_low: float, x_high: float, y: float) -> None:
        lines.append(f"\\draw[famInk,line width=0.35pt] ({x_low:.3f},{y:.3f}) -- ({x_high:.3f},{y:.3f});")
        lines.append(f"\\draw[famInk,line width=0.35pt] ({x_low:.3f},{y - 0.070:.3f}) -- ({x_low:.3f},{y + 0.070:.3f});")
        lines.append(f"\\draw[famInk,line width=0.35pt] ({x_high:.3f},{y - 0.070:.3f}) -- ({x_high:.3f},{y + 0.070:.3f});")

    lines = [
        "\\begin{figure}[t]",
        "\\centering",
        "\\definecolor{famAlign}{RGB}{0,114,178}",
        "\\definecolor{famLess}{RGB}{213,94,0}",
        "\\definecolor{famGrid}{RGB}{226,232,240}",
        "\\definecolor{famAxis}{RGB}{148,163,184}",
        "\\definecolor{famInk}{RGB}{31,41,55}",
        "\\definecolor{famMuted}{RGB}{75,85,99}",
        "\\resizebox{\\linewidth}{!}{%",
        "\\begin{tikzpicture}[x=1cm,y=1cm,font=\\sffamily\\scriptsize]",
        "\\path[use as bounding box] (0,0) rectangle (14.2,5.75);",
        "\\node[anchor=west,font=\\sffamily\\bfseries,text=famInk] at (0.05,5.08) {Model pair};",
        "\\node[anchor=west,font=\\sffamily\\bfseries,text=famInk] at (3.10,5.08) {Task success (\\% runs)};",
        "\\node[anchor=west,font=\\sffamily\\bfseries,text=famInk] at (9.15,5.08) {Evidence grounding (score / 5)};",
        "\\filldraw[fill=famAlign,draw=white,line width=0.25pt] (10.70,5.48) circle (0.075);",
        "\\node[anchor=west,text=famMuted] at (10.87,5.48) {Aligned};",
        "\\filldraw[fill=famLess,draw=white,line width=0.25pt] (12.20,5.48) circle (0.075);",
        "\\node[anchor=west,text=famMuted] at (12.37,5.48) {Less-restricted};",
    ]
    for base_x, width, max_value, tick_label in [
        (success_x, success_width, success_max, "\\%"),
        (ground_x, ground_width, ground_max, ""),
    ]:
        lines.append(f"\\draw[famAxis,line width=0.35pt] ({base_x:.2f},{axis_y:.2f}) -- ({base_x + width:.2f},{axis_y:.2f});")
        for tick in range(0, int(max_value) + 1, 5 if max_value == 20.0 else 1):
            x = scale_x(base_x, width, max_value, tick)
            lines.append(f"\\draw[famGrid,line width=0.25pt] ({x:.3f},{axis_y:.2f}) -- ({x:.3f},{grid_top:.2f});")
            lines.append(f"\\node[anchor=north,text=famMuted] at ({x:.3f},{axis_y - 0.11:.2f}) {{{tick}{tick_label}}};")
    for row, y in zip(rows, row_ys):
        label = label_map.get(row["name"], row["name"])
        lines.append(f"\\node[anchor=east,text=famInk,align=right] at ({label_x:.2f},{y:.3f}) {{{label}}};")
        lines.append(f"\\draw[famGrid,line width=0.25pt] (0.05,{y - 0.47:.3f}) -- ({ground_x + ground_width:.2f},{y - 0.47:.3f});")

        for dy, prefix, color in [
            (condition_offset, "aligned", "famAlign"),
            (-condition_offset, "uncensored", "famLess"),
        ]:
            y_point = y + dy
            success_value = row[f"{prefix}_success"]
            x_point = scale_x(success_x, success_width, success_max, success_value)
            x_low = scale_x(success_x, success_width, success_max, row[f"{prefix}_success_low"])
            x_high = scale_x(success_x, success_width, success_max, row[f"{prefix}_success_high"])
            add_ci(lines, x_low, x_high, y_point)
            add_point(lines, x_point, y_point, color)

            ground_value = row[f"{prefix}_ground"]
            ground_point = scale_x(ground_x, ground_width, ground_max, ground_value)
            add_point(lines, ground_point, y_point, color)
    lines.extend(
        [
            "\\end{tikzpicture}%",
            "}",
            "\\caption{Cross-pair security results. Success points include bootstrap 95\\% confidence intervals; grounding points show the mean deterministic evidence-grounding score out of five.}",
            "\\label{fig:model-family-results}",
            "\\end{figure}",
            "",
        ]
    )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def expected_outputs_manifest(out_path: Path) -> None:
    manifest: Dict[str, Any] = {}
    for name, (runs, analysis, _tasks) in DATASETS.items():
        summary_path = ROOT / analysis / "summary.json"
        if not summary_path.exists():
            continue
        summary = read_json(summary_path)
        manifest[name] = {
            "trace_count": summary["trace_count"],
            "success_by_condition": summary["success_by_condition"],
            "mean_grounding_by_condition": {
                condition: row["mean_grounding_score"]
                for condition, row in summary["grounding_by_condition"].items()
            },
            "runs_dir": runs,
            "analysis_dir": analysis,
        }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    TABLES.mkdir(exist_ok=True)
    safety_outcome_table(
        ROOT / "artifacts/redacted_traces/primary_31b_repair",
        ROOT / "analysis/primary_31b_repair",
        ROOT / "artifacts/redaction_audits/primary_31b_repair.json",
        TABLES / "safety_outcomes_primary.tex",
    )
    safety_outcome_table(
        ROOT / "artifacts/redacted_traces/replication_26b_a4b_repair",
        ROOT / "analysis/replication_26b_a4b_repair",
        ROOT / "artifacts/redaction_audits/replication_26b_a4b_repair.json",
        TABLES / "safety_outcomes_26b.tex",
    )
    robustness_table(
        [
            ("31B security", ROOT / "analysis/primary_31b_repair"),
            ("26B security", ROOT / "analysis/replication_26b_a4b_repair"),
            ("31B standard", ROOT / "analysis/standard_coding_31b_repair"),
        ],
        TABLES / "robustness_stats.tex",
    )
    aligned_failure_taxonomy(TABLES / "aligned_failure_taxonomy.tex")
    cross_study_table(TABLES / "cross_study_summary.tex")
    model_family_security_table(TABLES / "model_family_security.tex")
    model_family_figure(ROOT / "figures/model_family_results.tex")
    expected_outputs_manifest(ARTIFACTS / "expected_outputs.json")
    print(json.dumps({"generated": [
        "tables/safety_outcomes_primary.tex",
        "tables/safety_outcomes_26b.tex",
        "tables/robustness_stats.tex",
        "tables/aligned_failure_taxonomy.tex",
        "tables/cross_study_summary.tex",
        "tables/model_family_security.tex",
        "figures/model_family_results.tex",
        "artifacts/expected_outputs.json",
    ]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
