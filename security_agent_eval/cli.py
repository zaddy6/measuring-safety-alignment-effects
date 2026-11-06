"""Command-line interface for the evaluation package."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path

from .analysis import analyze
from .config import load_model_conditions, load_task_catalog, select_tasks, write_json
from .diagnostic import load_jsonl, run_diagnostic
from .harness import ExperimentRunner
from .redaction import public_trace
from .schema import validate_task_catalog


def cmd_validate_tasks(args) -> int:
    catalog = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    validate_task_catalog(catalog)
    counts = {}
    for task in catalog["tasks"]:
        counts[task["task_class"]] = counts.get(task["task_class"], 0) + 1
    print(f"validated {len(catalog['tasks'])} tasks")
    for key in sorted(counts):
        print(f"{key}: {counts[key]}")
    return 0


def cmd_list_tasks(args) -> int:
    for task in load_task_catalog(Path(args.tasks)):
        print(f"{task['task_id']}\t{task['task_class']}")
    return 0


def cmd_run(args) -> int:
    tasks = select_tasks(load_task_catalog(Path(args.tasks)), args.task_id, args.limit_tasks)
    models = load_model_conditions(Path(args.models))
    conditions = args.conditions or list(models.keys())
    missing = sorted(set(conditions) - set(models))
    if missing:
        raise SystemExit(f"missing model conditions in config: {missing}")
    runner = ExperimentRunner(Path(args.out), force_mock=args.mock, controller_mode=args.controller_mode)
    total = 0
    for task in tasks:
        for condition_name in conditions:
            for seed in args.seeds:
                output_path = Path(args.out) / condition_name / task["task_id"] / f"seed_{seed}.json"
                if args.skip_existing and output_path.exists():
                    total += 1
                    print(f"{task['task_id']}:{condition_name}:{seed}: skipped existing")
                    continue
                trace = runner.run(task, models[condition_name], seed)
                total += 1
                print(f"{trace['run_id']}: success={trace['success']} label={trace['primary_failure_label']}")
    print(f"wrote {total} traces to {args.out}")
    return 0


def cmd_analyze(args) -> int:
    summary = analyze(Path(args.runs), Path(args.out), Path(args.tasks) if args.tasks else None)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def cmd_redact(args) -> int:
    source = Path(args.runs)
    out = Path(args.out)
    count = 0
    for item in sorted(source.rglob("*.json")):
        trace = json.loads(item.read_text(encoding="utf-8"))
        rel = item.relative_to(source)
        write_json(out / rel, public_trace(trace))
        count += 1
    print(f"wrote {count} public traces to {out}")
    return 0


def cmd_diagnostic(args) -> int:
    prompts = load_jsonl(Path(args.prompts))
    models = load_model_conditions(Path(args.models))
    conditions = args.conditions or list(models.keys())
    summaries = []
    for condition_name in conditions:
        if condition_name not in models:
            raise SystemExit(f"missing model condition in config: {condition_name}")
        summary = run_diagnostic(prompts, models[condition_name], Path(args.out), force_mock=args.mock)
        summaries.append(summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
    write_json(Path(args.out) / "summary.json", {"conditions": summaries})
    return 0


def cmd_validate_models(args) -> int:
    models = load_model_conditions(Path(args.models))
    conditions = args.conditions or list(models.keys())
    ok = True
    for name in conditions:
        condition = models[name]
        url = condition.base_url.rstrip("/") + "/models"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
            served = [item.get("id") for item in body.get("data", [])]
            print(f"{name}: reachable {url} served={served}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            ok = False
            print(f"{name}: not reachable at {url}: {exc}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-agent-eval")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-tasks")
    validate.add_argument("--tasks", default="tasks/catalog.json")
    validate.set_defaults(func=cmd_validate_tasks)

    listing = sub.add_parser("list-tasks")
    listing.add_argument("--tasks", default="tasks/catalog.json")
    listing.set_defaults(func=cmd_list_tasks)

    run = sub.add_parser("run")
    run.add_argument("--tasks", default="tasks/catalog.json")
    run.add_argument("--models", default="configs/models.example.json")
    run.add_argument("--out", default="runs/pilot")
    run.add_argument("--conditions", nargs="+")
    run.add_argument("--seeds", nargs="+", type=int, default=[0])
    run.add_argument("--task-id", nargs="+")
    run.add_argument("--limit-tasks", type=int)
    run.add_argument("--mock", action="store_true", help="Use deterministic mock model instead of local model servers")
    run.add_argument("--skip-existing", action="store_true", help="Do not rerun traces already present at the output path")
    run.add_argument("--controller-mode", choices=["strict", "repair"], default="strict")
    run.set_defaults(func=cmd_run)

    analysis = sub.add_parser("analyze")
    analysis.add_argument("--runs", default="runs/pilot")
    analysis.add_argument("--out", default="analysis/pilot")
    analysis.add_argument("--tasks", help="Optional task catalog for grounding-target lookup")
    analysis.set_defaults(func=cmd_analyze)

    redact = sub.add_parser("redact")
    redact.add_argument("--runs", default="runs/pilot")
    redact.add_argument("--out", default="artifacts/redacted_traces")
    redact.set_defaults(func=cmd_redact)

    diagnostic = sub.add_parser("diagnostic")
    diagnostic.add_argument("--prompts", default="prompts/diagnostic_set.jsonl")
    diagnostic.add_argument("--models", default="configs/models.example.json")
    diagnostic.add_argument("--conditions", nargs="+")
    diagnostic.add_argument("--out", default="analysis/prompt_diagnostic")
    diagnostic.add_argument("--mock", action="store_true")
    diagnostic.set_defaults(func=cmd_diagnostic)

    validate_models = sub.add_parser("validate-models")
    validate_models.add_argument("--models", default="configs/models.example.json")
    validate_models.add_argument("--conditions", nargs="+")
    validate_models.set_defaults(func=cmd_validate_models)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
