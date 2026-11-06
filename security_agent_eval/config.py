"""Configuration and task loading helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .schema import validate_task_catalog


@dataclass(frozen=True)
class ModelCondition:
    condition: str
    model_id: str
    model_revision: str
    backend: str
    quantization: str
    base_url: str
    sampling_config: Dict[str, Any]
    prompt_template_hash: Optional[str] = None


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_task_catalog(path: Path) -> List[Dict[str, Any]]:
    catalog = read_json(path)
    validate_task_catalog(catalog)
    return catalog["tasks"]


def select_tasks(tasks: Iterable[Dict[str, Any]], task_ids: Optional[List[str]], limit: Optional[int]) -> List[Dict[str, Any]]:
    selected = list(tasks)
    if task_ids:
        wanted = set(task_ids)
        selected = [task for task in selected if task["task_id"] in wanted]
        missing = sorted(wanted - {task["task_id"] for task in selected})
        if missing:
            raise ValueError(f"unknown task ids: {missing}")
    if limit is not None:
        selected = selected[:limit]
    return selected


def load_model_conditions(path: Path) -> Dict[str, ModelCondition]:
    raw = read_json(path)
    defaults = raw.get("defaults", {})
    conditions: Dict[str, ModelCondition] = {}
    for condition, item in raw.get("conditions", {}).items():
        sampling = dict(defaults.get("sampling_config", {}))
        sampling.update(item.get("sampling_config", {}))
        conditions[condition] = ModelCondition(
            condition=condition,
            model_id=item["model_id"],
            model_revision=item.get("model_revision", "unknown"),
            backend=item.get("backend", defaults.get("backend", "openai-compatible")),
            quantization=item.get("quantization", defaults.get("quantization", "unknown")),
            base_url=item.get("base_url", defaults.get("base_url", "http://127.0.0.1:8080/v1")),
            sampling_config=sampling,
            prompt_template_hash=item.get("prompt_template_hash"),
        )
    return conditions
