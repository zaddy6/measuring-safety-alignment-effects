"""Generate the controller-repair and model-provenance appendix tables.

Counts are read directly from the public redacted traces in
``artifacts/redacted_traces/`` and model configs in ``configs/``.
"""
import collections
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STUDIES = [
    ("Gemma 31B", "primary_31b_repair", "models.example.json"),
    ("Gemma 26B A4B", "replication_26b_a4b_repair", "models.26b_a4b.json"),
    ("Qwen2.5-Coder 7B", "qwen25_coder_7b_repair", "models.qwen25_coder_7b.json"),
    ("Llama 3.1 8B", "llama31_8b_repair", "models.llama31_8b.json"),
]
CONDITION_ORDER = ["aligned", "authorized", "jailbreak", "uncensored"]
CONDITION_NAMES = {"aligned": "Aligned", "authorized": "Authorized", "jailbreak": "Placeholder", "uncensored": "Uncensored"}
RULES = ["repeat_list_files", "malformed_write_file_json", "filename_keyed_artifact"]


def cell(runs: int, events: int) -> str:
    return str(runs) if runs == events else f"{runs} ({events})"


def repair_table() -> str:
    lines = [
        r"\begin{tabular}{@{}llrrrr@{}}",
        r"\toprule",
        r"Model pair & Condition & Repeat list & Malformed write & Filename-keyed & Succ.\ using 2--4 \\",
        r"\midrule",
    ]
    for i, (pair, study, _) in enumerate(STUDIES):
        stats = collections.defaultdict(lambda: {"runs": 0, "succ": 0, "succ_rep": 0, "any": 0,
                                                 **{f"r_{r}": 0 for r in RULES}, **{f"e_{r}": 0 for r in RULES}})
        for path in glob.glob(str(ROOT / "artifacts" / "redacted_traces" / study / "*" / "*" / "seed_*.json")):
            trace = json.load(open(path))
            if trace.get("controller_mode") != "repair":
                sys.exit(f"unexpected controller mode in {path}")
            s = stats[trace["condition"]]
            s["runs"] += 1
            fired = set()
            for call in trace.get("tool_calls", []):
                args = call.get("arguments_redacted", {})
                if isinstance(args, dict) and "controller_repair" in args:
                    rule = args["controller_repair"]
                    if rule not in RULES:
                        sys.exit(f"unknown repair {rule} in {path}")
                    s[f"e_{rule}"] += 1
                    fired.add(rule)
            for rule in fired:
                s[f"r_{rule}"] += 1
            s["any"] += bool(fired)
            if trace.get("success") is True:
                s["succ"] += 1
                s["succ_rep"] += bool(fired)
        if i:
            lines.append(r"\midrule")
        for cond in CONDITION_ORDER:
            if cond not in stats:
                continue
            s = stats[cond]
            if s["runs"] != 150:
                sys.exit(f"expected 150 runs for {pair} {cond}, found {s['runs']}")
            row = [pair if cond == "aligned" else "", CONDITION_NAMES[cond]]
            row += [cell(s[f"r_{r}"], s[f"e_{r}"]) for r in RULES]
            row.append(f"{s['succ_rep']}/{s['succ']}")
            lines.append(" & ".join(row) + r" \\")
            print(f"{pair:18s} {cond:11s} runs={s['runs']} any_rule_2to4={s['any']} succ={s['succ']} succ_using={s['succ_rep']}", file=sys.stderr)
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def tex_escape(text: str) -> str:
    return text.replace("_", r"\_")


def provenance_table() -> str:
    lines = [
        r"\begin{tabular}{@{}lll@{}}",
        r"\toprule",
        r"Model pair & GGUF release (aligned / less-restricted) & SHA-256 prefix \\",
        r"\midrule",
    ]
    for pair, _, config in STUDIES:
        conditions = json.load(open(ROOT / "configs" / config))["conditions"]
        for cond in ("aligned", "uncensored"):
            c = conditions[cond]
            repo = c["gguf_repo_url"].removeprefix("https://huggingface.co/") if c.get("gguf_repo_url") else c["model_id"]
            gguf = Path(c["local_gguf"]).name
            sha = c["model_revision"].removeprefix("gguf-sha256:")
            if len(sha) != 64:
                sys.exit(f"unexpected hash for {pair} {cond}: {sha}")
            label = pair if cond == "aligned" else ""
            lines.append(f"{label} & \\texttt{{{tex_escape(repo)}}} & \\texttt{{{sha[:16]}}} \\\\")
            lines.append(f" & \\quad\\texttt{{{tex_escape(gguf)}}} & \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    (ROOT / "tables" / "controller_repairs.tex").write_text(repair_table(), encoding="utf-8")
    (ROOT / "tables" / "model_provenance.tex").write_text(provenance_table(), encoding="utf-8")
