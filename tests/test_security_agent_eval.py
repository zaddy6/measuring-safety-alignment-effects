import json
import tempfile
import unittest
from pathlib import Path

from security_agent_eval.analysis import analyze
from security_agent_eval.config import ModelCondition, load_task_catalog
from security_agent_eval.harness import ExperimentRunner, repair_filename_keyed_artifact, repair_malformed_write_file
from security_agent_eval.prompts import build_messages
from security_agent_eval.schema import validate_task_catalog, validate_trace
from security_agent_eval.tools import Sandbox, ToolPolicyError


ROOT = Path(__file__).resolve().parents[1]


class SecurityAgentEvalTests(unittest.TestCase):
    def test_catalog_has_expected_task_counts(self):
        catalog = json.loads((ROOT / "tasks/catalog.json").read_text(encoding="utf-8"))
        validate_task_catalog(catalog)
        counts = {}
        for task in catalog["tasks"]:
            counts[task["task_class"]] = counts.get(task["task_class"], 0) + 1
        self.assertEqual(sum(counts.values()), 30)
        self.assertEqual(set(counts.values()), {6})

    def test_sanity_catalog_validates(self):
        catalog = json.loads((ROOT / "tasks/sanity_catalog.json").read_text(encoding="utf-8"))
        validate_task_catalog(catalog)
        self.assertEqual(len(catalog["tasks"]), 12)
        self.assertEqual({task["task_class"] for task in catalog["tasks"]}, {"non_security_code_reasoning"})

    def test_standard_coding_catalog_validates(self):
        catalog = json.loads((ROOT / "tasks/standard_coding_catalog.json").read_text(encoding="utf-8"))
        validate_task_catalog(catalog)
        self.assertEqual(len(catalog["tasks"]), 8)
        self.assertEqual({task["task_class"] for task in catalog["tasks"]}, {"non_security_code_reasoning"})

    def test_authorization_prompt_variants_are_distinct(self):
        task = load_task_catalog(ROOT / "tasks/catalog.json")[0]
        prompts = {
            condition: build_messages(task, condition)[1]["content"]
            for condition in ["authorized", "auth-scope", "auth-evidence", "auth-policy"]
        }
        self.assertEqual(len(set(prompts.values())), 4)
        self.assertIn("local", prompts["auth-scope"].lower())
        self.assertIn("ground", prompts["auth-evidence"].lower())
        self.assertIn("redact", prompts["auth-policy"].lower())

    def test_sandbox_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Sandbox(Path(tmp), ["read_file"])
            with self.assertRaises(ToolPolicyError):
                sandbox.read_file("../outside.txt")

    def test_mock_run_writes_valid_trace(self):
        task = load_task_catalog(ROOT / "tasks/catalog.json")[0]
        condition = ModelCondition(
            condition="aligned",
            model_id="mock-model",
            model_revision="test",
            backend="mock",
            quantization="none",
            base_url="mock://local",
            sampling_config={"temperature": 0.0},
        )
        with tempfile.TemporaryDirectory() as tmp:
            trace = ExperimentRunner(Path(tmp), force_mock=True).run(task, condition, seed=0)
            validate_trace(trace)
            self.assertTrue(trace["success"])
            self.assertEqual(trace["primary_failure_label"], None)
            self.assertEqual(trace["controller_mode"], "strict")
            self.assertTrue((Path(tmp) / "aligned" / task["task_id"] / "seed_0.json").exists())

    def test_analysis_outputs_summary(self):
        tasks = load_task_catalog(ROOT / "tasks/catalog.json")[:1]
        conditions = [
            ModelCondition("aligned", "mock", "test", "mock", "none", "mock://local", {}),
            ModelCondition("uncensored", "mock", "test", "mock", "none", "mock://local", {}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "runs"
            out = Path(tmp) / "analysis"
            runner = ExperimentRunner(runs, force_mock=True)
            for condition in conditions:
                runner.run(tasks[0], condition, seed=0)
            summary = analyze(runs, out)
            self.assertEqual(summary["trace_count"], 2)
            self.assertTrue((out / "summary.json").exists())
            self.assertTrue((out / "grounding_run_level.csv").exists())
            self.assertEqual(summary["mcnemar_aligned_vs_uncensored"]["paired_runs"], 1)

    def test_repair_malformed_write_file(self):
        content = '{"tool":"write_file","arguments":{"path":"final_report.md","content":"# Title\\nRaw line'
        action = repair_malformed_write_file(content)
        self.assertEqual(action["tool"], "write_file")
        self.assertEqual(action["arguments"]["path"], "final_report.md")
        self.assertIn("Raw line", action["arguments"]["content"])

    def test_repair_filename_keyed_artifact(self):
        action = repair_filename_keyed_artifact({"final_report.md": "report body"}, ["final_report.md"])
        self.assertEqual(action["tool"], "write_file")
        self.assertEqual(action["arguments"]["path"], "final_report.md")
        self.assertEqual(action["arguments"]["controller_repair"], "filename_keyed_artifact")


if __name__ == "__main__":
    unittest.main()
