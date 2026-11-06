#!/usr/bin/env sh
set -eu

python3 -m security_agent_eval.cli validate-tasks --tasks tasks/catalog.json
python3 -m security_agent_eval.cli validate-tasks --tasks tasks/sanity_catalog.json
python3 -m security_agent_eval.cli validate-tasks --tasks tasks/standard_coding_catalog.json

python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/primary_31b_repair --tasks tasks/catalog.json --out analysis/primary_31b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/sanity_31b_repair --tasks tasks/sanity_catalog.json --out analysis/sanity_31b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/replication_26b_a4b_repair --tasks tasks/catalog.json --out analysis/replication_26b_a4b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/sanity_26b_a4b_repair --tasks tasks/sanity_catalog.json --out analysis/sanity_26b_a4b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/qwen25_coder_7b_repair --tasks tasks/catalog.json --out analysis/qwen25_coder_7b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/sanity_qwen25_coder_7b_repair --tasks tasks/sanity_catalog.json --out analysis/sanity_qwen25_coder_7b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/llama31_8b_repair --tasks tasks/catalog.json --out analysis/llama31_8b_repair
python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/sanity_llama31_8b_repair --tasks tasks/sanity_catalog.json --out analysis/sanity_llama31_8b_repair

if [ -d artifacts/redacted_traces/standard_coding_31b_repair ]; then
  python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/standard_coding_31b_repair --tasks tasks/standard_coding_catalog.json --out analysis/standard_coding_31b_repair
fi
if [ -d artifacts/redacted_traces/standard_coding_26b_a4b_repair ]; then
  python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/standard_coding_26b_a4b_repair --tasks tasks/standard_coding_catalog.json --out analysis/standard_coding_26b_a4b_repair
fi
if [ -d artifacts/redacted_traces/standard_coding_qwen25_coder_7b_repair ]; then
  python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/standard_coding_qwen25_coder_7b_repair --tasks tasks/standard_coding_catalog.json --out analysis/standard_coding_qwen25_coder_7b_repair
fi
if [ -d artifacts/redacted_traces/standard_coding_llama31_8b_repair ]; then
  python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/standard_coding_llama31_8b_repair --tasks tasks/standard_coding_catalog.json --out analysis/standard_coding_llama31_8b_repair
fi
if [ -d artifacts/redacted_traces/auth_prompt_robustness_31b ]; then
  python3 -m security_agent_eval.cli analyze --runs artifacts/redacted_traces/auth_prompt_robustness_31b --tasks tasks/catalog.json --out analysis/auth_prompt_robustness_31b
fi

python3 scripts/reviewer_audit.py summarize \
  --manifest artifacts/reviewer_audit_v2/sample_manifest.csv \
  --reviewer-a artifacts/reviewer_audit_v2/reviewer_a_labels.csv \
  --reviewer-b artifacts/reviewer_audit_v2/reviewer_b_labels.csv \
  --out artifacts/reviewer_audit_v2

python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/primary_31b_repair --tasks tasks/catalog.json --out artifacts/redaction_audits/primary_31b_repair.json
python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/replication_26b_a4b_repair --tasks tasks/catalog.json --out artifacts/redaction_audits/replication_26b_a4b_repair.json
python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/qwen25_coder_7b_repair --tasks tasks/catalog.json --out artifacts/redaction_audits/qwen25_coder_7b_repair.json
python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/llama31_8b_repair --tasks tasks/catalog.json --out artifacts/redaction_audits/llama31_8b_repair.json
if [ -d artifacts/redacted_traces/sanity_31b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/sanity_31b_repair --tasks tasks/sanity_catalog.json --out artifacts/redaction_audits/sanity_31b_repair.json
fi
if [ -d artifacts/redacted_traces/sanity_26b_a4b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/sanity_26b_a4b_repair --tasks tasks/sanity_catalog.json --out artifacts/redaction_audits/sanity_26b_a4b_repair.json
fi
if [ -d artifacts/redacted_traces/sanity_qwen25_coder_7b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/sanity_qwen25_coder_7b_repair --tasks tasks/sanity_catalog.json --out artifacts/redaction_audits/sanity_qwen25_coder_7b_repair.json
fi
if [ -d artifacts/redacted_traces/sanity_llama31_8b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/sanity_llama31_8b_repair --tasks tasks/sanity_catalog.json --out artifacts/redaction_audits/sanity_llama31_8b_repair.json
fi
if [ -d artifacts/redacted_traces/strict_ablation_31b ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/strict_ablation_31b --tasks tasks/catalog.json --out artifacts/redaction_audits/strict_ablation_31b.json
fi
if [ -d artifacts/redacted_traces/standard_coding_31b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/standard_coding_31b_repair --tasks tasks/standard_coding_catalog.json --out artifacts/redaction_audits/standard_coding_31b_repair.json
fi
if [ -d artifacts/redacted_traces/standard_coding_26b_a4b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/standard_coding_26b_a4b_repair --tasks tasks/standard_coding_catalog.json --out artifacts/redaction_audits/standard_coding_26b_a4b_repair.json
fi
if [ -d artifacts/redacted_traces/standard_coding_qwen25_coder_7b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/standard_coding_qwen25_coder_7b_repair --tasks tasks/standard_coding_catalog.json --out artifacts/redaction_audits/standard_coding_qwen25_coder_7b_repair.json
fi
if [ -d artifacts/redacted_traces/standard_coding_llama31_8b_repair ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/standard_coding_llama31_8b_repair --tasks tasks/standard_coding_catalog.json --out artifacts/redaction_audits/standard_coding_llama31_8b_repair.json
fi
if [ -d artifacts/redacted_traces/auth_prompt_robustness_31b ]; then
  python3 scripts/audit_redactions.py --traces artifacts/redacted_traces/auth_prompt_robustness_31b --tasks tasks/catalog.json --out artifacts/redaction_audits/auth_prompt_robustness_31b.json
fi

python3 scripts/paper_summaries.py
python3 scripts/camera_ready_tables.py
python3 -m unittest discover -s tests
latexmk -pdf -interaction=nonstopmode main.tex
