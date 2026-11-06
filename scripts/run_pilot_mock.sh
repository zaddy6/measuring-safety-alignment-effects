#!/usr/bin/env sh
set -eu

python3 -m security_agent_eval.cli validate-tasks --tasks tasks/catalog.json
python3 -m security_agent_eval.cli run \
  --tasks tasks/catalog.json \
  --models configs/models.example.json \
  --out runs/pilot_mock \
  --conditions aligned authorized jailbreak uncensored \
  --seeds 0 1 \
  --limit-tasks 3 \
  --mock
python3 -m security_agent_eval.cli analyze --runs runs/pilot_mock --out analysis/pilot_mock
python3 -m security_agent_eval.cli redact --runs runs/pilot_mock --out artifacts/redacted_traces/pilot_mock
