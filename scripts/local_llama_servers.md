# Local llama.cpp Servers

The main evaluation expects OpenAI-compatible local endpoints. Start one server
per loaded 31B model so each condition uses the same API shape.

Example aligned server:

```sh
llama-server \
  --model /models/gemma-4-31b-it.Q4_K_M.gguf \
  --host 127.0.0.1 \
  --port 8081 \
  --ctx-size 8192 \
  --jinja \
  --reasoning off
```

Example uncensored server:

```sh
llama-server \
  --model /models/gemma-4-31b-it-uncensored.Q4_K_M.gguf \
  --host 127.0.0.1 \
  --port 8082 \
  --ctx-size 8192 \
  --jinja \
  --reasoning off
```

Then run:

```sh
python3 -m security_agent_eval.cli run \
  --tasks tasks/catalog.json \
  --models configs/models.example.json \
  --out runs/pilot \
  --conditions aligned authorized jailbreak uncensored \
  --seeds 0 1 \
  --limit-tasks 3
```

Or use the helper:

```sh
export GEMMA_ALIGNED_GGUF=/models/gemma-4-31b-it.Q4_K_M.gguf
export GEMMA_UNCENSORED_GGUF=/models/gemma-4-31b-it-uncensored.Q4_K_M.gguf
scripts/start_llama_servers.sh
```

In a second terminal, verify endpoints:

```sh
python3 -m security_agent_eval.cli validate-models --models configs/models.example.json
```

Before reporting results, replace every `pin-after-download` revision in
`configs/models.example.json` with the exact downloaded revision or file hash.

## 26B A4B Replication Servers

The 26B A4B replication uses separate ports so it can coexist with the 31B
configuration:

```sh
export GEMMA_26B_A4B_ALIGNED_GGUF="$PWD/.local_tools/models/gemma-4-26B-A4B-it-GGUF/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf"
export GEMMA_26B_A4B_UNCENSORED_GGUF="$PWD/.local_tools/models/gemma-4-26B-A4B-it-uncensored-GGUF/gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf"
scripts/start_llama_servers_26b_a4b.sh
```

In a second terminal:

```sh
python3 -m security_agent_eval.cli validate-models \
  --models configs/models.26b_a4b.json \
  --conditions aligned uncensored
python3 -m security_agent_eval.cli run \
  --tasks tasks/catalog.json \
  --models configs/models.26b_a4b.json \
  --out runs/replication_26b_a4b_repair \
  --conditions aligned uncensored \
  --seeds 0 1 2 3 4 \
  --controller-mode repair
python3 -m security_agent_eval.cli run \
  --tasks tasks/sanity_catalog.json \
  --models configs/models.26b_a4b.json \
  --out runs/sanity_26b_a4b_repair \
  --conditions aligned uncensored \
  --seeds 0 1 2 3 4 \
  --controller-mode repair
```
