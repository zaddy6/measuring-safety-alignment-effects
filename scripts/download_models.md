# Downloading Local GGUF Weights

This project does not include model weights. The commands below fetch the exact
GGUF files used in the paper into the local paths that `configs/models.*.json`
expect. Two files are no longer at the head of their repositories, so those
commands pin the revision that contains them.

1. Configure Hugging Face access and accept any required model license terms on
   Hugging Face:

```sh
python3 -m pip install --user huggingface_hub
hf auth login
```

2. Download the eight files:

```sh
# Gemma 4 31B
hf download ggml-org/gemma-4-31B-it-GGUF \
  --revision fb5801c702a472691c6eba168f28af79a076fbe9 \
  --include gemma-4-31B-it-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-31B-it-GGUF
hf download TrevorJS/gemma-4-31B-it-uncensored-GGUF \
  --include gemma-4-31B-it-uncensored-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-31B-it-uncensored-GGUF
# Gemma 4 26B A4B
hf download unsloth/gemma-4-26B-A4B-it-GGUF \
  --revision 3365c68df1a83799b846d05324ebfadbb8cc70b3 \
  --include gemma-4-26B-A4B-it-UD-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-26B-A4B-it-GGUF
hf download TrevorJS/gemma-4-26B-A4B-it-uncensored-GGUF \
  --include gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-26B-A4B-it-uncensored-GGUF
# Qwen2.5-Coder 7B
hf download Qwen/Qwen2.5-Coder-7B-Instruct-GGUF \
  --include qwen2.5-coder-7b-instruct-q4_k_m.gguf \
  --local-dir .local_tools/models/Qwen2.5-Coder-7B-Instruct-GGUF
hf download bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF \
  --include Qwen2.5-Coder-7B-Instruct-abliterated-Q4_K_M.gguf \
  --local-dir .local_tools/models/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF
# Llama 3.1 8B
hf download bartowski/Meta-Llama-3.1-8B-Instruct-GGUF \
  --include Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf \
  --local-dir .local_tools/models/Meta-Llama-3.1-8B-Instruct-GGUF
hf download bartowski/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF \
  --include Meta-Llama-3.1-8B-Instruct-abliterated-Q4_K_M.gguf \
  --local-dir .local_tools/models/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF
```

3. Check every file against the SHA-256 hash recorded in its config:

```text
4f369f8fe0e1bedc5caee9abb89316887f548f80f3035398a5d222a737e699e6  gemma-4-31B-it-Q4_K_M.gguf
14a465017c087e60f77ebf2cb7d10622794a6b9112fe977aa3df43486079ae81  gemma-4-31B-it-uncensored-Q4_K_M.gguf
34c746b1d50ab813e29cd46c4796e3f43c741901a582f93a67b55b9fc9687b35  gemma-4-26B-A4B-it-UD-Q4_K_M.gguf
d482a5daba09e67c925359a1786c4c713d1c3bb35856d199cf296f7cf7bc6cb3  gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf
509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c  qwen2.5-coder-7b-instruct-q4_k_m.gguf
fdf02c16fb654ff60b2c30f1e91573ebc603a7084df3449df89120dca2b18170  Qwen2.5-Coder-7B-Instruct-abliterated-Q4_K_M.gguf
7b064f5842bf9532c91456deda288a1b672397a54fa729aa665952863033557c  Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
c6be866583f7bddb437b8ccd988fc499c98f1846934a1f3d48de7777313057cb  Meta-Llama-3.1-8B-Instruct-abliterated-Q4_K_M.gguf
```

```sh
shasum -a 256 .local_tools/models/*/*.gguf
```

4. Start one `llama.cpp` server per model (see `scripts/local_llama_servers.md`
   and the `scripts/start_llama_*.sh` helpers), then check the endpoints:

```sh
python3 -m security_agent_eval.cli validate-models --models configs/models.example.json
```
