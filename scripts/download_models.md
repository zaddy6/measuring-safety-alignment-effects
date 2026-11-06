# Downloading Local GGUF Weights

This project does not commit model weights.  Download them into
`.local_tools/models/` or another local directory and record exact file hashes
in `configs/models.example.json`.

1. Configure Hugging Face access:

```sh
python3 -m pip install --user huggingface_hub
hf auth login
```

2. Accept any required model license terms on Hugging Face.

3. Download matched GGUF quantizations.  The uncensored 31B GGUF repository is:

```sh
hf download TrevorJS/gemma-4-31B-it-uncensored-GGUF \
  --local-dir .local_tools/models/gemma-4-31B-it-uncensored-GGUF
```

4. Download an aligned Gemma 4 31B GGUF from a trusted quantization source, or
convert the official `google/gemma-4-31B-it` weights with the same quantization
class used for the uncensored condition.

For the completed 26B A4B replication, download the exact Q4-style files:

```sh
hf download unsloth/gemma-4-26B-A4B-it-GGUF \
  --include gemma-4-26B-A4B-it-UD-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-26B-A4B-it-GGUF
hf download TrevorJS/gemma-4-26B-A4B-it-uncensored-GGUF \
  --include gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf \
  --local-dir .local_tools/models/gemma-4-26B-A4B-it-uncensored-GGUF
```

The hashes used for the reported 26B replication are:

```text
34c746b1d50ab813e29cd46c4796e3f43c741901a582f93a67b55b9fc9687b35  gemma-4-26B-A4B-it-UD-Q4_K_M.gguf
d482a5daba09e67c925359a1786c4c713d1c3bb35856d199cf296f7cf7bc6cb3  gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf
```

5. Compute hashes:

```sh
shasum -a 256 .local_tools/models/**/*.gguf
```

6. Start servers:

```sh
export GEMMA_ALIGNED_GGUF=/absolute/path/to/aligned.Q4_K_M.gguf
export GEMMA_UNCENSORED_GGUF=/absolute/path/to/uncensored.Q4_K_M.gguf
scripts/start_llama_servers.sh
```

7. Verify:

```sh
python3 -m security_agent_eval.cli validate-models --models configs/models.example.json
python3 -m security_agent_eval.cli validate-models \
  --models configs/models.26b_a4b.json \
  --conditions aligned uncensored
```
