#!/usr/bin/env sh
set -eu

# Repeatable local setup helper. It intentionally does not embed credentials or
# download gated models unless the user has already configured Hugging Face
# access in the environment.

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/.local_tools"
VENV_DIR="$TOOLS_DIR/venv"
LLAMA_DIR="$TOOLS_DIR/llama.cpp"
MODEL_DIR="${MODEL_DIR:-$TOOLS_DIR/models}"

mkdir -p "$TOOLS_DIR" "$MODEL_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install "cmake>=3.28" "huggingface_hub>=0.23"

if [ ! -d "$LLAMA_DIR/.git" ]; then
  git clone https://github.com/ggerganov/llama.cpp "$LLAMA_DIR"
else
  git -C "$LLAMA_DIR" pull --ff-only
fi

"$VENV_DIR/bin/cmake" -S "$LLAMA_DIR" -B "$LLAMA_DIR/build" -DLLAMA_METAL=ON
"$VENV_DIR/bin/cmake" --build "$LLAMA_DIR/build" --config Release -j "$(sysctl -n hw.ncpu)"

cat <<EOF

llama.cpp built at:
  $LLAMA_DIR/build/bin

Add this to PATH for the current shell:
  export PATH="$LLAMA_DIR/build/bin:\$PATH"

Download model files after Hugging Face access is configured. Example:
  "$VENV_DIR/bin/hf" download TrevorJS/gemma-4-31B-it-uncensored-GGUF --local-dir "$MODEL_DIR/gemma-4-31B-it-uncensored-GGUF"

The official aligned Gemma repository may require accepting Google license
terms on Hugging Face before download. Record exact file hashes in
configs/models.example.json before reporting results.
EOF
