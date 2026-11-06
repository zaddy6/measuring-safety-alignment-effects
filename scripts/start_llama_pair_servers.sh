#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
LOCAL_LLAMA_SERVER="$ROOT_DIR/.local_tools/llama.cpp/build/bin/llama-server"

if command -v llama-server >/dev/null 2>&1; then
  LLAMA_SERVER="$(command -v llama-server)"
elif [ -x "$LOCAL_LLAMA_SERVER" ]; then
  LLAMA_SERVER="$LOCAL_LLAMA_SERVER"
else
  echo "llama-server not found. Run scripts/setup_local_models.sh first." >&2
  exit 1
fi

: "${ALIGNED_GGUF:?set ALIGNED_GGUF to the aligned GGUF path}"
: "${UNCENSORED_GGUF:?set UNCENSORED_GGUF to the uncensored/abliterated GGUF path}"

CTX_SIZE="${CTX_SIZE:-8192}"
HOST="${HOST:-127.0.0.1}"
ALIGNED_PORT="${ALIGNED_PORT:-8101}"
UNCENSORED_PORT="${UNCENSORED_PORT:-8102}"

"$LLAMA_SERVER" \
  --model "$ALIGNED_GGUF" \
  --host "$HOST" \
  --port "$ALIGNED_PORT" \
  --ctx-size "$CTX_SIZE" \
  --jinja \
  --reasoning off &
ALIGNED_PID=$!

"$LLAMA_SERVER" \
  --model "$UNCENSORED_GGUF" \
  --host "$HOST" \
  --port "$UNCENSORED_PORT" \
  --ctx-size "$CTX_SIZE" \
  --jinja \
  --reasoning off &
UNCENSORED_PID=$!

trap 'kill "$ALIGNED_PID" "$UNCENSORED_PID" 2>/dev/null || true' INT TERM EXIT
wait
