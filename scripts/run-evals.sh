#!/usr/bin/env bash
# Runs the eval configurations behind the README's numbers, one after another, into results/.
#
#   scripts/run-evals.sh                                  # the local-model matrix (needs Ollama)
#   scripts/run-evals.sh claude-opus-5-5:plain:3          # model:prompt:trials, any number of them
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
export PATH="$PATH:$HOME/.foundry/bin"

configs=("$@")
if [[ ${#configs[@]} -eq 0 ]]; then
  configs=(
    "scripted:plain:1"
    "ollama:qwen2.5:7b:plain:3"
    "ollama:qwen2.5:7b:guarded:3"
    "ollama:qwen2.5:3b:plain:3"
  )
fi

(cd contracts && forge build >/dev/null)
go build -o bin/leash ./cmd/leash

for c in "${configs[@]}"; do
  trials="${c##*:}"
  rest="${c%:*}"
  prompt="${rest##*:}"
  model="${rest%:*}"
  echo "== $model / $prompt / $trials trial(s)"
  bin/leash eval --model "$model" --prompt "$prompt" --trials "$trials" --out results
done
