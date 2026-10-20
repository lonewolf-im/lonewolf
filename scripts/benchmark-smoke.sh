#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s --server-binary ABS_PATH --bench-binary ABS_PATH --output NEW_DIR\n' "$0" >&2
  exit 2
}

server_binary=''
bench_binary=''
output=''
while (($#)); do
  (($# >= 2)) || usage
  case "$1" in
    --server-binary) server_binary=$2 ;;
    --bench-binary) bench_binary=$2 ;;
    --output) output=$2 ;;
    *) usage ;;
  esac
  shift 2
done
for executable in "$server_binary" "$bench_binary"; do
  [[ "$executable" == /* && -f "$executable" && -x "$executable" ]] || usage
done
[[ -n "$output" && ! -e "$output" && ! -L "$output" ]] || usage
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -m 700 -- "$output"
active_pid=''
cleanup() {
  if [[ -n "$active_pid" ]]; then
    kill -TERM "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
invoke() {
  "$@" &
  active_pid=$!
  local status=0
  wait "$active_pid" || status=$?
  active_pid=''
  return "$status"
}
for scenario in idle messages churn; do
  invoke "$bench_binary" run --config "$script_dir/../examples/bench/smoke-$scenario.toml" \
    --server-binary "$server_binary" --output "$output/$scenario"
  for artifact in result.json summary.md telemetry.ndjson server.log; do
    [[ -s "$output/$scenario/$artifact" ]] || exit 1
  done
done
invoke "$bench_binary" compare "$output/messages" "$output/messages" --output "$output/comparison"
for artifact in comparison.json comparison.md; do
  [[ -s "$output/comparison/$artifact" ]] || exit 1
done
