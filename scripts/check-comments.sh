#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
exec python3 scripts/check-rust-diff.py "${1:-origin/main}"
