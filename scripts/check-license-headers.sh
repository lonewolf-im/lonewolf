#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0
while IFS= read -r -d '' file; do
    if [[ "$(head -n 1 "$file")" != '// SPDX-License-Identifier: Apache-2.0' ]]; then
        printf '%s: missing Apache-2.0 SPDX header on the first line\n' "$file" >&2
        status=1
    fi
done < <(git ls-files --cached --others --exclude-standard -z -- '*.rs')

exit "$status"
