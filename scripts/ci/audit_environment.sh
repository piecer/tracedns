#!/usr/bin/env bash
# Application and audit-tool environments must be separate. Network is allowed.
set -euo pipefail
if (($# != 3)); then
    echo 'usage: audit_environment.sh APP_PYTHON PIP_AUDIT NEW_OUTPUT_DIR' >&2
    exit 2
fi
python=$1
audit=$2
output=$3
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
# Refuse stale reports and do not overwrite any existing evidence.
mkdir -- "$output"
"$python" -VV > "$output/python.txt" 2>&1
"$python" -m pip check > "$output/pip-check.txt" 2>&1
"$python" -m pip freeze --all > "$output/freeze.txt"
"$audit" --version > "$output/audit-version.txt" 2>&1
status=0
"$audit" --strict --disable-pip --no-deps -r "$output/freeze.txt" \
    -f json -o "$output/audit.json" > "$output/audit.stdout.log" 2> "$output/audit.stderr.log" || status=$?
printf '%s\n' "$status" > "$output/audit-exit.txt"
"$python" "$root/scripts/ci/validate_audit.py" "$output/audit.json" "$output/freeze.txt" "$status"
