#!/usr/bin/env bash
# Install/download/audit outside this wrapper. Never fall back to host networking.
set -euo pipefail
if (($# == 0)); then
    echo 'usage: bash scripts/ci/loopback_only.sh COMMAND [ARG ...]' >&2
    exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
python=${PYTHON:-python3}
python=$(command -v "$python")
uid=$(id -u)
gid=$(id -g)
if ((uid == 0)); then
    echo 'run as an unprivileged user, not root' >&2
    exit 2
fi
# Pass an explicit nonsecret environment; do not inherit proxy/token/service vars.
clean_env=("PATH=$PATH" "HOME=$HOME" "LANG=C.UTF-8" "CI=true" "PYTHON=$python"
    "npm_config_offline=true" "npm_config_audit=false" "npm_config_fund=false"
    "npm_config_update_notifier=false" "PYTHONDONTWRITEBYTECODE=1")
for name in VIRTUAL_ENV SSL_CERT_FILE REQUESTS_CA_BUNDLE PLAYWRIGHT_BROWSERS_PATH \
            PYTEST_ADDOPTS PLAYWRIGHT_JUNIT_OUTPUT_FILE TMPDIR; do
    if [[ -v "$name" ]]; then clean_env+=("$name=${!name}"); fi
done
# User namespaces work on many developer hosts. GitHub Ubuntu runners may
# restrict them with AppArmor; use their passwordless sudo for a netns instead.
if /usr/bin/unshare --user --map-current-user --net true 2>/dev/null; then
    launcher=(/usr/bin/unshare --user --map-current-user --keep-caps --net)
    drop=(/usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs)
else
    launcher=(sudo -n /usr/bin/unshare --net)
    drop=(/usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs)
fi
# Bring up lo while privileged, then permanently drop capabilities before Python,
# Node, browser or any repository test executes. Exit status is never swallowed.
exec "${launcher[@]}" /bin/bash -c '
    set -euo pipefail
    /usr/bin/ip link set lo up
    exec "$@"
' loopback-setup "${drop[@]}" /usr/bin/env -i "${clean_env[@]}" \
    /bin/bash -c 'set -euo pipefail; "$1" "$2/scripts/ci/network_probe.py"; shift 2; exec "$@"' \
    loopback-tests "$python" "$root" "$@"
